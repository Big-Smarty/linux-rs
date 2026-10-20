// SPDX-License-Identifier: GPL-2.0-only
//! `x86_64` CPL0 boundaries. See docs/implementation.md for the operation proof
//! matrix. No ordinary kernel code uses FP/SIMD; no entry may unwind.
// Local IRQ save/restore and raw-lock ordering translated from Linux 6.18.57
// arch/x86/include/asm/irqflags.h and include/linux/spinlock_api_smp.h (GPL-2.0).
// This implements neither paravirt alternatives nor scheduler/RT lock policy.
use core::{
    arch::{asm, naked_asm},
    marker::PhantomData,
    ptr,
    sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering, compiler_fence},
};
use kernel::{
    intc::{ERROR_VECTOR, ISA_IRQ_VECTOR_BASE, LOCAL_TIMER_VECTOR, SPURIOUS_VECTOR},
    sync::{RawSpinGuard, RawSpinLock},
};
use raw_cpuid::CpuId;
use x86_64::{
    PhysAddr, PrivilegeLevel, VirtAddr,
    instructions::{
        interrupts,
        port::Port,
        segmentation::{CS, DS, ES, FS, GS, SS, Segment},
        tables::{DescriptorTablePointer, lidt, load_tss},
    },
    registers::{
        control::{Cr0, Cr0Flags, Cr2, Cr3, Cr4, Cr4Flags},
        debug::{DebugAddressRegister, Dr0, Dr1, Dr2, Dr3, Dr6, Dr7},
        model_specific::{Efer, EferFlags, FsBase, GsBase, KernelGsBase, LStar, Msr, SFMask, Star},
        rflags::RFlags,
    },
    structures::{
        gdt::{Descriptor, DescriptorFlags, GlobalDescriptorTable, SegmentSelector},
        idt::{Entry, HandlerFunc},
        paging::PhysFrame,
        tss::TaskStateSegment,
    },
};

pub const STACK_BYTES: usize = 64 * 1024;
#[repr(C, align(4096))]
pub struct Stack {
    guard: [u8; 4096],
    usable: [u8; STACK_BYTES],
}
impl Stack {
    #[expect(
        clippy::large_stack_arrays,
        reason = "This constant initializes only the permanent BSS stacks below (the boot, double-fault, NMI, machine-check and debug stacks and the `KSTACKS` pool); ELF/disassembly inspection checks that no runtime stack temporary or copy exists."
    )]
    const ZERO: Self = Self {
        guard: [0; 4096],
        usable: [0; STACK_BYTES],
    };
}
#[unsafe(no_mangle)]
pub static mut BOOT_STACK: Stack = Stack::ZERO;
static mut DOUBLE_STACK: Stack = Stack::ZERO;
static mut NMI_STACK: Stack = Stack::ZERO;
static mut MACHINE_STACK: Stack = Stack::ZERO;
// Linux `IST_INDEX_DB` (arch/x86/kernel/idt.c:105): #DB can be taken in the
// SYSCALL entry window on the user's RSP, so it gets its own stack.
static mut DEBUG_STACK: Stack = Stack::ZERO;

/// Number of task kernel stacks (`THREAD_SIZE` stacks of `task_struct`), one
/// per scheduler slot. The idle task runs on [`BOOT_STACK`], as Linux's
/// `swapper` runs on its boot stack.
pub const KSTACK_SLOTS: usize = 128;
/// The kernel stacks of tasks. Same type as `BOOT_STACK`: a 4 KiB guard page
/// that `Tables::build` leaves unmapped, then 64 KiB of usable stack. An
/// overflow therefore faults on the guard, and with no stack left for the
/// exception frame escalates to #DF on its IST stack (`unexpected` names it).
/// A frame larger than the 4 KiB guard could jump over it unless the compiler
/// probes each page of the frame as it allocates it; the `x86_64-unknown-none`
/// target spec asks for inline probes and `kstack-overflow` recurses with 6 KiB
/// frames to catch a build that does not.
/// shortcut: a fixed pool in the image (about 8.5 MiB of bss) instead of
/// Linux's vmalloc'ed `THREAD_SIZE` stacks; upgrade with a stack window when
/// the task limit must follow `max_threads`.
static mut KSTACKS: [Stack; KSTACK_SLOTS] = [Stack::ZERO; KSTACK_SLOTS];

fn kstack_base(slot: usize) -> u64 {
    ptr::addr_of!(KSTACKS) as u64 + (slot * core::mem::size_of::<Stack>()) as u64
}
/// Address of the unmapped guard page of pool stack `slot`.
pub fn kstack_guard(slot: usize) -> u64 {
    kstack_base(slot)
}
/// Lowest usable address of pool stack `slot` (just above its guard page).
pub fn kstack_lowest(slot: usize) -> u64 {
    kstack_base(slot) + 4096
}
/// Initial stack pointer of pool stack `slot` (16-byte aligned).
pub fn kstack_top(slot: usize) -> u64 {
    kstack_base(slot) + core::mem::size_of::<Stack>() as u64
}
/// The initial stack pointer of the boot stack, where the idle task runs.
pub fn boot_stack_top() -> u64 {
    ptr::addr_of!(BOOT_STACK) as u64 + core::mem::size_of::<Stack>() as u64
}
/// The unmapped guard pages of every pool stack.
pub fn kstack_guards() -> impl Iterator<Item = u64> {
    (0..KSTACK_SLOTS).map(kstack_guard)
}
/// The pool slot whose stack (guard page included) contains `address`.
pub fn kstack_slot_of(address: u64) -> Option<usize> {
    let offset = address.checked_sub(kstack_base(0))?;
    let slot = usize::try_from(offset / core::mem::size_of::<Stack>() as u64).ok()?;
    (slot < KSTACK_SLOTS).then_some(slot)
}

pub fn guards() -> [u64; 5] {
    [
        ptr::addr_of!(BOOT_STACK) as u64,
        ptr::addr_of!(DOUBLE_STACK) as u64,
        ptr::addr_of!(NMI_STACK) as u64,
        ptr::addr_of!(MACHINE_STACK) as u64,
        ptr::addr_of!(DEBUG_STACK) as u64,
    ]
}

/// Boot ABI: Limine enters CPL0 long mode, valid mapped image, IRQ/DF clear,
/// no FP/SIMD ABI and no unwind. This naked boundary only installs our BSS stack
/// then calls ordinary System V Rust with RSP%16==8. RBP=0 terminates traces.
/// No Rust/intrinsic can set RSP or provide a loader entry without a prologue.
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start() -> ! {
    naked_asm!(
        "cli", "cld",
        "lea rsp, [rip + {stack} + {size}]",
        "xor ebp, ebp",
        "call {main}",
        "ud2",
        stack = sym BOOT_STACK,
        size = const core::mem::size_of::<Stack>(),
        main = sym crate::kernel_main,
    )
}

#[derive(Debug)]
pub enum Error {
    Nx,
    Pat,
    Paging,
    Stack,
    Cpu,
    InterruptGuard,
}

pub fn validate() -> Result<(), Error> {
    // x86_64 guarantees CPUID; raw-cpuid wraps the supported core::arch intrinsic
    // and reports a leaf above the CPU's maximum as absent.
    let cpuid = CpuId::new();
    if !cpuid
        .get_extended_processor_and_feature_identifiers()
        .is_some_and(|features| features.has_execute_disable())
    {
        return Err(Error::Nx);
    }
    if !cpuid
        .get_feature_info()
        .is_some_and(|features| features.has_pat())
    {
        return Err(Error::Pat);
    }
    // SAFETY: CPL0; IA32_PAT (0x277) exists because CPUID.1:EDX.PAT was checked.
    let pat = unsafe { Msr::new(0x277).read() };
    if pat & 0xff != 6 || (pat >> 40) & 0xff != 1 {
        return Err(Error::Pat);
    }
    // Device pages (LAPIC/IOAPIC/HPET) are mapped through a UC entry; require one
    // and remember its index (PAT<<2 | PCD<<1 | PWT). Reset value: entry 3.
    let uc = (0..8u8).find(|&index| pat.to_le_bytes()[usize::from(index)] == 0x00);
    let Some(uc) = uc else {
        return Err(Error::Pat);
    };
    MMIO_PAT_INDEX.store(uc, Ordering::Relaxed);
    let cr0 = Cr0::read();
    let cr4 = Cr4::read();
    // The address of a live local lies in the current stack frame; this replaces
    // an `mov rsp` asm site with the same containment check below.
    let marker = 0u8;
    let rsp = ptr::addr_of!(marker) as u64;
    // CR4.LA57, PGE and PCIDE: MOV to CR3 would leave global or other-PCID
    // loader translations alive (SDM Vol.3 4.10.4.1), defeating the new tree.
    if !cr0.contains(Cr0Flags::PAGING | Cr0Flags::WRITE_PROTECT | Cr0Flags::PROTECTED_MODE_ENABLE)
        || cr4.intersects(Cr4Flags::L5_PAGING | Cr4Flags::PAGE_GLOBAL | Cr4Flags::PCID)
    {
        return Err(Error::Paging);
    }
    // No XSAVE state management exists (`noxsave`), so CR4.OSXSAVE is cleared
    // if a loader set it: with it clear XSETBV/XGETBV/XSAVE are #UD and AVX is
    // unavailable, so no YMM/ZMM upper state can be read or written by ring 3
    // (as Linux `noxsave`). SAFETY below: CPL0, IF=0, one reserved-free bit.
    if cr4.contains(Cr4Flags::OSXSAVE) {
        // SAFETY: only OSXSAVE is removed; paging, PGE and PCIDE were checked
        // clear above, so the translation state is unchanged.
        unsafe {
            Cr4::update(|flags| flags.remove(Cr4Flags::OSXSAVE));
        }
    }
    let base = ptr::addr_of!(BOOT_STACK) as u64;
    if rsp < base + 4096 || rsp >= base + core::mem::size_of::<Stack>() as u64 {
        return Err(Error::Stack);
    }
    if !Efer::read().contains(EferFlags::NO_EXECUTE_ENABLE) {
        return Err(Error::Nx);
    }
    // Keep x87/SIMD inaccessible until real per-task xstate ownership exists.
    // CR0.EM/TS force #NM; OSFXSR/OSXSAVE remain clear from base5. Thus this
    // scalar-only cell neither depends on nor exposes unspecified firmware FP
    // state.
    // SAFETY: CPL0 IF=0; Cr0::write keeps every unlisted (reserved) bit and the
    // paging/WP/PE bits are read back unchanged; the target and linked code
    // exclude FP/SIMD. The crate's `mov cr0` asm has no `nomem`, preserves flags.
    unsafe {
        Cr0::write(cr0 | Cr0Flags::EMULATE_COPROCESSOR | Cr0Flags::TASK_SWITCHED);
    }
    Ok(())
}

pub fn interrupts_off() {
    // x86_64's CLI has no `nomem`, so ordinary operations cannot cross the
    // exclusion boundary (docs/implementation.md asm register).
    interrupts::disable();
}

const INTERRUPT_FLAG: u64 = 1 << 9;
// Currently BSP-local. Move this word with the other CPU-local state before
// releasing any AP. NMI/fault paths do not participate in this ownership domain.
// Pack depth<<1 and the first owner's IF in one word: the last removal captures
// the restoration flag atomically, without a separate reset/publication race.
/// PAT index of an uncached entry, set by `validate`.
static MMIO_PAT_INDEX: AtomicU8 = AtomicU8::new(3);

/// PAT index (`PAT<<2 | PCD<<1 | PWT`) of the uncached entry `validate` found.
pub fn mmio_pat_index() -> u8 {
    MMIO_PAT_INDEX.load(Ordering::Relaxed)
}

static IRQ_NESTING: AtomicU64 = AtomicU64::new(0);

/// `RFLAGS.IF` of the calling CPU (`irqs_disabled()` is its negation).
pub fn interrupts_enabled() -> bool {
    let flags: u64;
    // SAFETY: CPL0, owned mapped stack with no red zone. PUSHFQ/POP balance the
    // stack and only read flags. Omit nomem to retain the compiler boundary.
    unsafe {
        asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
    }
    flags & INTERRUPT_FLAG != 0
}

/// Private CPU-local exclusion: every use is a bounded non-scheduling hardware
/// transaction. NMI is NOT excluded and must never take the blocking timer lock.
/// Arbitrary destruction order is allowed: only the last live owner restores
/// the first owner's IF. !Send/!Sync prevents transfer, not nesting by itself.
/// Every current caller is BSP task/bootstrap or the nonblocking timer IRQ
/// probe, never NMI. A future scheduler must retain the no-migration contract.
#[must_use = "the guard retains local interrupt exclusion until dropped"]
struct LocalInterruptGuard {
    _local: PhantomData<*mut ()>,
}

impl LocalInterruptGuard {
    fn disable() -> Self {
        let flags: u64;
        // SAFETY: CPL0, owned stack, balanced PUSHFQ/POP, no red zone. A maskable
        // interrupt between the saved flags and CLI returns to the same state.
        // CLI changes IF; do not claim preserves_flags, nostack or nomem.
        unsafe {
            asm!("pushfq", "pop {}", "cli", out(reg) flags);
        }
        let entered = IRQ_NESTING.try_update(Ordering::Relaxed, Ordering::Relaxed, |state| {
            let next = state.checked_add(2)?;
            Some(if state == 0 {
                next | u64::from(flags & INTERRUPT_FLAG != 0)
            } else {
                next
            })
        });
        assert!(entered.is_ok(), "local interrupt nesting overflow");
        Self {
            _local: PhantomData,
        }
    }
}

impl Drop for LocalInterruptGuard {
    fn drop(&mut self) {
        let previous = IRQ_NESTING
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |state| {
                match state >> 1 {
                    0 => None,
                    1 => Some(0),
                    _ => Some(state - 2),
                }
            })
            .expect("local interrupt nesting underflow");
        if previous == 3 {
            // No other live owner remains. The root IF was1, so its IDT and
            // controller were already valid. The raw guard's Release store
            // precedes this compiler barrier and the non-nomem STI boundary;
            // x86 preserves that store order. This is not a DMA/weak-CPU fence.
            compiler_fence(Ordering::SeqCst);
            // SAFETY: CPU-local non-migrating ownership above; no NMI path uses
            // this domain. STI's shadow delays recognition, not IF restoration.
            unsafe {
                asm!("sti", options(nostack));
            }
        }
    }
}

/// IRQ-saving spinlock. Besides PIC programming and PIT latch/low/high
/// transactions (the IRQ EOI path never blocks on it), `services::IrqMutex`
/// builds the kernel's allocator/heap/page-table/process locks from it.
/// NMI/fault/emergency output never acquires it. Holders run no callbacks.
pub(crate) struct IrqSpinLock(RawSpinLock);

impl IrqSpinLock {
    pub(crate) const fn new() -> Self {
        Self(RawSpinLock::new())
    }

    pub(crate) fn lock(&self) -> IrqSpinGuard<'_> {
        let irq = LocalInterruptGuard::disable();
        IrqSpinGuard {
            raw: self.0.lock(),
            irq,
        }
    }

    pub(crate) fn try_lock(&self) -> Option<IrqSpinGuard<'_>> {
        let irq = LocalInterruptGuard::disable();
        Some(IrqSpinGuard {
            raw: self.0.try_lock()?,
            irq,
        })
    }
}

pub(crate) struct IrqSpinGuard<'a> {
    // Rust drops fields in declaration order: unlock BEFORE restoring IF.
    // The real IRQ probe below attempts this same lock on the first pending IRQ.
    raw: RawSpinGuard<'a>,
    irq: LocalInterruptGuard,
}

static TIMER_HW: IrqSpinLock = IrqSpinLock::new();
// BSP-only bootstrap probe, disabled outside irq_guard_test. Before AP release
// these exception/test fields must move into explicit per-CPU ownership.
static IRQ_LOCK_PROBE: AtomicU64 = AtomicU64::new(0);
const IRQ_LOCK_ARMED: u64 = 1;
const IRQ_LOCK_FAILED: u64 = 2;
const IRQ_LOCK_PASSED: u64 = 3;

pub fn halt() -> ! {
    interrupts_off();
    loop {
        // CPL0 stop policy; NMI can still arrive and uses its own IST; no
        // implicit reboot or firmware call.
        x86_64::instructions::hlt();
    }
}

#[cfg(feature = "qemu-self-test")]
pub fn exit(success: bool) -> ! {
    interrupts_off();
    // Only compiled into explicitly opted-in QEMU self-test artifacts. The
    // external runner must attach isa-debug-exit at f4, width4. Not physical I/O.
    compiler_fence(Ordering::SeqCst);
    // SAFETY: controlled virtual device, CPL0, one 32-bit OUT.
    unsafe { Port::<u32>::new(0xf4).write(if success { 0x10 } else { 0x11 }) };
    halt()
}

/// # Safety
/// Root is a live aligned owned four-level tree mapping every current
/// instruction/stack/descriptor/resource address with valid permissions. BSP
/// alone executes, IF clear, PCID/global mappings disabled; keep root alive.
pub unsafe fn activate_tables(root: u64) {
    let frame = PhysAddr::try_new(root)
        .ok()
        .and_then(|address| PhysFrame::from_start_address(address).ok())
        .expect("CR3 root must be a 4 KiB-aligned physical frame");
    // SAFETY: private caller has built a 4KiB-aligned owned four-level root,
    // maps current RIP/RSP/GDT/TSS/IDT and diagnostic/allocator resources with
    // same addresses, no PCID/global translations, only BSP executes. CR3 load
    // retires old non-global translations before continued accesses. The crate's
    // `mov cr3` omits nomem and preserves flags; PCD/PWT flags are zero as before.
    unsafe {
        Cr3::write_raw(frame, 0);
    }
}

pub fn active_tables() -> u64 {
    Cr3::read_raw().0.start_address().as_u64()
}

// Port I/O and IF control use the vendored `x86_64` crate (`Port`, `interrupts`),
// whose asm is `nomem`. This kernel's device sequences (configuration, EOI,
// mask) must stay ordered against ordinary memory work, so each access is
// bracketed by compiler fences; the processor keeps the I/O instructions
// themselves in order. No flags or stack are used.
pub(crate) fn out_byte(port: u16, value: u8) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: all callers name owned early PC devices (8259, 8254, CMOS index,
    // speaker gate 0x61, delay port 0x80) or the feature-gated emulated UART; the
    // ports are those of Linux's i8259.c/tsc.c/rtc.c for the same devices. No
    // general port API is exported; CPL0 (IOPL irrelevant).
    unsafe { Port::<u8>::new(port).write(value) };
    compiler_fence(Ordering::SeqCst);
}
pub(crate) fn in_byte(port: u16) -> u8 {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: same device ownership as `out_byte`; IN returns an initialized scalar.
    let value = unsafe { Port::<u8>::new(port).read() };
    compiler_fence(Ordering::SeqCst);
    value
}
pub(crate) fn io_wait() {
    out_byte(0x80, 0);
}
/// 32-bit port read for the ACPI PM timer.
pub(crate) fn in_dword(port: u16) -> u32 {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: the only caller reads the ACPI PM timer I/O port named by the
    // checked FADT (a 4-byte, read-only counter block); IN has no side effect there.
    let value = unsafe { Port::<u32>::new(port).read() };
    compiler_fence(Ordering::SeqCst);
    value
}
/// Enable maskable interrupts. Callers poll a bounded condition and restore
/// IF=0 with [`interrupts_off`] before returning.
pub(crate) fn interrupts_on() {
    compiler_fence(Ordering::SeqCst);
    // The IDT, controller and every handler reachable with IF=1 are installed by
    // the caller; BSP, CPL0.
    interrupts::enable();
    compiler_fence(Ordering::SeqCst);
}
/// Halt until an interrupt, then mask again. The crate's `enable_and_hlt` is the
/// adjacent `sti; hlt` pair: STI's one-instruction shadow makes it race-free
/// against an already pending interrupt. Needs an installed IDT and an armed
/// interrupt source that is known to work (a dead source halts forever; see
/// `timer::wait_until_ns`). IF is 0 on return.
pub(crate) fn wait_for_interrupt() {
    compiler_fence(Ordering::SeqCst);
    interrupts::enable_and_hlt();
    interrupts::disable();
    compiler_fence(Ordering::SeqCst);
}

#[cfg(feature = "qemu-self-test")]
pub fn serial_init() {
    out_byte(0x3f9, 0);
    out_byte(0x3fb, 0x80);
    out_byte(0x3f8, 1);
    out_byte(0x3f9, 0);
    out_byte(0x3fb, 3);
    out_byte(0x3fa, 0xc7);
    out_byte(0x3fc, 0x0b);
}
#[cfg(feature = "qemu-self-test")]
pub fn serial_byte(byte: u8) {
    // Bounded even on lost UART; never wait indefinitely in a panic/NMI path.
    for _ in 0..65536 {
        if in_byte(0x3fd) & 0x20 != 0 {
            out_byte(0x3f8, byte);
            return;
        }
        core::hint::spin_loop();
    }
}

// 64-bit GDT layout of Linux 6.18.57 arch/x86/include/asm/segment.h: 1 KERNEL32_CS,
// 2 KERNEL_CS, 3 KERNEL_DS, 4 USER32_CS, 5 USER_DS, 6 USER_CS (SYSRET order),
// 8-9 TSS. Flags are desc_defs.h DESC_CODE64/DESC_DATA64/DESC_CODE32 (+DESC_USER).
const KERNEL32_CS: SegmentSelector = SegmentSelector::new(1, PrivilegeLevel::Ring0);
pub const KERNEL_CS: SegmentSelector = SegmentSelector::new(2, PrivilegeLevel::Ring0);
const KERNEL_DS: SegmentSelector = SegmentSelector::new(3, PrivilegeLevel::Ring0);
const USER32_CS: SegmentSelector = SegmentSelector::new(4, PrivilegeLevel::Ring3);
const USER_DS: SegmentSelector = SegmentSelector::new(5, PrivilegeLevel::Ring3);
const USER_CS: SegmentSelector = SegmentSelector::new(6, PrivilegeLevel::Ring3);
const TSS_SELECTOR: SegmentSelector = SegmentSelector::new(8, PrivilegeLevel::Ring0);
// The crate documents Linux-equal descriptors; pin them to the Linux values here.
const _: () = {
    assert!(DescriptorFlags::KERNEL_CODE32.bits() == 0x00cf_9b00_0000_ffff);
    assert!(DescriptorFlags::KERNEL_CODE64.bits() == 0x00af_9b00_0000_ffff);
    assert!(DescriptorFlags::KERNEL_DATA.bits() == 0x00cf_9300_0000_ffff);
    assert!(DescriptorFlags::USER_CODE32.bits() == 0x00cf_fb00_0000_ffff);
    assert!(DescriptorFlags::USER_DATA.bits() == 0x00cf_f300_0000_ffff);
    assert!(DescriptorFlags::USER_CODE64.bits() == 0x00af_fb00_0000_ffff);
    assert!(KERNEL32_CS.0 == 0x08 && KERNEL_CS.0 == 0x10 && KERNEL_DS.0 == 0x18);
    assert!(USER32_CS.0 == 0x23 && USER_DS.0 == 0x2b && USER_CS.0 == 0x33);
    assert!(TSS_SELECTOR.0 == 0x40);
};
// The CPU writes the TSS busy bit and descriptor accessed bits; the crate's GDT
// entries are atomics, so those writes are not a data race with Rust accesses.
static mut TSS: TaskStateSegment = TaskStateSegment::new();
static mut GDT: GlobalDescriptorTable<10> = GlobalDescriptorTable::empty();
static mut IDT: [Entry<HandlerFunc>; 256] = [Entry::missing(); 256];

/// # Safety
/// Called once on BSP with IF clear, no AP execution and no live Rust references
/// to descriptor memory. All static image/stacks remain permanently reserved.
pub unsafe fn install_descriptors() {
    // SAFETY: forwarded caller contract; the GDT/CS must be live before the IDT
    // gates copy CS.
    unsafe {
        install_gdt();
        install_idt();
        scrub_debug_registers();
    }
}

/// # Safety
/// Same contract as [`install_descriptors`].
unsafe fn install_gdt() {
    // VirtAddr::new panics on a non-canonical address; these are our own
    // higher-half image statics, so that is a link-time invariant, not input.
    let top = |pointer: *const Stack| {
        VirtAddr::new(pointer as u64 + core::mem::size_of::<Stack>() as u64)
    };
    let tss = ptr::addr_of_mut!(TSS);
    // SAFETY: unique initialization before publication; the packed TSS fields are
    // assigned as whole places through a raw pointer, never by reference.
    unsafe {
        (*tss).privilege_stack_table = [
            top(ptr::addr_of!(BOOT_STACK)),
            VirtAddr::zero(),
            VirtAddr::zero(),
        ];
        (*tss).interrupt_stack_table = [
            top(ptr::addr_of!(DOUBLE_STACK)),
            top(ptr::addr_of!(NMI_STACK)),
            top(ptr::addr_of!(MACHINE_STACK)),
            top(ptr::addr_of!(DEBUG_STACK)),
            VirtAddr::zero(),
            VirtAddr::zero(),
            VirtAddr::zero(),
        ];
    }
    // Until the first task is switched in, ring-3 entries (none can occur yet)
    // would use the boot stack, like RSP0 above.
    KERNEL_STACK_TOP.store(top(ptr::addr_of!(BOOT_STACK)).as_u64(), Ordering::Relaxed);
    // SAFETY: the caller guarantees exclusive access to descriptor memory.
    let gdt = unsafe { &mut *ptr::addr_of_mut!(GDT) };
    for (descriptor, selector) in [
        (
            Descriptor::UserSegment(DescriptorFlags::KERNEL_CODE32.bits()),
            KERNEL32_CS,
        ),
        (Descriptor::kernel_code_segment(), KERNEL_CS),
        (Descriptor::kernel_data_segment(), KERNEL_DS),
        (
            Descriptor::UserSegment(DescriptorFlags::USER_CODE32.bits()),
            USER32_CS,
        ),
        (Descriptor::user_data_segment(), USER_DS),
        (Descriptor::user_code_segment(), USER_CS),
        // Linux leaves entry 7 null; append returns the layout index checked here.
        (
            Descriptor::UserSegment(0),
            SegmentSelector::new(7, PrivilegeLevel::Ring0),
        ),
        // SAFETY: TSS is a permanent static that outlives every use of the GDT.
        (
            unsafe { Descriptor::tss_segment_unchecked(tss) },
            TSS_SELECTOR,
        ),
    ] {
        assert_eq!(
            gdt.append(descriptor),
            selector,
            "GDT layout drifted from Linux"
        );
    }
    // SAFETY: the permanent GDT is complete and never modified after this point
    // except by the CPU's atomic-entry accessed/busy writes; CS reload far-returns
    // to the next instruction with the new kernel code selector (the crate's asm
    // pushes/pops exactly that frame), SS/DS/ES then load the flat data selector,
    // and LTR marks the owned, not-yet-busy TSS descriptor busy. Only CPL0,
    // IRQ-disabled BSP; none of the crate asm blocks unwind, they preserve flags.
    unsafe {
        gdt.load_unsafe();
        CS::set_reg(KERNEL_CS);
        SS::set_reg(KERNEL_DS);
        DS::set_reg(KERNEL_DS);
        ES::set_reg(KERNEL_DS);
        load_tss(TSS_SELECTOR);
    }
}

/// # Safety
/// Same contract as [`install_descriptors`]; the new GDT and CS are loaded.
unsafe fn install_idt() {
    let handlers = [
        v0 as *const (),
        v1 as *const (),
        v2 as *const (),
        v3 as *const (),
        v4 as *const (),
        v5 as *const (),
        v6 as *const (),
        v7 as *const (),
        v8 as *const (),
        v9 as *const (),
        v10 as *const (),
        v11 as *const (),
        v12 as *const (),
        v13 as *const (),
        v14 as *const (),
        v15 as *const (),
        v16 as *const (),
        v17 as *const (),
        v18 as *const (),
        v19 as *const (),
        v20 as *const (),
        v21 as *const (),
        v22 as *const (),
        v23 as *const (),
        v24 as *const (),
        v25 as *const (),
        v26 as *const (),
        v27 as *const (),
        v28 as *const (),
        v29 as *const (),
        v30 as *const (),
        v31 as *const (),
    ];
    // SAFETY: the caller guarantees exclusive access to descriptor memory.
    let idt = unsafe { &mut *ptr::addr_of_mut!(IDT) };
    for (index, gate) in idt.iter_mut().enumerate() {
        let handler = match handlers.get(index) {
            Some(&handler) => handler,
            None => match index {
                0x30 => irq0_entry as *const (),
                0x37 => pic_spurious7_entry as *const (),
                0x3f => pic_spurious15_entry as *const (),
                0xec => lapic_timer_entry as *const (),
                0xfe => apic_error_entry as *const (),
                0xff => apic_spurious_entry as *const (),
                _ => unexpected_entry as *const (),
            },
        };
        // Zero-based IST slots (the crate adds the hardware +1): #DF 1, NMI 2,
        // #MC 3, #DB 4 (Linux idt.c `ISTG` list).
        let ist = match index {
            8 => Some(0),
            2 => Some(1),
            18 => Some(2),
            1 => Some(3),
            _ => None,
        };
        // SAFETY: every handler is one of our entry stubs, which obey the CPU
        // interrupt-gate contract (documented at the entry macro). The gates are
        // typed `Entry<HandlerFunc>` although the error-code vectors point at naked
        // stubs with a different signature: only the address is stored, the type
        // parameter is a phantom and never used to call the handler. set_handler_addr
        // copies the CS loaded above, a valid 64-bit kernel code selector. IST slots
        // 0..=2 name the TSS stacks initialized above.
        unsafe {
            let options = gate.set_handler_addr(VirtAddr::new(handler as u64));
            if let Some(slot) = ist {
                options.set_stack_index(slot);
            }
            // Linux `SYSG`: INT3 and INTO may be executed by ring 3 (idt.c).
            if index == 3 || index == 4 {
                options.set_privilege_level(PrivilegeLevel::Ring3);
            }
        }
    }
    // SAFETY: the permanent initialized IDT is read by the CPU; lidt copies the
    // 10-byte pointer (readonly, no stack effect, flags unchanged).
    unsafe {
        lidt(&DescriptorTablePointer {
            limit: 4095,
            base: VirtAddr::from_ptr(idt.as_ptr()),
        });
    }
}

// Exception and interrupt entry, every vector: the five-word hardware frame
// becomes a Linux `struct pt_regs` (`PtRegs`) that Rust reads and edits in place.
//
// Why asm: the CPU enters with only the hardware frame on the stack and every
// GPR live; the full register file must be saved before any Rust code runs, and
// `iretq` is the only way back. No intrinsic or `extern "x86-interrupt"` lowering
// can do this: that ABI saves only the registers its handler happens to use, and
// its error-code lowering was independently found to misalign ordinary calls
// (retained integrated-007 fatal-PF witness). A signal frame, a handler entry or
// `rt_sigreturn` needs all fifteen GPRs, including RBX/RBP/R12-R15.
// Prerequisites: IDT gate installed by `install_idt` (interrupt gate, so IF=0 on
// entry); 64-bit mode always pushes SS:RSP, so the frame has five words whatever
// the CPL; the CPU aligns RSP to 16 bytes before pushing, so RSP%16 is 8 at
// entry without a hardware error code and 0 with one. Vectors 8, 10-14, 17, 21,
// 29 and 30 push an error code (the `error` arm); the others get a pushed -1.
// Inputs: none (the vector is an assembler constant). Layout: the stub pushes
// `orig_ax` (-1, or the hardware error code which it then reads into RDX and
// overwrites with -1, as Linux's `error_entry` does so that `syscall_get_nr`
// reports "not a syscall"), then DI SI DX CX AX R8-R11 BX BP R12-R15: 16
// pushes in total, which is exactly `PtRegs` below the hardware frame. One more
// `sub rsp, 8` makes RSP%16==0 at the CALL (RSP%16 is 0 once `orig_ax` is on the
// stack in both arms: the pushed -1, or the hardware error code), so the SysV
// callee sees RSP%16==8. Outputs/clobbers:
// RDI = &mut PtRegs, ESI = vector, RDX = error code (0 in the non-error arm);
// every GPR is restored from `PtRegs` (a handler may have changed any of them,
// including the return CS/RIP/RFLAGS/RSP/SS) and flags come back from IRETQ,
// which every stub reaches by `jmp` to the one `iret_site` below.
// CLD clears a live user DF for the C ABI. Memory: the stack stores/loads
// above, the handler may touch anything, so no `nomem`. Stack: ring-3 and
// ring-0 entries run on the current stack (BOOT_STACK for ring 3, IST for the
// vectors that have one); no red zone is used and the handler never unwinds
// (panic=abort). Control flow: CALL to `interrupt_handler`, then IRETQ; it
// returns once the pending-signal work of a ring-3 return is done. FP/SIMD
// state is not touched (the kernel is soft-float; user FP state stays live).
// Privilege: reachable from any CPL; user-controllable inputs are only the
// hardware frame contents, never trusted by the stub.
macro_rules! entry {
    ($name:ident, $vector:expr) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $name() {
            naked_asm!(
                "push -1",
                "push rdi", "push rsi", "push rdx", "push rcx", "push rax",
                "push r8", "push r9", "push r10", "push r11",
                "push rbx", "push rbp", "push r12", "push r13", "push r14", "push r15",
                "sub rsp, 8",
                "cld", "lea rdi, [rsp + 8]", "mov esi, {vector}", "xor edx, edx",
                "call {handler}",
                "add rsp, 8",
                "pop r15", "pop r14", "pop r13", "pop r12", "pop rbp", "pop rbx",
                "pop r11", "pop r10", "pop r9", "pop r8",
                "pop rax", "pop rcx", "pop rdx", "pop rsi", "pop rdi",
                "add rsp, 8", "jmp {iret}",
                vector = const $vector,
                handler = sym interrupt_handler,
                iret = sym iret_site,
            );
        }
    };
    ($name:ident, $vector:expr, error) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $name() {
            naked_asm!(
                "push rdi", "push rsi", "push rdx", "push rcx", "push rax",
                "push r8", "push r9", "push r10", "push r11",
                "push rbx", "push rbp", "push r12", "push r13", "push r14", "push r15",
                "mov rdx, [rsp + 120]", "mov qword ptr [rsp + 120], -1",
                "sub rsp, 8",
                "cld", "lea rdi, [rsp + 8]", "mov esi, {vector}",
                "call {handler}",
                "add rsp, 8",
                "pop r15", "pop r14", "pop r13", "pop r12", "pop rbp", "pop rbx",
                "pop r11", "pop r10", "pop r9", "pop r8",
                "pop rax", "pop rcx", "pop rdx", "pop rsi", "pop rdi",
                "add rsp, 8", "jmp {iret}",
                vector = const $vector,
                handler = sym interrupt_handler,
                iret = sym iret_site,
            );
        }
    };
}
// The one `IRETQ` of every exception, interrupt and `SYSCALL` return (Linux's
// `native_irq_return_iret`, arch/x86/entry/entry_64.S).
//
// Why asm: `IRETQ` is the only way to load CS:RIP, RFLAGS and SS:RSP at once and
// change privilege level; no intrinsic or safe construct exists. Why one site:
// the CPU validates the return frame only when `IRETQ` executes, in ring 0, and
// the frame can be hostile (a handler rewrites it through its `rt_sigreturn`
// frame or `rt_sigaction` address). Linux recognises that fault by the faulting
// address (`.Lerror_bad_iret`, `fixup_bad_iret`) instead of predicting the CPU's
// rules, and so does `fixup_bad_iret` below: exactly one address must exist.
// Prerequisites: reached by `jmp` from a stub or `syscall_entry` with CPL0, IF=0
// and every GPR already restored, RSP at the five-word frame (RIP, CS, RFLAGS,
// RSP, SS). Inputs/outputs: no register is read or written by this code; the
// registers are the user's. Clobbers: none (flags are loaded from the frame).
// Memory: pops the frame from the kernel stack only. Stack: the pop is the whole
// effect; no red zone, no unwinding (panic=abort). Control flow: does not return
// to Rust. If the CPU refuses the frame it raises #GP/#NP/#SS at THIS address
// with RSP unchanged, still pointing at the frame, which is what
// `fixup_bad_iret` relies on (SDM Vol. 2, IRET: faults leave the machine state
// as it was before the instruction). Privilege: CPL0 only. The function symbol
// is the faulting address (a naked function is exactly its body).
#[unsafe(naked)]
unsafe extern "C" fn iret_site() -> ! {
    naked_asm!("iretq");
}
entry!(v0, 0);
entry!(v1, 1);
entry!(v2, 2);
entry!(v3, 3);
entry!(v4, 4);
entry!(v5, 5);
entry!(v6, 6);
entry!(v7, 7);
entry!(v8, 8, error);
entry!(v9, 9);
entry!(v10, 10, error);
entry!(v11, 11, error);
entry!(v12, 12, error);
entry!(v13, 13, error);
entry!(v14, 14, error);
entry!(v15, 15);
entry!(v16, 16);
entry!(v17, 17, error);
entry!(v18, 18);
entry!(v19, 19);
entry!(v20, 20);
entry!(v21, 21, error);
entry!(v22, 22);
entry!(v23, 23);
entry!(v24, 24);
entry!(v25, 25);
entry!(v26, 26);
entry!(v27, 27);
entry!(v28, 28);
entry!(v29, 29, error);
entry!(v30, 30, error);
entry!(v31, 31);
entry!(irq0_entry, 0x30);
entry!(pic_spurious7_entry, 0x37);
entry!(pic_spurious15_entry, 0x3f);
entry!(lapic_timer_entry, 0xec);
entry!(apic_error_entry, 0xfe);
entry!(apic_spurious_entry, 0xff);
// The CPU does not push the vector number. Unassigned external slots share one
// compiler entry; its private sentinel is NEVER reported as a real vector.
const UNKNOWN_EXTERNAL_VECTOR: u64 = 256;
entry!(unexpected_entry, UNKNOWN_EXTERNAL_VECTOR);

static BREAKPOINTS: AtomicU64 = AtomicU64::new(0);
static BREAKPOINT_ARMED: AtomicU64 = AtomicU64::new(0);
static FAULTS: AtomicU64 = AtomicU64::new(0);
static FAULT_ADDRESS: AtomicU64 = AtomicU64::new(0);
static FAULT_RIP: AtomicU64 = AtomicU64::new(0);
static FAULT_ERROR: AtomicU64 = AtomicU64::new(0);
static FAULT_ARMED: AtomicU64 = AtomicU64::new(0);

/// Hardware interrupt vectors this kernel owns. Like Linux's `common_interrupt`
/// they are served identically at any CPL (`/init` runs with IF=1, so a timer or
/// spurious vector that was latched across the shutdown can arrive in ring 3):
/// they are not task exceptions. Returns false for everything else, including a
/// *real* 8259 IRQ7/15, which stays an unexpected vector.
fn external_interrupt(vector: u64, user: bool) -> bool {
    let base = u64::from(ISA_IRQ_VECTOR_BASE);
    match vector {
        v if v == u64::from(SPURIOUS_VECTOR) => crate::apic::spurious_interrupt(),
        v if v == u64::from(ERROR_VECTOR) => crate::apic::error_interrupt(),
        v if v == base => crate::timer::isa_irq0_interrupt(user),
        v if v == u64::from(LOCAL_TIMER_VECTOR) => crate::timer::lapic_timer_interrupt(user),
        // 8259 lines 7 and 15 raise a spurious vector when a request vanishes
        // between INTR and acknowledge (Linux spurious_8259A_irq): ignore only
        // when the in-service bit is clear.
        v if v == base + 7 || v == base + 15 => return crate::apic::pic_spurious(v != base + 7),
        _ => return false,
    }
    true
}

/// Consecutive refused returns to ring 3 without an entry from ring 3 between,
/// for the running task: a context switch swaps it with the next task's
/// ([`swap_bad_iret_depth`]), so one task's nested refusals neither count
/// against nor are reset by another's.
static BAD_IRET_DEPTH: AtomicU64 = AtomicU64::new(0);

/// Install `depth` as the running task's `BAD_IRET_DEPTH`; returns the
/// previous task's value for its save slot. Context: a switch, IF=0.
pub(crate) fn swap_bad_iret_depth(depth: u64) -> u64 {
    BAD_IRET_DEPTH.swap(depth, Ordering::Relaxed)
}
/// shortcut: Linux's `fixup_bad_iret` copies the user frame back to the top of
/// the entry stack, so a handler that keeps returning to a refused frame
/// (`SA_NODEFER` on a non-canonical handler address) loops forever there; this
/// kernel nests one exception frame per refusal on the same stack and stops
/// loudly at this depth. Upgrade by moving the frame to the stack top.
const BAD_IRET_LIMIT: u64 = 16;

/// `.Lerror_bad_iret` + `fixup_bad_iret` (`arch/x86/entry/entry_64.S`,
/// `arch/x86/kernel/traps.c`): `iretq` to a frame the CPU refuses (a non-canonical RIP, a
/// bad CS or SS selector, a compatibility RIP beyond its segment limit, ...)
/// raises #GP/#NP/#SS in ring 0 at [`iret_site`], with RSP still at that
/// frame. Make the exception look as if ring 3 had raised it: the user's own
/// RIP/CS/RFLAGS/RSP/SS replace the kernel ones in `regs` (the GPRs in `regs`
/// are already the user's, restored by the stub before `iretq`). The CPU, not
/// a prediction of its rules, decides; the error code is the CPU's.
///
/// Returns false (and changes nothing) for every exception that is not that.
fn fixup_bad_iret(regs: &mut PtRegs, vector: u64) -> bool {
    if !(10..=13).contains(&vector)
        || regs.cs != u64::from(KERNEL_CS.0)
        || regs.ip != iret_site as *const () as u64
    {
        return false;
    }
    // Every ring-3 entry runs on its task's pool stack (the boot stack belongs
    // to the idle task and never returns to ring 3), so the frame must lie in
    // the usable part of one pool slot.
    let frame = regs.sp;
    let Some(slot) = kstack_slot_of(frame) else {
        return false;
    };
    if !frame.is_multiple_of(8) || frame < kstack_lowest(slot) || frame > kstack_top(slot) - 5 * 8 {
        return false;
    }
    // SAFETY: the fault happened at `iret_site`, which only runs with RSP at the
    // five-word frame that a stub, `syscall_entry` or `restore_regs_and_iret`
    // left on a task's kernel stack (checked above to lie wholly inside the
    // usable part of one pool stack, 8-aligned), and the exception left RSP
    // unchanged; the CPU has pushed its own frame below it, so the words are
    // intact and initialized. Nothing else writes that stack while this handler
    // runs (interrupts are masked, single CPU, and the task is the one running).
    let [ip, cs, flags, sp, ss] = unsafe { ptr::read_volatile(frame as *const [u64; 5]) };
    if cs & 3 != 3 {
        return false; // a ring-0 return that failed is a kernel bug
    }
    if BAD_IRET_DEPTH.fetch_add(1, Ordering::Relaxed) >= BAD_IRET_LIMIT {
        crate::log!(
            "FAIL bad iret loop depth={} rip={:#x}\n",
            BAD_IRET_LIMIT,
            ip
        );
        crate::fail();
    }
    (regs.ip, regs.cs, regs.flags, regs.sp, regs.ss) = (ip, cs, flags, sp, ss);
    true
}

/// Rust half of every exception and interrupt entry; `regs` is the live
/// `pt_regs` on the entry stack (see the `entry!` proof above), and whatever
/// it holds on return is what `iretq` restores.
extern "C" fn interrupt_handler(regs: &mut PtRegs, vector: u64, error: u64) {
    // `user_mode(regs)`: any ring-3 CS (64-bit 0x33 or compatibility 0x23).
    let mut user = regs.cs & 3 == 3;
    if user {
        BAD_IRET_DEPTH.store(0, Ordering::Relaxed);
    } else if fixup_bad_iret(regs, vector) {
        // The exception was raised by the `iretq` back to ring 3: from here on it
        // is the user's exception (the signal's `ip`/`sp` are the refused frame's).
        user = true;
    }
    if external_interrupt(vector, user) {
        if user {
            // A tick can be the wake-up of an expired interval timer, and the
            // return to ring 3 is where pending signals are delivered.
            crate::userspace::exit_to_user(regs);
        }
        return;
    }
    if user {
        // An exception raised by init is a signal (`force_sig`); the return
        // path delivers it, except a page fault the address-space model
        // resolves, which returns here and `iretq`s to the faulting
        // instruction. CR2 is read first, before anything that could fault.
        let address = if vector == 14 { Cr2::read_raw() } else { 0 };
        crate::userspace::exception(regs, vector, error, address);
        return;
    }
    if regs.cs != u64::from(KERNEL_CS.0) {
        unexpected(regs, vector, error, 0);
    }
    match vector {
        3 if BREAKPOINT_ARMED.swap(0, Ordering::Acquire) == 1 => {
            BREAKPOINTS.fetch_add(1, Ordering::Relaxed);
        }
        14 => {
            // Read CR2 before any fallible work (CPL0; nomem asm, scalar output).
            let address = Cr2::read_raw();
            if FAULT_ARMED.swap(0, Ordering::Acquire) == 1
                && address == FAULT_ADDRESS.load(Ordering::Relaxed)
                && regs.ip == FAULT_RIP.load(Ordering::Relaxed)
                && error == FAULT_ERROR.load(Ordering::Relaxed)
            {
                // SAFETY: the entry boundary supplies the immovable live CPU
                // frame. Volatile commits recovery to that hardware frame, not
                // a compiler-local by-value copy; only RIP changes to the exact
                // reviewed recovery RET, preserving the saved CPL/flags/stack.
                unsafe {
                    ptr::write_volatile(
                        ptr::addr_of_mut!(regs.ip),
                        probe_return as *const () as u64,
                    );
                }
                FAULTS.fetch_add(1, Ordering::Relaxed);
            } else {
                unexpected(regs, vector, error, address);
            }
        }
        // A #DF taken on its IST stack: CR2 still holds the first fault's
        // address, which names a stack overflow (`unexpected`).
        8 => unexpected(regs, vector, error, Cr2::read_raw()),
        _ => unexpected(regs, vector, error, 0),
    }
}
#[cfg(feature = "boot-proofs")]
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn ordinary_call_stack_residue() -> u64 {
    // Observe the actual ordinary SysV callee-entry stack before any prologue.
    // Rust/intrinsics cannot expose that point. CALL/RET own one stack word;
    // RAX and arithmetic flags are caller-clobbered, memory is not accessed.
    // This witness never realigns or repairs its caller's stack.
    naked_asm!("mov rax, rsp", "and eax, 15", "ret");
}

fn unexpected(frame: &PtRegs, vector: u64, error: u64, address: u64) -> ! {
    #[cfg(feature = "boot-proofs")]
    {
        // SAFETY: ordinary scalar C-ABI CALL into the naked entry witness.
        // Deliberately observe, rather than normalize, a broken interrupt caller.
        let residue = unsafe { ordinary_call_stack_residue() };
        crate::log!("TRAP call-abi vector={} rsp_mod16={}\n", vector, residue);
        if residue != 8 {
            crate::log!("FAIL trap-call-abi\n");
            crate::fail();
        }
    }
    // A fault (or the double fault it became, when the exception frame had no
    // room either) on a task stack's guard page is a kernel stack overflow,
    // Linux's `handle_stack_overflow` ("kernel stack overflow (double-fault)").
    // The boot stack's guard is read on purpose by the `unexpected-page-fault`
    // case, so it keeps the plain trap line. CR2 at a #DF is the first fault's
    // address only in practice (the architecture does not specify it), so a
    // guard-page CR2 counts only with the faulting stack pointer on the same
    // stack: a stale CR2 or a stray access elsewhere is a plain trap.
    if let Some(slot) = kstack_slot_of(address).filter(|&slot| {
        address >> 12 == kstack_guard(slot) >> 12 && kstack_slot_of(frame.sp) == Some(slot)
    }) {
        crate::log!(
            "FAIL kernel stack overflow slot={} vector={} error={:#x} rip={:#x} cr2={:#x} rsp={:#x}\n",
            slot,
            vector,
            error,
            frame.ip,
            address,
            frame.sp
        );
        crate::fail();
    }
    if vector == UNKNOWN_EXTERNAL_VECTOR {
        crate::log!(
            "FAIL trap vector=unknown-external error={:#x} rip={:#x} rsp={:#x}\n",
            error,
            frame.ip,
            frame.sp
        );
        crate::fail();
    }
    crate::log!(
        "FAIL trap vector={} error={:#x} rip={:#x} cr2={:#x} rsp={:#x}\n",
        vector,
        error,
        frame.ip,
        address,
        frame.sp
    );
    crate::fail()
}

pub fn breakpoint_test() -> bool {
    let before = BREAKPOINTS.load(Ordering::Relaxed);
    BREAKPOINT_ARMED.store(1, Ordering::Release);
    // SAFETY: IDT/stack installed and the only expected breakpoint is armed.
    // Naked probe preserves its SysV callee-saved inputs and checks all15 GPRs.
    let preserved = unsafe { breakpoint_register_probe() };
    BREAKPOINT_ARMED.store(0, Ordering::Relaxed);
    preserved == 1 && BREAKPOINTS.load(Ordering::Relaxed) == before + 1
}

// Full-width, distinct nonzero high/low halves detect 64-bit truncation.
static REGISTER_PATTERNS: [u64; 15] = [
    0x0123_4567_89ab_cdef,
    0xfedc_ba98_7654_3210,
    0x55aa_33cc_0ff0_c3a5,
    0x89ab_cdef_0123_4567,
    0x0f1e_2d3c_4b5a_6978,
    0xa1b2_c3d4_e5f6_0718,
    0x8000_0001_0000_0001,
    0x7fff_fffe_0102_0304,
    0xcafe_0123_beef_4567,
    0x1357_9bdf_2468_ace0,
    0xe0ac_6824_df9b_5713,
    0xdead_beef_7654_3210,
    0x1029_3847_56ab_cdef,
    0xabcd_ef98_7654_3210,
    0x5a5a_a5a5_f0f0_0f0f,
];

// Ordinary Rust/intrinsics cannot place independent sentinels in every named
// GPR across a hardware event. This test-only boundary does so, compares each
// after return, and restores the caller's six SysV callee-saved registers. RSP
// is validated by balanced saves/RET; no heap, FP/vector, unwind or privilege
// change. Flags may change. Breakpoint has IF=0; IRQ probe restores IF=0 after
// STI/HLT. The entry boundary, not this probe, owns actual interrupt handling.
macro_rules! register_probe {
    ($name:ident, $($event:literal),+ $(; $operand:ident = sym $symbol:path)?) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $name() -> u64 {
            naked_asm!(
                "push rbx", "push rbp", "push r12", "push r13", "push r14", "push r15",
                "mov rax, [rip + {patterns}]", "mov rbx, [rip + {patterns} + 8]",
                "mov rcx, [rip + {patterns} + 16]", "mov rdx, [rip + {patterns} + 24]",
                "mov rsi, [rip + {patterns} + 32]", "mov rdi, [rip + {patterns} + 40]",
                "mov rbp, [rip + {patterns} + 48]", "mov r8, [rip + {patterns} + 56]",
                "mov r9, [rip + {patterns} + 64]", "mov r10, [rip + {patterns} + 72]",
                "mov r11, [rip + {patterns} + 80]", "mov r12, [rip + {patterns} + 88]",
                "mov r13, [rip + {patterns} + 96]", "mov r14, [rip + {patterns} + 104]",
                "mov r15, [rip + {patterns} + 112]",
                $($event,)+
                "cmp rax, [rip + {patterns}]", "jne 2f", "cmp rbx, [rip + {patterns} + 8]", "jne 2f",
                "cmp rcx, [rip + {patterns} + 16]", "jne 2f", "cmp rdx, [rip + {patterns} + 24]", "jne 2f",
                "cmp rsi, [rip + {patterns} + 32]", "jne 2f", "cmp rdi, [rip + {patterns} + 40]", "jne 2f",
                "cmp rbp, [rip + {patterns} + 48]", "jne 2f", "cmp r8, [rip + {patterns} + 56]", "jne 2f",
                "cmp r9, [rip + {patterns} + 64]", "jne 2f", "cmp r10, [rip + {patterns} + 72]", "jne 2f",
                "cmp r11, [rip + {patterns} + 80]", "jne 2f", "cmp r12, [rip + {patterns} + 88]", "jne 2f",
                "cmp r13, [rip + {patterns} + 96]", "jne 2f", "cmp r14, [rip + {patterns} + 104]", "jne 2f",
                "cmp r15, [rip + {patterns} + 112]", "jne 2f", "mov eax, 1", "jmp 3f",
                "2:", "xor eax, eax", "3:",
                "pop r15", "pop r14", "pop r13", "pop r12", "pop rbp", "pop rbx", "ret",
                patterns = sym REGISTER_PATTERNS,
                $($operand = sym $symbol,)?
            )
        }
    };
}
register_probe!(breakpoint_register_probe, "int3");
register_probe!(irq_register_probe, "sti", "hlt", "cli");
register_probe!(
    page_fault_register_probe, "sub rsp, 8", "call {fault_probe}", "add rsp, 8";
    fault_probe = sym probe_guard_read
);

#[unsafe(naked)]
unsafe extern "C" fn probe_guard_read() -> u64 {
    // The exact first instruction faults without changing any GPR. Its ordinary
    // CALL return address lets the existing exact-RIP recovery RET resume the
    // shared fifteen-register witness. No reference to the unmapped guard exists.
    naked_asm!("mov rax, [rip + {guard}]", "ret", guard = sym BOOT_STACK);
}

/// # Safety
/// BSP IF0 with owned IDT/CR3 and the `BOOT_STACK` guard verified unmapped; no
/// other fault permit is active and no AP shares this still-BSP-only state.
pub unsafe fn page_fault_register_test() -> bool {
    FAULT_ADDRESS.store(guards()[0], Ordering::Relaxed);
    FAULT_RIP.store(probe_guard_read as *const () as u64, Ordering::Relaxed);
    FAULT_ERROR.store(0, Ordering::Relaxed);
    let before = FAULTS.load(Ordering::Relaxed);
    FAULT_ARMED.store(1, Ordering::Release);
    // SAFETY: caller supplies the exact mapping/entry/ownership contract above.
    let preserved = unsafe { page_fault_register_probe() };
    FAULT_ARMED.store(0, Ordering::Relaxed);
    preserved == 1 && FAULTS.load(Ordering::Relaxed) == before + 1
}

pub fn irq_register_test() -> bool {
    let before = crate::timer::ticks();
    // SAFETY: only called after tick/IDT initialization, on BSP with IF=0.
    let preserved = unsafe { irq_register_probe() };
    preserved == 1 && crate::timer::ticks() > before
}

pub fn unexpected_breakpoint() -> ! {
    // Deliberate terminal negative case; no armed breakpoint permit, so the
    // handler is fatal. halt() is the defence if it ever returned.
    interrupts::int3();
    halt()
}

#[unsafe(naked)]
unsafe extern "C" fn probe_read(_address: u64) -> u64 {
    naked_asm!("mov rax, [rdi]", "ret");
}
#[unsafe(naked)]
unsafe extern "C" fn probe_write(_address: u64, _value: u64) {
    naked_asm!("mov [rdi], rsi", "ret");
}
#[unsafe(naked)]
unsafe extern "C" fn probe_execute(_address: u64) {
    naked_asm!("jmp rdi");
}
#[unsafe(naked)]
unsafe extern "C" fn probe_return() {
    naked_asm!("ret");
}

/// Deliberately access a tested nonpresent/readonly/NX page. Caller must own the
/// mapping and must only use the exact fault kind listed here. Neither a failed
/// check nor an unexpected vector may be mistaken for success.
/// # Safety
/// GDT/IDT/TSS and test recovery installed; IF clear; address either inaccessible
/// or valid for the selected read/write/execute probe, no live aliased reference.
pub unsafe fn fault_test(address: u64, kind: u8) -> bool {
    let (rip, error) = match kind {
        0 => (probe_read as *const () as u64, 0),
        1 => (probe_write as *const () as u64, 3),
        2 => (address, 17),
        _ => return false,
    };
    FAULT_ADDRESS.store(address, Ordering::Relaxed);
    FAULT_RIP.store(rip, Ordering::Relaxed);
    FAULT_ERROR.store(error, Ordering::Relaxed);
    // Release publishes the expected tuple before synchronous fault entry.
    FAULT_ARMED.store(1, Ordering::Release);
    let before = FAULTS.load(Ordering::Relaxed);
    // SAFETY: caller supplies a mapping meeting the chosen controlled-fault
    // contract; wrapper preserves call stack; handler redirects to naked RET.
    unsafe {
        match kind {
            0 => {
                let _ = probe_read(address);
            }
            1 => probe_write(address, 0),
            2 => probe_execute(address),
            _ => {}
        }
    }
    FAULT_ARMED.store(0, Ordering::Relaxed);
    FAULTS.load(Ordering::Relaxed) == before + 1
}

pub fn unexpected_fault() -> ! {
    // SAFETY: intentionally terminal guest exception after IDT installation;
    // no unwind/return, UD2 has no memory effect but handler diagnostics do.
    unsafe {
        asm!("ud2", options(noreturn));
    }
}

pub fn unexpected_page_fault() -> ! {
    // SAFETY: owned CR3/IDT are installed and this guard is verified unmapped.
    // Unlike fault_test, no recovery permit is armed: execute the real fatal
    // hardware-error-code path, including ordinary Rust diagnostic calls.
    unsafe {
        probe_read(guards()[0]);
    }
    crate::log!("FAIL fatal-page-fault guard unexpectedly readable\n");
    crate::fail()
}

/// Run `f` as one timer-hardware programming transaction: local interrupts off
/// and the timer lock held, so the tick IRQ cannot interleave with a
/// multi-register sequence. `f` must not sleep, allocate or take another lock.
pub(crate) fn timer_transaction<R>(f: impl FnOnce() -> R) -> R {
    let _owner = TIMER_HW.lock();
    f()
}

/// The tick handlers' nonblocking probe of the timer lock, active only inside
/// `irq_guard_test`: a held lock must make this fail, never deadlock.
pub(crate) fn irq_lock_probe() {
    if IRQ_LOCK_PROBE.load(Ordering::Acquire) == IRQ_LOCK_ARMED {
        let result = if TIMER_HW.try_lock().is_some() {
            IRQ_LOCK_PASSED
        } else {
            IRQ_LOCK_FAILED
        };
        IRQ_LOCK_PROBE.store(result, Ordering::Release);
    }
}

/// Execute nested saved-IF and lock/IRQ ownership checks against the real tick
/// interrupt (LAPIC timer or PIT). Called on the BSP after timer setup, before
/// any AP or scheduler execution. Every returning path has IF=0; intervals are
/// measured on the calibrated TSC, not by a loop count.
pub fn irq_guard_test(restore_early: bool) -> Result<(), Error> {
    if interrupts_enabled() || IRQ_NESTING.load(Ordering::Relaxed) != 0 {
        interrupts_off();
        return Err(Error::InterruptGuard);
    }
    {
        let _outer = LocalInterruptGuard::disable();
        {
            let _inner = LocalInterruptGuard::disable();
            if interrupts_enabled() {
                return Err(Error::InterruptGuard);
            }
        }
        if interrupts_enabled() {
            return Err(Error::InterruptGuard);
        }
    }
    if interrupts_enabled() {
        return Err(Error::InterruptGuard);
    }
    if !out_of_order_irq_guards(false) {
        return Err(Error::InterruptGuard);
    }
    // The caller initialized descriptors and the tick source. No lock is held,
    // no AP runs, and the bounded inner test never schedules or allocates.
    interrupts_on();
    let result = irq_guard_enabled_test(restore_early);
    interrupts_off();
    IRQ_LOCK_PROBE.store(0, Ordering::Release);
    result
}

fn out_of_order_irq_guards(initially_enabled: bool) -> bool {
    if interrupts_enabled() != initially_enabled {
        return false;
    }
    let first = LocalInterruptGuard::disable();
    let second = LocalInterruptGuard::disable();
    let initially_masked = !interrupts_enabled();
    drop(first);
    let still_masked = !interrupts_enabled();
    drop(second);
    initially_masked
        && still_masked
        && interrupts_enabled() == initially_enabled
        && IRQ_NESTING.load(Ordering::Relaxed) == 0
}

fn irq_guard_enabled_test(restore_early: bool) -> Result<(), Error> {
    if !out_of_order_irq_guards(true) {
        return Err(Error::InterruptGuard);
    }
    let owner = TIMER_HW.lock();
    if interrupts_enabled() || TIMER_HW.try_lock().is_some() || interrupts_enabled() {
        return Err(Error::InterruptGuard);
    }
    let blocked = crate::timer::poll_periods(2).map_err(|_| Error::InterruptGuard)?;
    if blocked != 0 {
        return Err(Error::InterruptGuard);
    }
    IRQ_LOCK_PROBE.store(IRQ_LOCK_ARMED, Ordering::Release);
    let resumed = if restore_early {
        // QEMU-only mutation selected by main: really restore IF while retaining
        // the raw lock, then observe actual IRQs over two tick periods. The IRQ
        // handler must fail its nonblocking acquisition, never deadlock.
        let IrqSpinGuard { raw, irq } = owner;
        drop(irq);
        let observation = crate::timer::poll_periods(2);
        drop(raw);
        observation
    } else {
        // Correct field destruction publishes unlock before restoring IF.
        drop(owner);
        if !interrupts_enabled() {
            return Err(Error::InterruptGuard);
        }
        crate::timer::poll_periods(2)
    }
    .map_err(|_| Error::InterruptGuard)?;
    let acquired = IRQ_LOCK_PROBE.load(Ordering::Acquire) == IRQ_LOCK_PASSED;
    crate::log!(
        "IRQ restore observation periods=2 irq_delta={} lock_acquired={}\n",
        resumed,
        acquired
    );
    if resumed == 0 || !acquired {
        return Err(Error::InterruptGuard);
    }
    Ok(())
}

pub fn unexpected_interrupt() -> ! {
    // SAFETY: deliberate CPL0 software interrupt into an unassigned IDT slot;
    // its shared entry must report unknown, never a fabricated vector number.
    unsafe {
        asm!("int 0x40", options(noreturn));
    }
}

// ---------------------------------------------------------------------------
// Ring 3 for the first-userspace slice (decision A18).
//
// Kernel stack: ring-3 -> ring-0 transitions of every kind (exception, IRQ and
// SYSCALL) run on the top of the running task's own kernel stack, a slot of the
// `KSTACKS` pool (4 KiB unmapped guard page, 64 KiB usable; the deepest path, a
// 2 KiB tty chunk plus formatting, is far below that), whose top `ktask` makes
// both `TSS.RSP0` and `KERNEL_STACK_TOP` on every switch. The boot stack is the
// idle task's. NMI, #DF, #MC and #DB keep their IST stacks.

/// Linux `struct pt_regs` (arch/x86/include/asm/ptrace.h, GPL-2.0), lowest
/// address first: the layout `syscall_entry` and the exception/interrupt
/// `entry!` stubs build and `iretq` consumes. It is the signal model's `Regs`
/// (one type): a handler entry or `rt_sigreturn` edits the live return frame.
pub use kernel::signal::Regs as PtRegs;
const _: () = assert!(core::mem::size_of::<PtRegs>() == 21 * 8);

/// Linux `MSR_SYSCALL_MASK` (arch/x86/kernel/cpu/common.c `syscall_init`):
/// CF PF AF ZF SF TF IF DF OF IOPL NT RF AC ID are cleared on SYSCALL.
const SYSCALL_MASK: u64 = 0x1
    | 0x4
    | 0x10
    | 0x40
    | 0x80
    | 0x100
    | 0x200
    | 0x400
    | 0x800
    | 0x3000
    | 0x4000
    | 0x1_0000
    | 0x4_0000
    | 0x20_0000;
const ENOSYS: i32 = 38;
const USER_CS_RAW: u16 = USER_CS.0;
const USER_DS_RAW: u16 = USER_DS.0;
// IA32_CSTAR: the target of SYSCALL from compatibility mode (AMD only).
const MSR_CSTAR: u32 = 0xc000_0083;
const MSR_SYSENTER_CS: u32 = 0x174;
const MSR_SYSENTER_ESP: u32 = 0x175;
const MSR_SYSENTER_EIP: u32 = 0x176;

/// Where `syscall_entry` switches to: the top of the running task's kernel
/// stack, the same value as `TSS.RSP0` (what the CPU loads on an exception or
/// interrupt from ring 3). Written only by [`set_kernel_stack`].
static KERNEL_STACK_TOP: AtomicU64 = AtomicU64::new(0);

/// Make `top` the kernel stack of the next ring-3 entry: `TSS.RSP0` for
/// exceptions and interrupts and `KERNEL_STACK_TOP` for `SYSCALL`
/// (`switch_to` -> `update_task_stack`, `arch/x86/include/asm/switch_to.h`).
///
/// Context: BSP, IF clear (a scheduler switch or boot), so no ring-3 entry can
/// observe the two halves of RSP0 torn; NMI/#DB/#DF/#MC use IST stacks, never
/// RSP0. `top` must be the 16-byte aligned top of a mapped kernel stack that
/// stays reserved while the task can enter ring 3.
pub fn set_kernel_stack(top: u64) {
    debug_assert!(top.is_multiple_of(16) && !interrupts_enabled());
    KERNEL_STACK_TOP.store(top, Ordering::Relaxed);
    // `privilege_stack_table[0]` is a u64 at offset 4 of the packed(4) TSS:
    // write its two halves as volatile aligned u32s (the CPU reads it).
    let tss = ptr::addr_of_mut!(TSS);
    // SAFETY: `TSS` is a permanent static, initialized by `install_gdt`; the
    // field is 4-aligned (packed(4)) and 24 bytes, so word 0 and 1 are in
    // bounds and aligned for u32; no reference to it exists (raw pointers only),
    // and the only other accessor is the CPU's RSP0 load, excluded by IF=0 above.
    unsafe {
        let rsp0 = ptr::addr_of_mut!((*tss).privilege_stack_table).cast::<u32>();
        ptr::write_volatile(rsp0, u32::try_from(top & 0xffff_ffff).unwrap_or(0));
        ptr::write_volatile(rsp0.add(1), u32::try_from(top >> 32).unwrap_or(0));
    }
}

/// Single-CPU scratch for the user RSP between SYSCALL and the stack switch.
/// shortcut: Linux keeps this per CPU behind SWAPGS; upgrade with SMP.
static mut USER_RSP: u64 = 0;

// 64-bit SYSCALL target (IA32_LSTAR).
//
// Why asm: SYSCALL leaves the user RSP live and changes no stack, so the stack
// switch and the register frame must be built before any Rust code can run.
// Prerequisites: EFER.SCE, STAR/LSTAR/SFMASK programmed by `enable_syscalls`;
// reached only from CPL3 (CPL0 never executes SYSCALL). On entry: CPL0,
// CS/SS = KERNEL_CS/DS from STAR, RCX = user RIP, R11 = user RFLAGS, RAX =
// number, RDI/RSI/RDX/R10/R8/R9 = arguments, RIP-relative static addressing,
// IF/DF/TF/AC/NT cleared by SFMASK so no maskable interrupt can intervene and
// DF=0 holds for the C ABI (NMI, #MC, #DF and #DB run on IST stacks and never
// touch the user RSP, so the window before the stack switch is safe). Registers: RSP is replaced by the
// running task's kernel stack top, `KERNEL_STACK_TOP` (16-aligned, a pool stack
// or the boot stack; written only by `set_kernel_stack` with IF=0, so no
// `schedule()` can run between SYSCALL and the load); 21 pushes build a Linux
// `pt_regs` (168 bytes), then `sub 8` makes RSP%16==0 at the CALL. RDI = &mut pt_regs (the number is
// `pt_regs.orig_ax`, truncated to `int` by the dispatcher); the C-ABI handler preserves RBX/RBP/R12-R15 and may write
// `pt_regs.ax`. Clobbers: all caller-saved registers (restored from pt_regs),
// flags (restored by IRETQ). Memory: writes the scratch slot and the kernel
// stack; the handler may access any memory, so no `nomem`. The return is
// IRETQ (through the shared `iret_site`) with the saved user RIP/CS/RFLAGS/RSP/SS,
// not SYSRET (shortcut: the SYSRET fast path needs canonical-RIP and RCX/R11
// checks). No red zone, no unwinding (the handler never unwinds; panic=abort).
// The user RSP may be non-canonical; IRETQ does not check it and a bad value
// faults in ring 3 (#SS on the first stack access).
// Not reentrant: nothing in ring 0 executes SYSCALL.
#[unsafe(naked)]
unsafe extern "C" fn syscall_entry() {
    naked_asm!(
        "mov [rip + {user_rsp}], rsp",
        "mov rsp, [rip + {stack_top}]",
        "push {ss}",
        "push qword ptr [rip + {user_rsp}]",
        "push r11",
        "push {cs}",
        "push rcx",
        "push rax",
        "push rdi", "push rsi", "push rdx", "push rcx",
        "push -{enosys}",
        "push r8", "push r9", "push r10", "push r11",
        "push rbx", "push rbp", "push r12", "push r13", "push r14", "push r15",
        "mov rdi, rsp",
        "sub rsp, 8",
        "call {handler}",
        "add rsp, 8",
        "jmp {restore}",
        user_rsp = sym USER_RSP,
        stack_top = sym KERNEL_STACK_TOP,
        ss = const USER_DS_RAW,
        cs = const USER_CS_RAW,
        enosys = const ENOSYS,
        handler = sym crate::userspace::syscall,
        restore = sym restore_regs_and_iret,
    );
}

// The shared tail of every return to ring 3 that is not an exception or
// interrupt stub: `syscall_entry` and the first run of a new task
// (`ret_from_fork_asm`). Linux's `swapgs_restore_regs_and_return_to_usermode`
// (arch/x86/entry/entry_64.S).
//
// Why asm: it must pop the whole `pt_regs` and end in `IRETQ`; no intrinsic
// restores 15 GPRs and then jumps. Why shared: one copy per entry path is one
// more place a register could be forgotten. Prerequisites: reached by `jmp`,
// never `call`ed, from CPL0 with IF=0, RSP = the base of a complete `pt_regs`
// (r15 lowest, `orig_ax` above the GPRs, then the five-word IRET frame) on the
// running task's kernel stack. Inputs/outputs: every GPR is loaded from
// `pt_regs`; no register is read. Clobbers: all, which is the point (flags come
// from the IRET frame). Memory: reads the frame, writes nothing; no red zone,
// no unwind (panic=abort). Control flow: `jmp` to the one `iret_site`, which
// `fixup_bad_iret` recognises by address; this function adds no second
// `iretq`. Privilege: CPL0 only.
#[unsafe(naked)]
unsafe extern "C" fn restore_regs_and_iret() -> ! {
    naked_asm!(
        "pop r15", "pop r14", "pop r13", "pop r12", "pop rbp", "pop rbx",
        "pop r11", "pop r10", "pop r9", "pop r8",
        "pop rax", "pop rcx", "pop rdx", "pop rsi", "pop rdi",
        "add rsp, 8",
        "jmp {iret}",
        iret = sym iret_site,
    );
}

// Linux `__switch_to_asm` (arch/x86/entry/entry_64.S:177-209): the register half
// of a context switch.
//
// Why asm: it exchanges RSP between two kernel stacks and resumes a frame
// that Rust did not call. Safe Rust cannot name RSP, and a normal `asm!` block
// may not change the stack pointer net, so no `asm!`/intrinsic form exists.
// Prerequisites: CPL0, IF=0, DF=0 (interrupt gates and SFMASK guarantee both),
// SysV C ABI call from `ktask::context_switch` with `prev_sp` a valid writable
// word (the previous task's `Thread::sp`) and `next_sp` a stack pointer that
// either an earlier `switch_to_asm` stored or `ktask::spawn` built as a
// `ForkFrame`, i.e. six callee-saved slots followed by a return address.
// Inputs: RDI = `prev_sp`, RSI = `next_sp`. Outputs: none; it returns when
// some later switch resumes this stack. Clobbers: the SysV caller-saved
// registers and flags are dead across the call by the C ABI; the callee-saved
// set RBP, RBX, R12-R15 is pushed here and popped from the next stack, so each
// task sees its own values come back. Memory: writes `*prev_sp` and the
// previous stack, reads the next stack; the call is opaque to the compiler
// (extern "C"), so all other memory is assumed changed. Stack: 6 pushes before
// the switch and 6 pops after, 8 bytes each, plus the `ret`; no red zone (the
// target disables it), no unwind (panic=abort). Control flow: `ret` goes to
// whatever return address the next stack holds. Privilege: CPL0 only. Not
// done, with the reason: Linux fills the return stack buffer here on CPUs
// affected by RSB underflow (`X86_FEATURE_RSB_CTXSW`) and the stack protector
// canary is not switched (the kernel is built without one);
// shortcut: no RSB fill, upgrade with the speculation-mitigation work.
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn switch_to_asm(_prev_sp: *mut u64, _next_sp: u64) {
    naked_asm!(
        "push rbp",
        "push rbx",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "mov [rdi], rsp",
        "mov rsp, rsi",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbx",
        "pop rbp",
        "ret",
    );
}

// Linux `ret_from_fork_asm` (arch/x86/entry/entry_64.S:228-260): the first
// instruction of every task. `switch_to_asm` `ret`s here on the first run of
// a task whose stack `ktask::spawn` filled with a `ForkFrame`.
//
// Why asm: a new task has no Rust caller frame to return into, so its first
// instruction must be reached by `ret` from a hand-built frame, and it must
// move the callee-saved register values that frame carried (RBX = thread
// function, R12 = its argument) into argument registers. Prerequisites: CPL0,
// IF=0, entered only by that `ret` with RSP = the base of the `pt_regs` the
// `ForkFrame` holds directly above the return slot, which is 8 mod 16 (the top
// of a pool stack is 16-aligned and `PtRegs` is 168 bytes) so that the `sub 8`
// below makes RSP 16-aligned at the CALL, the SysV rule. Inputs: RBX, R12
// (from the frame). Outputs: RDI = `&mut PtRegs`, RSI = thread function or 0,
// RDX = its argument; `ret_from_fork` is an `extern "C" fn` and never
// unwinds. Clobbers: all caller-saved registers (dead: nothing lives across the
// first instruction). Memory: only the stack (the CALL's return slot). Control
// flow: CALL `ret_from_fork` (a kernel thread never returns from it; a user
// task returns after its exit-to-user work), then `jmp` to the shared
// `restore_regs_and_iret`. No red zone, no unwind. Privilege: CPL0 only.
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn ret_from_fork_asm() {
    naked_asm!(
        "mov rdi, rsp",
        "mov rsi, rbx",
        "mov rdx, r12",
        "sub rsp, 8",
        "call {ret_from_fork}",
        "add rsp, 8",
        "jmp {restore}",
        ret_from_fork = sym crate::ktask::ret_from_fork,
        restore = sym restore_regs_and_iret,
    );
}

// IA32_CSTAR target: Linux `entry_SYSCALL32_ignore` (arch/x86/entry/entry_64_compat.S).
//
// Why asm: SYSRETL is the only way back to compatibility mode. Reached only
// by SYSCALL executed in compatibility mode on AMD CPUs (Intel raises #UD
// instead): RCX = next EIP, R11 = EFLAGS, user stack untouched. Sets EAX =
// -ENOSYS and returns with 32-bit SYSRET (CS = STAR[63:48] = USER32_CS, SS =
// +8, EIP = ECX, EFLAGS = R11; Intel-syntax `sysret` assembles to 0F 07
// without REX.W, i.e. SYSRETD). No memory, stack or unwind effects; flags
// are restored from R11. Without it CSTAR would be zero and a user could make
// ring 0 jump to address 0.
#[unsafe(naked)]
unsafe extern "C" fn syscall32_ignore() {
    naked_asm!("mov eax, -{enosys}", "sysret", enosys = const ENOSYS);
}

/// Program EFER.SCE, STAR, LSTAR, CSTAR, the SYSENTER MSRs and SFMASK as Linux's
/// `idt_syscall_init` does for a kernel without compat entry points.
///
/// # Errors
/// [`Error::Cpu`] when CPUID does not report SYSCALL/SYSRET.
///
/// # Safety
/// CPL0 on the BSP with IF clear, after `install_descriptors` (the GDT has
/// Linux's selector layout, pinned by the const assertions above, and TSS.RSP0
/// names the `BOOT_STACK` top). `syscall_entry` is only correct while no other
/// kernel code uses `USER_RSP` and while the CPU is on this single stack
/// discipline.
pub unsafe fn enable_syscalls() -> Result<(), Error> {
    if !CpuId::new()
        .get_extended_processor_and_feature_identifiers()
        .is_some_and(|features| features.has_syscall_sysret())
    {
        return Err(Error::Cpu);
    }
    // SAFETY: CPUID.80000001H:EDX.SYSCALL was checked; setting SCE only makes
    // SYSCALL/SYSRET legal and every other EFER bit is preserved by `update`.
    unsafe {
        Efer::update(|flags| *flags |= EferFlags::SYSTEM_CALL_EXTENSIONS);
    }
    // STAR: SYSCALL loads CS=KERNEL_CS, SS=KERNEL_CS+8 (KERNEL_DS); 64-bit
    // SYSRET (unused: we return by IRETQ) would load CS=USER32_CS+16, SS=+8.
    // `write` validates that the four selectors have exactly that relation.
    Star::write(USER_CS, USER_DS, KERNEL_CS, KERNEL_DS).map_err(|_| Error::Cpu)?;
    LStar::write(VirtAddr::new(syscall_entry as *const () as u64));
    let cpuid = CpuId::new();
    // Linux `wrmsrq_cstar`: Intel CPUs ignore 32-bit SYSCALL (it is #UD) and a
    // write is a #VE in a TDX guest, so only other vendors get the stub.
    let intel = cpuid
        .get_vendor_info()
        .is_some_and(|vendor| vendor.as_str() == "GenuineIntel");
    if !intel {
        // SAFETY: a non-Intel CPU with SYSCALL has IA32_CSTAR; the target is
        // the reviewed stub above.
        unsafe {
            Msr::new(MSR_CSTAR).write(syscall32_ignore as *const () as u64);
        }
    }
    // Linux `idt_syscall_init` (`ia32_enabled()` false branch): SYSENTER_CS/ESP/EIP
    // are zeroed, so SYSENTER from ring 3 raises #GP and never enters ring 0
    // at a stale target left by firmware or the loader.
    if cpuid
        .get_feature_info()
        .is_some_and(|features| features.has_sysenter_sysexit())
    {
        for msr in [MSR_SYSENTER_CS, MSR_SYSENTER_ESP, MSR_SYSENTER_EIP] {
            // SAFETY: CPUID.1:EDX.SEP reports these three MSRs; zero is the
            // architectural "disabled" value (a null CS selector).
            unsafe { Msr::new(msr).write(0) };
        }
    }
    SFMask::write(RFlags::from_bits_retain(SYSCALL_MASK));
    Ok(())
}

/// Result of [`enable_user_protection`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserProtection {
    pub smep: bool,
    pub smap: bool,
    pub umip: bool,
}

/// Enable CR4.SMEP and CR4.SMAP when CPUID.7.0:EBX reports them, and report
/// what CR4 actually holds afterwards.
///
/// SMAP needs no `STAC`/`CLAC`: the kernel reaches user memory only through the
/// direct-map alias of the frame (`usercopy`), never through a user virtual
/// address. shortcut: EFLAGS.AC is cleared by SFMASK for SYSCALL but not by
/// exception delivery; ring 3 may set AC, which only disarms SMAP for kernel
/// accesses to user pages, and there are none by construction. Add `CLAC` at
/// exception entry if a direct user-access path is ever introduced.
///
/// # Safety
/// CPL0 on the BSP before ring 3 runs. The kernel image and all kernel
/// mappings are supervisor pages, so no running kernel code is affected.
#[must_use]
pub unsafe fn enable_user_protection() -> UserProtection {
    let features = CpuId::new().get_extended_feature_info();
    let execute = features
        .as_ref()
        .is_some_and(raw_cpuid::ExtendedFeatures::has_smep);
    let access = features
        .as_ref()
        .is_some_and(raw_cpuid::ExtendedFeatures::has_smap);
    // Linux enables UMIP so ring 3 cannot read the IDT/GDT/TSS addresses with
    // SGDT/SIDT/STR/SMSW. shortcut: Linux then emulates SGDT/SIDT/SMSW with
    // dummy values (`fixup_umip_exception`); here those instructions kill init
    // with SIGSEGV. Upgrade with the emulation.
    let umip = features
        .as_ref()
        .is_some_and(raw_cpuid::ExtendedFeatures::has_umip);
    // SAFETY: each flag is set only if its CPUID bit is set, so no reserved bit
    // is written; other CR4 bits are preserved by `update`.
    unsafe {
        Cr4::update(|flags| {
            flags.set(Cr4Flags::SUPERVISOR_MODE_EXECUTION_PROTECTION, execute);
            flags.set(Cr4Flags::SUPERVISOR_MODE_ACCESS_PREVENTION, access);
            flags.set(Cr4Flags::USER_MODE_INSTRUCTION_PREVENTION, umip);
        });
    }
    let cr4 = Cr4::read();
    UserProtection {
        smep: cr4.contains(Cr4Flags::SUPERVISOR_MODE_EXECUTION_PROTECTION),
        smap: cr4.contains(Cr4Flags::SUPERVISOR_MODE_ACCESS_PREVENTION),
        umip: cr4.contains(Cr4Flags::USER_MODE_INSTRUCTION_PREVENTION),
    }
}

/// `nofsgsbase`: nothing in this kernel sets CR4.FSGSBASE, and `AT_HWCAP2 = 0`
/// (no `HWCAP2_FSGSBASE`) is only true while it stays clear.
#[must_use]
pub fn fsgsbase_enabled() -> bool {
    Cr4::read().contains(Cr4Flags::FSGSBASE)
}

/// Linux `x86_fsbase_read_cpu` without FSGSBASE: `rdmsr(MSR_FS_BASE)`. The
/// user's `%fs` base stays in the MSR while the kernel runs (nothing in the
/// kernel uses `%fs`), so no save/restore exists.
#[must_use]
pub fn user_fs_base() -> u64 {
    FsBase::read().as_u64()
}

/// `x86_gsbase_read_cpu_inactive`. Linux keeps the user's `%gs` base in
/// `MSR_KERNEL_GS_BASE` while it runs because it executes `SWAPGS` on entry;
/// this kernel never does (see `enter_user`), so the user's base is still the
/// live `MSR_GS_BASE`.
#[must_use]
pub fn user_gs_base() -> u64 {
    GsBase::read().as_u64()
}

/// `ARCH_SET_FS`: `loadseg(FS, 0)` then `x86_fsbase_write_cpu`. `base` is below
/// `TASK_SIZE_MAX` (checked by `arch_prctl`), hence canonical.
pub fn set_user_fs_base(base: u64) {
    let null = SegmentSelector::new(0, PrivilegeLevel::Ring0);
    // SAFETY: CPL0; the null selector is legal for FS in 64-bit mode and
    // `%fs` is not used by kernel code.
    unsafe { FS::set_reg(null) };
    FsBase::write(VirtAddr::new_truncate(base));
}

/// `ARCH_SET_GS`: `loadseg(GS, 0)` then the base write (see [`user_gs_base`]).
pub fn set_user_gs_base(base: u64) {
    let null = SegmentSelector::new(0, PrivilegeLevel::Ring0);
    // SAFETY: CPL0; the null selector is legal for GS in 64-bit mode and kernel
    // code never uses `%gs` (no per-CPU area is addressed through it).
    unsafe { GS::set_reg(null) };
    GsBase::write(VirtAddr::new_truncate(base));
}

/// The CPU's segment state at boot for a first user task (Linux's
/// `start_thread`): DS/ES/FS/GS null and FS/GS bases (and `KERNEL_GS_BASE`)
/// zero. No `SWAPGS` is ever executed by the kernel, so the user's GS base
/// lives in `MSR_GS_BASE` and `KERNEL_GS_BASE` stays zero. A task's own values
/// are applied at its switch-in ([`Segments::load`]); this sets the state the
/// boot context hands over, so the first switch-in finds nothing to reload.
///
/// # Safety
/// BSP at CPL0, before the first ring-3 task runs; no kernel code uses the
/// segment registers afterwards (64-bit mode ignores DS/ES, and the kernel uses
/// no `%fs`/`%gs`).
pub unsafe fn prepare_user_segments() {
    let null = SegmentSelector::new(0, PrivilegeLevel::Ring0);
    // SAFETY: CPL0. Null selectors are legal for DS/ES/FS/GS in 64-bit mode;
    // the caller guarantees no kernel code relies on their old values.
    unsafe {
        DS::set_reg(null);
        ES::set_reg(null);
        FS::set_reg(null);
        GS::set_reg(null);
    }
    FsBase::write(VirtAddr::zero());
    GsBase::write(VirtAddr::zero());
    KernelGsBase::write(VirtAddr::zero());
}

/// The per-task segment state a ring-3 task owns (`thread_struct`'s `ds`,
/// `es`, `fsindex`, `gsindex`, `fsbase`, `gsbase`; `arch/x86/kernel/process_64.c`
/// `save_fsgs` / `load_seg_legacy`). A switch-out [`save`](Segments::save)s the
/// running values and the next ring-3 task [`load`](Segments::load)s its own.
/// shortcut: both bases are always rewritten (`wrmsr`) instead of only when
/// they differ, which Linux does; upgrade with the FSGSBASE / cache work.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Segments {
    pub(crate) ds: u16,
    pub(crate) es: u16,
    pub(crate) fs: u16,
    pub(crate) gs: u16,
    pub(crate) fs_base: u64,
    pub(crate) gs_base: u64,
}

impl Segments {
    /// Read the running task's values. Context: CPL0.
    pub(crate) fn save() -> Self {
        Self {
            ds: DS::get_reg().0,
            es: ES::get_reg().0,
            fs: FS::get_reg().0,
            gs: GS::get_reg().0,
            fs_base: FsBase::read().as_u64(),
            gs_base: GsBase::read().as_u64(),
        }
    }

    /// Make these the running values. Loading a selector replaces the segment's
    /// hidden base, so a selector is reloaded only when it differs and the bases
    /// are written afterwards. Context: CPL0, IF=0.
    pub(crate) fn load(&self) {
        // SAFETY: CPL0. Each selector either is null or was read back from the
        // CPU by `save` (so it named a valid descriptor of the immutable GDT
        // when the CPU accepted it in ring 3) or is the initial null; loading
        // it again cannot fault. Kernel code uses none of these registers.
        unsafe {
            if DS::get_reg().0 != self.ds {
                DS::set_reg(SegmentSelector(self.ds));
            }
            if ES::get_reg().0 != self.es {
                ES::set_reg(SegmentSelector(self.es));
            }
            if FS::get_reg().0 != self.fs {
                FS::set_reg(SegmentSelector(self.fs));
            }
            if GS::get_reg().0 != self.gs {
                GS::set_reg(SegmentSelector(self.gs));
            }
        }
        FsBase::write(VirtAddr::new_truncate(self.fs_base));
        GsBase::write(VirtAddr::new_truncate(self.gs_base));
    }
}

/// Linux's initial FPU image for a new task (`fpstate_init_fxstate`, arch/x86/
/// kernel/fpu/core.c:536-540): FCW 0x37f, MXCSR 0x1f80 (`MXCSR_DEFAULT`),
/// everything else zero (x87 empty, XMM0-15 zero). FXSAVE layout: FCW at 0,
/// MXCSR at 24.
#[repr(C, align(16))]
#[derive(Clone)]
pub(crate) struct FxImage(pub(crate) [u8; 512]);

impl FxImage {
    pub(crate) const ZERO: Self = Self([0; 512]);

    /// The image of a new task.
    pub(crate) fn initial() -> Self {
        INIT_FXSTATE.clone()
    }
}

/// `switch_fpu_prepare`: save the running ring-3 task's x87/SSE state (live in
/// the registers, since the kernel is soft-float).
///
/// # Panics
/// Before `init_user_fpu`.
pub(crate) fn fpu_save(image: &mut FxImage) {
    assert!(
        FPU_READY.load(Ordering::Acquire),
        "FPU used before init_user_fpu"
    );
    // SAFETY: `FPU_READY` (CR4.OSFXSR=1, CR0.EM=TS=0, FXSR present); CPL0;
    // `image` is exclusively borrowed and 16-byte aligned.
    unsafe { save_fpu_state(image) };
}

/// `switch_fpu_finish`: make `image` the live state.
///
/// # Panics
/// Before `init_user_fpu`.
pub(crate) fn fpu_restore(image: &FxImage) {
    assert!(
        FPU_READY.load(Ordering::Acquire),
        "FPU used before init_user_fpu"
    );
    // SAFETY: as `fpu_save`; `image` holds a state `fpu_save` produced or the
    // initial state, so it has no reserved MXCSR bit.
    unsafe { restore_fpu_state(image) };
}
static INIT_FXSTATE: FxImage = {
    let mut bytes = [0u8; 512];
    bytes[0] = 0x7f;
    bytes[1] = 0x03;
    bytes[24] = 0x80;
    bytes[25] = 0x1f;
    FxImage(bytes)
};

/// `FXRSTOR` of [`INIT_FXSTATE`]. The only FP/SIMD instruction in the kernel:
/// the kernel itself stays soft-float, so user FP state is never touched by
/// ring 0 and needs no context switch while a single task runs.
///
/// # Safety
/// CPUID.1:EDX.FXSR, CR4.OSFXSR=1 and CR0.EM=0 (else #UD/#NM); CPL0.
#[target_feature(enable = "fxsr")]
unsafe fn load_initial_fpu_state() {
    // SAFETY: the image is 512 bytes, 16-byte aligned, immutable and valid
    // FXSAVE contents (no reserved MXCSR bits set); the caller gives the CPU
    // state FXRSTOR requires.
    unsafe { core::arch::x86_64::_fxrstor64(ptr::addr_of!(INIT_FXSTATE).cast()) };
}

/// Make x87/SSE usable from ring 3 the way Linux does with `noxsave`
/// (`fpu__init_cpu_generic`: CR4.OSFXSR|OSXMMEXCPT, CR0.TS=EM=0; arch/x86/
/// kernel/fpu/init.c) and give init Linux's initial FP state, so no firmware
/// or loader residue is visible to it. `#MF`/`#XM` then reach ring 3 as SIGFPE
/// through `exec::report`.
///
/// shortcut: one task and a soft-float kernel, so there is no FP context
/// switch, no lazy restore and no signal-frame FP state; upgrade with the
/// scheduler.
///
/// # Errors
/// [`Error::Cpu`] without FPU, FXSR, SSE and SSE2.
///
/// # Safety
/// CPL0 on the BSP, IF clear, before ring 3 runs.
pub unsafe fn init_user_fpu() -> Result<(), Error> {
    let supported = CpuId::new().get_feature_info().is_some_and(|features| {
        features.has_fpu()
            && features.has_fxsave_fxstor()
            && features.has_sse()
            && features.has_sse2()
    });
    if !supported {
        return Err(Error::Cpu);
    }
    // On AMD, EFER.FFXSR makes FXRSTOR at CPL0 skip the XMM registers, so
    // firmware XMM values would survive into ring 3: clear it first.
    // SAFETY: CPL0; `update` preserves every other EFER bit and FFXSR is
    // only an optimisation of FXSAVE/FXRSTOR.
    unsafe {
        Efer::update(|flags| flags.remove(EferFlags::FAST_FXSAVE_FXRSTOR));
    }
    // SAFETY: the CPUID bits above were checked; OSFXSR/OSXMMEXCPT are
    // reserved-free CR4 bits when FXSR/SSE exist; other bits are preserved.
    unsafe {
        Cr4::update(|flags| {
            flags.insert(Cr4Flags::OSFXSR | Cr4Flags::OSXMMEXCPT_ENABLE);
        });
        // MP and NE (native x87 error reporting, `#MF`) as Linux's CR0 state;
        // EM and TS cleared so ring 3 never takes `#NM`.
        Cr0::update(|flags| {
            flags.remove(Cr0Flags::EMULATE_COPROCESSOR | Cr0Flags::TASK_SWITCHED);
            flags.insert(Cr0Flags::MONITOR_COPROCESSOR | Cr0Flags::NUMERIC_ERROR);
        });
        // SAFETY: OSFXSR set, EM clear, FXSR checked.
        load_initial_fpu_state();
    }
    // Linux `fpu__init_system_mxcsr`: the MXCSR bits this CPU accepts come from
    // an FXSAVE image's MXCSR_MASK field (0 means the architectural 0xffbf).
    let mut image = FxImage([0; 512]);
    // SAFETY: the state FXSAVE needs was just established above.
    unsafe { save_fpu_state(&mut image) };
    let mask = u32::from_le_bytes([image.0[28], image.0[29], image.0[30], image.0[31]]);
    MXCSR_MASK.store(if mask == 0 { 0xffbf } else { mask }, Ordering::Relaxed);
    FPU_READY.store(true, Ordering::Release);
    Ok(())
}

/// `mxcsr_feature_mask`, valid once [`FPU_READY`].
static MXCSR_MASK: AtomicU32 = AtomicU32::new(0xffbf);
/// `init_user_fpu` ran: CR4.OSFXSR=1, CR0.EM=0, CR0.TS=0, FXSR/SSE present, so
/// FXSAVE/FXRSTOR cannot fault on their feature or CR bits.
static FPU_READY: AtomicBool = AtomicBool::new(false);

/// `FXSAVE64` of the live x87/XMM state.
///
/// # Safety
/// `FPU_READY` (CPUID FXSR, CR4.OSFXSR=1, CR0.EM=0 and TS=0); CPL0.
#[target_feature(enable = "fxsr")]
unsafe fn save_fpu_state(image: &mut FxImage) {
    // SAFETY: `image` is 512 bytes, 16-byte aligned (`FxImage`) and exclusively
    // borrowed, so FXSAVE's 512-byte store stays inside it; the caller gives
    // the CPU state FXSAVE requires. 64-bit form, as Linux (`fxsaveq`).
    unsafe { core::arch::x86_64::_fxsave64(image.0.as_mut_ptr()) };
}

/// `FXRSTOR64` of `image`.
///
/// # Safety
/// As [`save_fpu_state`], and `image` holds no reserved MXCSR bit (else #GP).
#[target_feature(enable = "fxsr")]
unsafe fn restore_fpu_state(image: &FxImage) {
    // SAFETY: 512 readable, 16-byte aligned bytes; the MXCSR condition is the
    // caller's contract.
    unsafe { core::arch::x86_64::_fxrstor64(image.0.as_ptr()) };
}

/// The CPU facts the signal model needs ([`kernel::signal::Cpu`]): the user FPU
/// state (which is live in the registers whenever the kernel runs, because the
/// kernel is soft-float) and the segment test of `force_valid_ss`.
pub struct UserCpu(());

impl UserCpu {
    /// # Panics
    /// Before `init_user_fpu` (a kernel bug: ring 3 cannot run yet).
    #[must_use]
    pub fn new() -> Self {
        assert!(
            FPU_READY.load(Ordering::Acquire),
            "user FPU used before init_user_fpu"
        );
        Self(())
    }
}

impl kernel::signal::Cpu for UserCpu {
    fn fxsave(&mut self) -> [u8; 512] {
        let mut image = FxImage([0; 512]);
        // SAFETY: `UserCpu::new` checked `FPU_READY`; CPL0 (kernel code).
        unsafe { save_fpu_state(&mut image) };
        image.0
    }

    fn mxcsr_mask(&self) -> u32 {
        MXCSR_MASK.load(Ordering::Relaxed)
    }

    fn fxrstor(&mut self, image: &[u8; 512]) {
        let aligned = FxImage(*image);
        let mxcsr = u32::from_le_bytes([image[24], image[25], image[26], image[27]]);
        if mxcsr & !self.mxcsr_mask() != 0 {
            // The caller validated this; a reserved bit would be a #GP in ring
            // 0, so fail safe to the init state instead.
            self.fpu_reset();
            return;
        }
        // SAFETY: `FPU_READY` as above; the reserved-MXCSR condition was just
        // checked; `aligned` is a 16-byte aligned 512-byte copy.
        unsafe { restore_fpu_state(&aligned) };
    }

    fn fpu_reset(&mut self) {
        // SAFETY: `FPU_READY` as above, CPL0; the image is the immutable Linux
        // initial state.
        unsafe { load_initial_fpu_state() };
    }

    // `force_valid_ss`'s `lar` (arch/x86/kernel/signal_64.c:28-48).
    //
    // Why asm: LAR (load access rights) has no Rust intrinsic and the x86_64
    // crate has no wrapper; reading the GDT descriptor by hand would reimplement
    // the hardware's selector walk (TI bit, LDT, limits, DPL/RPL rules) and
    // could disagree with it. Prerequisites: none beyond long mode; LAR with a
    // register operand takes no fault for any 16-bit value (a null, out of
    // range, LDT or system selector just clears ZF). Inputs: the selector in a
    // 16-bit register. Outputs: the access-rights dword in a 32-bit register,
    // preset to 0 and left untouched when LAR fails, so a failure reads as
    // rights 0 (Linux zeroes it explicitly). Clobbers: ZF (flags are not
    // declared preserved); no other register. Memory: none read or written
    // (`nomem`), no stack (`nostack`), no red zone, no side effect on any
    // descriptor. Privilege/context: any CPL, IF and preemption irrelevant. No
    // control flow, no unwind.
    fn ss_is_valid_user_data(&self, ss: u16) -> bool {
        // AR_DPL_MASK | AR_S | AR_P | AR_TYPE_MASK (the accessed bit 8 is not in
        // the mask): DPL 3, S, P and type read-write data or its expand-down form.
        const MASK: u32 = (3 << 13) | (1 << 12) | (1 << 15) | (7 << 9);
        const DPL3_S_P: u32 = (3 << 13) | (1 << 12) | (1 << 15);
        let mut rights: u32 = 0;
        // SAFETY: the instruction only reads the descriptor table entry the
        // selector names (architecturally, not through Rust memory) and writes
        // the register operand and ZF, as described above.
        unsafe {
            asm!(
                "lar {rights:e}, {selector:x}",
                rights = inout(reg) rights,
                selector = in(reg) ss,
                options(nomem, nostack),
            );
        }
        matches!(rights & MASK, v if v == DPL3_S_P | (1 << 9) || v == DPL3_S_P | (3 << 9))
    }
}

/// Linux `initialize_debug_regs`: no stale hardware breakpoint from the
/// loader/firmware can fire in ring 0 or in ring 3.
///
/// # Safety
/// CPL0 on the BSP, IF clear.
pub unsafe fn scrub_debug_registers() {
    Dr7::write_raw(0);
    Dr0::write(0);
    Dr1::write(0);
    Dr2::write(0);
    Dr3::write(0);
    // Linux `DR6_RESERVED`: the architectural reset value, with no stale
    // status bits (BS, B0-B3...) left by firmware or the loader. The crate has
    // no DR6 writer, and there is no intrinsic for `mov dr6`: one `asm!` site,
    // CPL0 only, a single register input, no memory, stack or flags effect.
    // SAFETY: CPL0; DR7 was cleared above, so no breakpoint is armed.
    unsafe { reset_dr6() };
}

/// `set_debugreg(DR6_RESERVED, 6)`: the architectural reset value, no stale
/// status bit. The crate has no DR6 writer and there is no intrinsic for
/// `mov dr6`: one `asm!` site, CPL0 only, a single register input, no memory,
/// stack or flags effect.
///
/// # Safety
/// CPL0.
unsafe fn reset_dr6() {
    // SAFETY: CPL0; writing DR6 changes no execution state (hardware only ORs
    // status bits into it) and the value is the reserved-bit pattern.
    unsafe {
        asm!("mov dr6, {}", in(reg) DR6_RESET, options(nomem, nostack, preserves_flags));
    }
}

/// `debug_read_clear_dr6`: the conditions of the `#DB` just taken (active-high,
/// the reserved bits flipped off) and DR6 back to its reset value, so the next
/// `#DB` reports only itself.
pub fn take_dr6() -> u64 {
    let raw = Dr6::read_raw();
    // SAFETY: the only callers run in the `#DB` handler at CPL0.
    unsafe { reset_dr6() };
    raw ^ DR6_RESET
}

/// `fpu__exception_code` for `#MF` (vector 16) / `#XM` (19): the `si_code` from
/// the live FPU state, 0 for a spurious exception.
pub fn fpu_exception_code(vector: u8) -> i32 {
    use kernel::signal::Cpu;
    let image = UserCpu::new().fxsave();
    let word = |at: usize| u16::from_le_bytes([image[at], image[at + 1]]);
    let mxcsr = u32::from_le_bytes([image[24], image[25], image[26], image[27]]);
    kernel::signal::info::fpu_exception_code(vector, word(0), word(2), mxcsr)
}

const DR6_RESET: u64 = 0xffff_0ff0;
