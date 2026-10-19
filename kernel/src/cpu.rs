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
    sync::atomic::{AtomicU64, Ordering, compiler_fence},
};
use kernel::sync::{RawSpinGuard, RawSpinLock};
use raw_cpuid::CpuId;
use x86_64::{
    PhysAddr, PrivilegeLevel, VirtAddr,
    instructions::{
        interrupts,
        segmentation::{CS, DS, ES, FS, GS, SS, Segment},
        tables::{DescriptorTablePointer, lidt, load_tss},
    },
    registers::{
        control::{Cr0, Cr0Flags, Cr2, Cr3, Cr4, Cr4Flags},
        debug::{DebugAddressRegister, Dr0, Dr1, Dr2, Dr3, Dr7},
        model_specific::{
            ApicBase, ApicBaseFlags, Efer, EferFlags, FsBase, GsBase, KernelGsBase, LStar, Msr,
            SFMask, Star,
        },
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
        reason = "This constant initializes only the four permanent BSS stacks below; ELF/disassembly inspection checks that no runtime stack temporary or copy exists."
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
    Apic,
    TimerCounter,
    TimerStalled,
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
static IRQ_NESTING: AtomicU64 = AtomicU64::new(0);

fn interrupts_enabled() -> bool {
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

/// The only blocking lock currently reachable here protects PIC programming
/// and PIT latch/low/high transactions. The IRQ EOI path never blocks on it;
/// NMI/fault/emergency output never acquires it. No callbacks or allocation.
struct IrqSpinLock(RawSpinLock);

impl IrqSpinLock {
    const fn new() -> Self {
        Self(RawSpinLock::new())
    }

    fn lock(&self) -> IrqSpinGuard<'_> {
        let irq = LocalInterruptGuard::disable();
        IrqSpinGuard {
            raw: self.0.lock(),
            irq,
        }
    }

    fn try_lock(&self) -> Option<IrqSpinGuard<'_>> {
        let irq = LocalInterruptGuard::disable();
        Some(IrqSpinGuard {
            raw: self.0.try_lock()?,
            irq,
        })
    }
}

struct IrqSpinGuard<'a> {
    // Rust drops fields in declaration order: unlock BEFORE restoring IF.
    // The real IRQ probe below attempts this same lock on the first pending IRQ.
    raw: RawSpinGuard<'a>,
    irq: LocalInterruptGuard,
}

static LEGACY_TIMER: IrqSpinLock = IrqSpinLock::new();
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
    // SAFETY: controlled virtual device, CPL0, scalar EAX/DX, no stack/flags
    // effects; omit nomem for device ordering. OUT has no supported intrinsic.
    unsafe {
        asm!("out dx, eax", in("dx") 0xf4u16, in("eax") if success { 0x10u32 } else { 0x11u32 }, options(nostack, preserves_flags));
    }
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

fn out_byte(port: u16, value: u8) {
    // SAFETY: all callers name owned early PC devices in an explicitly validated
    // legacy-PIC configuration, or feature-gated emulated UART. No general port
    // API is exported. OUT only uses AL/DX, preserves flags/stack; memory barrier
    // prevents compiler reordering across device configuration and acknowledgment.
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nostack, preserves_flags));
    }
}
fn in_byte(port: u16) -> u8 {
    let value: u8;
    // SAFETY: same device ownership as out_byte; IN returns initialized scalar.
    unsafe {
        asm!("in al, dx", in("dx") port, out("al") value, options(nostack, preserves_flags));
    }
    value
}
fn io_wait() {
    out_byte(0x80, 0);
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
            None if index == 32 => timer_entry as *const (),
            None => unexpected_entry as *const (),
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

// Non-error entries use the qualified compiler interrupt ABI. Its error-code
// entries misalign ordinary calls (retained integrated-007 fatal-PF witness).
// The error arm therefore supplies only the unavoidable hardware entry boundary:
// IA-32e aligns RSP16 before five frame words plus an error word, so entry RSP%16
// is zero. Save nine SysV caller-clobbered GPRs and eight padding bytes: CALL is
// aligned16, error is at +80 and the five-word frame at +88. Ordinary C-ABI Rust
// preserves RBX/RBP/R12-R15; all fifteen are exercised across a returning PF.
// No FP/SIMD, allocation, unwind or privilege transition is allowed. CLD clears
// live DF; IRETQ restores saved flags/stack after the hardware error is removed.
// Rust/intrinsics cannot express this entry/IRET boundary. Do not normalize an
// already misaligned ordinary Rust call or rely on forced inlining instead.
macro_rules! entry {
    ($name:ident, $vector:expr) => {
        extern "x86-interrupt" fn $name(mut frame: InterruptFrame) {
            interrupt_handler(&mut frame, $vector, 0);
        }
    };
    ($name:ident, $vector:expr, error) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $name() {
            naked_asm!(
                "push rax", "push rcx", "push rdx", "push rsi", "push rdi",
                "push r8", "push r9", "push r10", "push r11", "sub rsp, 8",
                "cld", "lea rdi, [rsp + 88]", "mov esi, {vector}",
                "mov rdx, [rsp + 80]", "call {handler}",
                "add rsp, 8", "pop r11", "pop r10", "pop r9", "pop r8",
                "pop rdi", "pop rsi", "pop rdx", "pop rcx", "pop rax",
                "add rsp, 8", "iretq",
                vector = const $vector,
                handler = sym interrupt_handler,
            );
        }
    };
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
entry!(timer_entry, 32);
// The CPU does not push the vector number. Unassigned external slots share one
// compiler entry; its private sentinel is NEVER reported as a real vector.
const UNKNOWN_EXTERNAL_VECTOR: u64 = 256;
entry!(unexpected_entry, UNKNOWN_EXTERNAL_VECTOR);

#[repr(C)]
struct InterruptFrame {
    rip: u64,
    cs: u64,
    flags: u64,
    rsp: u64,
    ss: u64,
}
static TICKS: AtomicU64 = AtomicU64::new(0);
static BREAKPOINTS: AtomicU64 = AtomicU64::new(0);
static BREAKPOINT_ARMED: AtomicU64 = AtomicU64::new(0);
static FAULTS: AtomicU64 = AtomicU64::new(0);
static FAULT_ADDRESS: AtomicU64 = AtomicU64::new(0);
static FAULT_RIP: AtomicU64 = AtomicU64::new(0);
static FAULT_ERROR: AtomicU64 = AtomicU64::new(0);
static FAULT_ARMED: AtomicU64 = AtomicU64::new(0);

extern "C" fn interrupt_handler(frame: &mut InterruptFrame, vector: u64, error: u64) {
    // Any ring-3 CS (64-bit 0x33 or compatibility 0x23, RPL 3).
    if frame.cs & 3 == 3 {
        // Any exception raised by init is fatal to it (no signal handlers exist
        // yet). CR2 is read first, before anything that could fault.
        let address = if vector == 14 { Cr2::read_raw() } else { 0 };
        crate::userspace::exception(vector, error, frame.rip, frame.rsp, address);
    }
    if frame.cs != u64::from(KERNEL_CS.0) {
        unexpected(frame, vector, error, 0);
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
                && frame.rip == FAULT_RIP.load(Ordering::Relaxed)
                && error == FAULT_ERROR.load(Ordering::Relaxed)
            {
                // SAFETY: the entry boundary supplies the immovable live CPU
                // frame. Volatile commits recovery to that hardware frame, not
                // a compiler-local by-value copy; only RIP changes to the exact
                // reviewed recovery RET, preserving the saved CPL/flags/stack.
                unsafe {
                    ptr::write_volatile(
                        ptr::addr_of_mut!(frame.rip),
                        probe_return as *const () as u64,
                    );
                }
                FAULTS.fetch_add(1, Ordering::Relaxed);
            } else {
                unexpected(frame, vector, error, address);
            }
        }
        32 => {
            TICKS.fetch_add(1, Ordering::Relaxed);
            out_byte(0x20, 0x20);
            if IRQ_LOCK_PROBE.load(Ordering::Acquire) == IRQ_LOCK_ARMED {
                let result = if LEGACY_TIMER.try_lock().is_some() {
                    IRQ_LOCK_PASSED
                } else {
                    IRQ_LOCK_FAILED
                };
                IRQ_LOCK_PROBE.store(result, Ordering::Release);
            }
        }
        _ => unexpected(frame, vector, error, 0),
    }
}
#[cfg(feature = "qemu-self-test")]
#[unsafe(naked)]
unsafe extern "C" fn ordinary_call_stack_residue() -> u64 {
    // Observe the actual ordinary SysV callee-entry stack before any prologue.
    // Rust/intrinsics cannot expose that point. CALL/RET own one stack word;
    // RAX and arithmetic flags are caller-clobbered, memory is not accessed.
    // This witness never realigns or repairs its caller's stack.
    naked_asm!("mov rax, rsp", "and eax, 15", "ret");
}

fn unexpected(frame: &InterruptFrame, vector: u64, error: u64, address: u64) -> ! {
    #[cfg(feature = "qemu-self-test")]
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
    if vector == UNKNOWN_EXTERNAL_VECTOR {
        crate::log!(
            "FAIL trap vector=unknown-external error={:#x} rip={:#x} rsp={:#x}\n",
            error,
            frame.rip,
            frame.rsp
        );
        crate::fail();
    }
    crate::log!(
        "FAIL trap vector={} error={:#x} rip={:#x} cr2={:#x} rsp={:#x}\n",
        vector,
        error,
        frame.rip,
        address,
        frame.rsp
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
    let before = ticks();
    // SAFETY: only called after PIT/PIC/IDT initialization, on BSP with IF=0.
    let preserved = unsafe { irq_register_probe() };
    preserved == 1 && ticks() > before
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

pub fn start_timer(legacy_pic: bool) -> Result<(), Error> {
    // Initialization remains BSP-only before AP release. This lock also makes
    // the port transaction indivisible with respect to later counter readers.
    let _owner = LEGACY_TIMER.lock();
    if !legacy_pic {
        return Err(Error::Cpu);
    }
    // IA32_APIC_BASE only exists when CPUID reports a local APIC.
    if CpuId::new()
        .get_feature_info()
        .is_some_and(|features| features.has_apic())
    {
        let mut msr = ApicBase::MSR;
        // SAFETY: CPL0 BSP; the MSR exists per the CPUID check above.
        let apic = unsafe { msr.read() };
        if apic & ApicBaseFlags::X2APIC_ENABLE.bits() != 0 {
            return Err(Error::Apic);
        }
        // Disable the local APIC for this explicit legacy-PIC UP test cell.
        // This is not APIC initialization or a permanent Linux policy choice.
        // SAFETY: only the enable bit changes; every other bit (including the
        // base address and reserved bits) is written back as read.
        unsafe { msr.write(apic & !ApicBaseFlags::LAPIC_ENABLE.bits()) };
    }
    out_byte(0x20, 0x11);
    io_wait();
    out_byte(0xa0, 0x11);
    io_wait();
    out_byte(0x21, 0x20);
    io_wait();
    out_byte(0xa1, 0x28);
    io_wait();
    out_byte(0x21, 4);
    io_wait();
    out_byte(0xa1, 2);
    io_wait();
    out_byte(0x21, 1);
    io_wait();
    out_byte(0xa1, 1);
    io_wait();
    out_byte(0x21, 0xfe);
    out_byte(0xa1, 0xff);
    // 8254 input 1,193,182Hz, mode2, divisor11932 (~100Hz), channel0 only.
    out_byte(0x43, 0x34);
    out_byte(0x40, 0x9c);
    out_byte(0x40, 0x2e);
    Ok(())
}
pub fn ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}
pub fn wait_tick() {
    // SAFETY: fully installed descriptors and armed PIT/PIC; BSP executes alone,
    // STI's one-instruction inhibition makes HLT race-free with pending IRQ;
    // handler preserves every scalar register. CLI restores early context.
    // HLT/IF control cannot be expressed with normal Rust/intrinsics. No unwind.
    unsafe {
        asm!("sti", "hlt", "cli");
    }
}
pub fn mask_timer() {
    let _owner = LEGACY_TIMER.lock();
    out_byte(0x21, 0xff);
}

pub struct TimerObservation {
    pub wraps: u8,
    pub irq_delta: u64,
}

fn pit_counter_locked(_owner: &RawSpinGuard<'_>) -> u16 {
    // One owner latches channel0 then consumes low/high once. IRQ EOI accesses
    // only PIC command20; NMI/fault handlers never access PIT or this lock.
    out_byte(0x43, 0);
    u16::from_le_bytes([in_byte(0x40), in_byte(0x40)])
}

fn pit_counter() -> u16 {
    pit_counter_locked(&LEGACY_TIMER.lock().raw)
}

/// Observe >=2 actual mode2 down-counter reloads while IF=1. The finite polling
/// bound is a failure limit, NOT a calibrated CPU delay or elapsed-time oracle.
/// Caller initialized PIT/PIC/IDT; return always restores IF=0.
pub fn observe_timer_periods() -> Result<TimerObservation, Error> {
    // SAFETY: installed IDT and owned initialized PIT/PIC, one BSP, bounded
    // non-sleeping sampling; compiler boundary permits all IRQ memory effects.
    unsafe {
        asm!("sti", options(nostack));
    }
    let observation = poll_timer_periods(pit_counter);
    interrupts_off();
    observation
}

fn poll_timer_periods(mut counter: impl FnMut() -> u16) -> Result<TimerObservation, Error> {
    let before = ticks();
    let mut previous = counter();
    let mut wraps = 0u8;
    let mut invalid_counter = previous > 11932;
    for _ in 0..2_000_000 {
        let current = counter();
        if current > 11932 {
            invalid_counter = true;
            break;
        }
        if current > previous {
            wraps += 1;
            if wraps == 2 {
                break;
            }
        }
        previous = current;
    }
    if invalid_counter {
        return Err(Error::TimerCounter);
    }
    if wraps < 2 {
        return Err(Error::TimerStalled);
    }
    Ok(TimerObservation {
        wraps,
        irq_delta: ticks() - before,
    })
}

/// Execute nested saved-IF and lock/IRQ ownership checks against the real PIT.
/// Called on the BSP after timer setup, before any AP or scheduler execution.
/// Every returning path has IF=0; no emulator delay substitutes for PIT wraps.
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
    // SAFETY: the caller initialized descriptors and PIC/PIT. No lock is held,
    // no AP runs, and the bounded inner test never schedules or allocates.
    unsafe {
        asm!("sti", options(nostack));
    }
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
    let owner = LEGACY_TIMER.lock();
    if interrupts_enabled() || LEGACY_TIMER.try_lock().is_some() || interrupts_enabled() {
        return Err(Error::InterruptGuard);
    }
    let blocked = poll_timer_periods(|| pit_counter_locked(&owner.raw))?;
    if blocked.wraps != 2 || blocked.irq_delta != 0 {
        return Err(Error::InterruptGuard);
    }
    IRQ_LOCK_PROBE.store(IRQ_LOCK_ARMED, Ordering::Release);
    let resumed = if restore_early {
        // QEMU-only mutation selected by main: really restore IF while retaining
        // the raw lock, then observe actual IRQs over two PIT wraps. The IRQ
        // handler must fail its nonblocking acquisition, never deadlock.
        let IrqSpinGuard { raw, irq } = owner;
        drop(irq);
        let observation = poll_timer_periods(|| pit_counter_locked(&raw));
        drop(raw);
        observation?
    } else {
        // Correct field destruction publishes unlock before restoring IF.
        drop(owner);
        if !interrupts_enabled() {
            return Err(Error::InterruptGuard);
        }
        poll_timer_periods(pit_counter)?
    };
    let acquired = IRQ_LOCK_PROBE.load(Ordering::Acquire) == IRQ_LOCK_PASSED;
    crate::log!(
        "IRQ restore observation pit_wraps={} irq_delta={} lock_acquired={}\n",
        resumed.wraps,
        resumed.irq_delta,
        acquired
    );
    if resumed.wraps != 2 || resumed.irq_delta == 0 || !acquired {
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
// SYSCALL) run on the top of BOOT_STACK, which is also TSS.RSP0. kernel_main's
// frame is abandoned by `enter_user` (it never returns) and everything the
// syscall/fault paths use lives in statics, so reusing that stack is sound; it
// keeps its 4 KiB unmapped guard page, and the deepest path (a 2 KiB tty chunk
// plus formatting) is far below its 64 KiB. NMI, #DF and #MC keep their IST
// stacks.

/// Linux `struct pt_regs` (arch/x86/include/asm/ptrace.h, GPL-2.0), lowest
/// address first: the layout `syscall_entry` builds and `iretq` consumes.
#[repr(C)]
pub struct PtRegs {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub bp: u64,
    pub bx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub ax: u64,
    pub cx: u64,
    pub dx: u64,
    pub si: u64,
    pub di: u64,
    pub orig_ax: u64,
    pub ip: u64,
    pub cs: u64,
    pub flags: u64,
    pub sp: u64,
    pub ss: u64,
}
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
// touch the user RSP, so the window before the stack switch is safe). Registers: RSP is replaced by the BOOT_STACK top
// (16-aligned); 21 pushes build a Linux `pt_regs` (168 bytes), then `sub 8`
// makes RSP%16==0 at the CALL. RDI = &mut pt_regs (the number is
// `pt_regs.orig_ax`, truncated to `int` by the dispatcher); the C-ABI handler preserves RBX/RBP/R12-R15 and may write
// `pt_regs.ax`. Clobbers: all caller-saved registers (restored from pt_regs),
// flags (restored by IRETQ). Memory: writes the scratch slot and the kernel
// stack; the handler may access any memory, so no `nomem`. The return is
// IRETQ with the saved user RIP/CS/RFLAGS/RSP/SS, not SYSRET (shortcut: the
// SYSRET fast path needs canonical-RIP and RCX/R11 checks). No red zone, no
// unwinding (the handler never unwinds; panic=abort). The user RSP may be
// non-canonical; IRETQ does not check it and a bad value faults in ring 3.
// Not reentrant: nothing in ring 0 executes SYSCALL.
#[unsafe(naked)]
unsafe extern "C" fn syscall_entry() {
    naked_asm!(
        "mov [rip + {user_rsp}], rsp",
        "lea rsp, [rip + {stack} + {size}]",
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
        "pop r15", "pop r14", "pop r13", "pop r12", "pop rbp", "pop rbx",
        "pop r11", "pop r10", "pop r9", "pop r8",
        "pop rax", "pop rcx", "pop rdx", "pop rsi", "pop rdi",
        "add rsp, 8",
        "iretq",
        user_rsp = sym USER_RSP,
        stack = sym BOOT_STACK,
        size = const core::mem::size_of::<Stack>(),
        ss = const USER_DS_RAW,
        cs = const USER_CS_RAW,
        enosys = const ENOSYS,
        handler = sym crate::userspace::syscall,
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
    // Linux `idt_syscall_init` (IA32_EMULATION=n branch): SYSENTER_CS/ESP/EIP
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

/// Linux `start_thread` for a new 64-bit task, then IRETQ to ring 3.
///
/// # Safety
/// BSP at CPL0; `install_descriptors` and `enable_syscalls` done; the active
/// tree maps `rip` executable and `sp` writable for the user; no Rust object
/// in the current stack frame is used afterwards (the frame is abandoned);
/// everything the syscall/fault paths need is in statics.
pub unsafe fn enter_user(rip: u64, sp: u64) -> ! {
    let null = SegmentSelector::new(0, PrivilegeLevel::Ring0);
    // SAFETY: CPL0. Null selectors are legal for DS/ES/FS/GS in 64-bit mode;
    // zero bases make user FS/GS start at 0 as in Linux (no SWAPGS is ever
    // executed by the kernel, so KERNEL_GS_BASE is just zeroed as well).
    unsafe {
        DS::set_reg(null);
        ES::set_reg(null);
        FS::set_reg(null);
        GS::set_reg(null);
    }
    FsBase::write(VirtAddr::zero());
    GsBase::write(VirtAddr::zero());
    KernelGsBase::write(VirtAddr::zero());
    // SAFETY: forwarded contract.
    unsafe { iret_to_user(rip, sp) }
}

// Why asm: IRETQ is the only way to enter CPL3 with an exact RIP/RSP/CS/SS/
// RFLAGS and all GPRs known. Inputs: RDI = user RIP, RSI = user RSP (both
// validated by the caller as mapped user addresses). Prerequisites: CPL0,
// TSS.RSP0 valid for the next ring-3 event, GDT with USER_CS/USER_DS.
// Effects: CLI first (IF is restored from the pushed RFLAGS = 0x202: IF set,
// IOPL 0, TF/NT/RF/AC/VM clear, bit 1 fixed); pushes the five-word frame on
// the current stack (consumed by IRETQ, never unwound; the stack is abandoned
// afterwards); zeroes every GPR like Linux's `elf_common_init`; clobbers all
// registers and flags; does not return. Memory: only the stack pushes; no
// `nomem` claim needed because the function never returns to Rust.
#[unsafe(naked)]
unsafe extern "C" fn iret_to_user(rip: u64, sp: u64) -> ! {
    naked_asm!(
        "cli",
        "push {ss}",
        "push rsi",
        "push 0x202",
        "push {cs}",
        "push rdi",
        "xor eax, eax", "xor ebx, ebx", "xor ecx, ecx", "xor edx, edx",
        "xor esi, esi", "xor edi, edi", "xor ebp, ebp",
        "xor r8d, r8d", "xor r9d, r9d", "xor r10d, r10d", "xor r11d, r11d",
        "xor r12d, r12d", "xor r13d, r13d", "xor r14d, r14d", "xor r15d, r15d",
        "iretq",
        ss = const USER_DS_RAW,
        cs = const USER_CS_RAW,
    );
}

/// Linux's initial FPU image for a new task (`fpstate_init_fxstate`, arch/x86/
/// kernel/fpu/core.c:536-540): FCW 0x37f, MXCSR 0x1f80 (`MXCSR_DEFAULT`),
/// everything else zero (x87 empty, XMM0-15 zero). FXSAVE layout: FCW at 0,
/// MXCSR at 24.
#[repr(C, align(16))]
struct FxImage([u8; 512]);
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
    Ok(())
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
}
