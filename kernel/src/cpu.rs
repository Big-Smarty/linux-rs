// SPDX-License-Identifier: GPL-2.0-only
//! `x86_64` CPL0 boundaries. See docs/implementation.md for the operation proof
//! matrix. No ordinary kernel code uses FP/SIMD; no entry may unwind.
// Local IRQ save/restore and raw-lock ordering translated from Linux 6.18.57
// arch/x86/include/asm/irqflags.h and include/linux/spinlock_api_smp.h (GPL-2.0).
// This implements neither paravirt alternatives nor scheduler/RT lock policy.
use core::{
    arch::{asm, naked_asm, x86_64::__cpuid},
    marker::PhantomData,
    ptr,
    sync::atomic::{AtomicU64, Ordering, compiler_fence},
};
use kernel::sync::{RawSpinGuard, RawSpinLock};

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

pub fn guards() -> [u64; 4] {
    [
        ptr::addr_of!(BOOT_STACK) as u64,
        ptr::addr_of!(DOUBLE_STACK) as u64,
        ptr::addr_of!(NMI_STACK) as u64,
        ptr::addr_of!(MACHINE_STACK) as u64,
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
    // x86_64 guarantees CPUID; the supported intrinsic declares scalar clobbers.
    let extended = __cpuid(0x8000_0000).eax;
    if extended < 0x8000_0001 || __cpuid(0x8000_0001).edx & (1 << 20) == 0 {
        return Err(Error::Nx);
    }
    if __cpuid(1).edx & (1 << 16) == 0 {
        return Err(Error::Pat);
    }
    let pat = read_msr(0x277);
    if pat & 0xff != 6 || (pat >> 40) & 0xff != 1 {
        return Err(Error::Pat);
    }
    let cr0: u64;
    let cr4: u64;
    let rsp: u64;
    // SAFETY: CPL0, no memory changes or stack accesses; integer outputs only.
    // MOV CR instructions have no Rust intrinsic. Read flags/stack unchanged.
    unsafe {
        asm!("mov {}, cr0", "mov {}, cr4", "mov {}, rsp", out(reg) cr0, out(reg) cr4, out(reg) rsp, options(nomem, nostack, preserves_flags));
    }
    // CR4.LA57, PGE and PCIDE: MOV to CR3 would leave global or other-PCID
    // loader translations alive (SDM Vol.3 4.10.4.1), defeating the new tree.
    if cr0 & ((1 << 31) | (1 << 16) | 1) != ((1 << 31) | (1 << 16) | 1)
        || cr4 & ((1 << 12) | (1 << 7) | (1 << 17)) != 0
    {
        return Err(Error::Paging);
    }
    let base = ptr::addr_of!(BOOT_STACK) as u64;
    if rsp < base + 4096 || rsp >= base + core::mem::size_of::<Stack>() as u64 {
        return Err(Error::Stack);
    }
    let efer = read_msr(0xc000_0080);
    if efer & (1 << 11) == 0 {
        return Err(Error::Nx);
    }
    // Keep x87/SIMD inaccessible until real per-task xstate ownership exists.
    // CR0.EM/TS force #NM; OSFXSR/OSXSAVE remain clear from base5. Thus this
    // scalar-only cell neither depends on nor exposes unspecified firmware FP
    // state. No Rust intrinsic can establish these privileged execution bits.
    // SAFETY: CPL0 IF=0, preserves paging/WP/PE and all reserved bits; the target
    // and linked code exclude FP/SIMD, no stack/flags changes or unwind.
    unsafe {
        asm!("mov cr0, {}", in(reg) cr0 | (1 << 2) | (1 << 3), options(nostack, preserves_flags));
    }
    Ok(())
}

pub fn interrupts_off() {
    // SAFETY: CPL0 BSP only; CLI changes IF, not memory or stack. Deliberately
    // omit nomem so ordinary operations cannot cross the exclusion boundary.
    unsafe {
        asm!("cli", options(nostack));
    }
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
        // SAFETY: CPL0 stop policy, no stack/memory/flags changes. NMI can still
        // arrive and uses its own IST; no implicit reboot or firmware call.
        unsafe {
            asm!("hlt", options(nomem, nostack, preserves_flags));
        }
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

fn read_msr(index: u32) -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: only architecturally defined EFER/APIC_BASE/PAT are passed after
    // CPU checks; CPL0, ECX input EAX/EDX outputs, no memory/stack/flags effects.
    unsafe {
        asm!("rdmsr", in("ecx") index, out("eax") low, out("edx") high, options(nomem, nostack, preserves_flags));
    }
    u64::from(low) | (u64::from(high) << 32)
}
#[expect(
    clippy::cast_possible_truncation,
    reason = "WRMSR's architectural ABI splits all 64 value bits into EDX:EAX; the low cast intentionally discards bits already supplied in EDX."
)]
fn write_msr(index: u32, value: u64) {
    // SAFETY: private callers constrain architectural bits to documented states;
    // CPL0 IRQ-disabled; EAX/EDX/ECX inputs only, flags/stack preserved. Omit nomem
    // so compiler memory operations do not cross a CPU-state transition.
    unsafe {
        asm!("wrmsr", in("ecx") index, in("eax") value as u32, in("edx") (value >> 32) as u32, options(nostack, preserves_flags));
    }
}

/// # Safety
/// Root is a live aligned owned four-level tree mapping every current
/// instruction/stack/descriptor/resource address with valid permissions. BSP
/// alone executes, IF clear, PCID/global mappings disabled; keep root alive.
pub unsafe fn activate_tables(root: u64) {
    // SAFETY: private caller has built a 4KiB-aligned owned four-level root,
    // maps current RIP/RSP/GDT/TSS/IDT and diagnostic/allocator resources with
    // same addresses, no PCID/global translations, only BSP executes. CR3 load
    // retires old non-global translations before continued accesses. Memory
    // operand ordering is intentional; flags/stack unchanged, no Rust intrinsic.
    unsafe {
        asm!("mov cr3, {}", in(reg) root, options(nostack, preserves_flags));
    }
}

pub fn active_tables() -> u64 {
    let value: u64;
    // SAFETY: CPL0 read, no memory/stack/flags effects; scalar output.
    unsafe {
        asm!("mov {}, cr3", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value & 0x000f_ffff_ffff_f000
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

#[repr(C, packed)]
struct TablePointer {
    limit: u16,
    base: u64,
}
#[repr(C, packed)]
struct TaskState {
    reserved0: u32,
    rsp: [u64; 3],
    reserved1: u64,
    ist: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    iomap: u16,
}
static mut TSS: TaskState = TaskState {
    reserved0: 0,
    rsp: [0; 3],
    reserved1: 0,
    ist: [0; 7],
    reserved2: 0,
    reserved3: 0,
    iomap: 104,
};
static mut GDT: [u64; 5] = [0, 0x00af_9a00_0000_ffff, 0x00cf_9200_0000_ffff, 0, 0];
#[repr(C)]
#[derive(Clone, Copy)]
struct Gate {
    low: u16,
    selector: u16,
    ist: u8,
    flags: u8,
    middle: u16,
    high: u32,
    zero: u32,
}
impl Gate {
    const fn empty() -> Self {
        Self {
            low: 0,
            selector: 0,
            ist: 0,
            flags: 0,
            middle: 0,
            high: 0,
            zero: 0,
        }
    }
    #[expect(
        clippy::cast_possible_truncation,
        reason = "The IDT ABI splits the complete 64-bit handler address into low16, middle16, and high32 fields; every discarded bit is retained in a higher field."
    )]
    fn new(handler: u64, ist: u8) -> Self {
        Self {
            low: handler as u16,
            selector: 8,
            ist,
            flags: 0x8e,
            middle: (handler >> 16) as u16,
            high: (handler >> 32) as u32,
            zero: 0,
        }
    }
}
static mut IDT: [Gate; 256] = [Gate::empty(); 256];

/// # Safety
/// Called once on BSP with IF clear, no AP execution and no live Rust references
/// to descriptor memory. All static image/stacks remain permanently reserved.
pub unsafe fn install_descriptors() {
    let top = |pointer: *const Stack| pointer as u64 + core::mem::size_of::<Stack>() as u64;
    // SAFETY: unique initialization before publication; packed fields written
    // unaligned through raw pointers, no references to descriptor RAM survive.
    unsafe {
        ptr::addr_of_mut!(TSS.rsp).write_unaligned([top(ptr::addr_of!(BOOT_STACK)), 0, 0]);
        ptr::addr_of_mut!(TSS.ist).write_unaligned([
            top(ptr::addr_of!(DOUBLE_STACK)),
            top(ptr::addr_of!(NMI_STACK)),
            top(ptr::addr_of!(MACHINE_STACK)),
            0,
            0,
            0,
            0,
        ]);
        let base = ptr::addr_of!(TSS) as u64;
        let limit = (core::mem::size_of::<TaskState>() - 1) as u64;
        let low =
            limit | ((base & 0x00ff_ffff) << 16) | (0x89u64 << 40) | ((base & 0xff00_0000) << 32);
        ptr::addr_of_mut!(GDT[3]).write(low);
        ptr::addr_of_mut!(GDT[4]).write(base >> 32);
    }
    let gdtr = TablePointer {
        limit: 39,
        base: ptr::addr_of!(GDT) as u64,
    };
    // SAFETY: GDTR points to initialized permanent GDT; stack valid/aligned; far
    // return pops exactly the 16 bytes pushed and reloads CS=8, data=16. RAX is
    // declared clobbered. LTR marks the owned TSS descriptor busy. No unwind,
    // only CPL0, IRQ-disabled BSP, no memory references alias these writes.
    unsafe {
        asm!(
            "lgdt [{}]", "push 8", "lea rax, [rip + 2f]", "push rax", "retfq", "2:",
            "mov ax, 16", "mov ds, ax", "mov es, ax", "mov ss, ax",
            "mov ax, 24", "ltr ax",
            in(reg) &raw const gdtr, out("rax") _,
        );
    }
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
    for index in 0..256 {
        let handler = match handlers.get(index) {
            Some(&handler) => handler,
            None if index == 32 => timer_entry as *const (),
            None => unexpected_entry as *const (),
        };
        let ist = match index {
            8 => 1,
            2 => 2,
            18 => 3,
            _ => 0,
        };
        // SAFETY: unique initialization of this exact in-bounds IDT element.
        unsafe {
            ptr::addr_of_mut!(IDT)
                .cast::<Gate>()
                .add(index)
                .write(Gate::new(handler as u64, ist));
        }
    }
    let idtr = TablePointer {
        limit: 4095,
        base: ptr::addr_of!(IDT) as u64,
    };
    // SAFETY: initialized permanent IDT, CPU copies 10-byte packed descriptor;
    // only CPL0, no memory mutation/stack effect, flags unchanged. LIDT has no
    // supported intrinsic. Do not assert nomem: the descriptor is read.
    unsafe {
        asm!("lidt [{}]", in(reg) &raw const idtr, options(readonly, nostack, preserves_flags));
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
    if frame.cs != 8 {
        unexpected(frame, vector, error, 0);
    }
    match vector {
        3 if BREAKPOINT_ARMED.swap(0, Ordering::Acquire) == 1 => {
            BREAKPOINTS.fetch_add(1, Ordering::Relaxed);
        }
        14 => {
            let address: u64;
            // SAFETY: page-fault CPL0 handler reads CR2 before any fallible work;
            // output only, no memory/stack/flag changes, architecture-only read.
            unsafe {
                asm!("mov {}, cr2", out(reg) address, options(nomem, nostack, preserves_flags));
            }
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
    // SAFETY: deliberate terminal negative case; no armed breakpoint permit.
    unsafe {
        asm!("int3", options(noreturn));
    }
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
    // SAFETY: x86_64 CPUID available. APIC_BASE only exists when feature set.
    if __cpuid(1).edx & (1 << 9) != 0 {
        let apic = read_msr(0x1b);
        if apic & (1 << 10) != 0 {
            return Err(Error::Apic);
        }
        // Disable the local APIC for this explicit legacy-PIC UP test cell.
        // This is not APIC initialization or a permanent Linux policy choice.
        write_msr(0x1b, apic & !(1 << 11));
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
