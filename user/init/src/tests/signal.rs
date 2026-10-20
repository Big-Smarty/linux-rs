// SPDX-License-Identifier: GPL-2.0-only
//! `signal` group: `rt_sigaction`, `rt_sigprocmask`, generation (`kill`, `tkill`, `tgkill`,
//! `rt_sigqueueinfo`), delivery to `SA_SIGINFO` handlers, `rt_sigreturn`, hardware faults,
//! `sigaltstack`, `rt_sigsuspend`/`rt_sigtimedwait`/`rt_sigpending` and restart behaviour.
//! Linux 6.18.57: `kernel/signal.c`, `arch/x86/kernel/signal.c`, `signal_64.c`, `traps.c`,
//! `mm/fault.c` (`__bad_area_nosemaphore`), `arch/x86/include/uapi/asm/{sigcontext,ucontext}.h`,
//! `include/uapi/asm-generic/{siginfo,signal-defs}.h`, `arch/x86/include/uapi/asm/signal.h`.
//!
//! Assembly proof (AGENTS.md rule 3) common to the seven stubs below: they run in user mode
//! (CPL 3), need no CPU feature beyond x86-64, never touch the FPU, and do not unwind
//! (`naked_asm!`, `extern "C"`, panic=abort). They exist because each must control an exact
//! instruction sequence a signal interrupts or a register file a signal restores, which neither
//! safe Rust nor an intrinsic expresses: a faulting load whose IP is known, a `syscall` with
//! `rax = 15` after the signal frame was popped, all general registers loaded before a trap.
//! Per-stub register, memory and flag contracts are on each function.

use core::arch::naked_asm;
use core::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering::Relaxed};

use syscalls::{Errno, Sysno};

use super::{PAGE, R, T, addr, addr_mut, fn_addr, getpid, gettid, mmap, sys};

const BAD: usize = 0xdead_0000_0000;

const SIGHUP: usize = 1;
const SIGILL: usize = 4;
const SIGTRAP: usize = 5;
const SIGFPE: usize = 8;
const SIGKILL: usize = 9;
const SIGUSR1: usize = 10;
const SIGSEGV: usize = 11;
const SIGUSR2: usize = 12;
const SIGALRM: usize = 14;
const SIGTERM: usize = 15;
const SIGSTOP: usize = 19;
const SIGRT0: usize = 34;

const SA_NOCLDSTOP: u64 = 1;
const SA_SIGINFO: u64 = 4;
const SA_ONSTACK: u64 = 0x0800_0000;
const SA_RESTART: u64 = 0x1000_0000;
const SA_NODEFER: u64 = 0x4000_0000;
const SA_RESETHAND: u64 = 0x8000_0000;
const SA_RESTORER: u64 = 0x0400_0000;

const SIG_BLOCK: usize = 0;
const SIG_UNBLOCK: usize = 1;
const SIG_SETMASK: usize = 2;

const SS_ONSTACK: u32 = 1;
const SS_DISABLE: u32 = 2;
const SS_AUTODISARM: u32 = 1 << 31;

const SI_USER: i32 = 0;
const SI_QUEUE: i32 = -1;
const SI_TKILL: i32 = -6;
const SI_KERNEL: i32 = 0x80;

fn bit(sig: usize) -> u64 {
    1 << (sig - 1)
}

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
struct KSigaction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
struct StackT {
    sp: u64,
    flags: u32,
    pad: u32,
    size: u64,
}

type Handler = extern "C" fn(i32, *const u64, *mut u64);

// ---------------------------------------------------------------------------------------------
// Records written by handlers (same thread; relaxed atomics are enough, the syscall `asm!`
// clobbers memory so the compiler cannot move accesses across it).

static COUNT: AtomicUsize = AtomicUsize::new(0);
static DEPTH: AtomicUsize = AtomicUsize::new(0);
static MAX_DEPTH: AtomicUsize = AtomicUsize::new(0);
static SIGNO_ARG: AtomicU64 = AtomicU64::new(0);
static SI: [AtomicU64; 16] = [const { AtomicU64::new(0) }; 16];
/// ucontext words at byte offsets 0, 16.., see `UC_*`.
static UC: [AtomicU64; 40] = [const { AtomicU64::new(0) }; 40];
static MASK_IN: AtomicU64 = AtomicU64::new(0);
static SP_IN: AtomicUsize = AtomicUsize::new(0);
static SS_IN: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
static ORDER: [AtomicU8; 16] = [const { AtomicU8::new(0) }; 16];
static ORDER_LEN: AtomicUsize = AtomicUsize::new(0);
static VALUES: [AtomicU64; 8] = [const { AtomicU64::new(0) }; 8];
/// Where a fault handler resumes (set by the probe stubs before they fault).
static RECOVER: AtomicUsize = AtomicUsize::new(0);
/// Address of the instruction a stub is about to execute (for `si_addr` of SIGFPE/SIGILL).
static FAULT_IP: AtomicUsize = AtomicUsize::new(0);
/// Return address and stack pointer seen on entry by `entry_probe`.
static ENTRY_RET: AtomicU64 = AtomicU64::new(0);
static ENTRY_RSP: AtomicU64 = AtomicU64::new(0);
static EXTRA_SIGNAL: AtomicUsize = AtomicUsize::new(0);
static NEW_MASK: AtomicU64 = AtomicU64::new(0);
static RBX_PATCH: AtomicU64 = AtomicU64::new(0);

// ucontext offsets (arch/x86/include/uapi/asm/ucontext.h, sigcontext.h): the glibc `gregs` index
// `n` is at byte `40 + 8 * n`.
const UC_FLAGS: usize = 0;
const UC_STACK_SP: usize = 16;
const UC_STACK_FLAGS: usize = 24;
const UC_STACK_SIZE: usize = 32;
const REG_RBX: usize = 40 + 8 * 11;
const REG_RAX: usize = 40 + 8 * 13;
const REG_RIP: usize = 40 + 8 * 16;
const REG_ERR: usize = 40 + 8 * 19;
const REG_TRAPNO: usize = 40 + 8 * 20;
const REG_CR2: usize = 40 + 8 * 22;
const UC_SIGMASK: usize = 296;

fn reset_records() {
    COUNT.store(0, Relaxed);
    DEPTH.store(0, Relaxed);
    MAX_DEPTH.store(0, Relaxed);
    ORDER_LEN.store(0, Relaxed);
    for w in SI.iter().chain(UC.iter()).chain(VALUES.iter()) {
        w.store(0, Relaxed);
    }
    EXTRA_SIGNAL.store(0, Relaxed);
}

fn si_word(i: usize) -> u64 {
    SI[i].load(Relaxed)
}

fn si_i32(offset: usize) -> i32 {
    (si_word(offset / 8) >> ((offset % 8) * 8)) as u32 as i32
}

fn uc_word(offset: usize) -> u64 {
    UC[offset / 8].load(Relaxed)
}

fn mask_now() -> u64 {
    let mut old = 0u64;
    let _ = sys(
        Sysno::rt_sigprocmask,
        &[SIG_BLOCK, 0, addr_mut(&mut old), 8],
    );
    old
}

fn sigaltstack_now() -> StackT {
    let mut old = StackT::default();
    let _ = sys(Sysno::sigaltstack, &[0, addr_mut(&mut old)]);
    old
}

/// Reads word `index` of a kernel-built signal frame structure.
fn frame_word(base: *const u64, index: usize) -> u64 {
    // SAFETY: `base` is the siginfo (16 words) or ucontext (>= 38 words) pointer the kernel passed
    // to the running handler; both live in the signal frame until the handler returns.
    unsafe { base.add(index).read() }
}

/// Everything a handler can observe, stored for the checks after delivery.
fn record(sig: i32, info: *const u64, uc: *mut u64) {
    COUNT.fetch_add(1, Relaxed);
    SIGNO_ARG.store(sig as u64, Relaxed);
    let n = ORDER_LEN.fetch_add(1, Relaxed);
    if let Some(slot) = ORDER.get(n) {
        slot.store(sig as u8, Relaxed);
    }
    if !info.is_null() {
        for (i, w) in SI.iter().enumerate() {
            w.store(frame_word(info, i), Relaxed);
        }
    }
    if !uc.is_null() {
        for (i, w) in UC.iter().enumerate() {
            w.store(frame_word(uc, i), Relaxed);
        }
    }
    MASK_IN.store(mask_now(), Relaxed);
    let marker = 0u8;
    SP_IN.store(addr(&marker), Relaxed);
    let ss = sigaltstack_now();
    SS_IN[0].store(ss.sp, Relaxed);
    SS_IN[1].store(u64::from(ss.flags), Relaxed);
    SS_IN[2].store(ss.size, Relaxed);
}

/// Writes a word of the kernel's ucontext (the frame `rt_sigreturn` restores from).
fn patch_uc(uc: *mut u64, offset: usize, value: u64) {
    // SAFETY: `uc` is the writable ucontext of the running handler; `offset / 8` is inside the
    // `sigcontext` / `uc_sigmask` area (offsets are the module constants above).
    unsafe { uc.add(offset / 8).write(value) };
}

extern "C" fn h_record(sig: i32, info: *const u64, uc: *mut u64) {
    record(sig, info, uc);
}

/// Records, then re-raises `EXTRA_SIGNAL` against itself (nesting / `SA_NODEFER` checks).
extern "C" fn h_nested(sig: i32, info: *const u64, uc: *mut u64) {
    record(sig, info, uc);
    let depth = DEPTH.fetch_add(1, Relaxed) + 1;
    MAX_DEPTH.fetch_max(depth, Relaxed);
    let extra = EXTRA_SIGNAL.swap(0, Relaxed);
    if extra != 0 {
        let _ = sys(Sysno::kill, &[getpid(), extra]);
    }
    DEPTH.fetch_sub(1, Relaxed);
}

/// Records a value passed with `rt_sigqueueinfo` (si_int at offset 24) in arrival order.
extern "C" fn h_values(sig: i32, info: *const u64, uc: *mut u64) {
    record(sig, info, uc);
    let n = COUNT.load(Relaxed) - 1;
    if let Some(slot) = VALUES.get(n) {
        slot.store(u64::from(si_i32(24) as u32), Relaxed);
    }
}

/// Resumes at `RECOVER` (a fault probe's recovery label) instead of re-executing the fault.
extern "C" fn h_recover(sig: i32, info: *const u64, uc: *mut u64) {
    record(sig, info, uc);
    patch_uc(uc, REG_RIP, RECOVER.load(Relaxed) as u64);
}

/// Changes the saved context: `rbx`, `rax`, and the mask restored by `rt_sigreturn`.
extern "C" fn h_patch(sig: i32, info: *const u64, uc: *mut u64) {
    record(sig, info, uc);
    patch_uc(uc, REG_RBX, RBX_PATCH.load(Relaxed));
    patch_uc(uc, REG_RAX, 0x2222_2222);
    patch_uc(uc, UC_SIGMASK, NEW_MASK.load(Relaxed));
}

/// Writes a byte to the pipe whose write end is `VALUES[7]` (restartable-read check).
extern "C" fn h_write_pipe(sig: i32, info: *const u64, uc: *mut u64) {
    record(sig, info, uc);
    let fd = VALUES[7].load(Relaxed) as usize;
    let _ = sys(Sysno::write, &[fd, addr(b"z"), 1]);
}

// ---------------------------------------------------------------------------------------------
// Assembly stubs.

/// `SA_RESTORER` trampoline: `rt_sigreturn`.
///
/// * Why asm: the kernel returns from a handler into this address with the signal frame on the
///   stack; the only way back is `syscall` with `rax = __NR_rt_sigreturn`, and no Rust construct
///   can run before a prologue or without a return address.
/// * Registers: writes `rax` (15) and, via `syscall`, `rcx`/`r11`; the kernel replaces every
///   register from the frame, so nothing is preserved or live here.
/// * Memory/flags/stack: the stack pointer at entry is the frame; the kernel reads it. Flags
///   are restored from the frame. User mode, interrupts unaffected.
/// * Control flow: never returns; `ud2` traps if the kernel returned (it must not).
#[unsafe(naked)]
unsafe extern "C" fn restorer() -> ! {
    naked_asm!("mov eax, 15", "syscall", "ud2")
}

/// Handler entry wrapper: records the return address and stack pointer the kernel built, then
/// tail-jumps to `h_record` with the stack untouched (so `h_record` sees exactly the entry state).
///
/// * Why asm: reading `[rsp]`/`rsp` before any prologue.
/// * Registers: clobbers `rax` only (caller-saved; the handler arguments `rdi`/`rsi`/`rdx` are
///   untouched). Memory: two 8-byte stores to `ENTRY_RET`/`ENTRY_RSP`; flags unchanged
///   (`mov`, `jmp`).
/// * Control flow: `jmp` to a Rust `extern "C"` handler that returns normally to the restorer.
#[unsafe(naked)]
unsafe extern "C" fn entry_probe() {
    naked_asm!(
        "mov rax, [rsp]",
        "mov [rip + {ret}], rax",
        "mov [rip + {rsp}], rsp",
        "jmp {handler}",
        ret = sym ENTRY_RET,
        rsp = sym ENTRY_RSP,
        handler = sym h_record,
    )
}

/// Loads a known value into every general register, executes `int3`, then stores the registers
/// (and the direction flag) the kernel handed back. Argument: `rdi` = `*mut [u64; 17]`.
///
/// Output order: rax rcx rdx rbx rbp rsi rdi r8 r9 r10 r11 r12 r13 r14 r15 flags-DF rsp-delta.
///
/// * Why asm: a signal must interrupt code whose entire register file is known, and `rt_sigreturn`
///   must restore all of it; no safe construct names `rbx`/`rbp` or can assert all 15 registers.
/// * Prerequisites: x86-64, user mode. `std` sets DF so the handler-entry DF clear and the
///   sigreturn DF restore are both observable.
/// * Registers: saves/restores the callee-saved set (`rbx rbp r12-r15`) on the stack, writes all
///   others (caller-saved, free to clobber), flags: DF set around the trap and cleared before
///   return (the System V ABI requires DF clear at calls).
/// * Memory/stack: pushes 7 words (6 callee-saved + the output pointer) below the entry `rsp`;
///   the kernel keeps 128 bytes of red zone above its frame, and the words live above `rsp`,
///   so the handler's frame never overlaps them. 17 stores through the caller's valid pointer.
/// * Control flow: `int3` raises SIGTRAP (handler installed by the caller) and resumes after it;
///   no unwinding.
#[unsafe(naked)]
unsafe extern "C" fn regs_probe(out: *mut [u64; 17]) {
    naked_asm!(
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "push rdi",
        "mov rax, 0x1111111111111111",
        "mov rcx, 0x2222222222222222",
        "mov rdx, 0x3333333333333333",
        "mov rbx, 0x4444444444444444",
        "mov rbp, 0x5555555555555555",
        "mov rsi, 0x6666666666666666",
        "mov rdi, 0x7777777777777777",
        "mov r8, 0x8888888888888888",
        "mov r9, 0x9999999999999999",
        "mov r10, 0xaaaaaaaaaaaaaaaa",
        "mov r11, 0xbbbbbbbbbbbbbbbb",
        "mov r12, 0xcccccccccccccccc",
        "mov r13, 0xdddddddddddddddd",
        "mov r14, 0xeeeeeeeeeeeeeeee",
        "mov r15, 0xffffffffffffffff",
        "std",
        "int3",
        // Back with all registers as sigreturn restored them; DF is what the frame held.
        "mov [rsp - 24], rax",
        "pushfq",
        "pop rax",
        "and rax, 0x400",
        "cld",
        "mov [rsp - 16], rax",
        "mov rax, [rsp]",
        "mov [rax + 8], rcx",
        "mov [rax + 16], rdx",
        "mov [rax + 24], rbx",
        "mov [rax + 32], rbp",
        "mov [rax + 40], rsi",
        "mov [rax + 48], rdi",
        "mov [rax + 56], r8",
        "mov [rax + 64], r9",
        "mov [rax + 72], r10",
        "mov [rax + 80], r11",
        "mov [rax + 88], r12",
        "mov [rax + 96], r13",
        "mov [rax + 104], r14",
        "mov [rax + 112], r15",
        "mov rcx, [rsp - 16]",
        "mov [rax + 120], rcx",
        "mov rcx, [rsp - 24]",
        "mov [rax], rcx",
        "pop rdi",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        "ret",
    )
}

/// Loads a byte from `rdi`; returns it, or -1 after `h_recover` resumed at the recovery label.
///
/// * Why asm: the faulting instruction's recovery point must be a known address, which Rust
///   cannot express for a load that may trap.
/// * Registers: writes `rax` (result), reads `rdi`; no other register. Memory: one 8-byte store
///   to `RECOVER`, one byte load from the caller's address (the fault under test); flags
///   unchanged except by `movzx`'s none.
/// * Control flow: the handler sets `rip` to label `2`, which returns -1 with the stack as at
///   the load (no pushes happened).
#[unsafe(naked)]
unsafe extern "C" fn probe_read(address: usize) -> usize {
    naked_asm!(
        "lea rax, [rip + 2f]",
        "mov [rip + {recover}], rax",
        "movzx eax, byte ptr [rdi]",
        "ret",
        "2:",
        "mov rax, -1",
        "ret",
        recover = sym RECOVER,
    )
}

/// Stores the byte `0x5a` to `rdi`; returns 0, or -1 after recovery. Contract as [`probe_read`]
/// except the faulting access is a write (`mov byte ptr [rdi], 0x5a`) and `rax` is the only
/// register written.
#[unsafe(naked)]
unsafe extern "C" fn probe_write(address: usize) -> usize {
    naked_asm!(
        "lea rax, [rip + 2f]",
        "mov [rip + {recover}], rax",
        "mov byte ptr [rdi], 0x5a",
        "xor eax, eax",
        "ret",
        "2:",
        "mov rax, -1",
        "ret",
        recover = sym RECOVER,
    )
}

/// Calls `rdi` (an address that must fault on instruction fetch); returns 0 if the call returned
/// or -1 after recovery.
///
/// * Registers: writes `rax`; the callee is never entered when the fetch faults, so its register
///   contract does not matter. Stack: `call` pushes one return address; the recovery label
///   (`2`) is entered with that word still pushed and removes it (`add rsp, 8`) before `ret`.
/// * Memory/control flow otherwise as [`probe_read`].
#[unsafe(naked)]
unsafe extern "C" fn probe_exec(address: usize) -> usize {
    naked_asm!(
        "lea rax, [rip + 2f]",
        "mov [rip + {recover}], rax",
        "call rdi",
        "xor eax, eax",
        "ret",
        "2:",
        "add rsp, 8",
        "mov rax, -1",
        "ret",
        recover = sym RECOVER,
    )
}

/// Executes `div` by zero; the handler recovers at label `2`. `FAULT_IP` receives the address of
/// the `div` itself (what `si_addr` must equal for `FPE_INTDIV`).
///
/// * Registers: writes `rax rcx rdx` (caller-saved). Flags: `div` leaves them undefined, none
///   is live. Memory: two 8-byte stores (`RECOVER`, `FAULT_IP`). Control flow as [`probe_read`].
#[unsafe(naked)]
unsafe extern "C" fn probe_div0() -> usize {
    naked_asm!(
        "lea rax, [rip + 2f]",
        "mov [rip + {recover}], rax",
        "lea rax, [rip + 3f]",
        "mov [rip + {ip}], rax",
        "xor edx, edx",
        "mov eax, 1",
        "xor ecx, ecx",
        "3:",
        "div rcx",
        "xor eax, eax",
        "ret",
        "2:",
        "mov rax, -1",
        "ret",
        recover = sym RECOVER,
        ip = sym FAULT_IP,
    )
}

/// Executes `ud2` (the architectural invalid opcode); recovery as [`probe_div0`], `FAULT_IP` is
/// the address of the `ud2`. Registers: `rax` only.
#[unsafe(naked)]
unsafe extern "C" fn probe_ud2() -> usize {
    naked_asm!(
        "lea rax, [rip + 2f]",
        "mov [rip + {recover}], rax",
        "lea rax, [rip + 3f]",
        "mov [rip + {ip}], rax",
        "3:",
        "ud2",
        "xor eax, eax",
        "ret",
        "2:",
        "mov rax, -1",
        "ret",
        recover = sym RECOVER,
        ip = sym FAULT_IP,
    )
}

// ---------------------------------------------------------------------------------------------

fn install(sig: usize, handler: Handler, flags: u64, mask: u64) -> R {
    install_raw(
        sig,
        fn_addr(handler as *const ()),
        flags | SA_RESTORER,
        mask,
    )
}

fn install_raw(sig: usize, handler: u64, flags: u64, mask: u64) -> R {
    let sa = KSigaction {
        handler,
        flags,
        restorer: fn_addr(restorer as *const ()),
        mask,
    };
    sys(Sysno::rt_sigaction, &[sig, addr(&sa), 0, 8])
}

fn query(sig: usize) -> (R, KSigaction) {
    let mut old = KSigaction {
        handler: 0xaa,
        flags: 0xaa,
        restorer: 0xaa,
        mask: 0xaa,
    };
    (
        sys(Sysno::rt_sigaction, &[sig, 0, addr_mut(&mut old), 8]),
        old,
    )
}

fn ignore(sig: usize) -> R {
    install_raw(sig, 1, 0, 0)
}

fn default(sig: usize) -> R {
    let sa = KSigaction::default();
    sys(Sysno::rt_sigaction, &[sig, addr(&sa), 0, 8])
}

fn procmask(how: usize, set: Option<u64>, old: Option<&mut u64>) -> R {
    sys(
        Sysno::rt_sigprocmask,
        &[
            how,
            set.as_ref().map_or(0, addr),
            old.map_or(0, addr_mut),
            8,
        ],
    )
}

fn pending() -> u64 {
    let mut set = 0u64;
    let _ = sys(Sysno::rt_sigpending, &[addr_mut(&mut set), 8]);
    set
}

fn kill(sig: usize) -> R {
    sys(Sysno::kill, &[getpid(), sig])
}

/// Every signal this group touches back to default, unblocked.
fn clean() {
    for sig in [
        SIGHUP, SIGILL, SIGTRAP, SIGFPE, SIGUSR1, SIGSEGV, SIGUSR2, SIGALRM, SIGRT0, 35,
    ] {
        let _ = default(sig);
    }
    let _ = procmask(SIG_SETMASK, Some(0), None);
    let _ = sys(
        Sysno::sigaltstack,
        &[
            addr(&StackT {
                flags: SS_DISABLE,
                ..StackT::default()
            }),
            0,
        ],
    );
    reset_records();
}

#[repr(C, align(4096))]
struct Altstack([u8; 4 * PAGE]);
static mut ALT: Altstack = Altstack([0; 4 * PAGE]);

fn alt_base() -> usize {
    core::ptr::addr_of!(ALT).addr()
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Itimerval {
    interval: [i64; 2],
    value: [i64; 2],
}

fn arm_timer_ms(ms: i64) {
    let it = Itimerval {
        value: [0, ms * 1000],
        ..Itimerval::default()
    };
    let _ = sys(Sysno::setitimer, &[0, addr(&it), 0]);
}

pub fn run() -> bool {
    let mut t = T::new("signal");
    actions(&mut t);
    masks(&mut t);
    generation(&mut t);
    delivery(&mut t);
    frames(&mut t);
    faults(&mut t);
    altstack(&mut t);
    waiting(&mut t);
    interruption(&mut t);
    init_special(&mut t);
    clean();
    t.finish()
}

fn actions(t: &mut T) {
    clean();
    t.eq(
        "sigaction-default",
        query(SIGUSR1),
        (Ok(0), KSigaction::default()),
    );
    let all = SA_SIGINFO | SA_RESTART | SA_NODEFER | SA_ONSTACK | SA_RESETHAND | SA_NOCLDSTOP;
    let mut old = KSigaction::default();
    let sa = KSigaction {
        handler: fn_addr(h_record as *const ()),
        flags: all | SA_RESTORER,
        restorer: fn_addr(restorer as *const ()),
        mask: bit(SIGUSR2),
    };
    t.eq(
        "sigaction-set-returns-old",
        (
            sys(
                Sysno::rt_sigaction,
                &[SIGUSR1, addr(&sa), addr_mut(&mut old), 8],
            ),
            old,
        ),
        (Ok(0), KSigaction::default()),
    );
    t.eq("sigaction-roundtrip", query(SIGUSR1), (Ok(0), sa));
    let sa2 = KSigaction {
        handler: 1,
        flags: 0,
        restorer: 0,
        mask: 0,
    };
    let mut old = KSigaction::default();
    t.eq(
        "sigaction-old-is-previous",
        (
            sys(
                Sysno::rt_sigaction,
                &[SIGUSR1, addr(&sa2), addr_mut(&mut old), 8],
            ),
            old,
        ),
        (Ok(0), sa),
    );
    t.eq("sigaction-ignore", query(SIGUSR1), (Ok(0), sa2));
    t.eq(
        "sigaction-default-again",
        (default(SIGUSR1), query(SIGUSR1)),
        (Ok(0), (Ok(0), KSigaction::default())),
    );
    // SIGKILL and SIGSTOP are removed from the saved mask.
    let r = install(SIGUSR1, h_record, 0, u64::MAX);
    let kept = !(bit(SIGKILL) | bit(SIGSTOP));
    t.eq(
        "sigaction-mask-strips-kill-stop",
        (r, query(SIGUSR1).1.mask),
        (Ok(0), kept),
    );
    t.eq(
        "sigaction-rt-signal",
        (install(64, h_record, 0, 0), query(64).1.handler),
        (Ok(0), fn_addr(h_record as *const ())),
    );
    t.eq("sigaction-rt-signal-reset", default(64), Ok(0));
    t.eq(
        "sigaction-sig-32",
        (install(32, h_record, 0, 0), default(32)),
        (Ok(0), Ok(0)),
    );
    t.eq(
        "sigaction-sig-0",
        install(0, h_record, 0, 0),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sigaction-sig-65",
        install(65, h_record, 0, 0),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sigaction-sig-huge",
        install(usize::MAX, h_record, 0, 0),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sigaction-sigkill-set",
        install(SIGKILL, h_record, 0, 0),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sigaction-sigstop-set",
        install(SIGSTOP, h_record, 0, 0),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sigaction-sigkill-ignore",
        ignore(SIGKILL),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sigaction-sigkill-query",
        query(SIGKILL),
        (Ok(0), KSigaction::default()),
    );
    t.eq(
        "sigaction-sigstop-query",
        query(SIGSTOP),
        (Ok(0), KSigaction::default()),
    );
    let sa = KSigaction::default();
    for (name, size) in [("zero", 0usize), ("four", 4), ("sixteen", 16), ("nine", 9)] {
        t.eq(
            format_args!("sigaction-bad-sigsetsize-{name}"),
            sys(Sysno::rt_sigaction, &[SIGUSR1, addr(&sa), 0, size]),
            Err(Errno::EINVAL),
        );
    }
    t.eq(
        "sigaction-null-null",
        sys(Sysno::rt_sigaction, &[SIGUSR1, 0, 0, 8]),
        Ok(0),
    );
    t.eq(
        "sigaction-null-null-bad-sig",
        sys(Sysno::rt_sigaction, &[0, 0, 0, 8]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sigaction-fault-act",
        sys(Sysno::rt_sigaction, &[SIGUSR1, BAD, 0, 8]),
        Err(Errno::EFAULT),
    );
    // The new action is installed before the old one is copied out.
    let _ = default(SIGUSR1);
    let sa = KSigaction {
        handler: 1,
        flags: 0,
        restorer: 0,
        mask: 0,
    };
    t.eq(
        "sigaction-fault-oact",
        sys(Sysno::rt_sigaction, &[SIGUSR1, addr(&sa), BAD, 8]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "sigaction-fault-oact-still-installed",
        query(SIGUSR1).1.handler,
        1,
    );
    clean();
}

fn masks(t: &mut T) {
    clean();
    t.eq("sigprocmask-initial", mask_now(), 0);
    let mut old = 7u64;
    t.eq(
        "sigprocmask-block",
        (
            procmask(SIG_BLOCK, Some(bit(SIGUSR1) | bit(SIGUSR2)), Some(&mut old)),
            old,
            mask_now(),
        ),
        (Ok(0), 0, bit(SIGUSR1) | bit(SIGUSR2)),
    );
    t.eq(
        "sigprocmask-unblock",
        (procmask(SIG_UNBLOCK, Some(bit(SIGUSR1)), None), mask_now()),
        (Ok(0), bit(SIGUSR2)),
    );
    t.eq(
        "sigprocmask-setmask",
        (procmask(SIG_SETMASK, Some(bit(SIGHUP)), None), mask_now()),
        (Ok(0), bit(SIGHUP)),
    );
    t.eq(
        "sigprocmask-query-only",
        (procmask(SIG_BLOCK, None, Some(&mut old)), old),
        (Ok(0), bit(SIGHUP)),
    );
    t.eq(
        "sigprocmask-kill-stop-unblockable",
        (procmask(SIG_SETMASK, Some(u64::MAX), None), mask_now()),
        (Ok(0), !(bit(SIGKILL) | bit(SIGSTOP))),
    );
    t.eq(
        "sigprocmask-block-kill-ignored",
        (
            procmask(SIG_SETMASK, Some(0), None),
            procmask(SIG_BLOCK, Some(bit(SIGKILL)), None),
            mask_now(),
        ),
        (Ok(0), Ok(0), 0),
    );
    t.eq(
        "sigprocmask-bad-how",
        procmask(3, Some(0), None),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sigprocmask-bad-how-big",
        procmask(usize::MAX, Some(0), None),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sigprocmask-bad-size",
        sys(Sysno::rt_sigprocmask, &[SIG_BLOCK, addr(&0u64), 0, 4]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sigprocmask-bad-size-null",
        sys(Sysno::rt_sigprocmask, &[SIG_BLOCK, 0, 0, 16]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sigprocmask-fault-set",
        sys(Sysno::rt_sigprocmask, &[SIG_BLOCK, BAD, 0, 8]),
        Err(Errno::EFAULT),
    );
    // The new mask is installed before the old one is copied out.
    t.eq(
        "sigprocmask-fault-oldset",
        sys(
            Sysno::rt_sigprocmask,
            &[SIG_SETMASK, addr(&bit(SIGUSR1)), BAD, 8],
        ),
        Err(Errno::EFAULT),
    );
    t.eq(
        "sigprocmask-fault-oldset-still-set",
        mask_now(),
        bit(SIGUSR1),
    );
    t.eq("sigpending-empty", pending(), 0);
    t.eq(
        "sigpending-fault",
        sys(Sysno::rt_sigpending, &[BAD, 8]),
        Err(Errno::EFAULT),
    );
    let mut set = 0xffff_ffff_ffff_ffffu64;
    t.eq(
        "sigpending-bad-size",
        sys(Sysno::rt_sigpending, &[addr_mut(&mut set), 16]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sigpending-short-size",
        (sys(Sysno::rt_sigpending, &[addr_mut(&mut set), 4]), set),
        (Ok(0), 0xffff_ffff_0000_0000),
    );
    clean();
}

fn generation(t: &mut T) {
    clean();
    t.eq("kill-signal-0-self", kill(0), Ok(0));
    t.eq(
        "kill-signal-0-missing",
        sys(Sysno::kill, &[99_999, 0]),
        Err(Errno::ESRCH),
    );
    t.eq("kill-bad-signal", kill(65), Err(Errno::EINVAL));
    t.eq(
        "kill-negative-signal",
        sys(Sysno::kill, &[1, usize::MAX]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "kill-missing",
        sys(Sysno::kill, &[99_999, SIGUSR1]),
        Err(Errno::ESRCH),
    );
    t.eq(
        "tgkill-missing-tid",
        sys(Sysno::tgkill, &[getpid(), 99_999, SIGUSR1]),
        Err(Errno::ESRCH),
    );
    t.eq(
        "tgkill-missing-tgid",
        sys(Sysno::tgkill, &[99_999, gettid(), 0]),
        Err(Errno::ESRCH),
    );
    t.eq(
        "tgkill-mismatched-tgid",
        sys(Sysno::tgkill, &[99_999, gettid(), SIGUSR1]),
        Err(Errno::ESRCH),
    );
    t.eq(
        "tgkill-negative-tid",
        sys(Sysno::tgkill, &[getpid(), usize::MAX, 0]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "tgkill-bad-signal",
        sys(Sysno::tgkill, &[getpid(), gettid(), 65]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "tkill-missing",
        sys(Sysno::tkill, &[99_999, SIGUSR1]),
        Err(Errno::ESRCH),
    );
    t.eq(
        "tkill-bad-signal",
        sys(Sysno::tkill, &[gettid(), 65]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "tkill-negative-tid",
        sys(Sysno::tkill, &[usize::MAX, 0]),
        Err(Errno::EINVAL),
    );
    let mut info = [0u64; 16];
    info[1] = SI_QUEUE as u32 as u64;
    t.eq(
        "sigqueueinfo-user-code-to-other-pid",
        sys(
            Sysno::rt_sigqueueinfo,
            &[99_999, SIGUSR1, addr(&[0u64; 16])],
        ),
        Err(Errno::EPERM),
    );
    t.eq(
        "sigqueueinfo-missing",
        sys(Sysno::rt_sigqueueinfo, &[99_999, SIGUSR1, addr(&info)]),
        Err(Errno::ESRCH),
    );
    t.eq(
        "sigqueueinfo-fault",
        sys(Sysno::rt_sigqueueinfo, &[getpid(), SIGUSR1, BAD]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "sigqueueinfo-bad-signal",
        sys(Sysno::rt_sigqueueinfo, &[getpid(), 65, addr(&info)]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sigqueueinfo-signal-0",
        sys(Sysno::rt_sigqueueinfo, &[getpid(), 0, addr(&info)]),
        Ok(0),
    );
    clean();
}

fn delivery(t: &mut T) {
    clean();
    // kill(getpid()): the handler has run when kill returns.
    t.eq(
        "install-usr1",
        install(SIGUSR1, h_record, SA_SIGINFO, 0),
        Ok(0),
    );
    t.eq("kill-self", kill(SIGUSR1), Ok(0));
    t.eq("kill-self-handler-ran", COUNT.load(Relaxed), 1);
    t.eq("handler-signo-arg", SIGNO_ARG.load(Relaxed), SIGUSR1 as u64);
    t.eq("siginfo-signo", si_i32(0), SIGUSR1 as i32);
    t.eq("siginfo-errno", si_i32(4), 0);
    t.eq("siginfo-code-user", si_i32(8), SI_USER);
    t.eq("siginfo-kill-pid", si_i32(16), 1);
    t.eq("siginfo-kill-uid", si_i32(20), 0);
    t.eq(
        "siginfo-rest-zero",
        SI[4..].iter().all(|w| w.load(Relaxed) == 0),
        true,
    );
    t.eq(
        "handler-mask-has-signal",
        MASK_IN.load(Relaxed),
        bit(SIGUSR1),
    );
    t.eq("mask-restored-after-handler", mask_now(), 0);
    t.eq("handler-flags-cleared-df", uc_word(UC_FLAGS) & !1, 6);
    // tgkill / tkill report SI_TKILL.
    reset_records();
    t.eq(
        "tgkill-self",
        sys(Sysno::tgkill, &[getpid(), gettid(), SIGUSR1]),
        Ok(0),
    );
    t.eq(
        "tgkill-delivered",
        (COUNT.load(Relaxed), si_i32(8), si_i32(16), si_i32(20)),
        (1, SI_TKILL, 1, 0),
    );
    reset_records();
    t.eq("tkill-self", sys(Sysno::tkill, &[gettid(), SIGUSR1]), Ok(0));
    t.eq(
        "tkill-delivered",
        (COUNT.load(Relaxed), si_i32(8), si_i32(16)),
        (1, SI_TKILL, 1),
    );
    // rt_sigqueueinfo carries code and value.
    reset_records();
    let mut info = [0u64; 16];
    info[0] = 0x77; // si_signo (the kernel overwrites it)
    info[1] = SI_QUEUE as u32 as u64; // si_code = SI_QUEUE
    info[2] = 1; // si_pid
    info[3] = 0x1234_5678_9abc_def0; // si_value (the kernel keeps it)
    t.eq(
        "sigqueueinfo-self",
        sys(Sysno::rt_sigqueueinfo, &[getpid(), SIGUSR1, addr(&info)]),
        Ok(0),
    );
    t.eq(
        "sigqueueinfo-delivered",
        (COUNT.load(Relaxed), si_i32(8), si_i32(16), si_word(3)),
        (1, SI_QUEUE, 1, 0x1234_5678_9abc_def0),
    );
    reset_records();
    t.eq(
        "tgsigqueueinfo-self",
        sys(
            Sysno::rt_tgsigqueueinfo,
            &[getpid(), gettid(), SIGUSR1, addr(&info)],
        ),
        Ok(0),
    );
    t.eq(
        "tgsigqueueinfo-delivered",
        (COUNT.load(Relaxed), si_i32(8)),
        (1, SI_QUEUE),
    );
    // Blocked: pending until unblocked, delivered inside the unblocking syscall.
    reset_records();
    let _ = procmask(SIG_BLOCK, Some(bit(SIGUSR1)), None);
    t.eq("blocked-kill", kill(SIGUSR1), Ok(0));
    t.eq("blocked-not-delivered", COUNT.load(Relaxed), 0);
    t.eq("blocked-pending", pending(), bit(SIGUSR1));
    t.eq("blocked-twice", kill(SIGUSR1), Ok(0));
    t.eq("blocked-standard-signal-coalesces", pending(), bit(SIGUSR1));
    t.eq(
        "unblock-delivers",
        procmask(SIG_UNBLOCK, Some(bit(SIGUSR1)), None),
        Ok(0),
    );
    t.eq("unblock-delivered-once", COUNT.load(Relaxed), 1);
    t.eq("unblock-clears-pending", pending(), 0);
    // Setting SIG_IGN discards a pending signal.
    let _ = procmask(SIG_BLOCK, Some(bit(SIGUSR1)), None);
    reset_records();
    let _ = kill(SIGUSR1);
    let was = pending();
    let _ = ignore(SIGUSR1);
    t.eq(
        "ignore-discards-pending",
        (was, pending()),
        (bit(SIGUSR1), 0),
    );
    let _ = procmask(SIG_UNBLOCK, Some(bit(SIGUSR1)), None);
    t.eq("ignored-never-delivered", COUNT.load(Relaxed), 0);
    t.eq(
        "ignored-send",
        (kill(SIGUSR1), COUNT.load(Relaxed), pending()),
        (Ok(0), 0, 0),
    );
    // Real-time signals queue; standard ones above did not.
    t.eq(
        "install-rt",
        install(SIGRT0, h_values, SA_SIGINFO, 0),
        Ok(0),
    );
    reset_records();
    let _ = procmask(SIG_BLOCK, Some(bit(SIGRT0)), None);
    for v in 1..=3u64 {
        info[3] = v;
        let _ = sys(Sysno::rt_sigqueueinfo, &[getpid(), SIGRT0, addr(&info)]);
    }
    t.eq("rt-queued-pending", pending(), bit(SIGRT0));
    let _ = procmask(SIG_UNBLOCK, Some(bit(SIGRT0)), None);
    t.eq(
        "rt-queued-all-delivered-in-order",
        (
            COUNT.load(Relaxed),
            VALUES[0].load(Relaxed),
            VALUES[1].load(Relaxed),
            VALUES[2].load(Relaxed),
        ),
        (3, 1, 2, 3),
    );
    reset_records();
    let _ = procmask(SIG_BLOCK, Some(bit(SIGRT0)), None);
    let _ = kill(SIGRT0);
    let _ = kill(SIGRT0);
    let _ = procmask(SIG_UNBLOCK, Some(bit(SIGRT0)), None);
    t.eq(
        "rt-kill-queues-too",
        (COUNT.load(Relaxed), si_i32(8)),
        (2, SI_USER),
    );
    // Lowest-numbered pending signal first; real-time after standard.
    let all = bit(SIGHUP) | bit(SIGUSR1) | bit(SIGUSR2) | bit(SIGRT0);
    let order = || [0, 1, 2, 3].map(|i| ORDER[i].load(Relaxed));
    // Handlers that block the others run one at a time, in dequeue order: lowest number first.
    for s in [SIGHUP, SIGUSR1, SIGUSR2, SIGRT0] {
        let _ = install(s, h_record, SA_SIGINFO, all);
    }
    reset_records();
    let _ = procmask(SIG_SETMASK, Some(all), None);
    for s in [SIGRT0, SIGUSR2, SIGUSR1, SIGHUP] {
        let _ = kill(s);
    }
    t.eq("order-pending", pending(), all);
    let _ = procmask(SIG_SETMASK, Some(0), None);
    t.eq(
        "order-masked-handlers-lowest-first",
        order(),
        [SIGHUP as u8, SIGUSR1 as u8, SIGUSR2 as u8, SIGRT0 as u8],
    );
    // Handlers that block nothing: every pending signal is dequeued (lowest first) and its frame
    // pushed before any handler starts, so the handlers run newest frame first.
    for s in [SIGHUP, SIGUSR1, SIGUSR2, SIGRT0] {
        let _ = install(s, h_record, SA_SIGINFO, 0);
    }
    reset_records();
    let _ = procmask(SIG_SETMASK, Some(all), None);
    for s in [SIGRT0, SIGUSR2, SIGUSR1, SIGHUP] {
        let _ = kill(s);
    }
    let _ = procmask(SIG_SETMASK, Some(0), None);
    t.eq(
        "order-unmasked-handlers-run-newest-frame-first",
        order(),
        [SIGRT0 as u8, SIGUSR2 as u8, SIGUSR1 as u8, SIGHUP as u8],
    );
    clean();
}

fn frames(t: &mut T) {
    clean();
    // The frame the kernel builds: return address is the restorer, stack alignment per psABI.
    t.eq(
        "install-entry-probe",
        {
            let sa = KSigaction {
                handler: fn_addr(entry_probe as *const ()),
                flags: SA_SIGINFO | SA_RESTORER,
                restorer: fn_addr(restorer as *const ()),
                mask: 0,
            };
            sys(Sysno::rt_sigaction, &[SIGUSR1, addr(&sa), 0, 8])
        },
        Ok(0),
    );
    let _ = kill(SIGUSR1);
    t.eq(
        "frame-return-is-restorer",
        ENTRY_RET.load(Relaxed),
        fn_addr(restorer as *const ()),
    );
    t.eq("frame-rsp-alignment", ENTRY_RSP.load(Relaxed) % 16, 8);
    // sa_mask and SA_NODEFER.
    clean();
    let _ = install(SIGUSR1, h_record, SA_SIGINFO, bit(SIGUSR2) | bit(SIGHUP));
    let _ = kill(SIGUSR1);
    t.eq(
        "sa_mask-blocked-in-handler",
        MASK_IN.load(Relaxed),
        bit(SIGUSR1) | bit(SIGUSR2) | bit(SIGHUP),
    );
    clean();
    let _ = install(SIGUSR1, h_record, SA_SIGINFO | SA_NODEFER, 0);
    let _ = kill(SIGUSR1);
    t.eq("nodefer-signal-not-blocked", MASK_IN.load(Relaxed), 0);
    // Without SA_NODEFER a signal raised inside its own handler waits for the handler to return.
    clean();
    let _ = install(SIGUSR1, h_nested, SA_SIGINFO, 0);
    EXTRA_SIGNAL.store(SIGUSR1, Relaxed);
    let _ = kill(SIGUSR1);
    t.eq(
        "defer-runs-after-return",
        (COUNT.load(Relaxed), MAX_DEPTH.load(Relaxed)),
        (2, 1),
    );
    clean();
    let _ = install(SIGUSR1, h_nested, SA_SIGINFO | SA_NODEFER, 0);
    EXTRA_SIGNAL.store(SIGUSR1, Relaxed);
    let _ = kill(SIGUSR1);
    t.eq(
        "nodefer-nests",
        (COUNT.load(Relaxed), MAX_DEPTH.load(Relaxed)),
        (2, 2),
    );
    // A different signal is delivered inside a handler.
    clean();
    let _ = install(SIGUSR1, h_nested, SA_SIGINFO, 0);
    let _ = install(SIGUSR2, h_record, SA_SIGINFO, 0);
    EXTRA_SIGNAL.store(SIGUSR2, Relaxed);
    let _ = kill(SIGUSR1);
    t.eq(
        "nested-other-signal-order",
        (
            ORDER[0].load(Relaxed),
            ORDER[1].load(Relaxed),
            COUNT.load(Relaxed),
        ),
        (SIGUSR1 as u8, SIGUSR2 as u8, 2),
    );
    // SA_RESETHAND: one-shot.
    clean();
    let _ = install(SIGUSR1, h_record, SA_SIGINFO | SA_RESETHAND, 0);
    let _ = kill(SIGUSR1);
    t.eq("resethand-delivered", COUNT.load(Relaxed), 1);
    // Only the handler is reset; flags, restorer and mask stay as installed.
    t.eq(
        "resethand-reset",
        query(SIGUSR1).1,
        KSigaction {
            handler: 0,
            flags: SA_SIGINFO | SA_RESETHAND | SA_RESTORER,
            restorer: fn_addr(restorer as *const ()),
            mask: 0,
        },
    );
    // Handlers without SA_SIGINFO get only the signal number.
    clean();
    let _ = install(SIGUSR1, h_record, 0, 0);
    let _ = kill(SIGUSR1);
    t.eq(
        "plain-handler",
        (COUNT.load(Relaxed), SIGNO_ARG.load(Relaxed)),
        (1, SIGUSR1 as u64),
    );
    // rt_sigreturn restores every register and the flags from the frame; the handler's changes
    // to the saved context win.
    clean();
    RBX_PATCH.store(0xbbbb_0000_bbbb_0000, Relaxed);
    NEW_MASK.store(bit(SIGUSR2), Relaxed);
    let _ = install(SIGTRAP, h_patch, SA_SIGINFO, 0);
    let mut out = [0u64; 17];
    // SAFETY: `regs_probe` stores 17 words through the valid pointer and preserves callee-saved
    // registers; the SIGTRAP handler is installed.
    unsafe { regs_probe(&raw mut out) };
    let want_unchanged = [
        0x2222_2222, // rax: patched by the handler
        0x2222_2222_2222_2222,
        0x3333_3333_3333_3333,
        0xbbbb_0000_bbbb_0000, // rbx: patched
        0x5555_5555_5555_5555,
        0x6666_6666_6666_6666,
        0x7777_7777_7777_7777,
        0x8888_8888_8888_8888,
        0x9999_9999_9999_9999,
        0xaaaa_aaaa_aaaa_aaaa,
        0xbbbb_bbbb_bbbb_bbbb,
        0xcccc_cccc_cccc_cccc,
        0xdddd_dddd_dddd_dddd,
        0xeeee_eeee_eeee_eeee,
        0xffff_ffff_ffff_ffff,
        0x400, // DF restored from the frame
    ];
    t.eq(
        "sigreturn-restores-registers",
        &out[..16],
        &want_unchanged[..],
    );
    t.eq("sigreturn-honours-patched-mask", mask_now(), bit(SIGUSR2));
    t.eq(
        "int3-signal",
        (COUNT.load(Relaxed), si_i32(0), si_i32(8)),
        (1, SIGTRAP as i32, SI_KERNEL),
    );
    t.eq(
        "int3-trapno-err",
        (uc_word(REG_TRAPNO), uc_word(REG_ERR)),
        (3, 0),
    );
    t.eq("int3-frame-eflags-df", uc_word(40 + 8 * 17) & 0x400, 0x400);
    clean();
}

fn faults(t: &mut T) {
    clean();
    let probe = |t: &mut T, name: &str, sig: usize, f: &dyn Fn() -> usize, want: usize| {
        reset_records();
        let _ = install(sig, h_recover, SA_SIGINFO, 0);
        let r = f();
        t.eq(
            format_args!("{name}-recovered"),
            (r, COUNT.load(Relaxed)),
            (want, 1),
        );
    };
    // SAFETY (every probe_* call below): each stub is `extern "C"`, preserves the registers the
    // ABI requires, and the SIGSEGV/SIGFPE/SIGILL handler resumes it at its own recovery label.
    probe(
        t,
        "segv-null-read",
        SIGSEGV,
        &|| unsafe { probe_read(0x10) },
        usize::MAX,
    );
    t.eq(
        "segv-null-read-info",
        (si_i32(0), si_i32(4), si_i32(8), si_word(2)),
        (SIGSEGV as i32, 0, 1, 0x10),
    );
    t.eq(
        "segv-null-read-context",
        (
            uc_word(REG_TRAPNO),
            uc_word(REG_ERR),
            uc_word(REG_CR2),
            uc_word(REG_RIP) & 0xfff != 0,
        ),
        (14, 4, 0x10, true),
    );
    probe(
        t,
        "segv-unmapped-write",
        SIGSEGV,
        &|| unsafe { probe_write(0x7000_0000_0123) },
        usize::MAX,
    );
    t.eq(
        "segv-unmapped-write-info",
        (si_i32(8), si_word(2), uc_word(REG_ERR), uc_word(REG_CR2)),
        (1, 0x7000_0000_0123, 6, 0x7000_0000_0123),
    );
    // Protection violations are SEGV_ACCERR.
    let page = mmap(0, 2 * PAGE, 0, 0x22, usize::MAX, 0).unwrap_or(0);
    probe(
        t,
        "segv-prot-none-read",
        SIGSEGV,
        &|| unsafe { probe_read(page + 8) },
        usize::MAX,
    );
    t.eq(
        "segv-prot-none-read-info",
        (si_i32(8), si_word(2), uc_word(REG_ERR)),
        (2, page as u64 + 8, 4),
    );
    let _ = sys(Sysno::mprotect, &[page, 2 * PAGE, 1]);
    // First touch is a not-present write (error code 6); after a read maps the page it is a
    // protection violation (error code 7).
    probe(
        t,
        "segv-read-only-write-untouched",
        SIGSEGV,
        &|| unsafe { probe_write(page + PAGE + 16) },
        usize::MAX,
    );
    t.eq(
        "segv-read-only-write-untouched-info",
        (si_i32(8), si_word(2), uc_word(REG_ERR)),
        (2, (page + PAGE) as u64 + 16, 6),
    );
    reset_records();
    t.eq(
        "read-only-read-ok-first",
        (unsafe { probe_read(page + 16) }, COUNT.load(Relaxed)),
        (0, 0),
    );
    probe(
        t,
        "segv-read-only-write",
        SIGSEGV,
        &|| unsafe { probe_write(page + 16) },
        usize::MAX,
    );
    t.eq(
        "segv-read-only-write-info",
        (si_i32(8), si_word(2), uc_word(REG_ERR)),
        (2, page as u64 + 16, 7),
    );
    reset_records();
    t.eq(
        "read-only-read-ok",
        (unsafe { probe_read(page + 16) }, COUNT.load(Relaxed)),
        (0, 0),
    );
    probe(
        t,
        "segv-exec-nx",
        SIGSEGV,
        &|| unsafe { probe_exec(page + 0x20) },
        usize::MAX,
    );
    t.eq(
        "segv-exec-nx-info",
        (si_i32(8), si_word(2), uc_word(REG_ERR), uc_word(REG_CR2)),
        (2, page as u64 + 0x20, 0x15, page as u64 + 0x20),
    );
    probe(
        t,
        "segv-exec-unmapped",
        SIGSEGV,
        &|| unsafe { probe_exec(0x7100_0000_0000) },
        usize::MAX,
    );
    t.eq(
        "segv-exec-unmapped-info",
        (si_i32(8), si_word(2), uc_word(REG_ERR)),
        (1, 0x7100_0000_0000, 0x14),
    );
    // A non-canonical address is a general-protection fault: SIGSEGV with SI_KERNEL, no address.
    probe(
        t,
        "segv-noncanonical",
        SIGSEGV,
        &|| unsafe { probe_read(0x8000_0000_0000_0000) },
        usize::MAX,
    );
    t.eq(
        "segv-noncanonical-info",
        (
            si_i32(0),
            si_i32(8),
            si_word(2),
            uc_word(REG_TRAPNO),
            uc_word(REG_ERR),
        ),
        (SIGSEGV as i32, SI_KERNEL, 0, 13, 0),
    );
    let _ = sys(Sysno::munmap, &[page, 2 * PAGE]);
    // Other synchronous exceptions.
    probe(
        t,
        "fpe-divide-by-zero",
        SIGFPE,
        &|| unsafe { probe_div0() },
        usize::MAX,
    );
    t.eq(
        "fpe-info",
        (
            si_i32(0),
            si_i32(8),
            si_word(2),
            uc_word(REG_TRAPNO),
            uc_word(REG_ERR),
        ),
        (SIGFPE as i32, 1, FAULT_IP.load(Relaxed) as u64, 0, 0),
    );
    probe(t, "ill-ud2", SIGILL, &|| unsafe { probe_ud2() }, usize::MAX);
    t.eq(
        "ill-info",
        (si_i32(0), si_i32(8), si_word(2), uc_word(REG_TRAPNO)),
        (SIGILL as i32, 2, FAULT_IP.load(Relaxed) as u64, 6),
    );
    // A fault with the signal blocked is not recoverable by a handler; the kernel kills the task,
    // so it is deliberately not exercised. A recovered fault leaves the mask intact.
    t.eq("mask-intact-after-faults", mask_now(), 0);
    clean();
}

fn altstack(t: &mut T) {
    clean();
    t.eq(
        "altstack-initial",
        sigaltstack_now(),
        StackT {
            sp: 0,
            flags: SS_DISABLE,
            pad: 0,
            size: 0,
        },
    );
    let base = alt_base() as u64;
    let alt = StackT {
        sp: base,
        flags: 0,
        pad: 0,
        size: (4 * PAGE) as u64,
    };
    let mut old = StackT {
        sp: 9,
        flags: 9,
        pad: 9,
        size: 9,
    };
    t.eq(
        "altstack-set",
        (
            sys(Sysno::sigaltstack, &[addr(&alt), addr_mut(&mut old)]),
            old,
        ),
        (
            Ok(0),
            StackT {
                sp: 0,
                flags: SS_DISABLE,
                pad: 0,
                size: 0,
            },
        ),
    );
    t.eq("altstack-get", sigaltstack_now(), alt);
    let small = StackT {
        sp: base,
        flags: 0,
        pad: 0,
        size: 1024,
    };
    t.eq(
        "altstack-too-small",
        sys(Sysno::sigaltstack, &[addr(&small), 0]),
        Err(Errno::ENOMEM),
    );
    t.eq(
        "altstack-min-size-ok",
        sys(
            Sysno::sigaltstack,
            &[addr(&StackT { size: 2048, ..alt }), 0],
        ),
        Ok(0),
    );
    t.eq("altstack-kept-after-error", sigaltstack_now().size, 2048);
    // SS_ONSTACK as input is accepted and means "armed" (kernel/signal.c: ss_mode != SS_ONSTACK).
    t.eq(
        "altstack-onstack-flag-accepted",
        sys(
            Sysno::sigaltstack,
            &[
                addr(&StackT {
                    flags: SS_ONSTACK,
                    ..alt
                }),
                0,
            ],
        ),
        Ok(0),
    );
    t.eq("altstack-onstack-flag-not-stored", sigaltstack_now(), alt);
    for (name, flags) in [("flag-4", 4), ("flag-8", 8)] {
        t.eq(
            format_args!("altstack-bad-flags-{name}"),
            sys(Sysno::sigaltstack, &[addr(&StackT { flags, ..alt }), 0]),
            Err(Errno::EINVAL),
        );
    }
    t.eq(
        "altstack-fault-new",
        sys(Sysno::sigaltstack, &[BAD, 0]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "altstack-fault-old",
        sys(Sysno::sigaltstack, &[0, BAD]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "altstack-null-null",
        sys(Sysno::sigaltstack, &[0, 0]),
        Ok(0),
    );
    t.eq(
        "altstack-reinstall",
        sys(Sysno::sigaltstack, &[addr(&alt), 0]),
        Ok(0),
    );
    // A handler with SA_ONSTACK runs on the alternate stack, and the kernel says so.
    let _ = install(SIGUSR1, h_record, SA_SIGINFO | SA_ONSTACK, 0);
    let _ = kill(SIGUSR1);
    let sp = SP_IN.load(Relaxed) as u64;
    t.holds(
        "altstack-handler-runs-on-it",
        (base..base + 4 * PAGE as u64).contains(&sp),
        sp,
        "inside the alternate stack",
    );
    t.eq(
        "altstack-in-handler-query",
        (
            SS_IN[0].load(Relaxed),
            SS_IN[1].load(Relaxed),
            SS_IN[2].load(Relaxed),
        ),
        (base, 1, (4 * PAGE) as u64),
    );
    // The frame records the interrupted context's stack state (not on the alternate stack: flags 0).
    t.eq(
        "altstack-ucontext-stack",
        (
            uc_word(UC_STACK_SP),
            uc_word(UC_STACK_FLAGS) as u32,
            uc_word(UC_STACK_SIZE),
        ),
        (base, 0, (4 * PAGE) as u64),
    );
    t.eq("altstack-after-handler", sigaltstack_now(), alt);
    // Without SA_ONSTACK the handler stays on the normal stack.
    reset_records();
    let _ = install(SIGUSR1, h_record, SA_SIGINFO, 0);
    let _ = kill(SIGUSR1);
    let sp = SP_IN.load(Relaxed) as u64;
    t.eq(
        "altstack-unused-without-flag",
        (
            (base..base + 4 * PAGE as u64).contains(&sp),
            SS_IN[1].load(Relaxed),
        ),
        (false, 0),
    );
    // Changing it while running on it is EPERM; SS_DISABLE too.
    // (verified through the nested handler below.)
    // SS_AUTODISARM: the stack is disarmed inside the handler and re-armed on return.
    t.eq(
        "altstack-autodisarm-set",
        sys(
            Sysno::sigaltstack,
            &[
                addr(&StackT {
                    flags: SS_AUTODISARM,
                    ..alt
                }),
                0,
            ],
        ),
        Ok(0),
    );
    t.eq(
        "altstack-autodisarm-get",
        sigaltstack_now(),
        StackT {
            flags: SS_AUTODISARM,
            ..alt
        },
    );
    reset_records();
    let _ = install(SIGUSR1, h_record, SA_SIGINFO | SA_ONSTACK, 0);
    let _ = kill(SIGUSR1);
    let sp = SP_IN.load(Relaxed) as u64;
    t.holds(
        "altstack-autodisarm-handler-on-stack",
        (base..base + 4 * PAGE as u64).contains(&sp),
        sp,
        "inside the alternate stack",
    );
    t.eq(
        "altstack-autodisarm-in-handler",
        (
            SS_IN[0].load(Relaxed),
            SS_IN[1].load(Relaxed),
            SS_IN[2].load(Relaxed),
        ),
        (0, u64::from(SS_DISABLE), 0),
    );
    t.eq(
        "altstack-autodisarm-rearmed",
        sigaltstack_now(),
        StackT {
            flags: SS_AUTODISARM,
            ..alt
        },
    );
    // Disabling.
    t.eq(
        "altstack-disable",
        sys(
            Sysno::sigaltstack,
            &[
                addr(&StackT {
                    flags: SS_DISABLE,
                    ..alt
                }),
                0,
            ],
        ),
        Ok(0),
    );
    t.eq(
        "altstack-disabled-query",
        sigaltstack_now(),
        StackT {
            sp: 0,
            flags: SS_DISABLE,
            pad: 0,
            size: 0,
        },
    );
    clean();
}

fn waiting(t: &mut T) {
    clean();
    let _ = install(SIGUSR1, h_record, SA_SIGINFO, 0);
    // rt_sigtimedwait takes a blocked pending signal without running the handler.
    let _ = procmask(SIG_BLOCK, Some(bit(SIGUSR1)), None);
    let _ = kill(SIGUSR1);
    let mut info = [0u64; 16];
    let set = bit(SIGUSR1);
    let zero = [0i64; 2];
    t.eq(
        "sigtimedwait-pending",
        (
            sys(
                Sysno::rt_sigtimedwait,
                &[addr(&set), addr_mut(&mut info), addr(&zero), 8],
            ),
            info[0] as i32,
            (info[1] >> 32) as i32,
            (info[2] & 0xffff_ffff) as i32,
        ),
        (Ok(SIGUSR1), SIGUSR1 as i32, SI_USER, 1),
    );
    t.eq(
        "sigtimedwait-consumed",
        (pending(), COUNT.load(Relaxed)),
        (0, 0),
    );
    t.eq(
        "sigtimedwait-none-poll",
        sys(Sysno::rt_sigtimedwait, &[addr(&set), 0, addr(&zero), 8]),
        Err(Errno::EAGAIN),
    );
    let ten_ms = [0i64, 10_000_000];
    let start = now_ns();
    t.eq(
        "sigtimedwait-timeout",
        sys(Sysno::rt_sigtimedwait, &[addr(&set), 0, addr(&ten_ms), 8]),
        Err(Errno::EAGAIN),
    );
    let waited = now_ns() - start;
    t.holds(
        "sigtimedwait-timeout-elapsed",
        (10_000_000..500_000_000).contains(&waited),
        waited,
        "10 ms <= wait < 500 ms",
    );
    t.eq(
        "sigtimedwait-bad-size",
        sys(Sysno::rt_sigtimedwait, &[addr(&set), 0, addr(&zero), 4]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sigtimedwait-bad-nsec",
        sys(
            Sysno::rt_sigtimedwait,
            &[addr(&set), 0, addr(&[0i64, 1_000_000_000]), 8],
        ),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sigtimedwait-fault-set",
        sys(Sysno::rt_sigtimedwait, &[BAD, 0, addr(&zero), 8]),
        Err(Errno::EFAULT),
    );
    // A signal that arrives while waiting wakes rt_sigtimedwait too.
    arm_timer_ms(20);
    let alrm = bit(SIGALRM);
    let _ = procmask(SIG_BLOCK, Some(alrm), None);
    let five_s = [5i64, 0];
    let start = now_ns();
    t.eq(
        "sigtimedwait-wakes-on-signal",
        sys(Sysno::rt_sigtimedwait, &[addr(&alrm), 0, addr(&five_s), 8]),
        Ok(SIGALRM),
    );
    let waited = now_ns() - start;
    t.holds(
        "sigtimedwait-woke-early",
        (15_000_000..2_000_000_000).contains(&waited),
        waited,
        "about 20 ms",
    );
    let _ = procmask(SIG_SETMASK, Some(0), None);
    // rt_sigsuspend: replaces the mask until a handled signal arrives, then EINTR and the old mask.
    reset_records();
    let _ = install(SIGALRM, h_record, SA_SIGINFO, 0);
    let _ = procmask(SIG_SETMASK, Some(bit(SIGALRM) | bit(SIGUSR2)), None);
    arm_timer_ms(20);
    let open = bit(SIGUSR2);
    t.eq(
        "sigsuspend-eintr",
        sys(Sysno::rt_sigsuspend, &[addr(&open), 8]),
        Err(Errno::EINTR),
    );
    t.eq(
        "sigsuspend-handler-ran",
        (COUNT.load(Relaxed), SIGNO_ARG.load(Relaxed)),
        (1, SIGALRM as u64),
    );
    t.eq(
        "sigsuspend-handler-saw-temporary-mask",
        MASK_IN.load(Relaxed),
        bit(SIGALRM) | bit(SIGUSR2),
    );
    t.eq(
        "sigsuspend-restores-mask",
        mask_now(),
        bit(SIGALRM) | bit(SIGUSR2),
    );
    t.eq(
        "sigsuspend-bad-size",
        sys(Sysno::rt_sigsuspend, &[addr(&open), 4]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sigsuspend-fault",
        sys(Sysno::rt_sigsuspend, &[BAD, 8]),
        Err(Errno::EFAULT),
    );
    let _ = procmask(SIG_SETMASK, Some(0), None);
    // pause().
    reset_records();
    arm_timer_ms(20);
    t.eq("pause-eintr", sys(Sysno::pause, &[]), Err(Errno::EINTR));
    t.eq("pause-handler-ran", COUNT.load(Relaxed), 1);
    clean();
}

fn now_ns() -> i64 {
    let mut ts = [0i64; 2];
    let _ = sys(Sysno::clock_gettime, &[1, addr_mut(&mut ts)]);
    ts[0] * 1_000_000_000 + ts[1]
}

fn interruption(t: &mut T) {
    clean();
    // nanosleep is interrupted by a handled signal, never restarted into the same call
    // (ERESTART_RESTARTBLOCK becomes EINTR when a handler runs), and reports the time left.
    for (name, flags) in [("plain", 0), ("restart", SA_RESTART)] {
        reset_records();
        let _ = install(SIGALRM, h_record, SA_SIGINFO | flags, 0);
        arm_timer_ms(20);
        let mut rem = [0i64; 2];
        let five = [5i64, 0];
        let r = sys(Sysno::nanosleep, &[addr(&five), addr_mut(&mut rem)]);
        t.eq(
            format_args!("nanosleep-interrupted-{name}"),
            (r, COUNT.load(Relaxed)),
            (Err(Errno::EINTR), 1),
        );
        t.holds(
            format_args!("nanosleep-remaining-{name}"),
            rem[0] == 4 && rem[1] > 900_000_000,
            rem,
            "about 4.98 s left",
        );
    }
    // A blocking read: EINTR without SA_RESTART, transparently restarted with it (here the
    // handler supplies the data the restarted read then gets).
    let mut fds = [0u32; 2];
    let _ = sys(Sysno::pipe2, &[addr_mut(&mut fds), 0]);
    let (rfd, wfd) = (fds[0] as usize, fds[1] as usize);
    VALUES[7].store(wfd as u64, Relaxed);
    let mut buf = [0u8; 4];
    reset_records();
    VALUES[7].store(wfd as u64, Relaxed);
    let _ = install(SIGALRM, h_record, SA_SIGINFO, 0);
    arm_timer_ms(20);
    t.eq(
        "read-eintr-without-restart",
        sys(Sysno::read, &[rfd, addr_mut(&mut buf), 4]),
        Err(Errno::EINTR),
    );
    t.eq("read-eintr-handler-ran", COUNT.load(Relaxed), 1);
    reset_records();
    VALUES[7].store(wfd as u64, Relaxed);
    let _ = install(SIGALRM, h_write_pipe, SA_SIGINFO | SA_RESTART, 0);
    arm_timer_ms(20);
    t.eq(
        "read-restarted-with-sa_restart",
        (sys(Sysno::read, &[rfd, addr_mut(&mut buf), 4]), buf[0]),
        (Ok(1), b'z'),
    );
    t.eq("read-restart-handler-ran-once", COUNT.load(Relaxed), 1);
    let _ = sys(Sysno::close, &[rfd]);
    let _ = sys(Sysno::close, &[wfd]);
    // The timer: one-shot delivery, then nothing pending.
    t.eq("itimer-expired", pending(), 0);
    clean();
}

fn init_special(t: &mut T) {
    clean();
    // Pid 1 ignores signals it has no handler for, even SIGKILL and SIGSTOP from itself
    // (SIGNAL_UNKILLABLE, `sig_task_ignored`); nothing is queued.
    for (name, sig) in [
        ("sigkill", SIGKILL),
        ("sigstop", SIGSTOP),
        ("sigterm", SIGTERM),
        ("sigusr1", SIGUSR1),
    ] {
        t.eq(
            format_args!("init-ignores-{name}"),
            (kill(sig), pending()),
            (Ok(0), 0),
        );
    }
    // ... but a blocked default-action signal is queued, not dropped.
    let _ = procmask(SIG_BLOCK, Some(bit(SIGUSR1)), None);
    t.eq(
        "blocked-default-signal-queued",
        (kill(SIGUSR1), pending()),
        (Ok(0), bit(SIGUSR1)),
    );
    let _ = ignore(SIGUSR1);
    t.eq("blocked-then-ignored-discarded", pending(), 0);
    clean();
}
