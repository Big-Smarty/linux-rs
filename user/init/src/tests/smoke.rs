// SPDX-License-Identifier: GPL-2.0-only
//! `signals` mode: a short, self-contained signal-delivery smoke test for the kernel's own
//! `kernel-test` case. Unlike the oracle `signal` group it needs only syscalls that exist on every
//! branch (`rt_sigaction`, `rt_sigprocmask`, `rt_sigpending`, `kill`, `setitimer`, `pause`,
//! `rt_sigsuspend`, `rt_sigtimedwait`, `sigaltstack`, `write`, `getpid`), and it checks the
//! delivery mechanism rather than Linux's error table: handler entry and return, the siginfo of
//! `kill`, a synchronous fault recovered by the handler (`#PF`, `#UD`, `#DE`), an interval timer
//! interrupting a busy loop in ring 3, `pause`/`rt_sigsuspend`/`rt_sigtimedwait` waking, and the
//! alternate signal stack. Timing is checked against the TSC, calibrated by the 20 ms busy-loop
//! timer of check 4 (a wait that returns at once must not pass). On Linux it prints the same
//! line, so it is also an oracle run.
//! Any mismatch exits with status 1 after printing `init: FAIL <check> got=<value>`.

use super::{
    addr, addr_mut, fn_addr, getpid,
    signal::{KSigaction, SA_RESTORER, SA_SIGINFO, bit, restorer},
    sys,
};
use crate::expect;
use core::arch::asm;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
use syscalls::{Errno, Sysno};

const SIGUSR1: usize = 10;
const SIGSEGV: usize = 11;
const SIGALRM: usize = 14;
const SIGFPE: usize = 8;
const SIGILL: usize = 4;
const SA_ONSTACK: u64 = 0x0800_0000;
const SIG_BLOCK: usize = 0;
const SIG_SETMASK: usize = 2;
const SI_USER: i32 = 0;
const SI_KERNEL: i32 = 0x80;
const SEGV_MAPERR: i32 = 1;

/// `ucontext` word index of `uc_mcontext.rip` (`gregs[REG_RIP]` at byte `40 + 8 * 16`).
const UC_RIP: usize = (40 + 8 * 16) / 8;
const UC_STACK_SP: usize = 2;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Itimerval {
    interval: [i64; 2],
    value: [i64; 2],
}

/// Which part of the interrupted state `corrupt` damages before the handler returns (`BAD_*`).
static CORRUPT: AtomicU64 = AtomicU64::new(0);
static SAVED_RIP: AtomicU64 = AtomicU64::new(0);
static SAVED_SEGS: AtomicU64 = AtomicU64::new(0);
const BAD_RIP: u64 = 1;
const BAD_CS: u64 = 2;
const BAD_SS: u64 = 3;
/// A non-canonical `rsp`: `iretq` to ring 3 loads it without a check (it faults only on the first
/// stack access), so Linux resumes user mode with it.
const BAD_SP: u64 = 4;
/// A compatibility-mode `cs` with a `rip` beyond its 4 GiB limit: `#GP(0)` at the `iretq`.
const BAD_CS32: u64 = 5;
const UC_SP: usize = (40 + 8 * 15) / 8;
const NONCANONICAL_SP: u64 = 0x8bad_f00d_5aad_c0de;
/// `ucontext` word holding `cs`, `gs`, `fs`, `ss` (`sigcontext` bytes 144..152).
const UC_SEGS: usize = (40 + 144) / 8;

static ERR: AtomicU64 = AtomicU64::new(0);
static TRAPNO: AtomicU64 = AtomicU64::new(0);
/// `ucontext` words of `sigcontext.err` and `.trapno` (`gregs[REG_ERR]`, `gregs[REG_TRAPNO]`).
const UC_ERR: usize = (40 + 8 * 19) / 8;
const UC_TRAPNO: usize = UC_ERR + 1;

static COUNT: AtomicUsize = AtomicUsize::new(0);
static SIGNO: AtomicU64 = AtomicU64::new(0);
static CODE: AtomicU64 = AtomicU64::new(0);
static PID: AtomicU64 = AtomicU64::new(0);
static ADDRESS: AtomicU64 = AtomicU64::new(0);
static SKIP: AtomicU64 = AtomicU64::new(0);
static ON_ALT: AtomicUsize = AtomicUsize::new(0);
static FLAG: AtomicUsize = AtomicUsize::new(0);

#[repr(C, align(4096))]
struct Altstack([u8; 16384]);
static mut ALT: Altstack = Altstack([0; 16384]);

fn alt_range() -> (usize, usize) {
    let base = core::ptr::addr_of!(ALT).addr();
    (base, base + 16384)
}

/// Records what the handler was given; a fault handler also steps over the faulting instruction
/// (`SKIP` bytes) so the interrupted code continues after it.
extern "C" fn handler(sig: i32, info: *const u64, uc: *mut u64) {
    COUNT.fetch_add(1, Relaxed);
    SIGNO.store(sig as u64, Relaxed);
    // SAFETY: `info` is the 128-byte siginfo and `uc` the ucontext the kernel just built on this
    // stack (SA_SIGINFO); the offsets are the uapi layout.
    unsafe {
        CODE.store(u64::from(info.add(1).read() as u32), Relaxed);
        PID.store(info.add(2).read() & 0xffff_ffff, Relaxed);
        ADDRESS.store(info.add(2).read(), Relaxed);
        let marker = 0u8;
        let sp = core::ptr::addr_of!(marker).addr();
        let (lo, hi) = alt_range();
        ON_ALT.store(usize::from(sp >= lo && sp < hi), Relaxed);
        ERR.store(uc.add(UC_ERR).read(), Relaxed);
        TRAPNO.store(uc.add(UC_TRAPNO).read(), Relaxed);
        let skip = SKIP.swap(0, Relaxed);
        if skip != 0 {
            let rip = uc.add(UC_RIP);
            rip.write(rip.read() + skip);
        }
        // The kernel reports the stack it switched from, not the alternate one, in `uc_stack`.
        let _ = uc.add(UC_STACK_SP).read();
    }
    FLAG.store(1, Relaxed);
}

/// Handler that returns a damaged state to `rt_sigreturn`: a non-canonical `rip`, a kernel `cs` or a
/// null `ss`, each of which makes the CPU refuse the return to ring 3. Linux turns that into a
/// `SIGSEGV` (`SI_KERNEL`) of the same task; `repair` (the SIGSEGV handler) then puts the saved
/// state back.
extern "C" fn corrupt(sig: i32, info: *const u64, uc: *mut u64) {
    handler(sig, info, uc);
    // SAFETY: `uc` is the ucontext the kernel built on this stack.
    unsafe {
        SAVED_RIP.store(uc.add(UC_RIP).read(), Relaxed);
        SAVED_SEGS.store(uc.add(UC_SEGS).read(), Relaxed);
        match CORRUPT.load(Relaxed) {
            BAD_RIP => uc.add(UC_RIP).write(0x8000_0000_0000_0000),
            BAD_CS => uc
                .add(UC_SEGS)
                .write(SAVED_SEGS.load(Relaxed) & !0xffff | 0x10),
            BAD_SP => uc.add(UC_SP).write(NONCANONICAL_SP),
            BAD_CS32 => {
                uc.add(UC_SEGS)
                    .write(SAVED_SEGS.load(Relaxed) & !0xffff | 0x23);
                uc.add(UC_RIP).write(0x1_0000_0000);
            }
            _ => uc
                .add(UC_SEGS)
                .write(SAVED_SEGS.load(Relaxed) & 0x0000_ffff_ffff_ffff),
        }
    }
}

/// The `SIGSEGV` handler of the bad-return checks: restore what `corrupt` saved.
extern "C" fn repair(sig: i32, info: *const u64, uc: *mut u64) {
    handler(sig, info, uc);
    // SAFETY: as in `corrupt`.
    unsafe {
        uc.add(UC_RIP).write(SAVED_RIP.load(Relaxed));
        uc.add(UC_SEGS).write(SAVED_SEGS.load(Relaxed));
    }
}

/// The stack pointer the asm blocks below save before they point `rsp` somewhere bad, and the one
/// they observed after a return.
static SAVED_SP: AtomicU64 = AtomicU64::new(0);
static OBSERVED_SP: AtomicU64 = AtomicU64::new(0);

/// `SIGSEGV` handler for the asm blocks below: records the signal, then puts the saved `rsp` back.
extern "C" fn fix_sp(sig: i32, info: *const u64, uc: *mut u64) {
    handler(sig, info, uc);
    // SAFETY: `uc` is the ucontext the kernel built on this stack.
    unsafe { uc.add(UC_SP).write(SAVED_SP.load(Relaxed)) };
}

/// `kill(getpid(), SIGUSR1)` whose handler returns a non-canonical `rsp`: the stack pointer user
/// mode resumes with is the first thing read back.
fn kill_observe_sp() {
    // SAFETY: `syscall` clobbers rax/rcx/r11 only (declared); `rsp` is saved before and restored
    // after, and between the `syscall` and the restore only `rsp` is stored, never used for
    // memory access, so a bad `rsp` cannot fault. The kernel pushes the handler frame below
    // `rsp - 128` (the red zone), and no stack memory is used by this block.
    unsafe {
        asm!(
            "mov [rip + {saved}], rsp",
            "syscall",
            "mov [rip + {seen}], rsp",
            "mov rsp, [rip + {saved}]",
            saved = sym SAVED_SP,
            seen = sym OBSERVED_SP,
            inout("rax") Sysno::kill as usize => _,
            in("rdi") getpid(),
            in("rsi") SIGUSR1,
            out("rcx") _,
            out("r11") _,
        );
    }
}

/// `rt_sigreturn` with `rsp` at an unmapped page: Linux prints `bad frame in rt_sigreturn` and
/// forces `SIGSEGV`; `fix_sp` (on the alternate stack) restores `rsp`.
fn sigreturn_bad_frame() {
    // SAFETY: as in `kill_observe_sp`: only rax/rcx/r11 are clobbered, `rsp` is restored by the
    // SIGSEGV handler through the saved context before user code runs again, and nothing in the
    // block touches the stack.
    unsafe {
        asm!(
            "mov [rip + {saved}], rsp",
            "mov rsp, {bad}",
            "syscall",
            saved = sym SAVED_SP,
            bad = in(reg) 0x1000usize,
            inout("rax") Sysno::rt_sigreturn as usize => _,
            out("rcx") _,
            out("r11") _,
        );
    }
}

fn tsc() -> u64 {
    // SAFETY: `rdtsc` is available in ring 3 (CR4.TSD is clear on both kernels).
    unsafe { core::arch::x86_64::_rdtsc() }
}

fn install_fn(sig: usize, f: extern "C" fn(i32, *const u64, *mut u64), flags: u64) {
    let sa = KSigaction {
        handler: fn_addr(f as *const ()),
        flags: SA_SIGINFO | SA_RESTORER | flags,
        restorer: fn_addr(restorer as *const ()),
        mask: 0,
    };
    expect(
        "rt_sigaction",
        sys(Sysno::rt_sigaction, &[sig, addr(&sa), 0, 8]),
        Ok(0),
    );
}

fn install(sig: usize, flags: u64) {
    let sa = KSigaction {
        handler: fn_addr(handler as *const ()),
        flags: SA_SIGINFO | SA_RESTORER | flags,
        restorer: fn_addr(restorer as *const ()),
        mask: 0,
    };
    expect(
        "rt_sigaction",
        sys(Sysno::rt_sigaction, &[sig, addr(&sa), 0, 8]),
        Ok(0),
    );
}

fn reset() {
    COUNT.store(0, Relaxed);
    SIGNO.store(0, Relaxed);
    CODE.store(0xffff, Relaxed);
    FLAG.store(0, Relaxed);
}

/// `started` (a TSC value) to now is at least 3/4 of `want_ms` milliseconds (`ms` TSC ticks each)
/// and not absurdly more.
fn elapsed(check: &str, started: u64, ms: u64, want_ms: u64) {
    let took = tsc() - started;
    expect(
        format_args!("{check}-not-early"),
        took >= want_ms * ms * 3 / 4,
        true,
    );
    expect(
        format_args!("{check}-not-late"),
        took < want_ms * ms * 50,
        true,
    );
}

fn timer_ms(ms: i64, interval_ms: i64) {
    let it = Itimerval {
        interval: [0, interval_ms * 1000],
        value: [0, ms * 1000],
    };
    expect(
        "setitimer",
        sys(Sysno::setitimer, &[0, addr(&it), 0]),
        Ok(0),
    );
}

/// One `rt_sigreturn` with a state the CPU refuses to `iret` to (`kind`, `corrupt`): SIGUSR1's
/// handler runs, then SIGSEGV's (`repair`) with `#GP` trap number 13 and error code `err`.
fn hostile_return(name: &str, kind: u64, err: u64) {
    reset();
    CORRUPT.store(kind, Relaxed);
    expect(
        "bad-return-kill",
        sys(Sysno::kill, &[getpid(), SIGUSR1]),
        Ok(0),
    );
    // SIGUSR1's handler ran, then the return failed and SIGSEGV's handler ran.
    expect(name, COUNT.load(Relaxed), 2);
    expect(name, SIGNO.load(Relaxed), SIGSEGV as u64);
    expect(name, CODE.load(Relaxed), SI_KERNEL as u64);
    expect(name, TRAPNO.load(Relaxed), 13);
    expect(name, ERR.load(Relaxed), err);
}

/// The hypervisor signature of QEMU's TCG (`TCGTCGTCGTCG`, CPUID leaf 0x4000_0000).
fn under_tcg() -> bool {
    // SAFETY: CPUID is available in ring 3 on every x86-64 CPU.
    let leaf = unsafe { core::arch::x86_64::__cpuid(0x4000_0000) };
    [leaf.ebx, leaf.ecx, leaf.edx]
        == [b"TCGT", b"CGTC", b"GTCG"].map(|word| u32::from_le_bytes(*word))
}

pub fn run() {
    // 1. kill(getpid()) runs the handler with the right arguments, then execution resumes here.
    install(SIGUSR1, 0);
    reset();
    expect("kill", sys(Sysno::kill, &[getpid(), SIGUSR1]), Ok(0));
    expect("kill-handler", COUNT.load(Relaxed), 1);
    expect("kill-signo", SIGNO.load(Relaxed), SIGUSR1 as u64);
    expect("kill-code", CODE.load(Relaxed), SI_USER as u64);
    expect("kill-pid", PID.load(Relaxed), getpid() as u64);

    // 2. A blocked signal waits in the pending set and is delivered on unblock.
    reset();
    let blocked = bit(SIGUSR1);
    let mut old = 0u64;
    let r = sys(
        Sysno::rt_sigprocmask,
        &[SIG_BLOCK, addr(&blocked), addr_mut(&mut old), 8],
    );
    expect("sigprocmask-block", r, Ok(0));
    expect(
        "blocked-kill",
        sys(Sysno::kill, &[getpid(), SIGUSR1]),
        Ok(0),
    );
    expect("blocked-not-run", COUNT.load(Relaxed), 0);
    let mut pending = 0u64;
    let _ = sys(Sysno::rt_sigpending, &[addr_mut(&mut pending), 8]);
    expect("blocked-pending", pending, blocked);
    expect(
        "sigprocmask-unblock",
        sys(Sysno::rt_sigprocmask, &[SIG_SETMASK, addr(&old), 0, 8]),
        Ok(0),
    );
    expect("unblock-delivers", COUNT.load(Relaxed), 1);

    // 3. Synchronous faults are signals; the handler steps over the instruction and the code
    //    after it runs (page fault, invalid opcode, divide error).
    install(SIGSEGV, 0);
    reset();
    SKIP.store(3, Relaxed);
    // SAFETY: a deliberate read of the unmapped page 0 (`mov rax, [rcx]` is 3 bytes); the SIGSEGV
    // handler advances `rip` by 3, so execution continues after it. Only `rax` is written.
    unsafe {
        asm!("mov rax, [rcx]", in("rcx") 0usize, out("rax") _, options(nostack));
    }
    expect("segv-handler", COUNT.load(Relaxed), 1);
    expect("segv-signo", SIGNO.load(Relaxed), SIGSEGV as u64);
    expect("segv-code", CODE.load(Relaxed), SEGV_MAPERR as u64);
    expect("segv-addr", ADDRESS.load(Relaxed), 0);

    install(SIGILL, 0);
    reset();
    SKIP.store(2, Relaxed);
    // SAFETY: `ud2` (2 bytes) raises #UD; the SIGILL handler advances `rip` past it.
    unsafe {
        asm!("ud2", options(nostack));
    }
    expect("ill-handler", COUNT.load(Relaxed), 1);
    expect("ill-signo", SIGNO.load(Relaxed), SIGILL as u64);

    install(SIGFPE, 0);
    reset();
    SKIP.store(2, Relaxed);
    // SAFETY: `div ecx` with ecx = 0 (2 bytes) raises #DE; the SIGFPE handler advances `rip` past
    // it. Writes eax/edx.
    unsafe {
        asm!("div ecx", in("ecx") 0u32, inout("eax") 1u32 => _, out("edx") _, options(nostack));
    }
    expect("fpe-handler", COUNT.load(Relaxed), 1);
    expect("fpe-signo", SIGNO.load(Relaxed), SIGFPE as u64);

    // 4. An interval timer interrupts a busy loop in ring 3 (delivery on interrupt return).
    install(SIGALRM, 0);
    reset();
    let started = tsc();
    timer_ms(20, 0);
    while FLAG.load(Relaxed) == 0 {
        core::hint::spin_loop();
    }
    // The 20 ms spin calibrates the TSC for the timing checks below.
    let ms = (tsc() - started) / 20;
    expect("itimer-spin-signo", SIGNO.load(Relaxed), SIGALRM as u64);
    expect("itimer-spin-code", CODE.load(Relaxed), SI_KERNEL as u64);
    // Not early, and not minutes late (a wake-up that never comes would hang, not fail).
    expect("itimer-spin-late", tsc() - started < 100 * ms, true);

    // 5. pause() sleeps until the timer's signal, runs the handler and fails with EINTR, after the
    //    timer's 20 ms (not at once).
    reset();
    let started = tsc();
    timer_ms(20, 0);
    expect("pause", sys(Sysno::pause, &[]), Err(Errno::EINTR));
    expect("pause-handler", COUNT.load(Relaxed), 1);
    elapsed("pause", started, ms, 20);

    // 6. rt_sigsuspend swaps the mask for the wait and restores it afterwards.
    reset();
    let alarm_blocked = bit(SIGALRM);
    let _ = sys(
        Sysno::rt_sigprocmask,
        &[SIG_SETMASK, addr(&alarm_blocked), 0, 8],
    );
    timer_ms(20, 0);
    let open = 0u64;
    expect(
        "sigsuspend",
        sys(Sysno::rt_sigsuspend, &[addr(&open), 8]),
        Err(Errno::EINTR),
    );
    expect("sigsuspend-handler", COUNT.load(Relaxed), 1);
    let mut mask = 0u64;
    let _ = sys(
        Sysno::rt_sigprocmask,
        &[SIG_BLOCK, 0, addr_mut(&mut mask), 8],
    );
    expect("sigsuspend-mask-restored", mask, alarm_blocked);

    // 7. rt_sigtimedwait: a poll finds nothing, a timeout expires, and the awaited blocked signal
    //    wakes the wait without running its handler.
    reset();
    let zero = [0i64; 2];
    let set = bit(SIGALRM);
    expect(
        "sigtimedwait-poll",
        sys(Sysno::rt_sigtimedwait, &[addr(&set), 0, addr(&zero), 8]),
        Err(Errno::EAGAIN),
    );
    let ten_ms = [0i64, 10_000_000];
    let started = tsc();
    expect(
        "sigtimedwait-timeout",
        sys(Sysno::rt_sigtimedwait, &[addr(&set), 0, addr(&ten_ms), 8]),
        Err(Errno::EAGAIN),
    );
    elapsed("sigtimedwait-timeout", started, ms, 10);
    timer_ms(20, 0);
    let five_s = [5i64, 0];
    let mut info = [0u64; 16];
    expect(
        "sigtimedwait-wakes",
        sys(
            Sysno::rt_sigtimedwait,
            &[addr(&set), addr_mut(&mut info), addr(&five_s), 8],
        ),
        Ok(SIGALRM),
    );
    expect("sigtimedwait-no-handler", COUNT.load(Relaxed), 0);
    expect("sigtimedwait-info", info[0] as i32, SIGALRM as i32);
    let _ = sys(Sysno::rt_sigprocmask, &[SIG_SETMASK, addr(&0u64), 0, 8]);

    // 7a. Interval timers: getitimer reports the remaining time, alarm returns the previous
    //     alarm's remaining seconds, a periodic timer keeps delivering, and timers of a few
    //     microseconds (expiring around the return to ring 3) are not lost. The window of the
    //     `exit_to_user` race this guards (an expiry between its clock reads) is tens of
    //     nanoseconds wide: 3000 rounds with the fix disabled did not hit it, so this proves
    //     the sub-tick timer path, not the race fix.
    reset();
    timer_ms(500, 0);
    let mut now = Itimerval::default();
    expect(
        "getitimer",
        sys(Sysno::getitimer, &[0, addr_mut(&mut now)]),
        Ok(0),
    );
    expect("getitimer-sec", now.value[0], 0);
    expect(
        "getitimer-usec",
        (400_000..=500_000).contains(&now.value[1]),
        true,
    );
    expect("getitimer-interval", now.interval, [0, 0]);
    expect("alarm-previous", sys(Sysno::alarm, &[2]), Ok(1));
    expect("alarm-remaining", sys(Sysno::alarm, &[0]), Ok(2));
    expect("alarm-quiet", COUNT.load(Relaxed), 0);
    reset();
    let started = tsc();
    timer_ms(5, 5);
    while COUNT.load(Relaxed) < 3 {
        core::hint::spin_loop();
    }
    timer_ms(0, 0);
    elapsed("periodic", started, ms, 13);
    expect("periodic-late", tsc() - started < 100 * ms, true);
    for round in 0..300usize {
        reset();
        let started = tsc();
        let it = Itimerval {
            interval: [0, 0],
            value: [0, 1 + (round % 60) as i64],
        };
        expect(
            "setitimer",
            sys(Sysno::setitimer, &[0, addr(&it), 0]),
            Ok(0),
        );
        while FLAG.load(Relaxed) == 0 && tsc() - started < 500 * ms {
            core::hint::spin_loop();
        }
        expect("tiny-timer-lost", FLAG.load(Relaxed), 1);
    }

    // 7b. A handler that returns a state the CPU would refuse to `iret` to (hostile `rt_sigreturn`
    //     frame): the kernel must survive and raise SIGSEGV for the task instead.
    install_fn(SIGUSR1, corrupt, 0);
    install_fn(SIGSEGV, repair, 0);
    // (name, damage, the #GP error code the CPU reports: the bad selector, 0 for a bad address).
    for (name, kind) in [("rip", BAD_RIP), ("cs", BAD_CS), ("ss", BAD_SS)] {
        hostile_return(name, kind, if kind == BAD_CS { 0x10 } else { 0 });
    }
    // A compatibility-mode `rip` beyond the 4 GiB segment limit is refused by real CPUs (KVM and
    // hardware: `#GP(0)` at the `iretq`); QEMU's TCG does not check the limit and runs the
    // truncated 32-bit state instead, so the case only means something elsewhere.
    if !under_tcg() {
        hostile_return("cs32-rip-beyond-limit", BAD_CS32, 0);
    }

    // A non-canonical `rsp` is not refused by `iretq`: user mode resumes with it.
    install_fn(SIGUSR1, corrupt, 0);
    reset();
    CORRUPT.store(BAD_SP, Relaxed);
    kill_observe_sp();
    expect("bad-sp-handler", COUNT.load(Relaxed), 1);
    expect("bad-sp-resumed", OBSERVED_SP.load(Relaxed), NONCANONICAL_SP);
    install(SIGUSR1, 0);
    install(SIGSEGV, 0);

    // 8. SA_ONSTACK runs the handler on the alternate stack.
    let stack = [core::ptr::addr_of!(ALT).addr() as u64, 0, 16384];
    expect(
        "sigaltstack",
        sys(Sysno::sigaltstack, &[addr(&stack), 0]),
        Ok(0),
    );
    install(SIGUSR1, SA_ONSTACK);
    reset();
    ON_ALT.store(0, Relaxed);
    expect(
        "kill-onstack",
        sys(Sysno::kill, &[getpid(), SIGUSR1]),
        Ok(0),
    );
    expect("onstack-handler", COUNT.load(Relaxed), 1);
    expect("onstack-sp", ON_ALT.load(Relaxed), 1);

    // 9. `rt_sigreturn` with an unreadable frame: Linux prints `bad frame in rt_sigreturn` and
    //    forces SIGSEGV (`SI_KERNEL`), whose handler runs on the alternate stack.
    install_fn(SIGSEGV, fix_sp, SA_ONSTACK);
    reset();
    sigreturn_bad_frame();
    expect("bad-frame-handler", COUNT.load(Relaxed), 1);
    expect("bad-frame-signo", SIGNO.load(Relaxed), SIGSEGV as u64);
    expect("bad-frame-code", CODE.load(Relaxed), SI_KERNEL as u64);
    expect("bad-frame-onstack", ON_ALT.load(Relaxed), 1);

    super::emit(format_args!("init: signals ok"));
}
