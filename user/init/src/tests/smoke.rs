// SPDX-License-Identifier: GPL-2.0-only
//! `signals` mode: a short, self-contained signal-delivery smoke test for the kernel's own
//! `kernel-test` case. Unlike the oracle `signal` group it needs only syscalls that exist on every
//! branch (`rt_sigaction`, `rt_sigprocmask`, `rt_sigpending`, `kill`, `setitimer`, `pause`,
//! `rt_sigsuspend`, `rt_sigtimedwait`, `sigaltstack`, `write`, `getpid`), and it checks the
//! delivery mechanism rather than Linux's error table: handler entry and return, the siginfo of
//! `kill`, a synchronous fault recovered by the handler (`#PF`, `#UD`, `#DE`), an interval timer
//! interrupting a busy loop in ring 3, `pause`/`rt_sigsuspend`/`rt_sigtimedwait` waking, and the
//! alternate signal stack. On Linux it prints the same line, so it is also an oracle run.
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
    timer_ms(20, 0);
    while FLAG.load(Relaxed) == 0 {
        core::hint::spin_loop();
    }
    expect("itimer-spin-signo", SIGNO.load(Relaxed), SIGALRM as u64);
    expect("itimer-spin-code", CODE.load(Relaxed), SI_KERNEL as u64);

    // 5. pause() sleeps until the timer's signal, runs the handler and fails with EINTR.
    reset();
    timer_ms(20, 0);
    expect("pause", sys(Sysno::pause, &[]), Err(Errno::EINTR));
    expect("pause-handler", COUNT.load(Relaxed), 1);

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
    expect(
        "sigtimedwait-timeout",
        sys(Sysno::rt_sigtimedwait, &[addr(&set), 0, addr(&ten_ms), 8]),
        Err(Errno::EAGAIN),
    );
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

    super::emit(format_args!("init: signals ok"));
}
