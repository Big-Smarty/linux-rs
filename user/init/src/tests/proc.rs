// SPDX-License-Identifier: GPL-2.0-only
//! `proc` group: `fork`, `wait4`/`waitid` status encoding and errors, exit codes, orphans,
//! `SIGCHLD`, `execve` of `/init` itself, sessions/process groups, pipes and `poll`. Linux
//! 6.18.57: `kernel/fork.c`, `kernel/exit.c` (`wait_task_zombie`, `kernel_waitid`),
//! `kernel/signal.c` (`do_notify_parent`), `fs/exec.c`, `fs/pipe.c`, `fs/select.c`,
//! `kernel/sys.c` (`setsid`, `setpgid`).
//!
//! Children run in the `fork`ed copy of this program, report through their exit status or a
//! pipe, and end with `exit_group`. The `execve` check re-enters this binary as `/init execd`
//! (see [`execd`]) with stdout redirected into a pipe the parent compares byte for byte.

use core::sync::atomic::{AtomicUsize, Ordering::Relaxed};

use syscalls::{Errno, Sysno};

use super::signal::{KSigaction, SA_NOCLDWAIT, SA_RESTORER, SA_SIGINFO, bit, restorer};
use super::{R, T, addr, addr_mut, die, fn_addr, getpid, sys};
use crate::Strings;

pub(super) const BAD: usize = 0xdead_0000_0000;
pub(super) const AT_FDCWD: usize = -100isize as usize;

pub(super) const SIGHUP: usize = 1;
pub(super) const SIGABRT: usize = 6;
pub(super) const SIGKILL: usize = 9;
pub(super) const SIGUSR1: usize = 10;
pub(super) const SIGUSR2: usize = 12;
pub(super) const SIGPIPE: usize = 13;
pub(super) const SIGTERM: usize = 15;
pub(super) const SIGCHLD: usize = 17;
const SIGCONT: usize = 18;
const SIGSTOP: usize = 19;

pub(super) const WNOHANG: usize = 1;
const WUNTRACED: usize = 2;
const WCONTINUED: usize = 8;
pub(super) const WEXITED: usize = 4;
pub(super) const WNOWAIT: usize = 0x0100_0000;

const O_NONBLOCK: usize = 0o4000;
const O_CLOEXEC: usize = 0o2_000_000;

pub(super) static CHLD_COUNT: AtomicUsize = AtomicUsize::new(0);
pub(super) static CHLD_INFO: [AtomicUsize; 4] = [const { AtomicUsize::new(0) }; 4];

/// SIGCHLD handler: counts and records `si_code`, `si_pid`, `si_uid`, `si_status`.
extern "C" fn on_chld(_sig: i32, info: *const u64, _uc: *mut u64) {
    CHLD_COUNT.fetch_add(1, Relaxed);
    // SAFETY: `info` is the kernel's siginfo for the running handler (SA_SIGINFO), 16 words.
    let words = unsafe { [info.add(1).read(), info.add(2).read(), info.add(3).read()] };
    CHLD_INFO[0].store((words[0] & 0xffff_ffff) as usize, Relaxed); // si_code
    CHLD_INFO[1].store((words[1] & 0xffff_ffff) as usize, Relaxed); // si_pid
    CHLD_INFO[2].store((words[1] >> 32) as usize, Relaxed); // si_uid
    CHLD_INFO[3].store((words[2] & 0xffff_ffff) as usize, Relaxed); // si_status
}

pub(super) fn sigaction(sig: usize, handler: u64, flags: u64) -> R {
    let sa = KSigaction {
        handler,
        flags: flags | SA_RESTORER,
        restorer: fn_addr(restorer as *const ()),
        mask: 0,
    };
    sys(Sysno::rt_sigaction, &[sig, addr(&sa), 0, 8])
}

pub(super) fn on_chld_ptr() -> u64 {
    fn_addr(on_chld as *const ())
}

pub(super) fn block(mask: u64) {
    let _ = sys(Sysno::rt_sigprocmask, &[2, addr(&mask), 0, 8]);
}

/// Forks; the child runs `f` and leaves with its return value as the exit status.
pub(super) fn spawn(f: impl FnOnce() -> usize) -> usize {
    match sys(Sysno::fork, &[]) {
        Ok(0) => die(f()),
        Ok(pid) => pid,
        Err(_) => usize::MAX,
    }
}

pub(super) fn wait4(pid: isize, options: usize) -> (R, i32) {
    let mut status = -1i32;
    (
        sys(
            Sysno::wait4,
            &[pid as usize, addr_mut(&mut status), options, 0],
        ),
        status,
    )
}

pub(super) fn waitid(idtype: usize, id: usize, options: usize) -> (R, [i32; 8]) {
    let mut info = [-1i32; 32];
    let r = sys(
        Sysno::waitid,
        &[idtype, id, addr_mut(&mut info), options, 0],
    );
    (
        r,
        [
            info[0], info[1], info[2], info[4], info[5], info[6], info[3], 0,
        ],
    )
}

/// Reaps every remaining child (so one test's leftovers cannot leak into the next).
pub(super) fn reap_all() {
    while sys(Sysno::wait4, &[usize::MAX, 0, 0, 0]).is_ok() {}
}

pub(super) fn nap(ms: i64) {
    let _ = sys(Sysno::nanosleep, &[addr(&[0i64, ms * 1_000_000]), 0]);
}

pub fn run() -> bool {
    let mut t = T::new("proc");
    reap_all();
    fork_and_exit(&mut t);
    wait_errors(&mut t);
    waitid_checks(&mut t);
    signals_and_stops(&mut t);
    sigchld(&mut t);
    orphans(&mut t);
    sessions(&mut t);
    exec(&mut t);
    pipes(&mut t);
    reap_all();
    t.finish()
}

fn fork_and_exit(t: &mut T) {
    let me = getpid();
    let mut fds = [0u32; 2];
    let _ = sys(Sysno::pipe2, &[addr_mut(&mut fds), 0]);
    let (rfd, wfd) = (fds[0] as usize, fds[1] as usize);
    let child = spawn(|| {
        // Report pid, parent pid, tid and pgid through the pipe: four 8-byte words.
        let words = [
            getpid(),
            sys(Sysno::getppid, &[]).unwrap_or(usize::MAX),
            super::gettid(),
            sys(Sysno::getpgid, &[0]).unwrap_or(usize::MAX),
        ];
        let _ = sys(Sysno::write, &[wfd, addr(&words), 32]);
        7
    });
    let _ = sys(Sysno::close, &[wfd]);
    t.holds(
        "fork-returns-child-pid",
        child > 1 && child != me && child < 1 << 22,
        child,
        "a new pid > 1",
    );
    let mut words = [0usize; 4];
    let n = sys(Sysno::read, &[rfd, addr_mut(&mut words), 32]);
    t.eq(
        "child-sees-own-pid",
        (n, words[0] == child, words[2] == child),
        (Ok(32), true, true),
    );
    t.eq("child-getppid-is-parent", words[1], me);
    t.eq("child-inherits-process-group", words[3], 0);
    let (r, status) = wait4(child as isize, 0);
    t.eq("wait4-reaps-child", r, Ok(child));
    t.eq("wait4-exit-status-encoding", status, 7 << 8);
    t.eq(
        "wait4-zombie-gone",
        wait4(child as isize, 0).0,
        Err(Errno::ECHILD),
    );
    let _ = sys(Sysno::close, &[rfd]);
    for (name, code, want) in [
        ("zero", 0usize, 0i32),
        ("one", 1, 0x100),
        ("255", 255, 0xff00),
        ("256-wraps", 256, 0),
        ("300-wraps", 300, 44 << 8),
        ("minus-one", usize::MAX, 0xff00),
        ("high-bits-ignored", 0xdead_beef_0000_0042, 0x4200),
    ] {
        let child = spawn(|| code);
        t.eq(
            format_args!("exit-code-{name}"),
            wait4(child as isize, 0),
            (Ok(child), want),
        );
    }
    // `exit` (one thread) ends the process the same way as `exit_group`.
    let child = spawn(|| {
        let _ = sys(Sysno::exit, &[9]);
        0
    });
    t.eq(
        "exit-syscall-single-thread",
        wait4(child as isize, 0),
        (Ok(child), 9 << 8),
    );
    // wait4 variants: any child, own process group, rusage.
    let a = spawn(|| 1);
    t.eq("wait4-any", wait4(-1, 0), (Ok(a), 0x100));
    let a = spawn(|| 2);
    t.eq("wait4-own-process-group", wait4(0, 0), (Ok(a), 0x200));
    let a = spawn(|| 3);
    let mut ru = [0xaai64; 18];
    let mut status = 0i32;
    let r = sys(
        Sysno::wait4,
        &[a, addr_mut(&mut status), 0, addr_mut(&mut ru)],
    );
    t.eq(
        "wait4-rusage",
        (r, status, ru[0] < 5 && ru[2] < 5),
        (Ok(a), 3 << 8, true),
    );
    let a = spawn(|| 4);
    t.eq("wait4-null-status", sys(Sysno::wait4, &[a, 0, 0, 0]), Ok(a));
    // A status pointer that faults still reaps the child.
    let a = spawn(|| 5);
    t.eq(
        "wait4-status-fault",
        sys(Sysno::wait4, &[a, BAD, 0, 0]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "wait4-status-fault-reaped",
        wait4(a as isize, 0).0,
        Err(Errno::ECHILD),
    );
    let a = spawn(|| 6);
    t.eq(
        "wait4-rusage-fault",
        sys(Sysno::wait4, &[a, 0, 0, BAD]),
        Err(Errno::EFAULT),
    );
    reap_all();
    // WNOHANG on a running child, then on the zombie.
    let sleeper = spawn(|| {
        let _ = sys(Sysno::pause, &[]);
        0
    });
    t.eq(
        "wait4-wnohang-running",
        wait4(sleeper as isize, WNOHANG),
        (Ok(0), -1),
    );
    let _ = sys(Sysno::kill, &[sleeper, SIGKILL]);
    t.eq(
        "wait4-after-sigkill",
        wait4(sleeper as isize, 0),
        (Ok(sleeper), 9),
    );
    t.eq(
        "wait4-wnohang-no-children",
        wait4(-1, WNOHANG).0,
        Err(Errno::ECHILD),
    );
}

fn wait_errors(t: &mut T) {
    reap_all();
    t.eq("wait4-no-children", wait4(-1, 0).0, Err(Errno::ECHILD));
    t.eq("wait4-missing-pid", wait4(99_999, 0).0, Err(Errno::ECHILD));
    t.eq(
        "wait4-missing-pgid",
        wait4(-99_999, 0).0,
        Err(Errno::ECHILD),
    );
    // The pid argument is a 32-bit `pid_t`: the high word is dropped, leaving 0 (own group).
    t.eq(
        "wait4-pid-truncated-to-int",
        sys(Sysno::wait4, &[0x8000_0000_0000_0000, 0, 0, 0]),
        Err(Errno::ECHILD),
    );
    t.eq(
        "wait4-int-min-32",
        sys(Sysno::wait4, &[i32::MIN as usize, 0, 0, 0]),
        Err(Errno::ESRCH),
    );
    t.eq("wait4-bad-options", wait4(-1, 0x10).0, Err(Errno::EINVAL));
    t.eq(
        "wait4-wexited-not-allowed",
        wait4(-1, WEXITED).0,
        Err(Errno::EINVAL),
    );
    let child = spawn(|| {
        let _ = sys(Sysno::pause, &[]);
        0
    });
    t.eq("wait4-not-my-child", wait4(1, 0).0, Err(Errno::ECHILD));
    t.eq("wait4-wrong-pgid", wait4(-1000, 0).0, Err(Errno::ECHILD));
    let _ = sys(Sysno::kill, &[child, SIGKILL]);
    reap_all();
}

fn waitid_checks(t: &mut T) {
    reap_all();
    t.eq(
        "waitid-no-children",
        waitid(0, 0, WEXITED).0,
        Err(Errno::ECHILD),
    );
    t.eq(
        "waitid-bad-idtype",
        waitid(9, 0, WEXITED).0,
        Err(Errno::EINVAL),
    );
    t.eq(
        "waitid-no-event-bits",
        waitid(0, 0, 0).0,
        Err(Errno::EINVAL),
    );
    t.eq(
        "waitid-bad-options",
        waitid(0, 0, WEXITED | 0x10).0,
        Err(Errno::EINVAL),
    );
    t.eq(
        "waitid-wnohang-only",
        waitid(0, 0, WNOHANG).0,
        Err(Errno::EINVAL),
    );
    // kernel/exit.c `waitid`: the siginfo pointer is checked after the wait, and EFAULT replaces
    // even ECHILD (`user_write_access_begin` fails first) ...
    t.eq(
        "waitid-fault-no-children",
        sys(Sysno::waitid, &[0, 0, BAD, WEXITED, 0]),
        Err(Errno::EFAULT),
    );
    // ... while an already-reaped zombie stays reaped.
    let zombie = spawn(|| 4);
    nap(50);
    t.eq(
        "waitid-fault-with-zombie",
        sys(Sysno::waitid, &[1, zombie, BAD, WEXITED, 0]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "waitid-fault-reaped-anyway",
        wait4(zombie as isize, 0).0,
        Err(Errno::ECHILD),
    );
    let child = spawn(|| 5);
    // WNOWAIT leaves the zombie for a later wait.
    let (r, info) = waitid(1, child, WEXITED | WNOWAIT);
    // [si_signo, si_errno, si_code, si_pid, si_uid, si_status, ..]
    t.eq(
        "waitid-exited",
        (r, info[0], info[1], info[2]),
        (Ok(0), SIGCHLD as i32, 0, 1),
    );
    t.eq(
        "waitid-exited-fields",
        (info[3], info[4], info[5]),
        (child as i32, 0, 5),
    );
    t.eq(
        "waitid-wnowait-keeps-zombie",
        waitid(1, child, WEXITED).1[3],
        child as i32,
    );
    t.eq(
        "waitid-then-gone",
        wait4(child as isize, 0).0,
        Err(Errno::ECHILD),
    );
    // CLD_KILLED / CLD_DUMPED codes.
    let k = spawn(|| {
        let _ = sys(Sysno::kill, &[getpid(), SIGTERM]);
        0
    });
    let (r, info) = waitid(0, 0, WEXITED);
    t.eq(
        "waitid-killed",
        (r, info[2], info[3], info[5]),
        (Ok(0), 2, k as i32, SIGTERM as i32),
    );
    // WNOHANG with nothing ready: success, siginfo zeroed.
    let sleeper = spawn(|| {
        let _ = sys(Sysno::pause, &[]);
        0
    });
    let (r, info) = waitid(1, sleeper, WEXITED | WNOHANG);
    t.eq("waitid-wnohang-empty", (r, info[0], info[3]), (Ok(0), 0, 0));
    t.eq(
        "waitid-wrong-pid",
        waitid(1, 99_999, WEXITED).0,
        Err(Errno::ECHILD),
    );
    t.eq(
        "waitid-pgid-zero-means-own",
        waitid(2, 0, WEXITED | WNOHANG).0,
        Ok(0),
    );
    t.eq(
        "waitid-pidfd-bad-fd",
        waitid(3, 999, WEXITED | WNOHANG).0,
        Err(Errno::EBADF),
    );
    let _ = sys(Sysno::kill, &[sleeper, SIGKILL]);
    t.eq(
        "waitid-null-info",
        sys(Sysno::waitid, &[1, sleeper, 0, WEXITED, 0]),
        Ok(0),
    );
    reap_all();
}

fn signals_and_stops(t: &mut T) {
    reap_all();
    for (name, sig) in [
        ("sigusr1", SIGUSR1),
        ("sigterm", SIGTERM),
        ("sigkill", SIGKILL),
        ("sighup", SIGHUP),
        ("sigabrt", SIGABRT),
    ] {
        let child = spawn(|| {
            let _ = sys(Sysno::kill, &[getpid(), sig]);
            0
        });
        // RLIMIT_CORE is 0, so a core-dumping signal reports no core-dump flag.
        t.eq(
            format_args!("killed-by-{name}"),
            wait4(child as isize, 0),
            (Ok(child), sig as i32),
        );
    }
    let child = spawn(|| {
        // SAFETY: deliberately not sound: the load from address 8 must raise SIGSEGV.
        let _ = unsafe { core::ptr::with_exposed_provenance::<u8>(8).read_volatile() };
        0
    });
    t.eq("killed-by-segv", wait4(child as isize, 0), (Ok(child), 11));
    let child = spawn(|| {
        let _ = sys(Sysno::kill, &[getpid(), SIGPIPE]);
        0
    });
    t.eq(
        "killed-by-sigpipe",
        wait4(child as isize, 0),
        (Ok(child), 13),
    );
    // The unkillable-init rule belongs to pid 1 only: a child dies of SIGSTOP/SIGTERM normally.
    // Stop and continue.
    let child = spawn(|| {
        let _ = sys(Sysno::kill, &[getpid(), SIGSTOP]);
        let _ = sys(Sysno::pause, &[]);
        0
    });
    t.eq(
        "wait4-stopped",
        wait4(child as isize, WUNTRACED),
        (Ok(child), (SIGSTOP as i32) << 8 | 0x7f),
    );
    t.eq(
        "wait4-stopped-reported-once",
        wait4(child as isize, WUNTRACED | WNOHANG),
        (Ok(0), -1),
    );
    let _ = sys(Sysno::kill, &[child, SIGCONT]);
    t.eq(
        "wait4-continued",
        wait4(child as isize, WCONTINUED),
        (Ok(child), 0xffff),
    );
    t.eq(
        "wait4-continued-reported-once",
        wait4(child as isize, WCONTINUED | WNOHANG),
        (Ok(0), -1),
    );
    let _ = sys(Sysno::kill, &[child, SIGKILL]);
    t.eq(
        "wait4-killed-after-continue",
        wait4(child as isize, 0),
        (Ok(child), 9),
    );
    let child = spawn(|| {
        let _ = sys(Sysno::kill, &[getpid(), SIGSTOP]);
        0
    });
    let (r, info) = waitid(1, child, 2 /* WSTOPPED */ | WNOWAIT);
    t.eq(
        "waitid-stopped",
        (r, info[0], info[2], info[3], info[5]),
        (Ok(0), SIGCHLD as i32, 5, child as i32, SIGSTOP as i32),
    );
    let _ = sys(Sysno::kill, &[child, SIGCONT]);
    let (r, info) = waitid(1, child, WEXITED);
    t.eq(
        "waitid-continued-then-exited",
        (r, info[2], info[5]),
        (Ok(0), 1, 0),
    );
    reap_all();
}

fn sigchld(t: &mut T) {
    reap_all();
    CHLD_COUNT.store(0, Relaxed);
    t.eq(
        "sigchld-handler-installed",
        sigaction(SIGCHLD, on_chld_ptr(), SA_SIGINFO),
        Ok(0),
    );
    // Blocked, then taken with rt_sigtimedwait: the notification exists even if the child is
    // reaped first.
    block(bit(SIGCHLD));
    let child = spawn(|| 5);
    let set = bit(SIGCHLD);
    let mut info = [0i32; 32];
    let five = [5i64, 0];
    let r = sys(
        Sysno::rt_sigtimedwait,
        &[addr(&set), addr_mut(&mut info), addr(&five), 8],
    );
    t.eq(
        "sigchld-queued-for-exit",
        (r, info[2], info[4], info[5], info[6]),
        (Ok(SIGCHLD), 1, child as i32, 0, 5),
    );
    t.eq(
        "sigchld-reap-after",
        wait4(child as isize, 0),
        (Ok(child), 5 << 8),
    );
    // Delivered to a handler: wait4 returns the child, the handler has run by then.
    CHLD_COUNT.store(0, Relaxed);
    block(0);
    let child = spawn(|| 9);
    t.eq(
        "sigchld-wait4-returns-child",
        wait4(child as isize, 0),
        (Ok(child), 9 << 8),
    );
    t.eq("sigchld-handler-ran-once", CHLD_COUNT.load(Relaxed), 1);
    t.eq(
        "sigchld-handler-info",
        [
            CHLD_INFO[0].load(Relaxed),
            CHLD_INFO[1].load(Relaxed),
            CHLD_INFO[2].load(Relaxed),
            CHLD_INFO[3].load(Relaxed),
        ],
        [1, child, 0, 9],
    );
    // Killed child: CLD_KILLED with the signal in si_status.
    CHLD_COUNT.store(0, Relaxed);
    let child = spawn(|| {
        let _ = sys(Sysno::kill, &[getpid(), SIGUSR2]);
        0
    });
    let _ = wait4(child as isize, 0);
    t.eq(
        "sigchld-killed-info",
        (
            CHLD_COUNT.load(Relaxed),
            CHLD_INFO[0].load(Relaxed),
            CHLD_INFO[3].load(Relaxed),
        ),
        (1, 2, SIGUSR2),
    );
    // Stopped child: SIGCHLD with CLD_STOPPED (no SA_NOCLDSTOP).
    CHLD_COUNT.store(0, Relaxed);
    let child = spawn(|| {
        let _ = sys(Sysno::kill, &[getpid(), SIGSTOP]);
        0
    });
    let _ = wait4(child as isize, WUNTRACED);
    t.eq(
        "sigchld-stopped-info",
        (
            CHLD_COUNT.load(Relaxed),
            CHLD_INFO[0].load(Relaxed),
            CHLD_INFO[3].load(Relaxed),
        ),
        (1, 5, SIGSTOP),
    );
    let _ = sys(Sysno::kill, &[child, SIGKILL]);
    let _ = wait4(child as isize, 0);
    // SIG_IGN and SA_NOCLDWAIT: children vanish, wait4 blocks for the last one and reports ECHILD.
    for (name, handler, flags) in [
        ("sig_ign", 1u64, 0u64),
        ("nocldwait", on_chld_ptr(), SA_SIGINFO | SA_NOCLDWAIT),
    ] {
        let _ = sigaction(SIGCHLD, handler, flags);
        let child = spawn(|| 3);
        t.eq(
            format_args!("sigchld-{name}-autoreap"),
            wait4(-1, 0).0,
            Err(Errno::ECHILD),
        );
        let _ = child;
    }
    let _ = sigaction(SIGCHLD, 0, 0);
    reap_all();
}

fn orphans(t: &mut T) {
    reap_all();
    let mut fds = [0u32; 2];
    let _ = sys(Sysno::pipe2, &[addr_mut(&mut fds), 0]);
    let (rfd, wfd) = (fds[0] as usize, fds[1] as usize);
    let parent = spawn(|| {
        let grandchild = spawn(|| {
            // Wait (bounded) until the parent is gone and init has adopted us.
            for _ in 0..200 {
                if sys(Sysno::getppid, &[]) == Ok(1) {
                    break;
                }
                nap(5);
            }
            let ppid = sys(Sysno::getppid, &[]).unwrap_or(usize::MAX);
            let _ = sys(Sysno::write, &[wfd, addr(&ppid), 8]);
            11
        });
        let _ = sys(Sysno::write, &[wfd, addr(&grandchild), 8]);
        10
    });
    let _ = sys(Sysno::close, &[wfd]);
    let mut words = [0usize; 2];
    let mut got = 0;
    while got < 16 {
        match sys(Sysno::read, &[rfd, addr_mut(&mut words) + got, 16 - got]) {
            Ok(n) if n > 0 => got += n,
            _ => break,
        }
    }
    t.eq("orphan-reports", got, 16);
    // Init reaps both: the parent (status 10) and the adopted grandchild (status 11).
    let mut seen = [(0usize, 0i32); 2];
    for slot in &mut seen {
        let (r, s) = wait4(-1, 0);
        *slot = (r.unwrap_or(0), s);
    }
    seen.sort_unstable();
    let mut want = [(parent, 10 << 8), (words[0], 11 << 8)];
    want.sort_unstable();
    t.eq("orphan-adopted-by-init", (words[1], seen), (1, want));
    t.eq("orphan-reaped-all", wait4(-1, 0).0, Err(Errno::ECHILD));
    let _ = sys(Sysno::close, &[rfd]);
}

fn sessions(t: &mut T) {
    reap_all();
    let mut fds = [0u32; 2];
    let _ = sys(Sysno::pipe2, &[addr_mut(&mut fds), 0]);
    let (rfd, wfd) = (fds[0] as usize, fds[1] as usize);
    let child = spawn(|| {
        let me = getpid();
        let words = [
            sys(Sysno::setsid, &[]).unwrap_or(0) == me,
            sys(Sysno::setsid, &[]) == Err(Errno::EPERM),
            sys(Sysno::getsid, &[0]) == Ok(me),
            sys(Sysno::getpgid, &[0]) == Ok(me),
            sys(Sysno::setpgid, &[0, 0]) == Err(Errno::EPERM),
            sys(Sysno::getpgid, &[1]) == Ok(0),
            sys(Sysno::setpgid, &[1, 1]) == Err(Errno::ESRCH),
        ]
        .map(u8::from);
        let _ = sys(Sysno::write, &[wfd, addr(&words), 7]);
        0
    });
    let mut got = [0xffu8; 7];
    let n = sys(Sysno::read, &[rfd, addr_mut(&mut got), 7]);
    t.eq("setsid-checks", (n, got), (Ok(7), [1; 7]));
    let _ = wait4(child as isize, 0);
    // setpgid on a child before it execs: allowed from the parent; then it leads its own group.
    let child = spawn(|| {
        let _ = sys(Sysno::pause, &[]);
        0
    });
    t.eq("setpgid-child", sys(Sysno::setpgid, &[child, child]), Ok(0));
    t.eq("getpgid-child", sys(Sysno::getpgid, &[child]), Ok(child));
    t.eq(
        "wait4-by-pgid",
        (
            sys(Sysno::kill, &[child, SIGKILL]),
            wait4(-(child as isize), 0),
        ),
        (Ok(0), (Ok(child), 9)),
    );
    t.eq(
        "setpgid-missing",
        sys(Sysno::setpgid, &[99_999, 0]),
        Err(Errno::ESRCH),
    );
    t.eq(
        "setpgid-negative-pgid",
        sys(Sysno::setpgid, &[0, usize::MAX]),
        Err(Errno::EINVAL),
    );
    let _ = sys(Sysno::close, &[rfd]);
    let _ = sys(Sysno::close, &[wfd]);
}

/// The line the re-executed `/init execd` prints, preceded by its hello line.
const EXEC_OUTPUT: &[u8] = b"init: hello from userspace\ninit: execd argv=/init,execd,third arg envp=EXEC=1,B=two fd40=Ok(0) fd41=Err(EBADF) usr1=0x0 usr2=0x1 usr1_blocked=true umask=0o77 cwd=/fixture ppid=1\n";

fn exec(t: &mut T) {
    reap_all();
    let init = b"/init\0";
    let argv = [addr(b"/init\0"), addr(b"execd\0"), addr(b"third arg\0"), 0];
    let envp = [addr(b"EXEC=1\0"), addr(b"B=two\0"), 0];
    // Failures return to the caller in-process.
    t.eq(
        "execve-missing",
        sys(
            Sysno::execve,
            &[addr(b"/nonexistent\0"), addr(&argv), addr(&envp)],
        ),
        Err(Errno::ENOENT),
    );
    t.eq(
        "execve-not-executable",
        sys(
            Sysno::execve,
            &[addr(b"/fixture/hello.txt\0"), addr(&argv), addr(&envp)],
        ),
        Err(Errno::EACCES),
    );
    t.eq(
        "execve-directory",
        sys(
            Sysno::execve,
            &[addr(b"/fixture\0"), addr(&argv), addr(&envp)],
        ),
        Err(Errno::EACCES),
    );
    t.eq(
        "execve-not-an-elf",
        sys(
            Sysno::execve,
            &[addr(b"/fixture/noexec\0"), addr(&argv), addr(&envp)],
        ),
        Err(Errno::ENOEXEC),
    );
    t.eq(
        "execve-empty-file",
        sys(
            Sysno::execve,
            &[addr(b"/fixture/empty\0"), addr(&argv), addr(&envp)],
        ),
        Err(Errno::EACCES),
    );
    t.eq(
        "execve-through-file",
        sys(
            Sysno::execve,
            &[addr(b"/init/x\0"), addr(&argv), addr(&envp)],
        ),
        Err(Errno::ENOTDIR),
    );
    t.eq(
        "execve-fault-path",
        sys(Sysno::execve, &[BAD, addr(&argv), addr(&envp)]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "execve-fault-argv",
        sys(Sysno::execve, &[addr(init), BAD, addr(&envp)]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "execve-fault-envp",
        sys(Sysno::execve, &[addr(init), addr(&argv), BAD]),
        Err(Errno::EFAULT),
    );
    let bad_arg = [addr(b"/init\0"), BAD, 0];
    t.eq(
        "execve-fault-argv-string",
        sys(Sysno::execve, &[addr(init), addr(&bad_arg), addr(&envp)]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "execveat-missing",
        sys(
            Sysno::execveat,
            &[
                AT_FDCWD,
                addr(b"nonexistent\0"),
                addr(&argv),
                addr(&envp),
                0,
            ],
        ),
        Err(Errno::ENOENT),
    );
    t.eq(
        "execveat-bad-flags",
        sys(
            Sysno::execveat,
            &[AT_FDCWD, addr(init), addr(&argv), addr(&envp), 0x8000_0000],
        ),
        Err(Errno::EINVAL),
    );

    // Success: descriptors, dispositions, mask, umask and cwd are inherited as Linux defines.
    let mut out = [0u32; 2];
    let _ = sys(Sysno::pipe2, &[addr_mut(&mut out), 0]);
    let (rfd, wfd) = (out[0] as usize, out[1] as usize);
    let child = spawn(|| {
        let _ = sys(Sysno::dup3, &[wfd, 1, 0]); // stdout -> the pipe
        let _ = sys(Sysno::dup3, &[wfd, 40, 0]); // inherited
        let _ = sys(Sysno::dup3, &[wfd, 41, O_CLOEXEC]); // closed by exec
        let _ = sigaction(SIGUSR1, on_chld_ptr(), SA_SIGINFO); // handler -> reset to default
        let _ = sigaction(SIGUSR2, 1, 0); // ignored -> stays ignored
        block(bit(SIGUSR1)); // mask survives
        let _ = sys(Sysno::umask, &[0o077]);
        let _ = sys(Sysno::chdir, &[addr(b"/fixture\0")]);
        let r = sys(Sysno::execve, &[addr(init), addr(&argv), addr(&envp)]);
        // Only reached if execve failed.
        let _ = sys(Sysno::write, &[2, addr(&r), 0]);
        99
    });
    let _ = sys(Sysno::close, &[wfd]);
    let mut text = [0u8; 512];
    let mut len = 0;
    while let Ok(n) = sys(Sysno::read, &[rfd, addr_mut(&mut text[len..]), 512 - len]) {
        if n == 0 {
            break;
        }
        len += n;
    }
    let _ = sys(Sysno::close, &[rfd]);
    t.eq("execve-output", &text[..len], EXEC_OUTPUT);
    t.eq(
        "execve-exit-status",
        wait4(child as isize, 0),
        (Ok(child), 42 << 8),
    );
}

/// The re-executed image (`/init execd ...`): reports what `execve` kept and exits 42.
/// Runs before `run()` prints its pid-dependent summary, so its stdout is deterministic.
pub fn execd(argv: Strings, envp: Strings) -> ! {
    use core::fmt::Write as _;
    struct Buf([u8; 480], usize);
    impl core::fmt::Write for Buf {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let n = s.len().min(self.0.len() - self.1);
            self.0[self.1..self.1 + n].copy_from_slice(&s.as_bytes()[..n]);
            self.1 += n;
            Ok(())
        }
    }
    let mut b = Buf([0; 480], 0);
    let join = |b: &mut Buf, items: Strings| {
        for (i, s) in items.iter().enumerate() {
            let _ = write!(
                b,
                "{}{}",
                if i > 0 { "," } else { "" },
                core::str::from_utf8(s).unwrap_or("?")
            );
        }
    };
    let _ = write!(b, "init: execd argv=");
    join(&mut b, argv);
    let _ = write!(b, " envp=");
    join(&mut b, envp);
    let fd = |n: usize| sys(Sysno::fcntl, &[n, 1, 0]);
    let mut sa = [KSigaction::default(); 2];
    for (i, sig) in [SIGUSR1, SIGUSR2].into_iter().enumerate() {
        let _ = sys(Sysno::rt_sigaction, &[sig, 0, addr_mut(&mut sa[i]), 8]);
    }
    let mut mask = 0u64;
    let _ = sys(Sysno::rt_sigprocmask, &[0, 0, addr_mut(&mut mask), 8]);
    let umask = sys(Sysno::umask, &[0o022]).unwrap_or(0);
    let mut cwd = [0u8; 32];
    let n = sys(Sysno::getcwd, &[addr_mut(&mut cwd), 32]).unwrap_or(1);
    let _ = write!(
        b,
        " fd40={:?} fd41={:?} usr1={:#x} usr2={:#x} usr1_blocked={} umask={umask:#o} cwd={} ppid={}",
        fd(40),
        fd(41),
        sa[0].handler,
        sa[1].handler,
        mask & bit(SIGUSR1) != 0,
        core::str::from_utf8(&cwd[..n - 1]).unwrap_or("?"),
        sys(Sysno::getppid, &[]).unwrap_or(usize::MAX),
    );
    let _ = b.write_char('\n');
    let _ = sys(Sysno::write, &[1, addr(&b.0), b.1]);
    die(42)
}

fn pipes(t: &mut T) {
    reap_all();
    let mut fds = [0u32; 2];
    t.eq("pipe2", sys(Sysno::pipe2, &[addr_mut(&mut fds), 0]), Ok(0));
    t.eq("pipe2-lowest-fds", (fds[0], fds[1]), (3, 4));
    let (rfd, wfd) = (fds[0] as usize, fds[1] as usize);
    let mut st = super::fs::Stat::default();
    let _ = sys(Sysno::fstat, &[rfd, addr_mut(&mut st)]);
    t.eq(
        "pipe-fstat",
        (st.mode, st.size, st.nlink, st.blksize),
        (0o010_600, 0, 1, 4096),
    );
    t.eq(
        "pipe-wrong-direction-read",
        sys(Sysno::read, &[wfd, addr_mut(&mut [0u8; 4]), 4]),
        Err(Errno::EBADF),
    );
    t.eq(
        "pipe-wrong-direction-write",
        sys(Sysno::write, &[rfd, addr(b"x"), 1]),
        Err(Errno::EBADF),
    );
    t.eq(
        "pipe-no-seek",
        sys(Sysno::lseek, &[rfd, 0, 0]),
        Err(Errno::ESPIPE),
    );
    t.eq(
        "pipe-no-pread",
        sys(Sysno::pread64, &[rfd, addr_mut(&mut [0u8; 4]), 4, 0]),
        Err(Errno::ESPIPE),
    );
    t.eq("pipe-size", sys(Sysno::fcntl, &[rfd, 1032, 0]), Ok(65536));
    // Parent writes, child reads and answers.
    let mut back = [0u32; 2];
    let _ = sys(Sysno::pipe2, &[addr_mut(&mut back), 0]);
    let (brfd, bwfd) = (back[0] as usize, back[1] as usize);
    let child = spawn(|| {
        let _ = sys(Sysno::close, &[wfd]); // else the request pipe never reaches EOF
        let mut buf = [0u8; 16];
        let n = sys(Sysno::read, &[rfd, addr_mut(&mut buf), 16]).unwrap_or(0);
        let mut reply = [0u8; 16];
        reply[..n].copy_from_slice(&buf[..n]);
        reply[..n].make_ascii_uppercase();
        let _ = sys(Sysno::write, &[bwfd, addr(&reply), n]);
        // EOF on the request pipe only after the parent closed its write end.
        let eof = sys(Sysno::read, &[rfd, addr_mut(&mut buf), 16]);
        usize::from(eof == Ok(0))
    });
    t.eq(
        "pipe-write",
        sys(Sysno::write, &[wfd, addr(b"ping"), 4]),
        Ok(4),
    );
    let mut buf = [0u8; 16];
    t.eq(
        "pipe-child-answer",
        (sys(Sysno::read, &[brfd, addr_mut(&mut buf), 16]), &buf[..4]),
        (Ok(4), b"PING".as_slice()),
    );
    let _ = sys(Sysno::close, &[wfd]);
    t.eq(
        "pipe-eof-seen-by-child",
        wait4(child as isize, 0),
        (Ok(child), 0x100),
    );
    t.eq(
        "pipe-parent-eof",
        {
            let _ = sys(Sysno::close, &[bwfd]);
            sys(Sysno::read, &[brfd, addr_mut(&mut buf), 16])
        },
        Ok(0),
    );
    let _ = (sys(Sysno::close, &[rfd]), sys(Sysno::close, &[brfd]));

    // Partial reads, FIONREAD, non-blocking, capacity, EPIPE.
    let _ = sys(Sysno::pipe2, &[addr_mut(&mut fds), O_NONBLOCK]);
    let (rfd, wfd) = (fds[0] as usize, fds[1] as usize);
    t.eq(
        "pipe-nonblock-empty",
        sys(Sysno::read, &[rfd, addr_mut(&mut buf), 16]),
        Err(Errno::EAGAIN),
    );
    let _ = sys(Sysno::write, &[wfd, addr(b"0123456789"), 10]);
    let mut avail = 0u32;
    t.eq(
        "pipe-fionread",
        (
            sys(Sysno::ioctl, &[rfd, 0x541b, addr_mut(&mut avail)]),
            avail,
        ),
        (Ok(0), 10),
    );
    t.eq(
        "pipe-partial-read",
        (sys(Sysno::read, &[rfd, addr_mut(&mut buf), 4]), &buf[..4]),
        (Ok(4), b"0123".as_slice()),
    );
    t.eq(
        "pipe-rest",
        (sys(Sysno::read, &[rfd, addr_mut(&mut buf), 16]), &buf[..6]),
        (Ok(6), b"456789".as_slice()),
    );
    let chunk = [0x5au8; 4096];
    let mut written = 0;
    while let Ok(n) = sys(Sysno::write, &[wfd, addr(&chunk), 4096]) {
        written += n;
        if written > 1 << 20 {
            break;
        }
    }
    t.eq("pipe-capacity", written, 65536);
    t.eq(
        "pipe-full-nonblock",
        sys(Sysno::write, &[wfd, addr(b"x"), 1]),
        Err(Errno::EAGAIN),
    );
    t.eq(
        "pipe-set-size-shrinks-not-below-data",
        sys(Sysno::fcntl, &[rfd, 1031, 4096]),
        Err(Errno::EBUSY),
    );
    t.eq("pipe-poll-full", poll(wfd, 4 /* POLLOUT */), 0);
    t.eq("pipe-poll-readable", poll(rfd, 1 /* POLLIN */), 1);
    let mut sink = [0u8; 4096];
    while sys(Sysno::read, &[rfd, addr_mut(&mut sink), 4096]).is_ok_and(|n| n > 0) {}
    t.eq("pipe-poll-drained", (poll(rfd, 1), poll(wfd, 4)), (0, 4));
    t.eq(
        "pipe-set-size",
        (
            sys(Sysno::fcntl, &[rfd, 1031, 4096]),
            sys(Sysno::fcntl, &[rfd, 1032, 0]),
        ),
        (Ok(4096), Ok(4096)),
    );
    t.eq(
        "pipe-set-size-rounds-up",
        (
            sys(Sysno::fcntl, &[rfd, 1031, 5000]),
            sys(Sysno::fcntl, &[rfd, 1032, 0]),
        ),
        (Ok(8192), Ok(8192)),
    );
    let _ = sys(Sysno::close, &[rfd]);
    t.eq(
        "pipe-poll-hangup-on-write-end",
        poll(wfd, 4) & 0x8, /* POLLERR */
        0x8,
    );
    // Writing with no reader: EPIPE (SIGPIPE ignored), SIGPIPE otherwise.
    let _ = sys(
        Sysno::rt_sigaction,
        &[
            SIGPIPE,
            addr(&KSigaction {
                handler: 1,
                ..KSigaction::default()
            }),
            0,
            8,
        ],
    );
    t.eq(
        "pipe-epipe",
        sys(Sysno::write, &[wfd, addr(b"x"), 1]),
        Err(Errno::EPIPE),
    );
    let _ = sys(
        Sysno::rt_sigaction,
        &[SIGPIPE, addr(&KSigaction::default()), 0, 8],
    );
    let child = spawn(|| {
        let _ = sys(Sysno::write, &[wfd, addr(b"x"), 1]);
        0
    });
    t.eq(
        "pipe-sigpipe-kills-writer",
        wait4(child as isize, 0),
        (Ok(child), SIGPIPE as i32),
    );
    let _ = sys(Sysno::close, &[wfd]);
    // poll on a pipe whose write end closed: POLLHUP, and read returns EOF.
    let _ = sys(Sysno::pipe2, &[addr_mut(&mut fds), 0]);
    let (rfd, wfd) = (fds[0] as usize, fds[1] as usize);
    t.eq("poll-empty-timeout", poll_timeout(rfd, 1, 10), 0);
    let _ = sys(Sysno::write, &[wfd, addr(b"x"), 1]);
    t.eq("poll-pollin", poll(rfd, 1), 1);
    let _ = sys(Sysno::close, &[wfd]);
    t.eq("poll-pollin-pollhup", poll(rfd, 1), 1 | 0x10);
    let _ = sys(Sysno::read, &[rfd, addr_mut(&mut buf), 1]);
    t.eq("poll-pollhup-only", poll(rfd, 1), 0x10);
    t.eq("poll-bad-fd-pollnval", poll(999, 1), 0x20);
    t.eq(
        "poll-negative-fd-ignored",
        poll_timeout(usize::MAX >> 32, 1, 0),
        0,
    );
    t.eq(
        "pipe2-bad-flags",
        sys(Sysno::pipe2, &[addr_mut(&mut fds), 0x8000_0000]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "pipe2-fault",
        sys(Sysno::pipe2, &[BAD, 0]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "pipe-legacy",
        sys(Sysno::pipe, &[addr_mut(&mut fds)]),
        Ok(0),
    );
    for fd in [fds[0], fds[1]] {
        let _ = sys(Sysno::close, &[fd as usize]);
    }
    let _ = sys(Sysno::close, &[rfd]);
}

/// `revents` of a one-descriptor `poll` with a zero timeout, or -1 on error.
fn poll(fd: usize, events: i16) -> i32 {
    poll_timeout(fd, events, 0)
}

fn poll_timeout(fd: usize, events: i16, ms: usize) -> i32 {
    #[repr(C)]
    struct Pollfd {
        fd: i32,
        events: i16,
        revents: i16,
    }
    let mut p = Pollfd {
        fd: fd as i32,
        events,
        revents: 0,
    };
    match sys(Sysno::poll, &[addr_mut(&mut p), 1, ms]) {
        Ok(_) => i32::from(p.revents),
        Err(_) => -1,
    }
}
