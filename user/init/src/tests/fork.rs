// SPDX-License-Identifier: GPL-2.0-only
//! `fork` group: process creation and its inheritance rules, `clone`/`clone3` argument checking,
//! exit and wait statuses, `waitid`, `SIGCHLD`, orphans and `execve` in a child, observed with
//! nothing but exit statuses and signals (no pipes, no job control: the `proc` group adds those).
//! Linux 6.18.57: `kernel/fork.c` (`copy_process`, `kernel_clone`, `clone3`), `kernel/exit.c`
//! (`wait_task_zombie`, `kernel_waitid`, `forget_original_parent`), `kernel/signal.c`
//! (`do_notify_parent`, `kill_something_info`).
//!
//! Children run in the `fork`ed copy of this program, report through their exit status (one
//! byte, so several answers share it as bits) and end with `exit_group`. The `forkleak` mode
//! (below) runs many of them to check that nothing is left behind.

use core::sync::atomic::{AtomicUsize, Ordering::Relaxed};

use syscalls::{Errno, Sysno};

use super::proc::{
    AT_FDCWD, BAD, CHLD_COUNT, CHLD_INFO, SIGABRT, SIGCHLD, SIGHUP, SIGKILL, SIGPIPE, SIGTERM,
    SIGUSR1, SIGUSR2, WEXITED, WNOHANG, WNOWAIT, block, nap, on_chld_ptr, reap_all, sigaction,
    spawn, wait4, waitid,
};
use super::signal::{KSigaction, SA_NOCLDWAIT, SA_SIGINFO, bit};
use super::{R, T, addr, addr_mut, die, getpid, gettid, sys};

const O_RDONLY: usize = 0;
const O_CLOEXEC: usize = 0o2_000_000;
const WCLONE: usize = 0x8000_0000;
const WALL: usize = 0x4000_0000;
const CLONE_VM: usize = 0x100;
const CLONE_FS: usize = 0x200;
const CLONE_SIGHAND: usize = 0x800;
const CLONE_PIDFD: usize = 0x1000;
const CLONE_THREAD: usize = 0x1_0000;
const CLONE_NEWNS: usize = 0x2_0000;
const CLONE_PARENT_SETTID: usize = 0x10_0000;
const CLONE_DETACHED: usize = 0x40_0000;

/// A word that a child changes after `fork`; the parent must keep its own copy.
static MEMORY: AtomicUsize = AtomicUsize::new(0);

pub fn run() -> bool {
    let mut t = T::new("fork");
    reap_all();
    ids(&mut t);
    memory(&mut t);
    descriptors(&mut t);
    inheritance(&mut t);
    many(&mut t);
    exits(&mut t);
    wait_errors(&mut t);
    waitid_checks(&mut t);
    kills(&mut t);
    sigchld(&mut t);
    orphans(&mut t);
    clone_arguments(&mut t);
    exec(&mut t);
    reap_all();
    t.finish()
}

/// Bit `n` of a child's exit status: whether `cond` held in the child.
fn flag(n: u32, cond: bool) -> usize {
    usize::from(cond) << n
}

fn ids(t: &mut T) {
    let me = getpid();
    let pgrp = sys(Sysno::getpgid, &[0]);
    let sid = sys(Sysno::getsid, &[0]);
    let child = spawn(|| {
        flag(0, getpid() != me)
            | flag(1, gettid() == getpid())
            | flag(2, sys(Sysno::getppid, &[]) == Ok(me))
            | flag(3, sys(Sysno::getpgid, &[0]) == pgrp)
            | flag(4, sys(Sysno::getsid, &[0]) == sid)
            | flag(5, sys(Sysno::getuid, &[]) == Ok(0))
    });
    t.holds(
        "fork-returns-child-pid",
        child > 1 && child != me && child < 1 << 22,
        child,
        "a new pid > 1",
    );
    t.eq(
        "child-ids",
        wait4(child as isize, 0),
        (Ok(child), 0x3f << 8),
    );
    let (a, b) = (spawn(|| 0), spawn(|| 0));
    t.holds(
        "pids-increase",
        a > child && b > a,
        (child, a, b),
        "increasing",
    );
    reap_all();
}

fn memory(t: &mut T) {
    reap_all();
    // Static data and stack: private copies.
    MEMORY.store(5, Relaxed);
    let mut local = 7usize;
    let local_ptr = core::ptr::from_mut(&mut local);
    let child = spawn(|| {
        let seen = MEMORY.load(Relaxed) + 10 * unsafe { local_ptr.read_volatile() };
        MEMORY.store(9, Relaxed);
        unsafe { local_ptr.write_volatile(8) };
        seen
    });
    t.eq(
        "fork-copies-memory",
        wait4(child as isize, 0),
        (Ok(child), 75 << 8),
    );
    t.eq(
        "fork-memory-is-private",
        (MEMORY.load(Relaxed), unsafe { local_ptr.read_volatile() }),
        (5, 7),
    );
    // Anonymous mappings: a written page, a never-touched page (zero page), a PROT_NONE page.
    let page = super::mmap(0, 3 * super::PAGE, 3, 0x22, usize::MAX, 0).unwrap_or(0);
    super::poke(page, 0x11);
    let _ = sys(Sysno::mprotect, &[page + 2 * super::PAGE, super::PAGE, 0]);
    let child = spawn(|| {
        let first = super::peek(page);
        let untouched = super::peek(page + super::PAGE);
        super::poke(page, 0x22);
        super::poke(page + super::PAGE, 0x33);
        usize::from(first)
            | usize::from(untouched) << 6
            | usize::from(super::peek(page) == 0x22) << 7
    });
    t.eq(
        "fork-mapped-pages",
        wait4(child as isize, 0),
        (Ok(child), 0x91 << 8),
    );
    t.eq(
        "fork-mapped-pages-private",
        (super::peek(page), super::peek(page + super::PAGE)),
        (0x11, 0),
    );
    // The PROT_NONE page stays inaccessible in the child.
    let child = spawn(|| usize::from(super::peek(page + 2 * super::PAGE)));
    t.eq(
        "fork-prot-none-stays",
        wait4(child as isize, 0),
        (Ok(child), 11),
    );
    // A page unmapped before the fork stays unmapped in the child.
    let _ = sys(Sysno::munmap, &[page + super::PAGE, super::PAGE]);
    let child = spawn(|| {
        usize::from(
            sys(Sysno::madvise, &[page + super::PAGE, super::PAGE, 0]) == Err(Errno::ENOMEM),
        )
    });
    t.eq(
        "fork-unmapped-stays",
        wait4(child as isize, 0),
        (Ok(child), 0x100),
    );
    let _ = sys(Sysno::munmap, &[page, super::PAGE]);
    // The program break and the stack.
    let brk = sys(Sysno::brk, &[0]).unwrap_or(0);
    let child = spawn(|| usize::from(sys(Sysno::brk, &[0]) == Ok(brk)));
    t.eq("fork-brk", wait4(child as isize, 0), (Ok(child), 0x100));
}

fn descriptors(t: &mut T) {
    reap_all();
    let fd = sys(
        Sysno::openat,
        &[
            AT_FDCWD,
            addr(b"/fixture/hello.txt\0"),
            O_RDONLY | O_CLOEXEC,
            0,
        ],
    )
    .unwrap_or(usize::MAX);
    // The open file description (and its offset) is shared with the child.
    let child = spawn(|| {
        let mut buf = [0u8; 5];
        let n = sys(Sysno::read, &[fd, addr_mut(&mut buf), 5]);
        let fd_flags = sys(Sysno::fcntl, &[fd, 1, 0]);
        let closed = sys(Sysno::close, &[fd]);
        flag(0, n == Ok(5) && &buf == b"hello")
            | flag(1, fd_flags == Ok(1))
            | flag(2, closed == Ok(0))
            | flag(
                3,
                sys(Sysno::read, &[fd, addr_mut(&mut buf), 5]) == Err(Errno::EBADF),
            )
    });
    t.eq(
        "fork-fd-child",
        wait4(child as isize, 0),
        (Ok(child), 0xf << 8),
    );
    let mut rest = [0u8; 5];
    t.eq(
        "fork-fd-offset-shared",
        (sys(Sysno::read, &[fd, addr_mut(&mut rest), 5]), rest),
        (Ok(5), *b", ora"),
    );
    t.eq(
        "fork-fd-parent-keeps-its-descriptor",
        sys(Sysno::fcntl, &[fd, 1, 0]),
        Ok(1),
    );
    let _ = sys(Sysno::close, &[fd]);
    // Descriptors 0-2 (the console) are inherited by the child.
    let child = spawn(|| {
        usize::from(sys(Sysno::fcntl, &[1, 3, 0]).is_ok())
            | usize::from(sys(Sysno::write, &[1, addr(b""), 0]) == Ok(0)) << 1
    });
    t.eq(
        "fork-console-inherited",
        wait4(child as isize, 0),
        (Ok(child), 3 << 8),
    );
}

fn inheritance(t: &mut T) {
    reap_all();
    // Working directory and umask are copied; changes stay on their side.
    let _ = sys(Sysno::chdir, &[addr(b"/fixture\0")]);
    let old_umask = sys(Sysno::umask, &[0o077]).unwrap_or(0);
    let child = spawn(|| {
        let mut cwd = [0u8; 16];
        let n = sys(Sysno::getcwd, &[addr_mut(&mut cwd), 16]).unwrap_or(0);
        let was = sys(Sysno::umask, &[0o022]);
        let _ = sys(Sysno::chdir, &[addr(b"/\0")]);
        flag(0, &cwd[..n] == b"/fixture\0") | flag(1, was == Ok(0o077))
    });
    t.eq(
        "fork-cwd-umask-inherited",
        wait4(child as isize, 0),
        (Ok(child), 3 << 8),
    );
    let mut cwd = [0u8; 16];
    let n = sys(Sysno::getcwd, &[addr_mut(&mut cwd), 16]).unwrap_or(0);
    t.eq(
        "fork-fs-is-private",
        (&cwd[..n], sys(Sysno::umask, &[old_umask])),
        (b"/fixture\0".as_slice(), Ok(0o077)),
    );
    let _ = sys(Sysno::chdir, &[addr(b"/\0")]);
    // Dispositions, the blocked mask and the alternate stack are copied; pending signals and
    // the real interval timer are not.
    let _ = sigaction(SIGUSR1, on_chld_ptr(), SA_SIGINFO);
    let _ = sigaction(SIGHUP, 1, 0); // SIG_IGN
    block(bit(SIGUSR2));
    let _ = sys(Sysno::kill, &[getpid(), SIGUSR2]); // pending in the parent only
    let _ = sys(Sysno::alarm, &[1000]);
    let handler = on_chld_ptr();
    let child = spawn(|| {
        let mut usr1 = KSigaction::default();
        let mut hup = KSigaction::default();
        let _ = sys(Sysno::rt_sigaction, &[SIGUSR1, 0, addr_mut(&mut usr1), 8]);
        let _ = sys(Sysno::rt_sigaction, &[SIGHUP, 0, addr_mut(&mut hup), 8]);
        let mut mask = 0u64;
        let _ = sys(Sysno::rt_sigprocmask, &[0, 0, addr_mut(&mut mask), 8]);
        let mut pending = 1u64;
        let _ = sys(Sysno::rt_sigpending, &[addr_mut(&mut pending), 8]);
        flag(0, usr1.handler == handler && usr1.flags & SA_SIGINFO != 0)
            | flag(1, hup.handler == 1)
            | flag(2, mask & bit(SIGUSR2) != 0)
            | flag(3, pending == 0)
            | flag(4, sys(Sysno::alarm, &[0]) == Ok(0))
    });
    t.eq(
        "fork-signal-state",
        wait4(child as isize, 0),
        (Ok(child), 0x1f << 8),
    );
    let mut pending = 0u64;
    let _ = sys(Sysno::rt_sigpending, &[addr_mut(&mut pending), 8]);
    t.eq(
        "fork-parent-keeps-pending-and-timer",
        (
            pending & bit(SIGUSR2) != 0,
            sys(Sysno::alarm, &[0]).map(|left| left >= 990),
        ),
        (true, Ok(true)),
    );
    // Discard the pending SIGUSR2 (ignoring a signal flushes it), then restore the dispositions.
    let _ = sigaction(SIGUSR2, 1, 0);
    block(0);
    let _ = sigaction(SIGUSR2, 0, 0);
    let _ = sigaction(SIGUSR1, 0, 0);
    let _ = sigaction(SIGHUP, 0, 0);
    // x87/SSE state and the %fs base are copied; the child's changes stay its own.
    set_mxcsr(0x1f80 | 1 << 13); // round down
    let tls = addr(&MEMORY);
    let _ = sys(Sysno::arch_prctl, &[0x1002, tls]);
    let child = spawn(|| {
        let seen = get_mxcsr();
        set_mxcsr(2 << 13 | 0x1f80);
        let mut fs = 0usize;
        let _ = sys(Sysno::arch_prctl, &[0x1003, addr_mut(&mut fs)]);
        let _ = sys(Sysno::arch_prctl, &[0x1002, tls + 8]);
        flag(0, seen >> 13 & 3 == 1) | flag(1, fs == tls)
    });
    t.eq(
        "fork-fpu-and-tls",
        wait4(child as isize, 0),
        (Ok(child), 3 << 8),
    );
    let after = get_mxcsr();
    let mut fs = 0usize;
    let _ = sys(Sysno::arch_prctl, &[0x1003, addr_mut(&mut fs)]);
    t.eq(
        "fork-fpu-and-tls-are-private",
        (after >> 13 & 3, fs),
        (1, tls),
    );
    set_mxcsr(0x1f80);
    let _ = sys(Sysno::arch_prctl, &[0x1002, 0]);
}

/// `stmxcsr`: the SSE control/status register of this task.
///
/// `asm!` proof (the program is soft-float, so no intrinsic is available without enabling the
/// feature): user mode, SSE usable (`fpu_checks` runs the same instructions first); one store
/// through a valid local pointer, no other memory, no stack use, flags unchanged.
fn get_mxcsr() -> u32 {
    let mut value = 0u32;
    // SAFETY: as the function's proof.
    unsafe {
        core::arch::asm!(
            "stmxcsr dword ptr [{p}]",
            p = in(reg) core::ptr::addr_of_mut!(value),
            options(nostack, preserves_flags),
        );
    }
    value
}

/// `ldmxcsr`: set the SSE control/status register of this task. The value must have no reserved
/// bit set (the callers pass `0x1f80` with a rounding mode).
///
/// `asm!` proof: as [`get_mxcsr`]; one load from a valid local pointer; the new rounding mode
/// affects only this task's later SSE instructions, which the program does not use outside
/// these helpers.
fn set_mxcsr(value: u32) {
    // SAFETY: as the function's proof.
    unsafe {
        core::arch::asm!(
            "ldmxcsr dword ptr [{p}]",
            p = in(reg) core::ptr::addr_of!(value),
            options(nostack, preserves_flags, readonly),
        );
    }
}

/// Many children alive at once, each with its own address space, all collected.
fn many(t: &mut T) {
    reap_all();
    let mut pids = [0usize; 24];
    for (i, slot) in pids.iter_mut().enumerate() {
        MEMORY.store(i, Relaxed);
        *slot = spawn(|| {
            nap(5);
            MEMORY.load(Relaxed) + 1
        });
    }
    let mut sum = 0usize;
    let mut alive = 0usize;
    loop {
        let (r, status) = wait4(-1, 0);
        match r {
            Ok(pid) if pids.contains(&pid) => {
                sum += (status >> 8) as usize & 0xff;
                alive += 1;
            }
            _ => break,
        }
    }
    t.eq("many-children", (alive, sum), (24, (1..=24).sum()));
}

fn exits(t: &mut T) {
    reap_all();
    let child = spawn(|| 7);
    let (r, status) = wait4(child as isize, 0);
    t.eq("wait4-reaps-child", r, Ok(child));
    t.eq("wait4-exit-status-encoding", status, 7 << 8);
    t.eq(
        "wait4-zombie-gone",
        wait4(child as isize, 0).0,
        Err(Errno::ECHILD),
    );
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
    // A blocking wait4 is woken by the exit of a child that is still running.
    let slow = spawn(|| {
        nap(20);
        12
    });
    t.eq(
        "wait4-blocks-until-exit",
        wait4(slow as isize, 0),
        (Ok(slow), 12 << 8),
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
    t.eq(
        "waitid-fault-no-children",
        sys(Sysno::waitid, &[0, 0, BAD, WEXITED, 0]),
        Err(Errno::EFAULT),
    );
    // An already-reaped zombie stays reaped.
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

fn kills(t: &mut T) {
    reap_all();
    for (name, sig) in [
        ("sigusr1", SIGUSR1),
        ("sigterm", SIGTERM),
        ("sigkill", SIGKILL),
        ("sighup", SIGHUP),
        ("sigabrt", SIGABRT),
        ("sigpipe", SIGPIPE),
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
    // A signal from another task: kill by pid, by group and tgkill.
    let sleeper = spawn(|| {
        let _ = sys(Sysno::pause, &[]);
        0
    });
    t.eq("kill-probe-child", sys(Sysno::kill, &[sleeper, 0]), Ok(0));
    t.eq(
        "kill-missing-pid",
        sys(Sysno::kill, &[99_999, SIGKILL]),
        Err(Errno::ESRCH),
    );
    t.eq(
        "tgkill-wrong-group",
        sys(Sysno::tgkill, &[sleeper + 1, sleeper, SIGKILL]),
        Err(Errno::ESRCH),
    );
    t.eq(
        "tgkill-child",
        sys(Sysno::tgkill, &[sleeper, sleeper, SIGTERM]),
        Ok(0),
    );
    t.eq(
        "wait4-after-tgkill",
        wait4(sleeper as isize, 0),
        (Ok(sleeper), SIGTERM as i32),
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
    // The middle process exits at once; its child waits (bounded) until init has adopted it and
    // reports in its exit status whether `getppid` became 1.
    let middle = spawn(|| {
        let grandchild = spawn(|| {
            for _ in 0..200 {
                if sys(Sysno::getppid, &[]) == Ok(1) {
                    break;
                }
                nap(5);
            }
            if sys(Sysno::getppid, &[]) == Ok(1) {
                11
            } else {
                12
            }
        });
        // The grandchild's pid travels in the exit status of the middle process (low bits).
        let _ = grandchild;
        10
    });
    // Init reaps both: the middle process (status 10) and the adopted grandchild (status 11).
    let mut seen = [(0usize, 0i32); 2];
    for slot in &mut seen {
        let (r, s) = wait4(-1, 0);
        *slot = (r.unwrap_or(0), s);
    }
    seen.sort_unstable_by_key(|&(_, status)| status);
    t.eq(
        "orphan-reaped-statuses",
        (seen[0].1, seen[1].1),
        (10 << 8, 11 << 8),
    );
    t.eq("orphan-middle-reported", seen[0].0, middle);
    t.holds(
        "orphan-adopted-by-init",
        seen[1].0 != middle && seen[1].0 != 0,
        seen,
        "the grandchild is a child of init",
    );
    t.eq("orphan-reaped-all", wait4(-1, 0).0, Err(Errno::ECHILD));
}

/// `clone` and `clone3` with the argument errors of `copy_process`, and the plain copies.
fn clone_arguments(t: &mut T) {
    reap_all();
    let clone =
        |flags: usize, tid_slot: usize| -> R { sys(Sysno::clone, &[flags, 0, tid_slot, 0, 0]) };
    t.eq(
        "clone-thread-without-sighand",
        clone(CLONE_THREAD | SIGCHLD, 0),
        Err(Errno::EINVAL),
    );
    t.eq(
        "clone-sighand-without-vm",
        clone(CLONE_SIGHAND | SIGCHLD, 0),
        Err(Errno::EINVAL),
    );
    t.eq(
        "clone-newns-with-fs",
        clone(CLONE_NEWNS | CLONE_FS | SIGCHLD, 0),
        Err(Errno::EINVAL),
    );
    t.eq(
        "clone-pidfd-with-detached",
        clone(CLONE_PIDFD | CLONE_DETACHED | SIGCHLD, 0),
        Err(Errno::EINVAL),
    );
    t.eq(
        "clone-pidfd-and-parent-settid-share-a-slot",
        clone(CLONE_PIDFD | CLONE_PARENT_SETTID | SIGCHLD, addr(&MEMORY)),
        Err(Errno::EINVAL),
    );
    t.eq(
        "clone-vm-thread-without-sighand-checked-first",
        clone(CLONE_THREAD | CLONE_VM | SIGCHLD, 0),
        Err(Errno::EINVAL),
    );
    // A plain copy: PARENT_SETTID stores the pid before the call returns.
    let mut stored = 0u32;
    let r = clone(CLONE_PARENT_SETTID | SIGCHLD, addr_mut(&mut stored));
    match r {
        Ok(0) => die(0),
        Ok(pid) => {
            t.eq(
                "clone-parent-settid",
                (stored as usize, wait4(pid as isize, 0)),
                (pid, (Ok(pid), 0)),
            );
        }
        Err(e) => t.eq("clone-parent-settid", Err::<usize, _>(e), Ok(0)),
    }
    // A faulting settid pointer does not fail the call.
    match clone(CLONE_PARENT_SETTID | SIGCHLD, BAD) {
        Ok(0) => die(3),
        Ok(pid) => t.eq(
            "clone-parent-settid-fault-ignored",
            wait4(pid as isize, 0),
            (Ok(pid), 3 << 8),
        ),
        Err(e) => t.eq(
            "clone-parent-settid-fault-ignored",
            Err::<(R, i32), _>(e),
            Ok((Ok(0), 0)),
        ),
    }
    // The exit signal chooses how the parent sees the child: SIGUSR1 (blocked here) makes it a
    // "clone child" that wait4 finds only with __WCLONE or __WALL.
    block(bit(SIGUSR1));
    match clone(SIGUSR1, 0) {
        Ok(0) => die(6),
        Ok(pid) => {
            t.eq(
                "clone-exit-signal-hides-from-plain-wait",
                wait4(pid as isize, 0).0,
                Err(Errno::ECHILD),
            );
            let mut set = 0u64;
            let mut info = [0i32; 32];
            let five = [5i64, 0];
            set |= bit(SIGUSR1);
            let r = sys(
                Sysno::rt_sigtimedwait,
                &[addr(&set), addr_mut(&mut info), addr(&five), 8],
            );
            t.eq(
                "clone-exit-signal-is-sent",
                (r, info[2], info[4]),
                (Ok(SIGUSR1), 1, pid as i32),
            );
            t.eq(
                "clone-wclone-finds-it",
                wait4(pid as isize, WCLONE),
                (Ok(pid), 6 << 8),
            );
        }
        Err(e) => t.eq(
            "clone-exit-signal-hides-from-plain-wait",
            Err::<R, _>(e),
            Ok(Ok(0)),
        ),
    }
    match clone(SIGUSR1, 0) {
        Ok(0) => die(7),
        Ok(pid) => t.eq(
            "clone-wall-finds-it",
            wait4(pid as isize, WALL),
            (Ok(pid), 7 << 8),
        ),
        Err(e) => t.eq("clone-wall-finds-it", Err::<(R, i32), _>(e), Ok((Ok(0), 0))),
    }
    // Exit signal 0: no signal, still a clone child.
    match clone(0, 0) {
        Ok(0) => die(8),
        Ok(pid) => {
            t.eq(
                "clone-no-exit-signal-needs-wclone",
                (wait4(pid as isize, WNOHANG).0, wait4(pid as isize, WCLONE)),
                (Err(Errno::ECHILD), (Ok(pid), 8 << 8)),
            );
        }
        Err(e) => t.eq(
            "clone-no-exit-signal-needs-wclone",
            Err::<(R, (R, i32)), _>(e),
            Ok((Ok(0), (Ok(0), 0))),
        ),
    }
    // Whatever is still pending is discarded by ignoring the signal before it is unblocked.
    let _ = sigaction(SIGUSR1, 1, 0);
    block(0);
    let _ = sigaction(SIGUSR1, 0, 0);
    reap_all();
    // clone3: a plain copy, then the argument errors in the kernel's order.
    let mut args = [0u64; 11];
    args[4] = SIGCHLD as u64;
    match sys(Sysno::clone3, &[addr(&args), 88]) {
        Ok(0) => die(21),
        Ok(pid) => t.eq(
            "clone3-plain-copy",
            wait4(pid as isize, 0),
            (Ok(pid), 21 << 8),
        ),
        Err(e) => t.eq("clone3-plain-copy", Err::<(R, i32), _>(e), Ok((Ok(0), 0))),
    }
    t.eq(
        "clone3-size-too-small",
        sys(Sysno::clone3, &[addr(&args), 63]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "clone3-size-zero",
        sys(Sysno::clone3, &[addr(&args), 0]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "clone3-size-too-big",
        sys(Sysno::clone3, &[addr(&args), 4097]),
        Err(Errno::E2BIG),
    );
    t.eq(
        "clone3-unreadable-struct",
        sys(Sysno::clone3, &[BAD, 88]),
        Err(Errno::EFAULT),
    );
    let mut bad = args;
    bad[4] = 65;
    t.eq(
        "clone3-invalid-exit-signal",
        sys(Sysno::clone3, &[addr(&bad), 88]),
        Err(Errno::EINVAL),
    );
    bad = args;
    bad[0] = 1 << 40;
    t.eq(
        "clone3-unknown-flag",
        sys(Sysno::clone3, &[addr(&bad), 88]),
        Err(Errno::EINVAL),
    );
    bad = args;
    bad[0] = CLONE_DETACHED as u64;
    t.eq(
        "clone3-detached-flag",
        sys(Sysno::clone3, &[addr(&bad), 88]),
        Err(Errno::EINVAL),
    );
    bad = args;
    bad[5] = 0x7000_0000;
    t.eq(
        "clone3-stack-without-size",
        sys(Sysno::clone3, &[addr(&bad), 88]),
        Err(Errno::EINVAL),
    );
    bad = args;
    bad[6] = 4096;
    t.eq(
        "clone3-size-without-stack",
        sys(Sysno::clone3, &[addr(&bad), 88]),
        Err(Errno::EINVAL),
    );
    bad = args;
    bad[9] = 1;
    t.eq(
        "clone3-set-tid-size-without-pointer",
        sys(Sysno::clone3, &[addr(&bad), 88]),
        Err(Errno::EINVAL),
    );
    // A larger struct must have zero trailing bytes.
    let mut big = [0u64; 12];
    big[4] = SIGCHLD as u64;
    big[11] = 1;
    t.eq(
        "clone3-nonzero-trailing-bytes",
        sys(Sysno::clone3, &[addr(&big), 96]),
        Err(Errno::E2BIG),
    );
}

fn exec(t: &mut T) {
    reap_all();
    let init = b"/init\0";
    let argv = [addr(b"/init\0"), addr(b"execd\0"), addr(b"third arg\0"), 0];
    let envp = [addr(b"EXEC=1\0"), 0];
    // A forked child replaces its image: the exit status is the new program's. Its one line of
    // output goes into a pipe nobody reads (it fits the buffer, so the writer never blocks) and
    // not to the console log, where the new image's banner would repeat init's first line.
    let mut fds = [0u32; 2];
    let _ = sys(Sysno::pipe2, &[addr_mut(&mut fds), 0]);
    let (read_end, write_end) = (fds[0] as usize, fds[1] as usize);
    let child = spawn(|| {
        let _ = sys(Sysno::dup3, &[write_end, 1, 0]);
        let r = sys(Sysno::execve, &[addr(init), addr(&argv), addr(&envp)]);
        // Only reached if execve failed.
        let _ = r;
        99
    });
    t.eq(
        "execve-in-child-exit-status",
        wait4(child as isize, 0),
        (Ok(child), 42 << 8),
    );
    let _ = sys(Sysno::close, &[read_end]);
    let _ = sys(Sysno::close, &[write_end]);
}

/// `forkleak` mode: 200 rounds of fork, exit and wait. Prints the counts (identical on the
/// pinned Linux) and, as an observation, the free RAM `sysinfo` reports before and after the
/// rounds (after two warm-up rounds, so the first use of each table is not counted); the
/// kernel-test case requires the two to be equal on this kernel, whose frames are all
/// accounted, while on the reference Linux slab and page-cache movement make them merely close.
pub fn forkleak() {
    fn free_ram() -> u64 {
        let mut info = [0u64; 14];
        let _ = sys(Sysno::sysinfo, &[addr_mut(&mut info)]);
        info[5]
    }
    let round = || {
        let child = spawn(|| 0);
        let (r, status) = wait4(child as isize, 0);
        r == Ok(child) && status == 0
    };
    let warm = round() && round();
    let before = free_ram();
    let mut reaped = 0usize;
    for _ in 0..200 {
        reaped += usize::from(round());
    }
    let after = free_ram();
    let none_left = wait4(-1, WNOHANG).0 == Err(Errno::ECHILD);
    super::emit(format_args!(
        "init: forkleak warm={warm} rounds=200 reaped={reaped} none_left={none_left}"
    ));
    super::emit(format_args!(
        "init: forkleak free_ram before={before} after={after}"
    ));
    if !(warm && reaped == 200 && none_left) {
        crate::exit(1);
    }
}

/// `forkbomb` mode (this kernel only: the stack pool is a named non-parity, Linux's limit is
/// `max_threads`): fork until `fork` fails, kill and reap everything, and do it again. The first
/// failure must be `EAGAIN`, every child must be reaped, a fork must work again afterwards and the
/// second flood must end where the first did with the same free RAM, which exercises every
/// failure path of `copy_process` that unwinds what it built.
pub fn forkbomb() {
    fn free_ram() -> u64 {
        let mut info = [0u64; 14];
        let _ = sys(Sysno::sysinfo, &[addr_mut(&mut info)]);
        info[5]
    }
    /// Forks until failure; returns (children, failed with EAGAIN, reaped).
    fn flood() -> (usize, bool, usize) {
        let mut pids = [0usize; 256];
        let mut made = 0;
        let mut eagain = false;
        while made < pids.len() {
            match sys(Sysno::fork, &[]) {
                Ok(0) => {
                    let _ = sys(Sysno::pause, &[]);
                    die(0);
                }
                Ok(pid) => {
                    pids[made] = pid;
                    made += 1;
                }
                Err(error) => {
                    eagain = error == Errno::EAGAIN;
                    break;
                }
            }
        }
        for &pid in &pids[..made] {
            let _ = sys(Sysno::kill, &[pid, SIGKILL]);
        }
        let mut reaped = 0;
        while let (Ok(pid), status) = wait4(-1, 0) {
            reaped += usize::from(pids[..made].contains(&pid) && status == 9);
        }
        (made, eagain, reaped)
    }
    let first = flood();
    let after_first = free_ram();
    let second = flood();
    let after_second = free_ram();
    let again = spawn(|| 0);
    let again_ok = wait4(again as isize, 0) == (Ok(again), 0);
    super::emit(format_args!(
        "init: forkbomb first children={} eagain={} reaped={}",
        first.0, first.1, first.2
    ));
    super::emit(format_args!(
        "init: forkbomb second children={} eagain={} reaped={} again={again_ok}",
        second.0, second.1, second.2
    ));
    super::emit(format_args!(
        "init: forkbomb free_ram after_first={after_first} after_second={after_second}"
    ));
    if !(first.1 && first.0 == first.2 && second.1 && second.0 == second.2 && again_ok) {
        crate::exit(1);
    }
}
