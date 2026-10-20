// SPDX-License-Identifier: GPL-2.0-only
//! `jobctl` group: job control beyond the `proc` rows. Group stop and continue by the four stop
//! signals (reported once, `WNOWAIT`, `WCONTINUED`, `SIGCHLD` with `CLD_STOPPED`/`CLD_CONTINUED`),
//! a stopped task that terminating signals wait for, `SIGCONT` before the stop was reported,
//! `kill` to a stopped process group, the rule that terminal stop signals do nothing in an
//! orphaned process group while `SIGSTOP` always works, the `SIGHUP` + `SIGCONT` a process group
//! gets when it becomes orphaned with a stopped member, and `setpgid`/`getsid` against children in
//! other groups and sessions and after `execve`. Linux 6.18.57: `kernel/signal.c`
//! (`prepare_signal`, `do_signal_stop`, `get_signal`, `task_participate_group_stop`),
//! `kernel/exit.c` (`will_become_orphaned_pgrp`, `kill_orphaned_pgrp`, `wait_task_stopped`,
//! `wait_task_continued`), `kernel/sys.c` (`setpgid`, `getsid`).
//!
//! A process group is orphaned when every member's parent is global init or inside the group
//! (`will_become_orphaned_pgrp`), so the test process (a child of nothing, pid 1) cannot make a
//! group that terminal stop signals still stop. Those checks run in a *middle process*, a child of
//! the test process whose own children each lead a group of their own: their parent is outside
//! the group, in the same session, which is the one link that keeps a group alive. The middle
//! process runs its checks with its own counters and hands them to the test process through a
//! pipe, so the lines of the group stay in one order and the one summary counts them all.
//!
//! Children report through their exit status and the signals they raise; they end with
//! `exit_group`. The re-executed image `/init jobwait` (see [`jobwait`]) is for the `setpgid`
//! check after `execve`.

use core::sync::atomic::{AtomicUsize, Ordering::Relaxed};

use syscalls::{Errno, Sysno};

use super::proc::{
    CHLD_COUNT, CHLD_INFO, SIGCHLD, SIGHUP, SIGKILL, SIGTERM, WEXITED, WNOHANG, WNOWAIT, nap,
    on_chld_ptr, reap_all, sigaction, spawn, wait4, waitid,
};
use super::signal::{SA_SIGINFO, bit};
use super::{R, T, addr, addr_mut, die, fn_addr, getpid, sys};

const SIGCONT: usize = 18;
const SIGSTOP: usize = 19;
const SIGTSTP: usize = 20;
const SIGTTIN: usize = 21;
const SIGTTOU: usize = 22;
const SA_NOCLDSTOP: u64 = 1;
const WUNTRACED: usize = 2;
const WCONTINUED: usize = 8;
const CLD_STOPPED: i32 = 5;
const CLD_CONTINUED: i32 = 6;
const EPERM: Errno = Errno::EPERM;

/// The write end of the pipe a signal handler of a child reports through.
static HANDLER_FD: AtomicUsize = AtomicUsize::new(0);

/// `wait4` status of a child stopped by `sig`.
fn stopped(sig: usize) -> i32 {
    ((sig as i32) << 8) | 0x7f
}

fn kill(pid: usize, sig: usize) -> R {
    sys(Sysno::kill, &[pid, sig])
}

fn kill_self(sig: usize) {
    let _ = kill(getpid(), sig);
}

fn pipe() -> (usize, usize) {
    let mut fds = [0u32; 2];
    let _ = sys(Sysno::pipe2, &[addr_mut(&mut fds), 0]);
    (fds[0] as usize, fds[1] as usize)
}

fn close(fd: usize) {
    let _ = sys(Sysno::close, &[fd]);
}

fn write_byte(fd: usize, byte: u8) {
    let _ = sys(Sysno::write, &[fd, addr(&byte), 1]);
}

/// Reads up to `buf.len()` bytes, until EOF; the number read.
fn read_all(fd: usize, buf: &mut [u8]) -> usize {
    let mut got = 0;
    while got < buf.len() {
        match sys(
            Sysno::read,
            &[fd, addr_mut(&mut buf[got..]), buf.len() - got],
        ) {
            Ok(n) if n > 0 => got += n,
            _ => break,
        }
    }
    got
}

/// Two wait results in pid order (the order in which two children are reported is not defined).
fn sorted(mut results: [(R, i32); 2]) -> [(R, i32); 2] {
    results.sort_unstable_by_key(|(r, _)| r.unwrap_or(0));
    results
}

/// A child that leads a process group of its own (the parent and the child both call `setpgid`,
/// so the group exists whichever runs first).
fn spawn_grouped(f: impl FnOnce() -> usize) -> usize {
    let pid = spawn(|| {
        let _ = sys(Sysno::setpgid, &[0, 0]);
        f()
    });
    let _ = sys(Sysno::setpgid, &[pid, pid]);
    pid
}

pub fn run() -> bool {
    let mut t = T::new("jobctl");
    reap_all();
    middle(&mut t, "stops-ran", stops);
    middle(&mut t, "notifications-ran", notifications);
    orphaned_group(&mut t);
    orphaned_hup(&mut t);
    sessions(&mut t);
    exec_and_setpgid(&mut t);
    reap_all();
    t.finish()
}

/// Runs `body` in a middle process (see the module comment) with its own counters, adds them to
/// `t` and checks that the process ran to its end.
fn middle(t: &mut T, name: &str, body: fn(&mut T)) {
    reap_all();
    let (rfd, wfd) = pipe();
    let m = spawn(|| {
        close(rfd);
        let mut local = T::new("jobctl");
        body(&mut local);
        reap_all();
        let (passed, failed) = local.counts();
        let words = [passed, failed];
        let _ = sys(Sysno::write, &[wfd, addr(&words), 8]);
        0
    });
    close(wfd);
    let mut words = [u32::MAX; 2];
    let mut bytes = [0u8; 8];
    let n = read_all(rfd, &mut bytes);
    close(rfd);
    words[0] = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    words[1] = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    t.eq(
        format_args!("{name}-to-the-end"),
        (n, wait4(m as isize, 0)),
        (8, (Ok(m), 0)),
    );
    if n == 8 {
        t.add(words[0], words[1]);
    }
}

/// Stop and continue, in a middle process: the children are not in an orphaned group.
fn stops(t: &mut T) {
    // Every stop signal stops, is reported once, and the continue lets the child exit.
    for (name, sig) in [
        ("sigstop", SIGSTOP),
        ("sigtstp", SIGTSTP),
        ("sigttin", SIGTTIN),
        ("sigttou", SIGTTOU),
    ] {
        let c = spawn_grouped(|| {
            kill_self(sig);
            3
        });
        t.eq(
            format_args!("{name}-stops"),
            wait4(c as isize, WUNTRACED),
            (Ok(c), stopped(sig)),
        );
        t.eq(
            format_args!("{name}-stop-reported-once"),
            wait4(c as isize, WUNTRACED | WNOHANG),
            (Ok(0), -1),
        );
        let _ = kill(c, SIGCONT);
        t.eq(
            format_args!("{name}-continues"),
            wait4(c as isize, 0),
            (Ok(c), 3 << 8),
        );
    }
    // A stopped child leaves terminating signals pending until it continues; then it dies of
    // the signal, which a handled signal would not have done.
    let c = spawn_grouped(|| {
        kill_self(SIGSTOP);
        let _ = sys(Sysno::pause, &[]);
        0
    });
    let _ = wait4(c as isize, WUNTRACED);
    t.eq(
        "sigterm-waits-for-the-continue",
        (
            kill(c, SIGTERM),
            wait4(c as isize, WNOHANG | WUNTRACED),
            waitid(1, c, WEXITED | WNOHANG).1[3],
        ),
        (Ok(0), (Ok(0), -1), 0),
    );
    let _ = kill(c, SIGCONT);
    t.eq(
        "sigcont-delivers-the-pending-sigterm",
        wait4(c as isize, 0),
        (Ok(c), SIGTERM as i32),
    );
    // SIGKILL does not wait.
    let c = spawn_grouped(|| {
        kill_self(SIGSTOP);
        0
    });
    let _ = wait4(c as isize, WUNTRACED);
    t.eq(
        "sigkill-kills-a-stopped-child",
        (kill(c, SIGKILL), wait4(c as isize, 0)),
        (Ok(0), (Ok(c), SIGKILL as i32)),
    );
    // WNOWAIT: the stop is reported again and again until a wait consumes it.
    let c = spawn_grouped(|| {
        kill_self(SIGTSTP);
        let _ = sys(Sysno::pause, &[]);
        0
    });
    let first = waitid(1, c, WUNTRACED | WNOWAIT);
    let second = waitid(1, c, WUNTRACED | WNOWAIT);
    // [si_signo, si_errno, si_code, si_pid, si_uid, si_status, ..]
    t.eq(
        "wnowait-stop-info",
        (first.0, first.1[0], first.1[2], first.1[3], first.1[5]),
        (Ok(0), SIGCHLD as i32, CLD_STOPPED, c as i32, SIGTSTP as i32),
    );
    t.eq("wnowait-stop-repeats", first, second);
    t.eq(
        "wnowait-then-wait-consumes",
        (
            wait4(c as isize, WUNTRACED),
            wait4(c as isize, WUNTRACED | WNOHANG),
        ),
        ((Ok(c), stopped(SIGTSTP)), (Ok(0), -1)),
    );
    // SIGCONT before the stop was reported: the report is gone, the continue is not.
    let _ = kill(c, SIGCONT);
    t.eq(
        "continue-cancels-the-unreported-stop",
        wait4(c as isize, WUNTRACED | WNOHANG),
        (Ok(0), -1),
    );
    let (r, info) = waitid(1, c, WCONTINUED);
    t.eq(
        "continue-is-reported",
        (r, info[0], info[2], info[3], info[5]),
        (
            Ok(0),
            SIGCHLD as i32,
            CLD_CONTINUED,
            c as i32,
            SIGCONT as i32,
        ),
    );
    t.eq(
        "continue-reported-once",
        wait4(c as isize, WCONTINUED | WNOHANG),
        (Ok(0), -1),
    );
    let _ = kill(c, SIGKILL);
    let _ = wait4(c as isize, 0);
    // The continue that was never reported is replaced by the next stop.
    let c = spawn_grouped(|| {
        kill_self(SIGSTOP);
        kill_self(SIGSTOP);
        2
    });
    let _ = waitid(1, c, WUNTRACED | WNOWAIT);
    let _ = kill(c, SIGCONT);
    // Blocks until the child stopped again (the continue cleared the first stop's code).
    let _ = waitid(1, c, WUNTRACED | WNOWAIT);
    t.eq(
        "second-stop-replaces-the-unreported-continue",
        (
            wait4(c as isize, WCONTINUED | WNOHANG),
            wait4(c as isize, WUNTRACED),
        ),
        ((Ok(0), -1), (Ok(c), stopped(SIGSTOP))),
    );
    let _ = kill(c, SIGCONT);
    t.eq(
        "stop-continue-stop-then-exit",
        wait4(c as isize, 0),
        (Ok(c), 2 << 8),
    );
    // SIGCONT to a child that never stopped is not a continue.
    let (rfd, wfd) = pipe();
    let c = spawn_grouped(|| {
        close(wfd);
        let mut byte = [0u8; 1];
        let _ = read_all(rfd, &mut byte);
        4
    });
    let _ = kill(c, SIGCONT);
    t.eq(
        "sigcont-on-a-running-child-reports-nothing",
        wait4(c as isize, WCONTINUED | WNOHANG),
        (Ok(0), -1),
    );
    close(wfd);
    close(rfd);
    t.eq(
        "running-child-unharmed",
        wait4(c as isize, 0),
        (Ok(c), 4 << 8),
    );
    // A handled stop signal runs its handler and does not stop.
    let c = spawn_grouped(|| {
        let _ = sigaction(SIGTSTP, handler_ptr(), 0);
        HANDLER_FD.store(0, Relaxed);
        kill_self(SIGTSTP);
        HANDLER_FD.load(Relaxed) + 1
    });
    t.eq(
        "handled-stop-signal-does-not-stop",
        wait4(c as isize, WUNTRACED),
        (Ok(c), 2 << 8),
    );
    // Blocked: pending until unblocked; a SIGCONT discards a pending stop signal and the other
    // way round (`prepare_signal`).
    let c = spawn_grouped(|| {
        let mut word = 0usize;
        super::proc::block(bit(SIGTSTP) | bit(SIGCONT));
        kill_self(SIGTSTP);
        word |= usize::from(pending() & bit(SIGTSTP) != 0);
        kill_self(SIGCONT);
        let after_cont = pending();
        word |= usize::from(after_cont & bit(SIGTSTP) == 0) << 1;
        word |= usize::from(after_cont & bit(SIGCONT) != 0) << 2;
        kill_self(SIGTSTP);
        let after_stop = pending();
        word |= usize::from(after_stop & bit(SIGCONT) == 0) << 3;
        word |= usize::from(after_stop & bit(SIGTSTP) != 0) << 4;
        word
    });
    t.eq(
        "stop-and-continue-discard-each-other",
        wait4(c as isize, WUNTRACED),
        (Ok(c), 0x1f << 8),
    );
    // A whole group: the stop signal reaches every member, the continue wakes them all.
    let (rfd, wfd) = pipe();
    let a = spawn_grouped(|| {
        close(wfd);
        let mut byte = [0u8; 1];
        let _ = read_all(rfd, &mut byte);
        5
    });
    let b = spawn(|| {
        let _ = sys(Sysno::setpgid, &[0, a]);
        close(wfd);
        let mut byte = [0u8; 1];
        let _ = read_all(rfd, &mut byte);
        6
    });
    let _ = sys(Sysno::setpgid, &[b, a]);
    t.eq(
        "setpgid-joins-a-sibling-group",
        sys(Sysno::getpgid, &[b]),
        Ok(a),
    );
    t.eq(
        "kill-group-stop",
        kill(0usize.wrapping_sub(a), SIGSTOP),
        Ok(0),
    );
    t.eq(
        "kill-group-stops-every-member",
        sorted([wait4(-1, WUNTRACED), wait4(-1, WUNTRACED)]),
        sorted([(Ok(a), stopped(SIGSTOP)), (Ok(b), stopped(SIGSTOP))]),
    );
    t.eq(
        "kill-group-continue",
        kill(0usize.wrapping_sub(a), SIGCONT),
        Ok(0),
    );
    // Both continues are reported before either child can exit (they wait for the pipe to close).
    t.eq(
        "kill-group-continues-every-member",
        sorted([wait4(-1, WCONTINUED), wait4(-1, WCONTINUED)]),
        sorted([(Ok(a), 0xffff), (Ok(b), 0xffff)]),
    );
    close(wfd);
    close(rfd);
    t.eq(
        "group-members-exit-after-continue",
        sorted([wait4(-1, 0), wait4(-1, 0)]),
        sorted([(Ok(a), 5 << 8), (Ok(b), 6 << 8)]),
    );
    // wait4(-1, WUNTRACED) finds the stopped child among running ones.
    let (rfd, wfd) = pipe();
    let runner = spawn_grouped(|| {
        close(wfd);
        let mut byte = [0u8; 1];
        let _ = read_all(rfd, &mut byte);
        0
    });
    let sleeper = spawn_grouped(|| {
        nap(20);
        kill_self(SIGSTOP);
        0
    });
    t.eq(
        "wait-sleeps-until-a-child-stops",
        wait4(-1, WUNTRACED),
        (Ok(sleeper), stopped(SIGSTOP)),
    );
    let _ = kill(sleeper, SIGCONT);
    close(wfd);
    close(rfd);
    t.eq(
        "the-others-exit-normally",
        sorted([wait4(-1, 0), wait4(-1, 0)]),
        sorted([(Ok(runner), 0), (Ok(sleeper), 0)]),
    );
}

/// `rt_sigpending` as a bit set.
fn pending() -> u64 {
    let mut set = 0u64;
    let _ = sys(Sysno::rt_sigpending, &[addr_mut(&mut set), 8]);
    set
}

/// A handler that records that it ran in a static and, if a pipe is set, writes `H` to it.
extern "C" fn on_signal(_sig: i32) {
    let fd = HANDLER_FD.load(Relaxed);
    if fd != 0 {
        write_byte(fd, b'H');
    } else {
        HANDLER_FD.store(1, Relaxed);
    }
}

fn handler_ptr() -> u64 {
    fn_addr(on_signal as *const ())
}

/// The `SIGCHLD` the parent gets for a stop and for a continue.
fn notifications(t: &mut T) {
    CHLD_COUNT.store(0, Relaxed);
    let _ = sigaction(SIGCHLD, on_chld_ptr(), SA_SIGINFO);
    let c = spawn_grouped(|| {
        kill_self(SIGTSTP);
        let _ = sys(Sysno::pause, &[]);
        0
    });
    let _ = wait4(c as isize, WUNTRACED);
    t.eq(
        "sigchld-for-a-stop",
        (
            CHLD_COUNT.load(Relaxed),
            CHLD_INFO[0].load(Relaxed),
            CHLD_INFO[1].load(Relaxed),
            CHLD_INFO[3].load(Relaxed),
        ),
        (1, CLD_STOPPED as usize, c, SIGTSTP),
    );
    CHLD_COUNT.store(0, Relaxed);
    let _ = kill(c, SIGCONT);
    let _ = wait4(c as isize, WCONTINUED);
    // The child sends this one when it wakes, after the parent's wait may have returned.
    for _ in 0..200 {
        if CHLD_COUNT.load(Relaxed) > 0 {
            break;
        }
        nap(5);
    }
    t.eq(
        "sigchld-for-a-continue",
        (
            CHLD_COUNT.load(Relaxed),
            CHLD_INFO[0].load(Relaxed),
            CHLD_INFO[1].load(Relaxed),
            CHLD_INFO[3].load(Relaxed),
        ),
        (1, CLD_CONTINUED as usize, c, SIGCONT),
    );
    let _ = kill(c, SIGKILL);
    let _ = wait4(c as isize, 0);
    // SA_NOCLDSTOP: no signal for either, the wait still reports both.
    let _ = sigaction(SIGCHLD, on_chld_ptr(), SA_SIGINFO | SA_NOCLDSTOP);
    CHLD_COUNT.store(0, Relaxed);
    let c = spawn_grouped(|| {
        kill_self(SIGSTOP);
        let _ = sys(Sysno::pause, &[]);
        0
    });
    let first = wait4(c as isize, WUNTRACED);
    let _ = kill(c, SIGCONT);
    let second = wait4(c as isize, WCONTINUED);
    nap(30);
    t.eq(
        "nocldstop-reports-without-a-signal",
        (first, second, CHLD_COUNT.load(Relaxed)),
        ((Ok(c), stopped(SIGSTOP)), (Ok(c), 0xffff), 0),
    );
    let _ = kill(c, SIGKILL);
    let _ = wait4(c as isize, 0);
    // The exit is still announced.
    t.eq(
        "nocldstop-still-announces-the-exit",
        CHLD_COUNT.load(Relaxed),
        1,
    );
    let _ = sigaction(SIGCHLD, 0, 0);
}

/// The test process's own children are in an orphaned group (pgrp 0, parent: global init):
/// terminal stop signals do nothing, `SIGSTOP` always works, a handler still runs.
fn orphaned_group(t: &mut T) {
    reap_all();
    for (name, sig) in [
        ("sigtstp", SIGTSTP),
        ("sigttin", SIGTTIN),
        ("sigttou", SIGTTOU),
    ] {
        let c = spawn(|| {
            kill_self(sig);
            5
        });
        t.eq(
            format_args!("orphaned-{name}-is-dropped"),
            wait4(c as isize, WUNTRACED),
            (Ok(c), 5 << 8),
        );
    }
    let c = spawn(|| {
        kill_self(SIGSTOP);
        6
    });
    t.eq(
        "orphaned-sigstop-still-stops",
        wait4(c as isize, WUNTRACED),
        (Ok(c), stopped(SIGSTOP)),
    );
    let _ = kill(c, SIGCONT);
    t.eq(
        "orphaned-sigstop-continues",
        wait4(c as isize, 0),
        (Ok(c), 6 << 8),
    );
    let c = spawn(|| {
        let _ = sigaction(SIGTSTP, handler_ptr(), 0);
        HANDLER_FD.store(0, Relaxed);
        kill_self(SIGTSTP);
        HANDLER_FD.load(Relaxed) + 6
    });
    t.eq(
        "orphaned-handled-sigtstp-runs-its-handler",
        wait4(c as isize, WUNTRACED),
        (Ok(c), 7 << 8),
    );
}

/// A group that becomes orphaned with a stopped member gets `SIGHUP` and then `SIGCONT`
/// (`kill_orphaned_pgrp`). The stopped member `S` leads a group; its parent `M` (a child of the
/// test process, in the test process's group) is the one link outside, and exits; `S` is then the
/// test process's child.
fn orphaned_hup(t: &mut T) {
    // What S does once it stops; `HANDLER_FD` is the pipe its handler writes to.
    #[derive(Clone, Copy)]
    enum Variant {
        Handler,
        Default,
        Blocked,
        Running,
    }
    for (name, variant) in [
        ("handled", Variant::Handler),
        ("default-action", Variant::Default),
        ("blocked", Variant::Blocked),
        ("no-stopped-member", Variant::Running),
    ] {
        reap_all();
        let (rfd, wfd) = pipe();
        let (pr, pw) = pipe();
        let (gr, gw) = pipe();
        let m = spawn(|| {
            let s = spawn_grouped(|| {
                close(pr);
                close(gw);
                HANDLER_FD.store(wfd, Relaxed);
                match variant {
                    Variant::Handler => {
                        let _ = sigaction(SIGHUP, handler_ptr(), 0);
                        kill_self(SIGSTOP);
                    }
                    Variant::Default => kill_self(SIGSTOP),
                    Variant::Blocked => {
                        super::proc::block(bit(SIGHUP));
                        kill_self(SIGSTOP);
                        write_byte(
                            wfd,
                            if pending() & bit(SIGHUP) != 0 {
                                b'P'
                            } else {
                                b'-'
                            },
                        );
                    }
                    Variant::Running => {
                        let mut byte = [0u8; 1];
                        let _ = read_all(gr, &mut byte);
                    }
                }
                write_byte(wfd, b'C');
                7
            });
            // Tell the test process who S is, then (but for the running variant) wait until
            // S has stopped, so that the exit below orphans a group with a stopped member.
            let words = [s];
            let _ = sys(Sysno::write, &[pw, addr(&words), 8]);
            if !matches!(variant, Variant::Running) {
                let (r, _) = wait4(s as isize, WUNTRACED);
                if r != Ok(s) {
                    return 1;
                }
            }
            0
        });
        close(pw);
        close(wfd);
        close(gr);
        let mut pid = [0u8; 8];
        let _ = read_all(pr, &mut pid);
        close(pr);
        let s = usize::from_le_bytes(pid);
        t.eq(
            format_args!("orphaned-{name}-parent-exits"),
            wait4(m as isize, 0),
            (Ok(m), 0),
        );
        // Whatever S wrote while the group was signalled.
        match variant {
            Variant::Running => write_byte(gw, b'x'),
            _ => {}
        }
        close(gw);
        let mut out = [0u8; 4];
        let n = read_all(rfd, &mut out);
        close(rfd);
        let (want_out, want_status): (&[u8], (R, i32)) = match variant {
            Variant::Handler => (b"HC", (Ok(s), 7 << 8)),
            Variant::Default => (b"", (Ok(s), SIGHUP as i32)),
            Variant::Blocked => (b"PC", (Ok(s), 7 << 8)),
            Variant::Running => (b"C", (Ok(s), 7 << 8)),
        };
        t.eq(
            format_args!("orphaned-{name}-what-the-member-saw"),
            &out[..n],
            want_out,
        );
        t.eq(
            format_args!("orphaned-{name}-member-status"),
            wait4(s as isize, 0),
            want_status,
        );
    }
}

/// `setpgid` and `getsid` against children in other groups and sessions.
fn sessions(t: &mut T) {
    reap_all();
    let (rfd, wfd) = pipe();
    let (gr, gw) = pipe();
    let leader = spawn(|| {
        close(rfd);
        close(gw);
        let me = getpid();
        let ok = sys(Sysno::setsid, &[]) == Ok(me);
        write_byte(wfd, u8::from(ok));
        let mut byte = [0u8; 1];
        let _ = read_all(gr, &mut byte);
        0
    });
    close(wfd);
    close(gr);
    let mut ready = [0u8; 1];
    let _ = read_all(rfd, &mut ready);
    close(rfd);
    t.eq("child-became-a-session-leader", ready, [1]);
    t.eq(
        "getsid-of-a-child-in-another-session",
        (
            sys(Sysno::getsid, &[leader]),
            sys(Sysno::getpgid, &[leader]),
            sys(Sysno::getsid, &[0]),
        ),
        (Ok(leader), Ok(leader), Ok(0)),
    );
    t.eq(
        "setpgid-of-a-child-in-another-session",
        sys(Sysno::setpgid, &[leader, leader]),
        Err(EPERM),
    );
    t.eq(
        "setpgid-into-a-group-of-another-session",
        sys(Sysno::setpgid, &[0, leader]),
        Err(EPERM),
    );
    t.eq(
        "setpgid-into-a-group-that-does-not-exist",
        sys(Sysno::setpgid, &[0, 99_999]),
        Err(EPERM),
    );
    t.eq(
        "kill-probes-a-group-of-another-session",
        kill(0usize.wrapping_sub(leader), 0),
        Ok(0),
    );
    close(gw);
    t.eq(
        "session-leader-exits",
        wait4(leader as isize, 0),
        (Ok(leader), 0),
    );
}

/// `setpgid` of a child that has called `execve` is `EACCES`, and `setpgid` of one that has not is
/// allowed (`PF_FORKNOEXEC`).
fn exec_and_setpgid(t: &mut T) {
    reap_all();
    let (ready_r, ready_w) = pipe();
    let (in_r, in_w) = pipe();
    let mut ready = [0u8; 1];
    let c = spawn(|| {
        close(ready_r);
        close(in_w);
        let _ = sys(Sysno::dup3, &[in_r, 0, 0]);
        let _ = sys(Sysno::dup3, &[ready_w, 40, 0]);
        let argv = [addr(b"/init\0"), addr(b"jobwait\0"), 0];
        let envp = [0usize];
        let _ = sys(Sysno::execve, &[addr(b"/init\0"), addr(&argv), addr(&envp)]);
        99
    });
    close(ready_w);
    close(in_r);
    let _ = read_all(ready_r, &mut ready);
    close(ready_r);
    t.eq("exec-image-is-running", ready, [1]);
    t.eq(
        "setpgid-after-execve",
        sys(Sysno::setpgid, &[c, c]),
        Err(Errno::EACCES),
    );
    t.eq("getpgid-unchanged", sys(Sysno::getpgid, &[c]), Ok(0));
    close(in_w);
    t.eq("exec-image-exits", wait4(c as isize, 0), (Ok(c), 17 << 8));
}

/// The image `/init jobwait` of [`exec_and_setpgid`]: say hello on descriptor 40, wait for the
/// end of standard input and exit 17.
pub fn jobwait() -> ! {
    write_byte(40, 1);
    let mut byte = [0u8; 1];
    let _ = read_all(0, &mut byte);
    die(17)
}
