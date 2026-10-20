// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: kernel/signal.c (the syscall
// entry points), kernel/time/itimer.c, arch/x86/kernel/signal_64.c
// (`rt_sigreturn`); the logic lives in `crate::signal`. GPL-2.0-only.
#![forbid(unsafe_code)]
//! Signal syscalls: `rt_sigaction`, `rt_sigprocmask`, `rt_sigpending`,
//! `sigaltstack`, `kill`, `tkill`, `tgkill`, `rt_sigqueueinfo`,
//! `rt_tgsigqueueinfo`, `rt_sigreturn`, `rt_sigsuspend`, `rt_sigtimedwait`,
//! `pause`, `restart_syscall`, `setitimer`, `getitimer` and `alarm`.
//!
//! The pure decisions are in [`crate::signal`]; this file only maps the raw
//! argument registers onto them. A target other than the caller (another
//! process, a process group, every process) goes through the task list
//! ([`crate::task::Tasklist`]: `kill_something_info`, `kill_proc_info`,
//! `send_specific`); a send to the caller itself keeps the `State`-level path
//! whose queue semantics `crate::signal::syscalls` tests (the same send
//! function underneath; the task-list path adds the permission check and the
//! wake-up of the target). The CPU-time interval timers (`ITIMER_VIRTUAL`,
//! `ITIMER_PROF`) stop loudly as [`Outcome::Unimplemented`]: they need the
//! time lane's CPU accounting.

use super::{Context, Outcome, error};
use crate::signal::{
    info::SigInfo,
    itimer::{sys_alarm, sys_getitimer, sys_setitimer},
    syscalls::{copy_siginfo_from_user, queueinfo_perm},
    syscalls::{
        sys_kill, sys_rt_sigaction, sys_rt_sigpending, sys_rt_sigprocmask, sys_rt_sigqueueinfo,
        sys_rt_tgsigqueueinfo, sys_sigaltstack, sys_tgkill, sys_tkill,
    },
    wait::{sys_pause, sys_rt_sigsuspend, sys_rt_sigtimedwait},
};
use syscalls::Sysno;

pub(super) fn dispatch<C: Context>(ctx: &mut C, sysno: Sysno, a: [u64; 6]) -> Option<Outcome> {
    let number = sysno as u32;
    let unimplemented =
        |value: Option<i64>| Some(value.map_or(Outcome::Unimplemented(number), Outcome::Return));
    let value = match sysno {
        Sysno::rt_sigaction => {
            let (mut state, mut pages) = ctx.parts();
            sys_rt_sigaction(&mut state, &mut pages, a[0], a[1], a[2], a[3])
        }
        Sysno::rt_sigprocmask => {
            let (mut state, mut pages) = ctx.parts();
            sys_rt_sigprocmask(&mut state, &mut pages, a[0], a[1], a[2], a[3])
        }
        Sysno::rt_sigpending => {
            let (state, mut pages) = ctx.parts();
            sys_rt_sigpending(&state, &mut pages, a[0], a[1])
        }
        Sysno::sigaltstack => {
            let sp = ctx.user_sp();
            let (mut state, mut pages) = ctx.parts();
            sys_sigaltstack(&mut state, &mut pages, a[0], a[1], sp)
        }
        Sysno::kill => return Some(kill(ctx, a)),
        Sysno::tkill => return Some(tkill(ctx, a)),
        Sysno::tgkill => return Some(tgkill(ctx, a)),
        Sysno::rt_sigqueueinfo => return Some(rt_sigqueueinfo(ctx, a)),
        Sysno::rt_tgsigqueueinfo => return Some(rt_tgsigqueueinfo(ctx, a)),
        // The syscall's value is the restored `rax` (0 after a bad frame).
        #[allow(clippy::cast_possible_wrap)]
        Sysno::rt_sigreturn => ctx.rt_sigreturn().ret as i64,
        Sysno::rt_sigsuspend => sys_rt_sigsuspend(ctx, a[0], a[1]),
        Sysno::rt_sigtimedwait => sys_rt_sigtimedwait(ctx, a[0], a[1], a[2], a[3]),
        Sysno::pause => sys_pause(ctx),
        Sysno::setitimer => return unimplemented(sys_setitimer(ctx, a[0], a[1], a[2])),
        Sysno::getitimer => return unimplemented(sys_getitimer(ctx, a[0], a[1])),
        Sysno::alarm => sys_alarm(ctx, a[0]),
        _ => return None,
    };
    Some(Outcome::Return(value))
}

/// `int` syscall parameters are the low 32 bits of the register.
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
const fn int(register: u64) -> i32 {
    register as u32 as i32
}

fn status(result: Result<(), syscalls::Errno>) -> i64 {
    result.map_or_else(error, |()| 0)
}

/// `prepare_kill_siginfo` for the caller: `SI_USER` for `kill`, `SI_TKILL`
/// for `tkill`/`tgkill`, from the caller's tgid and uid.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn kill_info<C: Context>(ctx: &mut C, sig: i32, thread: bool) -> SigInfo {
    let (tgid, uid) = (ctx.tgid().cast_signed(), ctx.attrs().cred.uid);
    SigInfo::from_kill(sig as u8, thread, tgid, uid)
}

/// `kill(pid, sig)`: `kill_something_info` for every target but the caller's
/// own process, the `State`-level send for it.
fn kill<C: Context>(ctx: &mut C, a: [u64; 6]) -> Outcome {
    let (pid, sig) = (int(a[0]), int(a[1]));
    if i64::from(pid) == i64::from(ctx.tgid())
        && let Some(value) = sys_kill(&mut ctx.state(), a[0], a[1])
    {
        return Outcome::Return(value);
    }
    let info = kill_info(ctx, sig, false);
    let t = ctx.tasks();
    Outcome::Return(status(
        t.list
            .kill_something_info(t.current, sig, info, pid, t.wake),
    ))
}

/// `tkill(tid, sig)`.
fn tkill<C: Context>(ctx: &mut C, a: [u64; 6]) -> Outcome {
    let (tid, sig) = (int(a[0]), int(a[1]));
    if tid > 0 && i64::from(tid) != i64::from(ctx.tid()) {
        return send_specific(ctx, 0, tid, sig);
    }
    Outcome::Return(sys_tkill(&mut ctx.state(), a[0], a[1]))
}

/// `tgkill(tgid, tid, sig)`.
#[allow(clippy::similar_names)]
fn tgkill<C: Context>(ctx: &mut C, a: [u64; 6]) -> Outcome {
    let (tgid, tid, sig) = (int(a[0]), int(a[1]), int(a[2]));
    let itself = i64::from(tid) == i64::from(ctx.tid()) && i64::from(tgid) == i64::from(ctx.tgid());
    if tid > 0 && tgid > 0 && !itself {
        return send_specific(ctx, tgid, tid, sig);
    }
    Outcome::Return(sys_tgkill(&mut ctx.state(), a[0], a[1], a[2]))
}

/// `do_tkill` for a thread other than the caller.
#[allow(clippy::similar_names)]
fn send_specific<C: Context>(ctx: &mut C, tgid: i32, tid: i32, sig: i32) -> Outcome {
    let info = kill_info(ctx, sig, true);
    let t = ctx.tasks();
    Outcome::Return(status(
        t.list
            .send_specific(t.current, tgid, tid, sig, info, t.wake),
    ))
}

/// `rt_sigqueueinfo(pid, sig, uinfo)` for a process other than the caller:
/// copy and validate the user info, the `EPERM` rule, then `kill_proc_info`.
fn rt_sigqueueinfo<C: Context>(ctx: &mut C, a: [u64; 6]) -> Outcome {
    let (pid, sig) = (int(a[0]), int(a[1]));
    if i64::from(pid) == i64::from(ctx.tgid()) {
        let (mut state, mut pages) = ctx.parts();
        return Outcome::Return(sys_rt_sigqueueinfo(
            &mut state, &mut pages, a[0], a[1], a[2],
        ));
    }
    let info = match copy_siginfo_from_user(ctx, sig, a[2]) {
        Ok(info) => info,
        Err(errno) => return Outcome::Return(error(errno)),
    };
    #[allow(clippy::cast_possible_wrap)]
    if let Err(errno) = queueinfo_perm(&info, ctx.tid() as i32, pid) {
        return Outcome::Return(error(errno));
    }
    let t = ctx.tasks();
    Outcome::Return(status(
        t.list.kill_proc_info(t.current, sig, info, pid, t.wake),
    ))
}

/// `rt_tgsigqueueinfo(tgid, tid, sig, uinfo)` for a thread other than the caller.
#[allow(clippy::similar_names)]
fn rt_tgsigqueueinfo<C: Context>(ctx: &mut C, a: [u64; 6]) -> Outcome {
    let (tgid, tid, sig) = (int(a[0]), int(a[1]), int(a[2]));
    let itself = i64::from(tid) == i64::from(ctx.tid()) && i64::from(tgid) == i64::from(ctx.tgid());
    if itself || tid <= 0 || tgid <= 0 {
        let (mut state, mut pages) = ctx.parts();
        return Outcome::Return(sys_rt_tgsigqueueinfo(
            &mut state, &mut pages, a[0], a[1], a[2], a[3],
        ));
    }
    let info = match copy_siginfo_from_user(ctx, sig, a[3]) {
        Ok(info) => info,
        Err(errno) => return Outcome::Return(error(errno)),
    };
    #[allow(clippy::cast_possible_wrap)]
    if let Err(errno) = queueinfo_perm(&info, ctx.tid() as i32, tid) {
        return Outcome::Return(error(errno));
    }
    let t = ctx.tasks();
    Outcome::Return(status(
        t.list
            .send_specific(t.current, tgid, tid, sig, info, t.wake),
    ))
}

#[cfg(test)]
mod tests {
    use super::super::{Outcome, dispatch, error, testing::task};
    use crate::{
        signal::{
            SA_RESTORER, SA_SIGINFO, SIGALRM, SIGUSR1, SIGUSR2, SigAction, SigSet, info::SigInfo,
            state::Target,
        },
        usercopy::copy_from_user,
    };
    use syscalls::{Errno, Sysno};

    const PAGE: u64 = 0x1000;
    fn neg(errno: Errno) -> Outcome {
        Outcome::Return(error(errno))
    }
    fn call(t: &mut super::super::testing::Task, no: Sysno, a: &[u64]) -> Outcome {
        let mut args = [0u64; 6];
        args[..a.len()].copy_from_slice(a);
        dispatch(t, no as u64, args)
    }
    fn put(t: &mut super::super::testing::Task, at: u64, bytes: &[u8]) {
        assert_eq!(crate::usercopy::copy_to_user(t, at, bytes), 0);
    }
    fn get<const N: usize>(t: &mut super::super::testing::Task, at: u64) -> [u8; N] {
        let mut out = [0u8; N];
        assert_eq!(copy_from_user(t, &mut out, at), 0);
        out
    }
    fn mapped() -> super::super::testing::Task {
        let mut t = task();
        t.pages.map(PAGE, true);
        t
    }
    fn itimerval(interval: (i64, i64), value: (i64, i64)) -> [u8; 32] {
        let mut raw = [0u8; 32];
        for (i, v) in [interval.0, interval.1, value.0, value.1]
            .into_iter()
            .enumerate()
        {
            raw[8 * i..8 * i + 8].copy_from_slice(&v.to_le_bytes());
        }
        raw
    }

    #[test]
    fn group_covers_exactly_the_signal_syscalls() {
        let mut t = mapped();
        for no in [
            Sysno::getpid,
            Sysno::write,
            Sysno::exit,
            Sysno::mmap,
            Sysno::rt_sigaction,
        ] {
            let claimed = super::dispatch(&mut t, no, [0; 6]).is_some();
            assert_eq!(claimed, no == Sysno::rt_sigaction, "{no:?}");
        }
        // kill(0) signals the caller's group (init alone: the signal is
        // dropped for it, the call succeeds); kill(-1) finds no process but
        // init and the caller: ESRCH.
        assert_eq!(call(&mut t, Sysno::kill, &[0, 9]), Outcome::Return(0));
        assert_eq!(call(&mut t, Sysno::kill, &[u64::MAX, 9]), neg(Errno::ESRCH));
        // CPU-time interval timers wait for the time lane.
        assert_eq!(
            call(&mut t, Sysno::setitimer, &[1, 0, 0]),
            Outcome::Unimplemented(Sysno::setitimer as u32)
        );
        assert_eq!(
            call(&mut t, Sysno::getitimer, &[2, PAGE]),
            Outcome::Unimplemented(Sysno::getitimer as u32)
        );
        assert_eq!(
            call(&mut t, Sysno::getitimer, &[3, PAGE]),
            neg(Errno::EINVAL)
        );
    }

    #[test]
    fn sigaction_kill_and_pending_reach_the_state() {
        let mut t = mapped();
        let act = SigAction {
            handler: 0x4000,
            flags: SA_SIGINFO | SA_RESTORER,
            restorer: 0x5000,
            mask: SigSet(0),
        };
        put(&mut t, PAGE, &act.to_bytes());
        let sig = u64::from(SIGUSR1);
        assert_eq!(
            call(&mut t, Sysno::rt_sigaction, &[sig, PAGE, 0, 8]),
            Outcome::Return(0)
        );
        assert_eq!(t.state.hand.actions[usize::from(SIGUSR1) - 1], act);
        // Block it, send it to ourselves, see it pending, unblock.
        put(&mut t, PAGE + 64, &SigSet::bit(SIGUSR1).to_le_bytes());
        assert_eq!(
            call(&mut t, Sysno::rt_sigprocmask, &[0, PAGE + 64, 0, 8]),
            Outcome::Return(0)
        );
        assert_eq!(call(&mut t, Sysno::kill, &[1, sig]), Outcome::Return(0));
        assert_eq!(
            call(&mut t, Sysno::rt_sigpending, &[PAGE + 128, 8]),
            Outcome::Return(0)
        );
        assert_eq!(
            get::<8>(&mut t, PAGE + 128),
            SigSet::bit(SIGUSR1).to_le_bytes()
        );
        assert_eq!(call(&mut t, Sysno::tgkill, &[1, 2, sig]), neg(Errno::ESRCH));
        assert_eq!(call(&mut t, Sysno::tkill, &[1, 65]), neg(Errno::EINVAL));
    }

    #[test]
    fn pause_sleeps_until_a_signal_and_asks_for_a_restart() {
        let mut t = mapped();
        t.script_signal(5_000, SIGUSR1);
        assert_eq!(call(&mut t, Sysno::pause, &[]), Outcome::Return(-514));
        assert_eq!(t.now, 5_000);
        assert!(t.state.pending_set().contains(SIGUSR1));
        // Already pending (unblocked): returns without waiting.
        let waits = t.waits;
        assert_eq!(call(&mut t, Sysno::pause, &[]), Outcome::Return(-514));
        assert_eq!(t.waits, waits);
    }

    #[test]
    fn sigsuspend_swaps_the_mask_and_keeps_the_old_one_for_the_return_path() {
        let mut t = mapped();
        t.state
            .set_blocked(SigSet(SigSet::bit(SIGUSR1) | SigSet::bit(SIGUSR2)));
        put(&mut t, PAGE, &0u64.to_le_bytes());
        t.script_signal(1_000, SIGUSR2);
        assert_eq!(
            call(&mut t, Sysno::rt_sigsuspend, &[PAGE, 8]),
            Outcome::Return(-514)
        );
        assert_eq!(t.state.me.blocked, SigSet::EMPTY);
        assert_eq!(
            t.state.me.saved_sigmask,
            Some(SigSet(SigSet::bit(SIGUSR1) | SigSet::bit(SIGUSR2)))
        );
        // Order: size, then the fault, before anything changes.
        let before = t.state.me.blocked;
        assert_eq!(
            call(&mut t, Sysno::rt_sigsuspend, &[PAGE, 4]),
            neg(Errno::EINVAL)
        );
        assert_eq!(
            call(&mut t, Sysno::rt_sigsuspend, &[0x9000, 8]),
            neg(Errno::EFAULT)
        );
        assert_eq!(t.state.me.blocked, before);
    }

    #[test]
    fn wait_event_interruptible_prefers_the_condition_then_a_signal() {
        use crate::sched::WaitKey;
        use crate::signal::wait::{ERESTARTSYS, wait_event_interruptible};
        let mut t = mapped();
        // Ready at once: no wait at all.
        assert_eq!(
            wait_event_interruptible(&mut t, WaitKey::NONE, |_| true),
            Ok(())
        );
        assert_eq!(t.waits, 0);
        // The "other side" makes it ready at the third look.
        let mut looks = 0;
        let r = wait_event_interruptible(&mut t, WaitKey::NONE, |t| {
            looks += 1;
            if looks == 3 {
                return true;
            }
            t.script_signal(t.now + 1, SIGUSR1); // a signal arrives, but...
            t.state.set_blocked(SigSet(SigSet::bit(SIGUSR1))); // ...stays blocked
            false
        });
        assert_eq!(r, Ok(()));
        // An unblocked signal ends the wait with -ERESTARTSYS.
        let mut t = mapped();
        t.script_signal(10, SIGUSR1);
        assert_eq!(
            wait_event_interruptible(&mut t, WaitKey::NONE, |_| false),
            Err(-ERESTARTSYS)
        );
        assert_eq!(t.now, 10);
        // Ready data wins over a pending signal.
        assert_eq!(
            wait_event_interruptible(&mut t, WaitKey::NONE, |_| true),
            Ok(())
        );
        // send_sig is the kernel's SI_USER from this process (SIGPIPE).
        let mut t = mapped();
        t.state.hand.actions[12].handler = 0x4000;
        t.state.send_sig(13);
        let (sig, info) = t.state.dequeue_signal().unwrap();
        assert_eq!((sig, info), (13, SigInfo::kill(13, 0, 1, 0)));
    }

    #[test]
    fn sleep_until_reports_the_time_left_when_a_signal_interrupts() {
        use crate::signal::wait::sleep_until;
        let mut t = mapped();
        // Deadline reached: None, even when a signal is pending as well.
        assert_eq!(sleep_until(&mut t, 5_000), None);
        assert_eq!(t.now, 5_000);
        // A signal at 8 us of a 20 us sleep: 12 us left.
        t.script_signal(8_000, SIGUSR1);
        assert_eq!(sleep_until(&mut t, 20_000), Some(12_000));
        assert_eq!(t.now, 8_000);
        // Still pending: returns at once with what is left.
        let waits = t.waits;
        assert_eq!(sleep_until(&mut t, 9_000), Some(1_000));
        assert_eq!(t.waits, waits);
        // The interval timer interrupts a sleep too.
        let mut t = mapped();
        put(&mut t, PAGE, &itimerval((0, 0), (0, 3)));
        assert_eq!(
            call(&mut t, Sysno::setitimer, &[0, PAGE, 0]),
            Outcome::Return(0)
        );
        assert_eq!(sleep_until(&mut t, 1_000_000), Some(1_000_000 - 3_000));
    }

    /// `nanosleep` through the real `sleep_until`: the remainder is measured
    /// against the hard expiry (soft + 50 us slack), as `hrtimer_expires_remaining`.
    #[test]
    fn nanosleep_remainder_and_wakeup_use_the_hard_expiry() {
        const MONO: u64 = 5_123_456_789;
        for (signal_at, left) in [(10_000, 1_040_000), (1_020_000, 30_000)] {
            let mut t = mapped();
            t.clocks.real_sleep = true;
            t.now = MONO;
            let mut ts = [0u8; 16];
            ts[8..].copy_from_slice(&1_000_000i64.to_le_bytes());
            put(&mut t, PAGE, &ts);
            t.script_signal(MONO + signal_at, SIGUSR1);
            assert_eq!(
                call(&mut t, Sysno::nanosleep, &[PAGE, PAGE + 16]),
                Outcome::Return(-516)
            );
            let rem = get::<16>(&mut t, PAGE + 16);
            assert_eq!(i64::from_le_bytes(rem[..8].try_into().unwrap()), 0);
            assert_eq!(i64::from_le_bytes(rem[8..].try_into().unwrap()), left);
            assert_eq!(
                t.clocks.restarts.last().unwrap().expires_ns,
                (MONO + 1_050_000).cast_signed()
            );
        }
        // Uninterrupted: the sleep ends at the hard expiry, not before.
        let mut t = mapped();
        t.clocks.real_sleep = true;
        t.now = MONO;
        let mut ts = [0u8; 16];
        ts[8..].copy_from_slice(&1_000_000i64.to_le_bytes());
        put(&mut t, PAGE, &ts);
        t.script_signal(MONO + 5_000_000, SIGUSR1);
        assert_eq!(
            call(&mut t, Sysno::nanosleep, &[PAGE, 0]),
            Outcome::Return(0)
        );
        assert_eq!(t.now, MONO + 1_050_000);
    }

    #[test]
    fn sigtimedwait_poll_timeout_and_wakeup() {
        let mut t = mapped();
        let set = SigSet(SigSet::bit(SIGUSR1));
        put(&mut t, PAGE, &set.0.to_le_bytes());
        let timeout = |t: &mut super::super::testing::Task, sec: i64, nsec: i64| {
            let mut raw = [0u8; 16];
            raw[..8].copy_from_slice(&sec.to_le_bytes());
            raw[8..].copy_from_slice(&nsec.to_le_bytes());
            put(t, PAGE + 256, &raw);
        };
        let wait = |t: &mut super::super::testing::Task, info: u64, ts: u64| {
            call(t, Sysno::rt_sigtimedwait, &[PAGE, info, ts, 8])
        };
        // Zero timeout: poll, EAGAIN, no sleeping.
        timeout(&mut t, 0, 0);
        assert_eq!(wait(&mut t, 0, PAGE + 256), neg(Errno::EAGAIN));
        assert_eq!(t.waits, 0);
        // 10 ms timeout elapses: EAGAIN after exactly the timeout.
        timeout(&mut t, 0, 10_000_000);
        let start = t.now;
        assert_eq!(wait(&mut t, 0, PAGE + 256), neg(Errno::EAGAIN));
        assert_eq!(t.now - start, 10_000_000);
        assert_eq!(t.state.me.blocked, SigSet::EMPTY, "mask restored");
        // A signal arriving during the wait is taken without running a handler.
        t.state.set_blocked(set);
        timeout(&mut t, 5, 0);
        t.script_signal(t.now + 20_000_000, SIGUSR1);
        let start = t.now;
        assert_eq!(wait(&mut t, PAGE + 512, PAGE + 256), Outcome::Return(10));
        assert_eq!(t.now - start, 20_000_000);
        assert_eq!(t.state.me.blocked, set, "blocked again afterwards");
        assert_eq!(t.state.pending_set(), SigSet::EMPTY, "consumed");
        let info = get::<128>(&mut t, PAGE + 512);
        assert_eq!(info[0..4], 10i32.to_le_bytes());
        // Argument order: size, set fault, timeout fault, then nsec.
        assert_eq!(
            call(&mut t, Sysno::rt_sigtimedwait, &[PAGE, 0, 0, 4]),
            neg(Errno::EINVAL)
        );
        assert_eq!(
            call(&mut t, Sysno::rt_sigtimedwait, &[0x9000, 0, PAGE + 256, 8]),
            neg(Errno::EFAULT)
        );
        assert_eq!(
            call(&mut t, Sysno::rt_sigtimedwait, &[PAGE, 0, 0x9000, 8]),
            neg(Errno::EFAULT)
        );
        timeout(&mut t, 0, 1_000_000_000);
        assert_eq!(wait(&mut t, 0, PAGE + 256), neg(Errno::EINVAL));
        timeout(&mut t, -1, 0);
        assert_eq!(wait(&mut t, 0, PAGE + 256), neg(Errno::EINVAL));
    }

    #[test]
    fn an_awaited_default_action_signal_neither_kills_nor_is_dropped() {
        // SIGTERM is fatal by default; blocked and awaited it must be taken by
        // the wait (`real_blocked`), also when init would otherwise ignore it.
        for init in [false, true] {
            let mut t = mapped();
            if init {
                t.state = crate::signal::State::standalone_init(1000);
            }
            let term = SigSet::bit(15);
            t.state.set_blocked(SigSet(term));
            put(&mut t, PAGE, &term.to_le_bytes());
            t.script_signal(1_000, 15);
            assert_eq!(
                call(&mut t, Sysno::rt_sigtimedwait, &[PAGE, 0, 0, 8]),
                Outcome::Return(15),
                "init={init}"
            );
            assert_eq!(t.state.sig.group_exit, None, "init={init}");
            assert_eq!(t.state.me.blocked, SigSet(term));
            assert_eq!(t.state.me.real_blocked, SigSet::EMPTY);
        }
    }

    #[test]
    fn sigtimedwait_is_interrupted_by_another_unblocked_signal() {
        let mut t = mapped();
        put(&mut t, PAGE, &SigSet::bit(SIGUSR1).to_le_bytes());
        t.script_signal(1_000, SIGUSR2);
        // No timeout: waits until something wakes it; USR2 is not awaited.
        assert_eq!(
            call(&mut t, Sysno::rt_sigtimedwait, &[PAGE, 0, 0, 8]),
            neg(Errno::EINTR)
        );
        assert!(t.state.pending_set().contains(SIGUSR2));
    }

    #[test]
    fn real_itimer_expiry_wakes_a_wait_and_the_interval_rearms_on_dequeue() {
        let mut t = mapped();
        put(&mut t, PAGE, &itimerval((0, 30_000), (0, 20_000)));
        assert_eq!(
            call(&mut t, Sysno::setitimer, &[0, PAGE, PAGE + 64]),
            Outcome::Return(0)
        );
        assert_eq!(get::<32>(&mut t, PAGE + 64), itimerval((0, 0), (0, 0)));
        // pause: woken by the timer at 20 ms with SIGALRM from the kernel.
        assert_eq!(call(&mut t, Sysno::pause, &[]), Outcome::Return(-514));
        assert_eq!(t.now, 20_000_000);
        let (sig, info) = t.state.dequeue_signal().expect("SIGALRM pending");
        assert_eq!((sig, info), (SIGALRM, SigInfo::kernel(SIGALRM)));
        // Dequeue re-armed the interval timer on its grid: 20 + 30 ms.
        assert_eq!(t.state.sig.itimer.next_event(), Some(50_000_000));
        assert_eq!(
            call(&mut t, Sysno::getitimer, &[0, PAGE + 128]),
            Outcome::Return(0)
        );
        assert_eq!(
            get::<32>(&mut t, PAGE + 128),
            itimerval((0, 30_000), (0, 30_000))
        );
        // alarm: replaces it, reports the rest rounded like Linux, and a
        // zero-second alarm cancels.
        assert_eq!(call(&mut t, Sysno::alarm, &[2]), Outcome::Return(1));
        assert_eq!(call(&mut t, Sysno::alarm, &[0]), Outcome::Return(2));
        assert_eq!(t.state.sig.itimer.next_event(), None);
        assert_eq!(call(&mut t, Sysno::alarm, &[0]), Outcome::Return(0));
    }

    #[test]
    fn setitimer_validates_before_arming_and_orders_its_errors() {
        let mut t = mapped();
        // value unreadable / not canonical -> before the `which` check.
        assert_eq!(
            call(&mut t, Sysno::setitimer, &[7, 0x9000, 0]),
            neg(Errno::EFAULT)
        );
        put(&mut t, PAGE, &itimerval((0, 0), (0, 1_000_000)));
        assert_eq!(
            call(&mut t, Sysno::setitimer, &[7, PAGE, 0]),
            neg(Errno::EINVAL)
        );
        put(&mut t, PAGE, &itimerval((-1, 0), (0, 5)));
        assert_eq!(
            call(&mut t, Sysno::setitimer, &[0, PAGE, 0]),
            neg(Errno::EINVAL)
        );
        put(&mut t, PAGE, &itimerval((0, 0), (1, 5)));
        assert_eq!(
            call(&mut t, Sysno::setitimer, &[7, PAGE, 0]),
            neg(Errno::EINVAL)
        );
        assert_eq!(
            t.state.sig.itimer.next_event(),
            None,
            "nothing armed by errors"
        );
        // A bad `ovalue` is reported after the timer is armed.
        assert_eq!(
            call(&mut t, Sysno::setitimer, &[0, PAGE, 0x9000]),
            neg(Errno::EFAULT)
        );
        assert!(t.state.sig.itimer.next_event().is_some());
        // NULL value disarms.
        assert_eq!(
            call(&mut t, Sysno::setitimer, &[0, 0, 0]),
            Outcome::Return(0)
        );
        assert_eq!(t.state.sig.itimer.next_event(), None);
    }

    #[test]
    fn restart_syscall_without_a_block_is_eintr_and_sigreturn_is_wired() {
        let mut t = mapped();
        assert_eq!(call(&mut t, Sysno::restart_syscall, &[]), neg(Errno::EINTR));
        t.state
            .send_signal(SIGUSR1, SigInfo::kernel(SIGUSR1), Target::Thread)
            .unwrap();
        // The fake's rt_sigreturn reports the restored rax it was given.
        t.sigreturn_ret = 77;
        assert_eq!(call(&mut t, Sysno::rt_sigreturn, &[]), Outcome::Return(77));
    }
}
