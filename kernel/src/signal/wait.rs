// SPDX-License-Identifier: GPL-2.0-only
// Linux 6.18.57 (commit 2ff600d29ee478d0a8d46ef8a58afb5e038fe692):
// kernel/signal.c: `do_sigtimedwait` 3823-3874, `rt_sigtimedwait` 3882-3911, `pause`
// 4900-4907, `sigsuspend` 4909-4920, `rt_sigsuspend` 4930-4941;
// include/linux/errno.h (`ERESTARTNOHAND`); include/linux/time64.h
// (`timespec64_valid`); include/linux/ktime.h (`ktime_set`). All GPL-2.0.
// Transformation: `schedule()` / `schedule_hrtimeout_range` become
// [`Task::wait`] in a loop that re-checks the wake condition; the timer slack
// (50 us) is not added to the deadline and the freezer is absent.
#![forbid(unsafe_code)]
//! The blocking signal syscalls: `pause`, `rt_sigsuspend`, `rt_sigtimedwait`.
//! (`restart_syscall` runs the time lane's `restart_block`, `syscall::time`.)
//!
//! # Contract
//! * Context: task context, interrupts masked; sleeping is [`Task::wait`],
//!   which leaves the CPU until a wake-up of its key, a signal or a deadline. Every iteration
//!   first brings the timers up to date ([`State::sync_timers`]) so an
//!   `ITIMER_REAL` expiry that woke the CPU has become a pending `SIGALRM`
//!   before the condition is examined, and no wake-up can be lost: the check
//!   and the state change that puts the task to sleep both run with interrupts
//!   masked, and the idle task's halt is `sti; hlt`.
//! * `pause` and `rt_sigsuspend` return `-ERESTARTNOHAND` with the wake-up
//!   signal still pending; the return path (`deliver`) turns that into
//!   `-EINTR` when a handler runs and restarts the call when the signal
//!   turned out to be ignored.

use super::{
    SIGKILL, SIGSTOP, SigSet, Task,
    deliver::ERESTARTNOHAND,
    info::SigInfo,
    state::State,
    syscalls::{get_user, put_user},
};
use crate::sched::WaitKey;
use syscalls::Errno;

fn err(errno: Errno) -> i64 {
    -i64::from(errno.into_raw())
}

/// Bring the timers up to date and borrow the state.
fn synced<T: Task>(task: &mut T) -> State<'_> {
    let now = task.now_ns();
    let mut state = task.state();
    state.sync_timers(now);
    state
}

/// `signal_pending(current)` after the timers are brought up to date: an
/// `ITIMER_REAL` that expired is `SIGALRM` pending before the answer.
pub fn signal_pending_synced<T: Task>(task: &mut T) -> bool {
    synced(task).signal_pending()
}

/// `-ERESTARTSYS` (512): what an interruptible wait returns when a signal is
/// pending; the return path turns it into `-EINTR` (handler without
/// `SA_RESTART`) or restarts the call.
pub const ERESTARTSYS: i64 = super::deliver::ERESTARTSYS;

/// `wait_event_interruptible(wq, cond)`: sleep on `key` (the wait queue) until
/// `ready` holds (`Ok`) or a signal is pending (`Err(-ERESTARTSYS)`), whichever
/// comes first. This is the primitive a blocking read or write (pipe, tty,
/// socket) waits with: `ready` examines whatever the other side changes, with
/// interrupts masked, so the check and the sleep cannot lose a wake-up; the
/// other side wakes `key` (`sched::Rq::wake_up_key`) after changing it. The
/// condition is tested before the signals, as the macro does, so ready data
/// wins over a pending signal. [`WaitKey::NONE`] is for a condition no one wakes
/// by key (only a signal or the interval timer ends the wait).
///
/// # Errors
/// `-ERESTARTSYS` as an `i64` in `Err`, ready to be the syscall's result.
pub fn wait_event_interruptible<T: Task>(
    task: &mut T,
    key: WaitKey,
    mut ready: impl FnMut(&mut T) -> bool,
) -> Result<(), i64> {
    loop {
        synced(task);
        if ready(task) {
            return Ok(());
        }
        if task.state().signal_pending() {
            return Err(-ERESTARTSYS);
        }
        task.wait(key, None);
    }
}

/// `do_nanosleep`'s wait: sleep until `CLOCK_MONOTONIC` reaches `deadline_ns`
/// or a signal is pending. `None` when the deadline was reached, `Some(left)`
/// with the nanoseconds remaining when a signal interrupted it (the caller then
/// reports the remainder and returns `-ERESTART_RESTARTBLOCK`). This is the body
/// of the binary's `Clocks::sleep_until`.
pub fn sleep_until<T: Task>(task: &mut T, deadline_ns: u64) -> Option<u64> {
    loop {
        let signalled = synced(task).signal_pending();
        let now = task.now_ns();
        if now >= deadline_ns {
            return None;
        }
        if signalled {
            return Some(deadline_ns - now);
        }
        task.wait(WaitKey::NONE, Some(deadline_ns));
    }
}

/// `pause()`: sleep until a signal is pending.
pub fn sys_pause<T: Task>(task: &mut T) -> i64 {
    while !synced(task).signal_pending() {
        task.wait(WaitKey::NONE, None);
    }
    -ERESTARTNOHAND
}

/// `rt_sigsuspend(unewset, sigsetsize)`: replace the mask by `*unewset`
/// (`SIGKILL`/`SIGSTOP` stripped) until a signal is pending; the old mask is
/// restored when the signal is delivered (`saved_sigmask`).
pub fn sys_rt_sigsuspend<T: Task>(task: &mut T, unewset: u64, sigsetsize: u64) -> i64 {
    if sigsetsize != 8 {
        return err(Errno::EINVAL);
    }
    let bytes = {
        let (_, mut pages) = task.parts();
        let Some(bytes) = get_user::<_, 8>(&mut pages, unewset) else {
            return err(Errno::EFAULT);
        };
        bytes
    };
    let mut state = task.state();
    state.me.saved_sigmask = Some(state.me.blocked);
    state.set_blocked(SigSet(u64::from_le_bytes(bytes)));
    while !synced(task).signal_pending() {
        task.wait(WaitKey::NONE, None);
    }
    -ERESTARTNOHAND
}

/// `timespec64_valid`: `0 <= tv_sec`, `0 <= tv_nsec < 1e9`.
fn timespec_valid(sec: i64, nsec: i64) -> bool {
    sec >= 0 && (0..1_000_000_000).contains(&nsec)
}

/// `ktime_set(sec, nsec)` saturated at `KTIME_MAX`.
fn ktime(sec: i64, nsec: i64) -> u64 {
    const KTIME_MAX: u64 = i64::MAX as u64;
    #[allow(clippy::cast_sign_loss)]
    let (sec, nsec) = (sec as u64, nsec as u64);
    if sec >= KTIME_MAX / 1_000_000_000 {
        KTIME_MAX
    } else {
        sec * 1_000_000_000 + nsec
    }
}

/// `rt_sigtimedwait(uthese, uinfo, uts, sigsetsize)`: take one of the signals
/// in `*uthese` from the pending sets without running its handler, waiting
/// for it (at most `*uts`, forever when `uts` is NULL, not at all for a zero
/// timeout) with those signals temporarily unblocked. Returns the signal
/// number; `EAGAIN` on timeout, `EINTR` when another signal interrupted the
/// wait (its handler then runs), `EINVAL` for a bad size or timespec, `EFAULT`
/// for an unreadable set/timeout or an unwritable `uinfo` (the signal is
/// consumed in that case, as in Linux).
pub fn sys_rt_sigtimedwait<T: Task>(
    task: &mut T,
    uthese: u64,
    uinfo: u64,
    uts: u64,
    sigsetsize: u64,
) -> i64 {
    if sigsetsize != 8 {
        return err(Errno::EINVAL);
    }
    let now = task.now_ns();
    let (these, timeout) = {
        let (_, mut pages) = task.parts();
        let Some(these) = get_user::<_, 8>(&mut pages, uthese) else {
            return err(Errno::EFAULT);
        };
        let timeout = if uts == 0 {
            None
        } else {
            let Some(raw) = get_user::<_, 16>(&mut pages, uts) else {
                return err(Errno::EFAULT);
            };
            let sec = i64::from_le_bytes(super::le(&raw, 0));
            let nsec = i64::from_le_bytes(super::le(&raw, 8));
            if !timespec_valid(sec, nsec) {
                return err(Errno::EINVAL);
            }
            Some(ktime(sec, nsec))
        };
        (these, timeout)
    };
    let mut state = task.state();
    // `mask` is the set to skip: everything not awaited, plus KILL and STOP.
    let awaited =
        SigSet(u64::from_le_bytes(these) & !(SigSet::bit(SIGKILL) | SigSet::bit(SIGSTOP)));
    let mask = SigSet(!awaited.0);
    state.sync_timers(now);
    let mut found = state.dequeue_signal_masked(mask);
    // `ret` of `schedule_hrtimeout_range`: -EINTR unless the timer ran out.
    let mut interrupted = false;
    if found.is_none() && timeout != Some(0) {
        // Temporarily unblock the awaited signals so they wake the sleep;
        // `real_blocked` keeps them "blocked" for `sig_ignored`.
        let real_blocked = state.me.blocked;
        state.me.real_blocked = real_blocked;
        state.me.blocked = SigSet(real_blocked.0 & mask.0);
        let deadline = timeout.map(|ns| now.saturating_add(ns));
        loop {
            if synced(task).signal_pending() {
                interrupted = true;
                break;
            }
            if deadline.is_some_and(|d| task.now_ns() >= d) {
                break;
            }
            task.wait(WaitKey::NONE, deadline);
        }
        let mut state = task.state();
        // __set_task_blocked(real_blocked), then collect.
        state.me.blocked = real_blocked;
        state.me.real_blocked = SigSet::EMPTY;
        found = state.dequeue_signal_masked(mask);
    }
    match found {
        None if interrupted => err(Errno::EINTR),
        None => err(Errno::EAGAIN),
        Some((sig, info)) => {
            let (_, mut pages) = task.parts();
            if uinfo != 0 && !put_user(&mut pages, uinfo, &SigInfo::to_bytes(&info)) {
                return err(Errno::EFAULT);
            }
            i64::from(sig)
        }
    }
}
