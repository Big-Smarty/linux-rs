// SPDX-License-Identifier: GPL-2.0-only
// Linux 6.18.57 (commit 2ff600d29ee478d0a8d46ef8a58afb5e038fe692):
// kernel/time/itimer.c (`itimer_get_remtime` 31-47, `do_getitimer` 76-98,
// `put_itimerval` 100-110, `getitimer` 113-120, `posixtimer_rearm_itimer`
// 156-166, `it_real_fn` 175-185, `do_setitimer` 225-290, `alarm_setitimer`
// 296-321, `alarm` 325-328, `get_itimerval` 330-350, `setitimer` 351-376),
// kernel/signal.c:659-660 (`dequeue_signal` rearms the interval timer),
// include/linux/ktime.h (`ktime_set`), kernel/time/hrtimer.c (`ktime_add_safe`,
// `hrtimer_forward`), include/uapi/linux/time.h (`ITIMER_*`,
// `struct __kernel_old_itimerval`). All GPL-2.0.
// Transformation: the `signal_struct` hrtimer becomes an absolute
// `CLOCK_MONOTONIC` expiry the binary arms in the clockevent (`State::itimer`,
// `Task::wait`); the callback `it_real_fn` is `State::sync_timers`, run at
// every kernel exit and wake-up. `ITIMER_VIRTUAL`/`ITIMER_PROF` need the
// CPU-time accounting of the time lane and are reported as unimplemented.
#![forbid(unsafe_code)]
//! `ITIMER_REAL`: `setitimer`, `getitimer` and `alarm`.
//!
//! # Contract
//! * Context: task context. Times are `CLOCK_MONOTONIC` nanoseconds in `u64`
//!   (`ktime_t` is a non-negative `s64`; every value saturates at `KTIME_MAX`).
//! * The timer is a one-shot [`RealTimer`] that sends `SIGALRM` to the process
//!   when it expires ([`RealTimer::expire`], called from [`State::sync_timers`]);
//!   an interval timer is re-armed only when the `SIGALRM` is dequeued from the
//!   shared queue (`posixtimer_rearm_itimer`), so a never-delivered alarm
//!   cannot flood.
//! * The `printk_once` warning of `setitimer(which, NULL, ..)` is not emitted
//!   (no log sink in the library).

use super::{
    Task,
    syscalls::{get_user, put_user},
};
use crate::usercopy::UserPages;
use syscalls::Errno;

pub const ITIMER_REAL: i32 = 0;
pub const ITIMER_VIRTUAL: i32 = 1;
pub const ITIMER_PROF: i32 = 2;

const NSEC_PER_SEC: u64 = 1_000_000_000;
const NSEC_PER_USEC: u64 = 1_000;
/// `KTIME_MAX`.
const KTIME_MAX: u64 = i64::MAX as u64;
/// `KTIME_SEC_MAX`.
const KTIME_SEC_MAX: u64 = KTIME_MAX / NSEC_PER_SEC;

/// `tsk->signal->real_timer` and `it_real_incr`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RealTimer {
    /// Absolute expiry while [`RealTimer::armed`]; the last expiry afterwards
    /// (`hrtimer_forward` continues from it).
    expires: u64,
    /// `it_real_incr`: the interval, 0 for a one-shot.
    incr: u64,
    /// `hrtimer_active`.
    armed: bool,
}

impl RealTimer {
    /// `itimer_get_remtime`: time left; an armed timer that is already due but
    /// has not run yet reports 1 us, a disarmed one 0.
    #[must_use]
    pub const fn remaining(&self, now: u64) -> u64 {
        if !self.armed {
            0
        } else if self.expires <= now {
            NSEC_PER_USEC
        } else {
            self.expires - now
        }
    }

    /// `it_real_incr`.
    #[must_use]
    pub const fn interval(&self) -> u64 {
        self.incr
    }

    /// The expiry the clockevent must wake the CPU for, if any.
    #[must_use]
    pub const fn next_event(&self) -> Option<u64> {
        if self.armed { Some(self.expires) } else { None }
    }

    /// `do_setitimer(ITIMER_REAL)`: cancel, then arm `value` ns from `now` (a
    /// zero `value` only disarms and clears the interval). Returns the old
    /// `(remaining, interval)`.
    pub fn start(&mut self, now: u64, value: u64, interval: u64) -> (u64, u64) {
        let old = (self.remaining(now), self.incr);
        self.armed = false;
        if value == 0 {
            self.incr = 0;
        } else {
            self.incr = interval;
            // hrtimer_start(HRTIMER_MODE_REL): `ktime_add_safe`.
            self.expires = now.saturating_add(value).min(KTIME_MAX);
            self.armed = true;
        }
        old
    }

    /// The hrtimer fired: `true` exactly once per expiry (`it_real_fn` sends
    /// `SIGALRM`; the timer is not restarted here).
    pub fn expire(&mut self, now: u64) -> bool {
        if self.armed && self.expires <= now {
            self.armed = false;
            true
        } else {
            false
        }
    }

    /// `posixtimer_rearm_itimer`, run when `SIGALRM` leaves the shared queue:
    /// a fired interval timer moves its expiry forward by whole intervals past
    /// `now` (`hrtimer_forward_now`) and starts again.
    pub fn rearm(&mut self, now: u64) {
        if self.armed || self.incr == 0 {
            return;
        }
        let interval = self.incr;
        // hrtimer_forward: `delta < 0` leaves the expiry (cannot happen for a
        // fired timer); otherwise whole intervals, and one more if still not
        // past `now`.
        if let Some(delta) = now.checked_sub(self.expires) {
            let mut expires = self.expires;
            if delta >= interval {
                expires = expires.saturating_add(interval.saturating_mul(delta / interval));
            }
            if expires <= now {
                expires = expires.saturating_add(interval);
            }
            self.expires = expires.min(KTIME_MAX);
        }
        self.armed = true;
    }
}

/// `ktime_set(sec, nsec)` for a canonical `timeval`/`timespec`.
fn ktime_set(sec: i64, nsec: u64) -> u64 {
    #[allow(clippy::cast_sign_loss)]
    let sec = sec as u64;
    if sec >= KTIME_SEC_MAX {
        KTIME_MAX
    } else {
        sec * NSEC_PER_SEC + nsec
    }
}

fn err(errno: Errno) -> i64 {
    -i64::from(errno.into_raw())
}

/// `get_itimerval`: the 32-byte `__kernel_old_itimerval` as
/// `(interval, value)` in nanoseconds. `EFAULT` for an unreadable struct,
/// `EINVAL` unless both `timeval`s are canonical.
fn get_itimerval<P: UserPages>(pages: &mut P, at: u64) -> Result<(u64, u64), Errno> {
    let raw = get_user::<_, 32>(pages, at).ok_or(Errno::EFAULT)?;
    let word = |i: usize| i64::from_le_bytes(super::le(&raw, 8 * i));
    let (interval, value) = ((word(0), word(1)), (word(2), word(3)));
    let valid = |(sec, usec): (i64, i64)| sec >= 0 && (0..1_000_000).contains(&usec);
    if !valid(interval) || !valid(value) {
        return Err(Errno::EINVAL);
    }
    #[allow(clippy::cast_sign_loss)]
    let ns = |(sec, usec): (i64, i64)| ktime_set(sec, usec as u64 * NSEC_PER_USEC);
    Ok((ns(interval), ns(value)))
}

/// `put_itimerval`: `tv_usec` is the nanosecond remainder divided by 1000.
fn put_itimerval<P: UserPages>(pages: &mut P, at: u64, interval: u64, value: u64) -> bool {
    let mut raw = [0u8; 32];
    for (i, ns) in [interval, value].into_iter().enumerate() {
        raw[16 * i..16 * i + 8].copy_from_slice(&(ns / NSEC_PER_SEC).to_le_bytes());
        raw[16 * i + 8..16 * i + 16]
            .copy_from_slice(&(ns % NSEC_PER_SEC / NSEC_PER_USEC).to_le_bytes());
    }
    put_user(pages, at, &raw)
}

#[allow(clippy::cast_possible_truncation)]
const fn int(register: u64) -> i32 {
    register as i32
}

/// `getitimer(which, value)`. `None`: `ITIMER_VIRTUAL`/`ITIMER_PROF` (CPU-time
/// timers) are not built yet; the caller reports an unimplemented syscall.
pub fn sys_getitimer<T: Task>(task: &mut T, which: u64, value: u64) -> Option<i64> {
    let now = task.now_ns();
    match int(which) {
        ITIMER_REAL => {}
        ITIMER_VIRTUAL | ITIMER_PROF => return None,
        _ => return Some(err(Errno::EINVAL)),
    }
    let (state, mut pages) = task.parts();
    let timer = state.itimer;
    Some(
        if put_itimerval(&mut pages, value, timer.interval(), timer.remaining(now)) {
            0
        } else {
            err(Errno::EFAULT)
        },
    )
}

/// `setitimer(which, value, ovalue)`: read and validate `value` first
/// (`EFAULT`, `EINVAL`; a NULL `value` is all zero), then `which` (`EINVAL`),
/// then arm, then write the old value to `ovalue` (`EFAULT`, the timer is
/// already set). `None` as for [`sys_getitimer`].
pub fn sys_setitimer<T: Task>(task: &mut T, which: u64, value: u64, ovalue: u64) -> Option<i64> {
    let now = task.now_ns();
    let (state, mut pages) = task.parts();
    let (interval, value_ns) = if value == 0 {
        (0, 0)
    } else {
        match get_itimerval(&mut pages, value) {
            Ok(pair) => pair,
            Err(errno) => return Some(err(errno)),
        }
    };
    match int(which) {
        ITIMER_REAL => {}
        ITIMER_VIRTUAL | ITIMER_PROF => return None,
        _ => return Some(err(Errno::EINVAL)),
    }
    let (old_value, old_interval) = state.itimer.start(now, value_ns, interval);
    Some(
        if ovalue != 0 && !put_itimerval(&mut pages, ovalue, old_interval, old_value) {
            err(Errno::EFAULT)
        } else {
            0
        },
    )
}

/// `alarm(seconds)`: `ITIMER_REAL` for `seconds` (an `unsigned int`), returning
/// the seconds left on the previous alarm rounded as Linux does (a pending
/// sub-second remainder counts as one second; so does one of half a second or
/// more).
pub fn sys_alarm<T: Task>(task: &mut T, seconds: u64) -> i64 {
    let now = task.now_ns();
    let state = task.state();
    #[allow(clippy::cast_possible_truncation)]
    let seconds = u64::from(seconds as u32);
    let (old, _) = state.itimer.start(now, seconds * NSEC_PER_SEC, 0);
    let (mut sec, nsec) = (old / NSEC_PER_SEC, old % NSEC_PER_SEC);
    if (sec == 0 && nsec != 0) || nsec >= NSEC_PER_SEC / 2 {
        sec += 1;
    }
    i64::try_from(sec).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_shot_fires_once_and_reports_remaining() {
        let mut t = RealTimer::default();
        assert_eq!(t.start(1_000, 5_000, 0), (0, 0));
        assert_eq!(t.remaining(1_000), 5_000);
        assert_eq!(t.remaining(3_000), 3_000);
        assert_eq!(t.next_event(), Some(6_000));
        assert!(!t.expire(5_999));
        assert!(t.expire(6_000));
        assert!(!t.expire(7_000), "fires once");
        assert_eq!(t.remaining(7_000), 0);
        assert_eq!(t.next_event(), None);
        // An armed timer that is due but not yet processed reads as 1 us.
        t.start(0, 10, 0);
        assert_eq!(t.remaining(10), NSEC_PER_USEC);
        assert_eq!(t.remaining(50), NSEC_PER_USEC);
    }

    #[test]
    fn restart_returns_the_old_value_and_interval() {
        let mut t = RealTimer::default();
        t.start(0, 1_000_000, 250_000);
        assert_eq!(t.start(400_000, 9, 0), (600_000, 250_000));
        assert_eq!(t.interval(), 0, "interval replaced");
        // A zero value disarms and clears the interval.
        t.start(0, 1_000_000, 250_000);
        assert_eq!(t.start(1, 0, 77), (999_999, 250_000));
        assert_eq!((t.interval(), t.next_event()), (0, None));
    }

    #[test]
    fn interval_rearms_only_when_asked_and_stays_on_the_grid() {
        let mut t = RealTimer::default();
        t.start(0, 100, 30);
        assert!(t.expire(100));
        // Nothing re-arms by itself.
        assert!(!t.expire(500));
        // hrtimer_forward_now: expiry 100 + k * 30, the first past `now`.
        t.rearm(145);
        assert_eq!(t.next_event(), Some(160));
        // A queued timer is left alone; a one-shot never re-arms.
        t.rearm(1_000);
        assert_eq!(t.next_event(), Some(160));
        let mut once = RealTimer::default();
        once.start(0, 10, 0);
        assert!(once.expire(10));
        once.rearm(20);
        assert_eq!(once.next_event(), None);
        // Exactly on the grid moves one full interval ahead.
        let mut grid = RealTimer::default();
        grid.start(0, 100, 30);
        assert!(grid.expire(100));
        grid.rearm(130);
        assert_eq!(grid.next_event(), Some(160));
        // Not yet past the old expiry: one interval after it.
        let mut early = RealTimer::default();
        early.start(0, 100, 30);
        assert!(early.expire(100));
        early.rearm(100);
        assert_eq!(early.next_event(), Some(130));
    }

    #[test]
    fn ktime_saturates() {
        assert_eq!(ktime_set(0, 5), 5);
        assert_eq!(ktime_set(2, 7), 2_000_000_007);
        assert_eq!(
            ktime_set(i64::try_from(KTIME_SEC_MAX).unwrap_or(0), 0),
            KTIME_MAX
        );
        assert_eq!(ktime_set(i64::MAX, 0), KTIME_MAX);
        let mut t = RealTimer::default();
        t.start(10, KTIME_MAX, 0);
        assert_eq!(t.next_event(), Some(KTIME_MAX));
    }
}
