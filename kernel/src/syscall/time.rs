// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692 (all GPL-2.0-only):
// kernel/time/posix-timers.c (`clockid_to_kclock` l.1535-1547, the `k_clock`
// tables l.1433-1531, `clock_settime`/`clock_gettime`/`clock_getres`/
// `clock_nanosleep` l.1117-1273 and l.1377-1403, `common_nsleep*`),
// kernel/time/posix-cpu-timers.c (`pid_for_clock` l.57-95,
// `posix_cpu_clock_getres/_set/_get`, `posix_cpu_nsleep`, `clock_process`,
// `clock_thread`), kernel/time/posix-clock.c (`clock_posix_dynamic`),
// kernel/time/alarmtimer.c (`alarm_clock`, `alarm_timer_nsleep`,
// `alarmtimer_do_nsleep`), kernel/time/hrtimer.c (`nanosleep` syscall,
// `hrtimer_nanosleep`, `do_nanosleep`, `nanosleep_copyout`),
// kernel/time/time.c (`time`, `gettimeofday`, `do_sys_settimeofday64`,
// `get_timespec64`/`put_timespec64`, `jiffies_64_to_clock_t`, `nsec_to_clock_t`),
// kernel/time/timekeeping.c (`do_settimeofday64`), kernel/sys.c (`times`),
// include/linux/time64.h (`timespec64_valid*`), include/linux/ktime.h,
// include/linux/jiffies.h (`INITIAL_JIFFIES`), include/uapi/linux/time.h,
// include/linux/posix-timers_types.h (`CPUCLOCK_*`, `CLOCKFD`).
// Transformation: one single-threaded task on one CPU with root credentials,
// no time namespaces (`timens_*` are identities), no suspend (BOOTTIME ==
// MONOTONIC), and no signals yet (the interrupted-sleep protocol is written and
// host-tested but nothing can interrupt a sleep today).
#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "ABI conversions between the signed 64-bit user layout and unsigned nanoseconds; \
every range is bounded by `timespec64_valid*` or `KTIME_MAX` at the call site"
)]
//! Time syscalls: `clock_gettime`, `clock_getres`, `clock_settime`,
//! `clock_nanosleep`, `nanosleep`, `gettimeofday`, `time`, `times`.
//!
//! Context: task context; the only blocking operation is [`Clocks::sleep_until`].
//! Pure decisions (clock-id decoding, validation, deadline arithmetic) live here
//! and are host-tested against a fake [`Clocks`]; the binary supplies the real
//! clocks, accounting and halting wait.
//!
//! # Signals
//! `Clocks::sleep_until` returns `Some(remaining)` when a signal interrupted the
//! sleep (the binary: `signal::wait::sleep_until`). This file then follows
//! `do_nanosleep`/`hrtimer_nanosleep`: it writes the remaining time to
//! `rem_out` (relative sleeps only) and returns `-ERESTART_RESTARTBLOCK` (516)
//! or, for absolute sleeps, `-ERESTARTNOHAND` (514), which the return to user
//! mode turns into `-EINTR` (a handler ran) or a restart (`signal::deliver`).
//! The `restart_block` is recorded through [`Clocks::set_restart_block`]:
//! `do_no_restart_syscall` with the `rmtp` pointer when a sleep starts, and the
//! restart function, `clockid` and absolute `expires` (the hard expiry, i.e.
//! including `timer_slack_ns` for hrtimer sleeps) when it is interrupted;
//! `restart_syscall` (219, [`restart_syscall`]) resumes with `deadline =
//! expires` (`hrtimer_nanosleep_restart`, `alarm_timer_nsleep_restart`), and
//! `rt_sigreturn` resets the block to `do_no_restart_syscall`
//! (`restore_sigcontext`).

use super::{Context, Outcome, error};
use crate::{
    time::{HZ, NSEC_PER_SEC, TICK_NSEC},
    usercopy::{copy_from_user, copy_to_user},
};
use syscalls::{Errno, Sysno};

const NS: i128 = NSEC_PER_SEC as i128;
/// `ktime_t` is a signed 64-bit nanosecond count; `KTIME_MAX` saturates.
const KTIME_MAX: i128 = i64::MAX as i128;
/// `KTIME_SEC_MAX = KTIME_MAX / NSEC_PER_SEC`.
const KTIME_SEC_MAX: i64 = i64::MAX / NSEC_PER_SEC as i64;
/// `TIME_SETTOD_SEC_MAX = KTIME_SEC_MAX - TIME_UPTIME_SEC_MAX` (30 years).
const TIME_SETTOD_SEC_MAX: i64 = KTIME_SEC_MAX - 30 * 365 * 24 * 3600;
const TIMER_ABSTIME: i32 = 1;
/// `hrtimer_resolution` with high-resolution timers active (from boot here).
const HRTIMER_RES_NS: i128 = 1;
/// `ERESTARTNOHAND` and `ERESTART_RESTARTBLOCK` (include/linux/errno.h).
const ERESTARTNOHAND: i64 = 514;
const ERESTART_RESTARTBLOCK: i64 = 516;
/// `USER_HZ`: the unit of `times(2)`.
const USER_HZ: u64 = 100;
/// `init_task.timer_slack_ns`: the hrtimer range of a normal task.
const TIMER_SLACK_NS: i128 = 50_000;
/// `INITIAL_JIFFIES = (unsigned long)(unsigned int)(-300 * HZ)`.
const INITIAL_JIFFIES: u64 = (-300i64 * HZ as i64) as u32 as u64;

/// A moment of the timekeeper: everything needed to read every clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockState {
    /// `CLOCK_MONOTONIC`.
    pub mono_ns: u64,
    /// `CLOCK_BOOTTIME - CLOCK_MONOTONIC` (time spent suspended).
    pub boot_offset_ns: u64,
    /// `CLOCK_REALTIME - CLOCK_MONOTONIC` (`-wall_to_monotonic`).
    pub real_offset_ns: i64,
    /// The realtime that the last `clock_settime(CLOCK_REALTIME)` stored, 0
    /// before any: `xtime` equals it until the next tick, so the coarse
    /// realtime readers (`time`, `CLOCK_REALTIME_COARSE`) never read below it.
    pub settod_real_ns: i64,
}

/// Which `restart_block.fn` is installed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestartFn {
    /// `do_no_restart_syscall`: `restart_syscall` fails with `EINTR`.
    None,
    /// `hrtimer_nanosleep_restart`.
    Hrtimer,
    /// `alarm_timer_nsleep_restart`.
    Alarm,
}

/// The `restart_block.nanosleep` fields `nanosleep`/`clock_nanosleep` fill.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RestartBlock {
    pub func: RestartFn,
    /// `hrtimer` base clock id (a relative `CLOCK_REALTIME` sleep is on
    /// `CLOCK_MONOTONIC`), or the `alarmtimer_type` for [`RestartFn::Alarm`].
    pub clockid: i32,
    /// Absolute expiry on that base, in ns.
    pub expires_ns: i64,
    /// `rmtp` user pointer, 0 for `TT_NONE`.
    pub rmtp: u64,
}

impl RestartBlock {
    /// `restart_block.fn = do_no_restart_syscall`, no `rmtp`.
    pub const NONE: Self = Self {
        func: RestartFn::None,
        clockid: 0,
        expires_ns: 0,
        rmtp: 0,
    };
}

/// What the time syscalls need beyond user memory; the binary implements it
/// over the timekeeper, the CPU-time accounting and the halting timer wait.
pub trait Clocks {
    fn clock_state(&self) -> ClockState;
    /// Install a new realtime offset (`do_settimeofday64`). Interrupts are off.
    /// `real_ns` is the time that was set (`tk_set_xtime`).
    fn set_realtime(&mut self, offset: i64, real_ns: i64);
    /// Store `current->restart_block` for `restart_syscall` (see the seam notes).
    fn set_restart_block(&mut self, block: RestartBlock);
    /// `current->restart_block` as stored by [`Self::set_restart_block`].
    fn restart_block(&self) -> RestartBlock;
    /// `CPUCLOCK_SCHED`/`VIRT`/`PROF` inputs of the (only) task.
    fn cpu_sample(&self) -> crate::cputime::CpuSample;
    /// `thread_group_cputime_adjusted`: `(utime, stime)` in ns for `times(2)`.
    fn cpu_adjusted(&mut self) -> (u64, u64);
    /// Block until `CLOCK_MONOTONIC` reaches `deadline_ns`. `None` when the
    /// deadline was reached; `Some(remaining_ns)` when a signal interrupted it.
    fn sleep_until(&mut self, deadline_ns: u64) -> Option<u64>;
    /// `capable(CAP_SYS_TIME)` / `capable(CAP_WAKE_ALARM)`.
    fn capable_sys_time(&self) -> bool;
    fn capable_wake_alarm(&self) -> bool;
    /// `alarmtimer_get_rtcdev() != NULL`: a wakeup-capable RTC exists.
    fn alarm_rtc(&self) -> bool;
}

/// The `k_clock` an id selects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kclock {
    Realtime,
    Monotonic,
    /// `CLOCK_PROCESS_CPUTIME_ID`.
    Process,
    /// `CLOCK_THREAD_CPUTIME_ID`.
    Thread,
    MonotonicRaw,
    RealtimeCoarse,
    MonotonicCoarse,
    Boottime,
    RealtimeAlarm,
    BoottimeAlarm,
    Tai,
    /// A negative id encoding `pid`, per-thread bit and CPU clock type.
    PosixCpu(i32),
    /// A negative id with `CLOCKFD` low bits: an fd of a posix-clock device.
    Dynamic,
}

/// `clockid_to_kclock` with `CONFIG_POSIX_AUX_CLOCKS=n`: ids 0..=11 minus the
/// unregistered `CLOCK_SGI_CYCLE` (10); everything else non-negative is invalid.
#[must_use]
pub fn clockid_to_kclock(id: i32) -> Option<Kclock> {
    if id < 0 {
        // `(id & CLOCKFD_MASK) == CLOCKFD`: CLOCKFD is CPUCLOCK_MAX (3), mask 7.
        return Some(if id & 7 == 3 {
            Kclock::Dynamic
        } else {
            Kclock::PosixCpu(id)
        });
    }
    Some(match id {
        0 => Kclock::Realtime,
        1 => Kclock::Monotonic,
        2 => Kclock::Process,
        3 => Kclock::Thread,
        4 => Kclock::MonotonicRaw,
        5 => Kclock::RealtimeCoarse,
        6 => Kclock::MonotonicCoarse,
        7 => Kclock::Boottime,
        8 => Kclock::RealtimeAlarm,
        9 => Kclock::BoottimeAlarm,
        11 => Kclock::Tai,
        _ => return None,
    })
}

pub(super) fn dispatch<C: Context>(ctx: &mut C, sysno: Sysno, args: [u64; 6]) -> Option<Outcome> {
    // `clockid_t` and `int` parameters are the low 32 bits, as in Linux.
    #[allow(clippy::cast_possible_truncation)]
    let (clock, flags) = (args[0] as i32, args[1] as i32);
    let ret = match sysno {
        Sysno::clock_gettime => clock_gettime(ctx, clock, args[1]),
        Sysno::clock_getres => clock_getres(ctx, clock, args[1]),
        Sysno::clock_settime => clock_settime(ctx, clock, args[1]),
        Sysno::clock_nanosleep => match clock_nanosleep(ctx, clock, flags, args[2], args[3]) {
            Ok(value) => value,
            Err(Never) => return Some(Outcome::Unimplemented(sysno as u32)),
        },
        Sysno::nanosleep => nanosleep(ctx, args[0], args[1]),
        Sysno::restart_syscall => restart_syscall(ctx),
        Sysno::gettimeofday => gettimeofday(ctx, args[0], args[1]),
        Sysno::time => time(ctx, args[0]),
        Sysno::times => times(ctx, args[0]),
        _ => return None,
    };
    Some(Outcome::Return(ret))
}

/// A path Linux implements but this slice does not: reported loudly.
struct Never;

type Ts = (i64, i64);

fn read_timespec<C: Context>(ctx: &mut C, at: u64) -> Result<Ts, Errno> {
    let mut raw = [0u8; 16];
    if copy_from_user(ctx, &mut raw, at) != 0 {
        return Err(Errno::EFAULT);
    }
    let (sec, nsec) = raw.split_at(8);
    Ok((
        i64::from_le_bytes(sec.try_into().unwrap_or_default()),
        i64::from_le_bytes(nsec.try_into().unwrap_or_default()),
    ))
}

fn write_timespec<C: Context>(ctx: &mut C, at: u64, ns: i128) -> Result<(), Errno> {
    let (sec, nsec) = (ns.div_euclid(NS) as i64, ns.rem_euclid(NS) as i64);
    let mut raw = [0u8; 16];
    raw[..8].copy_from_slice(&sec.to_le_bytes());
    raw[8..].copy_from_slice(&nsec.to_le_bytes());
    if copy_to_user(ctx, at, &raw) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(())
}

/// `put_user` of one 64-bit value.
fn put_i64<C: Context>(ctx: &mut C, at: u64, value: i64) -> Result<(), Errno> {
    if copy_to_user(ctx, at, &value.to_le_bytes()) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(())
}

/// `timespec64_valid`: no dates before 1970, at most 999999999 ns.
fn valid((sec, nsec): Ts) -> bool {
    sec >= 0 && (nsec as u64) < NSEC_PER_SEC
}

/// `timespec64_valid_settod`.
fn valid_settod(ts: Ts) -> bool {
    valid(ts) && (ts.0 as u64) < TIME_SETTOD_SEC_MAX as u64
}

/// `timespec64_to_ktime` (`ktime_set`): saturates at `KTIME_MAX`.
fn to_ktime((sec, nsec): Ts) -> i128 {
    if sec >= KTIME_SEC_MAX {
        KTIME_MAX
    } else {
        i128::from(sec) * NS + i128::from(nsec)
    }
}

/// `pid_for_clock` for the only task: pid 0 is "current", otherwise the id must
/// name this thread group. `which` (`CPUCLOCK_WHICH`) 3 is invalid.
fn cpu_clock_valid<C: Context>(ctx: &C, id: i32) -> Result<(), Errno> {
    let upid = !(id >> 3);
    // shortcut: one single-threaded task, so the thread id equals the tgid.
    // Replace with a pid/tid lookup when tasks exist.
    if id & 3 >= 3 || (upid != 0 && i64::from(upid) != i64::from(ctx.tgid())) {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

struct Now {
    state: ClockState,
}
impl Now {
    fn mono(&self) -> i128 {
        i128::from(self.state.mono_ns)
    }
    fn real(&self) -> i128 {
        self.mono() + i128::from(self.state.real_offset_ns)
    }
    fn boot(&self) -> i128 {
        self.mono() + i128::from(self.state.boot_offset_ns)
    }
    /// The tick-granular view: `ktime_get_coarse_*` is the value the last tick
    /// published. shortcut: derived by flooring monotonic time to a tick instead
    /// of from a tick-updated copy; identical to within one tick, and it keeps
    /// working if the tick is stopped. Replace when the timekeeper publishes xtime.
    fn coarse_mono(&self) -> i128 {
        self.mono() - self.mono() % i128::from(TICK_NSEC)
    }
    /// `ktime_get_coarse_real_ts64`: the tick view plus the offset, but right
    /// after `clock_settime` the exact value that was set (`xtime`) until the
    /// next tick passes it; later ticks are always above it.
    fn coarse_real(&self) -> i128 {
        (self.coarse_mono() + i128::from(self.state.real_offset_ns))
            .max(i128::from(self.state.settod_real_ns))
    }
}

/// The `clock_get_timespec` method, as nanoseconds.
fn clock_get<C: Context>(ctx: &C, kclock: Kclock, id: i32) -> Result<i128, Errno> {
    let now = Now {
        state: ctx.clock_state(),
    };
    Ok(match kclock {
        Kclock::Realtime | Kclock::Tai => now.real(), // tai_offset is 0
        Kclock::Monotonic | Kclock::MonotonicRaw => now.mono(),
        Kclock::Boottime => now.boot(),
        Kclock::RealtimeCoarse => now.coarse_real(),
        Kclock::MonotonicCoarse => now.coarse_mono(),
        Kclock::RealtimeAlarm | Kclock::BoottimeAlarm => {
            if !ctx.alarm_rtc() {
                return Err(Errno::EINVAL);
            }
            if kclock == Kclock::RealtimeAlarm {
                now.real()
            } else {
                now.boot()
            }
        }
        Kclock::Process | Kclock::Thread => i128::from(ctx.cpu_sample().runtime_ns),
        Kclock::PosixCpu(id) => {
            cpu_clock_valid(ctx, id)?;
            let sample = ctx.cpu_sample();
            i128::from(match id & 3 {
                0 => sample.user_ns + sample.system_ns,
                1 => sample.user_ns,
                _ => sample.runtime_ns,
            })
        }
        // No posix-clock device exists, so no fd names one: `fget` fails or the
        // file is not a posix clock, both -EINVAL (`get_clock_desc`).
        Kclock::Dynamic => {
            let _ = id;
            return Err(Errno::EINVAL);
        }
    })
}

fn clock_gettime<C: Context>(ctx: &mut C, id: i32, tp: u64) -> i64 {
    let Some(kclock) = clockid_to_kclock(id) else {
        return error(Errno::EINVAL);
    };
    match clock_get(ctx, kclock, id).and_then(|ns| write_timespec(ctx, tp, ns)) {
        Ok(()) => 0,
        Err(errno) => error(errno),
    }
}

fn clock_getres<C: Context>(ctx: &mut C, id: i32, tp: u64) -> i64 {
    let Some(kclock) = clockid_to_kclock(id) else {
        return error(Errno::EINVAL);
    };
    let res = match kclock {
        Kclock::Realtime
        | Kclock::Monotonic
        | Kclock::MonotonicRaw
        | Kclock::Boottime
        | Kclock::Tai => Ok(HRTIMER_RES_NS),
        // `ktime_to_timespec64(KTIME_LOW_RES)`: one tick.
        Kclock::RealtimeCoarse | Kclock::MonotonicCoarse => Ok(i128::from(TICK_NSEC)),
        Kclock::RealtimeAlarm | Kclock::BoottimeAlarm => {
            if ctx.alarm_rtc() {
                Ok(HRTIMER_RES_NS)
            } else {
                Err(Errno::EINVAL)
            }
        }
        // `PROCESS_CLOCK`/`THREAD_CLOCK` are `CPUCLOCK_SCHED`: 1 ns.
        Kclock::Process | Kclock::Thread => Ok(1),
        Kclock::PosixCpu(id) => cpu_clock_valid(ctx, id).map(|()| {
            if id & 3 == 2 {
                1
            } else {
                i128::from(NSEC_PER_SEC.div_ceil(HZ))
            }
        }),
        Kclock::Dynamic => Err(Errno::EINVAL),
    };
    match res {
        // `if (!error && tp && put_timespec64())`: a null `tp` is not an error.
        Ok(ns) if tp != 0 => write_timespec(ctx, tp, ns).map_or_else(error, |()| 0),
        Ok(_) => 0,
        Err(errno) => error(errno),
    }
}

/// `do_sys_settimeofday64(tv, NULL)` for `CLOCK_REALTIME`.
fn set_realtime<C: Context>(ctx: &mut C, ts: Ts) -> i64 {
    if !valid_settod(ts) {
        return error(Errno::EINVAL);
    }
    if !ctx.capable_sys_time() {
        return error(Errno::EPERM);
    }
    // `do_settimeofday64`: refuse a time that would put realtime before
    // monotonic (`wall_to_monotonic > ts_delta` makes the new offset positive).
    let new = to_ktime(ts) - i128::from(ctx.clock_state().mono_ns);
    if new < 0 {
        return error(Errno::EINVAL);
    }
    // `valid_settod` bounds `new` below 8.3e18 < i64::MAX.
    ctx.set_realtime(
        i64::try_from(new).unwrap_or(i64::MAX),
        i64::try_from(to_ktime(ts)).unwrap_or(i64::MAX),
    );
    0
}

fn clock_settime<C: Context>(ctx: &mut C, id: i32, tp: u64) -> i64 {
    // Only realtime, the CPU-clock ids and the dynamic ids have `clock_set`.
    let Some(kclock @ (Kclock::Realtime | Kclock::PosixCpu(_) | Kclock::Dynamic)) =
        clockid_to_kclock(id)
    else {
        return error(Errno::EINVAL);
    };
    let ts = match read_timespec(ctx, tp) {
        Ok(ts) => ts,
        Err(errno) => return error(errno),
    };
    match kclock {
        Kclock::Realtime => set_realtime(ctx, ts),
        // "You can never reset a CPU clock": EINVAL for a bad target, else EPERM.
        Kclock::PosixCpu(id) => error(cpu_clock_valid(ctx, id).err().unwrap_or(Errno::EPERM)),
        // `pc_clock_settime`: `timespec64_valid_strict`, then `get_clock_desc`
        // fails with EINVAL (no posix-clock fd can exist).
        _ => error(Errno::EINVAL),
    }
}

/// How `kc->nsleep` waits.
enum Sleeper {
    /// `common_nsleep*`: an hrtimer on this clock.
    Hrtimer,
    /// `alarm_timer_nsleep`.
    Alarm,
    /// `posix_cpu_nsleep`/`process_cpu_nsleep`.
    Cpu,
}

fn sleeper(kclock: Kclock) -> Option<Sleeper> {
    match kclock {
        Kclock::Realtime | Kclock::Monotonic | Kclock::Boottime | Kclock::Tai => {
            Some(Sleeper::Hrtimer)
        }
        Kclock::RealtimeAlarm | Kclock::BoottimeAlarm => Some(Sleeper::Alarm),
        Kclock::Process | Kclock::PosixCpu(_) => Some(Sleeper::Cpu),
        Kclock::Thread
        | Kclock::MonotonicRaw
        | Kclock::RealtimeCoarse
        | Kclock::MonotonicCoarse
        | Kclock::Dynamic => None,
    }
}

/// `ktime_add_safe`: saturates at `KTIME_MAX`.
fn add_safe(a: i128, b: i128) -> i128 {
    (a + b).min(KTIME_MAX)
}

/// How an interrupted relative sleep is resumed: `restart_block` minus `rmtp`.
#[derive(Clone, Copy)]
struct Resume {
    func: RestartFn,
    clockid: i32,
    expires_ns: i128,
}

/// `do_nanosleep`'s tail: sleep to `deadline_ns` (monotonic), report the
/// remaining time through `rem_out` and the restart code on interruption.
fn sleep_to<C: Context>(
    ctx: &mut C,
    deadline_ns: i128,
    rem_out: Option<u64>,
    abs: bool,
    resume: Resume,
) -> i64 {
    let deadline = u64::try_from(deadline_ns.clamp(0, KTIME_MAX)).unwrap_or(0);
    let Some(remaining) = ctx.sleep_until(deadline) else {
        return 0;
    };
    if let Some(rem_out) = rem_out {
        if remaining == 0 {
            return 0;
        }
        if let Err(errno) = write_timespec(ctx, rem_out, i128::from(remaining)) {
            return error(errno);
        }
    }
    // `hrtimer_nanosleep`/`alarm_timer_nsleep`: absolute sleeps neither report
    // the remaining time nor restart; relative ones install the restart block.
    if abs {
        return -ERESTARTNOHAND;
    }
    ctx.set_restart_block(RestartBlock {
        func: resume.func,
        clockid: resume.clockid,
        expires_ns: i64::try_from(resume.expires_ns.clamp(0, KTIME_MAX)).unwrap_or(i64::MAX),
        rmtp: rem_out.unwrap_or(0),
    });
    -ERESTART_RESTARTBLOCK
}

/// `sys_restart_syscall`: run `current->restart_block.fn`. Only the sleeps
/// install a continuation: `do_no_restart_syscall` fails with `EINTR`;
/// `hrtimer_nanosleep_restart` and `alarm_timer_nsleep_restart` sleep on to the
/// absolute `expires` of the block's clock, reporting the remaining time through
/// `rmtp` (`do_nanosleep`, `alarmtimer_do_nsleep`) and leaving the same block
/// installed when interrupted again.
fn restart_syscall<C: Context>(ctx: &mut C) -> i64 {
    let block = ctx.restart_block();
    // `restart->nanosleep.clockid`: the hrtimer clock id (1 monotonic, 7
    // boottime, 11 TAI) or the `alarmtimer_type` (0 realtime, 1 boottime).
    let kclock = match (block.func, block.clockid) {
        (RestartFn::None, _) => return error(Errno::EINTR),
        (RestartFn::Hrtimer, 1) => Kclock::Monotonic,
        (RestartFn::Hrtimer, 7) => Kclock::Boottime,
        (RestartFn::Hrtimer, _) => Kclock::Tai,
        (RestartFn::Alarm, 0) => Kclock::RealtimeAlarm,
        (RestartFn::Alarm, _) => Kclock::BoottimeAlarm,
    };
    let now = Now {
        state: ctx.clock_state(),
    };
    let expires = i128::from(block.expires_ns);
    // The expiry is on the timer's base; the wait is on the monotonic clock.
    let deadline = expires - (now.clock_of(kclock) - now.mono());
    let resume = Resume {
        func: block.func,
        clockid: block.clockid,
        expires_ns: expires,
    };
    sleep_to(
        ctx,
        deadline,
        (block.rmtp != 0).then_some(block.rmtp),
        false,
        resume,
    )
}

/// `current->restart_block.fn = do_no_restart_syscall` plus the `rmtp` fields,
/// as `nanosleep` and `clock_nanosleep` do before sleeping.
fn begin_sleep<C: Context>(ctx: &mut C, rem_out: Option<u64>) {
    ctx.set_restart_block(RestartBlock {
        rmtp: rem_out.unwrap_or(0),
        ..RestartBlock::NONE
    });
}

/// `sys_clock_nanosleep`. `Err(Never)` marks the CPU-clock wait this slice does
/// not implement.
fn clock_nanosleep<C: Context>(
    ctx: &mut C,
    id: i32,
    flags: i32,
    sleep_req: u64,
    rem_out: u64,
) -> Result<i64, Never> {
    let Some(kclock) = clockid_to_kclock(id) else {
        return Ok(error(Errno::EINVAL));
    };
    let Some(sleeper) = sleeper(kclock) else {
        return Ok(error(Errno::EOPNOTSUPP));
    };
    let ts = match read_timespec(ctx, sleep_req) {
        Ok(ts) => ts,
        Err(errno) => return Ok(error(errno)),
    };
    if !valid(ts) {
        return Ok(error(Errno::EINVAL));
    }
    let abs = flags & TIMER_ABSTIME != 0;
    // `if (flags & TIMER_ABSTIME) rem_out = NULL;`
    let rem_out = (!abs && rem_out != 0).then_some(rem_out);
    begin_sleep(ctx, rem_out);
    let now = Now {
        state: ctx.clock_state(),
    };
    let request = to_ktime(ts);
    // Absolute: translate the clock's time to monotonic (`timens_ktime_to_host`
    // is the identity); relative: `now + request` on the clock's base is the
    // same monotonic distance.
    let deadline = if abs {
        request - (now.clock_of(kclock) - now.mono())
    } else {
        add_safe(now.mono(), request)
    };
    match sleeper {
        Sleeper::Hrtimer => {
            // `hrtimer_nanosleep`: a relative `CLOCK_REALTIME` timer is moved
            // to the monotonic base; the restart expiry is the hard expiry,
            // `now + request + timer_slack_ns` on the timer's base.
            let base = if kclock == Kclock::Realtime {
                Kclock::Monotonic
            } else {
                kclock
            };
            let resume = Resume {
                func: RestartFn::Hrtimer,
                clockid: match base {
                    Kclock::Monotonic => 1,
                    Kclock::Boottime => 7,
                    _ => 11,
                },
                expires_ns: add_safe(add_safe(now.clock_of(base), request), TIMER_SLACK_NS),
            };
            Ok(sleep_to(ctx, deadline, rem_out, abs, resume))
        }
        Sleeper::Alarm => {
            if !ctx.alarm_rtc() {
                return Ok(error(Errno::EOPNOTSUPP));
            }
            if flags & !TIMER_ABSTIME != 0 {
                return Ok(error(Errno::EINVAL));
            }
            if !ctx.capable_wake_alarm() {
                return Ok(error(Errno::EPERM));
            }
            // shortcut: without suspend an alarm timer fires exactly when the
            // hrtimer on the same base would; the RTC wakeup is never armed.
            // Replace with a real `alarm_start` when suspend-to-RAM exists.
            let resume = Resume {
                func: RestartFn::Alarm,
                clockid: i32::from(kclock == Kclock::BoottimeAlarm),
                expires_ns: add_safe(now.clock_of(kclock), request),
            };
            Ok(sleep_to(ctx, deadline, rem_out, abs, resume))
        }
        Sleeper::Cpu => {
            // `posix_cpu_nsleep`: a per-thread clock naming the caller's own
            // thread cannot be slept on; any other bad target fails in
            // `posix_cpu_timer_create`.
            if let Kclock::PosixCpu(id) = kclock {
                if id & 4 != 0 {
                    let upid = !(id >> 3);
                    if upid == 0 || i64::from(upid) == i64::from(ctx.tgid()) {
                        return Ok(error(Errno::EINVAL));
                    }
                }
                if let Err(errno) = cpu_clock_valid(ctx, id) {
                    return Ok(error(errno));
                }
            }
            // `posix_cpu_timer_set` arms nothing for a zero expiry and fires at
            // once for an absolute one that is not in the future, so
            // `do_cpu_nanosleep` returns 0 without waiting.
            let cpu_now = clock_get(ctx, kclock, id).unwrap_or(0);
            if request == 0 || (abs && request <= cpu_now) {
                return Ok(0);
            }
            // The wait itself (a timer on the caller's own CPU time can only
            // fire while it runs) needs signals/threads to be observable; it is
            // not implemented and stops loudly instead of returning success.
            Err(Never)
        }
    }
}

impl Now {
    /// The reading of the clock `kclock` selects, for the sleepers.
    fn clock_of(&self, kclock: Kclock) -> i128 {
        match kclock {
            Kclock::Realtime | Kclock::Tai | Kclock::RealtimeAlarm => self.real(),
            Kclock::Boottime | Kclock::BoottimeAlarm => self.boot(),
            _ => self.mono(),
        }
    }
}

fn nanosleep<C: Context>(ctx: &mut C, sleep_req: u64, rem_out: u64) -> i64 {
    let ts = match read_timespec(ctx, sleep_req) {
        Ok(ts) => ts,
        Err(errno) => return error(errno),
    };
    if !valid(ts) {
        return error(Errno::EINVAL);
    }
    let rem_out = (rem_out != 0).then_some(rem_out);
    begin_sleep(ctx, rem_out);
    let mono = i128::from(ctx.clock_state().mono_ns);
    let request = to_ktime(ts);
    let resume = Resume {
        func: RestartFn::Hrtimer,
        clockid: 1,
        expires_ns: add_safe(add_safe(mono, request), TIMER_SLACK_NS),
    };
    sleep_to(ctx, add_safe(mono, request), rem_out, false, resume)
}

fn gettimeofday<C: Context>(ctx: &mut C, tv: u64, tz: u64) -> i64 {
    let result = (|| {
        if tv != 0 {
            let state = ctx.clock_state();
            let real = i128::from(state.mono_ns) + i128::from(state.real_offset_ns);
            // Two `put_user`s: seconds, then microseconds.
            put_i64(ctx, tv, real.div_euclid(NS) as i64)?;
            put_i64(ctx, tv + 8, (real.rem_euclid(NS) / 1000) as i64)?;
        }
        if tz != 0 {
            // `sys_tz`: nothing sets it (no settimeofday), so UTC, no DST.
            if copy_to_user(ctx, tz, &[0u8; 8]) != 0 {
                return Err(Errno::EFAULT);
            }
        }
        Ok(())
    })();
    result.map_or_else(error, |()| 0)
}

fn time<C: Context>(ctx: &mut C, tloc: u64) -> i64 {
    let now = Now {
        state: ctx.clock_state(),
    };
    // `ktime_get_real_seconds` is the tick-published `xtime_sec`.
    let seconds = now.coarse_real().div_euclid(NS) as i64;
    if tloc != 0
        && let Err(errno) = put_i64(ctx, tloc, seconds)
    {
        return error(errno);
    }
    seconds
}

fn times<C: Context>(ctx: &mut C, tbuf: u64) -> i64 {
    let state = ctx.clock_state();
    if tbuf != 0 {
        let (user, system) = ctx.cpu_adjusted();
        // `nsec_to_clock_t` (NSEC_PER_SEC % USER_HZ == 0); children: none exist.
        let ticks = |ns: u64| (ns / (NSEC_PER_SEC / USER_HZ)) as i64;
        let mut raw = [0u8; 32];
        raw[..8].copy_from_slice(&ticks(user).to_le_bytes());
        raw[8..16].copy_from_slice(&ticks(system).to_le_bytes());
        if copy_to_user(ctx, tbuf, &raw) != 0 {
            return error(Errno::EFAULT);
        }
    }
    // `jiffies_64_to_clock_t(get_jiffies_64())`: jiffies start at
    // `INITIAL_JIFFIES` and HZ (1000) is a multiple of USER_HZ.
    let jiffies = INITIAL_JIFFIES + state.mono_ns / TICK_NSEC;
    (jiffies / (HZ / USER_HZ)) as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syscall::{
        Outcome, dispatch, error,
        testing::{Task, task},
    };
    use syscalls::{Errno, Sysno};

    /// A `clockid_t` as a syscall register (the upper half is ignored by Linux).
    fn arg(clock: i32) -> u64 {
        u64::from(clock.cast_unsigned())
    }
    const BUF: u64 = 0x1000;
    const BAD: u64 = 0xdead_0000_0000;
    const MONO: i128 = 5_123_456_789;
    const OFFSET: i128 = 1_800_000_000_000_000_000;
    /// `make_process_cpuclock(1, which)` and its per-thread form.
    const fn cpu_clock(pid: i32, which: i32, thread: bool) -> i32 {
        ((!pid) << 3) | which | if thread { 4 } else { 0 }
    }

    fn user_task() -> Task {
        let mut task = task();
        task.pages.map(BUF, true);
        task
    }
    fn call(task: &mut Task, sysno: Sysno, args: [u64; 4]) -> Outcome {
        dispatch(
            task,
            sysno as u64,
            [args[0], args[1], args[2], args[3], 0, 0],
        )
    }
    fn ret(task: &mut Task, sysno: Sysno, args: [u64; 4]) -> i64 {
        match call(task, sysno, args) {
            Outcome::Return(value) => value,
            other => panic!("{other:?}"),
        }
    }
    fn neg(errno: Errno) -> i64 {
        error(errno)
    }
    fn put(task: &mut Task, at: u64, sec: i64, nsec: i64) {
        let mut raw = [0u8; 16];
        raw[..8].copy_from_slice(&sec.to_le_bytes());
        raw[8..].copy_from_slice(&nsec.to_le_bytes());
        assert_eq!(copy_to_user(task, at, &raw), 0);
    }
    fn get(task: &mut Task, at: u64) -> (i64, i64) {
        read_timespec(task, at).unwrap()
    }
    fn gettime(task: &mut Task, clock: i32) -> (i64, Ts) {
        put(task, BUF, -1, -1);
        let r = ret(task, Sysno::clock_gettime, [arg(clock), BUF, 0, 0]);
        (r, get(task, BUF))
    }
    fn ns(sec: i128, nsec: i128) -> Ts {
        ((sec as i64), nsec as i64)
    }

    #[test]
    fn clock_ids_decode_like_clockid_to_kclock() {
        assert_eq!(clockid_to_kclock(0), Some(Kclock::Realtime));
        assert_eq!(clockid_to_kclock(9), Some(Kclock::BoottimeAlarm));
        assert_eq!(clockid_to_kclock(11), Some(Kclock::Tai));
        for id in [10, 12, 16, 255, i32::MAX] {
            assert_eq!(clockid_to_kclock(id), None, "{id}");
        }
        let process = cpu_clock(1, 2, false);
        assert_eq!(process, -14);
        assert_eq!(clockid_to_kclock(process), Some(Kclock::PosixCpu(process)));
        // `(id & 7) == CLOCKFD` (3): a posix-clock fd, whatever the fd.
        assert_eq!(clockid_to_kclock(!5 << 3 | 3), Some(Kclock::Dynamic));
        assert_eq!(clockid_to_kclock(-1), Some(Kclock::PosixCpu(-1)));
        assert_eq!(
            clockid_to_kclock(i32::MIN),
            Some(Kclock::PosixCpu(i32::MIN))
        );
    }

    #[test]
    fn constants_match_linux() {
        assert_eq!(INITIAL_JIFFIES, 4_294_667_296);
        assert_eq!(KTIME_SEC_MAX, 9_223_372_036);
        assert_eq!(TIME_SETTOD_SEC_MAX, 8_277_292_036);
        assert!(valid((0, 999_999_999)));
        assert!(!valid((0, 1_000_000_000)));
        assert!(!valid((0, -1)));
        assert!(!valid((-1, 0)));
        assert!(!valid_settod((TIME_SETTOD_SEC_MAX, 0)));
        assert!(valid_settod((TIME_SETTOD_SEC_MAX - 1, 0)));
        assert_eq!(to_ktime((KTIME_SEC_MAX, 0)), KTIME_MAX);
        assert_eq!(to_ktime((1, 5)), 1_000_000_005);
    }

    #[test]
    fn gettime_reads_every_clock() {
        let mut t = user_task();
        let real = MONO + OFFSET;
        let coarse = MONO - MONO % 1_000_000;
        for (clock, want) in [
            (0, real),
            (1, MONO),
            (2, 3_000_000),
            (3, 3_000_000),
            (4, MONO),
            (5, coarse + OFFSET),
            (6, coarse),
            (7, MONO),
            (8, real),
            (9, MONO),
            (11, real),
            (cpu_clock(1, 0, false), 3_000_000),
            (cpu_clock(1, 1, true), 2_000_000),
            (cpu_clock(0, 2, true), 3_000_000),
        ] {
            let (r, ts) = gettime(&mut t, clock);
            assert_eq!(r, 0, "{clock}");
            assert_eq!(ts, ns(want.div_euclid(NS), want.rem_euclid(NS)), "{clock}");
        }
        // Boottime runs ahead of monotonic by the suspended time.
        t.clocks.state.boot_offset_ns = 7;
        assert_eq!(gettime(&mut t, 7).1, (5, 123_456_796));
    }

    #[test]
    fn gettime_errors_in_linux_order() {
        let mut t = user_task();
        for clock in [10, 12, 255, i32::MAX] {
            assert_eq!(gettime(&mut t, clock), (neg(Errno::EINVAL), (-1, -1)));
        }
        // Bad pointer: EFAULT, but an invalid clock is diagnosed first.
        assert_eq!(
            ret(&mut t, Sysno::clock_gettime, [1, BAD, 0, 0]),
            neg(Errno::EFAULT)
        );
        assert_eq!(
            ret(&mut t, Sysno::clock_gettime, [0, 0, 0, 0]),
            neg(Errno::EFAULT)
        );
        assert_eq!(
            ret(&mut t, Sysno::clock_gettime, [12, BAD, 0, 0]),
            neg(Errno::EINVAL)
        );
        // `clockid_t` is an int: the upper half of the register is ignored.
        assert_eq!(
            ret(&mut t, Sysno::clock_gettime, [1 << 32 | 1, BUF, 0, 0]),
            0
        );
        // No RTC: the alarm clocks are EINVAL, the others unaffected.
        t.clocks.rtc = false;
        assert_eq!(gettime(&mut t, 8).0, neg(Errno::EINVAL));
        assert_eq!(gettime(&mut t, 9).0, neg(Errno::EINVAL));
        assert_eq!(gettime(&mut t, 0).0, 0);
        // CPU clocks of other processes, bad `which` and posix-clock fds.
        for clock in [
            cpu_clock(2, 2, false),
            cpu_clock(1, 3, false),
            -1,
            !5 << 3 | 3,
        ] {
            assert_eq!(gettime(&mut t, clock).0, neg(Errno::EINVAL), "{clock}");
        }
    }

    #[test]
    fn getres_reports_resolution_per_clock() {
        let mut t = user_task();
        let res = |t: &mut Task, clock: i32| {
            put(t, BUF, -1, -1);
            let r = ret(t, Sysno::clock_getres, [arg(clock), BUF, 0, 0]);
            (r, get(t, BUF))
        };
        for clock in [0, 1, 2, 3, 4, 7, 8, 9, 11, cpu_clock(1, 2, false)] {
            assert_eq!(res(&mut t, clock), (0, (0, 1)), "{clock}");
        }
        for clock in [5, 6, cpu_clock(1, 0, false), cpu_clock(0, 1, true)] {
            assert_eq!(res(&mut t, clock), (0, (0, 1_000_000)), "{clock}");
        }
        // A null result pointer is valid; an invalid clock is not, null or not.
        assert_eq!(ret(&mut t, Sysno::clock_getres, [1, 0, 0, 0]), 0);
        assert_eq!(
            ret(&mut t, Sysno::clock_getres, [12, 0, 0, 0]),
            neg(Errno::EINVAL)
        );
        assert_eq!(
            ret(&mut t, Sysno::clock_getres, [1, BAD, 0, 0]),
            neg(Errno::EFAULT)
        );
        assert_eq!(res(&mut t, 12), (neg(Errno::EINVAL), (-1, -1)));
        t.clocks.rtc = false;
        assert_eq!(res(&mut t, 8).0, neg(Errno::EINVAL));
        assert_eq!(res(&mut t, !5 << 3 | 3).0, neg(Errno::EINVAL));
    }

    #[test]
    fn settime_follows_do_settimeofday64() {
        let mut t = user_task();
        let settime = |t: &mut Task, clock: i32, sec: i64, nsec: i64| {
            put(t, BUF, sec, nsec);
            ret(t, Sysno::clock_settime, [arg(clock), BUF, 0, 0])
        };
        // Only realtime (and CPU/posix-clock ids) have a setter.
        for clock in [1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 10, 12] {
            assert_eq!(settime(&mut t, clock, 0, 0), neg(Errno::EINVAL), "{clock}");
        }
        // Setter present: the pointer is read first, then the clock decides.
        assert_eq!(
            ret(&mut t, Sysno::clock_settime, [0, BAD, 0, 0]),
            neg(Errno::EFAULT)
        );
        assert_eq!(
            ret(&mut t, Sysno::clock_settime, [2, BAD, 0, 0]),
            neg(Errno::EINVAL)
        );
        assert_eq!(
            settime(&mut t, cpu_clock(1, 2, false), 0, 0),
            neg(Errno::EPERM)
        );
        assert_eq!(
            settime(&mut t, cpu_clock(9, 2, false), 0, 0),
            neg(Errno::EINVAL)
        );
        assert_eq!(settime(&mut t, !5 << 3 | 3, 0, 0), neg(Errno::EINVAL));
        // Validity, then privilege, then the "not before monotonic" rule.
        assert_eq!(settime(&mut t, 0, 5, 1_000_000_000), neg(Errno::EINVAL));
        assert_eq!(settime(&mut t, 0, -1, 0), neg(Errno::EINVAL));
        assert_eq!(
            settime(&mut t, 0, TIME_SETTOD_SEC_MAX, 0),
            neg(Errno::EINVAL)
        );
        t.clocks.capable = false;
        assert_eq!(settime(&mut t, 0, 100, 0), neg(Errno::EPERM));
        assert_eq!(settime(&mut t, 0, 0, -1), neg(Errno::EINVAL));
        t.clocks.capable = true;
        assert_eq!(settime(&mut t, 0, 5, 123_456_788), neg(Errno::EINVAL));
        assert_eq!(t.clocks.set, [0i64; 0]);
        // Equal to monotonic is allowed (offset 0); a later time sets the offset.
        assert_eq!(settime(&mut t, 0, 5, 123_456_789), 0);
        assert_eq!(settime(&mut t, 0, 1_000_000, 500), 0);
        assert_eq!(t.clocks.set, [0, 1_000_000_000_000_500 - 5_123_456_789]);
        assert_eq!(gettime(&mut t, 0).1, (1_000_000, 500));
    }

    #[test]
    fn nanosleep_and_clock_nanosleep_compute_monotonic_deadlines() {
        let mut t = user_task();
        let now = MONO as u64;
        put(&mut t, BUF, 1, 5);
        assert_eq!(ret(&mut t, Sysno::nanosleep, [BUF, 0, 0, 0]), 0);
        // CLOCK_REALTIME absolute: the deadline moves by the realtime offset.
        put(&mut t, BUF, OFFSET.div_euclid(NS) as i64 + 2, 0);
        assert_eq!(ret(&mut t, Sysno::clock_nanosleep, [0, 1, BUF, 0]), 0);
        // Boottime absolute (clamped by the boot offset); other flag bits are ignored.
        t.clocks.state.boot_offset_ns = 1_000;
        put(&mut t, BUF, 0, 4_000);
        assert_eq!(ret(&mut t, Sysno::clock_nanosleep, [7, 1, BUF, 0]), 0);
        assert_eq!(ret(&mut t, Sysno::clock_nanosleep, [1, 2, BUF, 0]), 0);
        // Past absolute deadlines clamp to zero: the wait returns at once.
        put(&mut t, BUF, 0, 1);
        assert_eq!(ret(&mut t, Sysno::clock_nanosleep, [1, 1, BUF, 0]), 0);
        assert_eq!(
            t.clocks.slept,
            [now + 1_000_000_005, 2_000_000_000, 3_000, now + 4_000, 1]
        );
    }

    #[test]
    fn sleep_validation_and_errors() {
        let mut t = user_task();
        for (sec, nsec) in [(0, 1_000_000_000), (0, -1), (-1, 0), (0, i64::MIN)] {
            put(&mut t, BUF, sec, nsec);
            assert_eq!(
                ret(&mut t, Sysno::nanosleep, [BUF, 0, 0, 0]),
                neg(Errno::EINVAL)
            );
            assert_eq!(
                ret(&mut t, Sysno::clock_nanosleep, [1, 0, BUF, 0]),
                neg(Errno::EINVAL)
            );
            assert_eq!(
                ret(&mut t, Sysno::clock_nanosleep, [1, 1, BUF, 0]),
                neg(Errno::EINVAL)
            );
        }
        assert_eq!(
            ret(&mut t, Sysno::nanosleep, [BAD, 0, 0, 0]),
            neg(Errno::EFAULT)
        );
        assert_eq!(
            ret(&mut t, Sysno::nanosleep, [0, 0, 0, 0]),
            neg(Errno::EFAULT)
        );
        // Clock checks precede the user pointer: invalid, then unsupported.
        assert_eq!(
            ret(&mut t, Sysno::clock_nanosleep, [12, 0, BAD, 0]),
            neg(Errno::EINVAL)
        );
        assert_eq!(
            ret(&mut t, Sysno::clock_nanosleep, [10, 0, BAD, 0]),
            neg(Errno::EINVAL)
        );
        for clock in [3, 4, 5, 6, !5 << 3 | 3] {
            assert_eq!(
                ret(&mut t, Sysno::clock_nanosleep, [arg(clock), 0, BAD, 0]),
                neg(Errno::EOPNOTSUPP),
                "{clock}"
            );
        }
        assert_eq!(
            ret(&mut t, Sysno::clock_nanosleep, [1, 0, BAD, 0]),
            neg(Errno::EFAULT)
        );
        // A bad `rem_out` is only written on interruption.
        put(&mut t, BUF, 0, 1);
        assert_eq!(ret(&mut t, Sysno::nanosleep, [BUF, BAD, 0, 0]), 0);
        assert_eq!(t.clocks.slept.len(), 1);
    }

    #[test]
    fn alarm_sleeps_check_rtc_flags_and_privilege_in_order() {
        let mut t = user_task();
        put(&mut t, BUF, 0, 1);
        t.clocks.rtc = false;
        assert_eq!(
            ret(&mut t, Sysno::clock_nanosleep, [8, 2, BUF, 0]),
            neg(Errno::EOPNOTSUPP)
        );
        t.clocks.rtc = true;
        assert_eq!(
            ret(&mut t, Sysno::clock_nanosleep, [8, 2, BUF, 0]),
            neg(Errno::EINVAL)
        );
        t.clocks.capable = false;
        assert_eq!(
            ret(&mut t, Sysno::clock_nanosleep, [9, 0, BUF, 0]),
            neg(Errno::EPERM)
        );
        t.clocks.capable = true;
        assert_eq!(ret(&mut t, Sysno::clock_nanosleep, [9, 0, BUF, 0]), 0);
        assert_eq!(ret(&mut t, Sysno::clock_nanosleep, [8, 1, BUF, 0]), 0);
        assert_eq!(t.clocks.slept.len(), 2);
    }

    #[test]
    fn cpu_clock_sleeps_are_loud_not_faked() {
        let mut t = user_task();
        put(&mut t, BUF, 0, 1);
        let number = Sysno::clock_nanosleep as u32;
        assert_eq!(
            call(&mut t, Sysno::clock_nanosleep, [2, 0, BUF, 0]),
            Outcome::Unimplemented(number)
        );
        let other = arg(cpu_clock(1, 2, false));
        assert_eq!(
            call(&mut t, Sysno::clock_nanosleep, [other, 0, BUF, 0]),
            Outcome::Unimplemented(number)
        );
        // Requests Linux answers at once: a zero expiry arms nothing, and an
        // absolute one that is not in the future fires immediately
        // (`posix_cpu_timer_set`). The fake process clock reads 3_000_000 ns,
        // the virtual clock (`which` 1) 2_000_000 ns.
        let virt = arg(cpu_clock(1, 1, false));
        for (clock, flags, ts) in [
            (2, 0, (0, 0)),
            (other, 0, (0, 0)),
            (2, 1, (0, 0)),
            (2, 1, (0, 3_000_000)),
            (2, 1, (0, 1)),
            (virt, 1, (0, 2_000_000)),
        ] {
            put(&mut t, BUF, ts.0, ts.1);
            assert_eq!(
                ret(&mut t, Sysno::clock_nanosleep, [clock, flags, BUF, 0]),
                0,
                "{clock} {flags} {ts:?}"
            );
        }
        // ... while a future expiry is the genuine wait that stops loudly.
        for (clock, flags, ts) in [
            (2, 1, (0, 3_000_001)),
            (2, 0, (0, 1)),
            (virt, 1, (0, 2_000_001)),
        ] {
            put(&mut t, BUF, ts.0, ts.1);
            assert_eq!(
                call(&mut t, Sysno::clock_nanosleep, [clock, flags, BUF, 0]),
                Outcome::Unimplemented(number),
                "{clock} {flags} {ts:?}"
            );
        }
        put(&mut t, BUF, 0, 1);
        // Own thread's clock cannot be slept on; unknown targets are invalid.
        let own = arg(cpu_clock(1, 2, true));
        let zero = arg(cpu_clock(0, 2, true));
        let foreign = arg(cpu_clock(7, 2, false));
        for clock in [own, zero, foreign] {
            assert_eq!(
                ret(&mut t, Sysno::clock_nanosleep, [clock, 0, BUF, 0]),
                neg(Errno::EINVAL)
            );
        }
    }

    #[test]
    fn interrupted_sleep_follows_do_nanosleep() {
        let mut t = user_task();
        put(&mut t, BUF, 1, 0);
        // Relative with rem_out: remaining time written, restart-block code returned.
        t.clocks.interrupt = Some(1_500_000_001);
        assert_eq!(
            ret(&mut t, Sysno::nanosleep, [BUF, BUF + 16, 0, 0]),
            -ERESTART_RESTARTBLOCK
        );
        assert_eq!(get(&mut t, BUF + 16), (1, 500_000_001));
        // Nothing remaining: success, rem_out untouched.
        put(&mut t, BUF + 32, 9, 9);
        t.clocks.interrupt = Some(0);
        assert_eq!(ret(&mut t, Sysno::nanosleep, [BUF, BUF + 32, 0, 0]), 0);
        assert_eq!(get(&mut t, BUF + 32), (9, 9));
        // A faulting rem_out wins over the restart code.
        t.clocks.interrupt = Some(5);
        assert_eq!(
            ret(&mut t, Sysno::nanosleep, [BUF, BAD, 0, 0]),
            neg(Errno::EFAULT)
        );
        // No rem_out: restart without reporting.
        t.clocks.interrupt = Some(5);
        assert_eq!(
            ret(&mut t, Sysno::nanosleep, [BUF, 0, 0, 0]),
            -ERESTART_RESTARTBLOCK
        );
        // Absolute: rem_out is ignored and the call restarts only on a handler-less signal.
        t.clocks.interrupt = Some(5);
        assert_eq!(
            ret(&mut t, Sysno::clock_nanosleep, [1, 1, BUF, BUF + 48]),
            -ERESTARTNOHAND
        );
        assert_eq!(get(&mut t, BUF + 48), (0, 0));
    }

    #[test]
    fn interrupted_sleep_records_the_restart_block() {
        let mut t = user_task();
        let mono = MONO as i64;
        let real = (MONO + OFFSET) as i64;
        let block = |func, clockid, expires_ns, rmtp| RestartBlock {
            func,
            clockid,
            expires_ns,
            rmtp,
        };
        let none = |rmtp| block(RestartFn::None, 0, 0, rmtp);
        t.clocks.state.boot_offset_ns = 1_000;
        put(&mut t, BUF, 1, 0);
        // (clock id, flags, expected restart block after the entry reset).
        // Hard expiry = now on the timer's base + 1 s + 50 us of slack; a relative
        // CLOCK_REALTIME sleep runs on the monotonic base.
        for (clock, flags, want) in [
            (
                1,
                0,
                block(RestartFn::Hrtimer, 1, mono + 1_000_050_000, BUF + 16),
            ),
            (
                0,
                0,
                block(RestartFn::Hrtimer, 1, mono + 1_000_050_000, BUF + 16),
            ),
            (
                7,
                0,
                block(
                    RestartFn::Hrtimer,
                    7,
                    mono + 1_000 + 1_000_050_000,
                    BUF + 16,
                ),
            ),
            (
                11,
                0,
                block(RestartFn::Hrtimer, 11, real + 1_000_050_000, BUF + 16),
            ),
            // Alarm sleeps have no slack and use the alarm type as the clock id.
            (
                8,
                0,
                block(RestartFn::Alarm, 0, real + 1_000_000_000, BUF + 16),
            ),
            (
                9,
                0,
                block(RestartFn::Alarm, 1, mono + 1_000 + 1_000_000_000, BUF + 16),
            ),
        ] {
            t.clocks.restarts.clear();
            t.clocks.interrupt = Some(5);
            assert_eq!(
                ret(
                    &mut t,
                    Sysno::clock_nanosleep,
                    [clock, flags, BUF, BUF + 16]
                ),
                -ERESTART_RESTARTBLOCK,
                "{clock}"
            );
            assert_eq!(t.clocks.restarts, [none(BUF + 16), want], "{clock}");
        }
        // nanosleep is CLOCK_MONOTONIC; without rmtp the pointer field is 0.
        t.clocks.restarts.clear();
        t.clocks.interrupt = Some(5);
        assert_eq!(
            ret(&mut t, Sysno::nanosleep, [BUF, 0, 0, 0]),
            -ERESTART_RESTARTBLOCK
        );
        assert_eq!(
            t.clocks.restarts,
            [
                none(0),
                block(RestartFn::Hrtimer, 1, mono + 1_000_050_000, 0)
            ]
        );
        // Absolute sleeps and completed sleeps leave `do_no_restart_syscall`.
        t.clocks.restarts.clear();
        t.clocks.interrupt = Some(5);
        assert_eq!(
            ret(&mut t, Sysno::clock_nanosleep, [1, 1, BUF, BUF + 16]),
            -ERESTARTNOHAND
        );
        assert_eq!(ret(&mut t, Sysno::clock_nanosleep, [1, 0, BUF, 0]), 0);
        assert_eq!(t.clocks.restarts, [none(0), none(0)]);
        // A huge relative request saturates at KTIME_MAX.
        put(&mut t, BUF, KTIME_SEC_MAX, 0);
        t.clocks.restarts.clear();
        t.clocks.interrupt = Some(5);
        assert_eq!(
            ret(&mut t, Sysno::nanosleep, [BUF, 0, 0, 0]),
            -ERESTART_RESTARTBLOCK
        );
        assert_eq!(
            t.clocks.restarts[1],
            block(RestartFn::Hrtimer, 1, i64::MAX, 0)
        );
    }

    #[test]
    fn restart_syscall_resumes_the_stored_block() {
        let mut t = user_task();
        let mono = MONO as i64;
        t.clocks.state.boot_offset_ns = 1_000;
        let block = |func, clockid, expires_ns| RestartBlock {
            func,
            clockid,
            expires_ns,
            rmtp: BUF + 16,
        };
        // `do_no_restart_syscall`.
        assert_eq!(
            ret(&mut t, Sysno::restart_syscall, [0; 4]),
            neg(Errno::EINTR)
        );
        t.clocks.restarts.push(RestartBlock::NONE);
        assert_eq!(
            ret(&mut t, Sysno::restart_syscall, [0; 4]),
            neg(Errno::EINTR)
        );
        // Each clock of the block: the wait is to the monotonic equivalent of the
        // absolute expiry; the base clocks differ from monotonic by their offset.
        for (func, clockid, expires, deadline) in [
            (RestartFn::Hrtimer, 1, mono + 7_000, MONO as u64 + 7_000),
            (
                RestartFn::Hrtimer,
                7,
                mono + 1_000 + 7_000,
                MONO as u64 + 7_000,
            ),
            (
                RestartFn::Hrtimer,
                11,
                mono + OFFSET as i64 + 7_000,
                MONO as u64 + 7_000,
            ),
            (
                RestartFn::Alarm,
                0,
                mono + OFFSET as i64 + 7_000,
                MONO as u64 + 7_000,
            ),
            (
                RestartFn::Alarm,
                1,
                mono + 1_000 + 7_000,
                MONO as u64 + 7_000,
            ),
        ] {
            let want = block(func, clockid, expires);
            t.clocks.restarts.push(want);
            t.clocks.slept.clear();
            // Slept to the end: success.
            assert_eq!(ret(&mut t, Sysno::restart_syscall, [0; 4]), 0, "{clockid}");
            assert_eq!(t.clocks.slept, [deadline], "{func:?} {clockid}");
            // Interrupted again: the remaining time is reported through `rmtp`
            // and the same block stays installed for the next restart.
            t.clocks.interrupt = Some(1_500_000_001);
            assert_eq!(
                ret(&mut t, Sysno::restart_syscall, [0; 4]),
                -ERESTART_RESTARTBLOCK
            );
            assert_eq!(get(&mut t, BUF + 16), (1, 500_000_001));
            assert_eq!(t.clocks.restarts.last(), Some(&want));
        }
    }

    #[test]
    fn coarse_realtime_reads_the_value_just_set() {
        let mut t = user_task();
        let coarse = |t: &mut Task| (gettime(t, 5).1, ret(t, Sysno::time, [0, 0, 0, 0]));
        // Before any set the tick view is floor(mono) + offset.
        assert_eq!(
            coarse(&mut t),
            ((1_800_000_005, 123_000_000), 1_800_000_005)
        );
        // `do_settimeofday64` stores xtime exactly: time() is T at once, not T-1.
        put(&mut t, BUF, 1_000_000, 0);
        assert_eq!(ret(&mut t, Sysno::clock_settime, [0, BUF, 0, 0]), 0);
        assert_eq!(coarse(&mut t), ((1_000_000, 0), 1_000_000));
        assert_eq!(gettime(&mut t, 0).1, (1_000_000, 0));
        // The next tick publishes real time again, which is above the set value.
        t.clocks.state.mono_ns = 5_124_000_000;
        assert_eq!(coarse(&mut t), ((1_000_000, 543_211), 1_000_000));
        t.clocks.state.mono_ns = 5_999_999_999;
        assert_eq!(coarse(&mut t), ((1_000_000, 875_543_211), 1_000_000));
        t.clocks.state.mono_ns = 6_000_000_000;
        assert_eq!(coarse(&mut t), ((1_000_000, 876_543_211), 1_000_000));
        // Setting the clock backwards lowers the floor with it.
        put(&mut t, BUF, 999_000, 7);
        assert_eq!(ret(&mut t, Sysno::clock_settime, [0, BUF, 0, 0]), 0);
        assert_eq!(coarse(&mut t), ((999_000, 7), 999_000));
    }

    #[test]
    fn wall_time_syscalls() {
        let mut t = user_task();
        let real = MONO + OFFSET;
        // gettimeofday: seconds, microseconds, and the (zero) timezone.
        assert_eq!(copy_to_user(&mut t, BUF + 32, &[0xaa; 8]), 0);
        assert_eq!(ret(&mut t, Sysno::gettimeofday, [BUF, BUF + 32, 0, 0]), 0);
        assert_eq!(
            get(&mut t, BUF),
            ns(real.div_euclid(NS), real.rem_euclid(NS) / 1000)
        );
        assert_eq!(get(&mut t, BUF + 32).0, 0);
        assert_eq!(ret(&mut t, Sysno::gettimeofday, [0, 0, 0, 0]), 0);
        assert_eq!(
            ret(&mut t, Sysno::gettimeofday, [BAD, 0, 0, 0]),
            neg(Errno::EFAULT)
        );
        assert_eq!(
            ret(&mut t, Sysno::gettimeofday, [0, BAD, 0, 0]),
            neg(Errno::EFAULT)
        );
        // time(): whole seconds of the tick-published realtime, stored and returned.
        let secs = (MONO - MONO % 1_000_000 + OFFSET).div_euclid(NS) as i64;
        assert_eq!(ret(&mut t, Sysno::time, [BUF, 0, 0, 0]), secs);
        assert_eq!(get(&mut t, BUF).0, secs);
        assert_eq!(ret(&mut t, Sysno::time, [0, 0, 0, 0]), secs);
        assert_eq!(ret(&mut t, Sysno::time, [BAD, 0, 0, 0]), neg(Errno::EFAULT));
    }

    #[test]
    fn times_reports_user_hz_ticks_and_boot_relative_jiffies() {
        let mut t = user_task();
        t.clocks.adjusted = (1_234_567_890, 99_999_999);
        // jiffies = INITIAL_JIFFIES + 5123 ms -> /10 for USER_HZ=100.
        let want = ((4_294_667_296u64 + 5_123) / 10) as i64;
        assert_eq!(ret(&mut t, Sysno::times, [BUF, 0, 0, 0]), want);
        let mut raw = [0u8; 32];
        assert_eq!(crate::usercopy::copy_from_user(&mut t, &mut raw, BUF), 0);
        let field = |i: usize| i64::from_le_bytes(raw[i * 8..i * 8 + 8].try_into().unwrap());
        assert_eq!((field(0), field(1), field(2), field(3)), (123, 9, 0, 0));
        assert_eq!(ret(&mut t, Sysno::times, [0, 0, 0, 0]), want);
        assert_eq!(
            ret(&mut t, Sysno::times, [BAD, 0, 0, 0]),
            neg(Errno::EFAULT)
        );
    }
}
