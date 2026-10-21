// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692 (all GPL-2.0-only):
// kernel/sched/cputime.c (`account_process_tick` l.475-503 for
// `CONFIG_TICK_CPU_ACCOUNTING=y`, `cputime_adjust` l.546-614,
// `thread_group_cputime_adjusted` l.636), kernel/time/posix-cpu-timers.c
// (`cpu_clock_sample` l.194: `CPUCLOCK_SCHED` is `sum_exec_runtime`, PROF and
// VIRT are the tick-accounted utime/stime), kernel/sys.c (`do_sys_times`).
// Transformation: one task on one CPU, so `sum_exec_runtime` is the time since
// the task started minus the time it slept (a sleeping task is not on the CPU,
// the halted CPU is idle), and the per-task counters are plain atomics that the
// tick interrupt and the syscall path share on that CPU.
#![forbid(unsafe_code)]
//! Per-task CPU-time accounting: the tick-based `utime`/`stime` and the exact
//! scheduler runtime, plus Linux's `cputime_adjust` scaling used by `times(2)`.
//!
//! Context: [`CpuAccount::tick`] runs in hardirq context (the timer tick) and
//! the other methods in task context with interrupts off or on; every field is
//! an atomic, nothing blocks or allocates. The sleep markers are written only by
//! the task itself, so a tick sees either "awake" or "asleep", never a torn
//! state. shortcut: one task; with a scheduler these become per-task fields
//! (`task_struct.utime/stime`, `se.sum_exec_runtime`) updated at context switch.

use crate::time::TICK_NSEC;
use core::sync::atomic::{AtomicU64, Ordering};

const NEVER: u64 = u64::MAX;

#[derive(Debug)]
#[allow(
    clippy::struct_field_names,
    reason = "every field is a nanosecond count; the unit suffix is the documentation"
)]
pub struct CpuAccount {
    /// Monotonic time the task first ran, or `NEVER` before it exists.
    start_ns: AtomicU64,
    /// Sleeping time accumulated by completed sleeps.
    slept_ns: AtomicU64,
    /// Monotonic time the current sleep began, `NEVER` while on the CPU.
    sleep_since_ns: AtomicU64,
    /// `utime`/`stime` in ns, advanced in whole ticks by [`Self::tick`].
    user_ns: AtomicU64,
    system_ns: AtomicU64,
    /// `prev_cputime` of `signal_struct`: the monotonic guard of `cputime_adjust`.
    prev_user_ns: AtomicU64,
    prev_system_ns: AtomicU64,
}

/// What the CPU-time clocks read at one instant, all in nanoseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuSample {
    /// `sum_exec_runtime` including the running slice: `CPUCLOCK_SCHED`.
    pub runtime_ns: u64,
    /// Tick-accounted user time: `CPUCLOCK_VIRT`.
    pub user_ns: u64,
    /// Tick-accounted system time; `CPUCLOCK_PROF` is `user_ns + system_ns`.
    pub system_ns: u64,
}

impl CpuAccount {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            start_ns: AtomicU64::new(NEVER),
            slept_ns: AtomicU64::new(0),
            sleep_since_ns: AtomicU64::new(NEVER),
            user_ns: AtomicU64::new(0),
            system_ns: AtomicU64::new(0),
            prev_user_ns: AtomicU64::new(0),
            prev_system_ns: AtomicU64::new(0),
        }
    }

    /// The task starts running at monotonic time `now_ns`; ticks before this
    /// belong to nobody. A new task (the bare-metal suite starts one fresh
    /// `/init` per group) begins with no accumulated time, as a new
    /// `task_struct` does; for the first task every field is already zero.
    pub fn start(&self, now_ns: u64) {
        for field in [
            &self.slept_ns,
            &self.user_ns,
            &self.system_ns,
            &self.prev_user_ns,
            &self.prev_system_ns,
        ] {
            field.store(0, Ordering::Relaxed);
        }
        self.sleep_since_ns.store(NEVER, Ordering::Relaxed);
        self.start_ns.store(now_ns, Ordering::Relaxed);
    }

    /// `account_process_tick` for `periods` elapsed ticks: a tick that finds the
    /// task in user mode is user time, one that finds it running in the kernel is
    /// system time, and one that finds it asleep (or no task yet) is idle time.
    ///
    /// Returns the nanoseconds charged (0 for an ignored tick), which the caller
    /// adds to the machine-wide `kernel_cpustat` (`ktask::charge_tick`).
    pub fn tick(&self, user_mode: bool, periods: u64) -> u64 {
        if self.start_ns.load(Ordering::Relaxed) == NEVER
            || self.sleep_since_ns.load(Ordering::Relaxed) != NEVER
        {
            return 0;
        }
        let field = if user_mode {
            &self.user_ns
        } else {
            &self.system_ns
        };
        let ns = periods.saturating_mul(TICK_NSEC);
        field.fetch_add(ns, Ordering::Relaxed);
        ns
    }

    /// The task leaves the CPU (it blocks) at `now_ns`.
    pub fn sleep_begin(&self, now_ns: u64) {
        self.sleep_since_ns.store(now_ns, Ordering::Relaxed);
    }

    /// The task is running again at `now_ns`.
    pub fn sleep_end(&self, now_ns: u64) {
        let since = self.sleep_since_ns.swap(NEVER, Ordering::Relaxed);
        if since != NEVER {
            self.slept_ns
                .fetch_add(now_ns.saturating_sub(since), Ordering::Relaxed);
        }
    }

    /// `sum_exec_runtime` at `now_ns` (`task_sched_runtime`).
    #[must_use]
    pub fn runtime_ns(&self, now_ns: u64) -> u64 {
        let start = self.start_ns.load(Ordering::Relaxed);
        if start == NEVER {
            return 0;
        }
        let since = self.sleep_since_ns.load(Ordering::Relaxed);
        let current = if since == NEVER {
            0
        } else {
            now_ns.saturating_sub(since)
        };
        now_ns
            .saturating_sub(start)
            .saturating_sub(self.slept_ns.load(Ordering::Relaxed))
            .saturating_sub(current)
    }

    #[must_use]
    pub fn sample(&self, now_ns: u64) -> CpuSample {
        CpuSample {
            runtime_ns: self.runtime_ns(now_ns),
            user_ns: self.user_ns.load(Ordering::Relaxed),
            system_ns: self.system_ns.load(Ordering::Relaxed),
        }
    }

    /// `thread_group_cputime_adjusted`: the `(utime, stime)` that `times(2)`
    /// reports, scaled to the exact runtime and monotonic across calls. Task
    /// context only (the `prev_cputime` lock of Linux is the single caller).
    pub fn adjusted(&self, now_ns: u64) -> (u64, u64) {
        let sample = self.sample(now_ns);
        let prev = (
            self.prev_user_ns.load(Ordering::Relaxed),
            self.prev_system_ns.load(Ordering::Relaxed),
        );
        let (user, system) = cputime_adjust(sample, prev);
        self.prev_user_ns.store(user, Ordering::Relaxed);
        self.prev_system_ns.store(system, Ordering::Relaxed);
        (user, system)
    }
}

impl Default for CpuAccount {
    fn default() -> Self {
        Self::new()
    }
}

/// `cputime_adjust`: guarantees `utime + stime == rtime` (unless `prev` already
/// exceeds it) and that neither component goes backwards. `prev` is
/// `(prev.utime, prev.stime)`; the result is the new `(utime, stime)`.
#[must_use]
pub fn cputime_adjust(sample: CpuSample, prev: (u64, u64)) -> (u64, u64) {
    let rtime = sample.runtime_ns;
    let (prev_user, prev_system) = prev;
    // Filter: rtime must have grown past what was already handed out.
    if prev_system.saturating_add(prev_user) >= rtime {
        return prev;
    }
    let (user, system) = (sample.user_ns, sample.system_ns);
    let mut system = if system == 0 {
        // No system tick yet: all runtime is user time.
        0
    } else if user == 0 {
        rtime
    } else {
        let scaled =
            u128::from(system) * u128::from(rtime) / (u128::from(system) + u128::from(user));
        u64::try_from(scaled).unwrap_or(rtime).min(rtime)
    };
    // Make sure stime does not go backwards, then utime.
    if system < prev_system {
        system = prev_system;
    }
    let mut user = rtime - system;
    if user < prev_user {
        user = prev_user;
        system = rtime - user;
    }
    (user, system)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(runtime_ns: u64, user_ns: u64, system_ns: u64) -> CpuSample {
        CpuSample {
            runtime_ns,
            user_ns,
            system_ns,
        }
    }

    #[test]
    fn adjust_scales_ticks_to_runtime_like_linux() {
        // No system ticks: everything is user time.
        assert_eq!(cputime_adjust(sample(900, 5, 0), (0, 0)), (900, 0));
        // No user ticks: everything is system time.
        assert_eq!(cputime_adjust(sample(900, 0, 5), (0, 0)), (0, 900));
        // 3:1 ticks scale to a 3:1 split of the exact runtime.
        assert_eq!(cputime_adjust(sample(1000, 3, 1), (0, 0)), (750, 250));
        // The sum always equals the runtime.
        let (u, s) = cputime_adjust(sample(1001, 7, 3), (0, 0));
        assert_eq!(u + s, 1001);
    }

    #[test]
    fn adjust_is_monotonic_and_filters_stale_runtime() {
        // rtime not past the already reported sum: previous values stay.
        assert_eq!(cputime_adjust(sample(100, 1, 1), (60, 40)), (60, 40));
        assert_eq!(cputime_adjust(sample(90, 1, 1), (60, 40)), (60, 40));
        // stime would shrink: it is held, utime absorbs the growth.
        assert_eq!(cputime_adjust(sample(200, 9, 1), (50, 50)), (150, 50));
        // utime would shrink: it is held, stime absorbs it.
        assert_eq!(cputime_adjust(sample(200, 1, 9), (150, 10)), (150, 50));
    }

    #[test]
    fn runtime_excludes_sleep_and_ticks_need_a_running_task() {
        let account = CpuAccount::new();
        assert_eq!(account.tick(true, 1), 0);
        assert_eq!(account.sample(1_000), sample(0, 0, 0));
        account.start(1_000);
        assert_eq!(account.tick(true, 2), 2 * TICK_NSEC);
        assert_eq!(account.tick(false, 1), TICK_NSEC);
        account.sleep_begin(5_000);
        assert_eq!(account.tick(true, 10), 0); // asleep: idle time, not accounted
        assert_eq!(account.runtime_ns(9_000), 4_000);
        account.sleep_end(9_000);
        assert_eq!(account.runtime_ns(10_000), 5_000);
        assert_eq!(
            account.sample(10_000),
            sample(5_000, 2 * TICK_NSEC, TICK_NSEC)
        );
        // Calls move the monotonic guard forward only.
        let (u1, s1) = account.adjusted(10_000);
        assert_eq!(u1 + s1, 5_000);
        assert_eq!(account.adjusted(10_000), (u1, s1));
    }
}
