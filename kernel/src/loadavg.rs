// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: include/linux/sched/loadavg.h
// (`FSHIFT`, `FIXED_1`, `LOAD_FREQ`, `EXP_1/5/15`, `calc_load`),
// kernel/sched/loadavg.c (`calc_load_fold_active`, `calc_global_load`,
// `calc_global_load_tick`, `get_avenrun`), kernel/time/tick-common.c
// (`tick_periodic`: `do_timer` before `update_process_times`), kernel/sys.c
// (`do_sysinfo`: `SI_LOAD_SHIFT - FSHIFT`). GPL-2.0-only.
// Transformation: one CPU and one counted task source; `calc_load_nohz_*`
// (idle CPUs folding their deltas) is absent because the CPU never enters the
// dynamic-idle path while a task is runnable.
#![forbid(unsafe_code)]
//! The load averages `sysinfo(2)` reports.
//!
//! The state is a pure function of the jiffies count: [`LoadAvg::loads_at`]
//! replays every sampling window up to `jiffies` on a copy, so no interrupt
//! hook or lock is needed and the result is identical to ticking each jiffy.
//! No allocation, no sleeping; any context.

/// `FSHIFT`: bits of fixed-point precision.
pub const FSHIFT: u32 = 11;
/// `FIXED_1`: 1.0 in fixed point.
pub const FIXED_1: u64 = 1 << FSHIFT;
/// `LOAD_FREQ`: sample every 5 s plus one tick, in jiffies, for `HZ == 1000`.
pub const LOAD_FREQ: u64 = 5 * crate::time::HZ + 1;
/// `1/exp(5 s / 1 min)`, `1/exp(5 s / 5 min)`, `1/exp(5 s / 15 min)` in fixed point.
pub const EXP: [u64; 3] = [1884, 2014, 2037];
/// `SI_LOAD_SHIFT`: the fixed-point shift of `struct sysinfo::loads`.
pub const SI_LOAD_SHIFT: u32 = 16;

/// `calc_load`: one exponential-decay step, rounding up while the load rises.
#[must_use]
pub fn calc_load(load: u64, exp: u64, active: u64) -> u64 {
    let mut new = load * exp + active * (FIXED_1 - exp);
    if active >= load {
        new += FIXED_1 - 1;
    }
    new / FIXED_1
}

/// `avenrun[]` plus the one CPU's and the global sampling state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoadAvg {
    /// `avenrun`, `FSHIFT`-bit fixed point.
    avenrun: [u64; 3],
    /// `rq->calc_load_update`: when this CPU next samples its task count.
    cpu_update: u64,
    /// `calc_load_update`: when the global average next updates (10 ticks after
    /// the CPU sampled).
    global_update: u64,
    /// `rq->calc_load_active`: what this CPU last contributed.
    cpu_active: i64,
    /// `calc_load_tasks`: the sum of every CPU's contribution.
    tasks: i64,
}

impl LoadAvg {
    /// `sched_init` / `init_rq`: the first window ends `LOAD_FREQ` jiffies from now.
    #[must_use]
    pub fn new(jiffies: u64) -> Self {
        Self {
            avenrun: [0; 3],
            cpu_update: jiffies + LOAD_FREQ,
            global_update: jiffies + LOAD_FREQ,
            cpu_active: 0,
            tasks: 0,
        }
    }

    /// Replay the sampling events due by `jiffies`, with `nr_active` =
    /// `nr_running + nr_uninterruptible` of the CPU at each of them. Events run
    /// in time order and, when simultaneous, as in `tick_periodic`: the global
    /// update (`calc_global_load`, 10 ticks after the window) before this CPU's
    /// sample (`calc_global_load_tick`). Several windows missed at once are
    /// replayed one by one, which is what the per-tick path would have done.
    pub fn advance(&mut self, jiffies: u64, nr_active: i64) {
        loop {
            let global = self.global_update + 10;
            if global <= self.cpu_update {
                if jiffies < global {
                    break;
                }
                let active = u64::try_from(self.tasks).map_or(0, |tasks| tasks * FIXED_1);
                for (load, exp) in self.avenrun.iter_mut().zip(EXP) {
                    *load = calc_load(*load, exp, active);
                }
                self.global_update += LOAD_FREQ;
            } else {
                if jiffies < self.cpu_update {
                    break;
                }
                self.tasks += nr_active - self.cpu_active;
                self.cpu_active = nr_active;
                self.cpu_update += LOAD_FREQ;
            }
        }
    }

    /// `get_avenrun(loads, 0, SI_LOAD_SHIFT - FSHIFT)` as of `jiffies`: the
    /// values `sysinfo` stores. Works on a copy; `self` stays the state at the
    /// start of the replay (cost is one step per elapsed 5 s window).
    #[must_use]
    pub fn loads_at(&self, jiffies: u64, nr_active: i64) -> [u64; 3] {
        let mut now = *self;
        now.advance(jiffies, nr_active);
        now.sysinfo_loads()
    }

    /// `get_avenrun(loads, 0, SI_LOAD_SHIFT - FSHIFT)` of the current state.
    #[must_use]
    pub fn sysinfo_loads(&self) -> [u64; 3] {
        self.avenrun.map(|load| load << (SI_LOAD_SHIFT - FSHIFT))
    }
}

#[cfg(test)]
mod tests {
    use super::{LOAD_FREQ, LoadAvg, calc_load};

    #[test]
    fn calc_load_matches_the_published_fixed_point_steps() {
        // From zero with one active task (2048): ceil(2048 * (2048 - exp) / 2048).
        assert_eq!(calc_load(0, 1884, 2048), 164);
        assert_eq!(calc_load(0, 2014, 2048), 34);
        assert_eq!(calc_load(0, 2037, 2048), 11);
        // Decaying rounds down; a steady state is a fixed point.
        assert_eq!(calc_load(2048, 1884, 0), 1884);
        assert_eq!(calc_load(2048, 1884, 2048), 2048);
    }

    #[test]
    fn a_busy_cpu_first_moves_the_average_ten_ticks_after_its_window() {
        let mut load = LoadAvg::new(0);
        assert_eq!(LOAD_FREQ, 5001);
        for jiffies in 1..=5010 {
            load.advance(jiffies, 1);
            assert_eq!(load.sysinfo_loads(), [0; 3], "{jiffies}");
        }
        // The CPU sampled at 5001; the global update waits for 5001 + 10.
        load.advance(5011, 1);
        assert_eq!(load.sysinfo_loads(), [164 << 5, 34 << 5, 11 << 5]);
        // The next window: CPU at 10002, global at 10012.
        for jiffies in 5012..=10011 {
            load.advance(jiffies, 1);
        }
        assert_eq!(load.sysinfo_loads()[0], 164 << 5);
        load.advance(10012, 1);
        let second = calc_load(164, 1884, 2048);
        assert_eq!(load.sysinfo_loads()[0], second << 5);
        assert_eq!(second, 315);
    }

    #[test]
    fn an_idle_cpu_decays_and_never_goes_negative() {
        let mut load = LoadAvg::new(100);
        load.advance(100 + 5001, 1);
        load.advance(100 + 5011, 1);
        let busy = load.sysinfo_loads()[0];
        assert!(busy > 0);
        // The task stops counting at the next sample: the contribution is removed.
        load.advance(100 + 10002, 0);
        load.advance(100 + 10012, 0);
        assert!(load.sysinfo_loads()[0] < busy);
        let mut load = LoadAvg::new(0);
        load.advance(5001, -3);
        load.advance(5011, -3);
        assert_eq!(load.sysinfo_loads(), [0; 3]);
    }

    #[test]
    fn a_late_replay_equals_ticking_every_jiffy() {
        let start = 123;
        let mut each = LoadAvg::new(start);
        for jiffies in start..=start + 40_000 {
            each.advance(jiffies, 1);
        }
        let once = LoadAvg::new(start);
        assert_eq!(once.loads_at(start + 40_000, 1), each.sysinfo_loads());
        assert_ne!(each.sysinfo_loads(), [0; 3]);
        // Not yet at the first global update: still zero, and `loads_at` leaves
        // the receiver untouched.
        assert_eq!(once.loads_at(start + 5010, 1), [0; 3]);
        assert_eq!(once, LoadAvg::new(start));
    }
}
