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
//! The load averages `sysinfo(2)` reports, advanced by the periodic tick.
//!
//! Context: called from the timer interrupt on the boot CPU, one tick at a time
//! (the owner serialises it with the reader). No allocation, no sleeping.

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

    /// One timer tick at `jiffies` with `nr_active` = `nr_running +
    /// nr_uninterruptible` of the CPU. Order as in `tick_periodic`: the global
    /// update (`calc_global_load`, 10 ticks after the window) first, then this
    /// CPU's sample (`calc_global_load_tick`).
    pub fn tick(&mut self, jiffies: u64, nr_active: i64) {
        if jiffies >= self.global_update + 10 {
            let active = u64::try_from(self.tasks).map_or(0, |tasks| tasks * FIXED_1);
            for (load, exp) in self.avenrun.iter_mut().zip(EXP) {
                *load = calc_load(*load, exp, active);
            }
            self.global_update += LOAD_FREQ;
        }
        if jiffies >= self.cpu_update {
            self.tasks += nr_active - self.cpu_active;
            self.cpu_active = nr_active;
            self.cpu_update += LOAD_FREQ;
        }
    }

    /// `get_avenrun(loads, 0, SI_LOAD_SHIFT - FSHIFT)`: the values `sysinfo` stores.
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
            load.tick(jiffies, 1);
            assert_eq!(load.sysinfo_loads(), [0; 3], "{jiffies}");
        }
        // The CPU sampled at 5001; the global update waits for 5001 + 10.
        load.tick(5011, 1);
        assert_eq!(load.sysinfo_loads(), [164 << 5, 34 << 5, 11 << 5]);
        // The next window: CPU at 10002, global at 10012.
        for jiffies in 5012..=10011 {
            load.tick(jiffies, 1);
        }
        assert_eq!(load.sysinfo_loads()[0], 164 << 5);
        load.tick(10012, 1);
        let second = calc_load(164, 1884, 2048);
        assert_eq!(load.sysinfo_loads()[0], second << 5);
        assert_eq!(second, 315);
    }

    #[test]
    fn an_idle_cpu_decays_and_never_goes_negative() {
        let mut load = LoadAvg::new(100);
        load.tick(100 + 5001, 1);
        load.tick(100 + 5011, 1);
        let busy = load.sysinfo_loads()[0];
        assert!(busy > 0);
        // The task stops counting at the next sample: the contribution is removed.
        load.tick(100 + 10002, 0);
        load.tick(100 + 10012, 0);
        assert!(load.sysinfo_loads()[0] < busy);
        let mut load = LoadAvg::new(0);
        load.tick(5001, -3);
        load.tick(5011, -3);
        assert_eq!(load.sysinfo_loads(), [0; 3]);
    }
}
