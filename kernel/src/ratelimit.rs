// SPDX-License-Identifier: GPL-2.0-only
// Linux 6.18.57 (commit 2ff600d29ee478d0a8d46ef8a58afb5e038fe692):
// lib/ratelimit.c (`___ratelimit` 28-100), include/linux/ratelimit_types.h
// (`DEFINE_RATELIMIT_STATE`), kernel/printk/printk.c:4699-4704
// (`printk_ratelimit_state`: 5 * HZ, burst 10, `__printk_ratelimit`),
// include/linux/jiffies.h (`time_is_before_jiffies`). All GPL-2.0.
// Transformation: one CPU, so the raw spinlock and the lockless fallback for a
// contended lock are gone; `rs_n_left` and the miss counter are plain fields.
#![forbid(unsafe_code)]
//! `printk_ratelimit()`: at most `burst` messages per `interval` jiffies, and a
//! count of the suppressed ones reported when the next interval starts.

/// A `struct ratelimit_state` with `RATELIMIT_MSG_ON_RELEASE` clear.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimit {
    interval: u64,
    burst: u32,
    begin: u64,
    left: u32,
    missed: u32,
    initialized: bool,
}

/// What [`RateLimit::check`] decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verdict {
    /// The caller may print (`___ratelimit` returned 1).
    pub allowed: bool,
    /// Messages suppressed in the interval that just ended; Linux prints
    /// `"<func>: <n> callbacks suppressed"` first when this is non-zero.
    pub suppressed: u32,
}

impl RateLimit {
    /// `DEFINE_RATELIMIT_STATE(name, interval, burst)`.
    #[must_use]
    pub const fn new(interval: u64, burst: u32) -> Self {
        Self {
            interval,
            burst,
            begin: 0,
            left: 0,
            missed: 0,
            initialized: false,
        }
    }

    /// `printk_ratelimit_state` of the kernel: `5 * HZ` jiffies, burst 10.
    #[must_use]
    pub const fn printk(hz: u64) -> Self {
        Self::new(5 * hz, 10)
    }

    /// `___ratelimit` at time `now` (jiffies). A zero interval never limits,
    /// a zero burst always does.
    pub fn check(&mut self, now: u64) -> Verdict {
        if self.interval == 0 {
            return Verdict {
                allowed: true,
                suppressed: 0,
            };
        }
        if self.burst == 0 {
            self.missed = self.missed.saturating_add(1);
            return Verdict {
                allowed: false,
                suppressed: 0,
            };
        }
        if !self.initialized {
            self.begin = now;
            self.initialized = true;
            self.left = self.burst;
        }
        let mut suppressed = 0;
        // time_is_before_jiffies(begin + interval): wrap-safe `now > begin + interval`.
        if now
            .wrapping_sub(self.begin.wrapping_add(self.interval))
            .cast_signed()
            > 0
        {
            self.left = self.burst;
            self.begin = now;
            suppressed = core::mem::take(&mut self.missed);
        }
        let allowed = self.left > 0;
        if allowed {
            self.left -= 1;
        } else {
            self.missed = self.missed.saturating_add(1);
        }
        Verdict {
            allowed,
            suppressed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RateLimit;

    #[test]
    fn burst_then_suppress_then_report_when_the_interval_ends() {
        let mut rl = RateLimit::printk(1000);
        // Ten messages go through at once, the eleventh and twelfth do not.
        for i in 0..10 {
            let v = rl.check(100 + i);
            assert!(v.allowed && v.suppressed == 0, "{i}");
        }
        for _ in 0..2 {
            let v = rl.check(2_000);
            assert!(!v.allowed && v.suppressed == 0);
        }
        // Exactly on the interval boundary (begin + 5000) is still inside it.
        assert!(!rl.check(100 + 5_000).allowed);
        // One jiffy later a new interval starts: the three misses are reported
        // with the first new message, and the burst is full again.
        let v = rl.check(100 + 5_001);
        assert_eq!((v.allowed, v.suppressed), (true, 3));
        for _ in 0..9 {
            assert!(rl.check(100 + 5_001).allowed);
        }
        let v = rl.check(100 + 5_002);
        assert_eq!((v.allowed, v.suppressed), (false, 0));
    }

    #[test]
    fn degenerate_states_and_wraparound() {
        let mut never = RateLimit::new(0, 3);
        assert!((0..100).all(|i| never.check(i).allowed));
        let mut always = RateLimit::new(10, 0);
        assert!(!always.check(1).allowed);
        // Jiffies wrap: the interval comparison is signed.
        let mut rl = RateLimit::new(100, 1);
        assert!(rl.check(u64::MAX - 10).allowed);
        assert!(!rl.check(u64::MAX).allowed);
        let v = rl.check(95); // wrapped past begin + 100
        assert_eq!((v.allowed, v.suppressed), (true, 1));
    }
}
