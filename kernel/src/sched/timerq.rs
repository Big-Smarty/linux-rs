// SPDX-License-Identifier: GPL-2.0-only
// Linux 6.18.57 (commit 2ff600d29ee478d0a8d46ef8a58afb5e038fe692), all
// GPL-2.0: kernel/time/hrtimer.c (`hrtimer_start_range_ns` re-arming an active
// timer, `__run_hrtimer` expiry in expiry order, `hrtimer_cancel`),
// kernel/time/sleep_timeout.c (`schedule_hrtimeout_range`).
// Transformation: an `hrtimer` red-black tree per CPU becomes one sorted
// fixed-capacity array (at most one entry per task, tens of tasks); the
// clockevent programming and the expiry interrupt are the binary's.
#![forbid(unsafe_code)]
//! The timer queue: absolute monotonic expiries with an owner key.
//!
//! # Contract
//! * Pure and allocation-free after [`TimerQueue::new`]: every insert is
//!   fallible against the reserved capacity, never grows, so it is callable
//!   from any context the caller's lock allows (a hardirq included).
//! * An owner has at most one entry; [`TimerQueue::insert`] re-arms it
//!   (`hrtimer_start` on an active timer).
//! * Entries with equal expiry fire in insertion order, so the wake order of
//!   simultaneous sleepers is deterministic.
//! * The queue never calls out. The binary drains due entries
//!   ([`TimerQueue::pop_due`]), releases its lock and only then acts on them,
//!   which is what keeps the lock order acyclic (`ktask`: no
//!   `TIMERQ -> RQ` edge).

use alloc::{collections::TryReserveError, vec::Vec};

/// The queue has no free entry. Cannot happen while the capacity is at least the
/// number of distinct owners.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Full;

/// Expiries in ascending order; `K` identifies the owner and what to do on
/// expiry (the binary's enum: a task wake-up today, the real interval timer
/// of the task model later).
#[derive(Debug)]
pub struct TimerQueue<K> {
    entries: Vec<(u64, K)>,
}

impl<K: Copy + PartialEq> TimerQueue<K> {
    /// A queue that can hold `capacity` entries.
    ///
    /// # Errors
    /// The allocation failed.
    pub fn new(capacity: usize) -> Result<Self, TryReserveError> {
        let mut entries = Vec::new();
        entries.try_reserve_exact(capacity)?;
        Ok(Self { entries })
    }

    /// Arm `owner` to expire at `expiry_ns`, replacing its previous entry.
    ///
    /// # Errors
    /// [`Full`] when every entry belongs to another owner.
    pub fn insert(&mut self, expiry_ns: u64, owner: K) -> Result<(), Full> {
        self.cancel(owner);
        // After the last entry that is not later, i.e. FIFO among equal expiries.
        let at = self.entries.partition_point(|&(when, _)| when <= expiry_ns);
        self.entries
            .push_within_capacity((expiry_ns, owner))
            .map_err(|_| Full)?;
        self.entries[at..].rotate_right(1);
        Ok(())
    }

    /// Disarm `owner`; whether it was armed (`hrtimer_cancel`).
    pub fn cancel(&mut self, owner: K) -> bool {
        match self.entries.iter().position(|&(_, key)| key == owner) {
            Some(at) => {
                self.entries.remove(at);
                true
            }
            None => false,
        }
    }

    /// The earliest expiry: what the clockevent is programmed for.
    #[must_use]
    pub fn next_expiry(&self) -> Option<u64> {
        self.entries.first().map(|&(when, _)| when)
    }

    /// Remove and return the earliest entry if it expired at or before `now_ns`.
    pub fn pop_due(&mut self, now_ns: u64) -> Option<K> {
        match self.entries.first() {
            Some(&(when, key)) if when <= now_ns => {
                self.entries.remove(0);
                Some(key)
            }
            _ => None,
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn queue(capacity: usize) -> TimerQueue<u32> {
        TimerQueue::new(capacity).unwrap()
    }

    #[test]
    fn expires_in_order_and_equal_expiries_fifo() {
        let mut q = queue(8);
        q.insert(30, 3).unwrap();
        q.insert(10, 1).unwrap();
        q.insert(20, 2).unwrap();
        q.insert(20, 4).unwrap();
        assert_eq!(q.next_expiry(), Some(10));
        assert_eq!(q.pop_due(5), None);
        assert_eq!(q.pop_due(25), Some(1));
        assert_eq!(q.pop_due(25), Some(2));
        assert_eq!(q.pop_due(25), Some(4));
        assert_eq!(q.pop_due(25), None);
        assert_eq!(q.pop_due(30), Some(3));
        assert!(q.is_empty());
    }

    #[test]
    fn insert_rearms_and_cancel_disarms() {
        let mut q = queue(2);
        q.insert(50, 1).unwrap();
        q.insert(60, 2).unwrap();
        // Re-arming an owner needs no free entry.
        q.insert(40, 2).unwrap();
        assert_eq!(q.len(), 2);
        assert_eq!(q.next_expiry(), Some(40));
        assert!(q.cancel(2));
        assert!(!q.cancel(2));
        assert_eq!(q.next_expiry(), Some(50));
    }

    #[test]
    fn full_queue_refuses_a_new_owner_without_growing() {
        let mut q = queue(1);
        q.insert(1, 1).unwrap();
        assert_eq!(q.insert(2, 2), Err(Full));
        assert_eq!(q.len(), 1);
        assert_eq!(q.next_expiry(), Some(1));
    }

    #[test]
    fn a_zero_capacity_queue_is_full() {
        let mut q = queue(0);
        assert_eq!(q.insert(1, 1), Err(Full));
        assert_eq!(q.next_expiry(), None);
    }
}
