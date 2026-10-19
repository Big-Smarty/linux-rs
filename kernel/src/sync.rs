// SPDX-License-Identifier: GPL-2.0-only
//! Native atomic exclusion for short, non-sleeping hardware transactions.
//!
//! This is an early test-and-test-and-set lock, not Linux qspinlock, lockdep,
//! `PREEMPT_RT`, scheduler/preemption control, fairness or an NMI-safe lock. The
//! architecture consumer must exclude same-CPU reentry before acquisition and
//! release the lock before restoring its saved interrupt state. It must not
//! sleep, allocate, fault on user memory, or invoke arbitrary callbacks while
//! holding the guard. Local IRQ masking alone does not exclude other CPUs.

use core::{
    hint::spin_loop,
    marker::PhantomData,
    sync::atomic::{AtomicBool, Ordering},
};

/// One native atomic ownership bit; no allocation or opaque fallback backend.
///
/// Successful acquire observes the previous owner's release. Failed acquire and
/// relaxed polling grant no ownership or payload visibility. The single-width
/// atomic is never mixed with non-atomic access. Progress requires the current
/// owner to run and release; no bounded-wait or fairness guarantee is claimed.
pub struct RawSpinLock {
    held: AtomicBool,
}

impl RawSpinLock {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            held: AtomicBool::new(false),
        }
    }

    /// Wait for exclusive ownership. The caller establishes the context rules
    /// in the module contract; this raw primitive does not mask interrupts.
    pub fn lock(&self) -> RawSpinGuard<'_> {
        loop {
            if let Some(guard) = self.try_lock() {
                return guard;
            }
            // Do not repeatedly issue a locked RMW while another owner holds
            // the cache line. A failed observation never accesses payload.
            while self.held.load(Ordering::Relaxed) {
                spin_loop();
            }
        }
    }

    /// Attempt once without spinning. A failed attempt has no spurious result
    /// and must not be treated as permission to access the protected resource.
    pub fn try_lock(&self) -> Option<RawSpinGuard<'_>> {
        self.held
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| RawSpinGuard {
                lock: self,
                _local: PhantomData,
            })
    }
}

impl Default for RawSpinLock {
    fn default() -> Self {
        Self::new()
    }
}

/// A non-transferable owner. Forgetting it retains the lock, never unlocks it.
/// Architecture wrappers retain their CPU-local saved state alongside it.
///
/// A guard cannot move to a different thread/CPU:
/// ```compile_fail
/// let lock = kernel::sync::RawSpinLock::new();
/// let guard = lock.lock();
/// std::thread::scope(|scope| {
///     scope.spawn(move || drop(guard));
/// });
/// ```
/// Nor may a shared guard reference cross threads:
/// ```compile_fail
/// let lock = kernel::sync::RawSpinLock::new();
/// let guard = lock.lock();
/// std::thread::scope(|scope| {
///     let reference = &guard;
///     scope.spawn(move || { let _ = core::hint::black_box(reference); });
/// });
/// ```
#[must_use = "dropping the guard releases the raw lock"]
pub struct RawSpinGuard<'a> {
    lock: &'a RawSpinLock,
    _local: PhantomData<*mut ()>,
}

impl Drop for RawSpinGuard<'_> {
    fn drop(&mut self) {
        self.lock.held.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::RawSpinLock;
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::thread;

    #[test]
    fn ownership_is_exclusive_and_drop_releases_only_its_lock() {
        let first = RawSpinLock::new();
        let second = RawSpinLock::default();
        let first_owner = first.try_lock().expect("initially unlocked");
        let second_owner = second.lock();
        assert!(first.try_lock().is_none());
        assert!(second.try_lock().is_none());
        drop(first_owner);
        let renewed = first.try_lock().expect("drop released the first lock");
        assert!(second.try_lock().is_none());
        drop(second_owner);
        assert!(second.try_lock().is_some());
        drop(renewed);
    }

    #[test]
    fn failed_contender_observes_payload_after_owner_release() {
        let lock = RawSpinLock::new();
        let payload = AtomicUsize::new(0);
        let failed_attempt = AtomicBool::new(false);
        let owner = lock.lock();
        thread::scope(|scope| {
            scope.spawn(|| {
                assert!(lock.try_lock().is_none());
                failed_attempt.store(true, Ordering::Relaxed);
                let _owner = lock.lock();
                // The flag above is relaxed and precedes the write below;
                // publication of this payload is through the lock, not a
                // release/acquire test rendezvous that could hide a defect.
                assert_eq!(payload.load(Ordering::Relaxed), 0x51a7);
                payload.store(0xc0de, Ordering::Relaxed);
            });
            while !failed_attempt.load(Ordering::Relaxed) {
                thread::yield_now();
            }
            payload.store(0x51a7, Ordering::Relaxed);
            drop(owner);
        });
        let _owner = lock.lock();
        assert_eq!(payload.load(Ordering::Relaxed), 0xc0de);
    }

    #[test]
    fn contending_threads_preserve_single_owner_and_paired_payload() {
        let lock = RawSpinLock::new();
        let active = AtomicUsize::new(0);
        let sequence = AtomicUsize::new(0);
        let complement = AtomicUsize::new(!0);
        thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    for _ in 0..4096 {
                        let _owner = lock.lock();
                        assert_eq!(active.fetch_add(1, Ordering::Relaxed), 0);
                        let value = sequence.load(Ordering::Relaxed);
                        assert_eq!(complement.load(Ordering::Relaxed), !value);
                        sequence.store(value + 1, Ordering::Relaxed);
                        core::hint::spin_loop();
                        complement.store(!(value + 1), Ordering::Relaxed);
                        assert_eq!(active.fetch_sub(1, Ordering::Relaxed), 1);
                    }
                });
            }
        });
        assert_eq!(sequence.load(Ordering::Relaxed), 4 * 4096);
        assert_eq!(complement.load(Ordering::Relaxed), !(4 * 4096));
        assert_eq!(active.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn forgotten_owner_does_not_forge_an_unlock() {
        let lock = RawSpinLock::new();
        core::mem::forget(lock.lock());
        assert!(lock.try_lock().is_none());
    }
}
