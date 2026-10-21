// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: kernel/futex/core.c
// (`get_futex_key` 510-760, `futex_match`, `__futex_queue`, `futex_unqueue`,
// `handle_futex_death` and `exit_robust_list` 1126-1260), kernel/futex/waitwake.c
// (`futex_wake` 156-197, `futex_atomic_op_inuser` 199-241, `futex_wake_op` 248-345,
// `futex_wait_setup`, `__futex_wait`, `futex_wait_multiple`), kernel/futex/requeue.c
// (`requeue_futex`, `futex_requeue` 390-720 without the priority-inheritance branches),
// kernel/futex/futex.h (`FLAGS_*`, `futex_to_flags`, `futex2_to_flags`),
// include/uapi/linux/futex.h. All GPL-2.0-or-later (kernel/futex) or GPL-2.0-only.
// Transformation: the hash buckets, their spinlocks, `plist` priorities and the per-process
// private hash are one FIFO vector under the caller's exclusion (the `PROCESS` lock); a
// waiter's `futex_q` is a [`Waiter`] entry, "woken" is the entry having left the vector and its
// owner's `woken` mark being set; the wake-up of the sleeping task is the caller's closure
// (`wake_up_q`). Priority inheritance (`pi_state`, `rt_mutex`) is not modelled (see
// `syscall::futex`); `FUTEX_FD` was removed from Linux.
#![forbid(unsafe_code)]
//! The futex queues: keys, waiters, `wake`, `requeue`, the `FUTEX_WAKE_OP` arithmetic and the
//! robust-list constants. The syscalls and the user-memory parts are `syscall::futex`.
//!
//! # Contract
//! * Context: task context with the caller's lock held; the type has no lock. The binary keeps
//!   it inside `PROCESS`, so the "hash bucket lock" is that lock and a waiter's sequence
//!   *queue, then read the user word* is not interleaved with another task's *write, then
//!   wake* (no task runs in between: ring 0 is not preempted, and the lock is dropped only
//!   in `Task::wait`).
//! * Allocation: a task waits on at most one futex at a time (`futex_wait`), or on up to
//!   [`WAITV_MAX`] (`futex_waitv`, which reserves its entries first and may fail with `ENOMEM`
//!   as `kcalloc` does). The vector is sized for one entry per scheduler slot when it is made, so
//!   a plain wait cannot fail to queue.
//! * Fairness: wake-ups go in queue order within a key (`plist` FIFO within one priority); a
//!   requeued waiter goes to the end (`plist_add` after `plist_del`).

use alloc::vec::Vec;
use syscalls::Errno;

pub const FUTEX_WAIT: u32 = 0;
pub const FUTEX_WAKE: u32 = 1;
pub const FUTEX_FD: u32 = 2;
pub const FUTEX_REQUEUE: u32 = 3;
pub const FUTEX_CMP_REQUEUE: u32 = 4;
pub const FUTEX_WAKE_OP: u32 = 5;
pub const FUTEX_LOCK_PI: u32 = 6;
pub const FUTEX_UNLOCK_PI: u32 = 7;
pub const FUTEX_TRYLOCK_PI: u32 = 8;
pub const FUTEX_WAIT_BITSET: u32 = 9;
pub const FUTEX_WAKE_BITSET: u32 = 10;
pub const FUTEX_WAIT_REQUEUE_PI: u32 = 11;
pub const FUTEX_CMP_REQUEUE_PI: u32 = 12;
pub const FUTEX_LOCK_PI2: u32 = 13;

pub const FUTEX_PRIVATE_FLAG: u32 = 128;
pub const FUTEX_CLOCK_REALTIME: u32 = 256;
/// `FUTEX_CMD_MASK`.
pub const FUTEX_CMD_MASK: u32 = !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);

/// `FUTEX_BITSET_MATCH_ANY`.
pub const BITSET_MATCH_ANY: u32 = 0xffff_ffff;
/// `FUTEX_WAITERS`, `FUTEX_OWNER_DIED`, `FUTEX_TID_MASK`.
pub const FUTEX_WAITERS: u32 = 0x8000_0000;
pub const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
pub const FUTEX_TID_MASK: u32 = 0x3fff_ffff;
/// `FUTEX_WAITV_MAX`.
pub const WAITV_MAX: usize = 128;
/// `ROBUST_LIST_LIMIT`.
pub const ROBUST_LIST_LIMIT: u32 = 2048;
/// `sizeof(struct robust_list_head)`.
pub const ROBUST_LIST_HEAD_SIZE: u64 = 24;

/// `FLAGS_SHARED`, `FLAGS_CLOCKRT` and `FLAGS_HAS_TIMEOUT` of `kernel/futex/futex.h`, with the
/// size field (`FLAGS_SIZE_32` is 2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flags(pub u32);

impl Flags {
    pub const SIZE_32: u32 = 0x0002;
    pub const SIZE_MASK: u32 = 0x0003;
    pub const SHARED: u32 = 0x0010;
    pub const CLOCKRT: u32 = 0x0020;
    pub const HAS_TIMEOUT: u32 = 0x0040;
    pub const STRICT: u32 = 0x0100;

    /// `futex_to_flags(op)`.
    #[must_use]
    pub const fn from_op(op: u32) -> Self {
        let mut flags = Self::SIZE_32;
        if op & FUTEX_PRIVATE_FLAG == 0 {
            flags |= Self::SHARED;
        }
        if op & FUTEX_CLOCK_REALTIME != 0 {
            flags |= Self::CLOCKRT;
        }
        Self(flags)
    }

    #[must_use]
    pub const fn shared(self) -> bool {
        self.0 & Self::SHARED != 0
    }

    #[must_use]
    pub const fn clock_realtime(self) -> bool {
        self.0 & Self::CLOCKRT != 0
    }

    #[must_use]
    pub const fn with(self, bits: u32) -> Self {
        Self(self.0 | bits)
    }
}

/// `union futex_key`: what two futex addresses must share to be the same futex.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    /// A process-private futex (`FUTEX_PRIVATE_FLAG`): the address space and the address.
    Private { mm: u64, page: u64, offset: u32 },
    /// A non-private futex on an anonymous page: the address space and the address, in a key
    /// that never equals a private one (`FUT_OFF_MMSHARED` is part of `offset` in Linux).
    MmShared { mm: u64, page: u64, offset: u32 },
    /// A non-private futex on a page of a mapped file: the file and the page index
    /// (`FUT_OFF_INODE`). shortcut: the identity is the open file description's, not the
    /// inode's, so two descriptions of one file do not match; upgrade with an inode id from the
    /// VFS.
    File { file: u64, index: u64, offset: u32 },
}

/// A queued waiter (`struct futex_q`).
#[derive(Clone, Copy, Debug)]
struct Waiter {
    ticket: u64,
    key: Key,
    bitset: u32,
    /// The sleeping task: its scheduler slot.
    owner: u32,
    /// For `futex_waitv`: the index in the caller's vector (the value `futex_waitv` returns).
    index: u32,
}

/// How the binary wakes the sleeping task of a waiter a waker took out of the queue
/// (`wake_up_q` -> `wake_up_process`): the key `CLASS_FUTEX` / `owner` on the scheduler.
pub trait FutexWaker {
    fn wake(&mut self, owner: u32);
}

/// A handle on a queued waiter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ticket(u64);

/// The futex hash: every waiting task of every address space, in queue order.
pub struct Futexes {
    queue: Vec<Waiter>,
    /// Per task slot: `Some(index)` once a waker took one of its waiters out of the queue.
    woken: Vec<Option<u32>>,
    next_ticket: u64,
}

impl Futexes {
    /// Queues for `slots` scheduler slots.
    ///
    /// # Errors
    /// `ENOMEM`.
    pub fn new(slots: usize) -> Result<Self, Errno> {
        let mut queue = Vec::new();
        queue.try_reserve_exact(slots).map_err(|_| Errno::ENOMEM)?;
        let mut woken = Vec::new();
        woken.try_reserve_exact(slots).map_err(|_| Errno::ENOMEM)?;
        for _ in 0..slots {
            let _ = woken.push_within_capacity(None);
        }
        Ok(Self {
            queue,
            woken,
            next_ticket: 1,
        })
    }

    /// Room for `count` more waiters of one `futex_waitv` call.
    ///
    /// # Errors
    /// `ENOMEM`.
    pub fn reserve(&mut self, count: usize) -> Result<(), Errno> {
        self.queue.try_reserve(count).map_err(|_| Errno::ENOMEM)
    }

    /// `futex_queue`: `owner` waits on `key` for a wake-up matching `bitset`. `index` is the
    /// entry's place in a `futex_waitv` vector (0 otherwise).
    ///
    /// # Panics
    /// When no room was reserved: a plain wait is one entry per slot, [`Futexes::reserve`]
    /// covers the vector of a `futex_waitv`.
    pub fn queue(&mut self, key: Key, bitset: u32, owner: u32, index: u32) -> Ticket {
        let ticket = self.next_ticket;
        self.next_ticket += 1;
        assert!(
            self.queue
                .push_within_capacity(Waiter {
                    ticket,
                    key,
                    bitset,
                    owner,
                    index,
                })
                .is_ok(),
            "futex queue without room"
        );
        Ticket(ticket)
    }

    /// `futex_unqueue`: take the waiter out if it is still there. `false`: a waker took it.
    pub fn unqueue(&mut self, ticket: Ticket) -> bool {
        match self.queue.iter().position(|w| w.ticket == ticket.0) {
            Some(at) => {
                self.queue.remove(at);
                true
            }
            None => false,
        }
    }

    /// `futex_unqueue_multiple`: take every waiter of `owner` out; the index of the last one
    /// that had been woken, if any.
    pub fn unqueue_owner(&mut self, owner: u32) -> Option<u32> {
        self.queue.retain(|w| w.owner != owner);
        self.take_woken(owner)
    }

    /// Whether a waker has taken one of `owner`'s waiters (and which: the `futex_waitv` index);
    /// the mark is consumed.
    pub fn take_woken(&mut self, owner: u32) -> Option<u32> {
        self.woken.get_mut(owner as usize)?.take()
    }

    /// Whether a waker has taken one of `owner`'s waiters, without consuming the mark.
    #[must_use]
    pub fn is_woken(&self, owner: u32) -> bool {
        self.woken.get(owner as usize).is_some_and(Option::is_some)
    }

    /// The waiters on `key`, for tests and `/proc`-style counts.
    #[must_use]
    pub fn waiting_on(&self, key: &Key) -> usize {
        self.queue.iter().filter(|w| w.key == *key).count()
    }

    /// Waiters in the whole system.
    #[must_use]
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// `__futex_wake_mark` + `wake_up_q`: the waiter at `at` leaves the queue, its owner is
    /// marked and told.
    fn wake_at(&mut self, at: usize, wake: &mut dyn FnMut(u32)) {
        let w = self.queue.remove(at);
        if let Some(mark) = self.woken.get_mut(w.owner as usize) {
            *mark = Some(w.index);
        }
        wake(w.owner);
    }

    /// `futex_wake(uaddr, flags, nr_wake, bitset)` after the key is known: wake up to `nr_wake`
    /// waiters on `key` whose bitset intersects `bitset`, oldest first. Like Linux it wakes one
    /// even for `nr_wake <= 0` when there is a waiter (`++ret >= nr_wake` after the wake). The
    /// number woken.
    pub fn wake(&mut self, key: &Key, nr_wake: i32, bitset: u32, wake: &mut dyn FnMut(u32)) -> i32 {
        let mut woken = 0;
        let mut at = 0;
        while at < self.queue.len() {
            let w = self.queue[at];
            if w.key != *key || w.bitset & bitset == 0 {
                at += 1;
                continue;
            }
            self.wake_at(at, wake);
            woken += 1;
            if woken >= nr_wake {
                break;
            }
        }
        woken
    }

    /// The wake loops of `futex_wake_op` after the atomic operation: up to `nr_wake` waiters of
    /// `key1`, then, if `second`, up to `nr_wake2` of `key2`. The number woken.
    pub fn wake_op(
        &mut self,
        key1: &Key,
        nr_wake: i32,
        key2: &Key,
        nr_wake2: i32,
        second: bool,
        wake: &mut dyn FnMut(u32),
    ) -> i32 {
        let mut woken = self.wake_all(key1, nr_wake, wake);
        if second {
            woken += self.wake_all(key2, nr_wake2, wake);
        }
        woken
    }

    /// `plist_for_each_entry_safe` over one key waking everything (`this->wake`): the
    /// `++ret >= nr` rule, any bitset.
    fn wake_all(&mut self, key: &Key, nr: i32, wake: &mut dyn FnMut(u32)) -> i32 {
        self.wake(key, nr, BITSET_MATCH_ANY, wake)
    }

    /// `futex_requeue` for plain futexes after the keys and the value check: the first
    /// `nr_wake` waiters of `key1` are woken, the next `nr_requeue` move to `key2` (to the end
    /// of the queue, behind the waiters already there). The number woken plus requeued
    /// (`task_count`).
    ///
    /// # Panics
    /// Never in practice: the `push_within_capacity` that follows a `remove` has room.
    pub fn requeue(
        &mut self,
        key1: &Key,
        key2: &Key,
        nr_wake: i32,
        nr_requeue: i32,
        wake: &mut dyn FnMut(u32),
    ) -> i32 {
        let mut task_count: i32 = 0;
        let mut at = 0;
        let end = self.queue.len();
        for _ in 0..end {
            if task_count - nr_wake >= nr_requeue {
                break;
            }
            if self.queue[at].key != *key1 {
                at += 1;
                continue;
            }
            task_count += 1;
            if task_count <= nr_wake {
                self.wake_at(at, wake);
            } else if key1 == key2 {
                // `requeue_futex` within one chain only rewrites the key (the same one).
                at += 1;
            } else {
                // requeue_futex: out of the old chain, onto the end of the new one. The moved
                // entries are behind every original entry, so the count of `end` visits
                // never meets one twice.
                let mut w = self.queue.remove(at);
                w.key = *key2;
                assert!(self.queue.push_within_capacity(w).is_ok(), "just removed");
            }
        }
        task_count
    }
}

/// `futex_atomic_op_inuser` without the memory access: the new value of the word and the result
/// of the comparison for `encoded_op`, given the word's old value `old`. `Err(ENOSYS)` for an
/// operation that does not exist (before the memory is touched) or, as in Linux, a comparison
/// that does not exist (after the operation was done: the caller has already stored the new
/// value).
pub struct WakeOp {
    op: u32,
    oparg: i32,
    cmp: u32,
    cmparg: i32,
}

impl WakeOp {
    /// Decode `encoded_op` (`FUTEX_OP(op, oparg, cmp, cmparg)`).
    #[must_use]
    pub fn decode(encoded: u32) -> Self {
        let sign_extend = |value: u32| -> i32 {
            // sign_extend32(value, 11)
            #[allow(clippy::cast_possible_wrap)]
            {
                ((value << 20) as i32) >> 20
            }
        };
        let op = (encoded & 0x7000_0000) >> 28;
        let cmp = (encoded & 0x0f00_0000) >> 24;
        let mut oparg = sign_extend((encoded & 0x00ff_f000) >> 12);
        let cmparg = sign_extend(encoded & 0x0000_0fff);
        if encoded & (8 << 28) != 0 {
            // "kill this print and return -EINVAL when userspace is sane again": the shift is
            // masked to 31 bits for a wild amount.
            #[allow(clippy::cast_sign_loss)]
            let shift = (oparg as u32) & 31;
            oparg = 1i32.wrapping_shl(shift);
        }
        Self {
            op,
            oparg,
            cmp,
            cmparg,
        }
    }

    /// The new value of the word for old value `old`; `ENOSYS` for an operation that does not
    /// exist (nothing is stored then).
    ///
    /// # Errors
    /// `ENOSYS`.
    pub fn apply(&self, old: u32) -> Result<u32, Errno> {
        #[allow(clippy::cast_sign_loss)]
        let arg = self.oparg as u32;
        Ok(match self.op {
            0 => arg,
            1 => old.wrapping_add(arg),
            2 => old | arg,
            3 => old & !arg,
            4 => old ^ arg,
            _ => return Err(Errno::ENOSYS),
        })
    }

    /// The comparison of `futex_atomic_op_inuser` on the old value.
    ///
    /// # Errors
    /// `ENOSYS` for a comparison that does not exist.
    pub fn compare(&self, old: u32) -> Result<bool, Errno> {
        #[allow(clippy::cast_possible_wrap)]
        let old = old as i32;
        Ok(match self.cmp {
            0 => old == self.cmparg,
            1 => old != self.cmparg,
            2 => old < self.cmparg,
            3 => old <= self.cmparg,
            4 => old > self.cmparg,
            5 => old >= self.cmparg,
            _ => return Err(Errno::ENOSYS),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn key(n: u64) -> Key {
        Key::Private {
            mm: 1,
            page: n << 12,
            offset: 0,
        }
    }

    fn queue_of(owners: &[(u64, u32, u32)]) -> Futexes {
        let mut f = Futexes::new(16).unwrap();
        for &(k, owner, bitset) in owners {
            f.queue(key(k), bitset, owner, 0);
        }
        f
    }

    fn woken(f: &mut Futexes, k: u64, nr: i32, bitset: u32) -> (i32, Vec<u32>) {
        let mut who = vec![];
        let n = f.wake(&key(k), nr, bitset, &mut |o| who.push(o));
        (n, who)
    }

    #[test]
    fn wake_goes_in_queue_order_per_key_and_counts() {
        let mut f = queue_of(&[(1, 0, !0), (2, 1, !0), (1, 2, !0), (1, 3, !0)]);
        assert_eq!(woken(&mut f, 1, 2, !0), (2, vec![0, 2]));
        assert_eq!(f.waiting_on(&key(1)), 1);
        assert_eq!(woken(&mut f, 1, 10, !0), (1, vec![3]));
        assert_eq!(woken(&mut f, 1, 10, !0), (0, vec![]));
        assert!(f.take_woken(0).is_some() && f.take_woken(0).is_none());
        assert!(f.is_woken(2) && !f.is_woken(1));
    }

    #[test]
    fn a_count_of_zero_or_less_still_wakes_one_waiter() {
        // `++ret >= nr_wake` follows the wake.
        for nr in [0, -1, i32::MIN] {
            let mut f = queue_of(&[(1, 0, !0), (1, 1, !0)]);
            assert_eq!(woken(&mut f, 1, nr, !0), (1, vec![0]), "{nr}");
        }
    }

    #[test]
    fn bitsets_select_waiters() {
        let mut f = queue_of(&[(1, 0, 1), (1, 1, 2), (1, 2, 6)]);
        assert_eq!(woken(&mut f, 1, 10, 8), (0, vec![]));
        assert_eq!(woken(&mut f, 1, 10, 2), (2, vec![1, 2]));
        assert_eq!(woken(&mut f, 1, 10, !0), (1, vec![0]));
    }

    #[test]
    fn keys_of_different_kinds_never_match() {
        let mut f = Futexes::new(4).unwrap();
        let private = Key::Private {
            mm: 1,
            page: 0,
            offset: 8,
        };
        let shared = Key::MmShared {
            mm: 1,
            page: 0,
            offset: 8,
        };
        f.queue(shared, !0, 0, 0);
        assert_eq!(f.wake(&private, 1, !0, &mut |_| {}), 0);
        assert_eq!(f.wake(&shared, 1, !0, &mut |_| {}), 1);
    }

    #[test]
    fn requeue_wakes_then_moves_to_the_end_of_the_target_queue() {
        let mut f = queue_of(&[(2, 9, !0), (1, 0, !0), (1, 1, !0), (1, 2, !0), (1, 3, !0)]);
        let mut who = vec![];
        let n = f.requeue(&key(1), &key(2), 1, 2, &mut |o| who.push(o));
        assert_eq!((n, who), (3, vec![0]));
        // Owner 3 stayed; owners 1 and 2 are behind owner 9 on key 2.
        assert_eq!(f.waiting_on(&key(1)), 1);
        assert_eq!(woken(&mut f, 2, 10, !0), (3, vec![9, 1, 2]));
        // Nothing to move: only what is on the key counts.
        let mut f = queue_of(&[(3, 0, !0)]);
        assert_eq!(f.requeue(&key(1), &key(2), 5, 5, &mut |_| {}), 0);
    }

    #[test]
    fn wake_op_decodes_and_computes_like_the_kernel() {
        let enc = |op: u32, oparg: u32, cmp: u32, cmparg: u32| {
            (op & 0xf) << 28 | (cmp & 0xf) << 24 | (oparg & 0xfff) << 12 | (cmparg & 0xfff)
        };
        let w = WakeOp::decode(enc(1, 1, 0, 5));
        assert_eq!((w.apply(5), w.compare(5)), (Ok(6), Ok(true)));
        assert_eq!(w.compare(6), Ok(false));
        // oparg is 12 bits signed, with the shift flag it is a bit number masked to 5 bits.
        assert_eq!(WakeOp::decode(enc(0, 0xfff, 1, 0)).apply(0), Ok(u32::MAX));
        assert_eq!(WakeOp::decode(enc(8, 4, 0, 0)).apply(7), Ok(16));
        assert_eq!(WakeOp::decode(enc(8, 36, 0, 0)).apply(0), Ok(16), "36 & 31");
        assert_eq!(WakeOp::decode(enc(3, 1, 0, 0)).apply(11), Ok(10));
        assert_eq!(WakeOp::decode(enc(4, 3, 0, 0)).apply(10), Ok(9));
        assert_eq!(WakeOp::decode(enc(2, 2, 0, 0)).apply(9), Ok(11));
        // Operations 5, 6, 7 and comparisons 6.. do not exist.
        assert_eq!(WakeOp::decode(enc(5, 1, 0, 0)).apply(0), Err(Errno::ENOSYS));
        assert_eq!(
            WakeOp::decode(enc(0, 1, 6, 0)).compare(0),
            Err(Errno::ENOSYS)
        );
        // Signed comparisons: -1 < 0.
        assert_eq!(WakeOp::decode(enc(0, 0, 2, 0)).compare(u32::MAX), Ok(true));
        assert_eq!(WakeOp::decode(enc(0, 0, 4, 0xfff)).compare(0), Ok(true));
    }
}
