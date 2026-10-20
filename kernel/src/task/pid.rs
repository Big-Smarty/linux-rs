// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: kernel/pid.c (`alloc_pid` 163-263,
// `free_pid`, `find_pid_ns`, `attach_pid`/`__change_pid` 328-365,
// `pid_task`), lib/idr.c (`idr_alloc_cyclic` 119-137), include/linux/pid.h
// (`enum pid_type`, `pid_has_task`), include/linux/threads.h (`PID_MAX_DEFAULT`,
// `RESERVED_PIDS`), init/init_task.c and kernel/pid.c (`init_struct_pid`).
// All GPL-2.0-only.
// Transformation: one PID namespace (the initial one), so a `struct pid` has
// one number; the radix-tree IDR is a vector indexed by number with a linear
// free-slot search; the four `hlist` heads are vectors (iterated newest first,
// as `hlist_add_head_rcu` leaves them); reference counts do not exist because
// a pid lives exactly while a task is attached to it.
#![forbid(unsafe_code)]
//! `struct pid`, the pid number allocator and `pid_task`.

use super::tasklist::TaskId;
use crate::arena::Id;
use alloc::vec::Vec;
use syscalls::Errno;

/// `enum pid_type`: the links of a task into a `struct pid`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PidType {
    Pid = 0,
    Tgid = 1,
    Pgid = 2,
    Sid = 3,
}

/// `PIDTYPE_MAX`.
pub const PIDTYPE_MAX: usize = 4;

/// `RESERVED_PIDS`: numbers below this are skipped once the allocator has
/// wrapped.
pub const RESERVED_PIDS: u32 = 300;
/// `PID_MAX_DEFAULT` (`CONFIG_BASE_SMALL=n`): also the `pid_max` of one CPU
/// (`PIDS_PER_CPU_DEFAULT * num_possible_cpus() = 1024` is below it).
pub const PID_MAX_DEFAULT: u32 = 0x8000;

/// A handle to a [`Pid`].
pub type PidId = Id<Pid>;

/// `struct pid`: the number and the tasks attached to it per [`PidType`].
#[derive(Debug)]
pub struct Pid {
    /// The number in the initial namespace; `0` only for `init_struct_pid`.
    pub nr: i32,
    /// Oldest first; `do_each_pid_task` visits them newest first
    /// ([`Pid::tasks`]).
    tasks: [Vec<TaskId>; PIDTYPE_MAX],
}

impl Pid {
    #[must_use]
    pub const fn new(nr: i32) -> Self {
        Self {
            nr,
            tasks: [Vec::new(), Vec::new(), Vec::new(), Vec::new()],
        }
    }

    /// `pid_has_task`.
    #[must_use]
    pub fn has_task(&self, ty: PidType) -> bool {
        !self.tasks[ty as usize].is_empty()
    }

    /// No task is attached for any type: the pid number may be freed.
    #[must_use]
    pub fn unused(&self) -> bool {
        self.tasks.iter().all(Vec::is_empty)
    }

    /// `do_each_pid_task`: the attached tasks, most recently attached first.
    pub fn tasks(&self, ty: PidType) -> impl Iterator<Item = TaskId> + '_ {
        self.tasks[ty as usize].iter().rev().copied()
    }

    /// `pid_task`: the first task of the list.
    #[must_use]
    pub fn first(&self, ty: PidType) -> Option<TaskId> {
        self.tasks[ty as usize].last().copied()
    }

    /// Make room for one more [`Pid::attach`], so that the attach cannot fail.
    ///
    /// # Errors
    /// `ENOMEM`.
    pub fn reserve(&mut self, ty: PidType) -> Result<(), Errno> {
        self.tasks[ty as usize]
            .try_reserve(1)
            .map_err(|_| Errno::ENOMEM)
    }

    /// `attach_pid` (`hlist_add_head_rcu`). Capacity was [`Pid::reserve`]d.
    ///
    /// # Panics
    /// When no room was reserved (a kernel bug).
    pub fn attach(&mut self, ty: PidType, task: TaskId) {
        assert!(
            self.tasks[ty as usize].push_within_capacity(task).is_ok(),
            "pid attach without reserve"
        );
    }

    /// `hlist_del_rcu` of the task's link.
    pub fn detach(&mut self, ty: PidType, task: TaskId) {
        let list = &mut self.tasks[ty as usize];
        if let Some(at) = list.iter().position(|&t| t == task) {
            list.remove(at);
        }
    }
}

/// The IDR of the initial PID namespace: number to `struct pid`.
pub struct PidTable {
    entries: Vec<Option<PidId>>,
    /// `idr->idr_next`, the cyclic allocation cursor.
    next: u32,
    /// `pid_max`.
    max: u32,
    /// Numbers handed out and not yet freed (`ns->pid_allocated`).
    allocated: usize,
}

impl PidTable {
    #[must_use]
    pub const fn new(pid_max: u32) -> Self {
        Self {
            entries: Vec::new(),
            next: 0,
            max: pid_max,
            allocated: 0,
        }
    }

    /// `find_pid_ns`: `nr` is the user's `pid_t`; negative and zero numbers
    /// name nothing (`init_struct_pid` is not in the IDR).
    #[must_use]
    pub fn find(&self, nr: i32) -> Option<PidId> {
        let nr = usize::try_from(nr).ok()?;
        self.entries.get(nr).copied().flatten()
    }

    fn free_at_or_after(&self, from: u32, max: u32) -> Option<u32> {
        let mut nr = from;
        while nr <= max {
            if self.entries.get(nr as usize).copied().flatten().is_none() {
                return Some(nr);
            }
            nr += 1;
        }
        None
    }

    /// `idr_alloc_cyclic(idr, ptr, start, end)`: the lowest free number from
    /// the cursor up to `end - 1`, wrapping to `start` once.
    fn alloc_cyclic(&mut self, start: u32, end: u32) -> Option<u32> {
        let max = end - 1;
        let mut id = self.next;
        if id < start {
            id = start;
        }
        let found = match self.free_at_or_after(id, max) {
            Some(found) => Some(found),
            None if id > start => self.free_at_or_after(start, max),
            None => None,
        }?;
        self.next = found + 1;
        Some(found)
    }

    /// `alloc_pid`'s number allocation: reserve a number for `pid` and make it
    /// visible to [`PidTable::find`]. `EAGAIN` when the namespace is full
    /// (`-ENOSPC`), `ENOMEM` when the table cannot grow; a failure of the very
    /// first allocation resets the cursor (`idr_set_cursor(0)`).
    ///
    /// # Errors
    /// `EAGAIN`, `ENOMEM`.
    pub fn alloc(&mut self, pid: PidId) -> Result<i32, Errno> {
        // "init really needs pid 1, but after reaching the maximum wrap back
        // to RESERVED_PIDS".
        let start = if self.next > RESERVED_PIDS {
            RESERVED_PIDS
        } else {
            1
        };
        let Some(nr) = self.alloc_cyclic(start, self.max) else {
            if self.allocated == 0 {
                self.next = 0;
            }
            return Err(Errno::EAGAIN);
        };
        let want = nr as usize + 1;
        if self.entries.len() < want {
            if self.entries.try_reserve(want - self.entries.len()).is_err() {
                // The number was only found, not taken; undo the cursor move.
                self.next = nr;
                return Err(Errno::ENOMEM);
            }
            while self.entries.len() < want {
                if self.entries.push_within_capacity(None).is_err() {
                    self.next = nr;
                    return Err(Errno::ENOMEM);
                }
            }
        }
        self.entries[nr as usize] = Some(pid);
        self.allocated += 1;
        i32::try_from(nr).map_err(|_| Errno::EAGAIN)
    }

    /// `free_pid`: the number may be allocated again (after the cursor wraps).
    pub fn free(&mut self, nr: i32) {
        if let Ok(nr) = usize::try_from(nr)
            && let Some(entry) = self.entries.get_mut(nr)
            && entry.take().is_some()
        {
            self.allocated -= 1;
        }
    }

    /// `ns->pid_allocated` without the `PIDNS_ADDING` bit.
    #[must_use]
    pub const fn allocated(&self) -> usize {
        self.allocated
    }

    /// `idr_get_cursor`.
    #[must_use]
    pub const fn cursor(&self) -> u32 {
        self.next
    }

    /// Heap bytes the number table holds. It is indexed by pid number, so it
    /// grows with the highest number handed out until the cursor wraps; a leak
    /// check subtracts it from the heap total.
    #[must_use]
    pub fn footprint_bytes(&self) -> usize {
        self.entries.capacity() * core::mem::size_of::<Option<PidId>>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arena::Arena;

    fn ids(count: usize) -> alloc::vec::Vec<PidId> {
        let mut arena: Arena<Pid> = Arena::new();
        // The ids only need to be distinct handles for the table.
        (0..count)
            .map(|_| arena.try_insert(Pid::new(0)).unwrap())
            .collect()
    }

    #[test]
    fn first_allocation_is_one_and_the_cursor_only_moves_forward() {
        let mut table = PidTable::new(PID_MAX_DEFAULT);
        let p = ids(4);
        assert_eq!(table.alloc(p[0]), Ok(1));
        assert_eq!(table.alloc(p[1]), Ok(2));
        assert_eq!(table.alloc(p[2]), Ok(3));
        // Freed numbers are not reused until the cursor wraps.
        table.free(2);
        assert_eq!(table.find(2), None);
        assert_eq!(table.alloc(p[3]), Ok(4));
        assert_eq!(table.cursor(), 5);
    }

    #[test]
    fn find_rejects_zero_negative_and_out_of_range_numbers() {
        let mut table = PidTable::new(PID_MAX_DEFAULT);
        let p = ids(1);
        table.alloc(p[0]).unwrap();
        for nr in [0, -1, i32::MIN, 2, 99_999, i32::MAX] {
            assert_eq!(table.find(nr), None, "{nr}");
        }
        assert_eq!(table.find(1), Some(p[0]));
    }

    #[test]
    fn wrap_goes_back_to_reserved_pids_and_skips_used_numbers() {
        // pid_max 303: the cursor passes RESERVED_PIDS (300), so the wrap
        // restarts at 300 instead of 1 (alloc_pid's pid_min).
        let mut table = PidTable::new(303);
        let p = ids(1);
        for nr in 1..=302 {
            assert_eq!(table.alloc(p[0]), Ok(nr));
        }
        assert_eq!(table.cursor(), 303);
        // 1..=302 are in use; 300..=302 are the only candidates after the wrap.
        assert_eq!(table.alloc(p[0]), Err(Errno::EAGAIN), "namespace full");
        table.free(1);
        table.free(301);
        // The cursor is past the end: wrap to 300, skip the used 300, take 301
        // (1 is free but below the reserved range).
        assert_eq!(table.alloc(p[0]), Ok(301));
        assert_eq!(table.alloc(p[0]), Err(Errno::EAGAIN));
    }

    #[test]
    fn failing_the_first_allocation_resets_the_cursor() {
        // pid_max 1: no number below it exists (the range is [1, 1)).
        let mut table = PidTable::new(1);
        table.next = 77;
        let p = ids(1);
        assert_eq!(table.alloc(p[0]), Err(Errno::EAGAIN));
        assert_eq!(table.cursor(), 0);
    }
}
