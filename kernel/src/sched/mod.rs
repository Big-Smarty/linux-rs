// SPDX-License-Identifier: GPL-2.0-only
// Linux 6.18.57 (commit 2ff600d29ee478d0a8d46ef8a58afb5e038fe692), all
// GPL-2.0: kernel/sched/core.c (`__schedule` 6801, `try_to_wake_up` 4159,
// `wake_up_state` 4444, `wake_up_new_task` 4831, `finish_task_switch` 5168,
// `sched_tick` 5597, `do_task_dead` 6953), kernel/sched/wait.c
// (`__wake_up_common` 93, `prepare_to_wait_event` 290), kernel/signal.c
// (`signal_wake_up_state` 745), kernel/sched/fair.c (`sysctl_sched_base_slice`
// 79), include/linux/sched.h (the `TASK_*` state bits), kernel/Kconfig.preempt
// (`PREEMPT_VOLUNTARY`).
// Transformation: one CPU, one run queue, FIFO instead of EEVDF (shortcut S1 of
// the process-lane plan), and no wait-queue objects: the wait channel is a key
// stored in the sleeper's slot, so a wake-up scans the slots instead of walking
// a list. The per-task state, wait key, queue membership and `need_resched`
// live here, not in the task struct, so waking needs this lock and no other.
#![forbid(unsafe_code)]
//! The scheduler model: run queue, task states, wait keys, wake-ups.
//!
//! Pure and allocation-free after [`Rq::new`]. The binary (`ktask`) owns the
//! stacks, the register switch and the locking; it calls this model with the
//! `RQ` lock held and interrupts masked, and acts on the answers after the lock
//! is released.
//!
//! # The seam for the task-model lane
//! * A task is a [`SchedId`] (generational, so a stale handle never reaches a
//!   reused slot). The task model stores one per task and never the state: it
//!   asks [`Rq::state`] and wakes through [`Rq::try_to_wake_up`],
//!   [`Rq::wake_interruptible`] (`signal_wake_up`) and [`Rq::wake_up_key`].
//! * A wait channel is a [`WaitKey`] = (class, id). Each owner registers one
//!   class constant below and builds keys from its own ids; [`Rq::wake_up_key`]
//!   wakes the sleepers of a key in the order Linux's wait queue yields them:
//!   the non-exclusive ones newest first (`prepare_to_wait_event` adds them at
//!   the head), then the exclusive ones oldest first (added at the tail), the
//!   latter only up to `nr_exclusive`.
//! * Blocking is a loop that re-checks the condition ([`Rq::prepare_to_wait`],
//!   check, `schedule`, [`Rq::finish_wait`]): spurious wake-ups are legal by
//!   construction, so the conditions stay pure functions of the owner's state.
//!
//! # Contract
//! * Context: all methods run with interrupts masked; the caller's lock makes
//!   them atomic against the tick and timer interrupts (single CPU).
//! * Lost wake-ups: the sleeper's state store, its condition check and the
//!   dequeue in [`Rq::schedule`] are one section with interrupts masked, so no
//!   waker can run between them. SMP needs the full barrier pairing (shortcut
//!   S6 of the plan).
//! * Ring 0 is never preempted (`CONFIG_PREEMPT_VOLUNTARY`): [`Rq::tick`] only
//!   sets `need_resched`, which the binary honours at the return to user mode
//!   and in explicit `schedule()` calls.
//! * Fairness: FIFO with a [`SLICE_TICKS`] slice. shortcut: no weights, no
//!   wake-up preemption, no EEVDF; upgrade with the scheduler-class work.

pub mod timerq;

use alloc::{collections::TryReserveError, vec::Vec};

/// Slice length in ticks. Linux's base slice is 0.7 ms (`sysctl_sched_base_slice`,
/// fair.c:79), under one tick at HZ=1000, so every tick with another task
/// runnable rotates the queue.
pub const SLICE_TICKS: u32 = 1;

/// Wait-key class of the scheduler self-test; owners add their own constants
/// here so two owners cannot collide.
pub const CLASS_TEST: u32 = u32::MAX;

/// A task handle: slot index plus the slot's generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchedId {
    index: u32,
    generation: u32,
}

impl SchedId {
    /// The slot index: stable while the task lives, and what the binary uses to
    /// find the task's stack and register context.
    #[must_use]
    pub const fn index(self) -> usize {
        self.index as usize
    }

    /// The handle as one word, to carry it through a context switch.
    #[must_use]
    pub const fn to_raw(self) -> u64 {
        (self.generation as u64) << 32 | self.index as u64
    }

    /// The inverse of [`SchedId::to_raw`]. A forged word is harmless: it names
    /// a slot and generation, and every use re-checks both.
    #[must_use]
    #[allow(
        clippy::cast_possible_truncation,
        reason = "the low half of the word is the index, by construction"
    )]
    pub const fn from_raw(raw: u64) -> Self {
        Self {
            index: raw as u32,
            generation: (raw >> 32) as u32,
        }
    }
}

/// `task->__state` as far as scheduling is concerned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskState {
    /// `TASK_RUNNING`: running or on the run queue.
    Running,
    /// `TASK_INTERRUPTIBLE`: asleep, a signal wakes it.
    Interruptible,
    /// `TASK_UNINTERRUPTIBLE`: asleep, only its key or timer wakes it.
    Uninterruptible,
    /// `TASK_DEAD`: past `do_task_dead`, waiting for the next task to free it.
    Dead,
}

impl TaskState {
    fn sleeping(self) -> bool {
        matches!(self, Self::Interruptible | Self::Uninterruptible)
    }
}

/// Which sleepers a key wake-up may wake: the `mode` argument of `__wake_up`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WakeMode {
    /// `TASK_NORMAL` (`wake_up`, `wake_up_all`): interruptible and
    /// uninterruptible sleepers.
    Normal,
    /// `TASK_INTERRUPTIBLE` (`wake_up_interruptible*`, used by pipe, tty and
    /// poll wake-ups): interruptible sleepers only.
    Interruptible,
}

impl WakeMode {
    fn wakes(self, state: TaskState) -> bool {
        match self {
            Self::Normal => state.sleeping(),
            Self::Interruptible => state == TaskState::Interruptible,
        }
    }
}

/// What a sleeper waits for besides a signal or its timer. `NONE` is woken by
/// neither.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaitKey(u64);

impl WaitKey {
    pub const NONE: Self = Self(0);

    /// The channel `(class, id)`.
    ///
    /// # Panics
    /// If `class` is zero (that is [`WaitKey::NONE`]).
    #[must_use]
    pub const fn new(class: u32, id: u32) -> Self {
        assert!(class != 0, "wait-key class 0 is the empty key");
        Self((class as u64) << 32 | id as u64)
    }
}

/// No free slot: the stack pool (or the task limit) is exhausted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoSlot;

/// A change of CPU owner that [`Rq::schedule`] decided on; the binary performs
/// the register switch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Switch {
    pub prev: SchedId,
    pub next: SchedId,
}

#[derive(Debug)]
struct Slot {
    generation: u32,
    used: bool,
    state: TaskState,
    key: WaitKey,
    /// Order in which sleepers went to sleep: the position in the key's wait
    /// queue (see [`Rq::wake_up_key`]).
    sleep_seq: u64,
    /// `WQ_FLAG_EXCLUSIVE`: queued at the tail, and counted by `nr_exclusive`.
    exclusive: bool,
    queued: bool,
    /// FIFO link while queued.
    next: Option<u32>,
    slice: u32,
}

impl Slot {
    const FREE: Self = Self {
        generation: 0,
        used: false,
        state: TaskState::Running,
        key: WaitKey::NONE,
        sleep_seq: 0,
        exclusive: false,
        queued: false,
        next: None,
        slice: 0,
    };
}

/// The run queue of the one CPU.
#[derive(Debug)]
pub struct Rq {
    slots: Vec<Slot>,
    head: Option<u32>,
    tail: Option<u32>,
    queued: usize,
    curr: u32,
    need_resched: bool,
    sleep_seq: u64,
}

/// Slot 0 is the idle task (`swapper`): always present, never queued, never
/// asleep.
const IDLE: u32 = 0;

impl Rq {
    /// A run queue for `capacity` tasks, the idle task included, which is
    /// running. All storage is reserved here.
    ///
    /// # Errors
    /// The allocation failed.
    ///
    /// # Panics
    /// If `capacity` is zero or does not fit a `u32`.
    pub fn new(capacity: usize) -> Result<Self, TryReserveError> {
        assert!(
            capacity >= 1 && u32::try_from(capacity).is_ok(),
            "run queue capacity"
        );
        let mut slots = Vec::new();
        slots.try_reserve_exact(capacity)?;
        for _ in 0..capacity {
            let pushed = slots.push_within_capacity(Slot::FREE);
            debug_assert!(pushed.is_ok(), "reserved above");
        }
        slots[0].used = true;
        Ok(Self {
            slots,
            head: None,
            tail: None,
            queued: 0,
            curr: IDLE,
            need_resched: false,
            sleep_seq: 0,
        })
    }

    fn id(&self, index: u32) -> SchedId {
        SchedId {
            index,
            generation: self.slots[index as usize].generation,
        }
    }

    fn slot(&self, id: SchedId) -> Option<&Slot> {
        self.slots
            .get(id.index())
            .filter(|slot| slot.used && slot.generation == id.generation)
    }

    fn slot_mut(&mut self, id: SchedId) -> Option<&mut Slot> {
        self.slots
            .get_mut(id.index())
            .filter(|slot| slot.used && slot.generation == id.generation)
    }

    /// The idle task.
    #[must_use]
    pub fn idle(&self) -> SchedId {
        self.id(IDLE)
    }

    /// `current`.
    #[must_use]
    pub fn curr(&self) -> SchedId {
        self.id(self.curr)
    }

    /// The task's state, `None` for a stale handle.
    #[must_use]
    pub fn state(&self, id: SchedId) -> Option<TaskState> {
        self.slot(id).map(|slot| slot.state)
    }

    /// `nr_running + nr_uninterruptible`: the queue, the running task if it is
    /// not idle, and the uninterruptible sleepers (what `loadavg` counts).
    #[must_use]
    pub fn nr_active(&self) -> usize {
        let running = usize::from(self.curr != IDLE);
        let blocked = self
            .slots
            .iter()
            .filter(|s| s.used && s.state == TaskState::Uninterruptible)
            .count();
        self.queued + running + blocked
    }

    /// Whether a task other than the current one could run.
    #[must_use]
    pub fn has_runnable(&self) -> bool {
        self.head.is_some()
    }

    /// `test_tsk_need_resched(current)`.
    #[must_use]
    pub fn need_resched(&self) -> bool {
        self.need_resched
    }

    pub fn set_need_resched(&mut self) {
        self.need_resched = true;
    }

    /// A slot for a new task, in state `Running` but not yet on the queue
    /// (`sched_fork`); [`Rq::wake_up_new_task`] makes it runnable.
    ///
    /// # Errors
    /// [`NoSlot`] when all slots are in use.
    pub fn add_task(&mut self) -> Result<SchedId, NoSlot> {
        let index = self.slots.iter().position(|s| !s.used).ok_or(NoSlot)?;
        let slot = &mut self.slots[index];
        slot.used = true;
        slot.state = TaskState::Running;
        slot.key = WaitKey::NONE;
        slot.exclusive = false;
        slot.queued = false;
        slot.next = None;
        slot.slice = 0;
        Ok(self.id(u32::try_from(index).map_err(|_| NoSlot)?))
    }

    fn enqueue(&mut self, index: u32) {
        let slot = &mut self.slots[index as usize];
        debug_assert!(!slot.queued && slot.state == TaskState::Running && index != IDLE);
        slot.queued = true;
        slot.next = None;
        match self.tail.replace(index) {
            Some(tail) => self.slots[tail as usize].next = Some(index),
            None => self.head = Some(index),
        }
        self.queued += 1;
    }

    fn dequeue(&mut self) -> Option<u32> {
        let index = self.head?;
        let slot = &mut self.slots[index as usize];
        self.head = slot.next.take();
        slot.queued = false;
        if self.head.is_none() {
            self.tail = None;
        }
        self.queued -= 1;
        Some(index)
    }

    /// `wake_up_new_task`: the new task joins the tail of the queue.
    ///
    /// Returns `false` for a stale handle or a task already runnable.
    pub fn wake_up_new_task(&mut self, id: SchedId) -> bool {
        match self.slot(id) {
            Some(slot) if slot.state == TaskState::Running && !slot.queued && id.index != IDLE => {
                self.enqueue(id.index);
                true
            }
            _ => false,
        }
    }

    /// `prepare_to_wait_event` for the current task: it will sleep on `key` in
    /// `state` once it calls [`Rq::schedule`] (it may still decide not to). It
    /// joins the head of the key's wait queue (`__add_wait_queue`).
    ///
    /// # Panics
    /// For a state that is not a sleeping one, or when the idle task sleeps.
    pub fn prepare_to_wait(&mut self, key: WaitKey, state: TaskState) {
        self.prepare(key, state, false);
    }

    /// `prepare_to_wait_exclusive`: as [`Rq::prepare_to_wait`] but at the tail
    /// of the queue (`__add_wait_queue_entry_tail`), where `nr_exclusive` of a
    /// wake-up counts it.
    pub fn prepare_to_wait_exclusive(&mut self, key: WaitKey, state: TaskState) {
        self.prepare(key, state, true);
    }

    fn prepare(&mut self, key: WaitKey, state: TaskState, exclusive: bool) {
        assert!(state.sleeping() && self.curr != IDLE, "prepare_to_wait");
        self.sleep_seq += 1;
        let seq = self.sleep_seq;
        let slot = &mut self.slots[self.curr as usize];
        slot.state = state;
        slot.key = key;
        slot.sleep_seq = seq;
        slot.exclusive = exclusive;
    }

    /// `finish_wait` for the current task: running again, no longer on a key.
    pub fn finish_wait(&mut self) {
        let slot = &mut self.slots[self.curr as usize];
        if slot.state.sleeping() {
            slot.state = TaskState::Running;
        }
        slot.key = WaitKey::NONE;
    }

    fn wake(&mut self, index: u32) {
        let slot = &mut self.slots[index as usize];
        slot.state = TaskState::Running;
        slot.key = WaitKey::NONE;
        // The current task is on the CPU, not on the queue: it just keeps going.
        if index != self.curr {
            self.enqueue(index);
        }
    }

    /// `try_to_wake_up(p, TASK_NORMAL)`: wake a sleeper of either kind.
    /// Whether it was asleep.
    pub fn try_to_wake_up(&mut self, id: SchedId) -> bool {
        match self.slot(id) {
            Some(slot) if slot.state.sleeping() => {
                self.wake(id.index);
                true
            }
            _ => false,
        }
    }

    /// `signal_wake_up_state(t, 0)`: wake only an interruptible sleeper. (The
    /// `TASK_WAKEKILL` stopped/traced case arrives with job control.)
    pub fn wake_interruptible(&mut self, id: SchedId) -> bool {
        match self.slot(id) {
            Some(slot) if slot.state == TaskState::Interruptible => {
                self.wake(id.index);
                true
            }
            _ => false,
        }
    }

    /// `__wake_up(key, mode, nr_exclusive)` (`__wake_up_common`): the sleepers
    /// of `key` whose state `mode` admits, in the order Linux's wait queue
    /// walks them: every non-exclusive one, newest first (they join the head),
    /// then exclusive ones, oldest first, stopping after `nr_exclusive` of them
    /// (`wake_up` is 1; 0, as in `wake_up_all`, wakes them all). Returns how
    /// many were woken. The empty key wakes nobody.
    ///
    /// shortcut: the queue is the slot array scanned by key, not a list, and a
    /// waiter that loops over several sleeps (Linux's `wait_event` keeps its
    /// entry queued between iterations) re-joins at the head on each one;
    /// upgrade with per-key wait entries (plan S5).
    pub fn wake_up_key(&mut self, key: WaitKey, mode: WakeMode, nr_exclusive: usize) -> usize {
        if key == WaitKey::NONE {
            return 0;
        }
        let mut woken = 0;
        let mut left = nr_exclusive;
        while let Some(index) = self
            .slots
            .iter()
            .enumerate()
            .filter(|(_, s)| s.used && s.key == key && mode.wakes(s.state))
            // List order: non-exclusive first, newest first; then exclusive,
            // oldest first.
            .min_by_key(|(_, s)| {
                (
                    s.exclusive,
                    if s.exclusive {
                        s.sleep_seq
                    } else {
                        !s.sleep_seq
                    },
                )
            })
            .and_then(|(index, _)| u32::try_from(index).ok())
        {
            let exclusive = self.slots[index as usize].exclusive;
            self.wake(index);
            woken += 1;
            if exclusive && left != 0 {
                left -= 1;
                if left == 0 {
                    break;
                }
            }
        }
        woken
    }

    /// Back to the state [`Rq::new`] made, for the bare-metal suite's group
    /// boundary: every task but idle is dropped (its slot freed, its handle
    /// stale), the queue is empty and idle is current. Context: idle is
    /// current (the caller runs on the boot stack).
    ///
    /// # Panics
    /// If another task is current.
    pub fn reset(&mut self) {
        assert!(self.curr == IDLE, "Rq::reset from a task");
        for slot in self.slots.iter_mut().skip(1) {
            let generation = slot.generation.wrapping_add(1);
            *slot = Slot::FREE;
            slot.generation = generation;
        }
        self.head = None;
        self.tail = None;
        self.queued = 0;
        self.need_resched = false;
    }

    /// `do_task_dead`'s state change: the current task is dead and must call
    /// [`Rq::schedule`] one last time. Its slot is released by [`Rq::free`]
    /// once another task runs (`finish_task_switch`).
    ///
    /// # Panics
    /// When the idle task exits.
    pub fn exit_current(&mut self) {
        assert!(self.curr != IDLE, "the idle task cannot exit");
        self.slots[self.curr as usize].state = TaskState::Dead;
    }

    /// `finish_task_switch` of a dead task: release its slot (the generation
    /// moves on, so stale handles stop resolving). Returns whether it was freed.
    pub fn free(&mut self, id: SchedId) -> bool {
        if id.index == self.curr {
            return false;
        }
        match self.slot_mut(id) {
            Some(slot) if slot.state == TaskState::Dead => {
                let generation = slot.generation.wrapping_add(1);
                *slot = Slot::FREE;
                slot.generation = generation;
                true
            }
            _ => false,
        }
    }

    /// `__schedule`: choose who runs next. A previous task that is still
    /// runnable (preempted or yielding) goes to the back of the queue; one that
    /// sleeps or died does not. `None` when the previous task keeps the CPU.
    pub fn schedule(&mut self) -> Option<Switch> {
        let prev = self.curr;
        self.need_resched = false;
        if prev != IDLE && self.slots[prev as usize].state == TaskState::Running {
            self.enqueue(prev);
        }
        let next = self.dequeue().unwrap_or(IDLE);
        self.slots[next as usize].slice = 0;
        if next == prev {
            return None;
        }
        let switch = Switch {
            prev: self.id(prev),
            next: self.id(next),
        };
        self.curr = next;
        Some(switch)
    }

    /// `sched_tick` for one timer tick: charge the current task's slice and ask
    /// for a reschedule when it is used up and another task waits (or when idle
    /// has work).
    pub fn tick(&mut self) {
        if self.head.is_none() {
            return;
        }
        let slot = &mut self.slots[self.curr as usize];
        slot.slice = slot.slice.saturating_add(1);
        if self.curr == IDLE || slot.slice >= SLICE_TICKS {
            self.need_resched = true;
        }
    }
}

#[cfg(test)]
mod tests;
