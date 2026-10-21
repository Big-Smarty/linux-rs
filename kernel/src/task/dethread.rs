// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: fs/exec.c (`de_thread` 912-1045,
// `exchange_tids`, `unshare_sighand` 1058-1085), kernel/pid.c (`transfer_pid`,
// `change_pid`), kernel/exit.c (`release_task`, `exit_notify`'s `notify_count`
// wake-up), kernel/signal.c (`zap_other_threads` 1384-1405). All GPL-2.0-only.
// Transformation: the sleeps of `de_thread` are the caller's (it waits on
// [`super::exit::de_thread_key`] and calls the steps again; a fatal signal while it waits is
// [`Tasklist::de_thread_abort`]); the exchange of pids and list positions is one
// uninterruptible step ([`Tasklist::de_thread_finish`]) that allocates nothing.
#![forbid(unsafe_code)]
//! `execve` from a thread of a multi-threaded process: every other thread is killed and gone,
//! the old leader is released, and the thread that executes becomes the leader with the old
//! leader's pid.

use super::{
    exit::Waker,
    pid::PidType,
    tasklist::{ExitState, Sighand, TaskId, Tasklist},
};
use crate::signal::SIGCHLD;
use alloc::boxed::Box;
use syscalls::Errno;

/// What [`Tasklist::de_thread_start`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeThread {
    /// The task is alone in its group: nothing to wait for.
    Alone,
    /// The other threads were killed; wait until [`Tasklist::de_thread_others_gone`].
    Wait,
}

impl Tasklist {
    /// The start of `de_thread(tsk)`: kill every other thread of the group.
    ///
    /// # Errors
    /// `EAGAIN` when a group exit or another `execve` of the group is already under way ("just
    /// return so that the signal is processed").
    pub fn de_thread_start(&mut self, tsk: TaskId, w: &mut dyn Waker) -> Result<DeThread, Errno> {
        if self.thread_group_empty(tsk) {
            // no_thread_group: we have changed execution domain
            if let Some(t) = self.task_mut(tsk) {
                t.exit_signal = SIGCHLD;
            }
            return Ok(DeThread::Alone);
        }
        let g = self.group_of(tsk).ok_or(Errno::ESRCH)?;
        if g.sig.group_exit.is_some() || g.group_exec_task.is_some() {
            return Err(Errno::EAGAIN);
        }
        let leader = self.thread_group_leader(tsk);
        if let Some(g) = self.group_mut(tsk) {
            g.group_exec_task = Some(tsk);
        }
        let count = self.zap_other_threads(tsk, w);
        if let Some(g) = self.group_mut(tsk) {
            g.notify_count = i32::try_from(count).unwrap_or(i32::MAX) - i32::from(!leader);
        }
        Ok(DeThread::Wait)
    }

    /// `sig->notify_count == 0`: every other thread (but a non-leader's old leader) has been
    /// released.
    #[must_use]
    pub fn de_thread_others_gone(&self, tsk: TaskId) -> bool {
        self.group_of(tsk).is_none_or(|g| g.notify_count == 0)
    }

    /// The second wait of a non-leader `execve`: the old leader must be a zombie before it can
    /// hand over its pid. `notify_count = -1` makes its `exit_notify` wake us. Returns whether
    /// the leader has already exited (`leader->exit_state`).
    pub fn de_thread_leader_exited(&mut self, tsk: TaskId) -> bool {
        let leader = self.group_leader(tsk);
        if leader == tsk {
            return true;
        }
        if let Some(g) = self.group_mut(tsk) {
            g.notify_count = -1;
        }
        self.task(leader)
            .is_none_or(|l| l.exit_state != ExitState::Live)
    }

    /// The `killed:` exit of `de_thread`: a fatal signal arrived while waiting.
    pub fn de_thread_abort(&mut self, tsk: TaskId) {
        if let Some(g) = self.group_mut(tsk) {
            g.group_exec_task = None;
            g.notify_count = 0;
        }
    }

    /// The last part of `de_thread`, with every other thread gone and, for a non-leader, the old
    /// leader a zombie: the thread takes the leader's pid, process group, session, place in the
    /// task list and among its parent's children (`exchange_tids`, `transfer_pid`,
    /// `list_replace`), becomes the leader with `SIGCHLD` as its exit signal, and the old
    /// leader (now `EXIT_DEAD` with no exit signal) is released.
    pub fn de_thread_finish(&mut self, tsk: TaskId, w: &mut dyn Waker) {
        let leader = self.group_leader(tsk);
        if leader != tsk {
            self.exchange_leader(tsk, leader);
            if let Some(t) = self.task_mut(tsk) {
                t.exit_signal = SIGCHLD;
            }
            if let Some(l) = self.task_mut(leader) {
                l.exit_signal = 0;
                l.exit_state = ExitState::Dead;
            }
            self.release_task(leader, w);
        } else if let Some(t) = self.task_mut(tsk) {
            t.exit_signal = SIGCHLD;
        }
        if let Some(g) = self.group_mut(tsk) {
            g.group_exec_task = None;
            g.notify_count = 0;
        }
    }

    /// `unshare_sighand(me)`: when another task still points at the caller's dispositions
    /// (`CLONE_SIGHAND` without `CLONE_THREAD`; its own threads are gone after `de_thread`) the
    /// caller gets a private copy.
    ///
    /// # Errors
    /// `ENOMEM`.
    pub fn unshare_sighand(&mut self, task: TaskId) -> Result<(), Errno> {
        let Some(old) = self.task(task).map(|t| t.sighand) else {
            return Err(Errno::ESRCH);
        };
        let Some(shared) = self.sighands.get(old) else {
            return Err(Errno::ESRCH);
        };
        if shared.count <= 1 {
            return Ok(());
        }
        let hand = Box::try_new((*shared.hand).clone()).map_err(|_| Errno::ENOMEM)?;
        let new = self
            .sighands
            .try_insert(Sighand { hand, count: 1 })
            .map_err(|_| Errno::ENOMEM)?;
        if let Some(old) = self.sighands.get_mut(old) {
            old.count -= 1;
        }
        if let Some(t) = self.task_mut(task) {
            t.sighand = new;
        }
        Ok(())
    }

    /// The tasks pointing at the dispositions of `task` (`sighand->count`).
    #[must_use]
    pub fn sighand_users(&self, task: TaskId) -> u32 {
        self.task(task)
            .and_then(|t| self.sighands.get(t.sighand))
            .map_or(0, |h| h.count)
    }

    /// `exchange_tids(tsk, leader)`, `transfer_pid(leader, tsk, ...)` x3, the replacement in
    /// the task list and the sibling list, and the new `group_leader` of every thread.
    fn exchange_leader(&mut self, tsk: TaskId, leader: TaskId) {
        // exchange_tids: the two threads swap their PIDTYPE_PID pids.
        let own = self.task(tsk).and_then(|t| t.pids[PidType::Pid as usize]);
        let theirs = self.task(leader).and_then(|t| t.pids[PidType::Pid as usize]);
        if let Some(t) = self.task_mut(tsk) {
            t.pids[PidType::Pid as usize] = theirs;
        }
        if let Some(l) = self.task_mut(leader) {
            l.pids[PidType::Pid as usize] = own;
        }
        if let Some(pid) = own.and_then(|p| self.pids.get_mut(p)) {
            pid.replace(PidType::Pid, tsk, leader);
        }
        if let Some(pid) = theirs.and_then(|p| self.pids.get_mut(p)) {
            pid.replace(PidType::Pid, leader, tsk);
        }
        // transfer_pid: the group's links move to the thread.
        for ty in [PidType::Tgid, PidType::Pgid, PidType::Sid] {
            let moved = self
                .task_mut(leader)
                .and_then(|l| l.pids[ty as usize].take());
            if let Some(t) = self.task_mut(tsk) {
                t.pids[ty as usize] = moved;
            }
            if let Some(pid) = moved.and_then(|p| self.pids.get_mut(p)) {
                pid.replace(ty, leader, tsk);
            }
        }
        // list_replace_rcu(&leader->tasks, &tsk->tasks)
        for entry in &mut self.order {
            if *entry == leader {
                *entry = tsk;
            }
        }
        // list_replace_init(&leader->sibling, &tsk->sibling)
        if let Some(parent) = self.task(leader).and_then(|l| l.real_parent) {
            self.list_replace(parent, leader, tsk);
        }
        // tsk->group_leader = tsk; leader->group_leader = tsk
        let mut index = 0;
        while let Some(t) = self.thread_at(tsk, index) {
            index += 1;
            if let Some(t) = self.task_mut(t) {
                t.group_leader = tsk;
            }
        }
        if self.child_reaper == leader {
            self.child_reaper = tsk;
        }
        self.touch_epoch(tsk);
    }
}
