// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: kernel/exit.c (`do_exit` 907-1027,
// `synchronize_group_exit` 878, `do_group_exit` 1099-1131, `exit_notify`
// 747-806, `forget_original_parent` 708-745, `reparent_leader` 684-706,
// `find_child_reaper`/`find_new_reaper` 608-682, `kill_orphaned_pgrp` 408-431,
// `will_become_orphaned_pgrp` 361-378, `has_stopped_jobs` 391-402),
// kernel/signal.c (`do_notify_parent` 2254-2345, `do_notify_parent_cldstop`
// 2365-2420, `__wake_up_parent`). All GPL-2.0-only.
// Transformation: one thread per group, no ptrace, no subreapers, no
// `pdeath_signal` (nothing sets it), no coredump; `release_task` of an
// auto-reaped task is immediate (Linux defers it past the `tasklist_lock`
// section on a `dead` list, which a single exclusion makes equivalent
// provided `kill_orphaned_pgrp` still sees the task, so the release is
// deferred past it here too). The parts of `do_exit` that tear down resources
// (`exit_mm`, `exit_files`, `exit_fs`) are the owner's: it runs them between
// [`Tasklist::exit_prepare`] and [`Tasklist::exit_notify`].
#![forbid(unsafe_code)]
//! `do_exit`'s process-tree half: group-exit bookkeeping, reparenting,
//! `SIGCHLD`, auto-reaping and orphaned process groups.

use super::{
    pid::PidType,
    tasklist::{ExitState, PF_EXITING, PF_SIGNALED, TaskId, Tasklist},
};
use crate::signal::{
    SA_NOCLDSTOP, SA_NOCLDWAIT, SIG_IGN, SIGCHLD, SIGCONT, SIGHUP, info::SigInfo, state::Target,
};

/// `SIGNAL_STOP_STOPPED`: a job-control stop is in effect.
pub const SIGNAL_STOP_STOPPED: u32 = 0x1;
/// `SIGNAL_STOP_CONTINUED`: `SIGCONT` since the last `WCONTINUED` report.
pub const SIGNAL_STOP_CONTINUED: u32 = 0x2;
/// `SIGNAL_CLD_STOPPED`: the parent owes a stop notification.
pub const SIGNAL_CLD_STOPPED: u32 = 0x10;
/// `SIGNAL_CLD_CONTINUED`: the parent owes a continue notification.
pub const SIGNAL_CLD_CONTINUED: u32 = 0x20;

/// `CLD_*` (`si_code` of `SIGCHLD`).
pub const CLD_EXITED: i32 = 1;
pub const CLD_KILLED: i32 = 2;
pub const CLD_DUMPED: i32 = 3;
pub const CLD_STOPPED: i32 = 5;
pub const CLD_CONTINUED: i32 = 6;

/// `USER_HZ`: `clock_t` ticks per second in `siginfo` and `times`.
const USER_HZ: u64 = 100;

/// What the owner of the scheduler provides to the model: wake the sleepers a
/// state change concerns. Wake-ups may be spurious (every sleeper re-checks
/// its condition), so implementations may be as coarse as "wake everyone".
pub trait Waker {
    /// `__wake_up_parent`: a child of `parent` changed state (exited, stopped,
    /// continued): `wait4`/`waitid` sleepers of `parent` re-check.
    fn child_event(&mut self, parent: TaskId);
    /// `signal_wake_up`: `task` has a signal queued.
    fn signal_wake(&mut self, task: TaskId);
}

/// For callers with no other task to wake (the single-task kernel).
pub struct NoWake;

impl Waker for NoWake {
    fn child_event(&mut self, _parent: TaskId) {}
    fn signal_wake(&mut self, _task: TaskId) {}
}

/// Why a task cannot go through [`Tasklist::exit_notify`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitError {
    /// The task is not in the list (already released).
    Gone,
    /// The child reaper (global init) cannot be notified out: its death panics
    /// first (`do_exit`), and a reaper dying without a successor needs
    /// `zap_pid_ns_processes`, which this namespace does not have.
    ReaperDied,
}

/// What [`Tasklist::exit_prepare`] decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitPrep {
    /// The last thread of global init is exiting: Linux panics with
    /// `"Attempted to kill init! exitcode=0x%08x"` (the value is `exitcode`).
    InitDied { exitcode: u32 },
    /// Carry on with `exit_mm`/`exit_files`/... then `exit_notify`.
    Proceed { group_dead: bool },
}

/// How `exit_notify` left the task.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notified {
    /// The task is a zombie for its parent to reap.
    Zombie,
    /// The parent ignores `SIGCHLD` (or has `SA_NOCLDWAIT`): the task was
    /// reaped at once and its id no longer resolves.
    Reaped,
}

/// `nsec_to_clock_t`.
fn clock_t(ns: u64) -> i64 {
    i64::try_from(ns / (1_000_000_000 / USER_HZ)).unwrap_or(i64::MAX)
}

impl Tasklist {
    /// `do_group_exit(exit_code)` before `do_exit`: the group's exit code is
    /// the first one set (`SIGNAL_GROUP_EXIT`), so a task already dying keeps
    /// its code. Returns the code `do_exit` runs with.
    pub fn do_group_exit(&mut self, task: TaskId, exit_code: u32) -> u32 {
        let Some(mut state) = self.signal_state(task) else {
            return exit_code;
        };
        // The one thread: nothing to `zap_other_threads`.
        state.group_exit_code(exit_code)
    }

    /// The process-tree half of `do_exit` up to `exit_notify`:
    /// `synchronize_group_exit`, `exit_signals` (`PF_EXITING`), the
    /// `group_dead` decision, the panic for global init, the cancellation of
    /// the real interval timer and `tsk->exit_code = code`. `signaled` is
    /// `PF_SIGNALED` (killed by a signal).
    pub fn exit_prepare(&mut self, task: TaskId, code: u32, signaled: bool) -> ExitPrep {
        let init = self.is_global_init(task);
        let Some(state) = self.signal_state(task) else {
            return ExitPrep::Proceed { group_dead: true };
        };
        // synchronize_group_exit: the last thread starts the group exit if
        // nobody did; `signal->flags = SIGNAL_GROUP_EXIT` drops the stop bits.
        if state.sig.group_exit.is_none() {
            state.sig.start_group_exit(code);
        }
        let group_code = state.sig.group_exit.unwrap_or(0);
        // The one thread: `live` drops to zero.
        if init {
            return ExitPrep::InitDied {
                exitcode: if group_code == 0 { code } else { group_code },
            };
        }
        // hrtimer_cancel(&tsk->signal->real_timer)
        state.sig.itimer.start(0, 0, 0);
        if let Some(t) = self.task_mut(task) {
            t.flags |= PF_EXITING | if signaled { PF_SIGNALED } else { 0 };
            t.exit_code = code;
        }
        ExitPrep::Proceed { group_dead: true }
    }

    /// `exit_notify`: hand the children to the reaper, tell the process group
    /// it may have become orphaned, become a zombie, notify the parent and
    /// auto-reap when the parent does not want the zombie.
    ///
    /// # Errors
    /// [`ExitError::Gone`], [`ExitError::ReaperDied`].
    pub fn exit_notify(&mut self, task: TaskId, w: &mut dyn Waker) -> Result<Notified, ExitError> {
        if self.task(task).is_none() {
            return Err(ExitError::Gone);
        }
        if task == self.child_reaper {
            return Err(ExitError::ReaperDied);
        }
        self.forget_original_parent(task, w);
        // group_dead: the one thread is the group.
        self.kill_orphaned_pgrp(task, None, w);
        if let Some(t) = self.task_mut(task) {
            t.exit_state = ExitState::Zombie;
        }
        let exit_signal = self.task(task).map_or(SIGCHLD, |t| t.exit_signal);
        let autoreap = self.do_notify_parent(task, exit_signal, w);
        if autoreap {
            if let Some(t) = self.task_mut(task) {
                t.exit_state = ExitState::Dead;
            }
            self.release_task(task);
            Ok(Notified::Reaped)
        } else {
            Ok(Notified::Zombie)
        }
    }

    /// `forget_original_parent`: every child gets the reaper as its parent
    /// (`reparent_leader` notifies the new parent about zombies and checks
    /// for newly orphaned groups), then the whole list moves to the reaper's
    /// tail.
    fn forget_original_parent(&mut self, father: TaskId, w: &mut dyn Waker) {
        // find_child_reaper: global init outlives its children (its own death
        // panicked earlier); find_new_reaper: no subreapers, no other thread.
        let reaper = self.child_reaper;
        let mut next = self.task(father).and_then(|t| t.first_child);
        while let Some(child) = next {
            next = self.task(child).and_then(|t| t.next_sibling);
            if let Some(t) = self.task_mut(child) {
                t.real_parent = Some(reaper);
            }
            // !same_thread_group(reaper, father)
            self.reparent_leader(father, child, w);
        }
        self.list_splice_tail(father, reaper);
        // The zombies whose new parent ignores SIGCHLD were marked EXIT_DEAD
        // by `reparent_leader`: release them now (Linux's `dead` list).
        self.release_dead_children(reaper);
    }

    /// `reparent_leader`.
    fn reparent_leader(&mut self, father: TaskId, child: TaskId, w: &mut dyn Waker) {
        let Some(t) = self.task_mut(child) else {
            return;
        };
        if t.exit_state == ExitState::Dead {
            return;
        }
        // "We don't want people slaying init."
        t.exit_signal = SIGCHLD;
        // If it has exited notify the new parent about this child's death.
        if t.exit_state == ExitState::Zombie
            && self.do_notify_parent(child, SIGCHLD, w)
            && let Some(t) = self.task_mut(child)
        {
            t.exit_state = ExitState::Dead;
        }
        self.kill_orphaned_pgrp(child, Some(father), w);
    }

    /// `release_task` for every `EXIT_DEAD` child of `parent`.
    fn release_dead_children(&mut self, parent: TaskId) {
        loop {
            let mut batch = [None; 8];
            let mut found = 0;
            for child in self.children(parent) {
                if self
                    .task(child)
                    .is_some_and(|t| t.exit_state == ExitState::Dead)
                {
                    batch[found] = Some(child);
                    found += 1;
                    if found == batch.len() {
                        break;
                    }
                }
            }
            if found == 0 {
                return;
            }
            for child in batch.into_iter().flatten() {
                self.release_task(child);
            }
        }
    }

    /// `do_notify_parent(tsk, sig)`: queue `SIGCHLD` for the real parent with
    /// the exit status, wake its `wait`ers, and report whether the parent
    /// wants no zombie (`SIG_IGN` or `SA_NOCLDWAIT` on `SIGCHLD`).
    pub fn do_notify_parent(&mut self, tsk: TaskId, sig: u8, w: &mut dyn Waker) -> bool {
        let Some(parent) = self.real_parent(tsk) else {
            return false;
        };
        let (pid, uid, exit_code, cpu) = {
            let Some(t) = self.task(tsk) else {
                return false;
            };
            (
                self.task_pid_vnr(tsk),
                t.cred.uid,
                t.exit_code,
                (t.utime_ns, t.stime_ns),
            )
        };
        let (code, status) = if exit_code & 0x80 != 0 {
            (CLD_DUMPED, exit_code & 0x7f)
        } else if exit_code & 0x7f != 0 {
            (CLD_KILLED, exit_code & 0x7f)
        } else {
            (CLD_EXITED, exit_code >> 8)
        };
        let info = SigInfo::chld(
            code,
            pid,
            uid,
            i32::try_from(status).unwrap_or(0),
            clock_t(cpu.0),
            clock_t(cpu.1),
        );
        let mut sig = sig;
        let mut autoreap = false;
        if let Some(mut state) = self.signal_state(parent) {
            let action = state.hand.actions[usize::from(SIGCHLD) - 1];
            if sig == SIGCHLD && (action.handler == SIG_IGN || action.flags & SA_NOCLDWAIT != 0) {
                // POSIX: ignoring SIGCHLD (or SA_NOCLDWAIT) means "reap me for
                // me"; the signal itself is only sent for SA_NOCLDWAIT.
                autoreap = true;
                if action.handler == SIG_IGN {
                    sig = 0;
                }
            }
            if sig != 0 {
                // Only a real-time signal sent with `si_code < 0` can fail.
                let _ = state.send_signal(sig, info, Target::Process);
                w.signal_wake(parent);
            }
        }
        w.child_event(parent);
        autoreap
    }

    /// `do_notify_parent_cldstop(tsk, false, why)`: `tsk` stopped or
    /// continued; `SIGCHLD` unless the parent ignores it or set
    /// `SA_NOCLDSTOP`, and the `wait`ers are woken either way.
    pub fn do_notify_parent_cldstop(&mut self, tsk: TaskId, why: i32, w: &mut dyn Waker) {
        let Some(parent) = self.real_parent(tsk) else {
            return;
        };
        let (pid, uid, cpu, stop_code) = {
            let Some(t) = self.task(tsk) else {
                return;
            };
            (
                self.task_pid_vnr(tsk),
                t.cred.uid,
                (t.utime_ns, t.stime_ns),
                t.signals.signal.stop_code,
            )
        };
        let status = match why {
            CLD_CONTINUED => i32::from(SIGCONT),
            CLD_STOPPED => i32::try_from(stop_code & 0x7f).unwrap_or(0),
            _ => 0,
        };
        let info = SigInfo::chld(why, pid, uid, status, clock_t(cpu.0), clock_t(cpu.1));
        if let Some(mut state) = self.signal_state(parent) {
            let action = state.hand.actions[usize::from(SIGCHLD) - 1];
            if action.handler != SIG_IGN && action.flags & SA_NOCLDSTOP == 0 {
                let _ = state.send_signal(SIGCHLD, info, Target::Process);
                w.signal_wake(parent);
            }
        }
        w.child_event(parent);
    }

    // ---- orphaned process groups ----------------------------------------------

    /// `task_pgrp(parent)` and `task_session(parent)`. A `None` parent is the
    /// idle task (`init_task`, init's `real_parent`), whose group and session
    /// are `init_struct_pid`; it is not `is_global_init`.
    fn group_and_session(
        &self,
        parent: Option<TaskId>,
    ) -> (Option<super::pid::PidId>, Option<super::pid::PidId>) {
        match parent {
            Some(t) => (
                self.task_pid_type(t, PidType::Pgid),
                self.task_pid_type(t, PidType::Sid),
            ),
            None => (Some(self.init_struct_pid()), Some(self.init_struct_pid())),
        }
    }

    /// `will_become_orphaned_pgrp`: no member (other than `ignored`, a task
    /// that is leaving) has a parent in another group of the same session.
    #[must_use]
    pub fn will_become_orphaned_pgrp(
        &self,
        pgrp: super::pid::PidId,
        ignored: Option<TaskId>,
    ) -> bool {
        let Some(pid) = self.pid(pgrp) else {
            return true;
        };
        for p in pid.tasks(PidType::Pgid) {
            let Some(t) = self.task(p) else { continue };
            if Some(p) == ignored || t.exit_state != ExitState::Live {
                continue;
            }
            if t.real_parent
                .is_some_and(|parent| self.is_global_init(parent))
            {
                continue;
            }
            let (parent_pgrp, parent_sid) = self.group_and_session(t.real_parent);
            if parent_pgrp != Some(pgrp) && parent_sid == self.task_pid_type(p, PidType::Sid) {
                return false;
            }
        }
        true
    }

    /// `is_current_pgrp_orphaned`.
    #[must_use]
    pub fn is_pgrp_orphaned(&self, task: TaskId) -> bool {
        match self.task_pid_type(task, PidType::Pgid) {
            Some(pgrp) => self.will_become_orphaned_pgrp(pgrp, None),
            None => true,
        }
    }

    /// `has_stopped_jobs`.
    #[must_use]
    pub fn has_stopped_jobs(&self, pgrp: super::pid::PidId) -> bool {
        self.pid(pgrp).is_some_and(|pid| {
            pid.tasks(PidType::Pgid).any(|p| {
                self.task(p)
                    .is_some_and(|t| t.signals.signal.job_flags & SIGNAL_STOP_STOPPED != 0)
            })
        })
    }

    /// `kill_orphaned_pgrp(tsk, parent)`: after `tsk` exits (`parent` `None`)
    /// or after a child of `parent` is reparented away, a process group that
    /// became orphaned and has stopped members gets `SIGHUP` then `SIGCONT`.
    pub fn kill_orphaned_pgrp(&mut self, tsk: TaskId, parent: Option<TaskId>, w: &mut dyn Waker) {
        let Some(pgrp) = self.task_pid_type(tsk, PidType::Pgid) else {
            return;
        };
        let (parent, ignored) = match parent {
            // exit: our father is in a different pgrp than we are and we were
            // the only connection outside.
            None => (self.real_parent(tsk), Some(tsk)),
            // reparent: our child is in a different pgrp than we are, and it
            // was the only connection outside.
            Some(parent) => (Some(parent), None),
        };
        let (parent_pgrp, parent_sid) = self.group_and_session(parent);
        if parent_pgrp != Some(pgrp)
            && parent_sid == self.task_pid_type(tsk, PidType::Sid)
            && self.will_become_orphaned_pgrp(pgrp, ignored)
            && self.has_stopped_jobs(pgrp)
        {
            let _ = self.kill_pgrp_priv(pgrp, SIGHUP, w);
            let _ = self.kill_pgrp_priv(pgrp, SIGCONT, w);
        }
    }
}
