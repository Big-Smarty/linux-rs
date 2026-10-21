// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: kernel/exit.c (`do_exit` 907-1027,
// `synchronize_group_exit` 878, `do_group_exit` 1099-1131, `exit_notify`
// 747-806, `forget_original_parent` 708-745, `reparent_leader` 684-706,
// `find_child_reaper`/`find_new_reaper` 608-682, `kill_orphaned_pgrp` 408-431,
// `will_become_orphaned_pgrp` 361-378, `has_stopped_jobs` 391-402),
// kernel/signal.c (`do_notify_parent` 2254-2345, `do_notify_parent_cldstop`
// 2365-2420, `__wake_up_parent`; the `parent_exec_id` fallback to SIGCHLD is
// 2273-2279). All GPL-2.0-only.
// Transformation: no ptrace, no subreapers, no `pdeath_signal` (nothing sets
// it), no coredump; the thread-group parts (`zap_other_threads`, the
// `group_dead` decisions, reparenting to a sibling thread, the zombie leader)
// follow `kernel/exit.c` and `kernel/signal.c`; `release_task` of an
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
    kill::SendTo,
    pid::PidType,
    tasklist::{ExitState, PF_EXITING, PF_SIGNALED, TaskId, Tasklist},
};
use crate::{
    sched::{CLASS_CHLDEXIT, SchedId, WaitKey},
    signal::{NSIG, SA_NOCLDSTOP, SA_NOCLDWAIT, SIG_IGN, SIGCHLD, SIGCONT, SIGHUP, info::SigInfo},
};

pub use crate::signal::jobctl::{
    CLD_CONTINUED, CLD_DUMPED, CLD_EXITED, CLD_KILLED, CLD_STOPPED, SIGNAL_CLD_CONTINUED,
    SIGNAL_CLD_STOPPED, SIGNAL_STOP_CONTINUED, SIGNAL_STOP_STOPPED,
};

/// `USER_HZ`: `clock_t` ticks per second in `siginfo` and `times`.
const USER_HZ: u64 = 100;

/// What the owner of the scheduler provides to the model: wake the sleepers a
/// state change concerns. Wake-ups may be spurious (every sleeper re-checks
/// its condition), so implementations may be as coarse as "wake everyone".
pub trait Waker {
    /// `__wake_up_parent`: a child of `parent` changed state (exited, stopped,
    /// continued): `wait4`/`waitid` sleepers of `parent` re-check.
    fn child_event(&mut self, parent: TaskId);
    /// `signal_wake_up(t, resume)`: `task` has a signal queued. `sched` is its
    /// scheduling handle ([`Tasklist::set_sched`]), `None` for a task that has
    /// none bound (the host fakes). `resume` (`TASK_WAKEKILL`) is set when the
    /// signal is fatal, so a job-control-stopped task wakes to die.
    fn signal_wake(&mut self, task: TaskId, sched: Option<SchedId>, resume: bool);
    /// `wake_up_state(t, __TASK_STOPPED)`: `SIGCONT` ended `task`'s job-control
    /// stop (`prepare_signal`).
    fn wake_stopped(&mut self, task: TaskId, sched: Option<SchedId>);
    /// `wake_up_process(sig->group_exec_task)`: the thread that `execve`s is waiting in
    /// `de_thread` for the other threads (or the old leader) to be gone, and one of them
    /// has just gone. `task` is the waiting thread.
    fn de_thread_event(&mut self, task: TaskId);
}

/// The wait queue `signal_struct::wait_chldexit` of a thread group: `do_wait` sleeps on it and
/// `child_event` wakes it. `leader` is the group leader (`Tasklist::group_leader`), whose slot
/// names the group; a slot reused by a later task only costs a spurious wake-up, which every
/// sleeper re-checks.
#[must_use]
pub fn chldexit_key(leader: TaskId) -> WaitKey {
    WaitKey::new(CLASS_CHLDEXIT, leader.slot())
}

/// The wait queue of a thread in `de_thread` waiting for the others to be gone: the id is the
/// slot of the waiting thread itself (`wake_up_process(group_exec_task)` names one task).
#[must_use]
pub fn de_thread_key(waiting: TaskId) -> WaitKey {
    WaitKey::new(crate::sched::CLASS_DETHREAD, waiting.slot())
}

/// For callers with no other task to wake (the single-task kernel).
pub struct NoWake;

impl Waker for NoWake {
    fn child_event(&mut self, _parent: TaskId) {}
    fn signal_wake(&mut self, _task: TaskId, _sched: Option<SchedId>, _resume: bool) {}
    fn wake_stopped(&mut self, _task: TaskId, _sched: Option<SchedId>) {}
    fn de_thread_event(&mut self, _task: TaskId) {}
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
    /// `zap_other_threads(p)`: every other thread of the group is marked for death with a
    /// pending `SIGKILL`, its pending group stop dropped, and woken (`signal_wake_up(t, 1)`).
    /// The number of other threads (the finished ones included), as `de_thread` waits for them.
    pub fn zap_other_threads(&mut self, p: TaskId, w: &mut dyn Waker) -> u32 {
        if let Some(sig) = self.sig_mut(p) {
            sig.group_stop_count = 0;
        }
        if let Some(mut state) = self.signal_state(p) {
            state.task_clear_jobctl_pending(crate::signal::jobctl::JOBCTL_PENDING_MASK);
        }
        let mut count = 0;
        let mut index = 0;
        while let Some(t) = self.thread_at(p, index) {
            index += 1;
            if t == p {
                continue;
            }
            count += 1;
            if self.task(t).is_none_or(|t| t.exit_state != ExitState::Live) {
                // "Don't bother with already dead threads"; the pending stop goes anyway.
                if let Some(mut state) = self.signal_state(t) {
                    state.task_clear_jobctl_pending(crate::signal::jobctl::JOBCTL_PENDING_MASK);
                }
                continue;
            }
            if let Some(mut state) = self.signal_state(t) {
                state.mark_killed();
            }
            self.signal_wake_up(t, true, w);
        }
        count
    }

    /// `do_group_exit(exit_code)` before `do_exit`: the group's exit code is
    /// the first one set (`SIGNAL_GROUP_EXIT`), so a task already dying keeps
    /// its code; otherwise the group exit starts and the other threads are
    /// killed. Returns the code `do_exit` runs with.
    pub fn do_group_exit(&mut self, task: TaskId, exit_code: u32, w: &mut dyn Waker) -> u32 {
        let Some(group_exit) = self.sig(task).map(|sig| sig.group_exit) else {
            return exit_code;
        };
        // "else if (sig->group_exec_task) exit_code = 0;": an `execve` of another thread is
        // collapsing the group and owns the other threads' deaths.
        if group_exit.is_none()
            && self
                .group_of(task)
                .is_some_and(|g| g.group_exec_task.is_some())
        {
            return 0;
        }
        // "if (signal_group_exit(sig)) exit_code = sig->group_exit_code; else start it".
        let code = self
            .signal_state(task)
            .map_or(exit_code, |mut state| state.group_exit_code(exit_code));
        // A task that gets here with the flag set (a fatal signal started the exit, or a core
        // dump signal's `get_signal` did) still has to be sure the others are dying: a signal
        // generated for the running task by its own `State` (a fault, `tgkill` on itself) could
        // not wake the other threads.
        self.zap_other_threads(task, w);
        code
    }

    /// The process-tree half of `do_exit` up to `exit_notify`:
    /// `synchronize_group_exit`, `exit_signals` (`PF_EXITING`), the
    /// `group_dead` decision, the panic for global init, the cancellation of
    /// the real interval timer and `tsk->exit_code = code`. `signaled` is
    /// `PF_SIGNALED` (killed by a signal).
    pub fn exit_prepare(
        &mut self,
        task: TaskId,
        code: u32,
        signaled: bool,
        w: &mut dyn Waker,
    ) -> ExitPrep {
        let init = self.is_global_init(task);
        if self.task(task).is_none() {
            return ExitPrep::Proceed { group_dead: true };
        }
        // synchronize_group_exit: the last thread to get here starts the group exit if nobody
        // did; `signal->flags = SIGNAL_GROUP_EXIT` drops the stop bits.
        if let Some(g) = self.group_mut(task) {
            g.quick_threads = g.quick_threads.saturating_sub(1);
            if g.quick_threads == 0 && g.sig.group_exit.is_none() {
                g.sig.group_exit = Some(code);
                g.sig.job_flags = 0;
                g.sig.group_stop_count = 0;
                g.sig.stop_code = 0;
            }
        }
        self.exit_signals(task, w);
        let group_dead = self.group_mut(task).is_none_or(|g| {
            g.live = g.live.saturating_sub(1);
            g.live == 0
        });
        if group_dead {
            let group_code = self.sig(task).and_then(|s| s.group_exit).unwrap_or(0);
            if init {
                return ExitPrep::InitDied {
                    exitcode: if group_code == 0 { code } else { group_code },
                };
            }
            // hrtimer_cancel(&tsk->signal->real_timer)
            if let Some(sig) = self.sig_mut(task) {
                sig.itimer.start(0, 0, 0);
            }
        }
        if let Some(t) = self.task_mut(task) {
            t.flags |= PF_EXITING | if signaled { PF_SIGNALED } else { 0 };
            t.exit_code = code;
        }
        ExitPrep::Proceed { group_dead }
    }

    /// `exit_signals`: the task is exiting. Its private pending signals are dropped and, when
    /// the group goes on and no group exit is under way, the shared signals only this thread
    /// could have taken are handed to another thread (`retarget_shared_pending`), and a group
    /// stop it was to join is completed without it.
    fn exit_signals(&mut self, task: TaskId, w: &mut dyn Waker) {
        if let Some(t) = self.task_mut(task) {
            t.flags |= PF_EXITING;
        }
        let Some(mut state) = self.signal_state(task) else {
            return;
        };
        let (blocked, shared) = (state.me.blocked, state.sig.shared_pending());
        let had_pending = state.signal_pending();
        let group_exit = state.sig.group_exit.is_some();
        state.flush_private();
        if !had_pending || self.thread_group_empty(task) || group_exit {
            return;
        }
        // retarget_shared_pending(tsk, &unblocked)
        let mut retarget = shared.0 & !blocked.0;
        if retarget != 0 {
            let mut index = 0;
            while retarget != 0
                && let Some(t) = self.thread_at(task, index)
            {
                index += 1;
                if t == task || self.task(t).is_none_or(|t| t.flags & PF_EXITING != 0) {
                    continue;
                }
                let Some(view) = self.signal_state(t) else {
                    continue;
                };
                if retarget & !view.me.blocked.0 == 0 {
                    continue;
                }
                // Remove the signals this thread can handle.
                retarget &= view.me.blocked.0;
                let wake = !view.signal_pending();
                if wake {
                    self.signal_wake_up(t, false, w);
                }
            }
        }
        let participate = self.signal_state(task).is_some_and(|mut s| {
            s.me.jobctl & crate::signal::jobctl::JOBCTL_STOP_PENDING != 0
                && s.task_participate_group_stop()
        });
        if participate {
            self.do_notify_parent_cldstop(task, CLD_STOPPED, w);
        }
    }

    /// `exit_notify`: hand the children to the reaper, tell the process group
    /// it may have become orphaned, become a zombie, notify the parent and
    /// auto-reap when the parent does not want the zombie. A thread that is
    /// not the leader never stays a zombie, and tells nobody; the leader of a
    /// group that still has threads stays a zombie without notifying its parent
    /// until the last of them is released.
    ///
    /// # Errors
    /// [`ExitError::Gone`], [`ExitError::ReaperDied`].
    pub fn exit_notify(
        &mut self,
        task: TaskId,
        group_dead: bool,
        w: &mut dyn Waker,
    ) -> Result<Notified, ExitError> {
        if self.task(task).is_none() {
            return Err(ExitError::Gone);
        }
        if task == self.child_reaper && self.find_alive_thread(task).is_none() {
            return Err(ExitError::ReaperDied);
        }
        self.forget_original_parent(task, w);
        let leader = self.group_leader(task);
        if group_dead {
            self.kill_orphaned_pgrp(leader, None, w);
        }
        if let Some(t) = self.task_mut(task) {
            t.exit_state = ExitState::Zombie;
        }
        self.touch_epoch(task);
        let autoreap = if leader == task {
            let exit_signal = self.task(task).map_or(SIGCHLD, |t| t.exit_signal);
            self.thread_group_empty(task) && self.do_notify_parent(task, exit_signal, w)
        } else {
            // untraced sub-thread
            true
        };
        // mt-exec, de_thread() is waiting for the group leader.
        let waiting = self
            .group_of(task)
            .and_then(|g| (g.notify_count < 0).then_some(g.group_exec_task).flatten());
        if let Some(waiting) = waiting {
            w.de_thread_event(waiting);
        }
        if autoreap {
            if let Some(t) = self.task_mut(task) {
                t.exit_state = ExitState::Dead;
            }
            self.release_task(task, w);
            Ok(Notified::Reaped)
        } else {
            Ok(Notified::Zombie)
        }
    }

    /// `find_alive_thread(p)`: a member of the group that is not exiting.
    #[must_use]
    pub fn find_alive_thread(&self, p: TaskId) -> Option<TaskId> {
        self.threads(p)
            .find(|&t| self.task(t).is_some_and(|t| t.flags & PF_EXITING == 0))
    }

    /// `forget_original_parent`: every child gets the reaper as its parent
    /// (`reparent_leader` notifies the new parent about zombies and checks
    /// for newly orphaned groups), then the whole list moves to the reaper's
    /// tail. The reaper is another live thread of the father's group when there
    /// is one (`find_new_reaper`), the namespace's reaper otherwise; a father
    /// that is the namespace's reaper passes the role to a live thread of its
    /// group (`find_child_reaper`).
    fn forget_original_parent(&mut self, father: TaskId, w: &mut dyn Waker) {
        let mut reaper = self.child_reaper;
        if reaper == father
            && let Some(alive) = self.find_alive_thread(father)
        {
            self.child_reaper = alive;
            reaper = alive;
        }
        // find_new_reaper: no subreapers.
        let reaper = self.find_alive_thread(father).unwrap_or(reaper);
        let mut next = self.task(father).and_then(|t| t.first_child);
        while let Some(child) = next {
            next = self.task(child).and_then(|t| t.next_sibling);
            let mut index = 0;
            while let Some(t) = self.thread_at(child, index) {
                index += 1;
                if let Some(t) = self.task_mut(t) {
                    t.real_parent = Some(reaper);
                }
            }
            // "If this is a threaded reparent there is no need to notify anyone anything has
            // happened."
            if !self.same_thread_group(reaper, father) {
                self.reparent_leader(father, child, w);
            }
        }
        self.list_splice_tail(father, reaper);
        // The zombies whose new parent ignores SIGCHLD were marked EXIT_DEAD
        // by `reparent_leader`: release them now (Linux's `dead` list).
        self.release_dead_children(reaper, w);
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
            && self.thread_group_empty(child)
            && self.do_notify_parent(child, SIGCHLD, w)
            && let Some(t) = self.task_mut(child)
        {
            t.exit_state = ExitState::Dead;
        }
        self.kill_orphaned_pgrp(child, Some(father), w);
    }

    /// `release_task` for every `EXIT_DEAD` child of `parent`.
    fn release_dead_children(&mut self, parent: TaskId, w: &mut dyn Waker) {
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
                self.release_task(child, w);
            }
        }
    }

    /// `do_notify_parent(tsk, sig)`: queue `SIGCHLD` for the real parent with
    /// the exit status, wake its `wait`ers, and report whether the parent
    /// wants no zombie (`SIG_IGN` or `SA_NOCLDWAIT` on `SIGCHLD`). `tsk` is a
    /// group leader without other threads.
    pub fn do_notify_parent(&mut self, tsk: TaskId, sig: u8, w: &mut dyn Waker) -> bool {
        let Some(parent) = self.real_parent(tsk) else {
            return false;
        };
        let (pid, uid, exit_code, cpu) = {
            let Some(t) = self.task(tsk) else {
                return false;
            };
            let (dead_u, dead_s) = self
                .group_of(tsk)
                .map_or((0, 0), |g| (g.dead_utime_ns, g.dead_stime_ns));
            (
                self.task_pid_vnr(tsk),
                t.cred.uid,
                t.exit_code,
                (t.utime_ns + dead_u, t.stime_ns + dead_s),
            )
        };
        let (code, status) = if exit_code & 0x80 != 0 {
            (CLD_DUMPED, exit_code & 0x7f)
        } else if exit_code & 0x7f != 0 {
            (CLD_KILLED, exit_code & 0x7f)
        } else {
            (CLD_EXITED, exit_code >> 8)
        };
        let mut info = SigInfo::chld(
            code,
            pid,
            uid,
            i32::try_from(status).unwrap_or(0),
            clock_t(cpu.0),
            clock_t(cpu.1),
        );
        let mut sig = sig;
        // "This is only possible if parent == real_parent. Check if it has
        // changed security domain." (kernel/signal.c:2273-2279)
        if sig != SIGCHLD
            && self.task(tsk).map(|t| t.parent_exec_id) != self.task(parent).map(|p| p.self_exec_id)
        {
            sig = SIGCHLD;
        }
        // `info.si_signo = sig`: a `clone` exit signal other than SIGCHLD carries
        // the same `_sigchld` payload.
        info.signo = i32::from(sig);
        let mut autoreap = false;
        if let Some(state) = self.signal_state(parent) {
            let action = state.hand.actions[usize::from(SIGCHLD) - 1];
            if sig == SIGCHLD && (action.handler == SIG_IGN || action.flags & SA_NOCLDWAIT != 0) {
                // POSIX: ignoring SIGCHLD (or SA_NOCLDWAIT) means "reap me for
                // me"; the signal itself is only sent for SA_NOCLDWAIT.
                autoreap = true;
                if action.handler == SIG_IGN {
                    sig = 0;
                }
            }
        }
        // `valid_signal(sig) && sig`: a `clone` exit signal above `_NSIG` is
        // never sent (it is not checked at the syscall). The signal goes to the group of the
        // thread that forked (`tsk->parent`), which `complete_signal` tries first.
        if sig != 0 && sig <= NSIG {
            // Only a real-time signal sent with `si_code < 0` can fail.
            let _ = self.send_signal_to(None, parent, sig, info, SendTo::Group, w);
        }
        let leader = self.group_leader(parent);
        w.child_event(leader);
        autoreap
    }

    /// `do_notify_parent_cldstop(tsk, false, why)`: the group of `tsk` stopped or
    /// continued; its leader tells the real parent: `SIGCHLD` unless the parent ignores it or
    /// set `SA_NOCLDSTOP`, and the `wait`ers are woken either way.
    pub fn do_notify_parent_cldstop(&mut self, tsk: TaskId, why: i32, w: &mut dyn Waker) {
        let tsk = self.group_leader(tsk);
        let Some(parent) = self.real_parent(tsk) else {
            return;
        };
        let (pid, uid, cpu, stop_code) = {
            let Some(t) = self.task(tsk) else {
                return;
            };
            let (dead_u, dead_s) = self
                .group_of(tsk)
                .map_or((0, 0), |g| (g.dead_utime_ns, g.dead_stime_ns));
            (
                self.task_pid_vnr(tsk),
                t.cred.uid,
                (t.utime_ns + dead_u, t.stime_ns + dead_s),
                self.sig(tsk).map_or(0, |s| s.stop_code),
            )
        };
        let status = match why {
            CLD_CONTINUED => i32::from(SIGCONT),
            CLD_STOPPED => i32::try_from(stop_code & 0x7f).unwrap_or(0),
            _ => 0,
        };
        let info = SigInfo::chld(why, pid, uid, status, clock_t(cpu.0), clock_t(cpu.1));
        let send = self.signal_state(parent).is_some_and(|state| {
            let action = state.hand.actions[usize::from(SIGCHLD) - 1];
            action.handler != SIG_IGN && action.flags & SA_NOCLDSTOP == 0
        });
        if send {
            let _ = self.send_signal_to(None, parent, SIGCHLD, info, SendTo::Group, w);
        }
        let leader = self.group_leader(parent);
        w.child_event(leader);
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
            // "p->exit_state && thread_group_empty(p)": a zombie leader with threads still counts.
            if Some(p) == ignored || (t.exit_state != ExitState::Live && self.thread_group_empty(p))
            {
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
                self.sig(p)
                    .is_some_and(|sig| sig.job_flags & SIGNAL_STOP_STOPPED != 0)
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
