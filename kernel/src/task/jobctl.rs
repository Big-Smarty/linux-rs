// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: kernel/sys.c (`getppid` 1016,
// `setpgid` 1114-1190, `do_getpgid` 1192-1214, `getpgid`, `getpgrp`, `getsid`
// 1229-1252, `set_special_pids` 1254-1263, `ksys_setsid` 1265-1302),
// kernel/fork.c and fs/exec.c (`PF_FORKNOEXEC` set by `copy_process` and
// cleared by `begin_new_exec`), kernel/signal.c (`do_signal_stop` 2636-2722 and
// the `SIGNAL_CLD_MASK` step of `get_signal` 2913-2940, whose state half is
// `crate::signal::jobctl`). All GPL-2.0-only.
// Transformation: no LSM hook (`security_task_*` allow); `proc_clear_tty` is
// [`Tasklist::proc_clear_tty`] (`signal->tty` is a flag, `task::ctty`), no
// `sched_autogroup_create_attach`, no connector event; the pid re-linking
// reserves its capacity first, so `ENOMEM` can replace success only when the
// heap is exhausted.
#![forbid(unsafe_code)]
//! Process groups and sessions: `setpgid`, `getpgid`, `getsid`, `setsid`; and
//! the task-list half of a group stop.

use super::{
    exit::{CLD_STOPPED, Waker},
    pid::PidType,
    tasklist::{PF_FORKNOEXEC, TaskId, Tasklist},
};
use crate::signal::jobctl::{
    JOBCTL_STOP_CONSUME, JOBCTL_STOP_PENDING, JOBCTL_STOP_SIGMASK, SIGNAL_CLD_MASK,
    SIGNAL_STOP_STOPPED,
};
use syscalls::Errno;

/// What [`Tasklist::signal_stop`] decided for the running task.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopPlan {
    /// The group stop was cancelled in the meantime (`SIGCONT`, `SIGKILL`):
    /// carry on with the next signal.
    Carry,
    /// The task is committed to stop and the parent has been told. `fatal`: a
    /// fatal signal is already pending, so the task must not sleep
    /// (`signal_pending_state` in `__schedule` returns it to the run queue).
    Stop { fatal: bool },
}

impl Tasklist {
    /// `setpgid(pid, pgid)` as `current` (`group_leader`) calls it; `pid` and
    /// `pgid` are the raw `pid_t`s.
    ///
    /// # Errors
    /// `EINVAL`, `ESRCH`, `EPERM`, `EACCES` (target already exec'd), `ENOMEM`.
    pub fn setpgid(&mut self, current: TaskId, pid: i32, group: i32) -> Result<(), Errno> {
        let leader = self.group_leader(current);
        let pid = if pid == 0 {
            self.task_pid_vnr(leader)
        } else {
            pid
        };
        let group = if group == 0 { pid } else { group };
        if group < 0 {
            return Err(Errno::EINVAL);
        }
        let p = self.find_task_by_vpid(pid).ok_or(Errno::ESRCH)?;
        if !self.thread_group_leader(p) {
            return Err(Errno::EINVAL);
        }
        let task = self.task(p).ok_or(Errno::ESRCH)?;
        if task
            .real_parent
            .is_some_and(|parent| self.same_thread_group(parent, leader))
        {
            // A child of the caller's group.
            if self.task_pid_type(p, PidType::Sid) != self.task_pid_type(leader, PidType::Sid) {
                return Err(Errno::EPERM);
            }
            if task.flags & PF_FORKNOEXEC == 0 {
                return Err(Errno::EACCES);
            }
        } else if p != leader {
            return Err(Errno::ESRCH);
        }
        if self.is_session_leader(p) {
            return Err(Errno::EPERM);
        }
        let own = self.task_pid_type(p, PidType::Pid).ok_or(Errno::ESRCH)?;
        let pgrp = if group == pid {
            own
        } else {
            let pgrp = self.find_vpid(group).ok_or(Errno::EPERM)?;
            let member = self.pid_task(pgrp, PidType::Pgid).ok_or(Errno::EPERM)?;
            if self.task_pid_type(member, PidType::Sid) != self.task_pid_type(leader, PidType::Sid)
            {
                return Err(Errno::EPERM);
            }
            pgrp
        };
        if self.task_pid_type(p, PidType::Pgid) != Some(pgrp) {
            self.reserve_attach(pgrp, PidType::Pgid)?;
            self.change_pid(p, PidType::Pgid, pgrp);
        }
        Ok(())
    }

    /// `getpgid(pid)`: `pid == 0` is the caller.
    ///
    /// # Errors
    /// `ESRCH`.
    pub fn getpgid(&self, current: TaskId, pid: i32) -> Result<i32, Errno> {
        let task = self.target_or_self(current, pid)?;
        Ok(self.task_pgrp_vnr(task))
    }

    /// `getsid(pid)`.
    ///
    /// # Errors
    /// `ESRCH`.
    pub fn getsid(&self, current: TaskId, pid: i32) -> Result<i32, Errno> {
        let task = self.target_or_self(current, pid)?;
        Ok(self.task_session_vnr(task))
    }

    fn target_or_self(&self, current: TaskId, pid: i32) -> Result<TaskId, Errno> {
        if pid == 0 {
            Ok(current)
        } else {
            self.find_task_by_vpid(pid).ok_or(Errno::ESRCH)
        }
    }

    /// `setsid()`: the new session's number.
    ///
    /// # Errors
    /// `EPERM` if already a session leader or a process group with the
    /// caller's pid number exists; `ENOMEM`.
    pub fn setsid(&mut self, current: TaskId) -> Result<i32, Errno> {
        let current = self.group_leader(current);
        let sid = self
            .task_pid_type(current, PidType::Pid)
            .ok_or(Errno::ESRCH)?;
        let session = self.pid_vnr(Some(sid));
        if self.is_session_leader(current) {
            return Err(Errno::EPERM);
        }
        // "Fail if a process group id already exists that equals the proposed
        // session id."
        if self.pid_task(sid, PidType::Pgid).is_some() {
            return Err(Errno::EPERM);
        }
        self.reserve_attach(sid, PidType::Sid)?;
        self.reserve_attach(sid, PidType::Pgid)?;
        if let Some(g) = self.group_mut(current) {
            g.session_leader = true;
        }
        // set_special_pids
        self.change_pid(current, PidType::Sid, sid);
        self.change_pid(current, PidType::Pgid, sid);
        // `proc_clear_tty(group_leader)`: the new session has no terminal.
        self.proc_clear_tty(current);
        Ok(session)
    }

    /// What `exec` commits for the process tree: `PF_FORKNOEXEC` is cleared
    /// and `self_exec_id` is bumped (`begin_new_exec`, fs/exec.c:1274), and the
    /// credentials are published (`commit_creds`).
    pub fn exec_committed(&mut self, task: TaskId, cred: &super::attrs::Cred) {
        if let Some(t) = self.task_mut(task) {
            t.flags &= !PF_FORKNOEXEC;
            t.self_exec_id = t.self_exec_id.wrapping_add(1);
        }
        self.publish_cred(task, cred);
        // begin_new_exec: without a set-id image or an unreadable binary (neither
        // exists here: the credentials do not change at exec and root reads
        // everything) the new mm is SUID_DUMP_USER.
        self.set_dumpable(task, true);
    }

    /// `do_signal_stop(signr)` for the running task `task`, up to the sleep:
    /// the group stop is started and joined ([`crate::signal::State::do_signal_stop`]),
    /// and when this task completed a fresh stop the real parent is told
    /// `CLD_STOPPED` (`do_notify_parent_cldstop`: `SIGCHLD` unless ignored or
    /// `SA_NOCLDSTOP`, the `wait` sleepers woken either way). The caller then
    /// leaves the CPU in `TASK_STOPPED` unless [`StopPlan::Stop::fatal`].
    pub fn signal_stop(&mut self, task: TaskId, signr: u8, w: &mut dyn Waker) -> StopPlan {
        let fresh = self
            .task(task)
            .is_some_and(|t| t.thread.jobctl & JOBCTL_STOP_PENDING == 0);
        if fresh {
            let began = self
                .signal_state_as(task, true)
                .is_some_and(|mut state| state.begin_group_stop(signr));
            if !began {
                return StopPlan::Carry;
            }
            // "for_other_each_thread(current, t) if (!task_is_stopped(t) &&
            // task_set_jobctl_pending(t, signr | gstop)) { group_stop_count++;
            // signal_wake_up(t, 0); }"
            let mut index = 0;
            while let Some(t) = self.thread_at(task, index) {
                index += 1;
                if t == task {
                    continue;
                }
                let joined = self
                    .signal_state(t)
                    .is_some_and(|mut state| state.join_group_stop(signr));
                if joined {
                    let sched = self.sched_of(t);
                    w.signal_wake(t, sched, false);
                }
            }
        }
        let Some(mut state) = self.signal_state_as(task, true) else {
            return StopPlan::Carry;
        };
        let notify = state.participate_and_stop();
        let fatal = state.fatal_signal_pending();
        if notify {
            self.do_notify_parent_cldstop(task, CLD_STOPPED, w);
        }
        StopPlan::Stop { fatal }
    }

    /// `task_join_group_stop(task)`: a new thread of a group that is stopping (or stopped)
    /// takes part in the stop its creator saw.
    pub(super) fn task_join_group_stop(&mut self, creator: TaskId, task: TaskId) {
        let Some(mut mask) = self
            .task(creator)
            .map(|t| t.thread.jobctl & JOBCTL_STOP_SIGMASK)
        else {
            return;
        };
        let Some(sig) = self.sig_mut(creator) else {
            return;
        };
        if sig.group_stop_count != 0 {
            sig.group_stop_count += 1;
            mask |= JOBCTL_STOP_CONSUME;
        } else if sig.job_flags & SIGNAL_STOP_STOPPED == 0 {
            return;
        }
        if let Some(mut state) = self.signal_state(task) {
            state.task_set_jobctl_pending(mask | JOBCTL_STOP_PENDING);
        }
    }

    /// The `SIGNAL_CLD_MASK` step at the top of `get_signal`: a task that was
    /// stopped and woke (or a group whose stop `SIGCONT` cancelled) owes its
    /// parent the `CLD_CONTINUED` (or `CLD_STOPPED`) notification; the bits are
    /// cleared first. A no-op when nothing is owed.
    pub fn notify_job_control(&mut self, task: TaskId, w: &mut dyn Waker) {
        // Every return to user mode asks: look at the flags before building a view.
        if self
            .sig(task)
            .is_none_or(|sig| sig.job_flags & SIGNAL_CLD_MASK == 0)
        {
            return;
        }
        let why = self
            .signal_state_as(task, true)
            .and_then(|mut state| state.take_cld_notification());
        if let Some(why) = why {
            self.do_notify_parent_cldstop(task, why, w);
        }
    }
}
