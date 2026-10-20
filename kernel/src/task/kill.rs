// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: kernel/signal.c
// (`kill_ok_by_cred` 806-815, `check_kill_permission` 823-857,
// `group_send_sig_info` 1465-1477, `__kill_pgrp_info` 1485-1507,
// `kill_pid_info_type` 1509-1530, `kill_proc_info`, `kill_something_info`
// 1628-1665, `SYSCALL_DEFINE2(kill)` and `prepare_kill_siginfo` 4012-4032).
// All GPL-2.0-only.
// Transformation: no LSM or audit hook; a signal reaches the target's
// [`crate::signal::State`] through its [`super::tasklist::Tasklist`] slot;
// waking the target is [`super::exit::Waker::signal_wake`]. Kernel threads do
// not exist, so `kill(-1)` here reaches only user tasks. The stop and continue
// effects of a signal are `crate::signal::jobctl`'s; this file wakes what they
// release.
#![forbid(unsafe_code)]
//! The `kill` family over the task list: target selection, permission and
//! delivery.

use super::{
    exit::Waker,
    pid::{PidId, PidType},
    tasklist::{TaskId, Tasklist},
};
use crate::signal::{NSIG, info::SigInfo, jobctl::JOBCTL_STOPPED, state::Target, valid_signal};
use syscalls::Errno;

/// `PIDTYPE_PID` (a thread) or the group (`PIDTYPE_TGID`, `PGID`, `MAX`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendTo {
    Thread,
    Group,
}

impl Tasklist {
    /// `kill_ok_by_cred(t)`.
    fn kill_ok_by_cred(&self, sender: TaskId, target: TaskId) -> bool {
        let (Some(s), Some(t)) = (self.task(sender), self.task(target)) else {
            return false;
        };
        let (c, tc) = (s.cred, t.cred);
        c.euid == tc.suid || c.euid == tc.uid || c.uid == tc.suid || c.uid == tc.uid || c.cap_kill
    }

    /// `check_kill_permission(sig, info, t)` for a signal sent by `sender`
    /// (`None`: the kernel itself, `SEND_SIG_PRIV`). `from_user` is
    /// `si_fromuser(info)` (`si_code <= 0`).
    ///
    /// # Errors
    /// `EINVAL` (not a signal number), `EPERM`.
    pub fn check_kill_permission(
        &self,
        sender: Option<TaskId>,
        sig: i32,
        from_user: bool,
        target: TaskId,
    ) -> Result<(), Errno> {
        if !valid_signal(sig) {
            return Err(Errno::EINVAL);
        }
        let Some(sender) = sender.filter(|_| from_user) else {
            return Ok(());
        };
        // same_thread_group(current, t)
        if sender != target && !self.kill_ok_by_cred(sender, target) {
            // SIGCONT may cross uids inside one session.
            let same_session = i32::from(crate::signal::SIGCONT) == sig
                && self
                    .task_pid_type(target, PidType::Sid)
                    .is_some_and(|sid| self.task_pid_type(sender, PidType::Sid) == Some(sid));
            if !same_session {
                return Err(Errno::EPERM);
            }
        }
        Ok(())
    }

    fn deliver(
        &mut self,
        sender: Option<TaskId>,
        target: TaskId,
        sig: i32,
        info: SigInfo,
        to: SendTo,
        w: &mut dyn Waker,
    ) -> Result<(), Errno> {
        // `do_send_sig_info`: a released task has no sighand to lock.
        let sig = u8::try_from(sig).map_err(|_| Errno::EINVAL)?;
        if sig == 0 || sig > NSIG {
            return Ok(());
        }
        let kind = match to {
            SendTo::Thread => Target::Thread,
            SendTo::Group => Target::Process,
        };
        // `task_curr(target)`: a task signalling itself (a single CPU runs one
        // task, and the sender is it).
        let mut state = self
            .signal_state_as(target, sender == Some(target))
            .ok_or(Errno::ESRCH)?;
        let was_stopped = state.me.jobctl & JOBCTL_STOPPED != 0;
        let result = state.send_signal(sig, info, kind);
        // `signal_wake_up(t, fatal)`: a fatal signal also wakes a stopped
        // task; `SIGCONT` ended the stop in `prepare_signal`.
        let resume = state.fatal_signal_pending();
        let continued = was_stopped && state.me.jobctl & JOBCTL_STOPPED == 0;
        let sched = self.sched_of(target);
        if continued {
            w.wake_stopped(target, sched);
        }
        w.signal_wake(target, sched, resume);
        result
    }

    /// `group_send_sig_info(sig, info, p, type)`: permission, then delivery
    /// (`sig == 0` only probes).
    ///
    /// # Errors
    /// `EINVAL`, `EPERM`, `ESRCH` for a released task, `EAGAIN` for a
    /// real-time signal that cannot be queued.
    pub fn group_send_sig_info(
        &mut self,
        sender: Option<TaskId>,
        sig: i32,
        info: SigInfo,
        target: TaskId,
        to: SendTo,
        w: &mut dyn Waker,
    ) -> Result<(), Errno> {
        self.check_kill_permission(sender, sig, info.code <= 0, target)?;
        if sig == 0 {
            return Ok(());
        }
        self.deliver(sender, target, sig, info, to, w)
    }

    /// `__kill_pgrp_info`: success if any member accepted the signal, else
    /// the last error, `ESRCH` for an empty group. Members are visited newest
    /// first (`do_each_pid_task`).
    ///
    /// # Errors
    /// The last member's error when no member accepted the signal, `ESRCH`
    /// for an empty or missing group.
    pub fn kill_pgrp_info(
        &mut self,
        sender: Option<TaskId>,
        sig: i32,
        info: SigInfo,
        pgrp: Option<PidId>,
        w: &mut dyn Waker,
    ) -> Result<(), Errno> {
        let mut ret = Err(Errno::ESRCH);
        let Some(pgrp) = pgrp else { return ret };
        let mut index = 0;
        // Membership cannot change while the signals are queued (nothing here
        // creates or exits tasks), so walk by position without a collected list.
        loop {
            let Some(member) = self
                .pid(pgrp)
                .and_then(|p| p.tasks(PidType::Pgid).nth(index))
            else {
                return ret;
            };
            index += 1;
            let err = self.group_send_sig_info(sender, sig, info, member, SendTo::Group, w);
            if ret.is_err() {
                ret = err;
            }
        }
    }

    /// `__kill_pgrp_info(sig, SEND_SIG_PRIV, pgrp)`: the kernel signalling a
    /// group (`SI_KERNEL`, no permission check).
    ///
    /// # Errors
    /// As [`Tasklist::kill_pgrp_info`].
    pub fn kill_pgrp_priv(&mut self, pgrp: PidId, sig: u8, w: &mut dyn Waker) -> Result<(), Errno> {
        self.kill_pgrp_info(None, i32::from(sig), SigInfo::kernel(sig), Some(pgrp), w)
    }

    /// `kill_pid_info_type` for a pid that may name no task.
    ///
    /// # Errors
    /// `ESRCH` when the pid names no task, else as [`Tasklist::group_send_sig_info`].
    pub fn kill_pid_info(
        &mut self,
        sender: Option<TaskId>,
        sig: i32,
        info: SigInfo,
        pid: Option<PidId>,
        w: &mut dyn Waker,
    ) -> Result<(), Errno> {
        let target = pid
            .and_then(|pid| self.pid_task(pid, PidType::Pid))
            .ok_or(Errno::ESRCH)?;
        self.group_send_sig_info(sender, sig, info, target, SendTo::Group, w)
    }

    /// `kill_proc_info(sig, info, pid)` (`rt_sigqueueinfo`): the process `pid`
    /// (`ESRCH` for 0, a negative number or a missing one).
    ///
    /// # Errors
    /// As [`Tasklist::kill_pid_info`].
    pub fn kill_proc_info(
        &mut self,
        sender: TaskId,
        sig: i32,
        info: SigInfo,
        pid: i32,
        w: &mut dyn Waker,
    ) -> Result<(), Errno> {
        let pid = if pid > 0 { self.find_vpid(pid) } else { None };
        self.kill_pid_info(Some(sender), sig, info, pid, w)
    }

    /// `do_send_specific(tgid, pid, sig, info)` (`tkill`, `tgkill`,
    /// `rt_tgsigqueueinfo`): the thread `tid`, which must belong to group
    /// `tgid` when `tgid > 0`; permission, then the thread's private queue.
    ///
    /// # Errors
    /// `ESRCH` for no such thread or a group mismatch, else as
    /// [`Tasklist::group_send_sig_info`].
    #[allow(clippy::similar_names)]
    pub fn send_specific(
        &mut self,
        sender: TaskId,
        tgid: i32,
        tid: i32,
        sig: i32,
        info: SigInfo,
        w: &mut dyn Waker,
    ) -> Result<(), Errno> {
        let target = self
            .find_task_by_vpid(tid)
            .filter(|&t| tgid <= 0 || self.task_tgid_vnr(t) == tgid)
            .ok_or(Errno::ESRCH)?;
        self.group_send_sig_info(Some(sender), sig, info, target, SendTo::Thread, w)
    }

    /// `kill_something_info(sig, info, pid)`: `pid > 0` one process, `0` the
    /// caller's group, `-1` every process but init and the caller's own group,
    /// `< -1` the group `-pid`.
    ///
    /// # Errors
    /// `ESRCH`, `EPERM`, `EINVAL` and `EAGAIN` as the delivery reports.
    pub fn kill_something_info(
        &mut self,
        sender: TaskId,
        sig: i32,
        info: SigInfo,
        pid: i32,
        w: &mut dyn Waker,
    ) -> Result<(), Errno> {
        if pid > 0 {
            let target = self.find_vpid(pid);
            return self.kill_pid_info(Some(sender), sig, info, target, w);
        }
        // -INT_MIN is undefined.
        if pid == i32::MIN {
            return Err(Errno::ESRCH);
        }
        if pid != -1 {
            let pgrp = if pid == 0 {
                self.task_pid_type(sender, PidType::Pgid)
            } else {
                self.find_vpid(-pid)
            };
            return self.kill_pgrp_info(Some(sender), sig, info, pgrp, w);
        }
        let (mut retval, mut count) = (Ok(()), 0usize);
        let mut index = 0;
        // `for_each_process`: creation order; the list does not change while
        // signals are queued.
        loop {
            let Some(p) = self.processes().nth(index) else {
                break;
            };
            index += 1;
            if self.task_pid_vnr(p) > 1 && p != sender {
                let err = self.group_send_sig_info(Some(sender), sig, info, p, SendTo::Group, w);
                count += 1;
                if err != Err(Errno::EPERM) {
                    retval = err;
                }
            }
        }
        if count == 0 {
            Err(Errno::ESRCH)
        } else {
            retval
        }
    }
}
