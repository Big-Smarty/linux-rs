// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: kernel/signal.c
// (`kill_ok_by_cred` 806-815, `check_kill_permission` 823-857,
// `group_send_sig_info` 1465-1477, `__kill_pgrp_info` 1485-1507,
// `kill_pid_info_type` 1509-1530, `kill_proc_info`, `kill_something_info`
// 1628-1665, `SYSCALL_DEFINE2(kill)` and `prepare_kill_siginfo` 4012-4032).
// All GPL-2.0-only.
// `prepare_signal` 895-968, `wants_signal` 970-985, `complete_signal`
// 987-1059, `do_send_sig_info`, `kill_pid_info`. All GPL-2.0-only.
// Transformation: no LSM or audit hook; a signal reaches the target's
// [`crate::signal::State`] through its [`super::tasklist::Tasklist`] slot;
// waking the target is [`super::exit::Waker::signal_wake`]. Kernel threads do
// not exist, so `kill(-1)` here reaches only user tasks. The stop and continue
// effects of a signal are `crate::signal::jobctl`'s; this file wakes what they
// release. `complete_signal` picks the thread to wake among the group's threads
// ([`Tasklist::send_signal_to`]); `task_sigpending(t)` is computed from the queues
// and masks ([`crate::signal::State::pending_without`]), not a stored `TIF_SIGPENDING`
// (shortcut: they differ only when an older shared signal waits for a thread that was
// not the one woken; upgrade with a per-thread flag).
#![forbid(unsafe_code)]
//! The `kill` family over the task list: target selection, permission and
//! delivery.

use super::{
    exit::Waker,
    pid::{PidId, PidType},
    tasklist::{TaskId, Tasklist},
};
use crate::signal::{
    NSIG, SIGALRM, SIGCONT, SIGKILL, State, info::SigInfo, jobctl::JOBCTL_STOPPED, sig_kernel_stop,
    state::Target, valid_signal,
};
use syscalls::Errno;

fn t_dumpable(list: &Tasklist, target: TaskId) -> bool {
    list.dumpable(target)
}

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

    /// `__ptrace_may_access(target, PTRACE_MODE_READ_REALCREDS)` for the task `caller`
    /// (kernel/ptrace.c:279-345): the same thread group; else the caller's *real* uid and gid
    /// (`FSCREDS` would use the filesystem ids) equal to the target's real, effective and saved
    /// ids, or `CAP_SYS_PTRACE`; and then a target whose address space is not dumpable needs the
    /// capability too.
    #[must_use]
    pub fn ptrace_may_access(&self, caller: TaskId, target: TaskId) -> bool {
        if self.same_thread_group(caller, target) {
            return true;
        }
        let (Some(c), Some(t)) = (self.task(caller), self.task(target)) else {
            return false;
        };
        let (c, t) = (c.cred, t.cred);
        let same = c.uid == t.euid
            && c.uid == t.suid
            && c.uid == t.uid
            && c.gid == t.egid
            && c.gid == t.sgid
            && c.gid == t.gid;
        c.cap_sys_ptrace || same && t_dumpable(self, target)
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
        if !self.same_thread_group(sender, target) && !self.kill_ok_by_cred(sender, target) {
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

    /// `send_signal_locked(sig, info, t, type)` and the wake-ups that follow it: the signal is
    /// generated for `target` (a thread: `PIDTYPE_PID`, or the group of which `target` is the
    /// preferred recipient: `PIDTYPE_TGID`), `prepare_signal` applies the job-control effects to
    /// every thread and drops what is ignored, the signal is queued, and `complete_signal`
    /// chooses the thread to wake (`wants_signal`: the target first, then the group's threads
    /// from `curr_target` on) or, when the signal is fatal to the group, starts the group exit
    /// and kills every thread. `curr` is the task running this code (`task_curr`): the sender,
    /// or `None` for a sender that is not a task (an interrupt, a parent that exits).
    ///
    /// # Errors
    /// `ESRCH` for a released task, `EAGAIN` for a real-time signal that cannot be queued.
    pub(super) fn send_signal_to(
        &mut self,
        curr: Option<TaskId>,
        target: TaskId,
        sig: u8,
        info: SigInfo,
        to: SendTo,
        w: &mut dyn Waker,
    ) -> Result<(), Errno> {
        if sig == 0 || sig > NSIG {
            return Ok(());
        }
        let kind = match to {
            SendTo::Thread => Target::Thread,
            SendTo::Group => Target::Process,
        };
        // prepare_signal(sig, p, force)
        let was_stopped;
        {
            let mut state = self
                .signal_state_as(target, curr == Some(target))
                .ok_or(Errno::ESRCH)?;
            was_stopped = state.me.jobctl & JOBCTL_STOPPED != 0;
            if !state.prepare(sig, State::forces(&info)) {
                // Dropped: ignored, or the group is dying. The stop and continue effects on
                // the target already happened.
                self.job_control_released(target, was_stopped, sig, curr, w);
                return Ok(());
            }
        }
        self.job_control_released(target, was_stopped, sig, curr, w);
        let queued = {
            let mut state = self
                .signal_state_as(target, curr == Some(target))
                .ok_or(Errno::ESRCH)?;
            state.enqueue(sig, info, kind)?
        };
        if queued {
            self.complete_signal(sig, target, to, curr, w);
        }
        Ok(())
    }

    /// The thread-wide half of `prepare_signal`'s stop and continue handling: the other
    /// threads' private queues and job-control bits, and the wake-up of every thread that a
    /// `SIGCONT` took out of a stop.
    fn job_control_released(
        &mut self,
        target: TaskId,
        target_was_stopped: bool,
        sig: u8,
        curr: Option<TaskId>,
        w: &mut dyn Waker,
    ) {
        if !(sig_kernel_stop(sig) || sig == SIGCONT) {
            return;
        }
        if sig == SIGCONT
            && target_was_stopped
            && self
                .task(target)
                .is_some_and(|t| t.thread.jobctl & JOBCTL_STOPPED == 0)
        {
            let sched = self.sched_of(target);
            w.wake_stopped(target, sched);
        }
        let mut index = 0;
        while let Some(t) = self.thread_at(target, index) {
            index += 1;
            if t == target {
                continue;
            }
            let released = self
                .signal_state_as(t, curr == Some(t))
                .is_some_and(|mut state| state.job_control_other_thread(sig));
            if released {
                let sched = self.sched_of(t);
                w.wake_stopped(t, sched);
            }
        }
    }

    /// `it_real_fn` for the thread group of `task`, run in the context of `task` (the thread
    /// that looks at the clock): the real interval timer is brought up to `now`, and an
    /// expiry sends `SIGALRM` to the group's *leader* (`kill_pid_info(SIGALRM, SEND_SIG_PRIV,
    /// leader_pid)`), whom `complete_signal` prefers; a thread that happens to run first does
    /// not take it unless the leader cannot (blocked, exiting).
    pub fn sync_timers(&mut self, task: TaskId, now: u64, w: &mut dyn Waker) {
        let fired = self.signal_state_as(task, true).is_some_and(|state| {
            state.sig.now_ns = now;
            state.sig.itimer.expire(now)
        });
        if fired {
            let leader = self.group_leader(task);
            // Only a real-time signal sent with `si_code < 0` can fail.
            let _ = self.send_signal_to(
                Some(task),
                leader,
                SIGALRM,
                SigInfo::kernel(SIGALRM),
                SendTo::Group,
                w,
            );
        }
    }

    /// `wants_signal(sig, t)`.
    fn wants_signal(&mut self, sig: u8, t: TaskId, curr: Option<TaskId>) -> bool {
        self.signal_state_as(t, curr == Some(t))
            .is_some_and(|state| {
                let before = state.pending_without(sig);
                state.wants_signal(sig, before)
            })
    }

    /// `complete_signal(sig, p, type)`: the signal is in a queue; find the thread to wake, and
    /// take the whole group down when the signal is fatal to it.
    fn complete_signal(
        &mut self,
        sig: u8,
        p: TaskId,
        to: SendTo,
        curr: Option<TaskId>,
        w: &mut dyn Waker,
    ) {
        // "Try the suggested task first (may or may not be the main thread)."
        let chosen = if self.wants_signal(sig, p, curr) {
            p
        } else if to == SendTo::Thread || self.thread_group_empty(p) {
            // "There is just one thread and it does not need to be woken. It will dequeue
            // unblocked signals before it runs again."
            return;
        } else {
            // "Otherwise try to find a suitable thread."
            let Some(start) = self.group_of(p).map(|g| g.curr_target) else {
                return;
            };
            let mut t = start;
            loop {
                if self.wants_signal(sig, t, curr) {
                    break;
                }
                t = self.next_thread(t);
                if t == start {
                    // "No thread needs to be woken. Any eligible threads will see the signal
                    // in the queue soon."
                    return;
                }
            }
            if let Some(g) = self.group_mut(p) {
                g.curr_target = t;
            }
            t
        };
        // "Found a killable thread. If the signal will be fatal, then start taking the whole
        // group down immediately."
        let fatal = self.signal_state(chosen).is_some_and(|state| {
            let blocked = state.me.real_blocked.contains(sig);
            state.fatal_to_group(sig, blocked)
        });
        if fatal {
            // "Start a group exit and wake everybody up. This way we don't have other
            // threads running and doing things after a slower thread has the fatal signal
            // pending."
            if let Some(mut state) = self.signal_state(chosen) {
                state.start_group_exit(u32::from(sig));
            }
            let mut index = 0;
            while let Some(t) = self.thread_at(p, index) {
                index += 1;
                if let Some(mut state) = self.signal_state(t) {
                    state.mark_killed();
                }
                self.signal_wake_up(t, true, w);
            }
            return;
        }
        // "The signal is already in the shared-pending queue. Tell the chosen thread to wake up
        // and dequeue it."
        self.signal_wake_up(chosen, sig == SIGKILL, w);
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
        let sig = u8::try_from(sig).map_err(|_| Errno::EINVAL)?;
        self.send_signal_to(sender, target, sig, info, to, w)
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
            if self.task_pid_vnr(p) > 1 && !self.same_thread_group(p, sender) {
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
