// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: kernel/sys.c (`getppid` 1016,
// `setpgid` 1114-1190, `do_getpgid` 1192-1214, `getpgid`, `getpgrp`, `getsid`
// 1229-1252, `set_special_pids` 1254-1263, `ksys_setsid` 1265-1302),
// kernel/fork.c and fs/exec.c (`PF_FORKNOEXEC` set by `copy_process` and
// cleared by `begin_new_exec`). All GPL-2.0-only.
// Transformation: no LSM hook (`security_task_*` allow); no `proc_clear_tty`
// (no controlling terminal: `signal->tty` does not exist), no
// `sched_autogroup_create_attach`, no connector event; the pid re-linking
// reserves its capacity first, so `ENOMEM` can replace success only when the
// heap is exhausted.
#![forbid(unsafe_code)]
//! Process groups and sessions: `setpgid`, `getpgid`, `getsid`, `setsid`.

use super::{
    pid::PidType,
    tasklist::{PF_FORKNOEXEC, TaskId, Tasklist},
};
use syscalls::Errno;

impl Tasklist {
    /// `setpgid(pid, pgid)` as `current` (`group_leader`) calls it; `pid` and
    /// `pgid` are the raw `pid_t`s.
    ///
    /// # Errors
    /// `EINVAL`, `ESRCH`, `EPERM`, `EACCES` (target already exec'd), `ENOMEM`.
    pub fn setpgid(&mut self, current: TaskId, pid: i32, group: i32) -> Result<(), Errno> {
        let pid = if pid == 0 {
            self.task_pid_vnr(current)
        } else {
            pid
        };
        let group = if group == 0 { pid } else { group };
        if group < 0 {
            return Err(Errno::EINVAL);
        }
        let p = self.find_task_by_vpid(pid).ok_or(Errno::ESRCH)?;
        // `thread_group_leader(p)` always holds: one thread per group.
        let task = self.task(p).ok_or(Errno::ESRCH)?;
        if task.real_parent == Some(current) {
            // A child of the caller.
            if self.task_pid_type(p, PidType::Sid) != self.task_pid_type(current, PidType::Sid) {
                return Err(Errno::EPERM);
            }
            if task.flags & PF_FORKNOEXEC == 0 {
                return Err(Errno::EACCES);
            }
        } else if p != current {
            return Err(Errno::ESRCH);
        }
        if task.session_leader {
            return Err(Errno::EPERM);
        }
        let own = self.task_pid_type(p, PidType::Pid).ok_or(Errno::ESRCH)?;
        let pgrp = if group == pid {
            own
        } else {
            let pgrp = self.find_vpid(group).ok_or(Errno::EPERM)?;
            let member = self.pid_task(pgrp, PidType::Pgid).ok_or(Errno::EPERM)?;
            if self.task_pid_type(member, PidType::Sid) != self.task_pid_type(current, PidType::Sid)
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
        let sid = self
            .task_pid_type(current, PidType::Pid)
            .ok_or(Errno::ESRCH)?;
        let session = self.pid_vnr(Some(sid));
        if self.task(current).ok_or(Errno::ESRCH)?.session_leader {
            return Err(Errno::EPERM);
        }
        // "Fail if a process group id already exists that equals the proposed
        // session id."
        if self.pid_task(sid, PidType::Pgid).is_some() {
            return Err(Errno::EPERM);
        }
        self.reserve_attach(sid, PidType::Sid)?;
        self.reserve_attach(sid, PidType::Pgid)?;
        if let Some(t) = self.task_mut(current) {
            t.session_leader = true;
        }
        // set_special_pids
        self.change_pid(current, PidType::Sid, sid);
        self.change_pid(current, PidType::Pgid, sid);
        Ok(session)
    }

    /// What `exec` commits for the process tree: `PF_FORKNOEXEC` is cleared
    /// (`begin_new_exec`) and the credentials are published
    /// (`commit_creds`).
    pub fn exec_committed(&mut self, task: TaskId, cred: &super::attrs::Cred) {
        if let Some(t) = self.task_mut(task) {
            t.flags &= !PF_FORKNOEXEC;
        }
        self.publish_cred(task, cred);
    }
}
