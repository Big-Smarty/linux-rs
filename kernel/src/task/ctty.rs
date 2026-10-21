// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: drivers/tty/tty_jobctrl.c
// (`proc_clear_tty`, `session_clear_tty` 138-148, `session_of_pgrp`, the
// `signal->tty` accesses), include/linux/sched/signal.h (`task_pgrp`,
// `task_session`), include/linux/pid.h (`get_pid`), kernel/pid.c (`pid_task`).
// All GPL-2.0.
// Transformation: `signal->tty` is the flag [`super::tasklist::Group`]`::ctty` (there is one
// terminal); a counted `struct pid *` is a [`PidRef`].
#![forbid(unsafe_code)]
//! The task list's side of controlling terminals.

use super::{
    exit::Waker,
    pid::{PidId, PidRef, PidType},
    tasklist::{TaskId, Tasklist},
};
use crate::signal::info::SigInfo;
use syscalls::Errno;

impl Tasklist {
    /// `get_pid(pid)`: a reference that outlives the pid's tasks.
    #[must_use]
    pub fn pid_ref(&self, pid: Option<PidId>) -> Option<PidRef> {
        let id = pid?;
        Some(PidRef {
            id,
            nr: self.pid(id)?.nr,
        })
    }

    /// `get_pid(task_pgrp(task))`.
    #[must_use]
    pub fn task_pgrp_ref(&self, task: TaskId) -> Option<PidRef> {
        self.pid_ref(self.task_pid_type(task, PidType::Pgid))
    }

    /// `get_pid(task_session(task))`.
    #[must_use]
    pub fn task_session_ref(&self, task: TaskId) -> Option<PidRef> {
        self.pid_ref(self.task_pid_type(task, PidType::Sid))
    }

    /// `current->signal->tty != NULL`.
    #[must_use]
    pub fn has_ctty(&self, task: TaskId) -> bool {
        self.group_of(task).is_some_and(|g| g.ctty)
    }

    /// Store `signal->tty` (set or cleared).
    pub fn set_ctty(&mut self, task: TaskId, on: bool) {
        if let Some(g) = self.group_mut(task) {
            g.ctty = on;
        }
    }

    /// `current->signal->leader`.
    #[must_use]
    pub fn is_session_leader(&self, task: TaskId) -> bool {
        self.group_of(task).is_some_and(|g| g.session_leader)
    }

    /// `proc_clear_tty`: `signal->tty = NULL`.
    pub fn proc_clear_tty(&mut self, task: TaskId) {
        self.set_ctty(task, false);
    }

    /// `signal->tty_old_pgrp`, read and cleared (`disassociate_ctty`).
    pub fn take_tty_old_pgrp(&mut self, task: TaskId) -> Option<PidRef> {
        self.group_mut(task)?.tty_old_pgrp.take()
    }

    /// Store `signal->tty_old_pgrp`.
    pub fn set_tty_old_pgrp(&mut self, task: TaskId, pgrp: Option<PidRef>) {
        if let Some(g) = self.group_mut(task) {
            g.tty_old_pgrp = pgrp;
        }
    }

    /// The tasks of a session, newest first (`do_each_pid_task(session,
    /// PIDTYPE_SID, p)`); empty when the session's pid is gone.
    pub fn session_members(&self, session: PidRef) -> impl Iterator<Item = TaskId> + '_ {
        self.pid(session.id)
            .into_iter()
            .flat_map(|p| p.tasks(PidType::Sid))
    }

    /// `session_clear_tty(session)`: every task of the session loses its
    /// controlling terminal.
    pub fn session_clear_tty(&mut self, session: Option<PidRef>) {
        let Some(session) = session else { return };
        let mut index = 0;
        loop {
            let Some(member) = self.session_members(session).nth(index) else {
                return;
            };
            index += 1;
            self.proc_clear_tty(member);
        }
    }

    /// `session_of_pgrp(pgrp)`: the session of the group's first member,
    /// falling back on the process the pid names (`gdb` needs it).
    #[must_use]
    pub fn session_of_pgrp(&self, pgrp: PidId) -> Option<PidId> {
        let p = self
            .pid_task(pgrp, PidType::Pgid)
            .or_else(|| self.pid_task(pgrp, PidType::Pid))?;
        self.task_pid_type(p, PidType::Sid)
    }

    /// `kill_pgrp(pgrp, sig, 1)` for a reference: `ESRCH` when the group has no
    /// member left.
    ///
    /// # Errors
    /// As `__kill_pgrp_info`.
    pub fn kill_pgrp_ref(&mut self, pgrp: PidRef, sig: u8, w: &mut dyn Waker) -> Result<(), Errno> {
        self.kill_pgrp_priv(pgrp.id, sig, w)
    }

    /// `send_signal_locked(sig, SEND_SIG_PRIV, p, PIDTYPE_TGID)`: the kernel sends
    /// `sig` to the process `task` (no permission check).
    pub fn send_sig_priv(&mut self, task: TaskId, sig: u8, w: &mut dyn Waker) {
        // The process accepts it or has already gone: the error is Linux's
        // ignored return value too.
        let _ = self.kill_task_priv(task, sig, w);
    }

    /// Parent of the pid of `task` in the pid table (`task_pid`), for tests.
    #[must_use]
    pub fn task_pid_ref(&self, task: TaskId) -> Option<PidRef> {
        self.pid_ref(self.task_pid_type(task, PidType::Pid))
    }

    fn kill_task_priv(&mut self, task: TaskId, sig: u8, w: &mut dyn Waker) -> Result<(), Errno> {
        self.group_send_sig_info(
            None,
            i32::from(sig),
            SigInfo::kernel(sig),
            task,
            super::kill::SendTo::Group,
            w,
        )
    }
}
