// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: include/linux/sched.h
// (`struct task_struct` fields `real_parent`, `children`, `exit_state`,
// `exit_code`, `exit_signal`, `flags`, `jobctl`, `pid_links`, `PF_*`),
// include/linux/sched/signal.h (`struct signal_struct`, `SIGNAL_*`),
// include/linux/sched/jobctl.h, kernel/fork.c (`copy_process` 2015-2480:
// the `tasklist_lock` publication block; `fork_init` `max_threads`),
// kernel/exit.c (`release_task`, `__unhash_process`), kernel/pid.c
// (`alloc_pid`, `free_pid`, `attach_pid`, `detach_pid`, `change_pid`,
// `pid_nr_ns`, `find_task_by_vpid`), include/linux/sched/signal.h
// (`is_global_init`, `task_pgrp`, `task_session`, `for_each_process`). All
// GPL-2.0-only.
// Transformation: `tasklist_lock`, `siglock` and `pidmap_lock` collapse into
// the caller's exclusion (`&mut Tasklist`); tasks and pids are arena slots
// addressed by generation-checked ids, not RCU pointers; one thread per thread
// group, so `signal_struct`, `sighand_struct` and the task's signal fields are
// the [`TaskSignals`] owned inline; no ptrace, no subreapers, one PID
// namespace. `init_task` (the idle task, pid 0, parent of init) is not a
// task here: init has `real_parent == None` and `getppid` reports 0.
#![forbid(unsafe_code)]
//! The task list: parentage, pids, process groups and sessions, credentials
//! snapshots and the publish/release protocol.
//!
//! # Contract
//! * Context: task or interrupt context with the caller's lock held; this type
//!   has no lock. The binary keeps it inside its process lock until the
//!   `TASKLIST` class of `docs/subsystems/process.md` exists.
//! * Allocation: fallible and reserve-before-publish. Everything that can
//!   fail during [`Tasklist::fork`] is allocated before the first link is
//!   made; [`Tasklist::release_task`] and every `change_pid` never allocate.
//! * Ids: a [`TaskId`] stops resolving when its task is released. Callers hold
//!   the id of `current` for as long as the task is not released.
//! * Cross-task readers (`kill`, `wait`) use [`CredSnapshot`], never the
//!   owner's `Attributes`: the owner may be gone.

use super::{
    attrs::Cred,
    pid::{PID_MAX_DEFAULT, Pid, PidId, PidTable, PidType},
};
use crate::{
    arena::{Arena, Id},
    signal::{Ids, SIGCHLD, State, TaskSignals},
};
use alloc::{boxed::Box, vec::Vec};
use syscalls::Errno;

pub type TaskId = Id<TaskStruct>;

/// `PF_EXITING`: the task is being torn down (set by `exit_signals`).
pub const PF_EXITING: u32 = 0x4;
/// `PF_FORKNOEXEC`: forked but has not exec'd (`setpgid` consults it).
pub const PF_FORKNOEXEC: u32 = 0x40;
/// `PF_SIGNALED`: killed by a signal.
pub const PF_SIGNALED: u32 = 0x400;

/// `JOBCTL_STOPPED`: mirrors `__TASK_STOPPED`, set by `do_signal_stop`. The
/// scheduler's task state is the authority once it exists; the wait code reads
/// this bit as `task_is_stopped()`.
pub const JOBCTL_STOPPED: u32 = 1 << 26;

/// `exit_state` (`EXIT_ZOMBIE`, `EXIT_DEAD`; `EXIT_TRACE` needs ptrace).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitState {
    /// `exit_state == 0`.
    Live,
    /// Exited, waiting for its parent to reap it.
    Zombie,
    /// Reaped or auto-reaped; `release_task` follows at once.
    Dead,
}

/// The parts of a task's credentials that another task reads: `kill`
/// permission, the `si_uid` of `SIGCHLD` and of `waitid`. Published at fork,
/// at exec and after every credential-changing syscall
/// ([`Tasklist::publish_cred`]); a test pins that no such syscall exists
/// without the publish call (`syscall::process` tests).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CredSnapshot {
    pub uid: u32,
    pub euid: u32,
    pub suid: u32,
    /// `ns_capable(CAP_KILL)`.
    pub cap_kill: bool,
    /// `capable(CAP_SYS_RESOURCE)` (the `RLIMIT_NPROC` bypass).
    pub cap_sys_resource: bool,
}

impl CredSnapshot {
    /// Snapshot of `cred`. shortcut: capability sets are not modelled
    /// (nothing can drop or add one: every credential syscall stops the kernel
    /// loudly), so a task holds every capability iff its effective uid is 0.
    /// Replace the two booleans with the real `cap_effective` bits with the
    /// first syscall that changes either.
    #[must_use]
    pub const fn of(cred: &Cred) -> Self {
        let root = cred.euid == 0;
        Self {
            uid: cred.uid,
            euid: cred.euid,
            suid: cred.suid,
            cap_kill: root,
            cap_sys_resource: root,
        }
    }
}

/// `struct task_struct` (the thread-group leader of a one-thread group) with
/// the parts of `signal_struct` that are not signal queues.
pub struct TaskStruct {
    /// `pid_links[]`: `PIDTYPE_PID`, `TGID`, `PGID`, `SID`.
    pub(super) pids: [Option<PidId>; 4],
    pub(super) real_parent: Option<TaskId>,
    /// `children` (head and tail) and `sibling` (links): the intrusive list
    /// of Linux, in `list_add_tail` order, which is the order `wait`
    /// considers children. Intrusive so that reparenting at exit (a splice)
    /// cannot fail to allocate.
    pub(super) first_child: Option<TaskId>,
    pub(super) last_child: Option<TaskId>,
    pub(super) prev_sibling: Option<TaskId>,
    pub(super) next_sibling: Option<TaskId>,
    pub exit_state: ExitState,
    /// `exit_code` (the `wait` status format).
    pub exit_code: u32,
    /// `exit_signal` (always `SIGCHLD`: no `clone` exit-signal argument yet).
    pub exit_signal: u8,
    /// `PF_*`.
    pub flags: u32,
    /// `jobctl` (`JOBCTL_*`).
    pub jobctl: u32,
    pub cred: CredSnapshot,
    /// `signal->leader`: a session leader.
    pub session_leader: bool,
    /// Own CPU time in nanoseconds, folded in by the owner before it exits
    /// (`task_cputime`).
    pub utime_ns: u64,
    pub stime_ns: u64,
    /// `signal->cutime`/`cstime`: the times of reaped children.
    pub cutime_ns: u64,
    pub cstime_ns: u64,
    /// `sighand` + `signal_struct` + the task's signal fields.
    pub(super) signals: Box<TaskSignals>,
}

/// What [`Tasklist::fork`] needs from the forking owner.
#[derive(Clone, Copy, Debug)]
pub struct ForkParams {
    /// `RLIMIT_SIGPENDING` of the child (copied from the parent's limits).
    pub rlimit_sigpending: u64,
    /// `RLIMIT_NPROC`'s soft limit: the `copy_process` `EAGAIN` check is
    /// bypassed for `CAP_SYS_RESOURCE`/`CAP_SYS_ADMIN` (root).
    pub rlimit_nproc: u64,
}

pub struct Tasklist {
    pub(super) tasks: Arena<TaskStruct>,
    pub(super) pids: Arena<Pid>,
    pub(super) table: PidTable,
    /// `init_struct_pid`: number 0, never freed, the group and session of init
    /// and of every task that has not called `setsid`/`setpgid` yet.
    init_pid: PidId,
    /// `pid_ns->child_reaper`.
    pub(super) child_reaper: TaskId,
    /// `for_each_process` order (`tasks` list order: creation order).
    order: Vec<TaskId>,
    nr_threads: u32,
    max_threads: u32,
}

impl Tasklist {
    /// The task list at `kernel_init`: pid 1 with `init_struct_pid` as its
    /// group and session, `SIGNAL_UNKILLABLE`, forked from the idle task.
    ///
    /// # Errors
    /// `ENOMEM`.
    pub fn new(
        max_threads: u32,
        cred: &Cred,
        rlimit_sigpending: u64,
    ) -> Result<(Self, TaskId), Errno> {
        let mut pids = Arena::new();
        let init_pid = pids.try_insert(Pid::new(0)).map_err(|_| Errno::ENOMEM)?;
        let mut list = Self {
            tasks: Arena::new(),
            pids,
            table: PidTable::new(PID_MAX_DEFAULT),
            init_pid,
            child_reaper: TaskId::DANGLING,
            order: Vec::new(),
            nr_threads: 0,
            max_threads,
        };
        let signals =
            Box::try_new(TaskSignals::new_init(rlimit_sigpending)).map_err(|_| Errno::ENOMEM)?;
        let own = list.alloc_pid()?;
        let init = list.publish(
            TaskStruct {
                pids: [Some(own), Some(own), Some(init_pid), Some(init_pid)],
                real_parent: None,
                first_child: None,
                last_child: None,
                prev_sibling: None,
                next_sibling: None,
                exit_state: ExitState::Live,
                exit_code: 0,
                exit_signal: SIGCHLD,
                flags: 0,
                jobctl: 0,
                cred: CredSnapshot::of(cred),
                session_leader: false,
                utime_ns: 0,
                stime_ns: 0,
                cutime_ns: 0,
                cstime_ns: 0,
                signals,
            },
            None,
        )?;
        list.child_reaper = init;
        Ok((list, init))
    }

    /// `alloc_pid`: a new `struct pid` with a number, attached to nothing.
    ///
    /// # Errors
    /// `EAGAIN` (namespace full), `ENOMEM`.
    pub fn alloc_pid(&mut self) -> Result<PidId, Errno> {
        let id = self
            .pids
            .try_insert(Pid::new(0))
            .map_err(|_| Errno::ENOMEM)?;
        match self.table.alloc(id) {
            Ok(nr) => {
                if let Some(pid) = self.pids.get_mut(id) {
                    pid.nr = nr;
                }
                Ok(id)
            }
            Err(errno) => {
                self.pids.remove(id);
                Err(errno)
            }
        }
    }

    /// The `tasklist_lock` block of `copy_process`: link a fully built task
    /// into the PID/TGID/PGID/SID lists, its parent's `children` and the task
    /// list. Everything that allocates happens first; the links cannot fail.
    fn publish(&mut self, task: TaskStruct, parent: Option<TaskId>) -> Result<TaskId, Errno> {
        // Reserve every vector the links will push into.
        self.order.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
        if let Some(parent) = parent
            && self.tasks.get(parent).is_none()
        {
            return Err(Errno::ESRCH);
        }
        for (ty, pid) in PID_TYPES.into_iter().zip(task.pids) {
            let pid = pid.ok_or(Errno::EINVAL)?;
            self.pids.get_mut(pid).ok_or(Errno::ESRCH)?.reserve(ty)?;
        }
        let links = task.pids;
        let id = self.tasks.try_insert(task).map_err(|_| Errno::ENOMEM)?;
        for (ty, pid) in PID_TYPES.into_iter().zip(links) {
            if let Some(pid) = pid.and_then(|pid| self.pids.get_mut(pid)) {
                pid.attach(ty, id);
            }
        }
        if let Some(parent) = parent {
            self.list_add_tail(parent, id);
        }
        assert!(self.order.push_within_capacity(id).is_ok());
        self.nr_threads += 1;
        Ok(id)
    }

    /// `copy_process`' publication (`fork`, no `CLONE_*` sharing): a child of
    /// `parent` in its process group and session, `exit_signal = SIGCHLD`,
    /// `PF_FORKNOEXEC`, the parent's credentials and, as a shortcut, a *default*
    /// signal state (see the comment at the allocation).
    ///
    /// Order of failures as in Linux: the `max_threads`/`RLIMIT_NPROC` check
    /// (`EAGAIN`), then pid allocation (`EAGAIN`, `ENOMEM`); a pending fatal
    /// signal (`EINTR`) is the caller's to check before this call (it holds
    /// the signal state of `current`).
    ///
    /// # Errors
    /// `EAGAIN`, `ENOMEM`, `ESRCH` for a stale or exiting parent.
    pub fn fork(&mut self, parent: TaskId, params: ForkParams) -> Result<TaskId, Errno> {
        let p = self.tasks.get(parent).ok_or(Errno::ESRCH)?;
        if p.exit_state != ExitState::Live {
            return Err(Errno::ESRCH);
        }
        let (pgid, sid, cred) = (p.pids[2], p.pids[3], p.cred);
        // copy_process: `nr_threads >= max_threads` is EAGAIN for everyone;
        // RLIMIT_NPROC is waived with CAP_SYS_RESOURCE (shortcut T9: Linux
        // counts per-user ucounts).
        if self.nr_threads >= self.max_threads {
            return Err(Errno::EAGAIN);
        }
        if !cred.cap_sys_resource && u64::from(self.nr_threads) >= params.rlimit_nproc {
            return Err(Errno::EAGAIN);
        }
        // shortcut: default dispositions, empty mask and reset altstack, where
        // `copy_process` copies the parent's actions and blocked mask
        // (`copy_sighand`, `dup_task_struct`), keeps the altstack unless
        // `CLONE_VM`, and clears only pending signals and the itimer; the
        // fork lane must take the parent's signal state before wiring `fork`.
        let signals =
            Box::try_new(TaskSignals::new(params.rlimit_sigpending)).map_err(|_| Errno::ENOMEM)?;
        let own = self.alloc_pid()?;
        let task = TaskStruct {
            pids: [Some(own), Some(own), pgid, sid],
            real_parent: Some(parent),
            first_child: None,
            last_child: None,
            prev_sibling: None,
            next_sibling: None,
            exit_state: ExitState::Live,
            exit_code: 0,
            exit_signal: SIGCHLD,
            flags: PF_FORKNOEXEC,
            jobctl: 0,
            cred,
            session_leader: false,
            utime_ns: 0,
            stime_ns: 0,
            cutime_ns: 0,
            cstime_ns: 0,
            signals,
        };
        match self.publish(task, Some(parent)) {
            Ok(id) => Ok(id),
            Err(errno) => {
                self.free_if_unused(own);
                Err(errno)
            }
        }
    }

    /// `release_task`: the dead task leaves the lists, its pids are freed when
    /// nothing else is attached, its slot is freed and its id stops
    /// resolving. The task has no children left (`forget_original_parent`
    /// handed them to the reaper at its exit).
    ///
    /// # Panics
    /// If the task is the child reaper (init is never released).
    pub fn release_task(&mut self, id: TaskId) {
        assert!(id != self.child_reaper, "init released");
        let Some(task) = self.tasks.remove(id) else {
            return;
        };
        debug_assert!(task.first_child.is_none(), "release_task with children");
        for (ty, pid) in PID_TYPES.into_iter().zip(task.pids) {
            if let Some(pid) = pid {
                if let Some(p) = self.pids.get_mut(pid) {
                    p.detach(ty, id);
                }
                self.free_if_unused(pid);
            }
        }
        if let Some(parent) = task.real_parent {
            self.list_unlink(parent, id, task.prev_sibling, task.next_sibling);
        }
        self.order.retain(|&t| t != id);
        self.nr_threads -= 1;
    }

    /// `free_pid` once the last link of every type is gone. `init_struct_pid`
    /// is never freed.
    pub(super) fn free_if_unused(&mut self, id: PidId) {
        if id == self.init_pid {
            return;
        }
        if self.pids.get(id).is_some_and(Pid::unused)
            && let Some(pid) = self.pids.remove(id)
        {
            self.table.free(pid.nr);
        }
    }

    // ---- lookup --------------------------------------------------------------

    #[must_use]
    pub fn task(&self, id: TaskId) -> Option<&TaskStruct> {
        self.tasks.get(id)
    }

    pub fn task_mut(&mut self, id: TaskId) -> Option<&mut TaskStruct> {
        self.tasks.get_mut(id)
    }

    /// `pid_ns->child_reaper`: global init.
    #[must_use]
    pub const fn child_reaper(&self) -> TaskId {
        self.child_reaper
    }

    /// `init_struct_pid`.
    #[must_use]
    pub const fn init_struct_pid(&self) -> PidId {
        self.init_pid
    }

    /// Live and zombie tasks, `nr_threads`.
    #[must_use]
    pub const fn nr_threads(&self) -> u32 {
        self.nr_threads
    }

    /// `for_each_process`: creation order.
    pub fn processes(&self) -> impl Iterator<Item = TaskId> + '_ {
        self.order.iter().copied()
    }

    /// `find_vpid`.
    #[must_use]
    pub fn find_vpid(&self, nr: i32) -> Option<PidId> {
        self.table.find(nr)
    }

    #[must_use]
    pub fn pid(&self, id: PidId) -> Option<&Pid> {
        self.pids.get(id)
    }

    /// `pid_task(pid, ty)`.
    #[must_use]
    pub fn pid_task(&self, pid: PidId, ty: PidType) -> Option<TaskId> {
        self.pids.get(pid)?.first(ty)
    }

    /// `find_task_by_vpid`.
    #[must_use]
    pub fn find_task_by_vpid(&self, nr: i32) -> Option<TaskId> {
        self.pid_task(self.find_vpid(nr)?, PidType::Pid)
    }

    /// `task_pid_type(task, ty)`.
    #[must_use]
    pub fn task_pid_type(&self, task: TaskId, ty: PidType) -> Option<PidId> {
        self.tasks.get(task)?.pids[ty as usize]
    }

    /// `pid_vnr`: the number of a pid, 0 for `init_struct_pid`.
    #[must_use]
    pub fn pid_vnr(&self, pid: Option<PidId>) -> i32 {
        pid.and_then(|pid| self.pids.get(pid)).map_or(0, |p| p.nr)
    }

    /// `task_pid_vnr`.
    #[must_use]
    pub fn task_pid_vnr(&self, task: TaskId) -> i32 {
        self.pid_vnr(self.task_pid_type(task, PidType::Pid))
    }

    /// `task_tgid_vnr`.
    #[must_use]
    pub fn task_tgid_vnr(&self, task: TaskId) -> i32 {
        self.pid_vnr(self.task_pid_type(task, PidType::Tgid))
    }

    /// `task_pgrp_vnr`.
    #[must_use]
    pub fn task_pgrp_vnr(&self, task: TaskId) -> i32 {
        self.pid_vnr(self.task_pid_type(task, PidType::Pgid))
    }

    /// `task_session_vnr`.
    #[must_use]
    pub fn task_session_vnr(&self, task: TaskId) -> i32 {
        self.pid_vnr(self.task_pid_type(task, PidType::Sid))
    }

    /// `getppid`: `task_tgid_vnr(real_parent)`, 0 for the child of the idle
    /// task.
    #[must_use]
    pub fn task_ppid_vnr(&self, task: TaskId) -> i32 {
        self.tasks
            .get(task)
            .and_then(|t| t.real_parent)
            .map_or(0, |parent| self.task_tgid_vnr(parent))
    }

    /// `is_global_init`.
    #[must_use]
    pub fn is_global_init(&self, task: TaskId) -> bool {
        self.task_tgid_vnr(task) == 1
    }

    /// `current->real_parent`.
    #[must_use]
    pub fn real_parent(&self, task: TaskId) -> Option<TaskId> {
        self.tasks.get(task)?.real_parent
    }

    /// `list_for_each_entry(p, &task->children, sibling)`.
    pub fn children(&self, task: TaskId) -> impl Iterator<Item = TaskId> + '_ {
        let mut next = self.tasks.get(task).and_then(|t| t.first_child);
        core::iter::from_fn(move || {
            let current = next?;
            next = self.tasks.get(current).and_then(|t| t.next_sibling);
            Some(current)
        })
    }

    /// `list_add_tail(&child->sibling, &parent->children)`.
    fn list_add_tail(&mut self, parent: TaskId, child: TaskId) {
        let tail = self.tasks.get(parent).and_then(|p| p.last_child);
        if let Some(c) = self.tasks.get_mut(child) {
            c.prev_sibling = tail;
            c.next_sibling = None;
        }
        match tail.and_then(|t| self.tasks.get_mut(t)) {
            Some(t) => t.next_sibling = Some(child),
            None => {
                if let Some(p) = self.tasks.get_mut(parent) {
                    p.first_child = Some(child);
                }
            }
        }
        if let Some(p) = self.tasks.get_mut(parent) {
            p.last_child = Some(child);
        }
    }

    /// `list_del(&child->sibling)` from `parent`'s list, given the links the
    /// child had.
    fn list_unlink(
        &mut self,
        parent: TaskId,
        child: TaskId,
        prev: Option<TaskId>,
        next: Option<TaskId>,
    ) {
        match prev.and_then(|p| self.tasks.get_mut(p)) {
            Some(p) => p.next_sibling = next,
            None => {
                if let Some(p) = self.tasks.get_mut(parent)
                    && p.first_child == Some(child)
                {
                    p.first_child = next;
                }
            }
        }
        match next.and_then(|n| self.tasks.get_mut(n)) {
            Some(n) => n.prev_sibling = prev,
            None => {
                if let Some(p) = self.tasks.get_mut(parent)
                    && p.last_child == Some(child)
                {
                    p.last_child = prev;
                }
            }
        }
    }

    /// `list_splice_tail_init(&from->children, &to->children)`: O(1), no
    /// allocation. The `real_parent` of each moved child is the caller's.
    pub(super) fn list_splice_tail(&mut self, from: TaskId, to: TaskId) {
        let Some(f) = self.tasks.get_mut(from) else {
            return;
        };
        let (first, last) = (f.first_child.take(), f.last_child.take());
        let (Some(first), Some(last)) = (first, last) else {
            return;
        };
        let to_last = self.tasks.get(to).and_then(|t| t.last_child);
        if let Some(c) = self.tasks.get_mut(first) {
            c.prev_sibling = to_last;
        }
        match to_last.and_then(|t| self.tasks.get_mut(t)) {
            Some(t) => t.next_sibling = Some(first),
            None => {
                if let Some(t) = self.tasks.get_mut(to) {
                    t.first_child = Some(first);
                }
            }
        }
        if let Some(t) = self.tasks.get_mut(to) {
            t.last_child = Some(last);
        }
    }

    // ---- signal state ---------------------------------------------------------

    /// The ids a signal sent by `task` carries (derived, not stored twice).
    #[must_use]
    pub fn signal_ids(&self, task: TaskId) -> Option<Ids> {
        let t = self.tasks.get(task)?;
        Some(Ids {
            pid: self.task_pid_vnr(task),
            tgid: self.task_tgid_vnr(task),
            uid: t.cred.uid,
            global_init: self.is_global_init(task),
        })
    }

    /// The `State` view of `task`'s signal objects.
    pub fn signal_state(&mut self, task: TaskId) -> Option<State<'_>> {
        let ids = self.signal_ids(task)?;
        Some(self.tasks.get_mut(task)?.signals.view(ids))
    }

    // ---- credentials ------------------------------------------------------------

    /// Publish `cred` as the snapshot cross-task readers see: at exec
    /// (`commit_creds`) and after every credential-changing syscall.
    pub fn publish_cred(&mut self, task: TaskId, cred: &Cred) {
        if let Some(t) = self.tasks.get_mut(task) {
            t.cred = CredSnapshot::of(cred);
        }
    }

    // ---- pid links --------------------------------------------------------------

    /// `change_pid`: re-attach `task` to `new` for a group/session link.
    /// `new` must have been [`Pid::reserve`]d for `ty`; the old pid is freed
    /// when nothing else is attached to it. A no-op if already attached.
    pub(super) fn change_pid(&mut self, task: TaskId, ty: PidType, new: PidId) {
        let Some(t) = self.tasks.get_mut(task) else {
            return;
        };
        let old = t.pids[ty as usize].replace(new);
        if old == Some(new) {
            return;
        }
        if let Some(p) = self.pids.get_mut(new) {
            p.attach(ty, task);
        }
        if let Some(old) = old {
            if let Some(p) = self.pids.get_mut(old) {
                p.detach(ty, task);
            }
            self.free_if_unused(old);
        }
    }

    pub(super) fn reserve_attach(&mut self, pid: PidId, ty: PidType) -> Result<(), Errno> {
        self.pids.get_mut(pid).ok_or(Errno::ESRCH)?.reserve(ty)
    }
}

/// The four link types in `pids[]` order.
const PID_TYPES: [PidType; 4] = [PidType::Pid, PidType::Tgid, PidType::Pgid, PidType::Sid];
