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
// addressed by generation-checked ids, not RCU pointers; a task is a thread,
// `signal_struct` is a [`Group`] and `sighand_struct` a [`Sighand`], each a
// counted arena slot shared by the tasks that point at it (`CLONE_THREAD`,
// `CLONE_SIGHAND`); the thread list is a vector, not an intrusive list; no
// ptrace, no subreapers, one PID namespace. `init_task` (the idle task, pid 0,
// parent of init) is not a task here: init has `real_parent == None` and
// `getppid` reports 0.
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
    pid::{PID_MAX_DEFAULT, Pid, PidId, PidRef, PidTable, PidType},
};
use crate::{
    arena::{Arena, Id},
    sched::SchedId,
    signal::{
        Ids, SIGCHLD, State, TaskSignals,
        state::{SigHand, SignalStruct, ThreadSignal},
    },
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
    /// The group ids (`/proc/<pid>` ownership and `ptrace_may_access`).
    pub gid: u32,
    pub egid: u32,
    pub sgid: u32,
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
            gid: cred.gid,
            egid: cred.egid,
            sgid: cred.sgid,
            cap_kill: root,
            cap_sys_resource: root,
        }
    }
}

pub type GroupId = Id<Group>;
pub type SighandId = Id<Sighand>;

/// `struct sighand_struct`: the dispositions, shared by the tasks that point at the slot
/// (`CLONE_SIGHAND`); `count` is `sighand->count`.
pub struct Sighand {
    pub(super) hand: Box<SigHand>,
    pub(super) count: u32,
}

/// `struct signal_struct`: what the tasks of one thread group share. `sig` holds the
/// signal-related fields ([`SignalStruct`]: the shared pending queue, group exit and stop
/// state, the interval timer); the rest is the thread list, the counters of
/// `synchronize_group_exit`/`do_exit`, the `exec` rendezvous (`de_thread`), the session and
/// terminal fields and the CPU times of finished threads and reaped children.
pub struct Group {
    pub(super) sig: Box<SignalStruct>,
    /// `thread_head`: the members in creation order (the leader first).
    pub(super) threads: Vec<TaskId>,
    /// `signal->live`: threads that have not gone through `exit_signals`.
    pub(super) live: u32,
    /// `signal->quick_threads`: threads that have not reached `synchronize_group_exit`.
    pub(super) quick_threads: u32,
    /// `signal->curr_target`: where `complete_signal` starts looking for a thread.
    pub(super) curr_target: TaskId,
    /// `signal->notify_count` (`de_thread`).
    pub(super) notify_count: i32,
    /// `signal->group_exec_task`.
    pub(super) exec_task: Option<TaskId>,
    /// `signal->leader`: a session leader.
    pub(super) session_leader: bool,
    /// `signal->tty != NULL`: the console tty is the controlling terminal (there is one tty, so
    /// no pointer). Inherited by `fork`, cleared by `setsid` and by the tty's hangup/release
    /// ([`Tasklist::session_clear_tty`]).
    pub(super) ctty: bool,
    /// `signal->tty_old_pgrp`: the foreground group of a terminal that was hung up under the
    /// session leader (`tty_signal_session_leader`).
    pub(super) tty_old_pgrp: Option<PidRef>,
    /// `signal->cutime`/`cstime`: the times of reaped children.
    pub(super) cutime_ns: u64,
    pub(super) cstime_ns: u64,
    /// `signal->utime`/`stime`: the times of threads that were released.
    pub(super) dead_utime_ns: u64,
    pub(super) dead_stime_ns: u64,
}

/// `struct task_struct` (one thread) with the pointers to the shared `signal_struct` and
/// `sighand_struct`.
pub struct TaskStruct {
    /// `pid_links[]`: `PIDTYPE_PID`, `TGID`, `PGID`, `SID`. Only a thread-group leader is
    /// linked into the last three (and `pid_task(pid, TGID|PGID|SID)` finds leaders only); the
    /// other threads answer `task_pgrp` and `task_session` through their leader.
    pub(super) pids: [Option<PidId>; 4],
    /// `group_leader`: the task itself for a leader.
    pub(super) group_leader: TaskId,
    /// `signal`.
    pub(super) group: GroupId,
    /// `sighand`.
    pub(super) sighand: SighandId,
    pub(super) real_parent: Option<TaskId>,
    /// `children` (head and tail) and `sibling` (links): the intrusive list
    /// of Linux, in `list_add_tail` order, which is the order `wait`
    /// considers children. Intrusive so that reparenting at exit (a splice)
    /// cannot fail to allocate. Only thread-group leaders are in a `children` list.
    pub(super) first_child: Option<TaskId>,
    pub(super) last_child: Option<TaskId>,
    pub(super) prev_sibling: Option<TaskId>,
    pub(super) next_sibling: Option<TaskId>,
    pub exit_state: ExitState,
    /// `exit_code` (the `wait` status format).
    pub exit_code: u32,
    /// `exit_signal`: `SIGCHLD` for `fork`, the `clone` argument otherwise.
    pub exit_signal: u8,
    /// `self_exec_id`: bumped by every `execve` ([`Tasklist::exec_committed`]),
    /// copied to a child by `dup_task_struct`.
    pub(super) self_exec_id: u64,
    /// `parent_exec_id`: the parent's `self_exec_id` when this task was
    /// cloned; `do_notify_parent` falls back to `SIGCHLD` if the parent has
    /// exec'd since (a custom exit signal does not cross a security domain).
    pub(super) parent_exec_id: u64,
    /// `PF_*`.
    pub flags: u32,
    /// `robust_list`: the user address `set_robust_list` registered (0: none); walked when
    /// the task leaves its address space. Per thread; a new task starts without one.
    pub robust_list: u64,
    pub cred: CredSnapshot,
    /// `get_dumpable(mm) == SUID_DUMP_USER` (`MMF_DUMPABLE`): copied by `fork`,
    /// set again by `execve`, cleared by `PR_SET_DUMPABLE` and by a change of
    /// the effective ids (`commit_creds`).
    pub dumpable: bool,
    /// Own CPU time in nanoseconds, folded in by the owner before it exits
    /// (`task_cputime`).
    pub utime_ns: u64,
    pub stime_ns: u64,
    /// The task's scheduling handle (the scheduler owns its state; the model
    /// only needs the handle to name whom to wake). `None` until the owner
    /// binds one with [`Tasklist::set_sched`].
    pub sched: Option<SchedId>,
    /// The task's own signal fields (`blocked`, the private pending queue, `jobctl`, the
    /// alternate stack).
    pub(super) thread: Box<ThreadSignal>,
}

/// What [`Tasklist::fork`] needs from the forking owner.
#[derive(Clone, Copy, Debug)]
pub struct ForkParams {
    /// `RLIMIT_SIGPENDING` of the child (copied from the parent's limits).
    pub rlimit_sigpending: u64,
    /// `RLIMIT_NPROC`'s soft limit: the `copy_process` `EAGAIN` check is
    /// bypassed for `CAP_SYS_RESOURCE`/`CAP_SYS_ADMIN` (root).
    pub rlimit_nproc: u64,
    /// `args->exit_signal`: the signal the parent receives when the child
    /// exits (`SIGCHLD` for `fork`; 0 for none; `clone` may name another,
    /// which makes the child a "clone child" for `__WCLONE`).
    pub exit_signal: u8,
    /// `CLONE_CLEAR_SIGHAND`: the child starts with default dispositions.
    pub clear_sighand: bool,
}

impl ForkParams {
    /// The limits of the forking task and the request's exit signal and
    /// signal-handler choice.
    #[must_use]
    pub fn of(attrs: &super::attrs::Attributes, request: &super::fork::ForkRequest) -> Self {
        Self {
            rlimit_sigpending: attrs.rlimits.get(super::attrs::RLIMIT_SIGPENDING).cur,
            rlimit_nproc: attrs.rlimits.get(super::attrs::RLIMIT_NPROC).cur,
            exit_signal: request.exit_signal,
            clear_sighand: request.clear_sighand,
        }
    }
}

/// What [`Tasklist::clone_task`] needs beyond [`ForkParams`]: which of the objects `copy_process`
/// shares instead of copying.
#[derive(Clone, Copy, Debug)]
pub struct CloneParams {
    pub fork: ForkParams,
    /// `CLONE_THREAD`: the child joins the caller's thread group (and shares its
    /// `signal_struct` and, necessarily, `sighand_struct`).
    pub thread: bool,
    /// `CLONE_SIGHAND`: the child shares the caller's dispositions.
    pub share_sighand: bool,
    /// `(clone_flags & (CLONE_VM | CLONE_VFORK)) == CLONE_VM`: `sas_ss_reset(p)`.
    pub reset_altstack: bool,
}

impl CloneParams {
    /// A plain `fork`/`vfork`/`clone` of a separate process.
    #[must_use]
    pub const fn process(fork: ForkParams) -> Self {
        Self {
            fork,
            thread: false,
            share_sighand: false,
            reset_altstack: false,
        }
    }

    /// The request's choices on top of the limits ([`ForkParams::of`]).
    #[must_use]
    pub fn of(attrs: &super::attrs::Attributes, request: &super::fork::ForkRequest) -> Self {
        Self {
            fork: ForkParams::of(attrs, request),
            thread: request.thread,
            share_sighand: request.share_sighand,
            reset_altstack: request.share_vm && !request.vfork,
        }
    }
}

pub struct Tasklist {
    pub(super) tasks: Arena<TaskStruct>,
    pub(super) groups: Arena<Group>,
    pub(super) sighands: Arena<Sighand>,
    pub(super) pids: Arena<Pid>,
    pub(super) table: PidTable,
    /// `init_struct_pid`: number 0, never freed, the group and session of init
    /// and of every task that has not called `setsid`/`setpgid` yet.
    init_pid: PidId,
    /// `pid_ns->child_reaper`.
    pub(super) child_reaper: TaskId,
    /// `for_each_process` order (`tasks` list order: creation order): thread-group leaders.
    pub(super) order: Vec<TaskId>,
    /// `nr_threads`: every task, not only leaders.
    nr_threads: u32,
    max_threads: u32,
    /// `total_forks`: tasks created since boot.
    forks: u64,
    /// What `/proc` mirrors changed ([`Tasklist::epoch`]).
    changes: ChangeLog,
}

/// How many recent changes [`ChangeLog`] remembers.
const CHANGE_LOG: usize = 64;

/// The pid numbers of the thread groups whose mirrored facts changed (a task
/// published or released, a credential snapshot published, the zombie
/// transition, a change of dumpability), newest last, in a ring of the last
/// [`CHANGE_LOG`]. A reader keeps the count it last saw and replays what came
/// after ([`Tasklist::changed_since`]); a reader that fell more than the ring
/// behind rebuilds from the task list instead. No allocation: nothing here can
/// fail, and nothing needs a consumer to keep it bounded.
#[derive(Clone, Copy)]
struct ChangeLog {
    ring: [i32; CHANGE_LOG],
    /// Changes recorded since boot.
    count: u64,
}

impl ChangeLog {
    /// The ring slot of change number `at`.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "the remainder is below CHANGE_LOG"
    )]
    const fn slot(at: u64) -> usize {
        (at % CHANGE_LOG as u64) as usize
    }

    fn note(&mut self, nr: i32) {
        self.ring[Self::slot(self.count)] = nr;
        self.count += 1;
    }

    fn since(&self, seen: u64) -> Option<impl Iterator<Item = i32> + '_> {
        let behind = self.count.checked_sub(seen)?;
        (behind <= CHANGE_LOG as u64)
            .then(|| (seen..self.count).map(|at| self.ring[Self::slot(at)]))
    }
}

impl Group {
    /// A thread group with no member yet; the creator links the first and sets
    /// `curr_target`.
    fn new(sig: Box<SignalStruct>) -> Self {
        Self {
            sig,
            threads: Vec::new(),
            live: 0,
            quick_threads: 0,
            curr_target: TaskId::DANGLING,
            notify_count: 0,
            exec_task: None,
            session_leader: false,
            ctty: false,
            tty_old_pgrp: None,
            cutime_ns: 0,
            cstime_ns: 0,
            dead_utime_ns: 0,
            dead_stime_ns: 0,
        }
    }
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
            groups: Arena::new(),
            sighands: Arena::new(),
            pids,
            table: PidTable::new(PID_MAX_DEFAULT),
            init_pid,
            child_reaper: TaskId::DANGLING,
            order: Vec::new(),
            nr_threads: 0,
            max_threads,
            forks: 0,
            changes: ChangeLog {
                ring: [0; CHANGE_LOG],
                count: 1,
            },
        };
        let (hand, sig, thread) = TaskSignals::new_init(rlimit_sigpending).into_parts();
        let hand = Box::try_new(hand).map_err(|_| Errno::ENOMEM)?;
        let sig = Box::try_new(sig).map_err(|_| Errno::ENOMEM)?;
        let thread = Box::try_new(thread).map_err(|_| Errno::ENOMEM)?;
        let sighand = list
            .sighands
            .try_insert(Sighand { hand, count: 0 })
            .map_err(|_| Errno::ENOMEM)?;
        let group = list
            .groups
            .try_insert(Group::new(sig))
            .map_err(|_| Errno::ENOMEM)?;
        let own = list.alloc_pid()?;
        let init = list.publish(
            TaskStruct {
                pids: [Some(own), Some(own), Some(init_pid), Some(init_pid)],
                group_leader: TaskId::DANGLING,
                group,
                sighand,
                real_parent: None,
                first_child: None,
                last_child: None,
                prev_sibling: None,
                next_sibling: None,
                exit_state: ExitState::Live,
                exit_code: 0,
                exit_signal: SIGCHLD,
                self_exec_id: 0,
                parent_exec_id: 0,
                flags: 0,
                robust_list: 0,
                cred: CredSnapshot::of(cred),
                dumpable: true,
                utime_ns: 0,
                stime_ns: 0,
                sched: None,
                thread,
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

    /// The `tasklist_lock` block of `copy_process` for a new thread-group leader: link a fully
    /// built task into the PID/TGID/PGID/SID lists, its parent's `children`, the task list and
    /// its (new, empty) group. Everything that allocates happens first; the links cannot fail.
    fn publish(&mut self, task: TaskStruct, parent: Option<TaskId>) -> Result<TaskId, Errno> {
        // Reserve every vector the links will push into.
        self.order.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
        if let Some(parent) = parent
            && self.tasks.get(parent).is_none()
        {
            return Err(Errno::ESRCH);
        }
        let group = task.group;
        self.groups
            .get_mut(group)
            .ok_or(Errno::ESRCH)?
            .threads
            .try_reserve(1)
            .map_err(|_| Errno::ENOMEM)?;
        for (ty, pid) in PID_TYPES.into_iter().zip(task.pids) {
            let pid = pid.ok_or(Errno::EINVAL)?;
            self.pids.get_mut(pid).ok_or(Errno::ESRCH)?.reserve(ty)?;
        }
        let links = task.pids;
        let sighand = task.sighand;
        let id = self.tasks.try_insert(task).map_err(|_| Errno::ENOMEM)?;
        if let Some(t) = self.tasks.get_mut(id) {
            t.group_leader = id;
        }
        if let Some(g) = self.groups.get_mut(group) {
            assert!(g.threads.push_within_capacity(id).is_ok());
            g.live = 1;
            g.quick_threads = 1;
            g.curr_target = id;
        }
        if let Some(h) = self.sighands.get_mut(sighand) {
            h.count += 1;
        }
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
        self.forks += 1;
        self.note_changed(id);
        Ok(id)
    }

    /// The `tasklist_lock` block of `copy_process` for a new thread of an existing group: only
    /// the `PIDTYPE_PID` link and the group's thread list.
    fn publish_thread(&mut self, task: TaskStruct) -> Result<TaskId, Errno> {
        let group = task.group;
        let own = task.pids[PidType::Pid as usize].ok_or(Errno::EINVAL)?;
        let sighand = task.sighand;
        let g = self.groups.get_mut(group).ok_or(Errno::ESRCH)?;
        if g.threads.try_reserve(1).is_err() {
            return Err(Errno::ENOMEM);
        }
        self.pids
            .get_mut(own)
            .ok_or(Errno::ESRCH)?
            .reserve(PidType::Pid)?;
        let id = self.tasks.try_insert(task).map_err(|_| Errno::ENOMEM)?;
        if let Some(g) = self.groups.get_mut(group) {
            assert!(g.threads.push_within_capacity(id).is_ok());
            g.live += 1;
            g.quick_threads += 1;
        }
        if let Some(h) = self.sighands.get_mut(sighand) {
            h.count += 1;
        }
        if let Some(pid) = self.pids.get_mut(own) {
            pid.attach(PidType::Pid, id);
        }
        self.nr_threads += 1;
        self.forks += 1;
        self.note_changed(id);
        Ok(id)
    }

    /// `copy_process`' publication (`fork`, no `CLONE_*` sharing): a child of
    /// `parent` in its process group and session, `exit_signal` from the
    /// arguments, `PF_FORKNOEXEC`, the parent's credentials and the signal
    /// state `copy_sighand`/`copy_signal` give it.
    ///
    /// Order of failures as in Linux: the `max_threads`/`RLIMIT_NPROC` check
    /// (`EAGAIN`), then pid allocation (`EAGAIN`, `ENOMEM`); a pending fatal
    /// signal (`EINTR`) is the caller's to check before this call (it holds
    /// the signal state of `current`).
    ///
    /// # Errors
    /// `EAGAIN`, `ENOMEM`, `ESRCH` for a stale or exiting parent.
    pub fn fork(&mut self, parent: TaskId, params: ForkParams) -> Result<TaskId, Errno> {
        self.clone_task(parent, CloneParams::process(params))
    }

    /// `copy_process` for the choices of `clone`/`clone3` that concern the task list: a new
    /// process (the parent's copy of the dispositions, or the shared ones with `CLONE_SIGHAND`)
    /// or, with `CLONE_THREAD`, a new thread of the caller's group sharing its `signal_struct`
    /// and `sighand_struct` (`copy_sighand`, `copy_signal`, the `thread_group_leader` branches
    /// of the publication block).
    ///
    /// # Errors
    /// `EAGAIN`, `ENOMEM`, `ESRCH` for a stale or exiting parent.
    #[allow(
        clippy::too_many_lines,
        reason = "one copy_process, each failure undoing what the steps before it allocated"
    )]
    pub fn clone_task(&mut self, parent: TaskId, params: CloneParams) -> Result<TaskId, Errno> {
        self.fork_allowed(parent, params.fork)?;
        let p = self.tasks.get(parent).ok_or(Errno::ESRCH)?;
        let (leader, pgid, sid, cred, exec_id, parent_exec_id, dumpable) = (
            p.group_leader,
            self.task_pid_type(parent, PidType::Pgid),
            self.task_pid_type(parent, PidType::Sid),
            p.cred,
            p.self_exec_id,
            p.parent_exec_id,
            p.dumpable,
        );
        let ctty = self.has_ctty(parent);
        let real_parent = if params.thread {
            p.real_parent
        } else {
            Some(parent)
        };
        let (group, old_sighand) = (p.group, p.sighand);
        // dup_task_struct: the task's own signal fields.
        let thread =
            Box::try_new(p.thread.fork_child(params.reset_altstack)).map_err(|_| Errno::ENOMEM)?;
        // copy_sighand: share the parent's, or a copy (with `CLONE_CLEAR_SIGHAND` reset).
        let new_hand = if params.share_sighand {
            None
        } else {
            let mut hand = self
                .sighands
                .get(old_sighand)
                .map(|h| (*h.hand).clone())
                .ok_or(Errno::ESRCH)?;
            if params.fork.clear_sighand {
                hand.flush();
            }
            let hand = Box::try_new(hand).map_err(|_| Errno::ENOMEM)?;
            Some(
                self.sighands
                    .try_insert(Sighand { hand, count: 0 })
                    .map_err(|_| Errno::ENOMEM)?,
            )
        };
        // copy_signal: a new thread group unless `CLONE_THREAD`.
        let new_group = if params.thread {
            None
        } else {
            let made = Box::try_new(SignalStruct::new(params.fork.rlimit_sigpending))
                .map_err(|_| Errno::ENOMEM)
                .and_then(|sig| {
                    self.groups
                        .try_insert(Group::new(sig))
                        .map_err(|_| Errno::ENOMEM)
                });
            match made {
                Ok(id) => Some(id),
                Err(errno) => {
                    if let Some(id) = new_hand {
                        self.sighands.remove(id);
                    }
                    return Err(errno);
                }
            }
        };
        let own = match self.alloc_pid() {
            Ok(own) => own,
            Err(errno) => {
                if let Some(id) = new_hand {
                    self.sighands.remove(id);
                }
                if let Some(id) = new_group {
                    self.groups.remove(id);
                }
                return Err(errno);
            }
        };
        let task = TaskStruct {
            pids: if params.thread {
                [Some(own), None, None, None]
            } else {
                [Some(own), Some(own), pgid, sid]
            },
            group_leader: if params.thread {
                leader
            } else {
                TaskId::DANGLING
            },
            group: new_group.unwrap_or(group),
            sighand: new_hand.unwrap_or(old_sighand),
            real_parent,
            first_child: None,
            last_child: None,
            prev_sibling: None,
            next_sibling: None,
            exit_state: ExitState::Live,
            exit_code: 0,
            // A thread has no exit signal (`p->exit_signal = -1`).
            exit_signal: if params.thread {
                0
            } else {
                params.fork.exit_signal
            },
            // dup_task_struct copies self_exec_id; copy_process: "p->parent_exec_id =
            // current->self_exec_id" for a child, the parent's own for a thread.
            self_exec_id: exec_id,
            parent_exec_id: if params.thread {
                parent_exec_id
            } else {
                exec_id
            },
            flags: PF_FORKNOEXEC,
            robust_list: 0,
            cred,
            // mm_init: the child's mm takes the parent's dumpability.
            dumpable,
            utime_ns: 0,
            stime_ns: 0,
            sched: None,
            thread,
        };
        let published = if params.thread {
            self.publish_thread(task)
        } else {
            self.publish(task, real_parent)
        };
        match published {
            Ok(id) => {
                if params.thread {
                    self.task_join_group_stop(parent, id);
                } else if let Some(g) = self.group_mut(id) {
                    // copy_signal: `p->signal->tty = tty_kref_get(current->signal->tty)`.
                    g.ctty = ctty;
                }
                Ok(id)
            }
            Err(errno) => {
                self.free_if_unused(own);
                if let Some(id) = new_hand {
                    self.sighands.remove(id);
                }
                if let Some(id) = new_group {
                    self.groups.remove(id);
                }
                Err(errno)
            }
        }
    }

    /// The checks `copy_process` makes before it allocates anything for the
    /// child: a live parent, then `RLIMIT_NPROC` and `max_threads`.
    ///
    /// # Errors
    /// `ESRCH` for a stale or exiting parent; `EAGAIN`.
    pub fn fork_allowed(&self, parent: TaskId, params: ForkParams) -> Result<(), Errno> {
        let p = self.tasks.get(parent).ok_or(Errno::ESRCH)?;
        if p.exit_state != ExitState::Live {
            return Err(Errno::ESRCH);
        }
        // `nr_threads >= max_threads` is EAGAIN for everyone; RLIMIT_NPROC is
        // waived with CAP_SYS_RESOURCE (shortcut T9: Linux counts per-user
        // ucounts).
        if self.nr_threads >= self.max_threads {
            return Err(Errno::EAGAIN);
        }
        if !p.cred.cap_sys_resource && u64::from(self.nr_threads) >= params.rlimit_nproc {
            return Err(Errno::EAGAIN);
        }
        Ok(())
    }

    /// Bind the scheduling handle of `task` (`wake_up_new_task` is the
    /// owner's, after this).
    pub fn set_sched(&mut self, task: TaskId, sched: SchedId) {
        if let Some(t) = self.tasks.get_mut(task) {
            t.sched = Some(sched);
        }
    }

    /// `signal_wake_up(t, resume)`: `TIF_SIGPENDING` is set for the thread (it looks at the
    /// shared queue from now on) and it is woken from an interruptible sleep (`resume`: also
    /// from a job-control stop).
    pub(super) fn signal_wake_up(
        &mut self,
        t: TaskId,
        resume: bool,
        w: &mut dyn super::exit::Waker,
    ) {
        if let Some(task) = self.tasks.get_mut(t) {
            task.thread.shared_seen = true;
        }
        let sched = self.sched_of(t);
        w.signal_wake(t, sched, resume);
    }

    /// The scheduling handle of `task`, if one was bound.
    #[must_use]
    pub fn sched_of(&self, task: TaskId) -> Option<SchedId> {
        self.tasks.get(task)?.sched
    }

    /// `release_task` (`__exit_signal`, `__unhash_process`): the dead task leaves the lists, its
    /// pids are freed when nothing else is attached, its slot is freed and its id stops
    /// resolving. The task has no children left (`forget_original_parent` handed them to the
    /// reaper at its exit). The last thread of a group frees the group; a thread that leaves a
    /// zombie leader alone in its group notifies the leader's parent (and releases the leader
    /// too when that parent wants no zombie): `w` carries those wake-ups.
    ///
    /// # Panics
    /// If the task is the child reaper (init is never released).
    pub fn release_task(&mut self, id: TaskId, w: &mut dyn super::exit::Waker) {
        let mut id = id;
        loop {
            assert!(id != self.child_reaper, "init released");
            let Some(next) = self.release_one(id, w) else {
                return;
            };
            id = next;
        }
    }

    /// One round of `release_task`; the zombie leader to release next (`zap_leader`).
    fn release_one(&mut self, id: TaskId, w: &mut dyn super::exit::Waker) -> Option<TaskId> {
        let nr = self.task_tgid_vnr(id);
        let (leader, group, sighand) = {
            let t = self.tasks.get(id)?;
            (t.group_leader, t.group, t.sighand)
        };
        let group_dead = leader == id;
        let task = self.tasks.remove(id)?;
        debug_assert!(task.first_child.is_none(), "release_task with children");
        // The members: the other threads' view of `curr_target` and `notify_count`.
        let mut empty_group = false;
        if let Some(g) = self.groups.get_mut(group) {
            if !group_dead {
                // "If there is any task waiting for the group exit then notify it."
                if g.notify_count > 0 {
                    g.notify_count -= 1;
                    if g.notify_count == 0
                        && let Some(waiting) = g.exec_task
                    {
                        w.de_thread_event(waiting);
                    }
                }
                if g.curr_target == id {
                    let at = g.threads.iter().position(|&t| t == id).unwrap_or(0);
                    g.curr_target = g
                        .threads
                        .get(at + 1)
                        .or_else(|| g.threads.first())
                        .copied()
                        .unwrap_or(leader);
                    if g.curr_target == id {
                        g.curr_target = leader;
                    }
                }
            }
            g.dead_utime_ns += task.utime_ns;
            g.dead_stime_ns += task.stime_ns;
            g.threads.retain(|&t| t != id);
            empty_group = g.threads.is_empty();
        }
        // __unhash_process: the thread's own pid always, the group's links with the leader.
        let own = task.pids[PidType::Pid as usize];
        if let Some(pid) = own {
            if let Some(p) = self.pids.get_mut(pid) {
                p.detach(PidType::Pid, id);
            }
            self.free_if_unused(pid);
        }
        if group_dead {
            for ty in [PidType::Tgid, PidType::Pgid, PidType::Sid] {
                if let Some(pid) = task.pids[ty as usize] {
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
        }
        // Sub-thread release leaves the sibling position to the leader; a leader may be released
        // while its group still has zombie-less threads only after `de_thread`.
        if let Some(h) = self.sighands.get_mut(sighand) {
            h.count -= 1;
            if h.count == 0 {
                self.sighands.remove(sighand);
            }
        }
        self.nr_threads -= 1;
        self.changes.note(nr);
        if empty_group {
            self.groups.remove(group);
            return None;
        }
        // "If we are the last non-leader member of the thread group, and the leader is zombie,
        // then notify the group leader's parent process (if it wants notification)."
        if !group_dead {
            let alone = self
                .groups
                .get(group)
                .is_some_and(|g| g.threads.len() == 1 && g.threads[0] == leader);
            if alone
                && self
                    .tasks
                    .get(leader)
                    .is_some_and(|l| l.exit_state == ExitState::Zombie)
            {
                if let Some(code) = self.groups.get(group).and_then(|g| g.sig.group_exit)
                    && let Some(l) = self.tasks.get_mut(leader)
                {
                    l.exit_code = code;
                }
                let exit_signal = self.tasks.get(leader).map_or(SIGCHLD, |l| l.exit_signal);
                if self.do_notify_parent(leader, exit_signal, w) {
                    if let Some(l) = self.tasks.get_mut(leader) {
                        l.exit_state = ExitState::Dead;
                    }
                    return Some(leader);
                }
            }
        }
        None
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

    /// `total_forks`.
    #[must_use]
    pub const fn forks(&self) -> u64 {
        self.forks
    }

    /// `idr_get_cursor(&pid_ns->idr) - 1`: the last pid handed out.
    #[must_use]
    pub fn last_pid(&self) -> i32 {
        i32::try_from(self.table.cursor().saturating_sub(1)).unwrap_or(i32::MAX)
    }

    /// A counter that moves whenever a thread group appears or disappears or
    /// the facts `/proc` mirrors of it change (credentials, the zombie
    /// transition, dumpability): [`crate::procfs::ProcState::sync`] follows it
    /// with [`Tasklist::changed_since`].
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.changes.count
    }

    /// The pid numbers whose mirrored facts changed after the `seen` value of
    /// [`Tasklist::epoch`], oldest first (a number can repeat), or `None` when
    /// more than the ring remembers happened since (rebuild from the list).
    #[must_use]
    pub fn changed_since(&self, seen: u64) -> Option<impl Iterator<Item = i32> + '_> {
        self.changes.since(seen)
    }

    /// Record that the facts `/proc` mirrors of `task` changed.
    fn note_changed(&mut self, task: TaskId) {
        let nr = self.task_tgid_vnr(task);
        self.changes.note(nr);
    }

    /// Mark the task changed for `/proc` readers: it became a zombie.
    pub(super) fn touch_epoch(&mut self, task: TaskId) {
        self.note_changed(task);
    }

    /// `get_dumpable(mm) == SUID_DUMP_USER` for the task (a task that is gone
    /// counts as dumpable: nothing reads it). shortcut: `fs.suid_dumpable`
    /// stays 0 and `SUID_DUMP_ROOT` does not exist, so a task is dumpable or
    /// not; no set-id `execve` exists to make the new image undumpable.
    #[must_use]
    pub fn dumpable(&self, task: TaskId) -> bool {
        self.tasks.get(task).is_none_or(|t| t.dumpable)
    }

    /// `set_dumpable(mm, value)` (`PR_SET_DUMPABLE`, `commit_creds`, `execve`).
    pub fn set_dumpable(&mut self, task: TaskId, dumpable: bool) {
        if let Some(t) = self.tasks.get_mut(task)
            && t.dumpable != dumpable
        {
            t.dumpable = dumpable;
            self.note_changed(task); // the /proc mirror copies it
        }
    }

    /// Live and zombie tasks, `nr_threads`.
    #[must_use]
    pub const fn nr_threads(&self) -> u32 {
        self.nr_threads
    }

    /// Heap bytes of the pid number table (grows with the highest pid number).
    #[must_use]
    pub fn pid_table_bytes(&self) -> usize {
        self.table.footprint_bytes()
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

    /// `task_pid_type(task, ty)`: the task's own pid, or (`signal->pids[ty]`) its group's,
    /// which the leader holds.
    #[must_use]
    pub fn task_pid_type(&self, task: TaskId, ty: PidType) -> Option<PidId> {
        let t = self.tasks.get(task)?;
        match ty {
            PidType::Pid => t.pids[PidType::Pid as usize],
            _ => self.tasks.get(t.group_leader)?.pids[ty as usize],
        }
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

    /// `list_replace_init(&old->sibling, &new->sibling)`: `new` takes `old`'s place among the
    /// children of `parent`.
    pub(super) fn list_replace(&mut self, parent: TaskId, old: TaskId, new: TaskId) {
        let (prev, next) = {
            let Some(o) = self.tasks.get_mut(old) else {
                return;
            };
            (o.prev_sibling.take(), o.next_sibling.take())
        };
        if let Some(n) = self.tasks.get_mut(new) {
            n.prev_sibling = prev;
            n.next_sibling = next;
        }
        match prev.and_then(|p| self.tasks.get_mut(p)) {
            Some(p) => p.next_sibling = Some(new),
            None => {
                if let Some(p) = self.tasks.get_mut(parent) {
                    p.first_child = Some(new);
                }
            }
        }
        match next.and_then(|n| self.tasks.get_mut(n)) {
            Some(n) => n.prev_sibling = Some(new),
            None => {
                if let Some(p) = self.tasks.get_mut(parent) {
                    p.last_child = Some(new);
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
    pub fn signal_ids(&self, task: TaskId, curr: bool) -> Option<Ids> {
        let t = self.tasks.get(task)?;
        Some(Ids {
            pid: self.task_pid_vnr(task),
            tgid: self.task_tgid_vnr(task),
            uid: t.cred.uid,
            global_init: self.is_global_init(task),
            exiting: t.flags & PF_EXITING != 0,
            curr,
        })
    }

    /// The `State` view of `task`'s signal objects, as seen by another task
    /// (`task_curr` false): what a sender, a waiter or a test examines.
    pub fn signal_state(&mut self, task: TaskId) -> Option<State<'_>> {
        self.signal_state_as(task, false)
    }

    /// [`Tasklist::signal_state`] with `curr` = `task_curr(task)`: the task is
    /// the one running this code (its own state, or the target of a signal it
    /// sends itself), which `wants_signal` reads.
    pub fn signal_state_as(&mut self, task: TaskId, curr: bool) -> Option<State<'_>> {
        let ids = self.signal_ids(task, curr)?;
        let t = self.tasks.get_mut(task)?;
        Some(State {
            hand: &mut self.sighands.get_mut(t.sighand)?.hand,
            sig: &mut self.groups.get_mut(t.group)?.sig,
            me: &mut t.thread,
            pid: ids.pid,
            tgid: ids.tgid,
            uid: ids.uid,
            global_init: ids.global_init,
            exiting: ids.exiting,
            curr: ids.curr,
        })
    }

    /// The `/proc` summary of a task's signal sets.
    #[must_use]
    pub fn signal_sets(&self, task: TaskId) -> Option<crate::signal::SigSets> {
        let t = self.tasks.get(task)?;
        let hand = &self.sighands.get(t.sighand)?.hand;
        let sig = &self.groups.get(t.group)?.sig;
        Some(crate::signal::SigSets::of(hand, sig, &t.thread))
    }

    // ---- thread groups ------------------------------------------------------------

    pub(super) fn group_of(&self, task: TaskId) -> Option<&Group> {
        self.groups.get(self.tasks.get(task)?.group)
    }

    pub(super) fn group_mut(&mut self, task: TaskId) -> Option<&mut Group> {
        let id = self.tasks.get(task)?.group;
        self.groups.get_mut(id)
    }

    /// The `signal_struct` signal fields of `task`'s group.
    #[must_use]
    pub fn sig(&self, task: TaskId) -> Option<&SignalStruct> {
        Some(&*self.group_of(task)?.sig)
    }

    pub(super) fn sig_mut(&mut self, task: TaskId) -> Option<&mut SignalStruct> {
        Some(&mut *self.group_mut(task)?.sig)
    }

    /// `task->group_leader`.
    #[must_use]
    pub fn group_leader(&self, task: TaskId) -> TaskId {
        self.tasks.get(task).map_or(task, |t| t.group_leader)
    }

    /// `thread_group_leader(task)`.
    #[must_use]
    pub fn thread_group_leader(&self, task: TaskId) -> bool {
        self.group_leader(task) == task
    }

    /// `same_thread_group(a, b)`.
    #[must_use]
    pub fn same_thread_group(&self, a: TaskId, b: TaskId) -> bool {
        match (self.tasks.get(a), self.tasks.get(b)) {
            (Some(a), Some(b)) => a.group == b.group,
            _ => false,
        }
    }

    /// `thread_group_empty(task)`: the task is the only thread of its group.
    #[must_use]
    pub fn thread_group_empty(&self, task: TaskId) -> bool {
        self.group_of(task).is_none_or(|g| g.threads.len() <= 1)
    }

    /// `get_nr_threads(task)`: the threads of the group, the zombie ones included.
    #[must_use]
    pub fn group_thread_count(&self, task: TaskId) -> u32 {
        self.group_of(task)
            .map_or(0, |g| u32::try_from(g.threads.len()).unwrap_or(u32::MAX))
    }

    /// `for_each_thread(task, t)`: the group's members in creation order. The collection is
    /// borrowed from the list, so the caller visits by index when it changes the list.
    pub fn threads(&self, task: TaskId) -> impl Iterator<Item = TaskId> + '_ {
        self.group_of(task)
            .into_iter()
            .flat_map(|g| g.threads.iter().copied())
    }

    /// The `index`th member of the group, for loops that change the list as they go.
    #[must_use]
    pub fn thread_at(&self, task: TaskId, index: usize) -> Option<TaskId> {
        self.group_of(task)?.threads.get(index).copied()
    }

    /// `next_thread(task)`: the next member, wrapping to the group leader.
    #[must_use]
    pub fn next_thread(&self, task: TaskId) -> TaskId {
        let Some(g) = self.group_of(task) else {
            return task;
        };
        let at = g.threads.iter().position(|&t| t == task);
        match at.and_then(|at| g.threads.get(at + 1)) {
            Some(&next) => next,
            None => self.group_leader(task),
        }
    }

    // ---- credentials ------------------------------------------------------------

    /// Publish `cred` as the snapshot cross-task readers see: at exec
    /// (`commit_creds`) and after every credential-changing syscall.
    pub fn publish_cred(&mut self, task: TaskId, cred: &Cred) {
        if let Some(t) = self.tasks.get_mut(task) {
            let new = CredSnapshot::of(cred);
            // commit_creds (kernel/cred.c:406-410): "dumpability changes" to
            // `suid_dumpable` (0) when the effective uid or gid, the fsuid or
            // fsgid, or the capabilities (`!cred_cap_issubset(old, new)`)
            // change. shortcut: only the first two are compared. This model
            // has no separate fsuid/fsgid (`setfsuid`/`setfsgid` stop the
            // kernel loudly, so they always equal the effective ids and move
            // with them) and no capability sets (`capset` stops loudly; the
            // capabilities are `euid == 0`, so they move only with the
            // effective uid). The first of `setfsuid`, `setfsgid` or `capset`
            // to be ported MUST add its comparison here (and a `CredSnapshot`
            // field), or a privilege change will leave the task dumpable.
            if t.cred.euid != new.euid || t.cred.egid != new.egid {
                t.dumpable = false;
            }
            t.cred = new;
            self.note_changed(task);
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
