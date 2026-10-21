// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: kernel/exit.c (`eligible_pid`
// 1141, `eligible_child` 1147-1173, `wait_task_zombie` 1180-1305,
// `task_stopped_code` 1306, `wait_task_stopped` 1336-1403,
// `wait_task_continued` 1408-1450, `wait_consider_task` 1460-1570,
// `do_wait_thread` 1572, `is_effectively_child` 1630, `do_wait_pid` 1644-1668,
// `__do_wait` 1670-1715, `kernel_waitid_prepare` 1742-1800, `kernel_wait4`
// 1853-1894), include/uapi/linux/wait.h. All GPL-2.0-only.
// Transformation: the sleep in `do_wait` is the caller's (`__do_wait` returns
// `-ERESTARTSYS` when a blocking wait found nothing and the caller sleeps on
// the parent's `wait_chldexit`, here [`super::exit::Waker::child_event`]); no
// ptrace (`EXIT_TRACE`, `ptrace_do_wait`); the children of every thread of the
// caller's group are considered unless `__WNOTHREAD`; `rusage` is the CPU times
// only.
#![forbid(unsafe_code)]
//! `wait4` and `waitid`: argument decoding and one pass over the children.

use super::{
    exit::{
        CLD_CONTINUED, CLD_DUMPED, CLD_EXITED, CLD_KILLED, CLD_STOPPED, NoWake,
        SIGNAL_STOP_CONTINUED, SIGNAL_STOP_STOPPED,
    },
    pid::{PidId, PidType},
    tasklist::{ExitState, TaskId, Tasklist},
};
use crate::signal::{SIGCHLD, SIGCONT, deliver::ERESTARTSYS};
use syscalls::Errno;

pub const WNOHANG: u32 = 0x0000_0001;
pub const WUNTRACED: u32 = 0x0000_0002;
pub const WSTOPPED: u32 = WUNTRACED;
pub const WEXITED: u32 = 0x0000_0004;
pub const WCONTINUED: u32 = 0x0000_0008;
pub const WNOWAIT: u32 = 0x0100_0000;
pub const WNOTHREAD: u32 = 0x2000_0000;
pub const WALL: u32 = 0x4000_0000;
pub const WCLONE: u32 = 0x8000_0000;

/// `P_ALL`, `P_PID`, `P_PGID`, `P_PIDFD` (`waitid`'s `which`).
pub const P_ALL: i32 = 0;
pub const P_PID: i32 = 1;
pub const P_PGID: i32 = 2;
pub const P_PIDFD: i32 = 3;

/// `wo_type`: which pids are eligible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitType {
    /// `PIDTYPE_MAX`: any child.
    Any,
    /// `PIDTYPE_PID`.
    Pid,
    /// `PIDTYPE_PGID`.
    Pgid,
}

/// `struct waitid_info`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WaitInfo {
    pub cause: i32,
    pub pid: i32,
    pub uid: u32,
    pub status: i32,
}

/// `struct wait_opts` and its outputs.
#[derive(Clone, Copy, Debug)]
pub struct WaitOpts {
    pub wo_type: WaitType,
    /// `wo_pid`: `None` is a pid number nobody has (`find_get_pid` failed).
    pub wo_pid: Option<PidId>,
    pub flags: u32,
    /// `wo_info != NULL` (`waitid`; `wait4` has none).
    pub with_info: bool,
    /// `notask_error`: `-ECHILD` or 0 while the search goes on.
    pub notask_error: i64,
    /// `wo_stat`: the `wait4` status word.
    pub stat: i32,
    pub info: WaitInfo,
    /// `getrusage(p, RUSAGE_BOTH)`: user and system time in nanoseconds of the
    /// child that was reported.
    pub rusage: (u64, u64),
}

impl WaitOpts {
    #[must_use]
    pub const fn new(
        wo_type: WaitType,
        wo_pid: Option<PidId>,
        flags: u32,
        with_info: bool,
    ) -> Self {
        Self {
            wo_type,
            wo_pid,
            flags,
            with_info,
            notask_error: 0,
            stat: 0,
            info: WaitInfo {
                cause: 0,
                pid: 0,
                uid: 0,
                status: 0,
            },
            rusage: (0, 0),
        }
    }
}

impl Tasklist {
    /// `kernel_wait4`'s argument handling for `wait4(upid, _, options, _)`.
    ///
    /// # Errors
    /// `EINVAL` for an option outside `WNOHANG|WUNTRACED|WCONTINUED|
    /// __WNOTHREAD|__WCLONE|__WALL`; `ESRCH` for `INT_MIN`.
    pub fn prepare_wait4(
        &self,
        current: TaskId,
        upid: i32,
        options: u32,
    ) -> Result<WaitOpts, Errno> {
        if options & !(WNOHANG | WUNTRACED | WCONTINUED | WNOTHREAD | WCLONE | WALL) != 0 {
            return Err(Errno::EINVAL);
        }
        // -INT_MIN is not defined.
        if upid == i32::MIN {
            return Err(Errno::ESRCH);
        }
        let (wo_type, wo_pid) = match upid {
            -1 => (WaitType::Any, None),
            ..-1 => (WaitType::Pgid, self.find_vpid(-upid)),
            0 => (WaitType::Pgid, self.task_pid_type(current, PidType::Pgid)),
            _ => (WaitType::Pid, self.find_vpid(upid)),
        };
        Ok(WaitOpts::new(wo_type, wo_pid, options | WEXITED, false))
    }

    /// `kernel_waitid_prepare` for `waitid(which, upid, _, options, _)`.
    /// `pidfd` resolves a `P_PIDFD` descriptor to its pid and whether the file
    /// is non-blocking (the VFS owns descriptors; it fails with `EBADF`).
    ///
    /// # Errors
    /// `EINVAL`, or the error of `pidfd`.
    pub fn prepare_waitid(
        &self,
        current: TaskId,
        which: i32,
        upid: i32,
        options: u32,
        pidfd: impl FnOnce(i32) -> Result<(Option<PidId>, bool), Errno>,
    ) -> Result<WaitOpts, Errno> {
        if options
            & !(WNOHANG | WNOWAIT | WEXITED | WSTOPPED | WCONTINUED | WNOTHREAD | WCLONE | WALL)
            != 0
        {
            return Err(Errno::EINVAL);
        }
        if options & (WEXITED | WSTOPPED | WCONTINUED) == 0 {
            return Err(Errno::EINVAL);
        }
        let mut flags = options;
        let (wo_type, wo_pid) = match which {
            P_ALL => (WaitType::Any, None),
            P_PID => {
                if upid <= 0 {
                    return Err(Errno::EINVAL);
                }
                (WaitType::Pid, self.find_vpid(upid))
            }
            P_PGID => {
                if upid < 0 {
                    return Err(Errno::EINVAL);
                }
                let pid = if upid != 0 {
                    self.find_vpid(upid)
                } else {
                    self.task_pid_type(current, PidType::Pgid)
                };
                (WaitType::Pgid, pid)
            }
            P_PIDFD => {
                if upid < 0 {
                    return Err(Errno::EINVAL);
                }
                let (pid, nonblock) = pidfd(upid)?;
                if nonblock {
                    flags |= WNOHANG;
                }
                (WaitType::Pid, pid)
            }
            _ => return Err(Errno::EINVAL),
        };
        Ok(WaitOpts::new(wo_type, wo_pid, flags, true))
    }

    fn eligible_pid(&self, wo: &WaitOpts, p: TaskId) -> bool {
        match wo.wo_type {
            WaitType::Any => true,
            WaitType::Pid => self.task_pid_type(p, PidType::Pid) == wo.wo_pid,
            WaitType::Pgid => self.task_pid_type(p, PidType::Pgid) == wo.wo_pid,
        }
    }

    fn eligible_child(&self, wo: &WaitOpts, p: TaskId) -> bool {
        if !self.eligible_pid(wo, p) {
            return false;
        }
        if wo.flags & WALL != 0 {
            return true;
        }
        // Wait for clone children only if __WCLONE is set; otherwise for
        // non-clone children only. A "clone" child reports with a signal
        // other than SIGCHLD; all of ours use SIGCHLD.
        let clone = self.task(p).is_some_and(|t| t.exit_signal != SIGCHLD);
        clone == (wo.flags & WCLONE != 0)
    }

    /// `is_effectively_child`: `target`'s real parent is `current`, or (without
    /// `__WNOTHREAD`) any thread of its group.
    fn is_effectively_child(&self, current: TaskId, wo: &WaitOpts, target: TaskId) -> bool {
        let Some(parent) = self.real_parent(target) else {
            return false;
        };
        current == parent || (wo.flags & WNOTHREAD == 0 && self.same_thread_group(current, parent))
    }

    /// One pass of `__do_wait` for `current`: the pid of the child reported
    /// (> 0, `wo` filled in, a zombie reaped unless `WNOWAIT`), `0` for
    /// `WNOHANG` with nothing ready, `-ECHILD` for nothing to wait for, or
    /// `-ERESTARTSYS` when a blocking wait found children but no event (the
    /// caller sleeps until [`super::exit::Waker::child_event`] and calls
    /// again, unless a signal is pending).
    pub fn do_wait_once(&mut self, current: TaskId, wo: &mut WaitOpts) -> i64 {
        wo.notask_error = -i64::from(Errno::ECHILD.into_raw());
        let ty = match wo.wo_type {
            WaitType::Any => None,
            WaitType::Pid => Some(PidType::Pid),
            WaitType::Pgid => Some(PidType::Pgid),
        };
        let nothing = ty.is_some_and(|ty| {
            wo.wo_pid
                .is_none_or(|pid| !self.pid(pid).is_some_and(|p| p.has_task(ty)))
        });
        if !nothing {
            if wo.wo_type == WaitType::Pid {
                // do_wait_pid: the target must be a child of `current` or of a thread of its
                // group.
                let target = wo.wo_pid.and_then(|pid| self.pid_task(pid, PidType::Tgid));
                if let Some(target) = target
                    && self.is_effectively_child(current, wo, target)
                {
                    let ret = self.wait_consider_task(current, wo, target);
                    if ret != 0 {
                        return ret;
                    }
                }
            } else {
                // do_wait_thread for `current`, then the other threads of its group in ring order.
                let mut tsk = current;
                loop {
                    let mut next = self.task(tsk).and_then(|t| t.first_child);
                    while let Some(child) = next {
                        next = self.task(child).and_then(|t| t.next_sibling);
                        let ret = self.wait_consider_task(current, wo, child);
                        if ret != 0 {
                            return ret;
                        }
                    }
                    if wo.flags & WNOTHREAD != 0 {
                        break;
                    }
                    tsk = self.next_thread(tsk);
                    if tsk == current {
                        break;
                    }
                }
            }
        }
        if wo.notask_error == 0 && wo.flags & WNOHANG == 0 {
            return -ERESTARTSYS;
        }
        wo.notask_error
    }

    /// `delay_group_leader(p)`: a leader with other threads is not reaped.
    fn delay_group_leader(&self, p: TaskId) -> bool {
        self.thread_group_leader(p) && !self.thread_group_empty(p)
    }

    /// `wait_consider_task` (no ptrace).
    fn wait_consider_task(&mut self, current: TaskId, wo: &mut WaitOpts, p: TaskId) -> i64 {
        let Some(state) = self.task(p).map(|t| t.exit_state) else {
            return 0;
        };
        if state == ExitState::Dead || !self.eligible_child(wo, p) {
            return 0;
        }
        if state == ExitState::Zombie {
            // we don't reap group leaders with subthreads
            if !self.delay_group_leader(p) {
                return self.wait_task_zombie(current, wo, p);
            }
            // "Allow access to stopped/continued state via zombie by falling through": with
            // WEXITED the event will come when the threads are gone, otherwise the stopped
            // state of the live threads is one.
        }
        // p is alive (or a leader with live threads) and it's gonna stop, continue or exit, so
        // there always is something to wait for.
        wo.notask_error = 0;
        let ret = self.wait_task_stopped(wo, p);
        if ret != 0 {
            return ret;
        }
        self.wait_task_continued(wo, p)
    }

    /// `getrusage(p, RUSAGE_BOTH)`: the CPU time of the group (its threads, the finished ones
    /// included) and of the children it has reaped.
    fn rusage_of(&self, p: TaskId) -> (u64, u64) {
        let (own_u, own_s) = self.group_cputime(p);
        self.group_of(p).map_or((own_u, own_s), |g| {
            (own_u + g.cutime_ns, own_s + g.cstime_ns)
        })
    }

    /// `thread_group_cputime(p)`: the live threads' times and those of the finished threads.
    #[must_use]
    pub fn group_cputime(&self, p: TaskId) -> (u64, u64) {
        let Some(g) = self.group_of(p) else {
            return (0, 0);
        };
        g.threads
            .iter()
            .filter_map(|&t| self.task(t))
            .fold((g.dead_utime_ns, g.dead_stime_ns), |(u, s), t| {
                (u + t.utime_ns, s + t.stime_ns)
            })
    }

    /// `signal->utime`/`stime`: the times of the group's threads that were released.
    #[must_use]
    pub fn dead_cputime(&self, p: TaskId) -> (u64, u64) {
        self.group_of(p)
            .map_or((0, 0), |g| (g.dead_utime_ns, g.dead_stime_ns))
    }

    /// `signal->cutime`/`cstime`: the times of the children the group has reaped.
    #[must_use]
    pub fn children_cputime(&self, p: TaskId) -> (u64, u64) {
        self.group_of(p)
            .map_or((0, 0), |g| (g.cutime_ns, g.cstime_ns))
    }

    /// `wait_task_zombie`.
    fn wait_task_zombie(&mut self, current: TaskId, wo: &mut WaitOpts, p: TaskId) -> i64 {
        if wo.flags & WEXITED == 0 {
            return 0;
        }
        let pid = self.task_pid_vnr(p);
        let Some(t) = self.task(p) else { return 0 };
        let uid = t.cred.uid;
        // `SIGNAL_GROUP_EXIT ? group_exit_code : exit_code`
        let status = self
            .sig(p)
            .and_then(|s| s.group_exit)
            .unwrap_or(t.exit_code);
        wo.rusage = self.rusage_of(p);
        if wo.flags & WNOWAIT == 0 {
            // Move the task's state to DEAD, then fold the times of the group (and those of
            // its reaped children) into the reaper's group `c*time`.
            let (ut, st) = self.group_cputime(p);
            let (cut, cst) = self
                .group_of(p)
                .map_or((0, 0), |g| (g.cutime_ns, g.cstime_ns));
            if let Some(t) = self.task_mut(p) {
                t.exit_state = ExitState::Dead;
            }
            if let Some(psig) = self.group_mut(current) {
                psig.cutime_ns += ut + cut;
                psig.cstime_ns += st + cst;
            }
            wo.stat = i32::try_from(status).unwrap_or(0);
            self.release_task(p, &mut NoWake);
        }
        if wo.with_info {
            // `(status & 0x7f) == 0`: exited normally.
            if status.trailing_zeros() >= 7 {
                wo.info.cause = CLD_EXITED;
                wo.info.status = i32::try_from(status >> 8).unwrap_or(0);
            } else {
                wo.info.cause = if status & 0x80 != 0 {
                    CLD_DUMPED
                } else {
                    CLD_KILLED
                };
                wo.info.status = i32::try_from(status & 0x7f).unwrap_or(0);
            }
            wo.info.pid = pid;
            wo.info.uid = uid;
        }
        i64::from(pid)
    }

    /// `wait_task_stopped` (not ptraced): reported once unless `WNOWAIT`.
    fn wait_task_stopped(&mut self, wo: &mut WaitOpts, p: TaskId) -> i64 {
        if wo.flags & WUNTRACED == 0 {
            return 0;
        }
        let pid = self.task_pid_vnr(p);
        let Some(uid) = self.task(p).map(|t| t.cred.uid) else {
            return 0;
        };
        let Some(sig) = self.sig_mut(p) else { return 0 };
        // task_stopped_code (not ptraced): `SIGNAL_STOP_STOPPED`, whatever the
        // task's own state (a stopped child that `SIGKILL` woke is still reported
        // until it exits).
        if sig.job_flags & SIGNAL_STOP_STOPPED == 0 {
            return 0;
        }
        let exit_code = sig.stop_code;
        if exit_code == 0 {
            return 0;
        }
        if wo.flags & WNOWAIT == 0 {
            sig.stop_code = 0;
        }
        wo.rusage = self.rusage_of(p);
        if wo.flags & WNOWAIT == 0 {
            wo.stat = i32::try_from((exit_code << 8) | 0x7f).unwrap_or(0);
        }
        if wo.with_info {
            wo.info = WaitInfo {
                cause: CLD_STOPPED,
                status: i32::try_from(exit_code).unwrap_or(0),
                pid,
                uid,
            };
        }
        i64::from(pid)
    }

    /// `wait_task_continued`.
    fn wait_task_continued(&mut self, wo: &mut WaitOpts, p: TaskId) -> i64 {
        if wo.flags & WCONTINUED == 0 {
            return 0;
        }
        let pid = self.task_pid_vnr(p);
        let Some(uid) = self.task(p).map(|t| t.cred.uid) else {
            return 0;
        };
        let Some(sig) = self.sig_mut(p) else { return 0 };
        if sig.job_flags & SIGNAL_STOP_CONTINUED == 0 {
            return 0;
        }
        if wo.flags & WNOWAIT == 0 {
            sig.job_flags &= !SIGNAL_STOP_CONTINUED;
        }
        wo.rusage = self.rusage_of(p);
        if wo.with_info {
            wo.info = WaitInfo {
                cause: CLD_CONTINUED,
                pid,
                uid,
                status: i32::from(SIGCONT),
            };
        } else {
            wo.stat = 0xffff;
        }
        i64::from(pid)
    }
}
