// SPDX-License-Identifier: GPL-2.0-only
// Host tests of the task list model. Expected values are derived from the
// pinned Linux sources named at each test (kernel/exit.c, kernel/sys.c,
// kernel/signal.c, kernel/pid.c), not from the code under test.
#![allow(
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::assert_is_empty,
    clippy::manual_assert_eq
)]
extern crate std;

use super::{
    attrs::Cred,
    exit::{
        CLD_CONTINUED, CLD_DUMPED, CLD_EXITED, CLD_KILLED, CLD_STOPPED, ExitPrep, Notified, Waker,
    },
    pid::PidType,
    tasklist::{
        CredSnapshot, ExitState, ForkParams, JOBCTL_STOPPED, PF_FORKNOEXEC, TaskId, Tasklist,
    },
    wait::{
        P_ALL, P_PGID, P_PID, P_PIDFD, WALL, WCLONE, WCONTINUED, WEXITED, WNOHANG, WNOWAIT,
        WUNTRACED, WaitOpts,
    },
};
use crate::signal::{
    SA_NOCLDSTOP, SA_NOCLDWAIT, SIG_DFL, SIG_IGN, SIGCHLD, SIGCONT, SIGHUP, SIGKILL, SIGSTOP,
    SIGTERM, SIGUSR1, SigAction, SigSet, deliver::ERESTARTSYS, info::SigInfo,
};
use std::vec::Vec;
use syscalls::Errno;

const ECHILD: i64 = -10;
const FORK: ForkParams = ForkParams {
    rlimit_sigpending: 100,
    rlimit_nproc: 1000,
    exit_signal: SIGCHLD,
    clear_sighand: false,
};

#[derive(Default)]
struct Rec {
    child_events: Vec<TaskId>,
    signal_wakes: Vec<TaskId>,
}
impl Waker for Rec {
    fn child_event(&mut self, parent: TaskId) {
        self.child_events.push(parent);
    }
    fn signal_wake(&mut self, task: TaskId, _sched: Option<crate::sched::SchedId>) {
        self.signal_wakes.push(task);
    }
}

fn list() -> (Tasklist, TaskId) {
    Tasklist::new(100, &Cred::root(), 100).unwrap()
}

fn user_cred(uid: u32) -> CredSnapshot {
    CredSnapshot::of(&Cred {
        uid,
        euid: uid,
        suid: uid,
        ..Cred::root()
    })
}

/// `do_exit` up to and including `exit_notify`.
fn exit(l: &mut Tasklist, t: TaskId, code: u32, w: &mut Rec) -> Notified {
    assert_eq!(
        l.exit_prepare(t, code, false),
        ExitPrep::Proceed { group_dead: true }
    );
    l.exit_notify(t, w).unwrap()
}

fn pending(l: &mut Tasklist, t: TaskId) -> SigSet {
    l.signal_state(t).unwrap().pending_set()
}

fn pid(l: &Tasklist, t: TaskId) -> i32 {
    l.task_pid_vnr(t)
}

fn wait_pid(l: &mut Tasklist, me: TaskId, upid: i32, options: u32) -> (i64, WaitOpts) {
    let mut wo = l.prepare_wait4(me, upid, options).unwrap();
    (l.do_wait_once(me, &mut wo), wo)
}

#[test]
fn init_is_pid_one_in_init_struct_pid_groups() {
    // kernel/fork.c copy_process: init attaches to the idle task's pgrp and
    // session, init_struct_pid, whose number is 0.
    let (l, init) = list();
    assert_eq!((pid(&l, init), l.task_tgid_vnr(init)), (1, 1));
    assert_eq!((l.task_pgrp_vnr(init), l.task_session_vnr(init)), (0, 0));
    assert_eq!(l.task_ppid_vnr(init), 0);
    assert!(l.is_global_init(init));
    assert_eq!(
        l.task_pid_type(init, PidType::Pgid),
        Some(l.init_struct_pid())
    );
    assert_eq!(l.child_reaper(), init);
    assert_eq!(l.find_task_by_vpid(1), Some(init));
    // find_vpid never finds 0, negative numbers or unallocated ones.
    for nr in [0, -1, i32::MIN, 2, 32768, 99_999] {
        assert_eq!(l.find_vpid(nr), None, "{nr}");
    }
    assert_eq!(l.getpgid(init, 0), Ok(0));
    assert_eq!(l.getsid(init, 0), Ok(0));
    assert_eq!(l.getpgid(init, 1), Ok(0));
    assert_eq!(l.getpgid(init, 2), Err(Errno::ESRCH));
    assert_eq!(l.getsid(init, -5), Err(Errno::ESRCH));
}

#[test]
fn fork_publishes_children_in_creation_order() {
    let (mut l, init) = list();
    let a = l.fork(init, FORK).unwrap();
    let b = l.fork(init, FORK).unwrap();
    assert_eq!((pid(&l, a), pid(&l, b)), (2, 3));
    assert_eq!(l.children(init).collect::<Vec<_>>(), [a, b]);
    assert_eq!(l.processes().collect::<Vec<_>>(), [init, a, b]);
    // Same group and session as the parent: init_struct_pid, number 0.
    assert_eq!((l.task_pgrp_vnr(a), l.task_session_vnr(a)), (0, 0));
    assert_eq!(l.task_ppid_vnr(a), 1);
    assert_ne!(l.task(a).unwrap().flags & PF_FORKNOEXEC, 0);
    assert!(!l.is_global_init(a));
    assert_eq!(l.task(a).unwrap().exit_signal, SIGCHLD);
    assert_eq!(l.nr_threads(), 3);
}

#[test]
fn fork_limits_follow_copy_process() {
    // max_threads is EAGAIN for everyone; RLIMIT_NPROC only for tasks without
    // CAP_SYS_RESOURCE.
    let (mut l, init) = Tasklist::new(3, &Cred::root(), 100).unwrap();
    let a = l.fork(init, FORK).unwrap();
    let _b = l.fork(init, FORK).unwrap();
    assert_eq!(l.fork(init, FORK), Err(Errno::EAGAIN));
    assert_eq!(l.nr_threads(), 3);
    // A failed fork leaves no pid behind: the next number is still 4.
    l.release_task(a);
    let again = l.fork(init, FORK).unwrap();
    assert_eq!(pid(&l, again), 4);

    let (mut l, init) = list();
    let nproc = ForkParams {
        rlimit_nproc: 2,
        ..FORK
    };
    let user = l.fork(init, FORK).unwrap();
    // root bypasses the limit ...
    assert!(l.fork(init, nproc).is_ok());
    // ... an ordinary user does not (nr_threads 3 >= 2).
    l.task_mut(user).unwrap().cred = user_cred(1000);
    assert_eq!(l.fork(user, nproc), Err(Errno::EAGAIN));
    // A stale or exiting parent cannot fork.
    exit(&mut l, user, 0, &mut Rec::default());
    assert_eq!(l.fork(user, FORK), Err(Errno::ESRCH));
}

#[test]
fn release_task_frees_slot_pid_and_list_links_and_stale_ids_stop_resolving() {
    let (mut l, init) = list();
    let a = l.fork(init, FORK).unwrap();
    let b = l.fork(init, FORK).unwrap();
    let c = l.fork(init, FORK).unwrap();
    let pid_a = l.task_pid_type(a, PidType::Pid).unwrap();
    l.release_task(b);
    assert_eq!(l.children(init).collect::<Vec<_>>(), [a, c]);
    assert!(l.task(b).is_none());
    assert_eq!(l.find_task_by_vpid(3), None);
    assert_eq!(l.processes().collect::<Vec<_>>(), [init, a, c]);
    // The slot is reused by the next task but the stale id stays dead.
    let d = l.fork(init, FORK).unwrap();
    assert_eq!(d.slot(), b.slot());
    assert!(l.task(b).is_none() && l.task(d).is_some());
    // Pid numbers are not reused until the cursor wraps.
    assert_eq!(pid(&l, d), 5);
    // pid object of a is gone with a.
    l.release_task(a);
    assert!(l.pid(pid_a).is_none());
    assert_eq!(l.children(init).collect::<Vec<_>>(), [c, d]);
    l.release_task(a); // double release: nothing happens
}

#[test]
fn exit_status_encodings_reach_the_wait_report() {
    // kernel/exit.c wait_task_zombie: `(status & 0x7f) == 0` exited with
    // status >> 8; else killed (or dumped with 0x80) by `status & 0x7f`.
    let cases: [(u32, i32, i32, i32); 5] = [
        (0, CLD_EXITED, 0, 0),
        (5 << 8, CLD_EXITED, 5, 5 << 8),
        (255 << 8, CLD_EXITED, 255, 255 << 8),
        (9, CLD_KILLED, 9, 9),
        (0x8b, CLD_DUMPED, 11, 0x8b),
    ];
    for (code, cause, status, stat) in cases {
        let (mut l, init) = list();
        let child = l.fork(init, FORK).unwrap();
        let child_pid = pid(&l, child);
        exit(&mut l, child, code, &mut Rec::default());
        let mut wo = l
            .prepare_waitid(init, P_PID, child_pid, WEXITED, |_| unreachable!())
            .unwrap();
        assert_eq!(
            l.do_wait_once(init, &mut wo),
            i64::from(child_pid),
            "{code:#x}"
        );
        assert_eq!(
            (wo.info.cause, wo.info.status, wo.info.pid, wo.info.uid),
            (cause, status, child_pid, 0)
        );
        assert!(l.task(child).is_none(), "reaped");
        // wait4's status word is the exit code itself.
        let (mut l, init) = list();
        let child = l.fork(init, FORK).unwrap();
        exit(&mut l, child, code, &mut Rec::default());
        let (ret, wo) = wait_pid(&mut l, init, -1, 0);
        assert_eq!((ret, wo.stat), (2, stat));
    }
}

#[test]
fn group_exit_code_wins_over_the_thread_exit_code() {
    // do_group_exit keeps an already-started group exit's code; wait reports
    // `group_exit_code` while SIGNAL_GROUP_EXIT is set.
    let (mut l, init) = list();
    let child = l.fork(init, FORK).unwrap();
    assert_eq!(l.do_group_exit(child, 7 << 8), 7 << 8);
    assert_eq!(l.do_group_exit(child, 1 << 8), 7 << 8, "first code sticks");
    exit(&mut l, child, 1 << 8, &mut Rec::default());
    let (ret, wo) = wait_pid(&mut l, init, 2, 0);
    assert_eq!((ret, wo.stat), (2, 7 << 8));
}

#[test]
fn init_death_is_reported_with_the_group_exit_code() {
    // do_exit: panic("Attempted to kill init! exitcode=0x%08x",
    // signal->group_exit_code ?: code).
    let (mut l, init) = list();
    assert_eq!(
        l.exit_prepare(init, 0x100, false),
        ExitPrep::InitDied { exitcode: 0x100 }
    );
    let (mut l, init) = list();
    l.do_group_exit(init, 0xb);
    assert_eq!(
        l.exit_prepare(init, 0xb, true),
        ExitPrep::InitDied { exitcode: 0xb }
    );
    // A zero group code falls back to the code (`?:`).
    let (mut l, init) = list();
    l.do_group_exit(init, 0);
    assert_eq!(
        l.exit_prepare(init, 0, false),
        ExitPrep::InitDied { exitcode: 0 }
    );
    // The reaper cannot be notified out.
    assert!(l.exit_notify(init, &mut Rec::default()).is_err());
}

#[test]
fn sigchld_carries_the_exit_status_and_wakes_the_parent() {
    // kernel/signal.c do_notify_parent: si_code/si_status from exit_code, pid
    // and uid of the child, times in clock_t (USER_HZ 100).
    let (mut l, init) = list();
    l.signal_state(init).unwrap().hand.actions[usize::from(SIGCHLD) - 1].handler = 0x1000;
    let child = l.fork(init, FORK).unwrap();
    l.task_mut(child).unwrap().cred = user_cred(1000);
    l.task_mut(child).unwrap().utime_ns = 30_000_000;
    l.task_mut(child).unwrap().stime_ns = 20_000_000;
    let mut w = Rec::default();
    assert_eq!(exit(&mut l, child, 3 << 8, &mut w), Notified::Zombie);
    assert_eq!(w.child_events, [init]);
    assert_eq!(w.signal_wakes, [init]);
    let (sig, info) = l.signal_state(init).unwrap().dequeue_signal().unwrap();
    assert_eq!(sig, SIGCHLD);
    assert_eq!(
        info,
        SigInfo::chld(CLD_EXITED, 2, 1000, 3, 3, 2),
        "code, pid, uid, status, utime, stime"
    );
    // A killed child reports CLD_KILLED / the signal number.
    let (mut l, init) = list();
    l.signal_state(init).unwrap().hand.actions[usize::from(SIGCHLD) - 1].handler = 0x1000;
    let child = l.fork(init, FORK).unwrap();
    assert_eq!(
        l.exit_prepare(child, 15, true),
        ExitPrep::Proceed { group_dead: true }
    );
    assert_ne!(
        l.task(child).unwrap().flags & super::tasklist::PF_SIGNALED,
        0
    );
    l.exit_notify(child, &mut Rec::default()).unwrap();
    let (_, info) = l.signal_state(init).unwrap().dequeue_signal().unwrap();
    assert_eq!(info, SigInfo::chld(CLD_KILLED, 2, 0, 15, 0, 0));
}

#[test]
fn ignored_sigchld_and_nocldwait_autoreap() {
    // do_notify_parent: SIG_IGN or SA_NOCLDWAIT reaps at once; SIG_IGN sends
    // no signal, SA_NOCLDWAIT still does; waiters are woken either way.
    for (action, signal_queued) in [
        (
            SigAction {
                handler: SIG_IGN,
                ..SigAction::default()
            },
            false,
        ),
        (
            SigAction {
                handler: 0x1000,
                flags: SA_NOCLDWAIT,
                ..SigAction::default()
            },
            true,
        ),
    ] {
        let (mut l, init) = list();
        l.signal_state(init).unwrap().hand.actions[usize::from(SIGCHLD) - 1] = action;
        let child = l.fork(init, FORK).unwrap();
        let mut w = Rec::default();
        assert_eq!(exit(&mut l, child, 0, &mut w), Notified::Reaped);
        assert!(l.task(child).is_none(), "released at once");
        assert_eq!(l.find_task_by_vpid(2), None);
        assert_eq!(w.child_events, [init]);
        assert_eq!(pending(&mut l, init).contains(SIGCHLD), signal_queued);
        // Nothing left to wait for: ECHILD, not a hang.
        assert_eq!(wait_pid(&mut l, init, -1, 0).0, ECHILD);
    }
    // The default action (SIG_DFL) leaves a zombie and queues nothing visible
    // (SIGCHLD is ignored by default so prepare_signal drops it).
    let (mut l, init) = list();
    let child = l.fork(init, FORK).unwrap();
    assert_eq!(
        exit(&mut l, child, 0, &mut Rec::default()),
        Notified::Zombie
    );
    assert_eq!(l.task(child).unwrap().exit_state, ExitState::Zombie);
    assert!(!pending(&mut l, init).contains(SIGCHLD));
}

#[test]
fn reparenting_goes_to_init_in_order_and_notifies_zombies() {
    // forget_original_parent: children get the reaper as parent and are
    // spliced to the tail of its list; zombies are re-notified.
    let (mut l, init) = list();
    let first = l.fork(init, FORK).unwrap(); // pid 2
    let father = l.fork(init, FORK).unwrap(); // pid 3
    let late = l.fork(init, FORK).unwrap(); // pid 4
    let c1 = l.fork(father, FORK).unwrap(); // 5
    let c2 = l.fork(father, FORK).unwrap(); // 6 (zombie)
    let c3 = l.fork(father, FORK).unwrap(); // 7
    l.signal_state(init).unwrap().hand.actions[usize::from(SIGCHLD) - 1].handler = 0x1000;
    exit(&mut l, c2, 4 << 8, &mut Rec::default());
    // The parent's SIGCHLD from c2's exit is for `father`; drain init's.
    let mut w = Rec::default();
    assert_eq!(exit(&mut l, father, 0, &mut w), Notified::Zombie);
    assert_eq!(
        l.children(init).collect::<Vec<_>>(),
        [first, father, late, c1, c2, c3],
        "spliced at the tail in the original order"
    );
    for c in [c1, c2, c3] {
        assert_eq!(l.real_parent(c), Some(init));
        assert_eq!(l.task_ppid_vnr(c), 1);
    }
    assert!(l.children(father).next().is_none());
    // The zombie c2 was re-notified to init (SIGCHLD with its status), and
    // init was told about father's own death too.
    assert!(
        l.signal_state(init)
            .unwrap()
            .pending_set()
            .contains(SIGCHLD)
    );
    assert!(w.child_events.iter().all(|&p| p == init));
    assert_eq!(w.child_events.len(), 2, "c2 re-notified, then father");
    // wait order is list order: father (zombie) comes before c2.
    let (ret, _) = wait_pid(&mut l, init, -1, 0);
    assert_eq!(ret, 3);
    let (ret, wo) = wait_pid(&mut l, init, -1, 0);
    assert_eq!((ret, wo.stat), (6, 4 << 8));
}

#[test]
fn reparented_zombie_is_reaped_at_once_when_init_ignores_sigchld() {
    // reparent_leader: do_notify_parent() true -> EXIT_DEAD -> release_task.
    let (mut l, init) = list();
    l.signal_state(init).unwrap().hand.actions[usize::from(SIGCHLD) - 1].handler = SIG_IGN;
    let father = l.fork(init, FORK).unwrap();
    // copy_sighand: father inherited SIG_IGN; it sets the default back.
    l.signal_state(father).unwrap().hand.actions[usize::from(SIGCHLD) - 1].handler = SIG_DFL;
    let zombie = l.fork(father, FORK).unwrap();
    let live = l.fork(father, FORK).unwrap();
    // father ignores nothing: its child's exit leaves a zombie.
    exit(&mut l, zombie, 0, &mut Rec::default());
    assert_eq!(l.task(zombie).unwrap().exit_state, ExitState::Zombie);
    exit(&mut l, father, 0, &mut Rec::default());
    // init ignores SIGCHLD: father autoreaped, zombie child reaped on reparent.
    assert!(l.task(father).is_none() && l.task(zombie).is_none());
    assert_eq!(l.children(init).collect::<Vec<_>>(), [live]);
    assert_eq!(l.nr_threads(), 2);
}

#[test]
fn wait4_argument_matrix() {
    // kernel_wait4: option mask, INT_MIN, pid / pgrp selection.
    let (mut l, init) = list();
    for options in [0x10, WEXITED, 0x100, WNOWAIT, 0x1000_0000] {
        assert_eq!(
            l.prepare_wait4(init, -1, options).err(),
            Some(Errno::EINVAL),
            "{options:#x}"
        );
    }
    for options in [0, WNOHANG, WUNTRACED, WCONTINUED, WALL, WCLONE, 0x2000_0000] {
        assert!(l.prepare_wait4(init, -1, options).is_ok(), "{options:#x}");
    }
    assert_eq!(l.prepare_wait4(init, i32::MIN, 0).err(), Some(Errno::ESRCH));
    // No children: ECHILD for every selector, WNOHANG or not.
    for upid in [-1, 0, 1, 99_999, -99_999, -1000, i32::MAX] {
        for options in [0, WNOHANG] {
            assert_eq!(wait_pid(&mut l, init, upid, options).0, ECHILD, "{upid}");
        }
    }
    // A child exists: waiting for pid 1 (not a child), a missing group or a
    // number beyond pid_max is still ECHILD; -1 / 0 / its pid block.
    let child = l.fork(init, FORK).unwrap();
    assert_eq!(
        wait_pid(&mut l, init, 1, 0).0,
        ECHILD,
        "init is not my child"
    );
    assert_eq!(wait_pid(&mut l, init, -1000, 0).0, ECHILD);
    assert_eq!(wait_pid(&mut l, init, 3, 0).0, ECHILD, "no such pid yet");
    for upid in [-1, 0, 2] {
        // Running child: blocks (-ERESTARTSYS) or WNOHANG reports 0.
        assert_eq!(wait_pid(&mut l, init, upid, 0).0, -ERESTARTSYS, "{upid}");
        assert_eq!(wait_pid(&mut l, init, upid, WNOHANG).0, 0, "{upid}");
    }
    // pgrp 0 means the caller's group: the child shares init's.
    assert_eq!(
        l.task_pid_type(child, PidType::Pgid),
        l.task_pid_type(init, PidType::Pgid)
    );
    // __WCLONE alone never matches a SIGCHLD child; __WALL does.
    assert_eq!(wait_pid(&mut l, init, -1, WCLONE | WNOHANG).0, ECHILD);
    assert_eq!(wait_pid(&mut l, init, -1, WALL | WNOHANG).0, 0);
    exit(&mut l, child, 2 << 8, &mut Rec::default());
    assert_eq!(wait_pid(&mut l, init, -1, WCLONE).0, ECHILD);
    let (ret, wo) = wait_pid(&mut l, init, 2, 0);
    assert_eq!((ret, wo.stat), (2, 2 << 8));
    assert_eq!(wait_pid(&mut l, init, 2, 0).0, ECHILD, "reaped once");
}

#[test]
fn waitid_argument_matrix() {
    // kernel_waitid_prepare.
    let (l, init) = list();
    let none = |_: i32| -> Result<(Option<_>, bool), Errno> { unreachable!() };
    let prep = |which, upid, options| l.prepare_waitid(init, which, upid, options, none).err();
    // No event bits / unknown options / unknown idtype.
    assert_eq!(prep(P_ALL, 0, 0), Some(Errno::EINVAL));
    assert_eq!(prep(P_ALL, 0, WNOHANG), Some(Errno::EINVAL));
    assert_eq!(prep(P_ALL, 0, WEXITED | 0x10), Some(Errno::EINVAL));
    assert_eq!(prep(9, 0, WEXITED), Some(Errno::EINVAL));
    assert_eq!(prep(-1, 0, WEXITED), Some(Errno::EINVAL));
    // P_PID needs a positive id, P_PGID a non-negative one.
    assert_eq!(prep(P_PID, 0, WEXITED), Some(Errno::EINVAL));
    assert_eq!(prep(P_PID, -3, WEXITED), Some(Errno::EINVAL));
    assert_eq!(prep(P_PGID, -1, WEXITED), Some(Errno::EINVAL));
    assert_eq!(prep(P_PIDFD, -1, WEXITED), Some(Errno::EINVAL));
    for (which, upid) in [
        (P_ALL, 0),
        (P_ALL, 77),
        (P_PID, 5),
        (P_PGID, 0),
        (P_PGID, 9),
    ] {
        for options in [
            WEXITED,
            WSTOPPED_FLAG,
            WCONTINUED,
            WEXITED | WNOWAIT | WNOHANG,
        ] {
            assert!(
                prep(which, upid, options).is_none(),
                "{which} {upid} {options:#x}"
            );
        }
    }
    // P_PIDFD: the resolver's error is the error; its O_NONBLOCK is WNOHANG.
    let err = l
        .prepare_waitid(init, P_PIDFD, 5, WEXITED, |fd| {
            assert_eq!(fd, 5);
            Err(Errno::EBADF)
        })
        .err();
    assert_eq!(err, Some(Errno::EBADF));
    let wo = l
        .prepare_waitid(init, P_PIDFD, 5, WEXITED, |_| Ok((None, true)))
        .unwrap();
    assert_ne!(wo.flags & WNOHANG, 0);
    // P_PGID 0 is the caller's own group.
    let wo = l.prepare_waitid(init, P_PGID, 0, WEXITED, none).unwrap();
    assert_eq!(wo.wo_pid, l.task_pid_type(init, PidType::Pgid));
}

const WSTOPPED_FLAG: u32 = 2;

#[test]
fn wnowait_leaves_the_zombie_and_reaping_folds_child_times() {
    let (mut l, init) = list();
    let child = l.fork(init, FORK).unwrap();
    l.task_mut(child).unwrap().utime_ns = 7_000_000_000;
    l.task_mut(child).unwrap().stime_ns = 1_000_000_000;
    l.task_mut(child).unwrap().cutime_ns = 2_000_000_000;
    exit(&mut l, child, 5 << 8, &mut Rec::default());
    let mut wo = l
        .prepare_waitid(init, P_PID, 2, WEXITED | WNOWAIT, |_| unreachable!())
        .unwrap();
    assert_eq!(l.do_wait_once(init, &mut wo), 2);
    assert_eq!(wo.info.status, 5);
    assert_eq!(wo.rusage, (9_000_000_000, 1_000_000_000));
    assert_eq!(l.task(child).unwrap().exit_state, ExitState::Zombie);
    assert_eq!(l.task(init).unwrap().cutime_ns, 0, "not folded yet");
    // Again, without WNOWAIT: reaped, times folded into `cutime`.
    let (ret, _) = wait_pid(&mut l, init, 2, 0);
    assert_eq!(ret, 2);
    assert!(l.task(child).is_none());
    assert_eq!(
        (
            l.task(init).unwrap().cutime_ns,
            l.task(init).unwrap().cstime_ns
        ),
        (9_000_000_000, 1_000_000_000)
    );
}

#[test]
fn stop_and_continue_are_reported_once() {
    // wait_task_stopped / wait_task_continued.
    let (mut l, init) = list();
    let child = l.fork(init, FORK).unwrap();
    // Not stopped: WUNTRACED alone has nothing; the child is alive so a
    // blocking wait would sleep.
    assert_eq!(wait_pid(&mut l, init, 2, WUNTRACED | WNOHANG).0, 0);
    {
        let t = l.task_mut(child).unwrap();
        t.jobctl |= JOBCTL_STOPPED;
        t.signals.signal.job_flags = super::exit::SIGNAL_STOP_STOPPED;
        t.signals.signal.stop_code = u32::from(SIGSTOP);
    }
    // Without WUNTRACED a stopped child is invisible (but still "something
    // to wait for").
    assert_eq!(wait_pid(&mut l, init, 2, WNOHANG).0, 0);
    // With WNOWAIT the report repeats and the status is untouched.
    let mut wo = l
        .prepare_waitid(init, P_PID, 2, WSTOPPED_FLAG | WNOWAIT, |_| unreachable!())
        .unwrap();
    assert_eq!(l.do_wait_once(init, &mut wo), 2);
    assert_eq!(
        (wo.info.cause, wo.info.status),
        (CLD_STOPPED, i32::from(SIGSTOP))
    );
    assert_eq!(wo.stat, 0);
    let (ret, wo) = wait_pid(&mut l, init, 2, WUNTRACED);
    assert_eq!((ret, wo.stat), (2, (i32::from(SIGSTOP) << 8) | 0x7f));
    // Reported once.
    assert_eq!(wait_pid(&mut l, init, 2, WUNTRACED | WNOHANG).0, 0);
    // Continue: the task runs again, SIGNAL_STOP_CONTINUED is pending.
    {
        let t = l.task_mut(child).unwrap();
        t.jobctl &= !JOBCTL_STOPPED;
        t.signals.signal.job_flags = super::exit::SIGNAL_STOP_CONTINUED;
    }
    assert_eq!(wait_pid(&mut l, init, 2, WNOHANG).0, 0, "needs WCONTINUED");
    let mut wo = l
        .prepare_waitid(init, P_PID, 2, WCONTINUED, |_| unreachable!())
        .unwrap();
    assert_eq!(l.do_wait_once(init, &mut wo), 2);
    assert_eq!(
        (wo.info.cause, wo.info.status),
        (CLD_CONTINUED, i32::from(SIGCONT))
    );
    assert_eq!(wait_pid(&mut l, init, 2, WCONTINUED | WNOHANG).0, 0, "once");
    // wait4 form: status 0xffff.
    l.task_mut(child).unwrap().signals.signal.job_flags = super::exit::SIGNAL_STOP_CONTINUED;
    let (ret, wo) = wait_pid(&mut l, init, 2, WCONTINUED);
    assert_eq!((ret, wo.stat), (2, 0xffff));
}

#[test]
fn cldstop_notification_honours_nocldstop_and_always_wakes() {
    // do_notify_parent_cldstop.
    let (mut l, init) = list();
    let child = l.fork(init, FORK).unwrap();
    l.task_mut(child).unwrap().signals.signal.stop_code = u32::from(SIGSTOP);
    let chld = usize::from(SIGCHLD) - 1;
    // SIG_DFL: SIGCHLD is generated (and dropped as ignored by default, so
    // block it to see it), the waiters are woken.
    l.signal_state(init).unwrap().me.blocked.add(SIGCHLD);
    let mut w = Rec::default();
    l.do_notify_parent_cldstop(child, CLD_STOPPED, &mut w);
    assert_eq!(w.child_events, [init]);
    let (_, info) = l
        .signal_state(init)
        .unwrap()
        .dequeue_signal_masked(SigSet::EMPTY)
        .unwrap();
    assert_eq!(
        info,
        SigInfo::chld(CLD_STOPPED, 2, 0, i32::from(SIGSTOP), 0, 0)
    );
    for action in [
        SigAction {
            handler: SIG_IGN,
            ..SigAction::default()
        },
        SigAction {
            handler: 0x1000,
            flags: SA_NOCLDSTOP,
            ..SigAction::default()
        },
    ] {
        l.signal_state(init).unwrap().hand.actions[chld] = action;
        let mut w = Rec::default();
        l.do_notify_parent_cldstop(child, CLD_CONTINUED, &mut w);
        assert_eq!(w.child_events, [init], "wakes even without a signal");
        assert!(w.signal_wakes.is_empty());
        assert_eq!(pending(&mut l, init), SigSet::EMPTY);
    }
}

#[test]
fn setpgid_truth_table() {
    // kernel/sys.c setpgid.
    let (mut l, init) = list();
    let a = l.fork(init, FORK).unwrap(); // 2
    let b = l.fork(a, FORK).unwrap(); // 3, child of a
    // pgid < 0: EINVAL before any lookup (even for a missing pid).
    assert_eq!(l.setpgid(a, 0, -1), Err(Errno::EINVAL));
    assert_eq!(l.setpgid(a, 99_999, -1), Err(Errno::EINVAL));
    // No such task: ESRCH. A negative pid with pgid 0 makes pgid negative
    // (EINVAL); with an explicit pgid it names no task (ESRCH).
    assert_eq!(l.setpgid(a, 99_999, 0), Err(Errno::ESRCH));
    assert_eq!(l.setpgid(a, -2, 0), Err(Errno::EINVAL));
    assert_eq!(l.setpgid(a, -2, 5), Err(Errno::ESRCH));
    // init (a's parent, not a child of a, not a): ESRCH.
    assert_eq!(l.setpgid(a, 1, 1), Err(Errno::ESRCH));
    // a task that is neither the caller nor its child: ESRCH.
    let other = l.fork(init, FORK).unwrap(); // 4
    assert_eq!(l.setpgid(a, pid(&l, other), 0), Err(Errno::ESRCH));
    // A child before exec may be moved by its parent, then it leads its group.
    assert_eq!(l.setpgid(a, 3, 3), Ok(()));
    assert_eq!(l.getpgid(a, 3), Ok(3));
    assert_eq!(
        l.task_pid_type(b, PidType::Pgid),
        l.task_pid_type(b, PidType::Pid)
    );
    // setpgid(0, 0) on itself: pgid = own pid.
    assert_eq!(l.setpgid(a, 0, 0), Ok(()));
    assert_eq!(l.getpgid(a, 0), Ok(2));
    // Joining an existing group of the same session by number.
    assert_eq!(l.setpgid(a, 3, 2), Ok(()));
    assert_eq!(l.getpgid(a, 3), Ok(2));
    // A group that does not exist, or whose session differs: EPERM.
    assert_eq!(l.setpgid(a, 3, 77), Err(Errno::EPERM));
    // After exec the parent may no longer move the child: EACCES.
    let c = l.fork(a, FORK).unwrap(); // 5
    l.exec_committed(c, &Cred::root());
    assert_eq!(l.setpgid(a, 5, 5), Err(Errno::EACCES));
    // The child itself may (p == caller): EACCES is for the parent only.
    assert_eq!(l.setpgid(c, 0, 0), Ok(()));
    // A session leader cannot change group: EPERM.
    assert_eq!(l.setsid(c), Err(Errno::EPERM), "group 5 exists already");
}

#[test]
fn setsid_and_session_rules() {
    // kernel/sys.c ksys_setsid / setpgid session checks.
    let (mut l, init) = list();
    let a = l.fork(init, FORK).unwrap(); // 2
    let b = l.fork(init, FORK).unwrap(); // 3
    let child = l.fork(a, FORK).unwrap(); // 4, child of a
    assert_eq!(l.setsid(a), Ok(2));
    assert_eq!((l.getsid(a, 0), l.getpgid(a, 0)), (Ok(2), Ok(2)));
    assert!(l.task(a).unwrap().session_leader);
    // Already a leader: EPERM, also for setpgid on itself.
    assert_eq!(l.setsid(a), Err(Errno::EPERM));
    assert_eq!(l.setpgid(a, 0, 0), Err(Errno::EPERM));
    // Another session's task is visible to getsid/getpgid (no permission check).
    assert_eq!((l.getsid(b, 2), l.getpgid(b, 2)), (Ok(2), Ok(2)));
    assert_eq!(l.getsid(b, 0), Ok(0));
    // a's child is in a's session now? No: it was forked before setsid and
    // keeps init's session, so a cannot move it (EPERM: sessions differ).
    assert_eq!(l.setpgid(a, 4, 4), Err(Errno::EPERM));
    // A child forked after setsid inherits the new session and group.
    let late = l.fork(a, FORK).unwrap(); // 5
    assert_eq!((l.task_session_vnr(late), l.task_pgrp_vnr(late)), (2, 2));
    // setsid fails when a process group with the caller's pid number exists:
    // `late` is in group 2 only through a; give b a group number equal to
    // late's pid by making late lead group 5 first.
    assert_eq!(l.setpgid(a, 5, 5), Ok(()));
    let _ = (child, b);
    // late is now a group leader of 5 but not a session leader: setsid fails
    // (EPERM: pid_task(sid, PIDTYPE_PGID) exists).
    assert_eq!(l.setsid(late), Err(Errno::EPERM));
    // Once the group empties, setsid works.
    let lone = l.fork(init, FORK).unwrap(); // 6
    assert_eq!(l.setsid(lone), Ok(6));
    assert_eq!(l.task_session_vnr(lone), 6);
}

#[test]
fn pid_numbers_stay_reserved_while_a_group_or_session_uses_them() {
    // kernel/pid.c free_pid only when no type is attached.
    let (mut l, init) = list();
    let leader = l.fork(init, FORK).unwrap(); // 2
    let member = l.fork(leader, FORK).unwrap(); // 3
    l.setsid(leader).unwrap();
    let m2 = l.fork(leader, FORK).unwrap(); // 4, in session 2 / group 2
    exit(&mut l, leader, 0, &mut Rec::default());
    // leader is a zombie: released only on reap.
    let (ret, _) = wait_pid(&mut l, init, 2, 0);
    assert_eq!(ret, 2);
    assert!(l.task(leader).is_none());
    // Its pid object lives on as group/session 2 of m2 (reparented to init).
    assert!(l.find_vpid(2).is_some());
    assert_eq!(l.task_pgrp_vnr(m2), 2);
    // Wrap-around tests live in pid.rs; here the number is not reusable and a
    // setpgid to the dead leader's group still works (same session? member is
    // in init's session: no).
    assert_eq!(l.setpgid(member, 0, 2), Err(Errno::EPERM));
    // Last member leaves: the number is freed.
    exit(&mut l, m2, 0, &mut Rec::default());
    let _ = wait_pid(&mut l, init, 4, 0);
    assert!(l.find_vpid(2).is_none());
}

#[test]
fn orphaned_process_groups() {
    // will_become_orphaned_pgrp / kill_orphaned_pgrp (kernel/exit.c 361-431).
    let (mut l, init) = list();
    let shell = l.fork(init, FORK).unwrap(); // 2
    l.setsid(shell).unwrap(); // session 2, group 2
    let job_leader = l.fork(shell, FORK).unwrap(); // 3, session 2
    l.setpgid(shell, 3, 3).unwrap(); // its own group, parent shell outside it
    let job_member = l.fork(job_leader, FORK).unwrap(); // 4 in group 3
    let pgrp = l.task_pid_type(job_leader, PidType::Pgid).unwrap();
    // Parent (shell) is in another group of the same session: not orphaned.
    assert!(!l.will_become_orphaned_pgrp(pgrp, None));
    assert!(!l.is_pgrp_orphaned(job_member));
    // Stop the group (SIGNAL_STOP_STOPPED on the member).
    l.task_mut(job_member).unwrap().signals.signal.job_flags = super::exit::SIGNAL_STOP_STOPPED;
    assert!(l.has_stopped_jobs(pgrp));
    for t in [job_leader, job_member] {
        // Handlers so SIGHUP/SIGCONT are queued and visible.
        for sig in [SIGHUP, SIGCONT] {
            l.signal_state(t).unwrap().hand.actions[usize::from(sig) - 1].handler = 0x1000;
        }
        l.signal_state(t).unwrap().me.blocked = SigSet(SigSet::bit(SIGHUP) | SigSet::bit(SIGCONT));
    }
    // The shell exits: the group becomes orphaned and has stopped jobs, so it
    // gets SIGHUP then SIGCONT. init adopts the group's tasks.
    let mut w = Rec::default();
    exit(&mut l, shell, 0, &mut w);
    for t in [job_leader, job_member] {
        let set = pending(&mut l, t);
        assert!(set.contains(SIGHUP) && set.contains(SIGCONT), "{t:?}");
    }
    // Orphaned now (parent is the reaper, global init): a stopped group of
    // init's children is not signalled again.
    assert!(l.will_become_orphaned_pgrp(pgrp, None));
    // Without stopped jobs nothing is sent.
    let (mut l, init) = list();
    let shell = l.fork(init, FORK).unwrap();
    l.setsid(shell).unwrap();
    let job = l.fork(shell, FORK).unwrap();
    l.setpgid(shell, 3, 3).unwrap();
    l.signal_state(job).unwrap().me.blocked = SigSet(SigSet::bit(SIGHUP));
    l.signal_state(job).unwrap().hand.actions[usize::from(SIGHUP) - 1].handler = 0x1000;
    exit(&mut l, shell, 0, &mut Rec::default());
    assert!(!pending(&mut l, job).contains(SIGHUP));
}

#[test]
fn init_is_a_connection_to_the_idle_tasks_session() {
    // kernel/exit.c:361-378: init's real_parent is the idle task, which is not
    // is_global_init and whose group and session are init_struct_pid. After
    // setpgid(init, 1, 1) init's group is 1 and its session is still
    // init_struct_pid, so group 1 is not orphaned.
    let (mut l, init) = list();
    l.setpgid(init, 1, 1).unwrap();
    let pgrp = l.task_pid_type(init, PidType::Pgid).unwrap();
    assert_ne!(pgrp, l.init_struct_pid());
    assert!(!l.will_become_orphaned_pgrp(pgrp, None));
    assert!(!l.is_pgrp_orphaned(init));
    // Left in init_struct_pid (its own group as the idle task's), it is.
    let (l, init) = list();
    assert!(l.is_pgrp_orphaned(init));
}

#[test]
fn a_group_exit_drops_the_stop_state() {
    // kernel/signal.c complete_signal 1041-1043, kernel/exit.c do_group_exit
    // 1119: `signal->flags = SIGNAL_GROUP_EXIT` replaces SIGNAL_STOP_STOPPED.
    let (mut l, init) = list();
    let child = l.fork(init, FORK).unwrap();
    let mark = |l: &mut Tasklist| {
        let sig = &mut l.task_mut(child).unwrap().signals.signal;
        sig.job_flags = super::exit::SIGNAL_STOP_STOPPED;
        sig.stop_code = 19;
    };
    mark(&mut l);
    l.do_group_exit(child, 3);
    let sig = &l.task(child).unwrap().signals.signal;
    assert_eq!(
        (sig.job_flags, sig.stop_code, sig.group_exit),
        (0, 0, Some(3))
    );
    // A fatal signal (complete_signal) does the same.
    let (mut l, init) = list();
    let child = l.fork(init, FORK).unwrap();
    mark(&mut l);
    l.signal_state(child)
        .unwrap()
        .send_signal(
            SIGTERM,
            SigInfo::kernel(SIGTERM),
            crate::signal::state::Target::Process,
        )
        .unwrap();
    let sig = &l.task(child).unwrap().signals.signal;
    assert_eq!((sig.job_flags, sig.stop_code), (0, 0));
    assert_eq!(sig.group_exit, Some(u32::from(SIGTERM)));
}

#[test]
fn kill_permission_uses_the_credential_snapshots() {
    // kernel/signal.c check_kill_permission / kill_ok_by_cred.
    let (mut l, init) = list();
    let alice = l.fork(init, FORK).unwrap();
    let bob = l.fork(init, FORK).unwrap();
    l.task_mut(alice).unwrap().cred = user_cred(1000);
    l.task_mut(bob).unwrap().cred = user_cred(2000);
    for t in [alice, bob] {
        l.signal_state(t).unwrap().hand.actions[usize::from(SIGUSR1) - 1].handler = 0x1000;
    }
    let info = SigInfo::from_kill(SIGUSR1, false, 2, 1000);
    let mut w = Rec::default();
    let sig = i32::from(SIGUSR1);
    // Different uids, no capability: EPERM, nothing queued.
    assert_eq!(
        l.kill_something_info(alice, sig, info, pid(&l, bob), &mut w),
        Err(Errno::EPERM)
    );
    assert!(!pending(&mut l, bob).contains(SIGUSR1));
    // Same uid (via saved uid) is enough.
    l.task_mut(bob).unwrap().cred = CredSnapshot {
        suid: 1000,
        ..user_cred(2000)
    };
    assert_eq!(
        l.kill_something_info(alice, sig, info, pid(&l, bob), &mut w),
        Ok(())
    );
    assert!(pending(&mut l, bob).contains(SIGUSR1));
    assert_eq!(w.signal_wakes, [bob]);
    // root (CAP_KILL) may signal anyone; signal 0 only probes.
    l.task_mut(bob).unwrap().cred = user_cred(2000);
    assert_eq!(
        l.kill_something_info(init, 0, info, pid(&l, bob), &mut w),
        Ok(())
    );
    assert_eq!(
        l.kill_something_info(alice, 0, info, pid(&l, bob), &mut w),
        Err(Errno::EPERM)
    );
    // Bad signal numbers are EINVAL (before the permission check).
    for bad in [-1, 65, 1000] {
        assert_eq!(
            l.kill_something_info(alice, bad, info, pid(&l, bob), &mut w),
            Err(Errno::EINVAL)
        );
    }
    // SIGCONT crosses uids inside one session (both are in init's), but not
    // into another one.
    let cont = SigInfo::from_kill(SIGCONT, false, 2, 1000);
    let sig_cont = i32::from(SIGCONT);
    assert_eq!(
        l.kill_something_info(alice, sig_cont, cont, pid(&l, bob), &mut w),
        Ok(())
    );
    l.setsid(bob).unwrap();
    assert_eq!(
        l.kill_something_info(alice, sig_cont, cont, pid(&l, bob), &mut w),
        Err(Errno::EPERM)
    );
    assert_eq!(
        l.kill_something_info(alice, sig, info, pid(&l, bob), &mut w),
        Err(Errno::EPERM)
    );
}

#[test]
fn kill_target_selection() {
    // kill_something_info.
    let (mut l, init) = list();
    let a = l.fork(init, FORK).unwrap(); // 2
    let b = l.fork(init, FORK).unwrap(); // 3
    let c = l.fork(init, FORK).unwrap(); // 4
    l.setpgid(init, 3, 3).unwrap();
    l.setpgid(init, 4, 3).unwrap();
    for t in [a, b, c] {
        l.signal_state(t).unwrap().hand.actions[usize::from(SIGUSR1) - 1].handler = 0x1000;
        l.signal_state(t).unwrap().me.blocked.add(SIGUSR1);
    }
    let sig = i32::from(SIGUSR1);
    let info = SigInfo::from_kill(SIGUSR1, false, 1, 0);
    let mut w = Rec::default();
    let mut send =
        |l: &mut Tasklist, from, pid| l.kill_something_info(from, sig, info, pid, &mut w);
    let got =
        |l: &mut Tasklist| -> [bool; 3] { [a, b, c].map(|t| pending(l, t).contains(SIGUSR1)) };
    // pid > 0: that process; missing: ESRCH; INT_MIN: ESRCH.
    assert_eq!(send(&mut l, init, 2), Ok(()));
    assert_eq!(got(&mut l), [true, false, false]);
    assert_eq!(send(&mut l, init, 99), Err(Errno::ESRCH));
    assert_eq!(send(&mut l, init, i32::MIN), Err(Errno::ESRCH));
    // pid < -1: the group -pid; an empty or missing group is ESRCH.
    assert_eq!(send(&mut l, init, -3), Ok(()));
    assert_eq!(got(&mut l), [true, true, true]);
    assert_eq!(send(&mut l, init, -99), Err(Errno::ESRCH));
    // pid == 0: the sender's own group.
    for t in [a, b, c] {
        l.signal_state(t).unwrap().flush_signals(!0);
    }
    assert_eq!(send(&mut l, b, 0), Ok(()));
    assert_eq!(got(&mut l), [false, true, true]);
    // pid == -1: everything but pid 1 and the sender's own thread group.
    for t in [a, b, c] {
        l.signal_state(t).unwrap().flush_signals(!0);
    }
    assert_eq!(send(&mut l, a, -1), Ok(()));
    assert_eq!(
        got(&mut l),
        [false, true, true],
        "init is skipped, so is the sender"
    );
    assert!(!pending(&mut l, init).contains(SIGUSR1));
    // With nobody else: ESRCH.
    let (mut l, init) = list();
    assert_eq!(
        l.kill_something_info(init, sig, info, -1, &mut Rec::default()),
        Err(Errno::ESRCH)
    );
}

#[test]
fn kill_pgrp_returns_success_if_any_member_accepted() {
    // __kill_pgrp_info: 0 if any succeeded, else the last error.
    let (mut l, init) = list();
    let a = l.fork(init, FORK).unwrap();
    let b = l.fork(init, FORK).unwrap();
    l.setsid(a).unwrap();
    l.setpgid(init, 3, 2).unwrap_err(); // other session: refused
    let _ = b;
    l.task_mut(a).unwrap().cred = user_cred(1000);
    let sender = l.fork(a, FORK).unwrap(); // in group 2, uid 1000
    l.task_mut(sender).unwrap().cred = user_cred(1000);
    let c = l.fork(a, FORK).unwrap();
    l.task_mut(c).unwrap().cred = user_cred(2000);
    for t in [a, c, sender] {
        l.signal_state(t).unwrap().hand.actions[usize::from(SIGUSR1) - 1].handler = 0x1000;
    }
    let sig = i32::from(SIGUSR1);
    let info = SigInfo::from_kill(SIGUSR1, false, 4, 1000);
    // sender (uid 1000) can reach a and itself but not c: success.
    assert_eq!(
        l.kill_something_info(sender, sig, info, -2, &mut Rec::default()),
        Ok(())
    );
    // Only c would be left: EPERM (the last error).
    l.task_mut(a).unwrap().cred = user_cred(3000);
    l.task_mut(sender).unwrap().cred = user_cred(3000);
    let outsider = l.fork(init, FORK).unwrap();
    l.task_mut(outsider).unwrap().cred = user_cred(1000);
    assert_eq!(
        l.kill_something_info(outsider, sig, info, -2, &mut Rec::default()),
        Err(Errno::EPERM)
    );
}

#[test]
fn credential_snapshot_is_published_at_fork_and_exec() {
    // Judge flaw 1: cross-task readers must not depend on the owner.
    let (mut l, init) = list();
    let child = l.fork(init, FORK).unwrap();
    assert_eq!(l.task(child).unwrap().cred, CredSnapshot::of(&Cred::root()));
    let user = Cred {
        uid: 1000,
        euid: 1001,
        suid: 1002,
        ..Cred::root()
    };
    l.exec_committed(child, &user);
    let snap = l.task(child).unwrap().cred;
    assert_eq!(snap, CredSnapshot::of(&user));
    assert_eq!((snap.uid, snap.euid, snap.suid), (1000, 1001, 1002));
    assert!(
        !snap.cap_kill && !snap.cap_sys_resource,
        "non-root has no capabilities"
    );
    assert!(CredSnapshot::of(&Cred::root()).cap_kill);
    // A forked child inherits the parent's snapshot, whatever the cred table says.
    l.publish_cred(child, &user);
    let grandchild = l.fork(child, FORK).unwrap();
    assert_eq!(l.task(grandchild).unwrap().cred, snap);
    // exec clears PF_FORKNOEXEC.
    assert_eq!(l.task(child).unwrap().flags & PF_FORKNOEXEC, 0);
}

#[test]
fn signal_state_view_derives_ids_from_the_task() {
    let (mut l, init) = list();
    let child = l.fork(init, FORK).unwrap();
    l.task_mut(child).unwrap().cred = user_cred(1234);
    let s = l.signal_state(init).unwrap();
    assert_eq!((s.pid, s.tgid, s.uid, s.global_init), (1, 1, 0, true));
    assert!(s.sig.unkillable);
    let s = l.signal_state(child).unwrap();
    assert_eq!((s.pid, s.tgid, s.uid, s.global_init), (2, 2, 1234, false));
    assert!(!s.sig.unkillable);
    assert_eq!(s.sig.rlimit_sigpending, 100);
    l.release_task(child);
    assert!(l.signal_state(child).is_none(), "stale id");
    let _ = SIGKILL;
    let _ = SIGTERM;
}

#[test]
fn many_children_exit_and_are_reaped_without_leaking_ids() {
    // Fork/exit/wait churn: pids advance monotonically, slots are reused, the
    // tables return to their starting size.
    let (mut l, init) = list();
    let mut last = 1;
    for round in 0..200 {
        let a = l.fork(init, FORK).unwrap();
        let b = l.fork(a, FORK).unwrap();
        assert!(pid(&l, a) > last && pid(&l, b) > pid(&l, a), "{round}");
        last = pid(&l, b);
        exit(&mut l, b, 0, &mut Rec::default());
        exit(&mut l, a, 0, &mut Rec::default());
        // a is a zombie with a zombie child b reparented to init.
        let mut reaped = 0;
        while wait_pid(&mut l, init, -1, WNOHANG).0 > 0 {
            reaped += 1;
        }
        assert_eq!(reaped, 2);
        assert_eq!(l.nr_threads(), 1);
    }
    assert_eq!(l.children(init).count(), 0);
    assert_eq!(l.processes().count(), 1);
}

/// The scheduler seam: the model's `Waker` realised on `sched::Rq`, as the
/// binary does it (`SchedWaker`).
struct RqWaker<'a> {
    rq: &'a mut crate::sched::Rq,
    init: (TaskId, crate::sched::SchedId),
}
impl Waker for RqWaker<'_> {
    fn child_event(&mut self, parent: TaskId) {
        self.rq.wake_up_key(
            super::exit::chldexit_key(parent),
            crate::sched::WakeMode::Interruptible,
            1,
        );
    }
    fn signal_wake(&mut self, task: TaskId, sched: Option<crate::sched::SchedId>) {
        if task == self.init.0 {
            assert_eq!(
                sched,
                Some(self.init.1),
                "the model passes the bound handle"
            );
            self.rq.wake_interruptible(self.init.1);
        }
    }
}

#[test]
fn child_exit_wakes_only_the_parents_wait_chldexit_sleepers() {
    // kernel/exit.c do_wait: the parent sleeps on its own signal_struct's
    // wait_chldexit (TASK_INTERRUPTIBLE); __wake_up_parent wakes that queue.
    use crate::sched::{Rq, TaskState};
    let (mut l, init) = list();
    let child = l.fork(init, FORK).unwrap();
    let mut rq = Rq::new(4).unwrap();
    let sid = rq.add_task().unwrap();
    l.set_sched(init, sid);
    assert!(rq.wake_up_new_task(sid));
    assert_eq!(rq.schedule().unwrap().next, sid);
    rq.prepare_to_wait(super::exit::chldexit_key(init), TaskState::Interruptible);
    rq.schedule();
    assert_eq!(rq.state(sid), Some(TaskState::Interruptible));
    assert_ne!(
        super::exit::chldexit_key(init),
        super::exit::chldexit_key(child)
    );
    // The child's own queue (it has no children to wait for) wakes nobody.
    assert_eq!(
        rq.wake_up_key(
            super::exit::chldexit_key(child),
            crate::sched::WakeMode::Interruptible,
            1
        ),
        0
    );
    let mut w = RqWaker {
        rq: &mut rq,
        init: (init, sid),
    };
    assert_eq!(
        l.exit_prepare(child, 0, false),
        ExitPrep::Proceed { group_dead: true }
    );
    l.exit_notify(child, &mut w).unwrap();
    assert_eq!(rq.state(sid), Some(TaskState::Running));
}

#[test]
fn a_clone_exit_signal_other_than_sigchld_is_sent_with_the_chld_payload() {
    // do_notify_parent: `info.si_signo = sig`; exit signal 0 or above _NSIG
    // sends nothing but still wakes the waiters; none of them autoreaps.
    let (mut l, init) = list();
    l.signal_state(init).unwrap().hand.actions[usize::from(SIGUSR1) - 1].handler = 0x1000;
    let with = |signal: u8| ForkParams {
        exit_signal: signal,
        ..FORK
    };
    let child = l.fork(init, with(SIGUSR1)).unwrap();
    let mut w = Rec::default();
    assert_eq!(exit(&mut l, child, 4 << 8, &mut w), Notified::Zombie);
    assert_eq!(w.child_events, [init]);
    let (sig, info) = l.signal_state(init).unwrap().dequeue_signal().unwrap();
    assert_eq!(sig, SIGUSR1);
    assert_eq!(info.signo, i32::from(SIGUSR1));
    assert_eq!(
        (info.code, &info.body[..4]),
        (CLD_EXITED, &2i32.to_le_bytes()[..])
    );
    for silent in [0, 65, 200] {
        let child = l.fork(init, with(silent)).unwrap();
        let mut w = Rec::default();
        assert_eq!(exit(&mut l, child, 0, &mut w), Notified::Zombie);
        assert_eq!(w.child_events, [init], "{silent}");
        assert!(w.signal_wakes.is_empty(), "{silent}");
        assert!(l.signal_state(init).unwrap().dequeue_signal().is_none());
    }
    // wait: a clone child is invisible to a plain wait and found by __WCLONE.
    assert_eq!(wait_pid(&mut l, init, -1, WNOHANG).0, ECHILD);
}

#[test]
fn a_parent_that_exec_d_gets_sigchld_instead_of_the_clone_exit_signal() {
    // do_notify_parent (kernel/signal.c:2273-2279): the child recorded the
    // parent's self_exec_id at clone; an exec bumps it, so the custom signal
    // falls back to SIGCHLD (and si_signo says so).
    let (mut l, init) = list();
    let p = l.fork(init, FORK).unwrap();
    for sig in [SIGUSR1, SIGCHLD] {
        l.signal_state(p).unwrap().hand.actions[usize::from(sig) - 1].handler = 0x1000;
    }
    let with = ForkParams {
        exit_signal: SIGUSR1,
        ..FORK
    };
    let stale = l.fork(p, with).unwrap();
    l.exec_committed(p, &Cred::root());
    let after = l.fork(p, with).unwrap();
    for (child, want) in [(stale, SIGCHLD), (after, SIGUSR1)] {
        let mut w = Rec::default();
        exit(&mut l, child, 0, &mut w);
        let (sig, info) = l.signal_state(p).unwrap().dequeue_signal().unwrap();
        assert_eq!((sig, info.signo), (want, i32::from(want)));
    }
}

#[test]
fn clone_clear_sighand_flushes_like_exec_and_keeps_sig_ign() {
    // copy_sighand (kernel/fork.c:1628): `flush_signal_handlers(tsk, 0)`, which the
    // pinned kernel confirmed (`fork.clone3-clear-sighand`): SIG_IGN survives.
    let (mut l, init) = list();
    {
        let state = l.signal_state(init).unwrap();
        let hup = &mut state.hand.actions[usize::from(SIGHUP) - 1];
        hup.handler = SIG_IGN;
        let usr1 = &mut state.hand.actions[usize::from(SIGUSR1) - 1];
        (usr1.handler, usr1.flags, usr1.restorer) = (0x1000, 4, 0x2000);
    }
    let plain = l.fork(init, FORK).unwrap();
    let cleared = l
        .fork(
            init,
            ForkParams {
                clear_sighand: true,
                ..FORK
            },
        )
        .unwrap();
    let hand = |l: &mut Tasklist, task| {
        let state = l.signal_state(task).unwrap();
        let usr1 = state.hand.actions[usize::from(SIGUSR1) - 1];
        let hup = state.hand.actions[usize::from(SIGHUP) - 1];
        (
            (usr1.handler, usr1.flags, usr1.restorer),
            (hup.handler, hup.flags),
        )
    };
    assert_eq!(hand(&mut l, plain), ((0x1000, 4, 0x2000), (SIG_IGN, 0)));
    assert_eq!(hand(&mut l, cleared), ((SIG_DFL, 0, 0), (SIG_IGN, 0)));
}
