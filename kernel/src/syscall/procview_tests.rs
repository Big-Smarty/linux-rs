// SPDX-License-Identifier: GPL-2.0-only
//! The incremental publication of `/proc`: what a view, the pid mirror and the
//! machine-wide totals keep up with is compared with building them from
//! scratch, after every kind of change and across the bounds of the change
//! logs (`FdTable::changed_since`, `Tasklist::changed_since`,
//! `Mm::vma_stamp`). The cost claim of `procfs::view` (time proportional to
//! what changed) rests on these equalities holding on the incremental path.

#![allow(
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::needless_range_loop
)]

extern crate std;

use std::{sync::Arc, vec::Vec};

use super::{
    Outcome, dispatch,
    testing::{Task, task},
};
use crate::{
    procfs::{
        ProcState,
        view::{Collect, TaskView},
    },
    task::{Attributes, Cred, TaskId, exit::NoWake, fork::ForkRequest, tasklist::ForkParams},
    vfs::{FdTable, FileId},
};
use syscalls::Sysno;

fn collect<'a>(
    attrs: &'a Attributes,
    fdt: &'a FdTable,
    t: &'a Task,
    exe: FileId,
    rss: (u64, u64, u64),
) -> Collect<'a> {
    Collect {
        attrs,
        fs: t.fs,
        fdt,
        files: &t.vfs.files,
        mm: Some(&t.mm),
        exe: Some(exe),
        rss,
        pgtables_bytes: 4096 * rss.0,
        min_flt: 0,
        maj_flt: 0,
        nvcsw: 0,
        nivcsw: 0,
        start_boottime_ns: 0,
        flags: 0,
        args: None,
    }
}

/// Every open descriptor of `view`, in order, with what `fdt` says of it.
fn assert_view_matches(view: &TaskView, fdt: &FdTable, t: &Task, what: &str) {
    let want: Vec<_> = fdt
        .iter()
        .map(|(fd, file, cloexec)| {
            (
                fd,
                file,
                cloexec,
                t.vfs.files.try_get(file).map_or(0, |f| f.serial),
            )
        })
        .collect();
    let got: Vec<_> = (0..fdt.max_fds() as u32)
        .filter_map(|fd| view.fd(fd))
        .map(|e| (e.fd, e.file, e.cloexec, e.serial))
        .collect();
    assert_eq!(got, want, "{what}: descriptors");
    assert_eq!(view.fds.len(), want.len(), "{what}: count");
    // `next_fd` visits exactly the open ones.
    let mut walked = Vec::new();
    let mut at = 0;
    while let Some(fd) = view.next_fd(at) {
        walked.push(fd);
        at = fd + 1;
    }
    assert_eq!(
        walked,
        want.iter().map(|w| w.0).collect::<Vec<_>>(),
        "{what}: next_fd"
    );
    assert_eq!(view.fd_stamp, fdt.stamp(), "{what}: stamp");
    assert_eq!(view.max_fds as usize, fdt.max_fds(), "{what}: max_fds");
}

#[test]
fn a_view_follows_the_descriptor_table_by_replaying_its_log() {
    let mut t = task();
    let cred = crate::vfs::Cred::root();
    let attrs = Attributes::init(1000);
    let mut files = Vec::new();
    for _ in 0..40 {
        let (read, write) = t.vfs.pipe_create(0, &cred).unwrap();
        files.push(read);
        files.push(write);
    }
    let exe = files[0];
    let mut fdt = FdTable::default();
    let mut view = TaskView::collect(collect(&attrs, &fdt, &t, exe, (0, 0, 0))).unwrap();
    assert_view_matches(&view, &fdt, &t, "empty");

    let step = |view: &mut TaskView, fdt: &FdTable, t: &Task, what: &str| {
        view.update(collect(&attrs, fdt, t, exe, (0, 0, 0)))
            .unwrap();
        assert_view_matches(view, fdt, t, what);
        // The incremental result equals a view built from nothing.
        let fresh = TaskView::collect(collect(&attrs, fdt, t, exe, (0, 0, 0))).unwrap();
        assert_view_matches(&fresh, fdt, t, what);
    };

    // A few changes at a time: the log is replayed.
    for i in 0..3 {
        let fd = fdt.alloc_fd(0, 4096, i == 1).unwrap();
        fdt.install(fd, files[i]);
    }
    step(&mut view, &fdt, &t, "open three");
    fdt.close(1);
    step(&mut view, &fdt, &t, "close one");
    let fd = fdt.alloc_fd(0, 4096, true).unwrap();
    assert_eq!(fd, 1, "lowest free descriptor");
    fdt.install(fd, files[5]);
    step(&mut view, &fdt, &t, "reuse the number");
    fdt.replace(2, files[6], true).unwrap();
    fdt.set_cloexec(0, true);
    step(&mut view, &fdt, &t, "dup2 and FD_CLOEXEC");
    // A reserved but uninstalled descriptor is not open yet.
    let reserved = fdt.alloc_fd(0, 4096, false).unwrap();
    step(&mut view, &fdt, &t, "reserved");
    fdt.install(reserved, files[7]);
    step(&mut view, &fdt, &t, "installed");
    // The table grows: a high descriptor, a sparse view.
    let high = fdt.alloc_fd(3000, 4096, false).unwrap();
    fdt.install(high, files[8]);
    step(&mut view, &fdt, &t, "sparse high descriptor");
    assert_eq!(view.next_fd(5), Some(high));
    assert_eq!(view.next_fd(high + 1), None);

    // More changes than the log remembers: the table is copied.
    for round in 0..3 {
        for fd in 0..50u32 {
            if round % 2 == 0 {
                if fdt.get(fd).is_none() {
                    let fd = fdt.alloc_fd(fd, 4096, false).unwrap();
                    fdt.install(fd, files[(fd as usize) % files.len()]);
                }
            } else {
                fdt.close(fd);
            }
        }
        step(&mut view, &fdt, &t, "burst");
    }
    // A view that never read the table (a new child's) copies it too.
    let child = t.vfs.dup_fd(&fdt).unwrap();
    let fresh = TaskView::collect(collect(&attrs, &child, &t, exe, (0, 0, 0))).unwrap();
    assert_view_matches(&fresh, &child, &t, "duplicated table");
}

#[test]
fn the_vma_vector_is_shared_until_the_address_space_changes() {
    let mut t = task();
    let attrs = Attributes::init(1000);
    let fdt = FdTable::default();
    let (read, _) = t.vfs.pipe_create(0, &crate::vfs::Cred::root()).unwrap();
    let mut view = TaskView::collect(collect(&attrs, &fdt, &t, read, (1, 0, 0))).unwrap();
    let first = Arc::clone(&view.mm.as_ref().unwrap().vmas);
    // Reading the address space (and republishing) shares the copy.
    let _ = t.mm.find_vma(0x1000);
    let _ = t.mm.vmas().len();
    view.update(collect(&attrs, &fdt, &t, read, (2, 0, 0)))
        .unwrap();
    let mm = view.mm.as_ref().unwrap();
    assert!(Arc::ptr_eq(&first, &mm.vmas), "unchanged: shared");
    assert_eq!(mm.rss_anon, 2, "the scalars are fresh");
    // An mmap moves the stamp: the next publication copies.
    let addr = {
        let r = dispatch(&mut t, Sysno::mmap as u64, [0, 8192, 3, 0x22, u64::MAX, 0]);
        match r {
            Outcome::Return(a) => a,
            other => panic!("{other:?}"),
        }
    };
    view.update(collect(&attrs, &fdt, &t, read, (2, 0, 0)))
        .unwrap();
    let mm = view.mm.as_ref().unwrap();
    assert!(!Arc::ptr_eq(&first, &mm.vmas), "changed: copied");
    assert_eq!(&**mm.vmas, t.mm.vmas(), "and equal");
    assert!(mm.vmas.iter().any(|v| v.start == addr as u64));
    let second = Arc::clone(&mm.vmas);
    view.update(collect(&attrs, &fdt, &t, read, (2, 0, 0)))
        .unwrap();
    assert!(Arc::ptr_eq(&second, &view.mm.as_ref().unwrap().vmas));
    // An munmap too.
    let r = dispatch(
        &mut t,
        Sysno::munmap as u64,
        [addr as u64, 4096, 0, 0, 0, 0],
    );
    assert!(matches!(r, Outcome::Return(0)), "{r:?}");
    view.update(collect(&attrs, &fdt, &t, read, (2, 0, 0)))
        .unwrap();
    let mm = view.mm.as_ref().unwrap();
    assert!(!Arc::ptr_eq(&second, &mm.vmas));
    assert_eq!(&**mm.vmas, t.mm.vmas());
    // Another address space (an `execve`) never matches an old stamp.
    let other = crate::mm::Mm::new(&t.env);
    assert_ne!(other.vma_stamp().0, t.mm.vma_stamp().0);
}

fn fork_child(t: &mut Task) -> (TaskId, i32) {
    let request = ForkRequest::plain(17);
    let id = t
        .tasks
        .fork(t.current, ForkParams::of(&t.attrs, &request))
        .unwrap();
    let pid = t.tasks.task_pid_vnr(id);
    (id, pid)
}

/// The mirror a procfs that started now would build.
fn from_scratch(t: &Task) -> ProcState {
    let mut fresh = ProcState::default();
    fresh.sync(&t.tasks).unwrap();
    fresh
}

fn assert_mirror(ps: &ProcState, t: &Task, what: &str) {
    let fresh = from_scratch(t);
    assert_eq!(ps.pids, fresh.pids, "{what}");
    assert_eq!(ps.nr_processes(), fresh.nr_processes(), "{what}: count");
}

#[test]
fn the_pid_mirror_follows_the_task_list_through_its_log() {
    let mut t = task();
    let mut ps = ProcState::default();
    ps.sync(&t.tasks).unwrap();
    assert_mirror(&ps, &t, "init");

    // Single changes.
    let (a, pa) = fork_child(&mut t);
    ps.sync(&t.tasks).unwrap();
    assert_mirror(&ps, &t, "fork");
    let user = Cred {
        uid: 1000,
        euid: 1000,
        suid: 1000,
        gid: 1000,
        egid: 1000,
        sgid: 1000,
        groups: &[],
    };
    t.tasks.publish_cred(a, &user);
    ps.sync(&t.tasks).unwrap();
    assert_mirror(&ps, &t, "credentials");
    assert_eq!(ps.facts(pa).unwrap().euid, 1000);
    assert!(!ps.facts(pa).unwrap().dumpable, "euid moved: not dumpable");
    t.tasks.set_dumpable(a, true);
    ps.sync(&t.tasks).unwrap();
    assert!(ps.facts(pa).unwrap().dumpable);
    assert_mirror(&ps, &t, "dumpable");
    t.tasks.exit_prepare(a, 0, false, &mut NoWake);
    t.tasks.exit_notify(a, true, &mut NoWake).unwrap();
    ps.sync(&t.tasks).unwrap();
    assert!(ps.facts(pa).unwrap().zombie);
    assert_mirror(&ps, &t, "zombie");
    t.tasks.release_task(a, &mut NoWake);
    ps.sync(&t.tasks).unwrap();
    assert!(ps.facts(pa).is_none());
    assert_mirror(&ps, &t, "released");

    // Several changes between two syncs, among them a release.
    let mut kids = Vec::new();
    for _ in 0..5 {
        kids.push(fork_child(&mut t));
    }
    t.tasks.exit_prepare(kids[1].0, 0, false, &mut NoWake);
    t.tasks.exit_notify(kids[1].0, true, &mut NoWake).unwrap();
    t.tasks.release_task(kids[1].0, &mut NoWake);
    kids.push(fork_child(&mut t));
    ps.sync(&t.tasks).unwrap();
    assert_mirror(&ps, &t, "several between syncs");

    // More than the log remembers: rebuilt from the list.
    for _ in 0..100 {
        kids.push(fork_child(&mut t));
    }
    ps.sync(&t.tasks).unwrap();
    assert_mirror(&ps, &t, "burst of forks");
    for &(id, _) in kids.iter().skip(10) {
        if t.tasks.task(id).is_some() {
            t.tasks.exit_prepare(id, 0, false, &mut NoWake);
            t.tasks.exit_notify(id, true, &mut NoWake).unwrap();
            t.tasks.release_task(id, &mut NoWake);
        }
    }
    ps.sync(&t.tasks).unwrap();
    assert_mirror(&ps, &t, "burst of releases");

    // After `prune` (no procfs) the mirror is stale and the next sync rebuilds.
    ps.prune(&t.tasks);
    let (_, late) = fork_child(&mut t);
    ps.prune(&t.tasks);
    ps.sync(&t.tasks).unwrap();
    assert!(ps.facts(late).is_some());
    assert_mirror(&ps, &t, "after a prune");
}

#[test]
fn views_and_totals_go_with_their_tasks() {
    let mut t = task();
    let attrs = Attributes::init(1000);
    let fdt = FdTable::default();
    let (exe, _) = t.vfs.pipe_create(0, &crate::vfs::Cred::root()).unwrap();
    let mut ps = ProcState::default();
    ps.sync(&t.tasks).unwrap();
    let mut pids = Vec::new();
    for i in 0..6u64 {
        let (_, pid) = fork_child(&mut t);
        ps.sync(&t.tasks).unwrap();
        // anon i+1, file i, shmem 2i
        ps.publish_update(pid, collect(&attrs, &fdt, &t, exe, (i + 1, i, 2 * i)))
            .unwrap();
        pids.push((pid, i));
    }
    let sum = |f: &dyn Fn(u64) -> u64| pids.iter().map(|&(_, i)| f(i)).sum::<u64>();
    let expect = |ps: &ProcState, live: &[(i32, u64)]| {
        let s = |f: &dyn Fn(u64) -> u64| live.iter().map(|&(_, i)| f(i)).sum::<u64>();
        let totals = ps.totals();
        assert_eq!(totals.anon_pages, s(&|i| i + 1));
        assert_eq!(totals.mapped_pages, s(&|i| 3 * i));
        assert_eq!(totals.pgtables_bytes, s(&|i| 4096 * (i + 1)));
    };
    expect(&ps, &pids);
    assert_eq!(ps.totals().anon_pages, sum(&|i| i + 1));
    // A republication replaces the figures, it does not add to them.
    let (p3, _) = pids[3];
    ps.publish_update(p3, collect(&attrs, &fdt, &t, exe, (50, 0, 0)))
        .unwrap();
    assert_eq!(
        ps.totals().anon_pages,
        sum(&|i| i + 1) - 4 + 50,
        "replaced, not added"
    );
    ps.publish_update(p3, collect(&attrs, &fdt, &t, exe, (4, 3, 6)))
        .unwrap();
    expect(&ps, &pids);
    // An exit takes the address space away from the totals ...
    let (p1, _) = pids[1];
    ps.exit(p1);
    let mut live: Vec<_> = pids.clone();
    live.retain(|&(p, _)| p != p1);
    expect(&ps, &live);
    // ... and a release takes the view away.
    let id = t.tasks.find_task_by_vpid(pids[2].0).unwrap();
    ps.exit(pids[2].0);
    t.tasks.exit_prepare(id, 0, false, &mut NoWake);
    t.tasks.exit_notify(id, true, &mut NoWake).unwrap();
    t.tasks.release_task(id, &mut NoWake);
    ps.sync(&t.tasks).unwrap();
    assert!(ps.view(pids[2].0).is_none(), "view of a released group");
    live.retain(|&(p, _)| p != pids[2].0);
    expect(&ps, &live);
    // Pruning (no procfs) keeps the totals right too.
    let id = t.tasks.find_task_by_vpid(pids[4].0).unwrap();
    t.tasks.exit_prepare(id, 0, false, &mut NoWake);
    t.tasks.exit_notify(id, true, &mut NoWake).unwrap();
    t.tasks.release_task(id, &mut NoWake);
    ps.prune(&t.tasks);
    live.retain(|&(p, _)| p != pids[4].0);
    expect(&ps, &live);
}

#[test]
fn a_view_never_replays_another_tables_log() {
    // A table that happens to be at the generation the view last read, but is
    // not the table it read, must be copied, not patched.
    let mut t = task();
    let attrs = Attributes::init(1000);
    let (read, write) = t.vfs.pipe_create(0, &crate::vfs::Cred::root()).unwrap();
    let mut first = FdTable::default();
    let fd = first.alloc_fd(0, 64, false).unwrap();
    first.install(fd, read);
    let mut view = TaskView::collect(collect(&attrs, &first, &t, read, (0, 0, 0))).unwrap();
    let mut second = FdTable::default();
    let a = second.alloc_fd(5, 64, false).unwrap();
    second.install(a, write);
    assert_eq!(second.stamp().1, first.stamp().1, "same generation");
    assert_ne!(second.stamp().0, first.stamp().0, "another table");
    view.update(collect(&attrs, &second, &t, read, (0, 0, 0)))
        .unwrap();
    assert_view_matches(&view, &second, &t, "swapped table");
    assert!(view.fd(0).is_none(), "nothing of the first table is left");
}

