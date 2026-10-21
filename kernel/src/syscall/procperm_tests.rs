// SPDX-License-Identifier: GPL-2.0-only
//! The permission matrix of `/proc` against the pinned Linux 6.18.57.
//!
//! This kernel has no credential-changing system call (the `setuid` family stops it loudly), so
//! the rules `hidepid`, `gid=`, `subset=pid`, ownership (`task_dump_owner`), `ptrace_may_access`
//! and the dumpable rules apply to no task it can run. They are checked here instead: the host
//! test builds the tasks Linux's recording had (a dumpable and a non-dumpable user task, a root
//! task, a zombie), mounts the six `proc` instances, lets four observers (root, another user, the
//! victims' user, a user in the victims' group) probe them through the real system calls and
//! compares each row with `procperm_linux.txt`: the `init: info procperm.*` rows the reference-only
//! mode `procperm` of the oracle's `/init` printed on the pinned Linux
//! (`target/linux-reference/init-reference-020`, local evidence).
//!
//! Linux keeps the dentries a lookup instantiated, so a second observer finds what the first one
//! was allowed to look up; the recording mounted fresh instances for every observer (a cold
//! dentry cache), which is the case this kernel's stateless lookups reproduce.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::too_many_lines
)]

extern crate std;

use std::{format, string::String, vec::Vec};

use super::{
    Outcome, dispatch,
    testing::{Task, task},
};
use crate::{
    procfs::view::{Collect, TaskView},
    task::{Attributes, Cred, TaskId, exit::NoWake, fork::ForkRequest, tasklist::ForkParams},
    vfs::{FdTable, O_CREAT, O_DIRECTORY, O_RDONLY},
};
use syscalls::{Errno, Sysno};

const PATH: u64 = 0x1000;
const PATH2: u64 = 0x1800;
const PATH3: u64 = 0x2000;
const OUT: u64 = 0x3000;

fn put(t: &mut Task, at: u64, data: &[u8]) {
    let page = t.pages.0.get_mut(&(at & !0xfff)).unwrap();
    let start = (at & 0xfff) as usize;
    page.0[start..start + data.len()].copy_from_slice(data);
}

fn get(t: &mut Task, at: u64, len: usize) -> Vec<u8> {
    let page = t.pages.0.get_mut(&(at & !0xfff)).unwrap();
    let start = (at & 0xfff) as usize;
    page.0[start..start + len].to_vec()
}

fn cstr(t: &mut Task, at: u64, text: &str) -> u64 {
    let mut bytes = text.as_bytes().to_vec();
    bytes.push(0);
    put(t, at, &bytes);
    at
}

fn call(t: &mut Task, sysno: Sysno, args: &[u64]) -> i64 {
    let mut full = [0; 6];
    full[..args.len()].copy_from_slice(args);
    match dispatch(t, sysno as u64, full) {
        Outcome::Return(value) => value,
        other => panic!("{sysno:?}: {other:?}"),
    }
}

/// The text of a result as the recording printed it: the errno's name or `ok`.
fn word(value: i64) -> String {
    if value >= 0 {
        "ok".into()
    } else {
        format!("{:?}", Errno::new(-value as i32))
    }
}

fn pages() -> Task {
    let mut t = task();
    for page in [0x1000, 0x2000, 0x3000, 0x4000] {
        t.pages.map(page, true);
    }
    t
}

/// A user task of the recording: its credentials, whether it is dumpable and whether it ended.
struct Victim {
    name: &'static str,
    pid: i32,
}

fn user_cred(uid: u32, gid: u32) -> Cred {
    Cred {
        uid,
        euid: uid,
        suid: uid,
        gid,
        egid: gid,
        sgid: gid,
        groups: &[],
    }
}

/// Fork a child of init, give it `cred` and the dumpable state, publish a view with one pipe
/// descriptor (`fd`) and an executable, and, for a zombie, end it.
fn victim(
    t: &mut Task,
    name: &'static str,
    cred: Cred,
    dumpable: bool,
    zombie: bool,
    fd: u32,
    exe: crate::vfs::FileId,
) -> Victim {
    let request = ForkRequest {
        exit_signal: 17,
        child_sp: 0,
        clear_sighand: false,
        clear_child_tid: 0,
        share_vm: false,
        vfork: false,
    };
    let id: TaskId = t
        .tasks
        .fork(t.current, ForkParams::of(&t.attrs, &request))
        .unwrap();
    let pid = t.tasks.task_pid_vnr(id);
    t.tasks.publish_cred(id, &cred);
    t.tasks.set_dumpable(id, dumpable);
    let vfs_cred = crate::vfs::Cred::of_task(&cred);
    let (read, _write) = t.vfs.pipe_create(0, &vfs_cred).unwrap();
    let mut fdt = FdTable::default();
    assert_eq!(fdt.alloc_fd(fd, 1024, false).unwrap(), fd);
    fdt.install(fd, read);
    let mut attrs = Attributes::init(1000);
    attrs.cred = cred;
    attrs.fs = t.attrs.fs;
    let view = TaskView::collect(Collect {
        attrs: &attrs,
        fdt: &fdt,
        files: &t.vfs.files,
        mm: Some(&t.mm),
        exe: Some(exe),
        rss: (0, 0, 0),
        pgtables_bytes: 0,
        min_flt: 0,
        maj_flt: 0,
        nvcsw: 0,
        nivcsw: 0,
        start_boottime_ns: 0,
        flags: 0,
        args: None,
    })
    .unwrap();
    t.vfs.fs.ns.proc.publish(pid, view).unwrap();
    if zombie {
        t.tasks.exit_prepare(id, 0, false);
        t.tasks.exit_notify(id, &mut NoWake).unwrap();
        t.vfs.fs.ns.proc.exit(pid);
    }
    Victim { name, pid }
}

fn stat_row(t: &mut Task, path: &str) -> String {
    let at = cstr(t, PATH, path);
    let r = call(t, Sysno::stat, &[at, OUT]);
    if r < 0 {
        return word(r);
    }
    let raw = get(t, OUT, 48);
    let mode = u32::from_le_bytes(raw[24..28].try_into().unwrap());
    let uid = u32::from_le_bytes(raw[28..32].try_into().unwrap());
    let gid = u32::from_le_bytes(raw[32..36].try_into().unwrap());
    format!("ok:{uid}:{gid}:{:o}", mode & 0o7777)
}

fn open_row(t: &mut Task, path: &str, flags: u32) -> String {
    let at = cstr(t, PATH, path);
    let r = call(t, Sysno::open, &[at, u64::from(flags), 0]);
    if r >= 0 {
        call(t, Sysno::close, &[r as u64]);
    }
    word(r)
}

fn link_row(t: &mut Task, path: &str) -> String {
    let at = cstr(t, PATH, path);
    word(call(t, Sysno::readlink, &[at, OUT, 256]))
}

/// The pids a directory lists (`getdents64`).
fn listed(t: &mut Task, dir: &str) -> Option<Vec<i32>> {
    let at = cstr(t, PATH, dir);
    let fd = call(t, Sysno::open, &[at, u64::from(O_RDONLY | O_DIRECTORY), 0]);
    if fd < 0 {
        return None;
    }
    let mut pids = Vec::new();
    loop {
        let n = call(t, Sysno::getdents64, &[fd as u64, OUT, 2048]);
        if n <= 0 {
            break;
        }
        let raw = get(t, OUT, n as usize);
        let mut at = 0;
        while at < raw.len() {
            let reclen = usize::from(u16::from_le_bytes([raw[at + 16], raw[at + 17]]));
            let name = &raw[at + 19..at + reclen];
            let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
            if raw[at + 18] == 4
                && let Ok(text) = core::str::from_utf8(&name[..end])
                && let Ok(pid) = text.parse::<i32>()
            {
                pids.push(pid);
            }
            at += reclen;
        }
    }
    call(t, Sysno::close, &[fd as u64]);
    Some(pids)
}

#[test]
fn the_permission_matrix_matches_the_pinned_linux() {
    let recorded: Vec<&str> = include_str!("procperm_linux.txt").lines().collect();
    let mut t = pages();
    let env = t.vfs.kernel_env();
    // The executable the victims "run": any regular file.
    let exe_path = cstr(&mut t, PATH2, "/exe");
    let exe_fd = call(&mut t, Sysno::open, &[exe_path, u64::from(O_CREAT), 0o755]);
    assert!(exe_fd >= 0);
    let exe = t.fdt.get(exe_fd as u32).unwrap();
    let fd = 5;
    let victims = [
        victim(&mut t, "user", user_cred(1000, 100), true, false, fd, exe),
        victim(
            &mut t,
            "undumpable",
            user_cred(1000, 100),
            false,
            false,
            fd,
            exe,
        ),
        victim(&mut t, "root", Cred::root(), true, false, fd, exe),
        victim(&mut t, "zombie", user_cred(1000, 100), true, true, fd, exe),
    ];
    let mounts = [
        ("plain", "/m/a", None),
        ("hide1", "/m/b", Some("hidepid=1")),
        ("hide2", "/m/c", Some("hidepid=2")),
        ("hide4", "/m/d", Some("hidepid=4")),
        ("gid100hide2", "/m/e", Some("gid=100,hidepid=2")),
        ("subsetpid", "/m/f", Some("subset=pid")),
    ];
    t.vfs.mkdir(&env, b"/m", 0o755).unwrap();
    for (_, point, data) in mounts {
        t.vfs.mkdir(&env, point.as_bytes(), 0o755).unwrap();
        let src = cstr(&mut t, PATH2, "proc");
        let dst = cstr(&mut t, PATH3, point);
        let ty = cstr(&mut t, PATH, "proc");
        let opts = data.map_or(0, |text| cstr(&mut t, PATH2 + 0x100, text));
        assert_eq!(
            call(&mut t, Sysno::mount, &[src, dst, ty, 0, opts]),
            0,
            "{point}"
        );
    }
    let observers = [
        ("root", Cred::root()),
        ("other", user_cred(2000, 200)),
        ("owner", user_cred(1000, 100)),
        ("group", user_cred(2000, 100)),
    ];
    let mut wrong: Vec<String> = Vec::new();
    let mut rows = 0;
    for (who, cred) in observers {
        t.attrs.cred = cred;
        for (mname, point, _) in mounts {
            let mut lines: Vec<(String, &'static str, i32)> = Vec::new();
            for v in &victims {
                let pid = v.pid;
                let dir = format!("{point}/{pid}");
                let head = stat_row(&mut t, &dir);
                let mut probe =
                    |name: &str, flags: u32| open_row(&mut t, &format!("{dir}/{name}"), flags);
                let stat = probe("stat", O_RDONLY);
                let environ = probe("environ", O_RDONLY);
                let maps = probe("maps", O_RDONLY);
                let comm = probe("comm", O_RDONLY);
                let cmdline = probe("cmdline", O_RDONLY);
                let exe_link = link_row(&mut t, &format!("{dir}/exe"));
                let cwd = link_row(&mut t, &format!("{dir}/cwd"));
                let mut probe =
                    |name: &str, flags: u32| open_row(&mut t, &format!("{dir}/{name}"), flags);
                let fd_dir = probe("fd", O_RDONLY | O_DIRECTORY);
                let fdinfo = probe("fdinfo", O_RDONLY | O_DIRECTORY);
                let fdinfofile = probe(&format!("fdinfo/{fd}"), O_RDONLY);
                lines.push((
                    format!(
                        "dir={head} stat={stat} environ={environ} maps={maps} comm={comm} cmdline={cmdline} exe={exe_link} cwd={cwd} fd={fd_dir} fdinfo={fdinfo} fdinfofile={fdinfofile}"
                    ),
                    v.name,
                    pid,
                ));
            }
            // The listing last, as the recording did.
            let listing = listed(&mut t, point);
            for (body, vname, pid) in lines {
                let seen = match &listing {
                    Some(pids) if pids.contains(&pid) => "in",
                    Some(_) => "out",
                    None => "err",
                };
                let got = format!("{who}.{mname}.{vname} {body} list={seen}");
                let key = format!("{who}.{mname}.{vname} ");
                let want = recorded.iter().find(|line| line.starts_with(&key));
                rows += 1;
                if want != Some(&got.as_str()) {
                    wrong.push(format!(
                        "got  {got}\nwant {}\n",
                        want.unwrap_or(&"(no row)")
                    ));
                }
            }
        }
    }
    assert_eq!(rows, recorded.len());
    assert!(
        wrong.is_empty(),
        "{} of {rows} rows differ from the pinned Linux:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}
