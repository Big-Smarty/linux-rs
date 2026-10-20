// SPDX-License-Identifier: GPL-2.0-only
//! `ids` group: identity, `uname`, `arch_prctl`, resource limits, `umask`, `getcwd`, CPU
//! affinity, `sysinfo` and the small per-task state libc reads at startup. Linux 6.18.57:
//! `kernel/sys.c`, `kernel/sched/syscalls.c`, `arch/x86/kernel/process_64.c`, `fs/fs_struct.c`,
//! `fs/d_path.c`, `include/asm-generic/resource.h` (`INIT_RLIMITS`), `init/init_task.c`.

use syscalls::{Errno, Sysno};

use super::{R, T, addr, addr_mut, getpid, gettid, sys};

const BAD: usize = 0xdead_0000_0000;
const INF: u64 = u64::MAX;

#[repr(C)]
struct Utsname {
    sysname: [u8; 65],
    nodename: [u8; 65],
    release: [u8; 65],
    version: [u8; 65],
    machine: [u8; 65],
    domainname: [u8; 65],
}

/// The text of a NUL-terminated field.
fn text(field: &[u8]) -> &[u8] {
    &field[..field.iter().position(|&b| b == 0).unwrap_or(field.len())]
}

/// The bytes after the first NUL must be zero (the kernel `memset`s the structure).
fn tail_zero(field: &[u8]) -> bool {
    field[text(field).len()..].iter().all(|&b| b == 0)
}

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
struct Rlimit {
    cur: u64,
    max: u64,
}

#[repr(C)]
#[derive(Default)]
struct Sysinfo {
    uptime: i64,
    loads: [u64; 3],
    totalram: u64,
    freeram: u64,
    sharedram: u64,
    bufferram: u64,
    totalswap: u64,
    freeswap: u64,
    procs: u16,
    pad: u16,
    pad2: u32,
    totalhigh: u64,
    freehigh: u64,
    mem_unit: u32,
    f: [u8; 4],
}

fn one(nr: Sysno) -> R {
    sys(nr, &[])
}

fn prlimit(pid: usize, res: usize, new: Option<&Rlimit>, old: Option<&mut Rlimit>) -> R {
    sys(
        Sysno::prlimit64,
        &[pid, res, new.map_or(0, addr), old.map_or(0, addr_mut)],
    )
}

fn arch_prctl(code: usize, arg: usize) -> R {
    sys(Sysno::arch_prctl, &[code, arg])
}

pub fn run() -> bool {
    let mut t = T::new("ids");
    identity(&mut t);
    uname(&mut t);
    arch(&mut t);
    limits(&mut t);
    misc(&mut t);
    t.finish()
}

fn identity(t: &mut T) {
    for (name, nr) in [
        ("getuid", Sysno::getuid),
        ("geteuid", Sysno::geteuid),
        ("getgid", Sysno::getgid),
        ("getegid", Sysno::getegid),
    ] {
        t.eq(name, one(nr), Ok(0));
    }
    t.eq("getpid", getpid(), 1);
    t.eq("gettid", gettid(), 1);
    // The initial task's parent is the idle task, which has no pid in the global namespace.
    t.eq("getppid", one(Sysno::getppid), Ok(0));
    t.eq("getpgrp", one(Sysno::getpgrp), Ok(0));
    t.eq("getpgid-self", sys(Sysno::getpgid, &[0]), Ok(0));
    t.eq("getpgid-pid", sys(Sysno::getpgid, &[1]), Ok(0));
    t.eq(
        "getpgid-missing",
        sys(Sysno::getpgid, &[99_999]),
        Err(Errno::ESRCH),
    );
    t.eq("getsid-self", sys(Sysno::getsid, &[0]), Ok(0));
    t.eq(
        "getsid-missing",
        sys(Sysno::getsid, &[99_999]),
        Err(Errno::ESRCH),
    );
    let (mut r, mut e, mut s) = (7u32, 7u32, 7u32);
    t.eq(
        "getresuid",
        (
            sys(
                Sysno::getresuid,
                &[addr_mut(&mut r), addr_mut(&mut e), addr_mut(&mut s)],
            ),
            r,
            e,
            s,
        ),
        (Ok(0), 0, 0, 0),
    );
    let (mut r, mut e, mut s) = (7u32, 7u32, 7u32);
    t.eq(
        "getresgid",
        (
            sys(
                Sysno::getresgid,
                &[addr_mut(&mut r), addr_mut(&mut e), addr_mut(&mut s)],
            ),
            r,
            e,
            s,
        ),
        (Ok(0), 0, 0, 0),
    );
    t.eq(
        "getresuid-fault",
        sys(Sysno::getresuid, &[BAD, BAD, BAD]),
        Err(Errno::EFAULT),
    );
    t.eq("getgroups-count", sys(Sysno::getgroups, &[0, 0]), Ok(0));
    t.eq("getgroups-empty", sys(Sysno::getgroups, &[4, BAD]), Ok(0));
    t.eq(
        "getgroups-negative",
        sys(Sysno::getgroups, &[usize::MAX, 0]),
        Err(Errno::EINVAL),
    );
    let mut word = 0u32;
    t.eq(
        "set_tid_address",
        sys(Sysno::set_tid_address, &[addr_mut(&mut word)]),
        Ok(1),
    );
    t.eq(
        "set_tid_address-null",
        sys(Sysno::set_tid_address, &[0]),
        Ok(1),
    );
    t.eq(
        "set_robust_list",
        sys(Sysno::set_robust_list, &[0x1000, 24]),
        Ok(0),
    );
    t.eq(
        "set_robust_list-size",
        sys(Sysno::set_robust_list, &[0x1000, 16]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "personality-query",
        sys(Sysno::personality, &[0xffff_ffff]),
        Ok(0),
    );
    t.eq("getpriority", sys(Sysno::getpriority, &[0, 0]), Ok(20));
    t.eq(
        "getpriority-bad-which",
        sys(Sysno::getpriority, &[9, 0]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sched_getscheduler",
        sys(Sysno::sched_getscheduler, &[0]),
        Ok(0),
    );
    t.eq(
        "sched_getscheduler-missing",
        sys(Sysno::sched_getscheduler, &[99_999]),
        Err(Errno::ESRCH),
    );
    t.eq(
        "sched_get_priority_max-other",
        sys(Sysno::sched_get_priority_max, &[0]),
        Ok(0),
    );
    t.eq(
        "sched_get_priority_max-fifo",
        sys(Sysno::sched_get_priority_max, &[1]),
        Ok(99),
    );
    t.eq(
        "sched_get_priority_min-fifo",
        sys(Sysno::sched_get_priority_min, &[1]),
        Ok(1),
    );
    t.eq(
        "sched_get_priority_max-bad",
        sys(Sysno::sched_get_priority_max, &[99]),
        Err(Errno::EINVAL),
    );
}

fn uname(t: &mut T) {
    let mut u = Utsname {
        sysname: [0xaa; 65],
        nodename: [0xaa; 65],
        release: [0xaa; 65],
        version: [0xaa; 65],
        machine: [0xaa; 65],
        domainname: [0xaa; 65],
    };
    t.eq("uname", sys(Sysno::uname, &[addr_mut(&mut u)]), Ok(0));
    t.eq("uname-sysname", text(&u.sysname), b"Linux".as_slice());
    t.eq("uname-nodename", text(&u.nodename), b"(none)".as_slice());
    t.eq("uname-release", text(&u.release), b"6.18.57".as_slice());
    t.holds(
        "uname-version",
        !text(&u.version).is_empty(),
        text(&u.version).len(),
        "non-empty",
    );
    t.eq("uname-machine", text(&u.machine), b"x86_64".as_slice());
    t.eq(
        "uname-domainname",
        text(&u.domainname),
        b"(none)".as_slice(),
    );
    t.holds(
        "uname-nul-padded",
        [
            &u.sysname,
            &u.nodename,
            &u.release,
            &u.version,
            &u.machine,
            &u.domainname,
        ]
        .iter()
        .all(|f| tail_zero(&f[..])),
        "stale bytes",
        "zero after each NUL",
    );
    t.eq("uname-fault", sys(Sysno::uname, &[BAD]), Err(Errno::EFAULT));
    t.eq("uname-null", sys(Sysno::uname, &[0]), Err(Errno::EFAULT));
}

fn arch(t: &mut T) {
    const SET_GS: usize = 0x1001;
    const SET_FS: usize = 0x1002;
    const GET_FS: usize = 0x1003;
    const GET_GS: usize = 0x1004;
    let get = |code: usize| {
        let mut v = 0xffffu64;
        (arch_prctl(code, addr_mut(&mut v)), v)
    };
    t.eq("arch_prctl-get-fs-initial", get(GET_FS), (Ok(0), 0));
    t.eq("arch_prctl-get-gs-initial", get(GET_GS), (Ok(0), 0));
    t.eq("arch_prctl-set-fs", arch_prctl(SET_FS, 0x1234_5000), Ok(0));
    t.eq("arch_prctl-get-fs", get(GET_FS), (Ok(0), 0x1234_5000));
    t.eq("arch_prctl-set-gs", arch_prctl(SET_GS, 0x2345_6000), Ok(0));
    t.eq("arch_prctl-get-gs", get(GET_GS), (Ok(0), 0x2345_6000));
    t.eq(
        "arch_prctl-fs-gs-independent",
        get(GET_FS),
        (Ok(0), 0x1234_5000),
    );
    t.eq(
        "arch_prctl-set-fs-unaligned",
        arch_prctl(SET_FS, 0x1234_5679),
        Ok(0),
    );
    t.eq(
        "arch_prctl-get-fs-unaligned",
        get(GET_FS),
        (Ok(0), 0x1234_5679),
    );
    t.eq(
        "arch_prctl-set-fs-last-user",
        arch_prctl(SET_FS, 0x7fff_ffff_efff),
        Ok(0),
    );
    t.eq(
        "arch_prctl-set-fs-task-size",
        arch_prctl(SET_FS, 0x7fff_ffff_f000),
        Err(Errno::EPERM),
    );
    t.eq(
        "arch_prctl-set-fs-noncanonical",
        arch_prctl(SET_FS, 0x8000_0000_0000),
        Err(Errno::EPERM),
    );
    t.eq(
        "arch_prctl-set-gs-kernel",
        arch_prctl(SET_GS, 0xffff_8000_0000_0000),
        Err(Errno::EPERM),
    );
    t.eq(
        "arch_prctl-set-gs-max",
        arch_prctl(SET_GS, usize::MAX),
        Err(Errno::EPERM),
    );
    t.eq(
        "arch_prctl-failed-set-keeps-fs",
        get(GET_FS),
        (Ok(0), 0x7fff_ffff_efff),
    );
    t.eq(
        "arch_prctl-get-fs-fault",
        arch_prctl(GET_FS, 0xdead_0000_0000),
        Err(Errno::EFAULT),
    );
    t.eq(
        "arch_prctl-get-gs-null",
        arch_prctl(GET_GS, 0),
        Err(Errno::EFAULT),
    );
    t.eq("arch_prctl-code-zero", arch_prctl(0, 0), Err(Errno::EINVAL));
    t.eq("arch_prctl-code-one", arch_prctl(1, 0), Err(Errno::EINVAL));
    t.eq(
        "arch_prctl-code-unknown",
        arch_prctl(0x1fff, 0),
        Err(Errno::EINVAL),
    );
    t.eq(
        "arch_prctl-code-huge",
        arch_prctl(usize::MAX, 0),
        Err(Errno::EINVAL),
    );
    t.eq("arch_prctl-get-cpuid", arch_prctl(0x1011, 0), Ok(1));
    t.eq("arch_prctl-restore-fs", arch_prctl(SET_FS, 0), Ok(0));
    t.eq("arch_prctl-restore-gs", arch_prctl(SET_GS, 0), Ok(0));
    t.eq(
        "arch_prctl-restored",
        (get(GET_FS), get(GET_GS)),
        ((Ok(0), 0), (Ok(0), 0)),
    );
}

fn limits(t: &mut T) {
    // INIT_RLIMITS (include/asm-generic/resource.h) with `fork_init`'s memory-derived NPROC and
    // SIGPENDING (checked only for their invariant: equal and non-zero).
    const MB: u64 = 1 << 20;
    let defaults: [(&str, Option<Rlimit>); 16] = [
        ("cpu", Some(Rlimit { cur: INF, max: INF })),
        ("fsize", Some(Rlimit { cur: INF, max: INF })),
        ("data", Some(Rlimit { cur: INF, max: INF })),
        (
            "stack",
            Some(Rlimit {
                cur: 8 * MB,
                max: INF,
            }),
        ),
        ("core", Some(Rlimit { cur: 0, max: INF })),
        ("rss", Some(Rlimit { cur: INF, max: INF })),
        ("nproc", None),
        (
            "nofile",
            Some(Rlimit {
                cur: 1024,
                max: 4096,
            }),
        ),
        (
            "memlock",
            Some(Rlimit {
                cur: 8 * MB,
                max: 8 * MB,
            }),
        ),
        ("as", Some(Rlimit { cur: INF, max: INF })),
        ("locks", Some(Rlimit { cur: INF, max: INF })),
        ("sigpending", None),
        (
            "msgqueue",
            Some(Rlimit {
                cur: 819_200,
                max: 819_200,
            }),
        ),
        ("nice", Some(Rlimit { cur: 0, max: 0 })),
        ("rtprio", Some(Rlimit { cur: 0, max: 0 })),
        ("rttime", Some(Rlimit { cur: INF, max: INF })),
    ];
    for (res, (name, want)) in defaults.into_iter().enumerate() {
        let mut got = Rlimit::default();
        let r = prlimit(0, res, None, Some(&mut got));
        match want {
            Some(w) => t.eq(format_args!("prlimit64-{name}"), (r, got), (Ok(0), w)),
            None => t.holds(
                format_args!("prlimit64-{name}"),
                r == Ok(0) && got.cur == got.max && got.cur > 0,
                got,
                "cur == max > 0",
            ),
        }
        let mut old = Rlimit::default();
        let r2 = sys(Sysno::getrlimit, &[res, addr_mut(&mut old)]);
        t.eq(format_args!("getrlimit-{name}"), (r2, old), (Ok(0), got));
    }
    let mut got = Rlimit::default();
    t.eq(
        "prlimit64-bad-resource",
        prlimit(0, 16, None, Some(&mut got)),
        Err(Errno::EINVAL),
    );
    t.eq(
        "getrlimit-bad-resource",
        sys(Sysno::getrlimit, &[16, addr_mut(&mut got)]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "prlimit64-missing-pid",
        prlimit(99_999, 7, None, Some(&mut got)),
        Err(Errno::ESRCH),
    );
    t.eq(
        "prlimit64-pid-1",
        prlimit(1, 7, None, Some(&mut got)),
        Ok(0),
    );
    t.eq(
        "prlimit64-fault",
        sys(Sysno::prlimit64, &[0, 7, 0, BAD]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "prlimit64-noop",
        sys(Sysno::prlimit64, &[0, 7, 0, 0]),
        Ok(0),
    );
    t.eq(
        "getrlimit-fault",
        sys(Sysno::getrlimit, &[7, BAD]),
        Err(Errno::EFAULT),
    );
    let bad = Rlimit { cur: 10, max: 5 };
    t.eq(
        "prlimit64-cur-above-max",
        prlimit(0, 4, Some(&bad), None),
        Err(Errno::EINVAL),
    );
    let new = Rlimit {
        cur: 4096,
        max: 8192,
    };
    let mut old = Rlimit::default();
    t.eq(
        "prlimit64-set-core",
        (prlimit(0, 4, Some(&new), Some(&mut old)), old),
        (Ok(0), Rlimit { cur: 0, max: INF }),
    );
    let mut now = Rlimit::default();
    t.eq(
        "prlimit64-core-readback",
        (prlimit(0, 4, None, Some(&mut now)), now),
        (Ok(0), new),
    );
    t.eq(
        "setrlimit-lower-max",
        sys(Sysno::setrlimit, &[4, addr(&Rlimit { cur: 1, max: 2 })]),
        Ok(0),
    );
    t.eq(
        "setrlimit-raise-max-as-root",
        sys(Sysno::setrlimit, &[4, addr(&Rlimit { cur: 3, max: 9 })]),
        Ok(0),
    );
    t.eq(
        "setrlimit-fault",
        sys(Sysno::setrlimit, &[4, BAD]),
        Err(Errno::EFAULT),
    );
    let big = Rlimit {
        cur: 2048,
        max: 1 << 21,
    };
    t.eq(
        "setrlimit-nofile-above-nr_open",
        prlimit(0, 7, Some(&big), None),
        Err(Errno::EPERM),
    );
    let nofile = Rlimit {
        cur: 2048,
        max: 4096,
    };
    t.eq(
        "prlimit64-set-nofile",
        prlimit(0, 7, Some(&nofile), None),
        Ok(0),
    );
    let mut now = Rlimit::default();
    t.eq(
        "prlimit64-nofile-readback",
        (prlimit(0, 7, None, Some(&mut now)), now),
        (Ok(0), nofile),
    );
    let restore = Rlimit {
        cur: 1024,
        max: 4096,
    };
    t.eq(
        "prlimit64-restore-nofile",
        prlimit(0, 7, Some(&restore), None),
        Ok(0),
    );
    let core = Rlimit { cur: 0, max: INF };
    t.eq(
        "prlimit64-restore-core",
        prlimit(0, 4, Some(&core), None),
        Ok(0),
    );
}

fn misc(t: &mut T) {
    t.eq("umask-initial", sys(Sysno::umask, &[0o077]), Ok(0o022));
    t.eq("umask-set", sys(Sysno::umask, &[0o027]), Ok(0o077));
    t.eq(
        "umask-masks-high-bits",
        sys(Sysno::umask, &[0o177_777]),
        Ok(0o027),
    );
    t.eq(
        "umask-high-bits-dropped",
        sys(Sysno::umask, &[0o022]),
        Ok(0o777),
    );

    let mut buf = [0xaau8; 64];
    t.eq(
        "getcwd",
        sys(Sysno::getcwd, &[addr_mut(&mut buf), 64]),
        Ok(2),
    );
    t.eq("getcwd-text", &buf[..3], b"/\0\xaa".as_slice());
    t.eq(
        "getcwd-exact-size",
        sys(Sysno::getcwd, &[addr_mut(&mut buf), 2]),
        Ok(2),
    );
    t.eq(
        "getcwd-too-small",
        sys(Sysno::getcwd, &[addr_mut(&mut buf), 1]),
        Err(Errno::ERANGE),
    );
    t.eq(
        "getcwd-zero-size",
        sys(Sysno::getcwd, &[addr_mut(&mut buf), 0]),
        Err(Errno::ERANGE),
    );
    t.eq(
        "getcwd-fault",
        sys(Sysno::getcwd, &[BAD, 64]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "getcwd-null",
        sys(Sysno::getcwd, &[0, 64]),
        Err(Errno::EFAULT),
    );

    // One CPU (`-smp 1`): the affinity mask is one `unsigned long` with bit 0 set.
    let mut mask = [0xffu8; 128];
    t.eq(
        "sched_getaffinity",
        sys(Sysno::sched_getaffinity, &[0, 128, addr_mut(&mut mask)]),
        Ok(8),
    );
    t.eq(
        "sched_getaffinity-mask",
        &mask[..9],
        [1, 0, 0, 0, 0, 0, 0, 0, 0xff].as_slice(),
    );
    t.eq(
        "sched_getaffinity-pid-1",
        sys(Sysno::sched_getaffinity, &[1, 8, addr_mut(&mut mask)]),
        Ok(8),
    );
    t.eq(
        "sched_getaffinity-small",
        sys(Sysno::sched_getaffinity, &[0, 4, addr_mut(&mut mask)]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sched_getaffinity-unaligned-len",
        sys(Sysno::sched_getaffinity, &[0, 12, addr_mut(&mut mask)]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sched_getaffinity-missing",
        sys(Sysno::sched_getaffinity, &[99_999, 8, addr_mut(&mut mask)]),
        Err(Errno::ESRCH),
    );
    t.eq(
        "sched_getaffinity-fault",
        sys(Sysno::sched_getaffinity, &[0, 8, BAD]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "sched_setaffinity-same",
        sys(Sysno::sched_setaffinity, &[0, 8, addr(&1u64)]),
        Ok(0),
    );
    t.eq(
        "sched_setaffinity-empty",
        sys(Sysno::sched_setaffinity, &[0, 8, addr(&0u64)]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sched_setaffinity-offline",
        sys(Sysno::sched_setaffinity, &[0, 8, addr(&2u64)]),
        Err(Errno::EINVAL),
    );

    let mut si = Sysinfo::default();
    t.eq("sysinfo", sys(Sysno::sysinfo, &[addr_mut(&mut si)]), Ok(0));
    t.holds(
        "sysinfo-uptime",
        (0..120).contains(&si.uptime),
        si.uptime,
        "booted under two minutes ago",
    );
    t.holds(
        "sysinfo-ram",
        // No upper bound: the reference VM has 512 MiB, the bare-metal suite
        // (docs/bare-metal-suite.md) runs on whatever RAM the machine has.
        si.totalram > 64 << 20 && si.freeram <= si.totalram && si.freeram > 0,
        (si.totalram, si.freeram),
        "64 MiB < total, 0 < free <= total",
    );
    t.eq("sysinfo-mem_unit", si.mem_unit, 1);
    t.eq("sysinfo-no-swap", (si.totalswap, si.freeswap), (0, 0));
    t.eq("sysinfo-no-highmem", (si.totalhigh, si.freehigh), (0, 0));
    t.eq("sysinfo-sharedram", si.sharedram <= si.totalram, true);
    t.holds("sysinfo-procs", si.procs >= 1, si.procs, ">= 1");
    t.eq(
        "sysinfo-fault",
        sys(Sysno::sysinfo, &[BAD]),
        Err(Errno::EFAULT),
    );

    // prctl: task name, dumpable, timer slack.
    let mut name = [0xaau8; 16];
    t.eq(
        "prctl-get-name",
        sys(Sysno::prctl, &[16, addr_mut(&mut name)]),
        Ok(0),
    );
    t.eq("prctl-get-name-value", &name[..5], b"init\0".as_slice());
    t.eq(
        "prctl-set-name",
        sys(Sysno::prctl, &[15, addr(b"oracle-test-with-long-name\0")]),
        Ok(0),
    );
    t.eq(
        "prctl-name-truncated",
        (sys(Sysno::prctl, &[16, addr_mut(&mut name)]), &name[..16]),
        (Ok(0), b"oracle-test-wit\0".as_slice()),
    );
    t.eq(
        "prctl-restore-name",
        sys(Sysno::prctl, &[15, addr(b"init\0")]),
        Ok(0),
    );
    t.eq("prctl-get-dumpable", sys(Sysno::prctl, &[3]), Ok(1));
    t.eq("prctl-get-timerslack", sys(Sysno::prctl, &[30]), Ok(50_000));
    t.eq("prctl-get-no-new-privs", sys(Sysno::prctl, &[39]), Ok(0));
    t.eq(
        "prctl-get-name-fault",
        sys(Sysno::prctl, &[16, BAD]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "prctl-bad-option",
        sys(Sysno::prctl, &[0x7fff_0000]),
        Err(Errno::EINVAL),
    );
}
