// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: fs/proc/base.c (GPL-2.0:
// `tgid_base_stuff`, `tid_base_stuff`, `proc_pident_readdir`,
// `proc_pident_lookup`, `proc_pid_lookup`, `proc_pid_readdir`,
// `proc_task_lookup`, `proc_task_readdir`, `next_tgid`, `has_pid_permissions`,
// `proc_pid_permission`, `proc_pid_getattr`, `task_dump_owner`,
// `proc_pid_make_inode`, `name_to_int`, `TGID_OFFSET`), fs/proc/root.c
// (`proc_root_readdir`, `proc_root_lookup`, `proc_root_getattr`,
// `proc_root_init`), fs/proc/generic.c (`proc_readdir_de`, `proc_lookup_de`,
// `pde_subdir_insert`), fs/proc/self.c, fs/proc/thread_self.c, fs/proc/fd.c
// (`proc_readfd_common`, `proc_fd_instantiate`, `proc_lookupfd_common`,
// `proc_fd_permission`, `proc_fd_access_allowed`, `tid_fd_mode`),
// fs/proc/proc_sysctl.c (`proc_sys_make_inode`), kernel/ptrace.c
// (`__ptrace_may_access`). All GPL-2.0.
// Copyright of the originals: Linus Torvalds and the procfs authors.
// Transformation: procfs inodes are not allocated. A node is a value (an
// [`InodeId`] with [`crate::vfs::PROC_NODE_BIT`] set that packs the
// superblock, the kind, the pid and a subindex), so a lookup in the immutable
// path walk creates nothing and an open file or working directory holds the
// node by value; whether it still names something is decided on every use,
// as `get_proc_task` does. The task facts a lookup needs are a mirror of the
// task list ([`ProcState::sync`]); what only the owning task can see is
// published by it ([`TaskView`], `userspace.rs`). Inode numbers are derived
// from the node (Linux's `get_next_ino` values are boot dependent).
#![forbid(unsafe_code)]
//! The procfs core: nodes, directory tables, lookup, readdir and attributes.
//!
//! # Contract
//! * Context: task context under the `vfs` lock class; nothing sleeps.
//! * Allocation: fallible; the node functions allocate nothing.
//! * A node names a pid, not a task: it goes stale when the pid is released
//!   and every operation on it then fails the way `get_proc_task` failing
//!   does (`ESRCH` on open files and permission, `ENOENT` on lookup).
//!
//! # What is routed
//! `/proc/self`, `/proc/thread-self`, `/proc/mounts`, the pid directories with
//! `task`, `fd`, `fdinfo`, `environ`, `status`, `personality`, `limits`,
//! `comm`, `cmdline`, `stat`, `statm`, `maps`, `cwd`, `root`, `exe`, `mounts`,
//! `mountinfo`, `wchan`, the global files in [`ROOT_ENTRIES`] and
//! `/proc/sys/{kernel,vm}`. Every other entry of Linux's tables is absent
//! (`ENOENT`), listed in `docs/implementation.md`.

pub mod bugs;
pub mod capflags;
pub mod cpuinfo;
pub mod show;
pub mod view;

use alloc::vec::Vec;
use syscalls::Errno;

use crate::{
    mm::Mm,
    task::Tasklist,
    vfs::{
        Cred, FileTable, InodeId, KResult, Kstat, MAY_EXEC, PROC_NODE_BIT, S_IFDIR, S_IFLNK,
        S_IFMT, S_IFREG, SbId, Timespec, dtype,
        fs::NodeAttr,
        mkdev,
        mount::{HidePid, ProcOpts},
        ops::Env,
    },
};

pub use view::{FdEntry, MmView, TaskView};

/// `PID_MAX_LIMIT`.
pub const PID_MAX_LIMIT: i64 = 4_194_304;
/// `FIRST_PROCESS_ENTRY`: where the process entries start in `/proc`'s
/// directory positions.
pub const FIRST_PROCESS_ENTRY: i64 = 256;
/// `TGID_OFFSET`: `FIRST_PROCESS_ENTRY` plus `self` and `thread-self`.
pub const TGID_OFFSET: i64 = FIRST_PROCESS_ENTRY + 2;
/// The base of the static (`proc_alloc_inum`) inode numbers, `PROC_DYNAMIC_FIRST`.
pub const PROC_DYNAMIC_FIRST: u64 = 0xF000_0000;

/// What a node is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Kind {
    /// `/proc`.
    Root = 0,
    /// `/proc/self` (a link to the caller's tgid).
    SelfLink,
    /// `/proc/thread-self`.
    ThreadSelf,
    /// `/proc/mounts` (a link to `self/mounts`).
    MountsLink,
    /// A global file of [`ROOT_ENTRIES`] (`sub` is its index).
    Global,
    /// `/proc/sys` and below (`sub` is the index in [`SYSCTLS`]).
    SysDir,
    SysFile,
    /// `/proc/<pid>`.
    Pid,
    /// `/proc/<pid>/task`.
    TaskDir,
    /// `/proc/<pid>/fd`, `fdinfo` (`in_task` for `task/<tid>/fd`).
    FdDir,
    FdinfoDir,
    /// `/proc/<pid>/fd/<n>` (`sub` = n).
    FdLink,
    /// `/proc/<pid>/fdinfo/<n>`.
    FdinfoFile,
    // The files of the pid directory, in `tgid_base_stuff` order.
    Environ,
    Status,
    Personality,
    Limits,
    Comm,
    Cmdline,
    Stat,
    Statm,
    Maps,
    Cwd,
    RootLink,
    Exe,
    Mounts,
    Mountinfo,
    Wchan,
}

impl Kind {
    const ALL: [Self; 31] = [
        Self::Root,
        Self::SelfLink,
        Self::ThreadSelf,
        Self::MountsLink,
        Self::Global,
        Self::SysDir,
        Self::SysFile,
        Self::Pid,
        Self::TaskDir,
        Self::FdDir,
        Self::FdinfoDir,
        Self::FdLink,
        Self::FdinfoFile,
        Self::Environ,
        Self::Status,
        Self::Personality,
        Self::Limits,
        Self::Comm,
        Self::Cmdline,
        Self::Stat,
        Self::Statm,
        Self::Maps,
        Self::Cwd,
        Self::RootLink,
        Self::Exe,
        Self::Mounts,
        Self::Mountinfo,
        Self::Wchan,
        // Padding so the table indexes by discriminant without a cast panic.
        Self::Wchan,
        Self::Wchan,
        Self::Wchan,
    ];

    fn from_raw(raw: u8) -> Option<Self> {
        Self::ALL.get(usize::from(raw)).copied()
    }
}

/// A procfs node: the unpacked [`InodeId`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcNode {
    /// The superblock (mount instance).
    pub sb: SbId,
    pub kind: Kind,
    /// Under `/proc/<pid>/task/<tid>/` (the thread flavour of the tables).
    pub in_task: bool,
    /// The thread group (0 for nodes outside a pid directory).
    pub tgid: i32,
    /// Index in a table, or the descriptor number.
    pub sub: u32,
}

const SB_SHIFT: u32 = 52;
const SB_MASK: u64 = (1 << 11) - 1;
const KIND_SHIFT: u32 = 44;
const TASK_SHIFT: u32 = 43;
const TGID_SHIFT: u32 = 21;
const TGID_MASK: u64 = (1 << 22) - 1;
const SUB_MASK: u64 = (1 << 21) - 1;
/// The highest superblock id a node can name.
#[allow(clippy::cast_possible_truncation)] // SB_MASK has 11 bits
pub const MAX_SB: SbId = SB_MASK as SbId;

impl ProcNode {
    /// The node's [`InodeId`].
    #[must_use]
    pub fn id(self) -> InodeId {
        InodeId(
            PROC_NODE_BIT
                | (u64::from(self.sb) & SB_MASK) << SB_SHIFT
                | u64::from(self.kind as u8) << KIND_SHIFT
                | u64::from(self.in_task) << TASK_SHIFT
                | (u64::from(self.tgid.unsigned_abs()) & TGID_MASK) << TGID_SHIFT
                | u64::from(self.sub) & SUB_MASK,
        )
    }

    /// Unpack a handle; `None` for a tmpfs inode.
    #[must_use]
    pub fn of(id: InodeId) -> Option<Self> {
        if !id.is_proc() {
            return None;
        }
        let raw = id.0;
        Some(Self {
            sb: ((raw >> SB_SHIFT) & SB_MASK) as SbId,
            kind: Kind::from_raw(((raw >> KIND_SHIFT) & 0xff) as u8)?,
            in_task: raw >> TASK_SHIFT & 1 != 0,
            tgid: ((raw >> TGID_SHIFT) & TGID_MASK) as i32,
            sub: (raw & SUB_MASK) as u32,
        })
    }

    #[must_use]
    pub const fn new(sb: SbId, kind: Kind) -> Self {
        Self {
            sb,
            kind,
            in_task: false,
            tgid: 0,
            sub: 0,
        }
    }

    #[must_use]
    pub const fn with_tgid(mut self, tgid: i32) -> Self {
        self.tgid = tgid;
        self
    }

    #[must_use]
    pub const fn with_sub(mut self, sub: u32) -> Self {
        self.sub = sub;
        self
    }

    #[must_use]
    pub const fn in_task(mut self) -> Self {
        self.in_task = true;
        self
    }

    /// Whether the node is a directory.
    #[must_use]
    pub fn is_dir(self) -> bool {
        self.mode() & S_IFMT == S_IFDIR
    }

    /// Whether the node is a symbolic link.
    #[must_use]
    pub fn is_symlink(self) -> bool {
        self.mode() & S_IFMT == S_IFLNK
    }

    /// The file type and permission bits (`i_mode`).
    #[must_use]
    pub fn mode(self) -> u32 {
        match self.kind {
            Kind::Root | Kind::SysDir | Kind::Pid | Kind::TaskDir | Kind::FdinfoDir => {
                S_IFDIR | 0o555
            }
            Kind::SelfLink
            | Kind::ThreadSelf
            | Kind::MountsLink
            | Kind::Cwd
            | Kind::RootLink
            | Kind::Exe => S_IFLNK | 0o777,
            Kind::Global | Kind::FdinfoFile => S_IFREG | 0o444,
            Kind::SysFile => S_IFREG | SYSCTLS[self.sub as usize].mode,
            Kind::FdDir => S_IFDIR | 0o500,

            // `proc_fd_instantiate`: S_IFLNK | S_IRUSR..S_IXUSR for the open
            // modes: read -> r, write -> w, plus x (`tid_fd_mode`).
            Kind::FdLink => S_IFLNK | 0o700,

            kind => S_IFREG | pid_entry(kind).map_or(0o444, |entry| entry.mode & 0o7777),
        }
    }
}

// ---- tables -----------------------------------------------------------------------

/// One entry of the pid directory tables.
#[derive(Clone, Copy)]
pub struct PidEntry {
    pub name: &'static str,
    /// The permission bits (and the file type for the directories and links).
    pub mode: u32,
    pub kind: Kind,
}

/// `tgid_base_stuff` restricted to what is routed, in Linux's order.
pub const PID_ENTRIES: [PidEntry; 18] = [
    PidEntry {
        name: "task",
        mode: S_IFDIR | 0o555,
        kind: Kind::TaskDir,
    },
    PidEntry {
        name: "fd",
        mode: S_IFDIR | 0o500,
        kind: Kind::FdDir,
    },
    PidEntry {
        name: "fdinfo",
        mode: S_IFDIR | 0o555,
        kind: Kind::FdinfoDir,
    },
    PidEntry {
        name: "environ",
        mode: 0o400,
        kind: Kind::Environ,
    },
    PidEntry {
        name: "status",
        mode: 0o444,
        kind: Kind::Status,
    },
    PidEntry {
        name: "personality",
        mode: 0o400,
        kind: Kind::Personality,
    },
    PidEntry {
        name: "limits",
        mode: 0o444,
        kind: Kind::Limits,
    },
    PidEntry {
        name: "comm",
        mode: 0o644,
        kind: Kind::Comm,
    },
    PidEntry {
        name: "cmdline",
        mode: 0o444,
        kind: Kind::Cmdline,
    },
    PidEntry {
        name: "stat",
        mode: 0o444,
        kind: Kind::Stat,
    },
    PidEntry {
        name: "statm",
        mode: 0o444,
        kind: Kind::Statm,
    },
    PidEntry {
        name: "maps",
        mode: 0o444,
        kind: Kind::Maps,
    },
    PidEntry {
        name: "cwd",
        mode: S_IFLNK | 0o777,
        kind: Kind::Cwd,
    },
    PidEntry {
        name: "root",
        mode: S_IFLNK | 0o777,
        kind: Kind::RootLink,
    },
    PidEntry {
        name: "exe",
        mode: S_IFLNK | 0o777,
        kind: Kind::Exe,
    },
    PidEntry {
        name: "mounts",
        mode: 0o444,
        kind: Kind::Mounts,
    },
    PidEntry {
        name: "mountinfo",
        mode: 0o444,
        kind: Kind::Mountinfo,
    },
    PidEntry {
        name: "wchan",
        mode: 0o444,
        kind: Kind::Wchan,
    },
];

fn pid_entry(kind: Kind) -> Option<&'static PidEntry> {
    PID_ENTRIES.iter().find(|entry| entry.kind == kind)
}

/// The entries of `/proc/<pid>/task/<tid>` (`tid_base_stuff`): the pid
/// directory without `task`.
fn dir_entries(in_task: bool) -> &'static [PidEntry] {
    if in_task {
        &PID_ENTRIES[1..]
    } else {
        &PID_ENTRIES
    }
}

/// A global file of `/proc` or a symbolic link, by name; sorted as Linux's
/// `pde_subdir` red-black tree lists them (length, then bytes).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Global {
    Sys,
    Stat,
    Uptime,
    Cmdline,
    Cpuinfo,
    Devices,
    Loadavg,
    Meminfo,
    Version,
    Filesystems,
}

pub const ROOT_ENTRIES: [(&str, Global); 10] = [
    ("sys", Global::Sys),
    ("stat", Global::Stat),
    ("uptime", Global::Uptime),
    ("cmdline", Global::Cmdline),
    ("cpuinfo", Global::Cpuinfo),
    ("devices", Global::Devices),
    ("loadavg", Global::Loadavg),
    ("meminfo", Global::Meminfo),
    ("version", Global::Version),
    ("filesystems", Global::Filesystems),
];

/// Index in the position order of `/proc`: `mounts` is registered between
/// `stat` and `uptime` by the same ordering (length 6, bytes).
fn root_order() -> impl Iterator<Item = RootEnt> {
    // sys(3) stat(4) mounts(6) uptime(6) cmdline(7) ... filesystems(11).
    const ORDER: [RootEnt; 11] = [
        RootEnt::Global(0),
        RootEnt::Global(1),
        RootEnt::MountsLink,
        RootEnt::Global(2),
        RootEnt::Global(3),
        RootEnt::Global(4),
        RootEnt::Global(5),
        RootEnt::Global(6),
        RootEnt::Global(7),
        RootEnt::Global(8),
        RootEnt::Global(9),
    ];
    ORDER.into_iter()
}

#[derive(Clone, Copy)]
enum RootEnt {
    Global(usize),
    MountsLink,
}

/// A sysctl entry (`ctl_table`).
#[derive(Clone, Copy)]
pub struct Sysctl {
    pub name: &'static str,
    /// The permission bits, or `S_IFDIR | 0o555` for a directory.
    pub mode: u32,
    /// Index of the parent in [`SYSCTLS`] (`usize::MAX` for the `sys` root).
    pub parent: usize,
    pub which: Sys,
}

/// What a sysctl file reads.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Sys {
    Dir,
    OsType,
    OsRelease,
    Version,
    Hostname,
    Domainname,
    PidMax,
    ThreadsMax,
    NgroupsMax,
    CapLastCap,
    OverflowUid,
    OverflowGid,
    RandomizeVaSpace,
    MaxMapCount,
    MmapMinAddr,
    OvercommitMemory,
}

const D: u32 = S_IFDIR | 0o555;

/// The routed part of the sysctl tree: `sys` is entry 0 (the root dir of the
/// tree is `/proc/sys`), its subdirectories and their files, each directory's
/// children sorted bytewise as the sysctl rb-tree lists them.
pub const SYSCTLS: [Sysctl; 18] = [
    Sysctl {
        name: "sys",
        mode: D,
        parent: usize::MAX,
        which: Sys::Dir,
    },
    Sysctl {
        name: "kernel",
        mode: D,
        parent: 0,
        which: Sys::Dir,
    },
    Sysctl {
        name: "vm",
        mode: D,
        parent: 0,
        which: Sys::Dir,
    },
    Sysctl {
        name: "cap_last_cap",
        mode: 0o444,
        parent: 1,
        which: Sys::CapLastCap,
    },
    Sysctl {
        name: "domainname",
        mode: 0o644,
        parent: 1,
        which: Sys::Domainname,
    },
    Sysctl {
        name: "hostname",
        mode: 0o644,
        parent: 1,
        which: Sys::Hostname,
    },
    Sysctl {
        name: "ngroups_max",
        mode: 0o444,
        parent: 1,
        which: Sys::NgroupsMax,
    },
    Sysctl {
        name: "osrelease",
        mode: 0o444,
        parent: 1,
        which: Sys::OsRelease,
    },
    Sysctl {
        name: "ostype",
        mode: 0o444,
        parent: 1,
        which: Sys::OsType,
    },
    Sysctl {
        name: "overflowgid",
        mode: 0o644,
        parent: 1,
        which: Sys::OverflowGid,
    },
    Sysctl {
        name: "overflowuid",
        mode: 0o644,
        parent: 1,
        which: Sys::OverflowUid,
    },
    Sysctl {
        name: "pid_max",
        mode: 0o644,
        parent: 1,
        which: Sys::PidMax,
    },
    Sysctl {
        name: "randomize_va_space",
        mode: 0o644,
        parent: 1,
        which: Sys::RandomizeVaSpace,
    },
    Sysctl {
        name: "threads-max",
        mode: 0o644,
        parent: 1,
        which: Sys::ThreadsMax,
    },
    Sysctl {
        name: "version",
        mode: 0o444,
        parent: 1,
        which: Sys::Version,
    },
    Sysctl {
        name: "max_map_count",
        mode: 0o644,
        parent: 2,
        which: Sys::MaxMapCount,
    },
    Sysctl {
        name: "mmap_min_addr",
        mode: 0o644,
        parent: 2,
        which: Sys::MmapMinAddr,
    },
    Sysctl {
        name: "overcommit_memory",
        mode: 0o644,
        parent: 2,
        which: Sys::OvercommitMemory,
    },
];

// ---- the task mirror ------------------------------------------------------------------

/// What a lookup, a readdir or an attribute query knows of a thread group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PidFacts {
    pub tgid: i32,
    /// `cred->uid`, `euid`, `suid` and the group ids: `__ptrace_may_access`.
    pub uid: u32,
    pub euid: u32,
    pub suid: u32,
    pub gid: u32,
    pub egid: u32,
    pub sgid: u32,
    /// `get_dumpable(mm) == SUID_DUMP_USER` (a task without an mm counts as
    /// dumpable: `task_dump_owner`).
    pub dumpable: bool,
    /// `exit_state != 0`: a zombie keeps its directory until reaped.
    pub zombie: bool,
}

/// What the address spaces of all live tasks add up to, as the published
/// views report them (`/proc/meminfo`'s `AnonPages`, `Mapped` and
/// `PageTables`): kept up to date as views are published and dropped, so the
/// global files read three words instead of visiting every task.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MmTotals {
    pub anon_pages: u64,
    pub mapped_pages: u64,
    pub pgtables_bytes: u64,
}

impl MmTotals {
    fn of(view: &TaskView) -> Self {
        view.mm.as_ref().map_or_else(Self::default, |mm| Self {
            anon_pages: mm.rss_anon,
            mapped_pages: mm.rss_file + mm.rss_shmem,
            pgtables_bytes: mm.pgtables_bytes,
        })
    }

    fn add(&mut self, other: Self) {
        self.anon_pages += other.anon_pages;
        self.mapped_pages += other.mapped_pages;
        self.pgtables_bytes += other.pgtables_bytes;
    }

    fn sub(&mut self, other: Self) {
        self.anon_pages -= other.anon_pages;
        self.mapped_pages -= other.mapped_pages;
        self.pgtables_bytes -= other.pgtables_bytes;
    }
}

/// The procfs state shared by every `proc` superblock: the live thread groups
/// and the views the tasks published.
#[derive(Default)]
pub struct ProcState {
    /// Sorted by tgid; meaningful while `mirror_valid`.
    pub pids: Vec<PidFacts>,
    /// [`Tasklist::epoch`] the mirror was brought up to date at.
    epoch: u64,
    /// `pids` was built (and has been followed since); false until the first
    /// [`ProcState::sync`] and again after a [`ProcState::prune`].
    mirror_valid: bool,
    /// [`Tasklist::epoch`] the views were last pruned at ([`ProcState::prune`]).
    pruned_epoch: u64,
    /// `(tgid, view)`, sorted by tgid.
    views: Vec<(i32, TaskView)>,
    /// The sum of the views' address-space figures.
    totals: MmTotals,
    /// `pde->size` of `/proc/cmdline`: the command line length plus one.
    pub cmdline_size: i64,
    /// The `i_mtime` and `i_ctime` of the nodes a `setattr` stamped (`ftruncate`, `O_TRUNC`).
    /// shortcut: a node nobody stamped reports the time of the `getattr` call, where Linux
    /// reports the time its inode was instantiated; a stamped one keeps its time until its pid
    /// is released or its superblock goes, where Linux's inode may be evicted earlier. Upgrade
    /// with stored inodes (a procfs inode cache).
    stamps: Vec<(InodeId, Timespec)>,
}

impl ProcState {
    /// What the mirror records of the task `id`.
    fn facts_of(tasks: &Tasklist, id: crate::task::TaskId) -> Option<PidFacts> {
        let task = tasks.task(id)?;
        let cred = task.cred;
        Some(PidFacts {
            tgid: tasks.task_tgid_vnr(id),
            uid: cred.uid,
            euid: cred.euid,
            suid: cred.suid,
            gid: cred.gid,
            egid: cred.egid,
            sgid: cred.sgid,
            dumpable: tasks.dumpable(id),
            zombie: task.exit_state != crate::task::tasklist::ExitState::Live,
        })
    }

    /// Bring the pid mirror up to date with the task list: replay the changes
    /// the list logged since the last call (time proportional to them), or
    /// rebuild from the whole list when the mirror is new or more than the
    /// log holds happened.
    ///
    /// # Errors
    /// `ENOMEM`; the old mirror stays.
    pub fn sync(&mut self, tasks: &Tasklist) -> KResult<()> {
        if self.mirror_valid && self.epoch == tasks.epoch() {
            return Ok(());
        }
        if self.mirror_valid
            && let Some(changed) = tasks.changed_since(self.epoch)
        {
            // One insertion per logged change at most: reserve them all first.
            let n = changed.count();
            self.pids.try_reserve(n).map_err(|_| Errno::ENOMEM)?;
            for nr in tasks.changed_since(self.epoch).into_iter().flatten() {
                let facts = tasks
                    .find_task_by_vpid(nr)
                    .filter(|&id| tasks.task_tgid_vnr(id) == nr)
                    .and_then(|id| Self::facts_of(tasks, id));
                match (self.pids.binary_search_by_key(&nr, |f| f.tgid), facts) {
                    (Ok(at), Some(facts)) => self.pids[at] = facts,
                    (Err(at), Some(facts)) => {
                        let _ = self.pids.push_within_capacity(facts);
                        self.pids[at..].rotate_right(1);
                    }
                    (Ok(at), None) => {
                        self.pids.remove(at);
                        self.drop_view(nr);
                    }
                    (Err(_), None) => self.drop_view(nr),
                }
            }
            self.epoch = tasks.epoch();
            return Ok(());
        }
        let mut pids: Vec<PidFacts> = Vec::new();
        pids.try_reserve_exact(tasks.nr_threads() as usize)
            .map_err(|_| Errno::ENOMEM)?;
        for id in tasks.processes() {
            if let Some(facts) = Self::facts_of(tasks, id) {
                let _ = pids.push_within_capacity(facts);
            }
        }
        pids.sort_unstable_by_key(|facts| facts.tgid);
        // Views of released groups go with them.
        self.retain_views(|tgid| pids.binary_search_by_key(&tgid, |f| f.tgid).is_ok());
        self.pids = pids;
        self.epoch = tasks.epoch();
        self.mirror_valid = true;
        Ok(())
    }

    /// Drop the views of released thread groups without building the mirror
    /// (no procfs exists, so nothing reads it, but the views of exited tasks
    /// must not pile up). Time proportional to the changes since the last
    /// call, nothing when the task list did not change.
    pub fn prune(&mut self, tasks: &Tasklist) {
        if self.mirror_valid {
            // Nothing follows the list from here on: the next sync rebuilds.
            self.mirror_valid = false;
            self.pids = Vec::new();
        }
        if self.pruned_epoch == tasks.epoch() {
            return;
        }
        if let Some(changed) = tasks.changed_since(self.pruned_epoch) {
            for nr in changed {
                if tasks.find_task_by_vpid(nr).is_none() {
                    self.drop_view(nr);
                }
            }
        } else {
            self.retain_views(|tgid| tasks.find_task_by_vpid(tgid).is_some());
        }
        self.pruned_epoch = tasks.epoch();
    }

    fn retain_views(&mut self, mut keep: impl FnMut(i32) -> bool) {
        let totals = &mut self.totals;
        self.views.retain(|(tgid, view)| {
            let kept = keep(*tgid);
            if !kept {
                totals.sub(MmTotals::of(view));
            }
            kept
        });
        // The nodes of the pids that went (a pid without a view has none).
        let views = &self.views;
        self.stamps.retain(|(id, _)| {
            ProcNode::of(*id).is_none_or(|node| {
                node.tgid == 0 || views.binary_search_by_key(&node.tgid, |(t, _)| *t).is_ok()
            })
        });
    }

    fn drop_view(&mut self, tgid: i32) {
        if let Ok(at) = self.views.binary_search_by_key(&tgid, |(t, _)| *t) {
            let (_, view) = self.views.remove(at);
            self.totals.sub(MmTotals::of(&view));
        }
        self.forget_pid(tgid);
    }

    /// The nodes below `/proc/<tgid>` are gone: forget what `setattr` stamped on them.
    fn forget_pid(&mut self, tgid: i32) {
        self.stamps
            .retain(|(id, _)| ProcNode::of(*id).is_none_or(|node| node.tgid != tgid));
    }

    /// The superblock `sb` is gone.
    pub fn forget_sb(&mut self, sb: SbId) {
        self.stamps
            .retain(|(id, _)| ProcNode::of(*id).is_none_or(|node| node.sb != sb));
    }

    /// The time `setattr_copy` stored in the node's `i_mtime` and `i_ctime`, if a `setattr`
    /// did.
    #[must_use]
    pub fn stamp(&self, id: InodeId) -> Option<Timespec> {
        self.stamps
            .iter()
            .find_map(|(node, time)| (*node == id).then_some(*time))
    }

    /// `setattr_copy` of `ATTR_MTIME | ATTR_CTIME` with the time `notify_change` took (`now`):
    /// both times of the node become `time`.
    ///
    /// # Errors
    /// `ENOMEM`.
    pub fn set_stamp(&mut self, id: InodeId, time: Timespec) -> KResult<()> {
        if let Some(entry) = self.stamps.iter_mut().find(|(node, _)| *node == id) {
            entry.1 = time;
            return Ok(());
        }
        self.stamps.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
        let _ = self.stamps.push_within_capacity((id, time));
        Ok(())
    }

    /// The facts of a thread group.
    #[must_use]
    pub fn facts(&self, tgid: i32) -> Option<&PidFacts> {
        self.pids
            .binary_search_by_key(&tgid, |facts| facts.tgid)
            .ok()
            .map(|at| &self.pids[at])
    }

    /// `nr_processes()` for the thread-group count of `/proc`'s link count.
    #[must_use]
    pub fn nr_processes(&self) -> usize {
        self.pids.len()
    }

    /// The view `tgid` last published.
    #[must_use]
    pub fn view(&self, tgid: i32) -> Option<&TaskView> {
        self.views
            .binary_search_by_key(&tgid, |(t, _)| *t)
            .ok()
            .map(|at| &self.views[at].1)
    }

    /// The view `tgid` last published, to refresh in place. Only the parts
    /// that carry no address-space figure may change through it (the totals
    /// are not adjusted).
    pub fn view_mut(&mut self, tgid: i32) -> Option<&mut TaskView> {
        let at = self.views.binary_search_by_key(&tgid, |(t, _)| *t).ok()?;
        Some(&mut self.views[at].1)
    }

    /// The address space `/proc/<tgid>` shows: the one the task last published.
    #[must_use]
    pub fn mm_of(&self, tgid: i32) -> Option<&MmView> {
        self.view(tgid)?.mm.as_ref()
    }

    /// Bring the address-space part of the view of `tgid` up to date with `mm`, which the task
    /// works in (the part of a publication a `vfork` hand-back needs).
    ///
    /// # Errors
    /// `ENOMEM`; the view is unchanged.
    pub fn publish_mm(
        &mut self,
        tgid: i32,
        mm: &Mm,
        rss: (u64, u64, u64),
        pgtables_bytes: u64,
    ) -> KResult<()> {
        if let Ok(at) = self.views.binary_search_by_key(&tgid, |(t, _)| *t) {
            let view = &mut self.views[at].1;
            let fresh = MmView::collect(view.mm.as_ref(), mm, rss, pgtables_bytes)?;
            self.totals.sub(MmTotals::of(view));
            view.mm = Some(fresh);
            self.totals.add(MmTotals::of(view));
        }
        Ok(())
    }

    /// The sum of the address-space figures of all published views.
    #[must_use]
    pub const fn totals(&self) -> MmTotals {
        self.totals
    }

    /// The task `tgid` exited: its view loses the address space, descriptors
    /// and filesystem context (`exit_mm`, `exit_files`, `exit_fs`).
    pub fn exit(&mut self, tgid: i32) {
        if let Ok(at) = self.views.binary_search_by_key(&tgid, |(t, _)| *t) {
            let view = &mut self.views[at].1;
            self.totals.sub(MmTotals::of(view));
            view.mm = None;
            view.exe = None;
            view.fds = view::FdView::default();
            view.has_files = false;
            view.has_fs = false;
            view.args = None;
        }
    }

    /// Publish (replace) the view of `tgid`.
    ///
    /// # Errors
    /// `ENOMEM`.
    pub fn publish(&mut self, tgid: i32, view: TaskView) -> KResult<()> {
        let added = MmTotals::of(&view);
        match self.views.binary_search_by_key(&tgid, |(t, _)| *t) {
            Ok(at) => {
                let old = core::mem::replace(&mut self.views[at].1, view);
                self.totals.sub(MmTotals::of(&old));
            }
            Err(at) => {
                self.views.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
                let _ = self.views.push_within_capacity((tgid, view));
                self.views[at..].rotate_right(1);
            }
        }
        self.totals.add(added);
        Ok(())
    }

    /// Bring the view of `tgid` up to date with what the task reports (or
    /// create it): [`TaskView::update`], so the time is proportional to what
    /// changed since the last publication.
    ///
    /// # Errors
    /// `ENOMEM`; the previous view stays.
    pub fn publish_update(&mut self, tgid: i32, input: view::Collect<'_>) -> KResult<()> {
        match self.views.binary_search_by_key(&tgid, |(t, _)| *t) {
            Ok(at) => {
                let view = &mut self.views[at].1;
                let old = MmTotals::of(view);
                view.update(input)?;
                let new = MmTotals::of(view);
                self.totals.sub(old);
                self.totals.add(new);
                Ok(())
            }
            Err(_) => self.publish(tgid, TaskView::collect(input)?),
        }
    }
}

// ---- who is asking ----------------------------------------------------------------------

/// The caller of a procfs operation (`current`).
#[derive(Clone, Copy, Debug)]
pub struct Caller {
    pub tgid: i32,
    pub cred: Cred,
}

impl Caller {
    /// `capable(CAP_SYS_PTRACE)`. shortcut: capability sets are not modelled;
    /// a task holds every capability iff its effective uid is 0 (see
    /// [`Cred::of_task`]).
    #[must_use]
    pub fn ptrace_cap(&self) -> bool {
        self.cred.sys_admin
    }

    /// `in_group_p(gid)`; shortcut: no supplementary groups exist yet.
    #[must_use]
    pub fn in_group(&self, gid: u32) -> bool {
        self.cred.fsgid == gid
    }

    /// `ptrace_may_access(task, PTRACE_MODE_READ_FSCREDS)` (`__ptrace_may_access`).
    #[must_use]
    pub fn ptrace_may_access(&self, facts: &PidFacts) -> bool {
        if facts.tgid == self.tgid {
            return true;
        }
        let (uid, gid) = (self.cred.fsuid, self.cred.fsgid);
        let same = uid == facts.euid
            && uid == facts.suid
            && uid == facts.uid
            && gid == facts.egid
            && gid == facts.sgid
            && gid == facts.gid;
        if !same && !self.ptrace_cap() {
            return false;
        }
        facts.dumpable || self.ptrace_cap()
    }

    /// `has_pid_permissions(fs_info, task, hide_pid_min)`.
    #[must_use]
    pub fn has_pid_permissions(
        &self,
        opts: &ProcOpts,
        facts: &PidFacts,
        hide_pid_min: HidePid,
    ) -> bool {
        if opts.hide_pid == HidePid::NotPtraceable {
            return self.ptrace_may_access(facts);
        }
        if (opts.hide_pid as u8) < hide_pid_min as u8 {
            return true;
        }
        if self.in_group(opts.gid) {
            return true;
        }
        self.ptrace_may_access(facts)
    }
}

/// `name_to_int`: a decimal number without a leading zero (`~0U` otherwise).
#[must_use]
pub fn name_to_int(name: &[u8]) -> Option<u32> {
    if name.is_empty() || name.len() > 10 || (name[0] == b'0' && name.len() > 1) {
        return None;
    }
    let mut value: u32 = 0;
    for &byte in name {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u32::from(byte - b'0'))?;
    }
    // `INT_MAX` bound of `name_to_int`: `if (n >= INT_MAX / 10 ...)`.
    (value < i32::MAX as u32).then_some(value)
}

// ---- lookup -------------------------------------------------------------------------------

/// `proc_lookup`/`proc_pid_lookup`/`proc_pident_lookup`/...: the child `name`
/// of directory `dir`, or `None`.
///
/// # Errors
/// `ENOENT` for a directory whose pid is gone (`proc_pident_lookup` does not
/// reach this: the task check is `get_proc_task`).
pub fn lookup(
    state: &ProcState,
    opts: &ProcOpts,
    caller: &Caller,
    dir: ProcNode,
    name: &[u8],
) -> KResult<Option<ProcNode>> {
    let sb = dir.sb;
    match dir.kind {
        Kind::Root => {
            if name == b"self" {
                return Ok(Some(ProcNode::new(sb, Kind::SelfLink)));
            }
            if name == b"thread-self" {
                return Ok(Some(ProcNode::new(sb, Kind::ThreadSelf)));
            }
            if name == b"mounts" {
                return Ok(Some(ProcNode::new(sb, Kind::MountsLink)));
            }
            if let Some(index) = ROOT_ENTRIES.iter().position(|(n, _)| n.as_bytes() == name) {
                let node = if ROOT_ENTRIES[index].1 == Global::Sys {
                    ProcNode::new(sb, Kind::SysDir)
                } else {
                    ProcNode::new(sb, Kind::Global).with_sub(sub_of(index))
                };
                // Subset=pid hides everything but the pids.
                return Ok((!opts.pidonly).then_some(node));
            }
            // proc_pid_lookup
            let Some(tgid) = name_to_int(name) else {
                return Ok(None);
            };
            let Ok(tgid) = i32::try_from(tgid) else {
                return Ok(None);
            };
            let Some(facts) = state.facts(tgid) else {
                return Ok(None);
            };
            if opts.hide_pid == HidePid::NotPtraceable
                && !caller.has_pid_permissions(opts, facts, HidePid::NoAccess)
            {
                return Ok(None);
            }
            Ok(Some(ProcNode::new(sb, Kind::Pid).with_tgid(tgid)))
        }
        Kind::Pid => {
            let Some(facts) = state.facts(dir.tgid) else {
                return Err(Errno::ENOENT);
            };
            let _ = facts;
            Ok(dir_entries(false)
                .iter()
                .find(|entry| entry.name.as_bytes() == name)
                .map(|entry| entry_node(sb, dir.tgid, false, entry)))
        }
        Kind::TaskDir => {
            // proc_task_lookup: the tid must be a thread of the group; there
            // is one thread per group, so only the tgid itself.
            let Some(tid) = name_to_int(name) else {
                return Ok(None);
            };
            if i64::from(tid) != i64::from(dir.tgid) || state.facts(dir.tgid).is_none() {
                return Ok(None);
            }
            Ok(Some(
                ProcNode::new(sb, Kind::Pid).with_tgid(dir.tgid).in_task(),
            ))
        }
        Kind::FdDir | Kind::FdinfoDir => {
            // proc_lookupfd_common
            let Some(fd) = name_to_int(name) else {
                return Ok(None);
            };
            let Some(view) = state.view(dir.tgid) else {
                return Ok(None);
            };
            if view.fd(fd).is_none() {
                return Ok(None);
            }
            let kind = if dir.kind == Kind::FdDir {
                Kind::FdLink
            } else {
                Kind::FdinfoFile
            };
            let mut node = ProcNode::new(sb, kind).with_tgid(dir.tgid).with_sub(fd);
            node.in_task = dir.in_task;
            Ok(Some(node))
        }
        Kind::SysDir => {
            let me = dir.sub as usize;
            Ok(SYSCTLS
                .iter()
                .enumerate()
                .find(|(_, e)| e.parent == me && e.name.as_bytes() == name)
                .map(|(index, entry)| {
                    let kind = if entry.which == Sys::Dir {
                        Kind::SysDir
                    } else {
                        Kind::SysFile
                    };
                    ProcNode::new(sb, kind).with_sub(sub_of(index))
                }))
        }
        _ => Err(Errno::ENOTDIR),
    }
}

/// The node of an entry of a pid (or tid) directory.
fn entry_node(sb: SbId, tgid: i32, in_task: bool, entry: &PidEntry) -> ProcNode {
    let mut node = ProcNode::new(sb, entry.kind).with_tgid(tgid);
    node.in_task = in_task;
    node
}

/// `..` of a node (`d_parent`).
#[must_use]
pub fn parent(node: ProcNode) -> ProcNode {
    let sb = node.sb;
    match node.kind {
        Kind::Root => node,
        Kind::SelfLink | Kind::ThreadSelf | Kind::MountsLink | Kind::Global | Kind::Pid
            if !node.in_task =>
        {
            ProcNode::new(sb, Kind::Root)
        }
        Kind::SysDir => {
            let me = node.sub as usize;
            match SYSCTLS[me].parent {
                usize::MAX => ProcNode::new(sb, Kind::Root),
                up => ProcNode::new(sb, Kind::SysDir).with_sub(sub_of(up)),
            }
        }
        Kind::SysFile => {
            ProcNode::new(sb, Kind::SysDir).with_sub(sub_of(SYSCTLS[node.sub as usize].parent))
        }
        Kind::Pid if node.in_task => ProcNode::new(sb, Kind::TaskDir).with_tgid(node.tgid),
        Kind::TaskDir => ProcNode::new(sb, Kind::Pid).with_tgid(node.tgid),
        Kind::FdLink => ProcNode {
            kind: Kind::FdDir,
            sub: 0,
            ..node
        },
        Kind::FdinfoFile => ProcNode {
            kind: Kind::FdinfoDir,
            sub: 0,
            ..node
        },
        _ => ProcNode {
            kind: Kind::Pid,
            sub: 0,
            ..node
        },
    }
}

/// The name of a node in its parent (`d_name`), for `d_path`.
///
/// # Errors
/// `ENOMEM`.
pub fn name_of(node: ProcNode, out: &mut crate::seq::Seq) -> KResult<()> {
    use core::fmt::Write;
    let text = |out: &mut crate::seq::Seq, s: &str| out.puts(s);
    match node.kind {
        Kind::Root => Ok(()),
        Kind::SelfLink => text(out, "self"),
        Kind::ThreadSelf => text(out, "thread-self"),
        Kind::MountsLink => text(out, "mounts"),
        Kind::Global => text(out, ROOT_ENTRIES[node.sub as usize].0),
        Kind::SysDir | Kind::SysFile => text(out, SYSCTLS[node.sub as usize].name),
        Kind::Pid | Kind::TaskDir if node.kind == Kind::TaskDir => text(out, "task"),
        Kind::Pid => write!(out, "{}", node.tgid).map_err(|_| Errno::ENOMEM),
        Kind::FdDir => text(out, "fd"),
        Kind::FdinfoDir => text(out, "fdinfo"),
        Kind::FdLink | Kind::FdinfoFile => write!(out, "{}", node.sub).map_err(|_| Errno::ENOMEM),
        kind => text(out, pid_entry(kind).map_or("?", |e| e.name)),
    }
}

// ---- attributes ------------------------------------------------------------------------------

/// `inode_permission` inputs of a node and its `stat` attributes.
#[derive(Clone, Copy, Debug)]
pub struct Attr {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub size: i64,
}

/// `task_dump_owner`: the owner of a task's nodes.
fn dump_owner(facts: Option<&PidFacts>, mode: u32) -> (u32, u32) {
    let Some(facts) = facts else {
        return (0, 0);
    };
    // task_dump_owner: the owner is the effective ids, except that a per-process node that is
    // not a world-readable directory belongs to root when the task has no `mm` (a zombie) or
    // its `mm` is not dumpable.
    if mode == S_IFDIR | 0o555 || (facts.dumpable && !facts.zombie) {
        (facts.euid, facts.egid)
    } else {
        (0, 0)
    }
}

/// The attributes of `node` (`proc_pid_getattr`/`proc_root_getattr`/...); a
/// node whose pid is gone keeps its mode and belongs to root, like the cached
/// inode of a dead task.
#[must_use]
pub fn attr(state: &ProcState, node: ProcNode, opts: &ProcOpts) -> Attr {
    let mode = node.mode();
    let owner = |kind_has_task: bool| {
        if kind_has_task {
            dump_owner(state.facts(node.tgid), mode)
        } else {
            (0, 0)
        }
    };
    let pid_scoped = !matches!(
        node.kind,
        Kind::Root
            | Kind::SelfLink
            | Kind::ThreadSelf
            | Kind::MountsLink
            | Kind::Global
            | Kind::SysDir
            | Kind::SysFile
    );
    let (uid, gid) = owner(pid_scoped);
    let mut size = 0;
    let mut nlink = 1;
    match node.kind {
        Kind::Root => {
            // proc_root.nlink + nr_processes(): 2 + the static directories.
            let dirs = 1; // sys
            nlink = 2 + dirs + u32::try_from(state.nr_processes()).unwrap_or(u32::MAX - 3 - dirs);
        }
        Kind::MountsLink => size = i64::try_from(b"self/mounts".len()).unwrap_or(0),
        Kind::SysDir => nlink = 1,
        Kind::Pid | Kind::TaskDir | Kind::FdDir | Kind::FdinfoDir => {
            let entries = dir_entries(node.kind == Kind::Pid && node.in_task);
            let subdirs = entries
                .iter()
                .filter(|e| e.mode & S_IFMT == S_IFDIR)
                .count();
            nlink = match node.kind {
                Kind::Pid => 2 + u32::try_from(subdirs).unwrap_or(0),
                // `task` counts the threads: 2 + 1.
                Kind::TaskDir => 3,
                _ => 2,
            };
            if node.kind == Kind::FdDir {
                // proc_fd_getattr: i_size = the open descriptor count.
                size = state
                    .view(node.tgid)
                    .map_or(0, |view| i64::try_from(view.fds.len()).unwrap_or(0));
            }
        }
        Kind::FdLink => size = 64,
        Kind::Global if ROOT_ENTRIES[node.sub as usize].1 == Global::Cmdline => {
            size = state.cmdline_size;
        }
        _ => {}
    }
    let _ = opts;
    Attr {
        mode,
        uid,
        gid,
        nlink,
        size,
    }
}

/// `i_ino` of a node: static inodes count up from [`PROC_DYNAMIC_FIRST`]
/// (`proc_alloc_inum`); the rest are derived from the pid and the kind.
#[must_use]
pub fn ino(node: ProcNode) -> u64 {
    match node.kind {
        Kind::SelfLink => PROC_DYNAMIC_FIRST,
        Kind::ThreadSelf => PROC_DYNAMIC_FIRST + 1,
        Kind::MountsLink => PROC_DYNAMIC_FIRST + 2,
        Kind::Root => 1,
        Kind::Global => PROC_DYNAMIC_FIRST + 0x100 + u64::from(node.sub),
        Kind::SysDir | Kind::SysFile => PROC_DYNAMIC_FIRST + 0x200 + u64::from(node.sub),
        _ => {
            let per_pid = 0x1_0000_0000u64 / 8;
            let _ = per_pid;
            // Below PROC_DYNAMIC_FIRST: pid * 64 + the kind (and the fd).
            let base = 0x1000_0000
                + (u64::try_from(node.tgid).unwrap_or(0) << 6).wrapping_mul(2)
                + u64::from(node.in_task) * 0x100_0000;
            (base + u64::from(node.kind as u8)) & 0xEFFF_FFFF
                | (u64::from(node.sub) << 8) & 0x0FFF_FF00
        }
    }
}

/// `generic_fillattr` for a node.
#[must_use]
pub fn getattr(
    state: &ProcState,
    node: ProcNode,
    opts: &ProcOpts,
    dev: u32,
    now: Timespec,
) -> Kstat {
    let attr = attr(state, node, opts);
    let stamp = state.stamp(node.id());
    Kstat {
        dev: mkdev(0, dev),
        ino: ino(node),
        mode: attr.mode,
        nlink: attr.nlink,
        uid: attr.uid,
        gid: attr.gid,
        rdev: 0,
        size: attr.size,
        blksize: 1024,
        blocks: 0,
        atime: now,
        // `setattr_copy` stored these; otherwise see `ProcState::stamps`.
        mtime: stamp.unwrap_or(now),
        ctime: stamp.unwrap_or(now),
        btime: now,
        attributes: 0,
        attributes_mask: crate::vfs::STATX_ATTR_AUTOMOUNT
            | crate::vfs::STATX_ATTR_DAX
            | crate::vfs::STATX_ATTR_MOUNT_ROOT,
        mnt_id: 0,
    }
}

/// What `->getattr` refuses: `pid_getattr` (the process and thread directories) answers `ENOENT`
/// for a process `hidepid` hides from the caller, "to make `getattr()` consistent with `readdir()`".
///
/// # Errors
/// `ENOENT`.
pub fn getattr_check(
    state: &ProcState,
    opts: &ProcOpts,
    caller: &Caller,
    node: ProcNode,
) -> KResult<()> {
    if node.kind == Kind::Pid
        && let Some(facts) = state.facts(node.tgid)
        && !caller.has_pid_permissions(opts, facts, HidePid::Invisible)
    {
        return Err(Errno::ENOENT);
    }
    Ok(())
}

// ---- readdir ------------------------------------------------------------------------------------

/// The callback of [`readdir`]: `(name, pos, ino, d_type)`, false when full.
pub type Actor<'a> = dyn FnMut(&[u8], i64, u64, u8) -> bool + 'a;

/// `dir_emit_dots` for a node whose `.` and `..` are known.
fn emit_dots(node: ProcNode, pos: &mut i64, actor: &mut Actor<'_>) -> bool {
    if *pos == 0 {
        if !actor(b".", *pos, ino(node), dtype(S_IFDIR)) {
            return false;
        }
        *pos = 1;
    }
    if *pos == 1 {
        if !actor(b"..", *pos, ino(parent(node)), dtype(S_IFDIR)) {
            return false;
        }
        *pos = 2;
    }
    true
}

/// Emit the table `entries` from `pos - 2` on (`proc_pident_readdir`).
fn readdir_table(state: &ProcState, node: ProcNode, pos: &mut i64, actor: &mut Actor<'_>) -> bool {
    let entries = dir_entries(node.in_task);
    let mut index = usize::try_from(*pos - 2).unwrap_or(usize::MAX);
    while let Some(entry) = entries.get(index) {
        let child = entry_node(node.sb, node.tgid, node.in_task, entry);
        if !actor(
            entry.name.as_bytes(),
            *pos,
            ino(child),
            dtype(entry.mode | (child.mode() & S_IFMT)),
        ) {
            return false;
        }
        index += 1;
        *pos = i64::try_from(index).unwrap_or(0) + 2;
    }
    let _ = state;
    true
}

/// `iterate_shared` of a procfs directory: call `actor` for each entry from
/// `*pos`; the position is `ctx->pos` as Linux leaves it.
///
/// # Errors
/// `ENOENT` when the directory's pid is gone (`get_proc_task` fails).
#[allow(clippy::too_many_lines)] // one arm per directory kind
pub fn readdir(
    state: &ProcState,
    opts: &ProcOpts,
    caller: &Caller,
    node: ProcNode,
    pos: &mut i64,
    actor: &mut Actor<'_>,
) -> KResult<()> {
    let sb = node.sb;
    match node.kind {
        Kind::Root => {
            if *pos < FIRST_PROCESS_ENTRY {
                if !emit_dots(node, pos, actor) {
                    return Ok(());
                }
                // proc_readdir_de: static entries at 2 + index.
                if !opts.pidonly {
                    let mut index = usize::try_from(*pos - 2).unwrap_or(usize::MAX);
                    for ent in root_order().skip(index) {
                        let (name, child) = match ent {
                            RootEnt::MountsLink => ("mounts", ProcNode::new(sb, Kind::MountsLink)),
                            RootEnt::Global(g) => {
                                let child = if ROOT_ENTRIES[g].1 == Global::Sys {
                                    ProcNode::new(sb, Kind::SysDir)
                                } else {
                                    ProcNode::new(sb, Kind::Global).with_sub(sub_of(g))
                                };
                                (ROOT_ENTRIES[g].0, child)
                            }
                        };
                        if !actor(name.as_bytes(), *pos, ino(child), dtype(child.mode())) {
                            return Ok(());
                        }
                        index += 1;
                        *pos = i64::try_from(index).unwrap_or(0) + 2;
                    }
                }
                *pos = FIRST_PROCESS_ENTRY;
            }
            readdir_pids(state, *opts, caller, sb, pos, actor);
            Ok(())
        }
        Kind::Pid => {
            if state.facts(node.tgid).is_none() {
                return Err(Errno::ENOENT);
            }
            if emit_dots(node, pos, actor) {
                readdir_table(state, node, pos, actor);
            }
            Ok(())
        }
        Kind::TaskDir => {
            if state.facts(node.tgid).is_none() {
                return Err(Errno::ENOENT);
            }
            if !emit_dots(node, pos, actor) {
                return Ok(());
            }
            // proc_task_readdir: the one thread, tid = tgid, at position 2.
            if *pos == 2 {
                let child = ProcNode::new(sb, Kind::Pid).with_tgid(node.tgid).in_task();
                let mut name = [0u8; 11];
                let len = fmt_decimal(&mut name, u64::try_from(node.tgid).unwrap_or(0));
                if !actor(&name[..len], *pos, ino(child), dtype(S_IFDIR)) {
                    return Ok(());
                }
                *pos = 3;
            }
            Ok(())
        }
        Kind::FdDir | Kind::FdinfoDir => {
            // proc_readfd_common
            let Some(view) = state.view(node.tgid) else {
                return Err(Errno::ENOENT);
            };
            if state.facts(node.tgid).is_none() {
                return Err(Errno::ENOENT);
            }
            if !emit_dots(node, pos, actor) {
                return Ok(());
            }
            // A zombie has released its files: only the dots remain.
            if !view.has_files {
                return Ok(());
            }
            let child_kind = if node.kind == Kind::FdDir {
                Kind::FdLink
            } else {
                Kind::FdinfoFile
            };
            let mut fd = u32::try_from(*pos - 2).unwrap_or(u32::MAX);
            loop {
                // fget_task_next: the next open descriptor at or after fd.
                let next = view.next_fd(fd);
                *pos = match next {
                    Some(n) => i64::from(n) + 2,
                    None => i64::from(view.max_fds) + 2,
                };
                let Some(n) = next else { break };
                fd = n;
                let mut child = ProcNode::new(sb, child_kind)
                    .with_tgid(node.tgid)
                    .with_sub(fd);
                child.in_task = node.in_task;
                let mut name = [0u8; 11];
                let len = fmt_decimal(&mut name, u64::from(fd));
                if !actor(&name[..len], *pos, ino(child), dtype(child.mode())) {
                    return Ok(());
                }
                fd += 1;
            }
            Ok(())
        }
        Kind::SysDir => {
            if !emit_dots(node, pos, actor) {
                return Ok(());
            }
            let me = node.sub as usize;
            let mut index = usize::try_from(*pos - 2).unwrap_or(usize::MAX);
            for (at, entry) in SYSCTLS
                .iter()
                .enumerate()
                .filter(|(_, e)| e.parent == me)
                .skip(index)
            {
                let kind = if entry.which == Sys::Dir {
                    Kind::SysDir
                } else {
                    Kind::SysFile
                };
                let child = ProcNode::new(sb, kind).with_sub(sub_of(at));
                if !actor(entry.name.as_bytes(), *pos, ino(child), dtype(child.mode())) {
                    return Ok(());
                }
                index += 1;
                *pos = i64::try_from(index).unwrap_or(0) + 2;
            }
            Ok(())
        }
        _ => Err(Errno::ENOTDIR),
    }
}

/// `proc_pid_readdir`: `self`, `thread-self`, then each thread group.
fn readdir_pids(
    state: &ProcState,
    opts: ProcOpts,
    caller: &Caller,
    sb: SbId,
    pos: &mut i64,
    actor: &mut Actor<'_>,
) {
    if *pos >= PID_MAX_LIMIT + TGID_OFFSET {
        return;
    }
    if *pos == TGID_OFFSET - 2 {
        let node = ProcNode::new(sb, Kind::SelfLink);
        if !actor(b"self", *pos, ino(node), dtype(S_IFLNK)) {
            return;
        }
        *pos += 1;
    }
    if *pos == TGID_OFFSET - 1 {
        let node = ProcNode::new(sb, Kind::ThreadSelf);
        if !actor(b"thread-self", *pos, ino(node), dtype(S_IFLNK)) {
            return;
        }
        *pos += 1;
    }
    let first = i32::try_from(*pos - TGID_OFFSET).unwrap_or(i32::MAX);
    let start = state.pids.partition_point(|facts| facts.tgid < first);
    for facts in &state.pids[start..] {
        if !caller.has_pid_permissions(&opts, facts, HidePid::Invisible) {
            continue;
        }
        *pos = i64::from(facts.tgid) + TGID_OFFSET;
        let node = ProcNode::new(sb, Kind::Pid).with_tgid(facts.tgid);
        let mut name = [0u8; 11];
        let len = fmt_decimal(&mut name, u64::try_from(facts.tgid).unwrap_or(0));
        if !actor(&name[..len], *pos, ino(node), dtype(S_IFDIR)) {
            return;
        }
    }
    *pos = PID_MAX_LIMIT + TGID_OFFSET;
}

/// Decimal digits of `value` into `buf`; returns the length.
fn fmt_decimal(buf: &mut [u8; 11], mut value: u64) -> usize {
    let mut digits = [0u8; 20];
    let mut n = 0;
    loop {
        digits[n] = b'0' + (value % 10) as u8;
        n += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    for (i, slot) in buf.iter_mut().take(n).enumerate() {
        *slot = digits[n - 1 - i];
    }
    n
}

// ---- permission -------------------------------------------------------------------------------

/// `inode_permission` for a procfs node, after the `sb_permission` check:
/// `proc_pid_permission` (hidepid) on a pid directory, `proc_fd_permission` on
/// the descriptor directories, `proc_tid_comm_permission` on `comm`, and the
/// generic mode check otherwise.
///
/// # Errors
/// `ESRCH` for a pid that is gone, `ENOENT`/`EPERM` for a hidden pid,
/// `EACCES`.
pub fn permission(
    state: &ProcState,
    opts: &ProcOpts,
    env: &Env,
    node: ProcNode,
    mask: u32,
) -> KResult<()> {
    let caller = Caller {
        tgid: env.tgid,
        cred: env.cred,
    };
    let attr = attr(state, node, opts);
    let node_attr = NodeAttr {
        mode: attr.mode,
        uid: attr.uid,
        gid: attr.gid,
    };
    let generic = || crate::vfs::path::permission(&node_attr, &env.cred, mask);
    match node.kind {
        // proc_sys_permission: the root of the tree is read-only for everyone.
        Kind::SysDir | Kind::SysFile => {
            let mode = if node.kind == Kind::SysDir && node.sub == 0 {
                0o555
            } else {
                SYSCTLS[node.sub as usize].mode
            };
            sysctl_permission(mode & 0o777, env, mask)
        }
        Kind::Pid => {
            // proc_pid_permission
            let Some(facts) = state.facts(node.tgid) else {
                return Err(Errno::ESRCH);
            };
            if !caller.has_pid_permissions(opts, facts, HidePid::NoAccess) {
                return Err(if opts.hide_pid == HidePid::Invisible {
                    Errno::ENOENT
                } else {
                    Errno::EPERM
                });
            }
            generic()
        }
        Kind::FdinfoDir | Kind::FdinfoFile => {
            // proc_fdinfo_permission: PTRACE_MODE_READ in addition to the mode bits.
            let Some(facts) = state.facts(node.tgid) else {
                return Err(Errno::ESRCH);
            };
            if !caller.ptrace_may_access(facts) {
                return Err(Errno::EACCES);
            }
            generic()
        }
        Kind::FdDir => {
            // proc_fd_permission: the owner's own thread group may always look.
            match generic() {
                Ok(()) => Ok(()),
                Err(error) => {
                    if node.tgid == env.tgid && state.facts(node.tgid).is_some() {
                        Ok(())
                    } else {
                        Err(error)
                    }
                }
            }
        }
        Kind::Comm => {
            // proc_tid_comm_permission
            if state.facts(node.tgid).is_none() {
                return Err(Errno::ESRCH);
            }
            if node.tgid == env.tgid && mask & MAY_EXEC == 0 {
                return Ok(());
            }
            generic()
        }
        _ => generic(),
    }
}

// ---- magic links --------------------------------------------------------------------------------

/// Where a magic link leads.
pub enum Magic {
    /// A tmpfs inode or procfs node (a path to jump to).
    Inode(InodeId),
    /// An anonymous inode (pipe, socket): not ported.
    Anonymous,
}

/// `proc_fd_access_allowed` + `proc_get_link` of `fd/<n>`, `cwd`, `root` and
/// `exe`.
///
/// # Errors
/// `EACCES` when the caller may not snoop on the task (or it is gone),
/// `ENOENT` when it has no such file, directory or executable.
pub fn magic_target(
    state: &ProcState,
    files: &FileTable,
    env: &Env,
    node: ProcNode,
) -> KResult<Magic> {
    let caller = Caller {
        tgid: env.tgid,
        cred: env.cred,
    };
    let allowed = state
        .facts(node.tgid)
        .is_some_and(|facts| caller.ptrace_may_access(facts));
    if !allowed {
        return Err(Errno::EACCES);
    }
    let view = state.view(node.tgid).ok_or(Errno::ENOENT)?;
    let entry = match node.kind {
        Kind::Cwd => return view.pwd().map(Magic::Inode).ok_or(Errno::ENOENT),
        Kind::RootLink => return view.root().map(Magic::Inode).ok_or(Errno::ENOENT),
        Kind::Exe => view.exe.ok_or(Errno::ENOENT)?,
        _ => *view.fd(node.sub).ok_or(Errno::ENOENT)?,
    };
    let file = files
        .get_checked(entry.file, entry.serial)
        .ok_or(Errno::ENOENT)?;
    Ok(file.inode.map_or(Magic::Anonymous, Magic::Inode))
}

// ---- open ---------------------------------------------------------------------------------------

/// The checks Linux makes when a procfs file is opened: `__mem_open` /
/// `proc_mem_open` (`environ`, `maps`) require `ptrace_may_access` on a task
/// that exists.
///
/// # Errors
/// `ESRCH` for a pid that is gone, `EACCES`.
pub fn open_check(state: &ProcState, env: &Env, node: ProcNode) -> KResult<()> {
    let pid_scoped = !matches!(
        node.kind,
        Kind::Root
            | Kind::SelfLink
            | Kind::ThreadSelf
            | Kind::MountsLink
            | Kind::Global
            | Kind::SysDir
            | Kind::SysFile
    );
    if pid_scoped && state.facts(node.tgid).is_none() {
        return Err(Errno::ESRCH);
    }
    if matches!(node.kind, Kind::Environ | Kind::Maps) {
        let caller = Caller {
            tgid: env.tgid,
            cred: env.cred,
        };
        let facts = state.facts(node.tgid).ok_or(Errno::ESRCH)?;
        // `proc_mem_open` (`mm_access`) finds no mm in a zombie and returns NULL: `maps` opens
        // (and reads nothing), `__mem_open` of `environ` turns it into ESRCH. With an mm,
        // `ptrace_may_access` decides.
        if facts.zombie {
            return if node.kind == Kind::Environ {
                Err(Errno::ESRCH)
            } else {
                Ok(())
            };
        }
        if !caller.ptrace_may_access(facts) {
            return Err(Errno::EACCES);
        }
    }
    // `mounts_open_common` needs the task's namespace proxy, which a zombie has dropped.
    if matches!(node.kind, Kind::Mounts | Kind::Mountinfo)
        && state.facts(node.tgid).is_some_and(|f| f.zombie)
    {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

/// Whether the entry has a `write` operation (`f_op->write`): `comm`, the
/// registered `/proc` entries (`proc_reg_write`, which answers `EIO` without a
/// `proc_write`) and the sysctls (`proc_sys_write`).
#[must_use]
pub fn has_write_op(node: ProcNode) -> bool {
    matches!(node.kind, Kind::Comm | Kind::Global | Kind::SysFile)
}

/// `S_IMMUTABLE`: `proc_pid_instantiate` and `proc_task_instantiate` mark the
/// process and thread directories, so nothing may be written in or deleted from
/// them (`inode_permission`, `may_delete`).
#[must_use]
pub fn is_immutable(node: ProcNode) -> bool {
    node.kind == Kind::Pid
}

/// `sysctl_perm` / `test_perm`: a sysctl entry is checked against its own mode
/// with the owner bits for root, the group bits for root's group and the other
/// bits otherwise; no capability overrides it.
fn sysctl_permission(mode: u32, env: &Env, mask: u32) -> KResult<()> {
    let mode = if env.cred.fsuid == 0 {
        mode >> 6
    } else if env.cred.fsgid == 0 {
        mode >> 3
    } else {
        mode
    };
    if (mask & !mode).trailing_zeros() >= 3 {
        Ok(())
    } else {
        Err(Errno::EACCES)
    }
}

/// A table index as a node's `sub` (the tables are far smaller than `u32`).
fn sub_of(index: usize) -> u32 {
    u32::try_from(index).unwrap_or(u32::MAX)
}
