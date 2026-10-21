// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: include/uapi/asm-generic/fcntl.h,
// include/uapi/linux/{stat,fcntl,limits}.h, include/linux/{fs,fcntl,stat,kdev_t,
// namei}.h, include/linux/kdev_t.h (`new_encode_dev`, `new_decode_dev`),
// fs/{namei,open,file,file_table,read_write,readdir,stat,fcntl,libfs,pipe,
// char_dev,fs_struct}.c, mm/shmem.c, init/initramfs.c. All GPL-2.0-only /
// GPL-2.0 (SPDX preserved per file in the sub-modules).
// Transformation: one in-memory tmpfs instance (the rootfs) replaces the
// dentry cache, mount table and inode/file operation tables. Dentry and inode
// collapse into one arena entry; the "dentry" of Linux is a `Child` record of
// its parent directory in creation order. Symbolic names for Linux's
// `file_operations` are the `FileKind` enum, dispatched by the syscall layer.
#![forbid(unsafe_code)]
// x86_64 only: `usize` is 64 bits, and the narrowing/sign casts below are the
// C types of the Linux ABI (`unsigned int` descriptors, `off_t`, `umode_t`,
// 32-bit inode numbers) reproduced on purpose.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
//! The VFS spine v0: tmpfs rootfs, path walk, open files, the descriptor
//! table, pipes and the initramfs unpacker, as pure host-testable code.
//!
//! # Layout
//! | module | owns | Linux |
//! | --- | --- | --- |
//! | [`tmpfs`] | inode arena, directory entries, page store, space accounting | `mm/shmem.c`, `fs/libfs.c` (`simple_offset_*`) |
//! | [`path`] | component walk, `..`, symlink following, parents for create | `fs/namei.c` |
//! | [`file`] | open files, `files_struct`, `fs_struct` | `fs/file.c`, `fs/file_table.c`, `fs/fs_struct.c` |
//! | [`pipe`] | pipe ring of page buffers | `fs/pipe.c` |
//! | [`mapping`] | what `mmap` needs of an open file, the page of a private file fault | `mm/mmap.c`, `mm/shmem.c` (`shmem_fault`) |
//! | [`ops`] | path-based operations (`open`, `mknod`, `unlink`, ...) | `fs/{open,namei,stat}.c` |
//! | [`initramfs`] | the cpio state machine | `init/initramfs.c` |
//!
//! # Context, locking and ownership
//! Task context only; nothing here sleeps, and every allocation is fallible
//! (`Vec::try_reserve` + `push_within_capacity`; `-ENOMEM` or `-ENOSPC`).
//! With one task and one CPU the caller's exclusive borrow of [`Vfs`] is the
//! whole synchronization story (Linux's `i_rwsem`, `d_lock`, `file_lock`,
//! `f_pos_lock` all collapse into it). Lock order for a second task: `PROCESS`
//! (`userspace`) -> `vfs` (new class, one per superblock) -> heap -> `FRAMES`
//! (`services`; a task's page tables are its own and `TABLES` is only the kernel template); the VFS never calls into the page tables, so the
//! reverse edge cannot occur. Ownership: [`Vfs`] owns every inode, open file
//! and pipe; handles ([`InodeId`], [`FileId`], [`PipeId`]) are indices that a
//! reference count keeps valid (`Tmpfs::iget`/`iput`, `FileTable::get`/`put`).
//!
//! shortcut: directory lookup is a linear scan of the entries; replace the
//! entry vector by a hash index when a directory with thousands of names matters.
//! The rootfs is mounted with no `MNT_RELATIME` (`init_mount_tree` passes no
//! flags), so Linux updates `atime` on every read, `getdents64` and `readlink`
//! (`relatime_need_update` is true without the flag); [`Tmpfs::touch_atime`]
//! does the same at those three sites. shortcut: `atime` is not updated by
//! following a symlink during a walk (`get_link`) or by a pipe read (the pipe
//! inode keeps one creation stamp); upgrade with a mutable walk. Every
//! timestamp comes from the [`Vfs::new`] clock, which the binary points at
//! `timer::ktime_get_real` (Linux's `current_time` without multigrain
//! granularity).

pub mod file;
pub mod initramfs;
pub mod mapping;
pub mod ops;
pub mod path;
pub mod pipe;
pub mod tmpfs;

use alloc::vec::Vec;
use syscalls::Errno;

pub use file::{Fd, FdTable, FileTable, FsStruct};
pub use ops::Env;
pub use tmpfs::Tmpfs;

pub type KResult<T> = Result<T, Errno>;

/// A tmpfs inode (arena index; `Tmpfs::iget` pins it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InodeId(pub(crate) u32);
impl InodeId {
    /// The arena index: a stable identity while the inode is pinned.
    #[must_use]
    pub const fn index(self) -> u32 {
        self.0
    }
}
/// An open file description (`struct file`; arena index in [`FileTable`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileId(pub(crate) u32);
impl FileId {
    /// The arena index: a stable identity while the description is open.
    #[must_use]
    pub const fn index(self) -> u32 {
        self.0
    }
}
/// A pipe (`pipe_inode_info`; arena index in [`Vfs`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PipeId(pub(crate) u32);

/// `struct timespec64`; the clock behind it is `timer::ktime_get_real`.
pub use crate::time::Timespec;

// ---- file types and mode bits (include/uapi/linux/stat.h) -----------------
pub const S_IFMT: u32 = 0o170_000;
pub const S_IFSOCK: u32 = 0o140_000;
pub const S_IFLNK: u32 = 0o120_000;
pub const S_IFREG: u32 = 0o100_000;
pub const S_IFBLK: u32 = 0o060_000;
pub const S_IFDIR: u32 = 0o040_000;
pub const S_IFCHR: u32 = 0o020_000;
pub const S_IFIFO: u32 = 0o010_000;
pub const S_ISUID: u32 = 0o4000;
pub const S_ISGID: u32 = 0o2000;
pub const S_ISVTX: u32 = 0o1000;
pub const S_IXGRP: u32 = 0o010;
pub const S_IXUGO: u32 = 0o111;
/// `S_IRWXUGO`.
pub const S_IRWXUGO: u32 = 0o777;
/// `S_IALLUGO`: permission bits plus set-id and sticky.
pub const S_IALLUGO: u32 = 0o7777;

// ---- open flags (arch/x86 uses the asm-generic values) ---------------------
pub const O_ACCMODE: u32 = 3;
pub const O_RDONLY: u32 = 0;
pub const O_WRONLY: u32 = 1;
pub const O_RDWR: u32 = 2;
pub const O_CREAT: u32 = 0o100;
pub const O_EXCL: u32 = 0o200;
pub const O_NOCTTY: u32 = 0o400;
pub const O_TRUNC: u32 = 0o1000;
pub const O_APPEND: u32 = 0o2000;
pub const O_NONBLOCK: u32 = 0o4000;
pub const O_DSYNC: u32 = 0o10000;
pub const FASYNC: u32 = 0o20000;
pub const O_DIRECT: u32 = 0o40000;
pub const O_LARGEFILE: u32 = 0o100_000;
pub const O_DIRECTORY: u32 = 0o200_000;
pub const O_NOFOLLOW: u32 = 0o400_000;
pub const O_NOATIME: u32 = 0o1_000_000;
pub const O_CLOEXEC: u32 = 0o2_000_000;
pub const __O_SYNC: u32 = 0o4_000_000;
pub const O_SYNC: u32 = __O_SYNC | O_DSYNC;
pub const O_PATH: u32 = 0o10_000_000;
pub const __O_TMPFILE: u32 = 0o20_000_000;
/// `VALID_OPEN_FLAGS` (include/linux/fcntl.h): everything else is dropped by
/// `open`/`openat` (`build_open_how`) and rejected by `openat2`.
pub const VALID_OPEN_FLAGS: u32 = O_RDONLY
    | O_WRONLY
    | O_RDWR
    | O_CREAT
    | O_EXCL
    | O_NOCTTY
    | O_TRUNC
    | O_APPEND
    | O_NONBLOCK
    | O_DSYNC
    | FASYNC
    | O_DIRECT
    | O_LARGEFILE
    | O_DIRECTORY
    | O_NOFOLLOW
    | O_NOATIME
    | O_CLOEXEC
    | O_SYNC
    | O_PATH
    | __O_TMPFILE;
/// `SETFL_MASK`: the flags `F_SETFL` can change (`FASYNC` is set only by
/// `->fasync`, never by the mask).
pub const SETFL_MASK: u32 = O_APPEND | O_NONBLOCK | O_DIRECT | O_NOATIME;

// ---- statx attributes (include/uapi/linux/stat.h) --------------------------
pub const STATX_ATTR_IMMUTABLE: u64 = 0x10;
pub const STATX_ATTR_APPEND: u64 = 0x20;
pub const STATX_ATTR_NODUMP: u64 = 0x40;
pub const STATX_ATTR_AUTOMOUNT: u64 = 0x1000;
pub const STATX_ATTR_MOUNT_ROOT: u64 = 0x2000;
pub const STATX_ATTR_DAX: u64 = 0x20_0000;

// ---- f_mode (include/linux/fs.h) -------------------------------------------
pub const FMODE_READ: u32 = 1 << 0;
pub const FMODE_WRITE: u32 = 1 << 1;
pub const FMODE_LSEEK: u32 = 1 << 2;
pub const FMODE_PREAD: u32 = 1 << 3;
pub const FMODE_PWRITE: u32 = 1 << 4;
pub const FMODE_CAN_READ: u32 = 1 << 5;
pub const FMODE_CAN_WRITE: u32 = 1 << 6;
pub const FMODE_PATH: u32 = 1 << 7;
pub const FMODE_CREATED: u32 = 1 << 8;
pub const FMODE_STREAM: u32 = 1 << 9;

// ---- *at() flags (include/uapi/linux/fcntl.h) -------------------------------
pub const AT_FDCWD: i32 = -100;
pub const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
pub const AT_REMOVEDIR: u32 = 0x200;
pub const AT_SYMLINK_FOLLOW: u32 = 0x400;
pub const AT_NO_AUTOMOUNT: u32 = 0x800;
pub const AT_EMPTY_PATH: u32 = 0x1000;
pub const AT_STATX_SYNC_TYPE: u32 = 0x6000;
pub const AT_EACCESS: u32 = 0x200;

// ---- access(2) / permission masks -------------------------------------------
pub const MAY_EXEC: u32 = 1;
pub const MAY_WRITE: u32 = 2;
pub const MAY_READ: u32 = 4;
pub const MAY_APPEND: u32 = 8;
pub const MAY_OPEN: u32 = 32;

pub const NAME_MAX: usize = 255;
pub const PATH_MAX: usize = 4096;
/// `MAXSYMLINKS`: symlinks followed in one walk.
pub const MAXSYMLINKS: u32 = 40;
/// `PAGE_SIZE`; the unit of tmpfs space accounting and pipe buffers.
pub const PAGE_SIZE: usize = 4096;
/// `MAX_LFS_FILESIZE` on 64-bit (`LLONG_MAX`).
pub const MAX_LFS_FILESIZE: i64 = i64::MAX;
/// `sysctl_nr_open`: the hard ceiling of a descriptor number.
pub const NR_OPEN: u64 = 1 << 20;
/// `INR_OPEN_CUR` / `INR_OPEN_MAX`: init's `RLIMIT_NOFILE`.
pub const INR_OPEN_CUR: u64 = 1024;
pub const INR_OPEN_MAX: u64 = 4096;

// ---- dev_t (include/linux/kdev_t.h) -----------------------------------------
/// `MKDEV` truncated to the 32-bit kernel `dev_t`.
#[must_use]
pub fn mkdev(major: u32, minor: u32) -> u32 {
    (u64::from(major) << 20 | u64::from(minor)) as u32
}
#[must_use]
pub fn major(dev: u32) -> u32 {
    dev >> 20
}
#[must_use]
pub fn minor(dev: u32) -> u32 {
    dev & 0xf_ffff
}
/// `new_encode_dev`: what `stat` and `mknod` carry in userspace.
#[must_use]
pub fn new_encode_dev(dev: u32) -> u32 {
    let (major, minor) = (major(dev), minor(dev));
    (minor & 0xff) | (major << 8) | ((minor & !0xff) << 12)
}
/// `new_decode_dev`.
#[must_use]
pub fn new_decode_dev(dev: u32) -> u32 {
    let major = (dev & 0xf_ff00) >> 8;
    let minor = (dev & 0xff) | ((dev >> 12) & 0xf_ff00);
    mkdev(major, minor)
}

/// `DT_*` (`include/linux/fs_types.h`, `fs_umode_to_dtype`).
#[must_use]
pub fn dtype(mode: u32) -> u8 {
    match mode & S_IFMT {
        S_IFREG => 8,
        S_IFDIR => 4,
        S_IFLNK => 10,
        S_IFCHR => 2,
        S_IFBLK => 6,
        S_IFIFO => 1,
        S_IFSOCK => 12,
        _ => 0,
    }
}

/// The calling task's filesystem credentials and the capabilities the VFS
/// consults. The kernel starts init as root with every capability.
///
/// shortcut: no supplementary groups and no capability machinery beyond the
/// bits `fs/` asks for; the ids workstream replaces this with the real
/// `struct cred` and `capable()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "one flag per capability, as `capable()` asks"
)]
pub struct Cred {
    pub fsuid: u32,
    pub fsgid: u32,
    /// `CAP_DAC_OVERRIDE`.
    pub dac_override: bool,
    /// `CAP_DAC_READ_SEARCH`.
    pub dac_read_search: bool,
    /// `CAP_FOWNER`.
    pub fowner: bool,
    /// `CAP_MKNOD`.
    pub mknod: bool,
    /// `CAP_CHOWN`.
    pub chown: bool,
    /// `CAP_FSETID`.
    pub fsetid: bool,
    /// `CAP_SYS_ADMIN`.
    pub sys_admin: bool,
    /// `CAP_SYS_BOOT`.
    pub sys_boot: bool,
}

impl Cred {
    /// The VFS view of the task's credentials: `fsuid`/`fsgid` follow the
    /// effective ids, and effective uid 0 carries every capability.
    ///
    /// shortcut: no capability sets exist yet (no `capset`, no setuid), so
    /// `capable()` is "euid is 0"; the credentials workstream replaces it.
    #[must_use]
    pub fn of_task(cred: &crate::task::Cred) -> Self {
        let root = cred.euid == 0;
        Self {
            fsuid: cred.euid,
            fsgid: cred.egid,
            dac_override: root,
            dac_read_search: root,
            fowner: root,
            mknod: root,
            chown: root,
            fsetid: root,
            sys_admin: root,
            sys_boot: root,
        }
    }

    /// uid 0 with a full capability set (`init`'s credentials).
    #[must_use]
    pub const fn root() -> Self {
        Self {
            fsuid: 0,
            fsgid: 0,
            dac_override: true,
            dac_read_search: true,
            fowner: true,
            mknod: true,
            chown: true,
            fsetid: true,
            sys_admin: true,
            sys_boot: true,
        }
    }
}

/// `struct kstat` as `stat`/`statx` report it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kstat {
    pub dev: u32,
    pub ino: u64,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u32,
    pub size: i64,
    pub blksize: u32,
    /// 512-byte units.
    pub blocks: u64,
    pub atime: Timespec,
    pub mtime: Timespec,
    pub ctime: Timespec,
    pub btime: Timespec,
    pub attributes: u64,
    pub attributes_mask: u64,
}

/// The mounted instance and every table hanging off it.
pub struct Vfs {
    pub fs: Tmpfs,
    pub files: FileTable,
    pipes: Vec<Option<pipe::Pipe>>,
    next_pipe_ino: u64,
    /// Pipe state changes so far (every mutable access to a pipe, every end
    /// released) and how many of them the scheduler has been told about
    /// ([`Vfs::take_pipe_events`]): the VFS is pure and cannot wake a sleeper.
    pipe_events: u64,
    pipe_events_seen: u64,
    /// Open file descriptions held by mappings (`vma->vm_file`).
    pins: Vec<mapping::Pin>,
    /// A write or truncate hit a file whose mapped pages are private copies.
    coherence_lost: bool,
    /// A private `/dev/zero` mapping was made (its VMA keeps no `vm_file`).
    zero_mapped: bool,
    /// A file on the console tty was opened or released since the tty last
    /// looked ([`Vfs::take_tty_touch`]): `tty->count` changed.
    tty_touched: bool,
}

impl Vfs {
    /// A fresh rootfs (tmpfs) with room for `max_blocks` pages and `max_inodes`
    /// inodes (Linux: `shmem_default_max_blocks` and `_max_inodes` are both
    /// half the RAM's page count).
    ///
    /// # Errors
    /// `ENOMEM` when the root inode cannot be allocated.
    pub fn new(max_blocks: u64, max_inodes: u64, clock: fn() -> Timespec) -> KResult<Self> {
        Ok(Self {
            fs: Tmpfs::new(max_blocks, max_inodes, clock)?,
            files: FileTable::default(),
            pipes: Vec::new(),
            next_pipe_ino: 1,
            pipe_events: 0,
            pipe_events_seen: 0,
            pins: Vec::new(),
            coherence_lost: false,
            zero_mapped: false,
            tty_touched: false,
        })
    }
}

/// Reserve room for one more element and append it: the only way a `Vec` grows
/// in this module (`Vec::push` does not exist under `no_global_oom_handling`).
pub(crate) fn try_push<T>(vec: &mut Vec<T>, value: T) -> KResult<()> {
    vec.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
    vec.push_within_capacity(value)
        .map(|_| ())
        .map_err(|_| Errno::ENOMEM)
}

/// A copy of `bytes` in a fallibly allocated vector.
pub(crate) fn try_copy(bytes: &[u8]) -> KResult<Vec<u8>> {
    let mut out = Vec::new();
    out.try_reserve_exact(bytes.len())
        .map_err(|_| Errno::ENOMEM)?;
    for &byte in bytes {
        out.push_within_capacity(byte).map_err(|_| Errno::ENOMEM)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
