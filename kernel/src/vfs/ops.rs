// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: fs/open.c (GPL-2.0:
// `build_open_how`, `build_open_flags`, `do_dentry_open`, `do_sys_openat2`,
// `do_faccessat`, `vfs_truncate`, `do_ftruncate`, `chmod_common`,
// `chown_common`, `ksys_chdir`/`ksys_fchdir`), fs/namei.c (`path_openat`,
// `open_last_lookups`, `lookup_open`, `do_open`, `may_open`, `do_tmpfile`,
// `do_o_path`, `filename_create`, `lookup_one_qstr_excl`, `may_create`,
// `may_delete`, `check_sticky`, `vfs_mknod`, `may_mknod`, `vfs_mkdir`,
// `do_unlinkat`, `do_rmdir`, `vfs_link`, `do_linkat`, `vfs_symlink`,
// `vfs_prepare_mode`), fs/stat.c (`do_readlinkat`), fs/d_path.c
// (`sys_getcwd`), init/main.c (`console_on_rootfs`), fs/init.c (`init_*`).
// Copyright of the originals: Linus Torvalds and the VFS authors.
// Transformation: no mounts, LSM, fsnotify, leases or write-access counting;
// the dentry/inode split collapses (see `vfs`); a path is walked by `path`.
#![forbid(unsafe_code)]
//! Path-based VFS operations with Linux's check order and `errno` precedence.
//!
//! Every function takes an [`Env`] (the caller's root, starting directory,
//! credentials and umask), never reads user memory and never sleeps.

use alloc::vec::Vec;
use syscalls::Errno;

use super::{
    __O_TMPFILE, AT_SYMLINK_NOFOLLOW, Cred, FMODE_CAN_READ, FMODE_CAN_WRITE, FMODE_LSEEK,
    FMODE_PATH, FMODE_PREAD, FMODE_PWRITE, FMODE_READ, FMODE_WRITE, FileId, FsStruct, InodeId,
    KResult, Kstat, MAY_APPEND, MAY_EXEC, MAY_READ, MAY_WRITE, NAME_MAX, O_ACCMODE, O_APPEND,
    O_CLOEXEC, O_CREAT, O_DIRECT, O_DIRECTORY, O_DSYNC, O_EXCL, O_NOATIME, O_NOCTTY, O_NOFOLLOW,
    O_PATH, O_TRUNC, S_IALLUGO, S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO, S_IFLNK, S_IFMT, S_IFREG,
    S_IFSOCK, S_IRWXUGO, S_ISGID, S_ISUID, S_ISVTX, S_IXGRP, Timespec, VALID_OPEN_FLAGS, Vfs,
    file::{CharDev, Dentry, File, FileKind},
    mkdev, new_decode_dev,
    path::{self, LOOKUP_DIRECTORY, LOOKUP_FOLLOW, LastKind, WALK_TRAILING, Walk},
    pipe::Pipe,
    try_copy,
};

/// The mount id of the kernel-internal pipefs mount in the reference
/// configuration (`/proc/<pid>/fdinfo` of a pipe, `init-reference-016`).
pub const PIPEFS_MNT_ID: u32 = 13;

/// What a path operation needs to know about the caller (`current`).
#[derive(Clone, Copy, Debug)]
pub struct Env {
    /// `fs->root`.
    pub root: InodeId,
    /// Where a relative path starts: `fs->pwd`, or the directory of a dirfd.
    pub start: InodeId,
    pub cred: Cred,
    /// `fs->umask`.
    pub umask: u32,
    /// `task_tgid_vnr(current)`: what `/proc/self` names (0 for the kernel).
    pub tgid: i32,
}

/// `UTIME_NOW` / `UTIME_OMIT` (include/linux/stat.h): the special `tv_nsec` values of `utimensat`.
pub const UTIME_NOW: i64 = (1 << 30) - 1;
pub const UTIME_OMIT: i64 = (1 << 30) - 2;

/// `renameat2` flags (include/uapi/linux/fcntl.h).
pub const RENAME_NOREPLACE: u32 = 1;
pub const RENAME_EXCHANGE: u32 = 2;
pub const RENAME_WHITEOUT: u32 = 4;

/// What [`Vfs::rename`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Renamed {
    Done,
    /// Every check passed, but `RENAME_EXCHANGE`/`RENAME_WHITEOUT` is not
    /// ported: the caller stops loudly.
    Unsupported,
}

/// `struct open_flags` after `build_open_flags`.
#[derive(Clone, Copy, Debug)]
pub struct OpenFlags {
    /// `op->open_flag` (without `O_CLOEXEC`).
    pub flags: u32,
    /// `op->mode` (`S_IFREG | perms` when creating).
    pub mode: u32,
    /// `op->acc_mode`.
    pub acc_mode: u32,
    /// `LOOKUP_FOLLOW` for the final component.
    pub follow: bool,
    /// `LOOKUP_DIRECTORY`.
    pub directory: bool,
    /// The descriptor gets `FD_CLOEXEC` (`how->flags & O_CLOEXEC`).
    pub cloexec: bool,
}

const O_PATH_FLAGS: u32 = O_DIRECTORY | O_NOFOLLOW | O_PATH | O_CLOEXEC;

fn will_create(flags: u32) -> bool {
    flags & (O_CREAT | __O_TMPFILE) != 0
}

/// `build_open_how` + `build_open_flags` for `open`/`openat`: unknown flag bits
/// are dropped, the mode only counts when creating.
///
/// # Errors
/// `EINVAL` for `O_DIRECTORY | O_CREAT`, `O_TMPFILE` without `O_DIRECTORY` or
/// write access, and `O_PATH` with flags it does not allow (cannot happen after
/// the mask).
pub fn build_open_flags(raw_flags: u32, mode: u32) -> KResult<OpenFlags> {
    // build_open_how
    let mut flags = raw_flags & VALID_OPEN_FLAGS;
    let mut mode = mode & S_IALLUGO;
    if flags & O_PATH != 0 {
        flags &= O_PATH_FLAGS;
    }
    if !will_create(flags) {
        mode = 0;
    }
    // build_open_flags
    let cloexec = flags & O_CLOEXEC != 0;
    let mut acc_mode = [
        MAY_READ,
        MAY_WRITE,
        MAY_READ | MAY_WRITE,
        MAY_READ | MAY_WRITE,
    ][(flags & O_ACCMODE) as usize];
    flags &= !O_CLOEXEC;
    let op_mode = if will_create(flags) {
        mode | S_IFREG
    } else {
        0
    };
    if flags & (O_DIRECTORY | O_CREAT) == (O_DIRECTORY | O_CREAT) {
        return Err(Errno::EINVAL);
    }
    if flags & __O_TMPFILE != 0 {
        if flags & O_DIRECTORY == 0 {
            return Err(Errno::EINVAL);
        }
        if acc_mode & MAY_WRITE == 0 {
            return Err(Errno::EINVAL);
        }
    }
    if flags & O_PATH != 0 {
        if flags & !O_PATH_FLAGS != 0 {
            return Err(Errno::EINVAL);
        }
        acc_mode = 0;
    }
    if flags & super::__O_SYNC != 0 {
        flags |= O_DSYNC;
    }
    let open_flag = flags;
    if flags & O_TRUNC != 0 {
        acc_mode |= MAY_WRITE;
    }
    if flags & O_APPEND != 0 {
        acc_mode |= MAY_APPEND;
    }
    let mut lookup_flags = flags;
    if flags & O_CREAT != 0 && flags & O_EXCL != 0 {
        lookup_flags |= O_NOFOLLOW;
    }
    Ok(OpenFlags {
        flags: open_flag,
        mode: op_mode,
        acc_mode,
        follow: lookup_flags & O_NOFOLLOW == 0,
        directory: flags & O_DIRECTORY != 0,
        cloexec,
    })
}

/// What `chrdev_open` finds for a device number.
enum Chr {
    Driver(CharDev),
    /// Registered in Linux (or possibly registered: the number is not one the
    /// reference configuration provably lacks), no Rust driver yet. `stream`
    /// is `nonseekable_open`: a terminal clears the seek bits, other drivers
    /// keep them and `lseek` stops loudly.
    Unported {
        stream: bool,
    },
    /// `-ENXIO`: nothing is registered, or the open itself fails that way.
    Absent,
}

/// The character devices of the reference configuration that matter here
/// (`drivers/char/mem.c` `devlist`, `drivers/tty/tty_io.c`).
///
/// Only `0:*` (no driver can register major 0 through `cdev_add`) answers
/// `ENXIO` here (`/dev/tty` without a controlling terminal is the caller's
/// state: `syscall::tty::after_open`); every other number may belong to a driver of the reference
/// configuration (misc 10, input 13, fb 29, ...), so opening it succeeds and
/// each later operation stops the kernel loudly.
fn chrdev(rdev: u32) -> Chr {
    match (super::major(rdev), super::minor(rdev)) {
        (1, 3) => Chr::Driver(CharDev::Null),
        (1, 5) => Chr::Driver(CharDev::Zero),
        (1, 7) => Chr::Driver(CharDev::Full),
        (5, 1) => Chr::Driver(CharDev::Console),
        // `tty_open_current_tty` answers `ENXIO` without a controlling terminal:
        // the caller's state, checked after the open (`syscall::tty::after_open`).
        (5, 0) => Chr::Driver(CharDev::TtyAux),
        (4, 64) => Chr::Driver(CharDev::TtyS0),
        (0, _) => Chr::Absent,
        // ptmx, the vt and the other serial ttys and the unix98 pty slaves: tty_open.
        (5, 2) | (4 | 136..=143, _) => Chr::Unported { stream: true },
        _ => Chr::Unported { stream: false },
    }
}

impl Vfs {
    /// `fput`: drop one reference; the last one releases the inode or pipe end.
    pub fn fput(&mut self, id: FileId) {
        let Some(file) = self.files.put(id) else {
            return;
        };
        if matches!(file.kind, FileKind::Char(dev) if dev.is_tty()) {
            self.tty_touched = true;
        }
        if let FileKind::Pipe { pipe, writer } = file.kind {
            self.pipe_release(pipe, writer);
        } else {
            if let Some(inode) = file.inode {
                self.fs.iput(inode);
            }
            if let Some(entry) = file.dentry {
                self.fs.iput(entry.parent);
            }
        }
    }

    /// `copy_fs_struct`: a forked child's own `fs_struct` with the same root,
    /// working directory and umask; each directory gets a new reference
    /// (`get_fs_root`, `get_fs_pwd`).
    pub fn dup_fs(&mut self, fs: &FsStruct) -> FsStruct {
        self.fs.iget(fs.root);
        self.fs.iget(fs.pwd);
        *fs
    }

    /// `exit_fs` -> `free_fs_struct`: the task's references on its root and
    /// working directory are dropped.
    pub fn put_fs(&mut self, fs: &FsStruct) {
        self.fs.iput(fs.root);
        self.fs.iput(fs.pwd);
    }

    /// `dup_fd` (`copy_files`): the child's descriptor table, every open
    /// description gaining a reference (`get_file`). Pipe ends are counted per
    /// description, not per descriptor, so they do not change.
    ///
    /// # Errors
    /// `ENOMEM`; nothing changed.
    pub fn dup_fd(&mut self, fdt: &super::FdTable) -> KResult<super::FdTable> {
        let child = fdt.duplicate()?;
        for (_, file, _) in child.iter() {
            self.files.dup(file);
        }
        Ok(child)
    }

    /// `close_files` (`exit_files`): every descriptor is closed in ascending
    /// order and its description released.
    pub fn close_files(&mut self, fdt: &mut super::FdTable) {
        let fds = u32::try_from(fdt.max_fds()).unwrap_or(u32::MAX);
        for fd in 0..fds {
            if let Some(file) = fdt.close(fd) {
                self.fput(file);
            }
        }
    }

    /// The caller's `fs_struct` update (`set_fs_pwd`): pins the new directory
    /// before dropping the old one.
    pub fn set_pwd(&mut self, fs: &mut FsStruct, dir: InodeId) {
        self.fs.iget(dir);
        let old = core::mem::replace(&mut fs.pwd, dir);
        self.fs.iput(old);
    }

    /// Timekeeping is up: see [`Tmpfs::start_timekeeping`].
    pub fn start_timekeeping(&mut self, clock: fn() -> Timespec, now: Timespec) {
        self.fs.start_timekeeping(clock, now);
    }

    /// A new `fs_struct` rooted at `/` with the given umask, pinning the root.
    pub fn new_fs_struct(&mut self, umask: u32) -> FsStruct {
        let root = self.fs.root();
        self.fs.iget(root);
        self.fs.iget(root);
        FsStruct {
            root,
            pwd: root,
            umask,
        }
    }

    /// `kernel/-` environment of the initramfs unpacker and `console_on_rootfs`.
    #[must_use]
    pub fn kernel_env(&self) -> Env {
        let root = self.fs.root();
        Env {
            root,
            start: root,
            cred: Cred::root(),
            umask: 0o022,
            tgid: 0,
        }
    }

    // ---- lookup and attributes ----------------------------------------------

    /// `filename_lookup`.
    ///
    /// # Errors
    /// See [`path::lookup`].
    pub fn lookup(&self, env: &Env, path: &[u8], flags: u32) -> KResult<InodeId> {
        path::lookup(&self.fs, &self.files, env, path, flags)
    }

    /// `vfs_getattr` of an inode or node, with the mount it belongs to.
    #[must_use]
    pub fn getattr(&self, inode: InodeId) -> Kstat {
        let mut stat = self.fs.getattr(inode);
        stat.mnt_id = self.mnt_id_of(inode);
        stat
    }

    /// `vfs_getattr` of a file (`vfs_fstat`): pipes are described by their
    /// pipefs inode.
    #[must_use]
    pub fn kstat_file(&self, id: FileId) -> Kstat {
        let file = self.files.get(id);
        match (file.kind, file.inode) {
            (FileKind::Pipe { pipe, .. }, _) => {
                let p = self.pipe(pipe);
                Kstat {
                    dev: mkdev(0, 3),
                    ino: p.ino,
                    mode: S_IFIFO | 0o600,
                    nlink: 1,
                    uid: p.uid,
                    gid: p.gid,
                    rdev: 0,
                    size: 0,
                    blksize: super::PAGE_SIZE as u32,
                    blocks: 0,
                    atime: p.time,
                    mtime: p.time,
                    ctime: p.time,
                    btime: p.time,
                    attributes: 0,
                    attributes_mask: 0,
                    mnt_id: self.pipe_mnt_id(),
                }
            }
            (_, Some(inode)) => self.getattr(inode),
            _ => unreachable!("a file without an inode is a pipe"),
        }
    }

    // ---- permission helpers (fs/namei.c) -------------------------------------

    fn may_create(&self, env: &Env, dir: InodeId) -> KResult<()> {
        if self.fs.is_dead(dir) {
            return Err(Errno::ENOENT); // IS_DEADDIR
        }
        self.fs.permission(env, dir, MAY_WRITE | MAY_EXEC)
    }

    /// The `i_op->unlink`/`rmdir` a procfs directory lacks: `EPERM` after the
    /// permission and `may_delete` checks.
    fn no_proc_create(dir: InodeId) -> KResult<()> {
        if dir.is_proc() {
            Err(Errno::EPERM)
        } else {
            Ok(())
        }
    }

    /// `check_sticky`: whether the sticky bit lets the caller touch `victim`.
    fn sticky_ok(&self, env: &Env, dir: InodeId, victim: InodeId) -> bool {
        let (d, v) = (self.fs.node_attr(dir), self.fs.node_attr(victim));
        d.mode & S_ISVTX == 0
            || v.uid == env.cred.fsuid
            || d.uid == env.cred.fsuid
            || env.cred.fowner
    }

    /// `may_delete`.
    fn may_delete(&self, env: &Env, dir: InodeId, victim: InodeId, isdir: bool) -> KResult<()> {
        self.fs.permission(env, dir, MAY_WRITE | MAY_EXEC)?;
        if !self.sticky_ok(env, dir, victim)
            || crate::procfs::ProcNode::of(victim).is_some_and(crate::procfs::is_immutable)
        {
            return Err(Errno::EPERM);
        }
        let victim_is_dir = self.fs.is_dir(victim);
        if isdir {
            if !victim_is_dir {
                return Err(Errno::ENOTDIR);
            }
            if victim == env.root {
                return Err(Errno::EBUSY);
            }
        } else if victim_is_dir {
            return Err(Errno::EISDIR);
        }
        if self.fs.is_dead(dir) {
            return Err(Errno::ENOENT); // IS_DEADDIR
        }
        Ok(())
    }

    /// `filename_create`: the parent directory and the missing final name.
    fn prepare_create(
        &self,
        env: &Env,
        path: &[u8],
        want_dir: bool,
    ) -> KResult<(InodeId, Vec<u8>)> {
        let parent = path::parent_of(&self.fs, &self.files, env, path)?;
        if parent.kind != LastKind::Norm {
            return Err(Errno::EEXIST);
        }
        if self.fs.is_dead(parent.dir) {
            return Err(Errno::ENOENT); // lookup_one_qstr_excl: no dentry in a dead dir
        }
        if self
            .fs
            .lookup_child(env, parent.dir, &parent.name)?
            .is_some()
        {
            return Err(Errno::EEXIST); // LOOKUP_EXCL
        }
        if parent.name.len() > NAME_MAX {
            return Err(Errno::ENAMETOOLONG); // simple_lookup
        }
        if parent.trailing_slash && !want_dir {
            return Err(Errno::ENOENT); // LOOKUP_CREATE dropped
        }
        // procfs has no negative dentry: the lookup of a missing name fails.
        if parent.dir.is_proc() {
            return Err(Errno::ENOENT);
        }
        // `err2 = mnt_want_write()` is reported last, after the lookup errors.
        self.fs.want_write(parent.dir)?;
        Ok((parent.dir, parent.name))
    }

    /// `vfs_prepare_mode`: strip the umask and keep only `perms` plus the type.
    fn prepare_mode(env: &Env, mode: u32, mask_perms: u32, kind: u32) -> u32 {
        (mode & !env.umask) & ((mask_perms & !S_IFMT) | (kind & S_IFMT))
    }

    // ---- creation ------------------------------------------------------------

    /// `mknodat` after the pathname was read: `may_mknod`, `filename_create`,
    /// then `vfs_create` or `vfs_mknod`.
    ///
    /// # Errors
    /// `EPERM` (directory type or no `CAP_MKNOD`), `EINVAL` (unknown type),
    /// `EEXIST`, `ENOENT`, `EACCES`, `ENOSPC`, `ENOMEM` and path errors.
    pub fn mknod(&mut self, env: &Env, path: &[u8], mode: u32, dev: u32) -> KResult<InodeId> {
        match mode & S_IFMT {
            0 | S_IFREG | S_IFCHR | S_IFBLK | S_IFIFO | S_IFSOCK => {}
            S_IFDIR => return Err(Errno::EPERM),
            _ => return Err(Errno::EINVAL),
        }
        let (dir, name) = self.prepare_create(env, path, false)?;
        self.may_create(env, dir)?;
        match mode & S_IFMT {
            0 | S_IFREG => {
                let mode = Self::prepare_mode(env, mode, S_IALLUGO, S_IFREG) | S_IFREG;
                self.fs.mknod(dir, &name, mode, 0, &env.cred)
            }
            S_IFCHR | S_IFBLK => {
                if !env.cred.mknod {
                    return Err(Errno::EPERM);
                }
                let mode = Self::prepare_mode(env, mode, mode, mode);
                self.fs
                    .mknod(dir, &name, mode, new_decode_dev(dev), &env.cred)
            }
            _ => {
                let mode = Self::prepare_mode(env, mode, mode, mode);
                self.fs.mknod(dir, &name, mode, 0, &env.cred)
            }
        }
    }

    /// `mkdirat` after the pathname was read.
    ///
    /// # Errors
    /// `EEXIST`, `ENOENT`, `EACCES`, `ENOSPC`, `ENOMEM` and path errors.
    pub fn mkdir(&mut self, env: &Env, path: &[u8], mode: u32) -> KResult<InodeId> {
        let (dir, name) = self.prepare_create(env, path, true)?;
        self.may_create(env, dir)?;
        let mode = Self::prepare_mode(env, mode, S_IRWXUGO | S_ISVTX, 0);
        self.fs.mknod(dir, &name, mode | S_IFDIR, 0, &env.cred)
    }

    /// `symlinkat`/`init_symlink`: `target` is stored verbatim.
    ///
    /// # Errors
    /// As [`Vfs::mkdir`]; `ENAMETOOLONG` for a target past a page.
    pub fn symlink(&mut self, env: &Env, target: &[u8], path: &[u8]) -> KResult<InodeId> {
        let (dir, name) = self.prepare_create(env, path, false)?;
        self.may_create(env, dir)?;
        self.fs.symlink(dir, &name, target, &env.cred)
    }

    /// `linkat` with `old` resolved by `old_flags`, as `do_linkat`/`init_link`.
    ///
    /// # Errors
    /// `ENOENT` (also for an unlinked source), `EEXIST`, `EPERM` (directory),
    /// `EACCES`, `ENOSPC`, `ENOMEM` and path errors.
    pub fn link(&mut self, env: &Env, old: &[u8], old_flags: u32, new: &[u8]) -> KResult<()> {
        self.link_at(env, old, old_flags, env, new)
    }

    /// `do_linkat` after the names were read: `old` is resolved in `old_env`
    /// by `old_flags`, `new` is created in `new_env`'s view (`filename_lookup`,
    /// then `filename_create`, then `vfs_link`).
    ///
    /// # Errors
    /// As [`Vfs::link`].
    pub fn link_at(
        &mut self,
        old_env: &Env,
        old: &[u8],
        old_flags: u32,
        new_env: &Env,
        new: &[u8],
    ) -> KResult<()> {
        let source = self.lookup(old_env, old, old_flags)?;
        let (dir, name) = self.prepare_create(new_env, new, false)?;
        // do_linkat: `old_path.mnt != new_path.mnt` is `EXDEV`, before `vfs_link`.
        if self.fs.sb_of(source) != self.fs.sb_of(dir) {
            return Err(Errno::EXDEV);
        }
        // vfs_link: may_create; IS_APPEND/IMMUTABLE; a directory (`!dir->i_op->link` is
        // false, `S_ISDIR` is EPERM).
        self.may_create(new_env, dir)?;
        if self.fs.is_dir(source) {
            return Err(Errno::EPERM);
        }
        if self.fs.inode(source).nlink == 0 {
            return Err(Errno::ENOENT);
        }
        self.fs.link(source, dir, &name)
    }

    /// `common_perm`-free `do_renameat2` after the pathnames were read, for
    /// `flags` without `RENAME_EXCHANGE`/`RENAME_WHITEOUT` working yet.
    ///
    /// The order is Linux's: flag validity, the walks to both parents,
    /// `EBUSY`/`EEXIST` for `.`/`..`/`/` final components, the lookups of the
    /// source (`ENOENT`) and the target (`EEXIST` with `RENAME_NOREPLACE`),
    /// the trailing-slash `ENOTDIR`s, `EINVAL`/`ENOTEMPTY` for a source or
    /// target that is the common ancestor chain, then `vfs_rename`'s own checks.
    ///
    /// # Errors
    /// The `rename(2)` errors.
    pub fn rename(
        &mut self,
        old: KResult<(Env, Vec<u8>)>,
        new: KResult<(Env, Vec<u8>)>,
        flags: u32,
    ) -> KResult<Renamed> {
        if flags & !(RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT) != 0 {
            return Err(Errno::EINVAL);
        }
        if flags & (RENAME_NOREPLACE | RENAME_WHITEOUT) != 0 && flags & RENAME_EXCHANGE != 0 {
            return Err(Errno::EINVAL);
        }
        let exchange = flags & RENAME_EXCHANGE != 0;
        // `filename_parentat` for the old name, then for the new one: an error
        // of resolving the second (a bad directory descriptor, a name that
        // could not be read) is only seen after the first walk succeeded.
        let (old_env, old) = old?;
        let from = path::parent_of(&self.fs, &self.files, &old_env, &old)?;
        let (new_env, new) = new?;
        let to = path::parent_of(&self.fs, &self.files, &new_env, &new)?;
        let (old_env, new_env) = (&old_env, &new_env);
        // do_renameat2: `old_path.mnt != new_path.mnt` is `EXDEV`, before the type checks.
        if self.fs.sb_of(from.dir) != self.fs.sb_of(to.dir) {
            return Err(Errno::EXDEV);
        }
        if from.kind != LastKind::Norm {
            return Err(Errno::EBUSY);
        }
        if to.kind != LastKind::Norm {
            return Err(if flags & RENAME_NOREPLACE != 0 {
                Errno::EEXIST
            } else {
                Errno::EBUSY
            });
        }
        // `mnt_want_write(old_path.mnt)` follows the type checks, before any lookup.
        self.fs.want_write(from.dir)?;
        // lock_rename: the child of one parent that is an ancestor of the other.
        let trap = if from.dir == to.dir {
            None
        } else {
            self.d_ancestor(from.dir, to.dir)
                .or_else(|| self.d_ancestor(to.dir, from.dir))
        };
        // lookup_one_qstr_excl for the source (must exist) ...
        let source = self
            .rename_lookup(old_env, from.dir, &from.name, false, false)?
            .ok_or(Errno::ENOENT)?;
        // ... and for the target (LOOKUP_CREATE unless exchanging; LOOKUP_EXCL for NOREPLACE).
        let target = self.rename_lookup(
            new_env,
            to.dir,
            &to.name,
            !exchange,
            flags & RENAME_NOREPLACE != 0,
        )?;
        if exchange && !target.is_some_and(|t| self.fs.is_dir(t)) && to.trailing_slash {
            return Err(Errno::ENOTDIR);
        }
        let is_dir = self.fs.is_dir(source);
        if !is_dir && (from.trailing_slash || (!exchange && to.trailing_slash)) {
            return Err(Errno::ENOTDIR);
        }
        if trap == Some(source) {
            return Err(Errno::EINVAL);
        }
        if target.is_some() && trap == target {
            return Err(if exchange {
                Errno::EINVAL
            } else {
                Errno::ENOTEMPTY
            });
        }
        // vfs_rename
        if target == Some(source) {
            return Ok(Renamed::Done);
        }
        self.may_delete(old_env, from.dir, source, is_dir)?;
        match target {
            None => self.may_create(new_env, to.dir)?,
            Some(t) => {
                let t_is_dir = self.fs.is_dir(t);
                self.may_delete(new_env, to.dir, t, if exchange { t_is_dir } else { is_dir })?;
            }
        }
        Self::no_proc_create(from.dir)?; // no `i_op->rename`
        if to.dir != from.dir {
            if is_dir {
                self.fs.permission(old_env, source, MAY_WRITE)?;
            }
            if let Some(t) = target
                && exchange
                && self.fs.is_dir(t)
            {
                self.fs.permission(old_env, t, MAY_WRITE)?;
            }
        }
        // vfs_rename: `is_local_mountpoint` of either dentry is `EBUSY`.
        if self.fs.ns.is_mountpoint(source) || target.is_some_and(|t| self.fs.ns.is_mountpoint(t)) {
            return Err(Errno::EBUSY);
        }
        if flags & (RENAME_EXCHANGE | RENAME_WHITEOUT) != 0 {
            return Ok(Renamed::Unsupported);
        }
        self.fs.rename(from.dir, &from.name, to.dir, &to.name)?;
        Ok(Renamed::Done)
    }

    /// `d_ancestor(p1, p2)`: the child of `p1` on the way from `p2` to the
    /// root (`p2` itself when it is a child of `p1`), or `None`.
    fn d_ancestor(&self, p1: InodeId, p2: InodeId) -> Option<InodeId> {
        // Both are in one superblock (`EXDEV` otherwise), whose root is its own parent.
        let mut p = p2;
        loop {
            let parent = self.fs.parent_dir(p);
            if parent == p1 {
                return Some(p);
            }
            if parent == p {
                return None;
            }
            p = parent;
        }
    }

    /// `lookup_one_qstr_excl` for `rename`: the entry, or `None` for a missing
    /// one that `create` allows. A dead directory has no dentries (`ENOENT`),
    /// a name beyond `NAME_MAX` fails in `simple_lookup`.
    fn rename_lookup(
        &self,
        env: &Env,
        dir: InodeId,
        name: &[u8],
        create: bool,
        excl: bool,
    ) -> KResult<Option<InodeId>> {
        match self.fs.lookup_child(env, dir, name)? {
            Some(_) if excl => Err(Errno::EEXIST),
            Some(found) => Ok(Some(found)),
            // procfs has no negative dentry: the lookup of a missing name fails.
            None if dir.is_proc() => Err(Errno::ENOENT),
            None if self.fs.is_dead(dir) => Err(Errno::ENOENT),
            None if name.len() > NAME_MAX => Err(Errno::ENAMETOOLONG),
            None if create => Ok(None),
            None => Err(Errno::ENOENT),
        }
    }

    // ---- removal -------------------------------------------------------------

    /// `unlinkat(0)`: remove a non-directory name.
    ///
    /// # Errors
    /// `EISDIR`, `ENOTDIR` (trailing slash on a file), `ENOENT`, `EACCES`,
    /// `EPERM` (sticky) and path errors.
    pub fn unlink(&mut self, env: &Env, path: &[u8]) -> KResult<()> {
        let parent = path::parent_of(&self.fs, &self.files, env, path)?;
        if parent.kind != LastKind::Norm {
            return Err(Errno::EISDIR);
        }
        // do_unlinkat: `mnt_want_write` precedes the lookup of the name.
        self.fs.want_write(parent.dir)?;
        let Some(victim) = self.fs.lookup_child(env, parent.dir, &parent.name)? else {
            return Err(if parent.name.len() > NAME_MAX {
                Errno::ENAMETOOLONG
            } else {
                Errno::ENOENT
            });
        };
        if parent.trailing_slash {
            return Err(if self.fs.is_dir(victim) {
                Errno::EISDIR
            } else {
                Errno::ENOTDIR
            });
        }
        self.may_delete(env, parent.dir, victim, false)?;
        Self::no_proc_create(parent.dir)?; // no `i_op->unlink`
        self.fs.unlink(parent.dir, &parent.name, false)
    }

    /// `rmdir` (`do_rmdir`).
    ///
    /// # Errors
    /// `EINVAL` (`.`), `ENOTEMPTY` (`..` or a non-empty directory), `EBUSY`
    /// (the root), `ENOTDIR`, `ENOENT`, `EACCES`, `EPERM` and path errors.
    pub fn rmdir(&mut self, env: &Env, path: &[u8]) -> KResult<()> {
        let parent = path::parent_of(&self.fs, &self.files, env, path)?;
        match parent.kind {
            LastKind::DotDot => return Err(Errno::ENOTEMPTY),
            LastKind::Dot => return Err(Errno::EINVAL),
            LastKind::Root => return Err(Errno::EBUSY),
            LastKind::Norm => {}
        }
        self.fs.want_write(parent.dir)?;
        let Some(victim) = self.fs.lookup_child(env, parent.dir, &parent.name)? else {
            return Err(if parent.name.len() > NAME_MAX {
                Errno::ENAMETOOLONG
            } else {
                Errno::ENOENT
            });
        };
        self.may_delete(env, parent.dir, victim, true)?;
        Self::no_proc_create(parent.dir)?; // no `i_op->rmdir`
        // vfs_rmdir: `is_local_mountpoint(dentry)` is `EBUSY`.
        if self.fs.ns.is_mountpoint(victim) {
            return Err(Errno::EBUSY);
        }
        self.fs.unlink(parent.dir, &parent.name, true)
    }

    // ---- attribute changes ---------------------------------------------------

    /// `chmod_common` -> `notify_change(ATTR_MODE | ATTR_CTIME)`.
    ///
    /// # Errors
    /// `EOPNOTSUPP` for a symbolic link (`notify_change`), `EPERM` unless the
    /// caller owns the file or has `CAP_FOWNER` (`setattr_prepare`).
    pub fn chmod(&mut self, env: &Env, inode: InodeId, mode: u32) -> KResult<()> {
        // do_fchmodat / fchmod: `mnt_want_write` precedes `chmod_common`.
        self.fs.want_write(inode)?;
        if self.fs.inode(inode).is_symlink() {
            return Err(Errno::EOPNOTSUPP);
        }
        if self.fs.inode(inode).uid != env.cred.fsuid && !env.cred.fowner {
            return Err(Errno::EPERM);
        }
        self.fs.set_mode(inode, mode, &env.cred);
        Ok(())
    }

    /// `chown_common` (`u32::MAX` leaves an id unchanged) ->
    /// `notify_change(ATTR_CTIME | ATTR_UID | ATTR_GID | ATTR_KILL_SUID |
    /// ATTR_KILL_SGID)`: a non-directory loses `S_ISUID` and, by
    /// `setattr_should_drop_sgid`, `S_ISGID`.
    ///
    /// # Errors
    /// `EPERM` (`chown_ok`, `chgrp_ok`): the owner may only "change" the owner to
    /// itself and the group to one it belongs to; anything else needs `CAP_CHOWN`. Also
    /// `EPERM` when a set-id bit would be dropped and the caller neither owns the file nor
    /// has `CAP_FOWNER` (the `ATTR_MODE` branch of `setattr_prepare`).
    pub fn chown(&mut self, env: &Env, inode: InodeId, uid: u32, gid: u32) -> KResult<()> {
        // do_fchownat / fchown: `mnt_want_write` precedes `chown_common`.
        self.fs.want_write(inode)?;
        let cur = self.fs.inode(inode);
        let owner = cur.uid == env.cred.fsuid;
        if uid != u32::MAX && !(owner && uid == cur.uid || env.cred.chown) {
            return Err(Errno::EPERM);
        }
        // `vfsgid_in_group_p`: the file system group id (no supplementary groups yet).
        if gid != u32::MAX
            && !(owner && (gid == cur.gid || gid == env.cred.fsgid) || env.cred.chown)
        {
            return Err(Errno::EPERM);
        }
        // `notify_change` turns ATTR_KILL_SUID/SGID into ATTR_MODE when a set-id bit would go
        // (fs/attr.c:495-513, judged as `set_owner` does), and `setattr_prepare` then wants
        // `inode_owner_or_capable` for the mode change, whatever the ids.
        let mode = cur.mode;
        let drops_set_id = mode & S_IFMT != S_IFDIR
            && (mode & S_ISUID != 0
                || mode & S_ISGID != 0
                    && (mode & S_IXGRP != 0 || !(env.cred.fsgid == cur.gid || env.cred.fsetid)));
        if drops_set_id && !(owner || env.cred.fowner) {
            return Err(Errno::EPERM);
        }
        self.fs.set_owner(inode, uid, gid, &env.cred);
        Ok(())
    }

    /// `vfs_utimes` with explicit times.
    pub fn utimes(&mut self, inode: InodeId, atime: Timespec, mtime: Timespec) {
        self.fs.set_times(inode, atime, mtime);
    }

    /// `vfs_utimes` for `utimensat`/`futimens`/`utimes`/`utime`: `times` are the two
    /// `(tv_sec, tv_nsec)` pairs (`None` for the current time). `UTIME_OMIT`
    /// leaves a time alone, `UTIME_NOW` takes the current time.
    ///
    /// # Errors
    /// `EINVAL` (`tv_nsec` out of range), `EPERM` (explicit times by a caller that
    /// neither owns the file nor has `CAP_FOWNER`; the same when only one of the
    /// two is `UTIME_NOW`), `EACCES` (current time by a caller without ownership
    /// or write permission).
    pub fn utimens(
        &mut self,
        env: &Env,
        inode: InodeId,
        times: Option<[(i64, i64); 2]>,
    ) -> KResult<()> {
        let valid = |nsec: i64| {
            nsec == UTIME_OMIT || nsec == UTIME_NOW || (0..=999_999_999).contains(&nsec)
        };
        let mut times = times;
        if let Some([a, m]) = times {
            if !valid(a.1) || !valid(m.1) {
                return Err(Errno::EINVAL);
            }
            if a.1 == UTIME_NOW && m.1 == UTIME_NOW {
                times = None;
            }
        }
        // vfs_utimes: `mnt_want_write` follows the validity checks.
        self.fs.want_write(inode)?;
        let owner_or_capable = {
            let node = self.fs.inode(inode);
            node.uid == env.cred.fsuid || env.cred.fowner
        };
        match times {
            // ATTR_TOUCH (`may_setattr`): the owner, else write permission.
            None => {
                if !owner_or_capable {
                    self.fs.permission(env, inode, MAY_WRITE)?;
                }
                let now = self.fs.now();
                self.fs.set_times(inode, now, now);
            }
            // ATTR_TIMES_SET (`setattr_prepare`): the owner or CAP_FOWNER.
            Some([atime, mtime]) => {
                if !owner_or_capable {
                    return Err(Errno::EPERM);
                }
                let now = self.fs.now();
                let at = |(sec, nsec): (i64, i64), current: Timespec| match nsec {
                    UTIME_OMIT => current,
                    UTIME_NOW => now,
                    _ => Timespec {
                        sec,
                        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                        nsec: nsec as u32,
                    },
                };
                let node = self.fs.inode(inode);
                let (a, m) = (at(atime, node.atime), at(mtime, node.mtime));
                self.fs.set_times(inode, a, m);
            }
        }
        Ok(())
    }

    /// `vfs_truncate`.
    ///
    /// # Errors
    /// `EISDIR`, `EINVAL`, `EACCES`.
    pub fn truncate(&mut self, env: &Env, inode: InodeId, length: u64) -> KResult<()> {
        self.truncate_check(env, inode)?;
        if inode.is_proc() {
            return Ok(()); // `proc_setattr` ignores ATTR_SIZE
        }
        self.do_truncate(&env.cred, inode, length);
        Ok(())
    }

    /// The checks of `vfs_truncate` before `do_truncate`: the type and the
    /// write permission.
    ///
    /// # Errors
    /// `EISDIR`, `EINVAL`, `EACCES`.
    pub fn truncate_check(&self, env: &Env, inode: InodeId) -> KResult<()> {
        if self.fs.is_dir(inode) {
            return Err(Errno::EISDIR);
        }
        if self.fs.file_type(inode) != S_IFREG {
            return Err(Errno::EINVAL);
        }
        // vfs_truncate: `mnt_want_write`, then `inode_permission`.
        self.fs.want_write(inode)?;
        self.fs.permission(env, inode, MAY_WRITE)
    }

    /// `do_truncate` after `inode_newsize_ok`: `dentry_needs_remove_privs`
    /// adds `ATTR_KILL_SUID`/`SGID` (forced), then `shmem_setattr` sets the
    /// size and both times.
    pub fn do_truncate(&mut self, cred: &Cred, inode: InodeId, length: u64) {
        self.remove_privs(cred, inode);
        // shmem_setattr unmaps the mappings (private copies included) only
        // when the size shrinks (`newsize <= oldsize`); growing changes no page
        // a mapping can hold.
        if length < self.fs.inode(inode).size {
            self.note_modified(inode);
        }
        self.fs.set_size(inode, length);
    }

    /// `file_remove_privs` / the `ATTR_KILL_*` part of `do_truncate`
    /// (`setattr_should_drop_suidgid`): a write or truncate by a caller without
    /// `CAP_FSETID` clears `S_ISUID`, and `S_ISGID` when the group-execute bit
    /// is set or the caller is not in the file's group (no supplementary
    /// groups exist yet).
    pub fn remove_privs(&mut self, cred: &Cred, inode: InodeId) {
        let node = self.fs.inode_mut(inode);
        if cred.fsetid || !node.is_reg() {
            return;
        }
        node.mode &= !S_ISUID;
        if node.mode & S_ISGID != 0 && (node.mode & S_IXGRP != 0 || cred.fsgid != node.gid) {
            node.mode &= !S_ISGID;
        }
    }

    /// `do_faccessat` after the path was resolved.
    ///
    /// # Errors
    /// `EACCES`.
    pub fn access_check(&self, env: &Env, inode: InodeId, mode: u32) -> KResult<()> {
        self.fs.permission(env, inode, mode)
    }

    // ---- getcwd --------------------------------------------------------------

    /// The path of `dir` below `root` (`prepend_path`), without the NUL.
    ///
    /// # Errors
    /// `ENOENT` for a removed directory, `ENOMEM`.
    pub fn dir_path(&self, root: InodeId, dir: InodeId) -> KResult<Vec<u8>> {
        // d_unlinked: a removed directory (or one below one) has no path.
        let mut cur = dir;
        while !cur.is_proc() && cur != self.fs.root() && !self.fs.is_mount_root(cur) {
            let parent = self.fs.parent_dir(cur);
            if self.fs.name_of(parent, cur).is_none() {
                return Err(Errno::ENOENT);
            }
            cur = parent;
        }
        let (mut path, reachable) = self.fs.d_path(root, dir)?;
        if !reachable {
            // `prepend_unreachable`: the path is not below the root.
            let mut out = try_copy(b"(unreachable)")?;
            out.try_reserve(path.len()).map_err(|_| Errno::ENOMEM)?;
            for byte in path.drain(..) {
                let _ = out.push_within_capacity(byte);
            }
            return Ok(out);
        }
        Ok(path)
    }

    /// `d_path` of an open file below `root`: the name it was opened by when
    /// it has one, else the path of its inode.
    ///
    /// # Errors
    /// `ENOMEM`.
    pub fn file_path(&self, root: InodeId, file: &File) -> KResult<(Vec<u8>, bool)> {
        let Some(inode) = file.inode else {
            return Ok((Vec::new(), false));
        };
        match &file.dentry {
            Some(entry) if !self.fs.is_dir(inode) => {
                let (mut path, reachable) = self.fs.d_path(root, entry.parent)?;
                if path.last() != Some(&b'/') {
                    path.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
                    let _ = path.push_within_capacity(b'/');
                }
                path.try_reserve(entry.name.len())
                    .map_err(|_| Errno::ENOMEM)?;
                for &byte in &entry.name {
                    let _ = path.push_within_capacity(byte);
                }
                Ok((path, reachable))
            }
            _ => self.fs.d_path(root, inode),
        }
    }

    /// `d_unlinked` of an open file's dentry.
    #[must_use]
    pub fn file_deleted(&self, file: &File) -> bool {
        let Some(inode) = file.inode else {
            return false;
        };
        if inode.is_proc() {
            return false;
        }
        match &file.dentry {
            Some(entry) if !self.fs.is_dir(inode) => {
                self.fs.is_dead(entry.parent)
                    || self.fs.tmp().lookup(entry.parent, &entry.name) != Some(inode)
            }
            _ => self.fs.is_dead(inode),
        }
    }

    /// The mount id of the internal pipefs mount (`pipe_mnt`).
    #[must_use]
    pub const fn pipe_mnt_id(&self) -> u32 {
        PIPEFS_MNT_ID
    }

    // ---- open ----------------------------------------------------------------

    /// `do_filp_open`: resolve (and create) `path` and return the open file.
    ///
    /// # Errors
    /// The `open(2)` errors, in Linux's order.
    pub fn open(&mut self, env: &Env, path: &[u8], op: &OpenFlags) -> KResult<FileId> {
        if op.flags & __O_TMPFILE != 0 {
            return self.open_tmpfile(env, path, op);
        }
        if op.flags & O_PATH != 0 {
            let flags = if op.follow { LOOKUP_FOLLOW } else { 0 }
                | if op.directory { LOOKUP_DIRECTORY } else { 0 };
            let found = path::lookup_dentry(&self.fs, &self.files, env, path, flags)?;
            return self.make_file(
                found.inode,
                op.flags,
                FileKind::Path,
                FMODE_PATH,
                found.dentry,
            );
        }
        let (inode, created, dentry) = self.open_last_lookups(env, path, op)?;
        self.do_open(env, inode, created, op, dentry)
    }

    /// `path_openat`'s walk and `open_last_lookups`/`lookup_open`: the inode
    /// to open and whether this call created it. A created inode is not yet
    /// pinned by a file.
    fn open_last_lookups(
        &mut self,
        env: &Env,
        path: &[u8],
        op: &OpenFlags,
    ) -> KResult<(InodeId, bool, Option<Dentry>)> {
        enum Resolved {
            Found(InodeId, Option<Dentry>),
            Missing(InodeId, Vec<u8>),
        }
        let create = op.flags & O_CREAT != 0;
        let mut directory = op.directory;
        let resolved = {
            let mut walk = Walk::new(&self.fs, &self.files, env, path, op.follow)?;
            let mut remaining = path;
            loop {
                let last = walk.link_path_walk(remaining)?;
                if last.kind != LastKind::Norm {
                    walk.walk_component(&last, WALK_TRAILING)?; // handle_dots
                    break Resolved::Found(walk.cur, None);
                }
                if create && last.trailing_slash {
                    return Err(Errno::EISDIR);
                }
                if last.trailing_slash {
                    walk.follow = true;
                    directory = true;
                }
                if create && walk.child(&last)?.is_none() {
                    if walk.fs.is_dead(walk.cur) {
                        return Err(Errno::ENOENT); // lookup_open: IS_DEADDIR
                    }
                    if last.name.len() > NAME_MAX {
                        return Err(Errno::ENAMETOOLONG);
                    }
                    break Resolved::Missing(walk.cur, try_copy(last.name)?);
                }
                let dir = walk.cur;
                if let Some(body) = walk.walk_component(&last, WALK_TRAILING)? {
                    remaining = body;
                } else {
                    let dentry = if walk.cur.is_proc() && dir.is_proc() || !walk.cur.is_proc() {
                        Some(Dentry {
                            parent: dir,
                            name: try_copy(last.name)?,
                        })
                    } else {
                        None
                    };
                    break Resolved::Found(walk.cur, dentry);
                }
            }
        };
        let (dir, name) = match resolved {
            Resolved::Found(found, dentry) => {
                return self
                    .check_found(found, directory, op)
                    .map(|inode| (inode, false, dentry));
            }
            Resolved::Missing(dir, name) => (dir, name),
        };
        // lookup_open: procfs's lookup of a missing name is `-ENOENT`; else
        // `got_write` false is `create_error = -EROFS`, or `may_o_create`.
        if dir.is_proc() {
            return Err(Errno::ENOENT);
        }
        self.fs.want_write(dir)?;
        self.may_create(env, dir)?;
        let mode = Self::prepare_mode(env, op.mode, S_IALLUGO, S_IFREG) | S_IFREG;
        let inode = self.fs.mknod(dir, &name, mode, 0, &env.cred)?;
        Ok((inode, true, Some(Dentry { parent: dir, name })))
    }

    /// The `do_open` checks that precede `may_open` for an existing inode.
    fn check_found(&self, inode: InodeId, directory: bool, op: &OpenFlags) -> KResult<InodeId> {
        let is_dir = self.fs.is_dir(inode);
        if op.flags & O_CREAT != 0 {
            if op.flags & O_EXCL != 0 {
                return Err(Errno::EEXIST);
            }
            if is_dir {
                return Err(Errno::EISDIR);
            }
        }
        if directory && !is_dir {
            return Err(Errno::ENOTDIR);
        }
        Ok(inode)
    }

    /// `do_open` from `may_open` on, then `vfs_open` and the truncation.
    fn do_open(
        &mut self,
        env: &Env,
        inode: InodeId,
        created: bool,
        op: &OpenFlags,
        dentry: Option<Dentry>,
    ) -> KResult<FileId> {
        let mut open_flag = op.flags;
        let mut acc_mode = op.acc_mode;
        let mut do_truncate = false;
        if created {
            open_flag &= !O_TRUNC;
            acc_mode = 0;
        } else if self.fs.file_type(inode) == S_IFREG && open_flag & O_TRUNC != 0 {
            // `mnt_want_write` before `may_open`.
            self.fs.want_write(inode)?;
            do_truncate = true;
        }
        self.may_open(env, inode, acc_mode, open_flag)?;
        let file = self.vfs_open(env, inode, open_flag, dentry)?;
        if do_truncate && !inode.is_proc() {
            self.do_truncate(&env.cred, inode, 0); // handle_truncate (0 is always within RLIMIT_FSIZE)
        }
        Ok(file)
    }

    /// `may_open`.
    fn may_open(&self, env: &Env, inode: InodeId, acc_mode: u32, flag: u32) -> KResult<()> {
        let node = self.fs.node_attr(inode);
        match node.mode & S_IFMT {
            S_IFLNK => return Err(Errno::ELOOP),
            S_IFDIR => {
                if acc_mode & MAY_WRITE != 0 {
                    return Err(Errno::EISDIR);
                }
                if acc_mode & MAY_EXEC != 0 {
                    return Err(Errno::EACCES);
                }
            }
            S_IFBLK | S_IFCHR | S_IFIFO | S_IFSOCK if acc_mode & MAY_EXEC != 0 => {
                return Err(Errno::EACCES);
            }
            // may_open_dev: a nodev mount does not open device nodes.
            S_IFBLK | S_IFCHR
                if self
                    .fs
                    .mount_of(inode)
                    .is_some_and(|m| m.flags & super::mount::MNT_NODEV != 0) =>
            {
                return Err(Errno::EACCES);
            }
            _ => {}
        }
        self.fs.permission(env, inode, acc_mode)?;
        // O_NOATIME can only be set by the owner or superuser.
        if flag & O_NOATIME != 0 && node.uid != env.cred.fsuid && !env.cred.fowner {
            return Err(Errno::EPERM);
        }
        Ok(())
    }

    /// `vfs_open`/`do_dentry_open` for a resolved inode.
    fn vfs_open(
        &mut self,
        env: &Env,
        inode: InodeId,
        open_flag: u32,
        dentry: Option<Dentry>,
    ) -> KResult<FileId> {
        let mode = self.fs.node_attr(inode).mode;
        let rdev = if inode.is_proc() {
            0
        } else {
            self.fs.inode(inode).rdev
        };
        let mut fmode = (open_flag & O_ACCMODE).wrapping_add(1) & O_ACCMODE;
        let mut unported_stream = false;
        if let Some(node) = crate::procfs::ProcNode::of(inode) {
            // proc_reg_open / the `open` of the entry.
            crate::procfs::open_check(&self.fs.ns.proc, env, node)?;
        }
        let kind = match mode & S_IFMT {
            S_IFREG if inode.is_proc() => FileKind::Proc,
            S_IFREG => FileKind::Regular,
            S_IFDIR => FileKind::Directory,
            S_IFCHR => match chrdev(rdev) {
                Chr::Driver(dev) => FileKind::Char(dev),
                Chr::Unported { stream } => {
                    unported_stream = stream;
                    FileKind::Unsupported
                }
                Chr::Absent => return Err(Errno::ENXIO),
            },
            // blkdev_get_no_open finds no device for major 0 and the reference
            // configuration registers others (loop, ram, ...): no block driver is
            // ported, so any other number stops loudly on use.
            S_IFBLK if super::major(rdev) == 0 => return Err(Errno::ENXIO),
            S_IFBLK => FileKind::Unsupported,
            // sock_no_open
            S_IFSOCK => return Err(Errno::ENXIO),
            // fifo_open: named pipes are not ported (`stream_open`: nonseekable).
            _ => {
                unported_stream = true;
                FileKind::Unsupported
            }
        };
        fmode |= FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE;
        match kind {
            // tty_open: nonseekable_open
            FileKind::Char(dev) if dev.is_tty() => {
                fmode &= !(FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE);
            }
            FileKind::Unsupported if unported_stream => {
                fmode &= !(FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE);
            }
            _ => {}
        }
        if fmode & FMODE_READ != 0 {
            fmode |= FMODE_CAN_READ;
        }
        // `f_op->write`: tmpfs files, and the procfs files with a writer.
        let writable = match crate::procfs::ProcNode::of(inode) {
            Some(node) => crate::procfs::has_write_op(node),
            None => kind != FileKind::Directory,
        };
        if fmode & FMODE_WRITE != 0 && writable {
            fmode |= FMODE_CAN_WRITE;
        }
        // do_dentry_open: `get_write_access` + `mnt_get_write_access` for a
        // regular file opened for writing on a read-only mount.
        if fmode & FMODE_WRITE != 0 && matches!(kind, FileKind::Regular | FileKind::Proc) {
            self.fs.want_write(inode)?;
        }
        // No inode here has `a_ops->direct_IO` (tmpfs has none, nor do the
        // device nodes): do_dentry_open rejects O_DIRECT.
        if open_flag & O_DIRECT != 0 {
            return Err(Errno::EINVAL);
        }
        let flags = open_flag & !(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC);
        self.make_file(inode, flags, kind, fmode, dentry)
    }

    fn make_file(
        &mut self,
        inode: InodeId,
        flags: u32,
        kind: FileKind,
        mode: u32,
        dentry: Option<Dentry>,
    ) -> KResult<FileId> {
        self.fs.iget(inode);
        // A dentry pins its parent.
        let parent = dentry.as_ref().map(|entry| entry.parent);
        if let Some(parent) = parent {
            self.fs.iget(parent);
        }
        let mut file = File::new(Some(inode), kind, flags, mode);
        file.dentry = dentry;
        file.poll_event = self.fs.ns.event;
        match self.files.alloc(file) {
            Ok(id) => {
                if matches!(kind, FileKind::Char(dev) if dev.is_tty()) {
                    self.tty_touched = true;
                }
                Ok(id)
            }
            Err(error) => {
                if let Some(parent) = parent {
                    self.fs.iput(parent);
                }
                self.fs.iput(inode);
                Err(error)
            }
        }
    }

    /// `do_tmpfile`: an unnamed regular file in directory `path`.
    fn open_tmpfile(&mut self, env: &Env, path: &[u8], op: &OpenFlags) -> KResult<FileId> {
        let dir = self.lookup(env, path, LOOKUP_FOLLOW | LOOKUP_DIRECTORY)?;
        self.fs.want_write(dir)?;
        self.may_create(env, dir)?;
        if dir.is_proc() {
            return Err(Errno::EOPNOTSUPP); // no `i_op->tmpfile`
        }
        let mode = Self::prepare_mode(env, op.mode, S_IALLUGO, S_IFREG) | S_IFREG;
        let sb = self.fs.inode(dir).sb;
        let inode = self.fs.mknod_unlinked(sb, mode, &env.cred)?;
        let flags = op.flags & !(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC);
        let file = self.vfs_open(env, inode, flags, None);
        // The file holds the only pin; an open failure frees the inode.
        if file.is_err() {
            self.fs.drop_unlinked(inode);
        }
        file
    }

    /// `ksys_chdir`/`ksys_fchdir` permission: search access on a directory.
    ///
    /// # Errors
    /// `ENOTDIR`, `EACCES`.
    pub fn chdir_check(&self, env: &Env, dir: InodeId) -> KResult<()> {
        if !self.fs.is_dir(dir) {
            return Err(Errno::ENOTDIR);
        }
        self.fs.permission(env, dir, MAY_EXEC)
    }

    /// Open `/dev/console` three times for init (`console_on_rootfs`): one
    /// `O_RDWR` file shared by descriptors 0, 1 and 2 of `fds`.
    ///
    /// # Errors
    /// The open error; the caller logs `Warning: unable to open an initial console.`
    pub fn console_on_rootfs(&mut self, fds: &mut super::FdTable) -> KResult<()> {
        let env = self.kernel_env();
        let op = build_open_flags(super::O_RDWR, 0)?;
        // filp_open from the kernel adds no O_LARGEFILE.
        let file = self.open(&env, b"/dev/console", &op)?;
        for _ in 0..3 {
            let fd = fds.alloc_fd(0, super::INR_OPEN_CUR, false)?;
            self.files.dup(file);
            fds.install(fd, file);
        }
        self.fput(file);
        Ok(())
    }

    // ---- the console tty's files ---------------------------------------------

    /// Whether a file on the console tty was opened or released since the last
    /// call (the tty's `count` must be recounted).
    pub fn take_tty_touch(&mut self) -> bool {
        core::mem::take(&mut self.tty_touched)
    }

    /// The open files on the console tty and how many of them are
    /// `/dev/console` ones (`cons_filp`).
    pub fn tty_files(&mut self) -> (u32, u32) {
        let (mut total, mut console) = (0, 0);
        for file in self.files.iter_mut() {
            if let FileKind::Char(dev) = file.kind
                && dev.is_tty()
            {
                total += 1;
                if dev == CharDev::Console {
                    console += 1;
                }
            }
        }
        (total, console)
    }

    /// `__tty_hangup`: every `tty_fops` file becomes a `hung_up_tty_fops` one;
    /// the `/dev/console` files keep working.
    pub fn tty_hangup_files(&mut self) {
        for file in self.files.iter_mut() {
            if matches!(file.kind, FileKind::Char(CharDev::TtyAux | CharDev::TtyS0)) {
                file.kind = FileKind::Char(CharDev::HungUp);
            }
        }
    }

    // ---- pipes ---------------------------------------------------------------

    pub(crate) fn pipe(&self, id: super::PipeId) -> &Pipe {
        self.pipes[id.0 as usize]
            .as_ref()
            .expect("stale pipe handle")
    }

    /// Mutable access to a pipe. Counts as a state change for the sleepers of
    /// the pipe ([`Vfs::take_pipe_events`]): data written or consumed, the
    /// capacity changed.
    ///
    /// # Panics
    /// On a stale handle (a kernel bug).
    pub fn pipe_mut(&mut self, id: super::PipeId) -> &mut Pipe {
        self.pipe_events = self.pipe_events.wrapping_add(1);
        self.pipes[id.0 as usize]
            .as_mut()
            .expect("stale pipe handle")
    }

    /// Whether any pipe changed since the last call: the owner of the
    /// scheduler then wakes the pipe sleepers (`wake_up_interruptible` on
    /// `rd_wait`/`wr_wait`, which the pure VFS cannot do), before it sleeps
    /// itself and when the system call ends. A pipe end released (`pipe_release`
    /// wakes both queues) is a change too.
    pub fn take_pipe_events(&mut self) -> bool {
        let changed = self.pipe_events != self.pipe_events_seen;
        self.pipe_events_seen = self.pipe_events;
        // A change of the mount table wakes the `poll` sleepers on `mounts`/`mountinfo`
        // (`touch_mnt_namespace`'s `wake_up_interruptible(&ns->poll)`), who share the key.
        self.fs.ns.take_event() || changed
    }

    /// Shared access for the syscall layer.
    #[must_use]
    pub fn pipe_ref(&self, id: super::PipeId) -> &Pipe {
        self.pipe(id)
    }

    /// `create_pipe_files`: `(read end, write end)`, not yet in a descriptor table.
    ///
    /// # Errors
    /// `ENOMEM`; `EINVAL` for flags `pipe2` does not take (checked by the caller).
    pub fn pipe_create(&mut self, flags: u32, cred: &Cred) -> KResult<(FileId, FileId)> {
        let now = self.fs.now();
        let pipe = Pipe::new(self.next_pipe_ino, cred.fsuid, cred.fsgid, now);
        self.next_pipe_ino += 1;
        let slot = if let Some(slot) = self.pipes.iter().position(Option::is_none) {
            self.pipes[slot] = Some(pipe);
            slot
        } else {
            self.pipes.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
            if self.pipes.push_within_capacity(Some(pipe)).is_err() {
                return Err(Errno::ENOMEM);
            }
            self.pipes.len() - 1
        };
        let id = super::PipeId(u32::try_from(slot).map_err(|_| Errno::ENOMEM)?);
        let status = flags & (super::O_NONBLOCK | O_DIRECT);
        let read = File::new(
            None,
            FileKind::Pipe {
                pipe: id,
                writer: false,
            },
            status | super::O_RDONLY,
            FMODE_READ | FMODE_CAN_READ,
        );
        let write = File::new(
            None,
            FileKind::Pipe {
                pipe: id,
                writer: true,
            },
            status | super::O_WRONLY,
            FMODE_WRITE | FMODE_CAN_WRITE,
        );
        let read = match self.files.alloc(read) {
            Ok(read) => read,
            Err(error) => {
                self.pipes[slot] = None;
                return Err(error);
            }
        };
        match self.files.alloc(write) {
            Ok(write) => Ok((read, write)),
            Err(error) => {
                // The read end owns its half of the pipe's counts.
                self.pipes[slot] = None;
                let _ = self.files.put(read);
                Err(error)
            }
        }
    }

    fn pipe_release(&mut self, id: super::PipeId, writer: bool) {
        let pipe = self.pipe_mut(id);
        if writer {
            pipe.writers -= 1;
        } else {
            pipe.readers -= 1;
        }
        if pipe.readers == 0 && pipe.writers == 0 {
            self.pipes[id.0 as usize] = None;
        }
    }
}

/// `AT_EMPTY_PATH`/`AT_SYMLINK_NOFOLLOW` as a lookup flag set for the stat family.
#[must_use]
pub fn stat_lookup_flags(flags: u32) -> u32 {
    if flags & AT_SYMLINK_NOFOLLOW == 0 {
        LOOKUP_FOLLOW
    } else {
        0
    }
}

impl Vfs {
    /// `do_close_on_exec`: close every descriptor carrying `FD_CLOEXEC`, in
    /// ascending order (`begin_new_exec`, after the point of no return).
    pub fn do_close_on_exec(&mut self, fdt: &mut super::FdTable) {
        let fds = u32::try_from(fdt.max_fds()).unwrap_or(u32::MAX);
        for fd in 0..fds {
            if fdt.get(fd).is_some()
                && fdt.cloexec(fd)
                && let Some(file) = fdt.close(fd)
            {
                self.fput(file);
            }
        }
    }
}
