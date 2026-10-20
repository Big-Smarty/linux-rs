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
    file::{CharDev, File, FileKind},
    mkdev, new_decode_dev,
    path::{self, LOOKUP_DIRECTORY, LOOKUP_FOLLOW, LastKind, WALK_TRAILING, Walk, permission},
    pipe::Pipe,
    try_copy, try_push,
};

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
/// Only `0:*` (no driver can register major 0 through `cdev_add`) and `5:0`
/// (`/dev/tty` without a controlling terminal, `tty_open_current_tty`) answer
/// `ENXIO`; every other number may belong to a driver of the reference
/// configuration (misc 10, input 13, fb 29, ...), so opening it succeeds and
/// each later operation stops the kernel loudly.
fn chrdev(rdev: u32) -> Chr {
    match (super::major(rdev), super::minor(rdev)) {
        (1, 3) => Chr::Driver(CharDev::Null),
        (1, 5) => Chr::Driver(CharDev::Zero),
        (1, 7) => Chr::Driver(CharDev::Full),
        (5, 1) => Chr::Driver(CharDev::Console),
        (0, _) | (5, 0) => Chr::Absent,
        // ptmx, the vt and serial ttys and the unix98 pty slaves: tty_open.
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
        match file.kind {
            FileKind::Pipe { pipe, writer } => self.pipe_release(pipe, writer),
            _ => {
                if let Some(inode) = file.inode {
                    self.fs.iput(inode);
                }
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
        }
    }

    // ---- lookup and attributes ----------------------------------------------

    /// `filename_lookup`.
    ///
    /// # Errors
    /// See [`path::lookup`].
    pub fn lookup(&self, env: &Env, path: &[u8], flags: u32) -> KResult<InodeId> {
        path::lookup(&self.fs, env, path, flags)
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
                }
            }
            (_, Some(inode)) => self.fs.getattr(inode),
            _ => unreachable!("a file without an inode is a pipe"),
        }
    }

    // ---- permission helpers (fs/namei.c) -------------------------------------

    fn may_create(&self, env: &Env, dir: InodeId) -> KResult<()> {
        if self.fs.is_dead(dir) {
            return Err(Errno::ENOENT); // IS_DEADDIR
        }
        permission(self.fs.inode(dir), &env.cred, MAY_WRITE | MAY_EXEC)
    }

    /// `check_sticky`: whether the sticky bit lets the caller touch `victim`.
    fn sticky_ok(&self, env: &Env, dir: InodeId, victim: InodeId) -> bool {
        let (d, v) = (self.fs.inode(dir), self.fs.inode(victim));
        d.mode & S_ISVTX == 0
            || v.uid == env.cred.fsuid
            || d.uid == env.cred.fsuid
            || env.cred.fowner
    }

    /// `may_delete`.
    fn may_delete(&self, env: &Env, dir: InodeId, victim: InodeId, isdir: bool) -> KResult<()> {
        permission(self.fs.inode(dir), &env.cred, MAY_WRITE | MAY_EXEC)?;
        if !self.sticky_ok(env, dir, victim) {
            return Err(Errno::EPERM);
        }
        let victim_is_dir = self.fs.inode(victim).is_dir();
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
        let parent = path::parent_of(&self.fs, env, path)?;
        if parent.kind != LastKind::Norm {
            return Err(Errno::EEXIST);
        }
        if self.fs.is_dead(parent.dir) {
            return Err(Errno::ENOENT); // lookup_one_qstr_excl: no dentry in a dead dir
        }
        if self.fs.lookup(parent.dir, &parent.name).is_some() {
            return Err(Errno::EEXIST); // LOOKUP_EXCL
        }
        if parent.name.len() > NAME_MAX {
            return Err(Errno::ENAMETOOLONG); // simple_lookup
        }
        if parent.trailing_slash && !want_dir {
            return Err(Errno::ENOENT); // LOOKUP_CREATE dropped
        }
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
        let source = self.lookup(env, old, old_flags)?;
        let (dir, name) = self.prepare_create(env, new, false)?;
        self.may_create(env, dir)?;
        let inode = self.fs.inode(source);
        if inode.is_dir() {
            return Err(Errno::EPERM);
        }
        if inode.nlink == 0 {
            return Err(Errno::ENOENT);
        }
        self.fs.link(source, dir, &name)
    }

    // ---- removal -------------------------------------------------------------

    /// `unlinkat(0)`: remove a non-directory name.
    ///
    /// # Errors
    /// `EISDIR`, `ENOTDIR` (trailing slash on a file), `ENOENT`, `EACCES`,
    /// `EPERM` (sticky) and path errors.
    pub fn unlink(&mut self, env: &Env, path: &[u8]) -> KResult<()> {
        let parent = path::parent_of(&self.fs, env, path)?;
        if parent.kind != LastKind::Norm {
            return Err(Errno::EISDIR);
        }
        let Some(victim) = self.fs.lookup(parent.dir, &parent.name) else {
            return Err(if parent.name.len() > NAME_MAX {
                Errno::ENAMETOOLONG
            } else {
                Errno::ENOENT
            });
        };
        if parent.trailing_slash {
            return Err(if self.fs.inode(victim).is_dir() {
                Errno::EISDIR
            } else {
                Errno::ENOTDIR
            });
        }
        self.may_delete(env, parent.dir, victim, false)?;
        self.fs.unlink(parent.dir, &parent.name, false)
    }

    /// `rmdir` (`do_rmdir`).
    ///
    /// # Errors
    /// `EINVAL` (`.`), `ENOTEMPTY` (`..` or a non-empty directory), `EBUSY`
    /// (the root), `ENOTDIR`, `ENOENT`, `EACCES`, `EPERM` and path errors.
    pub fn rmdir(&mut self, env: &Env, path: &[u8]) -> KResult<()> {
        let parent = path::parent_of(&self.fs, env, path)?;
        match parent.kind {
            LastKind::DotDot => return Err(Errno::ENOTEMPTY),
            LastKind::Dot => return Err(Errno::EINVAL),
            LastKind::Root => return Err(Errno::EBUSY),
            LastKind::Norm => {}
        }
        let Some(victim) = self.fs.lookup(parent.dir, &parent.name) else {
            return Err(if parent.name.len() > NAME_MAX {
                Errno::ENAMETOOLONG
            } else {
                Errno::ENOENT
            });
        };
        self.may_delete(env, parent.dir, victim, true)?;
        self.fs.unlink(parent.dir, &parent.name, true)
    }

    // ---- attribute changes ---------------------------------------------------

    /// `chmod_common`.
    ///
    /// # Errors
    /// `EPERM` unless the caller owns the file or has `CAP_FOWNER`.
    pub fn chmod(&mut self, env: &Env, inode: InodeId, mode: u32) -> KResult<()> {
        if self.fs.inode(inode).uid != env.cred.fsuid && !env.cred.fowner {
            return Err(Errno::EPERM);
        }
        self.fs.set_mode(inode, mode, &env.cred);
        Ok(())
    }

    /// `chown_common` (`u32::MAX` leaves an id unchanged).
    ///
    /// # Errors
    /// `EPERM` without `CAP_CHOWN` for any real change.
    pub fn chown(&mut self, env: &Env, inode: InodeId, uid: u32, gid: u32) -> KResult<()> {
        let cur = self.fs.inode(inode);
        let changes = (uid != u32::MAX && uid != cur.uid) || (gid != u32::MAX && gid != cur.gid);
        if changes && !env.cred.chown {
            return Err(Errno::EPERM);
        }
        self.fs.set_owner(inode, uid, gid);
        Ok(())
    }

    /// `vfs_utimes` with explicit times.
    pub fn utimes(&mut self, inode: InodeId, atime: Timespec, mtime: Timespec) {
        self.fs.set_times(inode, atime, mtime);
    }

    /// `vfs_truncate`.
    ///
    /// # Errors
    /// `EISDIR`, `EINVAL`, `EACCES`.
    pub fn truncate(&mut self, env: &Env, inode: InodeId, length: u64) -> KResult<()> {
        let node = self.fs.inode(inode);
        if node.is_dir() {
            return Err(Errno::EISDIR);
        }
        if !node.is_reg() {
            return Err(Errno::EINVAL);
        }
        permission(node, &env.cred, MAY_WRITE)?;
        self.do_truncate(&env.cred, inode, length);
        Ok(())
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
        permission(self.fs.inode(inode), &env.cred, mode)
    }

    // ---- getcwd --------------------------------------------------------------

    /// The path of `dir` below `root` (`prepend_path`), without the NUL.
    ///
    /// # Errors
    /// `ENOENT` for a removed directory, `ENOMEM`.
    pub fn dir_path(&self, root: InodeId, dir: InodeId) -> KResult<Vec<u8>> {
        let mut parts: Vec<InodeId> = Vec::new();
        let mut cur = dir;
        while cur != root && cur != self.fs.root() {
            let parent = self.fs.parent(cur);
            if self.fs.name_of(parent, cur).is_none() {
                return Err(Errno::ENOENT); // d_unlinked
            }
            try_push(&mut parts, cur)?;
            cur = parent;
        }
        let mut out = Vec::new();
        out.try_reserve(2).map_err(|_| Errno::ENOMEM)?;
        if parts.is_empty() {
            out.push_within_capacity(b'/').map_err(|_| Errno::ENOMEM)?;
            return Ok(out);
        }
        for &part in parts.iter().rev() {
            let parent = self.fs.parent(part);
            let name = self.fs.name_of(parent, part).unwrap_or(b"?");
            out.try_reserve(name.len() + 1).map_err(|_| Errno::ENOMEM)?;
            out.push_within_capacity(b'/').map_err(|_| Errno::ENOMEM)?;
            for &byte in name {
                out.push_within_capacity(byte).map_err(|_| Errno::ENOMEM)?;
            }
        }
        Ok(out)
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
            let inode = self.lookup(env, path, flags)?;
            return self.make_file(inode, op.flags, FileKind::Path, FMODE_PATH);
        }
        let (inode, created) = self.open_last_lookups(env, path, op)?;
        self.do_open(env, inode, created, op)
    }

    /// `path_openat`'s walk and `open_last_lookups`/`lookup_open`: the inode
    /// to open and whether this call created it. A created inode is not yet
    /// pinned by a file.
    fn open_last_lookups(
        &mut self,
        env: &Env,
        path: &[u8],
        op: &OpenFlags,
    ) -> KResult<(InodeId, bool)> {
        enum Resolved {
            Found(InodeId),
            Missing(InodeId, Vec<u8>),
        }
        let create = op.flags & O_CREAT != 0;
        let mut directory = op.directory;
        let resolved = {
            let mut walk = Walk::new(&self.fs, env, path, op.follow)?;
            let mut remaining = path;
            loop {
                let last = walk.link_path_walk(remaining)?;
                if last.kind != LastKind::Norm {
                    walk.walk_component(&last, WALK_TRAILING)?; // handle_dots
                    break Resolved::Found(walk.cur);
                }
                if create && last.trailing_slash {
                    return Err(Errno::EISDIR);
                }
                if last.trailing_slash {
                    walk.follow = true;
                    directory = true;
                }
                if create && walk.fs.lookup(walk.cur, last.name).is_none() {
                    if walk.fs.is_dead(walk.cur) {
                        return Err(Errno::ENOENT); // lookup_open: IS_DEADDIR
                    }
                    if last.name.len() > NAME_MAX {
                        return Err(Errno::ENAMETOOLONG);
                    }
                    break Resolved::Missing(walk.cur, try_copy(last.name)?);
                }
                match walk.walk_component(&last, WALK_TRAILING)? {
                    Some(body) => remaining = body,
                    None => break Resolved::Found(walk.cur),
                }
            }
        };
        let (dir, name) = match resolved {
            Resolved::Found(found) => {
                return self
                    .check_found(found, directory, op)
                    .map(|inode| (inode, false));
            }
            Resolved::Missing(dir, name) => (dir, name),
        };
        // lookup_open: create_error = may_o_create() for the missing name.
        self.may_create(env, dir)?;
        let mode = Self::prepare_mode(env, op.mode, S_IALLUGO, S_IFREG) | S_IFREG;
        let inode = self.fs.mknod(dir, &name, mode, 0, &env.cred)?;
        Ok((inode, true))
    }

    /// The `do_open` checks that precede `may_open` for an existing inode.
    fn check_found(&self, inode: InodeId, directory: bool, op: &OpenFlags) -> KResult<InodeId> {
        let node = self.fs.inode(inode);
        if op.flags & O_CREAT != 0 {
            if op.flags & O_EXCL != 0 {
                return Err(Errno::EEXIST);
            }
            if node.is_dir() {
                return Err(Errno::EISDIR);
            }
        }
        if directory && !node.is_dir() {
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
    ) -> KResult<FileId> {
        let mut open_flag = op.flags;
        let mut acc_mode = op.acc_mode;
        let mut do_truncate = false;
        if created {
            open_flag &= !O_TRUNC;
            acc_mode = 0;
        } else if self.fs.inode(inode).is_reg() && open_flag & O_TRUNC != 0 {
            do_truncate = true;
        }
        self.may_open(env, inode, acc_mode, open_flag)?;
        let file = self.vfs_open(inode, open_flag)?;
        if do_truncate {
            self.do_truncate(&env.cred, inode, 0); // handle_truncate (0 is always within RLIMIT_FSIZE)
        }
        Ok(file)
    }

    /// `may_open`.
    fn may_open(&self, env: &Env, inode: InodeId, acc_mode: u32, flag: u32) -> KResult<()> {
        let node = self.fs.inode(inode);
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
            _ => {}
        }
        permission(node, &env.cred, acc_mode)?;
        // O_NOATIME can only be set by the owner or superuser.
        if flag & O_NOATIME != 0 && node.uid != env.cred.fsuid && !env.cred.fowner {
            return Err(Errno::EPERM);
        }
        Ok(())
    }

    /// `vfs_open`/`do_dentry_open` for a resolved inode.
    fn vfs_open(&mut self, inode: InodeId, open_flag: u32) -> KResult<FileId> {
        let mode = self.fs.inode(inode).mode;
        let rdev = self.fs.inode(inode).rdev;
        let mut fmode = (open_flag & O_ACCMODE).wrapping_add(1) & O_ACCMODE;
        let mut unported_stream = false;
        let kind = match mode & S_IFMT {
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
            FileKind::Char(CharDev::Console) => {
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
        if fmode & FMODE_WRITE != 0 && kind != FileKind::Directory {
            fmode |= FMODE_CAN_WRITE;
        }
        // No inode here has `a_ops->direct_IO` (tmpfs has none, nor do the
        // device nodes): do_dentry_open rejects O_DIRECT.
        if open_flag & O_DIRECT != 0 {
            return Err(Errno::EINVAL);
        }
        let flags = open_flag & !(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC);
        self.make_file(inode, flags, kind, fmode)
    }

    fn make_file(
        &mut self,
        inode: InodeId,
        flags: u32,
        kind: FileKind,
        mode: u32,
    ) -> KResult<FileId> {
        self.fs.iget(inode);
        match self.files.alloc(File::new(Some(inode), kind, flags, mode)) {
            Ok(id) => Ok(id),
            Err(error) => {
                self.fs.iput(inode);
                Err(error)
            }
        }
    }

    /// `do_tmpfile`: an unnamed regular file in directory `path`.
    fn open_tmpfile(&mut self, env: &Env, path: &[u8], op: &OpenFlags) -> KResult<FileId> {
        let dir = self.lookup(env, path, LOOKUP_FOLLOW | LOOKUP_DIRECTORY)?;
        self.may_create(env, dir)?;
        let mode = Self::prepare_mode(env, op.mode, S_IALLUGO, S_IFREG) | S_IFREG;
        let inode = self.fs.mknod_unlinked(mode, &env.cred)?;
        let flags = op.flags & !(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC);
        let file = self.vfs_open(inode, flags);
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
        let node = self.fs.inode(dir);
        if !node.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        permission(node, &env.cred, MAY_EXEC)
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

    // ---- pipes ---------------------------------------------------------------

    pub(crate) fn pipe(&self, id: super::PipeId) -> &Pipe {
        self.pipes[id.0 as usize]
            .as_ref()
            .expect("stale pipe handle")
    }

    /// Mutable access to a pipe.
    ///
    /// # Panics
    /// On a stale handle (a kernel bug).
    pub fn pipe_mut(&mut self, id: super::PipeId) -> &mut Pipe {
        self.pipes[id.0 as usize]
            .as_mut()
            .expect("stale pipe handle")
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
