// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: fs/namei.c (GPL-2.0:
// `follow_down`/`__follow_mount_rcu`/`traverse_mounts`, `follow_dotdot`,
// `follow_up`), fs/namespace.c (`lookup_mnt`, `mnt_has_parent`,
// `path_mounted`, `__mnt_is_readonly`), fs/stat.c (`vfs_getattr`), fs/d_path.c
// (`prepend_path`, `d_path`), fs/dcache.c (`d_unlinked`).
// Transformation: the dentry/inode/mount triple of a `struct path` is one
// [`InodeId`] (a tmpfs inode or a procfs node), whose superblock names its
// mount (one mount per superblock, see `mount`).
#![forbid(unsafe_code)]
//! The filesystems of the namespace behind one interface: the tmpfs arena, the
//! mount table and the procfs nodes.
//!
//! # Contract
//! Context: task context under the `vfs` lock class. [`Fs`] dereferences to the
//! [`Tmpfs`] arena, so tmpfs-only operations keep their names; the operations
//! that must also accept a procfs node (`iget`, `iput`, `getattr`, `lookup`,
//! `readdir`, ...) are inherent methods of [`Fs`] and shadow the arena's.

use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};
use syscalls::Errno;

use super::{
    Cred, InodeId, KResult, Kstat, MAY_WRITE, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG, SbId, Timespec,
    mount::{
        FsType, MNT_NOATIME, MNT_NODEV, MNT_NODIRATIME, MNT_NOEXEC, MNT_NOSUID, MNT_NOSYMFOLLOW,
        MNT_READONLY, MNT_RELATIME, Mount, Namespace, ProcOpts, SB_MANDLOCK, SB_RDONLY,
        SB_SYNCHRONOUS,
    },
    ops::Env,
    tmpfs::Tmpfs,
    try_push,
};
use crate::{
    procfs::{self, Caller, ProcNode},
    seq::Seq,
};

/// `TMPFS_MAGIC` (include/uapi/linux/magic.h): the type of tmpfs and of the rootfs.
pub const TMPFS_MAGIC: u64 = 0x0102_1994;
/// `PROC_SUPER_MAGIC`.
pub const PROC_SUPER_MAGIC: u64 = 0x9fa0;
// `ST_*` (include/linux/statfs.h): what `calculate_f_flags` derives.
const ST_RDONLY: u64 = 0x0001;
const ST_NOSUID: u64 = 0x0002;
const ST_NODEV: u64 = 0x0004;
const ST_NOEXEC: u64 = 0x0008;
const ST_SYNCHRONOUS: u64 = 0x0010;
/// `ST_VALID`: `f_flags` is implemented.
pub const ST_VALID: u64 = 0x0020;
const ST_MANDLOCK: u64 = 0x0040;
const ST_NOATIME: u64 = 0x0400;
const ST_NODIRATIME: u64 = 0x0800;
const ST_RELATIME: u64 = 0x1000;
const ST_NOSYMFOLLOW: u64 = 0x2000;

/// A `struct kstatfs` of a filesystem of the namespace; the block size and name length are
/// the same everywhere here (`PAGE_SIZE`, `NAME_MAX`), `f_bavail` equals `f_bfree`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatfsInfo {
    pub magic: u64,
    pub blocks: u64,
    pub bfree: u64,
    pub files: u64,
    pub ffree: u64,
    pub flags: u64,
}

/// The namespace's filesystems.
pub struct Fs {
    tmp: Tmpfs,
    pub ns: Namespace,
}

impl Deref for Fs {
    type Target = Tmpfs;
    fn deref(&self) -> &Tmpfs {
        &self.tmp
    }
}

impl DerefMut for Fs {
    fn deref_mut(&mut self) -> &mut Tmpfs {
        &mut self.tmp
    }
}

/// The permission-relevant attributes of an inode or node.
#[derive(Clone, Copy, Debug)]
pub struct NodeAttr {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

impl Fs {
    /// # Errors
    /// `ENOMEM`.
    pub fn new(tmp: Tmpfs, ram_pages: u64) -> KResult<Self> {
        let root = tmp.root();
        Ok(Self {
            ns: Namespace::new(root, ram_pages)?,
            tmp,
        })
    }

    /// The tmpfs arena (the same as dereferencing).
    #[must_use]
    pub fn tmp(&self) -> &Tmpfs {
        &self.tmp
    }

    /// Mutable arena access.
    pub fn tmp_mut(&mut self) -> &mut Tmpfs {
        &mut self.tmp
    }

    /// The root of the root mount.
    #[must_use]
    pub fn root(&self) -> InodeId {
        self.tmp.root()
    }

    /// The superblock of an inode or node.
    #[must_use]
    pub fn sb_of(&self, id: InodeId) -> SbId {
        match ProcNode::of(id) {
            Some(node) => node.sb,
            None => self.tmp.inode(id).sb,
        }
    }

    /// The mount an inode or node belongs to (`path->mnt`); the namespace root
    /// mount for a handle whose mount is gone (detached).
    #[must_use]
    pub fn mount_of(&self, id: InodeId) -> Option<&Mount> {
        self.ns.mount_of_sb(self.sb_of(id))
    }

    /// Whether `id` is the root of its mount (`path_mounted`).
    #[must_use]
    pub fn is_mount_root(&self, id: InodeId) -> bool {
        self.mount_of(id).is_some_and(|m| m.root == id)
    }

    /// `traverse_mounts`: the root of the mount stacked at `id`, repeatedly.
    #[must_use]
    pub fn follow_mounts(&self, mut id: InodeId) -> InodeId {
        while let Some(mount) = self.mount_of(id)
            && let Some(child) = self.ns.child_at(mount.id, id)
        {
            id = child.root;
        }
        id
    }

    /// `follow_up` as `follow_dotdot` loops it: from the root of a mount to
    /// the point it covers, until a directory that is not a mount root.
    /// `None` when the namespace root is reached (or the mount is detached).
    #[must_use]
    pub fn follow_up(&self, mut id: InodeId) -> Option<InodeId> {
        let mut moved = false;
        while let Some(mount) = self.mount_of(id)
            && mount.root == id
            && mount.parent != mount.id
        {
            id = mount.point;
            moved = true;
        }
        moved.then_some(id)
    }

    /// The procfs options of the superblock of a node.
    #[must_use]
    pub fn proc_opts(&self, node: ProcNode) -> ProcOpts {
        if self.ns.has_sb(node.sb) {
            self.ns.sb(node.sb).proc
        } else {
            ProcOpts::DEFAULT
        }
    }

    /// Whether `id` is a directory.
    #[must_use]
    pub fn is_dir(&self, id: InodeId) -> bool {
        match ProcNode::of(id) {
            Some(node) => node.is_dir(),
            None => self.tmp.inode(id).is_dir(),
        }
    }

    /// Whether `id` is a symbolic link.
    #[must_use]
    pub fn is_symlink(&self, id: InodeId) -> bool {
        match ProcNode::of(id) {
            Some(node) => node.is_symlink(),
            None => self.tmp.inode(id).is_symlink(),
        }
    }

    /// The mode, owner and group of an inode or node (`inode_permission`).
    #[must_use]
    pub fn node_attr(&self, id: InodeId) -> NodeAttr {
        if let Some(node) = ProcNode::of(id) {
            let attr = procfs::attr(&self.ns.proc, node, &self.proc_opts(node));
            NodeAttr {
                mode: attr.mode,
                uid: attr.uid,
                gid: attr.gid,
            }
        } else {
            let inode = self.tmp.inode(id);
            NodeAttr {
                mode: inode.mode,
                uid: inode.uid,
                gid: inode.gid,
            }
        }
    }

    /// What `->getattr` refuses before `vfs_getattr` fills the stat (see
    /// [`procfs::getattr_check`]).
    ///
    /// # Errors
    /// `ENOENT` for a process directory `hidepid` hides from the caller.
    pub fn getattr_check(&self, caller: &procfs::Caller, id: InodeId) -> KResult<()> {
        match ProcNode::of(id) {
            Some(node) => procfs::getattr_check(&self.ns.proc, &self.proc_opts(node), caller, node),
            None => Ok(()),
        }
    }

    /// `vfs_getattr`.
    #[must_use]
    pub fn getattr(&self, id: InodeId) -> Kstat {
        if let Some(node) = ProcNode::of(id) {
            let dev = if self.ns.has_sb(node.sb) {
                self.ns.sb(node.sb).dev
            } else {
                0
            };
            procfs::getattr(
                &self.ns.proc,
                node,
                &self.proc_opts(node),
                dev,
                self.tmp.now(),
            )
        } else {
            let mut stat = self.tmp.getattr(id);
            // `vfs_statx_path`: STATX_ATTR_MOUNT_ROOT follows the mount.
            if self.is_mount_root(id) {
                stat.attributes |= crate::vfs::STATX_ATTR_MOUNT_ROOT;
            } else {
                stat.attributes &= !crate::vfs::STATX_ATTR_MOUNT_ROOT;
            }
            stat
        }
    }

    /// `ihold`/`dget`.
    pub fn iget(&mut self, id: InodeId) {
        match ProcNode::of(id) {
            Some(node) => {
                if self.ns.has_sb(node.sb) {
                    self.ns.sb_mut(node.sb).pins += 1;
                }
            }
            None => self.tmp.iget(id),
        }
    }

    /// `iput`/`dput`.
    pub fn iput(&mut self, id: InodeId) {
        match ProcNode::of(id) {
            Some(node) => {
                if self.ns.has_sb(node.sb) {
                    let info = self.ns.sb_mut(node.sb);
                    info.pins = info.pins.saturating_sub(1);
                }
            }
            None => self.tmp.iput(id),
        }
    }

    /// The child `name` of directory `dir` (not following mounts). For procfs
    /// directories the answer depends on the caller.
    ///
    /// # Errors
    /// `ENOENT` for a procfs directory whose pid is gone.
    pub fn lookup_child(&self, env: &Env, dir: InodeId, name: &[u8]) -> KResult<Option<InodeId>> {
        match ProcNode::of(dir) {
            Some(node) => {
                let caller = Caller {
                    tgid: env.tgid,
                    cred: env.cred,
                };
                procfs::lookup(&self.ns.proc, &self.proc_opts(node), &caller, node, name)
                    .map(|found| found.map(ProcNode::id))
            }
            None => Ok(self.tmp.lookup(dir, name)),
        }
    }

    /// `d_parent` of a directory.
    #[must_use]
    pub fn parent_dir(&self, dir: InodeId) -> InodeId {
        match ProcNode::of(dir) {
            Some(node) => procfs::parent(node).id(),
            None => self.tmp.parent(dir),
        }
    }

    /// `IS_DEADDIR` (a procfs directory is never dead; a stale pid fails on
    /// use).
    #[must_use]
    pub fn is_dead(&self, dir: InodeId) -> bool {
        ProcNode::of(dir).is_none() && self.tmp.is_dead(dir)
    }

    /// `iterate_dir` for any directory.
    ///
    /// # Errors
    /// `ENOENT` for a procfs directory whose pid is gone.
    pub fn readdir(
        &self,
        env: &Env,
        dir: InodeId,
        pos: &mut i64,
        actor: &mut super::tmpfs::Actor<'_>,
    ) -> KResult<()> {
        if let Some(node) = ProcNode::of(dir) {
            let caller = Caller {
                tgid: env.tgid,
                cred: env.cred,
            };
            procfs::readdir(
                &self.ns.proc,
                &self.proc_opts(node),
                &caller,
                node,
                pos,
                actor,
            )
        } else {
            self.tmp.readdir(dir, pos, actor);
            Ok(())
        }
    }

    /// `inode_permission`: `sb_permission` (a write to a regular file,
    /// directory or link of a read-only superblock is `EROFS`), then the
    /// node's own rule (procfs) or the generic mode check.
    ///
    /// # Errors
    /// `EROFS`, `EACCES`, and the procfs refusals (`ESRCH`, `EPERM`, `ENOENT`).
    pub fn permission(&self, env: &Env, id: InodeId, mask: u32) -> KResult<()> {
        let attr = self.node_attr(id);
        let ty = attr.mode & S_IFMT;
        if mask & MAY_WRITE != 0
            && matches!(ty, S_IFREG | S_IFDIR | S_IFLNK)
            && self.sb_is_readonly(self.sb_of(id))
        {
            return Err(Errno::EROFS);
        }
        if mask & MAY_WRITE != 0 && ProcNode::of(id).is_some_and(procfs::is_immutable) {
            return Err(Errno::EPERM); // IS_IMMUTABLE
        }
        match ProcNode::of(id) {
            Some(node) => procfs::permission(&self.ns.proc, &self.proc_opts(node), env, node, mask),
            None => super::path::permission(&attr, &env.cred, mask),
        }
    }

    /// `mnt_want_write`: `EROFS` when the mount of `id` is read-only.
    ///
    /// # Errors
    /// `EROFS`.
    pub fn want_write(&self, id: InodeId) -> KResult<()> {
        if self.mnt_is_readonly(id) {
            Err(Errno::EROFS)
        } else {
            Ok(())
        }
    }

    /// `__mnt_is_readonly` for the mount of `id`: the mount flag or a
    /// read-only superblock.
    #[must_use]
    pub fn mnt_is_readonly(&self, id: InodeId) -> bool {
        let sb = self.sb_of(id);
        let mount_ro = self
            .ns
            .mount_of_sb(sb)
            .is_some_and(|m| m.flags & MNT_READONLY != 0);
        mount_ro || self.sb_is_readonly(sb)
    }

    /// `sb_rdonly`.
    #[must_use]
    pub fn sb_is_readonly(&self, sb: SbId) -> bool {
        if !self.ns.has_sb(sb) {
            return false;
        }
        match self.ns.sb(sb).fstype {
            FsType::Rootfs | FsType::Tmpfs => self.tmp.has_sb(sb) && self.tmp.sb_rdonly(sb),
            FsType::Proc => self.ns.sb(sb).flags & SB_RDONLY != 0,
        }
    }

    // ---- d_path ---------------------------------------------------------------------

    /// The components of the path of `id` below the root `root`, outermost
    /// first, as `prepend_path` walks them, and whether `id` is reachable
    /// from `root` at all.
    fn path_parts(&self, root: InodeId, mut id: InodeId) -> KResult<(Vec<InodeId>, bool)> {
        let mut parts: Vec<InodeId> = Vec::new();
        loop {
            if id == root {
                return Ok((parts, true));
            }
            let Some(mount) = self.mount_of(id) else {
                // A detached mount: the path ends at its root.
                return Ok((parts, false));
            };
            if mount.root == id {
                if mount.parent == mount.id {
                    // The absolute root, and `root` was not met on the way.
                    return Ok((parts, false));
                }
                id = mount.point;
                continue;
            }
            try_push(&mut parts, id)?;
            id = self.parent_dir(id);
        }
    }

    /// `d_path` of `id` below `root`: `/a/b`, or `/` for the root itself. A
    /// name outside the root (a detached mount, an escaped working directory)
    /// is prefixed `(unreachable)`.
    ///
    /// # Errors
    /// `ENOMEM`.
    pub fn d_path(&self, root: InodeId, id: InodeId) -> KResult<(Vec<u8>, bool)> {
        let (parts, reachable) = self.path_parts(root, id)?;
        let mut seq = Seq::new();
        if parts.is_empty() {
            seq.put(b"/")?;
        }
        for &part in parts.iter().rev() {
            seq.putc(b'/')?;
            if let Some(node) = ProcNode::of(part) {
                procfs::name_of(node, &mut seq)?;
            } else {
                let parent = self.tmp.parent(part);
                seq.put(self.tmp.name_of(parent, part).unwrap_or(b"?"))?;
            }
        }
        Ok((seq.into_vec(), reachable))
    }

    /// `vfs_statfs` of the filesystem `id` is on: the superblock's `s_op->statfs`
    /// (`shmem_statfs` for the rootfs and tmpfs; procfs has `simple_statfs`, which reports
    /// the block size and name length only) and `calculate_f_flags` of its mount.
    #[must_use]
    pub fn statfs(&self, id: InodeId) -> StatfsInfo {
        let sb = self.sb_of(id);
        let (magic, counts) = match self.ns.sb(sb).fstype {
            FsType::Rootfs | FsType::Tmpfs => {
                let t = self.tmp.statfs(sb);
                (TMPFS_MAGIC, (t.blocks, t.bfree, t.files, t.ffree))
            }
            FsType::Proc => (PROC_SUPER_MAGIC, (0, 0, 0, 0)),
        };
        let flags_by_mnt = self.ns.mount_of_sb(sb).map_or(0, |m| {
            [
                (MNT_READONLY, ST_RDONLY),
                (MNT_NOSUID, ST_NOSUID),
                (MNT_NODEV, ST_NODEV),
                (MNT_NOEXEC, ST_NOEXEC),
                (MNT_NOATIME, ST_NOATIME),
                (MNT_NODIRATIME, ST_NODIRATIME),
                (MNT_RELATIME, ST_RELATIME),
                (MNT_NOSYMFOLLOW, ST_NOSYMFOLLOW),
            ]
            .iter()
            .filter(|(mnt, _)| m.flags & mnt != 0)
            .fold(0, |acc, (_, st)| acc | st)
        });
        let sb_flags = self.ns.sb(sb).flags;
        let flags_by_sb = [
            (SB_SYNCHRONOUS, ST_SYNCHRONOUS),
            (SB_MANDLOCK, ST_MANDLOCK),
            (SB_RDONLY, ST_RDONLY),
        ]
        .iter()
        .filter(|(sb, _)| sb_flags & sb != 0)
        .fold(0, |acc, (_, st)| acc | st);
        StatfsInfo {
            magic,
            blocks: counts.0,
            bfree: counts.1,
            files: counts.2,
            ffree: counts.3,
            flags: ST_VALID | flags_by_mnt | flags_by_sb,
        }
    }

    /// The pages tmpfs files hold, over every tmpfs superblock (`Shmem`).
    #[must_use]
    pub fn tmpfs_pages(&self) -> u64 {
        self.ns
            .mounts
            .iter()
            .filter(|m| self.tmp.has_sb(m.sb))
            .map(|m| self.tmp.sb_usage(m.sb).1)
            .sum()
    }

    /// Release the ids of detached mounts whose superblocks died.
    pub fn reap(&mut self) {
        let tmp = &self.tmp;
        self.ns.reap(|sb| !tmp.has_sb(sb));
    }

    /// The mode type bits of an inode or node.
    #[must_use]
    pub fn file_type(&self, id: InodeId) -> u32 {
        self.node_attr(id).mode & S_IFMT
    }

    /// Whether the handle names a directory or a link (`d_is_dir` stand-ins).
    #[must_use]
    pub fn kind_bits(&self, id: InodeId) -> (bool, bool) {
        let ty = self.file_type(id);
        (ty == S_IFDIR, ty == S_IFLNK)
    }

    /// Timestamp "now" of the clock.
    #[must_use]
    pub fn clock_now(&self) -> Timespec {
        self.tmp.now()
    }

    /// Whether the caller may use a [`Cred`] to read the node (placeholder for
    /// future per-node checks).
    #[must_use]
    pub fn cred_is_root(cred: &Cred) -> bool {
        cred.sys_admin
    }

    /// An error for stale handles.
    #[must_use]
    pub const fn stale() -> Errno {
        Errno::ESRCH
    }
}
