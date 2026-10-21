// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: fs/namespace.c (GPL-2.0:
// `path_mount`, `do_new_mount`, `do_new_mount_fc`, `do_add_mount`,
// `graft_tree`, `do_lock_mount`/`cant_mount`, `do_remount`,
// `do_reconfigure_mnt`, `change_mount_ro_state`, `mnt_make_readonly`,
// `set_mount_attributes`, `do_change_type`, `flags_to_propagation_type`,
// `can_umount`, `do_umount`, `do_umount_root`, `path_umount`, `ksys_umount`,
// `umount_tree`, `propagate_mount_busy`, `copy_mount_options`,
// `copy_mount_string`, `SYSCALL_DEFINE5(mount)`), fs/pnode.c
// (`change_mnt_propagation`), fs/super.c (`reconfigure_super`,
// `sb_prepare_remount_readonly`), fs/proc_namespace.c (`show_vfsmnt`,
// `show_mountinfo`, `show_sb_opts`, `show_vfsmnt_opts`, `mangle`,
// `show_type`), mm/shmem.c (`shmem_fill_super`, `shmem_reconfigure`,
// `shmem_show_options`), fs/proc/root.c (`proc_fill_super`,
// `proc_reconfigure`), fs/proc/inode.c (`proc_show_options`). All GPL-2.0.
// Copyright of the originals: Linus Torvalds, Al Viro and the VFS authors.
// Transformation: one namespace, no propagation peers, no bind or move mounts
// (loud stop), no user namespaces; the superblock is created before the
// mountpoint is checked, as `fc_mount` precedes `lock_mount`, and undone on
// failure.
#![forbid(unsafe_code)]
//! `mount(2)` and `umount2(2)`, and the text of the mount tables.
//!
//! # Contract
//! * Context: task context, the `vfs` lock class; nothing sleeps.
//! * The caller (the syscall layer) copies the strings from user memory in
//!   `SYSCALL_DEFINE5(mount)`'s order, resolves the mountpoint (`user_path_at`)
//!   and passes plain data.
//! * A behaviour that is not ported ends the call with [`MountFail::Loud`]
//!   (the caller turns it into `Outcome::Unimplemented`): bind and move mounts
//!   and the filesystems of the reference configuration this kernel lacks.

use alloc::vec::Vec;
use syscalls::Errno;

use super::{
    FMODE_WRITE, InodeId, KResult, S_IFBLK, S_IFMT, SbId, Vfs,
    file::FileKind,
    mount::{
        FsLookup, FsType, HidePid, MNT_ATIME_MASK, MNT_DETACH, MNT_EXPIRE, MNT_FORCE, MNT_NOATIME,
        MNT_NODEV, MNT_NODIRATIME, MNT_NOEXEC, MNT_NOSUID, MNT_NOSYMFOLLOW, MNT_READONLY,
        MNT_RELATIME, MNT_USER_SETTABLE_MASK, MS_BIND, MS_DIRSYNC, MS_I_VERSION, MS_LAZYTIME,
        MS_MANDLOCK, MS_MGC_MSK, MS_MGC_VAL, MS_MOVE, MS_NOATIME, MS_NODEV, MS_NODIRATIME,
        MS_NOEXEC, MS_NOSUID, MS_NOSYMFOLLOW, MS_NOUSER, MS_POSIXACL, MS_PRIVATE, MS_RDONLY,
        MS_REC, MS_RELATIME, MS_REMOUNT, MS_RMT_MASK, MS_SHARED, MS_SILENT, MS_SLAVE,
        MS_STRICTATIME, MS_SYNCHRONOUS, MS_UNBINDABLE, Mount, Parsed, ProcOpts, Propagation,
        SB_DIRSYNC, SB_LAZYTIME, SB_MANDLOCK, SB_NODIRATIME, SB_NOEXEC, SB_NOSUID, SB_RDONLY,
        SB_SYNCHRONOUS, SbInfo, get_fs_type, parse_proc, parse_tmpfs,
    },
    ops::Env,
    tmpfs::SbParams,
    try_copy,
};
use crate::{
    procfs::{Kind, MAX_SB, ProcNode},
    seq::{self, Seq},
};

/// Why a mount operation did not complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MountFail {
    Errno(Errno),
    /// A Linux behaviour that is not ported: stop the kernel loudly.
    Loud,
}

impl From<Errno> for MountFail {
    fn from(errno: Errno) -> Self {
        Self::Errno(errno)
    }
}

type MResult<T> = Result<T, MountFail>;

/// A mount request after the strings were copied (`do_mount` arguments).
pub struct MountArgs<'a> {
    /// `dev_name` (`None` for a NULL pointer).
    pub source: Option<&'a [u8]>,
    /// The resolved mountpoint (`user_path_at(dir_name, LOOKUP_FOLLOW)`).
    pub point: InodeId,
    /// `type` (`None` for a NULL pointer).
    pub fstype: Option<&'a [u8]>,
    pub flags: u64,
    /// The options page (`copy_mount_options`), NUL-terminated by the caller.
    pub data: Option<&'a [u8]>,
}

/// `overflowgid`: what an id with no mapping shows as (`/proc/sys/kernel/overflowgid`).
const OVERFLOWGID: u32 = 65534;

impl Vfs {
    /// The pid mirror of `/proc` follows the task list.
    ///
    /// # Errors
    /// `ENOMEM`.
    pub fn sync_proc(&mut self, tasks: &crate::task::Tasklist) -> KResult<()> {
        self.fs.ns.proc.sync(tasks)
    }

    /// `totalram_pages()`, from which tmpfs derives its default limits.
    pub fn set_ram_pages(&mut self, pages: u64) {
        self.fs.ns.ram_pages = pages;
    }

    /// Files open for writing on superblock `sb` (`mnt_get_write_count` /
    /// `FMODE_WRITER`): device nodes do not count.
    fn writers(&self, sb: SbId) -> bool {
        self.files.has_writer(|file| {
            file.mode & FMODE_WRITE != 0
                && matches!(file.kind, FileKind::Regular | FileKind::Proc)
                && file.inode.is_some_and(|inode| self.fs.sb_of(inode) == sb)
        })
    }

    /// Free the ids of detached mounts whose superblocks died.
    fn reap(&mut self) {
        self.fs.reap();
    }

    // ---- mount(2) ------------------------------------------------------------

    /// `path_mount`.
    ///
    /// # Errors
    /// The `mount(2)` errors in Linux's order; [`MountFail::Loud`] for the
    /// behaviours not ported.
    pub fn do_mount(&mut self, env: &Env, args: &MountArgs<'_>) -> MResult<()> {
        self.reap();
        let mut flags = args.flags;
        // Discard magic
        if flags & MS_MGC_MSK == MS_MGC_VAL {
            // C: `flags &= ~MS_MGC_MSK` with MS_MGC_MSK an `unsigned int`
            // (0xffff0000): the complement is 0x0000ffff, zero-extended to
            // `unsigned long`, so bits 16..63 are cleared.
            flags &= MS_MGC_MSK ^ 0xffff_ffff;
        }
        if flags & MS_NOUSER != 0 {
            return Err(Errno::EINVAL.into());
        }
        // may_mount
        if !env.cred.sys_admin {
            return Err(Errno::EPERM.into());
        }
        // Default to relatime unless overriden
        let mut mnt_flags = 0u32;
        if flags & MS_NOATIME == 0 {
            mnt_flags |= MNT_RELATIME;
        }
        for (ms, mnt) in [
            (MS_NOSUID, MNT_NOSUID),
            (MS_NODEV, MNT_NODEV),
            (MS_NOEXEC, MNT_NOEXEC),
            (MS_NOATIME, MNT_NOATIME),
            (MS_NODIRATIME, MNT_NODIRATIME),
        ] {
            if flags & ms != 0 {
                mnt_flags |= mnt;
            }
        }
        if flags & MS_STRICTATIME != 0 {
            mnt_flags &= !(MNT_RELATIME | MNT_NOATIME);
        }
        if flags & MS_RDONLY != 0 {
            mnt_flags |= MNT_READONLY;
        }
        if flags & MS_NOSYMFOLLOW != 0 {
            mnt_flags |= MNT_NOSYMFOLLOW;
        }
        // The default atime for remount is preservation
        if flags & MS_REMOUNT != 0
            && flags & (MS_NOATIME | MS_NODIRATIME | MS_RELATIME | MS_STRICTATIME) == 0
        {
            mnt_flags &= !MNT_ATIME_MASK;
            if let Some(mount) = self.fs.mount_of(args.point) {
                mnt_flags |= mount.flags & MNT_ATIME_MASK;
            }
        }
        let sb_flags = (flags
            & (MS_RDONLY
                | MS_SYNCHRONOUS
                | MS_MANDLOCK
                | MS_DIRSYNC
                | MS_SILENT
                | MS_POSIXACL
                | MS_LAZYTIME
                | MS_I_VERSION)) as u32;
        if flags & (MS_REMOUNT | MS_BIND) == (MS_REMOUNT | MS_BIND) {
            return self.do_reconfigure_mnt(args.point, mnt_flags);
        }
        if flags & MS_REMOUNT != 0 {
            return self.do_remount(env, args.point, sb_flags, mnt_flags, args.data);
        }
        if flags & MS_BIND != 0 {
            self.fs.ns.note_unimplemented();
            return Err(MountFail::Loud);
        }
        if flags & (MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE) != 0 {
            return self.do_change_type(args.point, flags);
        }
        if flags & MS_MOVE != 0 {
            self.fs.ns.note_unimplemented();
            return Err(MountFail::Loud);
        }
        self.do_new_mount(env, args, sb_flags, mnt_flags)
    }

    /// `do_new_mount` + `do_new_mount_fc`.
    fn do_new_mount(
        &mut self,
        env: &Env,
        args: &MountArgs<'_>,
        sb_flags: u32,
        mnt_flags: u32,
    ) -> MResult<()> {
        let Some(name) = args.fstype else {
            return Err(Errno::EINVAL.into());
        };
        let fstype = match get_fs_type(name) {
            FsLookup::Implemented(fstype) => fstype,
            FsLookup::Unknown => return Err(Errno::ENODEV.into()),
            FsLookup::Foreign { bdev } => {
                if bdev {
                    // get_tree_bdev: no source is `EINVAL`; the source must
                    // resolve and be a block device (`ENOTBLK`); the block
                    // layer is not ported.
                    let Some(source) = args.source else {
                        return Err(Errno::EINVAL.into());
                    };
                    let inode = self.lookup(env, source, super::path::LOOKUP_FOLLOW)?;
                    if self.fs.file_type(inode) != S_IFBLK {
                        return Err(Errno::ENOTBLK.into());
                    }
                }
                self.fs.ns.note_unimplemented();
                return Err(MountFail::Loud);
            }
        };
        // fc_mount: the options are parsed and the superblock built before the
        // mountpoint is looked at.
        let devname = try_copy(args.source.unwrap_or(b"none"))?;
        let (sb, root) = match fstype {
            FsType::Tmpfs => self.new_tmpfs(env, sb_flags, args.data)?,
            FsType::Proc => self.new_proc(env, sb_flags, args.data)?,
            FsType::Rootfs => return Err(Errno::ENODEV.into()),
        };
        // lock_mount: `cant_mount` (a removed mountpoint), then `graft_tree`.
        let attach = (|| -> KResult<()> {
            if self.fs.is_dead(args.point) {
                return Err(Errno::ENOENT);
            }
            if self.fs.is_dir(args.point) != self.fs.is_dir(root) {
                return Err(Errno::ENOTDIR);
            }
            let parent = self.fs.mount_of(args.point).map_or(1, |m| m.id);
            let id = self.fs.ns.alloc_mnt_id()?;
            let mount = Mount {
                id,
                parent,
                point: args.point,
                root,
                sb,
                flags: mnt_flags,
                devname,
                prop: Propagation::default(),
                expiry_mark: false,
            };
            if let Err(error) = self.fs.ns.attach(mount) {
                self.fs.ns.free_mnt_id(id);
                return Err(error);
            }
            Ok(())
        })();
        if let Err(error) = attach {
            self.discard_sb(sb);
            return Err(error.into());
        }
        Ok(())
    }

    /// Throw away a superblock that was never attached.
    fn discard_sb(&mut self, sb: SbId) {
        if self.fs.tmp().has_sb(sb) {
            self.fs.tmp_mut().detach_sb(sb);
        }
        self.fs.ns.free_sb(sb);
    }

    /// `shmem_fill_super` for a mount request.
    fn new_tmpfs(
        &mut self,
        env: &Env,
        sb_flags: u32,
        data: Option<&[u8]>,
    ) -> MResult<(SbId, InodeId)> {
        let _ = env;
        let ram = self.fs.ns.ram_pages;
        let opts = match parse_tmpfs(data, ram, sb_flags) {
            Parsed::Ok(opts) => opts,
            Parsed::Err(errno) => return Err(errno.into()),
            Parsed::Unported => {
                self.fs.ns.note_unimplemented();
                return Err(MountFail::Loud);
            }
        };
        let flags = opts.sb_flags;
        let params = SbParams {
            max_blocks: opts.blocks.unwrap_or(self.fs.ns.default_max_blocks()),
            max_inodes: opts.inodes.unwrap_or(self.fs.ns.default_max_inodes()),
            mode: opts.mode.unwrap_or(super::S_ISVTX | 0o777),
            uid: opts.uid.unwrap_or(0),
            gid: opts.gid.unwrap_or(0),
            rdonly: flags & SB_RDONLY != 0,
            first_ino: 1,
        };
        let sb = self.fs.ns.new_sb(|dev| SbInfo {
            fstype: FsType::Tmpfs,
            dev,
            flags,
            proc: ProcOpts::DEFAULT,
            pins: 0,
            detached: false,
        })?;
        let dev = self.fs.ns.sb(sb).dev;
        match self.fs.tmp_mut().new_sb(sb, dev, params) {
            Ok(root) => Ok((sb, root)),
            Err(error) => {
                self.fs.ns.free_sb(sb);
                Err(error.into())
            }
        }
    }

    /// `proc_fill_super` for a mount request.
    fn new_proc(
        &mut self,
        env: &Env,
        sb_flags: u32,
        data: Option<&[u8]>,
    ) -> MResult<(SbId, InodeId)> {
        let set = parse_proc(data, sb_flags)?;
        if let Some(path) = set.pidns {
            // proc_parse_pidns_param: `filp_open(path)` then "not an nsfs
            // file". The namespace files are not routed, so every file that
            // opens is refused the way Linux refuses a non-ns file.
            self.lookup(env, path, super::path::LOOKUP_FOLLOW)?;
            return Err(Errno::EINVAL.into());
        }
        let opts = ProcOpts {
            gid: set.gid.unwrap_or(0),
            hide_pid: set.hide_pid.unwrap_or(HidePid::Off),
            pidonly: set.pidonly.unwrap_or(false),
        };
        let flags = set.sb_flags | SB_NODIRATIME | SB_NOSUID | SB_NOEXEC;
        let sb = self.fs.ns.new_sb(|dev| SbInfo {
            fstype: FsType::Proc,
            dev,
            flags,
            proc: opts,
            pins: 0,
            detached: false,
        })?;
        if sb > MAX_SB {
            self.fs.ns.free_sb(sb);
            return Err(Errno::ENOSPC.into());
        }
        Ok((sb, ProcNode::new(sb, Kind::Root).id()))
    }

    // ---- remount, propagation ------------------------------------------------------

    /// `do_remount`.
    fn do_remount(
        &mut self,
        env: &Env,
        point: InodeId,
        sb_flags: u32,
        mnt_flags: u32,
        data: Option<&[u8]>,
    ) -> MResult<()> {
        let mnt_id = {
            let Some(mount) = self.fs.mount_of(point) else {
                return Err(Errno::EINVAL.into());
            };
            if mount.root != point {
                return Err(Errno::EINVAL.into()); // !path_mounted
            }
            mount.id
        };
        let sb = self.fs.sb_of(point);
        let info = self.fs.ns.sb(sb);
        let kind = info.fstype;
        let was_ro = info.flags & SB_RDONLY != 0;
        // fs_context_for_reconfigure: the mask is MS_RMT_MASK plus the data's.
        let rmt = MS_RMT_MASK as u32;
        let mut mask = rmt;
        let mut want = sb_flags & rmt;
        let mut proc_set = None;
        let (blocks, inodes) = match kind {
            FsType::Tmpfs | FsType::Rootfs => {
                let ram = self.fs.ns.ram_pages;
                let opts = match parse_tmpfs(data, ram, want) {
                    Parsed::Ok(opts) => opts,
                    Parsed::Err(errno) => return Err(errno.into()),
                    Parsed::Unported => {
                        self.fs.ns.note_unimplemented();
                        return Err(MountFail::Loud);
                    }
                };
                want = (opts.sb_flags & opts.sb_mask) | (want & !opts.sb_mask);
                mask |= opts.sb_mask;
                (opts.blocks, opts.inodes)
            }
            FsType::Proc => {
                let set = parse_proc(data, want)?;
                if set.pidns.is_some() {
                    return Err(Errno::EBUSY.into()); // cannot reconfigure pidns
                }
                want = (set.sb_flags & set.sb_mask) | (want & !set.sb_mask);
                mask |= set.sb_mask;
                // proc_reconfigure runs after reconfigure_super's checks.
                proc_set = Some((set.gid, set.hide_pid, set.pidonly));
                (None, None)
            }
        };
        // reconfigure_super
        if mask & !rmt != 0 {
            return Err(Errno::EINVAL.into());
        }
        let ro = want & SB_RDONLY != 0;
        let to_ro = ro && !was_ro;
        if to_ro && self.writers(sb) {
            return Err(Errno::EBUSY.into()); // sb_prepare_remount_readonly
        }
        if kind != FsType::Proc {
            self.fs.tmp_mut().reconfigure(sb, blocks, inodes)?;
        }
        let _ = env;
        let info = self.fs.ns.sb_mut(sb);
        if let Some((gid, hide, pidonly)) = proc_set {
            // proc_apply_options
            if let Some(gid) = gid {
                info.proc.gid = gid;
            }
            if let Some(hide) = hide {
                info.proc.hide_pid = hide;
            }
            if let Some(pidonly) = pidonly {
                info.proc.pidonly = pidonly;
            }
        }
        info.flags = (info.flags & !mask) | (want & mask);
        if kind != FsType::Proc {
            self.fs.tmp_mut().set_rdonly(sb, ro);
        }
        self.set_mount_attributes(mnt_id, mnt_flags);
        Ok(())
    }

    /// `set_mount_attributes`.
    fn set_mount_attributes(&mut self, id: u32, mnt_flags: u32) {
        if let Some(mount) = self.fs.ns.mounts.iter_mut().find(|m| m.id == id) {
            mount.flags = mnt_flags | (mount.flags & !MNT_USER_SETTABLE_MASK);
            self.fs.ns.event += 1; // set_mount_attributes: touch_mnt_namespace
        }
    }

    /// `do_reconfigure_mnt` (`MS_REMOUNT | MS_BIND`).
    fn do_reconfigure_mnt(&mut self, point: InodeId, mnt_flags: u32) -> MResult<()> {
        let Some(mount) = self.fs.mount_of(point) else {
            return Err(Errno::EINVAL.into());
        };
        if mount.root != point {
            return Err(Errno::EINVAL.into());
        }
        let (id, sb) = (mount.id, mount.sb);
        // change_mount_ro_state
        let readonly_request = mnt_flags & MNT_READONLY != 0;
        let is_ro = self.fs.mnt_is_readonly(point);
        if readonly_request != is_ro && readonly_request && self.writers(sb) {
            return Err(Errno::EBUSY.into()); // mnt_make_readonly
        }
        self.set_mount_attributes(id, mnt_flags);
        Ok(())
    }

    /// `do_change_type`.
    fn do_change_type(&mut self, point: InodeId, ms_flags: u64) -> MResult<()> {
        let Some(mount) = self.fs.mount_of(point) else {
            return Err(Errno::EINVAL.into());
        };
        if mount.root != point {
            return Err(Errno::EINVAL.into()); // !path_mounted
        }
        let root = mount.id;
        // flags_to_propagation_type
        let ty = ms_flags & !(MS_REC | MS_SILENT);
        let allowed = MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE;
        if ty & !allowed != 0 || !ty.is_power_of_two() {
            return Err(Errno::EINVAL.into());
        }
        let recurse = ms_flags & MS_REC != 0;
        // The mounts to change: the mount, and with MS_REC the tree below it.
        let mut ids: Vec<u32> = Vec::new();
        super::try_push(&mut ids, root)?;
        if recurse {
            let mut at = 0;
            while at < ids.len() {
                let parent = ids[at];
                // Collected by index so the borrow of the table ends before the push.
                let mut index = 0;
                while let Some(m) = self.fs.ns.mounts.get(index) {
                    index += 1;
                    if m.parent == parent && m.id != parent {
                        let id = m.id;
                        super::try_push(&mut ids, id)?;
                    }
                }
                at += 1;
            }
        }
        // MS_SHARED first invents the group ids (`invent_group_ids`), so a
        // failure leaves every mount as it was.
        if ty == MS_SHARED {
            for &id in &ids {
                let needs = self
                    .fs
                    .ns
                    .mount(id)
                    .is_some_and(|m| m.prop.shared.is_none());
                if needs {
                    let group = self.fs.ns.alloc_group_id()?;
                    if let Some(m) = self.fs.ns.mounts.iter_mut().find(|m| m.id == id) {
                        m.prop.shared = Some(group);
                    }
                }
            }
            return Ok(());
        }
        for &id in &ids {
            let released = self
                .fs
                .ns
                .mounts
                .iter_mut()
                .find(|m| m.id == id)
                .and_then(|m| {
                    let group = m.prop.shared.take();
                    // change_mnt_propagation: SLAVE leaves T_UNBINDABLE alone.
                    if ty != MS_SLAVE {
                        m.prop.unbindable = ty == MS_UNBINDABLE;
                    }
                    group
                });
            if let Some(group) = released {
                self.fs.ns.free_group_id(group);
            }
        }
        Ok(())
    }

    // ---- umount2(2) ------------------------------------------------------------------

    /// `path_umount` after `ksys_umount` validated `flags` and resolved
    /// `target` (`LOOKUP_MOUNTPOINT`).
    ///
    /// # Errors
    /// `EPERM`, `EINVAL`, `EBUSY`, `EAGAIN`.
    pub fn do_umount(&mut self, env: &Env, target: InodeId, flags: u32) -> KResult<()> {
        self.reap();
        // can_umount
        if !env.cred.sys_admin {
            return Err(Errno::EPERM);
        }
        let Some(mount) = self.fs.mount_of(target) else {
            return Err(Errno::EINVAL);
        };
        if mount.root != target {
            return Err(Errno::EINVAL); // !path_mounted
        }
        let id = mount.id;
        let sb = mount.sb;
        let is_root_mount = self.fs.mount_of(env.root).is_some_and(|m| m.id == id);
        // do_umount: MNT_EXPIRE
        if flags & MNT_EXPIRE != 0 {
            if is_root_mount || flags & (MNT_FORCE | MNT_DETACH) != 0 {
                return Err(Errno::EINVAL);
            }
            if self.mount_busy(id, sb) {
                return Err(Errno::EBUSY);
            }
            let mark = self
                .fs
                .ns
                .mounts
                .iter_mut()
                .find(|m| m.id == id)
                .map(|m| core::mem::replace(&mut m.expiry_mark, true));
            if mark == Some(false) {
                return Err(Errno::EAGAIN);
            }
        }
        // Unmounting the root remounts it read-only.
        if is_root_mount && flags & MNT_DETACH == 0 {
            return self.do_umount_root(sb);
        }
        // The absolute root of the namespace cannot be detached.
        if self.fs.ns.mount(id).is_some_and(|m| m.parent == m.id) {
            return Err(Errno::EINVAL);
        }
        if flags & MNT_DETACH == 0 && self.mount_busy(id, sb) {
            return Err(Errno::EBUSY);
        }
        let removed = self.fs.ns.detach_tree(id)?;
        for mount in removed {
            self.release_mount(&mount);
        }
        Ok(())
    }

    /// `propagate_mount_busy(mnt, 2)`: a child mount, or a holder of the
    /// mount beyond the namespace's own reference.
    fn mount_busy(&self, id: u32, sb: SbId) -> bool {
        self.fs.ns.has_children(id) || self.sb_pins(sb) != 0
    }

    /// Pins on the superblock's nodes.
    fn sb_pins(&self, sb: SbId) -> u64 {
        match self.fs.ns.sb(sb).fstype {
            FsType::Proc => self.fs.ns.sb(sb).pins,
            _ => self.fs.tmp().sb_pins(sb),
        }
    }

    /// `do_umount_root`: remount the root superblock read-only.
    fn do_umount_root(&mut self, sb: SbId) -> KResult<()> {
        let was_ro = self.fs.ns.sb(sb).flags & SB_RDONLY != 0;
        if !was_ro {
            if self.writers(sb) {
                return Err(Errno::EBUSY);
            }
            self.fs.ns.sb_mut(sb).flags |= SB_RDONLY;
            self.fs.tmp_mut().set_rdonly(sb, true);
        }
        Ok(())
    }

    /// The last reference of a detached mount: free its superblock or park its
    /// ids until the superblock dies.
    fn release_mount(&mut self, mount: &Mount) {
        let sb = mount.sb;
        if self.fs.ns.sb(sb).fstype == FsType::Proc {
            let info = self.fs.ns.sb_mut(sb);
            info.detached = true;
            if info.pins == 0 {
                self.fs.ns.free_mnt_id(mount.id);
                self.fs.ns.free_sb(sb);
            } else {
                // The ids return when the last pin goes (`reap`); if the
                // parking fails the ids are leaked, never reused wrongly.
                let _ = self.fs.ns.defer_release(sb, mount.id, mount.flags);
            }
        } else {
            self.fs.tmp_mut().detach_sb(sb);
            if self.fs.tmp().has_sb(sb) {
                let _ = self.fs.ns.defer_release(sb, mount.id, mount.flags);
            } else {
                self.fs.ns.free_mnt_id(mount.id);
                self.fs.ns.free_sb(sb);
            }
        }
    }

    // ---- /proc/<pid>/mounts, mountinfo -------------------------------------------------------

    /// `show_sb_opts`.
    fn show_sb_flags(seq: &mut Seq, info: &SbInfo) -> KResult<()> {
        for (flag, text) in [
            (SB_SYNCHRONOUS, ",sync"),
            (SB_DIRSYNC, ",dirsync"),
            (SB_MANDLOCK, ",mand"),
            (SB_LAZYTIME, ",lazytime"),
        ] {
            if info.flags & flag != 0 {
                seq.puts(text)?;
            }
        }
        Ok(())
    }

    /// `sb->s_op->show_options` of the superblock of mount `m`.
    fn show_fs_options(&self, seq: &mut Seq, m: &Mount) -> KResult<()> {
        let info = self.fs.ns.sb(m.sb);
        if info.fstype == FsType::Proc {
            // proc_show_options
            if info.proc.gid != 0 {
                // from_kgid_munged: the invalid id (gid_t)-1 shows as the overflow gid.
                let gid = if info.proc.gid == u32::MAX {
                    OVERFLOWGID
                } else {
                    info.proc.gid
                };
                seq::print(seq, format_args!(",gid={gid}"))?;
            }
            if info.proc.hide_pid != HidePid::Off {
                seq::print(seq, format_args!(",hidepid={}", info.proc.hide_pid.name()))?;
            }
            if info.proc.pidonly {
                seq.puts(",subset=pid")?;
            }
        } else {
            // shmem_show_options
            let (blocks, _, inodes, _) = self.fs.tmp().sb_usage(m.sb);
            let ns = &self.fs.ns;
            if blocks != ns.default_max_blocks() {
                seq::print(seq, format_args!(",size={}k", blocks * 4))?;
            }
            if inodes != ns.default_max_inodes() {
                seq::print(seq, format_args!(",nr_inodes={inodes}"))?;
            }
            let tmp = self.fs.tmp().sb(m.sb);
            if tmp.mode != (super::S_ISVTX | 0o777) {
                seq::print(seq, format_args!(",mode={:03o}", tmp.mode))?;
            }
            if tmp.uid != 0 {
                seq::print(seq, format_args!(",uid={}", tmp.uid))?;
            }
            if tmp.gid != 0 {
                seq::print(seq, format_args!(",gid={}", tmp.gid))?;
            }
        }
        Ok(())
    }

    /// `show_vfsmnt_opts`.
    fn show_mnt_options(seq: &mut Seq, flags: u32) -> KResult<()> {
        for (flag, text) in [
            (MNT_NOSUID, ",nosuid"),
            (MNT_NODEV, ",nodev"),
            (MNT_NOEXEC, ",noexec"),
            (MNT_NOATIME, ",noatime"),
            (MNT_NODIRATIME, ",nodiratime"),
            (MNT_RELATIME, ",relatime"),
            (MNT_NOSYMFOLLOW, ",nosymfollow"),
        ] {
            if flags & flag != 0 {
                seq.puts(text)?;
            }
        }
        Ok(())
    }

    /// The path of the mountpoint of `m` below `root`, or `None` when it is
    /// outside the root (`SEQ_SKIP`).
    fn mount_path(&self, root: InodeId, m: &Mount) -> KResult<Option<Vec<u8>>> {
        let (path, reachable) = self.fs.d_path(root, m.root)?;
        Ok(reachable.then_some(path))
    }

    /// `/proc/<pid>/mounts` (`show_vfsmnt`) for a reader whose root is `root`.
    ///
    /// # Errors
    /// `ENOMEM`.
    pub fn show_mounts(&self, root: InodeId, seq: &mut Seq) -> KResult<()> {
        for m in &self.fs.ns.mounts {
            let Some(path) = self.mount_path(root, m)? else {
                continue;
            };
            let info = self.fs.ns.sb(m.sb);
            seq.escape(&m.devname, b" \t\n\\#")?;
            seq.putc(b' ')?;
            seq.escape(&path, b" \t\n\\")?;
            seq.putc(b' ')?;
            seq.escape(info.fstype.name().as_bytes(), b" \t\n\\#")?;
            let ro = m.flags & MNT_READONLY != 0 || info.flags & SB_RDONLY != 0;
            seq.puts(if ro { " ro" } else { " rw" })?;
            Self::show_sb_flags(seq, info)?;
            Self::show_mnt_options(seq, m.flags)?;
            self.show_fs_options(seq, m)?;
            seq.puts(" 0 0\n")?;
            seq.end_record()?;
        }
        Ok(())
    }

    /// `/proc/<pid>/mountinfo` (`show_mountinfo`).
    ///
    /// # Errors
    /// `ENOMEM`.
    pub fn show_mountinfo(&self, root: InodeId, seq: &mut Seq) -> KResult<()> {
        for m in &self.fs.ns.mounts {
            let Some(path) = self.mount_path(root, m)? else {
                continue;
            };
            let info = self.fs.ns.sb(m.sb);
            seq::print(
                seq,
                format_args!("{} {} {}:{} / ", m.id, m.parent, 0, info.dev),
            )?;
            seq.escape(&path, b" \t\n\\")?;
            seq.puts(if m.flags & MNT_READONLY != 0 {
                " ro"
            } else {
                " rw"
            })?;
            Self::show_mnt_options(seq, m.flags)?;
            if let Some(group) = m.prop.shared {
                seq::print(seq, format_args!(" shared:{group}"))?;
            }
            if m.prop.unbindable {
                seq.puts(" unbindable")?;
            }
            seq.puts(" - ")?;
            seq.escape(info.fstype.name().as_bytes(), b" \t\n\\#")?;
            seq.putc(b' ')?;
            seq.escape(&m.devname, b" \t\n\\#")?;
            seq.puts(if info.flags & SB_RDONLY != 0 {
                " ro"
            } else {
                " rw"
            })?;
            Self::show_sb_flags(seq, info)?;
            self.show_fs_options(seq, m)?;
            seq.putc(b'\n')?;
            seq.end_record()?;
        }
        Ok(())
    }

    /// `statx`'s `stx_mnt_id`: the mount of `inode`.
    #[must_use]
    pub fn mnt_id_of(&self, inode: InodeId) -> u32 {
        self.fs.mount_of(inode).map_or(1, |m| m.id)
    }

    /// The type bits of an inode, for callers outside this module.
    #[must_use]
    pub fn mode_type(&self, inode: InodeId) -> u32 {
        self.fs.node_attr(inode).mode & S_IFMT
    }
}
