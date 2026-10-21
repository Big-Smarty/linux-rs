// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: fs/open.c (GPL-2.0:
// `chmod_common`, `SYSCALL_DEFINE2(fchmod)`, `do_fchmodat`, `chown_common`,
// `do_fchownat`, `ksys_fchown`, `vfs_truncate`, `do_sys_truncate`),
// fs/utimes.c (`vfs_utimes`, `do_utimes_path`, `do_utimes_fd`, `do_utimes`,
// `SYSCALL_DEFINE4(utimensat)`, `do_futimesat`, `SYSCALL_DEFINE2(utime)`),
// fs/attr.c (`notify_change`, `may_setattr`, `setattr_prepare`, `chown_ok`,
// `chgrp_ok`), fs/sync.c (`SYSCALL_DEFINE0(sync)`, `SYSCALL_DEFINE1(syncfs)`,
// `do_fsync`, `vfs_fsync_range`), drivers/char/mem.c (the character devices
// have no `->fsync`), arch/x86/entry/syscalls/syscall_64.tbl. All GPL-2.0 /
// GPL-2.0-only.
// Transformation: the attribute changes are `vfs::ops` (`chmod`, `chown`,
// `utimens`, `truncate_check`); this file reads the arguments, resolves the
// path or descriptor in Linux's order and maps the results.
// x86_64 only: the narrowing casts below are the C types of the Linux ABI
// (`int dfd`, `uid_t`, `umode_t`, `unsigned int`) reproduced on purpose.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
//! Attribute syscalls: `chmod`, `chown`, `utimensat` and its relatives,
//! `truncate`, `fsync`, `fdatasync`, `sync` and `syncfs`.
//!
//! Context: task context, never sleeps. Nothing here reaches a device: the only
//! file system is tmpfs, whose `->fsync` is `noop_fsync` and whose writeback
//! does not exist, so the sync calls validate the descriptor and succeed
//! exactly where Linux's do.

use syscalls::{Errno, Sysno};

use super::{
    Context, Outcome, Stop, Sys,
    fd::fdget,
    fs::{env_for_at, getname},
    outcome,
};
use crate::{
    task::RLIM_INFINITY,
    usercopy::copy_from_user,
    vfs::{
        AT_EMPTY_PATH, AT_FDCWD, AT_SYMLINK_NOFOLLOW, InodeId, file::FileKind, ops::UTIME_OMIT,
        path::LOOKUP_FOLLOW,
    },
};

pub(super) fn dispatch<C: Context>(ctx: &mut C, sysno: Sysno, a: [u64; 6]) -> Option<Outcome> {
    let result = match sysno {
        Sysno::chmod => fchmodat(ctx, AT_FDCWD, a[0], a[1], 0),
        Sysno::fchmodat => fchmodat(ctx, dfd(a[0]), a[1], a[2], 0),
        Sysno::fchmodat2 => fchmodat(ctx, dfd(a[0]), a[1], a[2], a[3]),
        Sysno::fchmod => fchmod(ctx, a[0], a[1]),
        Sysno::chown => fchownat(ctx, AT_FDCWD, a[0], a[1], a[2], 0),
        Sysno::lchown => fchownat(
            ctx,
            AT_FDCWD,
            a[0],
            a[1],
            a[2],
            u64::from(AT_SYMLINK_NOFOLLOW),
        ),
        Sysno::fchownat => fchownat(ctx, dfd(a[0]), a[1], a[2], a[3], a[4]),
        Sysno::fchown => fchown(ctx, a[0], a[1], a[2]),
        Sysno::utimensat => utimensat(ctx, dfd(a[0]), a[1], a[2], a[3]),
        Sysno::futimesat => futimesat(ctx, dfd(a[0]), a[1], a[2]),
        Sysno::utimes => futimesat(ctx, AT_FDCWD, a[0], a[1]),
        Sysno::utime => utime(ctx, a[0], a[1]),
        Sysno::truncate => truncate(ctx, a[0], a[1]),
        Sysno::fsync | Sysno::fdatasync => fsync(ctx, a[0]),
        Sysno::syncfs => syncfs(ctx, a[0]),
        // `ksys_sync`: no block device, no dirty page cache beyond tmpfs's own.
        Sysno::sync => Ok(0),
        _ => return None,
    };
    Some(outcome(sysno as u32, result))
}

/// A syscall `int dfd` argument.
fn dfd(raw: u64) -> i32 {
    raw as i32
}

/// `user_path_at`: the inode a path names, `LOOKUP_FOLLOW` unless `nofollow`,
/// an empty name only with `AT_EMPTY_PATH`.
fn user_path_at<C: Context>(
    ctx: &mut C,
    dfd: i32,
    path: u64,
    nofollow: bool,
    empty_ok: bool,
) -> Result<(crate::vfs::ops::Env, InodeId), Stop> {
    let name = getname(ctx, path, empty_ok)?;
    let env = env_for_at(ctx, dfd, &name)?;
    let flags = if nofollow { 0 } else { LOOKUP_FOLLOW };
    let inode = ctx.files().vfs.lookup(&env, &name, flags)?;
    Ok((env, inode))
}

/// The environment of a descriptor's own inode for the checks of an operation
/// on an open file (`f_path`).
fn fd_inode<C: Context>(ctx: &mut C, fd: u64) -> Result<(crate::vfs::ops::Env, InodeId), Stop> {
    let view = fdget(ctx, fd, false)?;
    // A pipe's inode is not part of the file system model.
    if matches!(view.kind, FileKind::Pipe { .. }) {
        return Err(Stop::Unimplemented);
    }
    let inode = view.inode.ok_or(Stop::Unimplemented)?;
    let cred = ctx.cred();
    let tgid = i32::try_from(ctx.tgid()).unwrap_or(0);
    let files = ctx.files();
    let env = crate::vfs::ops::Env {
        root: files.fs.root,
        start: files.fs.pwd,
        cred,
        umask: files.fs.umask,
        tgid,
    };
    Ok((env, inode))
}

/// The attribute changes of a procfs node (`proc_setattr`, `proc_notify_change`) are not
/// ported: the call stops the kernel rather than answer as a tmpfs inode would.
///
/// shortcut: stops loudly, ported with the procfs `setattr` operations.
fn not_proc(inode: InodeId) -> Result<(), Stop> {
    if inode.is_proc() {
        Err(Stop::Unimplemented)
    } else {
        Ok(())
    }
}

// ---- chmod -----------------------------------------------------------------------------

/// `do_fchmodat`: `mode` is a `umode_t`.
fn fchmodat<C: Context>(ctx: &mut C, dfd: i32, path: u64, mode: u64, flags: u64) -> Sys {
    let flags = flags as u32;
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(Errno::EINVAL.into());
    }
    let (env, inode) = user_path_at(
        ctx,
        dfd,
        path,
        flags & AT_SYMLINK_NOFOLLOW != 0,
        flags & AT_EMPTY_PATH != 0,
    )?;
    not_proc(inode)?;
    ctx.files().vfs.chmod(&env, inode, u32::from(mode as u16))?;
    Ok(0)
}

fn fchmod<C: Context>(ctx: &mut C, fd: u64, mode: u64) -> Sys {
    let (env, inode) = fd_inode(ctx, fd)?;
    not_proc(inode)?;
    ctx.files().vfs.chmod(&env, inode, u32::from(mode as u16))?;
    Ok(0)
}

// ---- chown -----------------------------------------------------------------------------

/// `do_fchownat`: `user` and `group` are `uid_t`/`gid_t` (`-1` keeps the id).
fn fchownat<C: Context>(ctx: &mut C, dfd: i32, path: u64, user: u64, group: u64, flag: u64) -> Sys {
    let flag = flag as u32;
    if flag & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(Errno::EINVAL.into());
    }
    let (env, inode) = user_path_at(
        ctx,
        dfd,
        path,
        flag & AT_SYMLINK_NOFOLLOW != 0,
        flag & AT_EMPTY_PATH != 0,
    )?;
    not_proc(inode)?;
    ctx.files()
        .vfs
        .chown(&env, inode, user as u32, group as u32)?;
    Ok(0)
}

fn fchown<C: Context>(ctx: &mut C, fd: u64, user: u64, group: u64) -> Sys {
    let (env, inode) = fd_inode(ctx, fd)?;
    not_proc(inode)?;
    ctx.files()
        .vfs
        .chown(&env, inode, user as u32, group as u32)?;
    Ok(0)
}

// ---- utimes ----------------------------------------------------------------------------

/// `do_utimes`: a NULL `filename` with a descriptor in `dfd` works on the open
/// file (and takes no flags), otherwise the path is resolved.
fn do_utimes<C: Context>(
    ctx: &mut C,
    dfd: i32,
    filename: u64,
    times: Option<[(i64, i64); 2]>,
    flags: u32,
) -> Sys {
    let (env, inode) = if filename == 0 && dfd != AT_FDCWD {
        if flags != 0 {
            return Err(Errno::EINVAL.into());
        }
        fd_inode(ctx, u64::from(dfd as u32))?
    } else {
        if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
            return Err(Errno::EINVAL.into());
        }
        user_path_at(
            ctx,
            dfd,
            filename,
            flags & AT_SYMLINK_NOFOLLOW != 0,
            flags & AT_EMPTY_PATH != 0,
        )?
    };
    not_proc(inode)?;
    ctx.files().vfs.utimens(&env, inode, times)?;
    Ok(0)
}

fn read_words<C: Context, const N: usize>(ctx: &mut C, at: u64) -> Result<[i64; N], Errno> {
    let mut raw = [[0u8; 8]; N];
    for (i, word) in raw.iter_mut().enumerate() {
        if copy_from_user(ctx, word, at.wrapping_add(8 * i as u64)) != 0 {
            return Err(Errno::EFAULT);
        }
    }
    Ok(raw.map(i64::from_le_bytes))
}

/// `SYSCALL_DEFINE4(utimensat)`: both times `UTIME_OMIT` does nothing, not even
/// look at the path.
fn utimensat<C: Context>(ctx: &mut C, dfd: i32, filename: u64, utimes: u64, flags: u64) -> Sys {
    let times = if utimes == 0 {
        None
    } else {
        let [as_, an, ms, mn] = read_words::<C, 4>(ctx, utimes)?;
        if an == UTIME_OMIT && mn == UTIME_OMIT {
            return Ok(0);
        }
        Some([(as_, an), (ms, mn)])
    };
    do_utimes(ctx, dfd, filename, times, flags as u32)
}

/// `do_futimesat` (`futimesat` and `utimes`): `struct timeval[2]`.
fn futimesat<C: Context>(ctx: &mut C, dfd: i32, filename: u64, utimes: u64) -> Sys {
    let times = if utimes == 0 {
        None
    } else {
        let [as_, au, ms, mu] = read_words::<C, 4>(ctx, utimes)?;
        // Catches every invalid value, including UTIME_NOW/OMIT, which only
        // `utimensat` accepts.
        if !(0..1_000_000).contains(&au) || !(0..1_000_000).contains(&mu) {
            return Err(Errno::EINVAL.into());
        }
        Some([(as_, 1000 * au), (ms, 1000 * mu)])
    };
    do_utimes(ctx, dfd, filename, times, 0)
}

/// `SYSCALL_DEFINE2(utime)`: `struct utimbuf { actime; modtime }`.
fn utime<C: Context>(ctx: &mut C, filename: u64, times: u64) -> Sys {
    let times = if times == 0 {
        None
    } else {
        let [actime, modtime] = read_words::<C, 2>(ctx, times)?;
        Some([(actime, 0), (modtime, 0)])
    };
    do_utimes(ctx, AT_FDCWD, filename, times, 0)
}

// ---- truncate --------------------------------------------------------------------------

/// `do_sys_truncate`: `long length`.
fn truncate<C: Context>(ctx: &mut C, path: u64, length: u64) -> Sys {
    let length = length as i64;
    if length < 0 {
        return Err(Errno::EINVAL.into());
    }
    let (env, inode) = user_path_at(ctx, AT_FDCWD, path, false, false)?;
    // vfs_truncate: type and write permission; then notify_change's
    // setattr_prepare -> inode_newsize_ok.
    ctx.files().vfs.truncate_check(&env, inode)?;
    if inode.is_proc() {
        // `proc_setattr` ignores ATTR_SIZE: truncating a procfs file is a no-op.
        return Ok(0);
    }
    let size = ctx.files().vfs.fs.inode(inode).size;
    if size < length as u64 {
        let limit = ctx.rlimit_fsize();
        if limit != RLIM_INFINITY && length as u64 > limit {
            ctx.state().send_sig(crate::signal::SIGXFSZ);
            return Err(Errno::EFBIG.into());
        }
    }
    ctx.files().vfs.do_truncate(&env.cred, inode, length as u64);
    Ok(0)
}

// ---- sync ------------------------------------------------------------------------------

/// `do_fsync`: `vfs_fsync_range` is `-EINVAL` without a `->fsync`, which
/// regular files and directories of tmpfs have (`noop_fsync`) and pipes, the
/// console and the memory devices do not.
fn fsync<C: Context>(ctx: &mut C, fd: u64) -> Sys {
    let view = fdget(ctx, fd, false)?;
    match view.kind {
        // procfs has no `->fsync` (`proc_reg_file_ops`, `proc_dir_operations`).
        FileKind::Directory if view.inode.is_some_and(InodeId::is_proc) => {
            Err(Errno::EINVAL.into())
        }
        FileKind::Regular | FileKind::Directory => Ok(0),
        FileKind::Pipe { .. } | FileKind::Char(_) | FileKind::Proc => Err(Errno::EINVAL.into()),
        FileKind::Path => Err(Errno::EBADF.into()),
        FileKind::Unsupported => Err(Stop::Unimplemented),
    }
}

/// `SYSCALL_DEFINE1(syncfs)`: `CLASS(fd, f)` (no `O_PATH`), then
/// `sync_filesystem` of a writable tmpfs, which has nothing to write.
fn syncfs<C: Context>(ctx: &mut C, fd: u64) -> Sys {
    let view = fdget(ctx, fd, false)?;
    if matches!(view.kind, FileKind::Unsupported) {
        return Err(Stop::Unimplemented);
    }
    Ok(0)
}
