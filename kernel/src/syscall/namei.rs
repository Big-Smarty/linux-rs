// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: fs/namei.c (GPL-2.0:
// `SYSCALL_DEFINE3(mkdirat)`, `SYSCALL_DEFINE2(mkdir)`, `do_mkdirat`,
// `SYSCALL_DEFINE1(rmdir)`, `do_rmdir`, `SYSCALL_DEFINE3(unlinkat)`,
// `do_symlinkat`, `SYSCALL_DEFINE3(symlinkat)`, `SYSCALL_DEFINE2(symlink)`,
// `do_linkat`, `SYSCALL_DEFINE5(linkat)`, `SYSCALL_DEFINE2(link)`,
// `do_renameat2`, `SYSCALL_DEFINE5(renameat2)`, `SYSCALL_DEFINE4(renameat)`,
// `SYSCALL_DEFINE2(rename)`), include/linux/syscalls.h and
// arch/x86/entry/syscalls/syscall_64.tbl. All GPL-2.0 / GPL-2.0-only.
// Transformation: the names are copied from user memory once, as `getname`
// does, and their errors are kept as values so that the order in which
// `do_linkat`/`do_renameat2`/`do_symlinkat` look at them is Linux's; the
// walks, permission checks and the tmpfs operations are `vfs::ops`.
// x86_64 only: the narrowing casts below are the C types of the Linux ABI
// (`int dfd`, `umode_t`, `unsigned int flags`) reproduced on purpose.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
//! Syscalls that create, remove and rename names: `mkdir`, `rmdir`,
//! `symlink`, `link`, `rename` and their `*at` forms.
//!
//! Context: task context, never sleeps. `RENAME_EXCHANGE` and
//! `RENAME_WHITEOUT` pass every check and then stop loudly
//! ([`Outcome::Unimplemented`]); everything else is complete.

use alloc::vec::Vec;
use syscalls::{Errno, Sysno};

use super::{
    Context, Outcome, Stop, Sys,
    fs::{env_for, env_for_at, getname},
    outcome,
};
use crate::vfs::{
    AT_EMPTY_PATH, AT_FDCWD, AT_REMOVEDIR, AT_SYMLINK_FOLLOW, ops::Renamed, path::LOOKUP_FOLLOW,
};

pub(super) fn dispatch<C: Context>(ctx: &mut C, sysno: Sysno, a: [u64; 6]) -> Option<Outcome> {
    let result = match sysno {
        Sysno::mkdir => mkdirat(ctx, AT_FDCWD, a[0], a[1]),
        Sysno::mkdirat => mkdirat(ctx, dfd(a[0]), a[1], a[2]),
        Sysno::rmdir => rmdir(ctx, AT_FDCWD, a[0]),
        Sysno::unlinkat => unlinkat(ctx, dfd(a[0]), a[1], a[2]),
        Sysno::symlink => symlinkat(ctx, a[0], AT_FDCWD, a[1]),
        Sysno::symlinkat => symlinkat(ctx, a[0], dfd(a[1]), a[2]),
        Sysno::link => linkat(ctx, AT_FDCWD, a[0], AT_FDCWD, a[1], 0),
        Sysno::linkat => linkat(ctx, dfd(a[0]), a[1], dfd(a[2]), a[3], a[4]),
        Sysno::rename => renameat2(ctx, AT_FDCWD, a[0], AT_FDCWD, a[1], 0),
        Sysno::renameat => renameat2(ctx, dfd(a[0]), a[1], dfd(a[2]), a[3], 0),
        Sysno::renameat2 => renameat2(ctx, dfd(a[0]), a[1], dfd(a[2]), a[3], a[4]),
        _ => return None,
    };
    Some(outcome(sysno as u32, result))
}

/// A syscall `int dfd` argument.
fn dfd(raw: u64) -> i32 {
    raw as i32
}

/// `do_mkdirat`: `mode` is a `umode_t`.
fn mkdirat<C: Context>(ctx: &mut C, dfd: i32, path: u64, mode: u64) -> Sys {
    let name = getname(ctx, path, false)?;
    let env = env_for(ctx, dfd, &name)?;
    ctx.files().vfs.mkdir(&env, &name, u32::from(mode as u16))?;
    Ok(0)
}

/// `do_rmdir`.
pub(super) fn rmdir<C: Context>(ctx: &mut C, dfd: i32, path: u64) -> Sys {
    let name = getname(ctx, path, false)?;
    let env = env_for(ctx, dfd, &name)?;
    ctx.files().vfs.rmdir(&env, &name)?;
    Ok(0)
}

/// `unlinkat`: only `AT_REMOVEDIR` is a flag, checked before the name is read.
fn unlinkat<C: Context>(ctx: &mut C, dfd: i32, path: u64, flag: u64) -> Sys {
    let flag = flag as u32;
    if flag & !AT_REMOVEDIR != 0 {
        return Err(Errno::EINVAL.into());
    }
    if flag & AT_REMOVEDIR != 0 {
        return rmdir(ctx, dfd, path);
    }
    super::fs::unlink(ctx, dfd, path)
}

/// `do_symlinkat`: both names are read first; the target's error comes before
/// the link name's.
fn symlinkat<C: Context>(ctx: &mut C, oldname: u64, newdfd: i32, newname: u64) -> Sys {
    let from = getname(ctx, oldname, false);
    let to = getname(ctx, newname, false);
    let from = from?;
    let to = to?;
    let env = env_for(ctx, newdfd, &to)?;
    ctx.files().vfs.symlink(&env, &from, &to)?;
    Ok(0)
}

/// `do_linkat`. The flags come first, then the old name's error, the old
/// lookup, the new name's error and the creation.
fn linkat<C: Context>(
    ctx: &mut C,
    olddfd: i32,
    oldname: u64,
    newdfd: i32,
    newname: u64,
    flags: u64,
) -> Sys {
    let flags = flags as u32;
    let empty_ok = flags & AT_EMPTY_PATH != 0;
    // getname_uflags(oldname, flags), getname(newname)
    let old = getname(ctx, oldname, empty_ok);
    let new = getname(ctx, newname, false);
    if flags & !(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(Errno::EINVAL.into());
    }
    let old = old?;
    // `LOOKUP_LINKAT_EMPTY` (fs/namei.c:2641-2646, `path_init`): only a walk relative to a
    // descriptor checks that a descriptor opened with other credentials needs
    // CAP_DAC_READ_SEARCH. The open-time credentials are not recorded, so the one case that
    // depends on them (an unprivileged caller) stops loudly.
    if empty_ok && olddfd != AT_FDCWD && old.first() != Some(&b'/') && !ctx.cred().dac_read_search {
        return Err(Stop::Unimplemented);
    }
    let lookup = if flags & AT_SYMLINK_FOLLOW != 0 {
        LOOKUP_FOLLOW
    } else {
        0
    };
    let old_env = env_for_at(ctx, olddfd, &old)?;
    // filename_lookup(old) precedes filename_create(new): the new name's own
    // errors (and the walk of its parent) are only seen once the old one exists.
    let vfs = &mut *ctx.files().vfs;
    let _ = vfs.lookup(&old_env, &old, lookup)?;
    let new = new?;
    let new_env = env_for(ctx, newdfd, &new)?;
    ctx.files()
        .vfs
        .link_at(&old_env, &old, lookup, &new_env, &new)?;
    Ok(0)
}

/// `do_renameat2`: invalid flags first, then the names in order, then the
/// walks. The `Unsupported` outcome (exchange, whiteout) is a loud stop.
fn renameat2<C: Context>(
    ctx: &mut C,
    olddfd: i32,
    oldname: u64,
    newdfd: i32,
    newname: u64,
    flags: u64,
) -> Sys {
    let flags = flags as u32;
    let from = getname(ctx, oldname, false);
    let to = getname(ctx, newname, false);
    let valid = crate::vfs::ops::RENAME_NOREPLACE
        | crate::vfs::ops::RENAME_EXCHANGE
        | crate::vfs::ops::RENAME_WHITEOUT;
    if flags & !valid != 0
        || (flags & (crate::vfs::ops::RENAME_NOREPLACE | crate::vfs::ops::RENAME_WHITEOUT) != 0
            && flags & crate::vfs::ops::RENAME_EXCHANGE != 0)
    {
        return Err(Errno::EINVAL.into());
    }
    let resolve = |ctx: &mut C, dfd: i32, name: Result<Vec<u8>, Errno>| {
        let name = name?;
        let env = env_for(ctx, dfd, &name)?;
        Ok((env, name))
    };
    let old = resolve(ctx, olddfd, from);
    let new = resolve(ctx, newdfd, to);
    match ctx.files().vfs.rename(old, new, flags)? {
        Renamed::Done => Ok(0),
        Renamed::Unsupported => Err(Stop::Unimplemented),
    }
}
