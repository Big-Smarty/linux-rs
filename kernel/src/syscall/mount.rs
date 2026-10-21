// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: fs/namespace.c (GPL-2.0:
// `SYSCALL_DEFINE5(mount)`, `copy_mount_string`, `copy_mount_options`,
// `do_mount`, `SYSCALL_DEFINE2(umount)`, `ksys_umount`), lib/strncpy_from_user.c
// and mm/util.c (`strndup_user`: `EFAULT`/`EINVAL`), fs/namei.c
// (`user_path_at_empty` through `getname_flags`, `LOOKUP_MOUNTPOINT`),
// arch/x86/entry/syscalls/syscall_64.tbl (165 `mount`, 166 `umount2`).
// Copyright of the originals: Linus Torvalds and the VFS authors.
// Transformation: the strings are copied into fallibly allocated vectors; the
// mount logic is `vfs::mountops`.
#![forbid(unsafe_code)]
//! `mount(2)` and `umount2(2)`.
//!
//! Context: task context. The arguments are copied in `SYSCALL_DEFINE5(mount)`'s
//! order (type, device name, options, then the mountpoint path), so the first
//! bad pointer decides the error.

use alloc::vec::Vec;
use syscalls::{Errno, Sysno};

use super::{
    Context, Outcome, Stop, Sys,
    fs::{env_for, getname},
    outcome,
};
use crate::{
    usercopy::{copy_from_user, strncpy_from_user},
    vfs::{
        AT_FDCWD, PAGE_SIZE, PATH_MAX,
        mount::{MNT_DETACH, MNT_EXPIRE, MNT_FORCE, UMOUNT_NOFOLLOW},
        mountops::{MountArgs, MountFail},
        path::LOOKUP_FOLLOW,
        try_copy,
    },
};

pub(super) fn dispatch<C: Context>(ctx: &mut C, sysno: Sysno, a: [u64; 6]) -> Option<Outcome> {
    let result = match sysno {
        Sysno::mount => mount(ctx, a[0], a[1], a[2], a[3], a[4]),
        Sysno::umount2 => umount2(ctx, a[0], a[1]),
        _ => return None,
    };
    Some(outcome(sysno as u32, result))
}

/// `copy_mount_string`: `strndup_user(data, PATH_MAX)`, NULL staying NULL.
fn copy_mount_string<C: Context>(ctx: &mut C, addr: u64) -> Result<Option<Vec<u8>>, Errno> {
    if addr == 0 {
        return Ok(None);
    }
    let mut buf = [0u8; PATH_MAX];
    match strncpy_from_user(ctx, &mut buf, addr) {
        None => Err(Errno::EFAULT),
        // strndup_user: a string longer than the bound is `EINVAL`.
        Some(len) if len == PATH_MAX => Err(Errno::EINVAL),
        Some(len) => try_copy(&buf[..len]).map(Some),
    }
}

/// `copy_mount_options`: up to a page of the options, the NUL forced at its
/// end; `EFAULT` only when not even the first byte is readable.
fn copy_mount_options<C: Context>(ctx: &mut C, addr: u64) -> Result<Option<Vec<u8>>, Errno> {
    if addr == 0 {
        return Ok(None);
    }
    let mut page = Vec::new();
    page.try_reserve_exact(PAGE_SIZE)
        .map_err(|_| Errno::ENOMEM)?;
    for _ in 0..PAGE_SIZE {
        page.push_within_capacity(0).map_err(|_| Errno::ENOMEM)?;
    }
    let left = copy_from_user(ctx, &mut page, addr);
    if left == PAGE_SIZE {
        return Err(Errno::EFAULT);
    }
    page[PAGE_SIZE - 1] = 0;
    Ok(Some(page))
}

fn mount<C: Context>(
    ctx: &mut C,
    dev_name: u64,
    dir_name: u64,
    fstype: u64,
    flags: u64,
    data: u64,
) -> Sys {
    let kernel_type = copy_mount_string(ctx, fstype)?;
    let kernel_dev = copy_mount_string(ctx, dev_name)?;
    let options = copy_mount_options(ctx, data)?;
    // do_mount: user_path_at(AT_FDCWD, dir_name, LOOKUP_FOLLOW)
    let name = getname(ctx, dir_name, false)?;
    let env = env_for(ctx, AT_FDCWD, &name)?;
    let vfs = &mut *ctx.files().vfs;
    let point = vfs.lookup(&env, &name, LOOKUP_FOLLOW)?;
    let args = MountArgs {
        source: kernel_dev.as_deref(),
        point,
        fstype: kernel_type.as_deref(),
        flags,
        data: options.as_deref(),
    };
    match vfs.do_mount(&env, &args) {
        Ok(()) => Ok(0),
        Err(MountFail::Errno(errno)) => Err(errno.into()),
        Err(MountFail::Loud) => Err(Stop::Unimplemented),
    }
}

fn umount2<C: Context>(ctx: &mut C, name: u64, flags: u64) -> Sys {
    #[allow(clippy::cast_possible_truncation)]
    let flags = flags as u32;
    // ksys_umount: the flags are checked before the path is read.
    if flags & !(MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW) != 0 {
        return Err(Errno::EINVAL.into());
    }
    let path = getname(ctx, name, false)?;
    let env = env_for(ctx, AT_FDCWD, &path)?;
    let lookup = if flags & UMOUNT_NOFOLLOW == 0 {
        LOOKUP_FOLLOW
    } else {
        0
    };
    let vfs = &mut *ctx.files().vfs;
    let target = vfs.lookup(&env, &path, lookup)?;
    vfs.do_umount(&env, target, flags)?;
    Ok(0)
}
