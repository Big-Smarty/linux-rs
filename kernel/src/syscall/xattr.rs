// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: fs/xattr.c (GPL-2.0:
// `import_xattr_name`, `xattr_permission`, `may_write_xattr`, `xattr_resolve_name`,
// `vfs_getxattr`, `__vfs_getxattr`, `vfs_listxattr`, `vfs_setxattr`, `__vfs_removexattr`,
// `do_getxattr`, `listxattr`, `setxattr_copy`, `path_{get,list,set,remove}xattrat` and the
// twelve classic system calls), fs/posix_acl.c (`vfs_get_acl`, `do_get_acl`, `posix_acl_type`),
// mm/shmem.c (`shmem_xattr_handlers`, `shmem_listxattr`, `shmem_xattr_handler_get`),
// include/uapi/linux/xattr.h (the prefixes and limits), arch/x86/entry/syscalls/syscall_64.tbl.
// Transformation: the extended attributes of a tmpfs inode live in `simple_xattrs`; this kernel
// has no way to create one yet, so the store is always empty and every read answers what an
// empty store answers. The calls that would create one stop loudly after Linux's checks.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
//! Extended attributes: `getxattr`, `listxattr`, `removexattr` and `setxattr` with their `l` and
//! `f` variants (the `*at` forms of Linux 6.13 as well).
//!
//! Context: task context, never sleeps. A tmpfs inode has the `security.`, `trusted.` and
//! `user.` handlers (`shmem_xattr_handlers`) and POSIX ACLs; procfs has none of them. The tmpfs
//! `simple_xattrs` list of every inode is empty because nothing can add to it.
//!
//! * shortcut: `setxattr` that would create or replace an attribute (and the ACL setters) stop
//!   loudly once Linux's checks have passed; upgrade with the `simple_xattrs` store of the tmpfs
//!   inode (the lists and the reads then follow from it), `fsnotify` is not modelled.
//! * shortcut: every tmpfs is `SB_POSIXACL` (the `noacl` mount option is not looked at).

use syscalls::{Errno, Sysno};

use super::{
    Context, Outcome, Stop, Sys,
    attr::{fd_inode_of, user_path_at},
    fd::fdget,
    outcome,
};
use crate::{
    usercopy::{copy_from_user, strncpy_from_user},
    vfs::{
        AT_EMPTY_PATH, AT_FDCWD, AT_SYMLINK_NOFOLLOW, InodeId, MAY_READ, MAY_WRITE, S_IFMT,
        file::FileKind, ops::Env,
    },
};

/// `XATTR_NAME_MAX` is 255; `import_xattr_name` copies into 256 bytes.
const NAME_BUFFER: usize = 256;
/// `XATTR_SIZE_MAX`.
const XATTR_SIZE_MAX: u64 = 65536;
const XATTR_CREATE: u64 = 1;
const XATTR_REPLACE: u64 = 2;
const S_IFREG: u32 = 0o100_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFLNK: u32 = 0o120_000;
const S_ISVTX: u32 = 0o1000;
/// `sizeof(struct xattr_args)` (`value`, `size`, `flags`) and its first version.
const XATTR_ARGS_SIZE: usize = 24;
/// The `at_flags` the `*xattr*at` calls accept.
const AT_FLAGS_XATTR: u32 = AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH;

pub(super) fn dispatch<C: Context>(ctx: &mut C, sysno: Sysno, a: [u64; 6]) -> Option<Outcome> {
    let result = match sysno {
        Sysno::getxattr => getxattrat(ctx, AT_FDCWD, a[0], 0, a[1], a[2], a[3]),
        Sysno::lgetxattr => getxattrat(ctx, AT_FDCWD, a[0], AT_SYMLINK_NOFOLLOW, a[1], a[2], a[3]),
        Sysno::fgetxattr => getxattrat(ctx, a[0] as i32, 0, AT_EMPTY_PATH, a[1], a[2], a[3]),
        Sysno::getxattrat => getxattrat_args(ctx, a),
        Sysno::listxattr => listxattrat(ctx, AT_FDCWD, a[0], 0, a[1], a[2]),
        Sysno::llistxattr => listxattrat(ctx, AT_FDCWD, a[0], AT_SYMLINK_NOFOLLOW, a[1], a[2]),
        Sysno::flistxattr => listxattrat(ctx, a[0] as i32, 0, AT_EMPTY_PATH, a[1], a[2]),
        Sysno::listxattrat => listxattrat(ctx, a[0] as i32, a[1], a[2] as u32, a[3], a[4]),
        Sysno::removexattr => removexattrat(ctx, AT_FDCWD, a[0], 0, a[1]),
        Sysno::lremovexattr => removexattrat(ctx, AT_FDCWD, a[0], AT_SYMLINK_NOFOLLOW, a[1]),
        Sysno::fremovexattr => removexattrat(ctx, a[0] as i32, 0, AT_EMPTY_PATH, a[1]),
        Sysno::removexattrat => removexattrat(ctx, a[0] as i32, a[1], a[2] as u32, a[3]),
        Sysno::setxattr => setxattrat(ctx, AT_FDCWD, a[0], 0, a[1], a[2], a[3], a[4]),
        Sysno::lsetxattr => setxattrat(
            ctx,
            AT_FDCWD,
            a[0],
            AT_SYMLINK_NOFOLLOW,
            a[1],
            a[2],
            a[3],
            a[4],
        ),
        Sysno::fsetxattr => setxattrat(ctx, a[0] as i32, 0, AT_EMPTY_PATH, a[1], a[2], a[3], a[4]),
        Sysno::setxattrat => setxattrat_args(ctx, a),
        _ => return None,
    };
    Some(outcome(sysno as u32, result))
}

/// `import_xattr_name`: at most 255 bytes and a NUL; an empty or too long name is `ERANGE`.
fn import_xattr_name<C: Context>(
    ctx: &mut C,
    name: u64,
) -> Result<([u8; NAME_BUFFER], usize), Errno> {
    let mut buf = [0u8; NAME_BUFFER];
    match strncpy_from_user(ctx, &mut buf, name) {
        None => Err(Errno::EFAULT),
        Some(0) => Err(Errno::ERANGE),
        Some(len) if len == NAME_BUFFER => Err(Errno::ERANGE),
        Some(len) => Ok((buf, len)),
    }
}

/// The target of a `*xattr*at` call: `getname_maybe_null` (NULL or empty path with
/// `AT_EMPTY_PATH` names the descriptor `dfd`), else the path walk of `lookup_flags`.
fn target<C: Context>(
    ctx: &mut C,
    dfd: i32,
    path: u64,
    at_flags: u32,
) -> Result<(Env, InodeId, bool), Stop> {
    if at_flags & AT_EMPTY_PATH != 0 {
        let by_fd = if path == 0 {
            true
        } else {
            let mut first = [0u8; 1];
            if copy_from_user(ctx, &mut first, path) != 0 {
                return Err(Errno::EFAULT.into());
            }
            first[0] == 0
        };
        if by_fd {
            // `CLASS(fd, f)(dfd)`: an O_PATH descriptor is refused like a closed one. The file's
            // dentry (`f_path.dentry`) is what the call looks at.
            let view = fdget(ctx, u64::from(dfd as u32), false)?;
            let (env, inode) = fd_inode_of(ctx, &view)?;
            return Ok((env, inode, matches!(view.kind, FileKind::Pipe { .. })));
        }
    }
    let (env, inode) = user_path_at(ctx, dfd, path, at_flags & AT_SYMLINK_NOFOLLOW != 0, false)?;
    Ok((env, inode, false))
}

fn unknown_at_flags(at_flags: u32) -> bool {
    at_flags & !AT_FLAGS_XATTR != 0
}

/// `is_posix_acl_xattr`.
fn is_posix_acl_xattr(name: &[u8]) -> bool {
    name == b"system.posix_acl_access" || name == b"system.posix_acl_default"
}

/// What `xattr_resolve_name` finds on a tmpfs inode.
enum Handler {
    /// `security.`, `trusted.` or `user.`, with the (non-empty) rest of the name.
    Known,
    /// A prefix with nothing after it (`-EINVAL`).
    EmptySuffix,
    /// No handler (`-EOPNOTSUPP`).
    None,
}

fn resolve_name(name: &[u8]) -> Handler {
    for prefix in [&b"security."[..], b"trusted.", b"user."] {
        if let Some(rest) = name.strip_prefix(prefix) {
            return if rest.is_empty() {
                Handler::EmptySuffix
            } else {
                Handler::Known
            };
        }
    }
    Handler::None
}

/// The file type bits of an inode (`i_mode & S_IFMT`).
fn file_type<C: Context>(ctx: &mut C, inode: InodeId) -> u32 {
    ctx.files().vfs.fs.node_attr(inode).mode & S_IFMT
}

/// `xattr_permission`. (`may_write_xattr`'s immutable, append-only and unmapped-id refusals
/// never hold here; a read-only mount is `mnt_want_write`'s, before this.)
fn xattr_permission<C: Context>(
    ctx: &mut C,
    env: &Env,
    inode: InodeId,
    name: &[u8],
    mask: u32,
) -> Result<(), Errno> {
    let write = mask & MAY_WRITE != 0;
    // No restriction for security.* and system.* from the VFS.
    if name.starts_with(b"security.") || name.starts_with(b"system.") {
        return Ok(());
    }
    let kind = file_type(ctx, inode);
    // The trusted.* namespace can only be accessed by privileged users.
    if name.starts_with(b"trusted.") {
        if !env.cred.sys_admin {
            return Err(if write { Errno::EPERM } else { Errno::ENODATA });
        }
        return Ok(());
    }
    // In the user.* namespace, only regular files and directories can have extended attributes.
    // For sticky directories, only the owner and privileged users can write attributes.
    if name.starts_with(b"user.") {
        if kind != S_IFREG && kind != S_IFDIR {
            return Err(if write { Errno::EPERM } else { Errno::ENODATA });
        }
        let attr = ctx.files().vfs.fs.node_attr(inode);
        // inode_owner_or_capable
        if kind == S_IFDIR
            && attr.mode & S_ISVTX != 0
            && write
            && env.cred.fsuid != attr.uid
            && !env.cred.fowner
        {
            return Err(Errno::EPERM);
        }
    }
    ctx.files().vfs.fs.permission(env, inode, mask)
}

/// `vfs_getxattr` on an inode whose store is empty.
fn vfs_getxattr<C: Context>(
    ctx: &mut C,
    env: &Env,
    inode: InodeId,
    name: &[u8],
) -> Result<i64, Errno> {
    xattr_permission(ctx, env, inode, name, MAY_READ)?;
    // security_inode_getxattr: no security module. A `security.` name asks the (absent) module
    // first and falls through (`-EOPNOTSUPP`).
    // __vfs_getxattr -> xattr_resolve_name: procfs has no handlers (no IOP_XATTR).
    if inode.is_proc() {
        return Err(Errno::EOPNOTSUPP);
    }
    match resolve_name(name) {
        Handler::None => Err(Errno::EOPNOTSUPP),
        Handler::EmptySuffix => Err(Errno::EINVAL),
        // simple_xattr_get on an empty list.
        Handler::Known => Err(Errno::ENODATA),
    }
}

/// `vfs_get_acl` (via `do_get_acl`) on an inode without an ACL.
fn vfs_get_acl<C: Context>(ctx: &mut C, inode: InodeId) -> Errno {
    // IS_POSIXACL: tmpfs only; symlinks have none.
    if inode.is_proc() || file_type(ctx, inode) == S_IFLNK {
        Errno::EOPNOTSUPP
    } else {
        Errno::ENODATA
    }
}

/// `SYSCALL_DEFINE4(getxattr)` family over `path_getxattrat`.
fn getxattrat<C: Context>(
    ctx: &mut C,
    dfd: i32,
    path: u64,
    at_flags: u32,
    name: u64,
    _value: u64,
    _size: u64,
) -> Sys {
    if unknown_at_flags(at_flags) {
        return Err(Errno::EINVAL.into());
    }
    let (kname, len) = import_xattr_name(ctx, name)?;
    let (env, inode, _pipe) = target(ctx, dfd, path, at_flags)?;
    let kname = &kname[..len];
    if is_posix_acl_xattr(kname) {
        return Err(vfs_get_acl(ctx, inode).into());
    }
    Ok(vfs_getxattr(ctx, &env, inode, kname)?)
}

/// `SYSCALL_DEFINE6(getxattrat)`.
fn getxattrat_args<C: Context>(ctx: &mut C, a: [u64; 6]) -> Sys {
    let [dfd, path, at_flags, name, uargs, usize] = a;
    let args = copy_xattr_args(ctx, uargs, usize)?;
    if args.flags != 0 {
        return Err(Errno::EINVAL.into());
    }
    getxattrat(
        ctx,
        dfd as i32,
        path,
        at_flags as u32,
        name,
        args.value,
        args.size,
    )
}

struct XattrArgs {
    value: u64,
    size: u64,
    flags: u64,
}

/// `copy_struct_from_user(&args, sizeof(args), uargs, usize)` after the size checks of
/// `getxattrat` and `setxattrat`.
fn copy_xattr_args<C: Context>(ctx: &mut C, uargs: u64, usize_: u64) -> Result<XattrArgs, Errno> {
    // XATTR_ARGS_SIZE_VER0 is the whole structure.
    if usize_ < XATTR_ARGS_SIZE as u64 {
        return Err(Errno::EINVAL);
    }
    if usize_ > 4096 {
        return Err(Errno::E2BIG);
    }
    let mut raw = [0u8; XATTR_ARGS_SIZE];
    if copy_from_user(ctx, &mut raw, uargs) != 0 {
        return Err(Errno::EFAULT);
    }
    // The tail beyond the known structure must be zero (`check_zeroed_user`).
    let mut rest = usize_ - XATTR_ARGS_SIZE as u64;
    let mut at = uargs + XATTR_ARGS_SIZE as u64;
    while rest > 0 {
        let mut chunk = [0u8; 256];
        let n = rest.min(256) as usize;
        if copy_from_user(ctx, &mut chunk[..n], at) != 0 {
            return Err(Errno::EFAULT);
        }
        if chunk[..n].iter().any(|&b| b != 0) {
            return Err(Errno::E2BIG);
        }
        rest -= n as u64;
        at += n as u64;
    }
    let word = |at: usize| u64::from_le_bytes(raw[at..at + 8].try_into().unwrap_or([0; 8]));
    Ok(XattrArgs {
        value: word(0),
        size: word(8),
        flags: u64::from(u32::from_le_bytes(raw[16..20].try_into().unwrap_or([0; 4]))),
    })
}

/// `SYSCALL_DEFINE3(listxattr)` family over `path_listxattrat`: every inode's list is empty
/// (`shmem_listxattr` of an empty `simple_xattrs`, `security_inode_listsecurity` without a
/// module for procfs), so the answer is 0 whatever the buffer.
fn listxattrat<C: Context>(
    ctx: &mut C,
    dfd: i32,
    path: u64,
    at_flags: u32,
    _list: u64,
    _size: u64,
) -> Sys {
    if unknown_at_flags(at_flags) {
        return Err(Errno::EINVAL.into());
    }
    // `getname_maybe_null` without a name and without AT_EMPTY_PATH reads the path; with
    // AT_EMPTY_PATH an empty one means the descriptor.
    target(ctx, dfd, path, at_flags)?;
    Ok(0)
}

/// `SYSCALL_DEFINE2(removexattr)` family over `path_removexattrat`.
fn removexattrat<C: Context>(ctx: &mut C, dfd: i32, path: u64, at_flags: u32, name: u64) -> Sys {
    if unknown_at_flags(at_flags) {
        return Err(Errno::EINVAL.into());
    }
    let (kname, len) = import_xattr_name(ctx, name)?;
    let (env, inode, _pipe) = target(ctx, dfd, path, at_flags)?;
    let kname = &kname[..len];
    // mnt_want_write(_file).
    ctx.files().vfs.fs.want_write(inode)?;
    if is_posix_acl_xattr(kname) {
        // vfs_remove_acl -> set_posix_acl with a NULL value: needs the ACL setters.
        return match vfs_get_acl(ctx, inode) {
            Errno::EOPNOTSUPP => Err(Errno::EOPNOTSUPP.into()),
            _ => Err(Stop::Unimplemented),
        };
    }
    // vfs_removexattr
    xattr_permission(ctx, &env, inode, kname, MAY_WRITE)?;
    if inode.is_proc() {
        return Err(Errno::EOPNOTSUPP.into());
    }
    match resolve_name(kname) {
        Handler::None => Err(Errno::EOPNOTSUPP.into()),
        Handler::EmptySuffix => Err(Errno::EINVAL.into()),
        // simple_xattr_set(NULL, XATTR_REPLACE) on an empty list.
        Handler::Known => Err(Errno::ENODATA.into()),
    }
}

/// `SYSCALL_DEFINE5(setxattr)` family over `path_setxattrat`.
#[allow(clippy::too_many_arguments)]
fn setxattrat<C: Context>(
    ctx: &mut C,
    dfd: i32,
    path: u64,
    at_flags: u32,
    name: u64,
    value: u64,
    size: u64,
    flags: u64,
) -> Sys {
    if unknown_at_flags(at_flags) {
        return Err(Errno::EINVAL.into());
    }
    // setxattr_copy: `int flags`.
    if u64::from(flags as u32) & !(XATTR_CREATE | XATTR_REPLACE) != 0 {
        return Err(Errno::EINVAL.into());
    }
    let (kname, len) = import_xattr_name(ctx, name)?;
    if size != 0 {
        if size > XATTR_SIZE_MAX {
            return Err(Errno::E2BIG.into());
        }
        // vmemdup_user: the value is read whole, the first unreadable byte is EFAULT.
        let mut at = 0;
        while at < size {
            let mut chunk = [0u8; 256];
            let n = (size - at).min(256) as usize;
            if copy_from_user(ctx, &mut chunk[..n], value.wrapping_add(at)) != 0 {
                return Err(Errno::EFAULT.into());
            }
            at += n as u64;
        }
    }
    let (env, inode, _pipe) = target(ctx, dfd, path, at_flags)?;
    let kname = &kname[..len];
    // mnt_want_write(_file)
    ctx.files().vfs.fs.want_write(inode)?;
    if is_posix_acl_xattr(kname) {
        return match vfs_get_acl(ctx, inode) {
            Errno::EOPNOTSUPP => Err(Errno::EOPNOTSUPP.into()),
            _ => Err(Stop::Unimplemented),
        };
    }
    // vfs_setxattr
    xattr_permission(ctx, &env, inode, kname, MAY_WRITE)?;
    if inode.is_proc() {
        return Err(Errno::EOPNOTSUPP.into());
    }
    match resolve_name(kname) {
        Handler::None => Err(Errno::EOPNOTSUPP.into()),
        Handler::EmptySuffix => Err(Errno::EINVAL.into()),
        // simple_xattr_set on an empty list: XATTR_REPLACE finds nothing, anything else would
        // create the attribute (the store is not ported).
        Handler::Known if flags & XATTR_REPLACE != 0 => Err(Errno::ENODATA.into()),
        Handler::Known => Err(Stop::Unimplemented),
    }
}

/// `SYSCALL_DEFINE6(setxattrat)`.
fn setxattrat_args<C: Context>(ctx: &mut C, a: [u64; 6]) -> Sys {
    let [dfd, path, at_flags, name, uargs, usize_] = a;
    let args = copy_xattr_args(ctx, uargs, usize_)?;
    setxattrat(
        ctx,
        dfd as i32,
        path,
        at_flags as u32,
        name,
        args.value,
        args.size,
        args.flags,
    )
}
