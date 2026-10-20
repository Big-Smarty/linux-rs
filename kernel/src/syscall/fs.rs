// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: fs/open.c (GPL-2.0:
// `do_sys_openat2`, `SYSCALL_DEFINE3(open)`, `do_faccessat`, `ksys_chdir`,
// `SYSCALL_DEFINE1(fchdir)`), fs/namei.c (`getname_flags`,
// `__getname_maybe_null`, `do_mknodat`, `do_unlinkat`, `path_init` dirfd
// rules), fs/stat.c (`cp_new_stat`, `cp_statx`, `vfs_fstatat`, `vfs_statx`,
// `do_statx`, `do_statx_fd`, `do_readlinkat`), fs/d_path.c (`sys_getcwd`),
// lib/strncpy_from_user.c (through `usercopy`), arch/x86/entry/syscalls/
// syscall_64.tbl. All GPL-2.0 / GPL-2.0-only.
// Transformation: pathnames are copied once into a fallibly allocated vector;
// the VFS operations (`vfs::Vfs`) never see user memory.
// x86_64 only: `usize` is 64 bits, and the narrowing/sign casts below are the
// C types of the Linux ABI (`unsigned int` descriptors, `off_t`, `umode_t`,
// 32-bit inode numbers) reproduced on purpose.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
//! Path-based file syscalls: `open`, `mknod`, `access`, `chdir`, `getcwd`,
//! `readlink`, `stat`, `statx`, `unlink`.

use alloc::vec::Vec;
use syscalls::{Errno, Sysno};

use super::{Context, Outcome, Sys, outcome};
use crate::{
    usercopy::{copy_from_user, copy_to_user, strncpy_from_user},
    vfs::{
        AT_EACCESS, AT_EMPTY_PATH, AT_FDCWD, AT_NO_AUTOMOUNT, AT_STATX_SYNC_TYPE,
        AT_SYMLINK_NOFOLLOW, Kstat, O_LARGEFILE, PATH_MAX, major, minor, new_encode_dev,
        ops::{Env, build_open_flags, stat_lookup_flags},
        path::{LOOKUP_DIRECTORY, LOOKUP_FOLLOW},
        try_copy,
    },
};

pub(super) fn dispatch<C: Context>(ctx: &mut C, sysno: Sysno, a: [u64; 6]) -> Option<Outcome> {
    let result = match sysno {
        Sysno::open => open(ctx, AT_FDCWD, a[0], a[1], a[2]),
        Sysno::openat => open(ctx, dfd(a[0]), a[1], a[2], a[3]),
        Sysno::mknod => mknod(ctx, AT_FDCWD, a[0], a[1], a[2]),
        Sysno::access => faccessat(ctx, AT_FDCWD, a[0], a[1], 0),
        Sysno::faccessat => faccessat(ctx, dfd(a[0]), a[1], a[2], 0),
        Sysno::faccessat2 => faccessat(ctx, dfd(a[0]), a[1], a[2], a[3]),
        Sysno::chdir => chdir(ctx, a[0]),
        Sysno::fchdir => fchdir(ctx, a[0]),
        Sysno::getcwd => getcwd(ctx, a[0], a[1]),
        Sysno::readlink => readlinkat(ctx, AT_FDCWD, a[0], a[1], a[2]),
        Sysno::readlinkat => readlinkat(ctx, dfd(a[0]), a[1], a[2], a[3]),
        Sysno::stat => stat(ctx, a[0], a[1], 0),
        Sysno::lstat => stat(ctx, a[0], a[1], AT_SYMLINK_NOFOLLOW),
        Sysno::newfstatat => newfstatat(ctx, dfd(a[0]), a[1], a[2], a[3]),
        Sysno::fstat => fstat(ctx, a[0], a[1]),
        Sysno::statx => statx(ctx, dfd(a[0]), a[1], a[2], a[3], a[4]),
        Sysno::unlink => unlink(ctx, a[0]),
        _ => return None,
    };
    Some(outcome(sysno as u32, result))
}

/// A syscall `int dfd` argument.
#[allow(clippy::cast_possible_truncation)]
fn dfd(raw: u64) -> i32 {
    raw as i32
}

// ---- pathnames -----------------------------------------------------------------

/// `getname_flags`: copy a pathname from user space. An empty name is
/// `ENOENT` unless `empty_ok` (`LOOKUP_EMPTY`).
pub(super) fn getname<C: Context>(
    ctx: &mut C,
    addr: u64,
    empty_ok: bool,
) -> Result<Vec<u8>, Errno> {
    let mut buf = [0u8; PATH_MAX];
    match strncpy_from_user(ctx, &mut buf, addr) {
        None => Err(Errno::EFAULT),
        Some(len) if len == PATH_MAX => Err(Errno::ENAMETOOLONG),
        Some(0) if !empty_ok => Err(Errno::ENOENT),
        Some(len) => try_copy(&buf[..len]),
    }
}

/// `getname_maybe_null`: with `AT_EMPTY_PATH` a NULL pointer or an empty string
/// means "the descriptor itself".
fn getname_maybe_null<C: Context>(
    ctx: &mut C,
    addr: u64,
    flags: u32,
) -> Result<Option<Vec<u8>>, Errno> {
    if flags & AT_EMPTY_PATH == 0 {
        return getname(ctx, addr, false).map(Some);
    }
    if addr == 0 {
        return Ok(None);
    }
    let mut first = [0u8; 1];
    if copy_from_user(ctx, &mut first, addr) != 0 {
        return Err(Errno::EFAULT);
    }
    if first[0] == 0 {
        return Ok(None);
    }
    getname(ctx, addr, true).map(Some)
}

/// The `Env` for a walk of `path` relative to `dfd` (`path_init`).
pub(super) fn env_for<C: Context>(ctx: &mut C, dfd: i32, path: &[u8]) -> Result<Env, Errno> {
    let cred = ctx.cred();
    let files = ctx.files();
    let fs = *files.fs;
    let start = if path.first() == Some(&b'/') {
        fs.root
    } else if dfd == AT_FDCWD {
        fs.pwd
    } else {
        #[allow(clippy::cast_sign_loss)]
        let id = files.fdt.get(dfd as u32).ok_or(Errno::EBADF)?;
        match files.vfs.files.get(id).inode {
            Some(inode) => inode,
            None if path.is_empty() => fs.pwd,
            None => return Err(Errno::ENOTDIR),
        }
    };
    Ok(Env {
        root: fs.root,
        start,
        cred,
        umask: fs.umask,
    })
}

// ---- open ------------------------------------------------------------------------

fn open<C: Context>(ctx: &mut C, dfd: i32, path: u64, flags: u64, mode: u64) -> Sys {
    // force_o_largefile(): always on x86-64. `flags` is an int, `mode` a umode_t.
    #[allow(clippy::cast_possible_truncation)]
    let flags = flags as u32 | O_LARGEFILE;
    #[allow(clippy::cast_possible_truncation)]
    let op = build_open_flags(flags, u32::from(mode as u16))?;
    let name = getname(ctx, path, false)?;
    let nofile = ctx.rlimit_nofile();
    let fd = ctx.files().fdt.alloc_fd(0, nofile, op.cloexec)?;
    let opened = env_for(ctx, dfd, &name).and_then(|env| ctx.files().vfs.open(&env, &name, &op));
    let files = ctx.files();
    match opened {
        Ok(file) => {
            files.fdt.install(fd, file);
            Ok(i64::from(fd))
        }
        Err(error) => {
            files.fdt.put_unused(fd);
            Err(error.into())
        }
    }
}

// ---- mknod / unlink ------------------------------------------------------------------

fn mknod<C: Context>(ctx: &mut C, dfd: i32, path: u64, mode: u64, dev: u64) -> Sys {
    let name = getname(ctx, path, false)?;
    let env = env_for(ctx, dfd, &name)?;
    #[allow(clippy::cast_possible_truncation)]
    ctx.files()
        .vfs
        .mknod(&env, &name, u32::from(mode as u16), dev as u32)?;
    Ok(0)
}

fn unlink<C: Context>(ctx: &mut C, path: u64) -> Sys {
    let name = getname(ctx, path, false)?;
    let env = env_for(ctx, AT_FDCWD, &name)?;
    ctx.files().vfs.unlink(&env, &name)?;
    Ok(0)
}

// ---- access ------------------------------------------------------------------------

fn faccessat<C: Context>(ctx: &mut C, dfd: i32, path: u64, mode: u64, flags: u64) -> Sys {
    #[allow(clippy::cast_possible_truncation)]
    let (mode, flags) = (mode as u32, flags as u32);
    if mode & !7 != 0 {
        return Err(Errno::EINVAL.into());
    }
    if flags & !(AT_EACCESS | AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(Errno::EINVAL.into());
    }
    let empty_ok = flags & AT_EMPTY_PATH != 0;
    let lookup = if flags & AT_SYMLINK_NOFOLLOW != 0 {
        0
    } else {
        LOOKUP_FOLLOW
    };
    let name = getname(ctx, path, empty_ok)?;
    let env = env_for(ctx, dfd, &name)?;
    let vfs = ctx.files().vfs;
    let inode = vfs.lookup(&env, &name, lookup)?;
    vfs.access_check(&env, inode, mode)?;
    Ok(0)
}

// ---- chdir / getcwd -------------------------------------------------------------------

fn chdir<C: Context>(ctx: &mut C, path: u64) -> Sys {
    let name = getname(ctx, path, false)?;
    let env = env_for(ctx, AT_FDCWD, &name)?;
    let files = ctx.files();
    let dir = files
        .vfs
        .lookup(&env, &name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY)?;
    files.vfs.chdir_check(&env, dir)?;
    files.vfs.set_pwd(files.fs, dir);
    Ok(0)
}

fn fchdir<C: Context>(ctx: &mut C, fd: u64) -> Sys {
    let cred = ctx.cred();
    let files = ctx.files();
    #[allow(clippy::cast_possible_truncation)]
    let id = files.fdt.get(fd as u32).ok_or(Errno::EBADF)?;
    let dir = files.vfs.files.get(id).inode.ok_or(Errno::ENOTDIR)?;
    let env = Env {
        root: files.fs.root,
        start: dir,
        cred,
        umask: files.fs.umask,
    };
    files.vfs.chdir_check(&env, dir)?;
    files.vfs.set_pwd(files.fs, dir);
    Ok(0)
}

fn getcwd<C: Context>(ctx: &mut C, buf: u64, size: u64) -> Sys {
    let files = ctx.files();
    let mut path = files.vfs.dir_path(files.fs.root, files.fs.pwd)?;
    path.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
    let _ = path.push_within_capacity(0);
    if path.len() as u64 > size {
        return Err(Errno::ERANGE.into());
    }
    if copy_to_user(ctx, buf, &path) != 0 {
        return Err(Errno::EFAULT.into());
    }
    Ok(path.len() as i64)
}

// ---- readlink --------------------------------------------------------------------------

fn readlinkat<C: Context>(ctx: &mut C, dfd: i32, path: u64, buf: u64, bufsiz: u64) -> Sys {
    #[allow(clippy::cast_possible_truncation)]
    let bufsiz = bufsiz as i32;
    if bufsiz <= 0 {
        return Err(Errno::EINVAL.into());
    }
    let name = getname(ctx, path, true)?;
    let env = env_for(ctx, dfd, &name)?;
    let vfs = ctx.files().vfs;
    let inode = vfs.lookup(&env, &name, 0)?;
    let target = match &vfs.fs.inode(inode).body {
        crate::vfs::tmpfs::Body::Link(target) => try_copy(target)?,
        _ => {
            return Err(if name.is_empty() {
                Errno::ENOENT
            } else {
                Errno::EINVAL
            }
            .into());
        }
    };
    #[allow(clippy::cast_sign_loss)]
    let n = target.len().min(bufsiz as usize);
    if copy_to_user(ctx, buf, &target[..n]) != 0 {
        return Err(Errno::EFAULT.into());
    }
    Ok(n as i64)
}

// ---- stat family ---------------------------------------------------------------------------

/// `cp_new_stat`: the 144-byte x86-64 `struct stat`.
fn put_stat<C: Context>(ctx: &mut C, addr: u64, st: &Kstat) -> Result<(), Errno> {
    let mut out = [0u8; 144];
    out[0..8].copy_from_slice(&u64::from(new_encode_dev(st.dev)).to_le_bytes());
    out[8..16].copy_from_slice(&st.ino.to_le_bytes());
    out[16..24].copy_from_slice(&u64::from(st.nlink).to_le_bytes());
    out[24..28].copy_from_slice(&st.mode.to_le_bytes());
    out[28..32].copy_from_slice(&st.uid.to_le_bytes());
    out[32..36].copy_from_slice(&st.gid.to_le_bytes());
    out[40..48].copy_from_slice(&u64::from(new_encode_dev(st.rdev)).to_le_bytes());
    out[48..56].copy_from_slice(&st.size.to_le_bytes());
    out[56..64].copy_from_slice(&i64::from(st.blksize).to_le_bytes());
    #[allow(clippy::cast_possible_wrap)]
    out[64..72].copy_from_slice(&(st.blocks as i64).to_le_bytes());
    for (i, t) in [st.atime, st.mtime, st.ctime].iter().enumerate() {
        out[72 + 16 * i..80 + 16 * i].copy_from_slice(&t.sec.to_le_bytes());
        out[80 + 16 * i..88 + 16 * i].copy_from_slice(&i64::from(t.nsec).to_le_bytes());
    }
    if copy_to_user(ctx, addr, &out) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(())
}

/// `vfs_fstat`: `fd_raw`, so `O_PATH` descriptors work.
fn kstat_fd<C: Context>(ctx: &mut C, fd: u64) -> Result<Kstat, Errno> {
    let files = ctx.files();
    #[allow(clippy::cast_possible_truncation)]
    let id = files.fdt.get(fd as u32).ok_or(Errno::EBADF)?;
    Ok(files.vfs.kstat_file(id))
}

fn fstat<C: Context>(ctx: &mut C, fd: u64, buf: u64) -> Sys {
    let st = kstat_fd(ctx, fd)?;
    put_stat(ctx, buf, &st)?;
    Ok(0)
}

fn stat<C: Context>(ctx: &mut C, path: u64, buf: u64, flags: u32) -> Sys {
    let st = fstatat(ctx, AT_FDCWD, path, flags)?;
    put_stat(ctx, buf, &st)?;
    Ok(0)
}

fn newfstatat<C: Context>(ctx: &mut C, dfd: i32, path: u64, buf: u64, flags: u64) -> Sys {
    #[allow(clippy::cast_possible_truncation)]
    let st = fstatat(ctx, dfd, path, flags as u32)?;
    put_stat(ctx, buf, &st)?;
    Ok(0)
}

/// `vfs_fstatat` -> `vfs_statx`.
fn fstatat<C: Context>(ctx: &mut C, dfd: i32, path: u64, flags: u32) -> Result<Kstat, Errno> {
    let name = getname_maybe_null(ctx, path, flags)?;
    if name.is_none() && dfd >= 0 {
        #[allow(clippy::cast_sign_loss)]
        return kstat_fd(ctx, dfd as u64);
    }
    vfs_statx(
        ctx,
        dfd,
        name.as_deref().unwrap_or(&[]),
        flags | AT_NO_AUTOMOUNT,
    )
}

fn vfs_statx<C: Context>(ctx: &mut C, dfd: i32, name: &[u8], flags: u32) -> Result<Kstat, Errno> {
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_EMPTY_PATH | AT_STATX_SYNC_TYPE) != 0 {
        return Err(Errno::EINVAL);
    }
    let env = env_for(ctx, dfd, name)?;
    let vfs = ctx.files().vfs;
    let inode = vfs.lookup(&env, name, stat_lookup_flags(flags))?;
    Ok(vfs.fs.getattr(inode))
}

const STATX_BASIC_STATS: u32 = 0x7ff;
const STATX_BTIME: u32 = 0x800;
const STATX_MNT_ID: u32 = 0x1000;
const STATX_CHANGE_COOKIE: u32 = 1 << 30;
const STATX_RESERVED: u32 = 0x8000_0000;
/// `mnt_id` of the rootfs mount (an arbitrary allocated id in Linux).
const ROOTFS_MNT_ID: u64 = 1;

fn put_statx<C: Context>(ctx: &mut C, addr: u64, st: &Kstat, mask: u32) -> Result<(), Errno> {
    let mut out = [0u8; 256];
    // generic_fillattr + shmem_getattr result mask, vfs_statx_path adds MNT_ID.
    let mut result = STATX_BASIC_STATS | STATX_MNT_ID;
    if mask & STATX_BTIME != 0 {
        result |= STATX_BTIME;
    }
    out[0..4].copy_from_slice(&result.to_le_bytes());
    out[4..8].copy_from_slice(&st.blksize.to_le_bytes());
    out[8..16].copy_from_slice(&st.attributes.to_le_bytes());
    out[16..20].copy_from_slice(&st.nlink.to_le_bytes());
    out[20..24].copy_from_slice(&st.uid.to_le_bytes());
    out[24..28].copy_from_slice(&st.gid.to_le_bytes());
    #[allow(clippy::cast_possible_truncation)]
    out[28..30].copy_from_slice(&(st.mode as u16).to_le_bytes());
    out[32..40].copy_from_slice(&st.ino.to_le_bytes());
    #[allow(clippy::cast_sign_loss)]
    out[40..48].copy_from_slice(&(st.size as u64).to_le_bytes());
    out[48..56].copy_from_slice(&st.blocks.to_le_bytes());
    out[56..64].copy_from_slice(&st.attributes_mask.to_le_bytes());
    let btime = if mask & STATX_BTIME != 0 {
        st.btime
    } else {
        crate::vfs::Timespec { sec: 0, nsec: 0 }
    };
    for (i, t) in [st.atime, btime, st.ctime, st.mtime].iter().enumerate() {
        out[64 + 16 * i..72 + 16 * i].copy_from_slice(&t.sec.to_le_bytes());
        out[72 + 16 * i..76 + 16 * i].copy_from_slice(&t.nsec.to_le_bytes());
    }
    out[128..132].copy_from_slice(&major(st.rdev).to_le_bytes());
    out[132..136].copy_from_slice(&minor(st.rdev).to_le_bytes());
    out[136..140].copy_from_slice(&major(st.dev).to_le_bytes());
    out[140..144].copy_from_slice(&minor(st.dev).to_le_bytes());
    out[144..152].copy_from_slice(&ROOTFS_MNT_ID.to_le_bytes());
    if copy_to_user(ctx, addr, &out) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(())
}

fn statx<C: Context>(ctx: &mut C, dfd: i32, path: u64, flags: u64, mask: u64, buf: u64) -> Sys {
    #[allow(clippy::cast_possible_truncation)]
    let (flags, mask) = (flags as u32, mask as u32);
    let name = getname_maybe_null(ctx, path, flags)?;
    let fd_only = name.is_none() && dfd >= 0;
    // do_statx / do_statx_fd
    if mask & STATX_RESERVED != 0 || flags & AT_STATX_SYNC_TYPE == AT_STATX_SYNC_TYPE {
        return Err(Errno::EINVAL.into());
    }
    let mask = mask & !STATX_CHANGE_COOKIE;
    let st = if fd_only {
        #[allow(clippy::cast_sign_loss)]
        kstat_fd(ctx, dfd as u64)?
    } else {
        vfs_statx(ctx, dfd, name.as_deref().unwrap_or(&[]), flags)?
    };
    put_statx(ctx, buf, &st, mask)?;
    Ok(0)
}
