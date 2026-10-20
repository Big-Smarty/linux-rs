// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: fs/read_write.c (GPL-2.0:
// `ksys_read`, `ksys_write`, `ksys_pread64`, `ksys_pwrite64`, `vfs_read`,
// `vfs_write`, `vfs_readv`, `do_readv`, `do_preadv`, `rw_verify_area`,
// `ksys_lseek`, `generic_file_llseek_size`, `vfs_setpos`), lib/iov_iter.c
// (`__import_iovec`), fs/file.c (`close_fd`, `do_dup2`, `ksys_dup3`, `sys_dup`,
// `f_dupfd`), fs/fcntl.c (`do_fcntl`, `setfl`, `check_fcntl_cmd`), fs/ioctl.c
// (`ksys_ioctl`, `do_vfs_ioctl`, `ioctl_fionbio`), fs/readdir.c
// (`iterate_dir`, `filldir64`, `sys_getdents64`), fs/pipe.c (`anon_pipe_read`,
// `anon_pipe_write`, `do_pipe2`, `__do_pipe_flags`, `pipe_ioctl`,
// `pipe_fcntl`), mm/shmem.c (`shmem_file_read_iter`, `shmem_file_llseek`),
// fs/libfs.c (`offset_dir_llseek`), drivers/char/mem.c (`null_fops`,
// `zero_fops`, `full_fops`), drivers/tty/tty_io.c and n_tty.c (`TCGETS`,
// `TIOCGWINSZ`, `TIOCGPGRP`, `FIONREAD`), include/uapi/asm-generic/ioctls.h,
// fs/open.c (`do_sys_ftruncate`). All GPL-2.0 / GPL-2.0-only.
// Transformation: the user-space iterators become `Dest`/bounce-buffer loops
// with the same page-sized fault granularity; waits become `Stop::Blocked`
// (one task, nobody to wake it).
// x86_64 only: `usize` is 64 bits, and the narrowing/sign casts below are the
// C types of the Linux ABI (`unsigned int` descriptors, `off_t`, `umode_t`,
// 32-bit inode numbers) reproduced on purpose.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
//! Descriptor-based file syscalls.
//!
//! Context: task context; nothing sleeps. An operation that would sleep with
//! no other task to wake it ends in [`Stop::Blocked`], a loud stop, never in a
//! guessed result. `SIGPIPE` has no delivery yet: writing to a pipe without
//! readers is [`Stop::Unimplemented`].

use alloc::vec::Vec;
use syscalls::{Errno, Sysno};

use super::{Context, MAX_RW_COUNT, Outcome, Stop, Sys, io, outcome};
use crate::{
    task::RLIM_INFINITY,
    usercopy::{access_ok, copy_from_user, copy_to_user},
    vfs::{
        FASYNC, FMODE_CAN_READ, FMODE_CAN_WRITE, FMODE_LSEEK, FMODE_PATH, FMODE_PREAD,
        FMODE_PWRITE, FMODE_READ, FMODE_WRITE, FileId, InodeId, MAX_LFS_FILESIZE, O_APPEND,
        O_CLOEXEC, O_DIRECT, O_EXCL, O_LARGEFILE, O_NOATIME, O_NONBLOCK, PAGE_SIZE, S_IFMT,
        SETFL_MASK,
        file::{CharDev, FileKind},
        tmpfs::DIR_OFFSET_EOD,
        try_push,
    },
};

/// `MAX_NON_LFS`: the offset limit of a file opened without `O_LARGEFILE`.
const MAX_NON_LFS: i64 = (1 << 31) - 1;
/// `UIO_MAXIOV`.
const UIO_MAXIOV: u64 = 1024;

pub(super) fn dispatch<C: Context>(ctx: &mut C, sysno: Sysno, a: [u64; 6]) -> Option<Outcome> {
    let result = match sysno {
        Sysno::read => read(ctx, a[0], a[1], a[2]),
        Sysno::write => write(ctx, a[0], a[1], a[2]),
        Sysno::close => close(ctx, a[0]),
        Sysno::lseek => lseek(ctx, a[0], a[1], a[2]),
        Sysno::pread64 => pread64(ctx, a[0], a[1], a[2], a[3]),
        Sysno::pwrite64 => pwrite64(ctx, a[0], a[1], a[2], a[3]),
        Sysno::readv => readv(ctx, a[0], a[1], a[2]),
        Sysno::preadv => preadv(ctx, a[0], a[1], a[2], a[3]),
        Sysno::ioctl => ioctl(ctx, a[0], a[1], a[2]),
        Sysno::pipe2 => pipe2(ctx, a[0], a[1]),
        Sysno::dup => dup(ctx, a[0]),
        Sysno::dup2 => dup2(ctx, a[0], a[1]),
        Sysno::dup3 => dup3(ctx, a[0], a[1], a[2]),
        Sysno::fcntl => fcntl(ctx, a[0], a[1], a[2]),
        Sysno::getdents64 => getdents64(ctx, a[0], a[1], a[2]),
        Sysno::ftruncate => ftruncate(ctx, a[0], a[1]),
        _ => return None,
    };
    Some(outcome(sysno as u32, result))
}

// ---- descriptor lookup ------------------------------------------------------

/// What a syscall needs of an open file, copied out of the file table.
#[derive(Clone, Copy)]
pub(super) struct View {
    pub id: FileId,
    pub kind: FileKind,
    pub flags: u32,
    pub mode: u32,
    pub pos: i64,
    pub inode: Option<InodeId>,
}

/// `fdget`/`fget_raw`: `raw` admits `O_PATH` descriptors.
pub(super) fn fdget<C: Context>(ctx: &mut C, fd: u64, raw: bool) -> Result<View, Errno> {
    let files = ctx.files();
    #[allow(clippy::cast_possible_truncation)]
    let id = files.fdt.get(fd as u32).ok_or(Errno::EBADF)?;
    let file = files.vfs.files.get(id);
    if !raw && file.mode & FMODE_PATH != 0 {
        return Err(Errno::EBADF);
    }
    Ok(View {
        id,
        kind: file.kind,
        flags: file.flags,
        mode: file.mode,
        pos: file.pos,
        inode: file.inode,
    })
}

fn set_pos<C: Context>(ctx: &mut C, view: &View, pos: i64) {
    ctx.files().vfs.files.get_mut(view.id).pos = pos;
}

// ---- user-space iterators ---------------------------------------------------

/// `iov_iter` over user buffers for a read: sequential segments.
struct Dest {
    segs: Vec<(u64, u64)>,
    seg: usize,
    used: u64,
    remaining: u64,
}

impl Dest {
    fn one(base: u64, len: u64) -> Result<Self, Errno> {
        let mut segs = Vec::new();
        try_push(&mut segs, (base, len))?;
        Ok(Self {
            segs,
            seg: 0,
            used: 0,
            remaining: len,
        })
    }

    /// Copy `data` to the next user bytes; returns the bytes copied (short on
    /// a fault). The cursor advances by what was copied.
    fn copy_out<C: Context>(&mut self, ctx: &mut C, data: &[u8]) -> usize {
        let mut done = 0;
        while done < data.len() && self.seg < self.segs.len() {
            let (base, len) = self.segs[self.seg];
            let room = (len - self.used) as usize;
            if room == 0 {
                self.seg += 1;
                self.used = 0;
                continue;
            }
            let n = room.min(data.len() - done);
            let missing = copy_to_user(ctx, base + self.used, &data[done..done + n]);
            let copied = n - missing;
            done += copied;
            self.used += copied as u64;
            self.remaining -= copied as u64;
            if missing != 0 {
                break;
            }
        }
        done
    }
}

/// `import_iovec` for `ITER_DEST`: the segments of `vlen` iovecs at `vec`.
fn import_iovec<C: Context>(ctx: &mut C, vec: u64, vlen: u64) -> Result<Dest, Errno> {
    if vlen > UIO_MAXIOV {
        return Err(Errno::EINVAL);
    }
    let mut segs = Vec::new();
    segs.try_reserve_exact(vlen as usize)
        .map_err(|_| Errno::ENOMEM)?;
    let mut total: i64 = 0;
    for i in 0..vlen {
        let mut raw = [0u8; 16];
        if copy_from_user(ctx, &mut raw, vec.wrapping_add(i * 16)) != 0 {
            return Err(Errno::EFAULT);
        }
        let base = u64::from_le_bytes(raw[..8].try_into().unwrap_or([0; 8]));
        let len = u64::from_le_bytes(raw[8..].try_into().unwrap_or([0; 8]));
        #[allow(clippy::cast_possible_wrap)]
        let signed = len as i64;
        if !access_ok(base, len) {
            return Err(Errno::EFAULT);
        }
        // `__import_iovec`: clamp the running total to MAX_RW_COUNT.
        let mut len = signed;
        let max = i64::from(MAX_RW_COUNT);
        if len > max - total {
            len = max - total;
        }
        total += len;
        #[allow(clippy::cast_sign_loss)]
        try_push(&mut segs, (base, len.max(0) as u64))?;
    }
    #[allow(clippy::cast_sign_loss)]
    Ok(Dest {
        segs,
        seg: 0,
        used: 0,
        remaining: total.max(0) as u64,
    })
}

// ---- read ---------------------------------------------------------------------

fn read<C: Context>(ctx: &mut C, fd: u64, buf: u64, count: u64) -> Sys {
    let view = fdget(ctx, fd, false)?;
    let mut pos = view.pos;
    let n = vfs_read(ctx, &view, buf, count, Some(&mut pos))?;
    set_pos(ctx, &view, pos);
    Ok(n)
}

fn pread64<C: Context>(ctx: &mut C, fd: u64, buf: u64, count: u64, pos: u64) -> Sys {
    #[allow(clippy::cast_possible_wrap)]
    let mut pos = pos as i64;
    if pos < 0 {
        return Err(Errno::EINVAL.into());
    }
    let view = fdget(ctx, fd, false)?;
    if view.mode & FMODE_PREAD == 0 {
        return Err(Errno::ESPIPE.into());
    }
    vfs_read(ctx, &view, buf, count, Some(&mut pos))
}

/// `rw_verify_area` for a position (`ppos` non-NULL): no negative offset, no
/// wraparound of `pos + count`.
fn verify_area(pos: i64, count: u64) -> Result<(), Errno> {
    #[allow(clippy::cast_possible_wrap)]
    if (count as i64) < 0 || pos < 0 || pos.wrapping_add(count as i64) < 0 {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

/// `vfs_read`. `pos` is the working copy of `f_pos` (`None` for a stream).
fn vfs_read<C: Context>(
    ctx: &mut C,
    view: &View,
    buf: u64,
    count: u64,
    pos: Option<&mut i64>,
) -> Sys {
    if view.mode & FMODE_READ == 0 {
        return Err(Errno::EBADF.into());
    }
    if view.mode & FMODE_CAN_READ == 0 {
        return Err(Errno::EINVAL.into());
    }
    if !access_ok(buf, count) {
        return Err(Errno::EFAULT.into());
    }
    if let Some(p) = pos.as_deref() {
        verify_area(*p, count)?;
    }
    let count = count.min(u64::from(MAX_RW_COUNT));
    let mut dest = Dest::one(buf, count)?;
    read_kind(ctx, view, &mut dest, pos)
}

fn readv<C: Context>(ctx: &mut C, fd: u64, vec: u64, vlen: u64) -> Sys {
    let view = fdget(ctx, fd, false)?;
    let mut pos = view.pos;
    let n = vfs_readv(ctx, &view, vec, vlen, &mut pos)?;
    set_pos(ctx, &view, pos);
    Ok(n)
}

fn preadv<C: Context>(ctx: &mut C, fd: u64, vec: u64, vlen: u64, pos_l: u64) -> Sys {
    // pos_from_hilo on 64-bit: the high word shifts out entirely.
    #[allow(clippy::cast_possible_wrap)]
    let mut pos = pos_l as i64;
    if pos < 0 {
        return Err(Errno::EINVAL.into());
    }
    let view = fdget(ctx, fd, false)?;
    if view.mode & FMODE_PREAD == 0 {
        return Err(Errno::ESPIPE.into());
    }
    vfs_readv(ctx, &view, vec, vlen, &mut pos)
}

fn vfs_readv<C: Context>(ctx: &mut C, view: &View, vec: u64, vlen: u64, pos: &mut i64) -> Sys {
    if view.mode & FMODE_READ == 0 {
        return Err(Errno::EBADF.into());
    }
    if view.mode & FMODE_CAN_READ == 0 {
        return Err(Errno::EINVAL.into());
    }
    let mut dest = import_iovec(ctx, vec, vlen)?;
    if dest.remaining == 0 {
        return Ok(0);
    }
    verify_area(*pos, dest.remaining)?;
    read_kind(ctx, view, &mut dest, Some(pos))
}

/// The `->read`/`->read_iter` of the file kind.
fn read_kind<C: Context>(ctx: &mut C, view: &View, dest: &mut Dest, pos: Option<&mut i64>) -> Sys {
    match view.kind {
        FileKind::Regular => {
            let (Some(pos), Some(inode)) = (pos, view.inode) else {
                return Err(Errno::EINVAL.into());
            };
            let result = read_regular(ctx, inode, dest, pos);
            // shmem_file_read_iter ends in file_accessed(), whatever the result.
            if view.flags & O_NOATIME == 0 {
                ctx.files().vfs.fs.touch_atime(inode);
            }
            result
        }
        FileKind::Directory => Err(Errno::EISDIR.into()), // generic_read_dir
        FileKind::Char(CharDev::Null) => Ok(0),           // read_null
        FileKind::Char(CharDev::Zero | CharDev::Full) => Ok(read_zero(ctx, dest)?),
        FileKind::Char(CharDev::Console) => {
            // n_tty_read with no input pending: sleeps; O_NONBLOCK -> EAGAIN.
            if view.flags & O_NONBLOCK != 0 {
                Err(Errno::EAGAIN.into())
            } else {
                Err(Stop::Blocked)
            }
        }
        FileKind::Pipe {
            pipe,
            writer: false,
        } => pipe_read(ctx, view, pipe, dest),
        FileKind::Pipe { writer: true, .. } | FileKind::Path => Err(Errno::EBADF.into()),
        FileKind::Unsupported => Err(Stop::Unimplemented),
    }
}

/// `shmem_file_read_iter`: page-granular copies, a short copy ends the read.
fn read_regular<C: Context>(ctx: &mut C, inode: InodeId, dest: &mut Dest, pos: &mut i64) -> Sys {
    let mut bounce = [0u8; PAGE_SIZE];
    let mut total: i64 = 0;
    let mut error = None;
    #[allow(clippy::cast_sign_loss)]
    while dest.remaining > 0 {
        let at = *pos as u64;
        let room = PAGE_SIZE - (at % PAGE_SIZE as u64) as usize;
        let want = room.min(usize::try_from(dest.remaining).unwrap_or(usize::MAX));
        let got = ctx.files().vfs.fs.read(inode, at, &mut bounce[..want]);
        if got == 0 {
            break;
        }
        let copied = dest.copy_out(ctx, &bounce[..got]);
        *pos += copied as i64;
        total += copied as i64;
        if copied < got {
            error = Some(Errno::EFAULT);
            break;
        }
    }
    if total > 0 {
        Ok(total)
    } else if let Some(error) = error {
        Err(error.into())
    } else {
        Ok(0)
    }
}

/// `read_iter_zero`: zero fill, page at a time, up to the first fault.
fn read_zero<C: Context>(ctx: &mut C, dest: &mut Dest) -> Result<i64, Stop> {
    let zeros = [0u8; PAGE_SIZE];
    let mut written: i64 = 0;
    while dest.remaining > 0 {
        let chunk = usize::try_from(dest.remaining)
            .unwrap_or(PAGE_SIZE)
            .min(PAGE_SIZE);
        let n = dest.copy_out(ctx, &zeros[..chunk]);
        if n == 0 {
            return if written > 0 {
                Ok(written)
            } else {
                Err(Errno::EFAULT.into())
            };
        }
        written += n as i64;
    }
    Ok(written)
}

fn pipe_read<C: Context>(
    ctx: &mut C,
    view: &View,
    pipe: crate::vfs::PipeId,
    dest: &mut Dest,
) -> Sys {
    let mut total_len = dest.remaining;
    if total_len == 0 {
        return Ok(0);
    }
    let mut ret: i64 = 0;
    let mut bounce = [0u8; PAGE_SIZE];
    loop {
        let (chars, empty) = {
            let p = ctx.files().vfs.pipe_ref(pipe);
            match p.front() {
                Some(front) => {
                    let n = front
                        .len()
                        .min(usize::try_from(total_len).unwrap_or(usize::MAX));
                    bounce[..n].copy_from_slice(&front[..n]);
                    (Some(n), false)
                }
                None => (None, true),
            }
        };
        if let Some(chars) = chars {
            let written = dest.copy_out(ctx, &bounce[..chars]);
            if written < chars {
                if ret == 0 {
                    return Err(Errno::EFAULT.into());
                }
                break;
            }
            ret += chars as i64;
            let p = ctx.files().vfs.pipe_mut(pipe);
            p.consume(chars);
            total_len -= chars as u64;
            if total_len == 0 {
                break;
            }
            if !p.is_empty() {
                continue;
            }
        }
        let _ = empty;
        if ctx.files().vfs.pipe_ref(pipe).writers == 0 || ret > 0 {
            break;
        }
        if view.flags & O_NONBLOCK != 0 {
            return Err(Errno::EAGAIN.into());
        }
        return Err(Stop::Blocked);
    }
    Ok(ret)
}

// ---- write --------------------------------------------------------------------

fn write<C: Context>(ctx: &mut C, fd: u64, buf: u64, count: u64) -> Sys {
    let view = fdget(ctx, fd, false)?;
    let mut pos = view.pos;
    let n = vfs_write(ctx, &view, buf, count, Some(&mut pos))?;
    set_pos(ctx, &view, pos);
    Ok(n)
}

fn pwrite64<C: Context>(ctx: &mut C, fd: u64, buf: u64, count: u64, pos: u64) -> Sys {
    #[allow(clippy::cast_possible_wrap)]
    let mut pos = pos as i64;
    if pos < 0 {
        return Err(Errno::EINVAL.into());
    }
    let view = fdget(ctx, fd, false)?;
    if view.mode & FMODE_PWRITE == 0 {
        return Err(Errno::ESPIPE.into());
    }
    vfs_write(ctx, &view, buf, count, Some(&mut pos))
}

fn vfs_write<C: Context>(
    ctx: &mut C,
    view: &View,
    buf: u64,
    count: u64,
    pos: Option<&mut i64>,
) -> Sys {
    if view.mode & FMODE_WRITE == 0 {
        return Err(Errno::EBADF.into());
    }
    if view.mode & FMODE_CAN_WRITE == 0 {
        return Err(Errno::EINVAL.into());
    }
    if !access_ok(buf, count) {
        return Err(Errno::EFAULT.into());
    }
    if let Some(p) = pos.as_deref() {
        verify_area(*p, count)?;
    }
    let count = count.min(u64::from(MAX_RW_COUNT));
    match view.kind {
        FileKind::Regular => {
            let (Some(pos), Some(inode)) = (pos, view.inode) else {
                return Err(Errno::EINVAL.into());
            };
            write_regular(ctx, view, inode, buf, count, pos)
        }
        FileKind::Char(CharDev::Console) => Ok(io::tty_write(ctx, buf, count)?),
        // write_null / write_zero: the data is discarded, never read.
        FileKind::Char(CharDev::Null | CharDev::Zero) => Ok(i64::try_from(count).unwrap_or(0)),
        FileKind::Char(CharDev::Full) => Err(Errno::ENOSPC.into()), // write_full
        FileKind::Pipe { pipe, writer: true } => pipe_write(ctx, view, pipe, buf, count),
        FileKind::Directory | FileKind::Pipe { .. } | FileKind::Path => Err(Errno::EBADF.into()),
        FileKind::Unsupported => Err(Stop::Unimplemented),
    }
}

/// `shmem_file_write_iter`: `generic_write_checks`, `file_remove_privs`,
/// `file_update_time`, `generic_perform_write`.
fn write_regular<C: Context>(
    ctx: &mut C,
    view: &View,
    inode: InodeId,
    buf: u64,
    count: u64,
    pos: &mut i64,
) -> Sys {
    if count == 0 {
        return Ok(0);
    }
    let cred = ctx.cred();
    let mut at = *pos;
    if view.flags & O_APPEND != 0 {
        at = i64::try_from(ctx.files().vfs.fs.inode(inode).size).unwrap_or(i64::MAX);
    }
    // generic_write_check_limits: `loff_t limit = rlimit(RLIMIT_FSIZE)`.
    let mut count = count;
    let limit = ctx.rlimit_fsize();
    if limit != RLIM_INFINITY {
        let limit = limit as i64;
        if at >= limit {
            return Err(Stop::SigXfsz); // send_sig(SIGXFSZ) + -EFBIG
        }
        count = count.min((limit - at) as u64);
    }
    let max_size = if view.flags & O_LARGEFILE == 0 {
        MAX_NON_LFS
    } else {
        MAX_LFS_FILESIZE
    };
    if at >= max_size {
        return Err(Errno::EFBIG.into());
    }
    #[allow(clippy::cast_sign_loss)]
    let count = count.min((max_size - at) as u64);
    // file_remove_privs, then file_update_time: both precede the copy, so a
    // write that then fails still updates the timestamps.
    let files = ctx.files();
    files.vfs.remove_privs(&cred, inode);
    files.vfs.fs.touch(inode);
    let mut bounce = [0u8; PAGE_SIZE];
    let mut written: u64 = 0;
    let mut status = None;
    while written < count {
        #[allow(clippy::cast_sign_loss)]
        let start = (at as u64) + written;
        let offset = (start % PAGE_SIZE as u64) as usize;
        let chunk = ((PAGE_SIZE - offset) as u64).min(count - written) as usize;
        let missing = copy_from_user(ctx, &mut bounce[..chunk], buf + written);
        let copied = chunk - missing;
        if copied == 0 {
            status = Some(Errno::EFAULT);
            break;
        }
        match ctx.files().vfs.fs.write(inode, start, &bounce[..copied]) {
            Ok(n) => {
                written += n as u64;
                if n < copied {
                    status = Some(Errno::ENOSPC);
                    break;
                }
            }
            Err(error) => {
                status = Some(error);
                break;
            }
        }
    }
    if written > 0 {
        // new_sync_write stores the position only for a positive result.
        *pos = at + i64::try_from(written).unwrap_or(0);
        Ok(i64::try_from(written).unwrap_or(i64::MAX))
    } else {
        Err(status.unwrap_or(Errno::EIO).into())
    }
}

fn pipe_write<C: Context>(
    ctx: &mut C,
    view: &View,
    pipe: crate::vfs::PipeId,
    buf: u64,
    count: u64,
) -> Sys {
    if count == 0 {
        return Ok(0);
    }
    if ctx.files().vfs.pipe_ref(pipe).readers == 0 {
        return Err(Stop::SigPipe); // send_sig(SIGPIPE) + -EPIPE
    }
    let mut bounce = [0u8; PAGE_SIZE];
    let mut ret: u64 = 0;
    let mut remaining = count;
    // Merge the sub-page head of the write into the newest buffer if it fits.
    #[allow(clippy::cast_possible_truncation)]
    let chars = (count & (PAGE_SIZE as u64 - 1)) as usize;
    let mergeable = {
        let p = ctx.files().vfs.pipe_ref(pipe);
        chars > 0 && !p.is_empty() && p.merge_room() >= chars
    };
    if mergeable {
        if copy_from_user(ctx, &mut bounce[..chars], buf) != 0 {
            return Err(Errno::EFAULT.into());
        }
        ctx.files().vfs.pipe_mut(pipe).merge(&bounce[..chars])?;
        ret += chars as u64;
        remaining -= chars as u64;
        if remaining == 0 {
            return Ok(i64::try_from(ret).unwrap_or(i64::MAX));
        }
    }
    loop {
        if ctx.files().vfs.pipe_ref(pipe).readers == 0 {
            return Err(Stop::SigPipe);
        }
        if !ctx.files().vfs.pipe_ref(pipe).is_full() {
            let want = remaining.min(PAGE_SIZE as u64) as usize;
            if copy_from_user(ctx, &mut bounce[..want], buf + ret) != 0 {
                if ret == 0 {
                    return Err(Errno::EFAULT.into());
                }
                break;
            }
            ctx.files().vfs.pipe_mut(pipe).push_page(&bounce[..want])?;
            ret += want as u64;
            remaining -= want as u64;
            if remaining == 0 {
                break;
            }
            continue;
        }
        if view.flags & O_NONBLOCK != 0 {
            if ret == 0 {
                return Err(Errno::EAGAIN.into());
            }
            break;
        }
        return Err(Stop::Blocked);
    }
    Ok(i64::try_from(ret).unwrap_or(i64::MAX))
}

// ---- lseek --------------------------------------------------------------------

/// `vfs_setpos`.
fn setpos(file_pos: i64, offset: i64, maxsize: i64) -> Result<i64, Errno> {
    let _ = file_pos;
    if offset < 0 || offset > maxsize {
        return Err(Errno::EINVAL);
    }
    Ok(offset)
}

fn lseek<C: Context>(ctx: &mut C, fd: u64, offset: u64, whence: u64) -> Sys {
    let view = fdget(ctx, fd, false)?;
    #[allow(clippy::cast_possible_truncation)]
    let whence = whence as u32;
    if whence > 4 {
        return Err(Errno::EINVAL.into());
    }
    #[allow(clippy::cast_possible_wrap)]
    let offset = offset as i64;
    if view.mode & FMODE_LSEEK == 0 {
        return Err(Errno::ESPIPE.into());
    }
    let new = match view.kind {
        FileKind::Regular => {
            let Some(inode) = view.inode else {
                return Err(Errno::EINVAL.into());
            };
            let size = i64::try_from(ctx.files().vfs.fs.inode(inode).size).unwrap_or(i64::MAX);
            match whence {
                0 => setpos(view.pos, offset, MAX_LFS_FILESIZE)?,
                1 if offset == 0 => view.pos,
                1 => setpos(view.pos, view.pos.wrapping_add(offset), MAX_LFS_FILESIZE)?,
                2 => setpos(view.pos, size.wrapping_add(offset), MAX_LFS_FILESIZE)?,
                _ => {
                    // SEEK_DATA / SEEK_HOLE
                    if offset < 0 {
                        return Err(Errno::ENXIO.into());
                    }
                    #[allow(clippy::cast_sign_loss)]
                    let found = ctx
                        .files()
                        .vfs
                        .fs
                        .seek_hole_data(inode, offset as u64, whence == 3)
                        .ok_or(Errno::ENXIO)?;
                    setpos(
                        view.pos,
                        i64::try_from(found).unwrap_or(i64::MAX),
                        MAX_LFS_FILESIZE,
                    )?
                }
            }
        }
        FileKind::Directory => {
            // offset_dir_llseek: SET and CUR only.
            let target = match whence {
                0 => offset,
                1 => offset.wrapping_add(view.pos),
                _ => return Err(Errno::EINVAL.into()),
            };
            if target < 0 {
                return Err(Errno::EINVAL.into());
            }
            setpos(view.pos, target, i64::MAX)?
        }
        // null_lseek / zero_lseek / full_lseek
        FileKind::Char(CharDev::Null | CharDev::Zero | CharDev::Full) => 0,
        // A driver this kernel lacks that Linux leaves seekable (the stream
        // kinds were refused above through the cleared FMODE_LSEEK): its
        // llseek is not ported.
        FileKind::Unsupported => return Err(Stop::Unimplemented),
        _ => return Err(Errno::ESPIPE.into()),
    };
    set_pos(ctx, &view, new);
    Ok(new)
}

// ---- close / dup ----------------------------------------------------------------

fn close<C: Context>(ctx: &mut C, fd: u64) -> Sys {
    let files = ctx.files();
    #[allow(clippy::cast_possible_truncation)]
    let id = files.fdt.close(fd as u32).ok_or(Errno::EBADF)?;
    files.vfs.fput(id);
    Ok(0)
}

fn dup<C: Context>(ctx: &mut C, fd: u64) -> Sys {
    let nofile = ctx.rlimit_nofile();
    let files = ctx.files();
    #[allow(clippy::cast_possible_truncation)]
    let id = files.fdt.get(fd as u32).ok_or(Errno::EBADF)?;
    let new = files.fdt.alloc_fd(0, nofile, false)?;
    files.vfs.files.dup(id);
    files.fdt.install(new, id);
    Ok(i64::from(new))
}

fn dup2<C: Context>(ctx: &mut C, old: u64, new: u64) -> Sys {
    #[allow(clippy::cast_possible_truncation)]
    if old as u32 == new as u32 {
        // The corner case: just check the descriptor.
        let files = ctx.files();
        files.fdt.get(old as u32).ok_or(Errno::EBADF)?;
        return Ok(i64::from(old as u32));
    }
    dup3_inner(ctx, old, new, 0)
}

fn dup3<C: Context>(ctx: &mut C, old: u64, new: u64, flags: u64) -> Sys {
    #[allow(clippy::cast_possible_truncation)]
    let flags = flags as u32;
    if flags & !O_CLOEXEC != 0 {
        return Err(Errno::EINVAL.into());
    }
    #[allow(clippy::cast_possible_truncation)]
    if old as u32 == new as u32 {
        return Err(Errno::EINVAL.into());
    }
    dup3_inner(ctx, old, new, flags)
}

/// `ksys_dup3` after its argument checks.
fn dup3_inner<C: Context>(ctx: &mut C, old: u64, new: u64, flags: u32) -> Sys {
    let nofile = ctx.rlimit_nofile();
    #[allow(clippy::cast_possible_truncation)]
    let (old, new) = (old as u32, new as u32);
    if u64::from(new) >= nofile {
        return Err(Errno::EBADF.into());
    }
    let files = ctx.files();
    let expanded = files.fdt.expand(u64::from(new));
    let id = files.fdt.get(old).ok_or(Errno::EBADF)?;
    match expanded {
        Ok(()) => {}
        Err(Errno::EMFILE) => return Err(Errno::EBADF.into()),
        Err(error) => return Err(error.into()),
    }
    files.vfs.files.dup(id);
    match files.fdt.replace(new, id, flags & O_CLOEXEC != 0) {
        Ok(old_file) => {
            if let Some(old_file) = old_file {
                files.vfs.fput(old_file);
            }
            Ok(i64::from(new))
        }
        Err(error) => {
            files.vfs.fput(id);
            Err(error.into())
        }
    }
}

// ---- fcntl ----------------------------------------------------------------------

const F_DUPFD: u32 = 0;
const F_GETFD: u32 = 1;
const F_SETFD: u32 = 2;
const F_GETFL: u32 = 3;
const F_SETFL: u32 = 4;
const F_GETLK: u32 = 5;
const F_SETLK: u32 = 6;
const F_SETLKW: u32 = 7;
const F_SETOWN: u32 = 8;
const F_GETOWN: u32 = 9;
const F_SETSIG: u32 = 10;
const F_GETSIG: u32 = 11;
const F_SETOWN_EX: u32 = 15;
const F_GETOWN_EX: u32 = 16;
const F_GETOWNER_UIDS: u32 = 17;
const F_OFD_GETLK: u32 = 36;
const F_OFD_SETLK: u32 = 37;
const F_OFD_SETLKW: u32 = 38;
const F_SETLEASE: u32 = 1024;
const F_GETLEASE: u32 = 1025;
const F_NOTIFY: u32 = 1026;
const F_DUPFD_QUERY: u32 = 1027;
const F_CREATED_QUERY: u32 = 1028;
const F_DUPFD_CLOEXEC: u32 = 1030;
const F_SETPIPE_SZ: u32 = 1031;
const F_GETPIPE_SZ: u32 = 1032;
const F_ADD_SEALS: u32 = 1033;
const F_GET_SEALS: u32 = 1034;
const F_GET_RW_HINT: u32 = 1035;
const F_SET_RW_HINT: u32 = 1036;
const FD_CLOEXEC: u32 = 1;

fn fcntl<C: Context>(ctx: &mut C, fd: u64, cmd: u64, arg: u64) -> Sys {
    let view = fdget(ctx, fd, true)?;
    #[allow(clippy::cast_possible_truncation)]
    let (fd, cmd, argi) = (fd as u32, cmd as u32, arg as u32);
    if view.mode & FMODE_PATH != 0
        && !matches!(
            cmd,
            F_CREATED_QUERY
                | F_DUPFD
                | F_DUPFD_CLOEXEC
                | F_DUPFD_QUERY
                | F_GETFD
                | F_SETFD
                | F_GETFL
        )
    {
        return Err(Errno::EBADF.into());
    }
    match cmd {
        F_CREATED_QUERY => Ok(i64::from(view.mode & crate::vfs::FMODE_CREATED != 0)),
        F_DUPFD => f_dupfd(ctx, argi, &view, false),
        F_DUPFD_CLOEXEC => f_dupfd(ctx, argi, &view, true),
        F_DUPFD_QUERY => {
            let other = fdget(ctx, u64::from(argi), true)?;
            Ok(i64::from(other.id == view.id))
        }
        F_GETFD => Ok(i64::from(ctx.files().fdt.cloexec(fd))),
        F_SETFD => {
            ctx.files().fdt.set_cloexec(fd, argi & FD_CLOEXEC != 0);
            Ok(0)
        }
        F_GETFL => Ok(i64::from(view.flags)),
        F_SETFL => setfl(ctx, &view, argi),
        F_SETPIPE_SZ => match view.kind {
            FileKind::Pipe { .. } => Err(Stop::Unimplemented),
            _ => Err(Errno::EBADF.into()),
        },
        F_GETPIPE_SZ => match view.kind {
            FileKind::Pipe { pipe, .. } => {
                Ok(i64::try_from(ctx.files().vfs.pipe_ref(pipe).size()).unwrap_or(0))
            }
            _ => Err(Errno::EBADF.into()),
        },
        F_GETLK | F_SETLK | F_SETLKW | F_OFD_GETLK | F_OFD_SETLK | F_OFD_SETLKW | F_GETOWN
        | F_SETOWN | F_GETOWN_EX | F_SETOWN_EX | F_GETOWNER_UIDS | F_GETSIG | F_SETSIG
        | F_GETLEASE | F_SETLEASE | F_NOTIFY | F_ADD_SEALS | F_GET_SEALS | F_GET_RW_HINT
        | F_SET_RW_HINT => Err(Stop::Unimplemented),
        _ => Err(Errno::EINVAL.into()),
    }
}

/// `f_dupfd`: `from` is the unsigned view of an `int`.
fn f_dupfd<C: Context>(ctx: &mut C, from: u32, view: &View, cloexec: bool) -> Sys {
    let nofile = ctx.rlimit_nofile();
    if u64::from(from) >= nofile {
        return Err(Errno::EINVAL.into());
    }
    let files = ctx.files();
    let new = files.fdt.alloc_fd(from, nofile, cloexec)?;
    files.vfs.files.dup(view.id);
    files.fdt.install(new, view.id);
    Ok(i64::from(new))
}

/// `inode_owner_or_capable` for an open file: the caller owns the inode (a
/// pipe's inode is its creator's) or has `CAP_FOWNER`.
fn owner_or_capable<C: Context>(ctx: &mut C, view: &View) -> bool {
    let cred = ctx.cred();
    let vfs = &ctx.files().vfs;
    let owner = match (view.inode, view.kind) {
        (Some(inode), _) => vfs.fs.inode(inode).uid,
        (None, FileKind::Pipe { pipe, .. }) => vfs.pipe_ref(pipe).uid,
        (None, _) => return cred.fowner,
    };
    owner == cred.fsuid || cred.fowner
}

/// `setfl`.
fn setfl<C: Context>(ctx: &mut C, view: &View, arg: u32) -> Sys {
    let mut arg = arg;
    // O_NOATIME can only be set by the owner or superuser.
    if arg & O_NOATIME != 0 && view.flags & O_NOATIME == 0 && !owner_or_capable(ctx, view) {
        return Err(Errno::EPERM.into());
    }
    // O_NDELAY == O_NONBLOCK on x86.
    let is_fifo = matches!(view.kind, FileKind::Pipe { .. });
    if !is_fifo && arg & O_DIRECT != 0 {
        return Err(Errno::EINVAL.into()); // no FMODE_CAN_ODIRECT anywhere here
    }
    if is_fifo && arg & O_DIRECT != 0 {
        return Err(Stop::Unimplemented); // packet mode
    }
    // ->fasync() sets FASYNC; tmpfs files, directories and the memory devices
    // have none, so the bit is ignored there (SETFL_MASK excludes it).
    if arg & FASYNC != view.flags & FASYNC
        && matches!(
            view.kind,
            FileKind::Pipe { .. } | FileKind::Char(CharDev::Console) | FileKind::Unsupported
        )
    {
        return Err(Stop::Unimplemented); // fasync_helper / SIGIO
    }
    arg &= SETFL_MASK;
    let file = ctx.files().vfs.files.get_mut(view.id);
    file.flags = arg | (file.flags & !SETFL_MASK);
    Ok(0)
}

// ---- ioctl ----------------------------------------------------------------------

const FIONREAD: u32 = 0x541b;
const FIONBIO: u32 = 0x5421;
const FIONCLEX: u32 = 0x5450;
const FIOCLEX: u32 = 0x5451;
const FIOASYNC: u32 = 0x5452;
const FIOQSIZE: u32 = 0x5460;
const TCGETS: u32 = 0x5401;
const TIOCGPGRP: u32 = 0x540f;
const TIOCGWINSZ: u32 = 0x5413;
const FIFREEZE: u32 = 0xc004_5877;
const FITHAW: u32 = 0xc004_5878;
const FIGETBSZ: u32 = 2;
const FIBMAP: u32 = 1;
const FICLONE: u32 = 0x4004_9409;
const FICLONERANGE: u32 = 0x4020_940d;
const FIDEDUPERANGE: u32 = 0xc018_9436;
const FS_IOC_GETFLAGS: u32 = 0x8008_6601;
const FS_IOC_SETFLAGS: u32 = 0x4008_6602;
const FS_IOC_FIEMAP: u32 = 0xc020_660b;
const FS_IOC_FSGETXATTR: u32 = 0x801c_581f;
const FS_IOC_FSSETXATTR: u32 = 0x401c_5820;
const FS_IOC_GETFSUUID: u32 = 0x8011_1500;
const FS_IOC_GETFSSYSFSPATH: u32 = 0x8081_1501;
/// `FS_IOC_RESVSP`, `_UNRESVSP`, `_RESVSP64`, `_UNRESVSP64`, `_ZERO_RANGE`
/// (`_IOW('X', 40/41/42/43/57, struct space_resv)`), reached through `file_ioctl`.
const FS_IOC_PREALLOCATE: [u32; 5] = [
    0x4030_5828,
    0x4030_5829,
    0x4030_582a,
    0x4030_582b,
    0x4030_5839,
];

/// The tty ioctl numbers `include/uapi/asm-generic/ioctls.h` defines: Linux
/// routes all of them through `tty_ioctl`, so an unimplemented one stops the
/// kernel instead of answering `ENOTTY`.
fn is_tty_ioctl(cmd: u32) -> bool {
    (0x5401..=0x5470).contains(&cmd) || matches!(cmd, 0x802c_542a | 0x402c_542b | 0x402c_542c)
}

/// `tty_std_termios` (`include/linux/tty.h`, `drivers/tty/tty_io.c`) as a `struct termios`: iflag ICRNL|IXON, oflag OPOST|ONLCR, cflag B38400|CS8|CREAD|HUPCL,
/// lflag ISIG|ICANON|ECHO|ECHOE|ECHOK|ECHOCTL|ECHOKE|IEXTEN, `INIT_C_CC`.
fn std_termios() -> [u8; 36] {
    let mut out = [0u8; 36];
    out[0..4].copy_from_slice(&0o2400u32.to_le_bytes());
    out[4..8].copy_from_slice(&0o5u32.to_le_bytes());
    out[8..12].copy_from_slice(&0o2277u32.to_le_bytes());
    out[12..16].copy_from_slice(&0o105_073u32.to_le_bytes());
    // c_line = N_TTY, then c_cc[19]
    let cc: [u8; 17] = [3, 28, 127, 21, 4, 0, 1, 0, 17, 19, 26, 0, 18, 15, 23, 22, 0];
    out[17..34].copy_from_slice(&cc);
    out
}

fn ioctl<C: Context>(ctx: &mut C, fd: u64, cmd: u64, arg: u64) -> Sys {
    let view = fdget(ctx, fd, false)?;
    #[allow(clippy::cast_possible_truncation)]
    let (fdn, cmd) = (fd as u32, cmd as u32);
    // do_vfs_ioctl
    match cmd {
        FIOCLEX => {
            ctx.files().fdt.set_cloexec(fdn, true);
            return Ok(0);
        }
        FIONCLEX => {
            ctx.files().fdt.set_cloexec(fdn, false);
            return Ok(0);
        }
        FIONBIO => {
            let mut raw = [0u8; 4];
            if copy_from_user(ctx, &mut raw, arg) != 0 {
                return Err(Errno::EFAULT.into());
            }
            let on = i32::from_le_bytes(raw) != 0;
            let file = ctx.files().vfs.files.get_mut(view.id);
            if on {
                file.flags |= O_NONBLOCK;
            } else {
                file.flags &= !O_NONBLOCK;
            }
            return Ok(0);
        }
        FIOQSIZE => {
            if let Some(inode) = view.inode {
                let node = ctx.files().vfs.fs.inode(inode);
                if matches!(
                    node.mode & S_IFMT,
                    crate::vfs::S_IFREG | crate::vfs::S_IFDIR | crate::vfs::S_IFLNK
                ) {
                    // inode_get_bytes: the allocated bytes, `i_blocks << 9`.
                    let bytes = node.blocks() << 9;
                    return put(ctx, arg, &bytes.to_le_bytes());
                }
            }
            return Err(Errno::ENOTTY.into());
        }
        FIFREEZE | FITHAW => {
            // ioctl_fsfreeze / ioctl_fsthaw: the capability check comes first,
            // then tmpfs has no freeze_fs/freeze_super.
            return Err(if ctx.cred().sys_admin {
                Errno::EOPNOTSUPP
            } else {
                Errno::EPERM
            }
            .into());
        }
        // The superblock's s_blocksize: tmpfs and pipefs are both PAGE_SIZE.
        FIGETBSZ => return put(ctx, arg, &(PAGE_SIZE as u32).to_le_bytes()),
        // shmem_fileattr_get (CONFIG_TMPFS_XATTR=y) exists for regular files
        // and directories, and no attribute flag can be set here: flags 0.
        FS_IOC_GETFLAGS | FS_IOC_FSGETXATTR
            if matches!(view.kind, FileKind::Regular | FileKind::Directory) =>
        {
            let len = if cmd == FS_IOC_GETFLAGS { 4 } else { 28 };
            return put(ctx, arg, &[0u8; 28][..len]);
        }
        // ->fileattr_set, FIEMAP, reflink and dedupe, filesystem UUID and sysfs
        // path have answers other than ENOTTY on tmpfs that are not ported.
        FS_IOC_SETFLAGS
        | FS_IOC_FSSETXATTR
        | FS_IOC_FIEMAP
        | FICLONE
        | FICLONERANGE
        | FIDEDUPERANGE
        | FS_IOC_GETFSUUID
        | FS_IOC_GETFSSYSFSPATH => {
            return Err(Stop::Unimplemented);
        }
        // file_ioctl, for regular files only.
        FIBMAP if matches!(view.kind, FileKind::Regular) => return Err(Stop::Unimplemented),
        c if matches!(view.kind, FileKind::Regular) && FS_IOC_PREALLOCATE.contains(&c) => {
            return Err(Stop::Unimplemented);
        }
        FIONREAD if matches!(view.kind, FileKind::Regular) => {
            let Some(inode) = view.inode else {
                return Err(Errno::ENOTTY.into());
            };
            let size = i64::try_from(ctx.files().vfs.fs.inode(inode).size).unwrap_or(i64::MAX);
            let left = i32::try_from(size - view.pos).unwrap_or(i32::MAX);
            return put(ctx, arg, &left.to_le_bytes());
        }
        FIOASYNC => return Err(Stop::Unimplemented),
        _ => {}
    }
    // vfs_ioctl -> ->unlocked_ioctl
    match view.kind {
        FileKind::Pipe { pipe, .. } if cmd == FIONREAD => {
            let n = i32::try_from(ctx.files().vfs.pipe_ref(pipe).available()).unwrap_or(i32::MAX);
            put(ctx, arg, &n.to_le_bytes())
        }
        FileKind::Char(CharDev::Console) => match cmd {
            TCGETS => put(ctx, arg, &std_termios()),
            TIOCGWINSZ => put(ctx, arg, &[0u8; 8]),
            // tiocgpgrp: the console is not init's controlling terminal.
            TIOCGPGRP => Err(Errno::ENOTTY.into()),
            FIONREAD => put(ctx, arg, &0i32.to_le_bytes()),
            c if is_tty_ioctl(c) => Err(Stop::Unimplemented),
            _ => Err(Errno::ENOTTY.into()),
        },
        FileKind::Unsupported => Err(Stop::Unimplemented),
        _ => Err(Errno::ENOTTY.into()),
    }
}

fn put<C: Context>(ctx: &mut C, arg: u64, bytes: &[u8]) -> Sys {
    if copy_to_user(ctx, arg, bytes) != 0 {
        return Err(Errno::EFAULT.into());
    }
    Ok(0)
}

// ---- pipe2 ----------------------------------------------------------------------

fn pipe2<C: Context>(ctx: &mut C, pipefd: u64, flags: u64) -> Sys {
    #[allow(clippy::cast_possible_truncation)]
    let flags = flags as u32;
    let allowed = O_CLOEXEC | O_NONBLOCK | O_DIRECT | O_EXCL;
    if flags & !allowed != 0 {
        return Err(Errno::EINVAL.into());
    }
    if flags & O_EXCL != 0 {
        return Err(Errno::ENOPKG.into()); // CONFIG_WATCH_QUEUE is not set
    }
    if flags & O_DIRECT != 0 {
        return Err(Stop::Unimplemented); // packet mode
    }
    let cred = ctx.cred();
    let nofile = ctx.rlimit_nofile();
    let cloexec = flags & O_CLOEXEC != 0;
    let files = ctx.files();
    let (read, write) = files.vfs.pipe_create(flags, &cred)?;
    let read_fd = match files.fdt.alloc_fd(0, nofile, cloexec) {
        Ok(fd) => fd,
        Err(error) => {
            files.vfs.fput(read);
            files.vfs.fput(write);
            return Err(error.into());
        }
    };
    let write_fd = match files.fdt.alloc_fd(0, nofile, cloexec) {
        Ok(fd) => fd,
        Err(error) => {
            files.fdt.put_unused(read_fd);
            files.vfs.fput(read);
            files.vfs.fput(write);
            return Err(error.into());
        }
    };
    let mut raw = [0u8; 8];
    raw[..4].copy_from_slice(&read_fd.to_le_bytes());
    raw[4..].copy_from_slice(&write_fd.to_le_bytes());
    if copy_to_user(ctx, pipefd, &raw) != 0 {
        let files = ctx.files();
        files.vfs.fput(read);
        files.vfs.fput(write);
        files.fdt.put_unused(read_fd);
        files.fdt.put_unused(write_fd);
        return Err(Errno::EFAULT.into());
    }
    let files = ctx.files();
    files.fdt.install(read_fd, read);
    files.fdt.install(write_fd, write);
    Ok(0)
}

// ---- getdents64 -------------------------------------------------------------------

fn getdents64<C: Context>(ctx: &mut C, fd: u64, dirent: u64, count: u64) -> Sys {
    let view = fdget(ctx, fd, false)?;
    #[allow(clippy::cast_possible_truncation)]
    let count = count as u32 as usize;
    if view.kind != FileKind::Directory {
        return Err(Errno::ENOTDIR.into());
    }
    let Some(dir) = view.inode else {
        return Err(Errno::ENOTDIR.into());
    };
    if ctx.files().vfs.fs.is_dead(dir) {
        return Err(Errno::ENOENT.into()); // iterate_dir: IS_DEADDIR
    }
    // iterate_dir -> offset_readdir, collecting the filldir64 records.
    let mut out: Vec<u8> = Vec::new();
    let mut starts: Vec<usize> = Vec::new();
    let mut ats: Vec<i64> = Vec::new();
    let mut pos = view.pos;
    let mut left = count;
    let mut failure = None;
    {
        let tmpfs = &ctx.files().vfs.fs;
        let mut actor = |name: &[u8], at: i64, ino: u64, dtype: u8| -> bool {
            failure = Some(Errno::EINVAL); // `buf->error`, only used if nothing fits
            let reclen = (19 + name.len() + 1 + 7) & !7;
            if reclen > left {
                return false;
            }
            if out.try_reserve(reclen).is_err()
                || starts.try_reserve(1).is_err()
                || ats.try_reserve(1).is_err()
            {
                failure = Some(Errno::ENOMEM);
                return false;
            }
            let start = out.len();
            let mut push = |bytes: &[u8]| {
                for &b in bytes {
                    let _ = out.push_within_capacity(b);
                }
            };
            push(&ino.to_le_bytes());
            push(&0i64.to_le_bytes()); // d_off, filled in below
            #[allow(clippy::cast_possible_truncation)]
            push(&(reclen as u16).to_le_bytes());
            push(&[dtype]);
            push(name);
            while out.len() < start + reclen {
                let _ = out.push_within_capacity(0);
            }
            let _ = starts.push_within_capacity(start);
            let _ = ats.push_within_capacity(at);
            left -= reclen;
            true
        };
        tmpfs.readdir(dir, &mut pos, &mut actor);
    }
    // iterate_dir: file_accessed() follows the iteration, whatever it gave.
    if view.flags & O_NOATIME == 0 {
        ctx.files().vfs.fs.touch_atime(dir);
    }
    if starts.is_empty() {
        // Nothing emitted: `buf.error` (EINVAL when the first record did not
        // fit) is the result; an exhausted directory gives 0.
        return match failure {
            Some(error) if ats.is_empty() && pos != DIR_OFFSET_EOD => Err(error.into()),
            _ => {
                set_pos(ctx, &view, pos);
                Ok(0)
            }
        };
    }
    // d_off of a record is the position of the one listed after it; the last
    // one gets `ctx->pos` after the walk.
    for (i, &start) in starts.iter().enumerate() {
        let d_off = ats.get(i + 1).copied().unwrap_or(pos);
        out[start + 8..start + 16].copy_from_slice(&d_off.to_le_bytes());
    }
    let mut stored = out.len();
    let missing = copy_to_user(ctx, dirent, &out);
    if missing != 0 {
        // filldir64 stops at the first record it cannot store (EFAULT only
        // when that is the first one); the walk position stays on it.
        let copied = out.len() - missing;
        let whole = starts
            .iter()
            .enumerate()
            .take_while(|&(i, _)| starts.get(i + 1).copied().unwrap_or(out.len()) <= copied)
            .count();
        if whole == 0 {
            return Err(Errno::EFAULT.into());
        }
        stored = starts.get(whole).copied().unwrap_or(out.len());
        pos = ats.get(whole).copied().unwrap_or(pos);
    }
    set_pos(ctx, &view, pos);
    Ok(i64::try_from(stored).unwrap_or(0))
}

// ---- ftruncate ----------------------------------------------------------------------

fn ftruncate<C: Context>(ctx: &mut C, fd: u64, length: u64) -> Sys {
    #[allow(clippy::cast_possible_wrap)]
    let length = length as i64;
    if length < 0 {
        return Err(Errno::EINVAL.into());
    }
    let view = fdget(ctx, fd, false)?;
    let Some(inode) = view.inode else {
        return Err(Errno::EINVAL.into());
    };
    let is_reg = ctx.files().vfs.fs.inode(inode).is_reg();
    if !is_reg || view.mode & FMODE_WRITE == 0 {
        return Err(Errno::EINVAL.into());
    }
    // `small` is false on 64-bit (the syscall passes 0), so MAX_NON_LFS never
    // applies. inode_newsize_ok (from notify_change): growing past
    // RLIMIT_FSIZE raises SIGXFSZ with -EFBIG, and s_maxbytes is
    // MAX_LFS_FILESIZE, which a non-negative length cannot exceed.
    let size = ctx.files().vfs.fs.inode(inode).size;
    #[allow(clippy::cast_sign_loss)]
    if size < length as u64 {
        let limit = ctx.rlimit_fsize();
        if limit != RLIM_INFINITY && length as u64 > limit {
            return Err(Stop::SigXfsz);
        }
    }
    let cred = ctx.cred();
    #[allow(clippy::cast_sign_loss)]
    ctx.files().vfs.do_truncate(&cred, inode, length as u64);
    Ok(0)
}
