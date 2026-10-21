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
// fs/open.c (`do_sys_ftruncate`), fs/splice.c (`SYSCALL_DEFINE6(splice)`,
// `__do_splice`, `do_splice`, `splice_file_to_pipe`, `wait_for_space`, `do_splice_read`,
// `SYSCALL_DEFINE4(vmsplice)`, `iter_to_pipe`, `vmsplice_to_user`, `__splice_from_pipe`),
// fs/read_write.c (`SYSCALL_DEFINE6(copy_file_range)`, `vfs_copy_file_range`,
// `generic_copy_file_checks`, `generic_file_rw_checks`), fs/ioctl.c (`ioctl_file_clone`),
// fs/remap_range.c (`vfs_clone_file_range`).
// All GPL-2.0 / GPL-2.0-only.
// Transformation: the user-space iterators become `Dest`/bounce-buffer loops
// with the same page-sized fault granularity; waits are interruptible sleeps
// on `sched::PIPE_KEY` (the pipe wait queues), woken when another task changes
// a pipe ([`crate::vfs::Vfs::take_pipe_events`]).
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
//! Context: task context. An operation that would sleep (an empty pipe or
//! console, a full pipe) sleeps interruptibly
//! ([`wait_event_interruptible`](crate::signal::wait::wait_event_interruptible)):
//! a pipe operation on [`PIPE_KEY`], woken by whichever task changes the pipe
//! or closes an end of it, and the console read until a signal arrives (no
//! input source exists). It ends with `-ERESTARTSYS` when a signal is pending
//! and nothing was transferred; a partial transfer is returned as it is. No
//! guard of the shared state is held while the task sleeps (the context drops
//! it in [`signal::Task::wait`](crate::signal::Task::wait)), so another task
//! runs system calls meanwhile and the loops re-read everything after a sleep.
//! `SIGPIPE` and `SIGXFSZ` are sent with `send_sig` as in Linux.

use alloc::vec::Vec;
use syscalls::{Errno, Sysno};

use super::{Context, MAX_RW_COUNT, Outcome, Stop, Sys, outcome, procio, tty};
use crate::{
    sched::PIPE_KEY,
    signal::{SIGPIPE, SIGXFSZ, wait::wait_event_interruptible},
    task::RLIM_INFINITY,
    usercopy::{access_ok, copy_from_user, copy_to_user},
    vfs::{
        FASYNC, FMODE_CAN_READ, FMODE_CAN_WRITE, FMODE_LSEEK, FMODE_PATH, FMODE_PREAD,
        FMODE_PWRITE, FMODE_READ, FMODE_WRITE, FileId, InodeId, MAX_LFS_FILESIZE, MAX_NON_LFS,
        O_APPEND, O_CLOEXEC, O_DIRECT, O_EXCL, O_LARGEFILE, O_NOATIME, O_NONBLOCK, PAGE_SIZE,
        S_IFMT, SETFL_MASK,
        file::{CharDev, FileKind},
        tmpfs::DIR_OFFSET_EOD,
        try_push,
    },
};

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
        Sysno::writev => writev(ctx, a[0], a[1], a[2]),
        Sysno::sendfile => sendfile(ctx, a[0], a[1], a[2], a[3]),
        Sysno::splice => splice(ctx, a),
        Sysno::vmsplice => vmsplice(ctx, a[0], a[1], a[2], a[3]),
        Sysno::copy_file_range => copy_file_range(ctx, a),
        Sysno::pwritev => pwritev(ctx, a[0], a[1], a[2], a[3]),
        Sysno::ioctl => ioctl(ctx, a[0], a[1], a[2]),
        // `SYSCALL_DEFINE1(pipe, ...)`: `do_pipe2(fildes, 0)`.
        Sysno::pipe => pipe2(ctx, a[0], 0),
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
pub(super) struct Dest {
    segs: Vec<(u64, u64)>,
    seg: usize,
    used: u64,
    pub(super) remaining: u64,
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

    /// Bytes the caller's buffers still have room for.
    pub(super) const fn remaining(&self) -> u64 {
        self.remaining
    }

    /// Copy `data` to the next user bytes; returns the bytes copied (short on
    /// a fault). The cursor advances by what was copied.
    pub(super) fn copy_out<C: Context>(&mut self, ctx: &mut C, data: &[u8]) -> usize {
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

/// `iov_iter` for a write (`ITER_SOURCE`): sequential user segments read with the
/// one fault-aware user copy, or (`ITER_BVEC` over a pipe's pages in `splice`)
/// bytes the kernel already holds.
pub(super) struct Src {
    data: SrcData,
    /// One buffer of `write(2)`/`pwrite64(2)` (`Src::one`), not the segments of an iovec: a
    /// `->write` sees it even when it is empty.
    plain: bool,
    seg: usize,
    used: u64,
    pub(super) remaining: u64,
}

enum SrcData {
    User(Vec<(u64, u64)>),
    Kernel(Vec<u8>),
}

impl Src {
    fn one(base: u64, len: u64) -> Result<Self, Errno> {
        let mut segs = Vec::new();
        try_push(&mut segs, (base, len))?;
        Ok(Self {
            data: SrcData::User(segs),
            plain: true,
            seg: 0,
            used: 0,
            remaining: len,
        })
    }

    /// An iterator over bytes held in the kernel.
    fn kernel(bytes: Vec<u8>) -> Self {
        let remaining = bytes.len() as u64;
        Self {
            data: SrcData::Kernel(bytes),
            plain: false,
            seg: 0,
            used: 0,
            remaining,
        }
    }

    /// `copy_from_iter`: fill `out` from the next bytes; returns the bytes
    /// copied (short on a fault). The cursor advances by what was copied.
    pub(super) fn copy_in<C: Context>(&mut self, ctx: &mut C, out: &mut [u8]) -> usize {
        let segs = match &self.data {
            SrcData::Kernel(bytes) => {
                let from = self.used as usize;
                let n = out.len().min(bytes.len() - from);
                out[..n].copy_from_slice(&bytes[from..from + n]);
                self.used += n as u64;
                self.remaining -= n as u64;
                return n;
            }
            SrcData::User(segs) => segs,
        };
        let mut done = 0;
        while done < out.len() && self.seg < segs.len() {
            let (base, len) = segs[self.seg];
            let room = (len - self.used) as usize;
            if room == 0 {
                self.seg += 1;
                self.used = 0;
                continue;
            }
            let n = room.min(out.len() - done);
            let missing = copy_from_user(ctx, &mut out[done..done + n], base + self.used);
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

    /// The buffer of a plain `write(2)`, consumed whole, empty or not (`vfs_write` calls `->write`
    /// for a zero count too).
    fn plain_buffer(&mut self) -> Option<(u64, u64)> {
        let SrcData::User(segs) = &self.data else {
            return None;
        };
        if !self.plain {
            return None;
        }
        let (base, len) = segs[0];
        self.plain = false;
        self.seg = segs.len();
        self.remaining = 0;
        Some((base + self.used, len - self.used))
    }

    /// The next non-empty user segment, consumed whole (`do_loop_readv_writev`'s walk); `None`
    /// at the end and for bytes held in the kernel.
    fn next_segment(&mut self) -> Option<(u64, u64)> {
        let SrcData::User(segs) = &self.data else {
            return None;
        };
        while self.seg < segs.len() {
            let (base, len) = segs[self.seg];
            let (from, room) = (self.used, len - self.used);
            self.seg += 1;
            self.used = 0;
            if room != 0 {
                self.remaining -= room;
                return Some((base + from, room));
            }
        }
        None
    }

    /// `iov_iter_revert`: give `n` consumed bytes back (`n` never exceeds what
    /// was consumed since the cursor was last at that point).
    pub(super) fn revert(&mut self, mut n: u64) {
        self.remaining += n;
        let SrcData::User(segs) = &self.data else {
            self.used -= n;
            return;
        };
        while n > 0 {
            if self.used == 0 {
                if self.seg == 0 {
                    return;
                }
                self.seg -= 1;
                self.used = segs[self.seg].1;
            }
            let back = n.min(self.used);
            self.used -= back;
            n -= back;
        }
    }
}

/// `__import_iovec`: the segments of `vlen` iovecs at `vec`, each range
/// checked with `access_ok`, and the total clamped to `MAX_RW_COUNT`.
fn import_segs<C: Context>(
    ctx: &mut C,
    vec: u64,
    vlen: u64,
) -> Result<(Vec<(u64, u64)>, u64), Errno> {
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
    Ok((segs, total.max(0) as u64))
}

/// `import_iovec` for `ITER_DEST`.
fn import_iovec<C: Context>(ctx: &mut C, vec: u64, vlen: u64) -> Result<Dest, Errno> {
    let (segs, remaining) = import_segs(ctx, vec, vlen)?;
    Ok(Dest {
        segs,
        seg: 0,
        used: 0,
        remaining,
    })
}

/// `import_iovec` for `ITER_SOURCE`.
fn import_iovec_src<C: Context>(ctx: &mut C, vec: u64, vlen: u64) -> Result<Src, Errno> {
    let (segs, remaining) = import_segs(ctx, vec, vlen)?;
    Ok(Src {
        data: SrcData::User(segs),
        plain: false,
        seg: 0,
        used: 0,
        remaining,
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
        FileKind::Proc => procio::read(ctx, view, dest, pos),
        FileKind::Directory => Err(Errno::EISDIR.into()), // generic_read_dir
        FileKind::Char(CharDev::Null) => Ok(0),           // read_null
        FileKind::Char(CharDev::Zero | CharDev::Full) => Ok(read_zero(ctx, dest)?),
        FileKind::Char(CharDev::Console | CharDev::TtyAux | CharDev::TtyS0 | CharDev::HungUp) => {
            tty::read(ctx, view, dest)
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

/// `pipe_readable`: data, or no writer left (EOF).
fn pipe_readable<C: Context>(ctx: &mut C, pipe: crate::vfs::PipeId) -> bool {
    let p = ctx.files().vfs.pipe_ref(pipe);
    !p.is_empty() || p.writers == 0
}

/// `anon_pipe_read`: copies buffer by buffer; a read that got something returns
/// it (a short read), one that found nothing sleeps for a writer (`rd_wait`)
/// unless the pipe has none (EOF) or is non-blocking.
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
        let chars = {
            let p = ctx.files().vfs.pipe_ref(pipe);
            p.front().map(|front| {
                let n = front
                    .len()
                    .min(usize::try_from(total_len).unwrap_or(usize::MAX));
                bounce[..n].copy_from_slice(&front[..n]);
                n
            })
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
        if ctx.files().vfs.pipe_ref(pipe).writers == 0 || ret > 0 {
            break;
        }
        if view.flags & O_NONBLOCK != 0 {
            return Err(Errno::EAGAIN.into());
        }
        // `wait_event_interruptible_exclusive(pipe->rd_wait, pipe_readable(pipe))
        // < 0`: nothing was read, so the call restarts with no side effect.
        if let Err(restart) = wait_event_interruptible(ctx, PIPE_KEY, |c| pipe_readable(c, pipe)) {
            return Ok(restart);
        }
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
    let mut src = Src::one(buf, count)?;
    write_kind(ctx, view, &mut src, pos)
}

/// `do_writev`'s `vfs_writev` for the position `pos` (`None` for a stream).
fn vfs_writev<C: Context>(
    ctx: &mut C,
    view: &View,
    vec: u64,
    vlen: u64,
    pos: Option<&mut i64>,
) -> Sys {
    if view.mode & FMODE_WRITE == 0 {
        return Err(Errno::EBADF.into());
    }
    if view.mode & FMODE_CAN_WRITE == 0 {
        return Err(Errno::EINVAL.into());
    }
    let mut src = import_iovec_src(ctx, vec, vlen)?;
    if src.remaining == 0 {
        return Ok(0);
    }
    if let Some(p) = pos.as_deref() {
        verify_area(*p, src.remaining)?;
    }
    write_kind(ctx, view, &mut src, pos)
}

fn writev<C: Context>(ctx: &mut C, fd: u64, vec: u64, vlen: u64) -> Sys {
    let view = fdget(ctx, fd, false)?;
    let mut pos = view.pos;
    let n = vfs_writev(ctx, &view, vec, vlen, Some(&mut pos))?;
    set_pos(ctx, &view, pos);
    Ok(n)
}

fn pwritev<C: Context>(ctx: &mut C, fd: u64, vec: u64, vlen: u64, pos_l: u64) -> Sys {
    // pos_from_hilo on 64-bit: the high word shifts out entirely.
    #[allow(clippy::cast_possible_wrap)]
    let mut pos = pos_l as i64;
    if pos < 0 {
        return Err(Errno::EINVAL.into());
    }
    let view = fdget(ctx, fd, false)?;
    if view.mode & FMODE_PWRITE == 0 {
        return Err(Errno::ESPIPE.into());
    }
    vfs_writev(ctx, &view, vec, vlen, Some(&mut pos))
}

/// The `->write_iter`/`->write` of the file kind.
fn write_kind<C: Context>(ctx: &mut C, view: &View, src: &mut Src, pos: Option<&mut i64>) -> Sys {
    match view.kind {
        FileKind::Regular => {
            let (Some(pos), Some(inode)) = (pos, view.inode) else {
                return Err(Errno::EINVAL.into());
            };
            write_regular(ctx, view, inode, src, pos)
        }
        FileKind::Char(CharDev::Console | CharDev::TtyAux | CharDev::TtyS0 | CharDev::HungUp) => {
            tty::write(ctx, view, src)
        }
        // write_null / write_zero: the data is discarded, never read.
        FileKind::Char(CharDev::Null | CharDev::Zero) => {
            Ok(i64::try_from(src.remaining).unwrap_or(0))
        }
        FileKind::Char(CharDev::Full) => Err(Errno::ENOSPC.into()), // write_full
        FileKind::Pipe { pipe, writer: true } => pipe_write(ctx, view, pipe, src),
        FileKind::Directory | FileKind::Pipe { .. } | FileKind::Path => Err(Errno::EBADF.into()),
        // `proc_reg_write` of an entry without a `proc_write`.
        FileKind::Proc
            if view
                .inode
                .and_then(crate::procfs::ProcNode::of)
                .is_some_and(|node| node.kind == crate::procfs::Kind::Global) =>
        {
            Err(Errno::EIO.into())
        }
        FileKind::Proc
            if view
                .inode
                .and_then(crate::procfs::ProcNode::of)
                .is_some_and(|node| node.kind == crate::procfs::Kind::Comm) =>
        {
            write_loop(ctx, src, |ctx, base, len| {
                procio::comm_write(ctx, view, base, len)
            })
        }
        // The other writers (the writable sysctls) are not ported: the
        // write stops the kernel rather than succeed or fail as Linux does not.
        FileKind::Proc | FileKind::Unsupported => Err(Stop::Unimplemented),
    }
}

/// `do_loop_readv_writev` for a file with a `->write` but no `->write_iter`: one `write` per
/// non-empty segment, stopping at the first short or failed one (an error only when nothing
/// was written before). A `->write` takes a user buffer, so a kernel-held source has no segment to
/// hand it: that stops the kernel loudly instead of writing zero bytes (no path reaches it today;
/// a `splice` into a procfs file stops before this).
fn write_loop<C: Context>(
    ctx: &mut C,
    src: &mut Src,
    mut write: impl FnMut(&mut C, u64, u64) -> Sys,
) -> Sys {
    if matches!(src.data, SrcData::Kernel(_)) {
        return Err(Stop::Unimplemented);
    }
    if let Some((base, len)) = src.plain_buffer() {
        return write(ctx, base, len);
    }
    let mut ret: i64 = 0;
    while let Some((base, len)) = src.next_segment() {
        match write(ctx, base, len) {
            Ok(n) => {
                ret += n;
                if u64::try_from(n).ok() != Some(len) {
                    break;
                }
            }
            Err(error) if ret == 0 => return Err(error),
            Err(_) => break,
        }
    }
    Ok(ret)
}

/// `shmem_file_write_iter`: `generic_write_checks`, `file_remove_privs`,
/// `file_update_time`, `generic_perform_write`.
fn write_regular<C: Context>(
    ctx: &mut C,
    view: &View,
    inode: InodeId,
    src: &mut Src,
    pos: &mut i64,
) -> Sys {
    let count = src.remaining;
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
            ctx.state().send_sig(SIGXFSZ);
            return Err(Errno::EFBIG.into());
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
        let copied = src.copy_in(ctx, &mut bounce[..chunk]);
        if copied == 0 {
            status = Some(Errno::EFAULT);
            break;
        }
        // After the copy, which can itself fault a page of a mapping of this
        // file in (a source buffer inside the file's own mapping), and before
        // the file changes; a write that copies nothing changes nothing.
        ctx.files().vfs.note_modified(inode);
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
    src: &mut Src,
) -> Sys {
    let count = src.remaining;
    if count == 0 {
        return Ok(0);
    }
    if ctx.files().vfs.pipe_ref(pipe).readers == 0 {
        ctx.state().send_sig(SIGPIPE);
        return Err(Errno::EPIPE.into());
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
        if src.copy_in(ctx, &mut bounce[..chars]) != chars {
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
            ctx.state().send_sig(SIGPIPE);
            if ret == 0 {
                return Err(Errno::EPIPE.into());
            }
            break;
        }
        if !ctx.files().vfs.pipe_ref(pipe).is_full() {
            let want = remaining.min(PAGE_SIZE as u64) as usize;
            if src.copy_in(ctx, &mut bounce[..want]) != want {
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
        // Wait for buffer space to become available.
        if view.flags & O_NONBLOCK != 0 {
            if ret == 0 {
                return Err(Errno::EAGAIN.into());
            }
            break;
        }
        // `signal_pending` after the full-pipe checks: a partial write is
        // returned, an empty one restarts; otherwise sleep for a reader to make
        // room (`wr_wait`) or leave, then look at everything again.
        // `wait_event_interruptible` tests its condition before the signals, so
        // `Err` is a signal with the pipe still full (and a reader present).
        if let Err(restart) = wait_event_interruptible(ctx, PIPE_KEY, |c| pipe_writable(c, pipe)) {
            if ret == 0 {
                return Ok(restart);
            }
            break;
        }
    }
    Ok(i64::try_from(ret).unwrap_or(i64::MAX))
}

/// `pipe_writable`: room for a buffer, or no reader left (the write fails).
fn pipe_writable<C: Context>(ctx: &mut C, pipe: crate::vfs::PipeId) -> bool {
    let p = ctx.files().vfs.pipe_ref(pipe);
    !p.is_full() || p.readers == 0
}

// ---- sendfile ------------------------------------------------------------------

/// `SYSCALL_DEFINE4(sendfile64)` (x86-64 `sendfile`): `out_fd`/`in_fd` are `int`s,
/// `offset` an optional `loff_t *` read before and written back after the copy.
fn sendfile<C: Context>(ctx: &mut C, out_fd: u64, in_fd: u64, offset: u64, count: u64) -> Sys {
    if offset == 0 {
        return do_sendfile(ctx, out_fd, in_fd, None, count);
    }
    let mut raw = [0u8; 8];
    if copy_from_user(ctx, &mut raw, offset) != 0 {
        return Err(Errno::EFAULT.into());
    }
    let mut pos = i64::from_le_bytes(raw);
    let ret = do_sendfile(ctx, out_fd, in_fd, Some(&mut pos), count);
    if copy_to_user(ctx, offset, &pos.to_le_bytes()) != 0 {
        return Err(Errno::EFAULT.into());
    }
    ret
}

/// `do_sendfile` with `max == 0` (the smaller `s_maxbytes` of the two tmpfs files,
/// `MAX_LFS_FILESIZE`). Input: a regular file (every other kind that splices stops
/// loudly). Output: a pipe (`splice_file_to_pipe`: one pipe's worth), or a file
/// (`do_splice_direct`: through a 16 page pipe until `count` or the end of the file)
/// that has `->splice_write`: a regular file, the console tty, `/dev/null` and
/// `/dev/zero`. The pipe pages are copies of the file bytes, not the page cache's pages.
fn do_sendfile<C: Context>(
    ctx: &mut C,
    out_fd: u64,
    in_fd: u64,
    ppos: Option<&mut i64>,
    count: u64,
) -> Sys {
    let input = fdget(ctx, in_fd, false)?;
    if input.mode & FMODE_READ == 0 {
        return Err(Errno::EBADF.into());
    }
    let mut cursor = match ppos.as_deref() {
        None => input.pos,
        Some(p) => {
            if input.mode & FMODE_PREAD == 0 {
                return Err(Errno::ESPIPE.into());
            }
            *p
        }
    };
    verify_area(cursor, count)?;
    let mut count = count.min(u64::from(MAX_RW_COUNT));
    let output = fdget(ctx, out_fd, false)?;
    if output.mode & FMODE_WRITE == 0 {
        return Err(Errno::EBADF.into());
    }
    let mut out_pos = output.pos;
    let max = MAX_LFS_FILESIZE;
    if i128::from(cursor) + i128::from(count) > i128::from(max) {
        if cursor >= max {
            return Err(Errno::EOVERFLOW.into());
        }
        count = (max - cursor) as u64;
    }
    let moved = if let FileKind::Pipe { pipe, writer: true } = output.kind {
        splice_file_to_pipe(
            ctx,
            &input,
            output.flags & O_NONBLOCK != 0,
            pipe,
            &mut cursor,
            count,
        )?
    } else {
        // do_splice_direct's own checks, then the rw_verify_area of do_sendfile.
        verify_area(out_pos, count)?;
        if output.flags & O_APPEND != 0 {
            return Err(Errno::EINVAL.into());
        }
        splice_direct(ctx, &input, &output, &mut cursor, &mut out_pos, count)?
    };
    if moved > 0 {
        set_pos(ctx, &output, out_pos);
        match ppos {
            Some(p) => *p = cursor,
            None => set_pos(ctx, &input, cursor),
        }
    }
    if cursor > max {
        return Err(Errno::EOVERFLOW.into());
    }
    Ok(moved)
}

/// The bytes `shmem_file_splice_read` puts into a pipe with `free` empty slots:
/// at most `len`, the file's end and what the slots hold (the first buffer is the
/// rest of its page).
fn splice_chunk(pos: i64, size: u64, len: u64, free: usize) -> usize {
    let at = pos as u64;
    if at >= size || free == 0 {
        return 0;
    }
    let room = free as u64 * PAGE_SIZE as u64 - at % PAGE_SIZE as u64;
    usize::try_from(len.min(size - at).min(room)).unwrap_or(0)
}

/// What `do_splice_read` finds behind `input`: the inode of a regular file (the
/// only `->splice_read` ported), `-EINVAL` for the files without one (a pipe, a
/// directory, `/dev/null`), or a `->splice_read` (`copy_splice_read` on a tty,
/// `/dev/zero`, `/dev/full`) that is not ported.
fn splice_source(input: &View) -> Result<InodeId, Stop> {
    match (input.kind, input.inode) {
        (FileKind::Regular, Some(inode)) => Ok(inode),
        (FileKind::Directory | FileKind::Pipe { .. } | FileKind::Char(CharDev::Null), _) => {
            Err(Errno::EINVAL.into())
        }
        _ => Err(Stop::Unimplemented),
    }
}

/// `splice_file_to_pipe`: wait for room (`wait_for_space`), then `do_splice_read` once.
fn splice_file_to_pipe<C: Context>(
    ctx: &mut C,
    input: &View,
    nonblock: bool,
    pipe: crate::vfs::PipeId,
    pos: &mut i64,
    count: u64,
) -> Sys {
    loop {
        let p = ctx.files().vfs.pipe_ref(pipe);
        if p.readers == 0 {
            ctx.state().send_sig(SIGPIPE);
            return Err(Errno::EPIPE.into());
        }
        if !p.is_full() {
            break;
        }
        if nonblock {
            return Err(Errno::EAGAIN.into());
        }
        if let Err(restart) = wait_event_interruptible(ctx, PIPE_KEY, |c| pipe_writable(c, pipe)) {
            return Ok(restart);
        }
    }
    // do_splice_read: nothing to read is not an error, whatever the file.
    if count == 0 {
        return Ok(0);
    }
    let inode = splice_source(input)?;
    let (size, free) = {
        let vfs = &*ctx.files().vfs;
        let p = vfs.pipe_ref(pipe);
        (vfs.fs.inode(inode).size, p.max_usage - p.slots_used())
    };
    let total = splice_chunk(*pos, size, count, free);
    let mut moved = 0usize;
    let mut page = [0u8; PAGE_SIZE];
    while moved < total {
        let at = (*pos as u64) + moved as u64;
        let take = (PAGE_SIZE - (at % PAGE_SIZE as u64) as usize).min(total - moved);
        let got = ctx.files().vfs.fs.read(inode, at, &mut page[..take]);
        if got == 0 {
            break;
        }
        ctx.files().vfs.pipe_mut(pipe).push_spliced(&page[..got])?;
        moved += got;
    }
    // shmem_file_splice_read ends in file_accessed(in).
    if input.flags & O_NOATIME == 0 {
        ctx.files().vfs.fs.touch_atime(inode);
    }
    *pos += moved as i64;
    Ok(moved as i64)
}

/// `do_splice_direct` -> `splice_direct_to_actor`: the input must be seekable; read
/// a chunk of at most a 16 page pipe from it, hand it to the output's
/// `->splice_write`, repeat until `count` bytes, the end of the input or a short or
/// failed write. The result is the bytes written, or the first error when nothing was.
fn splice_direct<C: Context>(
    ctx: &mut C,
    input: &View,
    output: &View,
    pos: &mut i64,
    out_pos: &mut i64,
    count: u64,
) -> Sys {
    if input.mode & FMODE_LSEEK == 0 {
        return Err(Errno::EINVAL.into());
    }
    // Which outputs have a `->splice_write` (`do_splice_from` answers -EINVAL
    // for the others, once there are data to write).
    let splice_write = match output.kind {
        FileKind::Regular
        | FileKind::Char(
            CharDev::Null
            | CharDev::Zero
            | CharDev::Console
            | CharDev::TtyAux
            | CharDev::TtyS0
            | CharDev::HungUp,
        ) => true,
        FileKind::Char(CharDev::Full) | FileKind::Directory => false,
        _ => return Err(Stop::Unimplemented),
    };
    let mut bytes: i64 = 0;
    let mut left = count;
    let mut failure: Option<Stop> = None;
    while left > 0 {
        let inode = match splice_source(input) {
            Ok(inode) => inode,
            Err(stop) => {
                failure = Some(stop);
                break;
            }
        };
        let size = ctx.files().vfs.fs.inode(inode).size;
        let chunk = splice_chunk(*pos, size, left, crate::vfs::pipe::PIPE_DEF_BUFFERS);
        if chunk == 0 {
            break;
        }
        let mut data = Vec::new();
        data.try_reserve_exact(chunk).map_err(|_| Errno::ENOMEM)?;
        let mut page = [0u8; PAGE_SIZE];
        while data.len() < chunk {
            let at = *pos as u64 + data.len() as u64;
            let take = (PAGE_SIZE - (at % PAGE_SIZE as u64) as usize).min(chunk - data.len());
            let n = ctx.files().vfs.fs.read(inode, at, &mut page[..take]);
            if n == 0 {
                break;
            }
            for &byte in &page[..n] {
                // The room was reserved above.
                let _ = data.push_within_capacity(byte);
            }
        }
        let read_len = data.len() as i64;
        if read_len == 0 {
            break;
        }
        let result = if splice_write {
            let mut src = Src::kernel(data);
            match output.kind {
                FileKind::Regular => match output.inode {
                    Some(out_inode) => write_regular(ctx, output, out_inode, &mut src, out_pos),
                    None => Err(Errno::EINVAL.into()),
                },
                FileKind::Char(CharDev::Null | CharDev::Zero) => Ok(read_len),
                _ => tty::write(ctx, output, &mut src),
            }
        } else {
            Err(Errno::EINVAL.into()) // warn_unsupported(out, "write")
        };
        match result {
            Ok(n) if n > 0 => {
                bytes += n;
                left -= n as u64;
                *pos += n;
                if n < read_len {
                    break;
                }
            }
            Ok(_) => break,
            Err(stop) => {
                failure = Some(stop);
                break;
            }
        }
    }
    // `done:` -> file_accessed(in), whatever happened.
    if input.flags & O_NOATIME == 0
        && let Some(inode) = input.inode
    {
        ctx.files().vfs.fs.touch_atime(inode);
    }
    if bytes > 0 {
        return Ok(bytes);
    }
    match failure {
        Some(stop) => Err(stop),
        None => Ok(0),
    }
}

// ---- splice --------------------------------------------------------------------

/// `SPLICE_F_NONBLOCK` and `SPLICE_F_ALL` (`MOVE | NONBLOCK | MORE | GIFT`).
const SPLICE_F_NONBLOCK: u64 = 2;
const SPLICE_F_ALL: u64 = 0xf;

/// `SYSCALL_DEFINE6(splice)`: `fd_in`/`fd_out` are `int`s, `off_in`/`off_out` optional
/// `loff_t *` read before and written back after the copy, `len` a `size_t`, `flags` an
/// `unsigned int`.
///
/// * Checks in Linux's order: a zero length is 0 (before anything else), unknown flags are
///   `EINVAL`, `fd_in` then `fd_out` `EBADF`, an offset for a pipe `ESPIPE` (`__do_splice`),
///   the offsets are read (`EFAULT`), then `do_splice`: `FMODE_READ`/`FMODE_WRITE` (`EBADF`),
///   and the pipe combination.
/// * A regular file into a pipe is `splice_file_to_pipe` (what `sendfile` shares), a pipe into a
///   pipe `splice_pipe_to_pipe` (buffers are moved, a partly used one is copied), a pipe into a
///   file `iter_file_splice_write` (a regular file, the tty or `/dev/null`/`/dev/zero`).
///   shortcut: the non-regular inputs (`copy_splice_read`) pass every check and stop loudly
///   (the tty `->splice_read` is not ported); two non-pipes are `EINVAL`, and a pipe spliced
///   to itself too.
fn splice<C: Context>(ctx: &mut C, a: [u64; 6]) -> Sys {
    let [fd_in, off_in, fd_out, off_out, len, flags] = a;
    if len == 0 {
        return Ok(0);
    }
    if (flags & 0xffff_ffff) & !SPLICE_F_ALL != 0 {
        return Err(Errno::EINVAL.into());
    }
    let input = fdget(ctx, fd_in, false)?;
    let output = fdget(ctx, fd_out, false)?;
    let ipipe = matches!(input.kind, FileKind::Pipe { .. });
    let opipe = matches!(output.kind, FileKind::Pipe { .. });
    if (ipipe && off_in != 0) || (opipe && off_out != 0) {
        return Err(Errno::ESPIPE.into());
    }
    let read_offset = |ctx: &mut C, at: u64| -> Result<Option<i64>, Errno> {
        if at == 0 {
            return Ok(None);
        }
        let mut raw = [0u8; 8];
        if copy_from_user(ctx, &mut raw, at) != 0 {
            return Err(Errno::EFAULT);
        }
        Ok(Some(i64::from_le_bytes(raw)))
    };
    // __do_splice reads off_out first, then off_in.
    let mut out_offset = read_offset(ctx, off_out)?;
    let mut in_offset = read_offset(ctx, off_in)?;
    // do_splice
    if input.mode & FMODE_READ == 0 || output.mode & FMODE_WRITE == 0 {
        return Err(Errno::EBADF.into());
    }
    let moved = if let (FileKind::Pipe { pipe: from, .. }, FileKind::Pipe { pipe: to, .. }) =
        (input.kind, output.kind)
    {
        if from == to {
            return Err(Errno::EINVAL.into());
        }
        let nonblock =
            flags & SPLICE_F_NONBLOCK != 0 || (input.flags | output.flags) & O_NONBLOCK != 0;
        splice_pipe_to_pipe(ctx, from, to, len, nonblock)?
    } else if let FileKind::Pipe { pipe: from, .. } = input.kind {
        if out_offset.is_some() && output.mode & FMODE_PWRITE == 0 {
            return Err(Errno::EINVAL.into());
        }
        if output.flags & O_APPEND != 0 {
            return Err(Errno::EINVAL.into());
        }
        let mut cursor = out_offset.unwrap_or(output.pos);
        verify_area(cursor, len)?;
        let nonblock = flags & SPLICE_F_NONBLOCK != 0 || input.flags & O_NONBLOCK != 0;
        let moved = splice_from_pipe(ctx, from, &output, &mut cursor, len, nonblock)?;
        match out_offset.as_mut() {
            Some(offset) => *offset = cursor,
            None => set_pos(ctx, &output, cursor),
        }
        moved
    } else if let FileKind::Pipe { pipe, .. } = output.kind {
        let mut cursor = match in_offset {
            Some(offset) => {
                if input.mode & FMODE_PREAD == 0 {
                    return Err(Errno::EINVAL.into());
                }
                offset
            }
            None => input.pos,
        };
        verify_area(cursor, len)?;
        let nonblock = flags & SPLICE_F_NONBLOCK != 0 || output.flags & O_NONBLOCK != 0;
        // do_splice_read: not more than the pipe has room for, not more than MAX_RW_COUNT.
        let count = len.min(u64::from(MAX_RW_COUNT));
        let moved = splice_file_to_pipe(ctx, &input, nonblock, pipe, &mut cursor, count)?;
        match in_offset.as_mut() {
            Some(offset) => *offset = cursor,
            None => set_pos(ctx, &input, cursor),
        }
        moved
    } else {
        return Err(Errno::EINVAL.into());
    };
    // __do_splice: the offsets go back (a fault here replaces the count).
    if let Some(offset) = out_offset.as_mut()
        && copy_to_user(ctx, off_out, &offset.to_le_bytes()) != 0
    {
        return Err(Errno::EFAULT.into());
    }
    if let Some(offset) = in_offset
        && copy_to_user(ctx, off_in, &offset.to_le_bytes()) != 0
    {
        return Err(Errno::EFAULT.into());
    }
    Ok(moved)
}

/// `ipipe_prep`: wait for data in `pipe` (`Err` carries the system call's final result).
fn ipipe_prep<C: Context>(
    ctx: &mut C,
    pipe: crate::vfs::PipeId,
    nonblock: bool,
) -> Result<(), Sys> {
    while ctx.files().vfs.pipe_ref(pipe).is_empty() {
        if ctx.state().signal_pending() {
            return Err(Ok(-crate::signal::wait::ERESTARTSYS));
        }
        if ctx.files().vfs.pipe_ref(pipe).writers == 0 {
            break;
        }
        if nonblock {
            return Err(Err(Errno::EAGAIN.into()));
        }
        let readable = |c: &mut C| {
            let p = c.files().vfs.pipe_ref(pipe);
            !p.is_empty() || p.writers == 0
        };
        if let Err(restart) = wait_event_interruptible(ctx, PIPE_KEY, readable) {
            return Err(Ok(restart));
        }
    }
    Ok(())
}

/// `opipe_prep`: wait for room in `pipe`.
fn opipe_prep<C: Context>(
    ctx: &mut C,
    pipe: crate::vfs::PipeId,
    nonblock: bool,
) -> Result<(), Sys> {
    while ctx.files().vfs.pipe_ref(pipe).is_full() {
        if ctx.files().vfs.pipe_ref(pipe).readers == 0 {
            ctx.state().send_sig(SIGPIPE);
            return Err(Err(Errno::EPIPE.into()));
        }
        if nonblock {
            return Err(Err(Errno::EAGAIN.into()));
        }
        if ctx.state().signal_pending() {
            return Err(Ok(-crate::signal::wait::ERESTARTSYS));
        }
        if let Err(restart) = wait_event_interruptible(ctx, PIPE_KEY, |c| pipe_writable(c, pipe)) {
            return Err(Ok(restart));
        }
    }
    Ok(())
}

/// `splice_pipe_to_pipe`: move buffers from `from` to `to`, up to `len` bytes.
fn splice_pipe_to_pipe<C: Context>(
    ctx: &mut C,
    from: crate::vfs::PipeId,
    to: crate::vfs::PipeId,
    mut len: u64,
    nonblock: bool,
) -> Sys {
    'retry: loop {
        if let Err(done) = ipipe_prep(ctx, from, nonblock) {
            return done;
        }
        if let Err(done) = opipe_prep(ctx, to, nonblock) {
            return done;
        }
        let mut ret: i64 = 0;
        loop {
            if ctx.files().vfs.pipe_ref(to).readers == 0 {
                ctx.state().send_sig(SIGPIPE);
                if ret == 0 {
                    return Err(Errno::EPIPE.into());
                }
                break;
            }
            let (empty, writers) = {
                let p = ctx.files().vfs.pipe_ref(from);
                (p.is_empty(), p.writers)
            };
            if empty && writers == 0 {
                break;
            }
            // Cannot make any progress: the input is empty or the output is full.
            if empty || ctx.files().vfs.pipe_ref(to).is_full() {
                if ret != 0 {
                    break;
                }
                if nonblock {
                    return Err(Errno::EAGAIN.into());
                }
                // Raced with another reader or writer: a zero would mean EOF, so retry.
                continue 'retry;
            }
            // Linux moves ring slots and never allocates: make the room in `to` first so that a
            // buffer detached from `from` can always be queued (no byte is ever dropped).
            let front = ctx.files().vfs.pipe_ref(from).front_len() as u64;
            let moved_buf = ctx.files().vfs.pipe_mut(to).reserve_buf().and_then(|()| {
                if len >= front {
                    let buf = ctx.files().vfs.pipe_mut(from).take_front();
                    buf.map(|buf| (buf, front)).ok_or(Errno::EINVAL)
                } else {
                    let buf = ctx.files().vfs.pipe_mut(from).split_front(len as usize);
                    buf.map(|buf| (buf, len))
                }
            });
            let (buf, moved) = match moved_buf {
                Ok(pair) => pair,
                Err(error) if ret == 0 => return Err(error.into()),
                Err(_) => break,
            };
            let queued = ctx.files().vfs.pipe_mut(to).push_buf(buf);
            assert!(
                queued.is_ok(),
                "splice: the room was reserved in the output pipe"
            );
            ret += moved as i64;
            len -= moved;
            if len == 0 {
                break;
            }
        }
        return Ok(ret);
    }
}

/// `iter_file_splice_write` (and the `splice_write_null`/`zero` of the memory devices): gather
/// the buffered bytes, write them to `output`, consume what was written, until `len` bytes are
/// done, the pipe is drained after at least one write, or it is empty with no writer left.
/// Outputs without a `->splice_write` (`/dev/full`) are `EINVAL` at once (`do_splice_from`).
fn splice_from_pipe<C: Context>(
    ctx: &mut C,
    pipe: crate::vfs::PipeId,
    output: &View,
    pos: &mut i64,
    len: u64,
    nonblock: bool,
) -> Sys {
    let splice_write = match output.kind {
        FileKind::Regular
        | FileKind::Char(
            CharDev::Null
            | CharDev::Zero
            | CharDev::Console
            | CharDev::TtyAux
            | CharDev::TtyS0
            | CharDev::HungUp,
        ) => true,
        FileKind::Char(CharDev::Full) | FileKind::Directory => false,
        _ => return Err(Stop::Unimplemented),
    };
    // do_splice_from: an output without ->splice_write is EINVAL before the pipe is touched.
    if !splice_write {
        return Err(Errno::EINVAL.into()); // warn_unsupported(out, "write")
    }
    let mut total = len;
    let mut spliced: i64 = 0;
    let mut result: Sys = Ok(0);
    while total > 0 {
        // splice_from_pipe_next
        if ctx.state().signal_pending() {
            result = Ok(-crate::signal::wait::ERESTARTSYS);
            break;
        }
        let mut stop = false;
        while ctx.files().vfs.pipe_ref(pipe).is_empty() {
            if ctx.files().vfs.pipe_ref(pipe).writers == 0 || spliced > 0 {
                stop = true;
                result = Ok(0);
                break;
            }
            if nonblock {
                stop = true;
                result = Err(Errno::EAGAIN.into());
                break;
            }
            if ctx.state().signal_pending() {
                stop = true;
                result = Ok(-crate::signal::wait::ERESTARTSYS);
                break;
            }
            let readable = |c: &mut C| {
                let p = c.files().vfs.pipe_ref(pipe);
                !p.is_empty() || p.writers == 0
            };
            if let Err(restart) = wait_event_interruptible(ctx, PIPE_KEY, readable) {
                stop = true;
                result = Ok(restart);
                break;
            }
        }
        if stop {
            break;
        }
        // Build the vector: at most `total` bytes of the buffers.
        let mut data = Vec::new();
        let take = usize::try_from(total).unwrap_or(usize::MAX);
        if let Err(error) = ctx.files().vfs.pipe_ref(pipe).peek(take, &mut data) {
            // Out of memory after some bytes were written is a short count.
            result = Err(error.into());
            break;
        }
        let gathered = data.len() as i64;
        if gathered == 0 {
            break;
        }
        let mut src = Src::kernel(data);
        let written = match output.kind {
            FileKind::Regular => match output.inode {
                Some(inode) => write_regular(ctx, output, inode, &mut src, pos),
                None => Err(Errno::EINVAL.into()),
            },
            FileKind::Char(CharDev::Null | CharDev::Zero) => Ok(gathered),
            _ => tty::write(ctx, output, &mut src),
        };
        match written {
            Ok(n) if n > 0 => {
                ctx.files().vfs.pipe_mut(pipe).consume_bytes(n as usize);
                spliced += n;
                total -= n as u64;
            }
            Ok(_) => break,
            Err(failure) => {
                result = Err(failure);
                break;
            }
        }
    }
    if spliced > 0 { Ok(spliced) } else { result }
}

/// `SYSCALL_DEFINE4(vmsplice)`: `fd` an `int`, `nr_segs` an `unsigned long`, `flags` an
/// `unsigned int`. The write end of a pipe takes user memory (`ITER_SOURCE`), the read end
/// gives it out (`ITER_DEST`); anything else is `EBADF`.
///
/// shortcut: the pipe gets copies of the user pages (`iter_to_pipe` pins them, so a later store
/// to the buffer shows in the pipe until it is read; the manual forbids relying on that).
fn vmsplice<C: Context>(ctx: &mut C, fd: u64, uiov: u64, nr_segs: u64, flags: u64) -> Sys {
    if (flags & 0xffff_ffff) & !SPLICE_F_ALL != 0 {
        return Err(Errno::EINVAL.into());
    }
    let view = fdget(ctx, u64::from(fd as u32), false)?;
    let source = if view.mode & FMODE_WRITE != 0 {
        true
    } else if view.mode & FMODE_READ != 0 {
        false
    } else {
        return Err(Errno::EBADF.into());
    };
    // import_iovec first and the empty iterator's zero before `get_pipe_info` (EBADF), as in
    // fs/splice.c:1600-1608.
    let (segs, total) = import_segs(ctx, uiov, nr_segs)?;
    if total == 0 {
        return Ok(0);
    }
    let FileKind::Pipe { pipe, .. } = view.kind else {
        return Err(Errno::EBADF.into());
    };
    let nonblock = flags & SPLICE_F_NONBLOCK != 0;
    if source {
        vmsplice_to_pipe(ctx, pipe, &segs, nonblock)
    } else {
        vmsplice_to_user(ctx, pipe, segs, total, nonblock)
    }
}

/// `vmsplice_to_pipe`: `wait_for_space`, then `iter_to_pipe`, one buffer per user page.
fn vmsplice_to_pipe<C: Context>(
    ctx: &mut C,
    pipe: crate::vfs::PipeId,
    segs: &[(u64, u64)],
    nonblock: bool,
) -> Sys {
    // wait_for_space
    loop {
        if ctx.files().vfs.pipe_ref(pipe).readers == 0 {
            ctx.state().send_sig(SIGPIPE);
            return Err(Errno::EPIPE.into());
        }
        if !ctx.files().vfs.pipe_ref(pipe).is_full() {
            break;
        }
        if nonblock {
            return Err(Errno::EAGAIN.into());
        }
        if ctx.state().signal_pending() {
            return Ok(-crate::signal::wait::ERESTARTSYS);
        }
        if let Err(restart) = wait_event_interruptible(ctx, PIPE_KEY, |c| pipe_writable(c, pipe)) {
            return Ok(restart);
        }
    }
    let mut total: i64 = 0;
    let mut failure: Option<Errno> = None;
    let mut page = [0u8; PAGE_SIZE];
    'segments: for &(base, len) in segs {
        let mut done = 0u64;
        while done < len {
            let at = base + done;
            let chunk = (len - done).min((PAGE_SIZE as u64) - at % PAGE_SIZE as u64) as usize;
            // iov_iter_get_pages2: a page that cannot be pinned ends the walk.
            if copy_from_user(ctx, &mut page[..chunk], at) != 0 {
                failure = Some(Errno::EFAULT);
                break 'segments;
            }
            // add_to_pipe: a full pipe ends it with EAGAIN.
            let vfs = &mut *ctx.files().vfs;
            if vfs.pipe_ref(pipe).is_full() {
                failure = Some(Errno::EAGAIN);
                break 'segments;
            }
            // Out of memory after some bytes were queued is a short count, as for a fault.
            if let Err(error) = vfs.pipe_mut(pipe).push_spliced(&page[..chunk]) {
                failure = Some(error);
                break 'segments;
            }
            total += chunk as i64;
            done += chunk as u64;
        }
    }
    if total > 0 {
        return Ok(total);
    }
    Err(failure.unwrap_or(Errno::EINVAL).into())
}

/// `vmsplice_to_user` -> `__splice_from_pipe(pipe_to_user)`.
fn vmsplice_to_user<C: Context>(
    ctx: &mut C,
    pipe: crate::vfs::PipeId,
    segs: Vec<(u64, u64)>,
    count: u64,
    nonblock: bool,
) -> Sys {
    let mut dest = Dest {
        segs,
        seg: 0,
        used: 0,
        remaining: count,
    };
    let mut total = count;
    let mut spliced: i64 = 0;
    let mut result: Sys = Ok(0);
    'outer: while total > 0 {
        // splice_from_pipe_next
        if ctx.state().signal_pending() {
            result = Ok(-crate::signal::wait::ERESTARTSYS);
            break;
        }
        while ctx.files().vfs.pipe_ref(pipe).is_empty() {
            if ctx.files().vfs.pipe_ref(pipe).writers == 0 || spliced > 0 {
                result = Ok(0);
                break 'outer;
            }
            if nonblock {
                result = Err(Errno::EAGAIN.into());
                break 'outer;
            }
            if ctx.state().signal_pending() {
                result = Ok(-crate::signal::wait::ERESTARTSYS);
                break 'outer;
            }
            let readable = |c: &mut C| {
                let p = c.files().vfs.pipe_ref(pipe);
                !p.is_empty() || p.writers == 0
            };
            if let Err(restart) = wait_event_interruptible(ctx, PIPE_KEY, readable) {
                result = Ok(restart);
                break 'outer;
            }
        }
        // splice_from_pipe_feed
        while total > 0 && !ctx.files().vfs.pipe_ref(pipe).is_empty() {
            let mut piece = Vec::new();
            let want = usize::try_from(total).unwrap_or(usize::MAX);
            let front = ctx.files().vfs.pipe_ref(pipe).front_len().min(want);
            if let Err(error) = ctx.files().vfs.pipe_ref(pipe).peek(front, &mut piece) {
                result = Err(error.into());
                break 'outer;
            }
            if piece.is_empty() {
                // eat_empty_buffer
                ctx.files().vfs.pipe_mut(pipe).consume(0);
                break;
            }
            // pipe_to_user: a short copy is -EFAULT (and the bytes stay in the pipe).
            let copied = dest.copy_out(ctx, &piece);
            if copied != piece.len() {
                result = Err(Errno::EFAULT.into());
                break 'outer;
            }
            ctx.files().vfs.pipe_mut(pipe).consume(copied);
            spliced += copied as i64;
            total -= copied as u64;
        }
    }
    if spliced > 0 { Ok(spliced) } else { result }
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
        FileKind::Proc => {
            return procio::lseek(ctx, &view, whence, offset)
                .inspect(|&new| set_pos(ctx, &view, new));
        }
        FileKind::Directory if view.inode.is_some_and(InodeId::is_proc) => {
            // generic_file_llseek on a procfs directory (i_size 0).
            procio::generic_llseek(view.pos, offset, whence)?
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
            FileKind::Pipe { pipe, .. } => pipe_set_size(ctx, pipe, argi),
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

/// `pipe_set_size` (`F_SETPIPE_SZ`): the capacity becomes `arg` rounded up to a
/// power of two pages (`round_pipe_size`); the call answers the new size.
/// `EBUSY` when more buffers hold data than the new capacity has slots.
/// The ring is not preallocated, so `ENOMEM` cannot happen here.
///
/// A task without `CAP_SYS_RESOURCE` is limited to `pipe_max_size` and to the
/// per-user buffer budget (`account_pipe_buffers`, `pipe-user-pages-*`), which
/// this kernel does not account: every task is root today (every credential
/// syscall stops the kernel), and a non-root one stops loudly instead of
/// skipping the checks.
fn pipe_set_size<C: Context>(ctx: &mut C, pipe: crate::vfs::PipeId, arg: u32) -> Sys {
    let Some(size) = crate::vfs::pipe::Pipe::round_pipe_size(arg) else {
        return Err(Errno::EINVAL.into());
    };
    let nr_slots = (size >> 12) as usize;
    if nr_slots == 0 {
        return Err(Errno::EINVAL.into());
    }
    if ctx.attrs().cred.euid != 0 {
        return Err(Stop::Unimplemented);
    }
    ctx.files().vfs.pipe_mut(pipe).set_slots(nr_slots)?;
    Ok(i64::from(size))
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
        (Some(inode), _) => vfs.fs.node_attr(inode).uid,
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
        && (matches!(view.kind, FileKind::Pipe { .. } | FileKind::Unsupported)
            || matches!(view.kind, FileKind::Char(dev) if dev.is_tty()))
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

#[allow(clippy::too_many_lines)] // one arm per ioctl family
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
            if let Some(inode) = view.inode.filter(|inode| !inode.is_proc()) {
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
        FICLONE => return file_clone(ctx, &view, arg),
        FICLONERANGE => {
            // ioctl_file_clone_range: `struct file_clone_range` is {s64 src_fd; u64 src_offset;
            // u64 src_length; u64 dest_offset}; the descriptor is read as the `s64` low word.
            let mut raw = [0u8; 32];
            if copy_from_user(ctx, &mut raw, arg) != 0 {
                return Err(Errno::EFAULT.into());
            }
            let src_fd = u64::from_le_bytes(raw[..8].try_into().unwrap_or([0; 8]));
            return file_clone(ctx, &view, src_fd);
        }
        // ->fileattr_set, FIEMAP, dedupe, filesystem UUID and sysfs path have answers other
        // than ENOTTY on tmpfs that are not ported.
        FS_IOC_SETFLAGS
        | FS_IOC_FSSETXATTR
        | FS_IOC_FIEMAP
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
        // do_vfs_ioctl: any S_ISREG inode answers `i_size - f_pos` (procfs files: 0, or the
        // `pde->size` of `cmdline`, minus the position, possibly negative).
        FIONREAD if matches!(view.kind, FileKind::Proc) => {
            let Some(inode) = view.inode else {
                return Err(Errno::ENOTTY.into());
            };
            let st = ctx.files().vfs.fs.getattr(inode);
            if st.mode & 0o170_000 != 0o100_000 {
                return Err(Errno::ENOTTY.into());
            }
            let left = i32::try_from(st.size - view.pos).unwrap_or(i32::MAX);
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
        FileKind::Char(CharDev::Console | CharDev::TtyAux | CharDev::TtyS0 | CharDev::HungUp) => {
            tty::ioctl(ctx, &view, cmd, arg)
        }
        FileKind::Unsupported => Err(Stop::Unimplemented),
        _ => Err(Errno::ENOTTY.into()),
    }
}

/// `generic_file_rw_checks`: a directory is `EISDIR`, anything but two regular files `EINVAL`,
/// then the modes (`EBADF`).
fn generic_file_rw_checks<C: Context>(ctx: &mut C, src: &View, dst: &View) -> Result<(), Stop> {
    let fs = &ctx.files().vfs.fs;
    let kind = |view: &View| match view.kind {
        FileKind::Directory => crate::vfs::S_IFDIR,
        FileKind::Regular => crate::vfs::S_IFREG,
        FileKind::Proc => view
            .inode
            .map_or(0, |inode| fs.node_attr(inode).mode & S_IFMT),
        FileKind::Pipe { .. } => 0o010_000,
        _ => 0o020_000,
    };
    let (in_type, out_type) = (kind(src), kind(dst));
    if in_type == crate::vfs::S_IFDIR || out_type == crate::vfs::S_IFDIR {
        return Err(Errno::EISDIR.into());
    }
    if in_type != crate::vfs::S_IFREG || out_type != crate::vfs::S_IFREG {
        return Err(Errno::EINVAL.into());
    }
    if src.mode & FMODE_READ == 0 || dst.mode & FMODE_WRITE == 0 || dst.flags & O_APPEND != 0 {
        return Err(Errno::EBADF.into());
    }
    Ok(())
}

/// Whether two open files are on the same super block (a pipe's inode is on pipefs).
fn same_super_block<C: Context>(ctx: &mut C, a: &View, b: &View) -> Result<bool, Stop> {
    let fs = &ctx.files().vfs.fs;
    let sb_of = |view: &View| view.inode.map(|inode| fs.sb_of(inode));
    Ok(match (&a.kind, &b.kind) {
        (FileKind::Pipe { .. }, FileKind::Pipe { .. }) => true,
        (FileKind::Pipe { .. }, _) | (_, FileKind::Pipe { .. }) => false,
        _ => match (sb_of(a), sb_of(b)) {
            (Some(x), Some(y)) => x == y,
            _ => return Err(Stop::Unimplemented),
        },
    })
}

/// `SYSCALL_DEFINE6(copy_file_range)` -> `vfs_copy_file_range`. Every file system here is
/// without `->copy_file_range` and `->remap_file_range`, so a copy within one super block is
/// `do_splice_direct` and a copy across two is `EXDEV` (`generic_copy_file_checks`).
fn copy_file_range<C: Context>(ctx: &mut C, a: [u64; 6]) -> Sys {
    let [fd_in, off_in, fd_out, off_out, len, flags] = a;
    let input = fdget(ctx, fd_in, false)?;
    let output = fdget(ctx, fd_out, false)?;
    let read_offset = |ctx: &mut C, at: u64, default: i64| -> Result<i64, Errno> {
        if at == 0 {
            return Ok(default);
        }
        let mut raw = [0u8; 8];
        if copy_from_user(ctx, &mut raw, at) != 0 {
            return Err(Errno::EFAULT);
        }
        Ok(i64::from_le_bytes(raw))
    };
    let mut pos_in = read_offset(ctx, off_in, input.pos)?;
    let mut pos_out = read_offset(ctx, off_out, output.pos)?;
    if flags & 0xffff_ffff != 0 {
        return Err(Errno::EINVAL.into());
    }
    // generic_copy_file_checks
    generic_file_rw_checks(ctx, &input, &output)?;
    if !same_super_block(ctx, &input, &output)? {
        return Err(Errno::EXDEV.into());
    }
    // (IS_IMMUTABLE and IS_SWAPFILE never hold.)
    let mut count = len;
    if (pos_in as u64).wrapping_add(count) < pos_in as u64
        || (pos_out as u64).wrapping_add(count) < pos_out as u64
    {
        return Err(Errno::EOVERFLOW.into());
    }
    // Shorten the copy to EOF.
    let (Some(in_inode), Some(out_inode)) = (input.inode, output.inode) else {
        return Err(Stop::Unimplemented);
    };
    let size_in = i64::try_from(ctx.files().vfs.fs.inode(in_inode).size).unwrap_or(i64::MAX);
    // The offsets are the caller's and may be negative: the C subtracts in uint64_t / loff_t
    // (-fwrapv), so every step wraps and a bad offset fails later in `rw_verify_area`.
    count = if pos_in >= size_in {
        0
    } else {
        count.min((size_in as u64).wrapping_sub(pos_in as u64))
    };
    // generic_write_check_limits: `count` is a loff_t there.
    #[allow(clippy::cast_possible_wrap)]
    let mut limited = count as i64;
    let limit = ctx.rlimit_fsize();
    if limit != RLIM_INFINITY {
        let limit = limit as i64;
        if pos_out >= limit {
            ctx.state().send_sig(SIGXFSZ);
            return Err(Errno::EFBIG.into());
        }
        limited = limited.min(limit.wrapping_sub(pos_out));
    }
    let max_size = if output.flags & O_LARGEFILE == 0 {
        MAX_NON_LFS
    } else {
        MAX_LFS_FILESIZE
    };
    if pos_out >= max_size {
        return Err(Errno::EFBIG.into());
    }
    limited = limited.min(max_size.wrapping_sub(pos_out));
    count = limited as u64;
    // Don't allow overlapped copying within the same file.
    if in_inode == out_inode
        && (pos_out as u64).wrapping_add(count) > pos_in as u64
        && (pos_out as u64) < (pos_in as u64).wrapping_add(count)
    {
        return Err(Errno::EINVAL.into());
    }
    verify_area(pos_in, count)?;
    verify_area(pos_out, count)?;
    if count == 0 {
        return Ok(0);
    }
    let count = count.min(u64::from(MAX_RW_COUNT));
    // do_splice_direct
    if output.flags & O_APPEND != 0 {
        return Err(Errno::EINVAL.into());
    }
    let mut cursor = pos_in;
    let mut out_cursor = pos_out;
    let moved = splice_direct(ctx, &input, &output, &mut cursor, &mut out_cursor, count)?;
    if moved > 0 {
        pos_in += moved;
        pos_out += moved;
        // A failing store of one offset is -EFAULT but the other offset is still updated.
        let mut fault = false;
        if off_in != 0 {
            fault |= copy_to_user(ctx, off_in, &pos_in.to_le_bytes()) != 0;
        } else {
            set_pos(ctx, &input, pos_in);
        }
        if off_out != 0 {
            fault |= copy_to_user(ctx, off_out, &pos_out.to_le_bytes()) != 0;
        } else {
            set_pos(ctx, &output, pos_out);
        }
        if fault {
            return Err(Errno::EFAULT.into());
        }
    }
    Ok(moved)
}

/// `ioctl_file_clone` -> `vfs_clone_file_range` up to the first answer that needs the file
/// system: `EBADF` for a bad source, `EXDEV` across super blocks, `generic_file_rw_checks`
/// (`EISDIR`, `EINVAL`, `EBADF`), then `EOPNOTSUPP`: tmpfs, procfs and pipefs have no
/// `->remap_file_range`, so no clone ever succeeds here and the offsets and length are never
/// looked at.
fn file_clone<C: Context>(ctx: &mut C, dst: &View, src_fd: u64) -> Sys {
    // `CLASS(fd, src_file)(srcfd)`: the argument is an `unsigned long` taken as an `int`.
    let src = fdget(ctx, u64::from(src_fd as u32), false)?;
    if !same_super_block(ctx, &src, dst)? {
        return Err(Errno::EXDEV.into());
    }
    generic_file_rw_checks(ctx, &src, dst)?;
    Err(Errno::EOPNOTSUPP.into())
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
    let cred = ctx.cred();
    let tgid = i32::try_from(ctx.tgid()).unwrap_or(0);
    let env = {
        let fs = ctx.files().fs;
        crate::vfs::Env {
            root: fs.root,
            start: dir,
            cred,
            umask: fs.umask,
            tgid,
        }
    };
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
        // A procfs directory whose pid is gone ends the call (`ENOENT`).
        tmpfs.readdir(&env, dir, &mut pos, &mut actor)?;
    }
    // iterate_dir: file_accessed() follows the iteration, whatever it gave.
    if view.flags & O_NOATIME == 0 && !dir.is_proc() {
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
    let is_reg = ctx.files().vfs.fs.file_type(inode) == crate::vfs::S_IFREG;
    if !is_reg || view.mode & FMODE_WRITE == 0 {
        return Err(Errno::EINVAL.into());
    }
    // `small` is cleared by the file's O_LARGEFILE, which every open sets on 64-bit (the syscall
    // itself passes 1), so MAX_NON_LFS never limits the length. inode_newsize_ok (from
    // notify_change): growing past RLIMIT_FSIZE raises SIGXFSZ with -EFBIG, then s_maxbytes
    // (MAX_LFS_FILESIZE, which a non-negative length cannot exceed, but MAX_NON_LFS on procfs).
    #[allow(clippy::cast_sign_loss)]
    let length = length as u64;
    let limit = ctx.rlimit_fsize();
    if let Err(refused) = ctx.files().vfs.newsize_ok(inode, length, limit) {
        if refused.signal {
            ctx.state().send_sig(SIGXFSZ);
        }
        return Err(Errno::EFBIG.into());
    }
    if inode.is_proc() {
        // The setattr of a procfs node copies ATTR_MTIME | ATTR_CTIME and no size.
        ctx.files().vfs.proc_touch(inode)?;
        return Ok(0);
    }
    let cred = ctx.cred();
    ctx.files().vfs.do_truncate(&cred, inode, length);
    Ok(0)
}
