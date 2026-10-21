// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: fs/select.c (GPL-2.0:
// `poll_select_set_timeout` 271, `__estimate_accuracy` and
// `select_estimate_accuracy`, `do_pollfd` 853, `do_poll` 876, `do_sys_poll`
// 967, `do_restart_poll` 1041, `SYSCALL_DEFINE3(poll)` 1062), include/linux/poll.h
// (`vfs_poll`, `DEFAULT_POLLMASK`), include/uapi/asm-generic/poll.h, fs/pipe.c
// (`pipe_poll` 660), drivers/tty/n_tty.c (`n_tty_poll`).
// Transformation: the poll table is the task's one wait key: a task that must
// sleep sleeps once on `sched::POLL_KEY` (every pipe, console tty or mount-table
// change wakes it) with the timeout as its timer, then scans every descriptor
// again, so it needs no per-file wait entries and no `poll_freewait`.
#![forbid(unsafe_code)]
//! `poll(2)`: readiness of pipes, the console and files that have no `->poll`.
//!
//! # Contract
//! * Context: task context. The call sleeps interruptibly: until a descriptor
//!   is ready, the timeout passes (`0` returns at once), or a signal is
//!   pending (`-ERESTARTNOHAND`, turned into `-ERESTART_RESTARTBLOCK` with the
//!   `restart_block` holding `ufds`, `nfds` and the absolute end, so
//!   `restart_syscall` polls again until the original end).
//! * `revents` is `mask & (events | POLLERR | POLLHUP)`; a descriptor that is
//!   not open (or `O_PATH`) is `POLLNVAL`; a negative `fd` is skipped with
//!   `revents` 0. The count is the number of entries with a non-zero `revents`.
//! * shortcut: `ppoll`, `select`, `pselect6` and `epoll` are not ported (they
//!   stay `Outcome::Unimplemented`); upgrade by adding their argument decoding
//!   in front of [`do_sys_poll`], which is their common engine in Linux too.

use super::{Context, Outcome, Stop, Sys, outcome, time::RestartBlock, time::RestartFn};
use crate::{
    sched::POLL_KEY,
    signal::wait::signal_pending_synced,
    usercopy::{access_ok, copy_from_user, put_user},
    vfs::file::{CharDev, FileKind},
};
use alloc::vec::Vec;
use syscalls::{Errno, Sysno};

const POLLIN: u16 = 0x0001;
const POLLOUT: u16 = 0x0004;
const POLLPRI: u16 = 0x0002;
const POLLERR: u16 = 0x0008;
const POLLHUP: u16 = 0x0010;
const POLLNVAL: u16 = 0x0020;
const POLLRDNORM: u16 = 0x0040;
const POLLWRNORM: u16 = 0x0100;
/// `DEFAULT_POLLMASK`: a file without `->poll` is always ready.
const DEFAULT_POLLMASK: u16 = POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM;

/// `-ERESTARTNOHAND` and `-ERESTART_RESTARTBLOCK`.
const ERESTARTNOHAND: i64 = 514;
const ERESTART_RESTARTBLOCK: i64 = 516;
/// `sizeof(struct pollfd)`.
const POLLFD_SIZE: usize = 8;
const POLLFD_BYTES: u64 = POLLFD_SIZE as u64;
/// `POLLFD_PER_PAGE`: the copy-in granularity (`(PAGE_SIZE - sizeof(poll_list)) / 8`).
const POLLFD_PER_PAGE: usize = 510;
/// `MAX_SLACK`: 100 ms.
const MAX_SLACK_NS: u64 = 100_000_000;
/// `current->timer_slack_ns` of a normal task.
const TIMER_SLACK_NS: u64 = 50_000;
/// `KTIME_MAX`.
const KTIME_MAX: u64 = i64::MAX as u64;

pub(super) fn dispatch<C: Context>(ctx: &mut C, sysno: Sysno, a: [u64; 6]) -> Option<Outcome> {
    let result = match sysno {
        // `unsigned int nfds`, `int timeout_msecs`: the low 32 bits.
        #[allow(clippy::cast_possible_truncation)]
        Sysno::poll => sys_poll(ctx, a[0], a[1] as u32, a[2] as i32),
        _ => return None,
    };
    Some(outcome(sysno as u32, result))
}

/// One `struct pollfd`.
#[derive(Clone, Copy)]
struct PollFd {
    fd: i32,
    events: u16,
    revents: u16,
}

/// The end of the wait (`struct timespec64 *end_time`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum End {
    /// `NULL`: no timeout.
    Forever,
    /// `{0, 0}`: do not wait (`poll_select_set_timeout`'s zero case).
    NoWait,
    /// Absolute `CLOCK_MONOTONIC` nanoseconds.
    At(u64),
}

impl End {
    /// `restart_block->poll.has_timeout` plus the time, in the one `i64` of
    /// [`RestartBlock::expires_ns`]: -1 is "no timeout", 0 "do not wait".
    #[allow(clippy::cast_possible_wrap)]
    fn to_restart(self) -> i64 {
        match self {
            Self::Forever => -1,
            Self::NoWait => 0,
            Self::At(ns) => ns as i64,
        }
    }

    #[allow(clippy::cast_sign_loss)]
    fn from_restart(ns: i64) -> Self {
        match ns {
            ..0 => Self::Forever,
            0 => Self::NoWait,
            _ => Self::At(ns as u64),
        }
    }
}

/// `poll_select_set_timeout(to, sec, nsec)` for `timeout_msecs >= 0`.
fn set_timeout(now_ns: u64, msecs: u64) -> End {
    let (sec, nsec) = (msecs / 1000, (msecs % 1000) * 1_000_000);
    if sec == 0 && nsec == 0 {
        End::NoWait
    } else {
        End::At(
            now_ns
                .saturating_add(sec * 1_000_000_000 + nsec)
                .min(KTIME_MAX),
        )
    }
}

/// `SYSCALL_DEFINE3(poll, ...)`.
fn sys_poll<C: Context>(ctx: &mut C, ufds: u64, nfds: u32, timeout_msecs: i32) -> Sys {
    let end = if timeout_msecs >= 0 {
        set_timeout(ctx.now_ns(), u64::from(timeout_msecs.unsigned_abs()))
    } else {
        End::Forever
    };
    let ret = do_sys_poll(ctx, ufds, nfds, end)?;
    if ret == -ERESTARTNOHAND {
        // `restart_block->poll.{ufds,nfds,tv_sec,tv_nsec,has_timeout}`.
        #[allow(clippy::cast_possible_wrap)]
        ctx.set_restart_block(RestartBlock {
            func: RestartFn::Poll,
            clockid: nfds as i32,
            expires_ns: end.to_restart(),
            rmtp: ufds,
        });
        return Ok(-ERESTART_RESTARTBLOCK);
    }
    Ok(ret)
}

/// `do_restart_poll`: poll again until the original end.
pub(super) fn restart<C: Context>(ctx: &mut C, block: RestartBlock, sysno: Sysno) -> Outcome {
    #[allow(clippy::cast_sign_loss)]
    let nfds = block.clockid as u32;
    let end = End::from_restart(block.expires_ns);
    let result = do_sys_poll(ctx, block.rmtp, nfds, end).map(|ret| {
        if ret == -ERESTARTNOHAND {
            ctx.set_restart_block(block);
            -ERESTART_RESTARTBLOCK
        } else {
            ret
        }
    });
    outcome(sysno as u32, result)
}

/// `do_sys_poll`: copy the array in, poll, copy the `revents` out. The result
/// is the count, `-ERESTARTNOHAND` when a signal ended the wait, or an error.
fn do_sys_poll<C: Context>(ctx: &mut C, ufds: u64, nfds: u32, end: End) -> Sys {
    if u64::from(nfds) > ctx.rlimit_nofile() {
        return Err(Errno::EINVAL.into());
    }
    // `copy_from_user` of the stack part and then page-sized chunks: a fault
    // anywhere is `-EFAULT` before anything is polled or written.
    let mut fds: Vec<PollFd> = Vec::new();
    let total = nfds as usize;
    while fds.len() < total {
        let chunk = (total - fds.len()).min(POLLFD_PER_PAGE);
        fds.try_reserve(chunk).map_err(|_| Errno::ENOMEM)?;
        let mut raw = [0u8; POLLFD_PER_PAGE * POLLFD_SIZE];
        let bytes = &mut raw[..chunk * POLLFD_SIZE];
        let at = ufds.wrapping_add(fds.len() as u64 * POLLFD_BYTES);
        if copy_from_user(ctx, bytes, at) != 0 {
            return Err(Errno::EFAULT.into());
        }
        for entry in bytes.as_chunks::<POLLFD_SIZE>().0 {
            let pollfd = PollFd {
                fd: i32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]),
                events: u16::from_le_bytes([entry[4], entry[5]]),
                revents: 0,
            };
            if fds.push_within_capacity(pollfd).is_err() {
                return Err(Errno::ENOMEM.into());
            }
        }
    }
    let count = do_poll(ctx, &mut fds, end)?;
    // `user_write_access_begin(ufds, nfds * sizeof(*ufds))`, then one 16-bit
    // store per entry: an unwritable page part-way leaves the earlier ones.
    if !access_ok(ufds, u64::from(nfds) * POLLFD_BYTES) {
        return Err(Errno::EFAULT.into());
    }
    for (index, pollfd) in fds.iter().enumerate() {
        let at = ufds + index as u64 * POLLFD_BYTES + 6;
        if !put_user(ctx, at, &pollfd.revents.to_le_bytes()) {
            return Err(Errno::EFAULT.into());
        }
    }
    Ok(count)
}

/// `select_estimate_accuracy` for a task of nice 0: a thousandth of the time
/// left, at least the timer slack and at most [`MAX_SLACK_NS`].
fn estimate_accuracy(end_ns: u64, now_ns: u64) -> u64 {
    let left = end_ns.saturating_sub(now_ns);
    (left / 1000).clamp(TIMER_SLACK_NS, MAX_SLACK_NS)
}

/// `do_poll`.
fn do_poll<C: Context>(ctx: &mut C, fds: &mut [PollFd], end: End) -> Sys {
    // Optimise the no-wait case.
    let mut timed_out = end == End::NoWait;
    // The timer fires at the hard expiry, soft + slack.
    let deadline = match end {
        End::At(ns) if !timed_out => Some(ns.saturating_add(estimate_accuracy(ns, ctx.now_ns()))),
        _ => None,
    };
    loop {
        let mut count: i64 = 0;
        for pollfd in fds.iter_mut() {
            let mask = do_pollfd(ctx, *pollfd)?;
            pollfd.revents = mask;
            if mask != 0 {
                count += 1;
            }
        }
        if count == 0 && signal_pending_synced(ctx) {
            count = -ERESTARTNOHAND;
        }
        if count != 0 || timed_out {
            return Ok(count);
        }
        // `poll_schedule_timeout`: asleep until a pipe changes, a signal, or
        // the end; only the timer running out counts as a timeout.
        ctx.wait(POLL_KEY, deadline);
        if deadline.is_some_and(|d| ctx.now_ns() >= d) {
            timed_out = true;
        }
    }
}

/// `do_pollfd`: the events of one descriptor.
fn do_pollfd<C: Context>(ctx: &mut C, pollfd: PollFd) -> Result<u16, Stop> {
    if pollfd.fd < 0 {
        return Ok(0);
    }
    #[allow(clippy::cast_sign_loss)]
    let Ok(view) = super::fd::fdget(ctx, pollfd.fd as u64, false) else {
        return Ok(POLLNVAL);
    };
    // `demangle_poll(events) | EPOLLERR | EPOLLHUP`.
    let filter = pollfd.events | POLLERR | POLLHUP;
    let mask = vfs_poll(ctx, &view)?;
    Ok(mask & filter)
}

/// `vfs_poll`: the ready events of an open file.
fn vfs_poll<C: Context>(ctx: &mut C, view: &super::fd::View) -> Result<u16, Stop> {
    Ok(match view.kind {
        // `pipe_poll`.
        FileKind::Pipe { pipe, writer } => {
            let p = ctx.files().vfs.pipe_ref(pipe);
            let mut mask = 0;
            if writer {
                if !p.is_full() {
                    mask |= POLLOUT | POLLWRNORM;
                }
                // "Most Unices do not set EPOLLERR for FIFOs but on Linux they
                // behave exactly like pipes for poll()."
                if p.readers == 0 {
                    mask |= POLLERR;
                }
            } else {
                if !p.is_empty() {
                    mask |= POLLIN | POLLRDNORM;
                }
                // An anonymous pipe: `filp->f_pipe` (0) never equals `w_counter`.
                if p.writers == 0 {
                    mask |= POLLHUP;
                }
            }
            mask
        }
        // `tty_poll` -> `n_tty_poll`, or `hung_up_tty_poll`.
        FileKind::Char(CharDev::Console | CharDev::TtyAux | CharDev::TtyS0 | CharDev::HungUp) => {
            super::tty::poll_mask(ctx, view)
        }
        // No `->poll`: `DEFAULT_POLLMASK`.
        FileKind::Proc
            if view
                .inode
                .and_then(crate::procfs::ProcNode::of)
                .is_some_and(|node| {
                    matches!(
                        node.kind,
                        crate::procfs::Kind::Mounts | crate::procfs::Kind::Mountinfo
                    )
                }) =>
        {
            // mounts_poll: readable, and EPOLLERR | EPOLLPRI once per mount table change.
            let vfs = &mut *ctx.files().vfs;
            let event = vfs.fs.ns.event;
            let file = vfs.files.get_mut(view.id);
            let mut mask = POLLIN | POLLRDNORM;
            if file.poll_event != event {
                file.poll_event = event;
                mask |= POLLERR | POLLPRI;
            }
            mask
        }
        FileKind::Regular | FileKind::Directory | FileKind::Proc | FileKind::Char(_) => {
            DEFAULT_POLLMASK
        }
        // `fdget` refused `O_PATH` already.
        FileKind::Path => POLLNVAL,
        FileKind::Unsupported => return Err(Stop::Unimplemented),
    })
}
