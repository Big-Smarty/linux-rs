// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: drivers/tty/tty_io.c (`tty_open`
// 2106-2185, `tty_read` 903-931, `iterate_tty_read` 837-901, `file_tty_write` and
// `iterate_tty_write` 954-1100, `tty_poll`, `tty_ioctl` 2685-2848, `tiocsti`,
// `tiocgwinsz`, `tiocswinsz`, `tioccons`, `tiocgetd`/`tiocsetd`, `tty_release`,
// `tty_wait_until_sent`), drivers/tty/n_tty.c (`n_tty_read`, `n_tty_write`,
// `n_tty_poll`, `job_control`), drivers/tty/tty_ioctl.c (`set_termios`,
// `tty_mode_ioctl`, `n_tty_ioctl_helper`), drivers/tty/tty_jobctrl.c, fs/ioctl.c
// (the generic commands that run before `tty_ioctl`), include/uapi/asm-generic/
// ioctls.h. All GPL-2.0 (n_tty.c GPL-1.0+).
// Transformation: each sleep of the C code drops the process lock and sleeps on
// `TTY_KEY` (`Task::wait`); the loops re-read everything after it, as
// `wait_event` does. The tty's `termios_rwsem` and `ldisc_sem` do not exist (one
// CPU, no lock is held across a sleep); the serialising mutexes are owner fields
// of the `Tty`.
#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]
//! The console tty as a file: `read`, `write`, `poll`, `ioctl`, `open`.
//!
//! # Contract
//! * Context: task context; blocking calls sleep interruptibly and return
//!   `-ERESTARTSYS` when a signal is pending and nothing was transferred.
//! * `/dev/console` files (`console_fops`) skip the job-control checks
//!   (`redirected_tty_write`); `/dev/tty` and `/dev/ttyS0` files (`tty_fops`) do
//!   not. A hung-up file reads 0, writes `EIO`.
//! * shortcut: `tty_update_time` (the 8-second atime/mtime update of the device
//!   nodes), `FASYNC`/`SIGIO`, the break/modem-line/serial-struct ioctls and line
//!   disciplines other than `N_TTY` stop the kernel loudly where Linux acts;
//!   upgrade with the driver pieces they need.

use super::{
    Context, Stop, Sys,
    fd::{Dest, View},
};
use crate::{
    sched::TTY_KEY,
    signal::{
        SIG_IGN, SIGTTIN, SIGTTOU, SIGWINCH,
        wait::{ERESTARTSYS, signal_pending_synced},
    },
    task::{TaskId, Tasklist, exit::Waker},
    tty::{
        Host, Tty, Winsize,
        jobctl::{self, CheckError},
        ldisc::{ReadEnv, ReadStep},
        termios::{Ktermios, TERMIO_SIZE, TERMIOS_SIZE, TERMIOS2_SIZE, baud_rate, input_baud_rate},
    },
    usercopy::{copy_from_user, copy_to_user},
    vfs::{
        FMODE_READ, O_NOCTTY, O_NONBLOCK,
        file::{CharDev, FileKind},
    },
};
use syscalls::Errno;

// ioctl numbers (include/uapi/asm-generic/ioctls.h)
const TCGETS: u32 = 0x5401;
const TCSETS: u32 = 0x5402;
const TCSETSW: u32 = 0x5403;
const TCSETSF: u32 = 0x5404;
const TCGETA: u32 = 0x5405;
const TCSETA: u32 = 0x5406;
const TCSETAW: u32 = 0x5407;
const TCSETAF: u32 = 0x5408;
const TCSBRK: u32 = 0x5409;
const TCXONC: u32 = 0x540a;
const TCFLSH: u32 = 0x540b;
const TIOCEXCL: u32 = 0x540c;
const TIOCNXCL: u32 = 0x540d;
const TIOCSCTTY: u32 = 0x540e;
const TIOCGPGRP: u32 = 0x540f;
const TIOCSPGRP: u32 = 0x5410;
const TIOCOUTQ: u32 = 0x5411;
const TIOCSTI: u32 = 0x5412;
const TIOCGWINSZ: u32 = 0x5413;
const TIOCSWINSZ: u32 = 0x5414;
const TIOCMGET: u32 = 0x5415;
const TIOCMBIS: u32 = 0x5416;
const TIOCMBIC: u32 = 0x5417;
const TIOCMSET: u32 = 0x5418;
const TIOCGSOFTCAR: u32 = 0x5419;
const TIOCSSOFTCAR: u32 = 0x541a;
const FIONREAD: u32 = 0x541b;
const TIOCCONS: u32 = 0x541d;
const TIOCGSERIAL: u32 = 0x541e;
const TIOCSSERIAL: u32 = 0x541f;
const TIOCNOTTY: u32 = 0x5422;
const TIOCSETD: u32 = 0x5423;
const TIOCGETD: u32 = 0x5424;
const TCSBRKP: u32 = 0x5425;
const TIOCSBRK: u32 = 0x5427;
const TIOCCBRK: u32 = 0x5428;
const TIOCGSID: u32 = 0x5429;
const TCGETS2: u32 = 0x802c_542a;
const TCSETS2: u32 = 0x402c_542b;
const TCSETSW2: u32 = 0x402c_542c;
const TCSETSF2: u32 = 0x402c_542d;
const TIOCGRS485: u32 = 0x542e;
const TIOCSRS485: u32 = 0x542f;
const TIOCGDEV: u32 = 0x8004_5432;
const TIOCVHANGUP: u32 = 0x5437;
const TIOCGEXCL: u32 = 0x8004_5440;
const TIOCGPTPEER: u32 = 0x5441;
const TIOCGISO7816: u32 = 0x8030_5442;
const TIOCSISO7816: u32 = 0xc030_5443;
const TIOCSERCONFIG: u32 = 0x5453;
const TIOCSERGWILD: u32 = 0x5454;
const TIOCSERSWILD: u32 = 0x5455;
const TIOCGLCKTRMIOS: u32 = 0x5456;
const TIOCSLCKTRMIOS: u32 = 0x5457;
const TIOCSERGSTRUCT: u32 = 0x5458;
const TIOCSERGETLSR: u32 = 0x5459;
const TIOCSERGETMULTI: u32 = 0x545a;
const TIOCSERSETMULTI: u32 = 0x545b;
const TIOCMIWAIT: u32 = 0x545c;
const TIOCGICOUNT: u32 = 0x545d;

/// `iterate_tty_read`'s `kernel_buf`.
const READ_CHUNK: usize = 64;
/// `iterate_tty_write`'s default chunk.
const WRITE_CHUNK: usize = 2048;

/// `Dev` of the console tty: `ttyS0`, 4:64, for `TIOCGDEV`.
const TTYS0_DEVT: u32 = (4 << 8) | 64;

fn neg(errno: Errno) -> i64 {
    -i64::from(errno.into_raw())
}

/// The `Host` of the tty: signals through the task list, bytes to the console.
struct Env<'a> {
    list: &'a mut Tasklist,
    wake: &'a mut dyn Waker,
    console: &'a mut dyn super::Console,
}

impl Host for Env<'_> {
    fn kill_pgrp(&mut self, pgrp: crate::task::pid::PidRef, sig: u8) {
        // `kill_pgrp(pgrp, sig, 1)`: the result is ignored (`ESRCH` for an empty group).
        let _ = self.list.kill_pgrp_ref(pgrp, sig, self.wake);
    }
    fn transmit(&mut self, bytes: &[u8]) {
        self.console.write(bytes);
    }
}

/// A host that can only put bytes on the wire: hangup and release restart the
/// discipline and flush, they never run `isig`.
struct Wire<'a>(&'a mut dyn super::Console);

impl Host for Wire<'_> {
    fn kill_pgrp(&mut self, _pgrp: crate::task::pid::PidRef, _sig: u8) {}
    fn transmit(&mut self, bytes: &[u8]) {
        self.0.write(bytes);
    }
}

/// The tty, the host and the caller from the context's parts.
fn env<C: Context>(ctx: &mut C) -> (&mut Tty, Env<'_>, TaskId) {
    let super::TtyParts {
        tty,
        tasks,
        console,
    } = ctx.tty_parts();
    (
        tty,
        Env {
            list: tasks.list,
            wake: tasks.wake,
            console,
        },
        tasks.current,
    )
}

/// `is_ignored(sig)`: blocked or explicitly `SIG_IGN`.
fn is_ignored<C: Context>(ctx: &mut C, sig: u8) -> bool {
    let state = ctx.state();
    state.me.blocked.contains(sig) || state.hand.actions[usize::from(sig) - 1].handler == SIG_IGN
}

/// `tty_check_change` / `__tty_check_change`: `Some(result)` ends the call.
fn check_change<C: Context>(ctx: &mut C, sig: u8) -> Option<Sys> {
    let ignored = is_ignored(ctx, sig);
    let (tty, env, me) = env(ctx);
    match jobctl::check_change(tty, env.list, me, env.wake, sig, ignored) {
        Ok(()) => None,
        Err(CheckError::Eio) => Some(Err(Errno::EIO.into())),
        Err(CheckError::Restart) => Some(Ok(-ERESTARTSYS)),
    }
}

/// Sleep on the tty key until `ready` or a signal; `Err` is `-ERESTARTSYS`.
fn wait_tty<C: Context>(ctx: &mut C, mut ready: impl FnMut(&mut C) -> bool) -> Result<(), i64> {
    loop {
        if ready(ctx) {
            return Ok(());
        }
        if signal_pending_synced(ctx) {
            return Err(-ERESTARTSYS);
        }
        ctx.wait(TTY_KEY, None);
    }
}

fn kind_of<C: Context>(ctx: &mut C, view: &View) -> FileKind {
    ctx.files().vfs.files.get(view.id).kind
}

fn hung_up<C: Context>(ctx: &mut C, view: &View) -> bool {
    kind_of(ctx, view) == FileKind::Char(CharDev::HungUp)
}

// ---- read ----------------------------------------------------------------------

/// The result of one `n_tty_read` call.
enum Chunk {
    Bytes {
        len: usize,
        more: Option<crate::tty::ldisc::ReadOp>,
    },
    Fail(Sys),
}

/// `ms` from now as the absolute `CLOCK_MONOTONIC` time of the wake-up.
fn deadline_of<C: Context>(ctx: &C, ms: Option<u64>) -> Option<u64> {
    ms.map(|ms| ctx.now_ns().saturating_add(ms.saturating_mul(1_000_000)))
}

/// `n_tty_read` without a cookie: job control, the reader lock, the loop.
fn first_chunk<C: Context>(ctx: &mut C, view: &View, kbuf: &mut [u8]) -> Chunk {
    let console = view.kind == FileKind::Char(CharDev::Console);
    // job_control(): "don't stop on /dev/console".
    if !console && let Some(result) = check_change(ctx, SIGTTIN) {
        return Chunk::Fail(result);
    }
    let nonblock = view.flags & O_NONBLOCK != 0;
    // Internal serialisation of reads.
    loop {
        let (tty, _, me) = env(ctx);
        if tty.read_try_lock(me) {
            break;
        }
        if nonblock {
            return Chunk::Fail(Err(Errno::EAGAIN.into()));
        }
        if signal_pending_synced(ctx) {
            return Chunk::Fail(Ok(-ERESTARTSYS));
        }
        ctx.wait(TTY_KEY, None);
    }
    let size = kbuf.len();
    let mut op = env(ctx).0.read_begin(size);
    loop {
        let signal_pending = signal_pending_synced(ctx);
        let hung = hung_up(ctx, view);
        let step = {
            let (tty, mut host, _) = env(ctx);
            let env = ReadEnv {
                nonblock,
                hung_up: hung,
                signal_pending,
            };
            tty.read_step(&mut host, &mut op, kbuf, &env)
        };
        match step {
            ReadStep::Done { len, more } => {
                return Chunk::Bytes {
                    len,
                    more: more.then_some(op),
                };
            }
            ReadStep::Error { errno, restart } => {
                return Chunk::Fail(match (errno, restart) {
                    (Some(errno), _) => Err(errno.into()),
                    (None, true) => Ok(-ERESTARTSYS),
                    (None, false) => Ok(0),
                });
            }
            ReadStep::Sleep { ms } => {
                let deadline = deadline_of(ctx, ms);
                ctx.wait(TTY_KEY, deadline);
                if let Some(deadline) = deadline {
                    let left = deadline.saturating_sub(ctx.now_ns());
                    op.timeout_ms = left.div_ceil(1_000_000);
                }
            }
        }
    }
}

/// `tty_read` + `iterate_tty_read` on a console-tty file.
pub(super) fn read<C: Context>(ctx: &mut C, view: &View, dest: &mut Dest) -> Sys {
    // hung_up_tty_read
    if hung_up(ctx, view) {
        return Ok(0);
    }
    let mut kbuf = [0u8; READ_CHUNK];
    let mut offset = 0usize;
    let mut retval: Option<Sys> = None;
    let mut cookie: Option<crate::tty::ldisc::ReadOp> = None;
    let mut count = usize::try_from(dest.remaining).unwrap_or(usize::MAX);
    loop {
        let size = count.min(READ_CHUNK);
        let chunk = match cookie.take() {
            Some(mut op) => {
                op.set_capacity(size);
                let step = {
                    let (tty, mut host, _) = env(ctx);
                    tty.read_continue(&mut host, &mut op, &mut kbuf[..size])
                };
                match step {
                    ReadStep::Done { len, more } => Chunk::Bytes {
                        len,
                        more: more.then_some(op),
                    },
                    _ => Chunk::Fail(Ok(0)),
                }
            }
            None => first_chunk(ctx, view, &mut kbuf[..size]),
        };
        match chunk {
            Chunk::Fail(result) => {
                // Did we have an earlier error (ie -EFAULT)?
                if retval.is_none() && offset == 0 {
                    retval = Some(result);
                }
                break;
            }
            Chunk::Bytes { len, more } => {
                if len == 0 {
                    break;
                }
                let copied = dest.copy_out(ctx, &kbuf[..len]);
                offset += copied;
                count -= copied;
                cookie = more;
                if copied != len {
                    count = 0;
                    retval = Some(Err(Errno::EFAULT.into()));
                }
                if cookie.is_none() {
                    break;
                }
            }
        }
    }
    // "We always clear tty buffer in case they contained passwords."
    kbuf.fill(0);
    if offset > 0 {
        return Ok(i64::try_from(offset).unwrap_or(i64::MAX));
    }
    retval.unwrap_or(Ok(0))
}

// ---- write ---------------------------------------------------------------------

/// `n_tty_write` of one chunk: bytes consumed, or the reason none were.
///
/// `Err` is a loud stop propagated from the job-control check, never a result.
fn n_tty_write<C: Context>(ctx: &mut C, view: &View, buf: &[u8]) -> Sys {
    let console = view.kind == FileKind::Char(CharDev::Console);
    // Job control check -- must be done at start (POSIX.1 7.1.1.4).
    if !console
        && env(ctx).0.tostop()
        && let Some(result) = check_change(ctx, SIGTTOU)
    {
        return match result {
            Ok(value) => Ok(value),
            Err(Stop::Errno(errno)) => Ok(neg(errno)),
            Err(stop) => Err(stop),
        };
    }
    {
        let (tty, mut host, _) = env(ctx);
        tty.write_begin(&mut host);
    }
    let nonblock = view.flags & O_NONBLOCK != 0;
    let mut done = 0usize;
    let mut retval = 0i64;
    loop {
        if signal_pending_synced(ctx) {
            retval = -ERESTARTSYS;
            break;
        }
        if hung_up(ctx, view) {
            retval = neg(Errno::EIO);
            break;
        }
        let pass = {
            let (tty, mut host, _) = env(ctx);
            tty.write_pass(&mut host, &buf[done..])
        };
        done += pass.consumed;
        if done == buf.len() {
            break;
        }
        if nonblock {
            retval = neg(Errno::EAGAIN);
            break;
        }
        ctx.wait(TTY_KEY, None);
    }
    Ok(if done > 0 {
        i64::try_from(done).unwrap_or(i64::MAX)
    } else {
        retval
    })
}

/// `tty_write` on a console-tty file, called by `vfs_write` after the descriptor,
/// access and clamp checks: `count` is at most `MAX_RW_COUNT`.
///
/// The tty copies at most 2048 bytes at a time (`iterate_tty_write`). A chunk
/// that cannot be fully copied from user memory is not written at all: the call
/// returns the bytes of the earlier chunks, or `-EFAULT` when there are none.
pub(super) fn write<C: Context>(ctx: &mut C, view: &View, src: &mut super::fd::Src) -> Sys {
    // hung_up_tty_write
    if hung_up(ctx, view) {
        return Err(Errno::EIO.into());
    }
    let nonblock = view.flags & O_NONBLOCK != 0;
    // tty_write_lock(tty, ndelay)
    loop {
        let (tty, _, me) = env(ctx);
        if tty.write_lock(me) {
            break;
        }
        if nonblock {
            return Err(Errno::EAGAIN.into());
        }
        if signal_pending_synced(ctx) {
            return Ok(-ERESTARTSYS);
        }
        ctx.wait(TTY_KEY, None);
    }
    let mut remaining = usize::try_from(src.remaining).unwrap_or(usize::MAX);
    let mut written = 0usize;
    let mut ret: i64 = 0;
    let mut chunk = [0u8; WRITE_CHUNK];
    // `for (;;)` in iterate_tty_write: a zero-length write still reaches n_tty_write
    // (TOSTOP check, echo flush, signal and hangup checks) once.
    loop {
        let size = remaining.min(WRITE_CHUNK);
        if src.copy_in(ctx, &mut chunk[..size]) != size {
            ret = neg(Errno::EFAULT);
            break;
        }
        let consumed = match n_tty_write(ctx, view, &chunk[..size]) {
            Ok(consumed) => consumed,
            Err(stop) => {
                let (tty, _, me) = env(ctx);
                tty.write_unlock(me);
                return Err(stop);
            }
        };
        if consumed <= 0 {
            ret = consumed;
            break;
        }
        let consumed = usize::try_from(consumed).unwrap_or(0);
        written += consumed;
        if consumed < size {
            // `iov_iter_revert(from, size - ret)`
            src.revert((size - consumed) as u64);
        }
        remaining -= consumed;
        if remaining == 0 {
            break;
        }
        ret = -ERESTARTSYS;
        if signal_pending_synced(ctx) {
            break;
        }
    }
    {
        let (tty, _, me) = env(ctx);
        tty.write_unlock(me);
    }
    if written > 0 {
        ret = i64::try_from(written).unwrap_or(i64::MAX);
    }
    Ok(ret)
}

// ---- poll ----------------------------------------------------------------------

const POLLIN: u16 = 0x1;
const POLLOUT: u16 = 0x4;
const POLLERR: u16 = 0x8;
const POLLHUP: u16 = 0x10;
const POLLRDNORM: u16 = 0x40;
const POLLWRNORM: u16 = 0x100;

/// `tty_poll` -> `n_tty_poll`, or `hung_up_tty_poll`.
pub(super) fn poll_mask<C: Context>(ctx: &mut C, view: &View) -> u16 {
    if hung_up(ctx, view) {
        return POLLIN | POLLOUT | POLLERR | POLLHUP | POLLRDNORM | POLLWRNORM;
    }
    env(ctx).0.poll_mask(false)
}

// ---- open ----------------------------------------------------------------------

/// The part of `tty_open` that needs the caller: `/dev/tty` without a
/// controlling terminal (`ENXIO`), `TTY_EXCLUSIVE` (`EBUSY`), the end of a
/// hangup, and the controlling-terminal acquisition by a session leader.
///
/// # Errors
/// `ENXIO`, `EBUSY`; the caller releases the file.
pub(super) fn after_open<C: Context>(
    ctx: &mut C,
    file: crate::vfs::FileId,
    open_flags: u32,
) -> Result<(), Errno> {
    let (kind, mode) = {
        let f = ctx.files().vfs.files.get(file);
        (f.kind, f.mode)
    };
    let FileKind::Char(dev) = kind else {
        return Ok(());
    };
    if !dev.is_tty() {
        return Ok(());
    }
    let sys_admin = ctx.cred().sys_admin;
    let (tty, env, me) = env(ctx);
    if dev == CharDev::TtyAux && !env.list.has_ctty(me) {
        return Err(Errno::ENXIO);
    }
    if tty.exclusive && !sys_admin {
        return Err(Errno::EBUSY);
    }
    tty.hupped = false;
    let noctty = open_flags & O_NOCTTY != 0 || dev == CharDev::Console;
    if !noctty {
        jobctl::open_set_tty(tty, env.list, me, mode & FMODE_READ != 0);
    }
    Ok(())
}

/// After a system call or an exit: recount the files on the tty and run the last
/// close if there are none (`tty_release`: the controlling terminals of the
/// session are dropped, the termios is remembered, the rest starts afresh).
pub fn housekeeping(vfs: &mut crate::vfs::Vfs, tty: &mut Tty, tasks: &mut Tasklist) {
    if !vfs.take_tty_touch() {
        return;
    }
    let (open, _) = vfs.tty_files();
    if open == 0 && tty.count != 0 {
        tasks.session_clear_tty(tty.ctrl.session);
        tty.final_release();
    }
    tty.count = open;
}

/// `__tty_hangup` as `tty_vhangup` / `tty_vhangup_session` run it: the files of
/// the tty other than `/dev/console` ones are hung up.
pub fn vhangup<C: Context>(ctx: &mut C, exit_session: bool) {
    let console_open = ctx.files().vfs.tty_files().1 > 0;
    let hung;
    {
        let (tty, env, _) = env(ctx);
        let Env {
            list,
            wake,
            console,
        } = env;
        hung = jobctl::hangup(
            tty,
            list,
            wake,
            &mut Wire(console),
            exit_session,
            console_open,
        );
    }
    if hung {
        ctx.files().vfs.tty_hangup_files();
    }
}

// ---- ioctl ---------------------------------------------------------------------

fn put<C: Context>(ctx: &mut C, arg: u64, bytes: &[u8]) -> Sys {
    if copy_to_user(ctx, arg, bytes) != 0 {
        return Err(Errno::EFAULT.into());
    }
    Ok(0)
}

fn get<C: Context, const N: usize>(ctx: &mut C, arg: u64) -> Result<[u8; N], Errno> {
    let mut raw = [0u8; N];
    if copy_from_user(ctx, &mut raw, arg) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(raw)
}

/// `tty_wait_until_sent(tty, 0)` + the `signal_pending` check of the ioctls
/// that precede a change with a drain: `Some(-EINTR)` when a signal arrived.
fn wait_until_sent<C: Context>(ctx: &mut C) -> Option<Sys> {
    let _ = wait_tty(ctx, |c| env(c).0.chars_in_buffer() == 0);
    if signal_pending_synced(ctx) {
        return Some(Err(Errno::EINTR.into()));
    }
    None
}

/// `set_termios(tty, arg, opt)`.
fn set_termios<C: Context>(
    ctx: &mut C,
    arg: u64,
    flavour: Flavour,
    flush: bool,
    wait: bool,
) -> Sys {
    if let Some(result) = check_change(ctx, SIGTTOU) {
        return result;
    }
    let mut tmp: Ktermios = env(ctx).0.termios;
    match flavour {
        Flavour::Termio => tmp.set_from_termio(&get::<_, TERMIO_SIZE>(ctx, arg)?),
        Flavour::Termios => tmp.set_from_termios(&get::<_, TERMIOS_SIZE>(ctx, arg)?),
        Flavour::Termios2 => tmp.set_from_termios2(&get::<_, TERMIOS2_SIZE>(ctx, arg)?),
    }
    // If old style Bfoo values are used then load c_ispeed/c_ospeed with the
    // real speed so it is unconditionally usable.
    tmp.ispeed = input_baud_rate(&tmp);
    tmp.ospeed = baud_rate(&tmp);
    if !(flush || wait) {
        let (tty, mut host, _) = env(ctx);
        tty.set_termios(&mut host, &tmp);
        return Ok(0);
    }
    loop {
        if let Err(restart) = wait_tty(ctx, |c| env(c).0.chars_in_buffer() == 0) {
            return Ok(restart);
        }
        let locked = {
            let (tty, _, me) = env(ctx);
            tty.write_lock(me)
        };
        if !locked {
            ctx.wait(TTY_KEY, None);
            continue;
        }
        // Racing writer?
        if env(ctx).0.chars_in_buffer() > 0 {
            let (tty, _, me) = env(ctx);
            tty.write_unlock(me);
            continue;
        }
        break;
    }
    {
        let (tty, mut host, me) = env(ctx);
        if flush {
            tty.n_tty_flush_buffer(&mut host);
        }
        tty.set_termios(&mut host, &tmp);
        tty.write_unlock(me);
    }
    Ok(0)
}

#[derive(Clone, Copy)]
enum Flavour {
    Termio,
    Termios,
    Termios2,
}

/// The ioctl numbers `tty_ioctl` reaches that this kernel does not drive: serial
/// line, modem-line and break control, `TIOCGPTPEER`.
fn is_unported(cmd: u32) -> bool {
    matches!(
        cmd,
        TIOCMGET
            | TIOCMBIS
            | TIOCMBIC
            | TIOCMSET
            | TIOCGSERIAL
            | TIOCSSERIAL
            | TIOCGRS485
            | TIOCSRS485
            | TIOCGPTPEER
            | TIOCGISO7816
            | TIOCSISO7816
            | TIOCSERCONFIG
            | TIOCSERGWILD
            | TIOCSERSWILD
            | TIOCSERGSTRUCT
            | TIOCSERGETLSR
            | TIOCSERGETMULTI
            | TIOCSERSETMULTI
            | TIOCMIWAIT
            | TIOCGICOUNT
    )
}

/// `tty_ioctl` for a console-tty file (`do_vfs_ioctl`'s generic commands were
/// handled by the caller).
pub(super) fn ioctl<C: Context>(ctx: &mut C, view: &View, cmd: u32, arg: u64) -> Sys {
    // hung_up_tty_ioctl
    if hung_up(ctx, view) {
        return Err(if cmd == TIOCSPGRP {
            Errno::ENOTTY
        } else {
            Errno::EIO
        }
        .into());
    }
    // Factor out some common prep work.
    if matches!(cmd, TIOCSETD | TIOCSBRK | TIOCCBRK | TCSBRK | TCSBRKP) {
        if let Some(result) = check_change(ctx, SIGTTOU) {
            return result;
        }
        if cmd != TIOCCBRK
            && let Some(result) = wait_until_sent(ctx)
        {
            return result;
        }
    }
    match cmd {
        TIOCSTI => tiocsti(ctx, arg),
        TIOCGWINSZ => {
            let ws = env(ctx).0.winsize;
            put(ctx, arg, &ws.to_bytes())
        }
        TIOCSWINSZ => {
            let ws = Winsize::from_bytes(&get::<_, 8>(ctx, arg)?);
            let (tty, mut host, _) = env(ctx);
            if tty.do_resize(ws) {
                // Signal the foreground process group (before the size is
                // visible to the signalled processes in Linux; one CPU here).
                if let Some(pgrp) = tty.ctrl.pgrp {
                    host.kill_pgrp(pgrp, SIGWINCH);
                }
            }
            Ok(0)
        }
        TIOCCONS => {
            if !ctx.cred().sys_admin {
                return Err(Errno::EPERM.into());
            }
            // The redirect is never set: a `/dev/console` file clears nothing.
            if view.kind == FileKind::Char(CharDev::Console) {
                Ok(0)
            } else {
                Err(Stop::Unimplemented)
            }
        }
        TIOCEXCL => {
            env(ctx).0.set_exclusive(true);
            Ok(0)
        }
        TIOCNXCL => {
            env(ctx).0.set_exclusive(false);
            Ok(0)
        }
        TIOCGEXCL => {
            let excl = i32::from(env(ctx).0.exclusive);
            put(ctx, arg, &excl.to_le_bytes())
        }
        TIOCGETD => put(ctx, arg, &0i32.to_le_bytes()),
        TIOCSETD => {
            let disc = i32::from_le_bytes(get::<_, 4>(ctx, arg)?);
            if !(0..30).contains(&disc) {
                return Err(Errno::EINVAL.into());
            }
            if disc == 0 {
                Ok(0)
            } else {
                Err(Stop::Unimplemented)
            }
        }
        TIOCVHANGUP => {
            if !ctx.cred().sys_admin {
                return Err(Errno::EPERM.into());
            }
            vhangup(ctx, false);
            Ok(0)
        }
        TIOCGDEV => put(ctx, arg, &TTYS0_DEVT.to_le_bytes()),
        TCSBRK => {
            // "non-zero arg means wait for all output data to be sent (performed
            // above) but don't send break".
            if arg == 0 {
                Err(Stop::Unimplemented)
            } else {
                Ok(0)
            }
        }
        TCSBRKP | TIOCSBRK | TIOCCBRK => Err(Stop::Unimplemented),
        TCFLSH => tcflsh(ctx, arg),
        // The job-control ioctls.
        TIOCNOTTY | TIOCSCTTY | TIOCGPGRP | TIOCSPGRP | TIOCGSID => {
            jobctl_ioctl(ctx, view, cmd, arg)
        }
        c if is_unported(c) => Err(Stop::Unimplemented),
        // `n_tty_ioctl` -> `n_tty_ioctl_helper` -> `tty_mode_ioctl`.
        _ => ldisc_ioctl(ctx, cmd, arg),
    }
}

fn tcflsh<C: Context>(ctx: &mut C, arg: u64) -> Sys {
    // `tty_buffer_flush`: the flip buffer was flushed into the discipline by
    // `tty_parts`, so there is nothing pending outside it.
    if let Some(result) = check_change(ctx, SIGTTOU) {
        return result;
    }
    let (tty, mut host, _) = env(ctx);
    tty.perform_flush(&mut host, arg)?;
    Ok(0)
}

fn tiocsti<C: Context>(ctx: &mut C, arg: u64) -> Sys {
    let sys_admin = ctx.cred().sys_admin;
    {
        let (_, env, me) = env(ctx);
        if !env.list.has_ctty(me) && !sys_admin {
            return Err(Errno::EPERM.into());
        }
    }
    let ch = get::<_, 1>(ctx, arg)?[0];
    let (tty, mut host, _) = env(ctx);
    tty.receive_buf_noflow(&mut host, &[ch], None);
    Ok(0)
}

fn jobctl_ioctl<C: Context>(ctx: &mut C, view: &View, cmd: u32, arg: u64) -> Sys {
    match cmd {
        TIOCNOTTY => {
            let console_open = ctx.files().vfs.tty_files().1 > 0;
            let (tty, env, me) = env(ctx);
            let Env {
                list,
                wake,
                console,
            } = env;
            jobctl::tiocnotty(tty, list, me, wake, &mut Wire(console), console_open)?;
            Ok(0)
        }
        TIOCSCTTY => {
            let sys_admin = ctx.cred().sys_admin;
            let readable = view.mode & FMODE_READ != 0;
            let (tty, env, me) = env(ctx);
            jobctl::tiocsctty(tty, env.list, me, arg, readable, sys_admin)?;
            Ok(0)
        }
        TIOCGPGRP => {
            let pgrp = {
                let (tty, env, me) = env(ctx);
                jobctl::tiocgpgrp(tty, env.list, me)?
            };
            put(ctx, arg, &pgrp.to_le_bytes())
        }
        TIOCSPGRP => {
            if let Some(result) = check_change(ctx, SIGTTOU) {
                return match result {
                    // retval == -EIO -> -ENOTTY
                    Err(Stop::Errno(Errno::EIO)) => Err(Errno::ENOTTY.into()),
                    other => other,
                };
            }
            let nr = i32::from_le_bytes(get::<_, 4>(ctx, arg)?);
            let (tty, env, me) = env(ctx);
            jobctl::tiocspgrp(tty, env.list, me, nr)?;
            Ok(0)
        }
        _ => {
            // TIOCGSID
            let sid = {
                let (tty, env, me) = env(ctx);
                jobctl::tiocgsid(tty, env.list, me)?
            };
            put(ctx, arg, &sid.to_le_bytes())
        }
    }
}

/// `tty_mode_ioctl` and what `n_tty_ioctl` adds, or `ENOTTY`.
fn ldisc_ioctl<C: Context>(ctx: &mut C, cmd: u32, arg: u64) -> Sys {
    match cmd {
        TIOCOUTQ => {
            let n = i32::try_from(env(ctx).0.tiocoutq()).unwrap_or(i32::MAX);
            put(ctx, arg, &n.to_le_bytes())
        }
        FIONREAD => {
            let n = env(ctx).0.tiocinq();
            put(ctx, arg, &n.to_le_bytes())
        }
        TCXONC => {
            if let Some(result) = check_change(ctx, SIGTTOU) {
                return result;
            }
            let (tty, mut host, _) = env(ctx);
            tty.tcxonc(&mut host, arg)?;
            Ok(0)
        }
        TCSETSF => set_termios(ctx, arg, Flavour::Termios, true, true),
        TCSETSW => set_termios(ctx, arg, Flavour::Termios, false, true),
        TCSETS => set_termios(ctx, arg, Flavour::Termios, false, false),
        TCGETS => {
            let raw = env(ctx).0.termios.to_termios();
            put(ctx, arg, &raw)
        }
        TCGETS2 => {
            let raw = env(ctx).0.termios.to_termios2();
            put(ctx, arg, &raw)
        }
        TCSETSF2 => set_termios(ctx, arg, Flavour::Termios2, true, true),
        TCSETSW2 => set_termios(ctx, arg, Flavour::Termios2, false, true),
        TCSETS2 => set_termios(ctx, arg, Flavour::Termios2, false, false),
        TCGETA => {
            let raw = env(ctx).0.termios.to_termio();
            put(ctx, arg, &raw)
        }
        TCSETAF => set_termios(ctx, arg, Flavour::Termio, true, true),
        TCSETAW => set_termios(ctx, arg, Flavour::Termio, false, true),
        TCSETA => set_termios(ctx, arg, Flavour::Termio, false, false),
        TIOCGLCKTRMIOS => {
            let raw = env(ctx).0.termios_locked.to_termios();
            put(ctx, arg, &raw)
        }
        TIOCSLCKTRMIOS => {
            // checkpoint_restore_ns_capable(&init_user_ns) is CAP_CHECKPOINT_RESTORE or
            // CAP_SYS_ADMIN; shortcut: `Cred` models CAP_SYS_ADMIN only, extend with the
            // credential model if CAP_CHECKPOINT_RESTORE is ever added.
            if !ctx.cred().sys_admin {
                return Err(Errno::EPERM.into());
            }
            let mut locked = env(ctx).0.termios_locked;
            locked.set_from_termios(&get::<_, TERMIOS_SIZE>(ctx, arg)?);
            env(ctx).0.termios_locked = locked;
            Ok(0)
        }
        TIOCGSOFTCAR => {
            let clocal = i32::from(env(ctx).0.termios.cflag & crate::tty::termios::CLOCAL != 0);
            put(ctx, arg, &clocal.to_le_bytes())
        }
        TIOCSSOFTCAR => {
            let enable = u32::from_le_bytes(get::<_, 4>(ctx, arg)?) != 0;
            let tty = env(ctx).0;
            tty.change_softcar(enable)?;
            Ok(0)
        }
        // Also TCGETX/TCSETX*: no driver handles them, so `tty_ioctl` ends in `-ENOTTY`.
        _ => Err(Errno::ENOTTY.into()),
    }
}
