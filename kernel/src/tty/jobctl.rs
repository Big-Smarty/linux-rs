// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: drivers/tty/tty_jobctrl.c
// (`__tty_check_change` 28-62, `__proc_set_tty` 90-115, `tty_open_proc_set_tty`
// 120-154, `tty_signal_session_leader` 190-235, `disassociate_ctty` 252-318,
// `no_tty`, `tiocsctty` 340-385, `tiocgpgrp`, `tiocspgrp` 466-515, `tiocgsid`),
// drivers/tty/tty_io.c (`__tty_hangup` 568-650, `tty_vhangup_session`),
// kernel/exit.c (`do_exit`: `disassociate_ctty(1)`). All GPL-2.0.
// Transformation: `signal->tty` is [`Tasklist::has_ctty`]; the tty's `session`
// and `pgrp` are [`PidRef`]s; `tasklist_lock`/`siglock`/`ctrl.lock` are the
// caller's exclusion.
#![forbid(unsafe_code)]
//! Job control of the console tty: foreground/background checks, controlling
//! terminal acquisition and release, hangup.

use super::{Ctrl, Host, Tty};
use crate::{
    signal::{SIGCONT, SIGHUP, SIGTTIN, info::SigInfo},
    task::{
        TaskId, Tasklist,
        exit::Waker,
        pid::{PidRef, PidType},
    },
};
use syscalls::Errno;

/// Why `__tty_check_change` refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckError {
    /// `-EIO`.
    Eio,
    /// `-ERESTARTSYS`: the signal was sent to the caller's group.
    Restart,
}

/// `__tty_check_change(tty, sig)` for the task `me`: a background process that
/// reads (`SIGTTIN`) or changes the terminal (`SIGTTOU`) is stopped; when the
/// signal is ignored or blocked the operation goes ahead (a read fails with
/// `EIO`), and an orphaned group gets `EIO`. `ignored` is `is_ignored(sig)`: the
/// signal is blocked or its disposition is `SIG_IGN`.
///
/// # Errors
/// [`CheckError`].
pub fn check_change(
    tty: &Tty,
    tasks: &mut Tasklist,
    me: TaskId,
    w: &mut dyn Waker,
    sig: u8,
    ignored: bool,
) -> Result<(), CheckError> {
    if !tasks.has_ctty(me) {
        return Ok(());
    }
    let pgrp = tasks.task_pid_type(me, PidType::Pgid);
    let Some(tty_pgrp) = tty.ctrl.pgrp else {
        // "tty->pgrp == NULL!" is only a warning.
        return Ok(());
    };
    if pgrp == Some(tty_pgrp.id) {
        return Ok(());
    }
    if ignored {
        return if sig == SIGTTIN {
            Err(CheckError::Eio)
        } else {
            Ok(())
        };
    }
    if tasks.is_pgrp_orphaned(me) {
        return Err(CheckError::Eio);
    }
    if let Some(pgrp) = pgrp {
        let _ = tasks.kill_pgrp_priv(pgrp, sig, w);
    }
    Err(CheckError::Restart)
}

/// `kill_pgrp(pgrp, sig, 0)`: `SEND_SIG_NOINFO`, a `kill`-style signal from `me`.
fn kill_pgrp_as(tasks: &mut Tasklist, me: TaskId, pgrp: PidRef, sig: u8, w: &mut dyn Waker) {
    let uid = tasks.task(me).map_or(0, |t| t.cred.uid);
    let info = SigInfo::from_kill(sig, false, tasks.task_tgid_vnr(me), uid);
    let _ = tasks.kill_pgrp_info(Some(me), i32::from(sig), info, Some(pgrp.id), w);
}

/// `__proc_set_tty`: `me` (a session leader) acquires the tty. An earlier
/// owner's references are dropped (`tiocsctty` stealing).
pub fn proc_set_tty(tty: &mut Tty, tasks: &mut Tasklist, me: TaskId) {
    tty.ctrl.pgrp = tasks.task_pgrp_ref(me);
    tty.ctrl.session = tasks.task_session_ref(me);
    tasks.set_ctty(me, true);
    tasks.set_tty_old_pgrp(me, None);
}

/// `tty_open_proc_set_tty`: opening the terminal makes it the controlling one
/// for a session leader that has none while the tty belongs to no session.
/// `readable` is `filp->f_mode & FMODE_READ`.
pub fn open_set_tty(tty: &mut Tty, tasks: &mut Tasklist, me: TaskId, readable: bool) {
    if tasks.is_session_leader(me) && !tasks.has_ctty(me) && tty.ctrl.session.is_none() && readable
    {
        proc_set_tty(tty, tasks, me);
    }
}

/// `tiocsctty`.
///
/// # Errors
/// `EPERM`.
pub fn tiocsctty(
    tty: &mut Tty,
    tasks: &mut Tasklist,
    me: TaskId,
    arg: u64,
    readable: bool,
    sys_admin: bool,
) -> Result<(), Errno> {
    let my_session = tasks.task_session_ref(me);
    if tasks.is_session_leader(me) && my_session == tty.ctrl.session && my_session.is_some() {
        return Ok(());
    }
    // The process must be a session leader and not have a controlling tty already.
    if !tasks.is_session_leader(me) || tasks.has_ctty(me) {
        return Err(Errno::EPERM);
    }
    if tty.ctrl.session.is_some() {
        // This tty is already the controlling tty for another session group!
        if arg == 1 && sys_admin {
            tasks.session_clear_tty(tty.ctrl.session);
        } else {
            return Err(Errno::EPERM);
        }
    }
    // See the comment in tty_open_proc_set_tty().
    if !readable && !sys_admin {
        return Err(Errno::EPERM);
    }
    proc_set_tty(tty, tasks, me);
    Ok(())
}

/// `tiocgpgrp`.
///
/// # Errors
/// `ENOTTY` when the tty is not the caller's controlling terminal.
pub fn tiocgpgrp(tty: &Tty, tasks: &Tasklist, me: TaskId) -> Result<i32, Errno> {
    if !tasks.has_ctty(me) {
        return Err(Errno::ENOTTY);
    }
    Ok(super::pid_nr(tty.ctrl.pgrp))
}

/// `tiocspgrp` after the `tty_check_change` and the user read: `pgrp_nr` is the
/// value the caller passed.
///
/// # Errors
/// `EINVAL`, `ENOTTY`, `ESRCH`, `EPERM`.
pub fn tiocspgrp(tty: &mut Tty, tasks: &Tasklist, me: TaskId, pgrp_nr: i32) -> Result<(), Errno> {
    if pgrp_nr < 0 {
        return Err(Errno::EINVAL);
    }
    if !tasks.has_ctty(me) || tty.ctrl.session != tasks.task_session_ref(me) {
        return Err(Errno::ENOTTY);
    }
    if tty.ctrl.session.is_none() {
        return Err(Errno::ENOTTY);
    }
    let pgrp = tasks.find_vpid(pgrp_nr).ok_or(Errno::ESRCH)?;
    if tasks.session_of_pgrp(pgrp) != tasks.task_pid_type(me, PidType::Sid) {
        return Err(Errno::EPERM);
    }
    tty.ctrl.pgrp = tasks.pid_ref(Some(pgrp));
    Ok(())
}

/// `tiocgsid`.
///
/// # Errors
/// `ENOTTY`.
pub fn tiocgsid(tty: &Tty, tasks: &Tasklist, me: TaskId) -> Result<i32, Errno> {
    if !tasks.has_ctty(me) {
        return Err(Errno::ENOTTY);
    }
    match tty.ctrl.session {
        Some(session) => Ok(session.nr),
        None => Err(Errno::ENOTTY),
    }
}

/// `tty_signal_session_leader`: `SIGHUP` and `SIGCONT` to the session leader(s) of
/// the tty's session, whose controlling terminal is cleared; with
/// `exit_session` the foreground group gets `SIGHUP` too.
fn signal_session_leader(
    tty: &mut Tty,
    tasks: &mut Tasklist,
    w: &mut dyn Waker,
    exit_session: bool,
) {
    let mut tty_pgrp: Option<PidRef> = None;
    if let Some(session) = tty.ctrl.session {
        let mut index = 0;
        loop {
            let Some(p) = tasks.session_members(session).nth(index) else {
                break;
            };
            index += 1;
            if tasks.has_ctty(p) {
                tasks.proc_clear_tty(p);
            }
            if !tasks.is_session_leader(p) {
                continue;
            }
            tasks.send_sig_priv(p, SIGHUP, w);
            tasks.send_sig_priv(p, SIGCONT, w);
            if tty.ctrl.pgrp.is_some() {
                tasks.set_tty_old_pgrp(p, tty.ctrl.pgrp);
            }
            tty_pgrp = tty.ctrl.pgrp;
        }
    }
    if let Some(pgrp) = tty_pgrp
        && exit_session
    {
        let _ = tasks.kill_pgrp_ref(pgrp, SIGHUP, w);
    }
}

/// `__tty_hangup`: the tty is hung up. `console_open`: some open file is a
/// `/dev/console` file (`cons_filp`), which the hangup does not replace; the
/// discipline is then restarted. The caller converts the other files of the tty
/// to hung-up ones when this returns true (the hangup ran).
pub fn hangup(
    tty: &mut Tty,
    tasks: &mut Tasklist,
    w: &mut dyn Waker,
    h: &mut dyn Host,
    exit_session: bool,
    console_open: bool,
) -> bool {
    if tty.hupped {
        return false;
    }
    // Some console devices are not actually hung up: tell readers to give up.
    tty.hupping = true;
    signal_session_leader(tty, tasks, w, exit_session);
    tty.ldisc_hangup(h, console_open);
    tty.ctrl = Ctrl::default();
    tty.hupped = true;
    tty.hupping = false;
    tty.events = tty.events.wrapping_add(1);
    true
}

/// `disassociate_ctty(on_exit)` for the session leader `me`: `on_exit` is the
/// exit of the leader, false is `TIOCNOTTY`. `console_open` as for [`hangup`];
/// true is returned when a hangup ran (its files are to be converted).
pub fn disassociate_ctty(
    tty: &mut Tty,
    tasks: &mut Tasklist,
    me: TaskId,
    w: &mut dyn Waker,
    h: &mut dyn Host,
    on_exit: bool,
    console_open: bool,
) -> bool {
    if !tasks.is_session_leader(me) {
        return false;
    }
    let mut hung = false;
    if tasks.has_ctty(me) {
        if on_exit {
            // tty_vhangup_session
            hung = hangup(tty, tasks, w, h, true, console_open);
        } else if let Some(pgrp) = tty.ctrl.pgrp {
            // `kill_pgrp(pgrp, sig, 0)`: from the caller, `SI_USER`.
            kill_pgrp_as(tasks, me, pgrp, SIGHUP, w);
            kill_pgrp_as(tasks, me, pgrp, SIGCONT, w);
        }
    } else if on_exit {
        if let Some(old) = tasks.take_tty_old_pgrp(me) {
            let _ = tasks.kill_pgrp_ref(old, SIGHUP, w);
            let _ = tasks.kill_pgrp_ref(old, SIGCONT, w);
        }
        return false;
    }
    if tasks.has_ctty(me) {
        tty.ctrl = Ctrl::default();
    }
    tasks.take_tty_old_pgrp(me);
    // Now clear signal->tty under the lock.
    let session = tasks.task_session_ref(me);
    tasks.session_clear_tty(session);
    hung
}

/// `TIOCNOTTY` (`no_tty`).
///
/// # Errors
/// `ENOTTY` when the tty is not the caller's controlling terminal.
pub fn tiocnotty(
    tty: &mut Tty,
    tasks: &mut Tasklist,
    me: TaskId,
    w: &mut dyn Waker,
    h: &mut dyn Host,
    console_open: bool,
) -> Result<(), Errno> {
    if !tasks.has_ctty(me) {
        return Err(Errno::ENOTTY);
    }
    // `on_exit` is false: no hangup, no files to convert.
    let _ = disassociate_ctty(tty, tasks, me, w, h, false, console_open);
    tasks.proc_clear_tty(me);
    Ok(())
}
