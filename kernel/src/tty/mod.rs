// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: drivers/tty/tty_io.c
// (`struct tty_struct` use, `tty_init_termios`, `tty_save_termios`, `tty_release`,
// `__tty_hangup`, `tty_hung_up_p`, `tty_ioctl`), drivers/tty/tty_jobctrl.c,
// include/linux/tty.h (`struct tty_struct`, `tty_ctrl`), drivers/tty/n_tty.c.
// All GPL-2.0 (n_tty.c GPL-1.0+; see `ldisc`).
// Transformation: one tty (`ttyS0`, the console), a single `Tty` object with the
// fixed N_TTY line discipline and the serial port's transmit queue; `struct pid`
// references are [`PidRef`]s (id plus number) because the task model frees a pid
// with its last task; every wake-up is a counter the caller turns into a wake of the
// tty key; the sleeping `mutex`es are owner fields.
#![forbid(unsafe_code)]
//! The tty core for the console: termios, the `N_TTY` line discipline, the serial
//! port's transmit queue, the controlling-terminal state and job control.
//!
//! # Contract
//! * Context: task context, or the hardirq glue of the input drivers with the
//!   process lock held (never in NMI); no sleeping, no allocation after
//!   [`Tty::new`]. Everything that sleeps in Linux is a state machine here
//!   ([`ldisc::ReadStep`], [`ldisc::WritePass`]); `syscall::tty` drives it.
//! * Locking: the caller serialises (the process lock). `Tty` sits at the
//!   `PROCESS`/`VFS` level of the lock-order DAG (`services`): tty -> task list
//!   is the order of `isig` and the job-control signals; nothing in here takes
//!   a lock.
//! * Wake-ups: [`Tty::take_events`] reports that a reader, writer or poller may
//!   proceed. The input worker's kick (`n_tty_kick_worker`) has no queue to run: the
//!   embedder flushes its flip buffer on every tty entry (`ttyin::flush`).

pub mod jobctl;
pub mod keyboard;
pub mod keymap_data;
pub mod ldisc;
pub mod scancode;
pub mod termios;

#[cfg(test)]
mod tests;

use crate::task::{TaskId, pid::PidRef};
use ldisc::{Ldata, Port};
use syscalls::Errno;
use termios::{Ktermios, SERIAL_INIT_TERMIOS};

/// What the line discipline needs from outside: signals for the foreground
/// group and the wire.
pub trait Host {
    /// `kill_pgrp(pgrp, sig, 1)`: the kernel signals a process group.
    fn kill_pgrp(&mut self, pgrp: PidRef, sig: u8);
    /// The bytes the UART puts on the wire (serial line and framebuffer).
    fn transmit(&mut self, bytes: &[u8]);
}

/// A [`Host`] for an operation that cannot signal or transmit (construction).
pub struct NullHost;
impl Host for NullHost {
    fn kill_pgrp(&mut self, _pgrp: PidRef, _sig: u8) {}
    fn transmit(&mut self, _bytes: &[u8]) {}
}

/// `struct winsize`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Winsize {
    pub row: u16,
    pub col: u16,
    pub xpixel: u16,
    pub ypixel: u16,
}

impl Winsize {
    #[must_use]
    pub fn to_bytes(self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[0..2].copy_from_slice(&self.row.to_le_bytes());
        out[2..4].copy_from_slice(&self.col.to_le_bytes());
        out[4..6].copy_from_slice(&self.xpixel.to_le_bytes());
        out[6..8].copy_from_slice(&self.ypixel.to_le_bytes());
        out
    }
    #[must_use]
    pub fn from_bytes(raw: &[u8; 8]) -> Self {
        let half = |at: usize| u16::from_le_bytes([raw[at], raw[at + 1]]);
        Self {
            row: half(0),
            col: half(2),
            xpixel: half(4),
            ypixel: half(6),
        }
    }
}

/// `struct tty_ctrl`: the session and foreground group the terminal belongs to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ctrl {
    pub session: Option<PidRef>,
    pub pgrp: Option<PidRef>,
}

/// `struct tty_struct` of the console tty.
#[allow(
    clippy::struct_excessive_bools,
    reason = "the flags and state bits of `struct tty_struct`"
)]
pub struct Tty {
    pub termios: Ktermios,
    /// `tty->termios_locked` (`TIOCGLCKTRMIOS`): nothing is locked.
    pub termios_locked: Ktermios,
    /// `driver->termios[idx]`: what the last close left behind.
    saved_termios: Ktermios,
    pub winsize: Winsize,
    pub ctrl: Ctrl,
    /// `TTY_HUPPED` / `TTY_HUPPING` / `TTY_EXCLUSIVE` / `TTY_THROTTLED`.
    pub hupped: bool,
    hupping: bool,
    pub exclusive: bool,
    throttled: bool,
    /// `tty->flow.stopped` / `tco_stopped`.
    flow_stopped: bool,
    flow_tco_stopped: bool,
    /// `tty->count`: open file descriptions on this tty.
    pub count: u32,
    ld: Ldata,
    port: Port,
    events: u32,
    /// `atomic_read_lock` / `atomic_write_lock`.
    read_owner: Option<TaskId>,
    write_owner: Option<TaskId>,
}

impl Tty {
    /// A freshly installed console tty: serial `init_termios`, `N_TTY` open.
    ///
    /// # Errors
    /// `ENOMEM`.
    pub fn new() -> Result<Self, Errno> {
        let mut tty = Self {
            termios: SERIAL_INIT_TERMIOS,
            termios_locked: Ktermios {
                iflag: 0,
                oflag: 0,
                cflag: 0,
                lflag: 0,
                line: 0,
                cc: [0; termios::NCCS],
                ispeed: 0,
                ospeed: 0,
            },
            saved_termios: SERIAL_INIT_TERMIOS,
            winsize: Winsize::default(),
            ctrl: Ctrl::default(),
            hupped: false,
            hupping: false,
            exclusive: false,
            throttled: false,
            flow_stopped: false,
            flow_tco_stopped: false,
            count: 0,
            ld: Ldata::new()?,
            port: Port::new()?,
            events: 0,
            read_owner: None,
            write_owner: None,
        };
        tty.ldisc_reinit(&mut NullHost);
        Ok(tty)
    }

    /// The reset of the last close (`tty_release_struct`): the termios is kept
    /// for the next open (`tty_save_termios`), everything else is dropped.
    pub fn final_release(&mut self) {
        self.saved_termios = self.termios;
        self.winsize = Winsize::default();
        self.ctrl = Ctrl::default();
        self.hupped = false;
        self.hupping = false;
        self.exclusive = false;
        self.throttled = false;
        self.flow_stopped = false;
        self.flow_tco_stopped = false;
        self.port.reset_all();
        self.read_owner = None;
        self.write_owner = None;
        self.ldisc_reinit(&mut NullHost);
        self.events = self.events.wrapping_add(1);
    }

    /// Wake-up counter: a change since the last look means readers, writers or
    /// pollers have something to re-check.
    pub fn take_events(&mut self) -> bool {
        core::mem::take(&mut self.events) != 0
    }

    /// `tty_write_lock(tty, ndelay)`: `false` when another writer owns the
    /// tty (`-EAGAIN` for `O_NDELAY`, else the caller sleeps).
    pub fn write_lock(&mut self, owner: TaskId) -> bool {
        match self.write_owner {
            None => {
                self.write_owner = Some(owner);
                true
            }
            Some(current) => current == owner,
        }
    }

    /// `tty_write_unlock`: writers waiting for the lock are woken.
    pub fn write_unlock(&mut self, owner: TaskId) {
        if self.write_owner == Some(owner) {
            self.write_owner = None;
            self.events = self.events.wrapping_add(1);
        }
    }

    /// Whether `owner` holds the reader serialisation lock (a read that
    /// returned `more` keeps it until the continuation).
    #[must_use]
    pub fn read_locked_by(&self, owner: TaskId) -> bool {
        self.read_owner == Some(owner)
    }

    /// Whether another task holds the read lock.
    #[must_use]
    pub fn read_busy(&self) -> bool {
        self.read_owner.is_some()
    }

    /// Whether another task holds the write lock.
    #[must_use]
    pub fn write_busy(&self) -> bool {
        self.write_owner.is_some()
    }

    /// `TIOCEXCL` / `TIOCNXCL` / `TIOCGEXCL`.
    pub fn set_exclusive(&mut self, on: bool) {
        self.exclusive = on;
    }

    /// `TCXONC`: `Err` is the errno of a bad action.
    ///
    /// # Errors
    /// `EINVAL`.
    pub fn tcxonc(&mut self, h: &mut dyn Host, action: u64) -> Result<(), Errno> {
        use termios::{DISABLED_CHAR, VSTART, VSTOP};
        match action {
            0 => {
                // TCOOFF
                if !self.flow_tco_stopped {
                    self.flow_tco_stopped = true;
                    self.stop_tty();
                }
            }
            1 => {
                // TCOON
                if self.flow_tco_stopped {
                    self.flow_tco_stopped = false;
                    self.start_tty(h);
                }
            }
            2 => {
                // TCIOFF
                let c = self.termios.cc[VSTOP];
                if c != DISABLED_CHAR {
                    self.send_xchar(h, c);
                }
            }
            3 => {
                // TCION
                let c = self.termios.cc[VSTART];
                if c != DISABLED_CHAR {
                    self.send_xchar(h, c);
                }
            }
            _ => return Err(Errno::EINVAL),
        }
        Ok(())
    }

    /// `tty_do_resize`: whether the size changed (the caller sends `SIGWINCH`
    /// to the foreground group then).
    pub fn do_resize(&mut self, ws: Winsize) -> bool {
        if ws == self.winsize {
            return false;
        }
        self.winsize = ws;
        true
    }

    /// `tty_open`'s tail: the hangup state of an earlier session ends.
    pub fn opened(&mut self) {
        self.count += 1;
        self.hupped = false;
    }

    /// `tty_release` for one file; returns true for the final close, after which
    /// the caller clears the controlling terminals of the session and calls
    /// [`Tty::final_release`].
    pub fn closed(&mut self) -> bool {
        self.count = self.count.saturating_sub(1);
        self.count == 0
    }
}

/// `pid_vnr` of a reference: the number it had.
#[must_use]
pub fn pid_nr(pid: Option<PidRef>) -> i32 {
    pid.map_or(0, |p| p.nr)
}
