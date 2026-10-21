// SPDX-License-Identifier: GPL-1.0+ (n_tty.c); GPL-2.0-only for the port
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: drivers/tty/n_tty.c (SPDX
// GPL-1.0+; the whole file's algorithms: `n_tty_receive_buf_common`,
// `n_tty_receive_char*`, `eraser`, `isig`, the echo buffer
// (`add_echo_byte`..`__process_echoes`), `do_output_char`, `process_output*`,
// `n_tty_set_termios`, `n_tty_read`, `n_tty_write`, `n_tty_poll`, `n_tty_ioctl`,
// `inq_canon`, `canon_copy_from_read_buf`, `copy_from_read_buf`),
// drivers/tty/tty_ioctl.c (`tty_set_termios`, `set_termios`, `__tty_perform_flush`,
// `n_tty_ioctl_helper`, `tty_mode_ioctl`, throttle helpers), drivers/tty/tty_io.c
// (`stop_tty`/`start_tty`, `__tty_hangup`, `tty_ldisc_hangup`), drivers/tty/serial/
// serial_core.c (`uart_write`, `uart_put_char`, `uart_flush_chars`,
// `uart_write_room`, `uart_chars_in_buffer`, `uart_flush_buffer`,
// `uart_send_xchar`, `uart_throttle`, `uart_unthrottle`, `uart_stop`/`uart_start`).
// Transformation: the line discipline and the 8250 transmit queue are one `Tty`;
// every sleep of the C code is a return value (`WriteStep`, `ReadStep`) so the
// caller drops its locks, sleeps on the tty key and calls again; `termios_rwsem`,
// `ldisc_sem`, `output_lock`, `atomic_read_lock` and `atomic_write_lock` reduce to
// the single-CPU exclusion of the caller plus the two owner fields that keep a
// sleeping reader/writer exclusive; the flip buffer is the caller's; pty packet
// mode, `TIOCPKT`, `FASYNC`/`SIGIO` and the audit hook do not exist here.
#![forbid(unsafe_code)]
//! The `N_TTY` line discipline over the serial console port.

use super::termios::{
    BRKINT, DISABLED_CHAR, ECHO, ECHOCTL, ECHOE, ECHOK, ECHOKE, ECHONL, ECHOPRT, EXTPROC, ICANON,
    ICRNL, IEXTEN, IGNBRK, IGNCR, IGNPAR, INLCR, INPCK, ISIG, ISTRIP, IUCLC, IUTF8, IXANY, IXOFF,
    IXON, Ktermios, NOFLSH, OCRNL, OLCUC, ONLCR, ONLRET, ONOCR, OPOST, PARMRK, TABDLY, TOSTOP,
    VEOF, VEOL, VEOL2, VERASE, VINTR, VKILL, VLNEXT, VMIN, VQUIT, VREPRINT, VSTART, VSTOP, VSUSP,
    VTIME, VWERASE, XTABS,
};
use super::{Host, Tty};
use crate::signal::{SIGINT, SIGQUIT, SIGTSTP};
use alloc::vec::Vec;
use syscalls::Errno;

/// `N_TTY_BUF_SIZE`.
pub const N_TTY_BUF_SIZE: usize = 4096;
const MASK_BITS: usize = N_TTY_BUF_SIZE - 1;
const WORDS: usize = N_TTY_BUF_SIZE / 64;
/// `TTY_THRESHOLD_THROTTLE` and `TTY_THRESHOLD_UNTHROTTLE`.
const TTY_THRESHOLD_THROTTLE: usize = 128;
const TTY_THRESHOLD_UNTHROTTLE: usize = 128;
const ECHO_OP_START: u8 = 0xff;
const ECHO_OP_MOVE_BACK_COL: u8 = 0x80;
const ECHO_OP_SET_CANON_COL: u8 = 0x81;
const ECHO_OP_ERASE_TAB: u8 = 0x82;
const ECHO_COMMIT_WATERMARK: usize = 256;
const ECHO_BLOCK: usize = 256;
/// `N_TTY_BUF_SIZE - (ECHO_BLOCK + 32)`.
const ECHO_DISCARD_WATERMARK: usize = N_TTY_BUF_SIZE - (ECHO_BLOCK + 32);
/// `WAKEUP_CHARS`: `poll` reports "writable" below this many queued bytes.
const WAKEUP_CHARS: usize = 256;
/// `UART_XMIT_SIZE` = `PAGE_SIZE`: the transmit queue of the serial port.
pub const XMIT_SIZE: usize = 4096;

/// `TTY_BREAK` etc.: the flag byte that accompanies a received character.
pub const TTY_NORMAL: u8 = 0;
pub const TTY_BREAK: u8 = 1;
pub const TTY_FRAME: u8 = 2;
pub const TTY_PARITY: u8 = 3;
pub const TTY_OVERRUN: u8 = 4;

fn iscntrl(c: u8) -> bool {
    c < 0x20 || c == 0x7f
}
fn isalnum(c: u8) -> bool {
    c.is_ascii_alphanumeric()
}

fn test_bit(words: &[u64; WORDS], bit: usize) -> bool {
    words[bit / 64] >> (bit % 64) & 1 != 0
}
fn set_bit(words: &mut [u64; WORDS], bit: usize) {
    words[bit / 64] |= 1 << (bit % 64);
}
fn clear_bit(words: &mut [u64; WORDS], bit: usize) {
    words[bit / 64] &= !(1 << (bit % 64));
}
/// `find_next_bit(words, size, offset)`: `size` when none.
fn find_next_bit(words: &[u64; WORDS], size: usize, offset: usize) -> usize {
    (offset..size)
        .find(|&bit| test_bit(words, bit))
        .unwrap_or(size)
}

/// `n` zero bytes, fallibly (`Vec::resize` does not exist under
/// `no_global_oom_handling`).
fn zeroed(n: usize) -> Result<Vec<u8>, Errno> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Errno::ENOMEM)?;
    for _ in 0..n {
        v.push_within_capacity(0).map_err(|_| Errno::ENOMEM)?;
    }
    Ok(v)
}

/// The serial port's transmit queue (`uart_state.port.xmit_fifo`, a `kfifo`).
pub(super) struct Port {
    fifo: Vec<u8>,
    head: usize,
    tail: usize,
    /// `port->x_char`: a priority character, sent even while stopped.
    x_char: Option<u8>,
}

impl Port {
    pub(super) fn new() -> Result<Self, Errno> {
        Ok(Self {
            fifo: zeroed(XMIT_SIZE)?,
            head: 0,
            tail: 0,
            x_char: None,
        })
    }
    pub(super) fn len(&self) -> usize {
        self.head - self.tail
    }
    pub(super) fn reset_all(&mut self) {
        self.reset();
        self.x_char = None;
    }
    fn avail(&self) -> usize {
        XMIT_SIZE - self.len()
    }
    /// `kfifo_put`.
    fn put(&mut self, c: u8) -> bool {
        if self.avail() == 0 {
            return false;
        }
        self.fifo[self.head & (XMIT_SIZE - 1)] = c;
        self.head += 1;
        true
    }
    /// `kfifo_in`: as much as fits.
    fn put_all(&mut self, bytes: &[u8]) -> usize {
        let n = bytes.len().min(self.avail());
        let from = self.head & (XMIT_SIZE - 1);
        let first = n.min(XMIT_SIZE - from);
        self.fifo[from..from + first].copy_from_slice(&bytes[..first]);
        self.fifo[..n - first].copy_from_slice(&bytes[first..n]);
        self.head += n;
        n
    }
    fn reset(&mut self) {
        self.head = 0;
        self.tail = 0;
    }
    /// The contiguous queued bytes, consumed with [`Port::advance`].
    fn chunk(&self) -> &[u8] {
        let from = self.tail & (XMIT_SIZE - 1);
        let to = (from + self.len()).min(XMIT_SIZE);
        &self.fifo[from..to]
    }
    fn advance(&mut self, n: usize) {
        self.tail += n;
    }
}

/// What `eraser` does for the character.
#[derive(PartialEq)]
enum EraseKind {
    Erase,
    Werase,
    Line,
}

/// `struct n_tty_data` (buffers on the heap, allocated once per tty).
#[allow(
    clippy::struct_excessive_bools,
    reason = "the flags of `struct n_tty_data`"
)]
pub(super) struct Ldata {
    read_head: usize,
    commit_head: usize,
    canon_head: usize,
    echo_head: usize,
    echo_commit: usize,
    echo_mark: usize,
    char_map: [u64; 4],
    no_room: bool,
    lnext: bool,
    erasing: bool,
    raw: bool,
    real_raw: bool,
    icanon: bool,
    push: bool,
    read_buf: Vec<u8>,
    read_flags: [u64; WORDS],
    echo_buf: Vec<u8>,
    read_tail: usize,
    line_start: usize,
    lookahead_count: usize,
    column: u32,
    canon_column: u32,
    echo_tail: usize,
}

impl Ldata {
    pub(super) fn new() -> Result<Self, Errno> {
        let read_buf = zeroed(N_TTY_BUF_SIZE)?;
        let echo_buf = zeroed(N_TTY_BUF_SIZE)?;
        Ok(Self {
            read_head: 0,
            commit_head: 0,
            canon_head: 0,
            echo_head: 0,
            echo_commit: 0,
            echo_mark: 0,
            char_map: [0; 4],
            no_room: false,
            lnext: false,
            erasing: false,
            raw: false,
            real_raw: false,
            icanon: false,
            push: false,
            read_buf,
            read_flags: [0; WORDS],
            echo_buf,
            read_tail: 0,
            line_start: 0,
            lookahead_count: 0,
            column: 0,
            canon_column: 0,
            echo_tail: 0,
        })
    }

    fn read_cnt(&self) -> usize {
        self.read_head.wrapping_sub(self.read_tail)
    }
    fn rbuf(&self, i: usize) -> u8 {
        self.read_buf[i & MASK_BITS]
    }
    fn ebuf(&self, i: usize) -> u8 {
        self.echo_buf[i & MASK_BITS]
    }
    fn char_map_test(&self, c: u8) -> bool {
        self.char_map[usize::from(c) / 64] >> (usize::from(c) % 64) & 1 != 0
    }
    fn char_map_set(&mut self, c: u8) {
        self.char_map[usize::from(c) / 64] |= 1 << (usize::from(c) % 64);
    }

    /// `put_tty_queue`.
    fn put_tty_queue(&mut self, c: u8) {
        self.read_buf[self.read_head & MASK_BITS] = c;
        self.read_head = self.read_head.wrapping_add(1);
    }

    /// `reset_buffer_flags`.
    fn reset_buffer_flags(&mut self) {
        self.read_head = 0;
        self.canon_head = 0;
        self.read_tail = 0;
        self.commit_head = 0;
        self.line_start = 0;
        self.erasing = false;
        self.read_flags = [0; WORDS];
        self.push = false;
        self.lookahead_count = 0;
    }

    /// `add_echo_byte`.
    fn add_echo_byte(&mut self, c: u8) {
        self.echo_buf[self.echo_head & MASK_BITS] = c;
        self.echo_head = self.echo_head.wrapping_add(1);
    }
    fn echo_move_back_col(&mut self) {
        self.add_echo_byte(ECHO_OP_START);
        self.add_echo_byte(ECHO_OP_MOVE_BACK_COL);
    }
    fn echo_set_canon_col(&mut self) {
        self.add_echo_byte(ECHO_OP_START);
        self.add_echo_byte(ECHO_OP_SET_CANON_COL);
    }
    fn echo_erase_tab(&mut self, num_chars: u32, after_tab: bool) {
        self.add_echo_byte(ECHO_OP_START);
        self.add_echo_byte(ECHO_OP_ERASE_TAB);
        // Only the value modulo 8 matters; the high bit flags "after a tab".
        let mut num = (num_chars & 7) as u8;
        if after_tab {
            num |= 0x80;
        }
        self.add_echo_byte(num);
    }
    /// `echo_char_raw`.
    fn echo_char_raw(&mut self, c: u8) {
        if c == ECHO_OP_START {
            self.add_echo_byte(ECHO_OP_START);
            self.add_echo_byte(ECHO_OP_START);
        } else {
            self.add_echo_byte(c);
        }
    }
    /// `echo_char`: control characters are tagged to be echoed as `^X`.
    fn echo_char(&mut self, c: u8, t: &Ktermios) {
        if c == ECHO_OP_START {
            self.add_echo_byte(ECHO_OP_START);
            self.add_echo_byte(ECHO_OP_START);
        } else {
            if t.lflag & ECHOCTL != 0 && iscntrl(c) && c != b'\t' {
                self.add_echo_byte(ECHO_OP_START);
            }
            self.add_echo_byte(c);
        }
    }
    /// `finish_erasing`.
    fn finish_erasing(&mut self) {
        if self.erasing {
            self.echo_char_raw(b'/');
            self.erasing = false;
        }
    }
}

fn is_continuation(c: u8, t: &Ktermios) -> bool {
    t.iflag & IUTF8 != 0 && c & 0xc0 == 0x80
}

/// What a canonical read of one 64-byte chunk produced, as the C function's
/// return value does: bytes, an error, or "sleep".
#[derive(Debug, PartialEq, Eq)]
pub enum ReadStep {
    /// Bytes are in the buffer (`.0` of them); `more`: the line discipline
    /// holds its locks and the caller must call again (`*cookie` set).
    Done { len: usize, more: bool },
    /// The read failed (`-EIO`, `-EAGAIN`, `-ERESTARTSYS` as the errno magnitude;
    /// `restart` for `-ERESTARTSYS`).
    Error { errno: Option<Errno>, restart: bool },
    /// Sleep until the tty changes or `ms` pass (`None`: no timeout), then call
    /// again with `ReadOp::timeout` updated.
    Sleep { ms: Option<u64> },
}

/// Per-read state of `n_tty_read` that survives a sleep (the C locals).
#[derive(Debug)]
pub struct ReadOp {
    minimum: usize,
    time_ms: u64,
    /// Remaining timeout in ms; `u64::MAX` is `MAX_SCHEDULE_TIMEOUT`.
    pub timeout_ms: u64,
    old_tail: usize,
    /// Bytes already in the caller's buffer.
    kb: usize,
    /// The caller's buffer size for this call (at most 64).
    nr: usize,
    started: bool,
    /// The read lock is held (a cookie continuation, or a sleep in progress).
    holds: bool,
}

/// Facts about the file and task `n_tty_read` consults.
#[derive(Clone, Copy, Debug)]
pub struct ReadEnv {
    /// `file->f_flags & O_NONBLOCK`.
    pub nonblock: bool,
    /// `tty_hung_up_p(file)`.
    pub hung_up: bool,
    /// `signal_pending(current)`.
    pub signal_pending: bool,
}

/// What one pass of `n_tty_write` did.
#[derive(Debug, PartialEq, Eq)]
pub struct WritePass {
    pub consumed: usize,
}

impl ReadOp {
    /// The capacity of the next `n_tty_continue_cookie` call (`nr`).
    pub fn set_capacity(&mut self, nr: usize) {
        self.nr = nr;
        self.kb = 0;
    }
}

impl Tty {
    // ---- the 8250 port -----------------------------------------------------

    fn tx_stopped(&self) -> bool {
        self.flow_stopped
    }

    /// `__uart_start` -> `start_tx`: priority character first, then the queue
    /// unless the tty is stopped.
    pub(super) fn uart_start(&mut self, h: &mut dyn Host) {
        if let Some(c) = self.port.x_char.take() {
            h.transmit(&[c]);
        }
        if self.tx_stopped() {
            return;
        }
        while self.port.len() > 0 {
            let n = {
                let chunk = self.port.chunk();
                h.transmit(chunk);
                chunk.len()
            };
            self.port.advance(n);
        }
        self.port.reset();
    }

    /// `uart_write`: queue, then start.
    pub(super) fn uart_write(&mut self, h: &mut dyn Host, bytes: &[u8]) -> usize {
        let n = self.port.put_all(bytes);
        self.uart_start(h);
        n
    }

    /// `tty_put_char` (`uart_put_char`).
    fn tty_put_char(&mut self, c: u8) -> bool {
        self.port.put(c)
    }

    pub(super) fn write_room(&self) -> usize {
        self.port.avail()
    }

    /// `tty_chars_in_buffer` (`uart_chars_in_buffer`).
    #[must_use]
    pub fn chars_in_buffer(&self) -> usize {
        self.port.len()
    }

    /// `tty_driver_flush_buffer` (`uart_flush_buffer`): the queue is discarded
    /// and writers are woken.
    pub(super) fn driver_flush_buffer(&mut self) {
        self.port.reset();
        self.events = self.events.wrapping_add(1);
    }

    /// `uart_send_xchar`.
    pub(super) fn send_xchar(&mut self, h: &mut dyn Host, c: u8) {
        self.port.x_char = Some(c);
        if c != 0 {
            self.uart_start(h);
        } else {
            self.port.x_char = None;
        }
    }

    /// `__stop_tty` (`uart_stop`: transmission is gated by `flow.stopped`).
    pub(super) fn stop_tty(&mut self) {
        self.flow_stopped = true;
    }

    /// `fn_hold` (Scroll Lock): stop a running tty, start a stopped one.
    pub fn hold_toggle(&mut self, h: &mut dyn Host) {
        if self.flow_stopped {
            self.start_tty(h);
        } else {
            self.stop_tty();
        }
    }

    /// `__start_tty` + `tty_wakeup`: restart the queue.
    pub(super) fn start_tty(&mut self, h: &mut dyn Host) {
        if !self.flow_stopped || self.flow_tco_stopped {
            return;
        }
        self.flow_stopped = false;
        self.uart_start(h);
        self.events = self.events.wrapping_add(1);
    }

    /// `uart_throttle`: with `IXOFF` the other side is told to stop.
    fn throttle(&mut self, h: &mut dyn Host) {
        if self.termios.iflag & IXOFF != 0 {
            self.send_xchar(h, self.termios.cc[VSTOP]);
        }
    }

    fn unthrottle_driver(&mut self, h: &mut dyn Host) {
        if self.termios.iflag & IXOFF != 0 {
            self.send_xchar(h, self.termios.cc[VSTART]);
        }
    }

    /// `tty_unthrottle`.
    pub(super) fn tty_unthrottle(&mut self, h: &mut dyn Host) {
        if self.throttled {
            self.throttled = false;
            self.unthrottle_driver(h);
        }
    }

    // ---- ldisc life cycle ------------------------------------------------------

    /// `n_tty_open` on an existing buffer set: zero it and learn the termios.
    pub(super) fn ldisc_reinit(&mut self, h: &mut dyn Host) {
        let ld = &mut self.ld;
        ld.reset_buffer_flags();
        ld.read_head = 0;
        ld.echo_head = 0;
        ld.echo_tail = 0;
        ld.echo_mark = 0;
        ld.echo_commit = 0;
        ld.no_room = false;
        ld.lnext = false;
        ld.push = false;
        ld.column = 0;
        ld.canon_column = 0;
        ld.read_flags = [0; WORDS];
        self.n_tty_set_termios(None, h);
        self.tty_unthrottle(h);
    }

    /// `n_tty_flush_buffer`.
    pub fn n_tty_flush_buffer(&mut self, h: &mut dyn Host) {
        self.ld.reset_buffer_flags();
        self.n_tty_kick_worker(h);
    }

    /// `n_tty_kick_worker`: the input worker stopped for lack of room and may run
    /// again. shortcut: there is no worker to queue; the embedder flushes the flip
    /// buffer on every tty entry and input interrupt (`ttyin::flush`), so input
    /// left behind waits for the next tty syscall, poll or interrupt.
    fn n_tty_kick_worker(&mut self, _h: &mut dyn Host) {
        self.ld.no_room = false;
    }

    /// `n_tty_set_termios`: the line discipline learns of a termios change.
    pub(super) fn n_tty_set_termios(&mut self, old: Option<&Ktermios>, h: &mut dyn Host) {
        let t = self.termios;
        let ld = &mut self.ld;
        let changed = match old {
            None => true,
            Some(old) => (old.lflag ^ t.lflag) & (ICANON | EXTPROC) != 0,
        };
        if changed {
            ld.read_flags = [0; WORDS];
            ld.line_start = ld.read_tail;
            if t.lflag & ICANON == 0 || ld.read_cnt() == 0 {
                ld.canon_head = ld.read_tail;
                ld.push = false;
            } else {
                set_bit(&mut ld.read_flags, ld.read_head.wrapping_sub(1) & MASK_BITS);
                ld.canon_head = ld.read_head;
                ld.push = true;
            }
            ld.commit_head = ld.read_head;
            ld.erasing = false;
            ld.lnext = false;
        }
        ld.icanon = t.lflag & ICANON != 0;
        if t.iflag & (ISTRIP | IUCLC | IGNCR | ICRNL | INLCR | IXON | PARMRK) != 0
            || t.lflag & (ICANON | ISIG | ECHO) != 0
        {
            ld.char_map = [0; 4];
            if t.iflag & (IGNCR | ICRNL) != 0 {
                ld.char_map_set(b'\r');
            }
            if t.iflag & INLCR != 0 {
                ld.char_map_set(b'\n');
            }
            if t.lflag & ICANON != 0 {
                ld.char_map_set(t.cc[VERASE]);
                ld.char_map_set(t.cc[VKILL]);
                ld.char_map_set(t.cc[VEOF]);
                ld.char_map_set(b'\n');
                ld.char_map_set(t.cc[VEOL]);
                if t.lflag & IEXTEN != 0 {
                    ld.char_map_set(t.cc[VWERASE]);
                    ld.char_map_set(t.cc[VLNEXT]);
                    ld.char_map_set(t.cc[VEOL2]);
                    if t.lflag & ECHO != 0 {
                        ld.char_map_set(t.cc[VREPRINT]);
                    }
                }
            }
            if t.iflag & IXON != 0 {
                ld.char_map_set(t.cc[VSTART]);
                ld.char_map_set(t.cc[VSTOP]);
            }
            if t.lflag & ISIG != 0 {
                ld.char_map_set(t.cc[VINTR]);
                ld.char_map_set(t.cc[VQUIT]);
                ld.char_map_set(t.cc[VSUSP]);
            }
            ld.char_map[0] &= !1; // clear_bit(__DISABLED_CHAR)
            ld.raw = false;
            ld.real_raw = false;
        } else {
            ld.raw = true;
            // TTY_DRIVER_REAL_RAW is set by the serial driver.
            ld.real_raw = (t.iflag & IGNBRK != 0
                || (t.iflag & BRKINT == 0 && t.iflag & PARMRK == 0))
                && (t.iflag & IGNPAR != 0 || t.iflag & INPCK == 0);
        }
        // "Fix tty hang when IXON is cleared" while the tty was stopped by STOP.
        if t.iflag & IXON == 0 && old.is_some_and(|o| o.iflag & IXON != 0) && !self.flow_tco_stopped
        {
            self.start_tty(h);
            self.process_echoes(h);
        }
        // "The termios change make the tty ready for I/O".
        self.events = self.events.wrapping_add(1);
    }

    // ---- output ------------------------------------------------------------------

    /// `do_output_char`: -1 when the queue is full and the character must be retried.
    fn do_output_char(&mut self, h: &mut dyn Host, c: u8, space: usize) -> isize {
        if space == 0 {
            return -1;
        }
        let t = self.termios;
        let mut c = c;
        match c {
            b'\n' => {
                if t.oflag & ONLRET != 0 {
                    self.ld.column = 0;
                }
                if t.oflag & ONLCR != 0 {
                    if space < 2 {
                        return -1;
                    }
                    self.ld.canon_column = 0;
                    self.ld.column = 0;
                    self.uart_write(h, b"\r\n");
                    return 2;
                }
                self.ld.canon_column = self.ld.column;
            }
            b'\r' => {
                if t.oflag & ONOCR != 0 && self.ld.column == 0 {
                    return 0;
                }
                if t.oflag & OCRNL != 0 {
                    c = b'\n';
                    if t.oflag & ONLRET != 0 {
                        self.ld.canon_column = 0;
                        self.ld.column = 0;
                    }
                } else {
                    self.ld.canon_column = 0;
                    self.ld.column = 0;
                }
            }
            b'\t' => {
                // 1 to 8 columns to the next tab stop.
                let pad = u8::try_from(8 - (self.ld.column & 7)).unwrap_or(8);
                let spaces = usize::from(pad);
                if t.oflag & TABDLY == XTABS {
                    if space < spaces {
                        return -1;
                    }
                    self.ld.column += u32::from(pad);
                    self.uart_write(h, &b"        "[..spaces]);
                    return isize::from(pad);
                }
                self.ld.column += u32::from(pad);
            }
            0x08 => {
                if self.ld.column > 0 {
                    self.ld.column -= 1;
                }
            }
            _ => {
                if !iscntrl(c) {
                    if t.oflag & OLCUC != 0 {
                        c = c.to_ascii_uppercase();
                    }
                    if !is_continuation(c, &t) {
                        self.ld.column += 1;
                    }
                }
            }
        }
        self.tty_put_char(c);
        1
    }

    /// `process_output`: -1 when the character must be retried.
    fn process_output(&mut self, h: &mut dyn Host, c: u8) -> isize {
        let room = self.write_room();
        if self.do_output_char(h, c, room) < 0 {
            -1
        } else {
            0
        }
    }

    /// `process_output_block`: output a block of plain characters at once.
    fn process_output_block(&mut self, h: &mut dyn Host, buf: &[u8]) -> usize {
        let space = self.write_room();
        if space == 0 {
            return 0;
        }
        let nr = buf.len().min(space);
        let t = self.termios;
        let mut i = 0;
        while i < nr {
            let c = buf[i];
            match c {
                b'\n' => {
                    if t.oflag & ONLRET != 0 {
                        self.ld.column = 0;
                    }
                    if t.oflag & ONLCR != 0 {
                        break;
                    }
                    self.ld.canon_column = self.ld.column;
                }
                b'\r' => {
                    if t.oflag & ONOCR != 0 && self.ld.column == 0 {
                        break;
                    }
                    if t.oflag & OCRNL != 0 {
                        break;
                    }
                    self.ld.canon_column = 0;
                    self.ld.column = 0;
                }
                b'\t' => break,
                0x08 => {
                    if self.ld.column > 0 {
                        self.ld.column -= 1;
                    }
                }
                _ => {
                    if !iscntrl(c) {
                        if t.oflag & OLCUC != 0 {
                            break;
                        }
                        if !is_continuation(c, &t) {
                            self.ld.column += 1;
                        }
                    }
                }
            }
            i += 1;
        }
        self.uart_write(h, &buf[..i])
    }

    /// `n_tty_process_echo_ops`: `Err(true)` is `-ENODATA` (not stored yet),
    /// `Err(false)` is `-ENOSPC`.
    fn n_tty_process_echo_ops(
        &mut self,
        tail: &mut usize,
        mut space: usize,
    ) -> Result<usize, bool> {
        if self.ld.echo_commit & MASK_BITS == (*tail + 1) & MASK_BITS {
            return Err(true);
        }
        let op = self.ld.ebuf(*tail + 1);
        match op {
            ECHO_OP_ERASE_TAB => {
                if self.ld.echo_commit & MASK_BITS == (*tail + 2) & MASK_BITS {
                    return Err(true);
                }
                let mut num_chars = u32::from(self.ld.ebuf(*tail + 2));
                if num_chars & 0x80 == 0 {
                    num_chars += self.ld.canon_column;
                }
                let num_bs = 8 - (num_chars & 7) as usize;
                if num_bs > space {
                    return Err(false);
                }
                space -= num_bs;
                for _ in 0..num_bs {
                    self.tty_put_char(0x08);
                    if self.ld.column > 0 {
                        self.ld.column -= 1;
                    }
                }
                *tail += 3;
            }
            ECHO_OP_SET_CANON_COL => {
                self.ld.canon_column = self.ld.column;
                *tail += 2;
            }
            ECHO_OP_MOVE_BACK_COL => {
                if self.ld.column > 0 {
                    self.ld.column -= 1;
                }
                *tail += 2;
            }
            ECHO_OP_START => {
                if space == 0 {
                    return Err(false);
                }
                self.tty_put_char(ECHO_OP_START);
                self.ld.column += 1;
                space -= 1;
                *tail += 2;
            }
            _ => {
                // A control character tagged to be echoed as `^X`.
                if space < 2 {
                    return Err(false);
                }
                self.tty_put_char(b'^');
                self.tty_put_char(op ^ 0o100);
                self.ld.column += 2;
                space -= 2;
                *tail += 2;
            }
        }
        Ok(space)
    }

    /// `__process_echoes`: returns the space it used.
    fn __process_echoes(&mut self, h: &mut dyn Host) -> usize {
        let old_space = self.write_room();
        let mut space = old_space;
        let mut tail = self.ld.echo_tail;
        'outer: while self.ld.echo_commit & MASK_BITS != tail & MASK_BITS {
            let c = self.ld.ebuf(tail);
            if c == ECHO_OP_START {
                match self.n_tty_process_echo_ops(&mut tail, space) {
                    Err(true) => {
                        self.ld.echo_tail = tail;
                        return old_space - space;
                    }
                    Err(false) => break 'outer,
                    Ok(left) => space = left,
                }
            } else {
                if self.termios.oflag & OPOST != 0 {
                    let used = self.do_output_char(h, c, space);
                    if used < 0 {
                        break;
                    }
                    space -= used.cast_unsigned();
                } else {
                    if space == 0 {
                        break;
                    }
                    self.tty_put_char(c);
                    space -= 1;
                }
                tail += 1;
            }
        }
        // Discard enough at the tail to prevent a subsequent echo overrun.
        while self.ld.echo_commit > tail && self.ld.echo_commit - tail >= ECHO_DISCARD_WATERMARK {
            if self.ld.ebuf(tail) == ECHO_OP_START {
                if self.ld.ebuf(tail + 1) == ECHO_OP_ERASE_TAB {
                    tail += 3;
                } else {
                    tail += 2;
                }
            } else {
                tail += 1;
            }
        }
        self.ld.echo_tail = tail;
        old_space - space
    }

    /// `commit_echoes`.
    fn commit_echoes(&mut self, h: &mut dyn Host) {
        let head = self.ld.echo_head;
        self.ld.echo_mark = head;
        let old = self.ld.echo_commit.wrapping_sub(self.ld.echo_tail);
        let nr = head.wrapping_sub(self.ld.echo_tail);
        if nr < ECHO_COMMIT_WATERMARK || (nr % ECHO_BLOCK > old % ECHO_BLOCK) {
            return;
        }
        self.ld.echo_commit = head;
        let echoed = self.__process_echoes(h);
        if echoed > 0 {
            self.uart_start(h);
        }
    }

    /// `process_echoes`.
    pub(super) fn process_echoes(&mut self, h: &mut dyn Host) {
        if self.ld.echo_mark == self.ld.echo_tail {
            return;
        }
        self.ld.echo_commit = self.ld.echo_mark;
        let echoed = self.__process_echoes(h);
        if echoed > 0 {
            self.uart_start(h);
        }
    }

    /// `flush_echoes`.
    fn flush_echoes(&mut self, h: &mut dyn Host) {
        let t = self.termios;
        if (t.lflag & ECHO == 0 && t.lflag & ECHONL == 0)
            || self.ld.echo_commit == self.ld.echo_head
        {
            return;
        }
        self.ld.echo_commit = self.ld.echo_head;
        self.__process_echoes(h);
    }

    // ---- input -------------------------------------------------------------------

    /// `eraser`.
    #[allow(
        clippy::too_many_lines,
        reason = "follows `eraser` of n_tty.c step by step"
    )]
    fn eraser(&mut self, c: u8) {
        let t = self.termios;
        if self.ld.read_head == self.ld.canon_head {
            return;
        }
        let kill_type = if c == t.cc[VERASE] {
            EraseKind::Erase
        } else if c == t.cc[super::termios::VWERASE] {
            EraseKind::Werase
        } else {
            if t.lflag & ECHO == 0 {
                self.ld.read_head = self.ld.canon_head;
                return;
            }
            if t.lflag & ECHOK == 0 || t.lflag & ECHOKE == 0 || t.lflag & ECHOE == 0 {
                self.ld.read_head = self.ld.canon_head;
                self.ld.finish_erasing();
                self.ld.echo_char(t.cc[VKILL], &t);
                if t.lflag & ECHOK != 0 {
                    self.ld.echo_char_raw(b'\n');
                }
                return;
            }
            EraseKind::Line
        };
        let mut seen_alnums = 0;
        while self.ld.read_head & MASK_BITS != self.ld.canon_head & MASK_BITS {
            let mut head = self.ld.read_head;
            let mut ch;
            // Erase a single possibly multibyte character.
            loop {
                head = head.wrapping_sub(1);
                ch = self.ld.rbuf(head);
                if !(is_continuation(ch, &t) && head & MASK_BITS != self.ld.canon_head & MASK_BITS)
                {
                    break;
                }
            }
            // Do not partially erase.
            if is_continuation(ch, &t) {
                break;
            }
            if kill_type == EraseKind::Werase {
                // Equivalent to BSD's ALTWERASE.
                if isalnum(ch) || ch == b'_' {
                    seen_alnums += 1;
                } else if seen_alnums > 0 {
                    break;
                }
            }
            let mut cnt = self.ld.read_head.wrapping_sub(head);
            self.ld.read_head = head;
            if t.lflag & ECHO != 0 {
                if t.lflag & ECHOPRT != 0 {
                    if !self.ld.erasing {
                        self.ld.echo_char_raw(b'\\');
                        self.ld.erasing = true;
                    }
                    // If cnt > 1, output a multi-byte character.
                    self.ld.echo_char(ch, &t);
                    cnt -= 1;
                    while cnt > 0 {
                        head = head.wrapping_add(1);
                        let byte = self.ld.rbuf(head);
                        self.ld.echo_char_raw(byte);
                        self.ld.echo_move_back_col();
                        cnt -= 1;
                    }
                } else if kill_type == EraseKind::Erase && t.lflag & ECHOE == 0 {
                    self.ld.echo_char(t.cc[VERASE], &t);
                } else if ch == b'\t' {
                    let mut num_chars: u32 = 0;
                    let mut after_tab = false;
                    let mut tail = self.ld.read_head;
                    // Count the columns used for characters since the start of
                    // input or after a previous tab.
                    while tail & MASK_BITS != self.ld.canon_head & MASK_BITS {
                        tail = tail.wrapping_sub(1);
                        let prev = self.ld.rbuf(tail);
                        if prev == b'\t' {
                            after_tab = true;
                            break;
                        } else if iscntrl(prev) {
                            if t.lflag & ECHOCTL != 0 {
                                num_chars += 2;
                            }
                        } else if !is_continuation(prev, &t) {
                            num_chars += 1;
                        }
                    }
                    self.ld.echo_erase_tab(num_chars, after_tab);
                } else {
                    if iscntrl(ch) && t.lflag & ECHOCTL != 0 {
                        self.ld.echo_char_raw(0x08);
                        self.ld.echo_char_raw(b' ');
                        self.ld.echo_char_raw(0x08);
                    }
                    if !iscntrl(ch) || t.lflag & ECHOCTL != 0 {
                        self.ld.echo_char_raw(0x08);
                        self.ld.echo_char_raw(b' ');
                        self.ld.echo_char_raw(0x08);
                    }
                }
            }
            if kill_type == EraseKind::Erase {
                break;
            }
        }
        if self.ld.read_head == self.ld.canon_head && t.lflag & ECHO != 0 {
            self.ld.finish_erasing();
        }
    }

    /// `__isig` + `isig`.
    fn isig(&mut self, h: &mut dyn Host, sig: u8) {
        if let Some(pgrp) = self.ctrl.pgrp {
            h.kill_pgrp(pgrp, sig);
        }
        if self.termios.lflag & NOFLSH == 0 {
            // Clear the echo buffer, the output queue and the input buffer.
            self.ld.echo_head = 0;
            self.ld.echo_tail = 0;
            self.ld.echo_mark = 0;
            self.ld.echo_commit = 0;
            self.driver_flush_buffer();
            self.ld.reset_buffer_flags();
        }
    }

    /// `n_tty_receive_break`.
    fn receive_break(&mut self, h: &mut dyn Host) {
        let t = self.termios;
        if t.iflag & IGNBRK != 0 {
            return;
        }
        if t.iflag & BRKINT != 0 {
            self.isig(h, SIGINT);
            return;
        }
        if t.iflag & PARMRK != 0 {
            self.ld.put_tty_queue(0xff);
            self.ld.put_tty_queue(0);
        }
        self.ld.put_tty_queue(0);
    }

    /// `n_tty_receive_parity_error`.
    fn receive_parity_error(&mut self, c: u8) {
        let t = self.termios;
        if t.iflag & INPCK != 0 {
            if t.iflag & IGNPAR != 0 {
                return;
            }
            if t.iflag & PARMRK != 0 {
                self.ld.put_tty_queue(0xff);
                self.ld.put_tty_queue(0);
                self.ld.put_tty_queue(c);
            } else {
                self.ld.put_tty_queue(0);
            }
        } else {
            self.ld.put_tty_queue(c);
        }
    }

    /// `n_tty_receive_signal_char`.
    fn receive_signal_char(&mut self, h: &mut dyn Host, signal: u8, c: u8) {
        self.isig(h, signal);
        if self.termios.iflag & IXON != 0 {
            self.start_tty(h);
        }
        if self.termios.lflag & ECHO != 0 {
            let t = self.termios;
            self.ld.echo_char(c, &t);
            self.commit_echoes(h);
        } else {
            self.process_echoes(h);
        }
    }

    /// `n_tty_receive_char_flow_ctrl`.
    fn receive_char_flow_ctrl(&mut self, h: &mut dyn Host, c: u8, lookahead_done: bool) -> bool {
        let t = self.termios;
        if c != t.cc[VSTART] && c != t.cc[VSTOP] {
            return false;
        }
        if lookahead_done {
            return true;
        }
        if c == t.cc[VSTART] {
            self.start_tty(h);
            self.process_echoes(h);
            return true;
        }
        self.stop_tty();
        true
    }

    /// `n_tty_receive_handle_newline`.
    fn receive_handle_newline(&mut self, c: u8) {
        let ld = &mut self.ld;
        set_bit(&mut ld.read_flags, ld.read_head & MASK_BITS);
        ld.put_tty_queue(c);
        ld.canon_head = ld.read_head;
        self.events = self.events.wrapping_add(1);
    }

    /// `n_tty_receive_char_canon`.
    fn receive_char_canon(&mut self, h: &mut dyn Host, c: u8) -> bool {
        let t = self.termios;
        if c == t.cc[VERASE]
            || c == t.cc[VKILL]
            || (c == t.cc[super::termios::VWERASE] && t.lflag & IEXTEN != 0)
        {
            self.eraser(c);
            self.commit_echoes(h);
            return true;
        }
        if c == t.cc[VLNEXT] && t.lflag & IEXTEN != 0 {
            self.ld.lnext = true;
            if t.lflag & ECHO != 0 {
                self.ld.finish_erasing();
                if t.lflag & ECHOCTL != 0 {
                    self.ld.echo_char_raw(b'^');
                    self.ld.echo_char_raw(0x08);
                    self.commit_echoes(h);
                }
            }
            return true;
        }
        if c == t.cc[VREPRINT] && t.lflag & ECHO != 0 && t.lflag & IEXTEN != 0 {
            let mut tail = self.ld.canon_head;
            self.ld.finish_erasing();
            self.ld.echo_char(c, &t);
            self.ld.echo_char_raw(b'\n');
            while tail & MASK_BITS != self.ld.read_head & MASK_BITS {
                let byte = self.ld.rbuf(tail);
                self.ld.echo_char(byte, &t);
                tail = tail.wrapping_add(1);
            }
            self.commit_echoes(h);
            return true;
        }
        if c == b'\n' {
            if t.lflag & (ECHO | ECHONL) != 0 {
                self.ld.echo_char_raw(b'\n');
                self.commit_echoes(h);
            }
            self.receive_handle_newline(c);
            return true;
        }
        if c == t.cc[VEOF] {
            self.receive_handle_newline(DISABLED_CHAR);
            return true;
        }
        if c == t.cc[VEOL] || (c == t.cc[VEOL2] && t.lflag & IEXTEN != 0) {
            if t.lflag & ECHO != 0 {
                // Record the column of first canon char.
                if self.ld.canon_head == self.ld.read_head {
                    self.ld.echo_set_canon_col();
                }
                self.ld.echo_char(c, &t);
                self.commit_echoes(h);
            }
            if c == 0xff && t.iflag & PARMRK != 0 {
                self.ld.put_tty_queue(c);
            }
            self.receive_handle_newline(c);
            return true;
        }
        false
    }

    /// `n_tty_receive_char_special`.
    fn receive_char_special(&mut self, h: &mut dyn Host, c: u8, lookahead_done: bool) {
        let t = self.termios;
        let mut c = c;
        if t.iflag & IXON != 0 && self.receive_char_flow_ctrl(h, c, lookahead_done) {
            return;
        }
        if t.lflag & ISIG != 0 {
            if c == t.cc[VINTR] {
                self.receive_signal_char(h, SIGINT, c);
                return;
            } else if c == t.cc[VQUIT] {
                self.receive_signal_char(h, SIGQUIT, c);
                return;
            } else if c == t.cc[VSUSP] {
                self.receive_signal_char(h, SIGTSTP, c);
                return;
            }
        }
        if self.flow_stopped
            && !self.flow_tco_stopped
            && t.iflag & IXON != 0
            && t.iflag & IXANY != 0
        {
            self.start_tty(h);
            self.process_echoes(h);
        }
        if c == b'\r' {
            if t.iflag & IGNCR != 0 {
                return;
            }
            if t.iflag & ICRNL != 0 {
                c = b'\n';
            }
        } else if c == b'\n' && t.iflag & INLCR != 0 {
            c = b'\r';
        }
        if self.ld.icanon && self.receive_char_canon(h, c) {
            return;
        }
        if t.lflag & ECHO != 0 {
            self.ld.finish_erasing();
            if c == b'\n' {
                self.ld.echo_char_raw(b'\n');
            } else {
                // Record the column of first canon char.
                if self.ld.canon_head == self.ld.read_head {
                    self.ld.echo_set_canon_col();
                }
                self.ld.echo_char(c, &t);
            }
            self.commit_echoes(h);
        }
        // PARMRK doubling check.
        if c == 0xff && t.iflag & PARMRK != 0 {
            self.ld.put_tty_queue(c);
        }
        self.ld.put_tty_queue(c);
    }

    /// `n_tty_receive_char`.
    fn receive_char(&mut self, h: &mut dyn Host, c: u8) {
        let t = self.termios;
        if self.flow_stopped
            && !self.flow_tco_stopped
            && t.iflag & IXON != 0
            && t.iflag & IXANY != 0
        {
            self.start_tty(h);
            self.process_echoes(h);
        }
        if t.lflag & ECHO != 0 {
            self.ld.finish_erasing();
            // Record the column of first canon char.
            if self.ld.canon_head == self.ld.read_head {
                self.ld.echo_set_canon_col();
            }
            self.ld.echo_char(c, &t);
            self.commit_echoes(h);
        }
        // PARMRK doubling check.
        if c == 0xff && t.iflag & PARMRK != 0 {
            self.ld.put_tty_queue(c);
        }
        self.ld.put_tty_queue(c);
    }

    fn receive_char_flagged(&mut self, h: &mut dyn Host, c: u8, flag: u8) {
        match flag {
            TTY_BREAK => self.receive_break(h),
            TTY_PARITY | TTY_FRAME => self.receive_parity_error(c),
            // TTY_OVERRUN is only counted; an unknown flag is logged by Linux.
            _ => {}
        }
    }

    fn receive_char_lnext(&mut self, h: &mut dyn Host, c: u8, flag: u8) {
        let t = self.termios;
        self.ld.lnext = false;
        if flag == TTY_NORMAL {
            let mut c = c;
            if t.iflag & ISTRIP != 0 {
                c &= 0x7f;
            }
            if t.iflag & IUCLC != 0 && t.lflag & IEXTEN != 0 {
                c = c.to_ascii_lowercase();
            }
            self.receive_char(h, c);
        } else {
            self.receive_char_flagged(h, c, flag);
        }
    }

    fn receive_buf_real_raw(&mut self, cp: &[u8]) {
        for &c in cp {
            self.ld.put_tty_queue(c);
        }
    }

    fn receive_buf_raw(&mut self, h: &mut dyn Host, cp: &[u8], fp: Option<&[u8]>) {
        for (i, &c) in cp.iter().enumerate() {
            let flag = fp.map_or(TTY_NORMAL, |f| f[i]);
            if flag == TTY_NORMAL {
                self.ld.put_tty_queue(c);
            } else {
                self.receive_char_flagged(h, c, flag);
            }
        }
    }

    fn receive_buf_standard(
        &mut self,
        h: &mut dyn Host,
        cp: &[u8],
        fp: Option<&[u8]>,
        lookahead_done: bool,
    ) {
        for (i, &c0) in cp.iter().enumerate() {
            let mut c = c0;
            let flag = fp.map_or(TTY_NORMAL, |f| f[i]);
            if self.ld.lnext {
                self.receive_char_lnext(h, c, flag);
                continue;
            }
            if flag != TTY_NORMAL {
                self.receive_char_flagged(h, c, flag);
                continue;
            }
            let t = self.termios;
            if t.iflag & ISTRIP != 0 {
                c &= 0x7f;
            }
            if t.iflag & IUCLC != 0 && t.lflag & IEXTEN != 0 {
                c = c.to_ascii_lowercase();
            }
            if t.lflag & EXTPROC != 0 {
                self.ld.put_tty_queue(c);
                continue;
            }
            if self.ld.char_map_test(c) {
                self.receive_char_special(h, c, lookahead_done);
            } else {
                self.receive_char(h, c);
            }
        }
    }

    /// `__receive_buf`.
    fn __receive_buf(&mut self, h: &mut dyn Host, cp: &[u8], fp: Option<&[u8]>) {
        let t = self.termios;
        let preops = t.iflag & ISTRIP != 0 || (t.iflag & IUCLC != 0 && t.lflag & IEXTEN != 0);
        let la_count = self.ld.lookahead_count.min(cp.len());
        if self.ld.real_raw {
            self.receive_buf_real_raw(cp);
        } else if self.ld.raw || (t.lflag & EXTPROC != 0 && !preops) {
            self.receive_buf_raw(h, cp, fp);
        } else {
            // (The `tty->closing` branch needs a tty being closed.)
            if la_count > 0 {
                self.receive_buf_standard(h, &cp[..la_count], fp.map(|f| &f[..la_count]), true);
            }
            if cp.len() > la_count {
                self.receive_buf_standard(h, &cp[la_count..], fp.map(|f| &f[la_count..]), false);
            }
            self.flush_echoes(h);
            self.uart_start(h);
        }
        self.ld.lookahead_count -= la_count;
        if self.ld.icanon && t.lflag & EXTPROC == 0 {
            return;
        }
        // Publish read_head to the consumer.
        self.ld.commit_head = self.ld.read_head;
        if self.ld.read_cnt() > 0 {
            self.events = self.events.wrapping_add(1);
        }
    }

    /// `n_tty_receive_buf2` (`n_tty_receive_buf_common` with flow control):
    /// process input; returns how many bytes of `cp` were taken.
    pub fn receive_buf(&mut self, h: &mut dyn Host, cp: &[u8], fp: Option<&[u8]>) -> usize {
        self.receive_buf_common(h, cp, fp, true)
    }

    /// `n_tty_lookahead_flow_ctrl` (the ldisc `lookahead_buf` method): the flip
    /// buffer calls it for input the discipline had no room for, so `^S`/`^Q`
    /// (IXON) take effect before the buffered bytes are read. `cp` must not be
    /// empty; the bytes are counted so the normal receive skips their flow
    /// control (`__receive_buf`).
    pub fn lookahead_flow_ctrl(&mut self, h: &mut dyn Host, cp: &[u8], fp: Option<&[u8]>) {
        self.ld.lookahead_count += cp.len();
        if self.termios.iflag & IXON == 0 {
            return;
        }
        for (i, &c) in cp.iter().enumerate() {
            if fp.is_none_or(|f| f[i] == TTY_NORMAL) {
                self.receive_char_flow_ctrl(h, c, false);
            }
        }
    }

    /// `n_tty_receive_buf` (no flow control: `TIOCSTI`, the ldisc `receive_buf`
    /// method).
    pub fn receive_buf_noflow(&mut self, h: &mut dyn Host, cp: &[u8], fp: Option<&[u8]>) -> usize {
        self.receive_buf_common(h, cp, fp, false)
    }

    fn receive_buf_common(
        &mut self,
        h: &mut dyn Host,
        cp: &[u8],
        fp: Option<&[u8]>,
        flow: bool,
    ) -> usize {
        let t = self.termios;
        let mut rcvd = 0;
        let mut cp = cp;
        let mut fp = fp;
        let mut room;
        let mut overflow;
        loop {
            let tail = self.ld.read_tail;
            let cnt = self.ld.read_head.wrapping_sub(tail);
            // `room` is signed in C: it can be negative when the buffer holds more
            // than N_TTY_BUF_SIZE bytes (a canonical line was switched to raw).
            let mut r = N_TTY_BUF_SIZE.cast_signed() - cnt.cast_signed();
            if t.iflag & PARMRK != 0 {
                r = (r + 2) / 3;
            }
            r -= 1;
            if r <= 0 {
                overflow = self.ld.icanon && self.ld.canon_head == tail;
                if overflow && r < 0 {
                    self.ld.read_head = self.ld.read_head.wrapping_sub(1);
                }
                r = isize::from(overflow);
                self.ld.no_room = flow && !overflow;
            } else {
                overflow = false;
            }
            room = r;
            let n = cp.len().min(r.max(0).cast_unsigned());
            if n == 0 {
                break;
            }
            // Ignore parity errors if handling overflow.
            if !overflow || fp.is_none_or(|f| f[0] != TTY_PARITY) {
                self.__receive_buf(h, &cp[..n], fp.map(|f| &f[..n]));
            }
            cp = &cp[n..];
            fp = fp.map(|f| &f[n..]);
            rcvd += n;
        }
        let _ = room;
        self.n_tty_check_throttle(h);
        if self.ld.no_room && self.chars_in_ldisc() == 0 {
            self.n_tty_kick_worker(h);
        }
        rcvd
    }

    /// `n_tty_check_throttle`.
    fn n_tty_check_throttle(&mut self, h: &mut dyn Host) {
        // In canonical mode with no newline yet the driver must not be throttled.
        if self.ld.icanon && self.ld.canon_head == self.ld.read_tail {
            return;
        }
        if N_TTY_BUF_SIZE - self.ld.read_cnt() >= TTY_THRESHOLD_THROTTLE {
            return;
        }
        if !self.throttled {
            self.throttled = true;
            self.throttle(h);
        }
    }

    /// `n_tty_check_unthrottle`.
    fn n_tty_check_unthrottle(&mut self, h: &mut dyn Host) {
        if self.chars_in_ldisc() > TTY_THRESHOLD_UNTHROTTLE {
            return;
        }
        self.n_tty_kick_worker(h);
        self.tty_unthrottle(h);
    }

    /// `chars_in_buffer` of the line discipline.
    fn chars_in_ldisc(&self) -> usize {
        let head = if self.ld.icanon {
            self.ld.canon_head
        } else {
            self.ld.commit_head
        };
        head.wrapping_sub(self.ld.read_tail)
    }

    // ---- read --------------------------------------------------------------------

    /// `input_available_p`.
    #[must_use]
    pub fn input_available(&self, poll: bool) -> bool {
        let t = &self.termios;
        let amt = if poll && t.cc[VTIME] == 0 && t.cc[VMIN] != 0 {
            usize::from(t.cc[VMIN])
        } else {
            1
        };
        if self.ld.icanon && t.lflag & EXTPROC == 0 {
            self.ld.canon_head != self.ld.read_tail
        } else {
            self.ld.commit_head.wrapping_sub(self.ld.read_tail) >= amt
        }
    }

    /// `zero_buffer`: a secret that is not echoed is erased once read.
    fn zero_buffer(&mut self, from: usize, n: usize) {
        if self.termios.lflag & ICANON != 0 && self.termios.lflag & ECHO == 0 {
            for i in 0..n {
                self.ld.read_buf[(from + i) & MASK_BITS] = 0;
            }
        }
    }

    /// `copy_from_read_buf`: true if data was copied and more remains.
    fn copy_from_read_buf(&mut self, kbuf: &mut [u8], kb: &mut usize, nr: &mut usize) -> bool {
        let head = self.ld.commit_head;
        let tail = self.ld.read_tail & MASK_BITS;
        let n = head
            .wrapping_sub(self.ld.read_tail)
            .min(N_TTY_BUF_SIZE - tail)
            .min(*nr);
        if n == 0 {
            return false;
        }
        kbuf[*kb..*kb + n].copy_from_slice(&self.ld.read_buf[tail..tail + n]);
        let is_eof = n == 1 && self.ld.read_buf[tail] == self.termios.cc[VEOF];
        self.zero_buffer(tail, n);
        self.ld.read_tail = self.ld.read_tail.wrapping_add(n);
        // Turn single EOF into zero-length read.
        if self.termios.lflag & EXTPROC != 0
            && self.ld.icanon
            && is_eof
            && head == self.ld.read_tail
        {
            return false;
        }
        *kb += n;
        *nr -= n;
        // If we have more to copy, let the caller know.
        head != self.ld.read_tail
    }

    /// `canon_copy_from_read_buf`: one line up to and including its delimiter.
    /// True when a continuation retry is useful.
    fn canon_copy_from_read_buf(
        &mut self,
        kbuf: &mut [u8],
        kb: &mut usize,
        nr: &mut usize,
    ) -> bool {
        if *nr == 0 {
            return false;
        }
        let canon_head = self.ld.canon_head;
        let n = (*nr).min(canon_head.wrapping_sub(self.ld.read_tail));
        let tail = self.ld.read_tail & MASK_BITS;
        let size = (tail + n).min(N_TTY_BUF_SIZE);
        let mut eol = find_next_bit(&self.ld.read_flags, size, tail);
        let more = n - (size - tail);
        let found = if eol == N_TTY_BUF_SIZE && more > 0 {
            // Scan wrapped without finding a set bit.
            eol = find_next_bit(&self.ld.read_flags, more, 0);
            eol != more
        } else {
            eol != size
        };
        let mut n = eol.wrapping_sub(tail);
        if n > N_TTY_BUF_SIZE {
            n = n.wrapping_add(N_TTY_BUF_SIZE);
        }
        let c = n + usize::from(found);
        if !found || self.ld.rbuf(eol) != DISABLED_CHAR {
            n = c;
        }
        // tty_copy
        for i in 0..n {
            kbuf[*kb + i] = self.ld.read_buf[(tail + i) & MASK_BITS];
        }
        self.zero_buffer(tail, n);
        *kb += n;
        *nr -= n;
        if found {
            clear_bit(&mut self.ld.read_flags, eol);
        }
        self.ld.read_tail = self.ld.read_tail.wrapping_add(c);
        if found {
            if self.ld.push {
                self.ld.push = false;
            } else {
                self.ld.line_start = self.ld.read_tail;
            }
            return false;
        }
        // No EOL found - do a continuation retry if there is more data.
        self.ld.read_tail != canon_head
    }

    /// `canon_skip_eof`.
    fn canon_skip_eof(&mut self) {
        let canon_head = self.ld.canon_head;
        let tail = self.ld.read_tail;
        if tail == canon_head {
            return;
        }
        let bit = tail & MASK_BITS;
        if !test_bit(&self.ld.read_flags, bit) || self.ld.rbuf(tail) != DISABLED_CHAR {
            return;
        }
        clear_bit(&mut self.ld.read_flags, bit);
        self.ld.read_tail = self.ld.read_tail.wrapping_add(1);
    }

    /// Start a read of up to `nr` (at most 64) bytes: `n_tty_read` after it took
    /// `atomic_read_lock` ([`Tty::read_try_lock`]) and up to the loop. The caller
    /// has done the job-control check.
    #[must_use]
    pub fn read_begin(&self, nr: usize) -> ReadOp {
        let t = &self.termios;
        let mut minimum = 0;
        let mut time_ms = 0;
        let mut timeout_ms = u64::MAX;
        if !self.ld.icanon {
            minimum = usize::from(t.cc[VMIN]);
            if minimum > 0 {
                time_ms = 100 * u64::from(t.cc[VTIME]);
            } else {
                timeout_ms = 100 * u64::from(t.cc[VTIME]);
                minimum = 1;
            }
        }
        ReadOp {
            minimum,
            time_ms,
            timeout_ms,
            old_tail: self.ld.read_tail,
            kb: 0,
            nr,
            started: false,
            holds: true,
        }
    }

    /// `mutex_trylock(&ldata->atomic_read_lock)` for `owner`: `false` when another
    /// reader owns it (`-EAGAIN` for `O_NONBLOCK`, else the caller sleeps).
    pub fn read_try_lock(&mut self, owner: crate::task::TaskId) -> bool {
        if self.read_owner.is_none() {
            self.read_owner = Some(owner);
            true
        } else {
            false
        }
    }

    fn read_unlock(&mut self, op: &mut ReadOp) {
        if op.holds {
            self.read_owner = None;
            op.holds = false;
            self.events = self.events.wrapping_add(1);
        }
    }

    /// `n_tty_continue_cookie`.
    pub fn read_continue(
        &mut self,
        h: &mut dyn Host,
        op: &mut ReadOp,
        kbuf: &mut [u8],
    ) -> ReadStep {
        let mut kb = 0;
        let mut nr = op.nr;
        if self.ld.icanon && self.termios.lflag & EXTPROC == 0 {
            // If we have filled the user buffer, see if we should skip an EOF
            // character before releasing the lock and returning done.
            if nr == 0 {
                self.canon_skip_eof();
            } else if self.canon_copy_from_read_buf(kbuf, &mut kb, &mut nr) {
                return ReadStep::Done {
                    len: kb,
                    more: true,
                };
            }
        } else if self.copy_from_read_buf(kbuf, &mut kb, &mut nr) {
            return ReadStep::Done {
                len: kb,
                more: true,
            };
        }
        // No more data - release locks and stop retries.
        self.n_tty_kick_worker(h);
        self.n_tty_check_unthrottle(h);
        self.read_unlock(op);
        ReadStep::Done {
            len: kb,
            more: false,
        }
    }

    /// `n_tty_wait_for_input`: `Some(step)` ends the read, `None` means "sleep".
    fn wait_for_input(&mut self, op: &mut ReadOp, env: ReadEnv) -> Option<(Option<Errno>, bool)> {
        if env.hung_up || self.hupping {
            return Some((None, false));
        }
        if op.timeout_ms == 0 {
            return Some((None, false));
        }
        if env.nonblock {
            return Some((Some(Errno::EAGAIN), false));
        }
        if env.signal_pending {
            return Some((None, true));
        }
        None
    }

    /// `n_tty_read`, from the top of its loop to its next sleep or return. Call
    /// again after waking with `op.timeout_ms` set to the time left.
    pub fn read_step(
        &mut self,
        h: &mut dyn Host,
        op: &mut ReadOp,
        kbuf: &mut [u8],
        env: &ReadEnv,
    ) -> ReadStep {
        op.started = true;
        let mut retval: (Option<Errno>, bool) = (None, false);
        while op.nr - op.kb > 0 {
            if !self.input_available(false) {
                match self.wait_for_input(op, *env) {
                    Some(result) => {
                        retval = result;
                        break;
                    }
                    None => {
                        return ReadStep::Sleep {
                            ms: if op.timeout_ms == u64::MAX {
                                None
                            } else {
                                Some(op.timeout_ms)
                            },
                        };
                    }
                }
            }
            let mut nr = op.nr - op.kb;
            let mut kb = op.kb;
            if self.ld.icanon && self.termios.lflag & EXTPROC == 0 {
                let more = self.canon_copy_from_read_buf(kbuf, &mut kb, &mut nr);
                op.kb = kb;
                if more {
                    return Self::read_more(op);
                }
            } else {
                let more = self.copy_from_read_buf(kbuf, &mut kb, &mut nr);
                op.kb = kb;
                if more && op.kb >= op.minimum {
                    return Self::read_more(op);
                }
            }
            self.n_tty_check_unthrottle(h);
            if op.kb >= op.minimum {
                break;
            }
            if op.time_ms != 0 {
                op.timeout_ms = op.time_ms;
            }
        }
        if op.old_tail != self.ld.read_tail {
            self.n_tty_kick_worker(h);
        }
        self.read_unlock(op);
        if op.kb > 0 {
            return ReadStep::Done {
                len: op.kb,
                more: false,
            };
        }
        match retval {
            // Nothing read and nothing wrong: end of file, or a timeout.
            (None, false) => ReadStep::Done {
                len: 0,
                more: false,
            },
            (errno, restart) => ReadStep::Error { errno, restart },
        }
    }

    /// `more_to_be_read`: return with the lock held.
    fn read_more(op: &ReadOp) -> ReadStep {
        ReadStep::Done {
            len: op.kb,
            more: true,
        }
    }

    // ---- write -------------------------------------------------------------------

    /// The start of `n_tty_write`: pending echo characters go out first.
    pub fn write_begin(&mut self, h: &mut dyn Host) {
        self.process_echoes(h);
    }

    /// One pass of the loop in `n_tty_write` over `buf`: output what fits.
    pub fn write_pass(&mut self, h: &mut dyn Host, buf: &[u8]) -> WritePass {
        let mut b = 0;
        if self.termios.oflag & OPOST != 0 {
            while b < buf.len() {
                let num = self.process_output_block(h, &buf[b..]);
                b += num;
                if b == buf.len() {
                    break;
                }
                if self.process_output(h, buf[b]) < 0 {
                    break;
                }
                b += 1;
            }
            self.uart_start(h);
        } else {
            while b < buf.len() {
                let num = self.uart_write(h, &buf[b..]);
                if num == 0 {
                    break;
                }
                b += num;
            }
        }
        WritePass { consumed: b }
    }

    // ---- poll / ioctl ------------------------------------------------------------

    /// `n_tty_poll`: the readiness mask (`POLLIN | POLLRDNORM`, `POLLHUP`, `POLLOUT
    /// | POLLWRNORM`); `hung_up` is `tty_hung_up_p(file)`, `write_locked`
    /// `tty_is_writelocked`.
    #[must_use]
    pub fn poll_mask(&self, hung_up: bool) -> u16 {
        const POLLIN: u16 = 0x1;
        const POLLOUT: u16 = 0x4;
        const POLLHUP: u16 = 0x10;
        const POLLRDNORM: u16 = 0x40;
        const POLLWRNORM: u16 = 0x100;
        let mut mask = 0;
        if self.input_available(true) {
            mask |= POLLIN | POLLRDNORM;
        }
        if hung_up {
            mask |= POLLHUP;
        }
        if self.write_owner.is_none()
            && self.chars_in_buffer() < WAKEUP_CHARS
            && self.write_room() > 0
        {
            mask |= POLLOUT | POLLWRNORM;
        }
        mask
    }

    /// `inq_canon`: the bytes of the current line available to `read`.
    fn inq_canon(&self) -> usize {
        if self.ld.canon_head == self.ld.read_tail {
            return 0;
        }
        let head = self.ld.canon_head;
        let mut tail = self.ld.read_tail;
        let mut nr = head.wrapping_sub(tail);
        // Skip EOF characters.
        while head & MASK_BITS != tail & MASK_BITS {
            if test_bit(&self.ld.read_flags, tail & MASK_BITS)
                && self.ld.rbuf(tail) == DISABLED_CHAR
            {
                nr -= 1;
            }
            tail = tail.wrapping_add(1);
        }
        nr
    }

    /// `TIOCINQ` (`FIONREAD`) of `n_tty_ioctl`.
    #[must_use]
    pub fn tiocinq(&self) -> u32 {
        let n = if self.termios.lflag & ICANON != 0 && self.termios.lflag & EXTPROC == 0 {
            self.inq_canon()
        } else {
            self.ld.read_cnt()
        };
        u32::try_from(n).unwrap_or(u32::MAX)
    }

    /// `tty_set_termios` for the already-merged `new` termios.
    pub fn set_termios(&mut self, h: &mut dyn Host, new: &Ktermios) {
        let old = self.termios;
        self.termios = *new;
        // `unset_locked_termios`: bits `TIOCSLCKTRMIOS` locked keep their value.
        let locked = self.termios_locked;
        let noset = |x: u32, y: u32, z: u32| (x & !z) | (y & z);
        self.termios.iflag = noset(self.termios.iflag, old.iflag, locked.iflag);
        self.termios.oflag = noset(self.termios.oflag, old.oflag, locked.oflag);
        self.termios.cflag = noset(self.termios.cflag, old.cflag, locked.cflag);
        self.termios.lflag = noset(self.termios.lflag, old.lflag, locked.lflag);
        if locked.line != 0 {
            self.termios.line = old.line;
        }
        for i in 0..self.termios.cc.len() {
            if locked.cc[i] != 0 {
                self.termios.cc[i] = old.cc[i];
            }
        }
        // Reset any ADDRB changes: ADDRB is changed through rs485_config.
        self.termios.cflag ^= (self.termios.cflag ^ old.cflag) & super::termios::ADDRB;
        // `uart_set_termios`.
        super::termios::uart_set_termios(&mut self.termios, &old);
        self.n_tty_set_termios(Some(&old), h);
    }

    /// `tty_change_softcar` (`TIOCSSOFTCAR`): set or clear `CLOCAL`.
    ///
    /// # Errors
    /// `EINVAL` when the driver left the bit as it was.
    pub fn change_softcar(&mut self, enable: bool) -> Result<(), Errno> {
        use super::termios::{CLOCAL, uart_set_termios};
        let old = self.termios;
        self.termios.cflag &= !CLOCAL;
        if enable {
            self.termios.cflag |= CLOCAL;
        }
        uart_set_termios(&mut self.termios, &old);
        if (self.termios.cflag & CLOCAL != 0) == enable {
            Ok(())
        } else {
            Err(Errno::EINVAL)
        }
    }

    /// `__tty_perform_flush` (`TCFLSH`): `Err` is `-EINVAL`.
    ///
    /// # Errors
    /// `EINVAL` for an unknown queue selector.
    pub fn perform_flush(&mut self, h: &mut dyn Host, arg: u64) -> Result<(), Errno> {
        match arg {
            0 => {
                self.n_tty_flush_buffer(h);
                self.tty_unthrottle(h);
            }
            1 => self.driver_flush_buffer(),
            2 => {
                self.n_tty_flush_buffer(h);
                self.tty_unthrottle(h);
                self.driver_flush_buffer();
            }
            _ => return Err(Errno::EINVAL),
        }
        Ok(())
    }

    /// `tty_ldisc_hangup` with `reinit`: flush the input and the queue, wake
    /// everyone and start the discipline afresh.
    pub(super) fn ldisc_hangup(&mut self, h: &mut dyn Host, reinit: bool) {
        self.n_tty_flush_buffer(h);
        self.driver_flush_buffer();
        self.events = self.events.wrapping_add(1);
        if reinit {
            self.ldisc_reinit(h);
        }
    }

    /// `n_tty_ioctl`'s `TIOCOUTQ`.
    #[must_use]
    pub fn tiocoutq(&self) -> u32 {
        u32::try_from(self.chars_in_buffer()).unwrap_or(u32::MAX)
    }

    /// Whether `TOSTOP` is set (`L_TOSTOP`).
    #[must_use]
    pub fn tostop(&self) -> bool {
        self.termios.lflag & TOSTOP != 0
    }
}
