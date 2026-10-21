// SPDX-License-Identifier: GPL-2.0-only
//! Host tests of the `N_TTY` port: input processing, echo, output processing,
//! reads in both modes and flow control. The expectations are what the pinned
//! `n_tty.c` produces for the same bytes (the differential runs in `docs/
//! implementation.md#the-console-tty` check the same cases against the real thing).

extern crate std;

use super::{
    Host, Tty,
    ldisc::{ReadEnv, ReadStep, TTY_BREAK},
    termios::{
        BRKINT, ECHO, ECHOCTL, ECHOE, ECHOK, ECHOKE, ECHONL, ICANON, ICRNL, IEXTEN, IGNCR, INLCR,
        ISIG, IXON, NOFLSH, OCRNL, ONLCR, OPOST, VEOF, VERASE, VINTR, VKILL, VMIN, VTIME, XTABS,
    },
};
use crate::task::pid::PidRef;
use std::vec::Vec;

#[derive(Default)]
struct Fake {
    wire: Vec<u8>,
    signals: Vec<u8>,
}
impl Host for Fake {
    fn kill_pgrp(&mut self, _pgrp: PidRef, sig: u8) {
        self.signals.push(sig);
    }
    fn transmit(&mut self, bytes: &[u8]) {
        self.wire.extend_from_slice(bytes);
    }
}

/// A tty with a foreground group (so `isig` has someone to signal).
fn tty() -> (Tty, Fake) {
    let mut tty = Tty::new().expect("tty");
    let mut host = Fake::default();
    tty.ctrl.pgrp = Some(pgrp());
    // The cooked defaults of the serial console.
    assert!(tty.termios.lflag & ICANON != 0);
    host.wire.clear();
    (tty, host)
}

fn pgrp() -> PidRef {
    use crate::{arena::Id, task::pid::Pid};
    let mut arena = crate::arena::Arena::<Pid>::new();
    let id: Id<Pid> = arena.try_insert(Pid::new(7)).unwrap();
    PidRef { id, nr: 7 }
}

fn feed(tty: &mut Tty, host: &mut Fake, bytes: &[u8]) {
    let mut rest = bytes;
    while !rest.is_empty() {
        let n = tty.receive_buf(host, rest, None);
        assert!(n > 0, "input stalled");
        rest = &rest[n..];
    }
}

fn read_all(tty: &mut Tty, host: &mut Fake, nonblock: bool) -> Vec<u8> {
    let env = ReadEnv {
        nonblock,
        hung_up: false,
        signal_pending: false,
    };
    let mut out = Vec::new();
    loop {
        let mut op = tty.read_begin(64);
        let mut buf = [0u8; 64];
        let mut step = tty.read_step(host, &mut op, &mut buf, &env);
        loop {
            match step {
                ReadStep::Done { len, more } => {
                    out.extend_from_slice(&buf[..len]);
                    if more {
                        step = tty.read_continue(host, &mut op, &mut buf);
                        continue;
                    }
                    if len == 0 {
                        return out;
                    }
                    break;
                }
                ReadStep::Error { .. } | ReadStep::Sleep { .. } => return out,
            }
        }
        if !tty.input_available(false) {
            return out;
        }
    }
}

#[test]
fn canonical_line_is_delivered_after_newline_and_echoed() {
    let (mut tty, mut host) = tty();
    feed(&mut tty, &mut host, b"abc");
    assert_eq!(host.wire, b"abc");
    assert!(!tty.input_available(false), "no line yet");
    feed(&mut tty, &mut host, b"\r");
    assert_eq!(host.wire, b"abc\r\n");
    assert_eq!(read_all(&mut tty, &mut host, true), b"abc\n");
}

#[test]
fn erase_kill_and_werase() {
    let (mut tty, mut host) = tty();
    feed(&mut tty, &mut host, b"abcd\x7f\x7f");
    assert_eq!(host.wire, b"abcd\x08 \x08\x08 \x08");
    host.wire.clear();
    feed(&mut tty, &mut host, b"\x15");
    // ECHOKE|ECHOE|ECHOK: the line is erased character by character.
    assert_eq!(host.wire, b"\x08 \x08\x08 \x08");
    host.wire.clear();
    feed(&mut tty, &mut host, b"foo bar\x17\n");
    assert_eq!(read_all(&mut tty, &mut host, true), b"foo \n");
}

#[test]
fn control_characters_echo_as_caret_notation() {
    let (mut tty, mut host) = tty();
    feed(&mut tty, &mut host, b"\x01\x1b");
    assert_eq!(host.wire, b"^A^[");
}

#[test]
fn eof_ends_the_line_without_a_newline_and_a_lone_eof_reads_zero() {
    let (mut tty, mut host) = tty();
    feed(&mut tty, &mut host, b"ab\x04");
    assert_eq!(read_all(&mut tty, &mut host, true), b"ab");
    feed(&mut tty, &mut host, b"\x04");
    assert!(tty.input_available(false));
    assert_eq!(read_all(&mut tty, &mut host, true), b"");
}

#[test]
fn isig_signals_the_foreground_group_and_flushes() {
    let (mut tty, mut host) = tty();
    for byte in b"xy\x03" {
        feed(&mut tty, &mut host, &[*byte]);
    }
    assert_eq!(host.signals, [2]);
    assert_eq!(host.wire, b"xy^C");
    assert!(!tty.input_available(false));
    feed(&mut tty, &mut host, b"\x1c");
    feed(&mut tty, &mut host, b"\x1a");
    assert_eq!(host.signals, [2, 3, 20]);
    // One batch: the echo of earlier bytes in it is discarded by the flush.
    host.wire.clear();
    feed(&mut tty, &mut host, b"pq\x03");
    assert_eq!(host.wire, b"^C");
}

#[test]
fn noflsh_keeps_the_input() {
    let (mut tty, mut host) = tty();
    let mut t = tty.termios;
    t.lflag |= NOFLSH;
    tty.set_termios(&mut host, &t);
    feed(&mut tty, &mut host, b"kept\n\x03");
    assert_eq!(read_all(&mut tty, &mut host, true), b"kept\n");
}

#[test]
fn input_mapping_icrnl_inlcr_igncr() {
    let (mut tty, mut host) = tty();
    let mut t = tty.termios;
    t.iflag &= !ICRNL;
    t.lflag &= !(ECHO | ICANON);
    t.cc[VMIN] = 1;
    tty.set_termios(&mut host, &t);
    feed(&mut tty, &mut host, b"a\rb\n");
    assert_eq!(read_all(&mut tty, &mut host, true), b"a\rb\n");
    t.iflag |= ICRNL | INLCR;
    tty.set_termios(&mut host, &t);
    feed(&mut tty, &mut host, b"a\rb\n");
    assert_eq!(read_all(&mut tty, &mut host, true), b"a\nb\r");
    t.iflag = (t.iflag & !(ICRNL | INLCR)) | IGNCR;
    tty.set_termios(&mut host, &t);
    feed(&mut tty, &mut host, b"a\rb");
    assert_eq!(read_all(&mut tty, &mut host, true), b"ab");
}

#[test]
fn raw_mode_vmin_vtime_decisions() {
    let (mut tty, mut host) = tty();
    let mut t = tty.termios;
    t.lflag &= !(ICANON | ECHO);
    t.cc[VMIN] = 3;
    t.cc[VTIME] = 0;
    tty.set_termios(&mut host, &t);
    feed(&mut tty, &mut host, b"xy");
    let env = ReadEnv {
        nonblock: false,
        hung_up: false,
        signal_pending: false,
    };
    let mut op = tty.read_begin(64);
    let mut buf = [0u8; 64];
    // Two bytes are below VMIN: the read sleeps for more.
    assert_eq!(
        tty.read_step(&mut host, &mut op, &mut buf, &env),
        ReadStep::Sleep { ms: None }
    );
    feed(&mut tty, &mut host, b"z!");
    assert_eq!(
        tty.read_step(&mut host, &mut op, &mut buf, &env),
        ReadStep::Done {
            len: 4,
            more: false
        }
    );
    assert_eq!(&buf[..4], b"xyz!");
    // VMIN=0, VTIME=2: a 200 ms timeout, then an empty read.
    t.cc[VMIN] = 0;
    t.cc[VTIME] = 2;
    tty.set_termios(&mut host, &t);
    let mut op = tty.read_begin(64);
    assert_eq!(
        tty.read_step(&mut host, &mut op, &mut buf, &env),
        ReadStep::Sleep { ms: Some(200) }
    );
    op.timeout_ms = 0;
    assert_eq!(
        tty.read_step(&mut host, &mut op, &mut buf, &env),
        ReadStep::Done {
            len: 0,
            more: false
        }
    );
}

#[test]
fn output_processing() {
    let (mut tty, mut host) = tty();
    let pass = tty.write_pass(&mut host, b"a\nb\tc\r");
    assert_eq!(pass.consumed, 6);
    assert_eq!(host.wire, b"a\r\nb\tc\r");
    host.wire.clear();
    let mut t = tty.termios;
    t.oflag = OPOST | OCRNL;
    tty.set_termios(&mut host, &t);
    tty.write_pass(&mut host, b"x\ry\n");
    assert_eq!(host.wire, b"x\ny\n");
    host.wire.clear();
    t.oflag = OPOST | XTABS | ONLCR;
    tty.set_termios(&mut host, &t);
    tty.write_pass(&mut host, b"\rab\tc");
    assert_eq!(host.wire, b"\rab      c");
    host.wire.clear();
    t.oflag = 0;
    tty.set_termios(&mut host, &t);
    tty.write_pass(&mut host, b"a\nb");
    assert_eq!(host.wire, b"a\nb");
}

#[test]
fn xoff_stops_output_and_xon_restarts_it() {
    let (mut tty, mut host) = tty();
    assert!(tty.termios.iflag & IXON != 0);
    feed(&mut tty, &mut host, b"\x13");
    tty.write_pass(&mut host, b"held");
    assert_eq!(host.wire, b"");
    assert_eq!(tty.chars_in_buffer(), 4);
    feed(&mut tty, &mut host, b"\x11");
    assert_eq!(host.wire, b"held");
    assert_eq!(tty.chars_in_buffer(), 0);
}

#[test]
fn break_with_brkint_raises_sigint() {
    let (mut tty, mut host) = tty();
    let mut t = tty.termios;
    t.iflag |= BRKINT;
    tty.set_termios(&mut host, &t);
    let n = tty.receive_buf(&mut host, &[0], Some(&[TTY_BREAK]));
    assert_eq!(n, 1);
    assert_eq!(host.signals, [2]);
}

#[test]
fn echo_flags() {
    let (mut tty, mut host) = tty();
    let mut t = tty.termios;
    t.lflag &= !ECHO;
    t.lflag |= ECHONL;
    tty.set_termios(&mut host, &t);
    feed(&mut tty, &mut host, b"quiet\n");
    assert_eq!(host.wire, b"\r\n");
    host.wire.clear();
    t.lflag = ICANON | ECHO | IEXTEN | ISIG; // no ECHOE/ECHOK/ECHOCTL/ECHOKE
    tty.set_termios(&mut host, &t);
    feed(&mut tty, &mut host, b"ab\x7f\x15\x01");
    assert_eq!(host.wire, b"ab\x7f\x15\x01");
    let _ = (
        ECHOCTL, ECHOE, ECHOK, ECHOKE, VERASE, VKILL, VINTR, VEOF, VTIME,
    );
}

#[test]
fn tiocinq_counts_the_line() {
    let (mut tty, mut host) = tty();
    feed(&mut tty, &mut host, b"ab\n");
    assert_eq!(tty.tiocinq(), 3);
    feed(&mut tty, &mut host, b"cd");
    assert_eq!(tty.tiocinq(), 3);
}

#[test]
fn switching_to_canonical_pushes_pending_bytes() {
    let (mut tty, mut host) = tty();
    let mut t = tty.termios;
    t.lflag &= !(ICANON | ECHO);
    tty.set_termios(&mut host, &t);
    feed(&mut tty, &mut host, b"pending");
    t.lflag |= ICANON;
    tty.set_termios(&mut host, &t);
    assert!(tty.input_available(false));
    assert_eq!(read_all(&mut tty, &mut host, true), b"pending");
}
