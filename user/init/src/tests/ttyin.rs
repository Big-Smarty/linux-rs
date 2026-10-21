// SPDX-License-Identifier: GPL-2.0-only
//! `ttyin` group: the console tty with input from the serial line, driven by the test harness
//! (`xtask`'s tty driver writes the bytes the script names to the guest's serial port after the
//! guest announces each stage with `init: stage <name>`). The stages cover the canonical line
//! editing of `n_tty.c` (erase, kill, word erase, `VEOF`, `VLNEXT`, `VREPRINT`, long lines and the
//! 64-byte read chunks), non-canonical `VMIN`/`VTIME`, the input mapping flags, the echo flags
//! (what the tty echoes is part of the observation), output processing (`OPOST`, `ONLCR`, `OCRNL`,
//! `ONOCR`, `ONLRET`, `OLCUC`, `XTABS`, column tracking), `ISIG` with a session leader, software
//! flow control, `poll`, `FIONREAD`, `O_NONBLOCK`, `TCFLSH` and `TCSETSF`.
//!
//! What the console wrote while a stage ran (the echo, the output under test) is *not* printed by
//! the test: the harness keeps the serial transcript of every stage and compares it with the
//! pinned Linux's (`xtask/oracle/expected.tsv`, rows of kind `echo`). The test prints only the
//! results it can see (the bytes read, the errors, the timings against generous bounds).
//!
//! Every stage restores the termios before it prints a result, and ends with an empty line so that
//! the result lines start at the beginning of a line.

use core::sync::atomic::{AtomicUsize, Ordering::Relaxed};

use syscalls::Sysno;

use super::proc::{nap, reap_all, sigaction, spawn, wait4};
use super::tty::{
    ECHO, ICANON, ISIG, IXON, O_NOCTTY, O_NONBLOCK, O_RDWR, SIGINT, Tio, close, errno, getattr,
    ioctl, num, open, poll, pollfd, set_cc, set_word, setattr, word, write,
};
use super::{T, addr, addr_mut, emit, fn_addr, sys};

const TCSETS: usize = 0x5402;
const TCSETSF: usize = 0x5404;
const TCXONC: usize = 0x540a;
const TIOCSTI: usize = 0x5412;
const TCFLSH: usize = 0x540b;
const TIOCOUTQ: usize = 0x5411;
const FIONREAD: usize = 0x541b;
const F_SETFL: usize = 4;
const F_GETFL: usize = 3;

const ICRNL: u32 = 0o400;
const INLCR: u32 = 0o100;
const IGNCR: u32 = 0o200;
const ISTRIP: u32 = 0o40;
const IUCLC: u32 = 0o1000;
const IXANY: u32 = 0o4000;
const OPOST: u32 = 1;
const OLCUC: u32 = 2;
const ONLCR: u32 = 4;
const OCRNL: u32 = 0o10;
const ONOCR: u32 = 0o20;
const ONLRET: u32 = 0o40;
const XTABS: u32 = 0o14000;
const ECHOE: u32 = 0o20;
const ECHOK: u32 = 0o40;
const ECHONL: u32 = 0o100;
const NOFLSH: u32 = 0o200;
const ECHOCTL: u32 = 0o1000;
const ECHOPRT: u32 = 0o2000;
const ECHOKE: u32 = 0o4000;
const IEXTEN: u32 = 0o100000;
const VTIME: usize = 5;
const VMIN: usize = 6;
const POLLIN: i16 = 1;
const POLLOUT: i16 = 4;
const POLLRDNORM: i16 = 0x40;
const SIGQUIT: usize = 3;
const SIGTSTP: usize = 20;
const CLOCK_MONOTONIC: usize = 1;

fn now_ms() -> u64 {
    let mut ts = [0i64; 2];
    let _ = sys(Sysno::clock_gettime, &[CLOCK_MONOTONIC, addr_mut(&mut ts)]);
    (ts[0] as u64) * 1000 + (ts[1] as u64) / 1_000_000
}

/// `init: stage <name>`: the line the harness waits for.
fn marker(name: impl core::fmt::Display) {
    emit(format_args!("init: stage {name}"));
}

/// Flushes the input (`TCSETSF`) and applies `edit` to the console's termios; the original is
/// returned for [`end`].
fn begin(edit: impl FnOnce(&mut Tio)) -> Tio {
    let (_, orig) = getattr(0);
    let mut t = orig;
    edit(&mut t);
    let _ = setattr(0, TCSETSF, &t);
    orig
}

/// Restores the termios (discarding unread input) and ends the line the echo may have left open.
fn end(orig: &Tio) {
    let _ = setattr(0, TCSETSF, orig);
    let _ = write(1, b"\n");
}

fn lflag(t: &mut Tio, set: u32, clear: u32) {
    let w = (word(t, 3) | set) & !clear;
    set_word(t, 3, w);
}

fn iflag(t: &mut Tio, set: u32, clear: u32) {
    let w = (word(t, 0) | set) & !clear;
    set_word(t, 0, w);
}

/// One `read(0, .., len)`: its result and the bytes.
fn rd(len: usize) -> (i64, [u8; 128]) {
    let mut buf = [0u8; 128];
    let r = num(sys(Sysno::read, &[0, addr_mut(&mut buf), len.min(128)]));
    (r, buf)
}

/// A read's outcome for a check: the count and the bytes as a short string.
fn bytes(r: (i64, [u8; 128])) -> (i64, [u8; 12]) {
    let mut out = [0u8; 12];
    if r.0 > 0 {
        let n = (r.0 as usize).min(12);
        out[..n].copy_from_slice(&r.1[..n]);
    }
    (r.0, out)
}

fn pad(s: &[u8]) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[..s.len()].copy_from_slice(s);
    out
}

pub fn run() -> bool {
    let mut t = T::new("ttyin");
    reap_all();
    let _ = sys(
        Sysno::mknod,
        &[addr(b"/dev/ttyS0\0"), 0o020_600, (4 << 8) | 64],
    );
    canon_echo(&mut t);
    canon_long(&mut t);
    canon_nonblock(&mut t);
    raw_vmin(&mut t);
    raw_vtime(&mut t);
    input_mapping(&mut t);
    echo_flags(&mut t);
    output_processing(&mut t);
    flow_control(&mut t);
    polling(&mut t);
    fionread(&mut t);
    flushing(&mut t);
    isig_stages(&mut t);
    t.finish()
}

fn canon_echo(t: &mut T) {
    let orig = begin(|_| {});
    marker("canon-echo");
    let a = bytes(rd(100)); // hello\r -> "hello\n"
    let b = bytes(rd(100)); // ab<DEL>c\n -> "ac\n"
    let c = bytes(rd(100)); // foo bar<^W>baz\n -> "foo baz\n"
    let d = bytes(rd(100)); // xyz<^U>ok\n -> "ok\n"
    let e = bytes(rd(100)); // abc<^D> -> "abc"
    let f = bytes(rd(100)); // <^D> -> end of file
    let g = bytes(rd(100)); // <^V><^C>q\n -> "\x03q\n"
    let h = bytes(rd(100)); // abc<^R>def\n -> "abcdef\n"
    let i = bytes(rd(100)); // a<TAB><DEL>b\n -> "ab\n"
    end(&orig);
    t.eq("canon-line", a, (6, pad(b"hello\n")));
    t.eq("canon-erase", b, (3, pad(b"ac\n")));
    t.eq("canon-word-erase", c, (8, pad(b"foo baz\n")));
    t.eq("canon-kill", d, (3, pad(b"ok\n")));
    t.eq("canon-eof-after-data", e, (3, pad(b"abc")));
    t.eq("canon-eof-alone-reads-zero", f, (0, [0; 12]));
    t.eq("canon-lnext", g, (3, pad(b"\x03q\n")));
    t.eq("canon-reprint-keeps-the-line", h, (7, pad(b"abcdef\n")));
    t.eq("canon-erase-tab", i, (3, pad(b"ab\n")));
}

fn canon_long(t: &mut T) {
    let orig = begin(|t| lflag(t, 0, ECHO));
    marker("canon-long");
    // 100 characters and a newline in one read of up to 200: the 64-byte chunks chain.
    let a = rd(200);
    // The next line is read in pieces of 8: the line is kept between reads.
    let b = rd(8);
    let c = rd(8);
    let d = rd(8);
    end(&orig);
    t.eq(
        "canon-long-line-one-read",
        (a.0, a.1[..100].iter().all(|&b| b == b'x')),
        (101, true),
    );
    t.eq("canon-long-line-last-byte", a.1[100], b'\n');
    t.eq(
        "canon-line-in-pieces",
        (bytes(b), bytes(c), bytes(d)),
        (
            (8, pad(b"yyyyyyyy")),
            (8, pad(b"yyyyyyyy")),
            (5, pad(b"yyyy\n")),
        ),
    );
}

fn canon_nonblock(t: &mut T) {
    let orig = begin(|t| lflag(t, 0, ECHO));
    let fl = num(sys(Sysno::fcntl, &[0, F_GETFL, 0]));
    let _ = sys(Sysno::fcntl, &[0, F_SETFL, fl as usize | O_NONBLOCK]);
    let none = rd(10).0;
    marker("nonblock");
    // The harness sends a line after the marker.
    let mut got = (-1, [0u8; 128]);
    for _ in 0..100 {
        got = rd(10);
        if got.0 != -11 {
            break;
        }
        nap(20);
    }
    let _ = sys(Sysno::fcntl, &[0, F_SETFL, fl as usize]);
    end(&orig);
    t.eq("nonblock-empty-eagain", none, -11);
    t.eq("nonblock-then-data", bytes(got), (3, pad(b"k!\n")));
}

fn raw_vmin(t: &mut T) {
    // VMIN=3: the read returns when three bytes are there.
    let orig = begin(|t| {
        lflag(t, 0, ICANON | ECHO);
        set_cc(t, VMIN, 3);
        set_cc(t, VTIME, 0);
    });
    marker("raw-vmin3");
    let start = now_ms();
    let a = bytes(rd(10));
    let waited = now_ms() - start;
    end(&orig);
    t.eq("raw-vmin3-bytes", a, (3, pad(b"abc")));
    t.eq(
        "raw-vmin3-waited-for-the-third",
        (150..3000).contains(&waited),
        true,
    );
    // VMIN=1: whatever is there, at once; a read of fewer bytes than are there takes them in turns.
    let orig = begin(|t| {
        lflag(t, 0, ICANON | ECHO);
        set_cc(t, VMIN, 1);
        set_cc(t, VTIME, 0);
    });
    marker("raw-vmin1");
    let a = bytes(rd(10));
    // Both of the next bytes have arrived (they are one burst, but a driver may take them one
    // by one: a read that wakes on the first would see only it).
    nap(300);
    let b = bytes(rd(2));
    end(&orig);
    t.eq("raw-vmin1", (a, b), ((1, pad(b"x")), (2, pad(b"yz"))));
    // VMIN larger than the 64-byte chunk the tty layer reads: the read ends when the chunk is full.
    let orig = begin(|t| {
        lflag(t, 0, ICANON | ECHO);
        set_cc(t, VMIN, 100);
        set_cc(t, VTIME, 0);
    });
    marker("raw-vmin100");
    let big = rd(128);
    end(&orig);
    t.eq("raw-vmin100", (big.0, big.1[63]), (64, b'3'));
}

fn raw_vtime(t: &mut T) {
    // VMIN=0, VTIME=3: wait up to 300 ms for the first byte.
    let orig = begin(|t| {
        lflag(t, 0, ICANON | ECHO);
        set_cc(t, VMIN, 0);
        set_cc(t, VTIME, 3);
    });
    marker("raw-vtime-timeout");
    let start = now_ms();
    let a = rd(10);
    let waited = now_ms() - start;
    end(&orig);
    t.eq("raw-vtime-timeout-returns-zero", a.0, 0);
    t.eq(
        "raw-vtime-timeout-waited",
        (250..3000).contains(&waited),
        true,
    );
    let orig = begin(|t| {
        lflag(t, 0, ICANON | ECHO);
        set_cc(t, VMIN, 0);
        set_cc(t, VTIME, 5);
    });
    marker("raw-vtime-early");
    let start = now_ms();
    let a = bytes(rd(10));
    let waited = now_ms() - start;
    end(&orig);
    t.eq("raw-vtime-early-byte", a, (1, pad(b"e")));
    t.eq("raw-vtime-early-before-the-timeout", waited < 450, true);
    // VMIN=2, VTIME=3: the inter-byte timer starts with the first byte.
    let orig = begin(|t| {
        lflag(t, 0, ICANON | ECHO);
        set_cc(t, VMIN, 2);
        set_cc(t, VTIME, 3);
    });
    marker("raw-vtime-interbyte");
    let start = now_ms();
    let a = bytes(rd(10));
    let waited = now_ms() - start;
    end(&orig);
    t.eq("raw-vtime-interbyte-one-byte", a, (1, pad(b"i")));
    t.eq(
        "raw-vtime-interbyte-waited",
        (250..3000).contains(&waited),
        true,
    );
    let orig = begin(|t| {
        lflag(t, 0, ICANON | ECHO);
        set_cc(t, VMIN, 2);
        set_cc(t, VTIME, 4);
    });
    marker("raw-vtime-two");
    let a = bytes(rd(10));
    end(&orig);
    t.eq("raw-vtime-two-bytes", a, (2, pad(b"pq")));
    // VMIN=0 VTIME=0: poll for data without waiting.
    let orig = begin(|t| {
        lflag(t, 0, ICANON | ECHO);
        set_cc(t, VMIN, 0);
        set_cc(t, VTIME, 0);
    });
    let start = now_ms();
    let a = rd(10);
    let waited = now_ms() - start;
    end(&orig);
    t.eq(
        "raw-vmin0-vtime0-returns-at-once",
        (a.0, waited < 400),
        (0, true),
    );
}

fn input_mapping(t: &mut T) {
    let cases: [(&str, u32, u32, &[u8]); 6] = [
        ("icrnl", ICRNL, 0, b"a\nb\nc\n"),
        ("no-icrnl", 0, ICRNL, b"a\rb\rc\r"),
        ("inlcr", INLCR, 0, b"a\rb\rc\r"),
        ("igncr", IGNCR, ICRNL, b"ac"),
        ("istrip", ISTRIP, 0, b"abc"),
        ("iuclc", IUCLC, 0, b"abc"),
    ];
    for (name, set, clear, want) in cases {
        let orig = begin(|t| {
            lflag(t, 0, ICANON | ECHO);
            set_cc(t, VMIN, want.len() as u8);
            set_cc(t, VTIME, 0);
            iflag(t, set, clear);
        });
        marker(format_args!("input-{name}"));
        let a = rd(20);
        end(&orig);
        let mut w = [0u8; 12];
        w[..want.len()].copy_from_slice(want);
        t.eq(
            format_args!("input-{name}"),
            (a.0, bytes(a).1),
            (want.len() as i64, w),
        );
    }
}

fn echo_flags(t: &mut T) {
    // Each stage reads one line, typed with edits and a control character; what is echoed is in
    // the transcript, what the process receives is the same for all of them.
    let cases: [(&str, u32, u32); 8] = [
        ("echo-off", 0, ECHO),
        ("echo-nl-only", ECHONL, ECHO),
        ("no-echoe", 0, ECHOE),
        ("no-echok", 0, ECHOK),
        ("no-echoctl", 0, ECHOCTL),
        ("echoprt", ECHOPRT, ECHOE),
        ("no-echoke", 0, ECHOKE),
        ("no-iexten", 0, IEXTEN),
    ];
    for (name, set, clear) in cases {
        let orig = begin(|t| lflag(t, set, clear));
        marker(format_args!("{name}"));
        let a = rd(60);
        end(&orig);
        let want: &[u8] = if clear == IEXTEN {
            // Without IEXTEN ^W and ^V are plain characters.
            b"xy\x01z\n"
        } else {
            b"xy\x01z\n"
        };
        t.eq(
            format_args!("{name}-line"),
            bytes(a),
            (want.len() as i64, pad(want)),
        );
    }
}

fn output_processing(t: &mut T) {
    // The bytes the console puts on the wire for the same text under different c_oflag.
    let text: &[u8] = b"a\nb\rc\td\x08e\tf\n";
    let cases: [(&str, u32, u32); 9] = [
        ("opost-onlcr", OPOST | ONLCR, !0),
        ("opost-only", OPOST, !0),
        ("no-opost", 0, !0),
        ("ocrnl", OPOST | OCRNL, !0),
        ("onocr", OPOST | ONOCR, !0),
        ("onlret", OPOST | ONLRET, !0),
        ("olcuc", OPOST | OLCUC | ONLCR, !0),
        ("xtabs", OPOST | XTABS | ONLCR, !0),
        ("onlcr-ocrnl-xtabs", OPOST | ONLCR | OCRNL | XTABS, !0),
    ];
    for (name, set, _) in cases {
        // The marker goes out under the default flags: `OLCUC` would shout it.
        marker(format_args!("out-{name}"));
        let orig = begin(|t| set_word(t, 1, set));
        let r = write(1, text);
        // Utf-8 (IUTF8 not set): bytes above 0x7f count as columns.
        let _ = write(1, b"xy\xc3\xa9\tz\n");
        let _ = write(1, b"0123456789\tq\r\tw\n");
        end(&orig);
        t.eq(format_args!("out-{name}"), num(r), text.len() as i64);
    }
}

fn flow_control(t: &mut T) {
    // ^S stops the output: what the process writes waits in the queue until ^Q.
    let orig = begin(|t| lflag(t, 0, ICANON));
    marker("flow-xoff");
    nap(300);
    let outq0 = queued();
    let w = write(1, b"held\n");
    let outq1 = queued();
    nap(500);
    let outq2 = queued();
    // The harness sent ^Q; in case it did not, the process sends one to itself.
    let _ = ioctl(0, TIOCSTI, addr(&0x11u8));
    end(&orig);
    t.eq("flow-xoff-queue-empty-before", outq0, 0);
    t.eq("flow-xoff-write", num(w), 5);
    t.eq("flow-xoff-queued", outq1, 6);
    t.eq("flow-xon-drains", outq2, 0);
    // IXANY: any character restarts the output.
    let orig = begin(|t| {
        lflag(t, ICANON, ECHO);
        iflag(t, IXANY, 0);
    });
    marker("flow-ixany");
    nap(300);
    let w = write(1, b"any\n");
    let q1 = queued();
    nap(500);
    let q2 = queued();
    let _ = ioctl(0, TIOCSTI, addr(&0x11u8));
    end(&orig);
    t.eq("flow-ixany", (num(w), q1, q2), (4, 5, 0));
    // TCOOFF is not undone by ^Q: only TCOON restarts the output.
    let orig = begin(|t| lflag(t, 0, ICANON | ECHO));
    marker("flow-tcooff");
    let _ = ioctl(0, TCXONC, 0);
    nap(400);
    let w = write(1, b"tco\n");
    let q1 = queued();
    nap(300);
    let q2 = queued();
    let _ = ioctl(0, TCXONC, 1);
    nap(200);
    let q3 = queued();
    end(&orig);
    t.eq(
        "flow-tcooff-stays-stopped-on-xon",
        (num(w), q1, q2, q3),
        (4, 5, 5, 0),
    );
    let _ = (IXON, ISIG);
}

fn queued() -> i64 {
    let mut n = -1i32;
    let _ = ioctl(0, TIOCOUTQ, addr_mut(&mut n));
    i64::from(n)
}

fn polling(t: &mut T) {
    let orig = begin(|t| lflag(t, 0, ECHO));
    marker("poll-canon");
    let mut fds = [pollfd(0, POLLIN | POLLRDNORM)];
    let none = num(poll(&mut fds, 200));
    let r0 = fds[0].revents;
    let mut fds2 = [pollfd(0, POLLIN | POLLRDNORM)];
    // "ab" arrives (no newline): not readable yet; then "\n": readable.
    let part = num(poll(&mut fds2, 400));
    let part_ev = fds2[0].revents;
    let mut fds3 = [pollfd(0, POLLIN | POLLRDNORM)];
    let line = num(poll(&mut fds3, 3000));
    let line_ev = fds3[0].revents;
    let mut out = [pollfd(1, POLLOUT)];
    let writable = (num(poll(&mut out, 0)), out[0].revents);
    let a = bytes(rd(10));
    end(&orig);
    t.eq("poll-canon-nothing", (none, r0), (0, 0));
    t.eq(
        "poll-canon-partial-line-not-readable",
        (part, part_ev),
        (0, 0),
    );
    t.eq(
        "poll-canon-line-readable",
        (line, line_ev),
        (1, POLLIN | POLLRDNORM),
    );
    t.eq("poll-console-writable", writable, (1, POLLOUT));
    t.eq("poll-canon-read", a, (3, pad(b"ab\n")));
    // Non-canonical, VMIN=3 and no timer: readable only with three bytes.
    let orig = begin(|t| {
        lflag(t, 0, ICANON | ECHO);
        set_cc(t, VMIN, 3);
        set_cc(t, VTIME, 0);
    });
    marker("poll-vmin");
    let mut f1 = [pollfd(0, POLLIN)];
    let two = (num(poll(&mut f1, 500)), f1[0].revents);
    let mut f2 = [pollfd(0, POLLIN)];
    let three = (num(poll(&mut f2, 3000)), f2[0].revents);
    let a = rd(10);
    end(&orig);
    t.eq("poll-vmin-two-bytes-not-readable", two, (0, 0));
    t.eq("poll-vmin-three-bytes-readable", three, (1, POLLIN));
    t.eq("poll-vmin-read", a.0, 3);
}

fn fionread(t: &mut T) {
    let orig = begin(|t| lflag(t, 0, ECHO));
    marker("fionread");
    nap(600);
    let mut n = [-1i32; 4];
    let _ = ioctl(0, FIONREAD, addr_mut(&mut n[0])); // "abc": no newline yet
    nap(10);
    let a = rd(100); // blocks until the "\n"
    end(&orig);
    t.eq("fionread-partial-line-is-zero", n[0], 0);
    t.eq("fionread-read", bytes(a), (4, pad(b"abc\n")));
    let orig = begin(|t| lflag(t, 0, ECHO));
    marker("fionread-canon");
    nap(700);
    let mut line = -1i32;
    let _ = ioctl(0, FIONREAD, addr_mut(&mut line)); // "xy<^D>" and "z\n" pending
    let a = rd(100);
    let b = rd(100);
    end(&orig);
    t.eq("fionread-counts-lines-without-eof-chars", line, 4);
    t.eq(
        "fionread-lines",
        (bytes(a), bytes(b)),
        ((2, pad(b"xy")), (2, pad(b"z\n"))),
    );
    let orig = begin(|t| {
        lflag(t, 0, ICANON | ECHO);
        set_cc(t, VMIN, 1);
    });
    marker("fionread-raw");
    nap(500);
    let mut raw = -1i32;
    let _ = ioctl(0, FIONREAD, addr_mut(&mut raw));
    let a = rd(10);
    end(&orig);
    t.eq("fionread-raw", (raw, a.0), (2, 2));
}

fn flushing(t: &mut T) {
    let orig = begin(|t| lflag(t, 0, ECHO));
    marker("tcflsh");
    nap(500);
    let before = {
        let mut n = -1i32;
        let _ = ioctl(0, FIONREAD, addr_mut(&mut n));
        n
    };
    let r = errno(ioctl(0, TCFLSH, 0));
    let after = {
        let mut n = -1i32;
        let _ = ioctl(0, FIONREAD, addr_mut(&mut n));
        n
    };
    end(&orig);
    t.eq("tcflsh-input", (before, r, after), (5, 0, 0));
    // TCSETSF discards unread input; TCSETS keeps it.
    let orig = begin(|t| lflag(t, 0, ECHO));
    marker("tcsetsf");
    nap(500);
    let (_, now) = getattr(0);
    let kept = {
        let _ = setattr(0, TCSETS, &now);
        let mut n = -1i32;
        let _ = ioctl(0, FIONREAD, addr_mut(&mut n));
        n
    };
    let _ = setattr(0, TCSETSF, &now);
    let dropped = {
        let mut n = -1i32;
        let _ = ioctl(0, FIONREAD, addr_mut(&mut n));
        n
    };
    end(&orig);
    t.eq("tcsetsf-flushes-input", (kept, dropped), (6, 0));
}

// ---- ISIG ---------------------------------------------------------------------------

static SEQ: [AtomicUsize; 8] = [const { AtomicUsize::new(0) }; 8];
static NSEQ: AtomicUsize = AtomicUsize::new(0);

extern "C" fn on_seq(sig: i32) {
    let i = NSEQ.fetch_add(1, Relaxed);
    if i < SEQ.len() {
        SEQ[i].store(sig as usize, Relaxed);
    }
}

fn pipe() -> (usize, usize) {
    let mut fds = [0u32; 2];
    let _ = sys(Sysno::pipe2, &[addr_mut(&mut fds), 0]);
    (fds[0] as usize, fds[1] as usize)
}

/// Runs `body` in a child that leads a session whose controlling terminal is `/dev/ttyS0` (the
/// console tty): `body` gets the descriptor and calls `ready` when its handlers are installed. The
/// parent prints the stage marker then, waits for the child and returns the numbers it filled in.
fn leader_stage<const N: usize>(
    name: &str,
    body: impl FnOnce(usize, &dyn Fn(), &mut [i64; N]),
) -> [i64; N] {
    let (ready_r, ready_w) = pipe();
    let (res_r, res_w) = pipe();
    let child = spawn(|| {
        close(ready_r);
        close(res_r);
        let _ = sys(Sysno::setsid, &[]);
        let fd = open(b"/dev/ttyS0\0", O_RDWR).unwrap_or(usize::MAX);
        let mut out = [i64::MIN; N];
        NSEQ.store(0, Relaxed);
        body(
            fd,
            &|| {
                let _ = sys(Sysno::write, &[ready_w, addr(&b"r"), 1]);
            },
            &mut out,
        );
        let _ = sys(Sysno::write, &[res_w, addr(&out), 8 * N]);
        0
    });
    close(ready_w);
    close(res_w);
    let mut b = [0u8; 1];
    let _ = sys(Sysno::read, &[ready_r, addr_mut(&mut b), 1]);
    marker(name);
    let mut out = [i64::MIN; N];
    let got = sys(Sysno::read, &[res_r, addr_mut(&mut out), 8 * N]);
    let _ = wait4(child as isize, 0);
    close(ready_r);
    close(res_r);
    let _ = write(1, b"\n");
    if got != Ok(8 * N) {
        return [i64::MIN; N];
    }
    out
}

fn install_handlers() {
    for sig in [SIGINT, SIGQUIT, SIGTSTP] {
        let _ = sigaction(sig, fn_addr(on_seq as *const ()), 0);
    }
}

fn seq() -> [i64; 4] {
    let n = NSEQ.load(Relaxed).min(4);
    let mut out = [0i64; 4];
    for (i, slot) in out.iter_mut().enumerate().take(n) {
        *slot = SEQ[i].load(Relaxed) as i64;
    }
    out
}

fn isig_stages(t: &mut T) {
    // Signals from the terminal go to the foreground group, flush the input, and interrupt the read.
    let r = leader_stage::<7>("isig", |fd, ready, o| {
        install_handlers();
        ready();
        let mut buf = [0u8; 16];
        let mut ret = [0i64; 4];
        let mut i = 0;
        while NSEQ.load(Relaxed) < 3 && i < 4 {
            ret[i] = num(sys(Sysno::read, &[fd, addr_mut(&mut buf), 16]));
            i += 1;
        }
        let s = seq();
        o[0] = s[0];
        o[1] = s[1];
        o[2] = s[2];
        o[3] = ret[0];
        o[4] = ret[1];
        o[5] = ret[2];
        // Everything typed before the signals was flushed with them: switching to raw mode would
        // make pending bytes readable.
        let (_, orig) = getattr(fd);
        let mut raw = orig;
        lflag(&mut raw, 0, ICANON | ECHO);
        set_cc(&mut raw, VMIN, 0);
        set_cc(&mut raw, VTIME, 0);
        let _ = setattr(fd, TCSETS, &raw);
        o[6] = num(sys(Sysno::read, &[fd, addr_mut(&mut buf), 16]));
        let _ = setattr(fd, TCSETSF, &orig);
    });
    t.eq(
        "isig-signals-flush-and-interrupt",
        r,
        [SIGINT as i64, SIGQUIT as i64, SIGTSTP as i64, -4, -4, -4, 0],
    );
    // ISIG off: the characters are data.
    let r = leader_stage::<4>("isig-off", |fd, ready, o| {
        install_handlers();
        let (_, orig) = getattr(fd);
        let mut t = orig;
        lflag(&mut t, 0, ISIG);
        let _ = setattr(fd, TCSETS, &t);
        ready();
        let mut buf = [0u8; 16];
        let n = num(sys(Sysno::read, &[fd, addr_mut(&mut buf), 16]));
        o[0] = n;
        o[1] = i64::from(buf[0]) | i64::from(buf[1]) << 8 | i64::from(buf[2]) << 16;
        o[2] = NSEQ.load(Relaxed) as i64;
        let _ = setattr(fd, TCSETSF, &orig);
        o[3] = 1;
    });
    t.eq("isig-off-characters-are-data", r, [4, 0x1a_1c_03, 0, 1]);
    // NOFLSH keeps the input a signal interrupts.
    let r = leader_stage::<5>("isig-noflsh", |fd, ready, o| {
        install_handlers();
        let (_, orig) = getattr(fd);
        let mut t = orig;
        lflag(&mut t, NOFLSH, 0);
        let _ = setattr(fd, TCSETS, &t);
        ready();
        let mut buf = [0u8; 16];
        let a = num(sys(Sysno::read, &[fd, addr_mut(&mut buf), 16]));
        o[0] = a;
        let b = num(sys(Sysno::read, &[fd, addr_mut(&mut buf), 16]));
        o[1] = b;
        o[2] = i64::from(buf[0]) | i64::from(buf[1]) << 8 | i64::from(buf[2]) << 16;
        o[3] = NSEQ.load(Relaxed) as i64;
        let _ = setattr(fd, TCSETSF, &orig);
        o[4] = 1;
    });
    t.eq("isig-noflsh-input-survives", r, [-4, 3, 0x0a_62_61, 1, 1]);
}

// ---- the keyboard -----------------------------------------------------------------------

/// `ttykbd` group: the bytes the console tty receives for keys, with the keyboard on the PS/2
/// port. On the pinned Linux the console is the virtual terminal (`console=tty0`, keys through
/// `drivers/tty/vt/keyboard.c` and `atkbd`); results go to `/dev/ttyS0` there, which on the
/// candidate is the same console tty. The harness presses keys with QMP `send-key` at every
/// stage marker; the process reads raw (no `ISIG`, `ICRNL`, `ECHO`) until the keys stop coming.
pub fn run_kbd() -> bool {
    let mut t = T::new("ttykbd");
    reap_all();
    let _ = sys(
        Sysno::mknod,
        &[addr(b"/dev/ttyS0\0"), 0o020_600, (4 << 8) | 64],
    );
    // Results are written to the serial line on both kernels.
    if let Ok(out) = open(b"/dev/ttyS0\0", O_RDWR | O_NOCTTY) {
        let _ = sys(Sysno::dup2, &[out, 1]);
    }
    let stages: [(&str, &[u8]); 10] = [
        ("kbd-ascii", b"abz09-= [\\;'`,./"),
        ("kbd-shift", b"A!_+{~?<"),
        (
            "kbd-ctrl",
            b"\x01\x03\x04\x1a\x1b\x1c\x1d\x00\x1e\x1f\x08\x0d\x09\x0a",
        ),
        ("kbd-special", b"\r\x7f\t\x1b "),
        (
            "kbd-cursor",
            b"\x1b[A\x1b[B\x1b[C\x1b[D\x1b[1~\x1b[2~\x1b[3~\x1b[4~\x1b[5~\x1b[6~",
        ),
        (
            "kbd-function",
            b"\x1b[[A\x1b[[B\x1b[[C\x1b[[D\x1b[[E\x1b[17~\x1b[18~\x1b[19~\x1b[20~\x1b[21~\x1b[23~\x1b[24~",
        ),
        ("kbd-alt", b"\x1ba\x1b1\x1b\r\x1b\x7f\x1b\x01"),
        ("kbd-caps", b"A1aa"),
        ("kbd-numpad-off", b"\x1b[1~\x1b[A\x1b[D\x1b[G\x1b[2~\x1b[3~\r+-*/"),
        ("kbd-numpad-on", b"787.0"),
    ];
    for (name, want) in stages {
        // Raw: nothing maps, signals or echoes; the first byte is waited for, then a second of
        // silence ends the stage.
        let orig = begin(|t| {
            lflag(t, 0, ICANON | ECHO | ISIG | IEXTEN);
            iflag(t, 0, ICRNL | INLCR | IGNCR | IXON | ISTRIP | IUCLC);
            set_cc(t, VMIN, 1);
            set_cc(t, VTIME, 0);
        });
        marker(name);
        let mut got = [0u8; 64];
        let mut n = 0;
        let r = rd(64);
        if r.0 > 0 {
            let k = (r.0 as usize).min(64);
            got[..k].copy_from_slice(&r.1[..k]);
            n = k;
            let (_, mut now) = getattr(0);
            set_cc(&mut now, VMIN, 0);
            set_cc(&mut now, VTIME, 10);
            let _ = setattr(0, TCSETS, &now);
            loop {
                let r = rd(64 - n);
                if r.0 <= 0 || n >= 64 {
                    break;
                }
                let k = r.0 as usize;
                got[n..n + k].copy_from_slice(&r.1[..k]);
                n += k;
            }
        }
        end(&orig);
        t.eq(name, &got[..n], want);
    }
    t.finish()
}
