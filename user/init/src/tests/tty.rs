// SPDX-License-Identifier: GPL-2.0-only
//! `tty` group: the console tty without input. The default termios in its three representations
//! (`TCGETS`, `TCGETS2`, `TCGETA`), `TIOCGWINSZ`/`TIOCSWINSZ`, `TCSETS*`/`TCSETA*` round trips and
//! the serial driver's speed handling, flow control (`TCXONC`, `TIOCOUTQ`), the small ioctls
//! (`TIOCEXCL`, `TIOCGETD`, `TIOCGDEV`, `TIOCSSOFTCAR`, `TCFLSH`, `TIOCSTI`, `FIONREAD`), the errors
//! of a process that has no controlling terminal, and the job-control rules of a session leader and
//! its children on `/dev/ttyS0` and `/dev/tty`: acquisition by `open` and `TIOCSCTTY`, `TIOCGPGRP`/
//! `TIOCSPGRP`/`TIOCGSID`/`TIOCNOTTY`, `SIGWINCH`, `SIGTTIN`/`SIGTTOU` and `EIO` for background and
//! orphaned groups, `TOSTOP`, hangup (`TIOCVHANGUP`, the exit of the session leader).
//! Linux 6.18.57: `drivers/tty/tty_io.c`, `tty_ioctl.c`, `tty_jobctrl.c`, `n_tty.c`,
//! `serial/serial_core.c`, `serial/8250/8250_port.c`.
//!
//! The console is `console=ttyS0`, so `/dev/console`, `/dev/ttyS0` and (for a session with it as
//! controlling terminal) `/dev/tty` are the same tty. Descriptors 0-2 are `/dev/console` files,
//! which job control and hangup leave alone; the job-control checks therefore use `/dev/ttyS0`
//! files. A test that changes the termios restores it before the next line is printed.

use core::sync::atomic::{AtomicUsize, Ordering::Relaxed};

use syscalls::{Errno, Sysno};

use super::proc::{BAD, SIGCHLD, SIGHUP, nap, reap_all, sigaction, spawn, wait4};
use super::{R, T, addr, addr_mut, fn_addr, sys};

const TCGETS: usize = 0x5401;
const TCSETS: usize = 0x5402;
const TCSETSW: usize = 0x5403;
const TCSETSF: usize = 0x5404;
const TCGETA: usize = 0x5405;
const TCSETA: usize = 0x5406;
const TCSETAW: usize = 0x5407;
const TCSETAF: usize = 0x5408;
const TCSBRK: usize = 0x5409;
const TCXONC: usize = 0x540a;
const TCFLSH: usize = 0x540b;
const TIOCEXCL: usize = 0x540c;
const TIOCNXCL: usize = 0x540d;
const TIOCSCTTY: usize = 0x540e;
const TIOCGPGRP: usize = 0x540f;
const TIOCSPGRP: usize = 0x5410;
const TIOCOUTQ: usize = 0x5411;
const TIOCSTI: usize = 0x5412;
const TIOCGWINSZ: usize = 0x5413;
const TIOCSWINSZ: usize = 0x5414;
const TIOCGSOFTCAR: usize = 0x5419;
const TIOCSSOFTCAR: usize = 0x541a;
const FIONREAD: usize = 0x541b;
const TIOCCONS: usize = 0x541d;
const TIOCNOTTY: usize = 0x5422;
const TIOCSETD: usize = 0x5423;
const TIOCGETD: usize = 0x5424;
const TIOCGSID: usize = 0x5429;
const TCGETS2: usize = 0x802c_542a;
const TCSETS2: usize = 0x402c_542b;
const TCSETSW2: usize = 0x402c_542c;
const TCSETSF2: usize = 0x402c_542d;
const TIOCGDEV: usize = 0x8004_5432;
const TCGETX: usize = 0x5432;
const TIOCVHANGUP: usize = 0x5437;
const TIOCGEXCL: usize = 0x8004_5440;
const TIOCGLCKTRMIOS: usize = 0x5456;
const TIOCSLCKTRMIOS: usize = 0x5457;

pub(super) const O_RDWR: usize = 2;
pub(super) const O_NOCTTY: usize = 0o400;
pub(super) const O_NONBLOCK: usize = 0o4000;
const S_IFCHR: usize = 0o020_000;

// c_iflag, c_oflag, c_lflag bits
const ICRNL: u32 = 0o400;
pub(super) const IXON: u32 = 0o2000;
const OPOST: u32 = 1;
const ONLCR: u32 = 4;
pub(super) const ISIG: u32 = 1;
pub(super) const ICANON: u32 = 2;
pub(super) const ECHO: u32 = 8;
const ECHOE: u32 = 0o20;
const ECHOK: u32 = 0o40;
const TOSTOP: u32 = 0o400;
const CLOCAL: u32 = 0o4000;
const CBAUD: u32 = 0o10017;
const BOTHER: u32 = 0o10000;
const B0: u32 = 0;
const B19200: u32 = 0o16;
const B38400: u32 = 0o17;
const B57600: u32 = 0o10001;
const B115200: u32 = 0o10002;
const B230400: u32 = 0o10003;
const VMIN: usize = 6;
const VEOF: usize = 4;

pub(super) const SIGINT: usize = 2;
pub(super) const SIGWINCH: usize = 28;
pub(super) const SIGTTIN: usize = 21;
pub(super) const SIGTTOU: usize = 22;
const SIGCONT: usize = 18;
const SIGKILL: usize = 9;
const SIG_IGN: u64 = 1;
const WUNTRACED: usize = 2;
const POLLIN: i16 = 1;
const POLLOUT: i16 = 4;
const POLLERR: i16 = 8;
const POLLHUP: i16 = 0x10;

/// `struct termios` as the kernel exchanges it (36 bytes): four flag words, `c_line`, `c_cc[19]`.
pub(super) type Tio = [u8; 36];

pub(super) fn word(t: &Tio, i: usize) -> u32 {
    u32::from_le_bytes([t[4 * i], t[4 * i + 1], t[4 * i + 2], t[4 * i + 3]])
}

pub(super) fn set_word(t: &mut Tio, i: usize, v: u32) {
    t[4 * i..4 * i + 4].copy_from_slice(&v.to_le_bytes());
}

/// `c_cc[i]` of a termios image.
pub(super) fn cc(t: &Tio, i: usize) -> u8 {
    t[17 + i]
}

pub(super) fn set_cc(t: &mut Tio, i: usize, v: u8) {
    t[17 + i] = v;
}

pub(super) fn ioctl(fd: usize, cmd: usize, arg: usize) -> R {
    sys(Sysno::ioctl, &[fd, cmd, arg])
}

pub(super) fn open(path: &[u8], flags: usize) -> R {
    sys(Sysno::open, &[addr(path), flags, 0])
}

pub(super) fn close(fd: usize) {
    let _ = sys(Sysno::close, &[fd]);
}

/// The result as one number: the value, or minus the errno.
pub(super) fn num(r: R) -> i64 {
    match r {
        Ok(v) => v as i64,
        Err(e) => -i64::from(e.into_raw()),
    }
}

pub(super) fn errno(r: R) -> i64 {
    num(r)
}

pub(super) fn getattr(fd: usize) -> (R, Tio) {
    let mut tio = [0u8; 36];
    (ioctl(fd, TCGETS, addr_mut(&mut tio)), tio)
}

pub(super) fn setattr(fd: usize, cmd: usize, tio: &Tio) -> R {
    ioctl(fd, cmd, addr(tio))
}

/// Writes all of `bytes` to `fd` in one `write`.
pub(super) fn write(fd: usize, bytes: &[u8]) -> R {
    sys(Sysno::write, &[fd, addr(bytes), bytes.len()])
}

fn getpgrp_of(fd: usize) -> (R, i32) {
    let mut v = -1i32;
    (ioctl(fd, TIOCGPGRP, addr_mut(&mut v)), v)
}

fn getsid_of(fd: usize) -> (R, i32) {
    let mut v = -1i32;
    (ioctl(fd, TIOCGSID, addr_mut(&mut v)), v)
}

fn winsize(fd: usize) -> (R, [u16; 4]) {
    let mut ws = [0xffffu16; 4];
    (ioctl(fd, TIOCGWINSZ, addr_mut(&mut ws)), ws)
}

fn pipe() -> (usize, usize) {
    let mut fds = [0u32; 2];
    let _ = sys(Sysno::pipe2, &[addr_mut(&mut fds), 0]);
    (fds[0] as usize, fds[1] as usize)
}

/// Runs `body` in a forked child and returns the `N` numbers it filled in (or `[i64::MIN; N]`
/// when it did not get to report), after reaping it.
fn in_child<const N: usize>(body: impl FnOnce(&mut [i64; N])) -> [i64; N] {
    let (rfd, wfd) = pipe();
    let pid = spawn(|| {
        close(rfd);
        let mut out = [i64::MIN; N];
        body(&mut out);
        let _ = sys(Sysno::write, &[wfd, addr(&out), 8 * N]);
        0
    });
    close(wfd);
    let mut out = [i64::MIN; N];
    let got = sys(Sysno::read, &[rfd, addr_mut(&mut out), 8 * N]);
    if got != Ok(8 * N) {
        out = [i64::MIN; N];
    }
    close(rfd);
    let _ = wait4(pid as isize, 0);
    out
}

static HANDLED: AtomicUsize = AtomicUsize::new(0);

extern "C" fn on_signal(_sig: i32) {
    HANDLED.fetch_add(1, Relaxed);
}

fn mknod(path: &[u8], dev: usize) -> R {
    sys(Sysno::mknod, &[addr(path), S_IFCHR | 0o600, dev])
}

pub fn run() -> bool {
    let mut t = T::new("tty");
    reap_all();
    t.eq(
        "mknod-ttyS0",
        errno(mknod(b"/dev/ttyS0\0", (4 << 8) | 64)),
        0,
    );
    t.eq("mknod-tty", errno(mknod(b"/dev/tty\0", 5 << 8)), 0);
    defaults(&mut t);
    winsize_ioctls(&mut t);
    termios_sets(&mut t);
    speeds(&mut t);
    small_ioctls(&mut t);
    flow_control(&mut t);
    no_controlling_terminal(&mut t);
    controlling_terminal(&mut t);
    t.finish()
}

fn defaults(t: &mut T) {
    // tty_std_termios with the 8250 console's c_cflag (B9600 | CS8 | CREAD | HUPCL | CLOCAL).
    let mut want: Tio = [0; 36];
    for (i, w) in [0o2400u32, 0o5, 0o6275, 0o105_073].into_iter().enumerate() {
        set_word(&mut want, i, w);
    }
    want[17..34].copy_from_slice(&[3, 28, 127, 21, 4, 0, 1, 0, 17, 19, 26, 0, 18, 15, 23, 22, 0]);
    for fd in 0..3 {
        let (r, got) = getattr(fd);
        t.eq(format_args!("tcgets-fd{fd}"), (num(r), got), (0, want));
    }
    let mut t2 = [0u8; 44];
    t.eq(
        "tcgets2",
        (
            num(ioctl(0, TCGETS2, addr_mut(&mut t2))),
            t2[..36] == want,
            t2[36..] == [0x80, 0x25, 0, 0, 0x80, 0x25, 0, 0],
        ),
        (0, true, true),
    );
    let mut ta = [0u8; 18];
    let mut want_a = [0u8; 18];
    for (i, w) in [0o2400u16, 0o5, 0o6275, 0o105_073].into_iter().enumerate() {
        want_a[2 * i..2 * i + 2].copy_from_slice(&w.to_le_bytes());
    }
    want_a[8] = 0;
    want_a[9..17].copy_from_slice(&[3, 28, 127, 21, 4, 0, 1, 0]);
    t.eq(
        "tcgeta",
        (num(ioctl(0, TCGETA, addr_mut(&mut ta))), ta),
        (0, want_a),
    );
    let mut locked = [0xaau8; 36];
    t.eq(
        "tiocglcktrmios-nothing-locked",
        (num(ioctl(0, TIOCGLCKTRMIOS, addr_mut(&mut locked))), locked),
        (0, [0u8; 36]),
    );
    t.eq(
        "tcgets-fault",
        errno(ioctl(0, TCGETS, BAD)),
        -i64::from(Errno::EFAULT.into_raw()),
    );
    t.eq(
        "tcgets2-fault",
        errno(ioctl(0, TCGETS2, BAD)),
        -i64::from(Errno::EFAULT.into_raw()),
    );
    t.eq("tcgetx", errno(ioctl(0, TCGETX, 0)), -25);
}

fn winsize_ioctls(t: &mut T) {
    t.eq("winsize-default", winsize(0), (Ok(0), [0, 0, 0, 0]));
    let set = [24u16, 80, 640, 480];
    t.eq("tiocswinsz", errno(ioctl(0, TIOCSWINSZ, addr(&set))), 0);
    t.eq("winsize-set", winsize(1), (Ok(0), set));
    t.eq(
        "winsize-via-ttyS0",
        {
            let fd = open(b"/dev/ttyS0\0", O_RDWR | O_NOCTTY).unwrap_or(usize::MAX);
            let r = winsize(fd);
            close(fd);
            r
        },
        (Ok(0), set),
    );
    t.eq("tiocswinsz-fault", errno(ioctl(0, TIOCSWINSZ, BAD)), -14);
    t.eq("tiocgwinsz-fault", errno(ioctl(0, TIOCGWINSZ, BAD)), -14);
    let zero = [0u16; 4];
    let _ = ioctl(0, TIOCSWINSZ, addr(&zero));
    t.eq("winsize-reset", winsize(0), (Ok(0), zero));
}

fn termios_sets(t: &mut T) {
    let (_, orig) = getattr(0);
    // TCSETS: ECHO and ICANON off.
    let mut raw = orig;
    set_word(&mut raw, 3, word(&orig, 3) & !(ECHO | ICANON));
    t.eq("tcsets", errno(setattr(0, TCSETS, &raw)), 0);
    t.eq("tcsets-readback", getattr(1).1 == raw, true);
    t.eq("tcsets-restore", errno(setattr(0, TCSETS, &orig)), 0);
    t.eq("tcsets-restored", getattr(0).1 == orig, true);
    // The waiting and flushing variants behave as TCSETS here (nothing is queued).
    for (name, cmd) in [("tcsetsw", TCSETSW), ("tcsetsf", TCSETSF)] {
        t.eq(format_args!("{name}"), errno(setattr(0, cmd, &raw)), 0);
        t.eq(format_args!("{name}-readback"), getattr(0).1 == raw, true);
        let _ = setattr(0, TCSETS, &orig);
    }
    // termios2 (44 bytes): the speeds ride along.
    let mut t2 = [0u8; 44];
    t2[..36].copy_from_slice(&raw);
    t2[36..40].copy_from_slice(&9600u32.to_le_bytes());
    t2[40..44].copy_from_slice(&9600u32.to_le_bytes());
    for (name, cmd) in [
        ("tcsets2", TCSETS2),
        ("tcsetsw2", TCSETSW2),
        ("tcsetsf2", TCSETSF2),
    ] {
        t.eq(format_args!("{name}"), errno(ioctl(0, cmd, addr(&t2))), 0);
        t.eq(format_args!("{name}-readback"), getattr(0).1 == raw, true);
        let _ = setattr(0, TCSETS, &orig);
    }
    // termio (18 bytes): the low 16 bits of each flag word and the first 8 characters.
    let mut ta = [0u8; 18];
    let _ = ioctl(0, TCGETA, addr_mut(&mut ta));
    let lflag = u16::from_le_bytes([ta[6], ta[7]]) & !((ECHO | ICANON) as u16);
    ta[6..8].copy_from_slice(&lflag.to_le_bytes());
    ta[9 + VMIN] = 4;
    for (name, cmd) in [
        ("tcseta", TCSETA),
        ("tcsetaw", TCSETAW),
        ("tcsetaf", TCSETAF),
    ] {
        t.eq(format_args!("{name}"), errno(ioctl(0, cmd, addr(&ta))), 0);
        let (_, now) = getattr(0);
        t.eq(
            format_args!("{name}-readback"),
            (word(&now, 3) & (ECHO | ICANON), cc(&now, VMIN)),
            (0, 4),
        );
        let _ = setattr(0, TCSETS, &orig);
    }
    t.eq(
        "tcsets-fault",
        errno(setattr(0, TCSETS, &orig).and(ioctl(0, TCSETS, BAD))),
        -14,
    );
    t.eq("tcsets2-fault", errno(ioctl(0, TCSETS2, BAD)), -14);
    t.eq("tcseta-fault", errno(ioctl(0, TCSETA, BAD)), -14);
    // TIOCSLCKTRMIOS locks bits: a later TCSETS cannot change them.
    let mut lock: Tio = [0; 36];
    set_word(&mut lock, 3, ECHO);
    t.eq(
        "tiocslcktrmios",
        errno(ioctl(0, TIOCSLCKTRMIOS, addr(&lock))),
        0,
    );
    let mut noecho = orig;
    set_word(&mut noecho, 3, word(&orig, 3) & !ECHO);
    t.eq("locked-echo-set", errno(setattr(0, TCSETS, &noecho)), 0);
    t.eq("locked-echo-unchanged", word(&getattr(0).1, 3) & ECHO, ECHO);
    let none: Tio = [0; 36];
    let _ = ioctl(0, TIOCSLCKTRMIOS, addr(&none));
    let _ = setattr(0, TCSETS, &orig);
    t.eq("termios-restored", getattr(0).1 == orig, true);
}

fn speeds(t: &mut T) {
    let (_, orig) = getattr(0);
    let speed = |t2: &[u8; 44]| {
        (
            u32::from_le_bytes([t2[8], t2[9], t2[10], t2[11]]),
            u32::from_le_bytes([t2[36], t2[37], t2[38], t2[39]]),
            u32::from_le_bytes([t2[40], t2[41], t2[42], t2[43]]),
        )
    };
    let get2 = || {
        let mut t2 = [0u8; 44];
        let r = ioctl(0, TCGETS2, addr_mut(&mut t2));
        (num(r), speed(&t2))
    };
    // A termios2 with the given c_cflag baud bits and speeds.
    let set2 = |baud: u32, ispeed: u32, ospeed: u32| {
        let mut t2 = [0u8; 44];
        t2[..36].copy_from_slice(&orig);
        let cflag = (word(&orig, 2) & !CBAUD) | baud;
        t2[8..12].copy_from_slice(&cflag.to_le_bytes());
        t2[36..40].copy_from_slice(&ispeed.to_le_bytes());
        t2[40..44].copy_from_slice(&ospeed.to_le_bytes());
        num(ioctl(0, TCSETS2, addr(&t2)))
    };
    let cbaud = || word(&getattr(0).1, 2) & CBAUD;
    let flags_base = word(&orig, 2) & !CBAUD;
    t.eq(
        "baud-9600-default",
        get2(),
        (0, (flags_base | 0o15, 9600, 9600)),
    );
    t.eq(
        "baud-19200",
        (set2(B19200, 0, 0), cbaud(), get2().1.1),
        (0, B19200, 19200),
    );
    t.eq("baud-38400", (set2(B38400, 0, 0), cbaud()), (0, B38400));
    t.eq(
        "baud-57600",
        (set2(B57600, 0, 0), cbaud(), get2().1.2),
        (0, B57600, 57600),
    );
    t.eq(
        "baud-115200",
        (set2(B115200, 0, 0), cbaud(), get2().1.2),
        (0, B115200, 115_200),
    );
    // 230400 is above what the 8250 divides down to (115200): the old speed is kept.
    t.eq(
        "baud-230400-refused",
        (set2(B230400, 0, 0), cbaud(), get2().1.2),
        (0, B115200, 115_200),
    );
    // BOTHER with an exact speed the chip can do: kept as BOTHER, or a Bxxx code if close.
    t.eq(
        "baud-bother-12345",
        (set2(BOTHER, 12345, 12345), cbaud(), get2().1.2),
        (0, BOTHER, 12345),
    );
    t.eq(
        "baud-bother-57600-becomes-code",
        (set2(BOTHER, 57600, 57600), cbaud(), get2().1.2),
        (0, B57600, 57600),
    );
    t.eq(
        "baud-bother-too-fast",
        (set2(BOTHER, 3_000_000, 3_000_000), get2().1.2),
        (0, 57600),
    );
    // B0 ("hang up"): the speed words are zero and the code stays.
    t.eq("baud-0", (set2(B0, 0, 0), cbaud()), (0, B0));
    t.eq("baud-0-speeds", get2().1, (word(&getattr(0).1, 2), 0, 0));
    t.eq("baud-back", (set2(B38400, 0, 0), cbaud()), (0, B38400));
    // The old termios call carries no speeds: the code is decoded.
    let mut o = orig;
    set_word(&mut o, 2, flags_base | B19200);
    t.eq(
        "tcsets-baud",
        (errno(setattr(0, TCSETS, &o)), get2().1.2),
        (0, 19200),
    );
    let _ = setattr(0, TCSETS, &orig);
    t.eq("baud-restored", getattr(0).1 == orig, true);
}

fn small_ioctls(t: &mut T) {
    let mut v = -1i32;
    t.eq(
        "tiocgetd",
        (num(ioctl(0, TIOCGETD, addr_mut(&mut v))), v),
        (0, 0),
    );
    t.eq("tiocsetd-ntty", errno(ioctl(0, TIOCSETD, addr(&0i32))), 0);
    t.eq(
        "tiocsetd-invalid",
        errno(ioctl(0, TIOCSETD, addr(&100i32))),
        -22,
    );
    t.eq(
        "tiocsetd-negative",
        errno(ioctl(0, TIOCSETD, addr(&-1i32))),
        -22,
    );
    let mut e = -1i32;
    t.eq(
        "tiocgexcl-off",
        (num(ioctl(0, TIOCGEXCL, addr_mut(&mut e))), e),
        (0, 0),
    );
    t.eq("tiocexcl", errno(ioctl(0, TIOCEXCL, 0)), 0);
    t.eq(
        "tiocgexcl-on",
        (num(ioctl(0, TIOCGEXCL, addr_mut(&mut e))), e),
        (0, 1),
    );
    t.eq("tiocnxcl", errno(ioctl(0, TIOCNXCL, 0)), 0);
    t.eq(
        "tiocgexcl-off-again",
        (num(ioctl(0, TIOCGEXCL, addr_mut(&mut e))), e),
        (0, 0),
    );
    let mut dev = 0u32;
    t.eq(
        "tiocgdev",
        (num(ioctl(0, TIOCGDEV, addr_mut(&mut dev))), dev),
        (0, (4 << 8) | 64),
    );
    let (_, orig) = getattr(0);
    let mut soft = -1i32;
    t.eq(
        "tiocgsoftcar",
        (num(ioctl(0, TIOCGSOFTCAR, addr_mut(&mut soft))), soft),
        (0, 1),
    );
    t.eq(
        "tiocssoftcar-off",
        errno(ioctl(0, TIOCSSOFTCAR, addr(&0i32))),
        0,
    );
    t.eq("softcar-clears-clocal", word(&getattr(0).1, 2) & CLOCAL, 0);
    t.eq(
        "tiocssoftcar-on",
        errno(ioctl(0, TIOCSSOFTCAR, addr(&1i32))),
        0,
    );
    t.eq(
        "softcar-sets-clocal",
        word(&getattr(0).1, 2) & CLOCAL,
        CLOCAL,
    );
    let _ = setattr(0, TCSETS, &orig);
    // FIONREAD/TIOCINQ and TIOCOUTQ on an idle tty.
    let mut n = -1i32;
    t.eq(
        "fionread",
        (num(ioctl(0, FIONREAD, addr_mut(&mut n))), n),
        (0, 0),
    );
    n = -1;
    t.eq(
        "tiocoutq",
        (num(ioctl(0, TIOCOUTQ, addr_mut(&mut n))), n),
        (0, 0),
    );
    t.eq("fionread-fault", errno(ioctl(0, FIONREAD, BAD)), -14);
    // TCFLSH: the three queue selectors, and an invalid one.
    for q in 0..3 {
        t.eq(format_args!("tcflsh-{q}"), errno(ioctl(0, TCFLSH, q)), 0);
    }
    t.eq("tcflsh-invalid", errno(ioctl(0, TCFLSH, 3)), -22);
    t.eq("tcxonc-invalid", errno(ioctl(0, TCXONC, 4)), -22);
    // tcdrain: nothing queued, returns at once.
    t.eq("tcsbrk-drain", errno(ioctl(0, TCSBRK, 1)), 0);
    // TIOCCONS by root on a /dev/console file clears the (absent) redirection.
    t.eq("tioccons-console", errno(ioctl(0, TIOCCONS, 0)), 0);
    // Not a terminal.
    let (r, w) = pipe();
    let mut tio = [0u8; 36];
    t.eq(
        "pipe-tcgets",
        errno(ioctl(r, TCGETS, addr_mut(&mut tio))),
        -25,
    );
    t.eq(
        "pipe-tiocgwinsz",
        errno(ioctl(w, TIOCGWINSZ, addr_mut(&mut [0u16; 4]))),
        -25,
    );
    close(r);
    close(w);
    let _ = sys(
        Sysno::mknod,
        &[addr(b"/dev/null\0"), S_IFCHR | 0o666, (1 << 8) | 3],
    );
    let null = open(b"/dev/null\0", O_RDWR).unwrap_or(usize::MAX);
    t.eq(
        "null-tcgets",
        errno(ioctl(null, TCGETS, addr_mut(&mut tio))),
        -25,
    );
    close(null);
    t.eq("unknown-ioctl", errno(ioctl(0, 0xdead, 0)), -25);
    // TIOCSTI by root injects a byte into the input queue.
    let before = {
        let mut n = -1i32;
        let _ = ioctl(0, FIONREAD, addr_mut(&mut n));
        n
    };
    t.eq("tiocsti", errno(ioctl(0, TIOCSTI, addr(&b'\n'))), 0);
    let mut after = -1i32;
    let _ = ioctl(0, FIONREAD, addr_mut(&mut after));
    t.eq("tiocsti-queued", (before, after), (0, 1));
    let mut byte = [0u8; 2];
    t.eq(
        "tiocsti-read",
        (sys(Sysno::read, &[0, addr_mut(&mut byte), 2]), byte[0]),
        (Ok(1), b'\n'),
    );
    t.eq("tiocsti-fault", errno(ioctl(0, TIOCSTI, BAD)), -14);
    let _ = (VEOF, ECHOE, ECHOK, TOSTOP, ICRNL, OPOST, ONLCR);
}

fn flow_control(t: &mut T) {
    // TCOOFF stops the transmitter: what is written stays queued (TIOCOUTQ) until TCOON. Nothing
    // is printed while the tty is stopped (the line would join the queue), and the queue starts
    // empty (tcdrain: the serial line sends its earlier output at its own pace).
    let queued = |fd: usize| {
        let mut n = -1i32;
        let _ = ioctl(fd, TIOCOUTQ, addr_mut(&mut n));
        n
    };
    let _ = ioctl(0, TCSBRK, 1);
    let off = num(ioctl(0, TCXONC, 0));
    let written = num(write(1, b"x\n"));
    let q_stopped = queued(0);
    let on = num(ioctl(0, TCXONC, 1));
    let _ = ioctl(0, TCSBRK, 1);
    let q_after = queued(0);
    t.eq("tcxonc-tcooff", off, 0);
    t.eq("write-while-stopped", written, 2);
    // "x\n" is "x\r\n" after ONLCR.
    t.eq("outq-while-stopped", q_stopped, 3);
    t.eq("tcxonc-tcoon", on, 0);
    t.eq("outq-after-tcoon", q_after, 0);
    // Writes are held while stopped, up to the 4096 bytes the queue can take.
    let fd = open(b"/dev/ttyS0\0", O_RDWR | O_NOCTTY | O_NONBLOCK).unwrap_or(usize::MAX);
    let page = [b'.'; 3000];
    let _ = ioctl(0, TCSBRK, 1);
    let _ = ioctl(0, TCXONC, 0);
    let w1 = num(write(fd, &page));
    // 1096 bytes of room are left: a non-blocking write takes what fits.
    let w2 = num(write(fd, &page));
    let w3 = num(write(fd, &page));
    let q_full = queued(fd);
    let mut fds = [pollfd(fd, POLLOUT)];
    let polled = (num(poll(&mut fds, 0)), fds[0].revents & POLLOUT);
    let _ = ioctl(0, TCFLSH, 1);
    let q_flushed = queued(fd);
    let _ = ioctl(0, TCXONC, 1);
    close(fd);
    let _ = ioctl(0, TCSBRK, 1);
    t.eq("fill-queue-1", w1, 3000);
    t.eq("fill-queue-2", w2, 1096);
    t.eq("fill-queue-full", w3, -11);
    t.eq("outq-full", q_full, 4096);
    t.eq("poll-full-queue-not-writable", polled, (0, 0));
    t.eq("tcflsh-output-empties-queue", q_flushed, 0);
    let _ = (POLLIN, POLLERR, POLLHUP);
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct Pollfd {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
}

pub(super) fn pollfd(fd: usize, events: i16) -> Pollfd {
    Pollfd {
        fd: fd as i32,
        events,
        revents: -1,
    }
}

pub(super) fn poll(fds: &mut [Pollfd], ms: i32) -> R {
    sys(Sysno::poll, &[addr_mut(fds), fds.len(), ms as usize])
}

fn no_controlling_terminal(t: &mut T) {
    // init is not a session leader and has no controlling terminal.
    t.eq(
        "tiocgpgrp-no-ctty",
        getpgrp_of(0).0.map_err(|e| e.into_raw()),
        Err(25),
    );
    t.eq(
        "tiocgsid-no-ctty",
        getsid_of(0).0.map_err(|e| e.into_raw()),
        Err(25),
    );
    t.eq(
        "tiocspgrp-no-ctty",
        errno(ioctl(0, TIOCSPGRP, addr(&1i32))),
        -25,
    );
    t.eq("tiocnotty-no-ctty", errno(ioctl(0, TIOCNOTTY, 0)), -25);
    t.eq("tiocsctty-not-leader", errno(ioctl(0, TIOCSCTTY, 0)), -1);
    t.eq(
        "open-dev-tty-no-ctty",
        errno(open(b"/dev/tty\0", O_RDWR)),
        -6,
    );
    // A process that is not the session leader does not acquire the terminal by opening it.
    let fd = open(b"/dev/ttyS0\0", O_RDWR).unwrap_or(usize::MAX);
    t.eq(
        "open-ttyS0-no-leader-no-ctty",
        getpgrp_of(fd).0.map_err(|e| e.into_raw()),
        Err(25),
    );
    close(fd);
    let _ = (
        SIGCHLD,
        SIGHUP,
        sigaction,
        SIGKILL,
        SIGCONT,
        SIG_IGN,
        WUNTRACED,
        fn_addr(on_signal as *const ()),
    );
}

fn setsid() -> i64 {
    num(sys(Sysno::setsid, &[]))
}

fn getpid() -> i64 {
    super::getpid() as i64
}

fn getpgid() -> i64 {
    num(sys(Sysno::getpgid, &[0]))
}

fn setpgid(pid: usize, pgid: usize) -> i64 {
    num(sys(Sysno::setpgid, &[pid, pgid]))
}

fn kill(pid: usize, sig: usize) -> i64 {
    num(sys(Sysno::kill, &[pid, sig]))
}

fn block(sig: usize) {
    let mask = 1u64 << (sig - 1);
    let _ = sys(Sysno::rt_sigprocmask, &[0, addr(&mask), 0, 8]);
}

const SIGTSTP_STOPPED: i32 = 0x157f; // stopped by SIGTTIN (the name is historical)
const SIGTTOU_STOPPED: i32 = 0x167f;

fn pgrp_of(fd: usize) -> i64 {
    let (r, v) = getpgrp_of(fd);
    if r.is_ok() { i64::from(v) } else { num(r) }
}

fn sid_of(fd: usize) -> i64 {
    let (r, v) = getsid_of(fd);
    if r.is_ok() { i64::from(v) } else { num(r) }
}

/// The session-leader scenarios. Each runs in a child that becomes a session leader (`setsid`),
/// reports numbers through a pipe and exits; when it exits with the terminal as its controlling
/// terminal the tty is hung up, which `/dev/console` files do not notice.
fn controlling_terminal(t: &mut T) {
    open_acquires(t);
    exit_hangup_then_reacquire(t);
    tiocsctty_rules(t);
    tiocspgrp_rules(t);
    winch(t);
    background_reads(t);
    background_writes(t);
    tiocnotty(t);
    setsid_clears(t);
    vhangup(t);
    leader_exit_hups_group(t);
}

fn open_acquires(t: &mut T) {
    let r = in_child::<10>(|o| {
        o[0] = setsid() - getpid();
        // After setsid the process has no controlling terminal, console descriptor or not.
        o[1] = pgrp_of(0);
        let fd = open(b"/dev/ttyS0\0", O_RDWR).unwrap_or(usize::MAX);
        o[2] = pgrp_of(fd) - getpid();
        o[3] = sid_of(fd) - getpid();
        // The console file is the same tty: now the controlling one.
        o[4] = pgrp_of(0) - getpid();
        let tty = open(b"/dev/tty\0", O_RDWR);
        o[5] = i64::from(tty.is_ok());
        o[6] = pgrp_of(tty.unwrap_or(usize::MAX)) - getpid();
        o[7] = getpgid() - getpid();
        // TIOCSCTTY by the owner again succeeds.
        o[8] = num(ioctl(fd, TIOCSCTTY, 0));
        // Opening it with O_NOCTTY does not matter once it is the terminal.
        o[9] = num(open(b"/dev/ttyS0\0", O_RDWR | O_NOCTTY).map(|f| f));
        o[9] = i64::from(o[9] >= 0);
    });
    t.eq(
        "open-ttyS0-session-leader-acquires",
        r,
        [0, -25, 0, 0, 0, 1, 0, 0, 0, 1],
    );
}

fn exit_hangup_then_reacquire(t: &mut T) {
    // The leader of the previous scenario exited holding the terminal: it was hung up, which
    // cleared its session and foreground group, so another session can take it by open.
    let (_, tio) = getattr(0);
    t.eq(
        "console-still-works-after-hangup",
        (num(write(1, b"")), word(&tio, 3) & ICANON),
        (0, ICANON),
    );
    let r = in_child::<4>(|o| {
        let _ = setsid();
        let fd = open(b"/dev/ttyS0\0", O_RDWR).unwrap_or(usize::MAX);
        o[0] = pgrp_of(fd) - getpid();
        o[1] = num(ioctl(fd, TCGETS, addr_mut(&mut [0u8; 36])));
        o[2] = pgrp_of(0) - getpid();
        o[3] = 1;
    });
    t.eq("reacquire-after-hangup", r, [0, 0, 0, 1]);
}

fn tiocsctty_rules(t: &mut T) {
    // A: leader that takes the terminal with TIOCSCTTY on the console file and waits.
    let (ready_r, ready_w) = pipe();
    let (go_r, go_w) = pipe();
    let (res_r, res_w) = pipe();
    let a = spawn(|| {
        close(ready_r);
        close(go_w);
        close(res_r);
        let _ = setsid();
        let mut o = [i64::MIN; 4];
        o[0] = num(ioctl(0, TIOCSCTTY, 0));
        o[1] = num(ioctl(0, TIOCSCTTY, 0));
        o[2] = sid_of(0) - getpid();
        let _ = sys(Sysno::write, &[ready_w, addr(&b"r"), 1]);
        let mut b = [0u8; 1];
        let _ = sys(Sysno::read, &[go_r, addr_mut(&mut b), 1]);
        // B stole the terminal: this session no longer has it.
        o[3] = pgrp_of(0);
        let _ = sys(Sysno::write, &[res_w, addr(&o), 32]);
        0
    });
    close(ready_w);
    close(go_r);
    close(res_w);
    let mut b = [0u8; 1];
    let _ = sys(Sysno::read, &[ready_r, addr_mut(&mut b), 1]);
    let r = in_child::<6>(|o| {
        // Not a leader: a child of a leader has the terminal as inherited state only; this
        // process is the child of init and not a leader.
        o[0] = num(ioctl(0, TIOCSCTTY, 0));
        let _ = setsid();
        o[1] = num(ioctl(0, TIOCSCTTY, 0));
        o[2] = num(ioctl(0, TIOCSCTTY, 1));
        o[3] = sid_of(0) - getpid();
        o[4] = num(ioctl(0, TIOCSCTTY, 0));
        o[5] = 1;
    });
    let _ = sys(Sysno::write, &[go_w, addr(&b"g"), 1]);
    let mut o = [i64::MIN; 4];
    let got = sys(Sysno::read, &[res_r, addr_mut(&mut o), 32]);
    let _ = wait4(a as isize, 0);
    close(ready_r);
    close(go_w);
    close(res_r);
    t.eq(
        "tiocsctty-owner",
        (got, o[0], o[1], o[2]),
        (Ok(32), 0, 0, 0),
    );
    t.eq("tiocsctty-steal", r, [-1, -1, 0, 0, 0, 1]);
    t.eq("tiocsctty-stolen-session-loses-terminal", o[3], -25);
}

fn tiocspgrp_rules(t: &mut T) {
    let r = in_child::<11>(|o| {
        let _ = setsid();
        let fd = open(b"/dev/ttyS0\0", O_RDWR).unwrap_or(usize::MAX);
        let me = getpid();
        o[0] = num(ioctl(fd, TIOCSPGRP, addr(&-1i32)));
        o[1] = num(ioctl(fd, TIOCSPGRP, addr(&(me as i32))));
        o[2] = pgrp_of(fd) - me;
        o[3] = num(ioctl(fd, TIOCSPGRP, addr(&9_999_999i32)));
        o[4] = num(ioctl(fd, TIOCSPGRP, addr(&0i32)));
        o[5] = num(ioctl(fd, TIOCSPGRP, BAD));
        // A group of another session.
        let (qr, qw) = pipe();
        let g = spawn(|| {
            let _ = setsid();
            let mut b = [0u8; 1];
            let _ = sys(Sysno::read, &[qr, addr_mut(&mut b), 1]);
            0
        });
        nap(30);
        o[6] = num(ioctl(fd, TIOCSPGRP, addr(&(g as i32))));
        // init's own group is another session's too.
        o[7] = num(ioctl(fd, TIOCSPGRP, addr(&1i32)));
        // A process group of the session: the terminal's foreground group changes to it. (The
        // leader is then a background process in an orphaned group: it cannot change it back,
        // the check answers ENOTTY.)
        let (pr, pw) = pipe();
        let c = spawn(|| {
            let _ = setpgid(0, 0);
            let mut b = [0u8; 1];
            let _ = sys(Sysno::read, &[pr, addr_mut(&mut b), 1]);
            0
        });
        let _ = setpgid(c, c);
        o[8] = num(ioctl(fd, TIOCSPGRP, addr(&(c as i32))));
        o[9] = pgrp_of(fd) - c as i64;
        let _ = sys(Sysno::write, &[pw, addr(&b"x"), 1]);
        let _ = sys(Sysno::write, &[qw, addr(&b"x"), 1]);
        let _ = wait4(c as isize, 0);
        let _ = wait4(g as isize, 0);
        o[10] = 1;
    });
    t.eq(
        "tiocspgrp-rules",
        r,
        [-22, 0, 0, -3, -3, -14, -1, -1, 0, 0, 1],
    );
}

fn winch(t: &mut T) {
    let r = in_child::<5>(|o| {
        let _ = setsid();
        let fd = open(b"/dev/ttyS0\0", O_RDWR).unwrap_or(usize::MAX);
        let _ = sigaction(SIGWINCH, fn_addr(on_signal as *const ()), 0);
        HANDLED.store(0, Relaxed);
        let a = [30u16, 100, 0, 0];
        o[0] = num(ioctl(fd, TIOCSWINSZ, addr(&a)));
        o[1] = HANDLED.load(Relaxed) as i64;
        // The same size again: no signal.
        o[2] = num(ioctl(fd, TIOCSWINSZ, addr(&a)));
        o[3] = HANDLED.load(Relaxed) as i64;
        let b = [0u16; 4];
        let _ = ioctl(fd, TIOCSWINSZ, addr(&b));
        o[4] = HANDLED.load(Relaxed) as i64;
    });
    t.eq("sigwinch-on-resize", r, [0, 1, 0, 1, 2]);
}

/// `read` of one byte from `fd`, as an exit status: 0 for a byte, the errno of a failure.
fn read_status(fd: usize) -> usize {
    let mut b = [0u8; 1];
    match sys(Sysno::read, &[fd, addr_mut(&mut b), 1]) {
        Ok(_) => 0,
        Err(e) => e.into_raw() as usize,
    }
}

/// `write` of a newline to `fd`, as an exit status.
fn write_status(fd: usize) -> usize {
    match write(fd, b"\n") {
        Ok(_) => 0,
        Err(e) => e.into_raw() as usize,
    }
}

/// A child in a group of its own that runs `f`; the parent's `wait4` result: how it ended.
fn bg_child(f: impl FnOnce() -> usize) -> (R, i32) {
    let c = spawn(|| {
        let _ = setpgid(0, 0);
        f()
    });
    let _ = setpgid(c, c);
    let r = wait4(c as isize, WUNTRACED);
    if let (Ok(_), s) = r {
        if s & 0xff == 0x7f {
            let _ = kill(c, SIGKILL);
            let _ = wait4(c as isize, 0);
        }
    }
    (r.0.map(|p| usize::from(p == c)), r.1)
}

fn background_reads(t: &mut T) {
    let r = in_child::<12>(|o| {
        let _ = setsid();
        let fd = open(b"/dev/ttyS0\0", O_RDWR).unwrap_or(usize::MAX);
        let (s, st) = bg_child(|| read_status(fd));
        o[0] = num(s);
        o[1] = i64::from(st);
        // SIGTTIN ignored: the read fails with EIO instead.
        let (s, st) = bg_child(|| {
            let _ = sigaction(SIGTTIN, SIG_IGN, 0);
            read_status(fd)
        });
        o[2] = num(s);
        o[3] = i64::from(st);
        // SIGTTIN blocked counts as ignored.
        let (s, st) = bg_child(|| {
            block(SIGTTIN);
            read_status(fd)
        });
        o[4] = num(s);
        o[5] = i64::from(st);
        // A /dev/console file is not subject to job control: no stop, no EIO.
        let (s, st) = bg_child(|| {
            let console = open(b"/dev/console\0", O_RDWR | O_NONBLOCK).unwrap_or(usize::MAX);
            read_status(console)
        });
        o[6] = num(s);
        o[7] = i64::from(st);
        // The foreground group itself reads without a problem (non-blocking: nothing there).
        let nb = open(b"/dev/ttyS0\0", O_RDWR | O_NONBLOCK).unwrap_or(usize::MAX);
        o[8] = read_status(nb) as i64;
        // An orphaned background group gets EIO without a signal: its only member's parent is
        // init (the middle process left).
        let (pr, pw) = pipe();
        let p = spawn(|| {
            let m = spawn(|| {
                let _ = setpgid(0, 0);
                while num(sys(Sysno::getppid, &[])) != 1 {
                    nap(10);
                }
                let code = read_status(fd);
                let _ = sys(Sysno::write, &[pw, addr(&code), 8]);
                0
            });
            let _ = m;
            0
        });
        let _ = wait4(p as isize, 0);
        let mut code = usize::MAX;
        o[9] = num(sys(Sysno::read, &[pr, addr_mut(&mut code), 8]));
        o[10] = code as i64;
        let _ = (SIGCONT, SIGTTOU_STOPPED, SIGTSTP_STOPPED);
        o[11] = 1;
    });
    t.eq(
        "background-reads",
        r,
        [
            1,
            i64::from(SIGTSTP_STOPPED),
            1,
            5 << 8,
            1,
            5 << 8,
            1,
            11 << 8,
            11,
            8,
            5,
            1,
        ],
    );
}

fn background_writes(t: &mut T) {
    let r = in_child::<15>(|o| {
        let _ = setsid();
        let fd = open(b"/dev/ttyS0\0", O_RDWR).unwrap_or(usize::MAX);
        let (_, orig) = getattr(fd);
        let mut tostop = orig;
        set_word(&mut tostop, 3, word(&orig, 3) | TOSTOP);
        // Without TOSTOP a background write goes through.
        o[0] = bg_child(|| write_status(fd)).1 as i64;
        let _ = setattr(fd, TCSETS, &tostop);
        // With TOSTOP it stops with SIGTTOU...
        let (s, st) = bg_child(|| write_status(fd));
        o[1] = num(s);
        o[2] = i64::from(st);
        // ...unless the signal is ignored or blocked...
        o[3] = bg_child(|| {
            let _ = sigaction(SIGTTOU, SIG_IGN, 0);
            write_status(fd)
        })
        .1 as i64;
        o[4] = bg_child(|| {
            block(SIGTTOU);
            write_status(fd)
        })
        .1 as i64;
        // ...and a /dev/console file never stops.
        o[5] = bg_child(|| {
            let console = open(b"/dev/console\0", O_RDWR).unwrap_or(usize::MAX);
            write_status(console)
        })
        .1 as i64;
        // A zero-length write still runs the line discipline's job-control check.
        o[14] = bg_child(|| match write(fd, b"") {
            Ok(_) => 0,
            Err(e) => e.into_raw() as usize,
        })
        .1 as i64;
        let _ = setattr(fd, TCSETS, &orig);
        // tcsetattr, TCXONC, TCFLSH and TIOCSPGRP stop a background process whatever TOSTOP is.
        for (i, cmd) in [TCSETS, TCXONC, TCFLSH, TIOCSPGRP].into_iter().enumerate() {
            let arg = match cmd {
                TCSETS => addr(&orig),
                TCXONC => 1,
                TCFLSH => 0,
                _ => addr(&1i32),
            };
            let (_, st) = bg_child(|| (-num(ioctl(fd, cmd, arg))) as usize & 0xff);
            o[6 + i] = i64::from(st);
        }
        // TIOCSWINSZ is not subject to job control.
        let ws = [0u16; 4];
        o[10] = bg_child(|| (-num(ioctl(fd, TIOCSWINSZ, addr(&ws)))) as usize & 0xff).1 as i64;
        // With SIGTTOU ignored they go through.
        o[11] = bg_child(|| {
            let _ = sigaction(SIGTTOU, SIG_IGN, 0);
            (-num(setattr(fd, TCSETS, &orig))) as usize & 0xff
        })
        .1 as i64;
        o[12] = i64::from(getattr(fd).1 == orig);
        o[13] = 1;
    });
    t.eq(
        "background-writes",
        r,
        [
            0,
            1,
            i64::from(SIGTTOU_STOPPED),
            0,
            0,
            0,
            i64::from(SIGTTOU_STOPPED),
            i64::from(SIGTTOU_STOPPED),
            i64::from(SIGTTOU_STOPPED),
            i64::from(SIGTTOU_STOPPED),
            0,
            0,
            1,
            1,
            i64::from(SIGTTOU_STOPPED),
        ],
    );
}

fn tiocnotty(t: &mut T) {
    let r = in_child::<10>(|o| {
        let _ = setsid();
        let fd = open(b"/dev/ttyS0\0", O_RDWR).unwrap_or(usize::MAX);
        let _ = sigaction(SIGHUP, SIG_IGN, 0);
        // A non-leader gives up the terminal for itself only.
        let c = spawn(|| {
            let before = pgrp_of(fd) > 0;
            let notty = num(ioctl(fd, TIOCNOTTY, 0));
            let after = pgrp_of(fd);
            usize::from(before) | usize::from(notty == 0) << 1 | usize::from(after == -25) << 2
        });
        o[0] = wait4(c as isize, 0).1 as i64 >> 8;
        o[1] = i64::from(pgrp_of(fd) > 0);
        // A member of the foreground group counts the SIGHUP the leader's TIOCNOTTY sends.
        let (ready_r, ready_w) = pipe();
        let (rep_r, rep_w) = pipe();
        let h = spawn(|| {
            let _ = sigaction(SIGHUP, fn_addr(on_signal as *const ()), 0);
            HANDLED.store(0, Relaxed);
            let _ = sys(Sysno::write, &[ready_w, addr(&b"r"), 1]);
            while HANDLED.load(Relaxed) == 0 {
                nap(10);
            }
            let out = [HANDLED.load(Relaxed) as i64, pgrp_of(fd)];
            let _ = sys(Sysno::write, &[rep_w, addr(&out), 16]);
            0
        });
        let mut b = [0u8; 1];
        let _ = sys(Sysno::read, &[ready_r, addr_mut(&mut b), 1]);
        nap(30);
        o[2] = num(ioctl(fd, TIOCNOTTY, 0));
        let mut rep = [i64::MIN; 2];
        let _ = sys(Sysno::read, &[rep_r, addr_mut(&mut rep), 16]);
        let _ = wait4(h as isize, 0);
        o[3] = rep[0];
        o[4] = rep[1];
        o[5] = pgrp_of(fd);
        o[6] = num(open(b"/dev/tty\0", O_RDWR));
        // The leader may take it again: the terminal belongs to no session now.
        o[7] = num(ioctl(fd, TIOCSCTTY, 0));
        o[8] = pgrp_of(fd) - getpid();
        // TIOCNOTTY by a process that is not on that terminal.
        o[9] = num(ioctl(5000, TIOCNOTTY, 0));
    });
    t.eq("tiocnotty", r, [7, 1, 0, 1, -25, -25, -6, 0, 0, -9]);
}

fn setsid_clears(t: &mut T) {
    let r = in_child::<6>(|o| {
        let _ = setsid();
        let fd = open(b"/dev/ttyS0\0", O_RDWR).unwrap_or(usize::MAX);
        let c = spawn(|| {
            let inherited = pgrp_of(fd) > 0;
            let _ = setsid();
            let cleared = pgrp_of(fd) == -25;
            // The new session leader does not take a terminal that belongs to another session.
            let again = open(b"/dev/ttyS0\0", O_RDWR).unwrap_or(usize::MAX);
            let not_taken = pgrp_of(again) == -25;
            usize::from(inherited) | usize::from(cleared) << 1 | usize::from(not_taken) << 2
        });
        o[0] = wait4(c as isize, 0).1 as i64 >> 8;
        o[1] = i64::from(pgrp_of(fd) > 0);
        o[2] = 1;
        o[3] = 0;
        o[4] = 0;
        o[5] = 0;
    });
    t.eq("setsid-clears-terminal", [r[0], r[1], r[2]], [7, 1, 1]);
}

fn vhangup(t: &mut T) {
    let r = in_child::<14>(|o| {
        let _ = setsid();
        let fd = open(b"/dev/ttyS0\0", O_RDWR).unwrap_or(usize::MAX);
        let _ = sigaction(SIGHUP, fn_addr(on_signal as *const ()), 0);
        HANDLED.store(0, Relaxed);
        o[0] = num(ioctl(fd, TIOCVHANGUP, 0));
        o[1] = HANDLED.load(Relaxed) as i64;
        let mut b = [0u8; 1];
        o[2] = num(sys(Sysno::read, &[fd, addr_mut(&mut b), 1]));
        o[3] = num(write(fd, b"x"));
        let mut fds = [pollfd(fd, POLLIN | POLLOUT)];
        o[4] = num(poll(&mut fds, 0));
        o[5] = i64::from(fds[0].revents);
        o[6] = num(ioctl(fd, TCGETS, addr_mut(&mut [0u8; 36])));
        o[7] = num(ioctl(fd, TIOCSPGRP, addr(&1i32)));
        // The /dev/console files are untouched, and the process lost its terminal.
        o[8] = num(ioctl(0, TCGETS, addr_mut(&mut [0u8; 36])));
        o[9] = pgrp_of(0);
        // Opening it again gives a working file (and, for the leader, the terminal again).
        let again = open(b"/dev/ttyS0\0", O_RDWR).unwrap_or(usize::MAX);
        o[10] = num(ioctl(again, TCGETS, addr_mut(&mut [0u8; 36])));
        o[11] = pgrp_of(again) - getpid();
        // The old file stays hung up.
        o[12] = num(ioctl(fd, TCGETS, addr_mut(&mut [0u8; 36])));
        o[13] = 1;
    });
    t.eq(
        "tiocvhangup",
        r,
        [
            0,
            1,
            0,
            -5,
            1,
            i64::from(POLLIN | POLLOUT | POLLERR | POLLHUP),
            -5,
            -25,
            0,
            -25,
            0,
            0,
            -5,
            1,
        ],
    );
}

fn leader_exit_hups_group(t: &mut T) {
    // The session leader exits with the terminal: its foreground group gets SIGHUP.
    let (rep_r, rep_w) = pipe();
    let l = spawn(|| {
        let _ = setsid();
        let fd = open(b"/dev/ttyS0\0", O_RDWR).unwrap_or(usize::MAX);
        let (ready_r, ready_w) = pipe();
        let h = spawn(|| {
            let _ = sigaction(SIGHUP, fn_addr(on_signal as *const ()), 0);
            HANDLED.store(0, Relaxed);
            let _ = sys(Sysno::write, &[ready_w, addr(&b"r"), 1]);
            while HANDLED.load(Relaxed) == 0 {
                nap(10);
            }
            let out = [HANDLED.load(Relaxed) as i64, pgrp_of(fd)];
            let _ = sys(Sysno::write, &[rep_w, addr(&out), 16]);
            0
        });
        let mut b = [0u8; 1];
        let _ = sys(Sysno::read, &[ready_r, addr_mut(&mut b), 1]);
        let _ = h;
        // Leave without waiting: init adopts the member.
        0
    });
    close(rep_w);
    let _ = wait4(l as isize, 0);
    let mut rep = [i64::MIN; 2];
    let got = sys(Sysno::read, &[rep_r, addr_mut(&mut rep), 16]);
    close(rep_r);
    reap_all();
    // The member was signalled once; the file it inherited is hung up (EIO).
    t.eq("leader-exit-sighup-to-group", (got, rep), (Ok(16), [1, -5]));
}
