// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: include/uapi/asm-generic/termbits.h and
// termbits-common.h (GPL-2.0 WITH Linux-syscall-note: the flag bits, `struct
// termios`/`termios2`/`ktermios`), include/uapi/asm-generic/termios.h (`struct
// termio`, `NCC`), include/linux/termios_internal.h (`INIT_C_CC`),
// drivers/tty/tty_io.c (`tty_std_termios`, 124-135), drivers/tty/serial/
// serial_core.c (`init_termios` of the serial driver, 2789-2791; `uart_get_baud_rate`
// 470-540), drivers/tty/tty_baudrate.c (`tty_termios_baud_rate`,
// `tty_termios_input_baud_rate`, `tty_termios_encode_baud_rate`), drivers/tty/
// tty_ioctl.c (`user_termio_to_kernel_termios`, `kernel_termios_to_user_termio`,
// the `copy_*_user` of `termios`/`termios2`, 223-270; `tty_termios_hw_change`).
// drivers/tty/serial/8250/8250_port.c (`serial8250_do_set_termios`, the tail that
// re-encodes the speed). GPL-2.0.
// Transformation: the `struct ktermios` memory image is a Rust struct with explicit
// little-endian (de)serialisation of the three user layouts; the 8250 driver's
// hardware programming is dropped (the baud divisor reaches no register), only its
// visible effect on the termios (speed normalisation) is kept.
#![forbid(unsafe_code)]
//! `struct ktermios` and its three user representations (`termio` 18 bytes,
//! `termios` 36 bytes, `termios2` 44 bytes), the default values and the baud
//! rate encoding.

pub const NCCS: usize = 19;
/// `NCC` of the legacy `struct termio`.
pub const NCC: usize = 8;

// c_cc indices
pub const VINTR: usize = 0;
pub const VQUIT: usize = 1;
pub const VERASE: usize = 2;
pub const VKILL: usize = 3;
pub const VEOF: usize = 4;
pub const VTIME: usize = 5;
pub const VMIN: usize = 6;
pub const VSWTC: usize = 7;
pub const VSTART: usize = 8;
pub const VSTOP: usize = 9;
pub const VSUSP: usize = 10;
pub const VEOL: usize = 11;
pub const VREPRINT: usize = 12;
pub const VDISCARD: usize = 13;
pub const VWERASE: usize = 14;
pub const VLNEXT: usize = 15;
pub const VEOL2: usize = 16;

// c_iflag
pub const IGNBRK: u32 = 0x001;
pub const BRKINT: u32 = 0x002;
pub const IGNPAR: u32 = 0x004;
pub const PARMRK: u32 = 0x008;
pub const INPCK: u32 = 0x010;
pub const ISTRIP: u32 = 0x020;
pub const INLCR: u32 = 0x040;
pub const IGNCR: u32 = 0x080;
pub const ICRNL: u32 = 0x100;
pub const IUCLC: u32 = 0x200;
pub const IXON: u32 = 0x400;
pub const IXANY: u32 = 0x800;
pub const IXOFF: u32 = 0x1000;
pub const IMAXBEL: u32 = 0x2000;
pub const IUTF8: u32 = 0x4000;

// c_oflag
pub const OPOST: u32 = 0x01;
pub const OLCUC: u32 = 0x02;
pub const ONLCR: u32 = 0x04;
pub const OCRNL: u32 = 0x08;
pub const ONOCR: u32 = 0x10;
pub const ONLRET: u32 = 0x20;
pub const OFILL: u32 = 0x40;
pub const OFDEL: u32 = 0x80;
pub const TABDLY: u32 = 0x1800;
pub const XTABS: u32 = 0x1800;

// c_cflag
pub const CBAUD: u32 = 0x0000_100f;
pub const CSIZE: u32 = 0x30;
pub const CS8: u32 = 0x30;
pub const CSTOPB: u32 = 0x40;
pub const CREAD: u32 = 0x80;
pub const PARENB: u32 = 0x100;
pub const HUPCL: u32 = 0x400;
pub const CLOCAL: u32 = 0x800;
pub const CBAUDEX: u32 = 0x1000;
pub const BOTHER: u32 = 0x1000;
pub const CIBAUD: u32 = 0x100f_0000;
pub const IBSHIFT: u32 = 16;
pub const ADDRB: u32 = 0x2000_0000;
pub const CMSPAR: u32 = 0x4000_0000;
pub const CRTSCTS: u32 = 0x8000_0000;
pub const B0: u32 = 0;
pub const B9600: u32 = 0o15;
pub const B38400: u32 = 0o17;

// c_lflag
pub const ISIG: u32 = 0x1;
pub const ICANON: u32 = 0x2;
pub const XCASE: u32 = 0x4;
pub const ECHO: u32 = 0x8;
pub const ECHOE: u32 = 0x10;
pub const ECHOK: u32 = 0x20;
pub const ECHONL: u32 = 0x40;
pub const NOFLSH: u32 = 0x80;
pub const TOSTOP: u32 = 0x100;
pub const ECHOCTL: u32 = 0x200;
pub const ECHOPRT: u32 = 0x400;
pub const ECHOKE: u32 = 0x800;
pub const FLUSHO: u32 = 0x1000;
pub const PENDIN: u32 = 0x4000;
pub const IEXTEN: u32 = 0x8000;
pub const EXTPROC: u32 = 0x1_0000;

/// `__DISABLED_CHAR`: a control character slot that is switched off.
pub const DISABLED_CHAR: u8 = 0;

/// `struct ktermios` (and, as its first 36 or 44 bytes, `struct termios` and
/// `struct termios2`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ktermios {
    pub iflag: u32,
    pub oflag: u32,
    pub cflag: u32,
    pub lflag: u32,
    pub line: u8,
    pub cc: [u8; NCCS],
    pub ispeed: u32,
    pub ospeed: u32,
}

/// `sizeof(struct termios)` and `sizeof(struct termios2)` on x86-64.
pub const TERMIOS_SIZE: usize = 36;
pub const TERMIOS2_SIZE: usize = 44;
/// `sizeof(struct termio)`.
pub const TERMIO_SIZE: usize = 18;

/// `INIT_C_CC`.
const INIT_C_CC: [u8; NCCS] = {
    let mut cc = [0u8; NCCS];
    cc[VINTR] = 3;
    cc[VQUIT] = 0x1c;
    cc[VERASE] = 0o177;
    cc[VKILL] = 0x15;
    cc[VEOF] = 4;
    cc[VSTART] = 0x11;
    cc[VSTOP] = 0x13;
    cc[VSUSP] = 0x1a;
    cc[VREPRINT] = 0x12;
    cc[VDISCARD] = 0x0f;
    cc[VWERASE] = 0x17;
    cc[VLNEXT] = 0x16;
    cc[VMIN] = 1;
    cc
};

/// `tty_std_termios`.
pub const STD_TERMIOS: Ktermios = Ktermios {
    iflag: ICRNL | IXON,
    oflag: OPOST | ONLCR,
    cflag: B38400 | CS8 | CREAD | HUPCL,
    lflag: ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE | IEXTEN,
    line: 0,
    cc: INIT_C_CC,
    ispeed: 38400,
    ospeed: 38400,
};

/// The serial driver's `init_termios` (`serial_core.c:2789-2791`): the standard
/// termios with `B9600 | CS8 | CREAD | HUPCL | CLOCAL` and 9600 baud, which is
/// what `console=ttyS0` without options gives the console tty.
pub const SERIAL_INIT_TERMIOS: Ktermios = Ktermios {
    cflag: B9600 | CS8 | CREAD | HUPCL | CLOCAL,
    ispeed: 9600,
    ospeed: 9600,
    ..STD_TERMIOS
};

fn le32(bytes: &[u8], at: usize) -> u32 {
    let mut word = [0u8; 4];
    word.copy_from_slice(&bytes[at..at + 4]);
    u32::from_le_bytes(word)
}

impl Ktermios {
    /// The `struct termios2` image of the termios (`kernel_termios_to_user_termios`).
    #[must_use]
    pub fn to_termios2(&self) -> [u8; TERMIOS2_SIZE] {
        let mut out = [0u8; TERMIOS2_SIZE];
        out[0..4].copy_from_slice(&self.iflag.to_le_bytes());
        out[4..8].copy_from_slice(&self.oflag.to_le_bytes());
        out[8..12].copy_from_slice(&self.cflag.to_le_bytes());
        out[12..16].copy_from_slice(&self.lflag.to_le_bytes());
        out[16] = self.line;
        out[17..36].copy_from_slice(&self.cc);
        out[36..40].copy_from_slice(&self.ispeed.to_le_bytes());
        out[40..44].copy_from_slice(&self.ospeed.to_le_bytes());
        out
    }

    /// The `struct termios` image (`kernel_termios_to_user_termios_1`): the first
    /// 36 bytes of the same memory.
    #[must_use]
    pub fn to_termios(&self) -> [u8; TERMIOS_SIZE] {
        let mut out = [0u8; TERMIOS_SIZE];
        out.copy_from_slice(&self.to_termios2()[..TERMIOS_SIZE]);
        out
    }

    /// `kernel_termios_to_user_termio`: 16-bit flags, `c_line`, the first
    /// `NCC` control characters.
    #[must_use]
    #[allow(
        clippy::cast_possible_truncation,
        reason = "the kernel truncates to unsigned short"
    )]
    pub fn to_termio(&self) -> [u8; TERMIO_SIZE] {
        let mut out = [0u8; TERMIO_SIZE];
        // The flag words are truncated to `unsigned short`.
        out[0..2].copy_from_slice(&(self.iflag as u16).to_le_bytes());
        out[2..4].copy_from_slice(&(self.oflag as u16).to_le_bytes());
        out[4..6].copy_from_slice(&(self.cflag as u16).to_le_bytes());
        out[6..8].copy_from_slice(&(self.lflag as u16).to_le_bytes());
        out[8] = self.line;
        out[9..9 + NCC].copy_from_slice(&self.cc[..NCC]);
        out
    }

    /// `user_termios_to_kernel_termios` (`termios2`, 44 bytes): every field.
    pub fn set_from_termios2(&mut self, raw: &[u8; TERMIOS2_SIZE]) {
        self.set_from_termios(raw[..TERMIOS_SIZE].try_into().unwrap_or(&[0; TERMIOS_SIZE]));
        self.ispeed = le32(raw, 36);
        self.ospeed = le32(raw, 40);
    }

    /// `user_termios_to_kernel_termios_1` (`termios`, 36 bytes): the speeds keep
    /// their value.
    pub fn set_from_termios(&mut self, raw: &[u8; TERMIOS_SIZE]) {
        self.iflag = le32(raw, 0);
        self.oflag = le32(raw, 4);
        self.cflag = le32(raw, 8);
        self.lflag = le32(raw, 12);
        self.line = raw[16];
        self.cc.copy_from_slice(&raw[17..36]);
    }

    /// `user_termio_to_kernel_termios`: the low 16 bits of each flag word are
    /// replaced, the high 16 kept; `c_line` and the first `NCC` characters.
    pub fn set_from_termio(&mut self, raw: &[u8; TERMIO_SIZE]) {
        let half = |at: usize| u32::from(u16::from_le_bytes([raw[at], raw[at + 1]]));
        self.iflag = (self.iflag & 0xffff_0000) | half(0);
        self.oflag = (self.oflag & 0xffff_0000) | half(2);
        self.cflag = (self.cflag & 0xffff_0000) | half(4);
        self.lflag = (self.lflag & 0xffff_0000) | half(6);
        self.line = raw[8];
        self.cc[..NCC].copy_from_slice(&raw[9..9 + NCC]);
    }
}

/// `baud_table`, indexed by the `CBAUD` code (`CBAUDEX` codes follow `B38400`).
const BAUD_TABLE: [u32; 31] = [
    0, 50, 75, 110, 134, 150, 200, 300, 600, 1200, 1800, 2400, 4800, 9600, 19200, 38400, 57600,
    115_200, 230_400, 460_800, 500_000, 576_000, 921_600, 1_000_000, 1_152_000, 1_500_000,
    2_000_000, 2_500_000, 3_000_000, 3_500_000, 4_000_000,
];

/// `baud_bits`: the `CBAUD` code of each table entry.
const BAUD_BITS: [u32; 31] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0x1001, 0x1002, 0x1003, 0x1004, 0x1005,
    0x1006, 0x1007, 0x1008, 0x1009, 0x100a, 0x100b, 0x100c, 0x100d, 0x100e, 0x100f,
];

fn cbaud_speed(mut cbaud: u32) -> u32 {
    if cbaud & CBAUDEX != 0 {
        cbaud &= !CBAUDEX;
        cbaud += 15;
    }
    BAUD_TABLE.get(cbaud as usize).copied().unwrap_or(0)
}

/// `tty_termios_baud_rate`: the output speed.
#[must_use]
pub fn baud_rate(t: &Ktermios) -> u32 {
    let cbaud = t.cflag & CBAUD;
    if cbaud == BOTHER {
        return t.ospeed;
    }
    cbaud_speed(cbaud)
}

/// `tty_termios_input_baud_rate`.
#[must_use]
pub fn input_baud_rate(t: &Ktermios) -> u32 {
    let cbaud = (t.cflag >> IBSHIFT) & CBAUD;
    if cbaud == B0 {
        return baud_rate(t);
    }
    if cbaud == BOTHER {
        return t.ispeed;
    }
    cbaud_speed(cbaud)
}

/// `tty_termios_encode_baud_rate`: store the speeds and the closest `Bxxx`
/// codes (within 2 %), or `BOTHER`.
pub fn encode_baud_rate(t: &mut Ktermios, mut ibaud: u32, obaud: u32) {
    if obaud == 0 {
        ibaud = 0;
    }
    t.ispeed = ibaud;
    t.ospeed = obaud;
    let ibinput = (t.cflag >> IBSHIFT) & CBAUD != B0;
    // `int` arithmetic in C: the closeness margins are 2 % of the speed.
    let mut iclose = i64::from(ibaud / 50);
    let mut oclose = i64::from(obaud / 50);
    if t.cflag & CBAUD == BOTHER {
        oclose = 0;
        if !ibinput {
            iclose = 0;
        }
    }
    if (t.cflag >> IBSHIFT) & CBAUD == BOTHER {
        iclose = 0;
    }
    t.cflag &= !CBAUD;
    t.cflag &= !(CBAUD << IBSHIFT);
    let (mut ifound, mut ofound) = (false, None);
    let (ib, ob) = (i64::from(ibaud), i64::from(obaud));
    for (index, &speed) in BAUD_TABLE.iter().enumerate() {
        let speed = i64::from(speed);
        if ob - oclose <= speed && ob + oclose >= speed {
            t.cflag |= BAUD_BITS[index];
            ofound = Some(index);
        }
        if ib - iclose <= speed && ib + iclose >= speed {
            // For input == output the input bits stay clear unless the user set them.
            ifound = true;
            if ofound != Some(index) || ibinput {
                t.cflag |= BAUD_BITS[index] << IBSHIFT;
            }
        }
    }
    if ofound.is_none() {
        t.cflag |= BOTHER;
    }
    if !ifound && (ibaud != obaud || ibinput) {
        t.cflag |= BOTHER << IBSHIFT;
    }
}

/// `tty_termios_hw_change`: whether anything a dumb device handles in hardware
/// differs between two termios.
#[must_use]
pub fn hw_change(a: &Ktermios, b: &Ktermios) -> bool {
    a.ispeed != b.ispeed
        || a.ospeed != b.ospeed
        || (a.cflag ^ b.cflag) & !(HUPCL | CREAD | CLOCAL) != 0
}

/// The highest speed of the emulated 8250 (`uartclk / 16`, `uartclk` 1.8432 MHz).
pub const UART_MAX_BAUD: u32 = 115_200;
/// `uartclk / 16 / UART_DIV_MAX`.
pub const UART_MIN_BAUD: u32 = 1;

/// `uart_get_baud_rate` for the 8250: the usable speed for `termios`, falling back
/// to `old`'s and finally clipping (`serial_core.c:470-540`). It may rewrite the
/// speed bits of `termios`.
pub fn uart_get_baud_rate(termios: &mut Ktermios, old: Option<&Ktermios>) -> u32 {
    let (min, max) = (UART_MIN_BAUD, UART_MAX_BAUD);
    let mut old = old;
    let mut hung_up = false;
    for attempt in 0..2 {
        let mut baud = baud_rate(termios);
        // `try == 0 && baud == 38400`: the spd_hi kludge, `altbaud` 38400 here.
        if attempt == 0 && baud == 38400 {
            baud = 38400;
        }
        if baud == 0 {
            hung_up = true;
            baud = 9600;
        }
        if baud >= min && baud <= max {
            return baud;
        }
        termios.cflag &= !CBAUD;
        if let Some(previous) = old {
            baud = baud_rate(previous);
            if !hung_up {
                encode_baud_rate(termios, baud, baud);
            }
            old = None;
            continue;
        }
        if !hung_up {
            if baud <= min {
                encode_baud_rate(termios, min + 1, min + 1);
            } else {
                encode_baud_rate(termios, max - 1, max - 1);
            }
        }
    }
    0
}

/// `uart_set_termios` + `serial8250_do_set_termios` as far as they change the
/// termios: nothing happens unless a hardware-relevant field changed; then the
/// speed is validated against the chip and re-encoded (`B0` is not rewritten).
pub fn uart_set_termios(new: &mut Ktermios, old: &Ktermios) {
    let iflag_mask = IGNBRK | BRKINT | IGNPAR | PARMRK | INPCK;
    if new.cflag == old.cflag
        && new.ospeed == old.ospeed
        && new.ispeed == old.ispeed
        && (new.iflag ^ old.iflag) & iflag_mask == 0
    {
        return;
    }
    let baud = uart_get_baud_rate(new, Some(old));
    if baud_rate(new) != 0 {
        encode_baud_rate(new, baud, baud);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_termios_match_the_pinned_console() {
        let t = SERIAL_INIT_TERMIOS;
        assert_eq!(
            [t.iflag, t.oflag, t.cflag, t.lflag],
            [0o2400, 0o5, 0o6275, 0o105_073]
        );
        let raw = t.to_termios();
        assert_eq!(raw.len(), 36);
        assert_eq!(
            &raw[17..34],
            &[3, 28, 127, 21, 4, 0, 1, 0, 17, 19, 26, 0, 18, 15, 23, 22, 0]
        );
        assert_eq!(t.to_termios2()[36..], [0x80, 0x25, 0, 0, 0x80, 0x25, 0, 0]);
    }

    #[test]
    fn baud_codes() {
        let mut t = STD_TERMIOS;
        assert_eq!(baud_rate(&t), 38400);
        t.cflag = (t.cflag & !CBAUD) | 0x1002;
        assert_eq!(baud_rate(&t), 115_200);
        t.cflag = (t.cflag & !CBAUD) | BOTHER;
        t.ospeed = 12_345;
        assert_eq!(baud_rate(&t), 12_345);
    }

    #[test]
    fn encode_prefers_a_standard_code_within_two_percent() {
        let mut t = SERIAL_INIT_TERMIOS;
        encode_baud_rate(&mut t, 57_600, 57_600);
        assert_eq!(t.cflag & (CBAUD | CIBAUD), 0x1001);
        assert_eq!((t.ispeed, t.ospeed), (57_600, 57_600));
        encode_baud_rate(&mut t, 12_345, 12_345);
        assert_eq!(t.cflag & CBAUD, BOTHER);
    }

    #[test]
    fn uart_rejects_speeds_above_the_chip_and_keeps_the_old_one() {
        let old = SERIAL_INIT_TERMIOS;
        let mut new = old;
        new.cflag = (new.cflag & !CBAUD) | 0x1003; // B230400
        uart_set_termios(&mut new, &old);
        assert_eq!(new.cflag & CBAUD, B9600);
        assert_eq!((new.ispeed, new.ospeed), (9600, 9600));
        let mut fast = old;
        fast.cflag = (fast.cflag & !CBAUD) | 0x1002; // B115200
        uart_set_termios(&mut fast, &old);
        assert_eq!(fast.cflag & CBAUD, 0x1002);
        assert_eq!(fast.ospeed, 115_200);
    }

    #[test]
    fn user_images_round_trip() {
        let mut t = STD_TERMIOS;
        let mut raw = t.to_termios2();
        raw[0] = 0xff;
        t.set_from_termios2(&raw);
        assert_eq!(t.iflag & 0xff, 0xff);
        let termio = t.to_termio();
        let mut u = STD_TERMIOS;
        u.set_from_termio(&termio);
        assert_eq!(u.cc[..NCC], t.cc[..NCC]);
        assert_eq!(u.cc[VEOL2], STD_TERMIOS.cc[VEOL2]);
    }
}
