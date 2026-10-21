// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: drivers/tty/vt/keyboard.c (SPDX
// GPL-2.0; `kbd_keycode` 1388-1520, the `k_*` and `fn_*` handlers 476-980,
// `handle_diacr`, `to_utf8`, `put_queue`, `applkey`, `do_compute_shiftstate`),
// include/uapi/linux/keyboard.h and include/linux/kbd_kern.h (the type and shift
// constants, `kbd_struct`). All GPL-2.0.
// Transformation: the output of `put_queue`/`puts_queue` is a callback of [`Out`]
// items (the caller inserts them into the console tty's flip buffer); one console
// (no `set_console`, `last_console`, scroll-back, `ctrl_alt_del`, magic SysRq or
// `SAK`: their keys are consumed and do nothing); LED state is kept but no LED
// command reaches the keyboard; raw and medium-raw modes (`KDSKBMODE`) do not exist,
// the keyboard is in Unicode mode (`default_utf8`) with the default flags
// (`KBD_DEFMODE`, `KBD_DEFLOCK`, NumLock off as `boot_params.kbd_status` is 0).
#![forbid(unsafe_code)]
//! The VT keyboard layer: keycodes to the bytes a Linux console delivers.

use super::keymap_data::{ACCENT_TABLE, FUNC_TABLE, K_HOLE, KEY_MAPS};

// types (include/uapi/linux/keyboard.h)
const KT_LATIN: u8 = 0;
const KT_FN: u8 = 1;
const KT_SPEC: u8 = 2;
const KT_PAD: u8 = 3;
const KT_DEAD: u8 = 4;
const KT_CUR: u8 = 6;
const KT_SHIFT: u8 = 7;
const KT_META: u8 = 8;
const KT_ASCII: u8 = 9;
const KT_LOCK: u8 = 10;
const KT_LETTER: u8 = 11;
const KT_SLOCK: u8 = 12;
const KT_DEAD2: u8 = 13;

// shift states
const KG_SHIFT: usize = 0;
const KG_CAPSSHIFT: usize = 8;
/// `NR_SHIFT`.
const NR_SHIFT: usize = 9;

// led flags
const VC_NUMLOCK: u8 = 1;
const VC_CAPSLOCK: u8 = 2;
// mode flags
const VC_APPLIC: u8 = 0;
const VC_CKMODE: u8 = 1;
const VC_REPEAT: u8 = 2;
const VC_CRLF: u8 = 3;
const VC_META: u8 = 4;
/// `KBD_DEFMODE`.
const KBD_DEFMODE: u8 = (1 << VC_REPEAT) | (1 << VC_META);

// KT_PAD values
const K_P0: u8 = 0;
const K_P1: u8 = 1;
const K_P2: u8 = 2;
const K_P3: u8 = 3;
const K_P4: u8 = 4;
const K_P5: u8 = 5;
const K_P6: u8 = 6;
const K_P7: u8 = 7;
const K_P8: u8 = 8;
const K_P9: u8 = 9;
const K_PENTER: u8 = 14;
const K_PCOMMA: u8 = 15;
const K_PDOT: u8 = 16;
// KT_FN values used by the keypad
const K_FIND: u8 = 20;
const K_INSERT: u8 = 21;
const K_REMOVE: u8 = 22;
const K_SELECT: u8 = 23;
const K_PGUP: u8 = 24;
const K_PGDN: u8 = 25;
// KT_CUR values
const K_DOWN: u8 = 0;
const K_LEFT: u8 = 1;
const K_RIGHT: u8 = 2;
const K_UP: u8 = 3;

/// What the keyboard layer wants the console tty to receive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Out {
    /// `put_queue`: one input byte.
    Byte(u8),
    /// `fn_send_intr`: the Break key, a `TTY_BREAK` character.
    Break,
    /// `fn_hold` (Scroll Lock): toggle `stop_tty`/`start_tty`.
    Hold,
}

/// The state of the tty `kbd_keycode` consults before it repeats a key.
#[derive(Clone, Copy, Debug)]
pub struct TtyInfo {
    /// `L_ECHO(tty)`.
    pub echo: bool,
    /// `tty_chars_in_buffer(tty) != 0`.
    pub output_queued: bool,
}

/// `kbd_table[0]` and the driver's file-scope variables.
pub struct Keyboard {
    key_down: [u64; 4],
    shift_down: [u8; NR_SHIFT],
    shift_state: u32,
    dead_key_next: bool,
    npadch_active: bool,
    npadch_value: u32,
    diacr: u32,
    rep: bool,
    lockstate: u8,
    slockstate: u8,
    ledflagstate: u8,
    modeflags: u8,
}

impl Default for Keyboard {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "every cast follows the range test of its branch and a shift or mask"
)]
fn sink_utf8(c: u32, out: &mut dyn FnMut(Out)) {
    // `to_utf8`
    if c < 0x80 {
        out(Out::Byte(c as u8));
    } else if c < 0x800 {
        out(Out::Byte(0xc0 | (c >> 6) as u8));
        out(Out::Byte(0x80 | (c & 0x3f) as u8));
    } else if c < 0x1_0000 {
        if (0xd800..0xe000).contains(&c) || c == 0xffff {
            return;
        }
        out(Out::Byte(0xe0 | (c >> 12) as u8));
        out(Out::Byte(0x80 | ((c >> 6) & 0x3f) as u8));
        out(Out::Byte(0x80 | (c & 0x3f) as u8));
    } else if c < 0x11_0000 {
        out(Out::Byte(0xf0 | (c >> 18) as u8));
        out(Out::Byte(0x80 | ((c >> 12) & 0x3f) as u8));
        out(Out::Byte(0x80 | ((c >> 6) & 0x3f) as u8));
        out(Out::Byte(0x80 | (c & 0x3f) as u8));
    }
}

fn puts(bytes: &[u8], out: &mut dyn FnMut(Out)) {
    for &b in bytes {
        out(Out::Byte(b));
    }
}

impl Keyboard {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            key_down: [0; 4],
            shift_down: [0; NR_SHIFT],
            shift_state: 0,
            dead_key_next: false,
            npadch_active: false,
            npadch_value: 0,
            diacr: 0,
            rep: false,
            lockstate: 0,
            slockstate: 0,
            ledflagstate: 0,
            modeflags: KBD_DEFMODE,
        }
    }

    fn mode(&self, flag: u8) -> bool {
        self.modeflags >> flag & 1 != 0
    }
    fn led(&self, flag: u8) -> bool {
        self.ledflagstate >> flag & 1 != 0
    }

    fn put_queue(c: u8, out: &mut dyn FnMut(Out)) {
        out(Out::Byte(c));
    }

    /// `applkey`.
    fn applkey(key: u8, application: bool, out: &mut dyn FnMut(Out)) {
        puts(&[0x1b, if application { b'O' } else { b'[' }, key], out);
    }

    /// `do_compute_shiftstate`.
    fn compute_shiftstate(&mut self) {
        self.shift_state = 0;
        self.shift_down = [0; NR_SHIFT];
        for k in 0..128usize {
            if self.key_down[k / 64] >> (k % 64) & 1 == 0 {
                continue;
            }
            let sym = super::keymap_data::PLAIN_MAP[k];
            let ty = (sym >> 8) as u8 & 0x0f;
            if ty != KT_SHIFT && ty != KT_SLOCK {
                continue;
            }
            let mut val = usize::from(sym & 0xff);
            if val == KG_CAPSSHIFT {
                val = KG_SHIFT;
            }
            self.shift_down[val] += 1;
            self.shift_state |= 1 << val;
        }
    }

    /// `handle_diacr`.
    fn handle_diacr(&mut self, ch: u32, out: &mut dyn FnMut(Out)) -> u32 {
        let d = self.diacr;
        self.diacr = 0;
        for &(diacr, base, result) in &ACCENT_TABLE {
            if u32::from(diacr) == d && u32::from(base) == ch {
                return u32::from(result);
            }
        }
        if ch == u32::from(b' ') || ch == d {
            return d;
        }
        sink_utf8(d, out);
        ch
    }

    /// `k_unicode`.
    fn k_unicode(&mut self, value: u32, up: bool, out: &mut dyn FnMut(Out)) {
        if up {
            return;
        }
        let mut value = value;
        if self.diacr != 0 {
            value = self.handle_diacr(value, out);
        }
        if self.dead_key_next {
            self.dead_key_next = false;
            self.diacr = value;
            return;
        }
        sink_utf8(value, out);
    }

    /// `k_deadunicode`.
    fn k_deadunicode(&mut self, value: u32, up: bool, out: &mut dyn FnMut(Out)) {
        if up {
            return;
        }
        self.diacr = if self.diacr != 0 {
            self.handle_diacr(value, out)
        } else {
            value
        };
    }

    /// `fn_handler[value]` (`k_spec`).
    fn k_spec(&mut self, value: u8, up: bool, out: &mut dyn FnMut(Out)) {
        if up {
            return;
        }
        match value {
            // fn_null
            0 => self.compute_shiftstate(),
            // fn_enter
            1 => {
                if self.diacr != 0 {
                    sink_utf8(self.diacr, out);
                    self.diacr = 0;
                }
                Self::put_queue(b'\r', out);
                if self.mode(VC_CRLF) {
                    Self::put_queue(b'\n', out);
                }
            }
            // fn_send_intr
            5 => out(Out::Break),
            // fn_caps_toggle
            7 => {
                if !self.rep {
                    self.ledflagstate ^= 1 << VC_CAPSLOCK;
                }
            }
            // fn_num
            8 => {
                if self.mode(VC_APPLIC) {
                    Self::applkey(b'P', true, out);
                } else if !self.rep {
                    self.ledflagstate ^= 1 << VC_NUMLOCK;
                }
            }
            // fn_hold
            9 => {
                if !self.rep {
                    out(Out::Hold);
                }
            }
            // fn_caps_on
            13 => {
                if !self.rep {
                    self.ledflagstate |= 1 << VC_CAPSLOCK;
                }
            }
            // fn_compose
            14 => self.dead_key_next = true,
            // fn_bare_num
            19 if !self.rep => self.ledflagstate ^= 1 << VC_NUMLOCK,
            // The register/memory/state dumps, console switching, scroll-back,
            // reboot, SAK and console spawning have no console to act on.
            _ => {}
        }
    }

    fn k_fn(value: u8, up: bool, out: &mut dyn FnMut(Out)) {
        if up {
            return;
        }
        if let Some(Some(text)) = FUNC_TABLE.get(usize::from(value)) {
            puts(text, out);
        }
    }

    fn k_cur(&self, value: u8, up: bool, out: &mut dyn FnMut(Out)) {
        const CUR_CHARS: &[u8; 4] = b"BDCA";
        if up {
            return;
        }
        Self::applkey(CUR_CHARS[usize::from(value & 3)], self.mode(VC_CKMODE), out);
    }

    fn k_pad(&mut self, value: u8, up: bool, out: &mut dyn FnMut(Out)) {
        const PAD_CHARS: &[u8; 21] = b"0123456789+-*/\r,.?()#";
        const APP_MAP: &[u8; 21] = b"pqrstuvwxylSRQMnnmPQS";
        if up {
            return;
        }
        // Kludge: shift forces cursor/number keys.
        if self.mode(VC_APPLIC) && self.shift_down[KG_SHIFT] == 0 {
            if let Some(&key) = APP_MAP.get(usize::from(value)) {
                Self::applkey(key, true, out);
            }
            return;
        }
        if !self.led(VC_NUMLOCK) {
            match value {
                K_PCOMMA | K_PDOT => return Self::k_fn(K_REMOVE, false, out),
                K_P0 => return Self::k_fn(K_INSERT, false, out),
                K_P1 => return Self::k_fn(K_SELECT, false, out),
                K_P2 => return self.k_cur(K_DOWN, false, out),
                K_P3 => return Self::k_fn(K_PGDN, false, out),
                K_P4 => return self.k_cur(K_LEFT, false, out),
                K_P6 => return self.k_cur(K_RIGHT, false, out),
                K_P7 => return Self::k_fn(K_FIND, false, out),
                K_P8 => return self.k_cur(K_UP, false, out),
                K_P9 => return Self::k_fn(K_PGUP, false, out),
                K_P5 => return Self::applkey(b'G', self.mode(VC_APPLIC), out),
                _ => {}
            }
        }
        if let Some(&c) = PAD_CHARS.get(usize::from(value)) {
            Self::put_queue(c, out);
        }
        if value == K_PENTER && self.mode(VC_CRLF) {
            Self::put_queue(b'\n', out);
        }
    }

    fn k_shift(&mut self, value: u8, up: bool, out: &mut dyn FnMut(Out)) {
        let old_state = self.shift_state;
        if self.rep {
            return;
        }
        let mut value = usize::from(value);
        if value >= NR_SHIFT {
            return;
        }
        // Mimic typewriter: a CapsShift key acts like Shift but undoes CapsLock.
        if value == KG_CAPSSHIFT {
            value = KG_SHIFT;
            if !up {
                self.ledflagstate &= !(1 << VC_CAPSLOCK);
            }
        }
        if up {
            // Two shift or control keys may be depressed simultaneously.
            if self.shift_down[value] > 0 {
                self.shift_down[value] -= 1;
            }
        } else {
            self.shift_down[value] = self.shift_down[value].saturating_add(1);
        }
        if self.shift_down[value] > 0 {
            self.shift_state |= 1 << value;
        } else {
            self.shift_state &= !(1 << value);
        }
        // Kludge: the Alt-numpad number ends when the modifier is released.
        if up && self.shift_state != old_state && self.npadch_active {
            sink_utf8(self.npadch_value, out);
            self.npadch_active = false;
        }
    }

    fn k_meta(&self, value: u8, up: bool, out: &mut dyn FnMut(Out)) {
        if up {
            return;
        }
        if self.mode(VC_META) {
            Self::put_queue(0x1b, out);
            Self::put_queue(value, out);
        } else {
            Self::put_queue(value | 0x80, out);
        }
    }

    fn k_ascii(&mut self, value: u8, up: bool) {
        if up {
            return;
        }
        let (base, value) = if value < 10 {
            // decimal input of code, while Alt depressed
            (10, u32::from(value))
        } else {
            // hexadecimal input of code, while AltGr depressed
            (16, u32::from(value - 10))
        };
        if !self.npadch_active {
            self.npadch_value = 0;
            self.npadch_active = true;
        }
        self.npadch_value = self.npadch_value.wrapping_mul(base).wrapping_add(value);
    }

    fn k_lock(&mut self, value: u8, up: bool) {
        if up || self.rep {
            return;
        }
        self.lockstate ^= 1u8.checked_shl(u32::from(value)).unwrap_or(0);
    }

    fn k_slock(&mut self, value: u8, up: bool, out: &mut dyn FnMut(Out)) {
        self.k_shift(value, up, out);
        if up || self.rep {
            return;
        }
        let bit = 1u8.checked_shl(u32::from(value)).unwrap_or(0);
        self.slockstate ^= bit;
        // Try to make Alt, oops, AltGr and such work.
        if !Self::map_exists(usize::from(self.lockstate ^ self.slockstate)) {
            self.slockstate = 0;
            self.slockstate ^= bit;
        }
    }

    fn map_exists(index: usize) -> bool {
        KEY_MAPS.get(index).is_some_and(Option::is_some)
    }

    /// `k_dead`: the obsolete dead-key values map to their spacing characters.
    fn k_dead(&mut self, value: u8, up: bool, out: &mut dyn FnMut(Out)) {
        const RET_DIACR: &[u8; 27] = b"`'^~\",_U.*=cki#o!?+-)(:n;$@";
        if let Some(&c) = RET_DIACR.get(usize::from(value)) {
            self.k_deadunicode(u32::from(c), up, out);
        }
    }

    /// One key event: `kbd_keycode(keycode, down, ...)`. `down` is 0 for a
    /// release, 1 for a press, 2 for a hardware repeat.
    pub fn keycode(&mut self, keycode: u16, down: u8, tty: TtyInfo, out: &mut dyn FnMut(Out)) {
        self.rep = down == 2;
        let kc = usize::from(keycode);
        if kc < 256 {
            if down != 0 {
                self.key_down[kc / 64] |= 1 << (kc % 64);
            } else {
                self.key_down[kc / 64] &= !(1 << (kc % 64));
            }
        }
        // Don't repeat a key if the input buffers are not empty and the
        // characters are not echoed locally.
        if self.rep && (!self.mode(VC_REPEAT) || (!tty.echo && tty.output_queued)) {
            return;
        }
        let shift_final = usize::try_from(
            (self.shift_state | u32::from(self.slockstate)) ^ u32::from(self.lockstate),
        )
        .unwrap_or(usize::MAX);
        let Some(key_map) = KEY_MAPS.get(shift_final).copied().flatten() else {
            self.compute_shiftstate();
            self.slockstate = 0;
            return;
        };
        if kc >= 256 {
            return;
        }
        let mut keysym = key_map.get(kc).copied().unwrap_or(K_HOLE);
        let mut ty = (keysym >> 8) as u8;
        if ty < 0xf0 {
            // A Unicode keysym.
            if down != 0 {
                self.k_unicode(u32::from(keysym), false, out);
            }
            return;
        }
        ty -= 0xf0;
        if ty == KT_LETTER {
            ty = KT_LATIN;
            if self.led(VC_CAPSLOCK)
                && let Some(map) = KEY_MAPS.get(shift_final ^ 1).copied().flatten()
            {
                keysym = map.get(kc).copied().unwrap_or(K_HOLE);
            }
        }
        let value = (keysym & 0xff) as u8;
        let up = down == 0;
        match ty {
            // k_self: the 8-bit value converted to Unicode (Latin-1 identity).
            KT_LATIN => self.k_unicode(u32::from(value), up, out),
            KT_FN => Self::k_fn(value, up, out),
            KT_SPEC => self.k_spec(value, up, out),
            KT_PAD => self.k_pad(value, up, out),
            KT_DEAD => self.k_dead(value, up, out),
            KT_CUR => self.k_cur(value, up, out),
            KT_SHIFT => self.k_shift(value, up, out),
            KT_META => self.k_meta(value, up, out),
            KT_ASCII => self.k_ascii(value, up),
            KT_LOCK => self.k_lock(value, up),
            KT_SLOCK => self.k_slock(value, up, out),
            KT_DEAD2 => self.k_deadunicode(u32::from(value), up, out),
            // Console switching (one console), braille and the reserved type: nothing.
            _ => {}
        }
        if ty != KT_SLOCK {
            self.slockstate = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    const TTY: TtyInfo = TtyInfo {
        echo: true,
        output_queued: false,
    };

    fn typed(kbd: &mut Keyboard, keys: &[(u16, u8)]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for &(code, down) in keys {
            kbd.keycode(code, down, TTY, &mut |o| match o {
                Out::Byte(b) => bytes.push(b),
                Out::Break => bytes.push(0xfe),
                Out::Hold => bytes.push(0xfd),
            });
        }
        bytes
    }

    const KEY_A: u16 = 30;
    const KEY_1: u16 = 2;
    const KEY_LEFTSHIFT: u16 = 42;
    const KEY_LEFTCTRL: u16 = 29;
    const KEY_LEFTALT: u16 = 56;
    const KEY_ENTER: u16 = 28;
    const KEY_BACKSPACE: u16 = 14;
    const KEY_CAPSLOCK: u16 = 58;
    const KEY_UP: u16 = 103;
    const KEY_F1: u16 = 59;
    const KEY_ESC: u16 = 1;
    const KEY_TAB: u16 = 15;

    #[test]
    fn printable_keys_enter_backspace_and_escape() {
        let mut kbd = Keyboard::new();
        assert_eq!(typed(&mut kbd, &[(KEY_A, 1), (KEY_A, 0)]), b"a");
        assert_eq!(typed(&mut kbd, &[(KEY_1, 1), (KEY_1, 0)]), b"1");
        assert_eq!(typed(&mut kbd, &[(KEY_ENTER, 1), (KEY_ENTER, 0)]), b"\r");
        assert_eq!(
            typed(&mut kbd, &[(KEY_BACKSPACE, 1), (KEY_BACKSPACE, 0)]),
            b"\x7f"
        );
        assert_eq!(typed(&mut kbd, &[(KEY_ESC, 1)]), b"\x1b");
        assert_eq!(typed(&mut kbd, &[(KEY_TAB, 1)]), b"\t");
    }

    #[test]
    fn shift_ctrl_alt_and_capslock() {
        let mut kbd = Keyboard::new();
        let shifted = typed(
            &mut kbd,
            &[
                (KEY_LEFTSHIFT, 1),
                (KEY_A, 1),
                (KEY_A, 0),
                (KEY_1, 1),
                (KEY_1, 0),
                (KEY_LEFTSHIFT, 0),
            ],
        );
        assert_eq!(shifted, b"A!");
        let ctrl = typed(
            &mut kbd,
            &[(KEY_LEFTCTRL, 1), (KEY_A, 1), (KEY_A, 0), (KEY_LEFTCTRL, 0)],
        );
        assert_eq!(ctrl, b"\x01");
        // Alt+a: ESC prefix (VC_META).
        let alt = typed(
            &mut kbd,
            &[(KEY_LEFTALT, 1), (KEY_A, 1), (KEY_A, 0), (KEY_LEFTALT, 0)],
        );
        assert_eq!(alt, b"\x1ba");
        let caps = typed(
            &mut kbd,
            &[
                (KEY_CAPSLOCK, 1),
                (KEY_CAPSLOCK, 0),
                (KEY_A, 1),
                (KEY_A, 0),
                (KEY_1, 1),
                (KEY_1, 0),
            ],
        );
        assert_eq!(caps, b"A1");
        // Shift undoes caps for letters.
        let both = typed(
            &mut kbd,
            &[
                (KEY_LEFTSHIFT, 1),
                (KEY_A, 1),
                (KEY_A, 0),
                (KEY_LEFTSHIFT, 0),
            ],
        );
        assert_eq!(both, b"a");
    }

    #[test]
    fn arrows_and_function_keys() {
        let mut kbd = Keyboard::new();
        assert_eq!(typed(&mut kbd, &[(KEY_UP, 1), (KEY_UP, 0)]), b"\x1b[A");
        assert_eq!(typed(&mut kbd, &[(KEY_F1, 1)]), b"\x1b[[A");
    }

    #[test]
    fn keypad_follows_numlock() {
        const KP7: u16 = 71;
        const KEY_NUMLOCK: u16 = 69;
        let mut kbd = Keyboard::new();
        assert_eq!(typed(&mut kbd, &[(KP7, 1)]), b"\x1b[1~");
        typed(&mut kbd, &[(KEY_NUMLOCK, 1), (KEY_NUMLOCK, 0)]);
        assert_eq!(typed(&mut kbd, &[(KP7, 1)]), b"7");
    }

    #[test]
    fn compose_builds_accented_characters_in_utf8() {
        const KEY_DOT: u16 = 52;
        const KEY_APOSTROPHE: u16 = 40;
        let mut kbd = Keyboard::new();
        // Ctrl+. is Compose in the default map; then ' and a give U+00E1.
        let out = typed(
            &mut kbd,
            &[
                (KEY_LEFTCTRL, 1),
                (KEY_DOT, 1),
                (KEY_DOT, 0),
                (KEY_LEFTCTRL, 0),
                (KEY_APOSTROPHE, 1),
                (KEY_APOSTROPHE, 0),
                (KEY_A, 1),
                (KEY_A, 0),
            ],
        );
        assert_eq!(out, "\u{e1}".as_bytes());
    }

    #[test]
    fn a_repeated_modifier_does_not_unbalance_the_shift_state() {
        let mut kbd = Keyboard::new();
        typed(
            &mut kbd,
            &[(KEY_LEFTSHIFT, 1), (KEY_LEFTSHIFT, 2), (KEY_LEFTSHIFT, 0)],
        );
        assert_eq!(typed(&mut kbd, &[(KEY_A, 1)]), b"a");
    }
}
