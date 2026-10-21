// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: drivers/input/keyboard/atkbd.c
// (SPDX GPL-2.0-only, Copyright (c) 1999-2002 Vojtech Pavlik: `atkbd_receive_byte`
// 480-600, `atkbd_need_xlate`, `atkbd_calculate_xl_bit`, `atkbd_compat_scancode`,
// `atkbd_set_keycode_table`), drivers/input/input.c (the `value` of a repeated
// key is the caller's: `atkbd_receive_byte` computes it itself).
// Transformation: the input-core event (`EV_KEY` code and value) is an
// [`KeyEvent`]; the module parameters have their default values (scancode set 2,
// translated when the controller translates, no softrepeat, no scroll wheel);
// the keyboard's BAT/reconnect and the error counters are dropped.
#![forbid(unsafe_code)]
//! The AT/PS/2 keyboard's scancode stream to keycodes.

use super::keymap_data::{ATKBD_SET2_KEYCODE, ATKBD_UNXLATE};

const RET_BAT: u8 = 0xaa;
const RET_EMUL0: u8 = 0xe0;
const RET_EMUL1: u8 = 0xe1;
const RET_RELEASE: u8 = 0xf0;
const RET_ERR: u8 = 0xff;
const RET_ACK: u8 = 0xfa;
const RET_NAK: u8 = 0xfe;
const RET_HANJA: u8 = 0xf1;
const RET_HANGEUL: u8 = 0xf2;
const KEY_UNKNOWN: u16 = 0;
const KEY_NULL: u16 = 255;
const KEY_HANGEUL: u16 = 122;
const KEY_HANJA: u16 = 123;
/// The default `dev->rep[REP_DELAY]` in ms: half of it is the duplicate window.
const REP_DELAY_MS: u64 = 250;

const XL_TABLE: [u8; 6] = [RET_BAT, RET_ERR, RET_ACK, RET_NAK, RET_HANJA, RET_HANGEUL];

/// One key event: `value` 0 release, 1 press, 2 hardware auto-repeat.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyEvent {
    pub keycode: u16,
    pub value: u8,
}

/// `struct atkbd` (receive side).
pub struct Atkbd {
    translated: bool,
    keycode: [u16; 512],
    force_release: [bool; 512],
    emul: u8,
    release: bool,
    xl_bit: u8,
    last: u32,
    time_ms: u64,
    key_down: [u64; 4],
}

impl Atkbd {
    /// A keyboard on a controller that does (`translated`) or does not translate
    /// set 2 to set 1 (`atkbd_set_keycode_table`).
    #[must_use]
    pub fn new(translated: bool) -> Self {
        let mut keycode = [0u16; 512];
        let mut force_release = [false; 512];
        if translated {
            for i in 0..128 {
                let scancode = usize::from(ATKBD_UNXLATE[i]);
                keycode[i] = ATKBD_SET2_KEYCODE[scancode];
                keycode[i | 0x80] = ATKBD_SET2_KEYCODE[scancode | 0x80];
            }
        } else {
            keycode = ATKBD_SET2_KEYCODE;
        }
        // HANGEUL and HANJA do not send release events: generate them.
        for (ret, key) in [(RET_HANGEUL, KEY_HANGEUL), (RET_HANJA, KEY_HANJA)] {
            let code = Self::compat_scancode(u32::from(ret), 0);
            keycode[code as usize] = key;
            force_release[code as usize] = true;
        }
        Self {
            translated,
            keycode,
            force_release,
            emul: 0,
            release: false,
            xl_bit: 0,
            last: 0,
            time_ms: 0,
            key_down: [0; 4],
        }
    }

    /// `atkbd_compat_scancode` for set 2.
    fn compat_scancode(code: u32, emul: u8) -> u32 {
        let mut code = (code & 0x7f) | ((code & 0x80) << 1);
        if emul == 1 {
            code |= 0x80;
        }
        code
    }

    /// `atkbd_need_xlate`.
    fn need_xlate(&self, code: u8) -> bool {
        if code == RET_EMUL0 || code == RET_EMUL1 {
            return false;
        }
        for (i, &entry) in XL_TABLE.iter().enumerate() {
            if code == entry {
                return self.xl_bit >> i & 1 != 0;
            }
        }
        true
    }

    /// `atkbd_calculate_xl_bit`.
    fn calculate_xl_bit(&mut self, code: u8) {
        for (i, &entry) in XL_TABLE.iter().enumerate() {
            if (code ^ entry).trailing_zeros() >= 7 {
                if code & 0x80 != 0 {
                    self.xl_bit &= !(1 << i);
                } else {
                    self.xl_bit |= 1 << i;
                }
                break;
            }
        }
    }

    fn is_down(&self, keycode: u16) -> bool {
        self.key_down[usize::from(keycode) / 64] >> (usize::from(keycode) % 64) & 1 != 0
    }
    fn set_down(&mut self, keycode: u16, down: bool) {
        let (word, bit) = (usize::from(keycode) / 64, usize::from(keycode) % 64);
        if down {
            self.key_down[word] |= 1 << bit;
        } else {
            self.key_down[word] &= !(1 << bit);
        }
    }

    /// `atkbd_receive_byte`: one byte from the controller. `now_ms` is a
    /// monotonic millisecond clock. Up to two events result (a forced release
    /// follows the press of the Hanja/Hangeul keys).
    pub fn receive_byte(&mut self, data: u8, now_ms: u64) -> [Option<KeyEvent>; 2] {
        let mut out = [None, None];
        let mut code = data;
        if self.translated {
            if self.emul != 0 || self.need_xlate(code) {
                self.release = code >> 7 != 0;
                code &= 0x7f;
            }
            if self.emul == 0 {
                self.calculate_xl_bit(data);
            }
        }
        match code {
            RET_EMUL0 => {
                self.emul = 1;
                return out;
            }
            RET_EMUL1 => {
                self.emul = 2;
                return out;
            }
            RET_RELEASE => {
                self.release = true;
                return out;
            }
            // A reset (the key states are gone with it), a spurious ACK/NAK or "too many keys
            // pressed".
            RET_BAT | RET_ACK | RET_NAK | RET_ERR => return out,
            _ => {}
        }
        let code = Self::compat_scancode(u32::from(code), self.emul);
        if self.emul != 0 {
            self.emul -= 1;
            if self.emul != 0 {
                return out;
            }
        }
        let keycode = self.keycode[code as usize];
        match keycode {
            KEY_NULL | KEY_UNKNOWN => {}
            _ => {
                let value;
                if self.release {
                    value = 0;
                    self.last = 0;
                } else if self.is_down(keycode) {
                    // "Workaround Toshiba laptop multiple keypress"
                    value = if now_ms < self.time_ms && self.last == code {
                        1
                    } else {
                        2
                    };
                } else {
                    value = 1;
                    self.last = code;
                    self.time_ms = now_ms + REP_DELAY_MS / 2;
                }
                self.set_down(keycode, value != 0);
                out[0] = Some(KeyEvent { keycode, value });
                if value != 0 && self.force_release[code as usize] {
                    self.set_down(keycode, false);
                    out[1] = Some(KeyEvent { keycode, value: 0 });
                }
            }
        }
        self.release = false;
        out
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    fn press_release(kbd: &mut Atkbd, make: &[u8], brk: &[u8]) -> (Vec<KeyEvent>, Vec<KeyEvent>) {
        let mut events = |bytes: &[u8]| {
            bytes
                .iter()
                .flat_map(|&b| kbd.receive_byte(b, 0))
                .flatten()
                .collect::<Vec<_>>()
        };
        let down = events(make);
        let up = events(brk);
        (down, up)
    }

    #[test]
    fn translated_set1_letters_and_extended_keys() {
        let mut kbd = Atkbd::new(true);
        // 'a' make 0x1e / break 0x9e = KEY_A 30
        let (down, up) = press_release(&mut kbd, &[0x1e], &[0x9e]);
        assert_eq!(
            down,
            [KeyEvent {
                keycode: 30,
                value: 1
            }]
        );
        assert_eq!(
            up,
            [KeyEvent {
                keycode: 30,
                value: 0
            }]
        );
        // Up arrow: E0 48 / E0 C8 = KEY_UP 103
        let (down, up) = press_release(&mut kbd, &[0xe0, 0x48], &[0xe0, 0xc8]);
        assert_eq!(
            down,
            [KeyEvent {
                keycode: 103,
                value: 1
            }]
        );
        assert_eq!(
            up,
            [KeyEvent {
                keycode: 103,
                value: 0
            }]
        );
        // Enter 0x1c = KEY_ENTER 28; F1 0x3b = KEY_F1 59; Esc 0x01 = 1.
        for (make, key) in [(0x1c, 28), (0x3b, 59), (0x01, 1), (0x0e, 14)] {
            let (down, _) = press_release(&mut kbd, &[make], &[make | 0x80]);
            assert_eq!(down[0].keycode, key);
        }
    }

    #[test]
    fn raw_set2_uses_f0_for_release() {
        let mut kbd = Atkbd::new(false);
        // 'a' make 0x1c, break F0 1C
        let (down, up) = press_release(&mut kbd, &[0x1c], &[0xf0, 0x1c]);
        assert_eq!(
            down,
            [KeyEvent {
                keycode: 30,
                value: 1
            }]
        );
        assert_eq!(
            up,
            [KeyEvent {
                keycode: 30,
                value: 0
            }]
        );
        // Right arrow E0 74 / E0 F0 74 = KEY_RIGHT 106
        let (down, up) = press_release(&mut kbd, &[0xe0, 0x74], &[0xe0, 0xf0, 0x74]);
        assert_eq!(
            down,
            [KeyEvent {
                keycode: 106,
                value: 1
            }]
        );
        assert_eq!(
            up,
            [KeyEvent {
                keycode: 106,
                value: 0
            }]
        );
    }

    #[test]
    fn a_repeated_make_code_is_a_hardware_repeat_after_the_duplicate_window() {
        let mut kbd = Atkbd::new(true);
        let first = kbd.receive_byte(0x1e, 0)[0];
        assert_eq!(
            first,
            Some(KeyEvent {
                keycode: 30,
                value: 1
            })
        );
        assert_eq!(kbd.receive_byte(0x1e, 50)[0].map(|e| e.value), Some(1));
        assert_eq!(kbd.receive_byte(0x1e, 400)[0].map(|e| e.value), Some(2));
    }
}
