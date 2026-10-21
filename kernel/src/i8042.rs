// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: drivers/input/serio/i8042.c
// (`i8042_flush` 280-300, `i8042_wait_read`/`i8042_wait_write`, `i8042_command`
// 330-420, `i8042_controller_selftest` 887-925, `i8042_controller_init` 928-1020,
// `i8042_enable_kbd_port` 1068-1085, `i8042_interrupt` 563-700),
// drivers/input/serio/i8042.h and i8042-acpipnpio.h (register and bit names),
// drivers/input/keyboard/atkbd.c (`ATKBD_CMD_ENABLE` after the probe). All GPL-2.0.
// Transformation: port I/O through `cpu::{in_byte, out_byte}` with bounded TSC waits
// (`timer::udelay`); only the keyboard port is driven (the auxiliary port stays
// disabled: no mouse); no ACPI/PnP, DMI quirk or `i8042.*` module-parameter
// handling; the keyboard is not reset or probed (it is left in the scancode set and
// translation the firmware chose, which both `scancode::Atkbd` modes understand) and
// its LEDs are not driven.
//! The i8042 keyboard controller and its keyboard (PS/2), feeding the console tty.
//!
//! shortcut: no keyboard `RESET`/`GETID`/`SSCANSET` probe sequence and no hotplug
//! (`serio` reconnect): a keyboard that is not in scanning mode with set 2 is
//! enabled with `0xF4` only; upgrade with the full `atkbd_probe`/`atkbd_select_set`
//! when a machine needs it.

use crate::{
    cpu::{in_byte, out_byte},
    services::IrqMutex,
    timer::udelay,
};
use kernel::tty::{
    keyboard::{Keyboard, Out, TtyInfo},
    ldisc::{TTY_BREAK, TTY_NORMAL},
    scancode::Atkbd,
};

const DATA: u16 = 0x60;
const STATUS: u16 = 0x64;
const COMMAND: u16 = 0x64;

const STR_OBF: u8 = 0x01;
const STR_IBF: u8 = 0x02;
const STR_AUXDATA: u8 = 0x20;

const CMD_RCTR: u8 = 0x20;
const CMD_WCTR: u8 = 0x60;
const CMD_TEST: u8 = 0xaa;
const RET_TEST: u8 = 0x55;

const CTR_KBDINT: u8 = 0x01;
const CTR_AUXINT: u8 = 0x02;
const CTR_KBDDIS: u8 = 0x10;
const CTR_AUXDIS: u8 = 0x20;
const CTR_XLATE: u8 = 0x40;

/// The ISA line of the keyboard.
pub(crate) const IRQ: u8 = 1;
/// `I8042_BUFFER_SIZE`.
const BUFFER_SIZE: u32 = 16;

struct State {
    atkbd: Atkbd,
    keyboard: Keyboard,
}

static STATE: IrqMutex<Option<State>> = IrqMutex::new(None);

/// `i8042_wait_write`: the input buffer is empty again (bounded).
fn wait_write() -> bool {
    for _ in 0..2000 {
        if in_byte(STATUS) & STR_IBF == 0 {
            return true;
        }
        udelay(50);
    }
    false
}

/// `i8042_wait_read`: an output byte is ready (bounded).
fn wait_read() -> bool {
    for _ in 0..2000 {
        if in_byte(STATUS) & STR_OBF != 0 {
            return true;
        }
        udelay(50);
    }
    false
}

/// `i8042_flush`: drop pending output; false if it never stops (no controller).
fn flush() -> bool {
    let mut count = 0;
    while in_byte(STATUS) & STR_OBF != 0 {
        if count >= BUFFER_SIZE {
            return false;
        }
        count += 1;
        udelay(50);
        let _ = in_byte(DATA);
    }
    true
}

/// Send a controller command with an optional parameter byte, and read `reply`
/// bytes (`i8042_command`).
fn command(cmd: u8, param: Option<u8>, reply: &mut [u8]) -> bool {
    if !wait_write() {
        return false;
    }
    out_byte(COMMAND, cmd);
    if let Some(param) = param {
        if !wait_write() {
            return false;
        }
        out_byte(DATA, param);
    }
    for byte in reply {
        if !wait_read() {
            return false;
        }
        *byte = in_byte(DATA);
    }
    true
}

/// `i8042_controller_init` + `i8042_enable_kbd_port`: returns whether the
/// controller translates (`I8042_CTR_XLATE`), or `None` without a usable
/// controller/keyboard port.
fn controller_init() -> Option<bool> {
    // i8042_controller_check: a floating bus reads all ones.
    if in_byte(STATUS) == 0xff || !flush() {
        return None;
    }
    // i8042_controller_selftest: five tries; on x86 giving up is not fatal.
    for _ in 0..5 {
        let mut reply = [0u8];
        if command(CMD_TEST, None, &mut reply) && reply[0] == RET_TEST {
            break;
        }
        udelay(50_000);
    }
    // A stable read of the command byte.
    let mut ctr = [0u8; 2];
    let mut n = 0usize;
    loop {
        if n >= 10 {
            return None;
        }
        if n != 0 {
            udelay(50);
        }
        let mut reply = [0u8];
        if !command(CMD_RCTR, None, &mut reply) {
            return None;
        }
        ctr[n % 2] = reply[0];
        n += 1;
        if n >= 2 && ctr[0] == ctr[1] {
            break;
        }
    }
    let mut value = ctr[0];
    let translated = value & CTR_XLATE != 0;
    // Disable the keyboard interface and interrupt while the port is set up;
    // the auxiliary port (mouse) stays off.
    value |= CTR_KBDDIS | CTR_AUXDIS;
    value &= !(CTR_KBDINT | CTR_AUXINT);
    if !command(CMD_WCTR, Some(value), &mut []) {
        return None;
    }
    flush();
    // i8042_enable_kbd_port
    value &= !CTR_KBDDIS;
    value |= CTR_KBDINT;
    if !command(CMD_WCTR, Some(value), &mut []) {
        return None;
    }
    Some(translated)
}

/// Enable scanning on the keyboard (`ATKBD_CMD_ENABLE`) and swallow its answer.
fn enable_keyboard() {
    if !wait_write() {
        return;
    }
    out_byte(DATA, 0xf4);
    // 0xFA (ACK) is the answer; a missing keyboard answers nothing.
    for _ in 0..1000 {
        if in_byte(STATUS) & STR_OBF != 0 {
            let _ = in_byte(DATA);
            return;
        }
        udelay(50);
    }
}

/// Probe the controller, bring up the keyboard port and route its interrupt.
/// Silent when there is no i8042 (a machine without PS/2 ports, USB legacy
/// emulation off).
///
/// # Safety
/// BSP, IF clear, after `timer::init` (the delay clock, the interrupt routes) and
/// `cpu::install_descriptors`; the ports 0x60/0x64 are the PC keyboard
/// controller's (no other owner exists in this kernel).
pub(crate) unsafe fn init() {
    let Some(translated) = controller_init() else {
        crate::log!("i8042: no controller\n");
        return;
    };
    *STATE.lock() = Some(State {
        atkbd: Atkbd::new(translated),
        keyboard: Keyboard::new(),
    });
    // SAFETY: the caller's contract.
    match unsafe { crate::timer::route_isa_irq(IRQ) } {
        Ok(()) => {
            enable_keyboard();
            crate::log!("i8042: keyboard port enabled translated={}\n", translated);
        }
        Err(error) => crate::log!("WARN i8042: keyboard interrupt not routed: {:?}\n", error),
    }
}

/// Vector 0x31 body: `i8042_interrupt` -> `atkbd_receive_byte` -> `kbd_keycode`.
pub(crate) fn interrupt() {
    crate::timer::eoi_isa(IRQ);
    let mut bytes = [0u8; BUFFER_SIZE as usize];
    let mut n = 0;
    while n < bytes.len() && in_byte(STATUS) & STR_OBF != 0 {
        let aux = in_byte(STATUS) & STR_AUXDATA != 0;
        let data = in_byte(DATA);
        // The auxiliary port is never enabled; anything from it is dropped.
        if !aux {
            bytes[n] = data;
            n += 1;
        }
    }
    if n == 0 {
        return;
    }
    let now_ms = crate::timer::ktime_get_ns() / 1_000_000;
    crate::userspace::with_tty(|tty, host| {
        let info = TtyInfo {
            echo: tty.termios.lflag & kernel::tty::termios::ECHO != 0,
            output_queued: tty.chars_in_buffer() != 0,
        };
        let mut hold = 0u32;
        {
            let mut guard = STATE.lock();
            let Some(state) = guard.as_mut() else {
                return;
            };
            for &byte in &bytes[..n] {
                for event in state.atkbd.receive_byte(byte, now_ms).into_iter().flatten() {
                    state.keyboard.keycode(
                        event.keycode,
                        event.value,
                        info,
                        &mut |out| match out {
                            Out::Byte(b) => crate::ttyin::push(b, TTY_NORMAL),
                            Out::Break => crate::ttyin::push(0, TTY_BREAK),
                            Out::Hold => hold += 1,
                        },
                    );
                }
            }
        }
        for _ in 0..hold {
            tty.hold_toggle(host);
        }
        crate::ttyin::flush(tty, host);
    });
}
