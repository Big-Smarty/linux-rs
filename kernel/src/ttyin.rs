// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: drivers/tty/tty_buffer.c (the flip
// buffer: `tty_insert_flip_char`, `flush_to_ldisc` 485-540),
// drivers/tty/serial/8250/8250_port.c (`serial8250_rx_chars` 1740-1800,
// `serial8250_read_char`, `serial8250_handle_irq`, `serial8250_do_set_termios`
// status masks), drivers/tty/serial/serial_core.c (`uart_insert_char`),
// drivers/input/serio/i8042.c (`i8042_interrupt` 563-700), drivers/tty/vt/
// keyboard.c (`put_queue`: the keyboard inserts into the tty's flip buffer).
// All GPL-2.0.
// Transformation: the flip buffer is a ring of (byte, flag) entries filled by
// the input interrupts and emptied by [`flush`] under the process lock; there is
// no `kworker`, the interrupt itself takes the lock (it can only arrive in ring 3
// or in the idle halt, where no lock is held: `services`) and flushes at once;
// input the line discipline had no room for is flushed by the next `tty_parts`
// (and `^S`/`^Q` behind it act at once: `lookahead_bufs`). One 8250 (COM1,
// IRQ4, QEMU builds only: a physical machine has no assumed serial port) and one
// i8042 keyboard (IRQ1).
//! Input of the console tty: the flip buffer and the interrupt glue.
//!
//! Lock order: `PROCESS` -> `i8042::STATE` -> `RX` (a leaf; the keyboard path holds
//! `STATE` across `push`, nothing takes them in the other order). The interrupt
//! handlers read the device, then take `PROCESS` (never `RX` first), so no handler
//! waits for a lock the interrupted code holds (it cannot hold one: see `services`).

#![cfg_attr(
    feature = "baremetal-suite",
    allow(dead_code, reason = "the bare-metal suite runs no console input")
)]

use crate::services::IrqMutex;
use kernel::syscall::Console;
use kernel::tty::{Host, Tty};

/// A host that can only put bytes on the wire (no foreground group to signal).
pub(crate) struct Wire<'a>(pub &'a mut dyn Console);

impl Host for Wire<'_> {
    fn kill_pgrp(&mut self, _pgrp: kernel::task::pid::PidRef, _sig: u8) {}
    fn transmit(&mut self, bytes: &[u8]) {
        self.0.write(bytes);
    }
}

/// Linux bounds the flip buffers by `TTYB_DEFAULT_MEM_LIMIT` (640 KiB of buffers,
/// tty_buffer.c:31); this ring holds 4096 two-byte entries (8 KiB).
/// shortcut: input beyond the ring is dropped much earlier than on Linux, grow
/// the ring (or make it dynamic) if a workload pastes more than ~8 KiB at once.
const RX_CAP: usize = 4096;

/// The flip buffer: (byte, flag) pairs, oldest first.
struct Rx {
    entries: [u16; RX_CAP],
    head: usize,
    tail: usize,
    /// `tty_buffer.lookahead` as an absolute index: entries below it were
    /// offered to the discipline's `lookahead_buf` already.
    lookahead: usize,
    dropped: u64,
}

static RX: IrqMutex<Rx> = IrqMutex::new(Rx {
    entries: [0; RX_CAP],
    head: 0,
    tail: 0,
    lookahead: 0,
    dropped: 0,
});

impl Rx {
    fn push(&mut self, byte: u8, flag: u8) {
        if self.head - self.tail == RX_CAP {
            // The flip buffer is full: input is dropped, as when the port's
            // buffer memory limit is reached.
            self.dropped += 1;
            return;
        }
        self.entries[self.head % RX_CAP] = u16::from(byte) | u16::from(flag) << 8;
        self.head += 1;
    }
    fn peek(&self, bytes: &mut [u8], flags: &mut [u8]) -> usize {
        self.peek_from(self.tail, bytes, flags)
    }
    fn peek_from(&self, from: usize, bytes: &mut [u8], flags: &mut [u8]) -> usize {
        let n = (self.head - from).min(bytes.len());
        for i in 0..n {
            [bytes[i], flags[i]] = self.entries[(from + i) % RX_CAP].to_le_bytes();
        }
        n
    }
    fn advance(&mut self, n: usize) {
        self.tail += n;
    }
}

use core::sync::atomic::{AtomicBool, Ordering};

/// The keyboard and UART interrupts are armed (their vectors are expected).
static KEYBOARD: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "qemu-self-test")]
static SERIAL: AtomicBool = AtomicBool::new(false);

pub(crate) fn keyboard_enabled() -> bool {
    KEYBOARD.load(Ordering::Acquire)
}
#[cfg(feature = "qemu-self-test")]
pub(crate) fn serial_enabled() -> bool {
    SERIAL.load(Ordering::Acquire)
}

/// Bring up the console tty's input devices: the 8250 receive interrupt (QEMU
/// profile) and the i8042 keyboard.
///
/// # Safety
/// BSP, IF clear, after `timer::init`, `cpu::install_descriptors` and the
/// installation of the process state the interrupts will take.
#[cfg(not(feature = "baremetal-suite"))]
pub(crate) unsafe fn init() {
    #[cfg(feature = "qemu-self-test")]
    {
        // SAFETY: the caller's contract; the QEMU profile has the 8250 at COM1.
        unsafe { init_serial() };
        SERIAL.store(true, Ordering::Release);
    }
    // SAFETY: the caller's contract.
    let routed = unsafe { crate::i8042::init() };
    KEYBOARD.store(routed, Ordering::Release);
}

/// Queue one received character with its status flag (`TTY_NORMAL`, `TTY_BREAK`,
/// ...) for the next [`flush`].
pub(crate) fn push(byte: u8, flag: u8) {
    RX.lock().push(byte, flag);
}

/// `flush_to_ldisc`: hand the queued input to the line discipline. Input the
/// discipline has no room for stays queued until the next `flush` (every tty
/// entry and input interrupt calls it).
pub(crate) fn flush(tty: &mut Tty, host: &mut dyn Host) {
    loop {
        let mut bytes = [0u8; 64];
        let mut flags = [0u8; 64];
        let n = RX.lock().peek(&mut bytes, &mut flags);
        if n == 0 {
            return;
        }
        let used = tty.receive_buf(host, &bytes[..n], Some(&flags[..n]));
        RX.lock().advance(used);
        if used < n {
            lookahead(tty, host);
            return;
        }
    }
}

/// `lookahead_bufs`: offer everything queued and not yet offered to the
/// discipline's `lookahead_buf` (`^S`/`^Q` behind a full input buffer).
fn lookahead(tty: &mut Tty, host: &mut dyn Host) {
    loop {
        let mut bytes = [0u8; 64];
        let mut flags = [0u8; 64];
        let n = {
            let mut rx = RX.lock();
            rx.lookahead = rx.lookahead.max(rx.tail);
            rx.peek_from(rx.lookahead, &mut bytes, &mut flags)
        };
        if n == 0 {
            return;
        }
        tty.lookahead_flow_ctrl(host, &bytes[..n], Some(&flags[..n]));
        RX.lock().lookahead += n;
    }
}

/// Whether input was dropped since boot (diagnostics).
#[allow(dead_code, reason = "reported by the self-test record when it exists")]
pub(crate) fn dropped() -> u64 {
    RX.lock().dropped
}

// ---- the 8250 (COM1, QEMU builds) --------------------------------------------

#[cfg(feature = "qemu-self-test")]
mod uart {
    use crate::cpu::{in_byte, out_byte};
    use kernel::tty::{
        Tty,
        ldisc::{TTY_BREAK, TTY_FRAME, TTY_NORMAL, TTY_OVERRUN, TTY_PARITY},
        termios::{BRKINT, CREAD, IGNBRK, IGNPAR, INPCK, PARMRK},
    };

    const RBR: u16 = 0x3f8;
    const IER: u16 = 0x3f9;
    const IIR: u16 = 0x3fa;
    const FCR: u16 = 0x3fa;
    const LSR: u16 = 0x3fd;
    const LSR_DR: u8 = 0x01;
    const LSR_OE: u8 = 0x02;
    const LSR_PE: u8 = 0x04;
    const LSR_FE: u8 = 0x08;
    const LSR_BI: u8 = 0x10;
    const LSR_THRE: u8 = 0x20;
    pub(super) const IRQ: u8 = 4;

    /// Enable the receive and line-status interrupts with a trigger level of one
    /// byte (the transmit FIFO and the output side stay as `serial_init` left them).
    pub(super) fn enable() {
        // Enable FIFOs, clear both, trigger level 1 byte.
        out_byte(FCR, 0x07);
        // Receive data + receive line status (`UART_IER_RLSI | UART_IER_RDI`).
        out_byte(IER, 0x05);
    }

    /// `UART_IIR_NO_INT`: nothing is pending any more.
    pub(super) fn idle() -> bool {
        in_byte(IIR) & 1 != 0
    }

    /// `serial8250_rx_chars` + `uart_insert_char`: one batch of the receive FIFO as
    /// (byte, flag) pairs filtered by the termios status masks. Returns the count.
    pub(super) fn read(tty: &Tty, out: &mut [(u8, u8); 64]) -> usize {
        let t = &tty.termios;
        // serial8250_do_set_termios: read_status_mask / ignore_status_mask.
        let mut read_mask = LSR_OE | LSR_THRE | LSR_DR;
        if t.iflag & INPCK != 0 {
            read_mask |= LSR_FE | LSR_PE;
        }
        if t.iflag & (BRKINT | PARMRK) != 0 {
            read_mask |= LSR_BI;
        }
        let mut ignore_mask = 0;
        if t.iflag & INPCK != 0 {
            ignore_mask |= LSR_PE | LSR_FE;
        }
        if t.iflag & IGNBRK != 0 {
            ignore_mask |= LSR_BI;
            if t.iflag & IGNPAR != 0 {
                ignore_mask |= LSR_OE;
            }
        }
        if t.cflag & CREAD == 0 {
            ignore_mask |= LSR_DR;
        }
        let mut n = 0;
        let mut budget = 256;
        let mut lsr = in_byte(LSR);
        while lsr & LSR_DR != 0 && budget > 0 && n + 2 <= out.len() {
            budget -= 1;
            let ch = in_byte(RBR);
            let mut flag = TTY_NORMAL;
            let mut status = lsr;
            if status & (LSR_BI | LSR_PE | LSR_FE | LSR_OE) != 0 {
                if status & LSR_BI != 0 {
                    status &= !(LSR_FE | LSR_PE);
                }
                status &= read_mask;
                if status & LSR_BI != 0 {
                    flag = TTY_BREAK;
                } else if status & LSR_PE != 0 {
                    flag = TTY_PARITY;
                } else if status & LSR_FE != 0 {
                    flag = TTY_FRAME;
                }
            }
            // uart_insert_char(port, lsr, UART_LSR_OE, ch, flag)
            if status & ignore_mask & !LSR_OE == 0 {
                out[n] = (ch, flag);
                n += 1;
            }
            if status & !ignore_mask & LSR_OE != 0 {
                out[n] = (0, TTY_OVERRUN);
                n += 1;
            }
            lsr = in_byte(LSR);
        }
        n
    }
}

/// Vector 0x34 body: the 8250's interrupt (`serial8250_handle_irq`).
#[cfg(feature = "qemu-self-test")]
pub(crate) fn serial_interrupt() {
    crate::timer::eoi_isa(uart::IRQ);
    crate::userspace::with_tty(|tty, host| {
        // `PASS_LIMIT`: a bounded number of passes until the UART is quiet.
        for _ in 0..256 {
            let mut batch = [(0u8, kernel::tty::ldisc::TTY_NORMAL); 64];
            let n = uart::read(tty, &mut batch);
            for &(byte, flag) in &batch[..n] {
                push(byte, flag);
            }
            flush(tty, host);
            if uart::idle() {
                break;
            }
        }
    });
}

/// Route and enable the UART's receive interrupt.
///
/// # Safety
/// BSP, IF clear, after `timer::init` and `cpu::install_descriptors`; the 8250 at
/// COM1 exists (the self-test profile's QEMU).
#[cfg(feature = "qemu-self-test")]
pub(crate) unsafe fn init_serial() {
    // SAFETY: the caller's contract.
    match unsafe { crate::timer::route_isa_irq(uart::IRQ) } {
        Ok(()) => uart::enable(),
        Err(error) => crate::log!("WARN tty: serial input interrupt not routed: {:?}\n", error),
    }
}
