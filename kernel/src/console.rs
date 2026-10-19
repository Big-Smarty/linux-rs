// SPDX-License-Identifier: GPL-2.0-only
//! Allocation-free diagnostics; framebuffer is an external MMIO resource, not
//! Rust allocation memory. Timer IRQ never logs. Emergency output does not lock.
//! This early character sink permits emergency/inter-CPU record interleaving;
//! it is not Linux printk, a record queue, or a promise of atomic whole lines.

use crate::boot::Framebuffer;
use core::{
    fmt::{self, Write},
    ptr,
    sync::atomic::{AtomicU32, AtomicUsize, Ordering},
};

static ADDRESS: AtomicUsize = AtomicUsize::new(0);
static PITCH: AtomicUsize = AtomicUsize::new(0);
static WIDTH: AtomicUsize = AtomicUsize::new(0);
static HEIGHT: AtomicUsize = AtomicUsize::new(0);
static CURSOR: AtomicUsize = AtomicUsize::new(0);
static FOREGROUND: AtomicU32 = AtomicU32::new(0);

/// Publish the sole permanent boot display before any AP execution.
///
/// # Safety
/// Called at most once. The complete pitch*height extent must remain mapped,
/// writable, nontrapping external framebuffer MMIO, outside Rust allocations;
/// no ordinary references to it may exist. Its validated loader reservation
/// and all mappings remain live. Layout atomics must never be republished while
/// normal/emergency readers run. ADDRESS release publishes immutable fields.
pub unsafe fn init(display: Option<Framebuffer>) -> bool {
    let Some(fb) = display else {
        return false;
    };
    if fb.bpp != 32
        || fb.model != 1
        || fb.width < 8
        || fb.height < 16
        || fb.width > 16384
        || fb.height > 16384
        || fb.pitch < fb.width * 4
        || fb.address & 3 != 0
        || fb.pitch & 3 != 0
        || fb.red_size != 8
        || fb.green_size != 8
        || fb.blue_size != 8
    {
        return false;
    }
    // Reject overlapping channels before constructing the monochrome RGB mask.
    if fb.red_shift > 24
        || fb.green_shift > 24
        || fb.blue_shift > 24
        || fb.red_shift.abs_diff(fb.green_shift) < 8
        || fb.red_shift.abs_diff(fb.blue_shift) < 8
        || fb.green_shift.abs_diff(fb.blue_shift) < 8
    {
        return false;
    }
    let (Ok(pitch), Ok(width), Ok(height), Ok(address)) = (
        usize::try_from(fb.pitch),
        usize::try_from(fb.width),
        usize::try_from(fb.height),
        usize::try_from(fb.address),
    ) else {
        return false;
    };
    PITCH.store(pitch, Ordering::Relaxed);
    WIDTH.store(width, Ordering::Relaxed);
    HEIGHT.store(height, Ordering::Relaxed);
    let foreground =
        (0xffu32 << fb.red_shift) | (0xffu32 << fb.green_shift) | (0xffu32 << fb.blue_shift);
    FOREGROUND.store(foreground, Ordering::Relaxed);
    // Release publishes all immutable layout fields to emergency readers. No
    // device/CPU mutates these atomics after initialization; no ordinary refs
    // are ever formed to the framebuffer. Cursor only allocates cell numbers.
    ADDRESS.store(address, Ordering::Release);
    true
}

struct Console;
impl Write for Console {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        for byte in text.bytes() {
            #[cfg(feature = "qemu-self-test")]
            crate::cpu::serial_byte(byte);
            pixel_byte(byte);
        }
        Ok(())
    }
}

pub fn write(arguments: fmt::Arguments<'_>) {
    let _ = Console.write_fmt(arguments);
}

fn pixel_byte(byte: u8) {
    let base = ADDRESS.load(Ordering::Acquire);
    if base == 0 {
        return;
    }
    let pitch = PITCH.load(Ordering::Relaxed);
    let width = WIDTH.load(Ordering::Relaxed) / 8;
    let height = HEIGHT.load(Ordering::Relaxed) / 16;
    if byte == b'\n' {
        // Atomically move to next line even if an exception interrupted output.
        let mut old = CURSOR.load(Ordering::Relaxed);
        loop {
            let next = ((old / width + 1) % height) * width;
            match CURSOR.compare_exchange_weak(old, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => break,
                Err(observed) => old = observed,
            }
        }
        return;
    }
    if byte == b'\r' {
        return;
    }
    let cell = CURSOR.fetch_add(1, Ordering::Relaxed) % (width * height);
    let x = cell % width * 8;
    let y = cell / width * 16;
    let glyph = glyph(byte.to_ascii_uppercase());
    let foreground = FOREGROUND.load(Ordering::Relaxed);
    for row in 0..16 {
        for column in 0..8 {
            let white = row > 0
                && row < 15
                && column > 0
                && column < 6
                && glyph[(row - 1) / 2] & (1 << (5 - column)) != 0;
            let address = base + (y + row) * pitch + (x + column) * 4;
            // SAFETY: init validated 32bpp layout, dimensions and whole resource
            // extent through BootInfo. Coordinates remain within that extent.
            // MMIO is outside Rust allocations, aligned, writable and nontrapping
            // under the loader resource contract; u32 accepts all bit patterns.
            unsafe {
                ptr::write_volatile(
                    ptr::without_provenance_mut(address),
                    if white { foreground } else { 0 },
                );
            };
        }
    }
}

// Original compact 5x7 diagnostic glyphs, doubled vertically, no external font.
fn glyph(byte: u8) -> [u8; 7] {
    match byte {
        b'A' => [14, 17, 17, 31, 17, 17, 17],
        b'B' => [30, 17, 17, 30, 17, 17, 30],
        b'C' => [14, 17, 16, 16, 16, 17, 14],
        b'D' => [30, 17, 17, 17, 17, 17, 30],
        b'E' => [31, 16, 16, 30, 16, 16, 31],
        b'F' => [31, 16, 16, 30, 16, 16, 16],
        b'G' => [14, 17, 16, 23, 17, 17, 15],
        b'H' => [17, 17, 17, 31, 17, 17, 17],
        b'I' => [14, 4, 4, 4, 4, 4, 14],
        b'J' => [7, 2, 2, 2, 18, 18, 12],
        b'K' => [17, 18, 20, 24, 20, 18, 17],
        b'L' => [16, 16, 16, 16, 16, 16, 31],
        b'M' => [17, 27, 21, 21, 17, 17, 17],
        b'N' => [17, 25, 21, 19, 17, 17, 17],
        b'O' => [14, 17, 17, 17, 17, 17, 14],
        b'P' => [30, 17, 17, 30, 16, 16, 16],
        b'Q' => [14, 17, 17, 17, 21, 18, 13],
        b'R' => [30, 17, 17, 30, 20, 18, 17],
        b'S' => [15, 16, 16, 14, 1, 1, 30],
        b'T' => [31, 4, 4, 4, 4, 4, 4],
        b'U' => [17, 17, 17, 17, 17, 17, 14],
        b'V' => [17, 17, 17, 17, 17, 10, 4],
        b'W' => [17, 17, 17, 21, 21, 27, 17],
        b'X' => [17, 17, 10, 4, 10, 17, 17],
        b'Y' => [17, 17, 10, 4, 4, 4, 4],
        b'Z' => [31, 1, 2, 4, 8, 16, 31],
        b'0' => [14, 17, 19, 21, 25, 17, 14],
        b'1' => [4, 12, 4, 4, 4, 4, 14],
        b'2' => [14, 17, 1, 2, 4, 8, 31],
        b'3' => [30, 1, 1, 14, 1, 1, 30],
        b'4' => [2, 6, 10, 18, 31, 2, 2],
        b'5' => [31, 16, 16, 30, 1, 1, 30],
        b'6' => [14, 16, 16, 30, 17, 17, 14],
        b'7' => [31, 1, 2, 4, 8, 8, 8],
        b'8' => [14, 17, 17, 14, 17, 17, 14],
        b'9' => [14, 17, 17, 15, 1, 1, 14],
        b'=' => [0, 0, 31, 0, 31, 0, 0],
        b'-' => [0, 0, 0, 31, 0, 0, 0],
        b':' => [0, 4, 4, 0, 4, 4, 0],
        b'.' => [0, 0, 0, 0, 0, 4, 4],
        b'/' => [1, 1, 2, 4, 8, 16, 16],
        b'_' => [0, 0, 0, 0, 0, 0, 31],
        b' ' => [0; 7],
        _ => [31, 17, 5, 4, 4, 0, 4],
    }
}

#[macro_export]
macro_rules! log { ($($arg:tt)*) => { $crate::console::write(format_args!($($arg)*)) }; }
