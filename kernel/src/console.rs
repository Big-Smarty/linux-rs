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
use font8x8::legacy::BASIC_LEGACY;

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
        write_bytes(text.as_bytes());
        Ok(())
    }
}

/// Raw bytes to the same sinks as `log!` (the init task's /dev/console).
pub fn write_bytes(bytes: &[u8]) {
    for &byte in bytes {
        #[cfg(feature = "qemu-self-test")]
        crate::cpu::serial_byte(byte);
        pixel_byte(byte);
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
    // font8x8 legacy table: bit `column` of each row byte is the pixel, LSB
    // leftmost. Printable ASCII is exact; every other byte shows a visible '?'.
    let glyph = BASIC_LEGACY[usize::from(if (b' '..=b'~').contains(&byte) {
        byte
    } else {
        b'?'
    })];
    let foreground = FOREGROUND.load(Ordering::Relaxed);
    for row in 0..16 {
        for column in 0..8 {
            // Each 8x8 glyph row is drawn on two scanlines (8x16 cell).
            let white = glyph[row / 2] & (1 << column) != 0;
            let address = base + (y + row) * pitch + (x + column) * 4;
            // SAFETY: init validated 32bpp layout, dimensions and whole resource
            // extent through BootInfo. Coordinates remain within that extent. The
            // address is a loader-published integer for foreign MMIO, so the
            // pointer takes exposed provenance, not none.
            // MMIO is outside Rust allocations, aligned, writable and nontrapping
            // under the loader resource contract; u32 accepts all bit patterns.
            unsafe {
                ptr::write_volatile(
                    ptr::with_exposed_provenance_mut::<u32>(address),
                    if white { foreground } else { 0 },
                );
            };
        }
    }
}

#[macro_export]
macro_rules! log { ($($arg:tt)*) => { $crate::console::write(format_args!($($arg)*)) }; }
