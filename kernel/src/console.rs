// SPDX-License-Identifier: GPL-2.0-only
//! Allocation-free diagnostics; framebuffer is an external MMIO resource, not
//! Rust allocation memory. Timer IRQ never logs. Emergency output does not lock.
//! This early character sink permits emergency/inter-CPU record interleaving;
//! it is not Linux printk, a record queue, or a promise of atomic whole lines.
//!
//! Display contract. `init` publishes up to `MAX_FRAMEBUFFERS` independently
//! validated loader framebuffers (pure checks in `fbtext`); every character is
//! drawn on all of them from one shared text grid (the smallest grid that fits
//! every accepted screen). The text is also kept in a fixed `SHADOW` of glyph
//! indices; a scroll shifts the shadow and redraws every cell from it, so the
//! framebuffer is only ever *written* (framebuffers are typically
//! write-combined, where reads are orders of magnitude slower than writes) and
//! a redrawn cell never keeps stale pixels. Cost: one full-screen write per
//! scrolled line.
//!
//! Emergency/no-lock properties: no lock, no allocation, no reference to
//! framebuffer or shadow bytes (volatile MMIO stores through exposed-provenance
//! pointers; atomics for the shadow). The cursor is the only coordination: a
//! compare-exchange hands each character a cell and decides who performs a
//! scroll. Reentrant or interleaved writers (an exception during output) may
//! garble text but cannot index outside the grid or the framebuffer; the layout
//! is immutable after the `COUNT` release store in `init`.

use core::{
    fmt::{self, Write},
    ptr,
    sync::atomic::{AtomicU8, AtomicUsize, Ordering},
};
use font8x8::legacy::BASIC_LEGACY;
use kernel::{
    boot::{Framebuffers, MAX_FRAMEBUFFERS},
    fbtext::{self, Layout, MAX_COLS, MAX_ROWS},
};

/// Layout words of one accepted framebuffer; written once by `init`.
struct Slot {
    address: AtomicUsize,
    width: AtomicUsize,
    height: AtomicUsize,
    pitch: AtomicUsize,
    bytes: AtomicUsize,
    foreground: AtomicUsize,
    scale_x: AtomicUsize,
    scale_y: AtomicUsize,
}

impl Slot {
    const fn new() -> Self {
        Self {
            address: AtomicUsize::new(0),
            width: AtomicUsize::new(0),
            height: AtomicUsize::new(0),
            pitch: AtomicUsize::new(0),
            bytes: AtomicUsize::new(0),
            foreground: AtomicUsize::new(0),
            scale_x: AtomicUsize::new(0),
            scale_y: AtomicUsize::new(0),
        }
    }
    fn store(&self, l: &Layout) {
        self.address.store(l.address, Ordering::Relaxed);
        self.width.store(l.width, Ordering::Relaxed);
        self.height.store(l.height, Ordering::Relaxed);
        self.pitch.store(l.pitch, Ordering::Relaxed);
        self.bytes.store(l.bytes, Ordering::Relaxed);
        self.foreground
            .store(l.foreground as usize, Ordering::Relaxed);
        self.scale_x.store(l.scale_x, Ordering::Relaxed);
        self.scale_y.store(l.scale_y, Ordering::Relaxed);
    }
    /// Valid only after `COUNT` (Acquire) covered this slot.
    fn load(&self) -> Layout {
        Layout {
            address: self.address.load(Ordering::Relaxed),
            width: self.width.load(Ordering::Relaxed),
            height: self.height.load(Ordering::Relaxed),
            pitch: self.pitch.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
            #[allow(clippy::cast_possible_truncation)] // stored from a u32
            foreground: self.foreground.load(Ordering::Relaxed) as u32,
            scale_x: self.scale_x.load(Ordering::Relaxed),
            scale_y: self.scale_y.load(Ordering::Relaxed),
            cols: COLS.load(Ordering::Relaxed),
            rows: ROWS.load(Ordering::Relaxed),
        }
    }
}

static SLOTS: [Slot; MAX_FRAMEBUFFERS] = [const { Slot::new() }; MAX_FRAMEBUFFERS];
/// Accepted framebuffers; the Release store publishes `SLOTS`, `COLS`, `ROWS`.
static COUNT: AtomicUsize = AtomicUsize::new(0);
static COLS: AtomicUsize = AtomicUsize::new(0);
static ROWS: AtomicUsize = AtomicUsize::new(0);
/// Next cell, `0..=COLS*ROWS` (see `fbtext::step`).
static CURSOR: AtomicUsize = AtomicUsize::new(0);
static SCROLLS: AtomicUsize = AtomicUsize::new(0);
/// Bare-metal suite pager: milliseconds a full screen stays up before the next
/// page replaces it (0 = ordinary scrolling). Set only after the clock runs.
#[cfg(feature = "baremetal-suite")]
static PAGER_MS: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "baremetal-suite")]
static PAGES: AtomicUsize = AtomicUsize::new(0);
/// Glyph index per cell (`0` = blank), row-major with stride `COLS`.
static SHADOW: [AtomicU8; MAX_COLS * MAX_ROWS] = [const { AtomicU8::new(0) }; MAX_COLS * MAX_ROWS];

/// Publish the permanent boot displays before any AP execution. Returns how
/// many framebuffers can be drawn on; each rejected one is reported on the
/// accepted ones, and the others are still used.
///
/// # Safety
/// Called at most once. For every `Some` entry, the complete pitch*height
/// extent must remain mapped, writable, nontrapping external framebuffer MMIO,
/// outside Rust allocations; no ordinary references to it may exist. Its
/// validated loader reservation and all mappings remain live. Layout atomics
/// must never be republished while normal/emergency readers run. `COUNT`
/// release publishes immutable fields.
pub unsafe fn init(list: &Framebuffers) -> usize {
    let mut accepted = [None; MAX_FRAMEBUFFERS];
    let mut rejected = [None; MAX_FRAMEBUFFERS];
    let (mut count, mut cols, mut rows) = (0, MAX_COLS, MAX_ROWS);
    // The accepted framebuffer that currently bounds the shared grid.
    let mut limit = 0;
    for (index, entry) in list.entries.iter().enumerate() {
        let Some(fb) = entry else { continue };
        match fbtext::validate(fb) {
            Ok(layout) => {
                SLOTS[count].store(&layout);
                accepted[count] = Some((index, layout));
                count += 1;
                if layout.cols < cols || layout.rows < rows {
                    limit = index;
                }
                cols = cols.min(layout.cols);
                rows = rows.min(layout.rows);
            }
            Err(reason) => rejected[index] = Some(reason),
        }
    }
    if count == 0 {
        // Nothing can be drawn. The reasons still reach COM1 under the QEMU
        // self-test profile; the default profile has no other sink, so the
        // screen stays blank (documented limitation, not a silent success).
        report_rejects(list, rejected);
        return 0;
    }
    COLS.store(cols, Ordering::Relaxed);
    ROWS.store(rows, Ordering::Relaxed);
    for (_, layout) in accepted.iter().flatten() {
        clear(layout);
    }
    // Release publishes all immutable layout fields to emergency readers. No
    // device/CPU mutates these atomics after initialization; no ordinary refs
    // are ever formed to the framebuffer. Cursor only allocates cell numbers.
    COUNT.store(count, Ordering::Release);
    crate::log!(
        "console: framebuffers used={} reported={} grid={}x{} limit=fb{}\n",
        count,
        list.reported,
        cols,
        rows,
        limit
    );
    for (index, layout) in accepted.iter().flatten() {
        crate::log!(
            "console: fb{} {}x{} bpp={} font={}x{}\n",
            index,
            layout.width,
            layout.height,
            layout.bytes * 8,
            layout.cell_width(),
            layout.cell_height()
        );
    }
    report_rejects(list, rejected);
    count
}

/// One line per loader entry that cannot be drawn on (to every working sink).
fn report_rejects(list: &Framebuffers, rejected: [Option<fbtext::Reject>; MAX_FRAMEBUFFERS]) {
    for (index, entry) in list.entries.iter().enumerate() {
        if let Some(reason) = rejected[index] {
            crate::log!("console: fb{} rejected: {}\n", index, reason.name());
        } else if entry.is_none() && (index as u64) < list.reported {
            crate::log!("console: fb{} rejected: loader validation\n", index);
        }
    }
}

/// Store one pixel; the only place framebuffer bytes are written.
fn put(l: &Layout, x: usize, y: usize, pixel: u32) {
    if x >= l.width || y >= l.height {
        return;
    }
    let address = l.address + y * l.pitch + x * l.bytes;
    let b = pixel.to_le_bytes();
    // SAFETY: `init` validated (fbtext::validate) the layout and `fbtext` plus
    // the loader boot check established that pitch*height bytes from `address`
    // are framebuffer MMIO; the check above keeps (x, y) inside width x height,
    // and pitch >= width*bytes, so [address, address+bytes) is inside that
    // extent. The address is a loader-published integer for foreign MMIO, so
    // the pointer takes exposed provenance, not none. MMIO is outside Rust
    // allocations, writable and nontrapping under the loader resource contract.
    // 2- and 4-byte stores are aligned (validate checks address and pitch);
    // 3-byte pixels are three byte stores. Every bit pattern is valid.
    unsafe {
        match l.bytes {
            4 => ptr::write_volatile(
                ptr::with_exposed_provenance_mut::<u32>(address),
                u32::from_le_bytes(b),
            ),
            2 => ptr::write_volatile(
                ptr::with_exposed_provenance_mut::<u16>(address),
                u16::from_le_bytes([b[0], b[1]]),
            ),
            _ => {
                for (i, byte) in b[..3].iter().enumerate() {
                    ptr::write_volatile(ptr::with_exposed_provenance_mut::<u8>(address + i), *byte);
                }
            }
        }
    }
}

fn clear(l: &Layout) {
    for y in 0..l.height {
        for x in 0..l.width {
            put(l, x, y, 0);
        }
    }
}

/// One pixel scanline of one cell. Glyph `0` (never written) is blank.
fn scanline(l: &Layout, col: usize, row: usize, line: usize, glyph: u8) {
    let glyph = if glyph == 0 { b' ' } else { glyph };
    // font8x8 legacy table: bit `column` of each row byte is the pixel, LSB
    // leftmost. Each of the 8 glyph rows is drawn on `scale_y` scanlines.
    let bits = BASIC_LEGACY[usize::from(glyph)][line / l.scale_y];
    let (x0, y) = (col * l.cell_width(), row * l.cell_height() + line);
    for px in 0..l.cell_width() {
        let on = fbtext::glyph_pixel(bits, px, l.scale_x);
        put(l, x0 + px, y, if on { l.foreground } else { 0 });
    }
}

fn draw_cell(l: &Layout, col: usize, row: usize, glyph: u8) {
    for line in 0..l.cell_height() {
        scanline(l, col, row, line, glyph);
    }
}

/// Cell glyph with the never-written `0` shown as a space.
const fn shown(glyph: u8) -> u8 {
    if glyph == 0 { b' ' } else { glyph }
}

/// Shift the text up one line and redraw the cells whose glyph changed on every
/// framebuffer. Most of a log screen is blank over blank, so skipping equal
/// cells removes most of the writes (a full redraw is `width*height*bytes` per
/// scrolled line). Trade-off: a cell garbled by a reentrant or interleaved
/// writer is no longer repaired by the next scroll, only by being rewritten.
/// Per row, changed cells are drawn scanline-major so adjacent changed cells are
/// written in ascending runs (write-combining friendly).
fn scroll(count: usize) {
    let (cols, rows) = (COLS.load(Ordering::Relaxed), ROWS.load(Ordering::Relaxed));
    for row in 0..rows {
        // Rows are processed top to bottom, so row+1 still holds its old text.
        let mut changed = [0u64; MAX_COLS / 64];
        for col in 0..cols {
            let old = SHADOW[row * cols + col].load(Ordering::Relaxed);
            let new = if row + 1 < rows {
                SHADOW[(row + 1) * cols + col].load(Ordering::Relaxed)
            } else {
                0
            };
            SHADOW[row * cols + col].store(new, Ordering::Relaxed);
            if shown(old) != shown(new) {
                changed[col / 64] |= 1 << (col % 64);
            }
        }
        if changed.iter().all(|&word| word == 0) {
            continue;
        }
        for slot in &SLOTS[..count] {
            let l = slot.load();
            for line in 0..l.cell_height() {
                for col in 0..cols {
                    if changed[col / 64] & (1 << (col % 64)) != 0 {
                        let glyph = SHADOW[row * cols + col].load(Ordering::Relaxed);
                        scanline(&l, col, row, line, glyph);
                    }
                }
            }
        }
    }
    SCROLLS.fetch_add(1, Ordering::Relaxed);
    drain();
}

/// Make everything written so far leave the CPU's write-combining buffers.
///
/// The framebuffer is mapped write-combining (`paging.rs`, PAT[5]); Intel and
/// AMD drain a partly filled WC buffer at their discretion, so the last lines
/// before `cli; hlt` could stay invisible. `SFENCE` orders and drains WC
/// stores (Intel SDM vol. 3, buffering of write-combining memory; AMD APM vol. 2,
/// write-combining memory type).
///
/// `core::arch::x86_64::_mm_sfence` is an intrinsic, not `asm!`. It is declared
/// with `#[target_feature(enable = "sse")]`, which this soft-float target cannot
/// enable on our own functions (`x86_softfloat_sse` deny), so it is called as an
/// out-of-line `unsafe` call from a function without the feature. The callee only
/// executes `sfence`: no registers or flags other than RIP, no XMM/MMX state (the
/// kernel never saves FP state in the kernel), no stack effect, and a compiler
/// memory barrier. The emitted instruction is checked in the disassembly (see
/// docs/implementation.md, "Framebuffer console on real hardware"). SFENCE's
/// only exceptions are `#UD` when CPUID.01H:EDX.SSE is clear or with a LOCK
/// prefix (Intel SDM vol. 2 and AMD APM vol. 3, SFENCE exception tables); it is
/// not subject to CR0.EM/TS or CR4.OSFXSR, and every x86-64 CPU has SSE.
fn drain() {
    if COUNT.load(Ordering::Relaxed) != 0 {
        // SAFETY: SFENCE exists on every x86_64 CPU (SSE is architectural there),
        // has no operands, and has no effect besides ordering/draining stores; it
        // is valid at any CPL and in any interrupt context. The only reason the
        // call is `unsafe` is the callee's `sse` target-feature attribute.
        unsafe { core::arch::x86_64::_mm_sfence() };
    }
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
        #[cfg(feature = "baremetal-suite")]
        crate::baremetal::capture_byte(byte);
        #[cfg(feature = "qemu-self-test")]
        crate::cpu::serial_byte(byte);
        #[cfg(feature = "baremetal-suite")]
        crate::baremetal::screen_byte(byte, pixel_byte);
        #[cfg(not(feature = "baremetal-suite"))]
        pixel_byte(byte);
    }
    // One drain per call: the chunk just written must be visible before a caller
    // can halt.
    drain();
}

pub fn write(arguments: fmt::Arguments<'_>) {
    let _ = Console.write_fmt(arguments);
}

fn pixel_byte(byte: u8) {
    let count = COUNT.load(Ordering::Acquire);
    if count == 0 || byte == b'\r' {
        return;
    }
    let (cols, rows) = (COLS.load(Ordering::Relaxed), ROWS.load(Ordering::Relaxed));
    if byte == b'\t' {
        // fbcon/vt: advance to the next multiple of 8 columns (spaces, no glyph).
        let column = (CURSOR.load(Ordering::Relaxed) >> 1) % cols;
        for _ in 0..8 - column % 8 {
            pixel_byte(b' ');
        }
        return;
    }
    #[cfg(feature = "baremetal-suite")]
    if PAGER_MS.load(Ordering::Relaxed) != 0
        && fbtext::step(CURSOR.load(Ordering::Relaxed), cols, rows, byte == b'\n').scroll
    {
        page_break();
    }
    // Atomically take the next cell even if an exception interrupted output;
    // the winner of the exchange owns any scroll this character implies.
    let mut old = CURSOR.load(Ordering::Relaxed);
    let step = loop {
        let step = fbtext::step(old, cols, rows, byte == b'\n');
        match CURSOR.compare_exchange_weak(old, step.next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break step,
            Err(observed) => old = observed,
        }
    };
    if step.scroll {
        scroll(count);
    }
    if let Some(cell) = step.cell {
        // Printable ASCII is exact; every other byte shows a visible '?'.
        let glyph = fbtext::glyph_index(byte);
        SHADOW[cell].store(glyph, Ordering::Relaxed);
        for slot in &SLOTS[..count] {
            draw_cell(&slot.load(), cell % cols, cell / cols, glyph);
        }
    }
}

/// Blank every framebuffer and the text grid and put the cursor at the top
/// left. Writes only (no framebuffer read); the shadow text is reset first so a
/// reentrant writer cannot resurrect old cells.
#[cfg(feature = "baremetal-suite")]
pub fn clear_screen() {
    let count = COUNT.load(Ordering::Acquire);
    for cell in &SHADOW {
        cell.store(0, Ordering::Relaxed);
    }
    CURSOR.store(0, Ordering::Relaxed);
    for slot in &SLOTS[..count] {
        clear(&slot.load());
    }
    drain();
}

/// Turn the pager on (`milliseconds != 0`) or off. While on, a screen that
/// fills up stays visible for that long and is then replaced by a fresh page
/// instead of scrolling, so each page can be photographed (the machine has no
/// keyboard driver and no serial console). Needs the monotonic clock.
#[cfg(feature = "baremetal-suite")]
pub fn set_pager(milliseconds: usize) {
    PAGER_MS.store(milliseconds, Ordering::Relaxed);
}

/// Busy-wait `milliseconds` on the TSC clock (interrupts stay as they are).
#[cfg(feature = "baremetal-suite")]
fn pause(milliseconds: usize) {
    let deadline = crate::timer::ktime_get_ns() + (milliseconds as u64) * 1_000_000;
    while crate::timer::ktime_get_ns() < deadline {
        core::hint::spin_loop();
    }
}

/// Hold the current page, then start an empty one with a page header.
#[cfg(feature = "baremetal-suite")]
pub fn page_hold() {
    page_break();
}

/// Text to the framebuffers only: not serial and not the suite's capture. The
/// suite replays its captured log with this (the log must not capture itself).
#[cfg(feature = "baremetal-suite")]
pub fn write_screen(bytes: &[u8]) {
    for &byte in bytes {
        pixel_byte(byte);
    }
}

#[cfg(feature = "baremetal-suite")]
fn page_break() {
    drain();
    pause(PAGER_MS.load(Ordering::Relaxed));
    clear_screen();
    let page = PAGES.fetch_add(1, Ordering::Relaxed) + 2;
    // Header cells only: not captured and not on serial (it is not log text).
    for byte in header_bytes("-- linux-rs suite, page ", page) {
        pixel_byte(byte);
    }
}

/// `prefix` followed by the decimal `number` and a newline, byte by byte.
#[cfg(feature = "baremetal-suite")]
fn header_bytes(prefix: &'static str, number: usize) -> impl Iterator<Item = u8> {
    let mut digits = [0u8; 20];
    let mut length = 0;
    let mut rest = number;
    loop {
        digits[length] = b'0' + u8::try_from(rest % 10).unwrap_or(0);
        length += 1;
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    prefix
        .bytes()
        .chain((0..length).rev().map(move |i| digits[i]))
        .chain(core::iter::once(b'\n'))
}

/// Layout facts of every drawn framebuffer, in slot order:
/// `(width, height, bits per pixel, columns, rows)`.
#[cfg(feature = "baremetal-suite")]
pub fn for_each_framebuffer(mut visit: impl FnMut(usize, usize, usize, usize, usize)) {
    let count = COUNT.load(Ordering::Acquire);
    let (cols, rows) = (COLS.load(Ordering::Relaxed), ROWS.load(Ordering::Relaxed));
    for slot in &SLOTS[..count] {
        let l = slot.load();
        visit(l.width, l.height, l.bytes * 8, cols, rows);
    }
}

/// The shared text grid `(columns, rows)`, `(0, 0)` without a framebuffer.
#[cfg(feature = "baremetal-suite")]
pub fn grid() -> (usize, usize) {
    if COUNT.load(Ordering::Acquire) == 0 {
        return (0, 0);
    }
    (COLS.load(Ordering::Relaxed), ROWS.load(Ordering::Relaxed))
}

/// Read one pixel back (self-test only; framebuffer reads can be very slow).
#[cfg(feature = "boot-proofs")]
fn get(l: &Layout, x: usize, y: usize) -> u32 {
    let address = l.address + y * l.pitch + x * l.bytes;
    let mut b = [0u8; 4];
    for (i, byte) in b[..l.bytes].iter_mut().enumerate() {
        // SAFETY: same extent argument as `put` (callers pass x < width,
        // y < height); byte loads from MMIO are valid for every address in it.
        *byte = unsafe { ptr::read_volatile(ptr::with_exposed_provenance::<u8>(address + i)) };
    }
    u32::from_le_bytes(b)
}

/// Whether the pixels of a cell on this framebuffer equal what its shadow
/// glyph must render (stale pixels or a failed scroll redraw differ).
#[cfg(feature = "boot-proofs")]
fn cell_matches(l: &Layout, col: usize, row: usize) -> bool {
    let cols = COLS.load(Ordering::Relaxed);
    let glyph = SHADOW[row * cols + col].load(Ordering::Relaxed);
    let glyph = if glyph == 0 { b' ' } else { glyph };
    (0..l.cell_height()).all(|line| {
        let bits = BASIC_LEGACY[usize::from(glyph)][line / l.scale_y];
        (0..l.cell_width()).all(|px| {
            let want = if fbtext::glyph_pixel(bits, px, l.scale_x) {
                l.foreground
            } else {
                0
            };
            get(l, col * l.cell_width() + px, row * l.cell_height() + line) == want
        })
    })
}

/// Write enough marker lines to force scrolling, then check the shadow tail,
/// that no stale cell survives, and that the pixels on every framebuffer match.
/// Output goes to the framebuffer only (not serial), then a CHECK record is
/// logged. Returns whether all checks held.
#[cfg(feature = "boot-proofs")]
pub fn self_test() -> bool {
    let count = COUNT.load(Ordering::Acquire);
    let (cols, rows) = (COLS.load(Ordering::Relaxed), ROWS.load(Ordering::Relaxed));
    if count == 0 {
        return false;
    }
    let before = SCROLLS.load(Ordering::Relaxed);
    pixel_byte(b'\n');
    let lines = rows + 2;
    // Six varying characters per line so a scroll changes several cells per row.
    let letter = |i: usize, k: usize| b'A' + u8::try_from((i + k) % 26).unwrap_or(0);
    for i in 0..lines {
        for k in 0..6.min(cols) {
            pixel_byte(letter(i, k));
        }
        pixel_byte(b'\n');
    }
    let scrolled = SCROLLS.load(Ordering::Relaxed) - before >= 2;
    let (mut tail, mut stale) = (true, false);
    for row in 0..rows {
        for k in 0..6.min(cols) {
            tail &= SHADOW[row * cols + k].load(Ordering::Relaxed) == letter(lines - rows + row, k);
        }
        stale |= (6..cols).any(|col| SHADOW[row * cols + col].load(Ordering::Relaxed) != 0);
    }
    // Pixels of whole rows (top, middle, bottom) must equal their shadow.
    let mut readback = true;
    for slot in &SLOTS[..count] {
        let l = slot.load();
        for row in [0, rows / 2, rows - 1] {
            for col in 0..cols {
                readback &= cell_matches(&l, col, row);
            }
        }
    }
    // Deferred wrap: a line of exactly `cols` characters plus '\n' leaves no blank
    // line, so the next line starts directly under it.
    pixel_byte(b'\n');
    for _ in 0..cols {
        pixel_byte(b'x');
    }
    pixel_byte(b'\n');
    pixel_byte(b'W');
    let cell = (CURSOR.load(Ordering::Relaxed) >> 1).saturating_sub(1);
    let wrap = cols >= 2
        && cell.is_multiple_of(cols)
        && cell >= cols
        && SHADOW[cell].load(Ordering::Relaxed) == b'W'
        && SHADOW[cell - 1].load(Ordering::Relaxed) == b'x'
        && SHADOW[cell - cols].load(Ordering::Relaxed) == b'x';
    let ok = scrolled && tail && !stale && readback && wrap;
    crate::log!(
        "CHECK console {} framebuffers={} scrolled={} tail={} stale={} readback={} wrap={}\n",
        if ok { "ok" } else { "FAILED" },
        count,
        scrolled,
        tail,
        stale,
        readback,
        wrap
    );
    ok
}

#[macro_export]
macro_rules! log { ($($arg:tt)*) => { $crate::console::write(format_args!($($arg)*)) }; }
