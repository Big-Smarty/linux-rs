// SPDX-License-Identifier: GPL-2.0-only
//! Pure framebuffer-text arithmetic: pixel formats, font scale, cursor and
//! scroll geometry. No hardware access; the unsafe MMIO drawing is `console.rs`.
//!
//! Provenance of the font choice: `get_default_font()` in Linux 6.18.57
//! `lib/fonts/fonts.c:111-151` (the scoring loop, reproduced below as
//! `choose_scale`), whose candidates on x86 are `VGA8x16` (`pref` 0,
//! `font_8x16.c:4632`), `VGA8x8` (`pref` 0, `font_8x8.c:2583`) and `TER16x32`
//! (`pref` -1, `font_ter16x32.c:2068`), the fonts `fbcon` falls back to
//! (`fbcon.c:995-998`). We hold only the 8x8 glyph table, so each candidate is
//! an integer scaling of it: 8x8 is scale (1,1), `VGA8x16` is (1,2) (the existing
//! line-doubled look) and `TER16x32` is (2,4). Larger scales (3,6) and (4,8) use
//! `TER16x32`'s `pref`; they only win where Linux's own formula already prefers
//! a bigger font than 16x32 and Linux has none (an extension for >4K panels).

use crate::boot::Framebuffer;

/// Text-grid bounds: the shadow buffer in `console.rs` is `MAX_COLS * MAX_ROWS`.
pub const MAX_COLS: usize = 256;
pub const MAX_ROWS: usize = 128;

/// Why a loader framebuffer cannot be drawn on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reject {
    /// Memory model is not RGB (Limine model 1).
    Model,
    /// Not 16, 24 or 32 bits per pixel.
    Depth,
    /// Width/height outside the supported range or no cell fits.
    Size,
    /// Pitch smaller than one row of pixels, or extent overflows.
    Pitch,
    /// Address or pitch not aligned to the access width.
    Alignment,
    /// A zero-width channel or a channel beyond the pixel.
    Channels,
    /// Two channels share bits.
    Overlap,
}

impl Reject {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Model => "model",
            Self::Depth => "depth",
            Self::Size => "size",
            Self::Pitch => "pitch",
            Self::Alignment => "alignment",
            Self::Channels => "channels",
            Self::Overlap => "overlap",
        }
    }
}

/// A validated, drawable framebuffer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Layout {
    pub address: usize,
    pub width: usize,
    pub height: usize,
    pub pitch: usize,
    /// Bytes per pixel: 2, 3 or 4.
    pub bytes: usize,
    /// White: every bit of every colour channel set; other bits (alpha/pad) zero.
    pub foreground: u32,
    /// Horizontal / vertical scale of the 8x8 glyphs.
    pub scale_x: usize,
    pub scale_y: usize,
    /// Text grid that fits, clamped to `MAX_COLS` x `MAX_ROWS`.
    pub cols: usize,
    pub rows: usize,
}

impl Layout {
    #[must_use]
    pub const fn cell_width(&self) -> usize {
        8 * self.scale_x
    }
    #[must_use]
    pub const fn cell_height(&self) -> usize {
        8 * self.scale_y
    }
}

/// Validate every field the loader supplied; nothing is trusted.
///
/// # Errors
/// The first reason the framebuffer cannot be drawn.
pub fn validate(fb: &Framebuffer) -> Result<Layout, Reject> {
    if fb.model != 1 {
        return Err(Reject::Model);
    }
    let bytes: usize = match fb.bpp {
        16 => 2,
        24 => 3,
        32 => 4,
        _ => return Err(Reject::Depth),
    };
    if fb.width < 8 || fb.height < 8 || fb.width > 16384 || fb.height > 16384 {
        return Err(Reject::Size);
    }
    let (Ok(address), Ok(width), Ok(height), Ok(pitch)) = (
        usize::try_from(fb.address),
        usize::try_from(fb.width),
        usize::try_from(fb.height),
        usize::try_from(fb.pitch),
    ) else {
        return Err(Reject::Size);
    };
    if pitch < width * bytes || pitch.checked_mul(height).is_none() {
        return Err(Reject::Pitch);
    }
    // 2- and 4-byte pixels are written as one aligned store; 3-byte as bytes.
    let alignment = if bytes == 3 { 1 } else { bytes };
    if address % alignment != 0 || pitch % alignment != 0 {
        return Err(Reject::Alignment);
    }
    let channels = [
        (fb.red_size, fb.red_shift),
        (fb.green_size, fb.green_shift),
        (fb.blue_size, fb.blue_shift),
    ];
    let mut foreground = 0u32;
    let depth = u32::from(fb.bpp);
    for (size, shift) in channels {
        // The channel must be non-empty and lie inside the pixel (so <= 32 bits).
        if size == 0 || u32::from(shift) + u32::from(size) > depth {
            return Err(Reject::Channels);
        }
        let mask = u32::try_from((((1u64 << size) - 1) << shift) & u64::from(u32::MAX))
            .map_err(|_| Reject::Channels)?;
        if foreground & mask != 0 {
            return Err(Reject::Overlap);
        }
        foreground |= mask;
    }
    let (scale_x, scale_y) = choose_scale(width, height).ok_or(Reject::Size)?;
    Ok(Layout {
        address,
        width,
        height,
        pitch,
        bytes,
        foreground,
        scale_x,
        scale_y,
        cols: (width / (8 * scale_x)).min(MAX_COLS),
        rows: (height / (8 * scale_y)).min(MAX_ROWS),
    })
}

/// Candidate cells as (`scale_x`, `scale_y`, `pref`), see the module header.
const CANDIDATES: [(usize, usize, i64); 5] =
    [(1, 1, 0), (1, 2, 0), (2, 4, -1), (3, 6, -1), (4, 8, -1)];

/// Linux `get_default_font` scoring (fonts.c:120-149) over the candidates that
/// fit the screen; ties keep the earlier (smaller) candidate like `c > cc`.
#[must_use]
pub fn choose_scale(xres: usize, yres: usize) -> Option<(usize, usize)> {
    let mut best: Option<((usize, usize), i64)> = None;
    for (scale_x, scale_y, pref) in CANDIDATES {
        let (width, height) = (8 * scale_x, 8 * scale_y);
        if width > xres || height > yres {
            continue;
        }
        let mut score = pref;
        if (yres < 400) == (height <= 8) {
            score += 1000;
        }
        // Prefer a bigger font for high resolution.
        let res = i64::try_from((xres / width) * (yres / height) / 1000).unwrap_or(i64::MAX);
        if res > 20 {
            score += 20 - res;
        }
        // fonts.c:141 adds 1000 for every font when no blit mask is given.
        score += 1000;
        if best.is_none_or(|(_, top)| score > top) {
            best = Some(((scale_x, scale_y), score));
        }
    }
    best.map(|(scale, _)| scale)
}

/// One cursor transition. `pos` counts cells in `0..=cols*rows`; `cols*rows`
/// means "the next character first scrolls" (so the last line is not wasted).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Step {
    /// Scroll the text up one line before placing the character.
    pub scroll: bool,
    /// Cell to draw, absent for a newline.
    pub cell: Option<usize>,
    pub next: usize,
}

/// Advance the cursor for a newline or a printable character.
///
/// Requires `cols >= 1`, `rows >= 1` and `pos <= cols * rows`; a larger `pos`
/// is treated as the pending-scroll position so hostile state cannot index out
/// of the grid.
#[must_use]
pub fn step(pos: usize, cols: usize, rows: usize, newline: bool) -> Step {
    let total = cols * rows;
    let pending = pos >= total;
    if newline {
        return Step {
            scroll: pending,
            cell: None,
            next: if pending {
                total
            } else {
                (pos / cols + 1) * cols
            },
        };
    }
    let cell = if pending { total - cols } else { pos };
    Step {
        scroll: pending,
        cell: Some(cell),
        next: cell + 1,
    }
}

/// The glyph index for a byte: printable ASCII is exact, anything else '?'.
#[must_use]
pub const fn glyph_index(byte: u8) -> u8 {
    if byte >= b' ' && byte <= b'~' {
        byte
    } else {
        b'?'
    }
}

/// Whether pixel column `x` (within the cell) of a glyph scanline is set; the
/// 8x8 table has bit `column` = pixel, LSB leftmost.
#[must_use]
pub const fn glyph_pixel(row_bits: u8, x: usize, scale_x: usize) -> bool {
    row_bits & (1 << (x / scale_x)) != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fb(bpp: u16, sizes: [u8; 3], shifts: [u8; 3]) -> Framebuffer {
        Framebuffer {
            address: 0xffff_8000_1000_0000,
            width: 2560,
            height: 1440,
            pitch: 2560 * u64::from(bpp / 8),
            bpp,
            model: 1,
            red_size: sizes[0],
            red_shift: shifts[0],
            green_size: sizes[1],
            green_shift: shifts[1],
            blue_size: sizes[2],
            blue_shift: shifts[2],
        }
    }

    #[test]
    fn standard_formats_build_white() {
        // BGRX8888 (OVMF/AMD GOP) and RGBX8888.
        assert_eq!(
            validate(&fb(32, [8; 3], [16, 8, 0])).unwrap().foreground,
            0x00ff_ffff
        );
        assert_eq!(
            validate(&fb(32, [8; 3], [0, 8, 16])).unwrap().foreground,
            0x00ff_ffff
        );
        // Alpha shifted above: padding byte stays zero.
        assert_eq!(
            validate(&fb(32, [8; 3], [8, 16, 24])).unwrap().foreground,
            0xffff_ff00
        );
    }

    #[test]
    fn ten_bit_and_narrow_formats() {
        // A2R10G10B10 and A2B10G10R10 (GOP BitMask / HDR modes).
        assert_eq!(
            validate(&fb(32, [10; 3], [20, 10, 0])).unwrap().foreground,
            0x3fff_ffff
        );
        assert_eq!(
            validate(&fb(32, [10; 3], [0, 10, 20])).unwrap().foreground,
            0x3fff_ffff
        );
        // RGB565 and 24-bit packed.
        let l = validate(&fb(16, [5, 6, 5], [11, 5, 0])).unwrap();
        assert_eq!((l.foreground, l.bytes), (0xffff, 2));
        let l = validate(&fb(24, [8; 3], [16, 8, 0])).unwrap();
        assert_eq!((l.foreground, l.bytes), (0x00ff_ffff, 3));
        // XRGB1555 reports bpp 16 with 5/5/5.
        assert_eq!(
            validate(&fb(16, [5; 3], [10, 5, 0])).unwrap().foreground,
            0x7fff
        );
    }

    #[test]
    fn rejects_only_the_undrawable() {
        assert_eq!(validate(&fb(8, [3, 3, 2], [5, 2, 0])), Err(Reject::Depth));
        assert_eq!(
            validate(&fb(32, [8; 3], [16, 8, 0]).with_model(0)),
            Err(Reject::Model)
        );
        assert_eq!(
            validate(&fb(32, [0, 8, 8], [16, 8, 0])),
            Err(Reject::Channels)
        );
        assert_eq!(validate(&fb(16, [8; 3], [16, 8, 0])), Err(Reject::Channels));
        assert_eq!(validate(&fb(32, [8; 3], [28, 8, 0])), Err(Reject::Channels));
        assert_eq!(validate(&fb(32, [8; 3], [4, 8, 0])), Err(Reject::Overlap));
        let mut f = fb(32, [8; 3], [16, 8, 0]);
        f.pitch -= 4;
        assert_eq!(validate(&f), Err(Reject::Pitch));
        f.pitch += 6;
        assert_eq!(validate(&f), Err(Reject::Alignment));
        let mut f = fb(32, [8; 3], [16, 8, 0]);
        f.width = 7;
        assert_eq!(validate(&f), Err(Reject::Size));
        f.width = 2560;
        f.address += 2;
        assert_eq!(validate(&f), Err(Reject::Alignment));
        // 24 bpp needs no alignment.
        let mut f = fb(24, [8; 3], [16, 8, 0]);
        f.address += 1;
        assert!(validate(&f).is_ok());
    }

    impl Framebuffer {
        fn with_model(mut self, model: u8) -> Self {
            self.model = model;
            self
        }
    }

    #[test]
    fn font_choice_follows_linux() {
        // yres < 400: only height<=8 fonts get the bonus (VGA8x8).
        assert_eq!(choose_scale(640, 350), Some((1, 1)));
        // VGA/XGA/FHD: VGA8x16.
        assert_eq!(choose_scale(640, 480), Some((1, 2)));
        assert_eq!(choose_scale(1024, 768), Some((1, 2)));
        assert_eq!(choose_scale(1920, 1080), Some((1, 2)));
        // QHD and 4K: TER16x32.
        assert_eq!(choose_scale(2560, 1440), Some((2, 4)));
        assert_eq!(choose_scale(3840, 2160), Some((2, 4)));
        // Beyond Linux's fonts the extension grows with the panel.
        assert_eq!(choose_scale(7680, 4320), Some((4, 8)));
        // Nothing fits.
        assert_eq!(choose_scale(7, 100), None);
    }

    #[test]
    fn grid_is_clamped_to_the_shadow() {
        let l = validate(&fb(32, [8; 3], [16, 8, 0])).unwrap();
        assert_eq!((l.cell_width(), l.cell_height()), (16, 32));
        assert_eq!((l.cols, l.rows), (160, 45));
        let mut f = fb(32, [8; 3], [16, 8, 0]);
        f.width = 16384;
        f.pitch = 16384 * 4;
        f.height = 16384;
        let l = validate(&f).unwrap();
        assert_eq!((l.cols, l.rows), (MAX_COLS, MAX_ROWS));
    }

    #[test]
    fn cursor_scrolls_lazily() {
        let (cols, rows) = (4, 3);
        let total = cols * rows;
        // Ordinary character and newline.
        assert_eq!(
            step(0, cols, rows, false),
            Step {
                scroll: false,
                cell: Some(0),
                next: 1
            }
        );
        assert_eq!(
            step(1, cols, rows, true),
            Step {
                scroll: false,
                cell: None,
                next: 4
            }
        );
        // Newline on the last row makes the scroll pending, not performed.
        assert_eq!(
            step(total - 1, cols, rows, true),
            Step {
                scroll: false,
                cell: None,
                next: total
            }
        );
        // The last cell advances to pending too.
        assert_eq!(
            step(total - 1, cols, rows, false),
            Step {
                scroll: false,
                cell: Some(total - 1),
                next: total
            }
        );
        // A character from pending scrolls once and lands on column 0 of the last row.
        assert_eq!(
            step(total, cols, rows, false),
            Step {
                scroll: true,
                cell: Some(total - cols),
                next: total - cols + 1
            }
        );
        // A newline from pending scrolls once and leaves a blank line.
        assert_eq!(
            step(total, cols, rows, true),
            Step {
                scroll: true,
                cell: None,
                next: total
            }
        );
        // Out-of-range state is clamped, never indexes outside the grid.
        assert_eq!(step(usize::MAX, cols, rows, false).cell, Some(total - cols));
    }

    #[test]
    fn simulated_log_keeps_the_tail() {
        // Model the shadow: 1-char lines through a 4x3 grid.
        let (cols, rows) = (4, 3);
        let mut cells = [0u8; 12];
        let mut pos = 0;
        for line in 0..10u8 {
            for newline in [false, true] {
                let s = step(pos, cols, rows, newline);
                if s.scroll {
                    cells.copy_within(cols.., 0);
                    cells[cols * (rows - 1)..].fill(0);
                }
                if let Some(cell) = s.cell {
                    cells[cell] = b'a' + line;
                }
                pos = s.next;
            }
        }
        assert_eq!([cells[0], cells[4], cells[8]], [b'h', b'i', b'j']);
        assert!(
            cells
                .iter()
                .enumerate()
                .all(|(i, &c)| i % cols == 0 || c == 0)
        );
    }

    #[test]
    fn glyph_helpers() {
        assert_eq!(glyph_index(b'A'), b'A');
        assert_eq!(glyph_index(0x80), b'?');
        assert_eq!(glyph_index(b'\t'), b'?');
        // Pixel x=3 of a scale-2 cell is glyph column 1.
        assert!(glyph_pixel(0b10, 3, 2));
        assert!(!glyph_pixel(0b10, 4, 2));
    }
}
