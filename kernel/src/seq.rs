// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: fs/seq_file.c (GPL-2.0:
// `seq_escape`, `seq_puts`, `seq_printf`, `seq_putc`, the full-buffer retry
// protocol), lib/string_helpers.c (`string_escape_mem`, `ESCAPE_OCTAL`).
// Copyright of the originals: Linus Torvalds and the VFS authors.
// Transformation: the buffer grows fallibly (`try_reserve`) instead of being
// doubled and the show function re-run; a failed growth is `ENOMEM`.
#![forbid(unsafe_code)]
//! A fallible, growable output buffer for the text files of `procfs` and the
//! mount tables (`seq_file`'s `m->buf`).
//!
//! # Contract
//! * Context: any (it allocates, so task context only in the kernel).
//! * Allocation: every append reserves first and reports failure; the buffer
//!   never grows infallibly, and a failed append leaves what was written so far
//!   intact.
//! * It implements [`core::fmt::Write`], so `write!(seq, "{} {}", a, b)` is
//!   `seq_printf`; a formatting error here means the allocator refused.

use alloc::vec::Vec;
use core::fmt;
use syscalls::Errno;

/// The output of a `show` function.
#[derive(Default)]
pub struct Seq {
    buf: Vec<u8>,
}

impl Seq {
    #[must_use]
    pub const fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// `seq_write`.
    ///
    /// # Errors
    /// `ENOMEM`.
    pub fn put(&mut self, bytes: &[u8]) -> Result<(), Errno> {
        self.buf
            .try_reserve(bytes.len())
            .map_err(|_| Errno::ENOMEM)?;
        for &byte in bytes {
            self.buf
                .push_within_capacity(byte)
                .map_err(|_| Errno::ENOMEM)?;
        }
        Ok(())
    }

    /// `seq_puts`.
    ///
    /// # Errors
    /// `ENOMEM`.
    pub fn puts(&mut self, text: &str) -> Result<(), Errno> {
        self.put(text.as_bytes())
    }

    /// `seq_putc`.
    ///
    /// # Errors
    /// `ENOMEM`.
    pub fn putc(&mut self, byte: u8) -> Result<(), Errno> {
        self.put(&[byte])
    }

    /// `seq_escape`: `bytes` with every byte of `esc` written as `\ooo` (three
    /// octal digits, `string_escape_mem(..., ESCAPE_OCTAL, esc)`).
    ///
    /// # Errors
    /// `ENOMEM`.
    pub fn escape(&mut self, bytes: &[u8], esc: &[u8]) -> Result<(), Errno> {
        for &byte in bytes {
            if esc.contains(&byte) {
                self.put(&[
                    b'\\',
                    b'0' + (byte >> 6),
                    b'0' + ((byte >> 3) & 7),
                    b'0' + (byte & 7),
                ])?;
            } else {
                self.putc(byte)?;
            }
        }
        Ok(())
    }

    /// Everything written so far.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Bytes written so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// The buffer, consuming the writer.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

impl fmt::Write for Seq {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.put(text.as_bytes()).map_err(|_| fmt::Error)
    }
}

/// `seq_printf` that reports allocation failure as `ENOMEM`.
///
/// # Errors
/// `ENOMEM`.
pub fn print(seq: &mut Seq, args: fmt::Arguments<'_>) -> Result<(), Errno> {
    fmt::write(seq, args).map_err(|_| Errno::ENOMEM)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_writes_octal_for_the_listed_bytes_only() {
        let mut seq = Seq::new();
        seq.escape(b"a b\tc\\d#e\n", b" \t\n\\#").unwrap();
        assert_eq!(seq.as_bytes(), b"a\\040b\\011c\\134d\\043e\\012");
    }

    #[test]
    fn formatting_appends() {
        let mut seq = Seq::new();
        print(&mut seq, format_args!("{}:{:>4}|", 7, 12)).unwrap();
        seq.puts("x").unwrap();
        assert_eq!(seq.as_bytes(), b"7:  12|x");
    }
}
