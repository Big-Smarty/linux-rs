// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: fs/seq_file.c (GPL-2.0:
// `seq_escape`, `seq_puts`, `seq_printf`, `seq_putc`, the full-buffer retry
// protocol), lib/string_helpers.c (`string_escape_mem`, `ESCAPE_OCTAL`).
// Copyright of the originals: Linus Torvalds and the VFS authors.
// Transformation: the buffer grows fallibly (`try_reserve`) instead of being
// doubled and the show function re-run; a failed growth is `ENOMEM`. A
// `seq_file`'s `read`/`lseek` state machine (`seq_read_iter`, `traverse`,
// `seq_lseek`) is [`SeqFile`], run over a whole generated text whose record
// boundaries the `show` functions mark ([`Seq::end_record`]).
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
    /// The end offset of each finished record (`->show` call).
    ends: Vec<usize>,
}

impl Seq {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buf: Vec::new(),
            ends: Vec::new(),
        }
    }

    /// End the current record: what was written since the last call is what one
    /// `->show` call of the `seq_operations` would have produced.
    ///
    /// # Errors
    /// `ENOMEM`.
    pub fn end_record(&mut self) -> Result<(), Errno> {
        self.ends.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
        let _ = self.ends.push_within_capacity(self.buf.len());
        Ok(())
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

    /// The text with its record boundaries; text after the last marked record
    /// is one more record (a `single_open` file is one record).
    ///
    /// # Errors
    /// `ENOMEM`.
    pub fn into_snapshot(mut self) -> Result<Snapshot, Errno> {
        if self.ends.last().copied().unwrap_or(0) != self.buf.len() {
            self.end_record()?;
        }
        Ok(Snapshot {
            text: self.buf,
            ends: self.ends,
        })
    }
}

/// The text a `seq_file` shows and where its records end.
pub struct Snapshot {
    text: Vec<u8>,
    ends: Vec<usize>,
}

impl Snapshot {
    fn start(&self, record: usize) -> usize {
        record
            .checked_sub(1)
            .and_then(|before| self.ends.get(before))
            .copied()
            .unwrap_or(0)
    }

    fn len(&self, record: usize) -> usize {
        self.ends
            .get(record)
            .map_or(0, |end| end - self.start(record))
    }

    fn bytes(&self, from: usize, to: usize) -> &[u8] {
        self.text.get(from..to).unwrap_or_default()
    }
}

/// `PAGE_SIZE`: the first size of a `seq_file` buffer.
const PAGE_SIZE: usize = 4096;
/// `MAX_RW_COUNT`: `seq_buf_alloc` refuses a bigger buffer.
const MAX_RW_COUNT: usize = 0x7fff_f000;

/// The per-open state of a `struct seq_file` (`size`, `index`, `read_pos` and
/// the buffered bytes), over a [`Snapshot`] taken where Linux would call
/// `->start` again.
///
/// A record is shown into a buffer of `size` bytes (it must be strictly
/// smaller: `seq_has_overflowed`), which doubles when a first record does not
/// fit and never shrinks. The buffered bytes are always the text from the
/// read position to `buf_end`.
///
/// shortcut: the text is generated once per `->start` at position 0 or after a
/// position change, not at every refill, so a refill sees the state of that
/// moment; a vanished task is still noticed (`start_err`). Upgrade with
/// live iterators over the task, VMA and mount lists.
#[derive(Default)]
pub struct SeqFile {
    snap: Option<Snapshot>,
    /// `m->size`; 0 while no buffer is allocated.
    size: usize,
    /// `m->index`: the next record to show.
    index: usize,
    /// `m->read_pos`.
    read_pos: i64,
    /// End of the buffered records in the text.
    buf_end: usize,
}

impl SeqFile {
    /// Whether a read at `pos` calls `->start` on a fresh iteration: from the
    /// beginning, or after a position change (`traverse`).
    #[must_use]
    pub fn wants_snapshot(&self, pos: i64) -> bool {
        self.snap.is_none() || pos == 0 || pos != self.read_pos
    }

    /// Whether `seq_lseek` to `offset` runs `->start`.
    #[must_use]
    pub fn seek_wants_snapshot(&self, offset: i64) -> bool {
        offset != self.read_pos && offset != 0
    }

    /// Use a freshly shown text.
    pub fn load(&mut self, snap: Snapshot) {
        self.snap = Some(snap);
    }

    /// The error path of `seq_read_iter` and `seq_lseek` ("with prejudice").
    pub fn reset(&mut self) {
        self.read_pos = 0;
        self.index = 0;
        self.buf_end = 0;
    }

    fn records(&self) -> usize {
        self.snap.as_ref().map_or(0, |snap| snap.ends.len())
    }

    /// `m->size <<= 1` and `seq_buf_alloc`.
    fn grow(&mut self) -> Result<(), Errno> {
        let size = self.size << 1;
        if size > MAX_RW_COUNT {
            self.size = 0; // the buffer was freed
            return Err(Errno::ENOMEM);
        }
        self.size = size;
        Ok(())
    }

    /// `seq_lseek` to `offset` (>= 0): `traverse` unless it is the read
    /// position.
    ///
    /// # Errors
    /// `ENOMEM` (the position is reset).
    pub fn seek(&mut self, offset: i64) -> Result<(), Errno> {
        if offset != self.read_pos {
            if let Err(errno) = self.traverse(offset) {
                self.reset();
                return Err(errno);
            }
            self.read_pos = offset;
        }
        Ok(())
    }

    /// `traverse`: show records from the first until `offset` is reached,
    /// leaving the rest of the record that contains it buffered.
    fn traverse(&mut self, offset: i64) -> Result<(), Errno> {
        self.index = 0;
        self.buf_end = 0;
        if offset == 0 {
            return Ok(());
        }
        if self.size == 0 {
            self.size = PAGE_SIZE;
        }
        let offset = usize::try_from(offset).unwrap_or(usize::MAX);
        let records = self.records();
        'again: loop {
            let mut pos = 0usize;
            for record in 0..records {
                let len = self.snap.as_ref().map_or(0, |snap| snap.len(record));
                if len >= self.size {
                    // Eoverflow: a bigger buffer, from the start again.
                    self.grow()?;
                    continue 'again;
                }
                if pos.saturating_add(len) > offset {
                    self.index = record + 1;
                    self.buf_end = pos + len;
                    return Ok(());
                }
                pos += len;
                if pos == offset {
                    self.index = record + 1;
                    self.buf_end = pos;
                    return Ok(());
                }
            }
            self.index = records;
            return Ok(());
        }
    }

    /// `seq_read_iter` for a read of `count` bytes at `pos`: `copy` receives
    /// the bytes to hand out (never more than `count` in all) and returns how
    /// many it delivered. `start_err` is the error `->start` would return now
    /// (a vanished task).
    ///
    /// # Errors
    /// `EFAULT` when nothing could be copied, `start_err` or `ENOMEM` when
    /// nothing was read.
    pub fn read(
        &mut self,
        pos: i64,
        count: usize,
        start_err: Option<Errno>,
        copy: &mut dyn FnMut(&[u8]) -> usize,
    ) -> Result<usize, Errno> {
        if count == 0 {
            return Ok(0);
        }
        if pos == 0 {
            self.index = 0;
            self.buf_end = 0;
        }
        if pos != self.read_pos {
            if let Err(errno) = self.traverse(pos) {
                self.reset();
                return Err(errno);
            }
            self.read_pos = pos;
        }
        if self.size == 0 {
            self.size = PAGE_SIZE;
        }
        let Some(snap) = self.snap.take() else {
            return Ok(0);
        };
        let result = self.read_snap(&snap, pos, count, start_err, copy);
        self.snap = Some(snap);
        result
    }

    fn read_snap(
        &mut self,
        snap: &Snapshot,
        pos: i64,
        count: usize,
        start_err: Option<Errno>,
        copy: &mut dyn FnMut(&[u8]) -> usize,
    ) -> Result<usize, Errno> {
        let mut at = usize::try_from(pos).unwrap_or(usize::MAX);
        let mut copied = 0usize;
        let mut left = self.buf_end.saturating_sub(at);
        let mut error = None;
        if left > 0 {
            // Something left in the buffer: copy it out first.
            let n = copy(snap.bytes(at, at + left.min(count)));
            copied += n;
            at += n;
            left -= n;
        }
        if left == 0 {
            self.buf_end = at;
            let records = snap.ends.len();
            // Get a non-empty record in the buffer.
            let first = loop {
                if self.index >= records {
                    break None; // EOF (`m_start` returns NULL at the sentinel)
                }
                if let Some(errno) = start_err {
                    error = Some(errno);
                    break None;
                }
                let len = snap.len(self.index);
                if len == 0 {
                    self.index += 1;
                } else if len < self.size {
                    break Some(self.index);
                } else if let Err(errno) = self.grow() {
                    error = Some(errno);
                    break None;
                }
            };
            if let Some(first) = first {
                // Fill: more records while the user wants them and they fit.
                let from = snap.start(first);
                let mut buffered = snap.len(first);
                loop {
                    self.index += 1;
                    if self.index >= records || buffered >= count - copied {
                        break;
                    }
                    let len = snap.len(self.index);
                    if buffered + len >= self.size {
                        break; // overflowed: the record is shown again later
                    }
                    buffered += len;
                }
                let n = copy(snap.bytes(from, from + buffered.min(count - copied)));
                copied += n;
                left = buffered - n;
                self.buf_end = from + buffered;
            }
        }
        if copied == 0 {
            return if left != 0 {
                Err(Errno::EFAULT)
            } else {
                error.map_or(Ok(0), Err)
            };
        }
        self.read_pos = pos + i64::try_from(copied).unwrap_or(0);
        Ok(copied)
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

    /// A text of records `lens` bytes long, record `i` made of byte `b'a' + i`.
    fn records(lens: &[usize]) -> Snapshot {
        let mut seq = Seq::new();
        for (i, &len) in lens.iter().enumerate() {
            for _ in 0..len {
                seq.putc(b'a' + u8::try_from(i % 26).unwrap()).unwrap();
            }
            seq.end_record().unwrap();
        }
        seq.into_snapshot().unwrap()
    }

    fn read(file: &mut SeqFile, pos: &mut i64, count: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut give = |bytes: &[u8]| {
            out.extend_from_slice(bytes);
            bytes.len()
        };
        let n = file.read(*pos, count, None, &mut give).unwrap();
        *pos += i64::try_from(n).unwrap();
        out
    }

    #[test]
    fn a_big_read_stops_before_the_record_that_overflows_the_buffer() {
        // 100-byte records: 40 fit a 4096-byte buffer (4000 < 4096), 41 do not.
        let mut file = SeqFile::default();
        file.load(records(&[100; 100]));
        let mut pos = 0;
        assert_eq!(read(&mut file, &mut pos, 1 << 20).len(), 4000);
        assert_eq!(read(&mut file, &mut pos, 1 << 20).len(), 4000);
        assert_eq!(read(&mut file, &mut pos, 1 << 20).len(), 2000);
        assert_eq!(read(&mut file, &mut pos, 1 << 20).len(), 0);
    }

    #[test]
    fn a_first_record_that_does_not_fit_doubles_the_buffer() {
        let mut file = SeqFile::default();
        file.load(records(&[5000, 100, 3000, 100]));
        let mut pos = 0;
        // 8192-byte buffer: 5000 + 100 + 3000 = 8100 fits, 100 more does not.
        assert_eq!(read(&mut file, &mut pos, 1 << 20).len(), 8100);
        assert_eq!(read(&mut file, &mut pos, 1 << 20).len(), 100);
    }

    #[test]
    fn small_reads_follow_the_flat_text() {
        let mut file = SeqFile::default();
        let snap = records(&[30, 50, 20]);
        let all: Vec<u8> = snap.text.clone();
        file.load(snap);
        let mut pos = 0;
        let mut got = Vec::new();
        loop {
            let chunk = read(&mut file, &mut pos, 7);
            if chunk.is_empty() {
                break;
            }
            got.extend(chunk);
        }
        assert_eq!(got, all);
    }

    #[test]
    fn a_seek_into_a_record_keeps_its_tail() {
        let mut file = SeqFile::default();
        let snap = records(&[30, 50, 20]);
        let all: Vec<u8> = snap.text.clone();
        file.load(snap);
        file.seek(40).unwrap();
        let mut pos = 40;
        assert_eq!(read(&mut file, &mut pos, 1000), all[40..].to_vec());
        file.seek(80).unwrap(); // a record boundary
        pos = 80;
        assert_eq!(read(&mut file, &mut pos, 1000), all[80..].to_vec());
        file.seek(5000).unwrap();
        pos = 5000;
        assert_eq!(read(&mut file, &mut pos, 1000), Vec::<u8>::new());
    }

    #[test]
    fn a_zero_length_read_and_a_vanished_task() {
        let mut file = SeqFile::default();
        file.load(records(&[10]));
        let mut give = |bytes: &[u8]| bytes.len();
        assert_eq!(file.read(0, 0, Some(Errno::ESRCH), &mut give), Ok(0));
        assert_eq!(
            file.read(0, 5, Some(Errno::ESRCH), &mut give),
            Err(Errno::ESRCH)
        );
        // The buffered tail is served before the next `->start` fails.
        assert_eq!(file.read(0, 4, None, &mut give), Ok(4));
        assert_eq!(file.read(4, 100, Some(Errno::ESRCH), &mut give), Ok(6));
        // At the end `->start` finds no record before it asks for the task.
        assert_eq!(file.read(10, 100, Some(Errno::ESRCH), &mut give), Ok(0));
    }

    #[test]
    fn formatting_appends() {
        let mut seq = Seq::new();
        print(&mut seq, format_args!("{}:{:>4}|", 7, 12)).unwrap();
        seq.puts("x").unwrap();
        assert_eq!(seq.as_bytes(), b"7:  12|x");
    }
}
