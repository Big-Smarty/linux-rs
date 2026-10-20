// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics translated from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: init/initramfs.c (GPL-2.0),
// lib/decompress.c (GPL-2.0), lib/kstrtox.c (GPL-2.0), and the bounded
// simple_strntoul conversion in lib/vsprintf.c (GPL-2.0-only).
// lib/vsprintf.c: Copyright (C) 1991, 1992 Linus Torvalds.
// Original attribution: Lars Wirzenius & Linus Torvalds. Its unrelated snprintf
// changes are credited to Crutcher Dunnavant (2001), and scnprintf/vscnprintf
// to Juergen Quade (2004); those formatting implementations are not ported here.
// Transformation: borrowed records replace the incremental global copy buffers;
// expose Linux name eligibility and hardlink keys without VFS side effects.
//! Allocation-free raw newc/crc decoding, not a filesystem or decompressor.
//!
//! The input must remain initialized, immutable and mapped for every returned
//! borrow. No locks, allocations, sleeping, I/O or destructive teardown occur.
//! Parsing is linear in records/names; checksum work is explicit. Early boot or
//! task context may use it; large-input scans do not belong in hardirq/NMI.
//!
//! Errors describe structural availability, not Linux unpack return codes:
//! pinned Linux's uncompressed path does not check the final FSM state and can
//! silently accept a truncated last record. This decoder reports missing bytes
//! instead of inventing a complete record. A future unpacker must preserve the
//! reference's partial effects and EOF behavior separately.

use super::bytes::{BoundsError, align4, c_name, range};

pub const HEADER_BYTES: u64 = 110;
pub const PATH_MAX: u32 = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compression {
    Gzip,
    Bzip2,
    Lzma,
    Xz,
    Lzo,
    Lz4,
    Zstd,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Bounds(BoundsError),
    Magic,
    OldCpio,
    Alignment,
    NameUnterminated,
    /// Recognized baseline method whose Rust decoder is still pending.
    CompressionPending(Compression),
}

impl From<BoundsError> for Error {
    fn from(value: BoundsError) -> Self {
        Self::Bounds(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Newc,
    Crc,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileType {
    Regular,
    Directory,
    Symlink,
    Block,
    Character,
    Fifo,
    Socket,
    Unknown(u32),
}

/// Lossless fields, including values a Linux unpacker ignores or narrows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Metadata {
    pub inode: u32,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub links: u32,
    pub mtime: u32,
    pub file_size: u32,
    pub device_major: u32,
    pub device_minor: u32,
    pub rdev_major: u32,
    pub rdev_minor: u32,
    pub name_size: u32,
    pub checksum: u32,
}

impl Metadata {
    /// Linux stores `c_mode` in `umode_t` before testing its type bits.
    #[must_use]
    pub fn file_type(self) -> FileType {
        match self.mode & 0xf000 {
            0x8000 => FileType::Regular,
            0x4000 => FileType::Directory,
            0xa000 => FileType::Symlink,
            0x6000 => FileType::Block,
            0x2000 => FileType::Character,
            0x1000 => FileType::Fifo,
            0xc000 => FileType::Socket,
            bits => FileType::Unknown(bits),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SkipReason {
    NameSize,
    SymlinkSize,
    NonRegularData,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    File,
    /// Clear hardlink state here, not merely at the input buffer's end.
    Trailer,
    /// Linux skips these without validating their name or checksum.
    Skipped(SkipReason),
}

/// Linux's actual `find_link` key includes file type, not just device/inode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HardlinkKey {
    pub device_major: u32,
    pub device_minor: u32,
    pub inode: u32,
    pub file_type: FileType,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checksum {
    pub expected: u32,
    pub actual: u32,
}

impl Checksum {
    #[must_use]
    pub fn matches(self) -> bool {
        self.expected == self.actual
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record<'a> {
    pub offset: u64,
    pub format: Format,
    pub metadata: Metadata,
    /// Includes all `c_namesize` bytes, including embedded/trailing NULs.
    pub raw_name: &'a [u8],
    pub data: &'a [u8],
    pub disposition: Disposition,
}

impl<'a> Record<'a> {
    /// Linux path bytes end at the FIRST NUL. No UTF-8/path normalization.
    /// Skipped records have no pathname consumed by the Linux unpacker.
    #[must_use]
    pub fn name(&self) -> Option<&'a [u8]> {
        match self.disposition {
            Disposition::Skipped(_) => None,
            Disposition::File | Disposition::Trailer => Some(c_name(self.raw_name)),
        }
    }

    /// The kernel appends a terminator; an earlier NUL ends the symlink target.
    /// Empty targets are passed to VFS, not rejected by archive decoding.
    #[must_use]
    pub fn symlink_target(&self) -> Option<&'a [u8]> {
        (self.disposition == Disposition::File && self.metadata.file_type() == FileType::Symlink)
            .then(|| c_name(self.data))
    }

    #[must_use]
    pub fn hardlink_key(&self) -> Option<HardlinkKey> {
        let file_type = self.metadata.file_type();
        if self.disposition != Disposition::File
            || self.metadata.links < 2
            || !matches!(
                file_type,
                FileType::Regular
                    | FileType::Block
                    | FileType::Character
                    | FileType::Fifo
                    | FileType::Socket
            )
        {
            return None;
        }
        Some(HardlinkKey {
            device_major: self.metadata.device_major,
            device_minor: self.metadata.device_minor,
            inode: self.metadata.inode,
            file_type,
        })
    }

    /// Compute the wrapping additive checksum Linux checks after a successful
    /// regular-file write. The caller controls that VFS-dependent check point.
    /// Linux does not verify newc, symlink, trailer or skipped-entry checksums.
    #[must_use]
    pub fn regular_checksum(&self) -> Option<Checksum> {
        (self.format == Format::Crc
            && self.disposition == Disposition::File
            && self.metadata.file_type() == FileType::Regular)
            .then(|| Checksum {
                expected: self.metadata.checksum,
                actual: self
                    .data
                    .iter()
                    .fold(0u32, |sum, &byte| sum.wrapping_add(u32::from(byte))),
            })
    }
}

/// One raw initramfs input, including concatenated archives and zero padding.
/// This is not a path lookup table and does not resolve duplicate names/links.
#[derive(Debug)]
pub struct Archive<'a> {
    bytes: &'a [u8],
    cursor: u64,
}

impl<'a> Archive<'a> {
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.cursor
    }

    /// Decode a whole record. Trailers are returned, not terminal sentinels.
    /// On failure the cursor stays at the failing record, permitting a precise
    /// diagnostic; callers must not ignore errors and retry indefinitely.
    ///
    /// # Errors
    /// Reports missing bytes/overflow, invalid magic/alignment/name, or a
    /// recognized compressed member whose implementation is still pending.
    pub fn next_record(&mut self) -> Result<Option<Record<'a>>, Error> {
        while self.cursor < self.bytes.len() as u64 {
            if range(self.bytes, self.cursor, 1)?[0] != 0 {
                break;
            }
            self.cursor += 1;
        }
        if self.cursor >= self.bytes.len() as u64 {
            return Ok(None);
        }
        let tail = range(
            self.bytes,
            self.cursor,
            self.bytes.len() as u64 - self.cursor,
        )?;
        if let Some(method) = compression(tail) {
            return Err(Error::CompressionPending(method));
        }
        if self.cursor & 3 != 0 {
            return Err(Error::Alignment);
        }
        let header = range(self.bytes, self.cursor, HEADER_BYTES)?;
        let format = match &header[..6] {
            b"070701" => Format::Newc,
            b"070702" => Format::Crc,
            b"070707" => return Err(Error::OldCpio),
            _ => return Err(Error::Magic),
        };
        let mut fields = [0u32; 13];
        for (value, bytes) in fields.iter_mut().zip(header[6..].as_chunks::<8>().0) {
            *value = hex_field(bytes);
        }
        let metadata = Metadata {
            inode: fields[0],
            mode: fields[1],
            uid: fields[2],
            gid: fields[3],
            links: fields[4],
            mtime: fields[5],
            file_size: fields[6],
            device_major: fields[7],
            device_minor: fields[8],
            rdev_major: fields[9],
            rdev_minor: fields[10],
            name_size: fields[11],
            checksum: fields[12],
        };
        let name_start = self
            .cursor
            .checked_add(HEADER_BYTES)
            .ok_or(BoundsError::Overflow)?;
        let name_end = name_start
            .checked_add(u64::from(metadata.name_size))
            .ok_or(BoundsError::Overflow)?;
        let data_start = align4(name_end)?;
        let raw_name = range(self.bytes, name_start, u64::from(metadata.name_size))?;
        // Reading the name includes alignment bytes in Linux's read_into path.
        range(self.bytes, name_end, data_start - name_end)?;
        let data = range(self.bytes, data_start, u64::from(metadata.file_size))?;
        let data_end = data_start
            .checked_add(u64::from(metadata.file_size))
            .ok_or(BoundsError::Overflow)?;
        let next = align4(data_end)?;
        let disposition = disposition(metadata, raw_name)?;
        let record = Record {
            offset: self.cursor,
            format,
            metadata,
            raw_name,
            data,
            disposition,
        };
        // Missing final data padding is allowed: no subsequent header is read.
        self.cursor = next;
        Ok(Some(record))
    }
}

fn disposition(metadata: Metadata, name: &[u8]) -> Result<Disposition, Error> {
    if metadata.name_size == 0 || metadata.name_size > PATH_MAX {
        return Ok(Disposition::Skipped(SkipReason::NameSize));
    }
    let file_type = metadata.file_type();
    if file_type == FileType::Symlink {
        if metadata.file_size > PATH_MAX {
            return Ok(Disposition::Skipped(SkipReason::SymlinkSize));
        }
    } else if file_type != FileType::Regular && metadata.file_size != 0 {
        return Ok(Disposition::Skipped(SkipReason::NonRegularData));
    }
    if name.last() != Some(&0) {
        return Err(Error::NameUnterminated);
    }
    // Symlinks take do_symlink, not do_name, even with the trailer spelling.
    Ok(
        if file_type != FileType::Symlink && c_name(name) == b"TRAILER!!!" {
            Disposition::Trailer
        } else {
            Disposition::File
        },
    )
}

// simple_strntoul(base=16,max_chars=8): optional 0x, stop at the first
// nonhex digit (including whitespace/sign), return zero if no digit. Do NOT
// substitute strict from_str_radix: that rejects headers Linux consumes.
pub(crate) fn hex_field(bytes: &[u8]) -> u32 {
    let bytes = if bytes.starts_with(b"0x") || bytes.starts_with(b"0X") {
        &bytes[2..]
    } else {
        bytes
    };
    let mut value = 0u32;
    for &byte in bytes {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => break,
        };
        value = value * 16 + u32::from(digit);
    }
    value
}

#[must_use]
pub fn compression(bytes: &[u8]) -> Option<Compression> {
    match bytes.get(..2)? {
        [0x1f, 0x8b | 0x9e] => Some(Compression::Gzip),
        [0x42, 0x5a] => Some(Compression::Bzip2),
        [0x5d, 0x00] => Some(Compression::Lzma),
        [0xfd, 0x37] => Some(Compression::Xz),
        [0x89, 0x4c] => Some(Compression::Lzo),
        [0x02, 0x21] => Some(Compression::Lz4),
        [0x28, 0xb5] => Some(Compression::Zstd),
        _ => None,
    }
}
