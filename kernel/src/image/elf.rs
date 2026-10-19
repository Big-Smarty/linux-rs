// SPDX-License-Identifier: GPL-2.0-only AND (GPL-2.0 WITH Linux-syscall-note)
// Selected layout/constants from include/uapi/linux/elf.h (GPL-2.0 WITH
// Linux-syscall-note); that exception applies to those definitions, not the
// implementation. Selected validation/interpreter semantics from
// fs/binfmt_elf.c (GPL-2.0-only), Copyright 1993, 1994: Eric Youngdale
// (ericy@cais.com), and arch/x86/include/asm/elf.h (GPL-2.0).
// Main executable header preparation follows fs/exec.c (GPL-2.0-only),
// Copyright (C) 1991, 1992 Linus Torvalds: zero-fill before the short read.
// Linux 6.18.57 commit 2ff600d29ee478d0a8d46ef8a58afb5e038fe692.
// Transformation: checked byte fields and lazy borrowed program tables replace
// native C overlays/allocated headers. No mappings or exec policy are ported.
//! Borrowed ELF decoding; successful parsing does not execute or admit a program.
//!
//! No allocation, unsafe, locks, sleeping or I/O. The caller retains immutable,
//! initialized, mapped input for every borrow. Decode in early boot/task context,
//! not an unbounded interrupt handler. Section tables are intentionally not read:
//! native Linux exec does not need them. Unknown kinds/flags stay lossless.

use core::ops::Range;

use super::bytes::{BoundsError, Endian, c_name, range};

pub const PT_LOAD: u32 = 1;
pub const PT_INTERP: u32 = 3;
pub const PT_GNU_STACK: u32 = 0x6474_e551;
pub const PT_GNU_PROPERTY: u32 = 0x6474_e553;
pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;
pub const EM_X86_64: u16 = 62;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Elf32,
    Elf64,
}

impl Class {
    #[must_use]
    pub const fn header_bytes(self) -> u64 {
        match self {
            Self::Elf32 => 52,
            Self::Elf64 => 64,
        }
    }

    #[must_use]
    pub const fn program_bytes(self) -> u16 {
        match self {
            Self::Elf32 => 32,
            Self::Elf64 => 56,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Bounds(BoundsError),
    Magic,
    Class(u8),
    Endian(u8),
    Type,
    Machine,
    ProgramEntrySize,
    ProgramCount,
    /// `PN_XNUM` requires section-zero `sh_info`; that structural decoder is pending.
    ExtendedProgramCountPending,
    ProgramIndex,
    InterpreterSize,
    InterpreterUnterminated,
    FileLargerThanMemory,
    AddressOverflow,
    Alignment,
}

impl From<BoundsError> for Error {
    fn from(value: BoundsError) -> Self {
        Self::Bounds(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// Raw ident bytes; an explicit native decoder need not agree with them.
    pub ident: [u8; 16],
    pub class: Class,
    pub endian: Endian,
    pub file_type: u16,
    pub machine: u16,
    pub version: u32,
    pub entry: u64,
    pub program_offset: u64,
    pub section_offset: u64,
    pub flags: u32,
    pub header_size: u16,
    pub program_entry_size: u16,
    pub program_count: u16,
    pub section_entry_size: u16,
    pub section_count: u16,
    pub section_names: u16,
}

impl Header {
    fn decode(bytes: &[u8], class: Class, endian: Endian) -> Result<Self, Error> {
        let bytes = range(bytes, 0, class.header_bytes())?;
        if &bytes[..4] != b"\x7fELF" {
            return Err(Error::Magic);
        }
        let ident = range(bytes, 0, 16)?.try_into().map_err(|_| Error::Magic)?;
        let (entry, program_offset, section_offset, flags_offset) = match class {
            Class::Elf32 => (
                u64::from(endian.u32(bytes, 24)?),
                u64::from(endian.u32(bytes, 28)?),
                u64::from(endian.u32(bytes, 32)?),
                36,
            ),
            Class::Elf64 => (
                endian.u64(bytes, 24)?,
                endian.u64(bytes, 32)?,
                endian.u64(bytes, 40)?,
                48,
            ),
        };
        Ok(Self {
            ident,
            class,
            endian,
            file_type: endian.u16(bytes, 16)?,
            machine: endian.u16(bytes, 18)?,
            version: endian.u32(bytes, 20)?,
            entry,
            program_offset,
            section_offset,
            flags: endian.u32(bytes, flags_offset)?,
            header_size: endian.u16(bytes, flags_offset + 4)?,
            program_entry_size: endian.u16(bytes, flags_offset + 6)?,
            program_count: endian.u16(bytes, flags_offset + 8)?,
            section_entry_size: endian.u16(bytes, flags_offset + 10)?,
            section_count: endian.u16(bytes, flags_offset + 12)?,
            section_names: endian.u16(bytes, flags_offset + 14)?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgramHeader {
    pub kind: u32,
    pub flags: u32,
    pub offset: u64,
    pub virtual_address: u64,
    pub physical_address: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub alignment: u64,
}

impl ProgramHeader {
    /// Arithmetic for a single load extent only; not mapping permission.
    /// Neither overlaps, W+X, entry backing nor `p_align` are rejected here.
    ///
    /// # Errors
    /// Reports filesz > memsz or an overflowing virtual end.
    pub fn load_range(self) -> Result<Option<Range<u64>>, Error> {
        if self.kind != PT_LOAD {
            return Ok(None);
        }
        if self.file_size > self.memory_size {
            return Err(Error::FileLargerThanMemory);
        }
        let end = self
            .virtual_address
            .checked_add(self.memory_size)
            .ok_or(Error::AddressOverflow)?;
        Ok(Some(self.virtual_address..end))
    }
}

#[derive(Debug)]
pub struct Elf<'a> {
    bytes: &'a [u8],
    header: Header,
    programs: &'a [u8],
}

impl<'a> Elf<'a> {
    /// Structural decode using the declared class and byte order. This does not
    /// impose current version, OSABI, `e_ehsize`, section-table or exec policy.
    ///
    /// # Errors
    /// Reports unknown encoding, invalid magic/table stride or missing bytes.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let ident = range(bytes, 0, 16)?;
        if &ident[..4] != b"\x7fELF" {
            return Err(Error::Magic);
        }
        let class = match ident[4] {
            1 => Class::Elf32,
            2 => Class::Elf64,
            value => return Err(Error::Class(value)),
        };
        let endian = match ident[5] {
            1 => Endian::Little,
            2 => Endian::Big,
            value => return Err(Error::Endian(value)),
        };
        Self::parse_as(bytes, class, endian)
    }

    /// Decode the layout selected by an architecture's binary handler, keeping
    /// raw ident values. Pinned native `x86_64` ignores `EI_CLASS/EI_DATA/version`;
    /// forcing those fields to select the layout changes Linux acceptance.
    ///
    /// # Errors
    /// Reports invalid magic/table stride or missing/overflowing byte ranges.
    pub fn parse_as(bytes: &'a [u8], class: Class, endian: Endian) -> Result<Self, Error> {
        Self::from_header(bytes, Header::decode(bytes, class, endian)?)
    }

    /// Only the preliminary native `x86_64` `binfmt_elf` checks. Not full exec
    /// acceptance: VFS permissions, mappings, properties and entry remain work.
    ///
    /// # Errors
    /// Reports wrong magic/type/machine, invalid program size/count or bounds.
    pub fn linux_x86_64(bytes: &'a [u8]) -> Result<Self, Error> {
        let header = if bytes.len() < 64 {
            // prepare_binprm clears its buffer before kernel_read. A short main
            // header is therefore zero-extended, unlike elf_read of an
            // interpreter header. Do not pad the program table or payload.
            let mut prefix = [0; 64];
            prefix[..bytes.len()].copy_from_slice(bytes);
            Header::decode(&prefix, Class::Elf64, Endian::Little)?
        } else {
            Header::decode(bytes, Class::Elf64, Endian::Little)?
        };
        if header.file_type != ET_EXEC && header.file_type != ET_DYN {
            return Err(Error::Type);
        }
        if header.machine != EM_X86_64 {
            return Err(Error::Machine);
        }
        if header.program_entry_size != Class::Elf64.program_bytes() {
            return Err(Error::ProgramEntrySize);
        }
        let size = u64::from(header.program_entry_size) * u64::from(header.program_count);
        if size == 0 || size > 65536 {
            return Err(Error::ProgramCount);
        }
        Self::from_header(bytes, header)
    }

    fn from_header(bytes: &'a [u8], header: Header) -> Result<Self, Error> {
        // ELF UAPI PN_XNUM is a sentinel, not literally 65535 entries. Native
        // Linux exec already rejects it via the 65536-byte table limit; other
        // consumers must not receive a silently partial extended table.
        if header.program_count == u16::MAX {
            return Err(Error::ExtendedProgramCountPending);
        }
        let programs = if header.program_count == 0 {
            &[][..]
        } else {
            if header.program_entry_size != header.class.program_bytes() {
                return Err(Error::ProgramEntrySize);
            }
            let length = u64::from(header.program_count) * u64::from(header.program_entry_size);
            range(bytes, header.program_offset, length)?
        };
        Ok(Self {
            bytes,
            header,
            programs,
        })
    }

    #[must_use]
    pub const fn header(&self) -> &Header {
        &self.header
    }

    /// Decode one program descriptor; no referenced payload is read here.
    ///
    /// # Errors
    /// Reports an out-of-range index or unavailable descriptor bytes.
    pub fn program(&self, index: u16) -> Result<ProgramHeader, Error> {
        if index >= self.header.program_count {
            return Err(Error::ProgramIndex);
        }
        let endian = self.header.endian;
        let length = u64::from(self.header.program_entry_size);
        let bytes = range(self.programs, u64::from(index) * length, length)?;
        Ok(match self.header.class {
            Class::Elf32 => ProgramHeader {
                kind: endian.u32(bytes, 0)?,
                offset: u64::from(endian.u32(bytes, 4)?),
                virtual_address: u64::from(endian.u32(bytes, 8)?),
                physical_address: u64::from(endian.u32(bytes, 12)?),
                file_size: u64::from(endian.u32(bytes, 16)?),
                memory_size: u64::from(endian.u32(bytes, 20)?),
                flags: endian.u32(bytes, 24)?,
                alignment: u64::from(endian.u32(bytes, 28)?),
            },
            Class::Elf64 => ProgramHeader {
                kind: endian.u32(bytes, 0)?,
                flags: endian.u32(bytes, 4)?,
                offset: endian.u64(bytes, 8)?,
                virtual_address: endian.u64(bytes, 16)?,
                physical_address: endian.u64(bytes, 24)?,
                file_size: endian.u64(bytes, 32)?,
                memory_size: endian.u64(bytes, 40)?,
                alignment: endian.u64(bytes, 48)?,
            },
        })
    }

    /// Borrow a descriptor's declared file range. Do this only when a consumer
    /// needs those bytes: Linux ignores unknown segments and allows mmap beyond
    /// EOF, with later fault semantics. Failure here is not an exec verdict.
    ///
    /// # Errors
    /// Reports a missing or overflowing payload range.
    pub fn segment_data(&self, program: ProgramHeader) -> Result<&'a [u8], Error> {
        Ok(range(self.bytes, program.offset, program.file_size)?)
    }

    /// First `PT_INTERP` wins, as in pinned `load_elf_binary`'s breaking loop.
    /// The last byte MUST be NUL, but embedded NULs and relative/empty pathnames
    /// are passed to `open_exec`; their VFS result is not a decoder decision.
    ///
    /// # Errors
    /// Reports size outside 2..=4096, missing bytes or absent final NUL.
    pub fn interpreter(&self) -> Result<Option<&'a [u8]>, Error> {
        for index in 0..self.header.program_count {
            let program = self.program(index)?;
            if program.kind != PT_INTERP {
                continue;
            }
            if !(2..=4096).contains(&program.file_size) {
                return Err(Error::InterpreterSize);
            }
            let bytes = self.segment_data(program)?;
            if bytes.last() != Some(&0) {
                return Err(Error::InterpreterUnterminated);
            }
            return Ok(Some(c_name(bytes)));
        }
        Ok(None)
    }

    /// Preserve `binfmt_elf`'s non-power-of-two `p_align` skip, not rejection.
    /// Returns the rounded maximum (zero when no valid alignment was present).
    ///
    /// # Errors
    /// Reports invalid page size, descriptor failure or rounding overflow.
    pub fn maximum_alignment(&self, page_size: u64) -> Result<u64, Error> {
        if !page_size.is_power_of_two() {
            return Err(Error::Alignment);
        }
        let mut maximum = 0;
        for index in 0..self.header.program_count {
            let program = self.program(index)?;
            if program.kind == PT_LOAD && program.alignment.is_power_of_two() {
                maximum = maximum.max(program.alignment);
            }
        }
        maximum
            .checked_add(page_size - 1)
            .map(|value| value & !(page_size - 1))
            .ok_or(Error::AddressOverflow)
    }

    /// Last `PT_GNU_STACK` wins; absence remains distinct from non-executable.
    ///
    /// # Errors
    /// Reports unavailable program descriptor bytes.
    pub fn executable_stack(&self) -> Result<Option<bool>, Error> {
        let mut executable = None;
        for index in 0..self.header.program_count {
            let program = self.program(index)?;
            if program.kind == PT_GNU_STACK {
                executable = Some(program.flags & PF_X != 0);
            }
        }
        Ok(executable)
    }
}
