// SPDX-License-Identifier: GPL-2.0-only
//! Immutable boot-image inspection. No VFS mutation, mappings, dynamic linking,
//! process creation or userspace execution is performed or implied.
//!
//! Returned summaries own scalars only. The boot owner can end all input borrows
//! before replacing loader mappings, without dangling payload/name references.
#![forbid(unsafe_code)]

pub mod bytes;
pub mod cpio;
pub mod elf;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ElfSummary {
    pub entry: u64,
    pub programs: u16,
    pub load_segments: u16,
    pub file_bytes: u64,
    pub memory_bytes: u64,
    pub has_interpreter: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ArchiveSummary {
    pub input_bytes: u64,
    pub records: u64,
    pub files: u64,
    pub regular_files: u64,
    pub symlinks: u64,
    pub hardlink_records: u64,
    pub trailers: u64,
    pub skipped: u64,
    pub payload_bytes: u64,
    pub elf_files: u64,
    pub load_segments: u64,
    pub interpreters: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Archive {
        offset: u64,
        error: cpio::Error,
    },
    Elf {
        archive_offset: u64,
        error: elf::Error,
    },
    Checksum {
        archive_offset: u64,
        checksum: cpio::Checksum,
    },
    CountOverflow,
}

/// Inspect structural ELF metadata and the actual bytes backing each load.
/// No native machine/type eligibility applies to arbitrary archive contents:
/// relocatable objects and ELF32 programs are files too. Native preliminary
/// checks remain an explicitly selected `Elf::linux_x86_64` operation.
/// Full-file byte availability is an inspection requirement, NOT Linux exec
/// policy: an eventual file mapping can extend beyond EOF and fault later.
/// Unknown non-load ranges, overlaps, W+X and non-power-of-two `p_align` survive.
///
/// # Errors
/// Reports structural header/table/interpreter failures, invalid load arithmetic,
/// missing load bytes, or counter overflow. An incomplete metadata inspection
/// does not make the containing archive framing invalid or reject VFS storage.
pub fn inspect_elf(bytes: &[u8]) -> Result<ElfSummary, elf::Error> {
    let elf = elf::Elf::parse(bytes)?;
    let mut summary = ElfSummary {
        entry: elf.header().entry,
        programs: elf.header().program_count,
        has_interpreter: elf.interpreter()?.is_some(),
        ..ElfSummary::default()
    };
    for index in 0..elf.header().program_count {
        let program = elf.program(index)?;
        if program.load_range()?.is_none() {
            continue;
        }
        // A zero-sized load has no file bytes to borrow, even with a meaningless
        // p_offset. Linux elf_load similarly takes the anonymous/BSS path.
        if program.file_size != 0 {
            elf.segment_data(program)?;
        }
        summary.load_segments += 1;
        summary.file_bytes = summary
            .file_bytes
            .checked_add(program.file_size)
            .ok_or(elf::Error::AddressOverflow)?;
        summary.memory_bytes = summary
            .memory_bytes
            .checked_add(program.memory_size)
            .ok_or(elf::Error::AddressOverflow)?;
    }
    Ok(summary)
}

/// Consume complete raw archive records and inspect every ELF regular payload.
/// The result contains no references; it can outlive the module's boot mapping.
/// This is an honest early consumer, not an unpacker or an init process.
///
/// # Errors
/// Reports malformed/incomplete bytes, pending compression, regular checksum
/// mismatch or ELF inspection failure, preserving the offending record offset.
pub fn inspect_archive(bytes: &[u8]) -> Result<ArchiveSummary, Error> {
    let mut archive = cpio::Archive::new(bytes);
    let mut summary = ArchiveSummary {
        input_bytes: bytes.len() as u64,
        ..ArchiveSummary::default()
    };
    loop {
        let record = archive.next_record().map_err(|error| Error::Archive {
            offset: archive.offset(),
            error,
        })?;
        let Some(record) = record else {
            return Ok(summary);
        };
        summary.records += 1;
        match record.disposition {
            cpio::Disposition::Trailer => {
                summary.trailers += 1;
                continue;
            }
            cpio::Disposition::Skipped(_) => {
                summary.skipped += 1;
                continue;
            }
            cpio::Disposition::File => summary.files += 1,
        }
        summary.payload_bytes = summary
            .payload_bytes
            .checked_add(record.data.len() as u64)
            .ok_or(Error::CountOverflow)?;
        if record.hardlink_key().is_some() {
            summary.hardlink_records += 1;
        }
        if record.metadata.file_type() == cpio::FileType::Symlink {
            summary.symlinks += 1;
        }
        if record.metadata.file_type() != cpio::FileType::Regular {
            continue;
        }
        summary.regular_files += 1;
        if let Some(checksum) = record.regular_checksum()
            && !checksum.matches()
        {
            return Err(Error::Checksum {
                archive_offset: record.offset,
                checksum,
            });
        }
        if !record.data.starts_with(b"\x7fELF") {
            continue;
        }
        let elf = inspect_elf(record.data).map_err(|error| Error::Elf {
            archive_offset: record.offset,
            error,
        })?;
        summary.elf_files += 1;
        summary.load_segments += u64::from(elf.load_segments);
        summary.interpreters += u64::from(elf.has_interpreter);
    }
}

#[cfg(test)]
mod tests;
