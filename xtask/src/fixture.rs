// SPDX-License-Identifier: GPL-2.0-only
//! Generated QEMU fixtures: the deterministic initramfs that carries the built `/init`,
//! a corrupt module for the kernel's skip path, and the kernel record each one must produce.
//! ELF facts come from the vetted `elf` crate, the archive from the vetted `cpio` crate.

use std::io::{self, Cursor};

use cpio::{NewcBuilder, write_cpio};
use elf::{ElfBytes, abi, endian::LittleEndian, file::Class};

/// Everything that is only valid when the kernel rejects it: not a cpio, starts with the gzip magic.
pub(crate) const CORRUPT_MODULE: &[u8] =
    b"\x1f\x8b\x08\x00bad-module: deterministic garbage, not a gzip stream\n";

/// Linux `PAGE_SIZE`: Limine reserves each module in whole pages (a zero-byte module keeps one).
const PAGE: usize = 4096;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn parse_error(error: &elf::ParseError) -> io::Error {
    invalid(format!("ELF parse error: {error}"))
}

/// Header-table facts about a little-endian ELF64 x86-64 `ET_EXEC` file.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ElfFacts {
    /// `[start, end)` virtual ranges of non-empty executable `PT_LOAD` segments.
    pub(crate) executable_segments: Vec<(u64, u64)>,
    pub(crate) loads: u64,
    pub(crate) interpreters: u64,
    pub(crate) dynamics: u64,
    /// Undefined entries of `.symtab` (the mandatory null symbol excluded); 0 without one.
    pub(crate) undefined_symbols: u64,
}

pub(crate) fn elf_facts(bytes: &[u8]) -> io::Result<ElfFacts> {
    let file =
        ElfBytes::<LittleEndian>::minimal_parse(bytes).map_err(|error| parse_error(&error))?;
    let header = file.ehdr;
    if header.class != Class::ELF64
        || header.e_type != abi::ET_EXEC
        || header.e_machine != abi::EM_X86_64
    {
        return Err(invalid("not a little-endian ELF64 x86-64 ET_EXEC file"));
    }
    let mut facts = ElfFacts {
        executable_segments: Vec::new(),
        loads: 0,
        interpreters: 0,
        dynamics: 0,
        undefined_symbols: 0,
    };
    for program in file.segments().into_iter().flatten() {
        match program.p_type {
            abi::PT_LOAD => {
                if program.p_filesz > program.p_memsz {
                    return Err(invalid("PT_LOAD file size exceeds its memory size"));
                }
                let end = program
                    .p_vaddr
                    .checked_add(program.p_memsz)
                    .ok_or_else(|| invalid("PT_LOAD address overflow"))?;
                facts.loads += 1;
                if program.p_flags & abi::PF_X != 0 && program.p_memsz > 0 {
                    facts.executable_segments.push((program.p_vaddr, end));
                }
            }
            abi::PT_INTERP => facts.interpreters += 1,
            abi::PT_DYNAMIC => facts.dynamics += 1,
            _ => {}
        }
    }
    if let Some((symbols, _)) = file.symbol_table().map_err(|error| parse_error(&error))? {
        facts.undefined_symbols = symbols
            .iter()
            .skip(1)
            .filter(elf::symbol::Symbol::is_undefined)
            .count() as u64;
    }
    Ok(facts)
}

/// The deterministic newc initramfs: `/dev` (directory), `/init` (the ELF), `/linuxrc` -> `/init`.
/// Fixed mtime 0, uid/gid 0 and sequential inode numbers; Linux-like link counts and modes.
///
/// Only `write_cpio` is used: `Writer::finish()` after a short write would emit a corrupt entry.
pub(crate) fn initramfs(init: &[u8]) -> io::Result<Vec<u8>> {
    if u32::try_from(init.len()).is_err() {
        return Err(invalid("init does not fit a newc file size"));
    }
    let entries = [
        (NewcBuilder::new("dev").mode(0o040_755).nlink(2), &b""[..]),
        (NewcBuilder::new("init").mode(0o100_755), init),
        (NewcBuilder::new("linuxrc").mode(0o120_777), &b"/init"[..]),
    ];
    write_cpio(
        entries
            .into_iter()
            .map(|(builder, data)| (builder, Cursor::new(data))),
        Vec::new(),
    )
}

/// The `CHECK image inspected` tail the kernel must print for [`initramfs`], by construction:
/// three files and the trailer, the ELF's own `PT_LOAD`/`PT_INTERP` counts, page-rounded reservation.
pub(crate) fn archive_counts(archive_len: usize, init: &ElfFacts) -> String {
    let reserved = archive_len.next_multiple_of(PAGE).max(PAGE);
    format!(
        "reserved={reserved} bytes={archive_len} records=4 files=3 regular=1 symlinks=1 trailers=1 skipped=0 elf=1 loads={} interpreters={} execution=false rootfs=false",
        init.loads, init.interpreters
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(field: &[u8]) -> u32 {
        u32::from_str_radix(std::str::from_utf8(field).unwrap(), 16).unwrap()
    }

    /// Independent newc walk: (name, mode, nlink, data) per entry, asserting the framing.
    fn entries(archive: &[u8]) -> Vec<(String, u32, u32, Vec<u8>)> {
        let (mut at, mut found) = (0, Vec::new());
        while at < archive.len() {
            assert_eq!(at % 4, 0, "entry starts 4-byte aligned");
            assert_eq!(&archive[at..at + 6], b"070701");
            let field = |n: usize| &archive[at + 6 + 8 * n..at + 14 + 8 * n];
            let (mode, nlink, size, name_size) =
                (hex(field(1)), hex(field(4)), hex(field(6)), hex(field(11)));
            assert_eq!(
                (hex(field(2)), hex(field(3)), hex(field(5))),
                (0, 0, 0),
                "uid, gid, mtime"
            );
            assert_eq!(hex(field(12)), 0, "newc checksum field");
            let name_at = at + 110;
            let name = &archive[name_at..name_at + name_size as usize - 1];
            assert_eq!(archive[name_at + name_size as usize - 1], 0);
            let data_at = (name_at + name_size as usize).next_multiple_of(4);
            assert!(
                archive[name_at + name_size as usize..data_at]
                    .iter()
                    .all(|&b| b == 0)
            );
            let end = data_at + size as usize;
            let next = end.next_multiple_of(4);
            assert!(
                archive[end..next].iter().all(|&b| b == 0),
                "zero data padding"
            );
            found.push((
                String::from_utf8(name.to_vec()).unwrap(),
                mode,
                nlink,
                archive[data_at..end].to_vec(),
            ));
            at = next;
        }
        found
    }

    #[test]
    fn initramfs_bytes_are_framed_padded_and_terminated() {
        let init = (0..=250u8).collect::<Vec<_>>(); // 251 bytes: forces data padding
        let archive = initramfs(&init).unwrap();
        assert_eq!(archive.len() % 4, 0);
        assert_eq!(archive, initramfs(&init).unwrap(), "deterministic");
        let found = entries(&archive);
        let summary = found
            .iter()
            .map(|(n, m, l, d)| (n.as_str(), *m, *l, d.len()))
            .collect::<Vec<_>>();
        assert_eq!(
            summary,
            [
                ("dev", 0o040_755, 2, 0),
                ("init", 0o100_755, 1, 251),
                ("linuxrc", 0o120_777, 1, 5),
                ("TRAILER!!!", 0, 1, 0)
            ]
        );
        assert_eq!(found[1].3, init);
        assert_eq!(found[2].3, b"/init");
        // Sequential inode numbers 0, 1, 2 (write_cpio) and the trailer.
        let inodes = [0, 1, 2].map(|i| hex(&archive[entry_offset(&archive, i) + 6..][..8]));
        assert_eq!(inodes, [0, 1, 2]);
    }

    fn entry_offset(archive: &[u8], index: usize) -> usize {
        let mut at = 0;
        for _ in 0..index {
            let name_size = hex(&archive[at + 94..at + 102]) as usize;
            let size = hex(&archive[at + 54..at + 62]) as usize;
            at = ((at + 110 + name_size).next_multiple_of(4) + size).next_multiple_of(4);
        }
        at
    }

    /// ELF64 header plus `programs` as (type, flags, vaddr, filesz, memsz) after it; no sections.
    fn synthetic_elf(programs: &[(u32, u32, u64, u64, u64)], machine: u16) -> Vec<u8> {
        let mut bytes = vec![0u8; 64 + 56 * programs.len()];
        bytes[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&machine.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&u16::try_from(programs.len()).unwrap().to_le_bytes());
        for (i, (kind, flags, vaddr, filesz, memsz)) in programs.iter().enumerate() {
            let p = 64 + 56 * i;
            bytes[p..p + 4].copy_from_slice(&kind.to_le_bytes());
            bytes[p + 4..p + 8].copy_from_slice(&flags.to_le_bytes());
            bytes[p + 16..p + 24].copy_from_slice(&vaddr.to_le_bytes());
            bytes[p + 32..p + 40].copy_from_slice(&filesz.to_le_bytes());
            bytes[p + 40..p + 48].copy_from_slice(&memsz.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn elf_facts_count_loads_interpreters_and_executable_ranges() {
        let bytes = synthetic_elf(
            &[
                (3, 4, 0, 0, 0),
                (1, 5, 0x20_0000, 16, 32),
                (1, 6, 0x30_0000, 8, 8),
                (1, 5, 0x40_0000, 0, 0),
                (2, 6, 0, 0, 0),
            ],
            62,
        );
        let facts = elf_facts(&bytes).unwrap();
        assert_eq!(facts.loads, 3);
        assert_eq!(
            (facts.interpreters, facts.dynamics, facts.undefined_symbols),
            (1, 1, 0)
        );
        assert_eq!(facts.executable_segments, [(0x20_0000, 0x20_0020)]);
        assert!(
            elf_facts(&synthetic_elf(&[(1, 5, 0, 0, 0)], 3)).is_err(),
            "not x86-64"
        );
        assert!(
            elf_facts(&synthetic_elf(&[(1, 5, 0, 9, 8)], 62)).is_err(),
            "filesz > memsz"
        );
        assert!(
            elf_facts(&synthetic_elf(&[(1, 5, u64::MAX, 0, 2)], 62)).is_err(),
            "overflow"
        );
        assert!(elf_facts(&bytes[..100]).is_err(), "truncated program table");
    }

    #[test]
    fn expected_counts_follow_the_archive_and_the_elf() {
        let facts = elf_facts(&synthetic_elf(
            &[(1, 5, 0x20_0000, 16, 16), (1, 6, 0x30_0000, 8, 8)],
            62,
        ))
        .unwrap();
        let counts = archive_counts(4096, &facts);
        assert!(counts.starts_with("reserved=4096 bytes=4096 records=4 files=3 regular=1 symlinks=1 trailers=1 skipped=0 elf=1 loads=2 interpreters=0 "));
        assert!(archive_counts(4097, &facts).starts_with("reserved=8192 bytes=4097 "));
        assert!(archive_counts(0, &facts).starts_with("reserved=4096 bytes=0 "));
    }

    #[test]
    fn corrupt_module_looks_like_gzip() {
        assert_eq!(&CORRUPT_MODULE[..2], [0x1f, 0x8b]);
    }
}
