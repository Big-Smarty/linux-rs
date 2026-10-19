// SPDX-License-Identifier: GPL-2.0-only
// Original Rust regression cases derived from the pinned source obligations in
// cpio.rs/elf.rs, including init/initramfs_test.c's filename-overrun test intent.
extern crate std;

use std::{format, vec, vec::Vec};

use super::{
    bytes::{self, BoundsError, Endian},
    cpio, elf, inspect_archive, inspect_elf,
};

fn cpio_record(name: &[u8], data: &[u8], mode: u32, crc: bool) -> Vec<u8> {
    let mut out = Vec::from(if crc { b"070702" } else { b"070701" });
    let checksum = data
        .iter()
        .fold(0u32, |sum, &byte| sum.wrapping_add(u32::from(byte)));
    let fields = [
        7,
        mode,
        12,
        34,
        2,
        56,
        u32::try_from(data.len()).unwrap(),
        8,
        9,
        5,
        1,
        u32::try_from(name.len()).unwrap(),
        checksum,
    ];
    for value in fields {
        out.extend_from_slice(format!("{value:08x}").as_bytes());
    }
    out.extend_from_slice(name);
    while out.len() & 3 != 0 {
        out.push(0);
    }
    out.extend_from_slice(data);
    while out.len() & 3 != 0 {
        out.push(0);
    }
    out
}

fn field(bytes: &mut [u8], index: usize, text: [u8; 8]) {
    bytes[6 + index * 8..14 + index * 8].copy_from_slice(&text);
}

fn le16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn le32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn le64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn elf64(count: u16) -> Vec<u8> {
    let mut bytes = vec![0; 64 + usize::from(count) * 56];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    le16(&mut bytes, 16, elf::ET_DYN);
    le16(&mut bytes, 18, elf::EM_X86_64);
    le32(&mut bytes, 20, 1);
    le64(&mut bytes, 32, 64);
    le16(&mut bytes, 52, 64);
    le16(&mut bytes, 54, 56);
    le16(&mut bytes, 56, count);
    bytes
}

fn load(bytes: &mut [u8], index: usize, offset: u64, address: u64, file: u64, memory: u64) {
    let base = 64 + index * 56;
    le32(bytes, base, elf::PT_LOAD);
    le32(bytes, base + 4, elf::PF_R | elf::PF_W | elf::PF_X);
    le64(bytes, base + 8, offset);
    le64(bytes, base + 16, address);
    le64(bytes, base + 32, file);
    le64(bytes, base + 40, memory);
    le64(bytes, base + 48, 4096);
}

#[test]
fn checked_ranges_and_endian_never_wrap_or_assume_alignment() {
    assert_eq!(bytes::range(&[1], u64::MAX, 2), Err(BoundsError::Overflow));
    assert_eq!(bytes::range(&[1], 1, 0).unwrap(), b"");
    assert!(matches!(
        bytes::range(&[1], 2, 0),
        Err(BoundsError::Truncated { .. })
    ));
    assert_eq!(
        Endian::Little.u32(&[9, 1, 2, 3, 4], 1).unwrap(),
        0x0403_0201
    );
    assert_eq!(Endian::Big.u32(&[9, 1, 2, 3, 4], 1).unwrap(), 0x0102_0304);
    assert!(Endian::Big.u64(&[], u64::MAX).is_err());
}

#[test]
fn cpio_multiple_members_optional_trailer_and_unaligned_input_pointer() {
    let mut bytes = vec![99, 0, 0, 0, 0];
    bytes.extend(cpio_record(b"a\0", b"xyz", 0x81ed, false));
    bytes.extend(cpio_record(b"TRAILER!!!\0\0\0", b"", 0, false));
    bytes.extend([0; 8]);
    bytes.extend(cpio_record(b"b\0", b"q", 0x81ed, false));
    bytes.pop();
    bytes.pop();
    bytes.pop(); // Final data padding is optional.
    let mut archive = cpio::Archive::new(&bytes[1..]);
    let a = archive.next_record().unwrap().unwrap();
    assert_eq!(a.offset, 4);
    assert_eq!(a.name(), Some(&b"a"[..]));
    assert_eq!(a.data, b"xyz");
    assert_eq!(
        archive.next_record().unwrap().unwrap().disposition,
        cpio::Disposition::Trailer
    );
    assert_eq!(archive.next_record().unwrap().unwrap().data, b"q");
    assert!(archive.next_record().unwrap().is_none());
}

#[test]
fn cpio_alignment_is_stream_relative_and_padding_is_not_required_zero() {
    let mut bytes = cpio_record(b"abc\0", b"x", 0x81ed, false);
    bytes[114..116].fill(0x88); // In-record name padding is consumed, not checked.
    bytes[117..120].fill(0x99); // Likewise data padding.
    bytes.extend(cpio_record(b"next\0", b"", 0x81ed, false));
    let mut archive = cpio::Archive::new(&bytes);
    assert_eq!(archive.next_record().unwrap().unwrap().data, b"x");
    assert_eq!(
        archive.next_record().unwrap().unwrap().name(),
        Some(&b"next"[..])
    );
    let mut bad = vec![0];
    bad.extend(cpio_record(b"a\0", b"", 0x81ed, false));
    assert_eq!(
        cpio::Archive::new(&bad).next_record(),
        Err(cpio::Error::Alignment)
    );
}

#[test]
fn cpio_names_preserve_first_nul_and_require_last_nul() {
    let bytes = cpio_record(b"a\0not-a-path\0", b"", 0x81ed, false);
    let record = cpio::Archive::new(&bytes).next_record().unwrap().unwrap();
    assert_eq!(record.name(), Some(&b"a"[..]));
    assert_eq!(record.raw_name, b"a\0not-a-path\0");
    let bad = cpio_record(b"a\0x", b"", 0x81ed, false);
    assert_eq!(
        cpio::Archive::new(&bad).next_record(),
        Err(cpio::Error::NameUnterminated)
    );
    let non_utf8 = cpio_record(b"/../\xff\0", b"", 0x81ed, false);
    assert_eq!(
        cpio::Archive::new(&non_utf8)
            .next_record()
            .unwrap()
            .unwrap()
            .name(),
        Some(&b"/../\xff"[..])
    );
}

#[test]
fn cpio_linux_field_parser_accepts_prefix_and_trailing_junk() {
    let mut bytes = cpio_record(b"a\0", b"", 0x81ed, false);
    field(&mut bytes, 0, *b"0x00002a");
    field(&mut bytes, 2, *b"12garbag");
    field(&mut bytes, 3, *b"-0000001");
    field(&mut bytes, 1, *b"ffff81ed");
    let record = cpio::Archive::new(&bytes).next_record().unwrap().unwrap();
    assert_eq!(record.metadata.inode, 42);
    assert_eq!(record.metadata.uid, 0x12);
    assert_eq!(record.metadata.gid, 0);
    assert_eq!(record.metadata.file_type(), cpio::FileType::Regular);
    assert_eq!(record.metadata.mode, 0xffff_81ed);
}

#[test]
fn cpio_linux_skips_ineligible_names_and_nonregular_data() {
    for name in [vec![], vec![b'x'; 4097]] {
        let bytes = cpio_record(&name, b"data", 0x81ed, false);
        let record = cpio::Archive::new(&bytes).next_record().unwrap().unwrap();
        assert_eq!(
            record.disposition,
            cpio::Disposition::Skipped(cpio::SkipReason::NameSize)
        );
        assert_eq!(record.name(), None);
    }
    let bytes = cpio_record(b"unterminated", b"data", 0x41ed, true);
    assert_eq!(
        cpio::Archive::new(&bytes)
            .next_record()
            .unwrap()
            .unwrap()
            .disposition,
        cpio::Disposition::Skipped(cpio::SkipReason::NonRegularData)
    );
    let bytes = cpio_record(b"unterminated", &vec![0; 4097], 0xa1ff, true);
    assert_eq!(
        cpio::Archive::new(&bytes)
            .next_record()
            .unwrap()
            .unwrap()
            .disposition,
        cpio::Disposition::Skipped(cpio::SkipReason::SymlinkSize)
    );
}

#[test]
fn cpio_crc_only_regular_content_is_checked_not_newc_or_symlinks() {
    let mut bytes = cpio_record(b"a\0", b"hello", 0x81ed, true);
    let record = cpio::Archive::new(&bytes).next_record().unwrap().unwrap();
    assert!(record.regular_checksum().unwrap().matches());
    field(&mut bytes, 12, *b"ffffffff");
    assert!(
        !cpio::Archive::new(&bytes)
            .next_record()
            .unwrap()
            .unwrap()
            .regular_checksum()
            .unwrap()
            .matches()
    );
    assert!(matches!(
        inspect_archive(&bytes),
        Err(super::Error::Checksum { .. })
    ));
    bytes[..6].copy_from_slice(b"070701");
    assert_eq!(
        cpio::Archive::new(&bytes)
            .next_record()
            .unwrap()
            .unwrap()
            .regular_checksum(),
        None
    );
    bytes[..6].copy_from_slice(b"070702");
    field(&mut bytes, 1, *b"0000a1ff");
    assert_eq!(
        cpio::Archive::new(&bytes)
            .next_record()
            .unwrap()
            .unwrap()
            .regular_checksum(),
        None
    );
}

#[test]
fn cpio_symlink_target_is_a_c_string_and_not_a_hardlink() {
    let bytes = cpio_record(b"TRAILER!!!\0", b"target\0suffix", 0xa1ff, true);
    let record = cpio::Archive::new(&bytes).next_record().unwrap().unwrap();
    assert_eq!(record.disposition, cpio::Disposition::File);
    assert_eq!(record.symlink_target(), Some(&b"target"[..]));
    assert_eq!(record.hardlink_key(), None);
    let bytes = cpio_record(b"a\0", b"", 0xa1ff, false);
    assert_eq!(
        cpio::Archive::new(&bytes)
            .next_record()
            .unwrap()
            .unwrap()
            .symlink_target(),
        Some(&b""[..])
    );
}

#[test]
fn cpio_hardlink_metadata_includes_type_and_explicit_reset_boundaries() {
    let mut bytes = cpio_record(b"first\0", b"", 0x81ed, false);
    bytes.extend(cpio_record(b"second\0", b"contents", 0x81ed, false));
    bytes.extend(cpio_record(b"node\0", b"", 0x21ed, false));
    // Contrary to the format prose, do_name accepts a regular trailer with data.
    bytes.extend(cpio_record(b"TRAILER!!!\0", b"ignored", 0x81ed, false));
    bytes.extend(cpio_record(b"independent\0", b"new", 0x81ed, false));
    let mut archive = cpio::Archive::new(&bytes);
    let first = archive.next_record().unwrap().unwrap();
    let second = archive.next_record().unwrap().unwrap();
    let node = archive.next_record().unwrap().unwrap();
    assert_eq!(first.hardlink_key(), second.hardlink_key());
    assert_ne!(first.hardlink_key(), node.hardlink_key());
    let trailer = archive.next_record().unwrap().unwrap();
    assert_eq!(trailer.disposition, cpio::Disposition::Trailer);
    assert_eq!(trailer.hardlink_key(), None);
    assert_eq!(
        archive.next_record().unwrap().unwrap().hardlink_key(),
        first.hardlink_key()
    );
}

#[test]
fn cpio_every_truncation_cut_is_reported_without_a_fabricated_record() {
    let bytes = cpio_record(b"name\0", b"payload", 0x81ed, false);
    for length in 1..bytes.len() - 1 {
        let result = cpio::Archive::new(&bytes[..length]).next_record();
        assert!(
            matches!(
                result,
                Err(cpio::Error::Bounds(BoundsError::Truncated { .. }))
            ),
            "cut={length}: {result:?}"
        );
    }
    let mut huge = bytes;
    field(&mut huge, 6, *b"ffffffff");
    assert!(matches!(
        cpio::Archive::new(&huge).next_record(),
        Err(cpio::Error::Bounds(_))
    ));
}

#[test]
fn cpio_compression_is_explicit_pending_work_not_fake_success() {
    for (magic, expected) in [
        ([0x1f, 0x8b], cpio::Compression::Gzip),
        ([0x1f, 0x9e], cpio::Compression::Gzip),
        ([0x42, 0x5a], cpio::Compression::Bzip2),
        ([0x5d, 0], cpio::Compression::Lzma),
        ([0xfd, 0x37], cpio::Compression::Xz),
        ([0x89, 0x4c], cpio::Compression::Lzo),
        ([2, 0x21], cpio::Compression::Lz4),
        ([0x28, 0xb5], cpio::Compression::Zstd),
    ] {
        assert_eq!(
            cpio::Archive::new(&magic).next_record(),
            Err(cpio::Error::CompressionPending(expected))
        );
    }
    let mut old = cpio_record(b"a\0", b"", 0x81ed, false);
    old[..6].copy_from_slice(b"070707");
    assert_eq!(
        cpio::Archive::new(&old).next_record(),
        Err(cpio::Error::OldCpio)
    );
}

#[test]
fn elf_native_keeps_ignored_ident_version_size_and_sections() {
    let mut bytes = elf64(1);
    bytes[4] = 0xff;
    bytes[5] = 0xff;
    bytes[6] = 0xff;
    bytes[7] = 0xff;
    le32(&mut bytes, 20, u32::MAX);
    le16(&mut bytes, 52, 0);
    le64(&mut bytes, 40, u64::MAX);
    le16(&mut bytes, 58, 1);
    le16(&mut bytes, 60, u16::MAX);
    let parsed = elf::Elf::linux_x86_64(&bytes).unwrap();
    assert_eq!(parsed.header().ident[4], 0xff);
    assert_eq!(parsed.header().section_offset, u64::MAX);
    assert!(matches!(
        elf::Elf::parse(&bytes),
        Err(elf::Error::Class(0xff))
    ));
}

#[test]
fn elf_generic_32_big_endian_fields_are_not_native_overlays() {
    let mut bytes = vec![0; 84];
    bytes[..7].copy_from_slice(b"\x7fELF\x01\x02\x00");
    bytes[16..18].copy_from_slice(&elf::ET_EXEC.to_be_bytes());
    bytes[18..20].copy_from_slice(&8u16.to_be_bytes());
    bytes[24..28].copy_from_slice(&0x1234_5678u32.to_be_bytes());
    bytes[28..32].copy_from_slice(&52u32.to_be_bytes());
    bytes[42..44].copy_from_slice(&32u16.to_be_bytes());
    bytes[44..46].copy_from_slice(&1u16.to_be_bytes());
    bytes[52..56].copy_from_slice(&elf::PT_LOAD.to_be_bytes());
    bytes[56..60].copy_from_slice(&0x1122_3344u32.to_be_bytes());
    bytes[60..64].copy_from_slice(&0x2345_6789u32.to_be_bytes());
    bytes[64..68].copy_from_slice(&0x5678_9abcu32.to_be_bytes());
    bytes[68..72].copy_from_slice(&0x1357_9bdfu32.to_be_bytes());
    bytes[72..76].copy_from_slice(&0x2468_ace0u32.to_be_bytes());
    bytes[76..80].copy_from_slice(&elf::PF_R.to_be_bytes());
    bytes[80..84].copy_from_slice(&0x4000u32.to_be_bytes());
    let parsed = elf::Elf::parse(&bytes).unwrap();
    assert_eq!(parsed.header().entry, 0x1234_5678);
    assert_eq!(
        parsed.program(0).unwrap(),
        elf::ProgramHeader {
            kind: elf::PT_LOAD,
            flags: elf::PF_R,
            offset: 0x1122_3344,
            virtual_address: 0x2345_6789,
            physical_address: 0x5678_9abc,
            file_size: 0x1357_9bdf,
            memory_size: 0x2468_ace0,
            alignment: 0x4000,
        }
    );
    assert!(elf::Elf::linux_x86_64(&bytes).is_err());
}

#[test]
fn elf_other_class_endian_combinations_decode_program_fields() {
    let mut big64 = elf64(1);
    load(&mut big64, 0, 0, 0x1234_5678_8765_4321, 0, 16);
    big64[5] = 2;
    for offset in [16, 18, 52, 54, 56, 58, 60, 62] {
        big64[offset..offset + 2].reverse();
    }
    for offset in [20, 48, 64, 68] {
        big64[offset..offset + 4].reverse();
    }
    for offset in [24, 32, 40, 72, 80, 88, 96, 104, 112] {
        big64[offset..offset + 8].reverse();
    }
    let decoded = elf::Elf::parse(&big64).unwrap();
    assert_eq!(decoded.header().endian, Endian::Big);
    assert_eq!(
        decoded.program(0).unwrap().virtual_address,
        0x1234_5678_8765_4321
    );
    assert_eq!(decoded.program(0).unwrap().memory_size, 16);

    let mut little32 = vec![0; 84];
    little32[..7].copy_from_slice(b"\x7fELF\x01\x01\x01");
    le16(&mut little32, 16, elf::ET_EXEC);
    le16(&mut little32, 18, 3);
    le32(&mut little32, 28, 52);
    le16(&mut little32, 42, 32);
    le16(&mut little32, 44, 1);
    le32(&mut little32, 52, elf::PT_LOAD);
    le32(&mut little32, 60, 0x7654_3210);
    le32(&mut little32, 72, 16);
    let decoded = elf::Elf::parse(&little32).unwrap();
    assert_eq!(decoded.header().class, elf::Class::Elf32);
    assert_eq!(decoded.program(0).unwrap().virtual_address, 0x7654_3210);
    assert_eq!(decoded.program(0).unwrap().memory_size, 16);
}

#[test]
fn elf_program_count_stride_and_ranges_match_native_prechecks() {
    assert!(matches!(
        elf::Elf::linux_x86_64(&elf64(0)),
        Err(elf::Error::ProgramCount)
    ));
    assert!(elf::Elf::linux_x86_64(&elf64(1170)).is_ok());
    assert!(matches!(
        elf::Elf::linux_x86_64(&elf64(1171)),
        Err(elf::Error::ProgramCount)
    ));
    let mut bytes = elf64(1);
    le16(&mut bytes, 54, 55);
    assert!(matches!(
        elf::Elf::linux_x86_64(&bytes),
        Err(elf::Error::ProgramEntrySize)
    ));
    le16(&mut bytes, 54, 56);
    le64(&mut bytes, 32, u64::MAX - 3);
    assert!(matches!(
        elf::Elf::linux_x86_64(&bytes),
        Err(elf::Error::Bounds(BoundsError::Overflow))
    ));
    le64(&mut bytes, 32, 0);
    assert!(elf::Elf::linux_x86_64(&bytes).is_ok()); // No phoff!=0 rule in Linux.
}

#[test]
fn elf_main_short_header_uses_zero_filled_binprm_not_interpreter_rules() {
    let mut bytes = elf64(1);
    le64(&mut bytes, 32, 0);
    bytes.truncate(57); // Low byte of e_phnum is present; all later bytes zero.
    let parsed = elf::Elf::linux_x86_64(&bytes).unwrap();
    assert_eq!(parsed.header().program_count, 1);
    assert_eq!(parsed.header().section_entry_size, 0);
    assert!(elf::Elf::parse_as(&bytes, elf::Class::Elf64, Endian::Little).is_err());
    bytes.truncate(56);
    assert!(matches!(
        elf::Elf::linux_x86_64(&bytes),
        Err(elf::Error::ProgramCount)
    ));
}

#[test]
fn elf_machine_type_precede_program_validation() {
    let mut bytes = elf64(1);
    le16(&mut bytes, 16, 1);
    le16(&mut bytes, 18, 3);
    le16(&mut bytes, 54, 0);
    assert!(matches!(
        elf::Elf::linux_x86_64(&bytes),
        Err(elf::Error::Type)
    ));
    le16(&mut bytes, 16, elf::ET_EXEC);
    assert!(matches!(
        elf::Elf::linux_x86_64(&bytes),
        Err(elf::Error::Machine)
    ));
    le16(&mut bytes, 18, elf::EM_X86_64);
    assert!(matches!(
        elf::Elf::linux_x86_64(&bytes),
        Err(elf::Error::ProgramEntrySize)
    ));
}

#[test]
fn elf_every_header_and_table_truncation_is_bounded() {
    let bytes = elf64(3);
    for length in 0..bytes.len() {
        assert!(
            elf::Elf::linux_x86_64(&bytes[..length]).is_err(),
            "cut={length}"
        );
    }
    assert!(elf::Elf::linux_x86_64(&bytes).unwrap().program(3).is_err());
}

#[test]
fn elf_preserves_overlap_wx_odd_alignment_and_unbacked_entry() {
    let mut bytes = elf64(3);
    load(&mut bytes, 0, 0, 4096, 64, 128);
    load(&mut bytes, 1, 0, 4096, 64, 128);
    le64(&mut bytes, 64 + 48, 3);
    le64(&mut bytes, 64 + 56 + 48, 0);
    le64(&mut bytes, 24, u64::MAX);
    le32(&mut bytes, 64 + 112, 0xf000_0001);
    le64(&mut bytes, 64 + 112 + 8, u64::MAX);
    le64(&mut bytes, 64 + 112 + 32, u64::MAX);
    let parsed = elf::Elf::linux_x86_64(&bytes).unwrap();
    assert_eq!(parsed.maximum_alignment(4096).unwrap(), 0);
    assert_eq!(parsed.program(0).unwrap().flags, 7);
    assert_eq!(
        parsed.program(0).unwrap().load_range(),
        parsed.program(1).unwrap().load_range()
    );
    assert_eq!(inspect_elf(&bytes).unwrap().load_segments, 2);
}

#[test]
fn elf_load_metadata_is_not_a_claim_of_mapped_file_bytes() {
    let mut bytes = elf64(1);
    load(&mut bytes, 0, 1 << 40, 4096, 16, 32);
    let parsed = elf::Elf::linux_x86_64(&bytes).unwrap();
    let program = parsed.program(0).unwrap();
    assert_eq!(program.load_range().unwrap(), Some(4096..4128));
    assert!(matches!(
        parsed.segment_data(program),
        Err(elf::Error::Bounds(_))
    ));
    assert!(inspect_elf(&bytes).is_err()); // Incomplete inspection, not exec verdict.
}

#[test]
fn elf_load_size_bss_and_structural_address_overflow() {
    let mut bytes = elf64(1);
    load(&mut bytes, 0, u64::MAX, 4096, 0, 4096);
    assert_eq!(inspect_elf(&bytes).unwrap().file_bytes, 0);
    let p = elf::Elf::linux_x86_64(&bytes).unwrap().program(0).unwrap();
    assert_eq!(p.load_range().unwrap(), Some(4096..8192));
    load(&mut bytes, 0, 0, u64::MAX, 0, 1);
    assert_eq!(
        elf::Elf::linux_x86_64(&bytes)
            .unwrap()
            .program(0)
            .unwrap()
            .load_range(),
        Err(elf::Error::AddressOverflow)
    );
    load(&mut bytes, 0, 0, 0, 2, 1);
    assert_eq!(
        elf::Elf::linux_x86_64(&bytes)
            .unwrap()
            .program(0)
            .unwrap()
            .load_range(),
        Err(elf::Error::FileLargerThanMemory)
    );
}

#[test]
fn elf_interpreter_first_wins_and_embedded_nul_is_permitted() {
    let mut bytes = elf64(2);
    let start = bytes.len() as u64;
    bytes.extend_from_slice(b"ld.so\0junk\0");
    le32(&mut bytes, 64, elf::PT_INTERP);
    le64(&mut bytes, 72, start);
    le64(&mut bytes, 96, 11);
    le32(&mut bytes, 120, elf::PT_INTERP);
    le64(&mut bytes, 128, u64::MAX);
    le64(&mut bytes, 152, u64::MAX);
    assert_eq!(
        elf::Elf::linux_x86_64(&bytes)
            .unwrap()
            .interpreter()
            .unwrap(),
        Some(&b"ld.so"[..])
    );
    // Later malformed PT_INTERP is ignored, not a duplicate-interpreter error.
    bytes[usize::try_from(start).unwrap()] = 0;
    assert_eq!(
        elf::Elf::linux_x86_64(&bytes)
            .unwrap()
            .interpreter()
            .unwrap(),
        Some(&b""[..])
    );
}

#[test]
fn elf_interpreter_sizes_and_terminator_fail_before_vfs() {
    let mut bytes = elf64(1);
    let start = bytes.len() as u64;
    bytes.extend_from_slice(b"ab\0");
    le32(&mut bytes, 64, elf::PT_INTERP);
    le64(&mut bytes, 72, start);
    for size in [0, 1, 4097, u64::MAX] {
        le64(&mut bytes, 96, size);
        assert_eq!(
            elf::Elf::linux_x86_64(&bytes).unwrap().interpreter(),
            Err(elf::Error::InterpreterSize)
        );
    }
    le64(&mut bytes, 96, 2);
    assert_eq!(
        elf::Elf::linux_x86_64(&bytes).unwrap().interpreter(),
        Err(elf::Error::InterpreterUnterminated)
    );
    le64(&mut bytes, 96, 3);
    le64(&mut bytes, 72, u64::MAX);
    assert_eq!(
        elf::Elf::linux_x86_64(&bytes).unwrap().interpreter(),
        Err(elf::Error::Bounds(BoundsError::Overflow))
    );
}

#[test]
fn elf_last_gnu_stack_wins_and_alignment_is_rounded() {
    let mut bytes = elf64(3);
    load(&mut bytes, 0, 0, 0, 0, 0);
    le64(&mut bytes, 112, 8192);
    le32(&mut bytes, 120, elf::PT_GNU_STACK);
    le32(&mut bytes, 124, elf::PF_X);
    le32(&mut bytes, 176, elf::PT_GNU_STACK);
    let parsed = elf::Elf::linux_x86_64(&bytes).unwrap();
    assert_eq!(parsed.executable_stack().unwrap(), Some(false));
    assert_eq!(parsed.maximum_alignment(4096).unwrap(), 8192);
    assert_eq!(parsed.maximum_alignment(3), Err(elf::Error::Alignment));
}

#[test]
fn actual_archive_consumer_returns_owned_only_summary() {
    let summary = {
        let elf = elf64(1);
        let mut bytes = cpio_record(b"bin/init\0", &elf, 0x81ed, false);
        bytes.extend(cpio_record(b"lib\0", b"usr/lib", 0xa1ff, false));
        bytes.extend(cpio_record(b"TRAILER!!!\0", b"", 0, false));
        inspect_archive(&bytes).unwrap()
    };
    assert_eq!(summary.records, 3);
    assert_eq!(summary.files, 2);
    assert_eq!(summary.regular_files, 1);
    assert_eq!(summary.symlinks, 1);
    assert_eq!(summary.elf_files, 1);
    assert_eq!(summary.trailers, 1);
}

#[test]
fn archive_inspection_does_not_impose_native_exec_eligibility() {
    let mut object = elf64(0);
    le16(&mut object, 16, 1); // ET_REL: regular archive content, not an exec.
    assert!(matches!(
        elf::Elf::linux_x86_64(&object),
        Err(elf::Error::Type)
    ));
    let mut compat = vec![0; 84];
    compat[..7].copy_from_slice(b"\x7fELF\x01\x01\x01");
    le16(&mut compat, 16, elf::ET_EXEC);
    le16(&mut compat, 18, 3); // EM_386
    le32(&mut compat, 28, 52);
    le16(&mut compat, 42, 32);
    le16(&mut compat, 44, 1);
    le32(&mut compat, 52, elf::PT_LOAD);
    le32(&mut compat, 72, 16);
    let mut archive = cpio_record(b"module.o\0", &object, 0x81a4, false);
    archive.extend(cpio_record(b"compat-program\0", &compat, 0x81ed, false));
    let summary = inspect_archive(&archive).unwrap();
    assert_eq!(summary.regular_files, 2);
    assert_eq!(summary.elf_files, 2);
    assert_eq!(summary.load_segments, 1);
    assert_eq!(summary.interpreters, 0);
}

#[test]
fn elf_extended_program_count_is_not_misread_as_a_literal_count() {
    let mut bytes = elf64(1);
    le16(&mut bytes, 56, u16::MAX);
    assert!(matches!(
        elf::Elf::parse(&bytes),
        Err(elf::Error::ExtendedProgramCountPending)
    ));
    assert!(matches!(
        elf::Elf::linux_x86_64(&bytes),
        Err(elf::Error::ProgramCount)
    ));
}
