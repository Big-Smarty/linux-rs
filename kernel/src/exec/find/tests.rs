#![allow(
    clippy::unreadable_literal,
    clippy::cast_possible_truncation,
    clippy::similar_names,
    clippy::large_types_passed_by_value,
    clippy::format_push_string,
    clippy::cast_possible_wrap
)]
extern crate std;
use super::{FindError, InitEntry, InitSearch, is_init};
use crate::image::cpio::FileType;
use std::{format, string::String, vec::Vec};

const REG: u32 = 0o100_755;
const DIR: u32 = 0o040_755;
const LNK: u32 = 0o120_777;

fn entry(name: &str, mode: u32, nlink: u32, data: &[u8]) -> Vec<u8> {
    let name = format!("{name}\0");
    let mut out = String::new();
    out += "070701";
    for field in [
        1,
        mode,
        0,
        0,
        nlink,
        0,
        data.len() as u32,
        0,
        0,
        0,
        0,
        name.len() as u32,
        0,
    ] {
        out += &format!("{field:08x}");
    }
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(name.as_bytes());
    bytes.resize(bytes.len().div_ceil(4) * 4, 0);
    bytes.extend_from_slice(data);
    bytes.resize(bytes.len().div_ceil(4) * 4, 0);
    bytes
}
fn archive(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = entries.concat();
    bytes.extend(entry("TRAILER!!!", 0, 1, b""));
    bytes
}
fn found(search: &InitSearch, modules: &[&[u8]]) -> (usize, Vec<u8>, u32, FileType) {
    let e = search.entry().unwrap();
    let data = modules[e.module][e.offset..e.offset + e.length].to_vec();
    (e.module, data, e.mode, e.kind)
}

#[test]
fn init_spellings_normalise_to_slash_init() {
    for name in [
        "init",
        "./init",
        "/init",
        "//init",
        "./././init",
        ".//init/",
        "/./init",
    ] {
        assert_eq!(is_init(name.as_bytes()), Some(true), "{name}");
    }
    for name in [
        "",
        "/",
        ".",
        "initx",
        "xinit",
        "sbin/init",
        "init/init",
        "init/x",
        "bin/../init",
    ] {
        assert_ne!(is_init(name.as_bytes()), Some(true), "{name}");
    }
    assert_eq!(is_init(b"bin/../init"), None);
    assert_eq!(is_init(b"../init"), None);
}

#[test]
fn finds_regular_init_and_later_entries_replace_earlier() {
    let first = archive(&[entry("etc", DIR, 1, b""), entry("./init", REG, 1, b"AAAA")]);
    let second = archive(&[entry("/init", 0o100_700, 1, b"BB")]);
    let mut search = InitSearch::new();
    assert_eq!(search.entry(), None);
    assert_eq!(search.scan(0, &first), Ok(true));
    assert_eq!(
        found(&search, &[&first]),
        (0, b"AAAA".to_vec(), REG, FileType::Regular)
    );
    assert_eq!(search.scan(1, &second), Ok(true));
    assert_eq!(
        found(&search, &[&first, &second]),
        (1, b"BB".to_vec(), 0o100_700, FileType::Regular)
    );
    // Within one archive, the last duplicate wins too.
    let twice = archive(&[
        entry("init", REG, 1, b"one"),
        entry("init", REG, 1, b"two!"),
    ]);
    let mut search = InitSearch::new();
    search.scan(0, &twice).unwrap();
    assert_eq!(found(&search, &[&twice]).1, b"two!");
}

#[test]
fn other_paths_are_ignored_and_absent_is_none() {
    let bytes = archive(&[
        entry("sbin/init", REG, 1, b"x"),
        entry("initrd", REG, 1, b"y"),
    ]);
    let mut search = InitSearch::new();
    assert_eq!(search.scan(0, &bytes), Ok(true));
    assert_eq!(search.entry(), None);
    // An empty module and a module of only padding are valid and change nothing.
    assert_eq!(search.scan(1, &[]), Ok(true));
    assert_eq!(search.scan(2, &[0; 16]), Ok(true));
    assert_eq!(search.entry(), None);
}

#[test]
fn empty_replacement_keeps_old_data_but_takes_new_mode() {
    let first = archive(&[entry("init", REG, 1, b"keepme")]);
    let second = archive(&[entry("init", 0o100_500, 1, b"")]);
    let mut search = InitSearch::new();
    search.scan(0, &first).unwrap();
    search.scan(1, &second).unwrap();
    assert_eq!(
        found(&search, &[&first, &second]),
        (0, b"keepme".to_vec(), 0o100_500, FileType::Regular)
    );
}

#[test]
fn non_regular_replacements_are_reported_not_hidden() {
    let reg = archive(&[entry("init", REG, 1, b"ELF")]);
    let link = archive(&[entry("init", LNK, 1, b"/bin/sh")]);
    let dir = archive(&[entry("init", DIR, 1, b"")]);
    let mut search = InitSearch::new();
    search.scan(0, &reg).unwrap();
    search.scan(1, &link).unwrap();
    let e = search.entry().unwrap();
    assert_eq!((e.module, e.kind), (1, FileType::Symlink));
    search.scan(2, &dir).unwrap();
    assert_eq!(search.entry().unwrap().kind, FileType::Directory);
    // A regular file replaces a symlink again.
    search.scan(3, &reg).unwrap();
    assert_eq!(search.entry().unwrap().kind, FileType::Regular);
}

#[test]
fn uninspectable_modules_stay_skipped_entirely() {
    let good = archive(&[entry("init", REG, 1, b"good")]);
    // Valid first record for init, then a truncated header: whole module skipped.
    let mut damaged = entry("init", REG, 1, b"evil");
    damaged.extend_from_slice(b"07070100");
    let mut search = InitSearch::new();
    search.scan(0, &good).unwrap();
    assert_eq!(search.scan(1, &damaged), Ok(false));
    assert_eq!(found(&search, &[&good]).1, b"good");
    // Compressed (pending decoder) and garbage modules are skipped as well.
    assert_eq!(search.scan(2, &[0x1f, 0x8b, 8, 0, 0, 0, 0, 0]), Ok(false));
    assert_eq!(search.scan(3, b"not a cpio"), Ok(false));
    // A module whose ELF content is structurally invalid is skipped, like main.rs.
    let bad_elf = archive(&[entry(
        "init",
        REG,
        1,
        b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0",
    )]);
    assert_eq!(search.scan(4, &bad_elf), Ok(false));
    assert_eq!(found(&search, &[&good]).0, 0);
}

#[test]
fn hard_linked_init_is_rejected_explicitly() {
    let bytes = archive(&[entry("init", REG, 2, b"x")]);
    let mut search = InitSearch::new();
    assert_eq!(search.scan(0, &bytes), Err(FindError::HardLink));
    assert_eq!(search.entry(), None);
}

#[test]
fn entry_offsets_index_the_module_bytes() {
    let bytes = archive(&[
        entry("a", REG, 1, b"zzzzz"),
        entry("init", REG, 1, b"0123456789"),
    ]);
    let mut search = InitSearch::new();
    search.scan(0, &bytes).unwrap();
    let InitEntry { offset, length, .. } = search.entry().unwrap();
    assert_eq!(&bytes[offset..offset + length], b"0123456789");
    assert_eq!(offset % 4, 0);
}
