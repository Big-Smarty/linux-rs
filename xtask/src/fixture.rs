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
    /// `[start, end)` file-backed extents (`p_vaddr..p_vaddr + p_filesz`) of the same segments:
    /// what `print_vma_addr` reports, since the bss tail is an anonymous mapping.
    pub(crate) executable_file_extents: Vec<(u64, u64)>,
    pub(crate) loads: u64,
    pub(crate) interpreters: u64,
    pub(crate) dynamics: u64,
    /// Undefined entries of `.symtab` (the mandatory null symbol excluded); 0 without one.
    pub(crate) undefined_symbols: u64,
    /// `e_entry`, which the kernel reports as `AT_ENTRY`.
    pub(crate) entry: u64,
    /// `e_phnum`, `AT_PHNUM`.
    pub(crate) phnum: u16,
    /// `AT_PHDR`: the virtual address at which the segment containing `e_phoff` maps the
    /// program-header table (`load_elf_binary`), 0 when no segment does.
    pub(crate) phdr: u64,
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
        executable_file_extents: Vec::new(),
        loads: 0,
        interpreters: 0,
        dynamics: 0,
        undefined_symbols: 0,
        entry: header.e_entry,
        phnum: header.e_phnum,
        phdr: 0,
    };
    for program in file.segments().into_iter().flatten() {
        match program.p_type {
            abi::PT_LOAD => {
                if program.p_offset <= header.e_phoff
                    && header.e_phoff < program.p_offset.wrapping_add(program.p_filesz)
                {
                    facts.phdr = (header.e_phoff - program.p_offset).wrapping_add(program.p_vaddr);
                }
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
                    facts
                        .executable_file_extents
                        .push((program.p_vaddr, program.p_vaddr + program.p_filesz));
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

const S_IFMT: u32 = 0o170_000;
const S_IFREG: u32 = 0o100_000;
const S_IFLNK: u32 = 0o120_000;

/// The files `user/init`'s `fs` and `proc` oracle tests read (name, mode, nlink, data), archived
/// after `/dev`, `/init` and `/linuxrc` in this order (parents first). The data is part of the
/// oracle contract: `xtask/oracle/expected.tsv` and the `fs` checks name these bytes.
pub(crate) const TEST_FILES: [(&str, u32, u32, &[u8]); 7] = [
    ("fixture", 0o040_755, 3, b""),
    ("fixture/hello.txt", 0o100_644, 1, b"hello, oracle\n"),
    ("fixture/empty", 0o100_644, 1, b""),
    ("fixture/noexec", 0o100_755, 1, b"not an executable\n"),
    ("fixture/sub", 0o040_755, 2, b""),
    ("fixture/sub/nested.txt", 0o100_644, 1, b"nested\n"),
    ("fixture/link", 0o120_777, 1, b"hello.txt"),
];

/// The deterministic newc initramfs: `/dev` (directory), `/init` (the ELF), `/linuxrc` -> `/init`,
/// then [`TEST_FILES`]. Fixed mtime 0, uid/gid 0 and sequential inode numbers; Linux-like link
/// counts and modes.
///
/// Only `write_cpio` is used: `Writer::finish()` after a short write would emit a corrupt entry.
pub(crate) fn initramfs(init: &[u8]) -> io::Result<Vec<u8>> {
    if u32::try_from(init.len()).is_err() {
        return Err(invalid("init does not fit a newc file size"));
    }
    let entries =
        [
            (NewcBuilder::new("dev").mode(0o040_755).nlink(2), &b""[..]),
            (NewcBuilder::new("init").mode(0o100_755), init),
            (NewcBuilder::new("linuxrc").mode(0o120_777), &b"/init"[..]),
        ]
        .into_iter()
        .chain(TEST_FILES.iter().map(|&(name, mode, nlink, data)| {
            (NewcBuilder::new(name).mode(mode).nlink(nlink), data)
        }));
    write_cpio(
        entries.map(|(builder, data)| (builder, Cursor::new(data))),
        Vec::new(),
    )
}

/// A deterministic newc archive without any `/init`: the kernel must end the boot the way Linux does
/// when `rdinit=/init` fails and no root device is configured.
pub(crate) fn initramfs_without_init() -> io::Result<Vec<u8>> {
    write_cpio(
        [(
            NewcBuilder::new("dev").mode(0o040_755).nlink(2),
            Cursor::new(&b""[..]),
        )]
        .into_iter(),
        Vec::new(),
    )
}

/// The host program the `busybox` oracle group runs (`BusyBox` v1.36.1, static, GPL-2.0-only). It is a
/// test input read at build time: never committed, its SHA-256 goes into the run's evidence, and
/// the case is `unavailable` when it is missing ([`busybox_unavailable`]).
pub(crate) const BUSYBOX_HOST_PATH: &str = "/usr/bin/busybox";

/// `mtime` of every file of the busybox archive (2001-09-09 01:46:40 UTC), so `ls -l` and
/// `stat` print the same on both kernels.
const BUSYBOX_MTIME: u32 = 1_000_000_000;

/// The applets the group executes by path (`/bin/<name>` -> `busybox`, as `busybox --install -s`
/// lays them out): `sh` runs its commands by `PATH` lookup, the group's runner by `argv[0]`.
pub(crate) const BUSYBOX_APPLETS: &[&str] = &[
    "[",
    "awk",
    "basename",
    "cat",
    "chmod",
    "cmp",
    "cp",
    "cut",
    "dd",
    "diff",
    "dirname",
    "du",
    "echo",
    "env",
    "expr",
    "false",
    "find",
    "grep",
    "head",
    "id",
    "ln",
    "ls",
    "md5sum",
    "mkdir",
    "mv",
    "nl",
    "od",
    "paste",
    "printf",
    "pwd",
    "readlink",
    "realpath",
    "rev",
    "rm",
    "rmdir",
    "sed",
    "seq",
    "sh",
    "sha1sum",
    "sha256sum",
    "sleep",
    "sort",
    "stat",
    "tac",
    "tail",
    "tee",
    "test",
    "touch",
    "tr",
    "true",
    "uniq",
    "wc",
    "xargs",
    "yes",
    "base64",
    "cksum",
    "comm",
    "date",
    "expand",
    "fold",
    "hexdump",
    "install",
    "kill",
    "sync",
    "timeout",
    "truncate",
    "uname",
    "unlink",
    "whoami",
    "xxd",
    "ash",
    "printenv",
    "tty",
    "bc",
    "dc",
    "factor",
    "gzip",
    "gunzip",
    "bzip2",
    "bunzip2",
    "xz",
    "unxz",
    "tar",
    "cpio",
    "patch",
    "usleep",
    "hostname",
    "nproc",
    "shuf",
    "chgrp",
    "chown",
    "mktemp",
];

/// Directories of the busybox archive: (name, mode), parents first.
const BUSYBOX_DIRS: &[(&str, u32)] = &[
    ("bin", 0o040_755),
    ("tmp", 0o041_777),
    ("bb", 0o040_755),
    ("bb/tree", 0o040_755),
    ("bb/tree/a", 0o040_755),
    ("bb/tree/a/b", 0o040_755),
];

/// The data files of the `busybox` group (name, mode, data). The bytes are part of the oracle
/// contract, like [`TEST_FILES`]. `bb/bin.dat` is generated: the 256 byte values in order.
const BUSYBOX_FILES: &[(&str, u32, &[u8])] = &[
    ("bb/hello.txt", 0o100_644, b"hello world\n"),
    (
        "bb/lines.txt",
        0o100_644,
        b"banana\napple\ncherry\napple\nbanana\napple\n",
    ),
    ("bb/nums.txt", 0o100_644, b"10\n9\n100\n1\n55\n"),
    ("bb/csv.txt", 0o100_644, b"a,b,c\n1,2,3\n4,5,6\n"),
    (
        "bb/words.txt",
        0o100_644,
        b"the quick brown fox\njumps over the lazy dog\n",
    ),
    ("bb/empty", 0o100_644, b""),
    ("bb/noperm", 0o100_000, b"secret\n"),
    (
        "bb/script.sh",
        0o100_755,
        b"#!/bin/sh\necho script $# $1\nexit 7\n",
    ),
    ("bb/tree/e.txt", 0o100_644, b"e\n"),
    ("bb/tree/a/d.txt", 0o100_644, b"dd\n"),
    ("bb/tree/a/b/c.txt", 0o100_644, b"ccc\n"),
    ("bb/tree/exec.sh", 0o100_755, b"#!/bin/sh\necho exec\n"),
];

/// Every non-data entry of [`busybox_initramfs`] besides the directories and `bin/busybox`:
/// symlinks (name, target).
const BUSYBOX_LINKS: &[(&str, &str)] =
    &[("bb/tree/link", "e.txt"), ("bb/tree/dangling", "nowhere")];

/// The 256 byte values in order: the input of the `od`/`md5sum` checks.
fn busybox_bin_dat() -> Vec<u8> {
    (0..=255u8).collect()
}

/// The deterministic second initramfs module of the `busybox` group: `/bin/busybox` (the host's
/// program, `0755`), a `/bin/<applet>` symlink per [`BUSYBOX_APPLETS`], `/tmp` and the data files
/// of [`BUSYBOX_FILES`] / [`BUSYBOX_LINKS`] with the fixed mtime [`BUSYBOX_MTIME`]. Linux unpacks
/// concatenated archives into one rootfs, so the pinned reference gets `init.cpio` + this one.
pub(crate) fn busybox_initramfs(busybox: &[u8]) -> io::Result<Vec<u8>> {
    if u32::try_from(busybox.len()).is_err() {
        return Err(invalid("busybox does not fit a newc file size"));
    }
    let bin_dat = busybox_bin_dat();
    let mut entries: Vec<(NewcBuilder, &[u8])> = Vec::new();
    let new = |name: &str, mode: u32| NewcBuilder::new(name).mode(mode).mtime(BUSYBOX_MTIME);
    for &(name, mode) in BUSYBOX_DIRS {
        entries.push((new(name, mode).nlink(2), &[]));
    }
    entries.push((new("bin/busybox", 0o100_755), busybox));
    for applet in BUSYBOX_APPLETS {
        entries.push((
            // `new` borrows the name only for the call; the builder owns its copy.
            new(&format!("bin/{applet}"), 0o120_777),
            b"busybox",
        ));
    }
    for &(name, mode, data) in BUSYBOX_FILES {
        entries.push((new(name, mode), data));
    }
    entries.push((new("bb/bin.dat", 0o100_644), &bin_dat));
    for &(name, target) in BUSYBOX_LINKS {
        entries.push((new(name, 0o120_777), target.as_bytes()));
    }
    write_cpio(
        entries
            .into_iter()
            .map(|(builder, data)| (builder, Cursor::new(data))),
        Vec::new(),
    )
}

/// The `CHECK image inspected` tail the kernel must print for [`busybox_initramfs`] (one ELF: the
/// busybox program, whose `PT_LOAD`/`PT_INTERP` counts come from its headers).
pub(crate) fn busybox_counts(archive_len: usize, program: &ElfFacts) -> String {
    let reserved = archive_len.next_multiple_of(PAGE).max(PAGE);
    // dirs + busybox + applet links + data files + bin.dat + links; the trailer is one more record.
    let files = BUSYBOX_DIRS.len()
        + 1
        + BUSYBOX_APPLETS.len()
        + BUSYBOX_FILES.len()
        + 1
        + BUSYBOX_LINKS.len();
    let regular = 1 + BUSYBOX_FILES.len() + 1;
    let symlinks = BUSYBOX_APPLETS.len() + BUSYBOX_LINKS.len();
    format!(
        "reserved={reserved} bytes={archive_len} records={} files={files} regular={regular} symlinks={symlinks} trailers=1 skipped=0 elf=1 loads={} interpreters={} execution=false rootfs=false",
        files + 1,
        program.loads,
        program.interpreters
    )
}

/// SHA-256 of the `BusyBox` program (`BusyBox` v1.36.1, static, x86-64-v4) the expected lines of the
/// `busybox` group were recorded with on the pinned Linux. Another program may print other
/// lines, so the group is `unavailable` on a host with a different one.
pub(crate) const BUSYBOX_SHA256: &str =
    "1097cdefbbfc633d390ce9487872158b60a857155d7f680658f1dca3c7febf0d";

/// The host program for the `busybox` group, or why this host cannot run the group: the file is
/// missing, it is not a static x86-64 `ET_EXEC` program, or the CPU lacks the AVX-512
/// instructions it was built for (x86-64-v4: F, BW, CD, DQ, VL). `cpuinfo` is `/proc/cpuinfo`.
pub(crate) fn busybox_input(path: &str, cpuinfo: &str) -> Result<Vec<u8>, String> {
    let program = std::fs::read(path).map_err(|error| format!("{path}: {error}"))?;
    let facts = elf_facts(&program).map_err(|error| format!("{path}: {error}"))?;
    if facts.interpreters != 0 || facts.dynamics != 0 {
        return Err(format!("{path} is not a static program"));
    }
    busybox_cpu(cpuinfo)?;
    Ok(program)
}

/// The CPU half of [`busybox_input`].
pub(crate) fn busybox_cpu(cpuinfo: &str) -> Result<(), String> {
    match missing_cpu_flag(cpuinfo, &BUSYBOX_CPU_FLAGS) {
        Some(flag) => Err(format!(
            "the CPU lacks {flag} (BusyBox is built for x86-64-v4)"
        )),
        None => Ok(()),
    }
}

/// The AVX-512 subset x86-64-v4 requires.
const BUSYBOX_CPU_FLAGS: [&str; 5] = ["avx512f", "avx512bw", "avx512cd", "avx512dq", "avx512vl"];

/// What the `xstate` group needs of the host CPU under KVM `-cpu host`: AVX-512 F/BW/DQ/VL, the
/// protection keys and `XSAVE`.
pub(crate) const XSTATE_CPU_FLAGS: [&str; 6] = [
    "xsave", "avx512f", "avx512bw", "avx512dq", "avx512vl", "pku",
];

/// The first of `wanted` that the `flags` line of `/proc/cpuinfo` does not list.
pub(crate) fn missing_cpu_flag<'a>(cpuinfo: &str, wanted: &[&'a str]) -> Option<&'a str> {
    let flags = cpuinfo
        .lines()
        .find(|line| line.starts_with("flags"))
        .unwrap_or_default();
    wanted
        .iter()
        .copied()
        .find(|flag| !flags.split_ascii_whitespace().any(|word| word == *flag))
}

/// What the kernel must report for the generated archive and run `/init` (qemu64 constants).
pub(crate) struct Expected {
    pub(crate) archive_counts: String,
    /// The `CHECK image inspected` tail of `busybox.cpio`, when the host provides it.
    pub(crate) busybox_counts: Option<String>,
    pub(crate) init: ElfFacts,
}

/// The summary line `user/init` prints for the pinned reference kernel, with the kernel's own
/// `vdso=0`, no-RSEQ configuration under `-cpu qemu64`: the oracle line minus its two `AT_RSEQ_*`
/// entries, with this binary's `AT_PHDR`/`AT_PHNUM`/`AT_ENTRY`. `argc` counts `/init` itself.
pub(crate) fn init_summary(init: &ElfFacts, argc: usize) -> String {
    format!(
        "init: argc={argc} argv0=/init pid=1 rsp_mod16=0 auxv=AT_MINSIGSTKSZ:0x5a0,AT_HWCAP:0x78bfbfd,AT_PAGESZ:0x1000,AT_CLKTCK:0x64,AT_PHDR:{:#x},AT_PHENT:0x38,AT_PHNUM:{:#x},AT_BASE:0x0,AT_FLAGS:0x0,AT_ENTRY:{:#x},AT_UID:0x0,AT_EUID:0x0,AT_GID:0x0,AT_EGID:0x0,AT_SECURE:0x0,AT_RANDOM:*,AT_HWCAP2:0x0,AT_EXECFN:*,AT_PLATFORM:* execfn=/init platform=x86_64 envp=HOME=/,TERM=linux",
        init.phdr, init.phnum, init.entry
    )
}

/// The `CHECK image inspected` tail the kernel must print for [`initramfs`], by construction:
/// the three base files, [`TEST_FILES`] and the trailer, the ELF's own `PT_LOAD`/`PT_INTERP` counts, page-rounded reservation.
pub(crate) fn archive_counts(archive_len: usize, init: &ElfFacts) -> String {
    let reserved = archive_len.next_multiple_of(PAGE).max(PAGE);
    let of_type = |kind| TEST_FILES.iter().filter(|f| f.1 & S_IFMT == kind).count();
    let files = 3 + TEST_FILES.len();
    let (regular, symlinks) = (1 + of_type(S_IFREG), 1 + of_type(S_IFLNK));
    format!(
        "reserved={reserved} bytes={archive_len} records={} files={files} regular={regular} symlinks={symlinks} trailers=1 skipped=0 elf=1 loads={} interpreters={} execution=false rootfs=false",
        files + 1,
        init.loads,
        init.interpreters
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(field: &[u8]) -> u32 {
        u32::from_str_radix(std::str::from_utf8(field).unwrap(), 16).unwrap()
    }

    /// Independent newc walk: (name, mode, nlink, data) per entry, asserting the framing.
    fn entries(archive: &[u8], mtime: u32) -> Vec<(String, u32, u32, Vec<u8>)> {
        let (mut at, mut found) = (0, Vec::new());
        while at < archive.len() {
            assert_eq!(at % 4, 0, "entry starts 4-byte aligned");
            assert_eq!(&archive[at..at + 6], b"070701");
            let field = |n: usize| &archive[at + 6 + 8 * n..at + 14 + 8 * n];
            let (mode, nlink, size, name_size) =
                (hex(field(1)), hex(field(4)), hex(field(6)), hex(field(11)));
            let trailer = &archive[at + 110..at + 110 + 10] == b"TRAILER!!!";
            assert_eq!(
                (hex(field(2)), hex(field(3)), hex(field(5))),
                (0, 0, if trailer { 0 } else { mtime }),
                "uid, gid, mtime"
            );
            assert_eq!(hex(field(12)), 0, "newc checksum field");
            assert_eq!(
                (7..=10).map(|n| hex(field(n))).collect::<Vec<_>>(),
                [0; 4],
                "dev and rdev numbers"
            );
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
        let found = entries(&archive, 0);
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
                ("fixture", 0o040_755, 3, 0),
                ("fixture/hello.txt", 0o100_644, 1, 14),
                ("fixture/empty", 0o100_644, 1, 0),
                ("fixture/noexec", 0o100_755, 1, 18),
                ("fixture/sub", 0o040_755, 2, 0),
                ("fixture/sub/nested.txt", 0o100_644, 1, 7),
                ("fixture/link", 0o120_777, 1, 9),
                ("TRAILER!!!", 0, 1, 0)
            ]
        );
        assert_eq!(found[1].3, init);
        assert_eq!(found[2].3, b"/init");
        // Sequential inode numbers 0, 1, 2 (write_cpio); the trailer has ino 0, mode 0, nlink 1.
        let inodes = [0, 1, 2, 3, 10].map(|i| hex(&archive[entry_offset(&archive, i) + 6..][..8]));
        assert_eq!(inodes, [0, 1, 2, 3, 0]);
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
        assert_eq!(facts.executable_file_extents, [(0x20_0000, 0x20_0010)]);
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
        assert!(counts.starts_with("reserved=4096 bytes=4096 records=11 files=10 regular=5 symlinks=2 trailers=1 skipped=0 elf=1 loads=2 interpreters=0 "));
        assert!(archive_counts(4097, &facts).starts_with("reserved=8192 bytes=4097 "));
        assert!(archive_counts(0, &facts).starts_with("reserved=4096 bytes=0 "));
    }

    #[test]
    fn expected_counts_describe_the_generated_archive() {
        let program = synthetic_elf(&[(1, 5, 0x20_0000, 16, 16), (1, 6, 0x30_0000, 8, 8)], 62);
        let facts = elf_facts(&program).unwrap();
        let archive = initramfs(&program).unwrap();
        let found = entries(&archive, 0);
        let of_type = |kind: u32| {
            found
                .iter()
                .filter(|e| e.0 != "TRAILER!!!" && e.1 & 0o170_000 == kind)
                .count()
        };
        let trailers = found.iter().filter(|e| e.0 == "TRAILER!!!").count();
        let elfs = found
            .iter()
            .filter(|e| e.1 & 0o170_000 == 0o100_000 && e.3.starts_with(b"\x7fELF"))
            .count();
        let expected = format!(
            "records={} files={} regular={} symlinks={} trailers={trailers} skipped=0 elf={elfs} loads={} interpreters={} ",
            found.len(),
            found.len() - trailers,
            of_type(0o100_000),
            of_type(0o120_000),
            facts.loads,
            facts.interpreters,
        );
        let counts = archive_counts(archive.len(), &facts);
        assert!(counts.contains(&expected), "{counts} vs {expected}");
    }

    /// A static program as `elf_facts` accepts it: one executable `PT_LOAD`.
    fn program() -> Vec<u8> {
        synthetic_elf(&[(1, 5, 0x40_0000, 16, 32), (1, 6, 0x50_0000, 8, 8)], 62)
    }

    #[test]
    fn busybox_module_is_framed_deterministic_and_counted() {
        let program = program();
        let archive = busybox_initramfs(&program).unwrap();
        assert_eq!(archive.len() % 4, 0);
        assert_eq!(archive, busybox_initramfs(&program).unwrap());
        let found = entries(&archive, BUSYBOX_MTIME);
        let named = |name: &str| found.iter().find(|entry| entry.0 == name).unwrap();
        // The program, its links and the data the group names, with the fixed mtime.
        assert_eq!(named("bin/busybox").1, 0o100_755);
        assert_eq!(named("bin/busybox").3, program);
        assert_eq!(named("bin/sh").1, 0o120_777);
        assert_eq!(named("bin/sh").3, b"busybox");
        assert_eq!(named("tmp").1, 0o041_777);
        assert_eq!(named("bb/hello.txt").3, b"hello world\n");
        assert_eq!(named("bb/bin.dat").3, (0..=255u8).collect::<Vec<_>>());
        assert_eq!(named("bb/tree/link").3, b"e.txt");
        assert_eq!(named("bb/noperm").1, 0o100_000);
        // Parents come first, so Linux's unpacker (which never creates parents) finds them.
        let position = |name: &str| found.iter().position(|e| e.0 == name).unwrap();
        let listed = BUSYBOX_DIRS
            .iter()
            .map(|entry| entry.0)
            .chain(BUSYBOX_FILES.iter().map(|entry| entry.0));
        for name in listed {
            if let Some((parent, _)) = name.rsplit_once('/') {
                assert!(position(parent) < position(name), "{name}");
            }
        }
        // Every applet is a link to the program and none is listed twice.
        let mut applets = BUSYBOX_APPLETS.to_vec();
        applets.sort_unstable();
        applets.dedup();
        assert_eq!(applets.len(), BUSYBOX_APPLETS.len());
        for applet in BUSYBOX_APPLETS {
            assert_eq!(named(&format!("bin/{applet}")).3, b"busybox", "{applet}");
        }
        // The counts the kernel must print for it.
        let facts = elf_facts(&program).unwrap();
        let counts = busybox_counts(archive.len(), &facts);
        let trailers = found.iter().filter(|e| e.0 == "TRAILER!!!").count();
        let of_type = |kind: u32| {
            found
                .iter()
                .filter(|e| e.0 != "TRAILER!!!" && e.1 & 0o170_000 == kind)
                .count()
        };
        let expected = format!(
            "records={} files={} regular={} symlinks={} trailers={trailers} skipped=0 elf=1 loads=2 interpreters=0 ",
            found.len(),
            found.len() - trailers,
            of_type(0o100_000),
            of_type(0o120_000),
        );
        assert!(counts.contains(&expected), "{counts} vs {expected}");
    }

    #[test]
    fn busybox_is_unavailable_without_the_program_or_the_cpu_features() {
        let avx512 = "flags\t: fpu sse2 avx512f avx512bw avx512cd avx512dq avx512vl pku xsave";
        assert_eq!(busybox_cpu(avx512), Ok(()));
        for missing in ["avx512f", "avx512bw", "avx512cd", "avx512dq", "avx512vl"] {
            let flags = avx512.replace(missing, "other");
            let reason = busybox_cpu(&flags).unwrap_err();
            assert!(reason.contains(missing), "{reason}");
        }
        assert!(busybox_cpu("model name\t: nothing").is_err());
        assert_eq!(missing_cpu_flag(avx512, &XSTATE_CPU_FLAGS), None);
        assert_eq!(
            missing_cpu_flag(&avx512.replace("pku", "ospke"), &XSTATE_CPU_FLAGS),
            Some("pku")
        );
        let error = busybox_input("/nonexistent/busybox", avx512).unwrap_err();
        assert!(error.contains("/nonexistent/busybox"), "{error}");
    }

    #[test]
    fn corrupt_module_looks_like_gzip() {
        assert_eq!(&CORRUPT_MODULE[..2], [0x1f, 0x8b]);
    }
}
