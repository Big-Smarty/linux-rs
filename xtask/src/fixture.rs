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
/// oracle contract: `xtask/oracle/expected.tsv` and the `fs` checks name these bytes. `proc` and
/// `mnt/a` .. `mnt/h` are the empty mount points of the `procfs` group.
pub(crate) const TEST_FILES: [(&str, u32, u32, &[u8]); 17] = [
    ("fixture", 0o040_755, 3, b""),
    ("fixture/hello.txt", 0o100_644, 1, b"hello, oracle\n"),
    ("fixture/empty", 0o100_644, 1, b""),
    ("fixture/noexec", 0o100_755, 1, b"not an executable\n"),
    ("fixture/sub", 0o040_755, 2, b""),
    ("fixture/sub/nested.txt", 0o100_644, 1, b"nested\n"),
    ("fixture/link", 0o120_777, 1, b"hello.txt"),
    ("proc", 0o040_755, 2, b""),
    ("mnt", 0o040_755, 10, b""),
    ("mnt/a", 0o040_755, 2, b""),
    ("mnt/b", 0o040_755, 2, b""),
    ("mnt/c", 0o040_755, 2, b""),
    ("mnt/d", 0o040_755, 2, b""),
    ("mnt/e", 0o040_755, 2, b""),
    ("mnt/f", 0o040_755, 2, b""),
    ("mnt/g", 0o040_755, 2, b""),
    ("mnt/h", 0o040_755, 2, b""),
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

// ---- the `dynelf` group's module ------------------------------------------------------------------

/// Where the host's programs and shared objects are read from (never committed): the `dynelf`
/// oracle group's inputs. `/usr/bin` and `/usr/lib` are the Arch/CachyOS locations; `/bin`, `/lib`
/// and `/lib64` are symlinks to them on the host and in the module.
pub(crate) const DYNAMIC_HOST_BIN: &str = "/usr/bin";
pub(crate) const DYNAMIC_HOST_LIB: &str = "/usr/lib";

/// The programs (of [`DYNAMIC_HOST_BIN`]) the group executes, directly or from `bash` scripts. Their
/// shared objects are found from `DT_NEEDED`, transitively, in [`DYNAMIC_HOST_LIB`].
pub(crate) const DYNAMIC_PROGRAMS: &[&str] = &[
    "base64",
    "basename",
    "bash",
    "cat",
    "chmod",
    "cmp",
    "comm",
    "cp",
    "cut",
    "date",
    "dd",
    "diff",
    "dirname",
    "du",
    "echo",
    "env",
    "expr",
    "factor",
    "false",
    "find",
    "fold",
    "gawk",
    "grep",
    "gzip",
    "head",
    "id",
    "ln",
    "ls",
    "mkdir",
    "mv",
    "nl",
    "nproc",
    "od",
    "paste",
    "printenv",
    "printf",
    "pwd",
    "readlink",
    "realpath",
    "rev",
    "rm",
    "sed",
    "seq",
    "sleep",
    "sort",
    "stat",
    "python3.14",
    "setsid",
    "stdbuf",
    "tac",
    "tail",
    "tar",
    "test",
    "true",
    "tty",
    "uname",
    "uniq",
    "wc",
    "whoami",
    "xargs",
    "xz",
    "yes",
];

/// Libraries that are loaded by name or by `LD_PRELOAD` rather than by `DT_NEEDED` (paths below
/// [`DYNAMIC_HOST_LIB`], stored under `usr/lib`).
pub(crate) const DYNAMIC_EXTRA_LIBS: &[&str] = &["coreutils/libstdbuf.so"];

/// The part of the Python 3.14 standard library the group's scripts import (paths below
/// `usr/lib/python3.14`, read from [`DYNAMIC_HOST_LIB`]`/python3.14`): the codec package every
/// start-up needs and what `re`, `json`, `collections`, `functools`, `struct`, `math` and
/// `binascii` pull in. Sources only (the group runs `python3 -B`).
pub(crate) const DYNAMIC_PYTHON_FILES: &[&str] = &[
    "os.py",
    "signal.py",
    "encodings/__init__.py",
    "encodings/aliases.py",
    "encodings/utf_8.py",
    "collections/__init__.py",
    "copyreg.py",
    "enum.py",
    "functools.py",
    "keyword.py",
    "linecache.py",
    "operator.py",
    "reprlib.py",
    "struct.py",
    "types.py",
    "json/__init__.py",
    "json/decoder.py",
    "json/encoder.py",
    "json/scanner.py",
    "re/__init__.py",
    "re/_casefix.py",
    "re/_compiler.py",
    "re/_constants.py",
    "re/_parser.py",
    "lib-dynload/_json.cpython-314-x86_64-linux-gnu.so",
    "lib-dynload/_struct.cpython-314-x86_64-linux-gnu.so",
    "lib-dynload/binascii.cpython-314-x86_64-linux-gnu.so",
    "lib-dynload/math.cpython-314-x86_64-linux-gnu.so",
];

/// The loader, which `PT_INTERP` names as `/lib64/ld-linux-x86-64.so.2`.
const DYNAMIC_LOADER: &str = "ld-linux-x86-64.so.2";

/// SHA-256 of every file of the module as the expected lines of the `dynelf` group were recorded
/// with on the pinned Linux (module path, digest). Another build of any of them may print other
/// lines (or lay out other mappings), so the group is `unavailable` on a host that differs.
pub(crate) const DYNAMIC_PINS: &[(&str, &str)] = &[
    (
        "usr/bin/base64",
        "5ed3f5be081c0c7f3823e8b23ba7f56c3096fdd1a8e948a9be2b1c8765b2185d",
    ),
    (
        "usr/bin/basename",
        "a0488c233f2cedba5dc2be2505dc731fa0448f1ef75297a938e7e831ced5cfe9",
    ),
    (
        "usr/bin/bash",
        "c157074818b094c84aaf31b8c80a1e149f234bb1c8c84a25e9a53e96afa30a29",
    ),
    (
        "usr/bin/cat",
        "364e0574030000b6d924441bef25e153a4aaa1ce07123d7fcaee8fa2e807ce40",
    ),
    (
        "usr/bin/chmod",
        "8b0e61201872bcc027da6c2090045efccfc3bbb6bb9b9cab65f911559bc09f15",
    ),
    (
        "usr/bin/cmp",
        "edcc51a8c7e7e85668f77f9a60b64ac9a771f20d0a2474348174c530ccf09abb",
    ),
    (
        "usr/bin/comm",
        "eb3fd0788950eaa495bf62db0221ec0df6e37d4d19da7b5557e6898aaabdbdfb",
    ),
    (
        "usr/bin/cp",
        "8ce26f08c86483fc25658a8bcb52a85f3dfe571ba17f2039d4ae84e80d8bcea7",
    ),
    (
        "usr/bin/cut",
        "66f0c15af9364cd62186aebaf1fb9dd5af66b3e2fae2db041ee1fbe4dffbcd7a",
    ),
    (
        "usr/bin/date",
        "1b99e1afca2642169fa0cf9a12eff6ea76b24adfa69c23be5bb843f320d77e33",
    ),
    (
        "usr/bin/dd",
        "97aec913820ba670e0d2e3f67431d518cb215c8cd509b3705022f769a008a9dd",
    ),
    (
        "usr/bin/diff",
        "6289e2e9460f0ad5b46ebe090baab2ea54a9681d7490cd57317f4ebdd4c9fc5d",
    ),
    (
        "usr/bin/dirname",
        "8db4d9adbb2b425c3ca1271e3d1f137a533c04a66ece898a804dbf759799c883",
    ),
    (
        "usr/bin/du",
        "1063eaadb0bc3bf662f0c1c8d8598330a9fbbd1cb91f3f784c832f626742c6bb",
    ),
    (
        "usr/bin/echo",
        "0d5dcb385d07ae3b4f9a0e464fe7c9c0427a1888b8931a798e920a5f55be37d2",
    ),
    (
        "usr/bin/env",
        "b91fd720ef6f3c0a69ad78d2ca446049d9a181900b0c0bad5aa0c6e11e18ef7f",
    ),
    (
        "usr/bin/expr",
        "f2574bba50552755ddbd13053f2468a9ea23a7fd7f53eb65057ab3aa5080644e",
    ),
    (
        "usr/bin/factor",
        "667d2ed6229e1bc38069c1b44da74ff6ff63de1626c0d0ad887e2ac9e4db64e6",
    ),
    (
        "usr/bin/false",
        "16ed3c6201c23f5f91bdfb589f2e9d6318d4984c0a423f8fdb5d2448486ed195",
    ),
    (
        "usr/bin/find",
        "dd7db3e8da1775fd4f196db8a9000d5d31c20bf82f105af567bea7c3db4303d6",
    ),
    (
        "usr/bin/fold",
        "04dac623d8a926f0a53f201ccb9542fddc341f4288fbaa64ed4cb2b95677ec4c",
    ),
    (
        "usr/bin/gawk",
        "19deee5f93180e2ffd1ee02c13d29391a2513499661234545c279fd14b360dfe",
    ),
    (
        "usr/bin/grep",
        "1f000906a29a17f35c3e3563f742533c7e917292c963ccd139d11a82b543c4ea",
    ),
    (
        "usr/bin/gzip",
        "cc5e7f5c9854ae45a566472d38f86ef816a559a637e6630e392e4885157f237b",
    ),
    (
        "usr/bin/head",
        "078201badeb023d15cf72db477a794d303132296b27860b55f85bf6f7e7a4133",
    ),
    (
        "usr/bin/id",
        "9597f365837e84e94d1c35e95fcc05b3db929c4995380c25fa6d4d5016a0e5cf",
    ),
    (
        "usr/bin/ln",
        "c4928c689e59d7186f957b47313ca1c7af2811552ba38fdcaa39681cd0bd3f48",
    ),
    (
        "usr/bin/ls",
        "aee98dea6ec77563422f024b81051cc75cd74ac0c4669478d1d922afe22905e0",
    ),
    (
        "usr/bin/mkdir",
        "32b4cd6a6de33a2d2b384c6fa98a2fffa436d20d2b89fd20c7d26a24f94339c2",
    ),
    (
        "usr/bin/mv",
        "bb1366f2f314679df9e1eb1ecbd74090386fbc089fc673c6c0eea0edcec41ad0",
    ),
    (
        "usr/bin/nl",
        "38530a6df1072309251b5be4983ca464e915c60dfa7a6b26f55f6121ea6182ff",
    ),
    (
        "usr/bin/nproc",
        "dc2f34148061c2194415a56fd837b321c506950e7ae3b168b58b5e617ac3b6c4",
    ),
    (
        "usr/bin/od",
        "8a138c3b5ae0d28e0e39815375f321c295b36d19b07a61d8d3ac0df9b4b37a50",
    ),
    (
        "usr/bin/paste",
        "80a46c0f72083918a21c46a4c6dce173c17c3076d68dea2d248cda506cbb28fa",
    ),
    (
        "usr/bin/printenv",
        "557f0347dffcce6f385d9370d78b63771541763101b4a56416c345e3185ae4cb",
    ),
    (
        "usr/bin/printf",
        "f946efc457b67ae1e9e251ad82d8cc7b3b1d28abfd65a0b110305899e9c3709e",
    ),
    (
        "usr/bin/pwd",
        "9fdb014786f7231e509108e9dfc213400de09a3de16ba9506f0d8d5582002ed4",
    ),
    (
        "usr/bin/python3.14",
        "7579d289e4d95778305acd13fc71be2a3800f7f6a202619505875234659c2c60",
    ),
    (
        "usr/bin/readlink",
        "6cc46db701fbec2b6a58268d654e46b6d117e62c72ac39255b75de0eeeaa14ac",
    ),
    (
        "usr/bin/realpath",
        "18ab75f37c2c9317e54fc30370ff0f22f4d40077b45043855e0eccd38ec1dbbf",
    ),
    (
        "usr/bin/rev",
        "093b67bef11b15dae4c94a1c7f1219001418ae82caae5ae342b3e8a9459bf0fa",
    ),
    (
        "usr/bin/rm",
        "011c2d0c1af901153e60667924c84ecdbb2052282b3e617aec9fc4b562325804",
    ),
    (
        "usr/bin/sed",
        "ab0baa3a8f4249be06868d410b494c801631a1cb859754769eee56b8824529e8",
    ),
    (
        "usr/bin/seq",
        "532ce877efdc430c0aa59c78e1ea3ba43c6bc53722f055b5c01f2c4686b892e9",
    ),
    (
        "usr/bin/setsid",
        "641d86a5f6e7e212592dec9354b0387dc8a7712582098af42bc99430f90a585f",
    ),
    (
        "usr/bin/sleep",
        "8f7b42375c8b53f47093509ac66b940698602e8e91d40534b1a7138e6265721a",
    ),
    (
        "usr/bin/sort",
        "9fac34d6007eb6f2ed5a40aaa362f570dc89eb6758ecfcb89dbffb6b43f6294b",
    ),
    (
        "usr/bin/stat",
        "2cca92992e6ef110ef1dde788b25995ee61ac107bd76fb02560f5a8ea85548e6",
    ),
    (
        "usr/bin/stdbuf",
        "4a75ec1dd046c447870cbb1f663f8a09a0c06e9855fd7cd924f2d92277119a78",
    ),
    (
        "usr/bin/tac",
        "499ec11588c2ec34ce698dfd02ec8bbbdb12f604f4c2c0cc2d34ab1b6271bb3f",
    ),
    (
        "usr/bin/tail",
        "78be062b99277693de93169118f4fe9c167c4be356109c6c8270ca6f2d169bb8",
    ),
    (
        "usr/bin/tar",
        "326bb5548b0a17ea3922a928634f141d0ac75d714edf08c096f0659bd90449f7",
    ),
    (
        "usr/bin/test",
        "666fd8f8ee66cfa880144e2e8881ad1d34773b673c3b43daff762a6c30c28cec",
    ),
    (
        "usr/bin/true",
        "1573301c316fd6297e2352441a9fb42eca9c32f97b3bb7ae1d45d3362811234d",
    ),
    (
        "usr/bin/tty",
        "3ba5753c0af8f1a2084e65927d4c9ec96e2e07bc8057288efd2101a9b12b0b89",
    ),
    (
        "usr/bin/uname",
        "69368312cf5e9db975a2c6ac55d7a372b0baac4f739f5e954a99c9d1bd6477a4",
    ),
    (
        "usr/bin/uniq",
        "5b1d69526ef4ae32e92d805f7dad50fcea9eda75662575cc3c1a333a9d3b967c",
    ),
    (
        "usr/bin/wc",
        "89b0a9b3ca913dbd7da9fd7bf01048478827087cf2f88192b1bb9bc215ee76f3",
    ),
    (
        "usr/bin/whoami",
        "c9169c71a2c9c1386368c363178383518a83269674fdde8d2d302f081090846f",
    ),
    (
        "usr/bin/xargs",
        "cc7e58da54ad0e016cb4c827cc071ebb656e9408584b1deddfbb6ffd8e56361a",
    ),
    (
        "usr/bin/xz",
        "4182bfda9f5658a1dba84788983df3c8a5dc80df971a8d1de7126523c95b4e6f",
    ),
    (
        "usr/bin/yes",
        "5c36362472df1383922c0d8cc466c495b370841d4be77c4c78d4764bdea72326",
    ),
    (
        "usr/lib/coreutils/libstdbuf.so",
        "777031fafe4156a6b1c898616b428a507218e64dc81d34fe7e9f188c2776c3d7",
    ),
    (
        "usr/lib/ld-linux-x86-64.so.2",
        "2db4c1e54273a52f75e7124fcfd6fe0d2d8bd7fc87f29780a75ab544b41bd53d",
    ),
    (
        "usr/lib/libacl.so.1",
        "0b79d488282c0687037344899b46370c9c448fcb03e87a2c1ba784a5fce4317f",
    ),
    (
        "usr/lib/libattr.so.1",
        "9b763be10a8adf9c40784ecc04419ffab4e8f944eefaf6043da685b8a44908b3",
    ),
    (
        "usr/lib/libc.so.6",
        "911cf3db7875760dc893b464ae89bddd4f697a377c710ffc13b84f67cbe1237b",
    ),
    (
        "usr/lib/libcap.so.2",
        "a765c823425ceab77e7c8e2b9e70b0b9dc7844d8cc85bc4a7507e609634ab914",
    ),
    (
        "usr/lib/libgmp.so.10",
        "69be619014fdf981ed7d0e1148a9c2082f42531ec8736f543b3c8928e11133cf",
    ),
    (
        "usr/lib/liblzma.so.5",
        "229f1b4044fb1c6a4ef9a1f95748d096536d5c3c7808a0266960c1fac0302d38",
    ),
    (
        "usr/lib/libm.so.6",
        "b42c5cc9e920e2df2038d06dce1124432e874fbe692c7275c866f9c19137b7a7",
    ),
    (
        "usr/lib/libmpfr.so.6",
        "b84ee11ae1836f14d2f6e04ce0d22d6315a6d90726d4e0a94cd6088bd258ae99",
    ),
    (
        "usr/lib/libncursesw.so.6",
        "0818af964c5e86421417a877e3b73266eb2dc5e0ce260f44962694c6f639fdc4",
    ),
    (
        "usr/lib/libpcre2-8.so.0",
        "ea5852c089f1978061189785e918881169d51180d8fdf8634ba9ea76a971585c",
    ),
    (
        "usr/lib/libpython3.14.so.1.0",
        "3af3675671f40e31c90a22e3ed159b5dfebd32d6719270c40c64bec7e096df3c",
    ),
    (
        "usr/lib/libreadline.so.8",
        "cf36d61484261364ef2d47ce4e6ecc6297f2fc20ba5ffc0c7358b4f5c2fc8393",
    ),
    (
        "usr/lib/libz.so.1",
        "2a252a45a28d93ca2e6a7d2662f6cef5cfa666c9da2f8cfbc90bc521c45a03c5",
    ),
    (
        "usr/lib/python3.14/collections/__init__.py",
        "cb8367b8edd188662143ea2e3942d360c2deae51c72fd779ec898f5076d2c2b9",
    ),
    (
        "usr/lib/python3.14/copyreg.py",
        "6376eb5722806396f5842997ac18add369ea9ac3ff4fcfe1460c41a088cac425",
    ),
    (
        "usr/lib/python3.14/encodings/__init__.py",
        "2b708410495acf12a6fad9d2de928dd89e567537c253eaa2b51aaae578e96c59",
    ),
    (
        "usr/lib/python3.14/encodings/aliases.py",
        "1ee993f8eb4986999b6501381e53947be9a04443626cb48b4190bcff2e87d3b4",
    ),
    (
        "usr/lib/python3.14/encodings/utf_8.py",
        "ba0cac060269583523ca9506473a755203037c57d466a11aa89a30a5f6756f3d",
    ),
    (
        "usr/lib/python3.14/enum.py",
        "fd23a7598fa1104ef892abcd4154d3627283e6361eb7a91cd11dc4a7b6fb3a93",
    ),
    (
        "usr/lib/python3.14/functools.py",
        "9db56d38172c4c9e689b21cc58c8538008b09d86b682faf4dd193b529cdd79d5",
    ),
    (
        "usr/lib/python3.14/json/__init__.py",
        "2dd10f1bf4c9ea5478e589216805e7f279d0e4bce134a19efa297404fb87407d",
    ),
    (
        "usr/lib/python3.14/json/decoder.py",
        "dc98d3e677612ea7311303f06a144cec6b91ebadc7ec037d1777501647578a07",
    ),
    (
        "usr/lib/python3.14/json/encoder.py",
        "d68a4d04d2cfd95897498307f29349058b42c3f48ea6aa6739714a09200a7d01",
    ),
    (
        "usr/lib/python3.14/json/scanner.py",
        "572958017eae8842eeddd0e3d18d3c56cc0a197348224915e1d87ce937841764",
    ),
    (
        "usr/lib/python3.14/keyword.py",
        "18c2be738c04ad20ad375f6a71db34b3823c7f40b0340f5294d0e89f3c9b093b",
    ),
    (
        "usr/lib/python3.14/lib-dynload/_json.cpython-314-x86_64-linux-gnu.so",
        "6ad48ca1bb469b15e32f95d88f2b48e999232a0671c87e8b26908cfaf6887584",
    ),
    (
        "usr/lib/python3.14/lib-dynload/_struct.cpython-314-x86_64-linux-gnu.so",
        "aaf38adce77a0fd69b300b2d8df664d7752bfeaf41ef90fb5ae09849c0c8f14e",
    ),
    (
        "usr/lib/python3.14/lib-dynload/binascii.cpython-314-x86_64-linux-gnu.so",
        "11e3ead57dba728f284668171194ef26f74397bc7d2734ba1f71eb78a9e3aec4",
    ),
    (
        "usr/lib/python3.14/lib-dynload/math.cpython-314-x86_64-linux-gnu.so",
        "e13cabcb991387d795f170476aacf25e07d689efb18ce677009b8cac45b4da4d",
    ),
    (
        "usr/lib/python3.14/linecache.py",
        "692daec68e2a419adf46bafc0eb2f8a2fb36c482183fa1ac47e00fec440f7d7e",
    ),
    (
        "usr/lib/python3.14/operator.py",
        "a9f9910965c31f841caad0447ee47299ac539a371422aefe200c86c60f3b4697",
    ),
    (
        "usr/lib/python3.14/os.py",
        "976bdb3e24925f2fb3ce43a4d788de6dcbb88a7cc8604c60ae690fbdd6507546",
    ),
    (
        "usr/lib/python3.14/re/__init__.py",
        "741a9de729ed8207bfa19db990f8826f1bf3661f33d0970a80c08cd1338ebc35",
    ),
    (
        "usr/lib/python3.14/re/_casefix.py",
        "1b12d9136f23db6c3f6f26053fefc15ca964b886838c7b9c1fabf8d2efc1e5c8",
    ),
    (
        "usr/lib/python3.14/re/_compiler.py",
        "d49f30cf9a1dbae33b200ed8befd9d0ce3ac612783a10ac35196536f98923e91",
    ),
    (
        "usr/lib/python3.14/re/_constants.py",
        "42253b3181b81aad6c46392f44a0ab26dcfa31feea411296f43ba16616a1ab0b",
    ),
    (
        "usr/lib/python3.14/re/_parser.py",
        "e57bd194a2d42398355ae7c1ccc2ddfb78421dd431eb81e3809dbe8ca9057dc4",
    ),
    (
        "usr/lib/python3.14/reprlib.py",
        "b04872e10d76252e44eae50cc785eb0fe478491afc4d7f0825a93f82b2eaba5f",
    ),
    (
        "usr/lib/python3.14/signal.py",
        "0363c964c90ac0b3e515de5749205e6e6454051a1211058375d84d91eab6071a",
    ),
    (
        "usr/lib/python3.14/struct.py",
        "50c14e55f94957804c1e45e975fedbe8e86f7e1dbb745b150370ff681155370a",
    ),
    (
        "usr/lib/python3.14/types.py",
        "8c54d3d5ffc1d1204237e6c69b25c27c7b05b483128f185eeed9ba7ef2229ac2",
    ),
];

/// One file of the module: its path in the archive (no leading slash), the bytes and where they
/// came from.
#[derive(Debug)]
pub(crate) struct DynamicFile {
    pub(crate) module_path: String,
    pub(crate) host_path: std::path::PathBuf,
    pub(crate) bytes: Vec<u8>,
}

/// `DT_NEEDED` names of a dynamically linked ELF64 file.
fn needed_libraries(bytes: &[u8]) -> Result<Vec<String>, String> {
    let file = ElfBytes::<LittleEndian>::minimal_parse(bytes).map_err(|e| e.to_string())?;
    let common = file.find_common_data().map_err(|e| e.to_string())?;
    let (Some(dynamic), Some(strings)) = (common.dynamic, common.dynsyms_strs) else {
        return Ok(Vec::new());
    };
    let mut names = Vec::new();
    for entry in dynamic.iter() {
        if entry.d_tag == abi::DT_NEEDED {
            let offset = usize::try_from(entry.d_val()).map_err(|e| e.to_string())?;
            names.push(strings.get(offset).map_err(|e| e.to_string())?.to_owned());
        }
    }
    Ok(names)
}

/// The files of the module, sorted by path: [`DYNAMIC_PROGRAMS`] under `usr/bin`, the loader and
/// the closure of their `DT_NEEDED` libraries under `usr/lib`. A library file is stored under its
/// soname (the host's `libc.so.6` is a name of the real file).
///
/// # Errors
/// A missing or unreadable program or library, or one that is not an ELF64 file.
pub(crate) fn dynamic_files(
    bin: &std::path::Path,
    lib: &std::path::Path,
) -> Result<Vec<DynamicFile>, String> {
    let read = |path: std::path::PathBuf| -> Result<(std::path::PathBuf, Vec<u8>), String> {
        let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        Ok((path, bytes))
    };
    let mut files: Vec<DynamicFile> = Vec::new();
    let mut pending: Vec<String> = vec![DYNAMIC_LOADER.to_owned()];
    for program in DYNAMIC_PROGRAMS {
        let (host_path, bytes) = read(bin.join(program))?;
        pending.extend(needed_libraries(&bytes).map_err(|e| format!("{program}: {e}"))?);
        files.push(DynamicFile {
            module_path: format!("usr/bin/{program}"),
            host_path,
            bytes,
        });
    }
    for relative in DYNAMIC_EXTRA_LIBS {
        let (host_path, bytes) = read(lib.join(relative))?;
        pending.extend(needed_libraries(&bytes).map_err(|e| format!("{relative}: {e}"))?);
        files.push(DynamicFile {
            module_path: format!("usr/lib/{relative}"),
            host_path,
            bytes,
        });
    }
    for relative in DYNAMIC_PYTHON_FILES {
        let (host_path, bytes) = read(lib.join("python3.14").join(relative))?;
        if std::path::Path::new(relative)
            .extension()
            .is_some_and(|ext| ext == "so")
        {
            pending.extend(needed_libraries(&bytes).map_err(|e| format!("{relative}: {e}"))?);
        }
        files.push(DynamicFile {
            module_path: format!("usr/lib/python3.14/{relative}"),
            host_path,
            bytes,
        });
    }
    while let Some(name) = pending.pop() {
        let module_path = format!("usr/lib/{name}");
        if files.iter().any(|f| f.module_path == module_path) {
            continue;
        }
        let (host_path, bytes) = read(lib.join(&name))?;
        pending.extend(needed_libraries(&bytes).map_err(|e| format!("{name}: {e}"))?);
        files.push(DynamicFile {
            module_path,
            host_path,
            bytes,
        });
    }
    files.sort_by(|a, b| a.module_path.cmp(&b.module_path));
    Ok(files)
}

/// Directories of the module: (name, mode), parents first. `bb` and below are the data files the
/// `busybox` group uses too; `proc` is the mount point the group makes itself.
const DYNAMIC_DIRS: &[(&str, u32)] = &[
    ("usr", 0o040_755),
    ("usr/bin", 0o040_755),
    ("usr/lib", 0o040_755),
    ("tmp", 0o041_777),
    ("bb", 0o040_755),
    ("bb/tree", 0o040_755),
    ("bb/tree/a", 0o040_755),
    ("bb/tree/a/b", 0o040_755),
];

/// [`DYNAMIC_DIRS`] and the directories the files need below `usr/lib/python3.14`, parents first.
fn dynamic_dirs(files: &[DynamicFile]) -> Vec<(String, u32)> {
    let mut dirs: Vec<(String, u32)> = DYNAMIC_DIRS
        .iter()
        .map(|&(name, mode)| (name.to_owned(), mode))
        .collect();
    let mut extra: Vec<String> = Vec::new();
    for file in files {
        let mut parent = file
            .module_path
            .rsplit_once('/')
            .map(|(dir, _)| dir.to_owned());
        while let Some(dir) = parent {
            if !dirs.iter().any(|d| d.0 == dir) && !extra.contains(&dir) {
                extra.push(dir.clone());
            }
            parent = dir.rsplit_once('/').map(|(up, _)| up.to_owned());
        }
    }
    extra.sort();
    dirs.extend(extra.into_iter().map(|dir| (dir, 0o040_755)));
    dirs
}

/// Symlinks of a merged-`/usr` root (name, target), as on the host.
const DYNAMIC_LINKS: &[(&str, &str)] = &[
    ("usr/bin/python3", "python3.14"),
    ("bin", "usr/bin"),
    ("lib", "usr/lib"),
    ("lib64", "usr/lib"),
    ("usr/lib64", "lib"),
    ("usr/bin/sh", "bash"),
];

/// The deterministic second initramfs module of the `dynelf` group: the files from
/// [`dynamic_files`] (`0755`), the merged-`/usr` links, `/tmp` and the data files of the `busybox`
/// group, all with the fixed mtime [`BUSYBOX_MTIME`]. Linux unpacks concatenated archives into one
/// rootfs, so the pinned reference gets `initramfs.cpio` + this one.
pub(crate) fn dynamic_initramfs(files: &[DynamicFile]) -> io::Result<Vec<u8>> {
    let bin_dat = busybox_bin_dat();
    let mut entries: Vec<(NewcBuilder, &[u8])> = Vec::new();
    let new = |name: &str, mode: u32| NewcBuilder::new(name).mode(mode).mtime(BUSYBOX_MTIME);
    let dirs = dynamic_dirs(files);
    for (name, mode) in &dirs {
        entries.push((new(name, *mode).nlink(2), &[]));
    }
    for file in files {
        if u32::try_from(file.bytes.len()).is_err() {
            return Err(invalid("a program does not fit a newc file size"));
        }
        entries.push((new(&file.module_path, 0o100_755), &file.bytes));
    }
    for &(name, target) in DYNAMIC_LINKS {
        entries.push((new(name, 0o120_777), target.as_bytes()));
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

/// The `CHECK image inspected` tail the kernel must print for [`dynamic_initramfs`]: every ELF
/// file is counted with its own `PT_LOAD` and `PT_INTERP` (an interpreter counts once per file).
pub(crate) fn dynamic_counts(archive_len: usize, files: &[DynamicFile]) -> io::Result<String> {
    let reserved = archive_len.next_multiple_of(PAGE).max(PAGE);
    let (mut loads, mut interpreters, mut elves) = (0u64, 0u64, 0u64);
    for file in files {
        // The kernel inspects the files that start with the ELF magic.
        if !file.bytes.starts_with(b"\x7fELF") {
            continue;
        }
        elves += 1;
        let elf = ElfBytes::<LittleEndian>::minimal_parse(&file.bytes)
            .map_err(|error| parse_error(&error))?;
        let mut interpreter = false;
        for program in elf.segments().into_iter().flatten() {
            match program.p_type {
                abi::PT_LOAD => loads += 1,
                abi::PT_INTERP => interpreter = true,
                _ => {}
            }
        }
        interpreters += u64::from(interpreter);
    }
    let regular = files.len() + BUSYBOX_FILES.len() + 1;
    let symlinks = DYNAMIC_LINKS.len() + BUSYBOX_LINKS.len();
    let entries = dynamic_dirs(files).len() + regular + symlinks;
    Ok(format!(
        "reserved={reserved} bytes={archive_len} records={} files={entries} regular={regular} symlinks={symlinks} trailers=1 skipped=0 elf={} loads={loads} interpreters={interpreters} execution=false rootfs=false",
        entries + 1,
        elves
    ))
}

/// The host files of the `dynelf` group or why this host cannot run the group: a file is
/// missing or not ELF, the CPU lacks the AVX-512 the x86-64-v4 builds need (`cpuinfo` is
/// `/proc/cpuinfo`), or a digest differs from the recorded one. `digests` maps each file (same
/// order as `files`) to its SHA-256.
pub(crate) fn dynamic_unavailable(
    cpuinfo: &str,
    files: &[DynamicFile],
    digests: &[String],
) -> Option<String> {
    if let Err(reason) = busybox_cpu(cpuinfo) {
        return Some(reason);
    }
    for (file, digest) in files.iter().zip(digests) {
        match DYNAMIC_PINS.iter().find(|pin| pin.0 == file.module_path) {
            None => {
                return Some(format!(
                    "{} is not among the recorded dynelf inputs",
                    file.module_path
                ));
            }
            Some(pin) if pin.1 != digest => {
                return Some(format!(
                    "{} is sha256 {digest}, not the {} the expected lines were recorded with",
                    file.host_path.display(),
                    pin.1
                ));
            }
            Some(_) => {}
        }
    }
    (files.len() != DYNAMIC_PINS.len()).then(|| {
        format!(
            "the module has {} files, {} were recorded",
            files.len(),
            DYNAMIC_PINS.len()
        )
    })
}

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
    /// The `CHECK image inspected` tail of `dynamic.cpio`, when the host provides it.
    pub(crate) dynamic_counts: Option<String>,
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
                ("proc", 0o040_755, 2, 0),
                ("mnt", 0o040_755, 10, 0),
                ("mnt/a", 0o040_755, 2, 0),
                ("mnt/b", 0o040_755, 2, 0),
                ("mnt/c", 0o040_755, 2, 0),
                ("mnt/d", 0o040_755, 2, 0),
                ("mnt/e", 0o040_755, 2, 0),
                ("mnt/f", 0o040_755, 2, 0),
                ("mnt/g", 0o040_755, 2, 0),
                ("mnt/h", 0o040_755, 2, 0),
                ("TRAILER!!!", 0, 1, 0)
            ]
        );
        assert_eq!(found[1].3, init);
        assert_eq!(found[2].3, b"/init");
        // Sequential inode numbers 0, 1, 2 (write_cpio); the trailer has ino 0, mode 0, nlink 1.
        let inodes = [0, 1, 2, 3, 20].map(|i| hex(&archive[entry_offset(&archive, i) + 6..][..8]));
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
        assert!(counts.starts_with("reserved=4096 bytes=4096 records=21 files=20 regular=5 symlinks=2 trailers=1 skipped=0 elf=1 loads=2 interpreters=0 "));
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
