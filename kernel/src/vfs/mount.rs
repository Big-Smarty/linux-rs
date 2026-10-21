// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: fs/namespace.c (GPL-2.0: `struct
// mount`, `mnt_alloc_id`, `mnt_alloc_group_id`, `change_mnt_propagation`
// state, `MNT_*` flags), include/linux/mount.h, include/uapi/linux/mount.h
// (`MS_*`), include/linux/fs.h (`SB_*`, `MNT_FORCE`...), fs/super.c
// (`get_anon_bdev`: `unnamed_dev_ida`), fs/fs_context.c
// (`vfs_parse_monolithic_sep`, `vfs_parse_sb_flag`, the `common_*_sb_flag`
// tables), fs/fs_parser.c (`fs_param_is_u32`, `fs_param_is_string`,
// `fs_param_is_flag`), mm/shmem.c (`shmem_parse_one`, `shmem_next_opt`,
// `shmem_parse_monolithic`, `shmem_fs_parameters`, `memparse` use), lib/cmdline.c
// (`memparse`), lib/vsprintf.c (`simple_strtoull`), fs/proc/root.c
// (`proc_parse_param`, `proc_parse_hidepid_param`, `proc_parse_subset_param`,
// `proc_fs_parameters`). All GPL-2.0 / GPL-2.0-only.
// Copyright of the originals: Linus Torvalds, Al Viro, David Howells and the
// VFS authors.
// Transformation: one mount namespace (no propagation peers, no user
// namespaces, no idmaps); mounts are a creation-ordered vector (the
// `mnt_list` order `/proc/self/mountinfo` prints); the id allocators are
// lowest-free bitsets starting from the occupancy the reference
// configuration leaves after boot (mount ids 1..=16, anonymous devices
// 1..=15), which is observable through mountinfo and `st_dev`.
#![forbid(unsafe_code)]
//! The mount namespace: mount table, superblock table, id allocators and the
//! mount-option parsers of the filesystems this kernel implements.
//!
//! # Contract
//! * Context: task context under the `vfs` lock class; no sleeping, all
//!   allocation fallible.
//! * Ownership: [`Namespace`] owns every [`Mount`] and the generic part of
//!   every superblock ([`SbInfo`]); the tmpfs-specific part lives in
//!   [`super::tmpfs::TmpSb`] under the same [`super::SbId`].

use alloc::vec::Vec;
use core::cell::Cell;
use syscalls::Errno;

use super::{InodeId, KResult, SbId, try_copy, try_push};

// ---- mount(2) flags (include/uapi/linux/mount.h) ---------------------------------
pub const MS_RDONLY: u64 = 1;
pub const MS_NOSUID: u64 = 2;
pub const MS_NODEV: u64 = 4;
pub const MS_NOEXEC: u64 = 8;
pub const MS_SYNCHRONOUS: u64 = 16;
pub const MS_REMOUNT: u64 = 32;
pub const MS_MANDLOCK: u64 = 64;
pub const MS_DIRSYNC: u64 = 128;
pub const MS_NOSYMFOLLOW: u64 = 256;
pub const MS_NOATIME: u64 = 1024;
pub const MS_NODIRATIME: u64 = 2048;
pub const MS_BIND: u64 = 4096;
pub const MS_MOVE: u64 = 8192;
pub const MS_REC: u64 = 16384;
pub const MS_SILENT: u64 = 32768;
pub const MS_POSIXACL: u64 = 1 << 16;
pub const MS_UNBINDABLE: u64 = 1 << 17;
pub const MS_PRIVATE: u64 = 1 << 18;
pub const MS_SLAVE: u64 = 1 << 19;
pub const MS_SHARED: u64 = 1 << 20;
pub const MS_RELATIME: u64 = 1 << 21;
pub const MS_I_VERSION: u64 = 1 << 23;
pub const MS_STRICTATIME: u64 = 1 << 24;
pub const MS_LAZYTIME: u64 = 1 << 25;
/// `MS_NOUSER` is the C `int` `(1<<31)`: widened to `unsigned long` it
/// sign-extends, so a `flags & MS_NOUSER` test covers bits 31..63.
pub const MS_NOUSER: u64 = 0xffff_ffff_8000_0000;
pub const MS_MGC_VAL: u64 = 0xC0ED_0000;
pub const MS_MGC_MSK: u64 = 0xffff_0000;
/// `MS_RMT_MASK`: the superblock flags a remount may alter.
pub const MS_RMT_MASK: u64 = MS_RDONLY | MS_SYNCHRONOUS | MS_MANDLOCK | MS_I_VERSION | MS_LAZYTIME;

// ---- superblock flags (include/linux/fs.h `SB_*`; the low ones equal `MS_*`) ----------
pub const SB_RDONLY: u32 = 1;
pub const SB_NOSUID: u32 = 2;
pub const SB_NOEXEC: u32 = 8;
pub const SB_SYNCHRONOUS: u32 = 16;
pub const SB_MANDLOCK: u32 = 64;
pub const SB_DIRSYNC: u32 = 128;
pub const SB_NODIRATIME: u32 = 2048;
pub const SB_SILENT: u32 = 1 << 15;
pub const SB_POSIXACL: u32 = 1 << 16;
pub const SB_I_VERSION: u32 = 1 << 23;
pub const SB_LAZYTIME: u32 = 1 << 25;

// ---- per-mount flags (include/linux/mount.h) -------------------------------------
pub const MNT_NOSUID: u32 = 0x01;
pub const MNT_NODEV: u32 = 0x02;
pub const MNT_NOEXEC: u32 = 0x04;
pub const MNT_NOATIME: u32 = 0x08;
pub const MNT_NODIRATIME: u32 = 0x10;
pub const MNT_RELATIME: u32 = 0x20;
pub const MNT_READONLY: u32 = 0x40;
pub const MNT_NOSYMFOLLOW: u32 = 0x80;
/// `MNT_USER_SETTABLE_MASK`.
pub const MNT_USER_SETTABLE_MASK: u32 = MNT_NOSUID
    | MNT_NODEV
    | MNT_NOEXEC
    | MNT_NOATIME
    | MNT_NODIRATIME
    | MNT_RELATIME
    | MNT_READONLY
    | MNT_NOSYMFOLLOW;
/// `MNT_ATIME_MASK`.
pub const MNT_ATIME_MASK: u32 = MNT_NOATIME | MNT_NODIRATIME | MNT_RELATIME;

// ---- umount2(2) flags (include/linux/fs.h) ----------------------------------------
pub const MNT_FORCE: u32 = 1;
pub const MNT_DETACH: u32 = 2;
pub const MNT_EXPIRE: u32 = 4;
pub const UMOUNT_NOFOLLOW: u32 = 8;

/// The mount ids the reference configuration's boot leaves allocated:
/// `rootfs` is 1 and the kernel-internal mounts (sockfs, pipefs, devtmpfs,
/// sysfs, ...) hold 2..=16, so the first mount a program makes is 17. Observed
/// in `target/linux-reference/init-reference-016` (`/proc/self/mountinfo`).
pub const BOOT_MNT_IDS: u32 = 16;
/// The anonymous device minors taken at boot (`unnamed_dev_ida`): the rootfs is
/// `0:2` and the first program-made superblock `0:16`.
pub const BOOT_ANON_DEVS: u32 = 15;
/// `shmem`/`rootfs` device number of the rootfs superblock.
pub const ROOTFS_DEV: u32 = 2;

/// A set of small positive integers with Linux's `ida_alloc_min`: the lowest
/// free id at or above a minimum. Growth is fallible.
#[derive(Default)]
pub struct IdSet {
    words: Vec<u64>,
}

impl IdSet {
    /// A set with ids `1..=n` taken.
    ///
    /// # Errors
    /// `ENOMEM`.
    pub fn with_taken(n: u32) -> KResult<Self> {
        let mut set = Self::default();
        for id in 1..=n {
            set.take(id)?;
        }
        Ok(set)
    }

    fn word(id: u32) -> (usize, u64) {
        ((id / 64) as usize, 1u64 << (id % 64))
    }

    /// Mark `id` taken.
    ///
    /// # Errors
    /// `ENOMEM`.
    pub fn take(&mut self, id: u32) -> KResult<()> {
        let (index, bit) = Self::word(id);
        while self.words.len() <= index {
            try_push(&mut self.words, 0)?;
        }
        self.words[index] |= bit;
        Ok(())
    }

    /// `ida_alloc_min(ida, min)`.
    ///
    /// # Errors
    /// `ENOMEM`.
    pub fn alloc_min(&mut self, min: u32) -> KResult<u32> {
        let mut id = min;
        loop {
            let (index, bit) = Self::word(id);
            if self.words.get(index).is_none_or(|word| word & bit == 0) {
                self.take(id)?;
                return Ok(id);
            }
            id += 1;
        }
    }

    /// `ida_free`.
    pub fn free(&mut self, id: u32) {
        let (index, bit) = Self::word(id);
        if let Some(word) = self.words.get_mut(index) {
            *word &= !bit;
        }
    }

    /// Whether `id` is taken.
    #[must_use]
    pub fn contains(&self, id: u32) -> bool {
        let (index, bit) = Self::word(id);
        self.words.get(index).is_some_and(|word| word & bit != 0)
    }
}

/// The filesystem types this kernel implements (`file_system_type`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsType {
    /// The rootfs (`rootfs_fs_type`: not mountable by name).
    Rootfs,
    Tmpfs,
    Proc,
}

impl FsType {
    /// `fs_type->name`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Rootfs => "rootfs",
            Self::Tmpfs => "tmpfs",
            Self::Proc => "proc",
        }
    }
}

/// What `get_fs_type` finds for a name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsLookup {
    /// Implemented here.
    Implemented(FsType),
    /// Registered in the reference configuration (`/proc/filesystems`), not
    /// implemented here. `bdev` types need a block device source
    /// (`get_tree_bdev`).
    Foreign { bdev: bool },
    /// Not registered: `ENODEV`.
    Unknown,
}

/// `get_fs_type(name)` against the registry of the reference configuration
/// (`target/linux-reference/init-reference-016`, `/proc/filesystems`).
#[must_use]
pub fn get_fs_type(name: &[u8]) -> FsLookup {
    match name {
        b"tmpfs" => FsLookup::Implemented(FsType::Tmpfs),
        b"proc" => FsLookup::Implemented(FsType::Proc),
        b"ext2" | b"ext3" | b"ext4" | b"vfat" | b"msdos" | b"iso9660" => {
            FsLookup::Foreign { bdev: true }
        }
        b"sysfs" | b"cgroup" | b"cgroup2" | b"devtmpfs" | b"binfmt_misc" | b"debugfs"
        | b"tracefs" | b"pipefs" | b"ramfs" | b"hugetlbfs" | b"devpts" | b"autofs"
        | b"efivarfs" => FsLookup::Foreign { bdev: false },
        _ => FsLookup::Unknown,
    }
}

/// The registered filesystems this kernel implements, in registration order
/// (`/proc/filesystems`): `(name, nodev)`.
pub const FILESYSTEMS: [(&str, bool); 2] = [("tmpfs", true), ("proc", true)];

// ---- option parsing -----------------------------------------------------------------

/// `simple_strtoull(s, &rest, base)`: the value and the unparsed tail (the
/// whole input when it starts with no digit; base 0 honours `0x` and `0`).
fn simple_strtoull(text: &[u8], base: u32) -> (u64, &[u8]) {
    let mut rest = text;
    let mut base = base;
    if base == 0 {
        if rest.first() == Some(&b'0') {
            if matches!(rest.get(1), Some(b'x' | b'X'))
                && rest.get(2).is_some_and(u8::is_ascii_hexdigit)
            {
                base = 16;
                rest = &rest[2..];
            } else {
                base = 8;
            }
        } else {
            base = 10;
        }
    } else if base == 16
        && rest.first() == Some(&b'0')
        && matches!(rest.get(1), Some(b'x' | b'X'))
        && rest.get(2).is_some_and(u8::is_ascii_hexdigit)
    {
        rest = &rest[2..];
    }
    let mut value = 0u64;
    while let Some(&byte) = rest.first() {
        let digit = match byte {
            b'0'..=b'9' => u32::from(byte - b'0'),
            b'a'..=b'f' => u32::from(byte - b'a') + 10,
            b'A'..=b'F' => u32::from(byte - b'A') + 10,
            _ => break,
        };
        if digit >= base {
            break;
        }
        value = value
            .wrapping_mul(u64::from(base))
            .wrapping_add(u64::from(digit));
        rest = &rest[1..];
    }
    (value, rest)
}

/// `memparse`: a number with an optional `K`/`M`/`G`/`T`/`P`/`E` suffix.
fn memparse(text: &[u8]) -> (u64, &[u8]) {
    let (mut value, rest) = simple_strtoull(text, 0);
    let shift = match rest.first() {
        Some(b'E' | b'e') => 60,
        Some(b'P' | b'p') => 50,
        Some(b'T' | b't') => 40,
        Some(b'G' | b'g') => 30,
        Some(b'M' | b'm') => 20,
        Some(b'K' | b'k') => 10,
        _ => return (value, rest),
    };
    value = value.wrapping_shl(shift);
    (value, &rest[1..])
}

/// `kstrtouint(s, base, &out)`: the whole string must be a number (one
/// trailing newline allowed, one leading `+` skipped, `-` refused), and fit 32 bits.
fn kstrtouint(text: &[u8], base: u32) -> Option<u32> {
    let text = text.strip_suffix(b"\n").unwrap_or(text);
    let text = text.strip_prefix(b"+").unwrap_or(text);
    if text.is_empty() || text[0] == b'-' || text[0] == b'+' {
        return None;
    }
    let (value, rest) = simple_strtoull(text, base);
    // `_kstrtoull`: a base prefix without a digit after it is an error.
    if !rest.is_empty() || (value == 0 && text.iter().all(|b| !b.is_ascii_hexdigit())) {
        return None;
    }
    u32::try_from(value).ok()
}

/// One `key[=value]` of a mount-data string.
#[derive(Clone, Copy)]
struct Param<'a> {
    key: &'a [u8],
    /// `None` is a flag (`fs_value_is_flag`); `Some("")` an empty string.
    value: Option<&'a [u8]>,
}

/// `vfs_parse_monolithic_sep` over `data` with either separator rule: calls
/// `each` for every non-empty key, skipping `=value` with no key. `tmpfs`
/// selects `shmem_next_opt` (a comma followed by a digit does not separate).
fn for_each_param<'a>(
    data: &'a [u8],
    tmpfs: bool,
    mut each: impl FnMut(Param<'a>) -> KResult<()>,
) -> KResult<()> {
    // The data is a C string: it ends at the first NUL.
    let data = data.split(|&b| b == 0).next().unwrap_or_default();
    let mut rest = Some(data);
    while let Some(text) = rest {
        let mut end = None;
        let mut from = 0;
        while let Some(at) = text[from..].iter().position(|&b| b == b',') {
            let comma = from + at;
            if tmpfs && text.get(comma + 1).is_some_and(u8::is_ascii_digit) {
                from = comma + 1;
                continue;
            }
            end = Some(comma);
            break;
        }
        let (option, tail) = match end {
            Some(comma) => (&text[..comma], Some(&text[comma + 1..])),
            None => (text, None),
        };
        rest = tail;
        if option.is_empty() {
            continue;
        }
        let param = match option.iter().position(|&b| b == b'=') {
            Some(0) => continue,
            Some(at) => Param {
                key: &option[..at],
                value: Some(&option[at + 1..]),
            },
            None => Param {
                key: option,
                value: None,
            },
        };
        each(param)?;
    }
    Ok(())
}

/// `vfs_parse_sb_flag`: the generic options every filesystem accepts.
/// Returns whether `key` was one.
fn parse_sb_flag(key: &[u8], set: &mut u32, mask: &mut u32) -> bool {
    let (flag, on) = match key {
        b"dirsync" => (SB_DIRSYNC, true),
        b"lazytime" => (SB_LAZYTIME, true),
        b"mand" => (SB_MANDLOCK, true),
        b"ro" => (SB_RDONLY, true),
        b"sync" => (SB_SYNCHRONOUS, true),
        b"async" => (SB_SYNCHRONOUS, false),
        b"nolazytime" => (SB_LAZYTIME, false),
        b"nomand" => (SB_MANDLOCK, false),
        b"rw" => (SB_RDONLY, false),
        _ => return false,
    };
    if on {
        *set |= flag;
    } else {
        *set &= !flag;
    }
    *mask |= flag;
    true
}

/// The parsed tmpfs options (`struct shmem_options`) and the generic
/// superblock flags the data string set.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TmpfsOpts {
    pub blocks: Option<u64>,
    pub inodes: Option<u64>,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub full_inums: Option<bool>,
    pub noswap: bool,
    /// `fc->sb_flags` bits set/cleared by `ro`, `sync`, ... and which of them.
    pub sb_flags: u32,
    pub sb_mask: u32,
}

/// The result of parsing mount data: options, or a Linux behaviour that is
/// not ported (`mpol=`).
pub enum Parsed<T> {
    Ok(T),
    Err(Errno),
    Unported,
}

/// A parameter that needs a non-empty value (`fs_param_is_string`).
fn string(value: Option<&[u8]>) -> KResult<&[u8]> {
    value.filter(|v| !v.is_empty()).ok_or(Errno::EINVAL)
}

/// `shmem_parse_monolithic` + `shmem_parse_one` over `data`, starting from the
/// superblock flags `sb_flags` of the request.
#[must_use]
pub fn parse_tmpfs(data: Option<&[u8]>, ram_pages: u64, sb_flags: u32) -> Parsed<TmpfsOpts> {
    let mut opts = TmpfsOpts {
        sb_flags,
        ..TmpfsOpts::default()
    };
    let Some(data) = data else {
        return Parsed::Ok(opts);
    };
    let mut unported = false;
    let result = for_each_param(data, true, |param| {
        if parse_sb_flag(param.key, &mut opts.sb_flags, &mut opts.sb_mask) {
            return Ok(());
        }
        match param.key {
            b"size" => {
                let (mut size, mut rest) = memparse(string(param.value)?);
                if rest.first() == Some(&b'%') {
                    size = (size << 12).wrapping_mul(ram_pages) / 100;
                    rest = &rest[1..];
                }
                if !rest.is_empty() {
                    return Err(Errno::EINVAL);
                }
                opts.blocks = Some(size.div_ceil(4096));
            }
            b"nr_blocks" => {
                let (blocks, rest) = memparse(string(param.value)?);
                if !rest.is_empty() || blocks > i64::MAX as u64 {
                    return Err(Errno::EINVAL);
                }
                opts.blocks = Some(blocks);
            }
            b"nr_inodes" => {
                let (inodes, rest) = memparse(string(param.value)?);
                // `ctx->inodes > ULONG_MAX / BOGO_INODE_SIZE` (1024).
                if !rest.is_empty() || inodes > u64::MAX / 1024 {
                    return Err(Errno::EINVAL);
                }
                opts.inodes = Some(inodes);
            }
            b"mode" => {
                let mode = kstrtouint(string(param.value)?, 8).ok_or(Errno::EINVAL)?;
                opts.mode = Some(mode & 0o7777);
            }
            // `fs_param_is_uid`/`gid`: `make_kuid`/`make_kgid` of (uid_t)-1 is
            // not `uid_valid`.
            b"uid" | b"gid" => {
                let id = kstrtouint(string(param.value)?, 0)
                    .filter(|&id| id != u32::MAX)
                    .ok_or(Errno::EINVAL)?;
                if param.key == b"uid" {
                    opts.uid = Some(id);
                } else {
                    opts.gid = Some(id);
                }
            }
            b"huge" => {
                // CONFIG_TRANSPARENT_HUGEPAGE=n: only `never` is accepted.
                let value = string(param.value)?;
                if !matches!(
                    value,
                    b"never" | b"always" | b"within_size" | b"advise" | b"deny" | b"force"
                ) || value != b"never"
                {
                    return Err(Errno::EINVAL);
                }
            }
            b"mpol" => {
                string(param.value)?;
                unported = true;
            }
            b"inode32" | b"inode64" | b"noswap" => {
                if param.value.is_some() {
                    return Err(Errno::EINVAL);
                }
                match param.key {
                    b"inode32" => opts.full_inums = Some(false),
                    b"inode64" => opts.full_inums = Some(true),
                    _ => opts.noswap = true,
                }
            }
            // Unknown, or an option of a configuration this kernel does not
            // declare (quota, casefold): `Unknown parameter`/`not built`.
            _ => return Err(Errno::EINVAL),
        }
        Ok(())
    });
    match result {
        Err(errno) => Parsed::Err(errno),
        Ok(()) if unported => Parsed::Unported,
        Ok(()) => Parsed::Ok(opts),
    }
}

/// `enum proc_hidepid`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HidePid {
    Off = 0,
    NoAccess = 1,
    Invisible = 2,
    NotPtraceable = 4,
}

impl HidePid {
    /// `hidepid2str`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::NoAccess => "noaccess",
            Self::Invisible => "invisible",
            Self::NotPtraceable => "ptraceable",
        }
    }
}

/// `struct proc_fs_info` as the mount options set it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcOpts {
    /// `pid_gid`.
    pub gid: u32,
    pub hide_pid: HidePid,
    /// `PROC_PIDONLY_ON` (`subset=pid`).
    pub pidonly: bool,
}

impl ProcOpts {
    pub const DEFAULT: Self = Self {
        gid: 0,
        hide_pid: HidePid::Off,
        pidonly: false,
    };
}

/// The parsed procfs options: what was set (a remount keeps the rest), the
/// generic superblock flags, and a `pidns=` path to open (checked by the
/// caller, which owns the path walk).
#[derive(Clone, Copy, Debug, Default)]
pub struct ProcOptSet<'a> {
    pub gid: Option<u32>,
    pub hide_pid: Option<HidePid>,
    pub pidonly: Option<bool>,
    pub pidns: Option<&'a [u8]>,
    pub sb_flags: u32,
    pub sb_mask: u32,
}

/// `proc_parse_param` over `data`.
///
/// # Errors
/// `EINVAL` for an unknown key, a missing or bad value, `hidepid` and
/// `subset` values Linux rejects.
pub fn parse_proc(data: Option<&[u8]>, sb_flags: u32) -> KResult<ProcOptSet<'_>> {
    let mut set = ProcOptSet {
        sb_flags,
        ..ProcOptSet::default()
    };
    let Some(data) = data else {
        return Ok(set);
    };
    let data = data.split(|&b| b == 0).next().unwrap_or_default();
    let mut flags = (set.sb_flags, set.sb_mask);
    let mut gid = None;
    let mut hide = None;
    let mut pidonly = None;
    let mut pidns = None;
    for_each_param(data, false, |param| {
        if parse_sb_flag(param.key, &mut flags.0, &mut flags.1) {
            return Ok(());
        }
        let value = param.value;
        match param.key {
            b"gid" => {
                gid = Some(
                    kstrtouint(value.filter(|v| !v.is_empty()).ok_or(Errno::EINVAL)?, 0)
                        .ok_or(Errno::EINVAL)?,
                );
            }
            b"hidepid" => {
                let text = string(value)?;
                hide = Some(match kstrtouint(text, 0) {
                    Some(0) => HidePid::Off,
                    Some(1) => HidePid::NoAccess,
                    Some(2) => HidePid::Invisible,
                    Some(4) => HidePid::NotPtraceable,
                    Some(_) => return Err(Errno::EINVAL),
                    None => match text {
                        b"off" => HidePid::Off,
                        b"noaccess" => HidePid::NoAccess,
                        b"invisible" => HidePid::Invisible,
                        b"ptraceable" => HidePid::NotPtraceable,
                        _ => return Err(Errno::EINVAL),
                    },
                });
            }
            b"subset" => {
                // `fsparam_string` without `fs_param_can_be_empty`: `subset=`
                // is `fs_param_is_string`'s bad value.
                let list = string(value)?;
                for item in list.split(|&b| b == b',') {
                    if item.is_empty() {
                        continue;
                    }
                    if item != b"pid" {
                        return Err(Errno::EINVAL);
                    }
                    pidonly = Some(true);
                }
            }
            b"pidns" => pidns = Some(value.filter(|v| !v.is_empty()).ok_or(Errno::EINVAL)?),
            _ => return Err(Errno::EINVAL),
        }
        Ok(())
    })?;
    set.sb_flags = flags.0;
    set.sb_mask = flags.1;
    set.gid = gid;
    set.hide_pid = hide;
    set.pidonly = pidonly;
    set.pidns = pidns;
    Ok(set)
}

// ---- the table ------------------------------------------------------------------------

/// The propagation state of a mount (`mnt_t_flags`, `mnt_group_id`): with one
/// namespace and no bind mounts a mount has no peers or masters, so a mount
/// is shared (with its own group id), or not, and possibly unbindable.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Propagation {
    /// `IS_MNT_SHARED`: the group id (`mnt_group_id`).
    pub shared: Option<u32>,
    /// `T_UNBINDABLE`.
    pub unbindable: bool,
}

/// `struct mount`.
pub struct Mount {
    /// `mnt_id`.
    pub id: u32,
    /// `mnt_parent->mnt_id` (the root mount is its own parent).
    pub parent: u32,
    /// `mnt_mountpoint`: where in the parent mount this one is attached (the
    /// root mount's is its own root).
    pub point: InodeId,
    /// `mnt.mnt_root`.
    pub root: InodeId,
    /// `mnt.mnt_sb`.
    pub sb: SbId,
    /// `mnt.mnt_flags`.
    pub flags: u32,
    /// `mnt_devname` (`none` when the mount names no source).
    pub devname: Vec<u8>,
    pub prop: Propagation,
    /// `mnt_expiry_mark`.
    pub expiry_mark: bool,
}

/// The generic part of a superblock (`struct super_block`).
pub struct SbInfo {
    pub fstype: FsType,
    /// `s_dev` minor (major 0).
    pub dev: u32,
    /// `s_flags` the mount options set (`SB_*`).
    pub flags: u32,
    /// `proc_fs_info` of a procfs superblock.
    pub proc: ProcOpts,
    /// Pins on the superblock's nodes other than a mount (open files, working
    /// directories) for a superblock whose nodes are not in the tmpfs arena.
    pub pins: u64,
    /// `fs_info->pid_ns`... one namespace: nothing to store.
    pub detached: bool,
}

/// A superblock whose mount is gone but whose resources are still held
/// (`MNT_DETACH`): the ids return with the last pin.
pub struct Zombie {
    pub sb: SbId,
    pub mnt_id: u32,
}

/// The mount namespace.
pub struct Namespace {
    pub mounts: Vec<Mount>,
    sbs: Vec<Option<SbInfo>>,
    mnt_ids: IdSet,
    devs: IdSet,
    groups: IdSet,
    zombies: Vec<Zombie>,
    /// `totalram_pages()`, for `shmem_default_max_blocks`/`inodes` (tmpfs
    /// options display and `size=NN%`).
    pub ram_pages: u64,
    /// A Linux behaviour was hit that is not ported: the syscall layer ends
    /// the call with `Outcome::Unimplemented` (a loud stop).
    loud: Cell<bool>,
    /// The procfs state (pids visible to lookups).
    pub proc: crate::procfs::ProcState,
    /// `mnt_namespace.event`: counts the changes of the mount table and of mount flags.
    pub event: u64,
    /// The `event` the `poll` sleepers were last woken for.
    event_seen: u64,
}

impl Namespace {
    /// The namespace `init_mount_tree` builds: the rootfs mount (id 1) on
    /// superblock 0.
    ///
    /// # Errors
    /// `ENOMEM`.
    pub fn new(root: InodeId, ram_pages: u64) -> KResult<Self> {
        let mut ns = Self {
            mounts: Vec::new(),
            sbs: Vec::new(),
            mnt_ids: IdSet::with_taken(BOOT_MNT_IDS)?,
            devs: IdSet::with_taken(BOOT_ANON_DEVS)?,
            groups: IdSet::default(),
            zombies: Vec::new(),
            event: 0,
            event_seen: 0,
            ram_pages,
            loud: Cell::new(false),
            proc: crate::procfs::ProcState::default(),
        };
        ns.sbs.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
        try_push(
            &mut ns.sbs,
            Some(SbInfo {
                fstype: FsType::Rootfs,
                dev: ROOTFS_DEV,
                flags: 0,
                proc: ProcOpts::DEFAULT,
                pins: 0,
                detached: false,
            }),
        )?;
        try_push(
            &mut ns.mounts,
            Mount {
                id: 1,
                parent: 1,
                point: root,
                root,
                sb: 0,
                // `init_mount_tree` passes no flags: no MNT_RELATIME.
                flags: 0,
                devname: try_copy(b"rootfs")?,
                prop: Propagation::default(),
                expiry_mark: false,
            },
        )?;
        Ok(ns)
    }

    /// Whether any procfs superblock exists (mounted, or held by an open file
    /// or working directory): otherwise no pid mirror or task view can be read.
    #[must_use]
    pub fn has_proc(&self) -> bool {
        self.sbs
            .iter()
            .flatten()
            .any(|sb| sb.fstype == FsType::Proc)
    }

    /// Record that a not-yet-ported Linux behaviour was reached.
    pub fn note_unimplemented(&self) {
        self.loud.set(true);
    }

    /// Take the record of [`Namespace::note_unimplemented`].
    pub fn take_unimplemented(&self) -> bool {
        self.loud.replace(false)
    }

    /// `shmem_default_max_blocks`.
    #[must_use]
    pub fn default_max_blocks(&self) -> u64 {
        self.ram_pages / 2
    }

    /// `shmem_default_max_inodes`.
    #[must_use]
    pub fn default_max_inodes(&self) -> u64 {
        self.ram_pages / 2
    }

    /// The superblock info.
    ///
    /// # Panics
    /// On an id that names no superblock (a kernel bug).
    #[must_use]
    pub fn sb(&self, sb: SbId) -> &SbInfo {
        self.sbs
            .get(usize::from(sb))
            .and_then(Option::as_ref)
            .expect("stale superblock")
    }

    /// Mutable superblock info.
    ///
    /// # Panics
    /// As [`Namespace::sb`].
    pub fn sb_mut(&mut self, sb: SbId) -> &mut SbInfo {
        self.sbs
            .get_mut(usize::from(sb))
            .and_then(Option::as_mut)
            .expect("stale superblock")
    }

    /// Whether `sb` is a live superblock of the table.
    #[must_use]
    pub fn has_sb(&self, sb: SbId) -> bool {
        self.sbs.get(usize::from(sb)).is_some_and(Option::is_some)
    }

    /// A free superblock id and its anonymous device (`get_anon_bdev`).
    ///
    /// # Errors
    /// `ENOMEM`; `ENOSPC` when the 16-bit id space is full.
    pub fn new_sb(&mut self, info: impl FnOnce(u32) -> SbInfo) -> KResult<SbId> {
        let slot = if let Some(slot) = self.sbs.iter().position(Option::is_none) {
            slot
        } else {
            try_push(&mut self.sbs, None)?;
            self.sbs.len() - 1
        };
        let id = SbId::try_from(slot).map_err(|_| Errno::ENOSPC)?;
        let dev = self.devs.alloc_min(1)?;
        self.sbs[slot] = Some(info(dev));
        Ok(id)
    }

    /// Drop a superblock entry and return its device number.
    pub fn free_sb(&mut self, sb: SbId) {
        if let Some(entry) = self.sbs.get_mut(usize::from(sb))
            && let Some(info) = entry.take()
        {
            self.devs.free(info.dev);
        }
    }

    /// `mnt_alloc_id`.
    ///
    /// # Errors
    /// `ENOMEM`.
    pub fn alloc_mnt_id(&mut self) -> KResult<u32> {
        self.mnt_ids.alloc_min(1)
    }

    /// `mnt_free_id`.
    pub fn free_mnt_id(&mut self, id: u32) {
        self.mnt_ids.free(id);
    }

    /// `mnt_alloc_group_id`.
    ///
    /// # Errors
    /// `ENOMEM`.
    pub fn alloc_group_id(&mut self) -> KResult<u32> {
        self.groups.alloc_min(1)
    }

    /// `mnt_release_group_id`.
    pub fn free_group_id(&mut self, id: u32) {
        self.groups.free(id);
    }

    /// The mount with `id`.
    #[must_use]
    pub fn mount(&self, id: u32) -> Option<&Mount> {
        self.mounts.iter().find(|m| m.id == id)
    }

    /// Position of the mount of superblock `sb` (one mount per superblock).
    #[must_use]
    pub fn mount_of_sb(&self, sb: SbId) -> Option<&Mount> {
        self.mounts.iter().find(|m| m.sb == sb)
    }

    /// `lookup_mnt`: the mount attached at `point` of the mount `parent`, the
    /// newest if several are stacked there.
    #[must_use]
    pub fn child_at(&self, parent: u32, point: InodeId) -> Option<&Mount> {
        self.mounts
            .iter()
            .rev()
            .find(|m| m.parent == parent && m.id != parent && m.point == point)
    }

    /// Whether any mount is attached below `id` (`!list_empty(&mnt->mnt_mounts)`).
    #[must_use]
    pub fn has_children(&self, id: u32) -> bool {
        self.mounts.iter().any(|m| m.parent == id && m.id != id)
    }

    /// Whether some mount is attached at `point` in the mount `parent`
    /// (`d_mountpoint`).
    #[must_use]
    pub fn is_mountpoint(&self, point: InodeId) -> bool {
        self.mounts
            .iter()
            .any(|m| m.id != m.parent && m.point == point)
    }

    /// Add a mount (`attach_recursive_mnt`'s list insertion).
    ///
    /// # Errors
    /// `ENOMEM`.
    pub fn attach(&mut self, mount: Mount) -> KResult<()> {
        try_push(&mut self.mounts, mount)?;
        self.event += 1; // commit_tree: touch_mnt_namespace
        Ok(())
    }

    /// Whether the mount table changed since the last call (the sleepers of `poll` are woken).
    pub fn take_event(&mut self) -> bool {
        let changed = self.event != self.event_seen;
        self.event_seen = self.event;
        changed
    }

    /// Remove the mount `id` and every mount below it (`umount_tree`),
    /// returning them for the caller to release.
    ///
    /// # Errors
    /// `ENOMEM` when the result vector cannot be reserved; nothing removed.
    pub fn detach_tree(&mut self, id: u32) -> KResult<Vec<Mount>> {
        let mut doomed: Vec<u32> = Vec::new();
        try_push(&mut doomed, id)?;
        let mut at = 0;
        while at < doomed.len() {
            let parent = doomed[at];
            for child in self
                .mounts
                .iter()
                .filter(|m| m.parent == parent && m.id != parent)
            {
                try_push(&mut doomed, child.id)?;
            }
            at += 1;
        }
        let mut out: Vec<Mount> = Vec::new();
        out.try_reserve_exact(doomed.len())
            .map_err(|_| Errno::ENOMEM)?;
        let mut index = 0;
        while index < self.mounts.len() {
            if doomed.contains(&self.mounts[index].id) {
                let mount = self.mounts.remove(index);
                let _ = out.push_within_capacity(mount);
            } else {
                index += 1;
            }
        }
        self.event += 1; // umount_tree: __touch_mnt_namespace
        Ok(out)
    }

    /// Park a detached mount's ids until its superblock dies.
    ///
    /// # Errors
    /// `ENOMEM`.
    pub fn defer_release(&mut self, sb: SbId, mnt_id: u32) -> KResult<()> {
        try_push(&mut self.zombies, Zombie { sb, mnt_id })
    }

    /// Release the ids of every parked mount whose superblock is dead
    /// (`tmpfs_dead(sb)` for a tmpfs-kind superblock; a procfs one is dead when
    /// it has no pins).
    pub fn reap(&mut self, tmpfs_dead: impl Fn(SbId) -> bool) {
        let mut index = 0;
        while index < self.zombies.len() {
            let sb = self.zombies[index].sb;
            let dead = match self.sbs.get(usize::from(sb)).and_then(Option::as_ref) {
                None => true,
                Some(info) if info.fstype == FsType::Proc => info.pins == 0,
                Some(_) => tmpfs_dead(sb),
            };
            if dead {
                let zombie = self.zombies.remove(index);
                self.mnt_ids.free(zombie.mnt_id);
                self.free_sb(sb);
            } else {
                index += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_sets_reuse_the_lowest_free_id() {
        let mut ids = IdSet::with_taken(16).unwrap();
        assert_eq!(ids.alloc_min(1).unwrap(), 17);
        assert_eq!(ids.alloc_min(1).unwrap(), 18);
        assert_eq!(ids.alloc_min(1).unwrap(), 19);
        ids.free(17);
        ids.free(19);
        assert_eq!(ids.alloc_min(1).unwrap(), 17);
        assert_eq!(ids.alloc_min(1).unwrap(), 19);
        assert_eq!(ids.alloc_min(1).unwrap(), 20);
        assert!(ids.contains(20) && !ids.contains(64));
        // The id space crosses a word.
        let mut many = IdSet::default();
        for expected in 1..=130 {
            assert_eq!(many.alloc_min(1).unwrap(), expected);
        }
    }

    #[test]
    fn memparse_and_strtoull_follow_the_kernel() {
        assert_eq!(memparse(b"1m"), (1 << 20, &b""[..]));
        assert_eq!(memparse(b"64k,x"), (64 << 10, &b",x"[..]));
        assert_eq!(memparse(b"0x10"), (16, &b""[..]));
        assert_eq!(memparse(b"010"), (8, &b""[..]));
        assert_eq!(memparse(b"zz"), (0, &b"zz"[..]));
        assert_eq!(memparse(b"2G"), (2 << 30, &b""[..]));
        assert_eq!(kstrtouint(b"0700", 8), Some(0o700));
        assert_eq!(kstrtouint(b"999", 8), None);
        assert_eq!(kstrtouint(b"4294967296", 0), None);
        assert_eq!(kstrtouint(b"", 0), None);
        assert_eq!(kstrtouint(b"-1", 0), None);
        assert_eq!(kstrtouint(b"7\n", 0), Some(7));
    }

    fn tmpfs(data: &[u8]) -> Result<TmpfsOpts, Errno> {
        match parse_tmpfs(Some(data), 1000, 0) {
            Parsed::Ok(opts) => Ok(opts),
            Parsed::Err(errno) => Err(errno),
            Parsed::Unported => panic!("unported"),
        }
    }

    #[test]
    fn tmpfs_options_parse_like_shmem_parse_one() {
        let o = tmpfs(b"size=1m,mode=0700,nr_inodes=100,uid=5,gid=6").unwrap();
        assert_eq!(
            (o.blocks, o.mode, o.inodes, o.uid, o.gid),
            (Some(256), Some(0o700), Some(100), Some(5), Some(6))
        );
        // size=NN% is a percentage of RAM.
        assert_eq!(tmpfs(b"size=50%").unwrap().blocks, Some(500));
        assert_eq!(tmpfs(b"bogus=1"), Err(Errno::EINVAL));
        assert_eq!(tmpfs(b"mode=999"), Err(Errno::EINVAL));
        assert_eq!(tmpfs(b"size=zz"), Err(Errno::EINVAL));
        assert_eq!(tmpfs(b"size"), Err(Errno::EINVAL));
        assert_eq!(tmpfs(b"size="), Err(Errno::EINVAL));
        assert_eq!(tmpfs(b"inode32=1"), Err(Errno::EINVAL));
        assert_eq!(tmpfs(b"huge=always"), Err(Errno::EINVAL));
        assert!(tmpfs(b"huge=never").is_ok());
        assert_eq!(tmpfs(b"quota"), Err(Errno::EINVAL));
        // Generic flags, empty items and `=x` are accepted/skipped; the value of
        // a generic flag is ignored.
        let o = tmpfs(b"ro,,=x,sync=9,nomand").unwrap();
        assert_eq!(o.sb_flags, SB_RDONLY | SB_SYNCHRONOUS);
        assert_eq!(o.sb_mask, SB_RDONLY | SB_SYNCHRONOUS | SB_MANDLOCK);
        // A comma before a digit continues the value (mpol node lists).
        assert!(matches!(
            parse_tmpfs(Some(b"mpol=interleave:0,1"), 1, 0),
            Parsed::Unported
        ));
        // ... so "size=4k,2" is one value with a junk tail.
        assert_eq!(tmpfs(b"size=4k,2"), Err(Errno::EINVAL));
    }

    #[test]
    fn proc_options_parse_like_proc_parse_param() {
        let o = parse_proc(Some(b"hidepid=2,gid=3,subset=pid"), 0).unwrap();
        assert_eq!(o.hide_pid, Some(HidePid::Invisible));
        assert_eq!((o.gid, o.pidonly), (Some(3), Some(true)));
        assert_eq!(
            parse_proc(Some(b"hidepid=ptraceable"), 0).unwrap().hide_pid,
            Some(HidePid::NotPtraceable)
        );
        assert_eq!(
            parse_proc(Some(b"hidepid=4"), 0).unwrap().hide_pid,
            Some(HidePid::NotPtraceable)
        );
        assert!(parse_proc(Some(b"hidepid=3"), 0).is_err());
        assert!(parse_proc(Some(b"hidepid=bogus"), 0).is_err());
        assert!(parse_proc(Some(b"subset=net"), 0).is_err());
        assert!(parse_proc(Some(b"bogus=1"), 0).is_err());
        assert!(parse_proc(Some(b"gid"), 0).is_err());
        assert!(parse_proc(Some(b"size=1"), 0).is_err());
        assert_eq!(parse_proc(Some(b"ro"), 0).unwrap().sb_flags, SB_RDONLY);
    }

    #[test]
    fn registry_distinguishes_ported_foreign_and_unknown() {
        assert_eq!(get_fs_type(b"tmpfs"), FsLookup::Implemented(FsType::Tmpfs));
        assert_eq!(get_fs_type(b"ext4"), FsLookup::Foreign { bdev: true });
        assert_eq!(get_fs_type(b"sysfs"), FsLookup::Foreign { bdev: false });
        assert_eq!(get_fs_type(b"rootfs"), FsLookup::Unknown);
        assert_eq!(get_fs_type(b"nosuchfs"), FsLookup::Unknown);
    }
}
