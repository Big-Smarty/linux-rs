// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: init/initramfs.c (`do_name`,
// `clean_path`, `maybe_link`, `unpack_to_rootfs`), init/main.c
// (`kernel_init_freeable`, `run_init_process`), fs/exec.c (`do_open_execat`).
// All GPL-2.0 / GPL-2.0-only.
// Transformation: the rootfs is not materialised; only the final state of the
// one path `/init` is tracked while the archives are walked in order.
#![forbid(unsafe_code)]
//! Locate `/init` the way a sequence of initramfs archives would leave it.
//!
//! All boot modules unpack in order into one rootfs. A later entry for the same
//! path replaces an earlier one; a regular file replaced by a regular file
//! keeps its old data when the new body is empty (`vfs_truncate` is skipped for
//! `body_len == 0` and `O_TRUNC` is not set). An archive that fails to parse is
//! skipped as a whole (the boot log already says so), including entries that
//! came before the damaged one: this project's earlier behaviour, stricter than
//! Linux's partial unpack.
//!
//! shortcut: names with `..` components are ignored (Linux resolves them, which
//! needs directory tracking), and a hard-linked (`nlink >= 2`) `/init` is
//! rejected instead of tracking link groups. Upgrade with a real rootfs.

use crate::image::{
    self,
    cpio::{Archive, Disposition, FileType},
};

/// Final state of `/init` after the last archive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitEntry {
    /// Boot module index holding the data.
    pub module: usize,
    /// Byte range of the file data inside that module.
    pub offset: usize,
    pub length: usize,
    pub mode: u32,
    pub kind: FileType,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindError {
    /// `/init` is a hard link; link groups are not tracked.
    HardLink,
}

/// Does `name` (up to its first NUL, as Linux treats it) denote `/init`?
/// `None` when it contains `..` and so cannot be decided without a tree.
fn is_init(name: &[u8]) -> Option<bool> {
    if name.split(|&byte| byte == b'/').any(|part| part == b"..") {
        return None;
    }
    let mut found = 0;
    for part in name.split(|&byte| byte == b'/') {
        match part {
            b"" | b"." => {}
            b"init" => {
                found += 1;
                if found > 1 {
                    return Some(false);
                }
            }
            _ => return Some(false),
        }
    }
    Some(found == 1)
}

#[derive(Debug, Default)]
pub struct InitSearch {
    entry: Option<InitEntry>,
}

impl InitSearch {
    #[must_use]
    pub const fn new() -> Self {
        Self { entry: None }
    }

    /// Fold one module into the search. On `Ok(false)` the module could not be
    /// inspected (it is skipped and changes nothing).
    ///
    /// # Errors
    /// [`FindError::HardLink`] for a hard-linked `/init` entry.
    pub fn scan(&mut self, module: usize, bytes: &[u8]) -> Result<bool, FindError> {
        if image::inspect_archive(bytes).is_err() {
            return Ok(false);
        }
        let mut archive = Archive::new(bytes);
        let mut entry = self.entry;
        // Inspected above: next_record cannot fail, and ends the same way.
        while let Ok(Some(record)) = archive.next_record() {
            match record.disposition {
                Disposition::Trailer | Disposition::Skipped(_) => continue,
                Disposition::File => {}
            }
            let Some(name) = record.name() else { continue };
            if is_init(name) != Some(true) {
                continue;
            }
            let kind = record.metadata.file_type();
            let current = InitEntry {
                module,
                offset: record.data.as_ptr().addr() - bytes.as_ptr().addr(),
                length: record.data.len(),
                mode: record.metadata.mode,
                kind,
            };
            if record.hardlink_key().is_some() {
                return Err(FindError::HardLink);
            }
            entry = Some(match entry {
                Some(old)
                    if kind == FileType::Regular
                        && old.kind == FileType::Regular
                        && current.length == 0 =>
                {
                    InitEntry {
                        mode: current.mode,
                        ..old
                    }
                }
                _ => current,
            });
        }
        self.entry = entry;
        Ok(true)
    }

    #[must_use]
    pub const fn entry(&self) -> Option<InitEntry> {
        self.entry
    }
}

#[cfg(test)]
mod tests;
