// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: init/initramfs.c (`do_name`,
// `clean_path`, `maybe_link`, `unpack_to_rootfs`), init/main.c
// (`kernel_init_freeable`, `run_init_process`), fs/exec.c (`do_open_execat`),
// fs/namei.c (`do_last`/`open_last_lookups`: `-EISDIR` for a trailing slash).
// All GPL-2.0 / GPL-2.0-only.
// Transformation: the rootfs is not materialised; only the final state of one
// path is tracked while the archives are walked in order.
#![forbid(unsafe_code)]
//! Locate a path (normally `/init`) the way a sequence of initramfs archives
//! would leave it.
//!
//! All boot modules unpack in order into one rootfs. A later regular entry for
//! the same path replaces an earlier one completely: `do_name` opens every
//! non-hard-linked regular file `O_WRONLY|O_CREAT|O_TRUNC` (initramfs.c:383-384),
//! so even an empty body leaves an empty file. An archive that fails to parse
//! is skipped as a whole (the boot log already says so), including entries that
//! came before the damaged one; see the shortcut below.
//!
//! shortcut: a damaged archive is skipped whole, whereas Linux's unpacker keeps
//! the entries it processed before the error (so Linux may still find a `/init`
//! this code never sees). shortcut: names with `..` components are ignored
//! (Linux resolves them, which needs directory tracking), and a hard-linked
//! (`nlink >= 2`) target is rejected instead of tracking link groups. Upgrade
//! with a real rootfs.

use crate::image::{
    self,
    cpio::{Archive, Disposition, FileType},
};

/// Final state of the searched path after the last archive.
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
    /// The path is a hard link; link groups are not tracked.
    HardLink,
}

/// Does `name` (up to its first NUL, as Linux treats it) denote the absolute
/// `path`? `None` when it contains `..` and so cannot be decided without a tree.
fn names_path(name: &[u8], path: &[u8]) -> Option<bool> {
    if name.split(|&byte| byte == b'/').any(|part| part == b"..") {
        return None;
    }
    let parts = |text| {
        <[u8]>::split(text, |&byte| byte == b'/').filter(|part| !part.is_empty() && *part != b".")
    };
    Some(parts(name).eq(parts(path)))
}

/// `open(O_CREAT)` fails with `-EISDIR` when the last component is empty
/// (trailing slash) or `.`; no regular file is ever created under such a name.
fn can_create_regular(name: &[u8]) -> bool {
    name.rsplit(|&byte| byte == b'/')
        .next()
        .is_some_and(|last| !last.is_empty() && last != b".")
}

#[derive(Debug)]
pub struct Search<'p> {
    path: &'p [u8],
    entry: Option<InitEntry>,
}

impl<'p> Search<'p> {
    /// Search for the absolute `path`, e.g. `b"/init"`.
    #[must_use]
    pub const fn new(path: &'p [u8]) -> Self {
        Self { path, entry: None }
    }

    /// Fold one module into the search. On `Ok(false)` the module could not be
    /// inspected (it is skipped and changes nothing).
    ///
    /// # Errors
    /// [`FindError::HardLink`] for a hard-linked entry of the path.
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
            if names_path(name, self.path) != Some(true) {
                continue;
            }
            let kind = record.metadata.file_type();
            if kind == FileType::Regular && !can_create_regular(name) {
                continue;
            }
            if record.hardlink_key().is_some() {
                return Err(FindError::HardLink);
            }
            entry = Some(InitEntry {
                module,
                offset: record.data.as_ptr().addr() - bytes.as_ptr().addr(),
                length: record.data.len(),
                mode: record.metadata.mode,
                kind,
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
