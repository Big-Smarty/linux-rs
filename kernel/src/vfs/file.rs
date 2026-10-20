// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: fs/file.c (GPL-2.0:
// `alloc_fd`/`__alloc_fd`, `expand_files`/`expand_fdtable` (`sysctl_nr_open`),
// `__put_unused_fd`, `file_close_fd_locked`, `do_dup2`, `find_next_fd`),
// fs/file_table.c (`alloc_empty_file`, reference counting), include/linux/fs.h
// (`struct file`, `FMODE_*`), fs/fs_struct.c (`struct fs_struct`).
// Transformation: `struct file` lives in an arena addressed by `FileId` with an
// explicit count instead of `atomic_long_t f_count`; the fdtable is a vector of
// optional handles with two bitmaps (`kernel::bitmap`), grown by powers of two.
#![forbid(unsafe_code)]
//! Open file descriptions, the per-process descriptor table and `fs_struct`.
//!
//! A [`File`] is shared by every descriptor that was `dup`ed from it (and by
//! forked children); [`FileTable::get`] adds a reference per descriptor and
//! [`FileTable::put`] reports the last drop, whose cleanup (releasing the
//! inode or pipe end) is [`super::Vfs::fput`]'s. Descriptor numbers are
//! allocated lowest-free-first from a `next_fd` hint exactly like `alloc_fd`.

use alloc::vec::Vec;
use syscalls::Errno;

use super::{FileId, InodeId, KResult, NR_OPEN, PipeId, try_push};
use crate::bitmap::{BITS_PER_WORD, Bitmap};

/// A character device the VFS can open (`chrdev_open` results).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CharDev {
    /// `/dev/console` (5:1) on the console tty.
    Console,
    /// 1:3, `null_fops`.
    Null,
    /// 1:5, `zero_fops`.
    Zero,
    /// 1:7, `full_fops`.
    Full,
}

/// What an open file is (the role of `file->f_op`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileKind {
    Regular,
    Directory,
    Char(CharDev),
    /// One end of a pipe; `writer` selects the write end.
    Pipe {
        pipe: PipeId,
        writer: bool,
    },
    /// `O_PATH`: only descriptor operations that `fget_raw` allows.
    Path,
    /// A device or FIFO that Linux opens but this kernel has no driver for yet.
    /// Every read, write or ioctl stops the kernel loudly.
    Unsupported,
}

pub struct File {
    /// The inode behind the file; `None` for pipes (their inode is the pipe).
    pub inode: Option<InodeId>,
    pub kind: FileKind,
    /// `f_flags`.
    pub flags: u32,
    /// `f_mode`.
    pub mode: u32,
    /// `f_pos`; the directory cookie for a directory.
    pub pos: i64,
    refs: u32,
}

impl File {
    #[must_use]
    pub fn new(inode: Option<InodeId>, kind: FileKind, flags: u32, mode: u32) -> Self {
        Self {
            inode,
            kind,
            flags,
            mode,
            pos: 0,
            refs: 1,
        }
    }
}

/// All open file descriptions of the system.
#[derive(Default)]
pub struct FileTable {
    files: Vec<Option<File>>,
    free: Vec<u32>,
}

impl FileTable {
    /// `alloc_empty_file`.
    ///
    /// # Errors
    /// `ENOMEM`.
    pub fn alloc(&mut self, file: File) -> KResult<FileId> {
        if let Some(slot) = self.free.pop() {
            self.files[slot as usize] = Some(file);
            return Ok(FileId(slot));
        }
        let slot = u32::try_from(self.files.len()).map_err(|_| Errno::ENFILE)?;
        self.files.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
        if self.files.push_within_capacity(Some(file)).is_err() {
            return Err(Errno::ENOMEM);
        }
        Ok(FileId(slot))
    }

    /// The file behind a handle held by a descriptor or an open call.
    ///
    /// # Panics
    /// On a stale handle (a kernel bug).
    #[must_use]
    pub fn get(&self, id: FileId) -> &File {
        self.files
            .get(id.0 as usize)
            .and_then(Option::as_ref)
            .expect("stale file handle")
    }

    /// Mutable access to the file behind a handle.
    ///
    /// # Panics
    /// On a stale handle (a kernel bug).
    pub fn get_mut(&mut self, id: FileId) -> &mut File {
        self.files
            .get_mut(id.0 as usize)
            .and_then(Option::as_mut)
            .expect("stale file handle")
    }

    /// `get_file`.
    pub fn dup(&mut self, id: FileId) {
        self.get_mut(id).refs += 1;
    }

    /// `fput`: drops a reference; the last one hands back the file for cleanup.
    pub fn put(&mut self, id: FileId) -> Option<File> {
        let file = self.get_mut(id);
        file.refs -= 1;
        if file.refs != 0 {
            return None;
        }
        let file = self.files[id.0 as usize].take();
        // Losing the free-list slot on ENOMEM only wastes an arena entry.
        let _ = try_push(&mut self.free, id.0);
        file
    }

    /// Descriptions in use (tests).
    #[must_use]
    pub fn open_count(&self) -> usize {
        self.files.iter().flatten().count()
    }

    /// The references held on all open descriptions together (descriptors,
    /// mappings, a running `read`): a leak check sees a description kept alive
    /// by one reference too many, which [`FileTable::open_count`] does not.
    #[must_use]
    pub fn total_refs(&self) -> u64 {
        self.files
            .iter()
            .flatten()
            .map(|file| u64::from(file.refs))
            .sum()
    }
}

/// `struct files_struct` (single-threaded sharing: one owner).
#[derive(Default)]
pub struct FdTable {
    fds: Vec<Option<FileId>>,
    open: Vec<usize>,
    cloexec: Vec<usize>,
    next_fd: u32,
}

/// A descriptor number as syscalls carry it (`unsigned int`).
pub type Fd = u32;

impl FdTable {
    /// `fdt->max_fds`.
    #[must_use]
    pub fn max_fds(&self) -> usize {
        self.fds.len()
    }

    /// `files_lookup_fd_locked`.
    #[must_use]
    pub fn get(&self, fd: Fd) -> Option<FileId> {
        self.fds.get(fd as usize).copied().flatten()
    }

    /// `get_close_on_exec`.
    #[must_use]
    pub fn cloexec(&self, fd: Fd) -> bool {
        self.cloexec_map()
            .and_then(|map| map.get(fd as usize))
            .unwrap_or(false)
    }

    fn cloexec_map(&self) -> Option<BitView<'_>> {
        (!self.fds.is_empty()).then(|| BitView {
            words: &self.cloexec,
            bits: self.fds.len(),
        })
    }

    /// `set_close_on_exec` / `__clear_close_on_exec` on an open descriptor.
    pub fn set_cloexec(&mut self, fd: Fd, on: bool) {
        let bits = self.fds.len();
        if let Some(mut map) = Bitmap::new(&mut self.cloexec, bits) {
            map.replace(fd as usize, on);
        }
    }

    /// `expand_files` for descriptor number `nr`: the table must hold index `nr`.
    ///
    /// # Errors
    /// `EMFILE` at or past `sysctl_nr_open`, `ENOMEM`.
    pub fn expand(&mut self, nr: u64) -> KResult<()> {
        if nr < self.fds.len() as u64 {
            return Ok(());
        }
        if nr >= NR_OPEN {
            return Err(Errno::EMFILE);
        }
        // `roundup_pow_of_two(nr + 1)`, at least NR_OPEN_DEFAULT (64).
        let size = usize::try_from(nr + 1)
            .map_err(|_| Errno::EMFILE)?
            .next_power_of_two()
            .max(BITS_PER_WORD);
        let words = size / BITS_PER_WORD;
        self.fds
            .try_reserve_exact(size - self.fds.len())
            .map_err(|_| Errno::ENOMEM)?;
        self.open
            .try_reserve_exact(words - self.open.len())
            .map_err(|_| Errno::ENOMEM)?;
        self.cloexec
            .try_reserve_exact(words - self.cloexec.len())
            .map_err(|_| Errno::ENOMEM)?;
        // Capacity is reserved: the pushes below cannot fail.
        while self.fds.len() < size {
            self.fds
                .push_within_capacity(None)
                .map_err(|_| Errno::ENOMEM)?;
        }
        while self.open.len() < words {
            self.open
                .push_within_capacity(0)
                .map_err(|_| Errno::ENOMEM)?;
            self.cloexec
                .push_within_capacity(0)
                .map_err(|_| Errno::ENOMEM)?;
        }
        Ok(())
    }

    /// `alloc_fd(start, end, flags)`: the lowest free descriptor `>= start`
    /// (and `>= next_fd`); it stays unpopulated until [`FdTable::install`].
    ///
    /// # Errors
    /// `EMFILE` when it would reach `end` (`RLIMIT_NOFILE`) or `NR_OPEN`.
    pub fn alloc_fd(&mut self, start: u32, end: u64, cloexec: bool) -> KResult<Fd> {
        let mut fd = start.max(self.next_fd);
        let bits = self.fds.len();
        if (fd as usize) < bits
            && let Some(map) = Bitmap::new(&mut self.open, bits)
        {
            fd = u32::try_from(map.find_next_zero_in(fd as usize, bits)).unwrap_or(u32::MAX);
        }
        if u64::from(fd) >= end {
            return Err(Errno::EMFILE);
        }
        self.expand(u64::from(fd))?;
        let bits = self.fds.len();
        if let Some(mut map) = Bitmap::new(&mut self.open, bits) {
            map.replace(fd as usize, true);
        }
        if let Some(mut map) = Bitmap::new(&mut self.cloexec, bits) {
            map.replace(fd as usize, cloexec);
        }
        if start <= self.next_fd {
            self.next_fd = fd + 1;
        }
        Ok(fd)
    }

    /// `fd_install`: populate a descriptor [`FdTable::alloc_fd`] reserved.
    pub fn install(&mut self, fd: Fd, file: FileId) {
        self.fds[fd as usize] = Some(file);
    }

    /// `put_unused_fd` / the bit clearing of `file_close_fd_locked`.
    fn release(&mut self, fd: Fd) {
        let bits = self.fds.len();
        if let Some(mut map) = Bitmap::new(&mut self.open, bits) {
            map.replace(fd as usize, false);
        }
        if let Some(mut map) = Bitmap::new(&mut self.cloexec, bits) {
            map.replace(fd as usize, false);
        }
        if fd < self.next_fd {
            self.next_fd = fd;
        }
    }

    /// `put_unused_fd`.
    pub fn put_unused(&mut self, fd: Fd) {
        self.release(fd);
    }

    /// `file_close_fd_locked`: empty the slot; the caller drops the file.
    pub fn close(&mut self, fd: Fd) -> Option<FileId> {
        let file = self.fds.get_mut(fd as usize)?.take()?;
        self.release(fd);
        Some(file)
    }

    /// `do_dup2`'s slot update: install `file` at `fd`, returning the file it
    /// replaced. `EBUSY` if the descriptor is reserved but not yet installed.
    ///
    /// # Errors
    /// `EBUSY`.
    pub fn replace(&mut self, fd: Fd, file: FileId, cloexec: bool) -> KResult<Option<FileId>> {
        let bits = self.fds.len();
        let reserved = Bitmap::new(&mut self.open, bits)
            .and_then(|map| map.get(fd as usize))
            .unwrap_or(false);
        let old = self.fds[fd as usize].replace(file);
        if old.is_none() && reserved {
            self.fds[fd as usize] = None;
            return Err(Errno::EBUSY);
        }
        if let Some(mut map) = Bitmap::new(&mut self.open, bits) {
            map.replace(fd as usize, true);
        }
        if let Some(mut map) = Bitmap::new(&mut self.cloexec, bits) {
            map.replace(fd as usize, cloexec);
        }
        Ok(old)
    }

    /// The descriptor table of a forked child (`dup_fd` without the `fget`
    /// per descriptor, which [`super::Vfs::dup_fd`] adds): the same
    /// descriptors and close-on-exec bits in a table sized for the highest
    /// open one (at least `NR_OPEN_DEFAULT`), `next_fd` 0 as `dup_fd` leaves
    /// it. Nothing is shared with `self`; on failure nothing was changed.
    ///
    /// # Errors
    /// `ENOMEM`.
    pub(super) fn duplicate(&self) -> KResult<Self> {
        let mut new = Self::default();
        let Some(highest) = self.fds.iter().rposition(Option::is_some) else {
            return Ok(new);
        };
        new.expand(highest as u64)?;
        let bits = new.fds.len();
        for (fd, file, cloexec) in self.iter() {
            new.fds[fd as usize] = Some(file);
            if let Some(mut map) = Bitmap::new(&mut new.open, bits) {
                map.replace(fd as usize, true);
            }
            if let Some(mut map) = Bitmap::new(&mut new.cloexec, bits) {
                map.replace(fd as usize, cloexec);
            }
        }
        Ok(new)
    }

    /// Every populated descriptor with its close-on-exec flag.
    pub fn iter(&self) -> impl Iterator<Item = (Fd, FileId, bool)> + '_ {
        (0..self.fds.len()).filter_map(move |fd| {
            let fd = u32::try_from(fd).ok()?;
            Some((fd, self.get(fd)?, self.cloexec(fd)))
        })
    }
}

/// Read-only bit access over a borrowed word slice.
struct BitView<'a> {
    words: &'a [usize],
    bits: usize,
}

impl BitView<'_> {
    fn get(&self, index: usize) -> Option<bool> {
        (index < self.bits)
            .then(|| self.words[index / BITS_PER_WORD] & (1 << (index % BITS_PER_WORD)) != 0)
    }
}

/// `struct fs_struct`: the root, the working directory and the umask.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FsStruct {
    pub root: InodeId,
    pub pwd: InodeId,
    /// `fs->umask` (init starts with 022).
    pub umask: u32,
}

impl FsStruct {
    /// `init_fs` before a rootfs exists: the root inode of every [`super::Tmpfs`]
    /// is arena slot 0 and the umask is `0022`. The references on root and cwd
    /// are taken by [`super::Vfs::new_fs_struct`], which the owner of the task
    /// calls once the rootfs exists and assigns over this value.
    pub const INIT: Self = Self {
        root: InodeId(0),
        pwd: InodeId(0),
        umask: 0o022,
    };
}
