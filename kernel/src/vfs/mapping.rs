// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: mm/mmap.c (`ksys_mmap_pgoff`'s
// `fget`, `file_mmap_size_max`, `do_mmap`'s file branch inputs), mm/shmem.c
// (`shmem_mmap`, `shmem_fault`, `shmem_get_folio_gfp`: a page whose first byte
// is at or past `i_size` is `-EINVAL`, hence `SIGBUS`), drivers/char/mem.c
// (`mmap_zero`, `zero_fops`; the other `*_fops` have no `->mmap`), fs/pipe.c
// (`pipefifo_fops`: no `->mmap`), fs/libfs.c (directory operations: no
// `->mmap`), fs/proc/inode.c (`proc_reg_mmap`, `proc_reg_file_ops`), mm/vma.c
// (`__mmap_setup`, `__mmap_new_file_vma`, `vms_abort_munmap_vmas`).
// GPL-2.0-only / GPL-2.0.
// Transformation: a mapping holds a reference on the open file description
// (`vma->vm_file`, kept in [`Vfs`]'s pin list and reconciled with the VMA set
// by the syscall layer); a file page is a private copy made at the first
// fault (no page cache, see the shortcut below), not a shared page-cache page.
#![forbid(unsafe_code)]
//! File-backed `mmap` support: what an open file offers `do_mmap`, the page
//! supplied for a private file fault, and the loud stop for the one situation
//! where the copy-at-fault model would differ from Linux.
//!
//! Context: task context, one task; nothing sleeps. Allocation is fallible:
//! the pin list is grown by [`Vfs::reserve_pin`] before the mapping is
//! committed, so [`Vfs::pin`] cannot fail afterwards.
//!
//! * shortcut: no page cache, so a `MAP_PRIVATE` file page is a private copy of
//!   the tmpfs page taken when it is first touched (what `do_cow_fault` would
//!   leave; a read fault maps the copy read-only as `do_read_fault` maps the
//!   page-cache page, so it counts as `RssShmem` and the first write copies it
//!   again, but where Linux maps the shared page and a later write to the file
//!   shows through until the first private write). A write or truncate of a file with a touched mapping therefore
//!   sets [`Vfs::take_coherence_loss`], which the dispatcher turns into a loud
//!   stop instead of letting the two diverge silently. A `MAP_SHARED` mapping
//!   is created only through a description that cannot write (`VM_SHARED` is
//!   then cleared, `VM_MAYWRITE` too, so it behaves as a private one); a
//!   writable one is not created (the syscall layer stops loudly), nor is any
//!   file mapping with `MAP_POPULATE`/`MAP_LOCKED` (`mm_populate` would take
//!   the copies at `mmap` time).
//!   Upgrade with the page cache (tmpfs pages as frames shared with the page
//!   tables).
//! * shortcut: a read fault on a hole or past nothing allocates no tmpfs page
//!   (`shmem_get_folio` would, and charge it): `st_blocks`/`used_blocks` do not
//!   change.

use super::{
    FdTable, FileId, KResult, MAX_LFS_FILESIZE, PAGE_SIZE, Vfs,
    file::{CharDev, FileKind},
};
use crate::{
    mm::FileInfo,
    procfs::{Kind, ProcNode},
    vfs::{FMODE_PATH, FMODE_READ, FMODE_WRITE},
};
use syscalls::Errno;

/// A reference on an open file description held by the mappings of one address
/// space (`vm_file`): `owner` names that address space (a forked child has its
/// own; there is one pin list for the system).
#[derive(Clone, Copy, Debug)]
pub struct Pin {
    pub file: FileId,
    pub owner: u32,
    /// A page was copied out of the file for this description's mappings.
    pub snapshot: bool,
}

/// What `fget(fd)` followed by `->mmap` offers `mmap(2)`.
#[derive(Clone, Copy, Debug)]
pub enum Mappable {
    /// A file `do_mmap` can check; `->mmap` is `shmem_mmap`, or absent
    /// (`can_mmap == false`: `-ENODEV`).
    File(FileInfo),
    /// `/dev/zero`: `->mmap` is `mmap_zero`; a private mapping is anonymous.
    Zero(FileInfo),
    /// A device Linux has a driver for that this kernel does not: its `->mmap`
    /// (and so the result) is unknown.
    Unported,
}

/// Why a page could not be supplied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileFault {
    /// `VM_FAULT_SIGBUS`: the page lies at or beyond `i_size`.
    Bus,
}

impl Vfs {
    /// `fget(fd)` and the facts `do_mmap` reads from it; `None` is `-EBADF`
    /// (closed, or an `O_PATH` descriptor, which `fget` refuses).
    #[must_use]
    pub fn mmap_info(&self, fdt: &FdTable, fd: u32) -> Option<Mappable> {
        let id = fdt.get(fd)?;
        let file = self.files.get(id);
        if file.mode & FMODE_PATH != 0 {
            return None;
        }
        let info = |can_mmap: bool, mmap_size_max: u64| FileInfo {
            // `vma->vm_file` identity: the open file description.
            id: u64::from(id.index()),
            readable: file.mode & FMODE_READ != 0,
            writable: file.mode & FMODE_WRITE != 0,
            // path_noexec: a `noexec` mount, or a procfs superblock (`SB_I_NOEXEC`).
            noexec: file.inode.is_some_and(|inode| self.fs.path_noexec(inode)),
            swapfile: false,
            append_only: false, // no chattr +a: `IS_APPEND` is never true
            can_mmap,
            mmap_error: None,
            mmap_size_max,
            mmap_sync: false,
            hugepages: false,
        };
        Some(match file.kind {
            // `shmem_file_operations`; `S_ISREG`: `MAX_LFS_FILESIZE`.
            FileKind::Regular => Mappable::File(info(true, MAX_LFS_FILESIZE as u64)),
            // `simple_offset_dir_operations`, `pipefifo_fops`, `null_fops`,
            // `full_fops` and `console_fops` have no `->mmap`; none of them is
            // `FOP_UNSIGNED_OFFSET` or a regular file: `ULONG_MAX`.
            FileKind::Directory
            | FileKind::Pipe { .. }
            | FileKind::Char(
                CharDev::Console
                | CharDev::TtyAux
                | CharDev::TtyS0
                | CharDev::HungUp
                | CharDev::Null
                | CharDev::Full,
            ) => Mappable::File(info(false, u64::MAX)),
            FileKind::Char(CharDev::Zero) => Mappable::Zero(info(true, u64::MAX)),
            // A procfs regular file is `S_ISREG`: `MAX_LFS_FILESIZE`. The entries of the global
            // table run on `proc_reg_file_ops`/`proc_iter_file_ops`, whose `->mmap` is
            // `proc_reg_mmap`: `-EIO` for an entry without `proc_mmap` (all of them here). The
            // process files, `fdinfo` and the sysctls have no `->mmap`.
            FileKind::Proc => {
                let global = file
                    .inode
                    .and_then(ProcNode::of)
                    .is_some_and(|node| node.kind == Kind::Global);
                let mut mapping = info(global, MAX_LFS_FILESIZE as u64);
                if global {
                    mapping.mmap_error = Some(Errno::EIO);
                }
                Mappable::File(mapping)
            }
            FileKind::Path => return None,
            FileKind::Unsupported => Mappable::Unported,
        })
    }

    /// Make room for one more [`Vfs::pin`].
    ///
    /// # Errors
    /// `ENOMEM`.
    pub fn reserve_pin(&mut self) -> KResult<()> {
        self.reserve_pins(1)
    }

    /// Make room for `count` more [`Vfs::pin`]s.
    ///
    /// # Errors
    /// `ENOMEM`.
    pub fn reserve_pins(&mut self, count: usize) -> KResult<()> {
        self.pins.try_reserve(count).map_err(|_| Errno::ENOMEM)
    }

    /// A mapping of address space `owner` now holds the open file description
    /// `id` (`FileInfo::id`); idempotent per owner. Storage was reserved by
    /// [`Vfs::reserve_pin`].
    ///
    /// # Panics
    /// If `id` is not an open description (a kernel bug) or no room was
    /// reserved.
    pub fn pin(&mut self, owner: u32, id: u64) {
        let file = file_of(id);
        if self
            .pins
            .iter()
            .any(|pin| pin.file == file && pin.owner == owner)
        {
            return;
        }
        self.files.dup(file);
        assert!(
            self.pins
                .push_within_capacity(Pin {
                    file,
                    owner,
                    snapshot: false
                })
                .is_ok(),
            "pin storage was not reserved"
        );
    }

    /// `dup_mmap`'s `get_file(vma->vm_file)` for a forked child: address
    /// space `to` holds every description `from` holds (and inherits whether
    /// its pages were copied out of the file, since the child's pages are
    /// copies of the parent's). Storage is reserved first: all or nothing.
    ///
    /// # Errors
    /// `ENOMEM`.
    pub fn pin_clone(&mut self, from: u32, to: u32) -> KResult<()> {
        let count = self.pins.iter().filter(|pin| pin.owner == from).count();
        self.pins.try_reserve(count).map_err(|_| Errno::ENOMEM)?;
        for index in 0..self.pins.len() {
            let pin = self.pins[index];
            if pin.owner == from {
                self.files.dup(pin.file);
                let pushed = self.pins.push_within_capacity(Pin { owner: to, ..pin });
                debug_assert!(pushed.is_ok(), "reserved above");
            }
        }
        Ok(())
    }

    /// `dup_mmap` takes no reference for a `VM_DONTCOPY` VMA: after [`Vfs::pin_clone`], drop the
    /// pins of `owner` whose description none of its VMAs maps (`mapped` says which are mapped).
    pub fn pin_retain(&mut self, owner: u32, mapped: impl Fn(u64) -> bool) {
        let mut index = self.pins.len();
        while index > 0 {
            index -= 1;
            if self.pins[index].owner == owner && !mapped(self.pin_id(index)) {
                self.unpin(index);
            }
        }
    }

    /// `exit_mmap`'s `fput(vma->vm_file)`: address space `owner` is gone.
    pub fn unpin_all(&mut self, owner: u32) {
        let mut index = self.pins.len();
        while index > 0 {
            index -= 1;
            if self.pins[index].owner == owner {
                self.unpin(index);
            }
        }
    }

    /// The address space that holds pin `index`.
    #[must_use]
    pub fn pin_owner(&self, index: usize) -> u32 {
        self.pins[index].owner
    }

    /// Number of descriptions pinned by mappings.
    #[must_use]
    pub fn pin_count(&self) -> usize {
        self.pins.len()
    }

    /// `FileInfo::id` of pin `index`.
    #[must_use]
    pub fn pin_id(&self, index: usize) -> u64 {
        u64::from(self.pins[index].file.index())
    }

    /// The last VMA of pin `index` is gone (`fput(vma->vm_file)`).
    pub fn unpin(&mut self, index: usize) {
        let pin = self.pins.swap_remove(index);
        self.fput(pin.file);
    }

    /// The page of the file behind a private mapping that `shmem_fault` would
    /// supply for page index `pgoff`, copied into `bytes` (the part past
    /// `i_size` and holes are zero).
    ///
    /// # Errors
    /// [`FileFault::Bus`] when the page starts at or past `i_size`.
    ///
    /// # Panics
    /// If `id` is not a pinned regular file (a kernel bug: the VMA set and the
    /// pin list are reconciled after every mapping change).
    pub fn fault_page(
        &mut self,
        owner: u32,
        id: u64,
        pgoff: u64,
        bytes: &mut [u8; PAGE_SIZE],
    ) -> Result<(), FileFault> {
        let file = file_of(id);
        let slot = self
            .pins
            .iter()
            .position(|pin| pin.file == file && pin.owner == owner)
            .expect("faulting file is pinned");
        let inode = self
            .files
            .get(file)
            .inode
            .expect("mapped file has an inode");
        let start = pgoff.checked_mul(PAGE_SIZE as u64).ok_or(FileFault::Bus)?;
        if start >= self.fs.inode(inode).size {
            return Err(FileFault::Bus);
        }
        let produced = self.fs.read(inode, start, bytes);
        bytes[produced..].fill(0);
        self.pins[slot].snapshot = true;
        Ok(())
    }

    /// `file_accessed(file)` of `shmem_mmap`: `touch_atime` unless the
    /// description was opened `O_NOATIME`.
    ///
    /// # Panics
    /// If `id` is not an open description with an inode (a kernel bug).
    pub fn file_accessed(&mut self, id: u64) {
        let file = self.files.get(file_of(id));
        if file.flags & super::O_NOATIME == 0 {
            let inode = file.inode.expect("mapped file has an inode");
            self.fs.touch_atime(inode);
        }
    }

    /// The inode behind the mapped description `id` (`FileInfo::id`) as a futex key names it
    /// (`get_inode_sequence_number`): the superblock and the inode number.
    ///
    /// # Panics
    /// If `id` is not an open description with an inode (a kernel bug: the VMA set and the pin
    /// list are reconciled after every mapping change).
    #[must_use]
    pub fn mapped_inode(&self, id: u64) -> (super::SbId, u64) {
        let inode = self
            .files
            .get(file_of(id))
            .inode
            .expect("mapped file has an inode");
        let inode = self.fs.inode(inode);
        (inode.sb, inode.ino)
    }

    /// A private `/dev/zero` mapping now exists (`mmap_zero`).
    pub fn note_zero_mapping(&mut self) {
        self.zero_mapped = true;
    }

    /// Whether a VMA without a file may be a `/dev/zero` mapping, which Linux
    /// still attributes to `vm_file` (`print_vma_addr`).
    #[must_use]
    pub fn zero_mapped(&self) -> bool {
        self.zero_mapped
    }

    /// A write or truncate is about to change (or has changed) the contents of
    /// `inode`: if a mapping holds a copy of its pages, the copy-at-fault model
    /// no longer matches Linux (see the module shortcut).
    pub fn note_modified(&mut self, inode: super::InodeId) {
        let touched = self
            .pins
            .iter()
            .any(|pin| pin.snapshot && self.files.get(pin.file).inode == Some(inode));
        self.coherence_lost |= touched;
    }

    /// Whether [`Vfs::note_modified`] found a copy that could now differ from
    /// Linux; clears the flag.
    pub fn take_coherence_loss(&mut self) -> bool {
        core::mem::take(&mut self.coherence_lost)
    }
}

/// The description behind a `FileInfo::id` of this module.
fn file_of(id: u64) -> FileId {
    FileId(u32::try_from(id).expect("mapped file id is a file handle"))
}
