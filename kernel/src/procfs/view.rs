// SPDX-License-Identifier: GPL-2.0-only
// Selected state from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: include/linux/mm_types.h
// (`struct mm_struct` fields `start_code`..`env_end`, `total_vm`.., the
// `MM_*PAGES` counters), include/linux/sched.h (`struct task_struct` fields
// the files of `/proc/<pid>` read), include/linux/fdtable.h (`max_fds`).
// Transformation: a plain-data snapshot of what only the owning task can
// see, published by the task when it leaves the kernel or sleeps (the
// `userspace.rs` binary builds it; nothing here touches hardware).
#![forbid(unsafe_code)]
//! What a task publishes for `/proc/<pid>/*` readers.
//!
//! # Contract
//! * Context: the publisher is the task itself (its state is its own); the
//!   readers run under the `vfs` lock class and only read.
//! * A view may lag the task by what it did since it last left the kernel; the
//!   file table's descriptors in it are validated against the file's serial
//!   before use ([`crate::vfs::FileTable::get_checked`]).
//! * Cost: a republication (`TaskView::update`) takes time proportional to
//!   what changed since the last one, not to the size of the task. The
//!   descriptors are replayed from the table's change log
//!   ([`FdTable::changed_since`]; a gap wider than the log copies the table),
//!   the VMA vector is shared while its stamp ([`Mm::vma_stamp`]) is unchanged
//!   and copied once after it moved, and the resident-page and page-table
//!   figures are counters the caller reads in constant time.

use alloc::{boxed::Box, sync::Arc, vec::Vec};

use crate::vfs::FsStruct;

use syscalls::Errno;

use crate::{
    mm::{Mm, Vma},
    task::{Attributes, COMM_LEN, Rlimits},
    vfs::{FdTable, FileId, FileTable, InodeId, KResult},
};

/// One open descriptor of a published table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FdEntry {
    pub fd: u32,
    pub file: FileId,
    /// [`crate::vfs::file::File::serial`] of the description when published.
    pub serial: u64,
    pub cloexec: bool,
}

/// The address-space facts of a published task (`mm_struct`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MmView {
    /// The VMAs as of `vma_stamp`, shared with the previous publication while
    /// [`Mm::vma_stamp`] has not moved.
    pub vmas: Arc<Vec<Vma>>,
    /// [`Mm::vma_stamp`] when `vmas` was copied.
    pub vma_stamp: (u64, u64),
    pub start_code: u64,
    pub end_code: u64,
    pub start_data: u64,
    pub end_data: u64,
    pub start_brk: u64,
    pub brk: u64,
    pub start_stack: u64,
    pub arg_start: u64,
    pub arg_end: u64,
    pub env_start: u64,
    pub env_end: u64,
    pub total_vm: u64,
    pub data_vm: u64,
    pub exec_vm: u64,
    pub stack_vm: u64,
    pub locked_vm: u64,
    /// `MM_ANONPAGES`, `MM_FILEPAGES`, `MM_SHMEMPAGES` (pages).
    pub rss_anon: u64,
    pub rss_file: u64,
    pub rss_shmem: u64,
    /// `mm->hiwater_rss` / `hiwater_vm` (pages): the highest values seen.
    pub hiwater_rss: u64,
    pub hiwater_vm: u64,
    /// `mm_pgtables_bytes`.
    pub pgtables_bytes: u64,
}

/// What a task publishes (the parts of `task_struct` that are not in the task
/// list).
#[derive(Debug)]
pub struct TaskView {
    /// The identity group's state of the task: credentials, `comm` and the personality.
    pub attrs: Attributes,
    /// `signal->rlim` of the task's thread group (`/proc/<pid>/limits`, `stat`'s `rsslim`).
    pub rlimits: Rlimits,
    /// The filesystem context (`fs->root`, `fs->pwd`, `fs->umask`).
    pub fs: FsStruct,
    /// `task->fs` still exists (`exit_fs` has not run).
    pub has_fs: bool,
    /// `None` for a task without an address space (a zombie).
    pub mm: Option<MmView>,
    /// `mm->exe_file`.
    pub exe: Option<FdEntry>,
    /// [`crate::vfs::FdTable::stamp`] when the table was read.
    pub fd_stamp: (u64, u64),
    /// The open descriptors; `max_fds` is `files_fdtable(files)->max_fds`.
    pub fds: FdView,
    pub max_fds: u32,
    /// `task->files` still exists (`exit_files` has not run).
    pub has_files: bool,
    /// `p->min_flt`, `maj_flt`, `nvcsw`, `nivcsw`.
    pub min_flt: u64,
    pub maj_flt: u64,
    pub nvcsw: u64,
    pub nivcsw: u64,
    /// `p->start_boottime` in nanoseconds.
    pub start_boottime_ns: u64,
    /// `p->flags` bits the task list does not keep (`PF_SUPERPRIV`).
    pub flags: u32,
    /// `task_nice`, `rt_priority`, `policy`.
    pub nice: i32,
    pub rt_priority: u32,
    pub policy: u32,
    /// The argument and environment bytes copied at `execve`
    /// (`arg_start..env_end`): what `/proc/<pid>/cmdline` and `environ` show for
    /// another task. shortcut: the caller's own are read live from its memory;
    /// a task that rewrote its `argv` after `execve` (`setproctitle`) shows the
    /// original to others until it republishes at the next `execve`. Shared
    /// between the views of one image (a republish keeps it without copying);
    /// `None` is empty.
    pub args: Option<Arc<Vec<u8>>>,
}

/// What [`TaskView::collect`] reads from the owning task.
pub struct Collect<'a> {
    pub attrs: &'a Attributes,
    pub rlimits: &'a Rlimits,
    pub fs: FsStruct,
    pub fdt: &'a FdTable,
    pub files: &'a FileTable,
    /// The address space (`None` keeps what the view has).
    pub mm: Option<&'a Mm>,
    pub exe: Option<FileId>,
    /// `(anon, file, shmem)` resident pages and the page-table bytes of the
    /// address space.
    pub rss: (u64, u64, u64),
    pub pgtables_bytes: u64,
    pub min_flt: u64,
    pub maj_flt: u64,
    pub nvcsw: u64,
    pub nivcsw: u64,
    pub start_boottime_ns: u64,
    pub flags: u32,
    /// The exec-time argument bytes to keep (the previous view's, or fresh).
    pub args: Option<Arc<Vec<u8>>>,
}

impl TaskView {
    /// Build the view of a live task.
    ///
    /// # Errors
    /// `ENOMEM`.
    pub fn collect(input: Collect<'_>) -> KResult<Self> {
        let mut view = Self {
            attrs: *input.attrs,
            rlimits: *input.rlimits,
            fs: input.fs,
            has_fs: true,
            mm: None,
            exe: None,
            // No table has this stamp, so the first update copies the table.
            fd_stamp: (0, u64::MAX),
            fds: FdView::default(),
            max_fds: 0,
            has_files: true,
            min_flt: 0,
            maj_flt: 0,
            nvcsw: 0,
            nivcsw: 0,
            start_boottime_ns: 0,
            flags: 0,
            nice: 0,
            rt_priority: 0,
            policy: 0,
            args: None,
        };
        view.update(input)?;
        Ok(view)
    }

    /// Bring the view up to date with the task: time proportional to what
    /// changed since the last update (see the module contract).
    ///
    /// # Errors
    /// `ENOMEM`; the view is unchanged.
    pub fn update(&mut self, input: Collect<'_>) -> KResult<()> {
        // Everything that can fail comes first; the commit below cannot.
        let mm = match input.mm {
            Some(mm) => Some(MmView::collect(
                self.mm.as_ref(),
                mm,
                input.rss,
                input.pgtables_bytes,
            )?),
            None => None, // kept below
        };
        self.fds.sync(self.fd_stamp, input.fdt, input.files)?;
        self.attrs = *input.attrs;
        self.rlimits = *input.rlimits;
        self.fs = input.fs;
        self.has_fs = true;
        self.has_files = true;
        if input.mm.is_some() {
            self.mm = mm;
        }
        self.exe = input.exe.map(|file| exe_entry(file, input.files));
        self.fd_stamp = input.fdt.stamp();
        self.max_fds = u32::try_from(input.fdt.max_fds()).unwrap_or(u32::MAX);
        self.min_flt = input.min_flt;
        self.maj_flt = input.maj_flt;
        self.nvcsw = input.nvcsw;
        self.nivcsw = input.nivcsw;
        self.start_boottime_ns = input.start_boottime_ns;
        self.flags = input.flags;
        self.args = input.args;
        Ok(())
    }

    /// The exec-time argument and environment bytes.
    #[must_use]
    pub fn args(&self) -> &[u8] {
        self.args.as_deref().map_or(&[], Vec::as_slice)
    }

    /// Bring the parts that follow the descriptor table, the filesystem
    /// context and the executable up to date, leaving the address-space part
    /// as published (what a syscall that opened, closed or `chdir`ed changed).
    /// Time proportional to the descriptors that changed.
    ///
    /// # Errors
    /// `ENOMEM`; the view is unchanged.
    pub fn refresh_files(
        &mut self,
        attrs: &Attributes,
        rlimits: &Rlimits,
        fs: FsStruct,
        fdt: &FdTable,
        files: &FileTable,
        exe: FileId,
    ) -> KResult<()> {
        self.fds.sync(self.fd_stamp, fdt, files)?;
        self.attrs = *attrs;
        self.rlimits = *rlimits;
        self.fs = fs;
        self.fd_stamp = fdt.stamp();
        self.max_fds = u32::try_from(fdt.max_fds()).unwrap_or(u32::MAX);
        self.exe = Some(exe_entry(exe, files));
        Ok(())
    }

    /// The descriptor `fd`, if open.
    #[must_use]
    pub fn fd(&self, fd: u32) -> Option<&FdEntry> {
        self.fds.get(fd)
    }

    /// `fget_task_next`: the first open descriptor at or after `fd`.
    #[must_use]
    pub fn next_fd(&self, fd: u32) -> Option<u32> {
        self.fds.next(fd)
    }

    /// `task->comm` as a byte string.
    #[must_use]
    pub fn comm_bytes(&self) -> &[u8] {
        let end = self
            .attrs
            .comm
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(COMM_LEN);
        &self.attrs.comm[..end]
    }

    /// `fs->root`, while the task has a filesystem context.
    #[must_use]
    pub fn root(&self) -> Option<InodeId> {
        self.has_fs.then_some(self.fs.root)
    }

    /// `fs->pwd`.
    #[must_use]
    pub fn pwd(&self) -> Option<InodeId> {
        self.has_fs.then_some(self.fs.pwd)
    }
}

fn exe_entry(file: FileId, files: &FileTable) -> FdEntry {
    FdEntry {
        fd: 0,
        file,
        serial: files.try_get(file).map_or(0, |f| f.serial),
        cloexec: false,
    }
}

/// Descriptors per [`FdView`] chunk.
const CHUNK: usize = 64;

/// The open descriptors of a published table, indexed by descriptor number in
/// chunks that exist only where a descriptor was ever open: an update touches
/// the descriptors that changed and nothing else, and a sparse table costs
/// the chunks it uses.
#[derive(Debug, Default)]
pub struct FdView {
    chunks: Vec<Option<Box<[Option<FdEntry>; CHUNK]>>>,
    open: usize,
}

impl FdView {
    /// The open descriptor `fd`.
    #[must_use]
    pub fn get(&self, fd: u32) -> Option<&FdEntry> {
        let fd = fd as usize;
        self.chunks
            .get(fd / CHUNK)?
            .as_ref()?
            .get(fd % CHUNK)?
            .as_ref()
    }

    /// The first open descriptor at or after `fd`.
    #[must_use]
    pub fn next(&self, fd: u32) -> Option<u32> {
        let fd = fd as usize;
        let mut index = fd / CHUNK;
        let mut from = fd % CHUNK;
        while index < self.chunks.len() {
            if let Some(chunk) = &self.chunks[index]
                && let Some(at) = chunk[from..].iter().position(Option::is_some)
            {
                return u32::try_from(index * CHUNK + from + at).ok();
            }
            index += 1;
            from = 0;
        }
        None
    }

    /// How many descriptors are open.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.open
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.open == 0
    }

    /// The chunk of descriptor `fd`, made if there is none (no descriptor
    /// changes).
    fn chunk_mut(&mut self, fd: u32) -> KResult<&mut [Option<FdEntry>; CHUNK]> {
        let index = fd as usize / CHUNK;
        if self.chunks.len() <= index {
            self.chunks
                .try_reserve(index + 1 - self.chunks.len())
                .map_err(|_| Errno::ENOMEM)?;
            while self.chunks.len() <= index {
                let _ = self.chunks.push_within_capacity(None);
            }
        }
        let slot = &mut self.chunks[index];
        if slot.is_none() {
            *slot = Some(Box::try_new([None; CHUNK]).map_err(|_| Errno::ENOMEM)?);
        }
        slot.as_deref_mut().ok_or(Errno::ENOMEM)
    }

    /// Record descriptor `fd` as `entry`; [`FdView::chunk_mut`] ran for it if
    /// `entry` is `Some`.
    fn put(&mut self, fd: u32, entry: Option<FdEntry>) {
        let fd = fd as usize;
        let Some(Some(chunk)) = self.chunks.get_mut(fd / CHUNK) else {
            return;
        };
        let slot = &mut chunk[fd % CHUNK];
        self.open += usize::from(entry.is_some());
        self.open -= usize::from(slot.is_some());
        *slot = entry;
    }

    /// Make the view equal to `fdt`, whose state `seen` (a
    /// [`FdTable::stamp`]) the view last read: replay the descriptors the
    /// table logged since, or copy the whole table when more than its log
    /// holds changed, when `seen` is another table's or when the view never
    /// read one. All or nothing.
    ///
    /// # Errors
    /// `ENOMEM`; the view is unchanged.
    fn sync(&mut self, seen: (u64, u64), fdt: &FdTable, files: &FileTable) -> KResult<()> {
        let seen = if seen.0 == fdt.stamp().0 {
            seen.1
        } else {
            u64::MAX
        };
        let entry_of = |fd: u32| {
            fdt.get(fd).map(|file| FdEntry {
                fd,
                file,
                serial: files.try_get(file).map_or(0, |f| f.serial),
                cloexec: fdt.cloexec(fd),
            })
        };
        let Some(changed) = fdt.changed_since(seen) else {
            let mut fresh = Self::default();
            for (fd, file, cloexec) in fdt.iter() {
                let serial = files.try_get(file).map_or(0, |f| f.serial);
                fresh.chunk_mut(fd)?[fd as usize % CHUNK] = Some(FdEntry {
                    fd,
                    file,
                    serial,
                    cloexec,
                });
                fresh.open += 1;
            }
            *self = fresh;
            return Ok(());
        };
        for fd in changed {
            if fdt.get(fd).is_some() {
                self.chunk_mut(fd)?;
            }
        }
        // Chunks exist for every descriptor that is open now: nothing fails.
        for fd in fdt.changed_since(seen).into_iter().flatten() {
            self.put(fd, entry_of(fd));
        }
        Ok(())
    }
}

impl MmView {
    /// The address-space facts of `mm`; the VMA vector is shared with `prev`
    /// while `mm` reports the same stamp, copied once otherwise.
    ///
    /// # Errors
    /// `ENOMEM`.
    pub fn collect(
        prev: Option<&Self>,
        mm: &Mm,
        rss: (u64, u64, u64),
        pgtables_bytes: u64,
    ) -> KResult<Self> {
        let stamp = mm.vma_stamp();
        let vmas = match prev {
            Some(prev) if prev.vma_stamp == stamp => Arc::clone(&prev.vmas),
            _ => {
                let mut vmas: Vec<Vma> = Vec::new();
                vmas.try_reserve_exact(mm.vmas().len())
                    .map_err(|_| Errno::ENOMEM)?;
                for vma in mm.vmas() {
                    let _ = vmas.push_within_capacity(*vma);
                }
                Arc::try_new(vmas).map_err(|_| Errno::ENOMEM)?
            }
        };
        let total_rss = rss.0 + rss.1 + rss.2;
        Ok(Self {
            vmas,
            vma_stamp: stamp,
            start_code: mm.start_code,
            end_code: mm.end_code,
            start_data: mm.start_data,
            end_data: mm.end_data,
            start_brk: mm.start_brk,
            brk: mm.brk,
            start_stack: mm.start_stack,
            arg_start: mm.arg_start,
            arg_end: mm.arg_end,
            env_start: mm.env_start,
            env_end: mm.env_end,
            total_vm: mm.total_vm,
            data_vm: mm.data_vm,
            exec_vm: mm.exec_vm,
            stack_vm: mm.stack_vm,
            locked_vm: mm.locked_vm,
            rss_anon: rss.0,
            rss_file: rss.1,
            rss_shmem: rss.2,
            hiwater_rss: total_rss,
            hiwater_vm: mm.hiwater_vm.max(mm.total_vm),
            pgtables_bytes,
        })
    }
}
