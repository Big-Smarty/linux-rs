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

use alloc::{sync::Arc, vec::Vec};

use syscalls::Errno;

use crate::{
    mm::{Mm, Vma},
    task::{Attributes, COMM_LEN},
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
#[derive(Debug, Default, PartialEq, Eq)]
pub struct MmView {
    pub vmas: Vec<Vma>,
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
    /// The identity group's state of the task: credentials, limits, `comm`,
    /// the filesystem context (`fs->root`, `fs->pwd`, `fs->umask`) and the
    /// personality.
    pub attrs: Attributes,
    /// `task->fs` still exists (`exit_fs` has not run).
    pub has_fs: bool,
    /// `None` for a task without an address space (a zombie).
    pub mm: Option<MmView>,
    /// `mm->exe_file`.
    pub exe: Option<FdEntry>,
    /// [`crate::vfs::FdTable::generation`] when the table was read.
    pub fd_gen: u64,
    /// `files_fdtable(files)->max_fds`; the open descriptors in ascending order.
    pub fds: Vec<FdEntry>,
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
    pub fdt: &'a FdTable,
    pub files: &'a FileTable,
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
        let fds = collect_fds(input.fdt, input.files)?;
        let mm = match input.mm {
            Some(mm) => Some(MmView::collect(mm, input.rss, input.pgtables_bytes)?),
            None => None,
        };
        let exe = input.exe.map(|file| FdEntry {
            fd: 0,
            file,
            serial: input.files.try_get(file).map_or(0, |f| f.serial),
            cloexec: false,
        });
        Ok(Self {
            attrs: *input.attrs,
            has_fs: true,
            mm,
            exe,
            fd_gen: input.fdt.generation(),
            fds,
            max_fds: u32::try_from(input.fdt.max_fds()).unwrap_or(u32::MAX),
            has_files: true,
            min_flt: input.min_flt,
            maj_flt: input.maj_flt,
            nvcsw: input.nvcsw,
            nivcsw: input.nivcsw,
            start_boottime_ns: input.start_boottime_ns,
            flags: input.flags,
            nice: 0,
            rt_priority: 0,
            policy: 0,
            args: input.args,
        })
    }

    /// The exec-time argument and environment bytes.
    #[must_use]
    pub fn args(&self) -> &[u8] {
        self.args.as_deref().map_or(&[], Vec::as_slice)
    }

    /// Bring the parts that follow the descriptor table, the filesystem
    /// context and the executable up to date, leaving the address-space part
    /// as published (what a syscall that opened, closed or `chdir`ed changed).
    ///
    /// # Errors
    /// `ENOMEM`; the view is unchanged.
    pub fn refresh_files(
        &mut self,
        attrs: &Attributes,
        fdt: &FdTable,
        files: &FileTable,
        exe: FileId,
    ) -> KResult<()> {
        let fds = collect_fds(fdt, files)?;
        self.attrs = *attrs;
        self.fds = fds;
        self.fd_gen = fdt.generation();
        self.max_fds = u32::try_from(fdt.max_fds()).unwrap_or(u32::MAX);
        self.exe = Some(FdEntry {
            fd: 0,
            file: exe,
            serial: files.try_get(exe).map_or(0, |f| f.serial),
            cloexec: false,
        });
        Ok(())
    }

    /// The descriptor `fd`, if open.
    #[must_use]
    pub fn fd(&self, fd: u32) -> Option<&FdEntry> {
        self.fds
            .binary_search_by_key(&fd, |entry| entry.fd)
            .ok()
            .map(|at| &self.fds[at])
    }

    /// `fget_task_next`: the first open descriptor at or after `fd`.
    #[must_use]
    pub fn next_fd(&self, fd: u32) -> Option<u32> {
        let at = self.fds.partition_point(|entry| entry.fd < fd);
        self.fds.get(at).map(|entry| entry.fd)
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
        self.has_fs.then_some(self.attrs.fs.root)
    }

    /// `fs->pwd`.
    #[must_use]
    pub fn pwd(&self) -> Option<InodeId> {
        self.has_fs.then_some(self.attrs.fs.pwd)
    }
}

/// The open descriptors in ascending order.
fn collect_fds(fdt: &FdTable, files: &FileTable) -> KResult<Vec<FdEntry>> {
    let mut fds: Vec<FdEntry> = Vec::new();
    for (fd, file, cloexec) in fdt.iter() {
        fds.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
        let serial = files.try_get(file).map_or(0, |f| f.serial);
        let _ = fds.push_within_capacity(FdEntry {
            fd,
            file,
            serial,
            cloexec,
        });
    }
    Ok(fds)
}

impl MmView {
    fn collect(mm: &Mm, rss: (u64, u64, u64), pgtables_bytes: u64) -> KResult<Self> {
        let mut vmas: Vec<Vma> = Vec::new();
        vmas.try_reserve_exact(mm.vmas().len())
            .map_err(|_| Errno::ENOMEM)?;
        for vma in mm.vmas() {
            let _ = vmas.push_within_capacity(*vma);
        }
        let total_rss = rss.0 + rss.1 + rss.2;
        Ok(Self {
            vmas,
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
