// SPDX-License-Identifier: GPL-2.0-only AND (GPL-2.0 WITH Linux-syscall-note)
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: fs/binfmt_elf.c (`load_elf_binary`
// segment loop, `elf_load`, `elf_map`; GPL-2.0-only, Copyright 1993, 1994: Eric
// Youngdale), mm/util.c (`vm_mmap`), fs/exec.c (`create_init_stack_vma`,
// `setup_arg_pages`, `open_exec` flags; GPL-2.0-only). GPL-2.0.
// Transformation: `vm_mmap`/`vm_brk_flags` are calls into the address-space
// model (`crate::mm`), which owns every mapping rule; the page cache is
// replaced by [`Pager::install`], called for each file page right after its
// mapping is committed (so a later `MAP_FIXED` segment frees what it replaces).
#![forbid(unsafe_code)]
//! Build the initial address space of a static `ET_EXEC` image through the
//! one mapping-rule mechanism, [`crate::mm::Mm`].
//!
//! Order as in `load_elf_binary`: the stack VMA exists first
//! ([`insert_stack`], `setup_arg_pages`), then every `PT_LOAD` is `elf_load`ed
//! ([`map_segments`]): `vm_mmap` of the file part (`MAP_FIXED_NOREPLACE` for
//! the first segment, `MAP_FIXED` after), `padzero` (done in the page contents),
//! `vm_brk_flags` for the bss, the post-mapping `TASK_SIZE` checks, then the
//! entry check; finally `start_brk`/`brk`/`start_data`/`end_data`.
//!
//! # Contract
//! * Context: early boot, task context, one thread; the caller owns the `Mm`
//!   and the tables behind `pt`. Allocation is fallible (`Vec::try_reserve`
//!   inside the model; frames inside [`Pager::install`]).
//! * shortcut: no page cache. File pages are installed eagerly as private
//!   frames (what `wp_page_copy` would produce). A page of a file VMA that is
//!   not present therefore has no source; the model reports `NeedsFile` and the
//!   kernel stops loudly. Upgrade with the VFS/page-cache owner.
//! * shortcut: Linux's `Uhuuh, elf segment ... mapped already` `pr_info` for a
//!   `-EEXIST` first segment is not printed.

use super::{
    plan::{LoadError, LoadPlan, Segment, Unsupported, failed, page_align},
    stack::{STACK_START, STACK_TOP},
};
use crate::{
    memory::PAGE_BYTES,
    mm::{
        Env, FileInfo, MAP_FIXED, MAP_FIXED_NOREPLACE, MAP_PRIVATE, Mm, Mmap, OutOfMemory,
        PROT_EXEC, PROT_READ, PROT_WRITE, PageProt, UserPages, VmFlags, Vma,
    },
    usercopy::TASK_SIZE_MAX,
};
use syscalls::Errno;

/// The page tables as the loader needs them: the model's operations plus
/// "make this page present with these contents" (the page cache stand-in).
pub trait Pager: UserPages {
    /// Install a fresh private frame holding `bytes` at `page` (page-aligned,
    /// below `TASK_SIZE_MAX`, inside a just-created VMA, no PTE yet) with
    /// `prot` (`accessible == false` keeps the frame behind a `PROT_NONE` PTE).
    ///
    /// # Errors
    /// [`OutOfMemory`] if a frame or table cannot be allocated; nothing changed.
    fn install(
        &mut self,
        page: u64,
        prot: PageProt,
        bytes: &[u8; PAGE_BYTES],
    ) -> Result<(), OutOfMemory>;
}

/// What `open_exec` leaves behind for `vm_mmap`: a read-only (`FMODE_READ`,
/// writers denied) regular file of the rootfs, a ramfs/tmpfs inode: it has
/// `->mmap`, no `noexec` mount, `s_maxbytes = MAX_LFS_FILESIZE`.
#[must_use]
pub const fn exec_file(id: u64) -> FileInfo {
    FileInfo {
        id,
        readable: true,
        writable: false,
        noexec: false,
        swapfile: false,
        append_only: false,
        can_mmap: true,
        mmap_size_max: i64::MAX.cast_unsigned(),
        mmap_sync: false,
        hugepages: false,
    }
}

/// `create_init_stack_vma` + `setup_arg_pages` for the final, already expanded
/// stack `[STACK_START, STACK_TOP)`.
///
/// # Errors
/// `ENOMEM` (storage or the overcommit policy), as `insert_vm_struct`.
pub fn insert_stack(mm: &mut Mm, env: &Env, exec_stack: bool) -> Result<(), LoadError> {
    let mut flags = VmFlags::STACK_FLAGS | mm.def_flags;
    if exec_stack {
        flags |= VmFlags::EXEC;
    }
    mm.insert_vm_struct(
        env,
        Vma {
            start: STACK_START,
            end: STACK_TOP,
            flags,
            pgoff: 0,
            file: None,
            anon: None,
        },
    )
    .map_err(failed)
}

fn prot_bits(segment: &Segment) -> u64 {
    let p = segment.prot;
    (if p.read { PROT_READ } else { 0 })
        | (if p.write { PROT_WRITE } else { 0 })
        | (if p.exec { PROT_EXEC } else { 0 })
}

/// `elf_load` of one segment up to (not including) the post-mapping checks.
fn elf_load(
    segment: &Segment,
    first: bool,
    file: &FileInfo,
    mm: &mut Mm,
    env: &Env,
    pt: &mut (impl Pager + ?Sized),
) -> Result<u64, Errno> {
    if segment.filesz != 0 && segment.file_pages != 0 {
        // elf_map -> vm_mmap(file, addr, size, prot, MAP_PRIVATE|FIXED..., off)
        let size = segment.file_pages * crate::memory::PAGE;
        let off = segment.file_offset;
        if off.wrapping_add(size) < off || off & (crate::memory::PAGE - 1) != 0 {
            return Err(Errno::EINVAL);
        }
        let flags = MAP_PRIVATE
            | if first {
                MAP_FIXED_NOREPLACE
            } else {
                MAP_FIXED
            };
        match mm.mmap(
            env,
            pt,
            segment.start,
            size,
            prot_bits(segment),
            flags,
            off >> 12,
            Some(file),
        )? {
            Mmap::NeedsFile(m) => {
                mm.mmap_region(env, pt, Some(m.file.id), m.addr, m.len, m.vm_flags, m.pgoff)?;
            }
            // Private regular files never take these branches.
            Mmap::Mapped(_) | Mmap::Unsupported(_) => return Err(Errno::EINVAL),
        }
    }
    if segment.memsz > segment.filesz {
        // Map the last of the segment; honour a request to be executable.
        let exec = if segment.prot.exec {
            VmFlags::EXEC
        } else {
            VmFlags::NONE
        };
        mm.vm_brk_flags(env, pt, segment.anon_start, segment.anon_len, exec)?;
    }
    Ok(segment.start)
}

/// Map every `PT_LOAD` of `plan` into `mm` and fill in its program-break and
/// data fields. `file` is the image, `info` its open file (see [`exec_file`]).
///
/// # Errors
/// The `execve` errno of Linux 6.18.57 for the same image and mm state
/// (the model's `ENOMEM`/`EEXIST`/`EOVERFLOW`/`EACCES`/... for the mapping
/// steps, `EINVAL` for the post-mapping checks), or an [`Unsupported`] case.
pub fn map_segments(
    plan: &LoadPlan,
    file: &[u8],
    info: &FileInfo,
    mm: &mut Mm,
    env: &Env,
    pt: &mut (impl Pager + ?Sized),
) -> Result<(), LoadError> {
    let mut elf_brk = 0u64;
    let mut start_data = 0u64;
    let mut end_data = 0u64;
    for (index, segment) in plan.segments().iter().enumerate() {
        let map_addr = elf_load(segment, index == 0, info, mm, env, pt).map_err(failed)?;
        // BAD_ADDR(error)
        if map_addr >= TASK_SIZE_MAX {
            return Err(failed(Errno::EINVAL));
        }
        let (k, filesz, memsz) = (segment.vaddr, segment.filesz, segment.memsz);
        start_data = start_data.max(k);
        // Check to see if the section's size will overflow the allowed task
        // size (set_brk can never work; avoids overflows below).
        if k >= TASK_SIZE_MAX
            || filesz > memsz
            || memsz > TASK_SIZE_MAX
            || TASK_SIZE_MAX - memsz < k
        {
            return Err(failed(Errno::EINVAL));
        }
        end_data = end_data.max(k + filesz);
        elf_brk = elf_brk.max(k + memsz);
        install_file_pages(segment, file, pt)?;
    }
    // BAD_ADDR(elf_entry)
    if plan.entry >= TASK_SIZE_MAX {
        return Err(failed(Errno::EINVAL));
    }
    // A later MAP_FIXED segment must not have replaced the argument stack.
    if !mm
        .find_vma(STACK_START)
        .is_some_and(|v| v.start == STACK_START && v.end == STACK_TOP && v.file.is_none())
    {
        return Err(LoadError::Unsupported(Unsupported::Overlap));
    }
    mm.start_brk = page_align(elf_brk);
    mm.brk = mm.start_brk;
    mm.start_data = start_data;
    mm.end_data = end_data;
    Ok(())
}

/// The page-cache stand-in for the file part of one segment.
fn install_file_pages(
    segment: &Segment,
    file: &[u8],
    pt: &mut (impl Pager + ?Sized),
) -> Result<(), LoadError> {
    if segment.file_pages == 0 {
        return Ok(());
    }
    // The last page starts at or beyond EOF: Linux raises SIGBUS on use.
    let last = segment
        .file_offset
        .saturating_add((segment.file_pages - 1) * crate::memory::PAGE);
    if last >= file.len() as u64 {
        return Err(LoadError::Unsupported(Unsupported::BeyondEof));
    }
    let prot = PageProt {
        accessible: segment.prot.accessible(),
        write: segment.prot.write,
        exec: segment.prot.exec,
    };
    let mut bytes = [0u8; PAGE_BYTES];
    for page in 0..segment.file_pages {
        let address = segment.start + page * crate::memory::PAGE;
        segment.fill_page(file, page, &mut bytes);
        pt.install(address, prot, &bytes)
            .map_err(|_| failed(Errno::ENOMEM))?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests;
