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
//! Build the initial address space of an `ET_EXEC` or `ET_DYN` image, with or without an
//! interpreter, through the one mapping-rule mechanism, [`crate::mm::Mm`].
//!
//! Order as in `load_elf_binary`: the stack VMA exists first
//! ([`insert_stack`], `setup_arg_pages`), then every `PT_LOAD` is `elf_load`ed
//! ([`map_image`]): `vm_mmap` of the file part (`MAP_FIXED_NOREPLACE` for
//! the first segment of an `ET_EXEC` or a program with an interpreter, `MAP_FIXED` after; an
//! `ET_DYN` without interpreter is placed top-down by the first `mmap`, or at an aligned address
//! found by a trial mapping when `p_align` exceeds a page), `padzero` (done in the page contents),
//! `vm_brk_flags` for the bss, the post-mapping `TASK_SIZE` checks, then `load_elf_interp`
//! (the same `elf_load`, relocated to wherever the first interpreter segment lands) and the entry
//! check; finally `start_brk`/`brk`/`start_data`/`end_data`. `norandmaps` removes
//! `arch_mmap_rnd` and `randomize_stack_top`, so `ELF_ET_DYN_BASE` is exact.
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
    plan::{
        ELF_ET_DYN_BASE, InterpPlan, LoadError, LoadPlan, Segment, Unsupported, failed, page_align,
        page_start,
    },
    stack::STACK_TOP,
};
use crate::{
    image::elf::{ET_DYN, ET_EXEC},
    memory::PAGE_BYTES,
    mm::{
        self, Env, FileInfo, MAP_FIXED, MAP_FIXED_NOREPLACE, MAP_PRIVATE, Mm, Mmap, OutOfMemory,
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
    /// `file` says the page belongs to a file mapping (a `vm_file` VMA), which
    /// decides how `/proc` counts it (`RssAnon` once written, else `RssShmem`).
    ///
    /// # Errors
    /// [`OutOfMemory`] if a frame or table cannot be allocated; nothing changed.
    fn install(
        &mut self,
        page: u64,
        prot: PageProt,
        file: bool,
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
        mmap_error: None,
        mmap_size_max: i64::MAX.cast_unsigned(),
        mmap_sync: false,
        hugepages: false,
    }
}

/// `create_init_stack_vma` + `setup_arg_pages` for the final, already expanded stack
/// `[start, STACK_TOP)` (see [`super::stack::stack_vma_start`]).
///
/// # Errors
/// `ENOMEM` (storage or the overcommit policy), as `insert_vm_struct`.
pub fn insert_stack(mm: &mut Mm, env: &Env, exec_stack: bool, start: u64) -> Result<(), LoadError> {
    let mut flags = VmFlags::STACK_FLAGS | mm.def_flags;
    if exec_stack {
        flags |= VmFlags::EXEC;
    }
    mm.insert_vm_struct(
        env,
        Vma {
            start,
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

/// `BAD_ADDR`: an address (or a negative errno) at or above `TASK_SIZE`.
const fn bad_addr(address: u64) -> bool {
    address >= TASK_SIZE_MAX
}

/// `elf_load` of one segment up to (not including) the post-mapping checks: the file part at
/// `bias + start` (`elf_map`: with `total_size`, the whole image is mapped first and the part past
/// the first segment is unmapped again), the bss. Returns the address `elf_map` mapped at.
/// The frames of the file pages are not installed here ([`install_file_pages`]).
#[allow(clippy::too_many_arguments)]
fn elf_load(
    segment: &Segment,
    bias: u64,
    fixed: u64,
    total_size: u64,
    file: &FileInfo,
    mm: &mut Mm,
    env: &Env,
    pt: &mut (impl Pager + ?Sized),
) -> Result<u64, LoadError> {
    // `addr` of elf_map: ELF_PAGESTART(load_bias + vaddr).
    let addr = bias.wrapping_add(segment.start);
    let mut map_addr = addr;
    if segment.filesz != 0 && segment.file_pages != 0 {
        // elf_map -> vm_mmap(file, addr, size, prot, MAP_PRIVATE|FIXED..., off)
        let size = segment.file_pages * crate::memory::PAGE;
        let off = segment.file_offset;
        let length = if total_size != 0 {
            page_align(total_size)
        } else {
            size
        };
        if off.wrapping_add(length) < off || off & (crate::memory::PAGE - 1) != 0 {
            return Err(failed(Errno::EINVAL));
        }
        let flags = MAP_PRIVATE | fixed;
        map_addr = match mm
            .mmap(
                env,
                pt,
                addr,
                length,
                prot_bits(segment),
                flags,
                off >> 12,
                Some(file),
            )
            .map_err(failed)?
        {
            Mmap::NeedsFile(m) => mm
                .mmap_region(env, pt, Some(m.file.id), m.addr, m.len, m.vm_flags, m.pgoff)
                .map_err(failed)?,
            // `do_mmap`: prot == PROT_EXEC takes `execute_only_pkey()`, so a `PF_X`-only segment
            // is execute-only with protection keys on (a read of it is SEGV_PKUERR). The model
            // carries no key: a loud stop, as for the syscalls.
            Mmap::Unsupported(mm::Unsupported::ExecuteOnlyPkey) => {
                return Err(LoadError::Unsupported(Unsupported::ExecuteOnlyPkey));
            }
            // The other branches are never taken by a private regular file.
            Mmap::Mapped(_) | Mmap::Unsupported(_) => return Err(failed(Errno::EINVAL)),
        };
        if total_size != 0 && !bad_addr(map_addr) {
            // vm_munmap(map_addr + size, total_size - size): the result is not looked at (a
            // total of one segment's size is `EINVAL` for the empty range).
            let _ = mm.munmap(
                env,
                pt,
                map_addr.wrapping_add(size),
                length.wrapping_sub(size),
            );
        }
    }
    if segment.memsz > segment.filesz {
        // Map the last of the segment; honour a request to be executable.
        let exec = if segment.prot.exec {
            VmFlags::EXEC
        } else {
            VmFlags::NONE
        };
        let delta = map_addr.wrapping_sub(segment.start);
        mm.vm_brk_flags(
            env,
            pt,
            segment.anon_start.wrapping_add(delta),
            segment.anon_len,
            exec,
        )
        .map_err(failed)?;
    }
    Ok(map_addr)
}

/// Where the image and its interpreter ended up: the numbers `create_elf_tables` and
/// `start_thread` take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    /// `load_bias` (zero for `ET_EXEC`).
    pub load_bias: u64,
    /// `AT_ENTRY`: the image's own entry point, biased.
    pub e_entry: u64,
    /// `AT_PHDR`: the biased address of the program header table.
    pub phdr: u64,
    /// `AT_BASE`: the interpreter's load address, 0 without one.
    pub interp_base: u64,
    /// `elf_entry`: where the task starts (the interpreter's entry, else `e_entry`).
    pub entry: u64,
}

/// An interpreter ready to be mapped: its plan, its bytes and the open file.
pub struct Interp<'a> {
    pub plan: &'a InterpPlan,
    pub bytes: &'a [u8],
    pub info: FileInfo,
}

/// `load_elf_interp`; returns the load address (the value `AT_BASE` gets).
fn load_elf_interp(
    interp: &Interp<'_>,
    no_base: u64,
    mm: &mut Mm,
    env: &Env,
    pt: &mut (impl Pager + ?Sized),
) -> Result<u64, LoadError> {
    // `error = ~0UL` for these: `(int)~0UL` is `-EPERM` to `load_elf_binary`.
    if interp.plan.file_type != ET_EXEC && interp.plan.file_type != ET_DYN {
        return Err(failed(Errno::EPERM));
    }
    let mut total_size = interp.plan.total_size;
    if total_size == 0 {
        return Err(failed(Errno::EINVAL));
    }
    let (mut load_addr, mut load_addr_set) = (0u64, false);
    for segment in interp.plan.segments() {
        let vaddr = segment.vaddr;
        let mut fixed = 0;
        if interp.plan.file_type == ET_EXEC || load_addr_set {
            fixed = MAP_FIXED;
        } else if no_base != 0 && interp.plan.file_type == ET_DYN {
            load_addr = vaddr.wrapping_neg();
        }
        // elf_load(interpreter, load_addr + vaddr, ...): the segment's own page start is
        // `ELF_PAGESTART(vaddr)`, so the bias is what is added to it.
        let bias = load_addr.wrapping_add(vaddr) & !(crate::memory::PAGE - 1);
        let bias = bias.wrapping_sub(segment.start);
        let map_addr = elf_load(segment, bias, fixed, total_size, &interp.info, mm, env, pt)?;
        total_size = 0;
        if bad_addr(map_addr) {
            return Err(failed(Errno::EINVAL));
        }
        if !load_addr_set && interp.plan.file_type == ET_DYN {
            load_addr = map_addr.wrapping_sub(page_start(vaddr));
            load_addr_set = true;
        }
        // The section's size must not overflow the task size.
        let k = load_addr.wrapping_add(vaddr);
        if bad_addr(k)
            || segment.filesz > segment.memsz
            || segment.memsz > TASK_SIZE_MAX
            || TASK_SIZE_MAX - segment.memsz < k
        {
            return Err(failed(Errno::ENOMEM));
        }
        // Not part of the C: the frames of the file part, at the address `elf_map` mapped.
        install_file_pages(
            segment,
            interp.bytes,
            map_addr.wrapping_sub(segment.start),
            pt,
        )?;
    }
    Ok(load_addr)
}

/// Map every `PT_LOAD` of `plan` (and the interpreter's) into `mm` and fill in its program-break
/// and data fields. `file` is the image, `info` its open file (see [`exec_file`]).
///
/// # Errors
/// The `execve` errno of Linux 6.18.57 for the same image and mm state
/// (the model's `ENOMEM`/`EEXIST`/`EOVERFLOW`/`EACCES`/... for the mapping
/// steps, `EINVAL` for the post-mapping checks), or an [`Unsupported`] case.
#[allow(
    clippy::too_many_lines,
    reason = "one function per Linux function, step for step"
)]
pub fn map_image(
    plan: &LoadPlan,
    file: &[u8],
    info: &FileInfo,
    interp: Option<&Interp<'_>>,
    mm: &mut Mm,
    env: &Env,
    pt: &mut (impl Pager + ?Sized),
) -> Result<Layout, LoadError> {
    // The argument stack as it is now: a later MAP_FIXED segment must not replace it.
    let stack = mm.find_vma(STACK_TOP - 1).map(|v| (v.start, v.end));
    let mut load_bias = 0u64;
    let mut first_pt_load = true;
    let mut elf_brk = 0u64;
    let mut start_data = 0u64;
    let mut end_data = 0u64;
    let mut start_code = u64::MAX;
    let mut end_code = 0u64;
    for segment in plan.segments() {
        let vaddr = segment.vaddr;
        let mut fixed = 0;
        let mut total_size = 0;
        if !first_pt_load {
            fixed = MAP_FIXED;
        } else if plan.file_type == ET_EXEC {
            fixed = MAP_FIXED_NOREPLACE;
        } else {
            // ET_DYN: the load bias is calculated once, for all the PT_LOADs.
            total_size = plan.total_size;
            if total_size == 0 {
                return Err(failed(Errno::EINVAL));
            }
            let alignment = plan.alignment;
            if interp.is_some() {
                // On ET_DYN with PT_INTERP, we do the ASLR (norandmaps: none).
                load_bias = ELF_ET_DYN_BASE;
                if alignment != 0 {
                    load_bias &= !(alignment - 1);
                }
                fixed = MAP_FIXED_NOREPLACE;
            } else if alignment > crate::memory::PAGE {
                // A trial mapping at address 0 finds where things would load, so that the
                // result can be aligned.
                let bias = 0u64.wrapping_sub(segment.start);
                let trial = elf_load(segment, bias, 0, total_size, info, mm, env, pt);
                let address = match trial {
                    Ok(address) if !bad_addr(address) => address,
                    Ok(_) => return Err(failed(Errno::EINVAL)),
                    Err(error) => return Err(error),
                };
                let _ = mm.munmap(env, pt, address, total_size);
                load_bias = address & !(alignment - 1);
                fixed = MAP_FIXED_NOREPLACE;
            }
            // The bias is lowered by the first vaddr so the remaining calculations on the ELF
            // vaddrs are offset correctly, then page aligned.
            load_bias = page_start(load_bias.wrapping_sub(vaddr));
        }
        let bias = load_bias;
        let map_addr = elf_load(segment, bias, fixed, total_size, info, mm, env, pt)?;
        // BAD_ADDR(error)
        if bad_addr(map_addr) {
            return Err(failed(Errno::EINVAL));
        }
        if first_pt_load {
            first_pt_load = false;
            if plan.file_type == ET_DYN {
                load_bias = load_bias
                    .wrapping_add(map_addr.wrapping_sub(page_start(load_bias.wrapping_add(vaddr))));
            }
        }
        let (k, filesz, memsz) = (vaddr, segment.filesz, segment.memsz);
        start_data = start_data.max(k);
        if segment.prot.exec {
            start_code = start_code.min(k);
        }
        // Check to see if the section's size will overflow the allowed task
        // size (set_brk can never work; avoids overflows below).
        if k >= TASK_SIZE_MAX
            || filesz > memsz
            || memsz > TASK_SIZE_MAX
            || TASK_SIZE_MAX - memsz < k
        {
            return Err(failed(Errno::EINVAL));
        }
        end_data = end_data.max(k.wrapping_add(filesz));
        if segment.prot.exec {
            end_code = end_code.max(k.wrapping_add(filesz));
        }
        elf_brk = elf_brk.max(k.wrapping_add(memsz));
        // Not part of the C: the frames of the file part. `map_addr` is where this segment's
        // first page is (fixed segments: `bias + start`).
        install_file_pages(segment, file, map_addr.wrapping_sub(segment.start), pt)?;
    }
    let e_entry = plan.entry.wrapping_add(load_bias);
    let phdr = plan.phdr.wrapping_add(load_bias);
    let mut elf_brk = elf_brk.wrapping_add(load_bias);
    start_code = start_code.wrapping_add(load_bias);
    end_code = end_code.wrapping_add(load_bias);
    start_data = start_data.wrapping_add(load_bias);
    end_data = end_data.wrapping_add(load_bias);

    let (entry, interp_base) = if let Some(interp) = interp {
        let load_addr = load_elf_interp(interp, load_bias, mm, env, pt)?;
        let elf_entry = load_addr.wrapping_add(interp.plan.entry);
        if bad_addr(elf_entry) {
            return Err(failed(Errno::EINVAL));
        }
        (elf_entry, load_addr)
    } else {
        // BAD_ADDR(elf_entry)
        if bad_addr(e_entry) {
            return Err(failed(Errno::EINVAL));
        }
        (e_entry, 0)
    };
    // A later MAP_FIXED segment must not have replaced the argument stack.
    if stack.is_none_or(|(start, end)| {
        !mm.find_vma(start)
            .is_some_and(|v| v.start == start && v.end == end && v.file.is_none())
    }) {
        return Err(LoadError::Unsupported(Unsupported::Overlap));
    }
    // "brk" handling: a loader executed directly (ET_DYN without PT_INTERP) has its brk moved
    // out of the mmap region into the unused ELF_ET_DYN_BASE region (CONFIG_COMPAT_BRK is n and
    // x86 has ARCH_HAS_ELF_RANDOMIZE). Without randomisation there is no gap and no
    // `arch_randomize_brk`.
    if plan.file_type == ET_DYN && interp.is_none() {
        elf_brk = ELF_ET_DYN_BASE;
    }
    mm.start_brk = page_align(elf_brk);
    mm.brk = mm.start_brk;
    mm.start_data = start_data;
    mm.end_data = end_data;
    mm.start_code = start_code;
    mm.end_code = end_code;
    Ok(Layout {
        load_bias,
        e_entry,
        phdr,
        interp_base,
        entry,
    })
}

/// [`map_image`] for an image without an interpreter whose layout the caller knows already
/// (`ET_EXEC`); the boot loader's entry point.
///
/// # Errors
/// As [`map_image`].
pub fn map_segments(
    plan: &LoadPlan,
    file: &[u8],
    info: &FileInfo,
    mm: &mut Mm,
    env: &Env,
    pt: &mut (impl Pager + ?Sized),
) -> Result<Layout, LoadError> {
    map_image(plan, file, info, None, mm, env, pt)
}

/// The page-cache stand-in for the file part of one segment, mapped at `bias + start`.
fn install_file_pages(
    segment: &Segment,
    file: &[u8],
    bias: u64,
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
        let address = bias
            .wrapping_add(segment.start)
            .wrapping_add(page * crate::memory::PAGE);
        segment.fill_page(file, page, &mut bytes);
        pt.install(address, prot, true, &bytes)
            .map_err(|_| failed(Errno::ENOMEM))?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests;
