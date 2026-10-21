// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: mm/mmap.c (`SYSCALL_DEFINE1(brk)`,
// `ksys_mmap_pgoff`, `SYSCALL_DEFINE2(munmap)`), mm/mremap.c (`SYSCALL_DEFINE5(mremap)`), arch/x86/kernel/sys_x86_64.c
// (`SYSCALL_DEFINE6(mmap)`), mm/mprotect.c (`SYSCALL_DEFINE3(mprotect)`),
// mm/madvise.c (`SYSCALL_DEFINE3(madvise)`, `do_madvise`, `madvise_populate`,
// `SYSCALL_DEFINE5(process_madvise)`), mm/gup.c (`faultin_page_range`), lib/iov_iter.c
// (`import_iovec`), kernel/pid.c (`pidfd_get_task`), drivers/tty/tty_io.c (`console_fops`: no
// `->mmap`). All GPL-2.0.
// Transformation: the decisions are `crate::mm`'s (this file decodes the
// register arguments, resolves the file descriptor and maps the model's
// outcomes to a return value); a request Linux serves with a shared file page,
// shmem or hugetlb object this kernel does not have yet ends in `Unimplemented`.
#![forbid(unsafe_code)]
//! Memory syscalls: `brk`, `mmap`, `munmap`, `mremap`, `mprotect`, `madvise`, `process_madvise`.
//!
//! Context: the one task, address-space lock held by construction (the
//! binary's `Process` lock). Heap storage for the VMA vector is reserved by
//! the model before it touches the page tables.
//!
//! * Outcomes that need an object this kernel lacks are `Unimplemented` (loud
//!   stop), never an errno Linux would not return: `MAP_SHARED|MAP_ANONYMOUS`
//!   (shmem), `MAP_HUGETLB` (hugetlbfs), a `MAP_SHARED` mapping of a file that
//!   can be written through it or of `/dev/zero` (pages shared with the file or
//!   with `shmem_zero_setup`), a device whose driver is not ported, the two `madvise`
//!   requests the model cannot answer ([`crate::mm::MadviseUnsupported`]; `MADV_REMOVE` and
//!   `MADV_WIPEONFORK` after a private `/dev/zero` mapping, which the model keeps as plain
//!   anonymous memory although Linux gives its VMA a file), and a tmpfs file mapping with
//!   `MAP_POPULATE`/`MAP_LOCKED` (`mm_populate` would take the private copies
//!   at `mmap` time, which the copy-at-fault model cannot reproduce without
//!   the page cache). `MAP_PRIVATE` mappings of tmpfs files (and read-only
//!   `MAP_SHARED` ones) are served by [`crate::vfs::mapping`].
//! * shortcut: `mm_populate` of `MAP_POPULATE|MAP_LOCKED` faults anonymous
//!   pages in exactly like Linux; `RLIMIT_MEMLOCK` and friends come from the
//!   fixed `INIT_RLIMITS` in `mm::Env`, not from `setrlimit`.

use super::{AddressSpace, Context, Files, Outcome, error, fd::import_segs};
use crate::{
    mm::{
        Env, FileMapping, MADV_POPULATE_READ, MADV_POPULATE_WRITE, MADV_REMOVE, MADV_WIPEONFORK,
        MAP_ANONYMOUS, Madvise, Mmap, PAGE_SIZE, VmFlags, madvise_range, mmap_off_to_pgoff,
    },
    vfs::mapping::Mappable,
};
use syscalls::{Errno, Sysno};

pub(super) fn dispatch<C: Context>(ctx: &mut C, sysno: Sysno, args: [u64; 6]) -> Option<Outcome> {
    Some(match sysno {
        Sysno::brk | Sysno::mmap | Sysno::munmap | Sysno::mremap => {
            let outcome = match sysno {
                Sysno::brk => {
                    let AddressSpace { mm, env, pages } = ctx.address_space();
                    Outcome::Return(mm.brk(env, pages, args[0]).cast_signed())
                }
                Sysno::mmap => mmap(ctx, args),
                Sysno::mremap => {
                    let AddressSpace { mm, env, pages } = ctx.address_space();
                    let [addr, old_len, new_len, flags, new_addr, _] = args;
                    Outcome::Return(
                        mm.mremap(env, pages, addr, old_len, new_len, flags, new_addr)
                            .map_or_else(error, u64::cast_signed),
                    )
                }
                _ => {
                    let AddressSpace { mm, env, pages } = ctx.address_space();
                    status(mm.munmap(env, pages, args[0], args[1]))
                }
            };
            // Each of these can delete VMAs (a shrinking `brk`, a `MAP_FIXED`
            // replacement, `munmap`): `fput(vma->vm_file)` for the files left.
            unpin_unmapped(ctx);
            outcome
        }
        Sysno::mprotect => {
            let AddressSpace { mm, env, pages } = ctx.address_space();
            match mm.mprotect(env, pages, args[0], args[1], args[2]) {
                Ok(None) => Outcome::Return(0),
                // The execute-only protection key: not ported, Linux serves it.
                Ok(Some(_)) => Outcome::Unimplemented(Sysno::mprotect as u32),
                Err(errno) => Outcome::Return(error(errno)),
            }
        }
        Sysno::madvise => madvise(ctx, args),
        Sysno::process_madvise => process_madvise(ctx, args),
        _ => return None,
    })
}

fn status(result: Result<(), Errno>) -> Outcome {
    Outcome::Return(result.map_or_else(error, |()| 0))
}

/// x86-64 `mmap(2)`: the byte offset must be page aligned, then
/// `ksys_mmap_pgoff` resolves the descriptor unless `MAP_ANONYMOUS`.
fn mmap<C: Context>(ctx: &mut C, [addr, len, prot, flags, fd, off]: [u64; 6]) -> Outcome {
    let pgoff = match mmap_off_to_pgoff(off) {
        Ok(pgoff) => pgoff,
        Err(errno) => return Outcome::Return(error(errno)),
    };
    // `fget(fd)` takes an `unsigned int`.
    #[allow(clippy::cast_possible_truncation)]
    let target = if flags & MAP_ANONYMOUS == 0 {
        match ctx.mmap_file(fd as u32) {
            Some(target) => Some(target),
            None => return Outcome::Return(error(Errno::EBADF)),
        }
    } else {
        None
    };
    let (file, zero) = match target {
        None => (None, false),
        Some(Mappable::File(file)) => (Some(file), false),
        Some(Mappable::Zero(file)) => (Some(file), true),
        // A driver Linux has and this kernel lacks: its `->mmap` decides.
        Some(Mappable::Unported) => return Outcome::Unimplemented(Sysno::mmap as u32),
    };
    let AddressSpace { mm, env, pages } = ctx.address_space();
    match mm.mmap(env, pages, addr, len, prot, flags, pgoff, file.as_ref()) {
        Ok(Mmap::Mapped(addr)) => Outcome::Return(addr.cast_signed()),
        Ok(Mmap::NeedsFile(mapping)) => file_mapping(ctx, &mapping, zero),
        // shmem or hugetlbfs: Linux serves these.
        Ok(Mmap::Unsupported(_)) => Outcome::Unimplemented(Sysno::mmap as u32),
        Err(errno) => Outcome::Return(error(errno)),
    }
}

/// `mmap_region` of a validated file mapping, then `->mmap`.
///
/// * `/dev/zero` (`mmap_zero`): a private mapping is anonymous
///   (`vma_set_anonymous`); a shared one is `shmem_zero_setup`, not ported.
///   shortcut: the VMA does not keep `vm_file`, so only `/proc/self/maps`
///   (which does not exist here) and the segfault line's ` in zero[...]`
///   could tell it from plain anonymous memory; the latter stops loudly once
///   such a mapping was made ([`crate::vfs::Vfs::zero_mapped`]). Its `pgoff` is
///   the file offset as in Linux, which keeps it from merging with its
///   neighbours.
/// * a tmpfs file (`shmem_mmap`): private mappings fault their pages in from
///   the file ([`crate::vfs::mapping`]); a `MAP_SHARED` mapping that can write
///   needs pages shared with the file and is not ported.
/// * `MAP_POPULATE`/`MAP_LOCKED` on a tmpfs file stops loudly: `mm_populate`
///   would COW-fault a writable private mapping at once, taking the file's
///   current contents, which a first-touch copy cannot reproduce.
fn file_mapping<C: Context>(ctx: &mut C, m: &FileMapping, zero: bool) -> Outcome {
    let unimplemented = Outcome::Unimplemented(Sysno::mmap as u32);
    if m.vm_flags.contains(VmFlags::SHARED) {
        return unimplemented;
    }
    if zero {
        let AddressSpace { mm, env, pages } = ctx.address_space();
        return match mm.mmap_region(env, pages, None, m.addr, m.len, m.vm_flags, m.pgoff) {
            Ok(addr) => {
                if m.populate != 0 {
                    mm.populate(pages, addr, m.populate);
                }
                ctx.files().vfs.note_zero_mapping();
                Outcome::Return(addr.cast_signed())
            }
            Err(errno) => Outcome::Return(error(errno)),
        };
    }
    // (mm_populate never runs when `->mmap` fails.)
    if m.populate != 0 && m.file.mmap_error.is_none() {
        return unimplemented;
    }
    // The pin that keeps the file alive for the VMA needs its slot before the
    // mapping is committed.
    if let Err(errno) = ctx.files().vfs.reserve_pin() {
        return Outcome::Return(error(errno));
    }
    let AddressSpace { mm, env, pages } = ctx.address_space();
    match mm.mmap_region_with(
        env,
        pages,
        Some(m.file.id),
        m.addr,
        m.len,
        m.vm_flags,
        m.pgoff,
        m.file.mmap_error,
    ) {
        Ok(addr) => {
            let Files { vfs, owner, .. } = ctx.files();
            vfs.pin(owner, m.file.id);
            // shmem_mmap: file_accessed(file).
            ctx.files().vfs.file_accessed(m.file.id);
            Outcome::Return(addr.cast_signed())
        }
        Err(errno) => Outcome::Return(error(errno)),
    }
}

/// `fput(vma->vm_file)` for every file no VMA maps any more.
/// shortcut: O(pins x VMAs) per call (skipped when nothing is pinned); keep a
/// per-description VMA count when programs hold many file mappings.
pub(super) fn unpin_unmapped<C: Context>(ctx: &mut C) {
    let owner = ctx.files().owner;
    let mut index = ctx.files().vfs.pin_count();
    while index > 0 {
        index -= 1;
        if ctx.files().vfs.pin_owner(index) != owner {
            continue;
        }
        let id = ctx.files().vfs.pin_id(index);
        let AddressSpace { mm, .. } = ctx.address_space();
        if !mm.vmas().iter().any(|vma| vma.file == Some(id)) {
            ctx.files().vfs.unpin(index);
        }
    }
}

/// `SYSCALL_DEFINE3(madvise)`: `do_madvise` for the caller's address space. The checks and the
/// walk are the model's ([`crate::mm::madvise_range`], [`crate::mm::Mm::madvise`]);
/// `MADV_POPULATE_*` faults the pages in through the task's own user-memory view.
fn madvise<C: Context>(ctx: &mut C, [start, len_in, behavior, ..]: [u64; 6]) -> Outcome {
    // `int behavior`.
    #[allow(clippy::cast_possible_truncation)]
    let behavior = (behavior as u32).cast_signed();
    let end = match madvise_range(start, len_in, behavior) {
        Ok(Some(end)) => end,
        Ok(None) => return Outcome::Return(0),
        Err(errno) => return Outcome::Return(error(errno)),
    };
    if behavior == MADV_POPULATE_READ || behavior == MADV_POPULATE_WRITE {
        return populate(ctx, start, end, behavior == MADV_POPULATE_WRITE);
    }
    // A private `/dev/zero` mapping is anonymous memory here but has `vm_file` in Linux, which
    // `MADV_REMOVE` (`EACCES`, not `EINVAL`) and `MADV_WIPEONFORK` (`EINVAL`) look at.
    if (behavior == MADV_REMOVE || behavior == MADV_WIPEONFORK) && ctx.files().vfs.zero_mapped() {
        return Outcome::Unimplemented(Sysno::madvise as u32);
    }
    let AddressSpace { mm, env, pages } = ctx.address_space();
    match mm.madvise(env, pages, start, end, behavior) {
        Ok(()) => Outcome::Return(0),
        Err(Madvise::Errno(errno)) => Outcome::Return(error(errno)),
        Err(Madvise::Unsupported(_)) => Outcome::Unimplemented(Sysno::madvise as u32),
    }
}

/// `madvise_populate`: `faultin_page_range` one VMA at a time. Each page is faulted in as the
/// task's own kernel access would be (`FaultPages`: a read maps the zero page or the file's
/// page, a write makes the private copy), which is what `handle_mm_fault` does for `gup`.
fn populate<C: Context>(ctx: &mut C, start: u64, end: u64, write: bool) -> Outcome {
    let pkru = ctx.pkru();
    let mut at = start;
    while at < end {
        let span_end = {
            let AddressSpace { mm, env, .. } = ctx.address_space();
            let env = Env { pkru, ..*env };
            match mm.populate_span(&env, at, end, write) {
                Ok(span_end) => span_end,
                Err(errno) => return Outcome::Return(error(errno)),
            }
        };
        while at < span_end {
            if ctx.page(at, write).is_none() {
                let AddressSpace { mm, pages, .. } = ctx.address_space();
                return Outcome::Return(error(mm.populate_error(&*pages, at)));
            }
            at += PAGE_SIZE;
        }
    }
    Outcome::Return(0)
}

/// `SYSCALL_DEFINE5(process_madvise)`: `flags` must be 0, the vector is imported (`ITER_DEST`),
/// then `pidfd_get_task` wants a pidfd. No pidfd exists here (`pidfd_open` and `CLONE_PIDFD` stop
/// the kernel), so a descriptor that is not one is `EBADF`, as in Linux for any other file or a
/// closed descriptor; nothing after that step can be reached.
fn process_madvise<C: Context>(
    ctx: &mut C,
    [_pidfd, vec, vlen, _behavior, flags, _]: [u64; 6],
) -> Outcome {
    // `unsigned int flags`.
    if flags & 0xffff_ffff != 0 {
        return Outcome::Return(error(Errno::EINVAL));
    }
    if let Err(errno) = import_segs(ctx, vec, vlen) {
        return Outcome::Return(error(errno));
    }
    Outcome::Return(error(Errno::EBADF))
}

#[cfg(test)]
mod tests;
