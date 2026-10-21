// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: mm/mmap.c (`SYSCALL_DEFINE1(brk)`,
// `ksys_mmap_pgoff`, `SYSCALL_DEFINE2(munmap)`), arch/x86/kernel/sys_x86_64.c
// (`SYSCALL_DEFINE6(mmap)`), mm/mprotect.c (`SYSCALL_DEFINE3(mprotect)`),
// mm/madvise.c (`do_madvise`, `is_valid_madvise`, `madvise_should_skip`,
// `madvise_walk_vmas`, `madvise_vma_behavior` for `MADV_NORMAL`),
// drivers/tty/tty_io.c (`console_fops`: no `->mmap`). All GPL-2.0.
// Transformation: the decisions are `crate::mm`'s (this file decodes the
// register arguments, resolves the file descriptor and maps the model's
// outcomes to a return value); a request Linux serves with a shared file page,
// shmem or hugetlb object this kernel does not have yet ends in `Unimplemented`.
#![forbid(unsafe_code)]
//! Memory syscalls: `brk`, `mmap`, `munmap`, `mprotect`, `madvise`.
//!
//! Context: the one task, address-space lock held by construction (the
//! binary's `Process` lock). Heap storage for the VMA vector is reserved by
//! the model before it touches the page tables.
//!
//! * Outcomes that need an object this kernel lacks are `Unimplemented` (loud
//!   stop), never an errno Linux would not return: `MAP_SHARED|MAP_ANONYMOUS`
//!   (shmem), `MAP_HUGETLB` (hugetlbfs), a `MAP_SHARED` mapping of a file that
//!   can be written through it or of `/dev/zero` (pages shared with the file or
//!   with `shmem_zero_setup`), a device whose driver is not ported and every
//!   `madvise` behaviour except `MADV_NORMAL`, and a tmpfs file mapping with
//!   `MAP_POPULATE`/`MAP_LOCKED` (`mm_populate` would take the private copies
//!   at `mmap` time, which the copy-at-fault model cannot reproduce without
//!   the page cache). `MAP_PRIVATE` mappings of tmpfs files (and read-only
//!   `MAP_SHARED` ones) are served by [`crate::vfs::mapping`].
//! * shortcut: `mm_populate` of `MAP_POPULATE|MAP_LOCKED` faults anonymous
//!   pages in exactly like Linux; `RLIMIT_MEMLOCK` and friends come from the
//!   fixed `INIT_RLIMITS` in `mm::Env`, not from `setrlimit`.

use super::{AddressSpace, Context, Files, Outcome, error};
use crate::{
    mm::{FileMapping, MAP_ANONYMOUS, Mmap, PAGE_SIZE, VmFlags, mmap_off_to_pgoff},
    vfs::mapping::Mappable,
};
use syscalls::{Errno, Sysno};

pub(super) fn dispatch<C: Context>(ctx: &mut C, sysno: Sysno, args: [u64; 6]) -> Option<Outcome> {
    Some(match sysno {
        Sysno::brk | Sysno::mmap | Sysno::munmap => {
            let outcome = match sysno {
                Sysno::brk => {
                    let AddressSpace { mm, env, pages } = ctx.address_space();
                    Outcome::Return(mm.brk(env, pages, args[0]).cast_signed())
                }
                Sysno::mmap => mmap(ctx, args),
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
    if m.populate != 0 {
        return unimplemented;
    }
    // The pin that keeps the file alive for the VMA needs its slot before the
    // mapping is committed.
    if let Err(errno) = ctx.files().vfs.reserve_pin() {
        return Outcome::Return(error(errno));
    }
    let AddressSpace { mm, env, pages } = ctx.address_space();
    match mm.mmap_region(
        env,
        pages,
        Some(m.file.id),
        m.addr,
        m.len,
        m.vm_flags,
        m.pgoff,
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

/// `MADV_*` values `madvise_behavior_valid` accepts under the declared
/// configuration (`CONFIG_KSM`, `CONFIG_TRANSPARENT_HUGEPAGE` and
/// `CONFIG_MEMORY_FAILURE` are off, so MERGEABLE/UNMERGEABLE, HUGEPAGE/
/// NOHUGEPAGE/COLLAPSE and `HWPOISON`/`SOFT_OFFLINE` are `-EINVAL`).
const fn madvise_behavior_valid(behavior: i32) -> bool {
    matches!(
        behavior,
        0..=4 | 8..=11 | 16..=24 | 102 | 103 // 0-2 hints, 3 WILLNEED, 4 DONTNEED, 8 FREE, 9 REMOVE, 10/11 FORK, 16-24, guard
    )
}

const MADV_NORMAL: i32 = 0;

/// `madvise(2)`: `is_valid_madvise` and `madvise_should_skip`, then the walk
/// over the VMAs of the range. Only `MADV_NORMAL` is implemented: it clears
/// `VM_RAND_READ|VM_SEQ_READ`, which no VMA here can have set, so it changes
/// nothing; its result is `madvise_walk_vmas`' (`-ENOMEM` for any hole).
fn madvise<C: Context>(ctx: &mut C, [start, len_in, behavior, ..]: [u64; 6]) -> Outcome {
    // `int behavior`.
    #[allow(clippy::cast_possible_truncation)]
    let behavior = (behavior as u32).cast_signed();
    if !madvise_behavior_valid(behavior) || start & (PAGE_SIZE - 1) != 0 {
        return Outcome::Return(error(Errno::EINVAL));
    }
    // PAGE_ALIGN(len_in) wrapped to zero from a small negative length.
    let Some(aligned) = len_in
        .checked_add(PAGE_SIZE - 1)
        .map(|n| n & !(PAGE_SIZE - 1))
    else {
        return Outcome::Return(error(Errno::EINVAL));
    };
    if start.checked_add(aligned).is_none() {
        return Outcome::Return(error(Errno::EINVAL));
    }
    if aligned == 0 {
        return Outcome::Return(0);
    }
    if behavior != MADV_NORMAL {
        return Outcome::Unimplemented(Sysno::madvise as u32);
    }
    let end = start + aligned;
    let AddressSpace { mm, .. } = ctx.address_space();
    // madvise_walk_vmas: carry on past a hole, remember ENOMEM.
    let mut at = start;
    let mut unmapped = 0;
    loop {
        let Some(vma) = mm.find_vma(at) else {
            return Outcome::Return(error(Errno::ENOMEM));
        };
        if at < vma.start {
            unmapped = error(Errno::ENOMEM);
            at = vma.start;
            if at >= end {
                break;
            }
        }
        if vma.end.min(end) >= end {
            break;
        }
        at = vma.end;
    }
    Outcome::Return(unmapped)
}

#[cfg(test)]
mod tests;
