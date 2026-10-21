// SPDX-License-Identifier: GPL-2.0-only
// Linux 6.18.57 (2ff600d29ee478d0a8d46ef8a58afb5e038fe692): mm/madvise.c (`madvise_walk_vmas`,
// `madvise_vma_behavior`, `madvise_update_vma`, `madvise_behavior_valid`, `is_valid_madvise`,
// `madvise_should_skip`, `madvise_do_behavior`, `madvise_dontneed_free`,
// `madvise_dontneed_free_valid_vma`, `madvise_free_single_vma`, `madvise_remove`,
// `madvise_cold`, `madvise_pageout`, `can_madv_lru_vma`, `madvise_willneed`,
// `madvise_guard_install`, `madvise_guard_remove`, `is_valid_guard_vma`, `madvise_populate`),
// mm/gup.c (`faultin_page_range`, `__get_user_pages` with `FOLL_MADV_POPULATE`,
// `check_vma_flags`, `faultin_page`), arch/x86/include/asm/pkeys.h
// (`arch_vma_access_permitted`), include/uapi/asm-generic/mman-common.h (`MADV_*`). GPL-2.0.
// Transformation: the mmap-lock / per-VMA-lock choice and the mmu_gather batching are gone (one
// task holds the address-space lock); `userfaultfd_remove`, `vfs_fadvise`, the swap-in walks and
// the LRU/reclaim hints have nothing to act on here (no userfaultfd, tmpfs and anonymous
// memory only, no swap, no reclaim) and their effect on the result is reproduced instead of
// their work; `CONFIG_ANON_VMA_NAME`, `CONFIG_KSM`, `CONFIG_TRANSPARENT_HUGEPAGE`,
// `CONFIG_MEMORY_FAILURE` and sealing are off in the declared configuration.
#![forbid(unsafe_code)]
//! `madvise(2)`: argument checks, the walk over the VMAs of the range and every advice the
//! declared configuration has. Page-table effects go through [`UserPages`].
//!
//! # Contract
//! * Context: task context holding the address-space lock; nothing sleeps. The only allocation
//!   is the VMA vector (`Vec::try_reserve` in the split/merge primitives) and page tables
//!   behind [`UserPages::install_guards`]; both report `ENOMEM`, never panic.
//! * Failure atomicity is Linux's: advice is applied to one VMA at a time and the first error
//!   ends the walk with what was done kept; a hole in the range is `ENOMEM` once the rest has
//!   been done.
//! * `MADV_FREE` leaves the pages alone. Linux marks them lazily freeable and frees them only
//!   under memory pressure; a kernel without reclaim never reaches that state, and until then
//!   a read returns the old data (checked on the reference, `madvise` oracle group).
//! * Not answered, stopped loudly ([`Unsupported`]): the advice Linux acts on with objects this
//!   kernel lacks. `MADV_POPULATE_*` is the system call layer's (it faults the pages in through
//!   the task's own user-memory view, see [`Mm::populate_span`]).

use syscalls::Errno;

use super::{
    env::Env,
    fault::{PF_WRITE, pkru_denies_key0},
    flags::{
        MADV_COLD, MADV_DODUMP, MADV_DOFORK, MADV_DONTDUMP, MADV_DONTFORK, MADV_DONTNEED,
        MADV_DONTNEED_LOCKED, MADV_FREE, MADV_GUARD_INSTALL, MADV_GUARD_REMOVE, MADV_KEEPONFORK,
        MADV_NORMAL, MADV_PAGEOUT, MADV_POPULATE_READ, MADV_POPULATE_WRITE, MADV_RANDOM,
        MADV_REMOVE, MADV_SEQUENTIAL, MADV_WILLNEED, MADV_WIPEONFORK, PAGE_SHIFT, VmFlags,
        offset_in_page, page_align,
    },
    pt::{Pte, UserPages},
    space::{Mm, Vma},
};

/// What the declared configuration cannot answer; the caller stops loudly.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Unsupported {
    /// `MADV_PAGEOUT` over resident page-cache pages of a file mapping: reclaim would unmap
    /// them (the resident-set counters show it) unless another mapping shares them, which
    /// needs the rmap this kernel does not have.
    PageoutFilePages,
    /// `MADV_REMOVE` of a shared, writable file mapping: no such mapping can exist yet.
    RemoveSharedFile,
}

/// The result of a request that did not succeed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Madvise {
    Errno(Errno),
    Unsupported(Unsupported),
}

impl From<Unsupported> for Madvise {
    fn from(gap: Unsupported) -> Self {
        Self::Unsupported(gap)
    }
}

impl From<Errno> for Madvise {
    fn from(errno: Errno) -> Self {
        Self::Errno(errno)
    }
}

/// `madvise_behavior_valid` under the declared configuration (`CONFIG_KSM`,
/// `CONFIG_TRANSPARENT_HUGEPAGE` and `CONFIG_MEMORY_FAILURE` are off: `MADV_MERGEABLE`,
/// `MADV_UNMERGEABLE`, `MADV_HUGEPAGE`, `MADV_NOHUGEPAGE`, `MADV_COLLAPSE`, `MADV_HWPOISON` and
/// `MADV_SOFT_OFFLINE` are not valid).
#[must_use]
pub const fn madvise_behavior_valid(behavior: i32) -> bool {
    matches!(
        behavior,
        MADV_NORMAL
            | MADV_RANDOM
            | MADV_SEQUENTIAL
            | MADV_WILLNEED
            | MADV_DONTNEED
            | MADV_FREE
            | MADV_REMOVE
            | MADV_DONTFORK
            | MADV_DOFORK
            | MADV_DONTDUMP
            | MADV_DODUMP
            | MADV_WIPEONFORK
            | MADV_KEEPONFORK
            | MADV_COLD
            | MADV_PAGEOUT
            | MADV_POPULATE_READ
            | MADV_POPULATE_WRITE
            | MADV_DONTNEED_LOCKED
            | MADV_GUARD_INSTALL
            | MADV_GUARD_REMOVE
    )
}

/// `madvise_should_skip` + `is_valid_madvise` + the range of `madvise_do_behavior`: the end
/// of `[start, start + PAGE_ALIGN(len_in))`, or `None` when nothing is to be done (length 0).
///
/// # Errors
/// `EINVAL`: an invalid advice, an unaligned `start`, a length that wraps when rounded up, or
/// an end that wraps.
pub fn madvise_range(start: u64, len_in: u64, behavior: i32) -> Result<Option<u64>, Errno> {
    if !madvise_behavior_valid(behavior) || offset_in_page(start) != 0 {
        return Err(Errno::EINVAL);
    }
    // "Check to see whether len was rounded up from small -ve to zero."
    let len = page_align(len_in).ok_or(Errno::EINVAL)?;
    let end = start.checked_add(len).ok_or(Errno::EINVAL)?;
    Ok((len != 0).then_some(end))
}

impl Mm {
    /// `madvise_walk_vmas` over `[start, end)` (both page aligned, `start < end`, as
    /// [`madvise_range`] returns) for every advice but `MADV_POPULATE_*` (refused with `EINVAL`).
    ///
    /// # Errors
    /// Linux's: `ENOMEM` for a hole in the range (after the rest was done) or a failed split,
    /// `EAGAIN` for a flag change that could not split or merge, `EINVAL`/`EACCES` as each
    /// advice says; [`Unsupported`] for what cannot be answered (nothing at or after that VMA
    /// was changed).
    pub fn madvise(
        &mut self,
        env: &Env,
        pt: &mut (impl UserPages + ?Sized),
        start: u64,
        end: u64,
        behavior: i32,
    ) -> Result<(), Madvise> {
        debug_assert!(madvise_behavior_valid(behavior) && start < end);
        let mut hole = false;
        let (mut at, mut idx) = (start, self.lower(start));
        loop {
            let Some(v) = self.vmas.get(idx).copied() else {
                return Err(Errno::ENOMEM.into());
            };
            // A gap between the VMAs of the range does not abort; ENOMEM is remembered.
            if at < v.start {
                hole = true;
                at = v.start;
                if at >= end {
                    break;
                }
            }
            let segment_end = v.end.min(end);
            let done = self.vma_behavior(env, pt, idx, at, segment_end, behavior)?;
            // The VMA may have merged with its neighbour: continue after it.
            let vma_end = self.vmas[done].end;
            at = segment_end.max(vma_end);
            if at >= end {
                break;
            }
            idx = self.lower(vma_end);
        }
        if hole {
            Err(Errno::ENOMEM.into())
        } else {
            Ok(())
        }
    }

    /// `madvise_vma_behavior` for `[start, end)` inside `vmas[idx]`; the index of the VMA that
    /// covers the range afterwards (a flag change can split or merge).
    fn vma_behavior(
        &mut self,
        env: &Env,
        pt: &mut (impl UserPages + ?Sized),
        idx: usize,
        start: u64,
        end: u64,
        behavior: i32,
    ) -> Result<usize, Madvise> {
        let v = self.vmas[idx];
        let pages = (end - start) >> PAGE_SHIFT;
        // (`can_madvise_modify`: no VMA is sealed, mseal(2) is not implemented.)
        match behavior {
            MADV_REMOVE => remove(&v)?,
            // `madvise_willneed` answers 0 whatever `vfs_fadvise` did: the swap-in walk finds no
            // swap entries and tmpfs pages are always cached.
            MADV_WILLNEED => {}
            MADV_COLD => lru_vma(&v)?,
            MADV_PAGEOUT => {
                lru_vma(&v)?;
                // (`can_do_file_pageout`: the only user is root.) Reclaim without swap keeps
                // anonymous pages but unmaps clean page-cache pages.
                if !v.is_anonymous() && pt.resident_file_pages(start, pages) != 0 {
                    return Err(Unsupported::PageoutFilePages.into());
                }
            }
            MADV_FREE | MADV_DONTNEED | MADV_DONTNEED_LOCKED => {
                dontneed_free(pt, &v, start, pages, behavior)?;
            }
            MADV_GUARD_INSTALL => return self.guard_install(pt, idx, start, pages),
            MADV_GUARD_REMOVE => {
                // Removing is non-destructive, so a locked VMA is fine.
                if v.flags.intersects(VmFlags::SPECIAL | VmFlags::HUGETLB) {
                    return Err(Errno::EINVAL.into());
                }
                pt.remove_guards(start, pages);
            }
            _ => return self.update_flags(env, idx, start, end, behavior),
        }
        Ok(idx)
    }

    /// The advice that only changes `vm_flags`: `madvise_vma_behavior`'s `switch`, then
    /// `madvise_update_vma`. `-ENOMEM` becomes `-EAGAIN` ("kernel resources, such as slab, are
    /// temporarily unavailable").
    fn update_flags(
        &mut self,
        env: &Env,
        idx: usize,
        start: u64,
        end: u64,
        behavior: i32,
    ) -> Result<usize, Madvise> {
        let v = self.vmas[idx];
        let old = v.flags;
        let mut new = match behavior {
            MADV_NORMAL => old & !(VmFlags::RAND_READ | VmFlags::SEQ_READ),
            MADV_SEQUENTIAL => (old & !VmFlags::RAND_READ) | VmFlags::SEQ_READ,
            MADV_RANDOM => (old & !VmFlags::SEQ_READ) | VmFlags::RAND_READ,
            MADV_DONTFORK => old | VmFlags::DONTCOPY,
            MADV_DOFORK => {
                if old.contains(VmFlags::IO) {
                    return Err(Errno::EINVAL.into());
                }
                old & !VmFlags::DONTCOPY
            }
            MADV_WIPEONFORK => {
                // "MADV_WIPEONFORK is only supported on anonymous memory."
                if v.file.is_some() || old.contains(VmFlags::SHARED) {
                    return Err(Errno::EINVAL.into());
                }
                old | VmFlags::WIPEONFORK
            }
            MADV_KEEPONFORK => {
                if old.contains(VmFlags::DROPPABLE) {
                    return Err(Errno::EINVAL.into());
                }
                old & !VmFlags::WIPEONFORK
            }
            MADV_DONTDUMP => old | VmFlags::DONTDUMP,
            MADV_DODUMP => {
                // (A hugetlb VMA may be dumped whatever its flags; none exists here.)
                if old.intersects(VmFlags::SPECIAL) || old.contains(VmFlags::DROPPABLE) {
                    return Err(Errno::EINVAL.into());
                }
                old & !VmFlags::DONTDUMP
            }
            // `MADV_POPULATE_*` is the system call layer's (`madvise_do_behavior` runs it before
            // the walk); the model refuses it instead of guessing an action.
            _ => return Err(Errno::EINVAL.into()),
        };
        // madvise_update_vma
        if new == old {
            return Ok(idx);
        }
        let at = self
            .vma_modify(env, idx, start, end, &mut new)
            .map_err(|errno| {
                if errno == Errno::ENOMEM {
                    Errno::EAGAIN
                } else {
                    errno
                }
            })?;
        self.vmas[at].flags = new;
        Ok(at)
    }

    /// `madvise_guard_install`: the whole VMA may now hold guards (`VM_MAYBE_GUARD`, set before
    /// anything else and kept if the rest fails), then every page of the range is a marker.
    fn guard_install(
        &mut self,
        pt: &mut (impl UserPages + ?Sized),
        idx: usize,
        start: u64,
        pages: u64,
    ) -> Result<usize, Madvise> {
        let flags = self.vmas[idx].flags;
        // `is_valid_guard_vma(vma, allow_locked = false)`
        if flags.intersects(VmFlags::SPECIAL | VmFlags::HUGETLB | VmFlags::LOCKED) {
            return Err(Errno::EINVAL.into());
        }
        self.vmas[idx].flags |= VmFlags::MAYBE_GUARD;
        // "If anonymous and we are establishing page tables the VMA ought to have an anon_vma."
        if self.vmas[idx].is_anonymous() {
            self.anon_vma_prepare(idx);
        }
        pt.install_guards(start, pages).map_err(|_| Errno::ENOMEM)?;
        Ok(idx)
    }

    /// The first step of `faultin_page_range` for the page at `at` (page aligned, below `end`):
    /// the VMA must exist (`ENOMEM`: the populate loop does not skip holes) and permit the
    /// access (`check_vma_flags` without `FOLL_FORCE`, any failure is `EINVAL`). Returns the end
    /// of the span of that VMA to fault in, `min(vma.end, end)`; the caller faults each page of
    /// it in through the task's user-memory view and calls [`Mm::populate_error`] for the page
    /// that fails.
    ///
    /// # Errors
    /// `ENOMEM` or `EINVAL`.
    pub fn populate_span(&self, env: &Env, at: u64, end: u64, write: bool) -> Result<u64, Errno> {
        let v = self
            .vmas
            .get(self.lower(at))
            .filter(|v| v.start <= at)
            .ok_or(Errno::ENOMEM)?;
        let needed = if write { VmFlags::WRITE } else { VmFlags::READ };
        // `arch_vma_access_permitted`: a data access (never an instruction fetch).
        let error_code = if write { PF_WRITE } else { 0 };
        if v.flags.intersects(VmFlags::IO | VmFlags::PFNMAP)
            || !v.flags.contains(needed)
            || (env.ospke && pkru_denies_key0(error_code, env.pkru))
        {
            return Err(Errno::EINVAL);
        }
        Ok(v.end.min(end))
    }

    /// Why the page at `at` of a span from [`Mm::populate_span`] could not be faulted in:
    /// `faultin_page`'s `vm_fault_to_errno` of the fault. A guard marker is `VM_FAULT_SIGSEGV`
    /// and a page past the end of a file `VM_FAULT_SIGBUS`: both `EFAULT`; running out of
    /// frames is `ENOMEM`.
    ///
    /// shortcut: a frame shortage in a file mapping reads as the `SIGBUS` it cannot be told
    /// from here; upgrade by returning the fault outcome from the user-memory view.
    #[must_use]
    pub fn populate_error(&self, pt: &(impl UserPages + ?Sized), at: u64) -> Errno {
        let file = self
            .vmas
            .get(self.lower(at))
            .is_some_and(|v| v.start <= at && !v.is_anonymous());
        if pt.lookup(at) == Pte::Guard || file {
            Errno::EFAULT
        } else {
            Errno::ENOMEM
        }
    }
}

/// `madvise_remove` before the file operation.
fn remove(v: &Vma) -> Result<(), Madvise> {
    if v.flags.contains(VmFlags::LOCKED) || v.file.is_none() {
        return Err(Errno::EINVAL.into());
    }
    // `vma_is_shared_maywrite`
    if !v.flags.contains(VmFlags::SHARED | VmFlags::MAYWRITE) {
        return Err(Errno::EACCES.into());
    }
    Err(Unsupported::RemoveSharedFile.into())
}

/// `can_madv_lru_vma`.
fn lru_vma(v: &Vma) -> Result<(), Madvise> {
    if v.flags
        .intersects(VmFlags::LOCKED | VmFlags::PFNMAP | VmFlags::HUGETLB)
    {
        Err(Errno::EINVAL.into())
    } else {
        Ok(())
    }
}

/// `madvise_dontneed_free` for a VMA that is not hugetlb.
fn dontneed_free(
    pt: &mut (impl UserPages + ?Sized),
    v: &Vma,
    start: u64,
    pages: u64,
    behavior: i32,
) -> Result<(), Madvise> {
    // `madvise_dontneed_free_valid_vma`
    let mut forbidden = VmFlags::PFNMAP;
    if behavior != MADV_DONTNEED_LOCKED {
        forbidden |= VmFlags::LOCKED;
    }
    if v.flags.intersects(forbidden) {
        return Err(Errno::EINVAL.into());
    }
    if behavior == MADV_FREE {
        // `madvise_free_single_vma`: "MADV_FREE works for only anon vma at the moment."
        if !v.is_anonymous() {
            return Err(Errno::EINVAL.into());
        }
        return Ok(());
    }
    // `zap_page_range_single_batched` with `even_cows`: private copies go too, so a private
    // file page reverts to the file and an anonymous page to a zero page. Guard markers stay.
    pt.zap(start, pages);
    Ok(())
}
