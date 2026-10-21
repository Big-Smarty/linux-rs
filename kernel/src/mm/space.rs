// SPDX-License-Identifier: GPL-2.0-only
// Linux 6.18.57 (2ff600d29ee478d0a8d46ef8a58afb5e038fe692): mm/vma.c
// (`__split_vma`/`split_vma`, `can_vma_merge_{left,right}`,
// `vma_merge_new_range`, `vma_merge_existing_range`, `vma_modify`,
// `vms_gather_munmap_vmas`, `vms_complete_munmap_vmas`, `anon_vma_compatible`,
// `find_mergeable_anon_vma`, `acct_stack_growth`, `expand_downwards`,
// `insert_vm_struct`), mm/mmap.c (`find_vma`, `find_vma_prev`,
// `may_expand_vm`, `vm_stat_account`, `mlock_future_ok`), include/linux/mm.h
// (`vm_start_gap`, `vm_end_gap`). GPL-2.0.
// Transformation: the maple tree and the `vma_iterator` become a sorted
// `Vec<Vma>` (the same first-VMA-with-end>addr lookup); `anon_vma` objects
// become an identity (`Option<u64>`) because only their equality is
// observable to merging; locks, RCU, rmap, hooks, mempolicy, userfaultfd and
// sealing are absent (single task, anonymous and file identity only). A
// fallible allocation (`Vec::try_reserve`) replaces every `kmem_cache_alloc`
// and `vma_iter_prealloc`.
#![forbid(unsafe_code)]
//! The address-space model: a VMA set and the primitive operations Linux's
//! `mm/vma.c` builds `mmap`, `munmap`, `mprotect`, `brk` and stack growth from.
//!
//! # Contract
//! * Context: task context holding the address-space lock (there is one task).
//!   Nothing here sleeps; the only allocation is the VMA vector, grown with
//!   `try_reserve` and reported as `ENOMEM` (never a panic or abort).
//! * Invariant: `vmas` is sorted by `start`, non-empty ranges, page aligned,
//!   pairwise disjoint (`start < end <= next.start`), all below `TASK_SIZE`.
//! * Failure atomicity: every primitive that can fail reserves its storage
//!   before it changes anything, so a failed primitive changes nothing. The
//!   composed system calls fail between primitives exactly where Linux does
//!   (a failed second split leaves the first split, `mprotect` over several
//!   VMAs leaves the finished prefix) and are documented where they do.

use alloc::vec::Vec;
use core::{
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicU64, Ordering},
};

use syscalls::Errno;

use super::{
    env::Env,
    flags::{PAGE_SHIFT, VmFlags, is_data_mapping, is_exec_mapping, is_stack_mapping, page_align},
};
use crate::usercopy::TASK_SIZE_MAX;

/// `TASK_SIZE` and `DEFAULT_MAP_WINDOW` for a 64-bit task under 4-level paging.
pub const TASK_SIZE: u64 = TASK_SIZE_MAX;

/// One `vm_area_struct`, reduced to the fields observable through the memory
/// system calls, `/proc/self/maps` and merging.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Vma {
    pub start: u64,
    pub end: u64,
    pub flags: VmFlags,
    /// `vm_pgoff`: the file page offset, or for an anonymous VMA the virtual
    /// page number of `start` (so splits and merges reuse the file checks).
    pub pgoff: u64,
    /// `vm_file` identity ([`super::FileInfo::id`]); `None` is anonymous.
    pub file: Option<u64>,
    /// `anon_vma` identity; `None` until the first write fault.
    pub anon: Option<u64>,
}

impl Vma {
    /// `vma_pages`.
    #[must_use]
    pub const fn pages(&self) -> u64 {
        (self.end - self.start) >> PAGE_SHIFT
    }
    /// `vma_is_anonymous`: no `vm_ops`. (Shared-anonymous shmem VMAs have a
    /// file in Linux and are not created here.)
    #[must_use]
    pub const fn is_anonymous(&self) -> bool {
        self.file.is_none()
    }
    /// `vma_is_accessible`.
    #[must_use]
    pub const fn is_accessible(&self) -> bool {
        self.flags.intersects(VmFlags::ACCESS)
    }
}

/// The sorted VMA vector, with a version that moves whenever it is borrowed
/// mutably (so a change can never be missed, and a borrow that changes nothing
/// costs only a spurious difference). `/proc` copies the vector when the
/// version moved and shares its last copy otherwise ([`Mm::vma_stamp`]).
#[derive(Debug, Default)]
pub(super) struct VmaList {
    list: Vec<Vma>,
    version: u64,
}

impl Deref for VmaList {
    type Target = Vec<Vma>;
    fn deref(&self) -> &Vec<Vma> {
        &self.list
    }
}

impl DerefMut for VmaList {
    fn deref_mut(&mut self) -> &mut Vec<Vma> {
        self.version += 1;
        &mut self.list
    }
}

/// Numbers the address spaces, so two different ones never share a
/// [`Mm::vma_stamp`] (an `execve` builds a new one).
static NEXT_MM_ID: AtomicU64 = AtomicU64::new(1);

/// The address space of the one task.
#[derive(Debug)]
pub struct Mm {
    pub(super) vmas: VmaList,
    /// Identifies this address space for [`Mm::vma_stamp`].
    id: u64,
    /// `mm->mmap_base`: top of the top-down area.
    pub mmap_base: u64,
    /// `mm->mmap_legacy_base`: bottom of the legacy area.
    pub mmap_legacy_base: u64,
    /// `MMF_TOPDOWN`.
    pub topdown: bool,
    pub start_brk: u64,
    pub brk: u64,
    pub start_data: u64,
    pub end_data: u64,
    /// `mm->start_code`, `end_code`: the executable `PT_LOAD`s' extent.
    pub start_code: u64,
    pub end_code: u64,
    /// `mm->start_stack`: the user stack pointer at the entry of the program.
    pub start_stack: u64,
    /// `mm->arg_start`, `arg_end`, `env_start`, `env_end`: the argument and
    /// environment strings (`/proc/<pid>/cmdline`, `environ`).
    pub arg_start: u64,
    pub arg_end: u64,
    pub env_start: u64,
    pub env_end: u64,
    /// `mm->hiwater_vm` (pages): the highest `total_vm` seen.
    pub hiwater_vm: u64,
    /// `mm->total_vm`, `data_vm`, `exec_vm`, `stack_vm`, `locked_vm` (pages).
    pub total_vm: u64,
    pub data_vm: u64,
    pub exec_vm: u64,
    pub stack_vm: u64,
    pub locked_vm: u64,
    /// `mm->def_flags` (`mlockall(MCL_FUTURE)` is not implemented: stays empty).
    pub def_flags: VmFlags,
    next_anon: u64,
}

pub(super) const fn enomem<T>() -> Result<T, Errno> {
    Err(Errno::ENOMEM)
}

impl Mm {
    /// An empty address space with the x86-64 layout of `arch_pick_mmap_layout`
    /// (no randomisation: the declared `norandmaps` configuration).
    #[must_use]
    pub fn new(env: &Env) -> Self {
        let (mmap_base, mmap_legacy_base) = super::layout::pick_mmap_base(env);
        Self {
            vmas: VmaList::default(),
            id: NEXT_MM_ID.fetch_add(1, Ordering::Relaxed),
            mmap_base,
            mmap_legacy_base,
            topdown: true,
            start_brk: 0,
            brk: 0,
            start_data: 0,
            end_data: 0,
            start_code: 0,
            end_code: 0,
            start_stack: 0,
            arg_start: 0,
            arg_end: 0,
            env_start: 0,
            env_end: 0,
            hiwater_vm: 0,
            total_vm: 0,
            data_vm: 0,
            exec_vm: 0,
            stack_vm: 0,
            locked_vm: 0,
            def_flags: VmFlags::NONE,
            next_anon: 0,
        }
    }

    /// The VMA half of `dup_mm` / `dup_mmap` for a forked child: the layout,
    /// the program break and every counter are copied, the VMAs are copied in
    /// address order, `mlock` state is not inherited (`VM_LOCKED_MASK` is
    /// cleared on each copy and `locked_vm` starts at 0) and each VMA that has
    /// an `anon_vma` gets a new one of its own (`anon_vma_fork`: the child's
    /// VMAs never share one, so two neighbours that shared it in the parent no
    /// longer merge on that account). A `VM_ACCOUNT` VMA is charged to the
    /// overcommit policy again, as `security_vm_enough_memory_mm` does.
    ///
    /// A `VM_DONTCOPY` VMA (`madvise(MADV_DONTFORK)`) is not copied and its pages come off the
    /// child's counters (`vm_stat_account(mm, flags, -pages)`), without being charged. A
    /// `VM_WIPEONFORK` VMA is copied without an `anon_vma` ("a clean slate": it gets one at the
    /// first write fault); [`Mm::copies_pages`] says its pages stay behind.
    ///
    /// The caller copies the pages (`copy_page_range`): this returns only the model.
    ///
    /// # Errors
    /// `ENOMEM`: the VMA vector cannot be reserved, or the charge is refused.
    /// Nothing of the parent changes.
    pub fn dup(&self, env: &Env) -> Result<Self, Errno> {
        let mut vmas = Vec::new();
        vmas.try_reserve_exact(self.vmas.len())
            .map_err(|_| Errno::ENOMEM)?;
        let mut next_anon = self.next_anon;
        for vma in self.vmas.iter() {
            if vma.flags.contains(VmFlags::DONTCOPY) {
                continue;
            }
            if vma.flags.contains(VmFlags::ACCOUNT) && !env.enough_memory(vma.pages()) {
                return enomem();
            }
            let mut copy = *vma;
            copy.flags = VmFlags(copy.flags.0 & !(VmFlags::LOCKED.0 | VmFlags::LOCKONFAULT.0));
            if copy.flags.contains(VmFlags::WIPEONFORK) {
                copy.anon = None;
            } else if copy.anon.is_some() {
                copy.anon = Some(next_anon);
                next_anon += 1;
            }
            vmas.push_within_capacity(copy).map_err(|_| Errno::ENOMEM)?;
        }
        let mut child = Self {
            vmas: VmaList {
                list: vmas,
                version: 0,
            },
            id: NEXT_MM_ID.fetch_add(1, Ordering::Relaxed),
            mmap_base: self.mmap_base,
            mmap_legacy_base: self.mmap_legacy_base,
            topdown: self.topdown,
            start_brk: self.start_brk,
            brk: self.brk,
            start_data: self.start_data,
            end_data: self.end_data,
            start_code: self.start_code,
            end_code: self.end_code,
            start_stack: self.start_stack,
            arg_start: self.arg_start,
            arg_end: self.arg_end,
            env_start: self.env_start,
            env_end: self.env_end,
            hiwater_vm: self.hiwater_vm,
            total_vm: self.total_vm,
            data_vm: self.data_vm,
            exec_vm: self.exec_vm,
            stack_vm: self.stack_vm,
            locked_vm: 0,
            // mm_init: `def_flags & VM_INIT_DEF_MASK` (include/linux/mm.h:499 is
            // VM_NOHUGEPAGE, which is VM_NONE without CONFIG_TRANSPARENT_HUGEPAGE):
            // VM_LOCKED from mlockall(MCL_FUTURE) never crosses a fork.
            def_flags: VmFlags::NONE,
            next_anon,
        };
        for vma in self
            .vmas
            .iter()
            .filter(|v| v.flags.contains(VmFlags::DONTCOPY))
        {
            child.stat_sub(vma.flags, vma.pages());
        }
        Ok(child)
    }

    /// Whether `fork` copies the pages of a VMA with `flags` into the child: not for
    /// `VM_DONTCOPY` (the VMA is not in the child at all) and not for `VM_WIPEONFORK`
    /// (`if (!(tmp->vm_flags & VM_WIPEONFORK)) copy_page_range()`). Every other populated page
    /// is copied, a guard marker included (`VM_MAYBE_GUARD` is in `VM_COPY_ON_FORK`, and a
    /// marker cannot be rebuilt by a fault).
    #[must_use]
    pub const fn copies_pages(flags: VmFlags) -> bool {
        !flags.intersects(VmFlags(VmFlags::DONTCOPY.0 | VmFlags::WIPEONFORK.0))
    }

    /// `create_elf_tables` / `load_elf_binary`: where the program's stack
    /// pointer and its argument and environment strings are.
    pub fn record_stack(
        &mut self,
        start_stack: u64,
        arg_start: u64,
        arg_end: u64,
        env_start: u64,
        env_end: u64,
    ) {
        self.start_stack = start_stack;
        self.arg_start = arg_start;
        self.arg_end = arg_end;
        self.env_start = env_start;
        self.env_end = env_end;
    }

    /// The VMAs in address order (`/proc/self/maps` order).
    #[must_use]
    pub fn vmas(&self) -> &[Vma] {
        &self.vmas
    }

    /// Names this address space and the state of its VMA vector: equal stamps
    /// mean [`Mm::vmas`] is unchanged (a copy taken earlier is still exact).
    #[must_use]
    pub fn vma_stamp(&self) -> (u64, u64) {
        (self.id, self.vmas.version)
    }
    /// `mm->map_count`.
    #[must_use]
    pub fn map_count(&self) -> u64 {
        self.vmas.len() as u64
    }

    /// Index of the first VMA with `end > addr` (`find_vma`), or `len()`.
    #[must_use]
    pub(super) fn lower(&self, addr: u64) -> usize {
        self.vmas.partition_point(|v| v.end <= addr)
    }

    /// `find_vma`: the first VMA with `end > addr`.
    #[must_use]
    pub fn find_vma(&self, addr: u64) -> Option<&Vma> {
        self.vmas.get(self.lower(addr))
    }

    /// `find_vma_intersection(start, end)`.
    #[must_use]
    pub fn find_vma_intersection(&self, start: u64, end: u64) -> Option<&Vma> {
        self.find_vma(start).filter(|v| v.start < end)
    }

    /// `vma_find(vmi, max)` started at `start`: index of the first VMA with
    /// `end > start` and `start < max`.
    pub(super) fn vma_find(&self, start: u64, max: u64) -> Option<usize> {
        let i = self.lower(start);
        (self.vmas.get(i)?.start < max).then_some(i)
    }

    /// `vm_start_gap`: the start minus the guard gap of a stack VMA.
    #[must_use]
    pub fn vm_start_gap(env: &Env, v: &Vma) -> u64 {
        let gap = if v.flags.contains(VmFlags::GROWSDOWN) {
            env.stack_guard_gap
        } else {
            0
        };
        v.start.saturating_sub(gap)
    }
    /// `vm_end_gap` (`CONFIG_STACK_GROWSUP` is n).
    #[must_use]
    pub const fn vm_end_gap(v: &Vma) -> u64 {
        v.end
    }

    pub(super) fn reserve(&mut self, n: usize) -> Result<(), Errno> {
        self.vmas.try_reserve(n).map_err(|_| Errno::ENOMEM)
    }

    /// Insert keeping order. Fails only if storage cannot be reserved, and
    /// then changes nothing.
    pub(super) fn insert_at(&mut self, at: usize, vma: Vma) -> Result<(), Errno> {
        self.reserve(1)?;
        self.vmas
            .push_within_capacity(vma)
            .map_err(|_| Errno::ENOMEM)?;
        self.vmas[at..].rotate_right(1);
        Ok(())
    }

    /// `insert_vm_struct`: link a VMA built by the loader (stack, vDSO).
    /// Unlike Linux, whose `create_init_stack_vma` sets `stack_vm = total_vm`
    /// by hand, the statistics are accounted here so the counters can never
    /// disagree with the VMA set (a later unmap cannot underflow them).
    ///
    /// # Errors
    /// `ENOMEM` if it intersects a VMA, is refused by the overcommit policy
    /// (`VM_ACCOUNT`) or storage cannot be reserved.
    pub fn insert_vm_struct(&mut self, env: &Env, mut vma: Vma) -> Result<(), Errno> {
        if self.find_vma_intersection(vma.start, vma.end).is_some() {
            return enomem();
        }
        if vma.flags.contains(VmFlags::ACCOUNT) && !env.enough_memory(vma.pages()) {
            return enomem();
        }
        if vma.is_anonymous() {
            vma.pgoff = vma.start >> PAGE_SHIFT;
        }
        let at = self.lower(vma.start);
        self.insert_at(at, vma)?;
        self.stat_add(vma.flags, vma.pages());
        if vma.flags.contains(VmFlags::LOCKED) {
            self.locked_vm += vma.pages();
        }
        Ok(())
    }

    /// `__split_vma`: split `vmas[idx]` at `addr` (`start < addr < end`) into
    /// two entries that share `anon_vma`; the upper one's `pgoff` advances.
    /// No `max_map_count` check (callers use [`Self::split_vma`] or document
    /// why Linux does not check).
    pub(super) fn split_raw(&mut self, idx: usize, addr: u64) -> Result<(), Errno> {
        let v = self.vmas[idx];
        debug_assert!(v.start < addr && addr < v.end);
        let hi = Vma {
            start: addr,
            pgoff: v.pgoff + ((addr - v.start) >> PAGE_SHIFT),
            ..v
        };
        self.insert_at(idx + 1, hi)?;
        self.vmas[idx].end = addr;
        Ok(())
    }

    /// `split_vma`: `__split_vma` behind the `map_count >= max_map_count` check.
    pub(super) fn split_vma(&mut self, env: &Env, idx: usize, addr: u64) -> Result<(), Errno> {
        if self.map_count() >= u64::from(env.max_map_count) {
            return enomem();
        }
        self.split_raw(idx, addr)
    }

    /// `may_expand_vm`.
    #[must_use]
    pub(super) fn may_expand_vm(&self, env: &Env, flags: VmFlags, npages: u64) -> bool {
        if self.total_vm.saturating_add(npages) > env.rlimit_as >> PAGE_SHIFT {
            return false;
        }
        if is_data_mapping(flags)
            && self.data_vm.saturating_add(npages) > env.rlimit_data >> PAGE_SHIFT
        {
            // Workaround for Valgrind (mm/mmap.c:1332).
            if env.rlimit_data == 0
                && self.data_vm.saturating_add(npages) <= env.rlimit_data_max >> PAGE_SHIFT
            {
                return true;
            }
            return env.ignore_rlimit_data;
        }
        true
    }

    /// `vm_stat_account` (`npages` may be negative through `sub`).
    pub(super) fn stat_add(&mut self, flags: VmFlags, npages: u64) {
        self.total_vm += npages;
        self.hiwater_vm = self.hiwater_vm.max(self.total_vm);
        if is_exec_mapping(flags) {
            self.exec_vm += npages;
        } else if is_stack_mapping(flags) {
            self.stack_vm += npages;
        } else if is_data_mapping(flags) {
            self.data_vm += npages;
        }
    }
    /// `vm_stat_account` with a negative count. Linux only `VM_WARN_ON`s on
    /// underflow; a bookkeeping bug must not become a user-reachable panic, so
    /// the counters saturate (the invariant is checked in debug builds).
    pub(super) fn stat_sub(&mut self, flags: VmFlags, npages: u64) {
        debug_assert!(self.total_vm >= npages, "total_vm underflow");
        self.total_vm = self.total_vm.saturating_sub(npages);
        let field = if is_exec_mapping(flags) {
            &mut self.exec_vm
        } else if is_stack_mapping(flags) {
            &mut self.stack_vm
        } else if is_data_mapping(flags) {
            &mut self.data_vm
        } else {
            return;
        };
        debug_assert!(*field >= npages, "vm statistic underflow");
        *field = field.saturating_sub(npages);
    }

    /// `mlock_future_ok`.
    #[must_use]
    pub(super) fn mlock_future_ok(&self, env: &Env, flags: VmFlags, bytes: u64) -> bool {
        if !flags.contains(VmFlags::LOCKED) || env.cap_ipc_lock {
            return true;
        }
        let locked = (bytes >> PAGE_SHIFT).saturating_add(self.locked_vm);
        locked <= env.rlimit_memlock >> PAGE_SHIFT
    }

    // ---- merging (mm/vma.c) ------------------------------------------------

    /// `is_mergeable_vma` + `is_mergeable_anon_vma` + the pgoff test, for a
    /// request. `anon_vma` compatibility is cases 1-3 of `is_mergeable_anon_vma`
    /// with `vma_is_fork_child` always false (there is no `fork`).
    fn mergeable(tgt: &Vma, req: &MergeReq) -> bool {
        (tgt.flags.0 ^ req.flags.0) & !VmFlags::IGNORE_MERGE.0 == 0
            && tgt.file == req.file
            && (tgt.anon.is_none() || req.anon.is_none() || tgt.anon == req.anon)
    }

    /// `can_vma_merge_left` (the request is placed after `prev`).
    fn can_merge_left(prev: Option<&Vma>, req: &MergeReq) -> bool {
        prev.is_some_and(|p| {
            p.end == req.start && Self::mergeable(p, req) && p.pgoff + p.pages() == req.pgoff
        })
    }

    /// `can_vma_merge_right`; `left` is the left candidate if it can merge.
    fn can_merge_right(next: Option<&Vma>, req: &MergeReq, left: Option<&Vma>) -> bool {
        let Some(n) = next else { return false };
        if n.start != req.end
            || !Self::mergeable(n, req)
            || n.pgoff != req.pgoff + ((req.end - req.start) >> PAGE_SHIFT)
        {
            return false;
        }
        // Both neighbours merge only if they are compatible with each other.
        left.is_none_or(|p| p.anon.is_none() || n.anon.is_none() || p.anon == n.anon)
    }

    /// `vma_merge_new_range`: place `req` into the gap between `vmas[lo-1]`
    /// and `vmas[lo]` by growing a neighbour. Returns the grown VMA's index.
    /// `just_expand` (the `brk` path) considers only the left neighbour.
    /// Allocation-free and infallible.
    pub(super) fn merge_new_range(
        &mut self,
        lo: usize,
        req: &MergeReq,
        just_expand: bool,
    ) -> Option<usize> {
        if req.flags.intersects(VmFlags::SPECIAL) {
            return None;
        }
        let prev = lo.checked_sub(1).map(|i| self.vmas[i]);
        let next = self.vmas.get(lo).copied();
        let left = Self::can_merge_left(prev.as_ref(), req);
        let right = !just_expand
            && Self::can_merge_right(next.as_ref(), req, if left { prev.as_ref() } else { None });
        match (left, right) {
            // `vma_expand` ORs the sticky flags of the request, the target and a removed `next`
            // into the target.
            (true, true) => {
                let p = lo - 1;
                let n = self.vmas[lo];
                self.vmas[p].end = n.end;
                // dup_anon_vma(target, next)
                self.vmas[p].anon = self.vmas[p].anon.or(n.anon);
                self.vmas[p].flags |= (req.flags | n.flags) & VmFlags::STICKY;
                self.vmas.remove(lo);
                Some(p)
            }
            (true, false) => {
                self.vmas[lo - 1].end = req.end;
                self.vmas[lo - 1].flags |= req.flags & VmFlags::STICKY;
                Some(lo - 1)
            }
            (false, true) => {
                let n = &mut self.vmas[lo];
                n.start = req.start;
                n.pgoff = req.pgoff;
                n.flags |= req.flags & VmFlags::STICKY;
                Some(lo)
            }
            (false, false) => None,
        }
    }

    /// `vma_merge_existing_range` for `vmas[mid]` whose sub-range
    /// `[req.start, req.end)` is about to take `req.flags`. Returns the index
    /// of the VMA that now covers the range, or `None` if nothing merged
    /// (nothing changed). Allocation-free and infallible.
    pub(super) fn merge_existing_range(&mut self, mid: usize, req: &MergeReq) -> Option<usize> {
        let m = self.vmas[mid];
        let left_side = req.start == m.start;
        let right_side = req.end == m.end;
        if req.flags.intersects(VmFlags::SPECIAL) || (!left_side && !right_side) {
            return None;
        }
        let prev = if left_side {
            mid.checked_sub(1).map(|i| self.vmas[i])
        } else {
            None
        };
        let merge_left = left_side && Self::can_merge_left(prev.as_ref(), req);
        let next = if right_side {
            self.vmas.get(mid + 1).copied()
        } else {
            None
        };
        let merge_right = right_side
            && Self::can_merge_right(
                next.as_ref(),
                req,
                if merge_left { prev.as_ref() } else { None },
            );
        if !merge_left && !merge_right {
            return None;
        }
        let remove_middle = left_side && right_side;
        let pglen = (req.end - req.start) >> PAGE_SHIFT;
        // `vm_flags_set(vmg->target, sticky_flags)`: the request's sticky flags and those of the
        // neighbours that merge. (Callers then reset the target's flags to the request's, as
        // `mprotect_fixup` and `madvise_update_vma` do.)
        if merge_left && merge_right {
            let n = self.vmas[mid + 1];
            let p = &mut self.vmas[mid - 1];
            p.end = n.end;
            // dup_anon_vma(prev, next->anon_vma ? next : middle)
            p.anon = p.anon.or(n.anon.or(m.anon));
            p.flags |= (req.flags | n.flags) & VmFlags::STICKY;
            self.vmas.drain(mid..=mid + 1);
            Some(mid - 1)
        } else if merge_left {
            let p = mid - 1;
            self.vmas[p].end = req.end;
            self.vmas[p].anon = self.vmas[p].anon.or(m.anon);
            self.vmas[p].flags |= req.flags & VmFlags::STICKY;
            if remove_middle {
                self.vmas.remove(mid);
            } else {
                self.vmas[mid].start = req.end;
                self.vmas[mid].pgoff = m.pgoff + pglen;
            }
            Some(p)
        } else {
            let n = mid + 1;
            let nv = self.vmas[n];
            self.vmas[n].anon = nv.anon.or(m.anon);
            self.vmas[n].flags |= req.flags & VmFlags::STICKY;
            self.vmas[n].start = req.start;
            self.vmas[n].pgoff = nv.pgoff - pglen;
            if remove_middle {
                self.vmas.remove(mid);
                Some(mid)
            } else {
                self.vmas[mid].end = req.start;
                Some(n)
            }
        }
    }

    /// `vma_modify_flags`: make `[start, end)` of `vmas[idx]` take `flags`,
    /// merging into a neighbour if possible, otherwise splitting. Returns the
    /// index of the VMA covering exactly the range (its flags are *not* yet
    /// changed unless merged into a VMA that already had them).
    pub(super) fn vma_modify(
        &mut self,
        env: &Env,
        idx: usize,
        start: u64,
        end: u64,
        flags: VmFlags,
    ) -> Result<usize, Errno> {
        let v = self.vmas[idx];
        let req = MergeReq {
            start,
            end,
            flags,
            pgoff: v.pgoff + ((start - v.start) >> PAGE_SHIFT),
            file: v.file,
            anon: v.anon,
        };
        if let Some(i) = self.merge_existing_range(idx, &req) {
            return Ok(i);
        }
        let mut at = idx;
        if v.start < start {
            self.split_vma(env, at, start)?;
            at += 1;
        }
        if self.vmas[at].end > end {
            self.split_vma(env, at, end)?;
        }
        Ok(at)
    }

    // ---- anon_vma ----------------------------------------------------------

    /// `anon_vma_compatible(a, b)`.
    fn anon_compatible(a: &Vma, b: &Vma) -> bool {
        a.end == b.start
            && a.file == b.file
            && (a.flags.0 ^ b.flags.0) & !(VmFlags::ACCESS.0 | VmFlags::IGNORE_MERGE.0) == 0
            && b.pgoff == a.pgoff + ((b.start - a.start) >> PAGE_SHIFT)
    }

    /// `anon_vma_prepare` (`__anon_vma_prepare` + `find_mergeable_anon_vma`):
    /// give `vmas[idx]` an `anon_vma`, reusing a compatible neighbour's so a
    /// later `mprotect` can merge. Called on the first write fault (and by
    /// stack growth). Infallible: identities are not memory.
    pub(super) fn anon_vma_prepare(&mut self, idx: usize) {
        let v = self.vmas[idx];
        if v.anon.is_some() {
            return;
        }
        let from_next = self
            .vmas
            .get(idx + 1)
            .filter(|n| Self::anon_compatible(&v, n))
            .and_then(|n| n.anon);
        let from_prev = idx
            .checked_sub(1)
            .map(|i| self.vmas[i])
            .filter(|p| Self::anon_compatible(p, &v))
            .and_then(|p| p.anon);
        let id = from_next.or(from_prev).unwrap_or_else(|| {
            let id = self.next_anon;
            self.next_anon += 1;
            id
        });
        self.vmas[idx].anon = Some(id);
    }

    // ---- stack growth ------------------------------------------------------

    /// `acct_stack_growth` for a stack VMA of `flags` that would be `size`
    /// bytes after growing by `grow` pages.
    fn acct_stack_growth(
        &self,
        env: &Env,
        flags: VmFlags,
        size: u64,
        grow: u64,
    ) -> Result<(), Errno> {
        if !self.may_expand_vm(env, flags, grow) {
            return enomem();
        }
        if size > env.rlimit_stack {
            return enomem();
        }
        if !self.mlock_future_ok(env, flags, grow << PAGE_SHIFT) {
            return enomem();
        }
        // Overcommit: the final test, as it updates statistics in Linux.
        if !env.enough_memory(grow) {
            return enomem();
        }
        Ok(())
    }

    /// `expand_downwards` (`expand_stack_locked` on x86): grow the
    /// `VM_GROWSDOWN` VMA `vmas[idx]` down to `address & PAGE_MASK`.
    ///
    /// # Errors
    /// `EFAULT` not a stack VMA; `EPERM` below `mmap_min_addr`; `ENOMEM` for the
    /// guard gap below an accessible neighbour, any limit in
    /// `acct_stack_growth`, or `grow > vm_pgoff`.
    pub fn expand_downwards(&mut self, env: &Env, idx: usize, address: u64) -> Result<(), Errno> {
        let v = self.vmas[idx];
        if !v.flags.contains(VmFlags::GROWSDOWN) {
            return Err(Errno::EFAULT);
        }
        let address = super::flags::page_floor(address);
        if address < env.mmap_min_addr {
            return Err(Errno::EPERM);
        }
        if let Some(p) = idx.checked_sub(1).map(|i| self.vmas[i]) {
            // Enforce stack_guard_gap (unsigned arithmetic as in Linux).
            if !p.flags.contains(VmFlags::GROWSDOWN)
                && p.is_accessible()
                && address.wrapping_sub(p.end) < env.stack_guard_gap
            {
                return enomem();
            }
        }
        self.anon_vma_prepare(idx);
        if address >= v.start {
            return Ok(());
        }
        let size = v.end - address;
        let grow = (v.start - address) >> PAGE_SHIFT;
        if grow > v.pgoff {
            return enomem();
        }
        self.acct_stack_growth(env, v.flags, size, grow)?;
        if v.flags.contains(VmFlags::LOCKED) {
            self.locked_vm += grow;
        }
        self.stat_add(v.flags, grow);
        self.vmas[idx].start = address;
        self.vmas[idx].pgoff -= grow;
        Ok(())
    }

    // ---- munmap (vms_gather_munmap_vmas / vms_complete_munmap_vmas) --------

    /// Split the VMAs at the boundaries of `[start, end)` and report the index
    /// range `lo..hi` of the VMAs now wholly inside it, with their statistics.
    /// `first` is `vma_find(start, end)`. On error the splits already made stay
    /// (as in Linux, which does not undo a successful first split).
    pub(super) fn gather_munmap(
        &mut self,
        env: &Env,
        first: usize,
        start: u64,
        end: u64,
    ) -> Result<Gathered, Errno> {
        let mut lo = first;
        let f = self.vmas[first];
        if start > f.start {
            // Do not let map_count exceed its limit after the unmap (but
            // allow it just above, temporarily, when the VMA is cut once).
            if end < f.end && self.map_count() >= u64::from(env.max_map_count) {
                return enomem();
            }
            self.split_raw(first, start)?;
            lo += 1;
        }
        let mut hi = lo;
        while self.vmas.get(hi).is_some_and(|v| v.start < end) {
            hi += 1;
        }
        // Does it split the end? Only the last VMA can extend past `end`.
        if self.vmas[hi - 1].end > end {
            self.split_raw(hi - 1, end)?;
        }
        let mut g = Gathered {
            lo,
            hi,
            ..Gathered::default()
        };
        for v in &self.vmas[lo..hi] {
            let n = v.pages();
            g.nr_pages += n;
            if v.flags.contains(VmFlags::LOCKED) {
                g.locked_vm += n;
            }
            if v.flags.contains(VmFlags::ACCOUNT) {
                g.nr_accounted += n;
            }
            if is_exec_mapping(v.flags) {
                g.exec_vm += n;
            } else if is_stack_mapping(v.flags) {
                g.stack_vm += n;
            } else if is_data_mapping(v.flags) {
                g.data_vm += n;
            }
        }
        Ok(g)
    }

    /// `vms_complete_munmap_vmas`: drop the gathered VMAs and their statistics.
    pub(super) fn complete_munmap(&mut self, g: &Gathered) {
        self.vmas.drain(g.lo..g.hi);
        debug_assert!(
            self.locked_vm >= g.locked_vm
                && self.total_vm >= g.nr_pages
                && self.exec_vm >= g.exec_vm
                && self.stack_vm >= g.stack_vm
                && self.data_vm >= g.data_vm,
            "vm statistic underflow"
        );
        self.locked_vm = self.locked_vm.saturating_sub(g.locked_vm);
        self.total_vm = self.total_vm.saturating_sub(g.nr_pages);
        self.exec_vm = self.exec_vm.saturating_sub(g.exec_vm);
        self.stack_vm = self.stack_vm.saturating_sub(g.stack_vm);
        self.data_vm = self.data_vm.saturating_sub(g.data_vm);
    }
}

/// What `vma_merge_*` is asked to merge: a range with the properties its VMA
/// will have (`struct vma_merge_struct`, reduced).
#[derive(Clone, Copy, Debug)]
pub(super) struct MergeReq {
    pub start: u64,
    pub end: u64,
    pub flags: VmFlags,
    pub pgoff: u64,
    pub file: Option<u64>,
    pub anon: Option<u64>,
}

/// `struct vma_munmap_struct` results.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Gathered {
    pub lo: usize,
    pub hi: usize,
    pub nr_pages: u64,
    pub nr_accounted: u64,
    pub locked_vm: u64,
    pub exec_vm: u64,
    pub stack_vm: u64,
    pub data_vm: u64,
}

/// `PAGE_ALIGN` for lengths as Linux computes it on `unsigned long` (a wrap
/// to 0 is how callers detect overflow).
pub(super) fn align_or_zero(x: u64) -> u64 {
    page_align(x).unwrap_or(0)
}
