// SPDX-License-Identifier: GPL-2.0-only
// Linux 6.18.57 (2ff600d29ee478d0a8d46ef8a58afb5e038fe692): mm/mremap.c
// (`SYSCALL_DEFINE5(mremap)`, `do_mremap`, `check_mremap_params`, `check_prep_vma`,
// `remap_move`, `mremap_to`, `mremap_at`, `expand_vma`, `expand_vma_in_place`,
// `vma_expandable`, `shrink_vma`, `move_vma`, `prep_move_vma`, `copy_vma_and_data`,
// `unmap_source_vma`, `dontunmap_complete`, `vrm_set_new_addr`, `vrm_calc_charge`,
// `vrm_overlaps`), mm/vma.c (`copy_vma`, `vma_merge_extend`, `vma_merge_copied_range`).
// GPL-2.0.
// Transformation: `struct vma_remap_struct` is [`Vrm`]; the maple-tree iterator walks are
// index arithmetic on the sorted VMA vector; `move_page_tables` is the page-table owner's
// [`UserPages::move_pages`], which moves a whole range or none (Linux moves what it can and the
// caller moves it back, `copy_vma_and_data`); userfaultfd, mseal, hugetlb, KSM, uprobes and the
// rmap locks are absent; commit accounting is the model's `enough_memory` test only.
#![forbid(unsafe_code)]
//! `mremap(2)`: shrink in place, grow in place, or move a range (also to a fixed address, also
//! leaving the old one behind with `MREMAP_DONTUNMAP`); a `MREMAP_FIXED` move of equal length
//! moves every VMA in the range ("batched move").

use syscalls::Errno;

use super::{
    env::Env,
    flags::{MAP_FIXED, MAP_SHARED, PAGE_SHIFT, VmFlags, offset_in_page},
    pt::UserPages,
    space::{MergeReq, Mm, TASK_SIZE, Vma, align_or_zero, enomem},
};

pub const MREMAP_MAYMOVE: u64 = 1;
pub const MREMAP_FIXED: u64 = 2;
pub const MREMAP_DONTUNMAP: u64 = 4;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    NoResize,
    Shrink,
    Expand,
}

/// `struct vma_remap_struct`.
struct Vrm {
    addr: u64,
    old_len: u64,
    new_len: u64,
    flags: u64,
    new_addr: u64,
    delta: u64,
    kind: Kind,
    populate_expand: bool,
}

impl Vrm {
    /// `vrm_implies_new_addr`.
    const fn implies_new_addr(&self) -> bool {
        self.flags & (MREMAP_FIXED | MREMAP_DONTUNMAP) != 0
    }
}

impl Mm {
    /// `vma_lookup`: the index of the VMA that contains `addr`.
    fn vma_lookup(&self, addr: u64) -> Option<usize> {
        let at = self.lower(addr);
        (self.vmas.get(at)?.start <= addr).then_some(at)
    }

    /// `mremap(2)`: the new address of the range.
    ///
    /// # Errors
    /// Linux's, in Linux's order; see the step comments.
    #[allow(
        clippy::too_many_arguments,
        reason = "the five syscall arguments plus the context"
    )]
    pub fn mremap(
        &mut self,
        env: &Env,
        pt: &mut (impl UserPages + ?Sized),
        addr: u64,
        old_len: u64,
        new_len: u64,
        flags: u64,
        new_addr: u64,
    ) -> Result<u64, Errno> {
        let mut vrm = Vrm {
            addr,
            old_len: align_or_zero(old_len),
            new_len: align_or_zero(new_len),
            flags,
            new_addr,
            delta: 0,
            kind: Kind::NoResize,
            populate_expand: false,
        };
        self.check_mremap_params(env, &vrm)?;
        let move_only = vrm.flags & MREMAP_FIXED != 0 && vrm.old_len == vrm.new_len;
        let result = if move_only {
            self.remap_move(env, pt, &mut vrm)
        } else {
            let vma = self.vma_lookup(vrm.addr);
            self.check_prep_vma(env, &mut vrm, vma).and_then(|()| {
                if vrm.implies_new_addr() {
                    self.mremap_to(env, pt, &mut vrm)
                } else {
                    self.mremap_at(env, pt, &mut vrm)
                }
            })
        };
        // A mlock()'d VMA that was expanded populates the new part.
        if result.is_ok() && vrm.populate_expand {
            self.populate(pt, vrm.new_addr.wrapping_add(vrm.old_len), vrm.delta);
        }
        result
    }

    /// `check_mremap_params`.
    fn check_mremap_params(&self, env: &Env, vrm: &Vrm) -> Result<(), Errno> {
        if vrm.flags & !(MREMAP_FIXED | MREMAP_MAYMOVE | MREMAP_DONTUNMAP) != 0 {
            return Err(Errno::EINVAL);
        }
        if offset_in_page(vrm.addr) != 0 {
            return Err(Errno::EINVAL);
        }
        if vrm.new_len == 0 || vrm.new_len > TASK_SIZE {
            return Err(Errno::EINVAL);
        }
        if !vrm.implies_new_addr() {
            return Ok(());
        }
        if vrm.new_addr > TASK_SIZE - vrm.new_len {
            return Err(Errno::EINVAL);
        }
        if offset_in_page(vrm.new_addr) != 0 {
            return Err(Errno::EINVAL);
        }
        // A fixed address implies a move.
        if vrm.flags & MREMAP_MAYMOVE == 0 {
            return Err(Errno::EINVAL);
        }
        if vrm.flags & MREMAP_DONTUNMAP != 0 && vrm.old_len != vrm.new_len {
            return Err(Errno::EINVAL);
        }
        // vrm_overlaps: the target must not overlap the source.
        let (end_old, end_new) = (vrm.addr + vrm.old_len, vrm.new_addr + vrm.new_len);
        if end_old > vrm.new_addr && end_new > vrm.addr {
            return Err(Errno::EINVAL);
        }
        // Stay four maps below the threshold: both ranges may be split in three.
        if self.map_count() + 2 >= u64::from(env.max_map_count).saturating_sub(3) {
            return enomem();
        }
        Ok(())
    }

    /// `check_prep_vma`; `vma` is the index of the VMA containing `vrm.addr`.
    fn check_prep_vma(&self, env: &Env, vrm: &mut Vrm, vma: Option<usize>) -> Result<(), Errno> {
        let v = self.vmas[vma.ok_or(Errno::EFAULT)?];
        vrm.delta = vrm.old_len.abs_diff(vrm.new_len);
        vrm.kind = if vrm.delta == 0 {
            Kind::NoResize
        } else if vrm.old_len > vrm.new_len {
            Kind::Shrink
        } else {
            Kind::Expand
        };
        // For convenience, new_addr is set even if the VMA will not move.
        if !vrm.implies_new_addr() {
            vrm.new_addr = vrm.addr;
        }
        // Below only meaningful if we expand or move a VMA.
        if vrm.kind != Kind::Expand && !vrm.implies_new_addr() {
            return Ok(());
        }
        let (mut old_len, new_len) = (vrm.old_len, vrm.new_len);
        // A zero old_len would 'duplicate' a mapping: only for shared ones.
        if old_len == 0 && !v.flags.intersects(VmFlags::SHARED | VmFlags::MAYSHARE) {
            return Err(Errno::EINVAL);
        }
        if vrm.flags & MREMAP_DONTUNMAP != 0
            && v.flags.intersects(VmFlags::DONTEXPAND | VmFlags::PFNMAP)
        {
            return Err(Errno::EINVAL);
        }
        // We permit crossing of boundaries for the range being unmapped by a shrink.
        if vrm.kind == Kind::Shrink {
            old_len = new_len;
        }
        // We can't remap across the end of VMAs, as another VMA may be adjacent.
        if old_len > v.end - vrm.addr {
            return Err(Errno::EFAULT);
        }
        if new_len == old_len {
            return Ok(());
        }
        // We are expanding and the VMA is mlock()'d so we need to populate.
        if v.flags.contains(VmFlags::LOCKED) {
            vrm.populate_expand = true;
        }
        // Need to be careful about a growing mapping.
        let pgoff = v.pgoff.wrapping_add((vrm.addr - v.start) >> PAGE_SHIFT);
        if pgoff.wrapping_add(new_len >> PAGE_SHIFT) < pgoff {
            return Err(Errno::EINVAL);
        }
        if v.flags.intersects(VmFlags::DONTEXPAND | VmFlags::PFNMAP) {
            return Err(Errno::EFAULT);
        }
        if !self.mlock_future_ok(env, v.flags, vrm.delta) {
            return Err(Errno::EAGAIN);
        }
        if !self.may_expand_vm(env, v.flags, vrm.delta >> PAGE_SHIFT) {
            return enomem();
        }
        Ok(())
    }

    /// `mremap_at`: resize in place, else move to the first available address.
    fn mremap_at(
        &mut self,
        env: &Env,
        pt: &mut (impl UserPages + ?Sized),
        vrm: &mut Vrm,
    ) -> Result<u64, Errno> {
        match vrm.kind {
            Kind::NoResize => Ok(vrm.addr),
            Kind::Shrink => {
                // Simply unmap the shrunken portion.
                self.munmap(env, pt, vrm.addr + vrm.new_len, vrm.delta)?;
                Ok(vrm.addr)
            }
            Kind::Expand => self.expand_vma(env, pt, vrm),
        }
    }

    /// `vma_expandable`.
    fn vma_expandable(&self, env: &Env, vma: &Vma, delta: u64) -> bool {
        let end = vma.end.wrapping_add(delta);
        if end < vma.end {
            return false;
        }
        if self.find_vma_intersection(vma.end, end).is_some() {
            return false;
        }
        self.get_unmapped_area(env, vma.start, end - vma.start, 0, MAP_FIXED)
            .is_ok()
    }

    /// `expand_vma`.
    fn expand_vma(
        &mut self,
        env: &Env,
        pt: &mut (impl UserPages + ?Sized),
        vrm: &mut Vrm,
    ) -> Result<u64, Errno> {
        let at = self.vma_lookup(vrm.addr).ok_or(Errno::EFAULT)?;
        let vma = self.vmas[at];
        // The range spans precisely to the end of the VMA: expand in place if possible.
        if vma.end - vrm.addr == vrm.old_len && self.vma_expandable(env, &vma, vrm.delta) {
            // vrm_calc_charge
            if vma.flags.contains(VmFlags::ACCOUNT) && !env.enough_memory(vrm.delta >> PAGE_SHIFT) {
                return enomem();
            }
            // vma_merge_extend: the new tail merges with this VMA (and the next if it fits).
            let req = MergeReq {
                start: vma.end,
                end: vma.end + vrm.delta,
                flags: vma.flags,
                pgoff: vma.pgoff + vma.pages(),
                file: vma.file,
                anon: vma.anon,
            };
            let merged = self
                .merge_new_range(at + 1, &req, false)
                .ok_or(Errno::ENOMEM)?;
            // vrm_stat_account
            let flags = self.vmas[merged].flags;
            let pages = vrm.delta >> PAGE_SHIFT;
            self.stat_add(flags, pages);
            if flags.contains(VmFlags::LOCKED) {
                self.locked_vm += pages;
            }
            return Ok(vrm.addr);
        }
        // We weren't able to just expand: create a new one and move it.
        if vrm.flags & MREMAP_MAYMOVE == 0 {
            return enomem();
        }
        self.vrm_set_new_addr(env, vrm, &vma)?;
        self.move_vma(env, pt, vrm)
    }

    /// `vrm_set_new_addr`: an `mmap`-like search (`MAP_FIXED` for `MREMAP_FIXED`, a hint for
    /// `MREMAP_DONTUNMAP`, none otherwise).
    fn vrm_set_new_addr(&self, env: &Env, vrm: &mut Vrm, vma: &Vma) -> Result<(), Errno> {
        let pgoff = vma.pgoff + ((vrm.addr - vma.start) >> PAGE_SHIFT);
        let hint = if vrm.implies_new_addr() {
            vrm.new_addr
        } else {
            0
        };
        let mut map_flags = 0;
        if vrm.flags & MREMAP_FIXED != 0 {
            map_flags |= MAP_FIXED;
        }
        if vma.flags.contains(VmFlags::MAYSHARE) {
            map_flags |= MAP_SHARED;
        }
        vrm.new_addr = self.get_unmapped_area(env, hint, vrm.new_len, pgoff, map_flags)?;
        Ok(())
    }

    /// `mremap_to`: remap to a new location (fixed or hinted).
    fn mremap_to(
        &mut self,
        env: &Env,
        pt: &mut (impl UserPages + ?Sized),
        vrm: &mut Vrm,
    ) -> Result<u64, Errno> {
        if vrm.flags & MREMAP_FIXED != 0 {
            // The VMA is moved to the destination, which is unmapped first.
            self.munmap(env, pt, vrm.new_addr, vrm.new_len)?;
        }
        // If a portion of a VMA was remapped elsewhere in the same VMA, the old VMA may have
        // changed: look it up again.
        let mut at = self.vma_lookup(vrm.addr).ok_or(Errno::EFAULT)?;
        if vrm.kind == Kind::Shrink {
            self.munmap(env, pt, vrm.addr + vrm.new_len, vrm.delta)?;
            at = self.vma_lookup(vrm.addr).ok_or(Errno::EFAULT)?;
            // Set up for the move now the shrink has been executed.
            vrm.old_len = vrm.new_len;
        }
        let vma = self.vmas[at];
        // MREMAP_DONTUNMAP expands by old_len since old_len == new_len.
        if vrm.flags & MREMAP_DONTUNMAP != 0
            && !self.may_expand_vm(env, vma.flags, vrm.old_len >> PAGE_SHIFT)
        {
            return enomem();
        }
        self.vrm_set_new_addr(env, vrm, &vma)?;
        self.move_vma(env, pt, vrm)
    }

    /// `move_vma`: copy the VMA to `vrm.new_addr`, move the page tables and unmap the source
    /// (unless `MREMAP_DONTUNMAP`).
    fn move_vma(
        &mut self,
        env: &Env,
        pt: &mut (impl UserPages + ?Sized),
        vrm: &mut Vrm,
    ) -> Result<u64, Errno> {
        let is_dontunmap = vrm.flags & MREMAP_DONTUNMAP != 0;
        let at = self.vma_lookup(vrm.addr).ok_or(Errno::EFAULT)?;
        let vma = self.vmas[at];
        // prep_move_vma: stay clear of the map count limit (do_munmap may split one vma in 3).
        if self.map_count() >= u64::from(env.max_map_count).saturating_sub(3) {
            return enomem();
        }
        // vrm_calc_charge
        if vma.flags.contains(VmFlags::ACCOUNT) {
            let charged = if is_dontunmap {
                vrm.new_len >> PAGE_SHIFT
            } else {
                vrm.delta >> PAGE_SHIFT
            };
            if !env.enough_memory(charged) {
                return enomem();
            }
        }
        // copy_vma_and_data
        let new_pgoff = vma.pgoff + ((vrm.addr - vma.start) >> PAGE_SHIFT);
        self.copy_vma(vrm.addr, vrm.new_addr, vrm.new_len, new_pgoff)?;
        // move_page_tables: all of the range or none (Linux moves what it can and moves it
        // back when it was not all).
        let mut error = None;
        if pt
            .move_pages(vrm.addr, vrm.new_addr, vrm.old_len >> PAGE_SHIFT)
            .is_err()
        {
            // The page tables stayed where they were: the new area is unmapped instead of the old.
            error = Some(Errno::ENOMEM);
            vrm.old_len = vrm.new_len;
            vrm.addr = vrm.new_addr;
        }
        // Total_vm is raised artificially high for a moment; restore the high watermark.
        let hiwater_vm = self.hiwater_vm;
        if is_dontunmap && error.is_none() {
            self.dontunmap_complete(vrm, &vma);
        }
        // vrm_stat_account(vrm, vrm->new_len): the flags of the VMA now at `vrm.addr`.
        let flags = self
            .vma_lookup(vrm.addr)
            .map_or(vma.flags, |i| self.vmas[i].flags);
        let pages = vrm.new_len >> PAGE_SHIFT;
        self.stat_add(flags, pages);
        if flags.contains(VmFlags::LOCKED) {
            self.locked_vm += pages;
        }
        if !is_dontunmap || error.is_some() {
            // unmap_source_vma: best effort; the commit accounting is not tracked here.
            let _ = self.munmap(env, pt, vrm.addr, vrm.old_len);
        }
        self.hiwater_vm = hiwater_vm;
        error.map_or(Ok(vrm.new_addr), Err)
    }

    /// `dontunmap_complete`: the old VMA can no longer be `mlock()`'d and, when it was copied
    /// whole, is a never-faulted anonymous VMA again.
    fn dontunmap_complete(&mut self, vrm: &Vrm, original: &Vma) {
        let Some(at) = self.vma_lookup(vrm.addr) else {
            return;
        };
        self.vmas[at].flags &= !(VmFlags::LOCKED | VmFlags::LOCKONFAULT);
        let (start, end) = (vrm.addr, vrm.addr + vrm.old_len);
        let whole = start == original.start && end == original.end;
        if whole && self.vmas[at].start == start {
            // unlink_anon_vmas, and the unfaulted anonymous invariant `pgoff == start >> 12`.
            self.vmas[at].anon = None;
            if self.vmas[at].file.is_none() {
                self.vmas[at].pgoff = self.vmas[at].start >> PAGE_SHIFT;
            }
        }
    }

    /// `copy_vma`: a VMA for `[new_addr, new_addr + len)` that continues `source` (merged with
    /// a neighbour when possible), `pgoff` being the file offset of its first page. Returns its
    /// index.
    fn copy_vma(
        &mut self,
        addr: u64,
        new_addr: u64,
        len: u64,
        mut pgoff: u64,
    ) -> Result<usize, Errno> {
        let src = self.vmas[self.vma_lookup(addr).ok_or(Errno::EFAULT)?];
        // An anonymous VMA that was never faulted takes a pgoff that matches its new place, which
        // gives it a better chance to merge.
        if src.file.is_none() && src.anon.is_none() {
            pgoff = new_addr >> PAGE_SHIFT;
        }
        let at = self.lower(new_addr);
        if self.vmas.get(at).is_some_and(|n| n.start < new_addr + len) {
            // Should never get here.
            return enomem();
        }
        let req = MergeReq {
            start: new_addr,
            end: new_addr + len,
            flags: src.flags,
            pgoff,
            file: src.file,
            anon: src.anon,
        };
        if let Some(merged) = self.merge_new_range(at, &req, false) {
            return Ok(merged);
        }
        self.insert_at(
            at,
            Vma {
                start: new_addr,
                end: new_addr + len,
                flags: src.flags,
                pgoff,
                file: src.file,
                anon: src.anon,
            },
        )?;
        Ok(at)
    }

    /// `remap_move`: a `MREMAP_FIXED` move of equal length moves every VMA of the range,
    /// keeping the gaps between them.
    fn remap_move(
        &mut self,
        env: &Env,
        pt: &mut (impl UserPages + ?Sized),
        vrm: &mut Vrm,
    ) -> Result<u64, Errno> {
        let (start, end) = (vrm.addr, vrm.addr + vrm.old_len);
        let new_addr = vrm.new_addr;
        let mut target_addr = new_addr;
        let mut res: Result<u64, Errno> = Err(Errno::EFAULT);
        let mut seen_vma = false;
        let mut last_end = 0;
        let mut cursor = start;
        while let Some(at) = self.vma_find(cursor, end) {
            let vma = self.vmas[at];
            // Account for start, end not aligned with VMA start, end.
            let addr = vma.start.max(start);
            let len = end.min(vma.end) - addr;
            // No gap permitted at the start of the range.
            if !seen_vma && start < vma.start {
                return Err(Errno::EFAULT);
            }
            // Keep the gaps between the source VMAs the same in the destination.
            let offset = if seen_vma { vma.start - last_end } else { 0 };
            last_end = vma.end;
            vrm.addr = addr;
            vrm.new_addr = target_addr + offset;
            vrm.old_len = len;
            vrm.new_len = len;
            // Every VMA of this model is anonymous or on tmpfs: `vma_multi_allowed`.
            self.check_prep_vma(env, vrm, Some(at))?;
            let res_vma = self.mremap_to(env, pt, vrm)?;
            if !seen_vma {
                res = Ok(res_vma);
            }
            seen_vma = true;
            target_addr = res_vma + vrm.new_len;
            // Continue after the part just moved (the VMA set changed).
            cursor = vma.end.min(end);
            if cursor >= end {
                break;
            }
        }
        res
    }
}
