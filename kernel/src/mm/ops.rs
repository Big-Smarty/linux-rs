// SPDX-License-Identifier: GPL-2.0-only
// Linux 6.18.57 (2ff600d29ee478d0a8d46ef8a58afb5e038fe692): mm/mmap.c
// (`SYSCALL_DEFINE1(brk)`, `check_brk_limits`, `do_mmap`, `ksys_mmap_pgoff`,
// `vm_brk_flags`, `__vm_munmap`), mm/util.c (`vm_mmap_pgoff`), mm/vma.c
// (`mmap_region`, `__mmap_region`, `__mmap_setup`, `__mmap_new_vma`,
// `__mmap_complete`, `do_brk_flags`, `do_vmi_munmap`, `do_vmi_align_munmap`),
// mm/mprotect.c (`do_mprotect_pkey`, `mprotect_fixup`), arch/x86/kernel/
// sys_x86_64.c (`SYSCALL_DEFINE6(mmap)`), include/linux/mm.h
// (`check_data_rlimit`), mm/gup.c (`populate_vma_page_range` flag choice).
// GPL-2.0.
// Transformation: the system calls become methods that return `Result<_,
// Errno>` instead of `-errno`; the file-backed branch stops at a typed
// outcome because the VFS owner supplies `file` and the `->mmap` hook; the
// shared-anonymous branch stops at `Unsupported` because shmem is not in
// scope; `userfaultfd`, memfd seals, MDWE, protection keys and sealing do not
// exist in the declared configuration.
#![forbid(unsafe_code)]
//! `mmap`, `munmap`, `mprotect` and `brk` with Linux's check order.

use syscalls::Errno;

use super::{
    env::{Env, FileInfo, RLIM_INFINITY},
    flags::{
        LEGACY_MAP_MASK, MAP_DROPPABLE, MAP_FIXED, MAP_FIXED_NOREPLACE, MAP_HUGETLB, MAP_LOCKED,
        MAP_NONBLOCK, MAP_NORESERVE, MAP_POPULATE, MAP_PRIVATE, MAP_SHARED, MAP_SHARED_VALIDATE,
        MAP_TYPE, PAGE_SHIFT, PAGE_SIZE, PROT_EXEC, PROT_GROWSDOWN, PROT_GROWSUP, PROT_READ,
        PROT_SEM, PROT_WRITE, VmFlags, calc_vm_flag_bits, calc_vm_prot_bits, offset_in_page,
        page_prot,
    },
    layout::round_hint_to_min,
    pt::UserPages,
    space::{MergeReq, Mm, TASK_SIZE, Vma, align_or_zero, enomem},
};

/// A request Linux would satisfy by creating a shmem/hugetlb file, which this
/// model does not provide. Nothing has been changed when this is returned.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Unsupported {
    /// `MAP_SHARED` without a file: `shmem_zero_setup` (mm/vma.c
    /// `__mmap_new_vma`). Waits for the shmem/tmpfs owner (WP-M3.6).
    SharedAnonymous,
    /// `MAP_HUGETLB` or a hugetlbfs file: `hugetlb_file_setup`.
    Hugetlb,
}

/// A validated file mapping: placement and flags are final, nothing has been
/// changed. The VFS owner calls `->mmap` and then [`Mm::mmap_region`] with
/// these values (or fails the system call).
#[derive(Clone, Copy, Debug)]
pub struct FileMapping {
    pub addr: u64,
    pub len: u64,
    pub vm_flags: VmFlags,
    pub pgoff: u64,
    pub file: FileInfo,
    /// `*populate` of `do_mmap`: bytes to pre-fault after mapping, or 0.
    pub populate: u64,
}

#[derive(Clone, Copy, Debug)]
pub enum Mmap {
    /// Anonymous mapping created (`addr` is the start of the requested range).
    Mapped(u64),
    NeedsFile(FileMapping),
    Unsupported(Unsupported),
}

/// x86-64 `SYSCALL_DEFINE6(mmap)`: the byte offset must be page aligned.
///
/// # Errors
/// `EINVAL` for an unaligned offset.
pub fn mmap_off_to_pgoff(off: u64) -> Result<u64, Errno> {
    if off & (PAGE_SIZE - 1) != 0 {
        Err(Errno::EINVAL)
    } else {
        Ok(off >> PAGE_SHIFT)
    }
}

/// `check_data_rlimit` (include/linux/mm.h:3570): `true` = over the limit.
fn data_over_limit(rlim: u64, new: u64, start: u64, end_data: u64, start_data: u64) -> bool {
    rlim < RLIM_INFINITY
        && new
            .wrapping_sub(start)
            .wrapping_add(end_data.wrapping_sub(start_data))
            > rlim
}

impl Mm {
    /// `ksys_mmap_pgoff` + `vm_mmap_pgoff` + `do_mmap` for a call that already
    /// passed the x86 offset check ([`mmap_off_to_pgoff`]) and, unless
    /// `MAP_ANONYMOUS`, resolved the descriptor (`EBADF`) into `file`.
    ///
    /// # Errors
    /// Linux's, in Linux's order; see the inline step comments.
    #[allow(
        clippy::too_many_arguments,
        reason = "the six syscall arguments plus the context"
    )]
    pub fn mmap(
        &mut self,
        env: &Env,
        pt: &mut (impl UserPages + ?Sized),
        addr: u64,
        len: u64,
        prot: u64,
        flags: u64,
        pgoff: u64,
        file: Option<&FileInfo>,
    ) -> Result<Mmap, Errno> {
        // ksys_mmap_pgoff: hugetlb files and MAP_HUGETLB
        match file {
            Some(f) if f.hugepages => return Ok(Mmap::Unsupported(Unsupported::Hugetlb)),
            Some(_) if flags & MAP_HUGETLB != 0 => return Err(Errno::EINVAL),
            None if flags & MAP_HUGETLB != 0 => {
                return Ok(Mmap::Unsupported(Unsupported::Hugetlb));
            }
            _ => {}
        }
        // (security_mmap_file / fsnotify_mmap_perm: permissive, no LSM.)
        let r = self.do_mmap(env, addr, len, prot, flags, pgoff, file)?;
        match r {
            Prepared::Anonymous {
                addr,
                len,
                vm_flags,
                pgoff,
                populate,
            } => {
                self.mmap_region(env, pt, None, addr, len, vm_flags, pgoff)?;
                if populate != 0 {
                    self.populate(pt, addr, populate);
                }
                Ok(Mmap::Mapped(addr))
            }
            Prepared::File(m) => Ok(Mmap::NeedsFile(m)),
            Prepared::Unsupported(u) => Ok(Mmap::Unsupported(u)),
        }
    }

    /// `do_mmap` up to (not including) `mmap_region`. Changes nothing.
    #[allow(
        clippy::too_many_lines,
        clippy::too_many_arguments,
        reason = "one function per Linux function, step for step"
    )]
    fn do_mmap(
        &self,
        env: &Env,
        addr: u64,
        len: u64,
        prot: u64,
        mut flags: u64,
        mut pgoff: u64,
        file: Option<&FileInfo>,
    ) -> Result<Prepared, Errno> {
        if len == 0 {
            return Err(Errno::EINVAL);
        }
        // READ_IMPLIES_EXEC: a 64-bit task never has it (elf_read_implies_exec
        // is 32-bit only), so `prot` is used as given.
        // force arch specific MAP_FIXED handling in get_unmapped_area
        if flags & MAP_FIXED_NOREPLACE != 0 {
            flags |= MAP_FIXED;
        }
        let addr = if flags & MAP_FIXED == 0 {
            round_hint_to_min(env, addr)
        } else {
            addr
        };
        // Careful about overflows..
        let len = align_or_zero(len);
        if len == 0 {
            return Err(Errno::ENOMEM);
        }
        // offset overflow?
        if pgoff.wrapping_add(len >> PAGE_SHIFT) < pgoff {
            return Err(Errno::EOVERFLOW);
        }
        // Too many mappings?
        if self.map_count() > u64::from(env.max_map_count) {
            return Err(Errno::ENOMEM);
        }
        // prot == PROT_EXEC would pick execute_only_pkey(): -1 without OSPKE.
        let mut vm_flags = calc_vm_prot_bits(prot)
            | calc_vm_flag_bits(flags)
            | self.def_flags
            | VmFlags::MAYREAD
            | VmFlags::MAYWRITE
            | VmFlags::MAYEXEC;

        let addr = self.get_unmapped_area(
            env,
            addr,
            len,
            if file.is_some() { pgoff } else { 0 },
            flags,
        )?;

        if flags & MAP_FIXED_NOREPLACE != 0
            && self.find_vma_intersection(addr, addr + len).is_some()
        {
            return Err(Errno::EEXIST);
        }
        // can_do_mlock()
        if flags & MAP_LOCKED != 0 && env.rlimit_memlock == 0 && !env.cap_ipc_lock {
            return Err(Errno::EPERM);
        }
        if !self.mlock_future_ok(env, vm_flags, len) {
            return Err(Errno::EAGAIN);
        }

        if let Some(file) = file {
            // file_mmap_ok
            let maxsize = file.mmap_size_max;
            if maxsize != 0 && len > maxsize {
                return Err(Errno::EOVERFLOW);
            }
            if pgoff > maxsize.wrapping_sub(len) >> PAGE_SHIFT {
                return Err(Errno::EOVERFLOW);
            }
            let mut flags_mask = LEGACY_MAP_MASK;
            if file.mmap_sync {
                flags_mask |= super::flags::MAP_SYNC;
            }
            match flags & MAP_TYPE {
                MAP_SHARED | MAP_SHARED_VALIDATE => {
                    if flags & MAP_TYPE == MAP_SHARED {
                        // Silently ignore unsupported flags with MAP_SHARED.
                        flags &= LEGACY_MAP_MASK;
                    }
                    if flags & !flags_mask != 0 {
                        return Err(Errno::EOPNOTSUPP);
                    }
                    if prot & PROT_WRITE != 0 {
                        if !file.writable {
                            return Err(Errno::EACCES);
                        }
                        if file.swapfile {
                            return Err(Errno::ETXTBSY);
                        }
                    }
                    // Do not allow writing to an append-only file.
                    if file.append_only && file.writable {
                        return Err(Errno::EACCES);
                    }
                    vm_flags |= VmFlags::SHARED | VmFlags::MAYSHARE;
                    if !file.writable {
                        vm_flags &= !(VmFlags::MAYWRITE | VmFlags::SHARED);
                    }
                }
                MAP_PRIVATE => {}
                _ => return Err(Errno::EINVAL),
            }
            if !file.readable {
                return Err(Errno::EACCES);
            }
            if file.noexec {
                if vm_flags.contains(VmFlags::EXEC) {
                    return Err(Errno::EPERM);
                }
                vm_flags &= !VmFlags::MAYEXEC;
            }
            if !file.can_mmap {
                return Err(Errno::ENODEV);
            }
            if vm_flags.contains(VmFlags::GROWSDOWN) {
                return Err(Errno::EINVAL);
            }
            // (memfd_check_seals_mmap: no memfd yet, see docs/implementation.md.)
        } else {
            match flags & MAP_TYPE {
                MAP_SHARED => {
                    if vm_flags.contains(VmFlags::GROWSDOWN) {
                        return Err(Errno::EINVAL);
                    }
                    // Ignore pgoff; shmem_zero_setup would follow.
                    vm_flags |= VmFlags::SHARED | VmFlags::MAYSHARE;
                    return Ok(Prepared::Unsupported(Unsupported::SharedAnonymous));
                }
                MAP_DROPPABLE => {
                    // A locked or stack area makes no sense to be droppable.
                    if flags & (MAP_LOCKED | MAP_HUGETLB) != 0 {
                        return Err(Errno::EINVAL);
                    }
                    if vm_flags.contains(VmFlags::GROWSDOWN) {
                        return Err(Errno::EINVAL);
                    }
                    vm_flags |= VmFlags::DROPPABLE
                        | VmFlags::NORESERVE
                        | VmFlags::WIPEONFORK
                        | VmFlags::DONTDUMP;
                    pgoff = addr >> PAGE_SHIFT;
                }
                MAP_PRIVATE => {
                    // Set pgoff according to addr for anon_vma.
                    pgoff = addr >> PAGE_SHIFT;
                }
                _ => return Err(Errno::EINVAL),
            }
        }

        // Set 'VM_NORESERVE' if we should not account for the memory use of
        // this mapping. (sysctl_overcommit_memory != OVERCOMMIT_NEVER always.)
        if flags & MAP_NORESERVE != 0 {
            vm_flags |= VmFlags::NORESERVE;
        }

        let populate = if vm_flags.contains(VmFlags::LOCKED)
            || flags & (MAP_POPULATE | MAP_NONBLOCK) == MAP_POPULATE
        {
            len
        } else {
            0
        };
        Ok(match file {
            Some(f) => Prepared::File(FileMapping {
                addr,
                len,
                vm_flags,
                pgoff,
                file: *f,
                populate,
            }),
            None => Prepared::Anonymous {
                addr,
                len,
                vm_flags,
                pgoff,
                populate,
            },
        })
    }

    /// `mmap_region`: map `[addr, addr + len)` (aligned, in range, flags and
    /// `pgoff` final), replacing whatever was mapped there.
    ///
    /// On `Err` the tables and statistics are unchanged; the VMAs overlapping
    /// the range may have been split at its edges, exactly as `__mmap_setup`
    /// leaves them when a later check fails.
    ///
    /// # Errors
    /// `ENOMEM`: `max_map_count` for a hole punch, `RLIMIT_AS`/`RLIMIT_DATA`,
    /// the overcommit policy, or storage.
    #[allow(
        clippy::too_many_arguments,
        reason = "mmap_region's own parameter list"
    )]
    pub fn mmap_region(
        &mut self,
        env: &Env,
        pt: &mut (impl UserPages + ?Sized),
        file: Option<u64>,
        addr: u64,
        len: u64,
        mut vm_flags: VmFlags,
        pgoff: u64,
    ) -> Result<u64, Errno> {
        // (MDWE off; arch_validate_flags is true on x86.)
        let end = addr + len;
        let pglen = len >> PAGE_SHIFT;
        // __mmap_setup: gather overlapping VMAs
        let (lo, g) = match self.vma_find(addr, end) {
            Some(first) => {
                let g = self.gather_munmap(env, first, addr, end)?;
                (g.lo, g)
            }
            None => (self.lower(addr), super::space::Gathered::default()),
        };
        // Check against address space limit.
        if !self.may_expand_vm(env, vm_flags, pglen - g.nr_pages) {
            return enomem();
        }
        // Private writable mapping: check memory availability.
        if (vm_flags & (VmFlags::NORESERVE | VmFlags::SHARED | VmFlags::WRITE)) == VmFlags::WRITE {
            let charged = pglen - g.nr_accounted;
            if charged != 0 && !env.enough_memory(charged) {
                return enomem();
            }
            vm_flags |= VmFlags::ACCOUNT;
        }
        // vma_iter_prealloc for a new VMA; nothing is modified until it exists.
        self.reserve(1)?;

        // __mmap_complete's vms_complete_munmap_vmas, then the new range.
        pt.unmap(addr, pglen);
        self.complete_munmap(&g);
        let req = MergeReq {
            start: addr,
            end,
            flags: vm_flags,
            pgoff,
            file,
            anon: None,
        };
        let idx = if let Some(i) = self.merge_new_range(lo, &req, false) {
            i
        } else {
            self.insert_at(
                lo,
                Vma {
                    start: addr,
                    end,
                    flags: vm_flags,
                    pgoff,
                    file,
                    anon: None,
                },
            )?;
            lo
        };
        let flags = self.vmas[idx].flags;
        self.stat_add(flags, pglen);
        if flags.contains(VmFlags::LOCKED) {
            self.locked_vm += pglen;
        }
        Ok(addr)
    }

    /// `munmap(2)` (`__vm_munmap` -> `do_vmi_munmap`).
    ///
    /// # Errors
    /// `EINVAL` (unaligned, out of range or zero length), `ENOMEM` (a hole
    /// punch past `max_map_count`, or storage; an earlier first split stays).
    pub fn munmap(
        &mut self,
        env: &Env,
        pt: &mut (impl UserPages + ?Sized),
        start: u64,
        len: u64,
    ) -> Result<(), Errno> {
        if offset_in_page(start) != 0 || start > TASK_SIZE || len > TASK_SIZE - start {
            return Err(Errno::EINVAL);
        }
        let end = start + align_or_zero(len);
        if end == start {
            return Err(Errno::EINVAL);
        }
        let Some(first) = self.vma_find(start, end) else {
            return Ok(());
        };
        let g = self.gather_munmap(env, first, start, end)?;
        pt.unmap(start, (end - start) >> PAGE_SHIFT);
        self.complete_munmap(&g);
        Ok(())
    }

    /// `check_brk_limits`.
    fn check_brk_limits(&self, env: &Env, addr: u64, len: u64) -> Result<(), Errno> {
        self.get_unmapped_area(env, addr, len, 0, MAP_FIXED)?;
        if self.mlock_future_ok(env, self.def_flags, len) {
            Ok(())
        } else {
            Err(Errno::EAGAIN)
        }
    }

    /// `do_brk_flags`: extend the VMA `prev` (which must end at `addr`) or
    /// create a new anonymous VMA for `[addr, addr + len)`.
    fn do_brk_flags(
        &mut self,
        env: &Env,
        prev: Option<usize>,
        addr: u64,
        len: u64,
        vm_flags: VmFlags,
    ) -> Result<(), Errno> {
        let vm_flags = vm_flags | VmFlags::DATA_DEFAULT | VmFlags::ACCOUNT | self.def_flags;
        let pages = len >> PAGE_SHIFT;
        if !self.may_expand_vm(env, vm_flags, pages) {
            return enomem();
        }
        if self.map_count() > u64::from(env.max_map_count) {
            return enomem();
        }
        if !env.enough_memory(pages) {
            return enomem();
        }
        let req = MergeReq {
            start: addr,
            end: addr + len,
            flags: vm_flags,
            pgoff: addr >> PAGE_SHIFT,
            file: None,
            anon: None,
        };
        // Expand the existing vma if possible.
        let merged = prev
            .filter(|&p| self.vmas[p].end == addr)
            .and_then(|p| self.merge_new_range(p + 1, &req, true));
        if merged.is_none() {
            let at = self.lower(addr);
            self.insert_at(
                at,
                Vma {
                    start: addr,
                    end: addr + len,
                    flags: vm_flags,
                    pgoff: req.pgoff,
                    file: None,
                    anon: None,
                },
            )?;
        }
        self.total_vm += pages;
        self.data_vm += pages;
        if vm_flags.contains(VmFlags::LOCKED) {
            self.locked_vm += pages;
        }
        Ok(())
    }

    /// `vm_brk_flags` (loader `.bss`): map zeroed anonymous memory at a fixed
    /// address, replacing what is there.
    ///
    /// # Errors
    /// As Linux: `ENOMEM` on overflow, `EINVAL` for flags other than `VM_EXEC`,
    /// the `check_brk_limits`/`do_vmi_munmap`/`do_brk_flags` errors.
    pub fn vm_brk_flags(
        &mut self,
        env: &Env,
        pt: &mut (impl UserPages + ?Sized),
        addr: u64,
        request: u64,
        vm_flags: VmFlags,
    ) -> Result<(), Errno> {
        let len = align_or_zero(request);
        if len < request {
            return enomem();
        }
        if len == 0 {
            return Ok(());
        }
        // Until we need other flags, refuse anything except VM_EXEC.
        if vm_flags & !VmFlags::EXEC != VmFlags::NONE {
            return Err(Errno::EINVAL);
        }
        self.check_brk_limits(env, addr, len)?;
        self.munmap(env, pt, addr, len)?;
        let prev = self.lower(addr).checked_sub(1);
        self.do_brk_flags(env, prev, addr, len, vm_flags)?;
        if self.def_flags.contains(VmFlags::LOCKED) {
            self.populate(pt, addr, len);
        }
        Ok(())
    }

    /// `brk(2)`: returns the new break, or the unchanged old break on any
    /// failure (Linux's `brk` never returns an errno).
    pub fn brk(&mut self, env: &Env, pt: &mut (impl UserPages + ?Sized), brk: u64) -> u64 {
        let orig = self.brk;
        // CONFIG_COMPAT_BRK is n: min_brk = start_brk.
        if brk < self.start_brk {
            return orig;
        }
        // Check against rlimit here, before the oldbrk == newbrk shortcut.
        if data_over_limit(
            env.rlimit_data,
            brk,
            self.start_brk,
            self.end_data,
            self.start_data,
        ) {
            return orig;
        }
        let newbrk = align_or_zero(brk);
        let oldbrk = align_or_zero(self.brk);
        if oldbrk == newbrk {
            self.brk = brk;
            return brk;
        }
        // Always allow shrinking brk.
        if brk <= self.brk {
            // Search one past newbrk.
            let Some(first) = self.vma_find(newbrk, oldbrk) else {
                return orig; // mapping intersects with an existing non-brk vma
            };
            if self.vmas[first].start >= oldbrk {
                return orig;
            }
            match self.gather_munmap(env, first, newbrk, oldbrk) {
                Ok(g) => {
                    pt.unmap(newbrk, (oldbrk - newbrk) >> PAGE_SHIFT);
                    self.complete_munmap(&g);
                    self.brk = brk;
                    return brk;
                }
                Err(_) => return orig,
            }
        }
        if self
            .check_brk_limits(env, oldbrk, newbrk.wrapping_sub(oldbrk))
            .is_err()
        {
            return orig;
        }
        // Only check if the next VMA is within the stack_guard_gap of the
        // expansion area.
        let next = self.vma_find(
            oldbrk,
            newbrk
                .wrapping_add(PAGE_SIZE)
                .wrapping_add(env.stack_guard_gap),
        );
        if let Some(i) = next
            && newbrk + PAGE_SIZE > Self::vm_start_gap(env, &self.vmas[i])
        {
            return orig;
        }
        let prev = self.brk_prev(oldbrk, next);
        if self
            .do_brk_flags(env, prev, oldbrk, newbrk - oldbrk, VmFlags::NONE)
            .is_err()
        {
            return orig;
        }
        self.brk = brk;
        if self.def_flags.contains(VmFlags::LOCKED) {
            self.populate(pt, oldbrk, newbrk - oldbrk);
        }
        brk
    }

    /// `vma_prev_limit(&vmi, mm->start_brk)` after `vma_find` left the
    /// iterator at `next`: the VMA before the break, unless the empty range
    /// between it and `next` reaches down to `start_brk` (maple tree
    /// `mas_prev_slot`: an empty slot starting at or below `min` underflows).
    fn brk_prev(&self, oldbrk: u64, next: Option<usize>) -> Option<usize> {
        let p = self.lower(oldbrk).checked_sub(1)?;
        let adjacent = next.is_some_and(|n| self.vmas[n].start == self.vmas[p].end);
        (adjacent || self.vmas[p].end > self.start_brk).then_some(p)
    }

    /// `mprotect(2)` (`do_mprotect_pkey` with `pkey == -1`).
    ///
    /// Errors partway leave the VMAs already processed changed, as in Linux.
    ///
    /// # Errors
    /// `EINVAL`, `ENOMEM` (length wrap, unmapped hole, limits, split
    /// failure), `EACCES` (beyond `VM_MAY*`).
    pub fn mprotect(
        &mut self,
        env: &Env,
        pt: &mut (impl UserPages + ?Sized),
        mut start: u64,
        len: u64,
        mut prot: u64,
    ) -> Result<(), Errno> {
        let grows = prot & (PROT_GROWSDOWN | PROT_GROWSUP);
        // (rier: READ_IMPLIES_EXEC is never set for a 64-bit task.)
        prot &= !(PROT_GROWSDOWN | PROT_GROWSUP);
        if grows == (PROT_GROWSDOWN | PROT_GROWSUP) {
            return Err(Errno::EINVAL); // can't be both
        }
        if offset_in_page(start) != 0 {
            return Err(Errno::EINVAL);
        }
        if len == 0 {
            return Ok(());
        }
        let len = align_or_zero(len);
        let end = start.wrapping_add(len);
        if end <= start {
            return Err(Errno::ENOMEM);
        }
        // arch_validate_prot
        if prot & !(PROT_READ | PROT_WRITE | PROT_EXEC | PROT_SEM) != 0 {
            return Err(Errno::EINVAL);
        }
        let Some(first) = self.vma_find(start, end) else {
            return Err(Errno::ENOMEM);
        };
        let v = self.vmas[first];
        if grows & PROT_GROWSDOWN != 0 {
            if v.start >= end {
                return Err(Errno::ENOMEM);
            }
            start = v.start;
            if !v.flags.contains(VmFlags::GROWSDOWN) {
                return Err(Errno::EINVAL);
            }
        } else {
            if v.start > start {
                return Err(Errno::ENOMEM);
            }
            if grows & PROT_GROWSUP != 0 {
                // end = vma->vm_end; then VM_GROWSUP (== VM_NONE on x86, so
                // `!(flags & VM_GROWSUP)` always holds) is required.
                return Err(Errno::EINVAL);
            }
        }
        let mut cursor = start;
        while cursor < end {
            let Some(idx) = self.vma_find(cursor, end) else {
                break;
            };
            let v = self.vmas[idx];
            // A hole before this VMA (a merged neighbour may start earlier).
            if v.start > cursor {
                return Err(Errno::ENOMEM);
            }
            // Each mprotect() call explicitly passes r/w/x permissions.
            let mut newflags = calc_vm_prot_bits(prot) | (v.flags & !VmFlags::ACCESS);
            // newflags >> 4 shift VM_MAY% in place of VM_%
            if (newflags.0 & !(newflags.0 >> 4)) & VmFlags::ACCESS.0 != 0 {
                return Err(Errno::EACCES);
            }
            // (MDWE, arch_validate_flags, security_file_mprotect: nothing to refuse.)
            let seg_end = v.end.min(end);
            self.mprotect_fixup(env, pt, idx, cursor, seg_end, &mut newflags)?;
            cursor = seg_end;
        }
        if cursor < end {
            Err(Errno::ENOMEM)
        } else {
            Ok(())
        }
    }

    /// `mprotect_fixup`.
    fn mprotect_fixup(
        &mut self,
        env: &Env,
        pt: &mut (impl UserPages + ?Sized),
        idx: usize,
        start: u64,
        end: u64,
        newflags: &mut VmFlags,
    ) -> Result<(), Errno> {
        let v = self.vmas[idx];
        let oldflags = v.flags;
        let nrpages = (end - start) >> PAGE_SHIFT;
        if *newflags == oldflags {
            return Ok(());
        }
        // If we make a private mapping writable we increase our commit; but
        // (without finer accounting) cannot reduce our commit if we make it
        // unwritable again except in the anonymous case where no anon_vma has
        // yet been assigned.
        if newflags.contains(VmFlags::WRITE) {
            // Check space limits when area turns into data.
            if !self.may_expand_vm(env, *newflags, nrpages)
                && self.may_expand_vm(env, oldflags, nrpages)
            {
                return enomem();
            }
            if !oldflags.intersects(
                VmFlags::ACCOUNT
                    | VmFlags::WRITE
                    | VmFlags::HUGETLB
                    | VmFlags::SHARED
                    | VmFlags::NORESERVE,
            ) {
                if !env.enough_memory(nrpages) {
                    return enomem();
                }
                *newflags |= VmFlags::ACCOUNT;
            }
        } else if oldflags.contains(VmFlags::ACCOUNT) && v.is_anonymous() && v.anon.is_none() {
            *newflags &= !VmFlags::ACCOUNT;
        }
        let at = self.vma_modify(env, idx, start, end, *newflags)?;
        self.vmas[at].flags = *newflags;
        pt.protect(start, nrpages, page_prot(*newflags));
        // Private VM_LOCKED VMA becoming writable: trigger COW to avoid major
        // fault on access.
        if (oldflags & (VmFlags::WRITE | VmFlags::SHARED | VmFlags::LOCKED)) == VmFlags::LOCKED
            && newflags.contains(VmFlags::WRITE)
        {
            self.populate(pt, start, end - start);
        }
        self.stat_sub(oldflags, nrpages);
        self.stat_add(*newflags, nrpages);
        Ok(())
    }
}

/// The result of `do_mmap`'s validation phase.
enum Prepared {
    Anonymous {
        addr: u64,
        len: u64,
        vm_flags: VmFlags,
        pgoff: u64,
        populate: u64,
    },
    File(FileMapping),
    Unsupported(Unsupported),
}
