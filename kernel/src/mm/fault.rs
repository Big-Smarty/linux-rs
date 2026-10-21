// SPDX-License-Identifier: GPL-2.0-only
// Linux 6.18.57 (2ff600d29ee478d0a8d46ef8a58afb5e038fe692): arch/x86/mm/fault.c
// (`handle_page_fault`, `do_kern_addr_fault`, `do_user_addr_fault`,
// `access_error`, `bad_area_*`, `pgtable_bad`), mm/mmap_lock.c
// (`lock_mm_and_find_vma`, `lock_vma_under_rcu`), mm/mmap.c
// (`expand_stack_locked`), mm/memory.c (`handle_mm_fault`,
// `handle_pte_fault`, `do_anonymous_page`, `do_wp_page`), mm/gup.c
// (`populate_vma_page_range`, `__mm_populate`). GPL-2.0.
// Transformation: the per-VMA-lock fast path and the mmap-lock path have the
// same outcome for one task and are one path; retries, signals pending, the
// OOM killer, perf events and accounting counters are the caller's.
#![forbid(unsafe_code)]
//! The user page-fault decision: which VMA, whether the access is allowed,
//! stack expansion, and the demand-zero / copy-on-write action on the page
//! tables, with the signal the faulting task gets when it is refused.
//!
//! # Contract
//! * Called for a fault taken in user mode (`PF_USER` set), with the faulting
//!   address from CR2 and the hardware error code. A kernel-mode fault on a
//!   user address is resolved by the usercopy layer before the access, so it
//!   never reaches here; a kernel-mode instruction fetch from user memory
//!   (`(error_code & (PF_USER | PF_INSTR)) == PF_INSTR`) is an oops the caller
//!   handles before calling.
//! * The vsyscall page: the reference configuration has
//!   `CONFIG_LEGACY_VSYSCALL_XONLY=y`, so a user instruction fetch there is
//!   emulated by `emulate_vsyscall`, which this model does not implement. It is
//!   reported as the distinct, loud [`FaultOutcome::Vsyscall`] (never a quiet
//!   `SIGSEGV`); only the cases where `emulate_vsyscall` itself returns false
//!   (a write, or a data read) continue to `SEGV_MAPERR`.
//! * Not modelled, named: protection keys and shadow stacks
//!   (the declared CPU/config has neither, so `PF_PK`/`PF_SHSTK`/`PF_SGX` are
//!   always an access error), prefetch erratum fix-ups (`is_prefetch`).

use super::{
    env::Env,
    flags::{PAGE_SIZE, VmFlags, page_floor, page_prot},
    pt::{Pte, UserPages},
    space::Mm,
};
use crate::usercopy::TASK_SIZE_MAX;

/// `VSYSCALL_ADDR` (-10 MiB).
pub const VSYSCALL_ADDR: u64 = 0xffff_ffff_ff60_0000;
pub const PF_PROT: u64 = 1 << 0;
pub const PF_WRITE: u64 = 1 << 1;
pub const PF_USER: u64 = 1 << 2;
pub const PF_RSVD: u64 = 1 << 3;
pub const PF_INSTR: u64 = 1 << 4;
pub const PF_PK: u64 = 1 << 5;
pub const PF_SHSTK: u64 = 1 << 6;
pub const PF_SGX: u64 = 1 << 15;

/// `bad_area_access_from_pkeys` for a VMA whose key is 0 (every mapping of this kernel), called
/// for an access error with protection keys on: the hardware reported a protection-key fault, or
/// `arch_vma_access_permitted` finds the access denied by the task's `pkru` (instruction fetches
/// are never affected by it; access-disable also denies writes). `true` is `SEGV_PKUERR`.
#[must_use]
pub fn pkru_denies_key0(error_code: u64, pkru: u32) -> bool {
    const AD: u32 = 1;
    const WD: u32 = 2;
    if error_code & PF_PK != 0 {
        return true;
    }
    if error_code & PF_INSTR != 0 {
        return false;
    }
    let denied = if error_code & PF_WRITE != 0 {
        AD | WD
    } else {
        AD
    };
    pkru & denied != 0
}

/// `si_code` of `SIGSEGV`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SegvCode {
    /// `SEGV_MAPERR`: address not mapped to an object.
    MapErr = 1,
    /// `SEGV_ACCERR`: invalid permissions for a mapped object.
    AccErr = 2,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FaultOutcome {
    /// The page tables now allow a retry of the faulting instruction.
    Handled,
    /// `force_sig_fault(SIGSEGV, code, address)`; `address` is the exact CR2.
    Segv { code: SegvCode, address: u64 },
    /// `do_sigbus`: `SIGBUS`, `BUS_ADRERR`.
    Bus { address: u64 },
    /// `VM_FAULT_OOM`: `pagefault_out_of_memory()` (the OOM killer decides).
    Oom,
    /// `pgtable_bad`: a reserved bit in a user PTE; Linux oopses and kills the
    /// task with `SIGKILL`.
    PgtableBad,
    /// A user instruction fetch at the vsyscall page (`0xffffffffff600000`
    /// page): Linux emulates `gettimeofday`/`time`/`getcpu` here
    /// (`emulate_vsyscall`, `vsyscall=xonly`). Not implemented: the caller must
    /// stop loudly or implement the emulation; nothing was changed.
    Vsyscall { address: u64, error_code: u64 },
    /// The VMA is file-backed: `->fault`/`do_wp_page` need the page cache.
    NeedsFile { address: u64, write: bool },
}

enum Step {
    Oom,
    Bus,
    NeedsFile,
}

/// `access_error` (arch/x86/mm/fault.c:1048): `true` = refuse with `SEGV_ACCERR`.
#[must_use]
fn access_error(error_code: u64, flags: VmFlags) -> bool {
    // PK and SGX hardware blocks, and shadow-stack accesses (no VM_SHADOW_STACK
    // VMA exists), can never be resolved by a follow-up action.
    if error_code & (PF_PK | PF_SGX | PF_SHSTK) != 0 {
        return true;
    }
    // write, present and write, not present
    if error_code & PF_WRITE != 0 {
        return !flags.contains(VmFlags::WRITE);
    }
    // read, present
    if error_code & PF_PROT != 0 {
        return true;
    }
    // read, not present
    !flags.intersects(VmFlags::ACCESS)
}

impl Mm {
    /// `do_user_addr_fault` (+ `do_kern_addr_fault` for a user access to a
    /// kernel address).
    pub fn handle_user_fault(
        &mut self,
        env: &Env,
        pt: &mut (impl UserPages + ?Sized),
        address: u64,
        error_code: u64,
    ) -> FaultOutcome {
        let segv = |code| FaultOutcome::Segv { code, address };
        // fault_in_kernel_space(): everything at or above TASK_SIZE_MAX that
        // is not the vsyscall page ends in bad_area_nosemaphore.
        let vsyscall = address & !(PAGE_SIZE - 1) == VSYSCALL_ADDR;
        if address >= TASK_SIZE_MAX && !vsyscall {
            return segv(SegvCode::MapErr);
        }
        // Reserved bits are never expected in the user portion of the tables.
        if error_code & PF_RSVD != 0 {
            return FaultOutcome::PgtableBad;
        }
        // emulate_vsyscall(): writes and kernel-privilege faults are never
        // fixed up; a data read is denied (`address != regs->ip`), approximated
        // by PF_INSTR since the instruction pointer is not an input here.
        if vsyscall && error_code & (PF_WRITE | PF_USER) == PF_USER && error_code & PF_INSTR != 0 {
            return FaultOutcome::Vsyscall {
                address,
                error_code,
            };
        }
        let write = error_code & (PF_WRITE | PF_SHSTK) != 0;

        // lock_mm_and_find_vma
        let mut idx = self.lower(address);
        match self.vmas.get(idx) {
            Some(v) if v.start <= address => {}
            Some(v) if v.flags.contains(VmFlags::GROWSDOWN) => {
                // We might still be successful, but only by extending a vma.
                if self.expand_downwards(env, idx, address).is_err() {
                    return segv(SegvCode::MapErr);
                }
            }
            _ => return segv(SegvCode::MapErr),
        }
        idx = self.lower(address);
        if access_error(error_code, self.vmas[idx].flags) {
            return segv(SegvCode::AccErr);
        }
        match self.fault_one(pt, idx, address, write) {
            Ok(()) => FaultOutcome::Handled,
            Err(Step::Oom) => FaultOutcome::Oom,
            Err(Step::Bus) => FaultOutcome::Bus { address },
            Err(Step::NeedsFile) => FaultOutcome::NeedsFile { address, write },
        }
    }

    /// `handle_mm_fault` -> `handle_pte_fault` for an anonymous VMA.
    fn fault_one(
        &mut self,
        pt: &mut (impl UserPages + ?Sized),
        idx: usize,
        address: u64,
        write: bool,
    ) -> Result<(), Step> {
        let v = self.vmas[idx];
        let page = page_floor(address);
        let prot = page_prot(v.flags);
        // A file VMA has no page cache to fault from yet (`NeedsFile`), but the
        // loader (and the future page cache) installs the pages it owns as
        // private frames. A present one is exactly what `wp_page_copy` would
        // have produced, so only the write-protect upgrade below applies.
        if !v.is_anonymous() && !matches!(pt.lookup(page), Pte::Anon { .. }) {
            return Err(Step::NeedsFile);
        }
        match pt.lookup(page) {
            Pte::Absent => {
                // do_anonymous_page: File mapping without ->vm_ops?
                if v.flags.contains(VmFlags::SHARED) {
                    return Err(Step::Bus);
                }
                if write {
                    self.anon_vma_prepare(idx);
                    pt.map_anon_page(page, prot).map_err(|_| Step::Oom)?;
                } else {
                    // Use the zero-page for reads.
                    pt.map_zero_page(page, prot).map_err(|_| Step::Oom)?;
                }
            }
            Pte::ZeroPage => {
                if write {
                    // do_wp_page -> wp_page_copy
                    self.anon_vma_prepare(idx);
                    pt.map_anon_page(page, prot).map_err(|_| Step::Oom)?;
                }
            }
            Pte::Anon { writable } => {
                // do_wp_page -> wp_page_reuse: no fork, so the page is exclusive.
                if write && !writable {
                    pt.make_writable(page);
                }
            }
        }
        Ok(())
    }

    /// `mm_populate` / `__mm_populate` with `ignore_errors`: fault in the
    /// pages of `[start, start + len)` that lie in accessible anonymous VMAs,
    /// writing where `populate_vma_page_range` sets `FOLL_WRITE`
    /// (`(vm_flags & (VM_WRITE | VM_SHARED)) == VM_WRITE`). Errors are ignored.
    pub fn populate(&mut self, pt: &mut (impl UserPages + ?Sized), start: u64, len: u64) {
        let end = start.saturating_add(len);
        let mut idx = self.lower(start);
        while let Some(v) = self.vmas.get(idx).copied() {
            if v.start >= end {
                break;
            }
            if v.is_anonymous()
                && v.is_accessible()
                && !v.flags.intersects(VmFlags::IO | VmFlags::PFNMAP)
            {
                let write = (v.flags & (VmFlags::WRITE | VmFlags::SHARED)) == VmFlags::WRITE;
                let mut a = v.start.max(page_floor(start));
                while a < v.end.min(end) {
                    let _ = self.fault_one(pt, idx, a, write);
                    a += PAGE_SIZE;
                }
            }
            idx += 1;
        }
    }
}
