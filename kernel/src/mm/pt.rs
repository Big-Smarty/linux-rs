// SPDX-License-Identifier: GPL-2.0-only
// Linux 6.18.57 (2ff600d29ee478d0a8d46ef8a58afb5e038fe692): mm/memory.c
// (`handle_pte_fault`, `do_anonymous_page`, `do_wp_page`), mm/mprotect.c
// (`change_protection`), mm/vma.c (`vms_clear_ptes`). GPL-2.0.
#![forbid(unsafe_code)]
//! The page-table side of the memory-mapping rules. The address-space model
//! decides *what* the tables must hold; the kernel's paging owner implements
//! these six operations on the real tables (and flushes the TLB), a host fake
//! implements them in tests.
//!
//! # Contract for implementors
//! * Context: task context, the caller holds the address-space lock (the one
//!   task, today). None of the methods sleeps or reclaims.
//! * `lookup`, `unmap` and `protect` never fail. Only the two `map_*` methods
//!   allocate (page-table and data frames) and may report
//!   [`OutOfMemory`]; on failure they leave the tables exactly as before.
//! * A page-aligned `page`/`start` is always inside the user range; the model
//!   checks that before calling.

use super::flags::PageProt;

/// A frame or page-table allocation failed (`VM_FAULT_OOM`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OutOfMemory;

/// What the tables hold for one user page.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Pte {
    /// No PTE, or a PTE the model never created (`pte_none`).
    Absent,
    /// The shared read-only zero page (`my_zero_pfn`).
    ZeroPage,
    /// A private anonymous frame; `writable` is the hardware write bit.
    Anon { writable: bool },
}

pub trait UserPages {
    #[must_use]
    fn lookup(&self, page: u64) -> Pte;
    /// Map the zero page read-only with `prot`'s exec/NX (`do_anonymous_page`
    /// read fault).
    ///
    /// # Errors
    /// [`OutOfMemory`] if an intermediate table cannot be allocated.
    fn map_zero_page(&mut self, page: u64, prot: PageProt) -> Result<(), OutOfMemory>;
    /// Map a freshly zeroed private frame for a *write* access; hardware
    /// writable iff `prot.write`. Replaces a zero-page mapping
    /// (`wp_page_copy`), after which the old mapping is gone.
    ///
    /// # Errors
    /// [`OutOfMemory`] if a frame or table cannot be allocated.
    fn map_anon_page(&mut self, page: u64, prot: PageProt) -> Result<(), OutOfMemory>;
    /// Set the hardware write bit of an exclusively owned anonymous page
    /// (`wp_page_reuse`).
    fn make_writable(&mut self, page: u64);
    /// Remove every mapping in `[start, start + pages * PAGE_SIZE)`, free the
    /// anonymous frames, flush the TLB. Returns the number of data frames freed.
    fn unmap(&mut self, start: u64, pages: u64) -> u64;
    /// Re-protect existing mappings in the range to `prot` (`change_protection`):
    /// drop the hardware write bit of private pages when `!prot.write`, set NX
    /// from `!prot.exec`, and make the PTE `PAGE_NONE` (frame retained) when
    /// `!prot.accessible`. It must not raise the hardware write bit of a
    /// private page that is not known exclusive; the write fault does that.
    fn protect(&mut self, start: u64, pages: u64, prot: PageProt);
}
