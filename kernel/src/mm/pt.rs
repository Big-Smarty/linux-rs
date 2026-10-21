// SPDX-License-Identifier: GPL-2.0-only
// Linux 6.18.57 (2ff600d29ee478d0a8d46ef8a58afb5e038fe692): mm/memory.c
// (`handle_pte_fault`, `do_anonymous_page`, `do_wp_page`), mm/mprotect.c
// (`change_protection`), mm/vma.c (`vms_clear_ptes`), mm/madvise.c (`guard_install_set_pte`,
// `guard_remove_pte_entry`), mm/memory.c (`zap_nonpresent_ptes`, `handle_pte_marker`). GPL-2.0.
#![forbid(unsafe_code)]
//! The page-table side of the memory-mapping rules. The address-space model
//! decides *what* the tables must hold; the kernel's paging owner implements
//! these six operations on the real tables (and flushes the TLB), a host fake
//! implements them in tests.
//!
//! # Contract for implementors
//! * Context: task context, the caller holds the address-space lock (the one
//!   task, today). None of the methods sleeps or reclaims.
//! * `lookup`, `unmap`, `zap`, `protect`, `remove_guards` and `resident_file_pages` never fail.
//!   Only the `map_*` methods and `install_guards` allocate (page-table and data frames) and
//!   may report [`OutOfMemory`]; `map_*` leave the tables exactly as before on failure (see
//!   [`UserPages::install_guards`] for the other).
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
    /// A guard marker (`PTE_MARKER_GUARD`, `madvise(MADV_GUARD_INSTALL)`): not present, holds
    /// no frame; touching the page is `SIGSEGV`.
    Guard,
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
    /// Remove every mapping in `[start, start + pages * PAGE_SIZE)`, guard markers included
    /// (`ZAP_FLAG_DROP_MARKER` of `unmap_vmas`: `munmap`, a replacing `mmap`, `mremap`), free
    /// the anonymous frames, flush the TLB. Returns the number of data frames freed.
    fn unmap(&mut self, start: u64, pages: u64) -> u64;
    /// `zap_page_range_single` without `ZAP_FLAG_DROP_MARKER` (`MADV_DONTNEED`): as
    /// [`UserPages::unmap`] but guard markers stay. Returns the number of data frames freed.
    fn zap(&mut self, start: u64, pages: u64) -> u64;
    /// `MADV_GUARD_INSTALL`: afterwards every page of the range holds a guard marker. A
    /// populated page is zapped first (its data is gone), a marker already there stays.
    /// Page tables are allocated as needed. On failure the pages before the one that could
    /// not be done are guards (`walk_page_range_mm` leaves what it did), the others unchanged.
    ///
    /// # Errors
    /// [`OutOfMemory`] if a table cannot be allocated.
    fn install_guards(&mut self, start: u64, pages: u64) -> Result<(), OutOfMemory>;
    /// `MADV_GUARD_REMOVE`: clear the guard markers of the range (nothing else changes).
    fn remove_guards(&mut self, start: u64, pages: u64);
    /// The resident pages of the range that are still the file's page-cache page (never written
    /// by the task): the pages `MADV_PAGEOUT` would unmap.
    #[must_use]
    fn resident_file_pages(&self, start: u64, pages: u64) -> u64;
    /// Re-protect existing mappings in the range to `prot` (`change_protection`):
    /// drop the hardware write bit of private pages when `!prot.write`, set NX
    /// from `!prot.exec`, and make the PTE `PAGE_NONE` (frame retained) when
    /// `!prot.accessible`. It must not raise the hardware write bit of a
    /// private page that is not known exclusive; the write fault does that.
    fn protect(&mut self, start: u64, pages: u64, prot: PageProt);
    /// `move_page_tables` (`mremap`): move every mapping of the `pages` pages at `old_start` to
    /// `new_start`, keeping the frames and the entry bits; the destination holds no mapping.
    /// All or nothing: on failure (a table could not be allocated) the tables are exactly as
    /// before.
    ///
    /// # Errors
    /// [`OutOfMemory`] if an intermediate table cannot be allocated.
    fn move_pages(&mut self, old_start: u64, new_start: u64, pages: u64)
    -> Result<(), OutOfMemory>;
}
