// SPDX-License-Identifier: GPL-2.0-only
//! BSP-owned four-level page tables.
//!
//! # Update rules (single CPU; replaces "all writes precede CR3 publication")
//! * Kernel half (PML4 index >= 256): written only by [`Tables::build`] and
//!   [`Tables::map_mmio`], both before [`Tables::activate`] (`map_mmio` refuses
//!   to run on an active tree); immutable afterwards, so it never needs
//!   invalidation. A later ioremap/hotplug mapping needs an explicit extension
//!   of this rule (and a TLB-visible protocol), not a quiet extra caller.
//! * User half (below `TASK_SIZE_MAX`): [`Tables::map_user`] and the `mm_*`
//!   operations (`mm_map_*`, `mm_unmap`, `mm_protect`, ...) may run after
//!   activation. They need
//!   `&mut Tables`. A task's tree is private to it (`userspace::TaskLocal`,
//!   reached only by the running task, no lock), so no other agent edits or
//!   walks the tree meanwhile (a fork reads the parent's tree from the parent's
//!   own context), and no `UserSpace` view (which borrows the same
//!   `&mut Tables`) can hold a frame reference across the edit.
//! * A not-present -> present transition needs no invalidation (hardware
//!   caches no absent entry; SDM Vol. 3 4.10.4.3), and a new intermediate
//!   table is zeroed before its parent entry becomes present.
//! * Clearing or tightening a present PTE (unmap, drop W, set NX) is an
//!   atomic read-modify-write (hardware may set accessed/dirty concurrently)
//!   followed by `invlpg` of that page; only then may a frame be reused or
//!   freed.
//! * `PROT_NONE` representation (`mm_protect`): a user PTE with the present bit
//!   clear, [`PROTNONE`] (bit 8, Linux's `_PAGE_PROTNONE`) set and the frame
//!   address kept **inverted** (arch/x86/include/asm/pgtable-invert.h
//!   `protnone_mask`, `pte_pfn`, `pfn_pte`: a non-zero entry with P clear
//!   stores the complement of its frame bits, so an L1TF-affected CPU that
//!   speculatively walks a not-present entry reaches a non-existent address,
//!   not the page's data; only [`leaf_entry`] and [`frame_bits`] touch the
//!   address field of a leaf). Hardware ignores every other bit of a
//!   not-present entry, so it faults with P=0, while software still knows
//!   which frame the page holds (`pte_present()` in Linux is "P or PROTNONE").
//!   Every walker that means "mapped" tests [`MAPPED`], every walker that means
//!   "reachable by the CPU" tests `PRESENT` (so `usercopy` refuses it).
//! * The shared zero page (`mm_map_zero`) is one frame allocated at boot
//!   ([`Tables::init_zero_page`]), mapped read-only by any number of PTEs and
//!   never reclaimed: `mm_unmap` recognises it by address.
//! * Intermediate user tables are never freed before address-space teardown.
//!   Teardown is [`Tables::destroy_user`] (`exit_mmap` + `free_pgtables` +
//!   `pgd_free`): the whole user half of a tree that is not the active one.
//!   `execve` keeps its tree (it unmaps the old image and builds the new one
//!   in place); the tables it leaves behind are reused.
//! * Every task has its own tree (`pgd_alloc`: [`Tables::fork_template`] or
//!   [`Tables::fork_user`]), whose upper half is a copy of the PML4 entries of
//!   the tree it came from. The kernel half is immutable after
//!   publication (above), so the shared lower-level tables never change under
//!   any of the copies.
//! * shortcut: SMP needs a TLB shootdown (IPI `invlpg` to every CPU that ran the
//!   address space, acknowledged before the frame is freed) in place of the
//!   local `invlpg`; the unfreed-frame ordering stays as above.
//!
//! Hardware accessed/dirty changes are read through raw volatile operations
//! and written (for live entries) through `AtomicU64`; no Rust reference to a
//! live table is formed.
use crate::{
    boot::{BootError, BootInfo},
    cpu,
    memory::{Allocator, Error as MemoryError, PAGE, PAGE_BYTES, Physical, Virtual},
};
use core::{
    ptr,
    sync::atomic::{AtomicU64, Ordering},
};
use kernel::usercopy::{TASK_SIZE_MAX, UserPages};
use x86_64::{VirtAddr, instructions::tlb};

const PRESENT: u64 = 1;
const WRITE: u64 = 2;
const USER: u64 = 4;
const ACCESSED: u64 = 1 << 5;
const DIRTY: u64 = 1 << 6;
const PWT: u64 = 1 << 3;
const PCD: u64 = 1 << 4;
const HUGE: u64 = 1 << 7;
/// Software `_PAGE_PROTNONE` (the global bit position, unused in user PTEs).
const PROTNONE: u64 = 1 << 8;
/// A leaf that holds a page: reachable (`PRESENT`) or `PROT_NONE`.
const MAPPED: u64 = PRESENT | PROTNONE;
/// Software bit (an `AVL` bit the hardware ignores): the page belongs to a file
/// mapping that is still the page-cache page ([`Tables::mm_install_page`] with
/// `file` and no write access): it counts as `RssShmem`, and the private copy
/// the first write makes ([`Tables::mm_make_writable`], `wp_page_copy`) clears it,
/// after which the page is `RssAnon` whatever a later `mprotect` does to the
/// write bit; see [`rss_class`].
const FILE: u64 = 1 << 9;
const NX: u64 = 1 << 63;
const ADDRESS: u64 = 0x000f_ffff_ffff_f000;
const LARGE: u64 = 2 * 1024 * 1024;

/// The frame address a leaf entry designates: a non-zero entry with P clear
/// (a `PROT_NONE` page) holds it complemented (`__pte_needs_invert`).
const fn frame_bits(entry: u64) -> u64 {
    if entry != 0 && entry & PRESENT == 0 {
        !entry & ADDRESS
    } else {
        entry & ADDRESS
    }
}

/// A leaf entry for `frame` with `flags` (`pfn_pte`): the frame is complemented
/// exactly when the entry is not present. Non-present `flags` are never zero
/// (`PROTNONE`), so the cleared entry stays all-zero and is never inverted.
const fn leaf_entry(frame: u64, flags: u64) -> u64 {
    let bits = frame & ADDRESS;
    (if flags & PRESENT == 0 {
        bits ^ ADDRESS
    } else {
        bits
    }) | flags
}

pub enum Error {
    Memory(MemoryError),
    Boot(BootError),
    Address,
    Conflict,
    Overflow,
    /// The isolation audit found a user bit in the kernel half or a user
    /// mapping at or above `TASK_SIZE_MAX`.
    Audit,
    /// A kernel-half edit was requested after CR3 publication.
    Active,
}
impl core::fmt::Debug for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Memory(error) => f.debug_tuple("Memory").field(error).finish(),
            Self::Boot(error) => f.debug_tuple("Boot").field(error).finish(),
            Self::Address => f.write_str("Address"),
            Self::Conflict => f.write_str("Conflict"),
            Self::Overflow => f.write_str("Overflow"),
            Self::Audit => f.write_str("Audit"),
            Self::Active => f.write_str("Active"),
        }
    }
}
impl From<MemoryError> for Error {
    fn from(value: MemoryError) -> Self {
        Self::Memory(value)
    }
}
impl From<BootError> for Error {
    fn from(value: BootError) -> Self {
        Self::Boot(value)
    }
}

unsafe extern "C" {
    static __text_start: u8;
    static __text_end: u8;
    static __rodata_start: u8;
    static __rodata_end: u8;
    static __data_start: u8;
    static __kernel_end: u8;
}

fn entry_pointer(direct_map: u64, physical: Physical, index: usize) -> Result<*mut u64, Error> {
    if physical.0 & (PAGE - 1) != 0 || index >= 512 {
        return Err(Error::Address);
    }
    let address = direct_map
        .checked_add(physical.0)
        .and_then(|n| n.checked_add(index as u64 * 8))
        .ok_or(Error::Overflow)?;
    Ok(ptr::with_exposed_provenance_mut(
        usize::try_from(address).map_err(|_| Error::Overflow)?,
    ))
}
fn read_entry(direct_map: u64, physical: Physical, index: usize) -> Result<u64, Error> {
    let pointer = entry_pointer(direct_map, physical, index)?;
    // SAFETY: root/child ownership originates from live allocated 4KiB RAM;
    // indices <=511, HHDM mapped, u64 aligned/valid. Volatile observes hardware
    // A/D changes without creating references. No software mutator races.
    Ok(unsafe { ptr::read_volatile(pointer) })
}

pub struct Tables {
    root: Physical,
    direct_map: u64,
    pub pages: usize,
    /// The shared read-only zero page, once [`Tables::init_zero_page`] ran.
    zero: Option<Physical>,
    /// The resident user pages that count as `RssAnon` and `RssShmem` (the
    /// zero page counts as neither) and the PUD, PMD and PTE pages of the user
    /// half (`mm_pgtables_bytes`), kept up to date by every edit of a user
    /// entry so `/proc` reads them in constant time. The walks that computed
    /// them ([`Tables::recount`]) remain the boot proofs' cross-check.
    rss_anon: u64,
    rss_shmem: u64,
    user_pt_pages: u64,
}

/// What a leaf entry adds to `(RssAnon, RssShmem)` of an address space whose
/// shared zero page is `zero`: nothing unless it is a present, non-zero page;
/// a page that is still the file's ([`FILE`]) is the page-cache page
/// (`MM_SHMEMPAGES`: every file here is on tmpfs), anything else a private
/// anonymous frame.
fn rss_class(zero: Option<Physical>, entry: u64) -> (u64, u64) {
    if entry & PRESENT == 0 || Some(Physical(entry & ADDRESS)) == zero {
        (0, 0)
    } else if entry & FILE != 0 {
        (0, 1)
    } else {
        (1, 0)
    }
}

impl Tables {
    /// A tree that is only its zeroed root: no user page, no user table.
    const fn empty(root: Physical, direct_map: u64, zero: Option<Physical>) -> Self {
        Self {
            root,
            direct_map,
            pages: 1,
            zero,
            rss_anon: 0,
            rss_shmem: 0,
            user_pt_pages: 0,
        }
    }

    pub fn build(boot: &BootInfo, allocator: &mut Allocator<'_>) -> Result<Self, Error> {
        let root = allocator.allocate()?.into_reserved();
        let mut tables = Self::empty(root, boot.direct_map, None);
        let result = (|| {
            let guards = cpu::guards();
            let image_end = ptr::addr_of!(__kernel_end) as u64;
            let image_length = image_end
                .checked_sub(boot.image_virtual)
                .ok_or(Error::Address)?;
            if !boot.contains_physical(boot.image_physical, image_length, 6) {
                return Err(Error::Address);
            }
            let sections = [
                (
                    ptr::addr_of!(__text_start) as u64,
                    ptr::addr_of!(__text_end) as u64,
                    PRESENT,
                ),
                (
                    ptr::addr_of!(__rodata_start) as u64,
                    ptr::addr_of!(__rodata_end) as u64,
                    PRESENT | NX,
                ),
                (
                    ptr::addr_of!(__data_start) as u64,
                    image_end,
                    PRESENT | WRITE | NX,
                ),
            ];
            for (start, end, flags) in sections {
                for address in (start..end).step_by(PAGE_BYTES) {
                    if guards.contains(&address)
                        || cpu::kstack_slot_of(address)
                            .is_some_and(|slot| address == cpu::kstack_guard(slot))
                    {
                        continue;
                    }
                    let physical = boot
                        .image_physical
                        .checked_add(address - boot.image_virtual)
                        .ok_or(Error::Overflow)?;
                    tables.map(
                        allocator,
                        Virtual(address),
                        Physical(physical),
                        flags,
                        false,
                    )?;
                }
            }
            for index in 0..boot.region_count() {
                let region = boot.region(index)?;
                // Image/modules intentionally have NO direct-map alias: kernel text
                // must not retain a writable physical alias. Reserved/bad/MMIO stays
                // unmapped. Firmware is read-only and not executable here.
                let flags = match region.kind {
                    0 | 5 => PRESENT | WRITE | NX,
                    2 | 3 | 8 => PRESENT | NX,
                    7 => PRESENT | WRITE | NX | (1 << 7) | (1 << 3), // PAT[5]=WC, 4KiB leaf
                    _ => continue,
                };
                let mut physical = region.base & !(PAGE - 1);
                let end = region
                    .base
                    .checked_add(region.length)
                    .and_then(|n| n.checked_add(PAGE - 1))
                    .ok_or(Error::Overflow)?
                    & !(PAGE - 1);
                while physical < end {
                    let virtual_address = boot
                        .direct_map
                        .checked_add(physical)
                        .ok_or(Error::Overflow)?;
                    if virtual_address < 0xffff_8000_0000_0000
                        || virtual_address >= boot.image_virtual
                    {
                        return Err(Error::Address);
                    }
                    let large = region.kind != 7
                        && physical.is_multiple_of(LARGE)
                        && virtual_address.is_multiple_of(LARGE)
                        && end - physical >= LARGE;
                    tables.map(
                        allocator,
                        Virtual(virtual_address),
                        Physical(physical),
                        flags,
                        large,
                    )?;
                    physical += if large { LARGE } else { PAGE };
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            tables.reclaim_unpublished(allocator, tables.root, 0)?;
            return Err(error);
        }
        Ok(tables)
    }

    fn reclaim_unpublished(
        &self,
        allocator: &mut Allocator<'_>,
        table: Physical,
        level: usize,
    ) -> Result<(), Error> {
        if self.is_active() {
            return Err(Error::Address);
        }
        if level < 3 {
            for index in 0..512 {
                let entry = self.read(table, index)?;
                if entry & PRESENT != 0 && entry & HUGE == 0 {
                    self.reclaim_unpublished(allocator, Physical(entry & ADDRESS), level + 1)?;
                }
            }
        }
        // SAFETY: only unpublished build/fault-injection trees enter this path.
        // Child tables were recursively retired; leaf mapped RAM is NOT freed.
        // No CPU has loaded the root, no DMA/references exist to table storage.
        unsafe {
            allocator.reclaim_reserved(table)?;
        }
        Ok(())
    }

    #[cfg(feature = "boot-proofs")]
    pub fn failure_tests(
        boot: &BootInfo,
        allocator: &mut Allocator<'_>,
        table_pages: usize,
    ) -> Result<(), Error> {
        let before = allocator.allocated();
        for limit in 0..table_pages {
            allocator.set_allocation_budget(Some(limit));
            let attempt = Self::build(boot, allocator);
            allocator.set_allocation_budget(None);
            match attempt {
                Err(Error::Memory(MemoryError::NoMemory)) => {}
                Ok(unexpected) => {
                    unexpected.reclaim_unpublished(allocator, unexpected.root, 0)?;
                    return Err(Error::Conflict);
                }
                Err(error) => return Err(error),
            }
            if allocator.allocated() != before {
                return Err(Error::Conflict);
            }
        }
        Ok(())
    }

    fn pointer(&self, physical: Physical, index: usize) -> Result<*mut u64, Error> {
        entry_pointer(self.direct_map, physical, index)
    }
    /// Record that a user leaf went from `old` to `new` in the counters.
    fn account(&mut self, old: u64, new: u64) {
        let (old, new) = (rss_class(self.zero, old), rss_class(self.zero, new));
        self.rss_anon = self.rss_anon + new.0 - old.0;
        self.rss_shmem = self.rss_shmem + new.1 - old.1;
    }
    fn read(&self, physical: Physical, index: usize) -> Result<u64, Error> {
        read_entry(self.direct_map, physical, index)
    }
    fn map(
        &mut self,
        allocator: &mut Allocator<'_>,
        virtual_address: Virtual,
        physical: Physical,
        flags: u64,
        large: bool,
    ) -> Result<(), Error> {
        let v = virtual_address.0;
        if v & (PAGE - 1) != 0 || physical.0 & (PAGE - 1) != 0 || physical.0 & !ADDRESS != 0 {
            return Err(Error::Address);
        }
        let indices = [
            ((v >> 39) & 511) as usize,
            ((v >> 30) & 511) as usize,
            ((v >> 21) & 511) as usize,
            ((v >> 12) & 511) as usize,
        ];
        let leaf_level = if large { 2 } else { 3 };
        let mut table = self.root;
        for (level, &index) in indices.iter().enumerate() {
            let old = self.read(table, index)?;
            if level == leaf_level {
                if old & MAPPED != 0 {
                    return Err(Error::Conflict);
                }
                let entry = leaf_entry(physical.0, flags | if large { HUGE } else { 0 });
                // SAFETY: the entry is not present (checked above) and hardware
                // never writes a non-present entry. Either the tree is
                // unpublished (one owner, no walker) or `&mut self` is the
                // running task's own private tree (`TaskLocal`, one CPU), and a
                // 0 -> present transition
                // needs no invalidation. No live Rust table reference exists.
                unsafe {
                    self.pointer(table, index)?.write_volatile(entry);
                }
                if flags & USER != 0 && !large {
                    self.account(0, entry);
                }
                return Ok(());
            }
            if old & PRESENT == 0 {
                let child = allocator.allocate()?.into_reserved();
                self.pages += 1;
                self.user_pt_pages += u64::from(flags & USER != 0);
                // SAFETY: same non-present parent entry and exclusive ownership
                // as above; the child frame was fully zeroed by the allocator
                // before its physical address is published in the PTE.
                unsafe {
                    self.pointer(table, index)?
                        .write_volatile(child.0 | PRESENT | WRITE | (flags & USER));
                }
                table = child;
            } else {
                // A user leaf below a supervisor-only table would be unreachable.
                if old & HUGE != 0 || (flags & USER != 0 && old & USER == 0) {
                    return Err(Error::Conflict);
                }
                table = Physical(old & ADDRESS);
            }
        }
        Err(Error::Address)
    }

    /// Map the 4 KiB device page at physical `address` (an ACPI-described LAPIC,
    /// IOAPIC or HPET block) uncached, writable, never executable, supervisor
    /// only, at its direct-map address `direct_map + address`. Like every table
    /// write, this happens before CR3 publication. The PWT/PCD/PAT bits select
    /// the UC entry of `IA32_PAT` that `cpu::validate` located (reset value:
    /// entry 3), so uncached does not rest on an assumed table.
    ///
    /// # Errors
    /// Rejects a call on the active tree (`Error::Active`), an unaligned or
    /// unrepresentable address, a page that is already mapped (RAM or a loader
    /// mapping: device pages must not alias memory) and allocation failure.
    pub fn map_mmio(
        &mut self,
        boot: &BootInfo,
        allocator: &mut Allocator<'_>,
        address: u64,
    ) -> Result<(), Error> {
        if self.is_active() {
            return Err(Error::Active);
        }
        let virtual_address = self
            .direct_map
            .checked_add(address)
            .ok_or(Error::Overflow)?;
        if virtual_address < 0xffff_8000_0000_0000 || virtual_address >= boot.image_virtual {
            return Err(Error::Address);
        }
        let uc = cpu::mmio_pat_index();
        let cache = (if uc & 1 != 0 { PWT } else { 0 })
            | (if uc & 2 != 0 { PCD } else { 0 })
            | (if uc & 4 != 0 { HUGE } else { 0 }); // bit 7 is PAT in a 4 KiB PTE
        self.map(
            allocator,
            Virtual(virtual_address),
            Physical(address),
            PRESENT | WRITE | NX | cache,
            false,
        )
    }

    /// Map one 4 KiB user page below `TASK_SIZE_MAX`: U/S set at every level,
    /// writable and executable only as requested (NX otherwise). Valid before
    /// and after activation (see the module's update rules).
    ///
    /// Ownership: the mapping takes over `frame`, which must be an order-zero
    /// reservation (`Frame::into_reserved`) mapped nowhere else, so that
    /// [`Tables::unmap_user_free`] can return it. Frames of a larger block are
    /// first split with `Allocator::split_reserved_order`.
    ///
    /// # Errors
    /// Rejects unaligned or out-of-range addresses, an already mapped page, a
    /// non-user table on the path, and allocation failure. On failure no PTE
    /// changed; intermediate tables created on the way stay (empty, harmless).
    pub fn map_user(
        &mut self,
        allocator: &mut Allocator<'_>,
        address: u64,
        frame: Physical,
        write: bool,
        exec: bool,
    ) -> Result<(), Error> {
        if address >= TASK_SIZE_MAX {
            return Err(Error::Address);
        }
        let flags = PRESENT | USER | if write { WRITE } else { 0 } | if exec { 0 } else { NX };
        self.map(allocator, Virtual(address), frame, flags, false)
    }

    /// The PTE slot of the user page at `address`, if every table above it is
    /// present (the PTE itself may be absent). Never creates tables.
    fn user_slot(&self, address: u64) -> Result<Option<*mut u64>, Error> {
        if address & (PAGE - 1) != 0 || address >= TASK_SIZE_MAX {
            return Err(Error::Address);
        }
        let mut table = self.root;
        for shift in [39, 30, 21] {
            let entry = self.read(table, ((address >> shift) & 511) as usize)?;
            if entry & PRESENT == 0 {
                return Ok(None);
            }
            if entry & HUGE != 0 || entry & USER == 0 {
                return Err(Error::Audit);
            }
            table = Physical(entry & ADDRESS);
        }
        self.pointer(table, ((address >> 12) & 511) as usize)
            .map(Some)
    }

    /// Map `pages` fresh zeroed anonymous pages at `start` (self-test helper
    /// over [`Tables::mm_map_anon`]). All or nothing: on any failure every page
    /// mapped so far is unmapped and freed again, so allocator accounting
    /// returns to its entry value (except for empty intermediate tables, which
    /// stay).
    ///
    /// The caller holds the `FRAMES` guard that `allocator` came from: it must
    /// not allocate from the heap meanwhile (see the rule in `services`).
    ///
    /// # Errors
    /// As [`Tables::mm_map_anon`], plus `Overflow`.
    #[cfg(feature = "boot-proofs")]
    fn map_anon_range(
        &mut self,
        allocator: &mut Allocator<'_>,
        start: u64,
        pages: u64,
        write: bool,
        exec: bool,
    ) -> Result<(), Error> {
        for done in 0..pages {
            let step = done
                .checked_mul(PAGE)
                .and_then(|n| start.checked_add(n))
                .ok_or(Error::Overflow)
                .and_then(|address| self.mm_map_anon(allocator, address, write, exec));
            if let Err(error) = step {
                // Pages `0..done` were mapped by this call; undo them.
                self.mm_unmap(allocator, start, done);
                return Err(error);
            }
        }
        Ok(())
    }

    /// The kernel's only way to reach user memory (see `usercopy`). The view
    /// exclusively borrows the tables, so no map/unmap/protect can run, and no
    /// other view exist, while any frame reference it hands out is alive.
    pub fn user_space(&mut self) -> UserSpace<'_> {
        UserSpace { tables: self }
    }

    /// Executed post-activation user-half checks: rollback at every allocation
    /// point, copy through a fresh anonymous mapping, `invlpg` after
    /// tightening and after unmapping (a write fault after `mm_protect` and a
    /// read fault after unmap, both of which a stale TLB entry would hide),
    /// conflict rollback, frame accounting. Uses unmapped pages inside init's
    /// existing stack page table, so no table is added.
    ///
    /// Negative control (QEMU TCG, recorded in `docs/implementation.md`):
    /// removing the `invlpg` from `mm_unmap` or from `mm_protect` makes this
    /// fail with `FAIL user-mm error=Conflict`. That is evidence for TCG's TLB
    /// model on this cell, not for real hardware.
    #[cfg(feature = "boot-proofs")]
    pub fn user_mm_tests(&mut self, allocator: &mut Allocator<'_>) -> Result<(), Error> {
        use kernel::mm::{PageProt, Pte};
        use kernel::{
            exec::stack::STACK_START,
            usercopy::{copy_from_user, copy_to_user},
        };
        let fail = || Error::Conflict;
        let base = STACK_START - 8 * PAGE;
        // With init loaded the tables for `base` exist already (so the audit's
        // table count is untouched); without it, create them once up front
        // and measure from there. Intermediate tables are never freed.
        self.map_anon_range(allocator, base, 1, true, false)?;
        self.mm_unmap(allocator, base, 1);
        let (frames, tables) = (allocator.allocated(), self.pages);
        let unchanged = |this: &Self, allocator: &Allocator<'_>| {
            allocator.allocated() == frames
                && this.pages == tables
                && (0..3).all(|page| matches!(this.lookup(Virtual(base + page * PAGE)), Ok(None)))
        };
        for limit in 0..3 {
            allocator.set_allocation_budget(Some(limit));
            let attempt = self.map_anon_range(allocator, base, 3, true, false);
            allocator.set_allocation_budget(None);
            if !matches!(attempt, Err(Error::Memory(MemoryError::NoMemory)))
                || !unchanged(self, allocator)
            {
                return Err(fail());
            }
        }
        self.map_anon_range(allocator, base, 3, true, false)?;
        if allocator.allocated() != frames + 3 || self.pages != tables {
            return Err(fail());
        }
        {
            let mut space = self.user_space();
            let data = [0xa5u8; 5000];
            let mut back = [0u8; 5000];
            let mut head = [0xffu8; 100];
            if copy_to_user(&mut space, base + 100, &data) != 0
                || copy_from_user(&mut space, &mut back, base + 100) != 0
                || back != data
                || copy_from_user(&mut space, &mut head, base) != 0
                || head != [0; 100]
            {
                return Err(fail());
            }
        }
        // Deliberate, test-only ring-0 access to a user address (the kernel
        // otherwise never dereferences one, see `usercopy`): it loads the
        // writable translation into the TLB so a missing `invlpg` is visible.
        let pointer =
            ptr::with_exposed_provenance_mut::<u8>(usize::try_from(base).map_err(|_| fail())?);
        // SAFETY: `base` is a mapped, writable, user-accessible page of the
        // active tree (just mapped by `map_anon_range`); one byte, naturally
        // aligned, no Rust reference to it exists (the `UserSpace` views above
        // ended). SMAP is not enabled yet (`userspace::start` turns it on after
        // this runs), so ring 0 may touch user pages.
        unsafe { pointer.write_volatile(0x5a) };
        let readable = |write| PageProt {
            accessible: true,
            write,
            exec: false,
        };
        self.mm_protect(base, 1, readable(false));
        if self.mm_lookup(base) != (Pte::Anon { writable: false })
            // SAFETY: IF clear, test recovery installed, readonly user page.
            || !unsafe { cpu::fault_test(base, 1) }
        {
            return Err(fail());
        }
        {
            let mut space = self.user_space();
            let mut byte = [0u8];
            if copy_to_user(&mut space, base, &[1]) != 1
                || copy_from_user(&mut space, &mut byte, base) != 0
                || byte != [0x5a]
            {
                return Err(fail());
            }
        }
        self.mm_make_writable(base);
        if self.mm_lookup(base) != (Pte::Anon { writable: true })
            // SAFETY: as above; the page is writable again.
            || unsafe { pointer.read_volatile() } != 0x5a
        {
            return Err(fail());
        }
        if self.mm_unmap(allocator, base, 3) != 3
            // SAFETY: IF clear, test recovery installed, now-unmapped page.
            || !unsafe { cpu::fault_test(base, 0) }
            || !unchanged(self, allocator)
            || self.mm_unmap(allocator, base, 3) != 0
        {
            return Err(fail());
        }
        self.mm_protect(base, 3, readable(true));
        if !unchanged(self, allocator) {
            return Err(fail());
        }
        // A conflict on the middle page rolls the first back, keeps the other.
        self.map_anon_range(allocator, base + PAGE, 1, false, false)?;
        if !matches!(
            self.map_anon_range(allocator, base, 3, true, false),
            Err(Error::Conflict)
        ) || !matches!(self.lookup(Virtual(base)), Ok(None))
            || !matches!(self.lookup(Virtual(base + PAGE)), Ok(Some(_)))
            || self.mm_unmap(allocator, base, 3) != 1
            || !unchanged(self, allocator)
        {
            return Err(fail());
        }
        // Every edit above went through the counters: they equal the walks.
        if !self.counters_match() {
            return Err(fail());
        }
        Ok(())
    }

    /// The physical address of this tree's PML4 (what CR3 holds when it is
    /// the active one).
    #[must_use]
    pub fn root_address(&self) -> u64 {
        self.root.0
    }

    /// `pgd_alloc`: a new tree with an empty user half whose kernel half is
    /// this tree's (the PML4 entries above `TASK_SIZE_MAX` are copied; the
    /// lower-level tables are shared, which the immutability of the kernel
    /// half permits). It shares the zero page. The caller owns the result and
    /// returns it with [`Tables::destroy_user`].
    ///
    /// # Errors
    /// Frame exhaustion; nothing was kept.
    pub fn fork_template(&self, allocator: &mut Allocator<'_>) -> Result<Self, Error> {
        let root = allocator.allocate()?.into_reserved();
        let child = Self::empty(root, self.direct_map, self.zero);
        for top in 256..512 {
            let entry = self.read(self.root, top)?;
            if entry != 0 {
                // SAFETY: `root` is a fresh, zeroed, order-zero reservation
                // that no CPU has loaded and nothing else references; `top` is
                // below 512 and the direct map covers it. The entry is copied
                // from a kernel-half slot, which is immutable after
                // publication, and shares the lower tables it points to.
                unsafe { child.pointer(root, top)?.write_volatile(entry) };
            }
        }
        Ok(child)
    }

    /// `dup_mmap` -> `copy_page_range` (eager): a new tree ([`Tables::fork_template`])
    /// with a private copy of every mapped user page of this one, same
    /// protection. The shared zero page stays shared, a `PROT_NONE` page stays
    /// `PROT_NONE` (its frame is copied), absent pages stay absent; accessed
    /// and dirty bits are not carried. On failure everything made is freed and
    /// this tree is unchanged.
    ///
    /// shortcut: copy-on-write is the upgrade (per-frame counts and a
    /// write-protecting walk of this tree, plan S2); the eager copy is
    /// observably the same and costs a frame per page.
    ///
    /// The caller holds the `FRAMES` guard `allocator` came from and has
    /// reserved all heap storage it needs (this allocates none).
    ///
    /// # Errors
    /// Frame exhaustion (`Error::Memory`).
    pub fn fork_user(&self, allocator: &mut Allocator<'_>) -> Result<Self, Error> {
        let mut child = self.fork_template(allocator)?;
        let mut failure: Option<Error> = None;
        let (zero, direct_map) = (self.zero, self.direct_map);
        self.for_each_user_slot(0, TASK_SIZE_MAX / PAGE, |address, slot| {
            if failure.is_some() {
                return;
            }
            // SAFETY: `slot` is a PTE of this tree (see `for_each_user_slot`);
            // a volatile read creates no reference and sees hardware A/D bits.
            let entry = unsafe { ptr::read_volatile(slot) };
            if entry & MAPPED == 0 || entry & USER == 0 {
                return;
            }
            let frame = Physical(frame_bits(entry));
            let flags = entry & !ADDRESS & !(ACCESSED | DIRTY);
            let outcome = if Some(frame) == zero {
                child.map(allocator, Virtual(address), frame, flags, false)
            } else {
                allocator
                    .allocate()
                    .map_err(Error::from)
                    .and_then(|mut copy| {
                        let bytes = copy.bytes();
                        let source = usize::try_from(direct_map + frame.0)
                            .map_err(|_| Error::Overflow)
                            .map(ptr::with_exposed_provenance::<u8>)?;
                        // SAFETY: `frame` is the order-zero private frame
                        // owned by this live user leaf (`mm_map_anon`,
                        // `mm_install_page`, `map_user`: never the zero page,
                        // excluded above), mapped in the direct map, 4 KiB
                        // long and initialised; `&self` (the task's own
                        // private tree, or the parent's from the forking parent) excludes a writer, user code
                        // does not run, and `bytes` is a different frame.
                        let source = unsafe { core::slice::from_raw_parts(source, PAGE_BYTES) };
                        bytes.copy_from_slice(source);
                        let copy = copy.into_reserved();
                        let mapped = child.map(allocator, Virtual(address), copy, flags, false);
                        if mapped.is_err() {
                            // SAFETY: `copy` is the order-zero reservation
                            // made above, mapped nowhere (`map` failed
                            // without writing the leaf).
                            unsafe { allocator.reclaim_reserved(copy)? };
                        }
                        mapped
                    })
            };
            if let Err(error) = outcome {
                failure = Some(error);
            }
        });
        match failure {
            None => Ok(child),
            Some(error) => {
                child.destroy_user(allocator);
                Err(error)
            }
        }
    }

    /// `exit_mmap` + `free_pgtables` + `pgd_free`: free every user page and
    /// table of this tree and its root. The kernel half belongs to the tree it
    /// was copied from and stays. Afterwards the tree no longer exists.
    ///
    /// # Panics
    /// If the tree is the active one (CR3 must have moved to another tree
    /// first: freeing live translation structures), or the allocator refuses a
    /// table it owns (a broken ownership invariant, never silently leaked).
    pub fn destroy_user(mut self, allocator: &mut Allocator<'_>) {
        assert!(!self.is_active(), "destroying the active page tables");
        self.mm_unmap(allocator, 0, TASK_SIZE_MAX / PAGE);
        for top in 0..256 {
            let entry = self.read(self.root, top).unwrap_or(0);
            if entry & PRESENT != 0 {
                let result = self.reclaim_unpublished(allocator, Physical(entry & ADDRESS), 1);
                assert!(result.is_ok(), "destroy_user: table refused: {result:?}");
            }
        }
        // SAFETY: the root is this tree's order-zero reservation
        // (`fork_template`/`build`), no CPU has it loaded (asserted above),
        // every table below it was just returned and no `UserSpace` view can
        // exist (we consumed the only owner).
        let result = unsafe { allocator.reclaim_reserved(self.root) };
        assert!(result.is_ok(), "destroy_user: root refused: {result:?}");
    }

    /// # Safety
    /// BSP IRQ-disabled; all currently used image/stack/descriptor/loader and
    /// framebuffer addresses must be covered by `build()`'s exact mappings. No
    /// additional CPUs, PCID or global translations; root remains owned forever.
    pub unsafe fn activate(&self) {
        // SAFETY: caller establishes exactly the architecture publication contract.
        unsafe {
            cpu::activate_tables(self.root.0);
        }
    }
    pub fn is_active(&self) -> bool {
        cpu::active_tables() == self.root.0
    }

    pub fn lookup(&self, address: Virtual) -> Result<Option<(Physical, u64)>, Error> {
        if !crate::boot::canonical_range(address.0, 1) {
            return Err(Error::Address);
        }
        let mut table = self.root;
        for shift in [39, 30, 21, 12] {
            let entry = self.read(table, ((address.0 >> shift) & 511) as usize)?;
            if entry & PRESENT == 0 {
                return Ok(None);
            }
            if shift == 12 {
                return Ok(Some((
                    Physical((entry & ADDRESS) | (address.0 & 4095)),
                    entry,
                )));
            }
            if entry & HUGE != 0 {
                if shift != 21 {
                    return Err(Error::Address);
                }
                return Ok(Some((
                    Physical((entry & ADDRESS & !(LARGE - 1)) | (address.0 & (LARGE - 1))),
                    entry,
                )));
            }
            table = Physical(entry & ADDRESS);
        }
        Err(Error::Address)
    }

    pub fn check_permissions(&self, boot: &BootInfo) -> Result<bool, Error> {
        let text = self
            .lookup(Virtual(ptr::addr_of!(__text_start) as u64))?
            .ok_or(Error::Address)?
            .1;
        let data = self
            .lookup(Virtual(ptr::addr_of!(__data_start) as u64))?
            .ok_or(Error::Address)?
            .1;
        let rodata = self
            .lookup(Virtual(ptr::addr_of!(__rodata_start) as u64))?
            .ok_or(Error::Address)?
            .1;
        let alias = self.lookup(Virtual(boot.direct_map + boot.image_physical))?;
        let mut guards_absent = true;
        for guard in cpu::guards().into_iter().chain(cpu::kstack_guards()) {
            guards_absent &= self.lookup(Virtual(guard))?.is_none();
        }
        Ok(text & (WRITE | NX) == 0
            && data & (WRITE | NX) == WRITE | NX
            && rodata & (WRITE | NX) == NX
            && alias.is_none()
            && guards_absent)
    }
}

/// The memory-mapping model's page-table operations (`kernel::mm::UserPages`)
/// on the real tables. Locking: callers hold `&mut Tables` (the running task's
/// own tree, no lock) and pass the frame allocator (the `FRAMES` guard or, before
/// publication, the loader's own); none of these allocates from the heap, so
/// the `services` rule (reserve heap memory before taking `FRAMES`) holds.
impl Tables {
    /// Allocate the shared zero page. Call once, before any `mm_map_zero`.
    ///
    /// # Errors
    /// Frame exhaustion; `Conflict` if called twice.
    pub fn init_zero_page(&mut self, allocator: &mut Allocator<'_>) -> Result<(), Error> {
        if self.zero.is_some() {
            return Err(Error::Conflict);
        }
        // The allocator zeroes every frame it issues; this one is never mapped
        // writable and never written through the direct map.
        self.zero = Some(allocator.allocate()?.into_reserved());
        Ok(())
    }

    /// Whether [`Tables::init_zero_page`] already ran.
    #[must_use]
    pub fn has_zero_page(&self) -> bool {
        self.zero.is_some()
    }

    /// The user range `[start, start + pages * 4096)` clamped to the user half, as `(start, end)`.
    fn user_range(start: u64, pages: u64) -> (u64, u64) {
        let end = pages
            .checked_mul(PAGE)
            .and_then(|n| start.checked_add(n))
            .map_or(TASK_SIZE_MAX, |end| end.min(TASK_SIZE_MAX));
        (start & !(PAGE - 1), end)
    }

    /// The next present leaf table at or after `*address` below `end`, skipping absent table
    /// levels; `*address` is advanced to the first page that table covers in the range. `None`
    /// once the range holds no more tables.
    fn next_user_table(&self, address: &mut u64, end: u64) -> Option<Physical> {
        'range: while *address < end {
            let mut table = self.root;
            for shift in [39u32, 30, 21] {
                let index = ((*address >> shift) & 511) as usize;
                let entry = self.read(table, index).unwrap_or(0);
                // A huge or supervisor entry in the user half is an isolation
                // bug the audit reports; never walk through it.
                if entry & PRESENT == 0 || entry & HUGE != 0 || entry & USER == 0 {
                    *address = (*address | ((1u64 << shift) - 1)) + 1;
                    continue 'range;
                }
                table = Physical(entry & ADDRESS);
            }
            return Some(table);
        }
        None
    }

    /// Visit the leaf slots of `[start, start + pages * 4096)` (clamped to the
    /// user range) whose page tables exist, skipping absent table levels so a
    /// sparse multi-terabyte range costs only the tables that are present.
    /// `visit(address, slot)`; the slot is a valid PTE address (`pointer`).
    fn for_each_user_slot(&self, start: u64, pages: u64, mut visit: impl FnMut(u64, *mut u64)) {
        let (mut address, end) = Self::user_range(start, pages);
        while let Some(table) = self.next_user_table(&mut address, end) {
            let table_end = (address | (LARGE - 1)) + 1;
            while address < end.min(table_end) {
                if let Ok(slot) = self.pointer(table, ((address >> 12) & 511) as usize) {
                    visit(address, slot);
                }
                address += PAGE;
            }
        }
    }

    /// The first user page at or after `from` in `[from, end)` whose entry is mapped (the pages
    /// [`Tables::mm_move_one`] moves), skipping absent table levels.
    fn next_mapped_user_page(&self, from: u64, end: u64) -> Option<u64> {
        let mut address = from;
        while let Some(table) = self.next_user_table(&mut address, end) {
            let table_end = (address | (LARGE - 1)) + 1;
            while address < end.min(table_end) {
                if let Ok(slot) = self.pointer(table, ((address >> 12) & 511) as usize) {
                    // SAFETY: `pointer` returns a valid, aligned PTE slot of this tree inside
                    // the direct map; a volatile read creates no reference (as `mm_resident`).
                    let entry = unsafe { ptr::read_volatile(slot) };
                    if entry & MAPPED != 0 && entry & USER != 0 {
                        return Some(address);
                    }
                }
                address += PAGE;
            }
        }
        None
    }

    /// The resident pages of `[start, start + pages * 4096)` that are not the
    /// shared zero page: `(pages, pages still the file's)`. A walk over the
    /// present tables only (`for_each_user_slot`): what `/proc/<pid>/status`'s
    /// `RssAnon` and `RssShmem` were computed from before the counters, now the
    /// self-test's cross-check ([`UserSpace::check_counters`]).
    #[cfg(feature = "qemu-self-test")]
    #[must_use]
    pub fn mm_resident(&self, start: u64, pages: u64) -> (u64, u64) {
        let (mut present, mut filed) = (0, 0);
        self.for_each_user_slot(start, pages, |_, slot| {
            // SAFETY: `for_each_user_slot` hands out a valid, aligned PTE slot
            // of this tree inside the direct map; a volatile read creates no
            // reference and observes hardware accessed/dirty updates.
            let entry = unsafe { ptr::read_volatile(slot) };
            if entry & PRESENT != 0 && Some(Physical(frame_bits(entry))) != self.zero {
                present += 1;
                filed += u64::from(entry & FILE != 0);
            }
        });
        (present, filed)
    }

    /// `mm_pgtables_bytes`: the PUD, PMD and PTE pages of the user half, by
    /// walking them (the counters' cross-check, [`Tables::counters_match`]).
    #[cfg(feature = "boot-proofs")]
    #[must_use]
    fn mm_table_pages(&self) -> u64 {
        let mut count = 0u64;
        for pgd in 0..256 {
            let Ok(entry) = self.read(self.root, pgd) else {
                continue;
            };
            if entry & PRESENT == 0 || entry & USER == 0 {
                continue;
            }
            count += 1;
            let pud = Physical(entry & ADDRESS);
            for upper in 0..512 {
                let Ok(entry) = self.read(pud, upper) else {
                    continue;
                };
                if entry & PRESENT == 0 || entry & HUGE != 0 {
                    continue;
                }
                count += 1;
                let pmd = Physical(entry & ADDRESS);
                for middle in 0..512 {
                    let Ok(entry) = self.read(pmd, middle) else {
                        continue;
                    };
                    if entry & PRESENT != 0 && entry & HUGE == 0 {
                        count += 1;
                    }
                }
            }
        }
        count
    }

    /// Whether the counters equal what a walk of the whole user half finds:
    /// resident pages by [`rss_class`] and the table pages.
    #[cfg(feature = "boot-proofs")]
    fn counters_match(&self) -> bool {
        let zero = self.zero;
        let (mut anon, mut shmem) = (0, 0);
        self.for_each_user_slot(0, TASK_SIZE_MAX / PAGE, |_, slot| {
            // SAFETY: `slot` is a PTE of this tree (see `for_each_user_slot`);
            // a volatile read creates no reference.
            let class = rss_class(zero, unsafe { ptr::read_volatile(slot) });
            (anon, shmem) = (anon + class.0, shmem + class.1);
        });
        (anon, shmem, self.mm_table_pages()) == (self.rss_anon, self.rss_shmem, self.user_pt_pages)
    }

    /// What the model sees at `page`.
    #[must_use]
    pub fn mm_lookup(&self, page: u64) -> kernel::mm::Pte {
        use kernel::mm::Pte;
        let Ok(Some(slot)) = self.user_slot(page) else {
            return Pte::Absent;
        };
        // SAFETY: `user_slot` returned an aligned PTE of this tree inside the
        // direct map; a volatile read creates no reference and observes
        // hardware accessed/dirty updates.
        let entry = unsafe { ptr::read_volatile(slot) };
        if entry & MAPPED == 0 {
            Pte::Absent
        } else if Some(Physical(frame_bits(entry))) == self.zero {
            Pte::ZeroPage
        } else {
            Pte::Anon {
                writable: entry & WRITE != 0,
            }
        }
    }

    /// Map the zero page read-only at `page` (`do_anonymous_page` read fault).
    ///
    /// # Errors
    /// Table allocation failure (`Error::Memory`); a mapped page is `Conflict`.
    pub fn mm_map_zero(
        &mut self,
        allocator: &mut Allocator<'_>,
        page: u64,
        exec: bool,
    ) -> Result<(), Error> {
        let zero = self.zero.ok_or(Error::Address)?;
        let flags = PRESENT | USER | if exec { 0 } else { NX };
        self.map(allocator, Virtual(page), zero, flags, false)
    }

    /// Give `page` a private zeroed frame (`do_anonymous_page` write fault,
    /// `wp_page_copy` from the zero page): hardware-writable iff `write`.
    ///
    /// # Errors
    /// Frame or table exhaustion; nothing changed then.
    pub fn mm_map_anon(
        &mut self,
        allocator: &mut Allocator<'_>,
        page: u64,
        write: bool,
        exec: bool,
    ) -> Result<(), Error> {
        let frame = allocator.allocate()?.into_reserved();
        let flags = PRESENT | USER | if write { WRITE } else { 0 } | if exec { 0 } else { NX };
        let result = self.mm_install(allocator, page, frame, flags);
        if result.is_err() {
            // SAFETY: `frame` is the order-zero reservation made above and
            // `mm_install` failed without publishing it.
            unsafe { allocator.reclaim_reserved(frame)? };
        }
        result
    }

    /// Install `frame` (an order-zero reservation) as the page's PTE: into an
    /// empty slot, or over the zero page (then the old translation is
    /// invalidated). Anything else is `Conflict`.
    fn mm_install(
        &mut self,
        allocator: &mut Allocator<'_>,
        page: u64,
        frame: Physical,
        flags: u64,
    ) -> Result<(), Error> {
        if let Some(slot) = self.user_slot(page)? {
            // SAFETY: as in `unmap_user`.
            let entry = unsafe { AtomicU64::from_ptr(slot) };
            let old = entry.load(Ordering::Acquire);
            if old & MAPPED != 0 {
                if Some(Physical(frame_bits(old))) != self.zero || old & USER == 0 {
                    return Err(Error::Conflict);
                }
                let new = leaf_entry(frame.0, flags);
                entry.store(new, Ordering::Release);
                self.account(old, new);
                // A not-present -> present change needs no invalidation, but
                // this replaces a live read-only translation of the zero page.
                tlb::flush(VirtAddr::new(page));
                return Ok(());
            }
        }
        self.map(allocator, Virtual(page), frame, flags, false)
    }

    /// Install a private frame holding `bytes` (the loader's page-cache
    /// stand-in); `accessible == false` keeps it behind a `PROT_NONE` PTE.
    /// `file` says the page is the file's page-cache page ([`FILE`], `RssShmem`):
    /// it is ignored when `prot.write` is set, because a page installed
    /// writable is the private copy a write fault made (`do_cow_fault`, `RssAnon`);
    /// a read fault installs it read-only (`do_read_fault`) and the first write
    /// copies it ([`Tables::mm_make_writable`]).
    ///
    /// # Errors
    /// As [`Tables::mm_map_anon`].
    pub fn mm_install_page(
        &mut self,
        allocator: &mut Allocator<'_>,
        page: u64,
        prot: kernel::mm::PageProt,
        file: bool,
        bytes: &[u8; PAGE_BYTES],
    ) -> Result<(), Error> {
        let mut frame = allocator.allocate()?;
        frame.bytes().copy_from_slice(bytes);
        let frame = frame.into_reserved();
        let flags = if prot.accessible {
            PRESENT | USER | if prot.write { WRITE } else { 0 } | if prot.exec { 0 } else { NX }
        } else {
            PROTNONE | USER | NX
        } | if file && !prot.write { FILE } else { 0 };
        let result = self.map(allocator, Virtual(page), frame, flags, false);
        if result.is_err() {
            // SAFETY: as in `mm_map_anon`.
            unsafe { allocator.reclaim_reserved(frame)? };
        }
        result
    }

    /// `wp_page_reuse` / `wp_page_copy`: set the hardware write bit of the
    /// present private page. A page that was still the file's becomes the
    /// task's own copy ([`FILE`] cleared: `RssShmem` -> `RssAnon`).
    pub fn mm_make_writable(&mut self, page: u64) {
        let Ok(Some(slot)) = self.user_slot(page) else {
            return;
        };
        // SAFETY: as in `unmap_user`.
        let entry = unsafe { AtomicU64::from_ptr(slot) };
        let mut old = entry.load(Ordering::Acquire);
        // Never on a not-present (PROT_NONE) entry, the zero page or a
        // supervisor entry: the model only asks for exclusive anonymous pages.
        while old & PRESENT != 0 && old & USER != 0 && Some(Physical(old & ADDRESS)) != self.zero {
            let new = (old | WRITE) & !FILE;
            match entry.compare_exchange_weak(old, new, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => {
                    self.account(old, new);
                    break;
                }
                Err(current) => old = current,
            }
        }
        // A stale read-only translation would fault again; drop it.
        tlb::flush(VirtAddr::new(page));
    }

    /// Remove every mapping in the range, invalidate it on this CPU and return
    /// the data frames (never the zero page) to the allocator. Returns how many
    /// data frames were freed.
    pub fn mm_unmap(&mut self, allocator: &mut Allocator<'_>, start: u64, pages: u64) -> u64 {
        let zero = self.zero;
        let mut freed = 0;
        let (mut anon, mut shmem) = (0, 0);
        self.for_each_user_slot(start, pages, |address, slot| {
            // SAFETY: `slot` is a PTE of this tree (see `for_each_user_slot`);
            // `&mut self` excludes software writers and `AtomicU64` makes the
            // swap atomic against the hardware's accessed/dirty updates.
            let entry = unsafe { AtomicU64::from_ptr(slot) };
            let seen = entry.load(Ordering::Acquire);
            // Never clear what is not a user page (the audit reports it).
            if seen & MAPPED == 0 || seen & USER == 0 {
                return;
            }
            let old = entry.swap(0, Ordering::AcqRel);
            let class = rss_class(zero, old);
            (anon, shmem) = (anon + class.0, shmem + class.1);
            if old & PRESENT != 0 {
                // Single CPU: `invlpg` retires the cached translation. SMP needs
                // a shootdown acknowledged before the frame is freed.
                tlb::flush(VirtAddr::new(address));
            }
            let frame = Physical(frame_bits(old));
            if Some(frame) != zero {
                // SAFETY: a user leaf is the unique owner of an order-zero
                // reservation (`mm_map_anon`/`mm_install_page`/`map_user`), the
                // PTE is cleared and invalidated above, and no `UserSpace`
                // borrow can be live (we hold `&mut self`).
                let result = unsafe { allocator.reclaim_reserved(frame) };
                // The PTE is already gone: a refusal means the ownership
                // invariant above is broken (double free, wrong order, foreign
                // frame). Stop loudly rather than leak the frame silently.
                assert!(
                    result.is_ok(),
                    "mm_unmap: user frame {frame:?} refused by the allocator: {result:?}"
                );
                freed += 1;
            }
        });
        self.rss_anon -= anon;
        self.rss_shmem -= shmem;
        freed
    }

    /// `move_page_tables`: move the user entries of `pages` pages from `old_start` to
    /// `new_start` (frames, flags and the resident counters unchanged; the old translations are
    /// invalidated). The destination must be free. All or nothing: when a table for the
    /// destination cannot be allocated the entries moved so far are moved back (their tables
    /// exist) and the error is returned.
    ///
    /// # Errors
    /// Table exhaustion (`Error::Memory`).
    pub fn mm_move(
        &mut self,
        allocator: &mut Allocator<'_>,
        old_start: u64,
        new_start: u64,
        pages: u64,
    ) -> Result<(), Error> {
        // Only the mapped entries are visited: a sparse range costs the tables that are present
        // (`move_page_tables` skips empty PMD/PUD extents the same way).
        let (_, old_end) = Self::user_range(old_start, pages);
        let mut cursor = old_start;
        let mut failure = None;
        while let Some(from) = self.next_mapped_user_page(cursor, old_end) {
            match self.mm_move_one(allocator, from, new_start + (from - old_start)) {
                Ok(()) => cursor = from + PAGE,
                Err(error) => {
                    failure = Some(error);
                    break;
                }
            }
        }
        let Some(error) = failure else {
            return Ok(());
        };
        // Move back what moved (the destination holds exactly those entries): the source
        // entries' tables still exist and the entries are not present there any more, so this
        // cannot fail.
        let new_end = new_start + (cursor - old_start);
        let mut back_from = new_start;
        while let Some(from) = self.next_mapped_user_page(back_from, new_end) {
            let back = self.mm_move_one(allocator, from, old_start + (from - new_start));
            assert!(back.is_ok(), "mm_move: revert of a moved entry failed");
            back_from = from + PAGE;
        }
        Err(error)
    }

    /// One entry of [`Tables::mm_move`]: a mapped user entry at `from` becomes the entry at `to`.
    fn mm_move_one(
        &mut self,
        allocator: &mut Allocator<'_>,
        from: u64,
        to: u64,
    ) -> Result<(), Error> {
        let Some(slot) = self.user_slot(from)? else {
            return Ok(());
        };
        // SAFETY: `slot` is a PTE of this tree (see `user_slot`); `&mut self` excludes software
        // writers and `AtomicU64` makes the swap atomic against the hardware's accessed/dirty
        // updates.
        let entry = unsafe { AtomicU64::from_ptr(slot) };
        let seen = entry.load(Ordering::Acquire);
        // Never move what is not a user page.
        if seen & MAPPED == 0 || seen & USER == 0 {
            return Ok(());
        }
        // Build the destination first (it may need tables): a failure leaves the source alone.
        // `map` accounts the new leaf, so the old one is un-accounted here.
        let old = entry.swap(0, Ordering::AcqRel);
        self.account(old, 0);
        if old & PRESENT != 0 {
            tlb::flush(VirtAddr::new(from));
        }
        let flags = old & !ADDRESS;
        match self.map(
            allocator,
            Virtual(to),
            Physical(frame_bits(old)),
            flags,
            false,
        ) {
            Ok(()) => Ok(()),
            Err(error) => {
                // SAFETY: the slot was emptied above and nothing else touched it.
                entry.store(old, Ordering::Release);
                self.account(0, old);
                Err(error)
            }
        }
    }

    /// `change_protection`: re-protect the mapped pages of the range. The write
    /// bit is only ever cleared here (a private page becomes writable again
    /// through the write fault), `!exec` sets NX, and `!accessible` turns the
    /// PTE into the `PROT_NONE` form (frame kept).
    pub fn mm_protect(&mut self, start: u64, pages: u64, prot: kernel::mm::PageProt) {
        let zero = self.zero;
        // Signed change of the two counters, summed over the range.
        let (mut anon, mut shmem) = (0i64, 0i64);
        self.for_each_user_slot(start, pages, |address, slot| {
            // SAFETY: as in `mm_unmap`.
            let entry = unsafe { AtomicU64::from_ptr(slot) };
            let mut old = entry.load(Ordering::Acquire);
            loop {
                if old & MAPPED == 0 || old & USER == 0 {
                    return;
                }
                let keep = old & !(PRESENT | PROTNONE | WRITE | NX | ADDRESS);
                let frame = frame_bits(old);
                let new = if prot.accessible {
                    // WRITE survives only on a page that had it and still may.
                    let write = if old & PRESENT != 0 && old & WRITE != 0 && prot.write {
                        WRITE
                    } else {
                        0
                    };
                    leaf_entry(
                        frame,
                        keep | PRESENT | write | if prot.exec { 0 } else { NX },
                    )
                } else {
                    leaf_entry(frame, keep | PROTNONE | NX)
                };
                match entry.compare_exchange_weak(old, new, Ordering::AcqRel, Ordering::Acquire) {
                    Ok(_) => {
                        let (before, after) = (rss_class(zero, old), rss_class(zero, new));
                        anon += after.0.cast_signed() - before.0.cast_signed();
                        shmem += after.1.cast_signed() - before.1.cast_signed();
                        break;
                    }
                    Err(current) => old = current,
                }
            }
            // Tightening needs the invalidation; loosening of a cached entry
            // is harmless. One `invlpg` per previously present page. SMP needs
            // a shootdown.
            if old & PRESENT != 0 {
                tlb::flush(VirtAddr::new(address));
            }
        });
        self.rss_anon = self.rss_anon.wrapping_add_signed(anon);
        self.rss_shmem = self.rss_shmem.wrapping_add_signed(shmem);
    }
}

/// Where the model's frame operations get their allocator: the `FRAMES`
/// service, locked per operation.
trait Backing {
    fn tables(&self) -> &Tables;
    fn parts<R>(&mut self, f: impl FnOnce(&mut Tables, &mut Allocator<'_>) -> R) -> R;
}

impl Backing for UserSpace<'_> {
    fn tables(&self) -> &Tables {
        self.tables
    }
    fn parts<R>(&mut self, f: impl FnOnce(&mut Tables, &mut Allocator<'_>) -> R) -> R {
        // Lock order `PROCESS` -> heap -> `FRAMES`: the tables are the running
        // task's own (this view borrows them, no lock) and the model reserved
        // its heap storage before calling; `FRAMES` is a leaf.
        let mut frames = crate::services::FRAMES.lock();
        f(self.tables, &mut frames)
    }
}

impl Backing for Tables {
    fn tables(&self) -> &Tables {
        self
    }
    fn parts<R>(&mut self, f: impl FnOnce(&mut Tables, &mut Allocator<'_>) -> R) -> R {
        // As `UserSpace`'s: the tables are a task's own address space and `FRAMES` a leaf.
        let mut frames = crate::services::FRAMES.lock();
        f(self, &mut frames)
    }
}

fn out_of_memory(error: Error) -> kernel::mm::OutOfMemory {
    // Only exhaustion is a legitimate failure. Anything else means the model
    // asked for a page it had not checked, a kernel bug: stop loudly.
    match error {
        Error::Memory(MemoryError::NoMemory) => kernel::mm::OutOfMemory,
        other => panic!("mm page-table backend: {other:?}"),
    }
}

macro_rules! mm_pages {
    ([$($generics:tt)*] $ty:ty) => {
        impl<$($generics)*> kernel::mm::UserPages for $ty {
            fn lookup(&self, page: u64) -> kernel::mm::Pte {
                Backing::tables(self).mm_lookup(page)
            }
            fn map_zero_page(
                &mut self,
                page: u64,
                prot: kernel::mm::PageProt,
            ) -> Result<(), kernel::mm::OutOfMemory> {
                self.parts(|tables, frames| tables.mm_map_zero(frames, page, prot.exec))
                    .map_err(out_of_memory)
            }
            fn map_anon_page(
                &mut self,
                page: u64,
                prot: kernel::mm::PageProt,
            ) -> Result<(), kernel::mm::OutOfMemory> {
                self.parts(|tables, frames| tables.mm_map_anon(frames, page, prot.write, prot.exec))
                    .map_err(out_of_memory)
            }
            fn make_writable(&mut self, page: u64) {
                self.parts(|tables, _| tables.mm_make_writable(page));
            }
            fn unmap(&mut self, start: u64, pages: u64) -> u64 {
                self.parts(|tables, frames| tables.mm_unmap(frames, start, pages))
            }
            fn protect(&mut self, start: u64, pages: u64, prot: kernel::mm::PageProt) {
                self.parts(|tables, _| tables.mm_protect(start, pages, prot));
            }
            fn move_pages(
                &mut self,
                old_start: u64,
                new_start: u64,
                pages: u64,
            ) -> Result<(), kernel::mm::OutOfMemory> {
                self.parts(|tables, frames| tables.mm_move(frames, old_start, new_start, pages))
                    .map_err(out_of_memory)
            }
        }
    };
}
mm_pages!(['a] UserSpace<'a>);
mm_pages!([] Tables);

impl kernel::exec::load::Pager for Tables {
    fn install(
        &mut self,
        page: u64,
        prot: kernel::mm::PageProt,
        file: bool,
        bytes: &[u8; PAGE_BYTES],
    ) -> Result<(), kernel::mm::OutOfMemory> {
        self.parts(|tables, frames| tables.mm_install_page(frames, page, prot, file, bytes))
            .map_err(out_of_memory)
    }
}

impl kernel::exec::load::Pager for UserSpace<'_> {
    fn install(
        &mut self,
        page: u64,
        prot: kernel::mm::PageProt,
        file: bool,
        bytes: &[u8; PAGE_BYTES],
    ) -> Result<(), kernel::mm::OutOfMemory> {
        self.parts(|tables, frames| tables.mm_install_page(frames, page, prot, file, bytes))
            .map_err(out_of_memory)
    }
}

/// Resolves user pages by walking the tree in software and aliasing the frame
/// through the direct map, so no user virtual address is ever dereferenced.
///
/// The view holds `&mut Tables`: while it (or a frame reference it returned)
/// lives, nothing can unmap, free or protect a page.
pub struct UserSpace<'a> {
    tables: &'a mut Tables,
}

impl UserSpace<'_> {
    /// `pgd_alloc` ([`Tables::fork_template`]): a new tree with an empty user half and this
    /// tree's kernel half, for a task that has no address space of its own (yet).
    ///
    /// # Errors
    /// Frame exhaustion.
    pub fn empty_tree(&mut self) -> Result<Tables, Error> {
        self.parts(|tables, frames| tables.fork_template(frames))
    }

    /// The page-table half of a fork ([`Tables::fork_user`]) with the frame
    /// allocator locked for the copy. The caller reserved its heap storage
    /// first (`services`: no heap allocation under `FRAMES`).
    ///
    /// # Errors
    /// Frame exhaustion.
    pub fn fork_tables(&mut self) -> Result<Tables, Error> {
        self.parts(|tables, frames| tables.fork_user(frames))
    }
}

impl UserSpace<'_> {
    /// `(anon, file, shmem)` resident pages of the address space: a page of a
    /// file mapping that the task has not written is the page-cache page
    /// (`MM_SHMEMPAGES`: every file here is on tmpfs); a written one is a
    /// private copy (`MM_ANONPAGES`). Constant time: the counters
    /// [`Tables::account`] keeps.
    #[must_use]
    pub fn rss(&self) -> (u64, u64, u64) {
        (self.tables.rss_anon, 0, self.tables.rss_shmem)
    }

    /// `mm_pgtables_bytes`, from the counter of user table pages.
    #[must_use]
    pub fn table_bytes(&self) -> u64 {
        self.tables.user_pt_pages * PAGE
    }

    /// Cross-check of the counters against walks (self-test builds only): the
    /// per-entry walk of the whole user half, the per-VMA walk the counters
    /// replaced (`vmas` are the task's own), and the table walk. A mismatch
    /// is a bug in the counter maintenance and stops the kernel.
    ///
    /// # Panics
    /// If a counter disagrees with its walk.
    #[cfg(feature = "qemu-self-test")]
    pub fn check_counters(&self, vmas: &[kernel::mm::Vma]) {
        assert!(
            self.tables.counters_match(),
            "rss/page-table counters disagree with the page tables"
        );
        let (mut anon, mut shmem) = (0, 0);
        for vma in vmas {
            // Only a file VMA may hold a page that is still the file's.
            let (present, filed) = self.tables.mm_resident(vma.start, vma.pages());
            let filed = if vma.file.is_some() { filed } else { 0 };
            anon += present - filed;
            shmem += filed;
        }
        assert_eq!(
            (anon, shmem),
            (self.tables.rss_anon, self.tables.rss_shmem),
            "rss counters disagree with the per-VMA walk"
        );
    }
}

impl UserSpace<'_> {
    /// Whether the kernel can access the page now (present and user at every
    /// level, writable at every level when `write`): no fault would be needed.
    #[must_use]
    pub fn resident(&self, page: u64, write: bool) -> bool {
        self.translate(page, write).is_some()
    }

    /// The raw leaf entry of the user page at page-aligned `page`, or 0 (self-test
    /// evidence of the `PROT_NONE` frame inversion).
    #[cfg(all(feature = "boot-proofs", not(feature = "baremetal-suite")))]
    #[must_use]
    pub fn raw_entry(&self, page: u64) -> u64 {
        match self.tables.user_slot(page) {
            // SAFETY: `user_slot` returned an aligned PTE of this tree inside
            // the direct map; a volatile read creates no reference.
            Ok(Some(slot)) => unsafe { ptr::read_volatile(slot) },
            _ => 0,
        }
    }

    /// Whether `after` is `before` (a present leaf) turned `PROT_NONE`: P clear,
    /// `PROTNONE` set and exactly the frame bits complemented (self-test).
    #[cfg(all(feature = "boot-proofs", not(feature = "baremetal-suite")))]
    #[must_use]
    pub fn protnone_guard(before: u64, after: u64) -> bool {
        before & PRESENT != 0
            && after & (PRESENT | PROTNONE) == PROTNONE
            && (before ^ after) & ADDRESS == ADDRESS
            && frame_bits(after) == before & ADDRESS
    }

    /// The frame of the user page at page-aligned `address`; present, user at
    /// every level, and writable at every level when `write`.
    fn translate(&self, address: u64, write: bool) -> Option<Physical> {
        self.tables.translate_user(address, write)
    }
}

impl Tables {
    /// The frame of the user page at page-aligned `address`; present, user at
    /// every level, and writable at every level when `write`.
    fn translate_user(&self, address: u64, write: bool) -> Option<Physical> {
        if address >= TASK_SIZE_MAX {
            return None;
        }
        let required = PRESENT | USER | if write { WRITE } else { 0 };
        let mut table = self.root;
        for shift in [39, 30, 21, 12] {
            let index = usize::try_from((address >> shift) & 511).ok()?;
            let entry = read_entry(self.direct_map, table, index).ok()?;
            if entry & required != required {
                return None;
            }
            if shift == 12 {
                return Some(Physical(entry & ADDRESS));
            }
            if entry & HUGE != 0 {
                return None;
            }
            table = Physical(entry & ADDRESS);
        }
        None
    }

    /// The direct-map address of the frame backing the user page at `page`, for
    /// [`UserPages::page`]'s two implementations (which carry the proof for turning it into
    /// a reference). No access happens here.
    fn user_page_pointer(&self, page: u64, write: bool) -> Option<*mut [u8; PAGE_BYTES]> {
        let physical = self.translate_user(page, write)?;
        let address = usize::try_from(self.direct_map.checked_add(physical.0)?).ok()?;
        Some(ptr::with_exposed_provenance_mut::<[u8; PAGE_BYTES]>(
            address,
        ))
    }
}

/// What [`UserSpace::audit`] counted.
#[derive(Clone, Copy, Debug)]
pub struct UserAudit {
    pub user_pages: u64,
    pub user_tables: u64,
    pub kernel_entries: u64,
}

impl UserSpace<'_> {
    /// Executed isolation audit of the published tree: in the upper half (PML4
    /// index >= 256, where every kernel mapping lives) no entry at any level
    /// may carry the user bit; in the lower half every present entry must be a
    /// user entry, leaves must be 4 KiB pages, and none may reach
    /// `TASK_SIZE_MAX`.
    ///
    /// # Errors
    /// [`Error::Audit`] on the first violation, or a table-read error.
    pub fn audit(&self) -> Result<UserAudit, Error> {
        let mut audit = UserAudit {
            user_pages: 0,
            user_tables: 0,
            kernel_entries: 0,
        };
        for top in 0..512usize {
            let entry = read_entry(self.tables.direct_map, self.tables.root, top)?;
            if entry & PRESENT == 0 {
                continue;
            }
            if top >= 256 {
                self.audit_kernel(Physical(entry & ADDRESS), entry, 1, &mut audit)?;
            } else {
                if entry & USER == 0 {
                    return Err(Error::Audit);
                }
                audit.user_tables += 1;
                self.audit_user(Physical(entry & ADDRESS), (top as u64) << 39, 1, &mut audit)?;
            }
        }
        Ok(audit)
    }

    fn audit_kernel(
        &self,
        table: Physical,
        entry: u64,
        level: u32,
        audit: &mut UserAudit,
    ) -> Result<(), Error> {
        audit.kernel_entries += 1;
        if entry & USER != 0 {
            return Err(Error::Audit);
        }
        // `level` numbers the table `entry` maps (PDPT 1, PD 2, PT 3; 4 means
        // `entry` is a 4 KiB PTE). Leaves: 1 GiB/2 MiB pages and PTEs.
        if level >= 4 || (level >= 2 && entry & HUGE != 0) {
            return Ok(());
        }
        for index in 0..512usize {
            let child = read_entry(self.tables.direct_map, table, index)?;
            if child & PRESENT != 0 {
                self.audit_kernel(Physical(child & ADDRESS), child, level + 1, audit)?;
            }
        }
        Ok(())
    }

    fn audit_user(
        &self,
        table: Physical,
        base: u64,
        level: u32,
        audit: &mut UserAudit,
    ) -> Result<(), Error> {
        let shift = 39 - 9 * level;
        for index in 0..512usize {
            let entry = read_entry(self.tables.direct_map, table, index)?;
            // A leaf is mapped when present or `PROT_NONE` (it holds a frame
            // either way and must satisfy the same isolation rules); a table
            // entry only counts when present. Both bits at once is no state
            // this code creates.
            let mapped = if level == 3 {
                entry & MAPPED != 0
            } else {
                entry & PRESENT != 0
            };
            if !mapped {
                continue;
            }
            if level == 3 && entry & MAPPED == MAPPED {
                return Err(Error::Audit);
            }
            let address = base | ((index as u64) << shift);
            if entry & USER == 0 || address >= TASK_SIZE_MAX || (level < 3 && entry & HUGE != 0) {
                return Err(Error::Audit);
            }
            if level == 3 {
                audit.user_pages += 1;
            } else {
                audit.user_tables += 1;
                self.audit_user(Physical(entry & ADDRESS), address, level + 1, audit)?;
            }
        }
        Ok(())
    }
}

/// SAFETY argument shared by the two `UserPages` implementations below.
///
/// `user_page_pointer` found a present user leaf. Its frame is one of two kinds. (1) A private
/// frame: an order-zero allocator reservation that exactly one leaf owns (`map_user`,
/// `mm_map_anon`, `mm_install_page`) and only `mm_unmap` frees, after clearing and invalidating
/// that leaf. (2) The shared zero frame (`Tables::init_zero_page`): mapped by any number of
/// leaves, never freed, and hardware-read-only in every leaf, so `translate(write)` never
/// returns it. The frame is live, initialized (allocator zeroing, then plain bytes) and 4 KiB
/// aligned. The direct map covers all usable RAM read-write (checked by `Allocator::new`).
/// The caller holds `&mut Tables` (directly or through the view) for as long as the returned
/// borrow lives, so nothing can free, remap or hand out another reference to the frame, and
/// user code does not run (one CPU) while the kernel holds it. Any byte pattern is a valid
/// `[u8; N]`. The zero frame stays zero only because every caller obeys the `UserPages::page`
/// contract: a page requested with `write == false` is only read (the sole caller is
/// `usercopy::walk`, whose read visitor is `copy_from_user`).
impl UserPages for Tables {
    fn page(&mut self, page: u64, write: bool) -> Option<&mut [u8; PAGE_BYTES]> {
        let pointer = self.user_page_pointer(page, write)?;
        // SAFETY: see the argument above; the borrow is tied to `&mut self`.
        Some(unsafe { &mut *pointer })
    }
}

impl UserPages for UserSpace<'_> {
    fn page(&mut self, page: u64, write: bool) -> Option<&mut [u8; PAGE_BYTES]> {
        self.tables.page(page, write)
    }
}
