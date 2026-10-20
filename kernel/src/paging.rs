// SPDX-License-Identifier: GPL-2.0-only
//! BSP-owned four-level page tables.
//!
//! # Update rules (single CPU; replaces "all writes precede CR3 publication")
//! * Kernel half (PML4 index >= 256): written only by [`Tables::build`] before
//!   [`Tables::activate`]; immutable afterwards, so it never needs invalidation.
//! * User half (below `TASK_SIZE_MAX`): [`Tables::map_user`], [`Tables::unmap_user`]
//!   and [`Tables::protect_user`] may run after activation. They need
//!   `&mut Tables`, i.e. the `services::TABLES` lock, so no other agent edits
//!   or walks the tree meanwhile, and no `UserSpace` view (which borrows the
//!   same `&mut Tables`) can hold a frame reference across the edit.
//! * A not-present -> present transition needs no invalidation (hardware
//!   caches no absent entry; SDM Vol. 3 4.10.4.3), and a new intermediate
//!   table is zeroed before its parent entry becomes present.
//! * Clearing or tightening a present PTE (unmap, drop W, set NX) is an
//!   atomic read-modify-write (hardware may set accessed/dirty concurrently)
//!   followed by `invlpg` of that page; only then may a frame be reused or
//!   freed.
//! * Intermediate user tables are never freed before address-space teardown.
//!   shortcut: no teardown exists (one process, init's death ends the boot);
//!   upgrade with `exit`/`execve` (Linux `free_pgtables`).
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
const HUGE: u64 = 1 << 7;
const NX: u64 = 1 << 63;
const ADDRESS: u64 = 0x000f_ffff_ffff_f000;
const LARGE: u64 = 2 * 1024 * 1024;

pub enum Error {
    Memory(MemoryError),
    Boot(BootError),
    Address,
    Conflict,
    Overflow,
    /// The isolation audit found a user bit in the kernel half or a user
    /// mapping at or above `TASK_SIZE_MAX`.
    Audit,
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
}

impl Tables {
    pub fn build(boot: &BootInfo, allocator: &mut Allocator<'_>) -> Result<Self, Error> {
        let root = allocator.allocate()?.into_reserved();
        let mut tables = Self {
            root,
            direct_map: boot.direct_map,
            pages: 1,
        };
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
                    if guards.contains(&address) {
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

    #[cfg(feature = "qemu-self-test")]
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
                if old & PRESENT != 0 {
                    return Err(Error::Conflict);
                }
                let entry = physical.0 | flags | if large { HUGE } else { 0 };
                // SAFETY: the entry is not present (checked above) and hardware
                // never writes a non-present entry. Either the tree is
                // unpublished (one owner, no walker) or `&mut self` is the
                // TABLES lock on the only CPU, and a 0 -> present transition
                // needs no invalidation. No live Rust table reference exists.
                unsafe {
                    self.pointer(table, index)?.write_volatile(entry);
                }
                return Ok(());
            }
            if old & PRESENT == 0 {
                let child = allocator.allocate()?.into_reserved();
                self.pages += 1;
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
    #[allow(
        dead_code,
        reason = "used by the self-test now and by the mm syscalls (brk/mmap/munmap/mprotect) next"
    )]
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

    /// Remove the user mapping at `address` and invalidate it on this CPU.
    /// Returns the frame it mapped (now unreferenced, still reserved) or
    /// `None` if nothing was mapped.
    ///
    /// # Errors
    /// Rejects an unaligned or out-of-range address, or a non-user entry.
    #[allow(
        dead_code,
        reason = "used by the self-test now and by the mm syscalls (brk/mmap/munmap/mprotect) next"
    )]
    pub fn unmap_user(&mut self, address: u64) -> Result<Option<Physical>, Error> {
        let Some(slot) = self.user_slot(address)? else {
            return Ok(None);
        };
        // SAFETY: `slot` is an aligned PTE of this tree inside the direct map
        // (`entry_pointer`); `&mut self` excludes software writers, and
        // `AtomicU64` makes the swap race-free against the hardware's own
        // accessed/dirty updates of this entry.
        let old = unsafe { AtomicU64::from_ptr(slot) }.swap(0, Ordering::AcqRel);
        if old & PRESENT == 0 {
            return Ok(None);
        }
        // Single CPU: `invlpg` retires every cached translation of the page
        // (and covering paging-structure entries). SMP needs a shootdown here.
        tlb::flush(VirtAddr::new(address));
        if old & USER == 0 {
            return Err(Error::Audit);
        }
        Ok(Some(Physical(old & ADDRESS)))
    }

    /// Change the protection of the mapped user page at `address` and
    /// invalidate it on this CPU. Returns the previous `(write, exec)` so a
    /// caller can roll a multi-page change back, or `None` if not mapped.
    ///
    /// # Errors
    /// Rejects an unaligned or out-of-range address, or a non-user entry.
    #[allow(
        dead_code,
        reason = "used by the self-test now and by the mm syscalls (brk/mmap/munmap/mprotect) next"
    )]
    pub fn protect_user(
        &mut self,
        address: u64,
        write: bool,
        exec: bool,
    ) -> Result<Option<(bool, bool)>, Error> {
        let Some(slot) = self.user_slot(address)? else {
            return Ok(None);
        };
        // SAFETY: as in `unmap_user`.
        let entry = unsafe { AtomicU64::from_ptr(slot) };
        let mut old = entry.load(Ordering::Acquire);
        loop {
            if old & PRESENT == 0 {
                return Ok(None);
            }
            if old & USER == 0 {
                return Err(Error::Audit);
            }
            let new =
                (old & !(WRITE | NX)) | if write { WRITE } else { 0 } | if exec { 0 } else { NX };
            // A/D bits set by hardware between load and exchange make the CAS
            // fail and retry with the fresh value instead of being lost.
            match entry.compare_exchange_weak(old, new, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => break,
                Err(current) => old = current,
            }
        }
        // Loosening needs none, tightening needs it; one `invlpg` is cheap and
        // also clears any stale entry. SMP needs a shootdown here.
        tlb::flush(VirtAddr::new(address));
        Ok(Some((old & WRITE != 0, old & NX == 0)))
    }

    /// Map `pages` fresh zeroed anonymous pages at `start`. All or nothing:
    /// on any failure every page mapped so far is unmapped and freed again, so
    /// allocator accounting returns to its entry value (except for empty
    /// intermediate tables, which stay).
    ///
    /// # Errors
    /// As [`Tables::map_user`], plus frame exhaustion.
    #[allow(
        dead_code,
        reason = "used by the self-test now and by the mm syscalls (brk/mmap/munmap/mprotect) next"
    )]
    pub fn map_user_anon(
        &mut self,
        allocator: &mut Allocator<'_>,
        start: u64,
        pages: u64,
        write: bool,
        exec: bool,
    ) -> Result<(), Error> {
        for done in 0..pages {
            let step = (|| {
                let address = done
                    .checked_mul(PAGE)
                    .and_then(|n| start.checked_add(n))
                    .ok_or(Error::Overflow)?;
                let frame = allocator.allocate()?.into_reserved();
                let result = self.map_user(allocator, address, frame, write, exec);
                if result.is_err() {
                    // SAFETY: `frame` is the order-zero reservation made one
                    // line above and `map_user` failed without mapping it, so
                    // nothing references it.
                    unsafe { allocator.reclaim_reserved(frame)? };
                }
                result
            })();
            if let Err(error) = step {
                // Pages `0..done` were mapped by this call; undo them. A
                // failure here cannot be recovered and is reported instead.
                self.unmap_user_free(allocator, start, done)?;
                return Err(error);
            }
        }
        Ok(())
    }

    /// Unmap `pages` user pages from `start` (holes are skipped) and return
    /// their frames to the allocator. Returns how many frames were freed.
    ///
    /// # Errors
    /// Address errors as [`Tables::unmap_user`]; the allocator rejecting a
    /// frame (a mapped frame that was not an order-zero reservation).
    #[allow(
        dead_code,
        reason = "used by the self-test now and by the mm syscalls (brk/mmap/munmap/mprotect) next"
    )]
    pub fn unmap_user_free(
        &mut self,
        allocator: &mut Allocator<'_>,
        start: u64,
        pages: u64,
    ) -> Result<u64, Error> {
        let mut freed = 0;
        for index in 0..pages {
            let address = index
                .checked_mul(PAGE)
                .and_then(|n| start.checked_add(n))
                .ok_or(Error::Overflow)?;
            if let Some(frame) = self.unmap_user(address)? {
                // SAFETY: `map_user`'s contract made this mapping the unique
                // owner of an order-zero reservation. The PTE was cleared and
                // invalidated above, and no `UserSpace` borrow of `&mut self`
                // can be live, so no reference or translation remains. (SMP:
                // other CPUs' shootdown must also precede this.)
                unsafe { allocator.reclaim_reserved(frame)? };
                freed += 1;
            }
        }
        Ok(freed)
    }

    /// The kernel's only way to reach user memory (see `usercopy`). The view
    /// exclusively borrows the tables, so no map/unmap/protect can run, and no
    /// other view exist, while any frame reference it hands out is alive.
    pub fn user_space(&mut self) -> UserSpace<'_> {
        UserSpace { tables: self }
    }

    /// Executed post-activation user-half checks: rollback at every allocation
    /// point, copy through a fresh anonymous mapping, `invlpg` after
    /// tightening and after unmapping (proved by faults a stale TLB entry
    /// would hide), conflict rollback, frame accounting. Uses unmapped pages
    /// inside init's existing stack page table, so no table is added.
    #[cfg(feature = "qemu-self-test")]
    pub fn user_mm_tests(&mut self, allocator: &mut Allocator<'_>) -> Result<(), Error> {
        use kernel::{
            exec::stack::STACK_START,
            usercopy::{copy_from_user, copy_to_user},
        };
        let fail = || Error::Conflict;
        let base = STACK_START - 8 * PAGE;
        // With init loaded the tables for `base` exist already (so the audit's
        // table count is untouched); without it, create them once up front
        // and measure from there. Intermediate tables are never freed.
        self.map_user_anon(allocator, base, 1, true, false)?;
        self.unmap_user_free(allocator, base, 1)?;
        let (frames, tables) = (allocator.allocated(), self.pages);
        let unchanged = |this: &Self, allocator: &Allocator<'_>| {
            allocator.allocated() == frames
                && this.pages == tables
                && (0..3).all(|page| matches!(this.lookup(Virtual(base + page * PAGE)), Ok(None)))
        };
        for limit in 0..3 {
            allocator.set_allocation_budget(Some(limit));
            let attempt = self.map_user_anon(allocator, base, 3, true, false);
            allocator.set_allocation_budget(None);
            if !matches!(attempt, Err(Error::Memory(MemoryError::NoMemory)))
                || !unchanged(self, allocator)
            {
                return Err(fail());
            }
        }
        self.map_user_anon(allocator, base, 3, true, false)?;
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
        // SAFETY (all raw accesses below): `base` is a mapped, writable user
        // page of the active tree; SMAP is not enabled yet (it is turned on in
        // `userspace::start`), so ring 0 may touch it. This also loads the
        // writable translation into the TLB.
        let pointer =
            ptr::with_exposed_provenance_mut::<u8>(usize::try_from(base).map_err(|_| fail())?);
        unsafe { pointer.write_volatile(0x5a) };
        if self.protect_user(base, false, false)? != Some((true, false))
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
        if self.protect_user(base, true, false)? != Some((false, false))
            // SAFETY: as above; the page is writable again.
            || unsafe { pointer.read_volatile() } != 0x5a
        {
            return Err(fail());
        }
        if self.unmap_user_free(allocator, base, 3)? != 3
            // SAFETY: IF clear, test recovery installed, now-unmapped page.
            || !unsafe { cpu::fault_test(base, 0) }
            || !unchanged(self, allocator)
            || self.unmap_user_free(allocator, base, 3)? != 0
            || self.protect_user(base, true, false)?.is_some()
            || !matches!(self.unmap_user(base + 1), Err(Error::Address))
            || !matches!(self.unmap_user(TASK_SIZE_MAX), Err(Error::Address))
        {
            return Err(fail());
        }
        // A conflict on the middle page rolls the first back, keeps the other.
        self.map_user_anon(allocator, base + PAGE, 1, false, false)?;
        if !matches!(
            self.map_user_anon(allocator, base, 3, true, false),
            Err(Error::Conflict)
        ) || !matches!(self.lookup(Virtual(base)), Ok(None))
            || !matches!(self.lookup(Virtual(base + PAGE)), Ok(Some(_)))
            || self.unmap_user_free(allocator, base, 3)? != 1
            || !unchanged(self, allocator)
        {
            return Err(fail());
        }
        Ok(())
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
        for guard in cpu::guards() {
            guards_absent &= self.lookup(Virtual(guard))?.is_none();
        }
        Ok(text & (WRITE | NX) == 0
            && data & (WRITE | NX) == WRITE | NX
            && rodata & (WRITE | NX) == NX
            && alias.is_none()
            && guards_absent)
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
    /// The frame of the user page at page-aligned `address`; present, user at
    /// every level, and writable at every level when `write`.
    fn translate(&self, address: u64, write: bool) -> Option<Physical> {
        if address >= TASK_SIZE_MAX {
            return None;
        }
        let required = PRESENT | USER | if write { WRITE } else { 0 };
        let mut table = self.tables.root;
        for shift in [39, 30, 21, 12] {
            let index = usize::try_from((address >> shift) & 511).ok()?;
            let entry = read_entry(self.tables.direct_map, table, index).ok()?;
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
            if entry & PRESENT == 0 {
                continue;
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

impl UserPages for UserSpace<'_> {
    fn page(&mut self, page: u64, write: bool) -> Option<&mut [u8; PAGE_BYTES]> {
        let physical = self.translate(page, write)?;
        let address = usize::try_from(self.tables.direct_map.checked_add(physical.0)?).ok()?;
        let pointer = ptr::with_exposed_provenance_mut::<[u8; PAGE_BYTES]>(address);
        // SAFETY: `translate` found a present user leaf. Only `map_user` installs
        // them, from an order-zero allocator reservation mapped nowhere else
        // that `unmap_user_free` is the only way to free, so the 4 KiB frame
        // is live, initialized (allocator zeroing, then plain bytes) and 4 KiB
        // aligned. The direct map covers all usable RAM read-write (checked by
        // `Allocator::new`). The view holds `&mut Tables`, so nothing can free,
        // remap or hand out another reference to the frame while the returned
        // borrow (tied to `&mut self`) lives, and user code does not run (one
        // CPU) while the kernel holds it. Any byte pattern is a valid `[u8; N]`.
        Some(unsafe { &mut *pointer })
    }
}
