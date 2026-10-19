// SPDX-License-Identifier: GPL-2.0-only
//! One non-sleeping, BSP-exclusive physical allocator for orders 0 through 10.
//! Compact metadata reserves its own usable-RAM pages. Selected buddy splitting
//! and coalescing are not full Linux zones/NUMA/GFP/reclaim/migration/hotplug.
#[path = "buddy.rs"]
mod buddy;

use crate::{
    bitmap::BITS_PER_WORD,
    boot::{BootError, BootInfo},
};
use buddy::{Arena, Block, Buddy};
use core::{ptr, slice};

pub use buddy::MAX_ORDER;
pub const PAGE_BYTES: usize = 4096;
pub const PAGE: u64 = PAGE_BYTES as u64;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Physical(pub u64);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Virtual(pub u64);

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Boot(BootError),
    Overflow,
    NoMemory,
    Alignment,
    Order,
    Ownership,
}
impl From<BootError> for Error {
    fn from(value: BootError) -> Self {
        Self::Boot(value)
    }
}

/// One uniquely owned, fully initialized contiguous physical extent. All access
/// is BSP-exclusive: neither this owner nor its allocator is Send or Sync.
#[must_use = "an allocated frame must be released or transferred to a mapping owner"]
pub struct Frame {
    block: Block,
    // Retains foreign-allocation exposed provenance across HHDM translation.
    pointer: *mut u8,
}
impl Frame {
    #[must_use]
    pub fn physical(&self) -> Physical {
        Physical(self.block.pfn() * PAGE)
    }
    #[must_use]
    pub fn order(&self) -> u32 {
        self.block.order()
    }
    #[must_use]
    pub fn page_count(&self) -> usize {
        self.block.pages()
    }
    #[must_use]
    pub fn byte_count(&self) -> usize {
        self.page_count() * PAGE_BYTES
    }
    pub fn bytes(&mut self) -> &mut [u8] {
        // SAFETY: one noncopy token owns this complete extent within one loader
        // allocation. Every byte was raw-zeroed before issue, HHDM bounds were
        // checked at allocator construction, and &mut self excludes all aliases.
        unsafe { slice::from_raw_parts_mut(self.pointer, self.byte_count()) }
    }
    /// Transfer the complete extent into a longer-lived reservation. The caller
    /// must retain its exact order alongside the address for eventual reclaim.
    /// Losing either leaks the extent, never creates another owner. This is not
    /// permission to reclaim live CPU stacks, DMA buffers or published mappings.
    #[must_use]
    pub fn into_reserved(self) -> Physical {
        self.physical()
    }
}

pub struct Allocator<'a> {
    boot: &'a BootInfo,
    buddy: Buddy<'a>,
    metadata_length: u64,
    #[cfg(feature = "qemu-self-test")]
    allocation_budget: Option<usize>,
}

fn metadata_start(boot: &BootInfo, length: u64) -> Result<u64, Error> {
    for i in 0..boot.region_count() {
        let region = boot.region(i)?;
        let start = region.base.max(PAGE);
        if region.kind == 0
            && start
                .checked_add(length)
                .is_some_and(|end| end <= region.base + region.length)
        {
            return Ok(start);
        }
    }
    Err(Error::NoMemory)
}

impl<'a> Allocator<'a> {
    /// # Errors
    /// Rejects invalid handoff ranges/addresses, metadata-size overflow, or lack
    /// of one usable allocation large enough for all actual RAM-sized metadata.
    ///
    /// # Safety
    /// Exactly one allocator is created from the unique boot handoff. All usable
    /// RAM, including each complete region's allocator provenance, is exclusively
    /// transferred by the loader; no CPU/DMA/firmware accesses it. Loader data and
    /// nonusable regions stay reserved. Caller is the BSP before AP publication;
    /// IRQ/NMI handlers never enter this non-reentrant allocator.
    pub unsafe fn new(boot: &'a BootInfo) -> Result<Self, Error> {
        let mut arena_count = 0usize;
        let mut total = 0usize;
        let mut bits = 0usize;
        let mut previous_end = 0;
        for i in 0..boot.region_count() {
            let region = boot.region(i)?;
            previous_end = crate::boot::checked_region(region, previous_end)?;
            let start = region.base.max(PAGE);
            if region.kind != 0 || start >= previous_end {
                continue;
            }
            let arena = Arena::new(start / PAGE, previous_end / PAGE, bits)?;
            total = total.checked_add(arena.pages()).ok_or(Error::Overflow)?;
            bits = arena.bits_end();
            arena_count += 1;
            // Prove every later allocation's entire HHDM extent before mutating
            // allocation state. No potentially failing address step remains on
            // allocation after the buddy has transferred ownership.
            let address = boot.direct_map.checked_add(start).ok_or(Error::Overflow)?;
            let length = previous_end - start;
            let end = address.checked_add(length - 1).ok_or(Error::Overflow)?;
            if !boot.contains_virtual(address, length, 0)
                || !crate::boot::canonical_range(address, length)
                || usize::try_from(end).is_err()
                || address == 0
            {
                return Err(Error::Ownership);
            }
        }
        if total == 0 {
            return Err(Error::NoMemory);
        }
        let arena_bytes = arena_count
            .checked_mul(size_of::<Arena>())
            .ok_or(Error::Overflow)?;
        let area_words = bits.div_ceil(BITS_PER_WORD);
        let free_words = Buddy::free_words(bits)?;
        let words = area_words.checked_add(free_words).ok_or(Error::Overflow)?;
        let bytes = words
            .checked_mul(size_of::<usize>())
            .and_then(|n| n.checked_add(arena_bytes))
            .ok_or(Error::Overflow)?;
        if bytes > isize::MAX as usize {
            return Err(Error::Overflow);
        }
        let length = (bytes as u64)
            .checked_add(PAGE - 1)
            .ok_or(Error::Overflow)?
            & !(PAGE - 1);
        let metadata_start = metadata_start(boot, length)?;
        let address = boot
            .direct_map
            .checked_add(metadata_start)
            .ok_or(Error::Overflow)?;
        if !address.is_multiple_of(align_of::<Arena>() as u64)
            || !arena_bytes.is_multiple_of(align_of::<usize>())
        {
            return Err(Error::Alignment);
        }
        let address = usize::try_from(address).map_err(|_| Error::Overflow)?;
        let pointer = ptr::with_exposed_provenance_mut::<u8>(address);
        // SAFETY: this single complete usable-RAM allocation was checked above.
        // Its descriptor prefix and native-word suffix are aligned and disjoint;
        // metadata length fits isize. Raw initialization precedes typed views.
        // No owner is issued until all metadata backing pages are excluded.
        let (arenas, storage) = unsafe {
            ptr::write_bytes(pointer, 0, bytes);
            (
                slice::from_raw_parts_mut(
                    ptr::with_exposed_provenance_mut::<Arena>(address),
                    arena_count,
                ),
                slice::from_raw_parts_mut(
                    ptr::with_exposed_provenance_mut::<usize>(address + arena_bytes),
                    words,
                ),
            )
        };
        // Arena contains integers/arrays only: raw zero is a valid representation
        // before each descriptor is replaced by its checked actual geometry.
        let mut bits_start = 0;
        let mut arena_index = 0;
        for i in 0..boot.region_count() {
            let region = boot.region(i)?;
            let start = region.base.max(PAGE);
            let end = region.base + region.length;
            if region.kind != 0 || start >= end {
                continue;
            }
            let arena = Arena::new(start / PAGE, end / PAGE, bits_start)?;
            bits_start = arena.bits_end();
            arenas[arena_index] = arena;
            arena_index += 1;
        }
        let (free, heads) = storage.split_at_mut(free_words);
        let buddy = Buddy::new(
            arenas,
            free,
            heads,
            metadata_start / PAGE..(metadata_start + length) / PAGE,
        )?;
        Ok(Self {
            boot,
            buddy,
            metadata_length: length,
            #[cfg(feature = "qemu-self-test")]
            allocation_budget: None,
        })
    }

    #[must_use]
    pub fn total(&self) -> usize {
        self.buddy.total()
    }
    /// Includes permanently reserved metadata pages and all live frame pages.
    #[must_use]
    pub fn allocated(&self) -> usize {
        self.buddy.allocated()
    }
    #[must_use]
    pub fn metadata_pages(&self) -> usize {
        (self.metadata_length / PAGE) as usize
    }
    #[must_use]
    pub fn available(&self) -> usize {
        self.buddy.available()
    }

    /// # Errors
    /// Reports actual order-zero exhaustion. No sleep/reclaim/IO/reserves occur.
    pub fn allocate(&mut self) -> Result<Frame, Error> {
        self.allocate_aligned(PAGE)
    }
    /// Alignment is in bytes; allocates one page through the shared buddy path.
    /// # Errors
    /// Rejects alignment below one page or not a power of two; reports exhaustion.
    pub fn allocate_aligned(&mut self, alignment: u64) -> Result<Frame, Error> {
        self.allocate_order_aligned(0, alignment)
    }
    /// Allocate exactly `2^order` contiguous pages, naturally size-aligned.
    /// This BSP-only request never sleeps, reclaims, enters IO/FS or uses reserves.
    /// # Errors
    /// Orders above `MAX_ORDER` fail with `Order`; insufficient unfragmented RAM
    /// fails with `NoMemory` without changing ownership or accounting.
    pub fn allocate_order(&mut self, order: u32) -> Result<Frame, Error> {
        self.allocate_order_aligned(order, PAGE)
    }
    /// `order` counts powers of 4096-byte pages; `alignment` is a power-of-two
    /// BYTE alignment of at least 4096. Natural block-size alignment is always
    /// additionally guaranteed, even when the requested alignment is smaller.
    /// # Errors
    /// Rejects an invalid order/alignment or actual alignment-filtered exhaustion.
    /// No owner or accounting change occurs on a failed request.
    /// # Panics
    /// Only if the constructor's checked HHDM address invariant is violated.
    pub fn allocate_order_aligned(&mut self, order: u32, alignment: u64) -> Result<Frame, Error> {
        if alignment < PAGE || !alignment.is_power_of_two() {
            return Err(Error::Alignment);
        }
        #[cfg(feature = "qemu-self-test")]
        if self.allocation_budget == Some(0) {
            return Err(Error::NoMemory);
        }
        let block = self.buddy.allocate(order, alignment / PAGE)?;
        // Constructor checked whole-arena HHDM arithmetic and uintptr fit. Block
        // cannot leave that same original loader allocation or overlap metadata.
        let address = self.boot.direct_map + block.pfn() * PAGE;
        let pointer = ptr::with_exposed_provenance_mut::<u8>(
            usize::try_from(address).expect("constructor checked every HHDM address"),
        );
        let byte_count = block.pages() * PAGE_BYTES;
        // SAFETY: buddy state transferred this complete exclusive live usable
        // extent; no other owner/reference/CPU/DMA access exists. Raw zeroing
        // initializes every byte before Frame can form a reference to the extent.
        unsafe { ptr::write_bytes(pointer, 0, byte_count) };
        #[cfg(feature = "qemu-self-test")]
        if let Some(remaining) = &mut self.allocation_budget {
            *remaining -= 1;
        }
        Ok(Frame { block, pointer })
    }

    /// Release the complete owned extent, coalescing free physical buddies.
    /// # Errors
    /// Rejects a foreign token without modifying allocator state. Release is
    /// BSP-only, non-sleeping/non-reentrant, just like allocation.
    pub fn release(&mut self, frame: Frame) -> Result<(), Error> {
        self.buddy.release(frame.block)
    }

    /// # Errors
    /// Rejects a foreign, wrong-order, interior, metadata or non-live reservation.
    /// # Safety
    /// Caller exclusively owns an ORDER-ZERO reservation from this allocator.
    /// No references, CPU/DMA users or translations remain; active tables need
    /// prior CR3/TLB/SMP retirement. Never reclaim the same reservation twice.
    pub unsafe fn reclaim_reserved(&mut self, physical: Physical) -> Result<(), Error> {
        // SAFETY: caller establishes exact order-zero ownership and quiescence.
        unsafe { self.reclaim_reserved_order(physical, 0) }
    }

    /// Reclaim one whole reservation using its ORIGINAL order, not a rounded
    /// byte request. Pre-publication rollback may use this only after removing
    /// all references; AP publication requires a separate quiescence proof.
    /// # Errors
    /// Rejects invalid order, misalignment, wrong head/order, metadata or a free
    /// extent without changing state. Checks cannot establish mapping quiescence.
    /// # Safety
    /// Caller owns exactly the live `(physical, order)` reservation transferred
    /// by `Frame::into_reserved` from this allocator, with no remaining token,
    /// references, CPU users, DMA or translations. CR3/TLB/SMP retirement must
    /// precede reclaim of published storage. No second reclaim is permitted.
    pub unsafe fn reclaim_reserved_order(
        &mut self,
        physical: Physical,
        order: u32,
    ) -> Result<(), Error> {
        if !physical.0.is_multiple_of(PAGE) {
            return Err(Error::Alignment);
        }
        // SAFETY: the caller proves exclusive reservation ownership and complete
        // retirement. Buddy independently checks exact live head/order identity.
        let block = unsafe { self.buddy.reserved_block(physical.0 / PAGE, order)? };
        self.buddy.release(block)
    }

    #[cfg(feature = "qemu-self-test")]
    pub fn set_allocation_budget(&mut self, budget: Option<usize>) {
        self.allocation_budget = budget;
    }

    /// # Safety
    /// `first` heads the exclusive initialized order-zero reservation chain made
    /// by `test_exhaustion`. Pop transfers its head with no remaining alias.
    #[cfg(feature = "qemu-self-test")]
    unsafe fn pop_test_reservation(&self, first: &mut u64) -> Result<Frame, Error> {
        // SAFETY: caller owns this exact live chain head and transfers its token.
        let block = unsafe { self.buddy.reserved_block(*first / PAGE, 0)? };
        let pointer = ptr::with_exposed_provenance_mut::<u8>(
            usize::try_from(self.boot.direct_map + *first).map_err(|_| Error::Overflow)?,
        );
        // SAFETY: initialized live chain head, no aliases or concurrent accesses.
        *first = unsafe { ptr::read_unaligned(pointer.cast::<u64>()) };
        Ok(Frame { block, pointer })
    }

    /// Actual mixed-order RAM exercise. Returns the largest order exercised.
    /// Requires one naturally aligned order-10 block in this QEMU cell.
    /// # Errors
    /// Fails on any allocation/content/alignment/reservation/accounting mismatch.
    #[cfg(feature = "qemu-self-test")]
    pub fn test_orders(&mut self) -> Result<u32, Error> {
        let before = self.allocated();
        for order in 0..=MAX_ORDER {
            let mut frame = self.allocate_order(order)?;
            if frame.order() != order
                || frame.page_count() != 1usize << order
                || !frame.physical().0.is_multiple_of(frame.byte_count() as u64)
                || !frame.bytes().iter().all(|&byte| byte == 0)
                || self.allocated() != before + (1usize << order)
            {
                return Err(Error::Ownership);
            }
            frame.bytes().fill(0xa5);
            self.release(frame)?;
        }
        let mut whole = self.allocate_order(MAX_ORDER)?;
        let physical = whole.physical();
        whole.bytes().fill(0x5a);
        let _reservation = whole.into_reserved();
        // SAFETY: this local test owns the reservation, never published or mapped
        // separately, and its last byte borrow ended before transfer.
        unsafe { self.reclaim_reserved_order(physical, MAX_ORDER)? };
        let mut merged = self.allocate_order(MAX_ORDER)?;
        if merged.physical() != physical || !merged.bytes().iter().all(|&byte| byte == 0) {
            return Err(Error::Ownership);
        }
        self.release(merged)?;
        let aligned = self.allocate_order_aligned(4, 32 * PAGE)?;
        if !aligned.physical().0.is_multiple_of(32 * PAGE) || aligned.byte_count() != 65536 {
            return Err(Error::Alignment);
        }
        self.release(aligned)?;
        if !matches!(self.allocate_order(MAX_ORDER + 1), Err(Error::Order))
            || !matches!(self.allocate_order_aligned(4, 8191), Err(Error::Alignment))
            || !matches!(
                self.allocate_order_aligned(4, 1 << 63),
                Err(Error::NoMemory)
            )
        {
            return Err(Error::Ownership);
        }
        self.set_allocation_budget(Some(0));
        let failed = matches!(self.allocate_order(4), Err(Error::NoMemory));
        self.set_allocation_budget(None);
        if !failed || self.allocated() != before {
            return Err(Error::Ownership);
        }
        Ok(MAX_ORDER)
    }

    /// Exhaust actual RAM while retaining one order-four extent, then split it
    /// into pages, force physical fragmentation, coalesce and restore all pages.
    /// # Errors
    /// Reports real allocation/address or conservation failures. A controlled
    /// guest failure stops rather than recycling a partially recovered ledger.
    #[cfg(feature = "qemu-self-test")]
    pub fn test_exhaustion(&mut self) -> Result<usize, Error> {
        let before = self.available();
        let mut whole = self.allocate_order(4)?;
        let physical = whole.physical();
        whole.bytes().fill(0xa5);
        let mut first = 0u64;
        let mut count = whole.page_count();
        loop {
            match self.allocate() {
                Ok(mut frame) => {
                    frame.bytes()[..8].copy_from_slice(&first.to_le_bytes());
                    first = frame.physical().0;
                    let _ownership = frame.into_reserved();
                    count += 1;
                }
                Err(Error::NoMemory) => break,
                Err(error) => return Err(error),
            }
        }
        if self.available() != 0
            || count != before
            || !matches!(self.allocate(), Err(Error::NoMemory))
        {
            return Err(Error::Ownership);
        }
        // The ledger retains every other free page. Releasing this block makes
        // exactly its sixteen physical pages available, independent of tie order.
        self.release(whole)?;
        let mut pages: [Option<Frame>; 16] = core::array::from_fn(|_| None);
        let mut seen = 0u16;
        for slot in &mut pages {
            let mut page = self.allocate()?;
            let offset = page
                .physical()
                .0
                .checked_sub(physical.0)
                .ok_or(Error::Ownership)?
                / PAGE;
            if offset >= 16
                || seen & (1 << offset) != 0
                || !page.bytes().iter().all(|&byte| byte == 0)
            {
                return Err(Error::Ownership);
            }
            seen |= 1 << offset;
            page.bytes().fill(0x5a);
            *slot = Some(page);
        }
        if seen != u16::MAX || self.available() != 0 {
            return Err(Error::Ownership);
        }
        for slot in &mut pages {
            if slot
                .as_ref()
                .is_some_and(|page| (page.physical().0 / PAGE) & 1 == 0)
            {
                self.release(slot.take().ok_or(Error::Ownership)?)?;
            }
        }
        if self.available() != 8 || !matches!(self.allocate_order(1), Err(Error::NoMemory)) {
            return Err(Error::Ownership);
        }
        for mut page in pages.into_iter().flatten() {
            if !page.bytes().iter().all(|&byte| byte == 0x5a) {
                return Err(Error::Ownership);
            }
            self.release(page)?;
        }
        let mut merged = self.allocate_order(4)?;
        if merged.physical() != physical
            || self.available() != 0
            || !merged.bytes().iter().all(|&byte| byte == 0)
        {
            return Err(Error::Ownership);
        }
        self.release(merged)?;
        while first != 0 {
            // SAFETY: the ledger stayed reserved while the distinct pool ran.
            let frame = unsafe { self.pop_test_reservation(&mut first)? };
            self.release(frame)?;
        }
        let aligned = self.allocate_aligned(2 * PAGE)?;
        if !aligned.physical().0.is_multiple_of(2 * PAGE) {
            return Err(Error::Alignment);
        }
        self.release(aligned)?;
        if !matches!(self.allocate_aligned(1 << 63), Err(Error::NoMemory))
            || self.available() != before
        {
            return Err(Error::Ownership);
        }
        Ok(count)
    }
}
