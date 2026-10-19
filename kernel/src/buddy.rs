// SPDX-License-Identifier: GPL-2.0-only AND GPL-2.0-or-later
//
// Selected buddy algorithms translated from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692:
// mm/page_alloc.c (GPL-2.0-only), __rmqueue_smallest, expand, __free_one_page.
// Original file notices (including work outside the translated mechanisms):
// Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
// Swap reorganised 29.12.95, Stephen Tweedie
// Support of BIGMEM added by Gerhard Wichert, Siemens AG, July 1999
// Reshaped it to be a zoned allocator, Ingo Molnar, Red Hat, 1999
// Discontiguous memory support, Kanoj Sarcar, SGI, Nov 1999
// Zone balancing, Kanoj Sarcar, SGI, Jan 2000
// Per cpu hot/cold page lists, bulk allocation, Martin J. Bligh, Sept 2002
//         (lots of bits borrowed from Ingo Molnar & Andrew Morton)
// mm/internal.h (GPL-2.0-or-later), __find_buddy_pfn/page_is_buddy:
// Copyright (C) 2004 Red Hat, Inc. All Rights Reserved.
// Written by David Howells (dhowells@redhat.com)
// include/linux/mmzone.h (GPL-2.0), default MAX_PAGE_ORDER.
//
// Transformation: compact native-word bitmaps replace C free lists; checked
// loader arenas replace the as-yet unported zone/page metadata. New Rust owner
// tokens, reservation checks and metadata layout are GPL-2.0-only project work.
// Every order uses smallest-order selection and lower-child splitting. This is
// not the zone, migration-type, per-CPU-cache, reserve or reclaim policy.

use super::Error;
use crate::bitmap::{BITS_PER_WORD, Bitmap};
use core::ops::Range;

/// Selected initial `x86_64`/4KiB default, not a universal Linux limit: pinned
/// mmzone.h uses `CONFIG_ARCH_FORCE_MAX_ORDER` when an architecture config sets it.
pub const MAX_ORDER: u32 = 10;
const ORDERS: usize = MAX_ORDER as usize + 1;
// Each parent bit indexes one native word in the level below it.
const INDEX_LEVELS: usize = usize::BITS.div_ceil(usize::BITS.ilog2()) as usize;

#[derive(Clone, Copy)]
struct SummaryLevel {
    start: usize,
    bits: usize,
}

struct FreeLayout {
    levels: [SummaryLevel; INDEX_LEVELS],
    depth: usize,
    leaf_words: usize,
    summary_bits: usize,
    words: usize,
}

impl FreeLayout {
    fn new(bits: usize) -> Result<Self, Error> {
        let leaf_words = bits.div_ceil(BITS_PER_WORD);
        let mut layout = Self {
            levels: [SummaryLevel { start: 0, bits: 0 }; INDEX_LEVELS],
            depth: 0,
            leaf_words,
            summary_bits: 0,
            words: leaf_words,
        };
        let mut children = leaf_words;
        while children > 1 {
            layout.levels[layout.depth] = SummaryLevel {
                start: layout.summary_bits,
                bits: children,
            };
            layout.depth += 1;
            let words = children.div_ceil(BITS_PER_WORD);
            layout.summary_bits = words
                .checked_mul(BITS_PER_WORD)
                .and_then(|bits| layout.summary_bits.checked_add(bits))
                .ok_or(Error::Overflow)?;
            layout.words = layout.words.checked_add(words).ok_or(Error::Overflow)?;
            children = words;
        }
        Ok(layout)
    }
}

/// The same free-area bits, indexed by word-sized empty/nonempty summaries.
/// A set summary bit means its child word contains no logical free (zero) bit.
/// Padding stays set. No address hint or duplicate page-ownership state exists.
struct FreeAreas<'a> {
    leaves: Bitmap<'a>,
    summaries: Bitmap<'a>,
    layout: FreeLayout,
}

impl<'a> FreeAreas<'a> {
    /// Checks every size before initializing the empty free-area hierarchy.
    fn new(storage: &'a mut [usize], bits: usize) -> Result<Self, Error> {
        let layout = FreeLayout::new(bits)?;
        let storage = storage.get_mut(..layout.words).ok_or(Error::NoMemory)?;
        let (leaves, summaries) = storage.split_at_mut(layout.leaf_words);
        let mut leaves = Bitmap::new(leaves, bits).ok_or(Error::NoMemory)?;
        let mut summaries = Bitmap::new(summaries, layout.summary_bits).ok_or(Error::NoMemory)?;
        leaves.fill_range(0, bits, true);
        summaries.fill_range(0, layout.summary_bits, true);
        Ok(Self {
            leaves,
            summaries,
            layout,
        })
    }

    fn get(&self, index: usize) -> Option<bool> {
        self.leaves.get(index)
    }

    fn replace(&mut self, index: usize, value: bool) -> Option<bool> {
        let previous = self.leaves.replace(index, value)?;
        if previous == value || self.layout.depth == 0 {
            return Some(previous);
        }
        let mut child = index / BITS_PER_WORD;
        let start = child * BITS_PER_WORD;
        let end = start
            .saturating_add(BITS_PER_WORD)
            .min(self.leaves.bit_count());
        // Publishing a zero proves nonfullness without rereading the word.
        let mut full = value && self.leaves.find_next_zero_in(start, end) == end;
        for (depth, level) in self.layout.levels[..self.layout.depth].iter().enumerate() {
            if self.summaries.replace(level.start + child, full) == Some(full)
                || depth + 1 == self.layout.depth
            {
                break;
            }
            child /= BITS_PER_WORD;
            let start = level.start + child * BITS_PER_WORD;
            let end = start
                .saturating_add(BITS_PER_WORD)
                .min(level.start + level.bits);
            full = full && self.summaries.find_next_zero_in(start, end) == end;
        }
        Some(previous)
    }

    // Each invocation examines at most one native word, including at a partial
    // arena/order boundary. Parent indices are relative to that level's origin.
    fn word_zero(&self, level: usize, start: usize, end: usize) -> usize {
        if level == 0 {
            self.leaves.find_next_zero_in(start, end)
        } else {
            let offset = self.layout.levels[level - 1].start;
            self.summaries
                .find_next_zero_in(offset + start, offset + end)
                - offset
        }
    }

    fn indexed_zero(&self, level: usize, start: usize, end: usize) -> usize {
        if start >= end {
            return end;
        }
        let boundary = start
            .saturating_add(BITS_PER_WORD - start % BITS_PER_WORD)
            .min(end);
        let first = self.word_zero(level, start, boundary);
        if first < boundary || boundary == end {
            return first;
        }
        // The starting partial word was exhausted. A parent summary skips all
        // later full words; only the final partial word can yield a false lead.
        let parent_end = end.div_ceil(BITS_PER_WORD);
        let child = self.indexed_zero(level + 1, boundary / BITS_PER_WORD, parent_end);
        if child == parent_end {
            return end;
        }
        let start = child * BITS_PER_WORD;
        self.word_zero(level, start, start.saturating_add(BITS_PER_WORD).min(end))
    }

    fn find_next_zero_in(&self, start: usize, end: usize) -> usize {
        self.indexed_zero(0, start, end.min(self.leaves.bit_count()))
    }
}

/// One original usable loader allocation, never a span over a physical hole.
/// Each order contains only complete naturally aligned blocks in this arena.
#[derive(Clone, Copy)]
pub(super) struct Arena {
    start: u64,
    end: u64,
    offsets: [usize; ORDERS],
    bits_end: usize,
}

impl Arena {
    pub(super) fn new(start: u64, end: u64, bits_start: usize) -> Result<Self, Error> {
        if start == 0 || start >= end {
            return Err(Error::Ownership);
        }
        usize::try_from(end - start).map_err(|_| Error::Overflow)?;
        let mut offsets = [0; ORDERS];
        let mut bits_end = bits_start;
        for order in 0..=MAX_ORDER {
            offsets[order as usize] = bits_end;
            let first = start
                .checked_add((1u64 << order) - 1)
                .ok_or(Error::Overflow)?
                >> order;
            let count = (end >> order).saturating_sub(first);
            bits_end = bits_end
                .checked_add(usize::try_from(count).map_err(|_| Error::Overflow)?)
                .ok_or(Error::Overflow)?;
        }
        Ok(Self {
            start,
            end,
            offsets,
            bits_end,
        })
    }

    pub(super) fn pages(&self) -> usize {
        usize::try_from(self.end - self.start).expect("constructor checked arena size")
    }

    pub(super) fn bits_end(&self) -> usize {
        self.bits_end
    }

    fn first(&self, order: u32) -> u64 {
        (self.start + (1u64 << order) - 1) >> order
    }

    fn bounds(&self, order: u32) -> Range<usize> {
        let start = self.offsets[order as usize];
        let count = usize::try_from((self.end >> order).saturating_sub(self.first(order)))
            .expect("order extent is bounded by the checked arena size");
        start..start + count
    }

    fn index(&self, pfn: u64, order: u32) -> Option<usize> {
        let pages = 1u64 << order;
        if pfn < self.start || pfn & (pages - 1) != 0 || pfn > self.end.saturating_sub(pages) {
            return None;
        }
        Some(
            self.offsets[order as usize]
                + usize::try_from((pfn >> order) - self.first(order)).ok()?,
        )
    }
}

/// A unique live allocation. Forgetting it can leak pages, never duplicate them.
/// The metadata address stays stable even when its allocator is moved.
#[must_use]
pub(super) struct Block {
    pfn: u64,
    order: u32,
    arena: usize,
    origin: *const usize,
}

impl Block {
    pub(super) fn pfn(&self) -> u64 {
        self.pfn
    }

    pub(super) fn order(&self) -> u32 {
        self.order
    }

    pub(super) fn pages(&self) -> usize {
        1usize << self.order
    }
}

/// Exclusive, non-reentrant state for the same BSP allocator as `Frame`.
/// Free blocks are encoded by clear bits; allocated heads by set bits. Exact
/// head/order checks reject releasing two neighboring owners or part of a larger
/// allocation. No per-page duplicate state or address-selection hint is needed.
pub(super) struct Buddy<'a> {
    arenas: &'a [Arena],
    free: FreeAreas<'a>,
    heads: Bitmap<'a>,
    reserved: Range<u64>,
    allocated: usize,
    total: usize,
    origin: *const usize,
}

impl<'a> Buddy<'a> {
    /// Includes all checked nonempty-word summary storage, not just leaf bits.
    pub(super) fn free_words(bits: usize) -> Result<usize, Error> {
        Ok(FreeLayout::new(bits)?.words)
    }

    pub(super) fn new(
        arenas: &'a [Arena],
        free: &'a mut [usize],
        heads: &'a mut [usize],
        reserved: Range<u64>,
    ) -> Result<Self, Error> {
        if arenas.is_empty() || reserved.start > reserved.end {
            return Err(Error::Ownership);
        }
        let mut total = 0usize;
        let mut bits_end = 0;
        let mut physical_end = 0;
        for arena in arenas {
            if arena.start < physical_end || arena.offsets[0] != bits_end {
                return Err(Error::Ownership);
            }
            physical_end = arena.end;
            total = total.checked_add(arena.pages()).ok_or(Error::Overflow)?;
            bits_end = arena.bits_end;
        }
        let origin = free.as_ptr();
        let heads = Bitmap::new(heads, bits_end).ok_or(Error::NoMemory)?;
        let free = FreeAreas::new(free, bits_end)?;
        let mut buddy = Self {
            arenas,
            free,
            heads,
            reserved,
            allocated: total,
            total,
            origin,
        };
        buddy.heads.fill_range(0, bits_end, false);
        for arena in arenas {
            if buddy.reserved.is_empty() {
                buddy.add_initial_range(arena, arena.start, arena.end);
                continue;
            }
            let excluded_start = buddy.reserved.start.clamp(arena.start, arena.end);
            let excluded_end = buddy.reserved.end.clamp(arena.start, arena.end);
            buddy.add_initial_range(arena, arena.start, excluded_start);
            buddy.add_initial_range(arena, excluded_end, arena.end);
        }
        Ok(buddy)
    }

    fn add_initial_range(&mut self, arena: &Arena, mut start: u64, end: u64) {
        self.allocated -=
            usize::try_from(end - start).expect("initial range stays inside checked arena");
        while start < end {
            let order = start
                .trailing_zeros()
                .min((end - start).ilog2())
                .min(MAX_ORDER);
            let index = arena.offsets[order as usize]
                + usize::try_from((start >> order) - arena.first(order))
                    .expect("initial block stays inside checked arena");
            self.free.replace(index, false);
            start += 1u64 << order;
        }
    }

    pub(super) fn total(&self) -> usize {
        self.total
    }

    pub(super) fn allocated(&self) -> usize {
        self.allocated
    }

    pub(super) fn available(&self) -> usize {
        self.total() - self.allocated
    }

    pub(super) fn validate_request(order: u32, alignment: u64) -> Result<(), Error> {
        if order > MAX_ORDER {
            return Err(Error::Order);
        }
        // Alignment is expressed in pages here, bytes at the public boundary.
        if !alignment.is_power_of_two() {
            return Err(Error::Alignment);
        }
        Ok(())
    }

    pub(super) fn allocate(&mut self, order: u32, alignment: u64) -> Result<Block, Error> {
        Self::validate_request(order, alignment)?;
        if self.available() < 1usize << order {
            return Err(Error::NoMemory);
        }
        for current_order in order..=MAX_ORDER {
            for (arena_index, arena) in self.arenas.iter().enumerate() {
                let range = arena.bounds(current_order);
                let mut index = self.free.find_next_zero_in(range.start, range.end);
                while index < range.end {
                    let pfn = (arena.first(current_order) + (index - range.start) as u64)
                        << current_order;
                    if pfn & (alignment - 1) == 0 {
                        return Ok(self.claim(arena_index, pfn, order, current_order, index));
                    }
                    // Skip the entire ineligible PFN interval, rather than
                    // enumerating its free heads. The indexed search also skips
                    // full words inside the remaining eligible search range.
                    let Some(aligned) = pfn.checked_add(alignment - 1) else {
                        break;
                    };
                    let Some(next) = arena.index(aligned & !(alignment - 1), current_order) else {
                        break;
                    };
                    index = self.free.find_next_zero_in(next, range.end);
                }
            }
        }
        Err(Error::NoMemory)
    }

    fn claim(
        &mut self,
        arena_index: usize,
        pfn: u64,
        order: u32,
        mut current_order: u32,
        index: usize,
    ) -> Block {
        let arena = &self.arenas[arena_index];
        // All indices are complete descendants of the selected free block.
        // No fallible operation remains after the first state change.
        self.free.replace(index, true);
        while current_order > order {
            current_order -= 1;
            let other = pfn + (1u64 << current_order);
            let sibling = arena.offsets[current_order as usize]
                + usize::try_from((other >> current_order) - arena.first(current_order))
                    .expect("split descendant stays inside checked arena");
            self.free.replace(sibling, false);
        }
        let head = arena.offsets[order as usize]
            + usize::try_from((pfn >> order) - arena.first(order))
                .expect("claimed block stays inside checked arena");
        self.heads.replace(head, true);
        self.allocated += 1usize << order;
        Block {
            pfn,
            order,
            arena: arena_index,
            origin: self.origin,
        }
    }

    fn live_head(&self, pfn: u64, order: u32, arena: &Arena) -> Result<usize, Error> {
        if order > MAX_ORDER {
            return Err(Error::Order);
        }
        let index = arena.index(pfn, order).ok_or(Error::Ownership)?;
        let end = pfn + (1u64 << order);
        if !self.reserved.is_empty() && pfn < self.reserved.end && self.reserved.start < end
            || self.heads.get(index) != Some(true)
        {
            return Err(Error::Ownership);
        }
        Ok(index)
    }

    #[expect(
        clippy::needless_pass_by_value,
        reason = "Consumes the only allocation token."
    )]
    pub(super) fn release(&mut self, block: Block) -> Result<(), Error> {
        if block.origin != self.origin {
            return Err(Error::Ownership);
        }
        let arena = self.arenas.get(block.arena).ok_or(Error::Ownership)?;
        let head = self.live_head(block.pfn, block.order, arena)?;
        self.heads.replace(head, false);
        self.allocated -= block.pages();
        let mut pfn = block.pfn;
        let mut order = block.order;
        while order < MAX_ORDER {
            let sibling = pfn ^ (1u64 << order);
            let Some(index) = arena.index(sibling, order) else {
                break;
            };
            if self.free.get(index) != Some(false) {
                break;
            }
            self.free.replace(index, true);
            pfn &= sibling;
            order += 1;
        }
        let index = arena.offsets[order as usize]
            + usize::try_from((pfn >> order) - arena.first(order))
                .expect("coalesced block stays inside checked arena");
        self.free.replace(index, false);
        Ok(())
    }

    /// # Safety
    /// Caller owns this exact live reservation with no token or other remaining
    /// users. All CPU/device/mapping access must have ended before reconstitution.
    pub(super) unsafe fn reserved_block(&self, pfn: u64, order: u32) -> Result<Block, Error> {
        let (arena_index, arena) = self
            .arenas
            .iter()
            .enumerate()
            .find(|(_, arena)| pfn >= arena.start && pfn < arena.end)
            .ok_or(Error::Ownership)?;
        self.live_head(pfn, order, arena)?;
        Ok(Block {
            pfn,
            order,
            arena: arena_index,
            origin: self.origin,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Arena, BITS_PER_WORD, Block, Buddy, Error, FreeAreas, FreeLayout, INDEX_LEVELS, MAX_ORDER,
    };
    use core::ops::Range;

    fn check_summaries(free: &FreeAreas<'_>) {
        let mut child_bits = free.leaves.bit_count();
        let mut child_offset = None;
        for level in &free.layout.levels[..free.layout.depth] {
            for index in 0..level.bits {
                let start = index * BITS_PER_WORD;
                let end = start.saturating_add(BITS_PER_WORD).min(child_bits);
                let full = (start..end).all(|bit| {
                    if let Some(offset) = child_offset {
                        free.summaries.get(offset + bit) == Some(true)
                    } else {
                        free.leaves.get(bit) == Some(true)
                    }
                });
                assert_eq!(free.summaries.get(level.start + index), Some(full));
            }
            for padding in level.bits..level.bits.div_ceil(BITS_PER_WORD) * BITS_PER_WORD {
                assert_eq!(free.summaries.get(level.start + padding), Some(true));
            }
            child_bits = level.bits;
            child_offset = Some(level.start);
        }
    }

    #[test]
    fn hierarchy_layout_capacity_and_initialization_are_checked() {
        let word = BITS_PER_WORD;
        for (bits, words) in [
            (0, 0),
            (1, 1),
            (word, 1),
            (word + 1, 3),
            (word * word, word + 1),
            (word * word + 1, word + 4),
            (word * word * word + 1, word * word + word + 5),
        ] {
            assert_eq!(Buddy::free_words(bits), Ok(words));
        }
        let largest = FreeLayout::new(usize::MAX).expect("bounded layout");
        assert!(largest.depth <= INDEX_LEVELS);
        assert!(largest.levels[largest.depth - 1].bits <= word);
        let mut short = [0x5ausize; 2];
        assert!(matches!(
            FreeAreas::new(&mut short, word + 1),
            Err(Error::NoMemory)
        ));
        assert_eq!(short, [0x5a; 2]);
        let mut storage = [0x5ausize; 4];
        {
            let mut free = FreeAreas::new(&mut storage, word + 1).expect("sized hierarchy");
            assert_eq!(free.find_next_zero_in(0, usize::MAX), word + 1);
            assert_eq!(free.replace(word + 1, false), None);
            assert_eq!(free.replace(usize::MAX, false), None);
            assert_eq!(free.replace(word, false), Some(true));
            assert_eq!(free.replace(word, false), Some(false));
            assert_eq!(free.find_next_zero_in(0, word + 1), word);
            check_summaries(&free);
        }
        assert_eq!(storage[1] & !1, 0x5a & !1);
        assert_eq!(storage[3], 0x5a);
        let mut empty_storage = [];
        let empty = FreeAreas::new(&mut empty_storage, 0).expect("empty hierarchy");
        assert_eq!(empty.find_next_zero_in(0, usize::MAX), 0);
        assert_eq!(empty.find_next_zero_in(usize::MAX, usize::MAX), 0);
    }

    #[test]
    fn hierarchy_boundaries_and_both_transition_directions_match_literal_bits() {
        const WORD: usize = BITS_PER_WORD;
        const BITS: usize = WORD * WORD * WORD + WORD + 7;
        extern crate std;
        let mut storage = std::vec::Vec::new();
        storage
            .try_reserve_exact(WORD * WORD + 2 * WORD + 8)
            .expect("host hierarchy storage");
        storage.resize(WORD * WORD + 2 * WORD + 8, 0);
        let mut free = FreeAreas::new(&mut storage, BITS).expect("three-level hierarchy");
        let positions = [
            0,
            WORD - 1,
            WORD,
            WORD + 1,
            WORD * WORD - 1,
            WORD * WORD,
            WORD * WORD + 1,
            BITS - 1,
        ];
        let boundaries = [
            0,
            1,
            WORD - 1,
            WORD,
            WORD + 1,
            WORD + 2,
            WORD * WORD - 1,
            WORD * WORD,
            WORD * WORD + 1,
            WORD * WORD + 2,
            BITS - 1,
            BITS,
            BITS + 1,
        ];
        let mut available = [false; 8];
        for value in [false, true] {
            for (slot, &position) in positions.iter().enumerate() {
                free.replace(position, value).expect("in bounds");
                available[slot] = !value;
                check_summaries(&free);
                for &start in &boundaries {
                    for &end in &boundaries {
                        let end = end.min(BITS);
                        let expected = positions
                            .iter()
                            .enumerate()
                            .filter(|&(index, position)| {
                                available[index] && *position >= start && *position < end
                            })
                            .map(|(_, &position)| position)
                            .min()
                            .unwrap_or(end);
                        assert_eq!(
                            free.find_next_zero_in(start, end),
                            expected,
                            "{start}..{end}"
                        );
                    }
                }
            }
        }
        assert_eq!(free.find_next_zero_in(0, BITS), BITS);
    }

    fn with_buddy(ranges: &[(u64, u64)], reserved: Range<u64>, test: impl FnOnce(&mut Buddy<'_>)) {
        let mut arenas = [Arena::new(1, 2, 0).expect("fixture"); 4];
        let mut bits = 0;
        for (arena, &(start, end)) in arenas.iter_mut().zip(ranges) {
            *arena = Arena::new(start, end, bits).expect("fixture geometry");
            bits = arena.bits_end();
        }
        let mut free = [0usize; 512];
        let mut heads = [0usize; 512];
        let mut buddy = Buddy::new(&arenas[..ranges.len()], &mut free, &mut heads, reserved)
            .expect("fixture metadata");
        check_partition(&buddy);
        test(&mut buddy);
        check_partition(&buddy);
    }

    // Independent per-page oracle: exactly one free block or allocated head
    // covers each unreserved page, no free block covers any reserved page, and
    // two simultaneously free physical buddies are never left uncoalesced.
    fn check_partition(buddy: &Buddy<'_>) {
        check_summaries(&buddy.free);
        let mut allocated = 0;
        let mut free_pages = 0;
        for arena in buddy.arenas {
            for pfn in arena.start..arena.end {
                let mut free_coverage = 0;
                let mut owned_coverage = 0;
                for order in 0..=MAX_ORDER {
                    let base = pfn & !((1u64 << order) - 1);
                    if let Some(index) = arena.index(base, order) {
                        free_coverage += usize::from(buddy.free.get(index) == Some(false));
                        owned_coverage += usize::from(buddy.heads.get(index) == Some(true));
                    }
                }
                let reserved = buddy.reserved.contains(&pfn);
                assert_eq!(
                    free_coverage + owned_coverage + usize::from(reserved),
                    1,
                    "pfn={pfn}"
                );
                let occupied = owned_coverage == 1 || reserved;
                allocated += usize::from(occupied);
                free_pages += free_coverage;
            }
            for order in 0..MAX_ORDER {
                for index in arena.bounds(order) {
                    if buddy.free.get(index) != Some(false) {
                        continue;
                    }
                    let pfn = (arena.first(order) + (index - arena.offsets[order as usize]) as u64)
                        << order;
                    if let Some(sibling) = arena.index(pfn ^ (1u64 << order), order) {
                        assert_ne!(
                            buddy.free.get(sibling),
                            Some(false),
                            "unmerged buddies order={order}"
                        );
                    }
                }
            }
        }
        assert_eq!(allocated, buddy.allocated());
        assert_eq!(free_pages, buddy.available());
        assert_eq!(allocated + free_pages, buddy.total());
    }

    #[test]
    fn every_order_splits_and_coalesces_the_only_maximal_block() {
        for order in 0..=MAX_ORDER {
            with_buddy(&[(1024, 2048)], 0..0, |buddy| {
                let mut blocks: [Option<Block>; 1024] = core::array::from_fn(|_| None);
                let count = 1024 >> order;
                for (index, slot) in blocks[..count].iter_mut().enumerate() {
                    let block = buddy.allocate(order, 1).expect("split");
                    assert_eq!(block.pfn(), 1024 + ((index as u64) << order));
                    assert_eq!(block.order(), order);
                    *slot = Some(block);
                }
                assert_eq!(buddy.available(), 0);
                assert!(matches!(buddy.allocate(order, 1), Err(Error::NoMemory)));
                check_partition(buddy);
                for slot in blocks[..count].iter_mut().rev() {
                    buddy
                        .release(slot.take().expect("live owner"))
                        .expect("release");
                }
                check_partition(buddy);
                let whole = buddy.allocate(MAX_ORDER, 1).expect("fully coalesced");
                assert_eq!(whole.pfn(), 1024);
                assert_eq!(whole.pages(), 1024);
                buddy.release(whole).expect("whole release");
            });
        }
    }

    #[test]
    fn physical_holes_region_boundaries_and_metadata_never_merge() {
        with_buddy(&[(3, 17), (32, 40), (40, 48), (64, 96)], 70..74, |buddy| {
            let before = buddy.available();
            assert_eq!(buddy.allocated(), 4);
            assert!(matches!(buddy.allocate(5, 1), Err(Error::NoMemory)));
            let mut blocks: [Option<Block>; 62] = core::array::from_fn(|_| None);
            for slot in blocks.iter_mut().take(before) {
                let block = buddy.allocate(0, 1).expect("usable page");
                assert!(
                    (3..17).contains(&block.pfn())
                        || (32..48).contains(&block.pfn())
                        || (64..96).contains(&block.pfn())
                );
                assert!(!(70..74).contains(&block.pfn()));
                *slot = Some(block);
            }
            assert_eq!(buddy.available(), 0);
            for slot in blocks.iter_mut().take(before).step_by(2) {
                buddy
                    .release(slot.take().expect("even owner"))
                    .expect("even release");
            }
            check_partition(buddy);
            for slot in blocks.iter_mut().take(before).skip(1).step_by(2) {
                buddy
                    .release(slot.take().expect("odd owner"))
                    .expect("odd release");
            }
            check_partition(buddy);
            // Adjacent original loader allocations 32..40 and 40..48 do not
            // constitute one provenance domain or an order-four free block.
            assert!(buddy.arenas[1].index(32, 4).is_none());
            assert_eq!(buddy.available(), before);
        });
    }

    #[test]
    fn aligned_single_page_does_not_require_its_buddy_to_be_free() {
        with_buddy(&[(8, 16)], 0..0, |buddy| {
            let mut blocks: [Option<Block>; 8] = core::array::from_fn(|_| None);
            for slot in &mut blocks {
                *slot = Some(buddy.allocate(0, 1).expect("exhaust"));
            }
            buddy
                .release(blocks[0].take().expect("aligned page"))
                .expect("release");
            let aligned = buddy
                .allocate(0, 8)
                .expect("aligned singleton with occupied buddy");
            assert_eq!(aligned.pfn(), 8);
            assert_eq!(aligned.pages(), 1);
            assert_eq!(buddy.available(), 0);
            buddy.release(aligned).expect("aligned free");
            for block in blocks.into_iter().flatten() {
                buddy.release(block).expect("remaining free");
            }
        });
    }

    #[test]
    fn stronger_alignment_fragmentation_and_bad_requests_are_atomic() {
        with_buddy(&[(3, 29)], 0..0, |buddy| {
            let aligned = buddy.allocate(2, 16).expect("overaligned block");
            assert_eq!(aligned.pfn(), 16);
            assert_eq!(aligned.pages(), 4);
            let before = buddy.allocated();
            for (order, alignment, expected) in [
                (MAX_ORDER + 1, 1, Error::Order),
                (0, 0, Error::Alignment),
                (0, 3, Error::Alignment),
                (2, 64, Error::NoMemory),
                (5, 1, Error::NoMemory),
            ] {
                assert!(
                    matches!(buddy.allocate(order, alignment), Err(error) if error == expected)
                );
                assert_eq!(buddy.allocated(), before);
                check_partition(buddy);
            }
            buddy.release(aligned).expect("free");
        });
        with_buddy(&[(32, 48)], 0..0, |buddy| {
            let mut blocks: [Option<Block>; 16] = core::array::from_fn(|_| None);
            for slot in &mut blocks {
                *slot = Some(buddy.allocate(0, 1).expect("exhaust"));
            }
            for slot in blocks.iter_mut().step_by(2) {
                buddy.release(slot.take().expect("even")).expect("release");
            }
            assert_eq!(buddy.available(), 8);
            assert!(matches!(buddy.allocate(1, 1), Err(Error::NoMemory)));
            check_partition(buddy);
            for block in blocks.into_iter().flatten() {
                buddy.release(block).expect("odd release");
            }
            let whole = buddy.allocate(4, 1).expect("all buddies restored");
            buddy.release(whole).expect("release");
        });
    }

    #[test]
    fn smallest_order_is_selected_across_all_arenas() {
        with_buddy(&[(16, 32), (40, 44)], 0..0, |buddy| {
            let exact = buddy.allocate(2, 1).expect("smallest sufficient");
            assert_eq!(exact.pfn(), 40);
            let large = buddy.allocate(4, 1).expect("larger first arena preserved");
            assert_eq!(large.pfn(), 16);
            buddy.release(exact).expect("exact free");
            buddy.release(large).expect("large free");
        });
    }

    #[test]
    fn exact_live_head_order_and_origin_are_required() {
        with_buddy(&[(16, 48)], 16..18, |buddy| {
            let block = buddy.allocate(3, 1).expect("owner");
            let pfn = block.pfn();
            let arena = &buddy.arenas[block.arena];
            assert_eq!(buddy.live_head(pfn, 2, arena), Err(Error::Ownership));
            assert_eq!(buddy.live_head(pfn + 1, 3, arena), Err(Error::Ownership));
            assert_eq!(
                buddy.live_head(pfn, MAX_ORDER + 1, arena),
                Err(Error::Order)
            );
            assert_eq!(buddy.live_head(16, 0, arena), Err(Error::Ownership));
            let wrong = Block {
                pfn,
                order: 3,
                arena: block.arena,
                origin: core::ptr::null(),
            };
            let before = buddy.allocated();
            assert_eq!(buddy.release(wrong), Err(Error::Ownership));
            assert_eq!(buddy.allocated(), before);
            buddy.release(block).expect("correct release");
            assert_eq!(buddy.live_head(pfn, 3, arena), Err(Error::Ownership));
            let first = buddy.allocate(0, 1).expect("first");
            let second = buddy.allocate(0, 1).expect("second");
            assert_eq!(
                buddy.live_head(first.pfn() & !1, 1, arena),
                Err(Error::Ownership)
            );
            buddy.release(first).expect("first free");
            buddy.release(second).expect("second free");
        });
    }

    #[test]
    fn checked_geometry_and_metadata_exhaustion_do_not_publish_owners() {
        assert!(matches!(Arena::new(0, 1, 0), Err(Error::Ownership)));
        assert!(matches!(Arena::new(1, 1, 0), Err(Error::Ownership)));
        assert!(matches!(
            Arena::new(u64::MAX - 1, u64::MAX, 0),
            Err(Error::Overflow)
        ));
        assert!(matches!(Arena::new(1, 3, usize::MAX), Err(Error::Overflow)));
        let arenas = [Arena::new(1, 100, 0).expect("geometry")];
        let mut free = [0xa5usize; 8];
        let mut heads = [];
        assert!(matches!(
            Buddy::new(&arenas, &mut free, &mut heads, 0..0),
            Err(Error::NoMemory)
        ));
        assert_eq!(free, [0xa5; 8]);
        let leaf_words = arenas[0].bits_end().div_ceil(BITS_PER_WORD);
        let mut heads = [0x69usize; 8];
        assert!(matches!(
            Buddy::new(&arenas, &mut free[..leaf_words], &mut heads, 0..0),
            Err(Error::NoMemory)
        ));
        assert_eq!(free, [0xa5; 8]);
        assert_eq!(heads, [0x69; 8]);
        with_buddy(&[(8, 16)], 8..16, |buddy| {
            assert_eq!(buddy.available(), 0);
            assert!(matches!(buddy.allocate(0, 1), Err(Error::NoMemory)));
        });
    }

    #[test]
    fn empty_reservation_never_divides_a_free_buddy() {
        with_buddy(&[(8, 16)], 10..10, |buddy| {
            let whole = buddy
                .allocate(3, 1)
                .expect("empty reservation has no effect");
            assert_eq!(whole.pfn(), 8);
            assert_eq!(buddy.available(), 0);
            buddy.release(whole).expect("release");
        });
    }

    #[test]
    fn literal_geometry_oracles_cover_irregular_arenas_and_order_cap() {
        with_buddy(&[(3, 11)], 0..0, |buddy| {
            for (pfn, order) in [(3, 0), (4, 2), (8, 1), (10, 0)] {
                let index = buddy.arenas[0].index(pfn, order).expect("literal block");
                assert_eq!(buddy.free.get(index), Some(false));
            }
            assert_eq!(buddy.available(), 8);
            assert!(matches!(buddy.allocate(3, 1), Err(Error::NoMemory)));
        });
        with_buddy(&[(8, 10), (10, 12)], 0..0, |buddy| {
            assert!(matches!(buddy.allocate(2, 1), Err(Error::NoMemory)));
            let a = buddy.allocate(1, 1).expect("first arena");
            let b = buddy.allocate(1, 1).expect("second arena");
            assert_eq!((a.pfn(), b.pfn()), (8, 10));
            buddy.release(a).expect("first release");
            buddy.release(b).expect("second release");
        });
        with_buddy(&[(2048, 4096)], 0..0, |buddy| {
            let a = buddy.allocate(MAX_ORDER, 1).expect("first maximal block");
            let b = buddy.allocate(MAX_ORDER, 1).expect("second maximal block");
            assert_eq!((a.pfn(), b.pfn()), (2048, 3072));
            buddy.release(a).expect("first release");
            buddy.release(b).expect("second release");
        });
    }

    #[test]
    fn moving_allocator_preserves_stable_metadata_identity() {
        let arenas = [Arena::new(8, 16, 0).expect("geometry")];
        let mut free = [0; 1];
        let mut heads = [0; 1];
        let mut original = Buddy::new(&arenas, &mut free, &mut heads, 0..0).expect("metadata");
        let block = original.allocate(2, 1).expect("owner before move");
        let mut moved = original;
        moved.release(block).expect("same originating metadata");
        check_partition(&moved);
        assert_eq!(moved.available(), 8);
    }

    #[test]
    fn deterministic_mixed_orders_preserve_exact_partition() {
        with_buddy(&[(3, 191), (256, 512)], 73..81, |buddy| {
            let initial = buddy.available();
            let mut live: [Option<Block>; 64] = core::array::from_fn(|_| None);
            let mut seed = 0xcafe_f00d_dead_beefu64;
            for _ in 0..4096 {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let index =
                    usize::try_from(seed % live.len() as u64).expect("bounded fixture index");
                if let Some(block) = live[index].take() {
                    buddy.release(block).expect("owned release");
                } else {
                    let order = ((seed >> 16) % 8) as u32;
                    let alignment = 1 << ((seed >> 24) % 9);
                    let before = buddy.allocated();
                    match buddy.allocate(order, alignment) {
                        Ok(block) => {
                            assert_eq!(block.pfn() & (alignment.max(1 << order) - 1), 0);
                            live[index] = Some(block);
                        }
                        Err(Error::NoMemory) => assert_eq!(buddy.allocated(), before),
                        Err(error) => panic!("unexpected allocation error: {error:?}"),
                    }
                }
                check_partition(buddy);
            }
            for block in live.into_iter().flatten() {
                buddy.release(block).expect("final release");
            }
            assert_eq!(buddy.available(), initial);
        });
    }

    #[test]
    fn aligned_search_skips_ineligible_free_ranges_and_checked_overflow() {
        extern crate std;

        with_buddy(&[(3, 8195)], 0..0, |buddy| {
            // Host-only fixture storage keeps every owner without overflowing
            // the test thread's stack; no kernel allocator or scope reduction.
            let mut blocks = std::vec::Vec::new();
            blocks
                .try_reserve_exact(8192)
                .expect("host fixture storage");
            blocks.resize_with(8192, || None);
            for slot in &mut blocks {
                *slot = Some(buddy.allocate(0, 1).expect("exhaust"));
            }
            let mut eligible = None;
            for slot in &mut blocks {
                let pfn = slot.as_ref().expect("live owner").pfn();
                if pfn & 1 != 0 {
                    buddy
                        .release(slot.take().expect("odd owner"))
                        .expect("fragment");
                } else if pfn == 4096 {
                    eligible = slot.take();
                }
            }
            assert_eq!(buddy.available(), 4096);
            assert!(matches!(buddy.allocate(0, 4096), Err(Error::NoMemory)));
            check_partition(buddy);
            buddy
                .release(eligible.expect("aligned owner"))
                .expect("release eligible");
            let aligned = buddy.allocate(0, 4096).expect("only eligible free PFN");
            assert_eq!(aligned.pfn(), 4096);
            buddy.release(aligned).expect("release");
            for block in blocks.into_iter().flatten() {
                buddy.release(block).expect("restore");
            }
            assert_eq!(buddy.available(), 8192);
        });
        with_buddy(&[(u64::MAX - 8191, u64::MAX - 4095)], 0..0, |buddy| {
            let before = buddy.available();
            assert!(matches!(
                buddy.allocate(0, 1u64 << 63),
                Err(Error::NoMemory)
            ));
            assert_eq!(buddy.available(), before);
        });
    }
}
