// SPDX-License-Identifier: GPL-2.0-only
//! The fallible kernel heap policy: a power-of-two buddy heap that grows by
//! whole chunks from a [`ChunkSource`] (the physical frame allocator in the
//! kernel, a fake in host tests) and reports exhaustion as `None`.
//!
//! The free-list engine is the vendored `buddy_system_allocator` 0.13.0
//! `Heap` (MIT; `default-features = false`: no spinlock, no `alloc`, no
//! dependency; see `docs/dependencies.md`). This module adds what the crate
//! does not have: growth on demand, a checked request size, and the contract
//! below. The `GlobalAlloc` adapter and the lock are in the binary
//! (`heap.rs` next to `main.rs`).
//!
//! # Contract
//! * Context: task context. The caller serializes access (the kernel wraps the
//!   heap in an IRQ-saving mutex) and never sleeps, reclaims or does I/O here;
//!   allocation never blocks. Interrupt handlers MUST NOT allocate until a
//!   GFP-style atomic reserve exists; NMI/#DF/#MC never may.
//! * Failure: every path that cannot be satisfied returns `None` with no
//!   state change visible to the caller: an oversized request (more than the
//!   largest block, `2^(ORDERS-1)` = 4 MiB, which is also the largest chunk the
//!   frame allocator can supply, Linux's `KMALLOC_MAX_SIZE` analogue) or a
//!   source that has no memory. There is no panic and no abort on any layout.
//! * Rounding: a request occupies the next power of two of `max(size, align,
//!   8)`; the waste is internal fragmentation of up to 50%.
//!   shortcut: free chunks are never returned to the source, and `dealloc`
//!   scans a free list to find the buddy (O(free blocks of that order)).
//!   Upgrade with measured need: a slab layer for hot small sizes
//!   (`slabmalloc`-style), chunk return on idle.

use buddy_system_allocator::Heap;
use core::{alloc::Layout, mem::size_of, ptr::NonNull};

/// Largest block is `2^(ORDERS - 1)` bytes: 4 MiB, exactly the largest chunk
/// the frame allocator can produce (`MAX_ORDER` 10), so a request the cap
/// accepts can in principle be served and one above it never asks the source.
pub const ORDERS: usize = 23;
/// Smallest chunk requested from a source: 64 KiB amortizes growth.
pub const MIN_CHUNK: usize = 64 * 1024;

/// Supplies fresh memory to a [`KernelHeap`].
///
/// # Safety
/// `grow` must return `(start, length)` of a region that is writable, not
/// otherwise referenced, and valid for the rest of the program (the heap never
/// returns it), disjoint from every region returned before, with
/// `length >= min_bytes`. For the heap to be able to satisfy the request that
/// caused the growth, `start` should be aligned to the power of two that
/// `length` is (a violation only makes the retry fail, never unsound).
pub unsafe trait ChunkSource {
    fn grow(&mut self, min_bytes: usize) -> Option<(usize, usize)>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeapStats {
    /// Bytes handed to the heap by its source.
    pub total: usize,
    /// Bytes currently occupied after power-of-two rounding.
    pub allocated: usize,
    /// Bytes currently requested by callers.
    pub requested: usize,
    /// Successful growths.
    pub chunks: usize,
    /// Growths the source refused.
    pub refused: usize,
}

pub struct KernelHeap<S> {
    heap: Heap<ORDERS>,
    source: S,
    chunks: usize,
    refused: usize,
}

impl<S: ChunkSource> KernelHeap<S> {
    #[must_use]
    pub const fn new(source: S) -> Self {
        Self {
            heap: Heap::new(),
            source,
            chunks: 0,
            refused: 0,
        }
    }

    /// Allocate `layout`, growing from the source when no free block fits.
    /// `None` is the allocation failure; nothing else is observable.
    pub fn alloc(&mut self, layout: Layout) -> Option<NonNull<u8>> {
        if let Ok(block) = self.heap.alloc(layout) {
            return Some(block);
        }
        // The engine's own sizing rule, checked: layouts never exceed isize::MAX
        // so the power of two exists, but be explicit that no panic can occur.
        let block = layout
            .size()
            .checked_next_power_of_two()?
            .max(layout.align())
            .max(size_of::<usize>());
        if block > 1 << (ORDERS - 1) {
            return None;
        }
        let Some((start, length)) = self.source.grow(block.max(MIN_CHUNK)) else {
            self.refused += 1;
            return None;
        };
        // SAFETY: `ChunkSource::grow`'s contract: a writable, unreferenced,
        // permanent region disjoint from all earlier ones.
        unsafe { self.heap.add_to_heap(start, start.checked_add(length)?) };
        self.chunks += 1;
        self.heap.alloc(layout).ok()
    }

    /// # Safety
    /// `block` and `layout` are exactly those of a successful, not yet freed
    /// `alloc` on this heap.
    pub unsafe fn dealloc(&mut self, block: NonNull<u8>, layout: Layout) {
        // SAFETY: forwarded caller contract.
        unsafe { self.heap.dealloc(block, layout) };
    }

    #[must_use]
    pub fn stats(&self) -> HeapStats {
        HeapStats {
            total: self.heap.stats_total_bytes(),
            allocated: self.heap.stats_alloc_actual(),
            requested: self.heap.stats_alloc_user(),
            chunks: self.chunks,
            refused: self.refused,
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::{ChunkSource, KernelHeap, MIN_CHUNK, ORDERS};
    use core::alloc::Layout;
    use std::{alloc::alloc_zeroed, vec::Vec};

    /// Leaks naturally aligned chunks; `budget` chunks then refuses.
    struct Fake {
        budget: usize,
        asked: Vec<usize>,
    }
    // SAFETY: each chunk is a fresh leaked allocation of a power-of-two length,
    // aligned to it, valid for the life of the test process.
    unsafe impl ChunkSource for Fake {
        fn grow(&mut self, min_bytes: usize) -> Option<(usize, usize)> {
            self.asked.push(min_bytes);
            self.budget = self.budget.checked_sub(1)?;
            let length = min_bytes.next_power_of_two();
            let layout = Layout::from_size_align(length, length).ok()?;
            // SAFETY: non-zero size.
            let pointer = unsafe { alloc_zeroed(layout) };
            (!pointer.is_null()).then_some((pointer as usize, length))
        }
    }
    fn heap(budget: usize) -> KernelHeap<Fake> {
        KernelHeap::new(Fake {
            budget,
            asked: Vec::new(),
        })
    }
    fn layout(size: usize, align: usize) -> Layout {
        Layout::from_size_align(size, align).unwrap()
    }

    #[test]
    fn first_allocation_grows_and_free_restores_accounting() {
        let mut heap = heap(4);
        let block = heap.alloc(layout(100, 8)).expect("grows once");
        let stats = heap.stats();
        assert_eq!((stats.chunks, stats.total), (1, MIN_CHUNK));
        assert_eq!((stats.allocated, stats.requested), (128, 100));
        // SAFETY: the block and layout of the allocation above.
        unsafe { heap.dealloc(block, layout(100, 8)) };
        let stats = heap.stats();
        assert_eq!((stats.allocated, stats.requested), (0, 0));
        // The freed block is reused without growing again.
        assert!(heap.alloc(layout(100, 8)).is_some());
        assert_eq!(heap.stats().chunks, 1);
    }

    #[test]
    fn exhaustion_grows_again_then_reports_none_without_side_effects() {
        let mut heap = heap(2);
        let mut live = Vec::new();
        while let Some(block) = heap.alloc(layout(4096, 4096)) {
            live.push(block);
        }
        // Two 64 KiB chunks of 4 KiB blocks, then the source refused.
        assert_eq!(live.len(), 2 * MIN_CHUNK / 4096);
        let stats = heap.stats();
        assert_eq!((stats.chunks, stats.refused), (2, 1));
        assert_eq!(stats.allocated, 2 * MIN_CHUNK);
        for block in live {
            // SAFETY: allocated above with this layout, freed once.
            unsafe { heap.dealloc(block, layout(4096, 4096)) };
        }
        assert_eq!(heap.stats().allocated, 0);
        assert!(
            heap.alloc(layout(4096, 4096)).is_some(),
            "memory is reusable"
        );
    }

    #[test]
    fn oversized_and_absurd_layouts_fail_without_asking_the_source() {
        let mut heap = heap(8);
        assert!(heap.alloc(layout((1 << (ORDERS - 1)) + 1, 1)).is_none());
        assert!(heap.alloc(layout(isize::MAX as usize - 4096, 8)).is_none());
        assert!(heap.alloc(layout(8, 1 << (ORDERS + 3))).is_none());
        assert_eq!(heap.stats().chunks, 0);
        assert_eq!(heap.source.asked.len(), 0);
        // The largest legal block is still served by one big chunk.
        assert!(heap.alloc(layout(1 << (ORDERS - 1), 8)).is_some());
        assert_eq!(heap.source.asked, [1 << (ORDERS - 1)]);
    }

    #[test]
    fn refusing_source_is_an_allocation_failure_and_recovers() {
        let mut heap = heap(0);
        assert!(heap.alloc(layout(8, 8)).is_none());
        assert_eq!(heap.stats().refused, 1);
        heap.source.budget = 1;
        assert!(heap.alloc(layout(8, 8)).is_some());
    }

    #[test]
    fn alignment_is_honored_and_allocations_never_overlap() {
        let mut heap = heap(64);
        let mut live: Vec<(core::ptr::NonNull<u8>, Layout, u8)> = Vec::new();
        for (index, (size, align)) in [
            (1, 1),
            (24, 8),
            (200, 64),
            (4096, 4096),
            (5000, 16),
            (1, 8192),
        ]
        .into_iter()
        .cycle()
        .take(300)
        .enumerate()
        {
            let wanted = layout(size, align);
            let block = heap.alloc(wanted).expect("fits");
            assert_eq!(block.as_ptr() as usize % align, 0);
            let tag = u8::try_from(index % 251).unwrap();
            // SAFETY: the block is exclusively ours for `size` bytes.
            unsafe { block.as_ptr().write_bytes(tag, size) };
            live.push((block, wanted, tag));
        }
        for (block, wanted, tag) in &live {
            // SAFETY: still live; written above, so initialized.
            let bytes = unsafe { core::slice::from_raw_parts(block.as_ptr(), wanted.size()) };
            assert!(bytes.iter().all(|byte| byte == tag), "overlap");
        }
        for (block, wanted, _) in live {
            // SAFETY: each exactly once with its own layout.
            unsafe { heap.dealloc(block, wanted) };
        }
        assert_eq!(heap.stats().allocated, 0);
    }
}
