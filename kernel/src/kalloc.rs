// SPDX-License-Identifier: GPL-2.0-only
//! The kernel's `#[global_allocator]`: `kernel::heap::KernelHeap` over buddy
//! frames, behind an IRQ-saving mutex.
//!
//! # Fallibility is a compile-time property
//! Target builds compile `alloc` with `--cfg no_global_oom_handling` (the
//! maintained build and the target Clippy command pass it, see
//! `docs/kernel-tooling.md`), the way Rust-for-Linux does. `Box::new`,
//! `Vec::push`, `vec!`, `String::from`, `format!` and every other API that can
//! abort on exhaustion then do not exist; only `try_*`/`push_within_capacity`
//! style calls compile. Exhaustion is `AllocError`/`TryReserveError`, never an
//! abort, and no `alloc_error_handler` is needed.
//!
//! # Contexts and locking
//! Task context only (see `kernel::heap` for the full contract). The heap lock
//! is [`IrqMutex`] and sits between `PROCESS` and `FRAMES` in the lock order
//! (`services`): growth takes `FRAMES` while holding the heap lock, and no
//! path holds `FRAMES` while allocating. Nothing here allocates while holding
//! `FRAMES`, and `FRAMES` never calls the heap. Interrupt handlers and the
//! panic/fault paths MUST NOT allocate (they only `log!`).
//!
//! Latency: growth zero-fills a whole frame block (up to 4 MiB) and `dealloc`
//! scans free lists, both with the heap lock held and interrupts masked, so a
//! large growth delays timer interrupts by that much. Acceptable for the
//! current single task; revisit (smaller chunks, zero-on-demand) before
//! latency-sensitive work or when interrupts start to allocate-adjacent work.
//!
//! shortcut: heap memory comes from order-0..10 frame blocks that are never
//! returned (no chunk reclaim yet); allocations are bounded by the largest
//! free frame block (4 MiB), Linux's `KMALLOC_MAX_SIZE` analogue.

use crate::services::{self, FRAMES, IrqMutex};
use alloc::alloc::{GlobalAlloc, Layout};
use core::{
    cell::UnsafeCell,
    ptr::{self, NonNull},
    sync::atomic::{AtomicBool, Ordering},
};
use kernel::{
    heap::{ChunkSource, KernelHeap},
    memory::{MAX_ORDER, PAGE_BYTES},
};

/// Size of the boot arena: the heap's minimum chunk (`kernel::heap::MIN_CHUNK`).
const ARENA_BYTES: usize = 64 * 1024;

/// Memory for allocations made *before* `services::FRAMES` exists. The boot
/// installs `FRAMES` before the rootfs and the loader's `Mm` are built, so
/// nothing allocates here today; it stays as the fallback for any earlier
/// allocation. Natural alignment of its length, as `ChunkSource` asks.
#[repr(C, align(65536))]
struct BootArena(UnsafeCell<[u8; ARENA_BYTES]>);
// SAFETY: the bytes are reached only through the one `(start, length)` handed
// to the heap by `grow` (guarded by `ARENA_TAKEN`), never as a Rust reference.
unsafe impl Sync for BootArena {}
static BOOT_ARENA: BootArena = BootArena(UnsafeCell::new([0; ARENA_BYTES]));
static ARENA_TAKEN: AtomicBool = AtomicBool::new(false);

/// Chunks are whole buddy frame blocks seen through the direct map; before
/// `FRAMES` is installed the single chunk is the static [`BootArena`].
struct FrameChunks;

// SAFETY: the boot arena is a static, writable, 64 KiB aligned, zero-initialised
// byte array that nothing else references, handed out at most once
// (`ARENA_TAKEN`) and kept by the heap for good. Otherwise `allocate_order`
// yields a zeroed, exclusively owned, naturally aligned run of usable RAM; the
// direct map covers it read-write (checked by `Allocator::new`);
// `into_reserved` ends the token without freeing, so the heap owns the run for
// good and nothing else can allocate or map it. Runs are disjoint because the
// allocator never issues a live frame twice.
unsafe impl ChunkSource for FrameChunks {
    fn grow(&mut self, min_bytes: usize) -> Option<(usize, usize)> {
        if !FRAMES.is_installed() {
            // Boot arena: exactly one chunk, never returned. A request that
            // does not fit, or a second one, fails like exhaustion (callers
            // use fallible APIs). shortcut: 64 KiB until frames exist; the
            // boot sequence allocates nothing before `FRAMES` is installed.
            if min_bytes > ARENA_BYTES || ARENA_TAKEN.swap(true, Ordering::AcqRel) {
                return None;
            }
            return Some((BOOT_ARENA.0.get() as usize, ARENA_BYTES));
        }
        let pages = min_bytes.div_ceil(PAGE_BYTES).checked_next_power_of_two()?;
        let order = pages.ilog2();
        if order > MAX_ORDER {
            return None;
        }
        // Lock order: heap (held by the caller) -> FRAMES. One CPU, IF masked
        // in every critical section: a held FRAMES is held by our own caller
        // (a heap allocation made while holding a FRAMES guard), which would
        // otherwise spin forever. Fail loudly instead (`services` rule).
        let Some(mut frames) = FRAMES.try_lock() else {
            panic!(
                "heap growth needs FRAMES, which the allocating caller holds: lock-order violation"
            );
        };
        let frame = frames.allocate_order(order).ok()?;
        let start = services::boot()
            .direct_map
            .checked_add(frame.physical().0)
            .and_then(|address| usize::try_from(address).ok());
        let length = frame.byte_count();
        if let Some(start) = start {
            let _owned_by_the_heap = frame.into_reserved();
            return Some((start, length));
        }
        // Unreachable (`Allocator::new` proved every address fits); give the
        // run back instead of leaking it.
        frames.release(frame).ok()?;
        None
    }
}

struct KernelAlloc(IrqMutex<KernelHeap<FrameChunks>>);

// SAFETY: `KernelHeap` returns blocks that are valid, suitably aligned,
// exclusive and at least `layout.size()` bytes until deallocated, and `None`
// (mapped to null) on failure, all under one lock so concurrent callers are
// serialized. `dealloc` receives only pointers from `alloc` with their layout
// (the `GlobalAlloc` contract). `alloc_zeroed`/`realloc` use the provided
// defaults built from these two.
unsafe impl GlobalAlloc for KernelAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.0
            .lock()
            .alloc(layout)
            .map_or(ptr::null_mut(), NonNull::as_ptr)
    }

    unsafe fn dealloc(&self, block: *mut u8, layout: Layout) {
        if let Some(block) = NonNull::new(block) {
            // SAFETY: `GlobalAlloc::dealloc`'s contract is `KernelHeap::dealloc`'s.
            unsafe { self.0.lock().dealloc(block, layout) };
        }
    }
}

#[global_allocator]
static HEAP: KernelAlloc = KernelAlloc(IrqMutex::new(KernelHeap::new(FrameChunks)));

/// Whether the heap lock is free right now (see `Service::is_free`).
#[cfg(feature = "baremetal-suite")]
pub fn lock_free() -> bool {
    HEAP.0.try_lock().is_some()
}

#[cfg(any(feature = "boot-proofs", feature = "qemu-self-test"))]
fn stats() -> kernel::heap::HeapStats {
    HEAP.0.lock().stats()
}

/// Bytes the callers of the heap currently hold (`HeapStats::requested`): the
/// self-test builds compare it before and after a workload to find a leak of
/// kernel objects that the frame count would hide.
#[cfg(feature = "qemu-self-test")]
pub fn requested_bytes() -> usize {
    stats().requested
}

/// Executed heap proof on the real allocator: fallible Vec/Box, alignment,
/// growth from buddy frames, injected frame exhaustion (clean failure, no
/// state change, recovery), the size cap and exact accounting.
#[cfg(feature = "boot-proofs")]
pub fn self_test() -> Result<(), &'static str> {
    use alloc::{alloc::alloc, alloc::dealloc, boxed::Box, vec::Vec};
    const BIG: usize = 4 << 20;
    let frames = || FRAMES.lock().allocated();
    let (base, base_frames) = (stats(), frames());
    {
        let mut numbers: Vec<u32> = Vec::new();
        numbers.try_reserve_exact(1000).map_err(|_| "vec-reserve")?;
        for n in 0..1000 {
            numbers.push_within_capacity(n).map_err(|_| "vec-push")?;
        }
        if !(0..1000).zip(&numbers).all(|(n, &m)| n == m) {
            return Err("vec-contents");
        }
        let page = Box::try_new([0xa5u8; PAGE_BYTES]).map_err(|_| "box")?;
        if page.iter().any(|&byte| byte != 0xa5) {
            return Err("box-contents");
        }
        let layout = Layout::from_size_align(PAGE_BYTES, PAGE_BYTES).map_err(|_| "layout")?;
        // SAFETY: non-zero size; freed with the same layout below.
        let aligned = unsafe { alloc(layout) };
        if aligned.is_null() || !(aligned as usize).is_multiple_of(PAGE_BYTES) {
            return Err("align");
        }
        // SAFETY: the block just allocated with `layout`.
        unsafe { dealloc(aligned, layout) };
    }
    if stats().requested != base.requested || stats().allocated != base.allocated {
        return Err("accounting-small");
    }
    // Growth: more than the heap can have free forces buddy-frame chunks.
    let grown = stats();
    let mut buffers: [Vec<u8>; 8] = core::array::from_fn(|_| Vec::new());
    for buffer in &mut buffers {
        buffer.try_reserve_exact(128 << 10).map_err(|_| "grow")?;
        buffer.push_within_capacity(1).map_err(|_| "grow-push")?;
    }
    let after = stats();
    if after.chunks <= grown.chunks
        || after.total <= grown.total
        || frames() != base_frames + (after.total - base.total) / PAGE_BYTES
    {
        return Err("growth");
    }
    drop(buffers);
    // Injected exhaustion: no frame can be had, the request is bigger than any
    // free heap block, so it must fail and leave heap and frames untouched.
    let before = (stats(), frames());
    FRAMES.lock().set_allocation_budget(Some(0));
    let mut huge: Vec<u8> = Vec::new();
    let refused = huge.try_reserve_exact(BIG).is_err();
    FRAMES.lock().set_allocation_budget(None);
    let now = stats();
    if !refused
        || now.total != before.0.total
        || now.chunks != before.0.chunks
        || now.refused != before.0.refused + 1
        || frames() != before.1
    {
        return Err("oom-injection");
    }
    // Recovery: the same request now succeeds, and a request above the
    // largest block is rejected without touching the frame allocator.
    huge.try_reserve_exact(BIG).map_err(|_| "oom-recovery")?;
    drop(huge);
    let mut over: Vec<u8> = Vec::new();
    let tried = stats().refused;
    // 8 MiB and 16 MiB exceed the 4 MiB cap: rejected before the source.
    if over.try_reserve_exact(8 << 20).is_ok()
        || over.try_reserve_exact(16 << 20).is_ok()
        || stats().refused != tried
    {
        return Err("over-cap");
    }
    let end = stats();
    if end.requested != base.requested || end.allocated != base.allocated {
        return Err("accounting-final");
    }
    Ok(())
}
