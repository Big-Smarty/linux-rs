// SPDX-License-Identifier: GPL-2.0-only
//! The one 32-bit MMIO accessor pair for uncached device pages (local APIC,
//! IOAPIC, HPET). Addresses come only from `paging::Tables::map_mmio`.
#![allow(
    clippy::cast_possible_truncation,
    reason = "this kernel only builds for x86_64 where usize is 64 bits"
)]

use core::ptr;

/// # Safety
/// `address` is a 4-byte-aligned virtual address inside a page mapped by
/// `paging::Tables::map_mmio` (present, uncached, supervisor-only) that stays
/// mapped; the device register at that address tolerates a 32-bit read and the
/// caller has excluded concurrent register sequences that depend on it.
pub unsafe fn read32(address: u64) -> u32 {
    // SAFETY: forwarded; volatile because the read has device side effects/ordering
    // and no Rust reference to the register exists. The mapping is UC, so x86
    // keeps this access ordered with the surrounding device accesses.
    unsafe { ptr::read_volatile(ptr::with_exposed_provenance::<u32>(address as usize)) }
}

/// # Safety
/// As [`read32`], and the write is a valid register value for that device.
pub unsafe fn write32(address: u64, value: u32) {
    // SAFETY: forwarded; see `read32`.
    unsafe {
        ptr::write_volatile(
            ptr::with_exposed_provenance_mut::<u32>(address as usize),
            value,
        );
    }
}
