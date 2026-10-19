// SPDX-License-Identifier: GPL-2.0-only AND 0BSD
// Protocol layouts/constants translated from include/limine.h and PROTOCOL.md,
// Limine protocol 3a0526b700e356f0eac1b71a77697b3fd1c707a3.
// Copyright (C) 2022-2026 Mintsuki and contributors.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
//
// Transformation: selected wire definitions expressed in Rust under their 0BSD
// terms. Original validation/ownership code added under GPL-2.0-only. Both notices
// apply to this combined file; no bootloader implementation is incorporated.

use core::{mem, ptr, slice};

const COMMON: [u64; 2] = [0xc7b1_dd30_df4c_8b88, 0x0a82_e883_a194_f07b];

#[repr(C)]
struct Request {
    id: [u64; 4],
    revision: u64,
    response: *const u64,
}

impl Request {
    const fn new(a: u64, b: u64) -> Self {
        Self {
            id: [COMMON[0], COMMON[1], a, b],
            revision: 0,
            response: ptr::null(),
        }
    }
}

#[used]
#[unsafe(link_section = ".limine_requests_start")]
static START: [u64; 4] = [
    0xf6b8_f4b3_9de7_d1ae,
    0xfab9_1a69_40fc_b9cf,
    0x785c_6ed0_15d3_e316,
    0x181e_920a_7852_b9d9,
];
#[used]
#[unsafe(link_section = ".limine_requests")]
static mut BASE: [u64; 3] = [0xf956_2b2d_5c95_a6c8, 0x6a7b_3849_4453_6bdc, 5];

macro_rules! request {
    ($name:ident, $a:expr, $b:expr) => {
        #[used]
        #[unsafe(link_section = ".limine_requests")]
        static mut $name: Request = Request::new($a, $b);
    };
}
request!(MEMORY, 0x67cf_3d9d_378a_806f, 0xe304_acdf_c50c_3c62);
request!(HHDM, 0x48dc_f1cb_8ad2_b852, 0x6398_4e95_9a98_244b);
request!(ADDRESS, 0x71ba_7686_3cc5_5f63, 0xb264_4a48_c516_a487);
request!(RSDP, 0xc5e7_7b6b_397e_7b43, 0x2763_7845_accd_cf3c);
request!(FIRMWARE, 0x8c2f_75d9_0bef_28a8, 0x7045_a468_8eac_00c3);
request!(FRAMEBUFFER, 0x9d58_27dc_d881_dd75, 0xa314_8604_f6fa_b11b);
request!(COMMAND, 0x4b16_1536_e598_651e, 0xb390_ad4a_2f1f_303a);
request!(MODULES, 0x3e7e_2797_02be_32af, 0xca1c_4f3b_d128_0cee);

#[repr(C)]
struct PagingRequest {
    request: Request,
    preferred: u64,
    maximum: u64,
    minimum: u64,
}
#[used]
#[unsafe(link_section = ".limine_requests")]
static mut PAGING: PagingRequest = PagingRequest {
    request: Request {
        id: [
            COMMON[0],
            COMMON[1],
            0x95c1_a0ed_ab09_44cb,
            0xa4e5_cb38_42f7_488a,
        ],
        revision: 1,
        response: ptr::null(),
    },
    preferred: 0,
    maximum: 0,
    minimum: 0,
};

#[used]
#[unsafe(link_section = ".limine_requests_end")]
static END: [u64; 2] = [0xadc0_e053_1bb1_0d03, 0x9572_709f_3176_4c62];

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Region {
    pub base: u64,
    pub length: u64,
    pub kind: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootError {
    Revision,
    Missing,
    Pointer,
    Count,
    Overflow,
    Overlap,
    Alignment,
    Address,
    Firmware,
    CommandLine,
}

pub struct BootInfo {
    regions: &'static [*const Region],
    modules: &'static [*const ModulePrefix],
    pub direct_map: u64,
    pub image_physical: u64,
    pub image_virtual: u64,
    pub rsdp: u64,
    pub test: TestMode,
    command_line: [u8; COMMAND_LINE_SIZE],
    command_line_length: usize,
}

/// Linux x86 `COMMAND_LINE_SIZE` (arch/x86/include/asm/setup.h), NUL included.
/// Linux silently truncates a longer line; a cut word or a cut `--` separator
/// would change its meaning, so this loader boundary rejects it instead.
const COMMAND_LINE_SIZE: usize = 2048;

// Limine File Structure's consumed prefix, under the protocol/0BSD notice
// above. Remaining file/path/UUID fields are not dereferenced.
#[repr(C)]
#[derive(Clone, Copy)]
struct ModulePrefix {
    revision: u64,
    address: u64,
    size: u64,
}

fn covers_physical(
    regions: impl IntoIterator<Item = Result<Region, BootError>>,
    address: u64,
    length: u64,
    kind: u64,
) -> bool {
    let Some(end) = address.checked_add(length) else {
        return false;
    };
    let mut covered = address;
    for region in regions {
        let Ok(region) = region else {
            return false;
        };
        let Some(region_end) = region.base.checked_add(region.length) else {
            return false;
        };
        if region.kind == kind && region.base <= covered && covered <= region_end {
            if end <= region_end {
                return true;
            }
            covered = region_end;
        }
    }
    false
}

/// A retained physical reservation, not a virtual mapping or an executable.
/// Payload bytes remain owned by the boot handoff after inspection. A future
/// owned-rootfs consumer must copy consumed data before the loader mapping ends.
#[derive(Clone, Copy, Debug)]
pub struct ModuleSpan {
    physical: u64,
    length: u64,
    reserved_length: u64,
}

impl ModuleSpan {
    fn from_file(address: u64, length: u64, direct_map: u64) -> Result<Self, BootError> {
        // Limine allocates storage even for a zero-byte file. Its logical length
        // stays zero; retain the exclusive backing page without exposing it as
        // file data (pmm.s2.c ext_mem_alloc_type / uri.c uri_open).
        let reserved_length = length.max(1).checked_add(4095).ok_or(BootError::Overflow)? & !4095;
        if length > isize::MAX as u64
            || usize::try_from(length).is_err()
            || !aligned(address, 4096)
            || !canonical_range(address, reserved_length)
        {
            return Err(BootError::Address);
        }
        let physical = address.checked_sub(direct_map).ok_or(BootError::Address)?;
        Ok(Self {
            physical,
            length,
            reserved_length,
        })
    }

    #[must_use]
    pub const fn physical(self) -> u64 {
        self.physical
    }
    #[must_use]
    pub const fn length(self) -> u64 {
        self.length
    }
    #[must_use]
    pub const fn reserved_length(self) -> u64 {
        self.reserved_length
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TestMode {
    Normal,
    Panic,
    UnexpectedFault,
    UnexpectedPageFault,
    UnexpectedBreakpoint,
    UnexpectedInterrupt,
    UnmaskedTimer,
    IrqRestoreEarly,
    BadMap,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Framebuffer {
    pub address: u64,
    pub width: u64,
    pub height: u64,
    pub pitch: u64,
    pub bpp: u16,
    pub model: u8,
    pub red_size: u8,
    pub red_shift: u8,
    pub green_size: u8,
    pub green_shift: u8,
    pub blue_size: u8,
    pub blue_shift: u8,
    // Protocol's seven unused bytes are tail padding, NOT an initialized u8
    // array. Typed reads never assume a value for unspecified reserved storage.
    // Remaining revisioned fields are not read by this implementation.
}

fn aligned(address: u64, alignment: usize) -> bool {
    address != 0 && address & (alignment as u64 - 1) == 0 && address >= 0xffff_8000_0000_0000
}

/// Copy a NUL-terminated line of at most `COMMAND_LINE_SIZE - 1` bytes.
fn bounded_command_line(
    mut byte: impl FnMut(usize) -> Result<u8, BootError>,
) -> Result<([u8; COMMAND_LINE_SIZE], usize), BootError> {
    let mut line = [0; COMMAND_LINE_SIZE];
    for length in 0..COMMAND_LINE_SIZE {
        match byte(length)? {
            0 => return Ok((line, length)),
            value => line[length] = value,
        }
    }
    Err(BootError::CommandLine)
}

/// Read a response scalar without forming a reference to mutable request memory.
/// # Safety
/// The trusted loader must have completed its writes and supplied a mapped,
/// initialized response of the requested protocol layout. Loader RAM remains
/// reserved; no firmware/AP/device may mutate this allocation after handoff.
unsafe fn response(request: *const Request, words: usize) -> Result<&'static [u64], BootError> {
    // SAFETY: caller supplies a linked request object; loader writes are complete.
    let address = unsafe { ptr::read_volatile(ptr::addr_of!((*request).response)) };
    if !aligned(address as u64, mem::align_of::<u64>()) {
        return Err(BootError::Missing);
    }
    // SAFETY: protocol response allocation and immutable lifetime are the caller's
    // obligations; bounds are the exact required prefix, all u64 patterns valid.
    Ok(unsafe { slice::from_raw_parts(address, words) })
}

impl BootInfo {
    /// Protocol revision plus the memory-map view; entries are NOT yet validated.
    ///
    /// # Safety
    /// Same contract as `take`.
    unsafe fn mapped() -> Result<Self, BootError> {
        // SAFETY: caller establishes completed loader writes to this image.
        if unsafe { ptr::read_volatile(ptr::addr_of!(BASE[2])) } != 0
            || unsafe { ptr::read_volatile(ptr::addr_of!(BASE[1])) } != 5
        {
            return Err(BootError::Revision);
        }
        // SAFETY: same handoff contract, each layout is defined by its request ID.
        let memory = unsafe { response(ptr::addr_of!(MEMORY), 3)? };
        let direct_map = unsafe { response(ptr::addr_of!(HHDM), 2)? }[1];
        if !aligned(direct_map, 4096) {
            return Err(BootError::Address);
        }
        let count = usize::try_from(memory[1]).map_err(|_| BootError::Count)?;
        if count == 0
            || count > isize::MAX as usize / mem::size_of::<*const Region>()
            || !aligned(memory[2], mem::align_of::<*const Region>())
        {
            return Err(BootError::Count);
        }
        // SAFETY: the protocol supplies exactly count pointer entries in its live
        // immutable response allocation; no capacity guess or merged allocation.
        let regions = unsafe { slice::from_raw_parts(memory[2] as *const *const Region, count) };
        Ok(Self {
            regions,
            modules: &[],
            direct_map,
            image_physical: 0,
            image_virtual: 0,
            rsdp: 0,
            test: TestMode::Normal,
            command_line: [0; COMMAND_LINE_SIZE],
            command_line_length: 0,
        })
    }

    /// The loader framebuffer, found before any other fallible step so that every
    /// later failure can reach the screen. A missing or invalid display is
    /// explicit (`None`), never fabricated.
    ///
    /// The extent is checked against the still-unvalidated memory map: a union
    /// of loader-declared kind7 entries is sound for that question whatever the
    /// order, and a malformed map only fails the later `take`.
    ///
    /// # Safety
    /// Same contract as `take`.
    #[must_use]
    pub unsafe fn take_framebuffer() -> Option<Framebuffer> {
        // SAFETY: same contract as this function.
        let info = unsafe { Self::mapped() }.ok()?;
        // SAFETY: same response lifetime, optional response is handled as failure.
        let fb = unsafe { response(ptr::addr_of!(FRAMEBUFFER), 3) }.ok()?;
        if fb[1] == 0 || !info.contains_virtual(fb[2], 8, 5) {
            return None;
        }
        // SAFETY: array first pointer lies inside reserved loader memory.
        let pointer = unsafe { ptr::read(fb[2] as *const *const Framebuffer) };
        if !info.contains_virtual(pointer as u64, mem::size_of::<Framebuffer>() as u64, 5) {
            return None;
        }
        // SAFETY: validated mapped loader storage; all fields integers.
        let display = unsafe { ptr::read_unaligned(pointer) };
        let length = display.pitch.checked_mul(display.height)?;
        info.contains_virtual(display.address, length, 7)
            .then_some(display)
    }

    /// The loader command line without its NUL, at most 2047 bytes.
    #[must_use]
    pub fn command_line(&self) -> &[u8] {
        &self.command_line[..self.command_line_length]
    }

    /// Consume the one bootstrap handoff. No other constructor exists.
    ///
    /// # Errors
    /// Rejects unsupported protocol/firmware, invalid response pointers/counts,
    /// malformed memory ranges, or overflowing/unmapped addresses.
    ///
    /// # Safety
    /// Called once at CPL0 from a conforming, trusted Limine base-5+ loader;
    /// response allocations/mappings remain reserved and immutable indefinitely.
    pub unsafe fn take() -> Result<Self, BootError> {
        // SAFETY: same contract as this function.
        let mut info = unsafe { Self::mapped()? };
        // SAFETY: same handoff contract, each layout is defined by its request ID.
        let address = unsafe { response(ptr::addr_of!(ADDRESS), 3)? };
        let rsdp = unsafe { response(ptr::addr_of!(RSDP), 2)? }[1];
        let firmware = unsafe { response(ptr::addr_of!(FIRMWARE), 2)? }[1];
        if firmware != 2 {
            return Err(BootError::Firmware);
        }
        // UEFI RSDP storage need not be naturally aligned: all ACPI fields are
        // decoded from bytes. Only its mapped canonical address is required.
        if rsdp < info.direct_map {
            return Err(BootError::Address);
        }
        info.image_physical = address[1];
        info.image_virtual = address[2];
        info.rsdp = rsdp;
        let mut previous_end = 0;
        for index in 0..info.regions.len() {
            let region = info.region(index)?;
            previous_end = checked_region(region, previous_end)?;
        }
        if address[2] != 0xffff_ffff_8000_0000 || address[1] & 4095 != 0 {
            return Err(BootError::Address);
        }
        // SAFETY: take's trusted single handoff supplies initialized immutable
        // protocol allocations; no AP/DMA/firmware writer or reclaim exists.
        unsafe {
            info.take_modules()?;
        }
        // SAFETY: optional command response; every byte is checked against kind5.
        if let Ok(command) = unsafe { response(ptr::addr_of!(COMMAND), 2) } {
            let (line, length) = bounded_command_line(|offset| {
                let address = command[1]
                    .checked_add(offset as u64)
                    .ok_or(BootError::Overflow)?;
                if !info.contains_virtual(address, 1, 5) {
                    return Err(BootError::CommandLine);
                }
                // SAFETY: this byte lies inside immutable loader RAM (kind5).
                Ok(unsafe { ptr::read(address as *const u8) })
            })?;
            info.command_line = line;
            info.command_line_length = length;
            // The mutation selectors exist only in the QEMU self-test build: a
            // physical entry's editable command line must not choose them.
            #[cfg(feature = "qemu-self-test")]
            {
                info.test = match info.command_line() {
                    b"test=panic" => TestMode::Panic,
                    b"test=unexpected-fault" => TestMode::UnexpectedFault,
                    b"test=unexpected-page-fault" => TestMode::UnexpectedPageFault,
                    b"test=unexpected-breakpoint" => TestMode::UnexpectedBreakpoint,
                    b"test=unexpected-interrupt" => TestMode::UnexpectedInterrupt,
                    b"test=unmasked-timer" => TestMode::UnmaskedTimer,
                    b"test=irq-restore-early" => TestMode::IrqRestoreEarly,
                    b"test=bad-map" => TestMode::BadMap,
                    _ => TestMode::Normal,
                };
            }
        }
        Ok(info)
    }

    #[must_use]
    pub fn region_count(&self) -> usize {
        self.regions.len()
    }

    /// Consume optional module metadata, retaining only kind5 loader allocations.
    ///
    /// # Safety
    /// Same trusted completed handoff and immutable allocation lifetime as take.
    /// Region coverage is additional validation, not initialization/provenance.
    unsafe fn take_modules(&mut self) -> Result<(), BootError> {
        // SAFETY: linked request exists; the trusted loader has finished writes.
        let pointer = unsafe { ptr::read_volatile(ptr::addr_of!(MODULES.response)) };
        if pointer.is_null() {
            return Ok(());
        }
        if !aligned(pointer as u64, mem::align_of::<u64>())
            || !self.contains_virtual(pointer as u64, 24, 5)
        {
            return Err(BootError::Pointer);
        }
        // SAFETY: the trusted response allocation is initialized, immutable and
        // live; exact prefix alignment/class/extent were checked before reading.
        let response = unsafe { slice::from_raw_parts(pointer, 3) };
        let count = usize::try_from(response[1]).map_err(|_| BootError::Count)?;
        if count == 0 {
            return Ok(());
        }
        let length = count
            .checked_mul(mem::size_of::<*const ModulePrefix>())
            .ok_or(BootError::Overflow)?;
        if length > isize::MAX as usize
            || !aligned(response[2], mem::align_of::<*const ModulePrefix>())
            || !self.contains_virtual(response[2], length as u64, 5)
        {
            return Err(BootError::Count);
        }
        // SAFETY: trusted Limine provides one initialized pointer-array
        // allocation of exactly count entries, immutable and retained in kind5.
        // Region coverage does not merge allocations or imply initialization.
        self.modules = unsafe {
            slice::from_raw_parts(
                ptr::with_exposed_provenance(
                    usize::try_from(response[2]).map_err(|_| BootError::Address)?,
                ),
                count,
            )
        };
        for index in 0..count {
            self.module_span(index)?;
        }
        Ok(())
    }

    #[must_use]
    pub fn module_count(&self) -> usize {
        self.modules.len()
    }

    /// Copy a retained module's physical ownership descriptor, never its bytes.
    ///
    /// # Errors
    /// Rejects invalid indexes, prefixes, alignment, extent or slice size.
    pub fn module_span(&self, index: usize) -> Result<ModuleSpan, BootError> {
        let pointer = *self.modules.get(index).ok_or(BootError::Count)?;
        if !aligned(pointer as u64, mem::align_of::<ModulePrefix>())
            || !self.contains_virtual(pointer as u64, mem::size_of::<ModulePrefix>() as u64, 5)
        {
            return Err(BootError::Pointer);
        }
        // SAFETY: take's trusted immutable file descriptor allocation is kept
        // in kind5, which remains mapped after owned CR3. The complete consumed
        // prefix was checked; all fields permit every u64 bit pattern.
        let file = unsafe { ptr::read(pointer) };
        let span = ModuleSpan::from_file(file.address, file.size, self.direct_map)?;
        if !self.contains_physical(span.physical, span.reserved_length, 6) {
            return Err(BootError::Address);
        }
        Ok(span)
    }

    /// Borrow exactly the initialized file bytes, not page padding.
    ///
    /// # Errors
    /// Rejects overflowing, unmapped, noncanonical or unrepresentable ranges.
    ///
    /// # Safety
    /// For nonempty files the original loader mapping epoch MUST still be
    /// active. The caller guarantees these trusted bytes remain initialized,
    /// immutable and reserved, with no firmware/AP/DMA/software writers.
    /// All returned/derived borrows MUST end before owned CR3 activation,
    /// unmap or reclaim. `&BootInfo` alone does not prove the mapping epoch.
    /// For a zero-length file no storage is borrowed: an empty slice is returned
    /// while its independently tracked backing reservation remains retained.
    pub unsafe fn module_bytes(&self, span: ModuleSpan) -> Result<&[u8], BootError> {
        if span.length == 0 {
            return Ok(&[]);
        }
        let address = self
            .direct_map
            .checked_add(span.physical)
            .ok_or(BootError::Overflow)?;
        let length = usize::try_from(span.length).map_err(|_| BootError::Address)?;
        if length > isize::MAX as usize || !self.contains_virtual(address, span.length, 6) {
            return Err(BootError::Address);
        }
        // SAFETY: caller establishes a single live initialized immutable loader
        // file allocation and the still-active mapping epoch. Exact extent,
        // canonicality, isize bound and kind6 reservation have been checked.
        // No fabricated 'static lifetime escapes this borrow.
        Ok(unsafe {
            slice::from_raw_parts(
                ptr::with_exposed_provenance(
                    usize::try_from(address).map_err(|_| BootError::Address)?,
                ),
                length,
            )
        })
    }

    /// # Errors
    /// Rejects an out-of-bounds index or an invalid loader entry pointer.
    pub fn region(&self, index: usize) -> Result<Region, BootError> {
        let pointer = *self.regions.get(index).ok_or(BootError::Count)?;
        if !aligned(pointer as u64, mem::align_of::<Region>()) {
            return Err(BootError::Pointer);
        }
        // SAFETY: trusted loader's immutable allocation is the take() boundary;
        // each pointer is nonnull/aligned, fields permit every bit pattern.
        Ok(unsafe { ptr::read(pointer) })
    }

    #[must_use]
    pub fn contains_virtual(&self, address: u64, length: u64, kind: u64) -> bool {
        if !canonical_range(address, length) {
            return false;
        }
        address
            .checked_sub(self.direct_map)
            .is_some_and(|physical| self.contains_physical(physical, length, kind))
    }

    #[must_use]
    pub fn contains_physical(&self, address: u64, length: u64, kind: u64) -> bool {
        covers_physical(
            (0..self.region_count()).map(|index| self.region(index)),
            address,
            length,
            kind,
        )
    }

    /// Borrow a previously identified immutable ACPI RSDP/SDT allocation.
    ///
    /// # Errors
    /// Rejects unmapped/wrong-class extents, arithmetic overflow, or an address
    /// or length that cannot be represented by a Rust slice on this target.
    ///
    /// # Safety
    /// The caller must establish that this is live initialized RSDP or SDT
    /// storage (possibly malformed bytes), NOT FACS or arbitrary NVS/runtime
    /// data. The trusted loader/firmware must keep the complete borrowed extent
    /// stable: no firmware, SMM, AP, DMA or software writer for the returned
    /// borrow, and no reclaim/unmapping. A reserved memory class alone proves
    /// neither initialization nor immutability. Bounds/class checks below are
    /// additional checks, not a substitute for these caller obligations.
    pub unsafe fn acpi_table_bytes(
        &self,
        physical: u64,
        length: usize,
    ) -> Result<&[u8], BootError> {
        if ![2, 3, 8]
            .iter()
            .any(|&kind| self.contains_physical(physical, length as u64, kind))
        {
            return Err(BootError::Address);
        }
        let address = self
            .direct_map
            .checked_add(physical)
            .ok_or(BootError::Overflow)?;
        if length > isize::MAX as usize || !canonical_range(address, length as u64) {
            return Err(BootError::Address);
        }
        // SAFETY: caller establishes initialized immutable RSDP/SDT storage and
        // excludes all firmware/AP/DMA/software writers for this borrow. This
        // function checks mapped class, full bounds, overflow and canonicality.
        // Lifetime is bounded by &self, never manufactured as 'static.
        Ok(unsafe {
            slice::from_raw_parts(
                ptr::with_exposed_provenance(
                    usize::try_from(address).map_err(|_| BootError::Address)?,
                ),
                length,
            )
        })
    }
}

/// Validate one production memory-map extent in ascending order.
///
/// # Errors
/// Rejects zero length, wraparound, overlap, or unaligned usable RAM.
pub fn checked_region(region: Region, previous_end: u64) -> Result<u64, BootError> {
    if region.length == 0 {
        return Err(BootError::Count);
    }
    let end = region
        .base
        .checked_add(region.length)
        .ok_or(BootError::Overflow)?;
    if region.base < previous_end {
        return Err(BootError::Overlap);
    }
    if region.kind == 0 && (region.base & 4095 != 0 || region.length & 4095 != 0) {
        return Err(BootError::Alignment);
    }
    Ok(end)
}

#[cfg(any(test, feature = "qemu-self-test"))]
#[must_use]
pub fn regression_checks() -> bool {
    let valid = Region {
        base: 4096,
        length: 8192,
        kind: 0,
    };
    checked_region(valid, 4096) == Ok(12288)
        && checked_region(Region { length: 0, ..valid }, 0) == Err(BootError::Count)
        && checked_region(valid, 8192) == Err(BootError::Overlap)
        && checked_region(
            Region {
                base: 4097,
                ..valid
            },
            0,
        ) == Err(BootError::Alignment)
        && checked_region(
            Region {
                length: 8193,
                ..valid
            },
            0,
        ) == Err(BootError::Alignment)
        && checked_region(
            Region {
                base: u64::MAX - 4095,
                length: 8192,
                kind: 0,
            },
            0,
        ) == Err(BootError::Overflow)
        && checked_region(
            Region {
                base: 17,
                length: 3,
                kind: 1,
            },
            0,
        ) == Ok(20)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn production_range_validator_rejects_malformed_maps() {
        assert!(regression_checks());
    }
    #[test]
    fn adjacent_ranges_and_unknown_reserved_kinds_are_not_truncated() {
        let mut previous = 0;
        for region in [
            Region {
                base: 0,
                length: 4096,
                kind: 1,
            },
            Region {
                base: 4096,
                length: 4096,
                kind: 0,
            },
            Region {
                base: 8192,
                length: 17,
                kind: 255,
            },
        ] {
            previous = checked_region(region, previous).expect("valid adjacent map");
        }
        assert_eq!(previous, 8209);
    }

    #[test]
    fn command_line_is_copied_exactly_or_rejected() {
        let copy = |text: &[u8]| {
            bounded_command_line(|i| text.get(i).copied().ok_or(BootError::CommandLine))
        };
        let (line, length) = copy(b"a b -- c\0junk").unwrap();
        assert_eq!(&line[..length], b"a b -- c");
        let mut longest = [b'x'; COMMAND_LINE_SIZE];
        longest[COMMAND_LINE_SIZE - 1] = 0;
        assert_eq!(copy(&longest).unwrap().1, COMMAND_LINE_SIZE - 1);
        longest[COMMAND_LINE_SIZE - 1] = b'x';
        assert_eq!(copy(&longest), Err(BootError::CommandLine));
        assert_eq!(copy(b"unterminated"), Err(BootError::CommandLine));
    }

    #[test]
    fn zero_byte_module_retains_its_page_without_borrowing_padding() {
        let direct_map = 0xffff_8000_0000_0000;
        let span = ModuleSpan::from_file(direct_map + 0x3000, 0, direct_map).unwrap();
        assert_eq!(span.physical(), 0x3000);
        assert_eq!(span.length(), 0);
        assert_eq!(span.reserved_length(), 4096);
        let info = BootInfo {
            regions: &[],
            modules: &[],
            direct_map,
            image_physical: 0,
            image_virtual: 0,
            rsdp: 0,
            test: TestMode::Normal,
            command_line: [0; COMMAND_LINE_SIZE],
            command_line_length: 0,
        };
        // SAFETY: the explicit empty-file path forms no storage reference and
        // needs no live host mapping. This is not a simulated loader allocation.
        assert_eq!(unsafe { info.module_bytes(span) }.unwrap(), b"");
    }

    #[test]
    fn module_metadata_rejects_bad_addresses_and_sizes() {
        let direct_map = 0xffff_8000_0000_0000;
        for (length, reserved) in [(1, 4096), (4096, 4096), (4097, 8192)] {
            let span = ModuleSpan::from_file(direct_map + 4096, length, direct_map).unwrap();
            assert_eq!(span.reserved_length(), reserved);
            assert_eq!(span.length(), length);
        }
        for (address, length, map) in [
            (0, 1, direct_map),
            (direct_map + 1, 1, direct_map),
            (direct_map + 4096, isize::MAX as u64 + 1, direct_map),
            (u64::MAX - 4095, 4097, direct_map),
            (direct_map, 1, direct_map + 4096),
        ] {
            assert!(ModuleSpan::from_file(address, length, map).is_err());
        }
        assert!(matches!(
            ModuleSpan::from_file(direct_map, u64::MAX, direct_map),
            Err(BootError::Overflow)
        ));
    }

    #[test]
    fn module_extent_coverage_accepts_adjacency_but_not_gaps_or_wrong_kinds() {
        let first = Region {
            base: 4096,
            length: 4096,
            kind: 6,
        };
        let second = Region {
            base: 8192,
            length: 4096,
            kind: 6,
        };
        assert!(covers_physical([Ok(first), Ok(second)], 4096, 8192, 6));
        assert!(!covers_physical(
            [
                Ok(first),
                Ok(Region {
                    base: 12288,
                    ..second
                })
            ],
            4096,
            8192,
            6
        ));
        assert!(!covers_physical(
            [Ok(first), Ok(Region { kind: 5, ..second })],
            4096,
            8192,
            6
        ));
        assert!(!covers_physical(
            [Err(BootError::Pointer), Ok(second)],
            8192,
            4096,
            6
        ));
        assert!(!covers_physical([Ok(first)], u64::MAX, 2, 6));
        assert!(!covers_physical(
            [Ok(Region {
                length: u64::MAX,
                ..first
            })],
            4096,
            1,
            6
        ));
    }
}

#[must_use]
pub fn canonical_range(address: u64, length: u64) -> bool {
    let canonical = |value: u64| value >> 47 == 0 || value >> 47 == 0x1ffff;
    canonical(address)
        && length
            .checked_sub(1)
            .and_then(|last| address.checked_add(last))
            .is_some_and(|last| canonical(last) && (last >> 47) == (address >> 47))
}

#[cfg(test)]
mod address_tests {
    use super::canonical_range;
    #[test]
    fn whole_mapping_must_be_canonical_nonempty_and_nonoverflowing() {
        assert!(canonical_range(0xffff_8000_0000_0000, 4096));
        assert!(canonical_range(0xffff_ffff_ffff_f000, 4096));
        assert!(!canonical_range(0xffff_ffff_ffff_f000, 4097));
        assert!(!canonical_range(0x0000_8000_0000_0000, 1));
        assert!(!canonical_range(0x0000_7fff_ffff_ffff, 2));
        assert!(!canonical_range(0xffff_8000_0000_0000, 0));
    }
}
