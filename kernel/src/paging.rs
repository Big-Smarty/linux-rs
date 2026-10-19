// SPDX-License-Identifier: GPL-2.0-only
//! BSP-owned four-level page tables. All software writes occur before CR3
//! publication; hardware accessed/dirty changes are read only via raw volatile
//! operations afterwards. No mutable Rust reference to a live table is formed.
use crate::{
    boot::{BootError, BootInfo},
    cpu,
    memory::{Allocator, Error as MemoryError, PAGE, PAGE_BYTES, Physical, Virtual},
};
use core::ptr;

const PRESENT: u64 = 1;
const WRITE: u64 = 2;
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
}
impl core::fmt::Debug for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Memory(error) => f.debug_tuple("Memory").field(error).finish(),
            Self::Boot(error) => f.debug_tuple("Boot").field(error).finish(),
            Self::Address => f.write_str("Address"),
            Self::Conflict => f.write_str("Conflict"),
            Self::Overflow => f.write_str("Overflow"),
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
        if physical.0 & (PAGE - 1) != 0 || index >= 512 {
            return Err(Error::Address);
        }
        let address = self
            .direct_map
            .checked_add(physical.0)
            .and_then(|n| n.checked_add(index as u64 * 8))
            .ok_or(Error::Overflow)?;
        Ok(ptr::with_exposed_provenance_mut(
            usize::try_from(address).map_err(|_| Error::Overflow)?,
        ))
    }
    fn read(&self, physical: Physical, index: usize) -> Result<u64, Error> {
        let pointer = self.pointer(physical, index)?;
        // SAFETY: root/child ownership originates from live allocated 4KiB RAM;
        // indices <=511, HHDM mapped, u64 aligned/valid. Volatile observes hardware
        // A/D changes without creating references. No software mutator races.
        Ok(unsafe { ptr::read_volatile(pointer) })
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
                // SAFETY: unpublished tables have one BSP owner; no hardware can
                // walk this root before activate(), no live Rust table references.
                unsafe {
                    self.pointer(table, index)?.write_volatile(entry);
                }
                return Ok(());
            }
            if old & PRESENT == 0 {
                let child = allocator.allocate()?.into_reserved();
                self.pages += 1;
                // SAFETY: same exclusive unpublished tree; child frame was fully
                // zeroed before its owning physical address is published in PTE.
                unsafe {
                    self.pointer(table, index)?
                        .write_volatile(child.0 | PRESENT | WRITE);
                }
                table = child;
            } else {
                if old & HUGE != 0 {
                    return Err(Error::Conflict);
                }
                table = Physical(old & ADDRESS);
            }
        }
        Err(Error::Address)
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
