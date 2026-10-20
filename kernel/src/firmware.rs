// SPDX-License-Identifier: GPL-2.0-only
//! Allocation-free ACPI root-table validation and static-table decoding (MADT,
//! HPET, FADT timer fields), not AML or ACPI completion.
//!
//! Provenance: MADT/HPET/FADT layouts follow the ACPI 6.5 specification as
//! consumed by Linux 6.18.57 arch/x86/kernel/acpi/boot.c (GPL-2.0-only):
//! `acpi_parse_madt` (l.148 PCAT_COMPAT), `acpi_parse_lapic_addr_ovr`,
//! `acpi_parse_ioapic`, `acpi_parse_int_src_ovr`, `acpi_parse_nmi_src`,
//! `acpi_parse_lapic_nmi`, `acpi_parse_fadt` (l.1034) and drivers/acpi/tables.c
//! (`acpi_parse_entries_array`: an entry shorter than its structure is an
//! error). ISA IRQ routing mirrors `mp_config_acpi_legacy_irqs` (boot.c) and
//! the polarity/trigger defaults mirror `irq_active_low`/`irq_is_level`
//! (arch/x86/kernel/apic/io_apic.c:672, 738). The code is a Rust re-expression
//! over fixed-capacity arrays, not a line port.
use crate::boot::{BootError, BootInfo};
use crate::image::bytes::Endian;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Map(BootError),
    Signature,
    Checksum,
    Length,
    Revision,
    /// A decoded field has an invalid value (e.g. a zero HPET base).
    Value,
}
impl From<BootError> for Error {
    fn from(value: BootError) -> Self {
        Self::Map(value)
    }
}

pub struct Acpi {
    pub tables: usize,
    pub legacy_pic: bool,
    /// First MADT ("APIC") found in the XSDT, fully decoded.
    pub madt: Option<Madt>,
    /// First HPET description table.
    pub hpet: Option<Hpet>,
    /// Timer-relevant FADT fields.
    pub fadt: Option<Fadt>,
}
fn checksum(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |sum, &b| sum.wrapping_add(b)) == 0
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    Endian::Little
        .u32(bytes, offset as u64)
        .map_err(|_| Error::Length)
}
fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, Error> {
    Endian::Little
        .u64(bytes, offset as u64)
        .map_err(|_| Error::Length)
}

fn rsdp_length(bytes: &[u8]) -> Result<usize, Error> {
    if bytes.len() < 20 {
        return Err(Error::Length);
    }
    if &bytes[..8] != b"RSD PTR " {
        return Err(Error::Signature);
    }
    if !checksum(&bytes[..20]) {
        return Err(Error::Checksum);
    }
    if bytes[15] < 2 {
        return Err(Error::Revision);
    }
    let length = u32_at(bytes, 20)? as usize;
    if length < 36 {
        return Err(Error::Length);
    }
    Ok(length)
}

/// Parse a revision-2+ RSDP and return its XSDT physical address.
///
/// # Errors
/// Rejects invalid length, signature, revision, or either RSDP checksum.
pub fn parse_rsdp(bytes: &[u8]) -> Result<u64, Error> {
    let length = rsdp_length(bytes)?;
    if !checksum(bytes.get(..length).ok_or(Error::Length)?) {
        return Err(Error::Checksum);
    }
    u64_at(bytes, 24)
}

fn sdt_length(bytes: &[u8]) -> Result<usize, Error> {
    if bytes.len() < 36 {
        return Err(Error::Length);
    }
    let length = u32_at(bytes, 4)? as usize;
    if length < 36 {
        return Err(Error::Length);
    }
    Ok(length)
}

/// Return the initialized extent described by one checked SDT header.
///
/// # Errors
/// Rejects truncated/invalid lengths or a nonzero table checksum.
pub fn parse_sdt(bytes: &[u8]) -> Result<&[u8], Error> {
    let length = sdt_length(bytes)?;
    let table = bytes.get(..length).ok_or(Error::Length)?;
    if !checksum(table) {
        return Err(Error::Checksum);
    }
    Ok(table)
}

/// IOAPIC capacity. Linux's `MAX_IO_APICS` is 128; entries beyond this table
/// are counted in [`Madt::dropped`] and unused.
// shortcut: 32 IOAPICs and 32 overrides cover every consumer and two-socket
// server platform; raise when a larger machine's MADT is seen to drop entries.
pub const MAX_IOAPICS: usize = 32;
pub const MAX_OVERRIDES: usize = 32;
pub const MAX_NMI_SOURCES: usize = 16;
pub const MAX_LAPIC_NMIS: usize = 16;
/// First vector-less "ISA" IRQ count (`nr_legacy_irqs()` with an 8259 pair).
pub const ISA_IRQS: u8 = 16;

/// MADT type 1: I/O APIC.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ioapic {
    pub id: u8,
    pub address: u32,
    pub gsi_base: u32,
}
/// MADT type 2: interrupt source override (bus is always 0 = ISA).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IntSourceOverride {
    pub source: u8,
    pub gsi: u32,
    /// MPS INTI flags: polarity bits 0-1, trigger bits 2-3.
    pub flags: u16,
}
/// MADT type 3: NMI source.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NmiSource {
    pub flags: u16,
    pub gsi: u32,
}
/// MADT type 4/10: local APIC NMI. `uid` 0xffff_ffff targets every processor.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LapicNmi {
    pub uid: u32,
    pub flags: u16,
    pub lint: u8,
}

/// Decoded MADT. Only fields the early interrupt/time code consumes are kept;
/// every processor entry is validated and counted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Madt {
    /// Physical local APIC address after the (last non-zero) type 5 override.
    pub lapic_address: u64,
    /// MADT flag bit 0: dual 8259 present (`ACPI_MADT_PCAT_COMPAT`).
    pub pcat_compat: bool,
    /// Type 0 entries with Enabled or Online-Capable set / total type 0 / total type 9.
    pub cpus_usable: u32,
    pub lapic_entries: u32,
    pub x2apic_entries: u32,
    /// Largest APIC ID in any processor entry (x2APIC ids are 32-bit).
    pub max_apic_id: u32,
    ioapics: [Ioapic; MAX_IOAPICS],
    ioapic_count: usize,
    overrides: [IntSourceOverride; MAX_OVERRIDES],
    override_count: usize,
    nmi_sources: [NmiSource; MAX_NMI_SOURCES],
    nmi_source_count: usize,
    lapic_nmis: [LapicNmi; MAX_LAPIC_NMIS],
    lapic_nmi_count: usize,
    /// Semantically bogus entries Linux also skips (zero/duplicate IOAPIC
    /// address) plus well-formed entries that did not fit the fixed tables.
    pub dropped: u32,
}

/// Trigger and polarity of one interrupt line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trigger {
    Edge,
    Level,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Polarity {
    ActiveHigh,
    ActiveLow,
}
/// Where one ISA IRQ lands: a global system interrupt plus its signalling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IsaRoute {
    pub gsi: u32,
    pub trigger: Trigger,
    pub polarity: Polarity,
}

impl Madt {
    #[must_use]
    pub fn ioapics(&self) -> &[Ioapic] {
        &self.ioapics[..self.ioapic_count]
    }
    #[must_use]
    pub fn overrides(&self) -> &[IntSourceOverride] {
        &self.overrides[..self.override_count]
    }
    #[must_use]
    pub fn nmi_sources(&self) -> &[NmiSource] {
        &self.nmi_sources[..self.nmi_source_count]
    }
    #[must_use]
    pub fn lapic_nmis(&self) -> &[LapicNmi] {
        &self.lapic_nmis[..self.lapic_nmi_count]
    }

    /// The route of ISA `irq` (0..16): the first matching override, else the
    /// identity mapping, edge-triggered and active high (the ISA "conforming"
    /// defaults of `irq_active_low`/`irq_is_level`). An identity GSI that an
    /// override has already claimed for another source is not routed
    /// (`mp_config_acpi_legacy_irqs` "already used" test).
    #[must_use]
    pub fn isa_route(&self, irq: u8) -> Option<IsaRoute> {
        if irq >= ISA_IRQS {
            return None;
        }
        let route = |gsi: u32, flags: u16| IsaRoute {
            gsi,
            // Reserved encodings (2) are Linux's "Broken BIOS": level / low.
            trigger: match (flags >> 2) & 3 {
                0 | 1 => Trigger::Edge,
                _ => Trigger::Level,
            },
            polarity: match flags & 3 {
                0 | 1 => Polarity::ActiveHigh,
                _ => Polarity::ActiveLow,
            },
        };
        if let Some(o) = self.overrides().iter().find(|o| o.source == irq) {
            return Some(route(o.gsi, o.flags));
        }
        let gsi = u32::from(irq);
        if self.overrides().iter().any(|o| o.gsi == gsi) {
            return None;
        }
        Some(route(gsi, 0))
    }

    /// Index of the IOAPIC whose pins `[gsi_base, gsi_base + pins)` contain `gsi`
    /// given each IOAPIC's pin count (read from hardware by the caller).
    #[must_use]
    pub fn ioapic_for_gsi(&self, gsi: u32, pins: impl Fn(&Ioapic) -> u32) -> Option<usize> {
        self.ioapics().iter().position(|io| {
            gsi >= io.gsi_base && u64::from(gsi) < u64::from(io.gsi_base) + u64::from(pins(io))
        })
    }

    fn push<T: Copy>(slot: &mut [T], count: &mut usize, dropped: &mut u32, value: T) {
        if let Some(entry) = slot.get_mut(*count) {
            *entry = value;
            *count += 1;
        } else {
            *dropped += 1;
        }
    }
}

/// Decode and validate every MADT record.
///
/// Structural violations (a known entry shorter than its structure, a record
/// that overruns the table or has length < 2) are errors, as in Linux's
/// `acpi_parse_entries_array`. Entries Linux skips with a warning (zero or
/// duplicate IOAPIC address) or that exceed the fixed tables only increment
/// [`Madt::dropped`]. Unknown types are skipped by their declared length.
///
/// # Errors
/// Rejects invalid SDT contents, a non-MADT signature, or malformed records.
pub fn parse_madt(bytes: &[u8]) -> Result<Madt, Error> {
    let table = parse_sdt(bytes)?;
    if &table[..4] != b"APIC" {
        return Err(Error::Signature);
    }
    if table.len() < 44 {
        return Err(Error::Length);
    }
    let mut madt = Madt {
        lapic_address: u64::from(u32_at(table, 36)?),
        pcat_compat: u32_at(table, 40)? & 1 != 0,
        cpus_usable: 0,
        lapic_entries: 0,
        x2apic_entries: 0,
        max_apic_id: 0,
        ioapics: [Ioapic::default(); MAX_IOAPICS],
        ioapic_count: 0,
        overrides: [IntSourceOverride::default(); MAX_OVERRIDES],
        override_count: 0,
        nmi_sources: [NmiSource::default(); MAX_NMI_SOURCES],
        nmi_source_count: 0,
        lapic_nmis: [LapicNmi::default(); MAX_LAPIC_NMIS],
        lapic_nmi_count: 0,
        dropped: 0,
    };
    let mut cursor = 44;
    while cursor < table.len() {
        if table.len() - cursor < 2 {
            return Err(Error::Length);
        }
        let kind = table[cursor];
        let length = table[cursor + 1] as usize;
        if length < 2 || length > table.len() - cursor {
            return Err(Error::Length);
        }
        let entry = &table[cursor..cursor + length];
        let minimum = match kind {
            0 => 8,
            1 | 5 | 10 => 12,
            2 => 10,
            3 => 8,
            4 => 6,
            9 => 16,
            _ => 2,
        };
        if length < minimum {
            return Err(Error::Length);
        }
        match kind {
            0 => {
                madt.lapic_entries += 1;
                // Enabled (bit 0) or Online Capable (bit 1): Linux `acpi_parse_lapic`.
                if u32_at(entry, 4)? & 3 != 0 {
                    madt.cpus_usable += 1;
                }
                madt.max_apic_id = madt.max_apic_id.max(u32::from(entry[3]));
            }
            9 => {
                madt.x2apic_entries += 1;
                if u32_at(entry, 8)? & 3 != 0 {
                    madt.cpus_usable += 1;
                }
                madt.max_apic_id = madt.max_apic_id.max(u32_at(entry, 4)?);
            }
            1 => {
                let io = Ioapic {
                    id: entry[2],
                    address: u32_at(entry, 4)?,
                    gsi_base: u32_at(entry, 8)?,
                };
                // "Bogus (zero) I/O APIC address ... skipping" / already registered.
                if io.address == 0 || madt.ioapics().iter().any(|o| o.address == io.address) {
                    madt.dropped += 1;
                } else {
                    Madt::push(
                        &mut madt.ioapics,
                        &mut madt.ioapic_count,
                        &mut madt.dropped,
                        io,
                    );
                }
            }
            2 => {
                let o = IntSourceOverride {
                    source: entry[3],
                    gsi: u32_at(entry, 4)?,
                    flags: u16::from_le_bytes([entry[8], entry[9]]),
                };
                Madt::push(
                    &mut madt.overrides,
                    &mut madt.override_count,
                    &mut madt.dropped,
                    o,
                );
            }
            3 => {
                let n = NmiSource {
                    flags: u16::from_le_bytes([entry[2], entry[3]]),
                    gsi: u32_at(entry, 4)?,
                };
                Madt::push(
                    &mut madt.nmi_sources,
                    &mut madt.nmi_source_count,
                    &mut madt.dropped,
                    n,
                );
            }
            4 => {
                // uid 0xff = all processors (ACPI 6.5 table 5.46).
                let uid = if entry[2] == 0xff {
                    u32::MAX
                } else {
                    u32::from(entry[2])
                };
                let n = LapicNmi {
                    uid,
                    flags: u16::from_le_bytes([entry[3], entry[4]]),
                    lint: entry[5],
                };
                Madt::push(
                    &mut madt.lapic_nmis,
                    &mut madt.lapic_nmi_count,
                    &mut madt.dropped,
                    n,
                );
            }
            10 => {
                let n = LapicNmi {
                    uid: u32_at(entry, 4)?,
                    flags: u16::from_le_bytes([entry[2], entry[3]]),
                    lint: entry[8],
                };
                Madt::push(
                    &mut madt.lapic_nmis,
                    &mut madt.lapic_nmi_count,
                    &mut madt.dropped,
                    n,
                );
            }
            5 => {
                // Last non-zero override wins (`acpi_parse_lapic_addr_ovr`).
                let address = u64_at(entry, 4)?;
                if address != 0 {
                    madt.lapic_address = address;
                }
            }
            _ => {}
        }
        cursor += length;
    }
    Ok(madt)
}

/// HPET description table (ACPI "HPET"): the system-memory base only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hpet {
    pub address: u64,
    pub number: u8,
    pub min_tick: u16,
}

/// Decode an HPET table: GAS must be system memory, the base non-zero and
/// 1 KiB aligned (the register block is 1 KiB).
///
/// # Errors
/// Rejects invalid SDT contents, signature, short table, or a bad address.
pub fn parse_hpet(bytes: &[u8]) -> Result<Hpet, Error> {
    let table = parse_sdt(bytes)?;
    if &table[..4] != b"HPET" {
        return Err(Error::Signature);
    }
    if table.len() < 56 {
        return Err(Error::Length);
    }
    let address = u64_at(table, 44)?;
    if table[40] != 0 || address == 0 || address & 0x3ff != 0 {
        return Err(Error::Value);
    }
    Ok(Hpet {
        address,
        number: table[52],
        min_tick: u16::from_le_bytes([table[53], table[54]]),
    })
}

/// FADT fields consumed by time and interrupt setup.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fadt {
    pub revision: u8,
    /// ACPI PM timer I/O port (0 = none), `X_PM_TMR_BLK` preferred over `PM_TMR_BLK`.
    pub pm_timer_port: u16,
    /// FADT flag `TMR_VAL_EXT`: the PM timer is 32 bits wide, else 24.
    pub pm_timer_32bit: bool,
    /// RTC century register index in CMOS (0 = none; FADT revision >= 3).
    pub century: u8,
    /// IA-PC boot flag bit 5 (`ACPI_FADT_NO_CMOS_RTC`).
    pub no_cmos_rtc: bool,
    /// FADT flag bit 20 (`HW_REDUCED_ACPI`): no legacy PIC/PIT/RTC to assume.
    pub hardware_reduced: bool,
}

/// Decode the FADT ("FACP") timer-related fields as `acpi_parse_fadt` and
/// `drivers/clocksource/acpi_pm.c` consume them. A PM timer is accepted only
/// in I/O space with a 4-byte block.
///
/// # Errors
/// Rejects invalid SDT contents, signature or a table too short for the
/// fields of its own revision.
pub fn parse_fadt(bytes: &[u8]) -> Result<Fadt, Error> {
    let table = parse_sdt(bytes)?;
    if &table[..4] != b"FACP" {
        return Err(Error::Signature);
    }
    // Rev 1 FADT is 116 bytes; the fields below end at offset 116 (flags @112).
    if table.len() < 116 {
        return Err(Error::Length);
    }
    let revision = table[8];
    let flags = u32_at(table, 112)?;
    // acpi_parse_fadt (boot.c:1000-1015): revision >= FADT2_REVISION_ID (3) prefers
    // the extended block when it is I/O space, else falls back to PM_TMR_BLK.
    let legacy = u32_at(table, 76)?;
    let mut port = if legacy <= 0xffff { legacy } else { 0 };
    if revision >= 3 && table.len() >= 220 && table[208] == 1 {
        let x = u64_at(table, 212)?;
        if x != 0 && x <= 0xffff {
            port = x as u32;
        }
    }
    let ok = table[91] == 4 && port != 0;
    let boot_flags = u16::from_le_bytes([table[109], table[110]]);
    Ok(Fadt {
        revision,
        pm_timer_port: if ok { port as u16 } else { 0 },
        pm_timer_32bit: flags & (1 << 8) != 0,
        century: if revision >= 3 { table[108] } else { 0 },
        no_cmos_rtc: boot_flags & (1 << 5) != 0,
        hardware_reduced: flags & (1 << 20) != 0,
    })
}

/// # Safety
/// `physical` names a stable initialized SDT allocation reached through the
/// trusted firmware's immutable ACPI root. No firmware/AP/DMA/software writer
/// may change its header or declared body while borrowed; FACS is not an SDT.
unsafe fn table(boot: &BootInfo, physical: u64) -> Result<&[u8], Error> {
    // SAFETY: caller supplies immutable SDT storage; mapping/range checks remain
    // in the narrow accessor and untrusted lengths remain fallible below.
    let header = unsafe { boot.acpi_table_bytes(physical, 36)? };
    let length = sdt_length(header)?;
    // SAFETY: same live stable SDT allocation; no writer can race the header's
    // length versus the full-body borrow. Extent is checked by the accessor.
    parse_sdt(unsafe { boot.acpi_table_bytes(physical, length)? })
}

/// Check the immutable firmware SDT tree and summarize the bootstrap facts.
///
/// # Errors
/// Rejects unmapped addresses, malformed root/child tables, bad checksums,
/// or an unsupported root structure.
///
/// # Safety
/// Trusted firmware must provide initialized, stable RSDP/XSDT and referenced
/// SDT allocations for this call, with no firmware/SMM/AP/DMA/software writers.
/// Malformed contents are checked, but mutable FACS/arbitrary NVS or runtime
/// storage is not accepted as an immutable table. No borrowed bytes escape.
pub unsafe fn discover(boot: &BootInfo) -> Result<Acpi, Error> {
    let physical = boot
        .rsdp
        .checked_sub(boot.direct_map)
        .ok_or(Error::Length)?;
    // SAFETY: caller establishes trusted immutable RSDP allocation after loader
    // handoff, with no firmware/AP/DMA/software mutation during this call.
    let header = unsafe { boot.acpi_table_bytes(physical, 36)? };
    let length = rsdp_length(header)?;
    // SAFETY: same stable allocation; accessor bounds-checks the declared body.
    let root_physical = parse_rsdp(unsafe { boot.acpi_table_bytes(physical, length)? })?;
    // SAFETY: caller's trusted immutable ACPI tree contract covers this XSDT.
    let root = unsafe { table(boot, root_physical)? };
    if &root[..4] != b"XSDT" {
        return Err(Error::Signature);
    }
    if (root.len() - 36) % 8 != 0 {
        return Err(Error::Length);
    }
    let mut acpi = Acpi {
        tables: 0,
        legacy_pic: false,
        madt: None,
        hpet: None,
        fadt: None,
    };
    for pointer in root[36..].as_chunks::<8>().0 {
        // SAFETY: this initialized XSDT pointer belongs to the trusted immutable
        // SDT tree under discover's explicit firmware/no-writer contract. The
        // pointed-to table's mapped bounds/header/checksum are still validated.
        let bytes = unsafe { table(boot, u64::from_le_bytes(*pointer))? };
        acpi.tables += 1;
        // The first table of each kind wins, as in Linux's table lookup. A malformed
        // MADT fails discovery; a bad HPET/FADT merely leaves that timer absent
        // (Linux ignores an unusable HPET and falls back to other clocks).
        match &bytes[..4] {
            b"APIC" if acpi.madt.is_none() => {
                let madt = parse_madt(bytes)?;
                acpi.legacy_pic = madt.pcat_compat;
                acpi.madt = Some(madt);
            }
            b"HPET" if acpi.hpet.is_none() => acpi.hpet = parse_hpet(bytes).ok(),
            b"FACP" if acpi.fadt.is_none() => acpi.fadt = parse_fadt(bytes).ok(),
            _ => {}
        }
    }
    Ok(acpi)
}

#[cfg(any(test, feature = "qemu-self-test"))]
fn repair_checksum(bytes: &mut [u8], offset: usize) {
    bytes[offset] = 0;
    bytes[offset] = 0u8.wrapping_sub(bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b)));
}

#[cfg(any(test, feature = "qemu-self-test"))]
#[must_use]
pub fn regression_checks() -> bool {
    let mut rsdp = [0u8; 36];
    rsdp[..8].copy_from_slice(b"RSD PTR ");
    rsdp[15] = 2;
    rsdp[20..24].copy_from_slice(&36u32.to_le_bytes());
    rsdp[24..32].copy_from_slice(&0x1234_5000u64.to_le_bytes());
    repair_checksum(&mut rsdp[..20], 8);
    repair_checksum(&mut rsdp, 32);
    if parse_rsdp(&rsdp) != Ok(0x1234_5000) {
        return false;
    }
    for length in 0..36 {
        if parse_rsdp(&rsdp[..length]).is_ok() {
            return false;
        }
    }
    let mut corrupt = rsdp;
    corrupt[24] ^= 1;
    if parse_rsdp(&corrupt) != Err(Error::Checksum) {
        return false;
    }
    let mut madt = [0u8; 48];
    madt[..4].copy_from_slice(b"APIC");
    madt[4..8].copy_from_slice(&48u32.to_le_bytes());
    madt[40] = 1;
    madt[44] = 127; // Unknown MADT entry is retained/skipped by its real length.
    madt[45] = 4;
    repair_checksum(&mut madt, 9);
    if parse_madt(&madt).map(|m| m.pcat_compat) != Ok(true) {
        return false;
    }
    madt[45] = 0;
    repair_checksum(&mut madt, 9);
    if parse_madt(&madt) != Err(Error::Length) {
        return false;
    }
    madt[45] = 5;
    repair_checksum(&mut madt, 9);
    if parse_madt(&madt) != Err(Error::Length) {
        return false;
    }
    madt[45] = 4;
    madt[4..8].copy_from_slice(&49u32.to_le_bytes());
    parse_sdt(&madt) == Err(Error::Length)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::{vec, vec::Vec};
    #[test]
    fn rsdp_sdt_madt_valid_and_malformed_corpus() {
        assert!(regression_checks());
    }
    #[test]
    fn no_table_field_is_read_before_its_bound() {
        for length in 0..36 {
            let bytes = [0u8; 36];
            assert_eq!(parse_sdt(&bytes[..length]), Err(Error::Length));
        }
    }

    /// Build an SDT: 36-byte header, 8 table-specific bytes (MADT address+flags), entries.
    fn sdt(signature: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut table = vec![0u8; 36];
        table[..4].copy_from_slice(signature);
        table.extend_from_slice(body);
        let length = table.len() as u32;
        table[4..8].copy_from_slice(&length.to_le_bytes());
        table[8] = 1;
        repair_checksum(&mut table, 9);
        table
    }
    fn madt_with(flags: u32, entries: &[&[u8]]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0xfee0_0000u32.to_le_bytes());
        body.extend_from_slice(&flags.to_le_bytes());
        for entry in entries {
            body.extend_from_slice(entry);
        }
        sdt(b"APIC", &body)
    }
    fn lapic(id: u8, flags: u32) -> Vec<u8> {
        let mut e = vec![0, 8, 0, id];
        e.extend_from_slice(&flags.to_le_bytes());
        e
    }
    fn x2apic(id: u32, flags: u32) -> Vec<u8> {
        let mut e = vec![9, 16, 0, 0];
        e.extend_from_slice(&id.to_le_bytes());
        e.extend_from_slice(&flags.to_le_bytes());
        e.extend_from_slice(&0u32.to_le_bytes());
        e
    }
    fn ioapic(id: u8, address: u32, base: u32) -> Vec<u8> {
        let mut e = vec![1, 12, id, 0];
        e.extend_from_slice(&address.to_le_bytes());
        e.extend_from_slice(&base.to_le_bytes());
        e
    }
    fn iso(source: u8, gsi: u32, flags: u16) -> Vec<u8> {
        let mut e = vec![2, 10, 0, source];
        e.extend_from_slice(&gsi.to_le_bytes());
        e.extend_from_slice(&flags.to_le_bytes());
        e
    }

    #[test]
    fn madt_qemu_q35_shape_is_decoded() {
        let table = madt_with(
            1,
            &[
                &lapic(0, 1),
                &ioapic(0, 0xfec0_0000, 0),
                &iso(0, 2, 0),
                &iso(5, 5, 0xd),
                &iso(10, 10, 0xd),
                &iso(11, 11, 0xd),
                &[4, 6, 0xff, 0, 0, 1],
            ],
        );
        let madt = parse_madt(&table).unwrap();
        assert!(madt.pcat_compat);
        assert_eq!(
            (madt.cpus_usable, madt.lapic_entries, madt.x2apic_entries),
            (1, 1, 0)
        );
        assert_eq!(madt.lapic_address, 0xfee0_0000);
        assert_eq!(
            madt.ioapics(),
            &[Ioapic {
                id: 0,
                address: 0xfec0_0000,
                gsi_base: 0
            }]
        );
        assert_eq!(madt.overrides().len(), 4);
        assert_eq!(
            madt.lapic_nmis(),
            &[LapicNmi {
                uid: u32::MAX,
                flags: 0,
                lint: 1
            }]
        );
        // ISA IRQ0 -> GSI 2 edge/high; IRQ2's identity GSI 2 is claimed by that override.
        assert_eq!(
            madt.isa_route(0),
            Some(IsaRoute {
                gsi: 2,
                trigger: Trigger::Edge,
                polarity: Polarity::ActiveHigh
            })
        );
        assert_eq!(madt.isa_route(2), None);
        assert_eq!(
            madt.isa_route(5),
            Some(IsaRoute {
                gsi: 5,
                trigger: Trigger::Level,
                polarity: Polarity::ActiveHigh
            })
        );
        assert_eq!(madt.isa_route(1).unwrap().gsi, 1);
        assert_eq!(madt.isa_route(16), None);
    }

    #[test]
    fn madt_x2apic_override_and_counts() {
        let mut ovr = vec![5, 12, 0, 0];
        ovr.extend_from_slice(&0xfee0_1000u64.to_le_bytes());
        let table = madt_with(
            0,
            &[
                &lapic(0, 1),
                &lapic(1, 2),
                &lapic(2, 0),
                &x2apic(0x1ff, 1),
                &ovr,
            ],
        );
        let madt = parse_madt(&table).unwrap();
        assert!(!madt.pcat_compat);
        assert_eq!(
            (madt.cpus_usable, madt.lapic_entries, madt.x2apic_entries),
            (3, 3, 1)
        );
        assert_eq!(madt.max_apic_id, 0x1ff);
        assert_eq!(madt.lapic_address, 0xfee0_1000);
        // A zero override is ignored, the previous value stays.
        let mut zero = vec![5, 12, 0, 0];
        zero.extend_from_slice(&0u64.to_le_bytes());
        let madt = parse_madt(&madt_with(0, &[&zero])).unwrap();
        assert_eq!(madt.lapic_address, 0xfee0_0000);
    }

    #[test]
    fn madt_hostile_entries() {
        // Every known type shorter than its structure is a Length error.
        for (kind, minimum) in [
            (0u8, 8usize),
            (1, 12),
            (2, 10),
            (3, 8),
            (4, 6),
            (5, 12),
            (9, 16),
            (10, 12),
        ] {
            for length in 2..minimum {
                let mut e = vec![0u8; length];
                e[0] = kind;
                e[1] = length as u8;
                assert_eq!(
                    parse_madt(&madt_with(0, &[&e])),
                    Err(Error::Length),
                    "{kind}/{length}"
                );
            }
        }
        // Overrun, zero and one-byte lengths.
        assert_eq!(
            parse_madt(&madt_with(0, &[&[0, 9, 0, 0, 0, 0, 0, 0]])),
            Err(Error::Length)
        );
        assert_eq!(parse_madt(&madt_with(0, &[&[1, 0]])), Err(Error::Length));
        assert_eq!(parse_madt(&madt_with(0, &[&[1]])), Err(Error::Length));
        // A longer-than-needed known entry is accepted and skipped by its real length.
        let mut long = lapic(3, 1);
        long[1] = 12;
        long.extend_from_slice(&[0xaa; 4]);
        assert_eq!(
            parse_madt(&madt_with(0, &[&long, &lapic(4, 1)]))
                .unwrap()
                .cpus_usable,
            2
        );
        // Zero and duplicate IOAPIC addresses are skipped like Linux; overflowing the
        // fixed tables drops entries without panicking.
        let table = madt_with(
            0,
            &[
                &ioapic(0, 0, 0),
                &ioapic(1, 0xfec0_0000, 0),
                &ioapic(2, 0xfec0_0000, 24),
            ],
        );
        let madt = parse_madt(&table).unwrap();
        assert_eq!((madt.ioapics().len(), madt.dropped), (1, 2));
        let many: Vec<Vec<u8>> = (0..MAX_OVERRIDES as u8 + 5)
            .map(|i| iso(i % 16, 99, 0))
            .collect();
        let refs: Vec<&[u8]> = many.iter().map(Vec::as_slice).collect();
        let madt = parse_madt(&madt_with(0, &refs)).unwrap();
        assert_eq!((madt.overrides().len(), madt.dropped), (MAX_OVERRIDES, 5));
        // Bad checksum / signature / truncated header.
        let mut bad = madt_with(0, &[]);
        bad[40] ^= 1;
        assert_eq!(parse_madt(&bad), Err(Error::Checksum));
        let mut wrong = madt_with(0, &[]);
        wrong[0] = b'X';
        repair_checksum(&mut wrong, 9);
        assert_eq!(parse_madt(&wrong), Err(Error::Signature));
        assert_eq!(parse_madt(&madt_with(0, &[])[..43]), Err(Error::Length));
    }

    #[test]
    fn isa_route_flag_decoding_matches_linux_defaults() {
        let table = madt_with(
            0,
            &[
                &iso(1, 1, 0x0f),
                &iso(3, 3, 0x05),
                &iso(4, 4, 0x0b),
                &iso(6, 6, 0x08),
            ],
        );
        let madt = parse_madt(&table).unwrap();
        // polarity 3 (low) trigger 3 (level)
        assert_eq!(
            madt.isa_route(1).unwrap(),
            IsaRoute {
                gsi: 1,
                trigger: Trigger::Level,
                polarity: Polarity::ActiveLow
            }
        );
        // polarity 1 (high) trigger 1 (edge)
        assert_eq!(
            madt.isa_route(3).unwrap(),
            IsaRoute {
                gsi: 3,
                trigger: Trigger::Edge,
                polarity: Polarity::ActiveHigh
            }
        );
        // polarity 3, trigger 2 (reserved): Broken BIOS -> level, low
        assert_eq!(
            madt.isa_route(4).unwrap(),
            IsaRoute {
                gsi: 4,
                trigger: Trigger::Level,
                polarity: Polarity::ActiveLow
            }
        );
        // polarity 0 (conforming) trigger 2 (reserved) -> level, ISA high
        assert_eq!(
            madt.isa_route(6).unwrap(),
            IsaRoute {
                gsi: 6,
                trigger: Trigger::Level,
                polarity: Polarity::ActiveHigh
            }
        );
    }

    #[test]
    fn ioapic_lookup_by_gsi_range() {
        let table = madt_with(
            0,
            &[&ioapic(0, 0xfec0_0000, 0), &ioapic(1, 0xfec1_0000, 24)],
        );
        let madt = parse_madt(&table).unwrap();
        let pins = |_: &Ioapic| 24;
        assert_eq!(madt.ioapic_for_gsi(2, pins), Some(0));
        assert_eq!(madt.ioapic_for_gsi(24, pins), Some(1));
        assert_eq!(madt.ioapic_for_gsi(48, pins), None);
        assert_eq!(madt.ioapic_for_gsi(u32::MAX, pins), None);
    }

    fn hpet_table(space: u8, address: u64) -> Vec<u8> {
        let mut body = vec![0u8; 20];
        body[4] = space;
        body[8..16].copy_from_slice(&address.to_le_bytes());
        body[16] = 3;
        body[17..19].copy_from_slice(&0x80u16.to_le_bytes());
        sdt(b"HPET", &body)
    }
    #[test]
    fn hpet_table_is_validated() {
        assert_eq!(
            parse_hpet(&hpet_table(0, 0xfed0_0000)),
            Ok(Hpet {
                address: 0xfed0_0000,
                number: 3,
                min_tick: 0x80
            })
        );
        assert_eq!(parse_hpet(&hpet_table(1, 0xfed0_0000)), Err(Error::Value));
        assert_eq!(parse_hpet(&hpet_table(0, 0)), Err(Error::Value));
        assert_eq!(parse_hpet(&hpet_table(0, 0xfed0_0100)), Err(Error::Value));
        assert_eq!(
            parse_hpet(&hpet_table(0, 0xfed0_0000)[..50]),
            Err(Error::Length)
        );
        let mut wrong = hpet_table(0, 0xfed0_0000);
        wrong[0] = b'X';
        repair_checksum(&mut wrong, 9);
        assert_eq!(parse_hpet(&wrong), Err(Error::Signature));
    }

    fn fadt_table(revision: u8, len: usize) -> Vec<u8> {
        let mut table = sdt(b"FACP", &vec![0u8; len - 36]);
        table[8] = revision;
        table
    }
    #[test]
    fn fadt_timer_fields() {
        let mut t = fadt_table(3, 244);
        t[76..80].copy_from_slice(&0x608u32.to_le_bytes());
        t[91] = 4;
        t[108] = 0x32;
        t[112..116].copy_from_slice(&((1u32 << 8) | (1 << 20)).to_le_bytes());
        t[109] = 1 << 5;
        repair_checksum(&mut t, 9);
        let f = parse_fadt(&t).unwrap();
        assert_eq!(
            f,
            Fadt {
                revision: 3,
                pm_timer_port: 0x608,
                pm_timer_32bit: true,
                century: 0x32,
                no_cmos_rtc: true,
                hardware_reduced: true
            }
        );
        // Extended block in I/O space wins; memory space does not.
        t[208] = 1;
        t[212..220].copy_from_slice(&0x1808u64.to_le_bytes());
        repair_checksum(&mut t, 9);
        assert_eq!(parse_fadt(&t).unwrap().pm_timer_port, 0x1808);
        t[208] = 0;
        repair_checksum(&mut t, 9);
        assert_eq!(parse_fadt(&t).unwrap().pm_timer_port, 0x608);
        // Wrong length byte, rev 1 century, short table.
        t[91] = 3;
        repair_checksum(&mut t, 9);
        assert_eq!(parse_fadt(&t).unwrap().pm_timer_port, 0);
        let mut r1 = fadt_table(1, 116);
        r1[108] = 9;
        repair_checksum(&mut r1, 9);
        assert_eq!(parse_fadt(&r1).unwrap().century, 0);
        assert_eq!(parse_fadt(&fadt_table(3, 244)[..100]), Err(Error::Length));
    }
}
