// SPDX-License-Identifier: GPL-2.0-only
//! Allocation-free ACPI root-table validation, not AML or ACPI completion.
use crate::boot::{BootError, BootInfo};
use crate::image::bytes::Endian;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Map(BootError),
    Signature,
    Checksum,
    Length,
    Revision,
}
impl From<BootError> for Error {
    fn from(value: BootError) -> Self {
        Self::Map(value)
    }
}

pub struct Acpi {
    pub tables: usize,
    pub legacy_pic: bool,
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

/// Validate every MADT record and report the legacy PIC presence flag.
///
/// # Errors
/// Rejects invalid SDT contents, a non-MADT signature, or malformed records.
pub fn parse_madt(bytes: &[u8]) -> Result<bool, Error> {
    let table = parse_sdt(bytes)?;
    if &table[..4] != b"APIC" {
        return Err(Error::Signature);
    }
    if table.len() < 44 {
        return Err(Error::Length);
    }
    let mut cursor = 44;
    while cursor < table.len() {
        if table.len() - cursor < 2 {
            return Err(Error::Length);
        }
        let length = table[cursor + 1] as usize;
        if length < 2 || length > table.len() - cursor {
            return Err(Error::Length);
        }
        cursor += length;
    }
    Ok(u32_at(table, 40)? & 1 != 0)
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
    };
    for pointer in root[36..].as_chunks::<8>().0 {
        // SAFETY: this initialized XSDT pointer belongs to the trusted immutable
        // SDT tree under discover's explicit firmware/no-writer contract. The
        // pointed-to table's mapped bounds/header/checksum are still validated.
        let bytes = unsafe { table(boot, u64::from_le_bytes(*pointer))? };
        acpi.tables += 1;
        if &bytes[..4] == b"APIC" {
            acpi.legacy_pic = parse_madt(bytes)?;
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
    if parse_madt(&madt) != Ok(true) {
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
    use super::*;
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
}
