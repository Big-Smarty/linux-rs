// SPDX-License-Identifier: GPL-2.0-only
//! Shared checked byte access, using the existing firmware decoder convention.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundsError {
    Overflow,
    Truncated { offset: u64, length: u64 },
}

/// Explicit file byte order, independent of the executing CPU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

/// Borrow exactly the requested range, never saturating or truncating it.
///
/// # Errors
/// Reports arithmetic/address-width overflow or unavailable input bytes.
pub fn range(bytes: &[u8], offset: u64, length: u64) -> Result<&[u8], BoundsError> {
    let end = offset.checked_add(length).ok_or(BoundsError::Overflow)?;
    let start = usize::try_from(offset).map_err(|_| BoundsError::Overflow)?;
    let end = usize::try_from(end).map_err(|_| BoundsError::Overflow)?;
    bytes
        .get(start..end)
        .ok_or(BoundsError::Truncated { offset, length })
}

fn array<const N: usize>(bytes: &[u8], offset: u64) -> Result<[u8; N], BoundsError> {
    range(bytes, offset, N as u64)?
        .try_into()
        .map_err(|_| BoundsError::Truncated {
            offset,
            length: N as u64,
        })
}

impl Endian {
    /// # Errors
    /// Reports an unavailable or overflowing two-byte range.
    pub fn u16(self, bytes: &[u8], offset: u64) -> Result<u16, BoundsError> {
        let value = array(bytes, offset)?;
        Ok(match self {
            Self::Little => u16::from_le_bytes(value),
            Self::Big => u16::from_be_bytes(value),
        })
    }

    /// # Errors
    /// Reports an unavailable or overflowing four-byte range.
    pub fn u32(self, bytes: &[u8], offset: u64) -> Result<u32, BoundsError> {
        let value = array(bytes, offset)?;
        Ok(match self {
            Self::Little => u32::from_le_bytes(value),
            Self::Big => u32::from_be_bytes(value),
        })
    }

    /// # Errors
    /// Reports an unavailable or overflowing eight-byte range.
    pub fn u64(self, bytes: &[u8], offset: u64) -> Result<u64, BoundsError> {
        let value = array(bytes, offset)?;
        Ok(match self {
            Self::Little => u64::from_le_bytes(value),
            Self::Big => u64::from_be_bytes(value),
        })
    }
}

pub(super) fn align4(value: u64) -> Result<u64, BoundsError> {
    value
        .checked_add(3)
        .map(|v| v & !3)
        .ok_or(BoundsError::Overflow)
}

pub(super) fn c_name(bytes: &[u8]) -> &[u8] {
    &bytes[..bytes
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(bytes.len())]
}
