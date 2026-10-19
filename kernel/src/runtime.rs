// SPDX-License-Identifier: GPL-2.0-only
//! The linked image requires memset and memcpy. Supply scalar Rust rather than
//! compiler-builtins x86 REP assembly optimizations: ordinary memory operations
//! do not meet this project's unavoidable-assembly exception.
use core::{ffi::c_void, mem::MaybeUninit, ptr};

/// Compiler memory ABI: caller supplies `count` valid writable bytes with no
/// competing aliases/accesses; null is permitted only for count=0. No unwind.
#[unsafe(no_mangle)]
unsafe extern "C" fn memset(destination: *mut c_void, value: i32, count: usize) -> *mut c_void {
    let bytes = destination.cast::<u8>();
    // The compiler memset ABI specifies the integer's low eight bits, including
    // for negative values. An explicit byte extraction avoids signed casts.
    let byte = value.to_le_bytes()[0];
    let prefix = ((8 - (bytes as usize & 7)) & 7).min(count);
    let word = u64::from(byte) * 0x0101_0101_0101_0101;
    let mut offset = 0;
    while offset < prefix {
        // SAFETY: offset<count, byte alignment, original caller provenance and
        // exclusive writable extent. Volatile prevents recursive memset lowering.
        unsafe {
            ptr::write_volatile(bytes.add(offset), byte);
        }
        offset += 1;
    }
    while count - offset >= 8 {
        // SAFETY: prefix aligned this address to8; full u64 lies inside caller's
        // allocation and every bit pattern is initialized. No reference created.
        unsafe {
            #[expect(
                clippy::cast_ptr_alignment,
                reason = "The byte prologue advances to an eight-byte boundary; this loop owns a complete aligned u64 within the caller's extent."
            )]
            let aligned = bytes.add(offset).cast::<u64>();
            ptr::write_volatile(aligned, word);
        }
        offset += 8;
    }
    while offset < count {
        // SAFETY: final in-bounds caller-owned bytes, same provenance as above.
        unsafe {
            ptr::write_volatile(bytes.add(offset), byte);
        }
        offset += 1;
    }
    destination
}

/// Compiler memory ABI: `count` bytes in valid nonoverlapping memory ranges,
/// which may share an allocation. Shared source readers are allowed; source
/// writes and conflicting destination accesses are excluded. Preserve possibly
/// uninitialized padding. Null only for count=0; return destination, no unwind.
#[unsafe(no_mangle)]
unsafe extern "C" fn memcpy(
    destination: *mut c_void,
    source: *const c_void,
    count: usize,
) -> *mut c_void {
    let bytes = destination.cast::<MaybeUninit<u8>>();
    let input = source.cast::<MaybeUninit<u8>>();
    let prefix = ((8 - (bytes as usize & 7)) & 7).min(count);
    let mut offset = 0;
    while offset < prefix {
        // SAFETY: in-bounds source and exclusive byte destination; MaybeUninit
        // preserves uninitialized padding. Volatile prevents recursive lowering.
        unsafe {
            ptr::write_volatile(bytes.add(offset), ptr::read(input.add(offset)));
        }
        offset += 1;
    }
    while count - offset >= 8 {
        // SAFETY: complete words in the caller's valid nonoverlapping ranges.
        // Source alignment is arbitrary; the destination prologue aligned it.
        unsafe {
            let word = ptr::read_unaligned(input.add(offset).cast::<MaybeUninit<u64>>());
            #[expect(
                clippy::cast_ptr_alignment,
                reason = "The byte prologue aligns the destination; this loop owns a complete aligned u64 within the caller's extent."
            )]
            let aligned = bytes.add(offset).cast::<MaybeUninit<u64>>();
            ptr::write_volatile(aligned, word);
        }
        offset += 8;
    }
    while offset < count {
        // SAFETY: final in-bounds source/destination, without interpreting padding.
        unsafe {
            ptr::write_volatile(bytes.add(offset), ptr::read(input.add(offset)));
        }
        offset += 1;
    }
    destination
}

#[cfg(feature = "qemu-self-test")]
pub fn self_test() -> bool {
    for offset in 0..8 {
        for count in 0..=33 {
            let mut bytes = [0xa5u8; 48];
            let pointer = bytes.as_mut_ptr();
            // SAFETY: the entire selected extent is in this uniquely owned
            // stack allocation, including zero length and unaligned prefixes.
            let returned = unsafe { memset(pointer.add(offset).cast(), 0x15a, count) };
            if returned != unsafe { pointer.add(offset) }.cast() {
                return false;
            }
            for (index, &byte) in bytes.iter().enumerate() {
                let expected = if index >= offset && index < offset + count {
                    0x5a
                } else {
                    0xa5
                };
                if byte != expected {
                    return false;
                }
            }
        }
    }
    // SAFETY: zero-byte memory ABIs perform no access and permit null.
    if !unsafe {
        memset(ptr::null_mut(), -1, 0).is_null()
            && memcpy(ptr::null_mut(), ptr::null(), 0).is_null()
    } {
        return false;
    }
    copy_self_test() && padded_copy_self_test() && disjoint_range_self_test()
}

#[cfg(feature = "qemu-self-test")]
fn copy_self_test() -> bool {
    let mut source = [0u8; 80];
    for (byte, value) in source.iter_mut().zip(0u8..) {
        *byte = value.wrapping_mul(37).wrapping_add(11);
    }
    for source_offset in 0..8 {
        for destination_offset in 0..8 {
            for count in 0..=65 {
                let mut destination = [0xa5u8; 80];
                let pointer = destination.as_mut_ptr();
                // SAFETY: distinct initialized stack allocations; every
                // offset/count pair is in bounds, including both alignments.
                let returned = unsafe {
                    memcpy(
                        pointer.add(destination_offset).cast(),
                        source.as_ptr().add(source_offset).cast(),
                        count,
                    )
                };
                if returned != unsafe { pointer.add(destination_offset) }.cast() {
                    return false;
                }
                for (index, &byte) in destination.iter().enumerate() {
                    let expected =
                        if index >= destination_offset && index < destination_offset + count {
                            source[source_offset + index - destination_offset]
                        } else {
                            0xa5
                        };
                    if byte != expected {
                        return false;
                    }
                }
            }
        }
    }
    source
        .iter()
        .zip(0u8..)
        .all(|(&byte, value)| byte == value.wrapping_mul(37).wrapping_add(11))
}

#[cfg(feature = "qemu-self-test")]
fn padded_copy_self_test() -> bool {
    #[repr(C)]
    struct Padded {
        byte: u8,
        word: u64,
    }
    let mut source = MaybeUninit::<Padded>::uninit();
    let mut destination = MaybeUninit::<Padded>::zeroed();
    // SAFETY: write the two fields without initializing or reading padding;
    // copy the complete distinct objects; examine only initialized fields.
    unsafe {
        ptr::addr_of_mut!((*source.as_mut_ptr()).byte).write(0x5a);
        ptr::addr_of_mut!((*source.as_mut_ptr()).word).write(0x1234_5678_9abc_def0);
        let returned = memcpy(
            destination.as_mut_ptr().cast(),
            source.as_ptr().cast(),
            core::mem::size_of::<Padded>(),
        );
        returned == destination.as_mut_ptr().cast()
            && ptr::addr_of!((*destination.as_ptr()).byte).read() == 0x5a
            && ptr::addr_of!((*destination.as_ptr()).word).read() == 0x1234_5678_9abc_def0
    }
}

#[cfg(feature = "qemu-self-test")]
fn disjoint_range_self_test() -> bool {
    for (source_offset, destination_offset) in [(3, 43), (43, 3)] {
        let mut bytes = [0u8; 80];
        for (byte, value) in bytes.iter_mut().zip(0u8..) {
            *byte = value;
        }
        let pointer = bytes.as_mut_ptr();
        let first_reader = &bytes[source_offset..source_offset + 17];
        // SAFETY: disjoint 17-byte ranges in this one allocation; the source's
        // shared reader remains valid because only the destination is written.
        let returned = unsafe {
            memcpy(
                pointer.add(destination_offset).cast(),
                first_reader.as_ptr().cast(),
                17,
            )
        };
        if returned != unsafe { pointer.add(destination_offset) }.cast()
            || first_reader
                .iter()
                .enumerate()
                .any(|(index, &byte)| usize::from(byte) != source_offset + index)
        {
            return false;
        }
        for (index, &byte) in bytes.iter().enumerate() {
            let expected = if index >= destination_offset && index < destination_offset + 17 {
                source_offset + index - destination_offset
            } else {
                index
            };
            if usize::from(byte) != expected {
                return false;
            }
        }
    }
    true
}
