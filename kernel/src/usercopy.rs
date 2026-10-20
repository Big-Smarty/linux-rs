// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: arch/x86/include/asm/uaccess_64.h
// (`__access_ok`, `USER_PTR_MAX`), arch/x86/include/asm/page_64_types.h
// (`TASK_SIZE_MAX`), lib/usercopy.c (`_copy_from_user` zero-fills the
// uncopied tail), include/linux/uaccess.h (copy_{to,from}_user return the
// number of bytes NOT copied), lib/strncpy_from_user.c, arch/x86/include/asm/uaccess.h
// (`put_user` is one store). All GPL-2.0.
// Transformation: the exception-table fixup is replaced by a software page
// table walk performed before each page is touched; no user virtual address is
// ever dereferenced.
#![forbid(unsafe_code)]
//! The single user-memory access mechanism: range check, then per-page
//! resolution through the owner of the user page tables, then a copy through
//! the kernel's own alias of the frame.
//!
//! # Contract
//! * Context: task context of the one user task, interrupts in any state; no
//!   sleeping and no locks here. The [`UserPages`] implementor may resolve a
//!   non-resident page by taking the page fault Linux would take for a kernel
//!   access to user memory (`userspace::Syscall::page`: demand-zero or
//!   copy-on-write through the address-space model, which can allocate frames
//!   and heap storage, fallibly); a refused fault is a short copy.
//! * Why no fault can occur: [`UserPages::page`] resolves a user page to a
//!   kernel-addressable frame (present, user, and writable when `write`)
//!   *before* any byte moves. The kernel never touches the user virtual
//!   address, so SMAP cannot trap and no `STAC`/`CLAC` window exists. A future
//!   implementation that dereferences user addresses directly MUST open and
//!   close the `AC` window around exactly the copy loops below, and then needs
//!   an exception-table fixup instead of this walk.
//! * TOCTOU: resolution and copy happen under one exclusive borrow. The
//!   [`UserPages`] implementor (`paging::UserSpace`) holds `&mut Tables`, the
//!   running task's own private tree (`userspace::TaskLocal`: no other task
//!   or CPU reaches it, so no lock is needed), so no `mm_*` table edit (`mm_unmap`,
//!   `mm_protect`, ...) can run between the two (the fault-in that
//!   [`UserPages::page`] itself performs happens before it returns the frame),
//!   and the returned page borrow ends before any such edit can start. User code does not run during a syscall (one CPU).
//!   Upgrade path: a second CPU, or a thread sharing the address space, needs an
//!   address-space lock to cover other CPUs' faults and unmaps, plus a
//!   TLB shootdown before frames are freed; direct dereference of user
//!   addresses would instead need fault-and-fixup copies.
//! * Short copies: like Linux, the functions return how many bytes were NOT
//!   copied. Bytes before the first inaccessible page are copied; a failed
//!   `copy_from_user` zero-fills the remainder of the destination.

use crate::memory::{PAGE, PAGE_BYTES};

/// Linux `TASK_SIZE_MAX` (4-level paging) and the x86 `USER_PTR_MAX`.
pub const TASK_SIZE_MAX: u64 = (1 << 47) - PAGE;

/// Linux x86 `__access_ok` for a runtime-sized range: no wraparound and the
/// end (exclusive) is at most `TASK_SIZE_MAX`. A zero-length range at
/// `TASK_SIZE_MAX` itself is accepted, as in Linux.
#[must_use]
pub fn access_ok(address: u64, length: u64) -> bool {
    address
        .checked_add(length)
        .is_some_and(|end| end <= TASK_SIZE_MAX)
}

/// Resolves user pages for kernel access. The implementor owns the page tables.
pub trait UserPages {
    /// The frame backing the 4 KiB page that starts at `page` (page-aligned),
    /// or `None` when the page is not present, not user-accessible, or (when
    /// `write`) not writable. Reads need no readable flag: x86 has none.
    ///
    /// The result of a `write == false` request MAY alias a frame shared by
    /// many mappings (the zero page): the caller MUST only read through it and
    /// never write. Only a `write == true` result is exclusively writable.
    fn page(&mut self, page: u64, write: bool) -> Option<&mut [u8; PAGE_BYTES]>;
}

impl<T: UserPages + ?Sized> UserPages for &mut T {
    fn page(&mut self, page: u64, write: bool) -> Option<&mut [u8; PAGE_BYTES]> {
        (**self).page(page, write)
    }
}

/// Visit the pages of `[address, address + length)` in order. Returns the
/// number of bytes not visited.
fn walk<P: UserPages>(
    pages: &mut P,
    address: u64,
    length: usize,
    write: bool,
    mut visit: impl FnMut(&mut [u8], usize),
) -> usize {
    if !access_ok(address, length as u64) {
        return length;
    }
    let mut done = 0;
    while done < length {
        // access_ok bounded address + length below 2^47: no overflow here.
        let at = address + done as u64;
        let offset = (at % PAGE) as usize;
        let count = (PAGE_BYTES - offset).min(length - done);
        let Some(page) = pages.page(at - offset as u64, write) else {
            break;
        };
        visit(&mut page[offset..offset + count], done);
        done += count;
    }
    length - done
}

/// Copy `from` to user memory at `to`. Returns the bytes NOT copied.
pub fn copy_to_user<P: UserPages>(pages: &mut P, to: u64, from: &[u8]) -> usize {
    walk(pages, to, from.len(), true, |page, done| {
        page.copy_from_slice(&from[done..done + page.len()]);
    })
}

/// Copy user memory at `from` into `to`. Returns the bytes NOT copied; the
/// uncopied tail of `to` is zeroed so no stale kernel bytes survive.
pub fn copy_from_user<P: UserPages>(pages: &mut P, to: &mut [u8], from: u64) -> usize {
    let missing = walk(pages, from, to.len(), false, |page, done| {
        to[done..done + page.len()].copy_from_slice(page);
    });
    let copied = to.len() - missing;
    to[copied..].fill(0);
    missing
}

/// `put_user` of one value: a single store, so it either happens completely
/// or not at all (a store that crosses into an unwritable page faults before
/// any byte changes). Returns whether it was stored. Unlike [`copy_to_user`],
/// there is no short copy to report.
pub fn put_user<P: UserPages>(pages: &mut P, to: u64, value: &[u8]) -> bool {
    if !access_ok(to, value.len() as u64) {
        return false;
    }
    let first = to & !(PAGE - 1);
    let last = (to + value.len().saturating_sub(1) as u64) & !(PAGE - 1);
    let writable = |pages: &mut P, page: u64| pages.page(page, true).is_some();
    if value.is_empty() {
        return true;
    }
    writable(pages, first) && writable(pages, last) && copy_to_user(pages, to, value) == 0
}

/// `strncpy_from_user` (`lib/strncpy_from_user.c`): copy the NUL-terminated
/// string at `from` into `to`, at most `to.len()` bytes, stopping after the NUL.
/// Returns the length without the NUL (`to.len()` when no NUL was found within
/// the caller's limit), or `None` for `-EFAULT`: `from` outside `TASK_SIZE_MAX`,
/// an inaccessible byte before the NUL, or the end of the address space reached
/// with no NUL while the caller would have accepted more bytes. Only the bytes
/// up to and including the NUL are written; Linux's word-at-a-time path also
/// stores zeros after the NUL within its last word, so callers must not rely on
/// the bytes of `to` past the string either way.
pub fn strncpy_from_user<P: UserPages>(pages: &mut P, to: &mut [u8], from: u64) -> Option<usize> {
    if from >= TASK_SIZE_MAX {
        return if to.is_empty() { Some(0) } else { None };
    }
    // Clamp as Linux does (`max = min(count, TASK_SIZE_MAX - src)`).
    let limit = to
        .len()
        .min(usize::try_from(TASK_SIZE_MAX - from).unwrap_or(usize::MAX));
    for (index, slot) in to.iter_mut().take(limit).enumerate() {
        let mut byte = [0u8];
        if copy_from_user(pages, &mut byte, from + index as u64) != 0 {
            return None;
        }
        *slot = byte[0];
        if byte[0] == 0 {
            return Some(index);
        }
    }
    // Hit `max` (`res == max`): fine when that was the caller's own limit,
    // `-EFAULT` when the address space ended first (lib/strncpy_from_user.c:63-72).
    (limit == to.len()).then_some(limit)
}

#[cfg(test)]
pub(crate) mod fake {
    extern crate std;
    use super::{PAGE_BYTES, UserPages};
    use std::{boxed::Box, collections::BTreeMap};

    /// Sparse user space: page address -> (contents, writable).
    #[derive(Default)]
    pub struct Space(pub BTreeMap<u64, (Box<[u8; PAGE_BYTES]>, bool)>);

    impl Space {
        pub fn map(&mut self, page: u64, writable: bool) {
            self.0.insert(page, (Box::new([0; PAGE_BYTES]), writable));
        }
    }
    impl UserPages for Space {
        fn page(&mut self, page: u64, write: bool) -> Option<&mut [u8; PAGE_BYTES]> {
            let (bytes, writable) = self.0.get_mut(&page)?;
            (*writable || !write).then_some(&mut **bytes)
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::{
        TASK_SIZE_MAX, access_ok, copy_from_user, copy_to_user, fake::Space, put_user,
        strncpy_from_user,
    };

    #[test]
    fn access_ok_edges_match_linux_runtime_size_branch() {
        assert!(access_ok(0, 0));
        assert!(access_ok(0, TASK_SIZE_MAX));
        assert!(!access_ok(0, TASK_SIZE_MAX + 1));
        assert!(access_ok(TASK_SIZE_MAX, 0));
        assert!(!access_ok(TASK_SIZE_MAX, 1));
        assert!(access_ok(TASK_SIZE_MAX - 1, 1));
        assert!(!access_ok(TASK_SIZE_MAX + 1, 0));
        assert!(!access_ok(u64::MAX, 1));
        assert!(!access_ok(u64::MAX - 1, 4));
        assert!(!access_ok(1, u64::MAX));
    }

    #[test]
    fn copies_across_page_boundaries_both_ways() {
        let mut space = Space::default();
        space.map(0x1000, true);
        space.map(0x2000, true);
        let data: std::vec::Vec<u8> = (0..300u16)
            .map(|n| u8::try_from(n % 256).unwrap())
            .collect();
        assert_eq!(copy_to_user(&mut space, 0x1f80, &data), 0);
        let mut back = std::vec![0xaa; 300];
        assert_eq!(copy_from_user(&mut space, &mut back, 0x1f80), 0);
        assert_eq!(back, data);
        assert_eq!(space.0[&0x2000].0[0], data[0x80]);
    }

    #[test]
    fn short_write_keeps_bytes_before_the_hole_and_reports_the_rest() {
        let mut space = Space::default();
        space.map(0x1000, true);
        let data = [7u8; 100];
        // 96 bytes fit before the unmapped page at 0x2000.
        assert_eq!(copy_to_user(&mut space, 0x1fa0, &data), 100 - 0x60);
        assert!(space.0[&0x1000].0[0xfa0..].iter().all(|&b| b == 7));
    }

    #[test]
    fn short_read_zero_fills_the_uncopied_tail() {
        let mut space = Space::default();
        space.map(0x1000, true);
        space.0.get_mut(&0x1000).unwrap().0.fill(9);
        let mut buf = [0x55u8; 64];
        assert_eq!(copy_from_user(&mut space, &mut buf, 0x1fe0), 32);
        assert!(buf[..32].iter().all(|&b| b == 9));
        assert!(buf[32..].iter().all(|&b| b == 0));
    }

    #[test]
    fn write_to_read_only_page_copies_nothing_but_read_succeeds() {
        let mut space = Space::default();
        space.map(0x1000, false);
        assert_eq!(copy_to_user(&mut space, 0x1000, &[1, 2, 3]), 3);
        let mut buf = [1u8; 3];
        assert_eq!(copy_from_user(&mut space, &mut buf, 0x1000), 0);
        assert_eq!(buf, [0; 3]);
    }

    #[test]
    fn range_check_precedes_any_page_access() {
        let mut space = Space::default();
        space.map(TASK_SIZE_MAX - 0x1000, true);
        // Last valid page is fully copyable ...
        assert_eq!(copy_to_user(&mut space, TASK_SIZE_MAX - 4, &[1; 4]), 0);
        // ... one more byte crosses TASK_SIZE_MAX and nothing is copied.
        assert_eq!(copy_to_user(&mut space, TASK_SIZE_MAX - 4, &[2; 5]), 5);
        assert_eq!(space.0[&(TASK_SIZE_MAX - 0x1000)].0[0xffc], 1);
        let mut buf = [0xffu8; 4];
        assert_eq!(copy_from_user(&mut space, &mut buf, u64::MAX - 1), 4);
        assert_eq!(buf, [0; 4]);
        // Address zero is just an unmapped page, not special-cased.
        assert_eq!(copy_to_user(&mut space, 0, &[1]), 1);
        assert_eq!(copy_to_user(&mut space, 0, &[]), 0);
    }

    #[test]
    fn strncpy_at_the_top_of_the_address_space() {
        let mut space = Space::default();
        let last = TASK_SIZE_MAX - 0x1000;
        space.map(last, true);
        space.0.get_mut(&last).unwrap().0.fill(b'a');
        let mut to = [0u8; 8];
        // 4 bytes remain below TASK_SIZE_MAX and the string has no NUL there.
        let from = TASK_SIZE_MAX - 4;
        assert_eq!(strncpy_from_user(&mut space, &mut to, from), None);
        // The caller's limit equals the room: that is as much as it asked for.
        assert_eq!(strncpy_from_user(&mut space, &mut to[..4], from), Some(4));
        assert_eq!(&to[..4], b"aaaa");
        assert_eq!(strncpy_from_user(&mut space, &mut to[..3], from), Some(3));
        // A NUL inside the room wins regardless of the limit.
        space.0.get_mut(&last).unwrap().0[0xffe] = 0;
        assert_eq!(strncpy_from_user(&mut space, &mut to, from), Some(2));
    }

    #[test]
    fn put_user_is_all_or_nothing() {
        let mut space = Space::default();
        space.map(0x1000, true);
        assert!(put_user(&mut space, 0x1ff8, &[1; 8]));
        // Straddles into the unmapped page: nothing is stored.
        assert!(!put_user(&mut space, 0x1ffc, &[2; 8]));
        assert_eq!(space.0[&0x1000].0[0xffc], 1);
        assert!(!put_user(&mut space, 0x5000, &[1]));
        assert!(put_user(&mut space, 0x5000, &[]));
        assert!(!put_user(&mut space, TASK_SIZE_MAX, &[1]));
    }

    #[test]
    fn strncpy_stops_at_the_nul_and_reports_faults() {
        let mut space = Space::default();
        space.map(0x1000, true);
        space.0.get_mut(&0x1000).unwrap().0[0xff8..].copy_from_slice(b"abc\0defg");
        let mut to = [0x55u8; 16];
        assert_eq!(strncpy_from_user(&mut space, &mut to, 0x1ff8), Some(3));
        assert_eq!(&to[..5], b"abc\0\x55");
        // No NUL within the limit: the limit, no terminator written.
        assert_eq!(strncpy_from_user(&mut space, &mut to[..2], 0x1ff8), Some(2));
        // The string runs into the unmapped page before its NUL.
        assert_eq!(strncpy_from_user(&mut space, &mut to, 0x1ffc), None);
        assert_eq!(strncpy_from_user(&mut space, &mut to, 0), None);
        assert_eq!(strncpy_from_user(&mut space, &mut to, TASK_SIZE_MAX), None);
        assert_eq!(
            strncpy_from_user(&mut space, &mut to[..0], TASK_SIZE_MAX),
            Some(0)
        );
    }
}
