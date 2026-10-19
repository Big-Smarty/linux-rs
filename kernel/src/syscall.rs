// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: arch/x86/entry/syscall_64.c
// (`do_syscall_x64`: the number is an `int`, compared as `unsigned int`),
// arch/x86/entry/syscalls/syscall_64.tbl, fs/read_write.c (`vfs_write`),
// include/linux/fs.h (`MAX_RW_COUNT`), drivers/tty/tty_io.c
// (`iterate_tty_write`), drivers/tty/n_tty.c (`do_output_char`),
// kernel/exit.c (`sys_exit`, `sys_exit_group`), kernel/sys.c (`sys_getpid`).
// All GPL-2.0-only. Syscall names/numbers come from the `syscalls` crate
// (BSD-2-Clause), whose x86_64 table was compared against the pinned tbl.
// Transformation: the VFS/tty stack is reduced to the one open file the init
// process owns (/dev/console on fds 0-2) with its default termios.
#![forbid(unsafe_code)]
//! The minimal first-userspace syscall slice as pure functions.
//!
//! Context: task context, one task, one CPU; nothing here sleeps or allocates.
//! A syscall number that Linux 6.18.57 does not implement returns `-ENOSYS`; a
//! number it implements that this slice does not is reported as
//! [`Outcome::Unimplemented`] so the caller stops loudly instead of faking
//! success or a broad `ENOSYS`.

use crate::usercopy::{UserPages, access_ok, copy_from_user};
use syscalls::{Errno, Sysno};

/// `MAX_RW_COUNT = INT_MAX & PAGE_MASK`.
pub const MAX_RW_COUNT: u32 = 0x7fff_f000;
/// `iterate_tty_write`'s default chunk (no `TTY_NO_WRITE_SPLIT`).
pub const TTY_CHUNK: u32 = 2048;

/// `Sysno` values the `syscalls` crate lists for `x86_64` that the pinned
/// 6.18.57 `syscall_64.tbl` leaves without an entry point or maps to
/// `sys_ni_syscall`: Linux answers these with `-ENOSYS`, so they are not
/// "implemented but missing". Derived by comparing the crate's table with the
/// pinned file; `table_drift_guard` keeps the list sorted and valid.
const NOT_IMPLEMENTED_BY_LINUX: [u32; 17] = [
    134, 156, 174, 177, 178, 180, 181, 182, 183, 184, 185, 205, 211, 212, 214, 215, 236,
];

/// Byte sink for the console tty (serial and framebuffer in the kernel).
pub trait Console {
    fn write(&mut self, bytes: &[u8]);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Value for `rax`: the result, or `-errno`.
    Return(i64),
    /// The init task exits with this `exit_code` (`(status & 0xff) << 8`).
    Exit(u32),
    /// A syscall inside Linux's table that this slice does not implement.
    Unimplemented(u32),
}

fn error(errno: Errno) -> i64 {
    -i64::from(errno.into_raw())
}

/// Dispatch one syscall. `number` is the raw `rax`; Linux reads it as `int`,
/// so the upper 32 bits are ignored. Arguments beyond a syscall's arity are
/// ignored, and `unsigned int` parameters are truncated, exactly as in Linux.
pub fn dispatch<P: UserPages, C: Console>(
    pages: &mut P,
    console: &mut C,
    number: u64,
    args: [u64; 6],
) -> Outcome {
    #[allow(clippy::cast_possible_truncation)]
    let number = number as u32;
    let Some(sysno) = Sysno::new(number as usize) else {
        return Outcome::Return(error(Errno::ENOSYS));
    };
    if NOT_IMPLEMENTED_BY_LINUX.binary_search(&number).is_ok() {
        return Outcome::Return(error(Errno::ENOSYS));
    }
    match sysno {
        Sysno::write => Outcome::Return(write(pages, console, args[0], args[1], args[2])),
        Sysno::getpid => Outcome::Return(1),
        Sysno::exit | Sysno::exit_group => Outcome::Exit(exit_code(args[0])),
        _ => Outcome::Unimplemented(number),
    }
}

/// `do_exit((error_code & 0xff) << 8)` / `do_group_exit` of the same value.
#[must_use]
pub fn exit_code(status: u64) -> u32 {
    #[allow(clippy::cast_possible_truncation)]
    let status = status as u8;
    u32::from(status) << 8
}

/// `write(2)` on the console. fds 0, 1 and 2 are init's `/dev/console`
/// (opened `O_RDWR`, then duplicated); every other fd is closed.
///
/// Order as in `ksys_write` -> `vfs_write`: fd lookup (`-EBADF`), `access_ok`
/// on the UNCLAMPED count (`-EFAULT`), clamp to `MAX_RW_COUNT`, then the tty
/// copies at most 2048 bytes at a time. A chunk that cannot be fully copied
/// from user memory is not written at all: the call returns the bytes of the
/// earlier chunks, or `-EFAULT` when there are none.
///
/// Output processing is the default `tty_std_termios` (`OPOST | ONLCR`):
/// `\n` becomes `\r\n`, nothing else changes, and the return value counts
/// input bytes. (The pinned oracle's serial log shows the same `\r\n`.)
fn write<P: UserPages, C: Console>(
    pages: &mut P,
    console: &mut C,
    fd: u64,
    buffer: u64,
    count: u64,
) -> i64 {
    #[allow(clippy::cast_possible_truncation)]
    if !matches!(fd as u32, 0..=2) {
        return error(Errno::EBADF);
    }
    if !access_ok(buffer, count) {
        return error(Errno::EFAULT);
    }
    // The clamp is below 2^31, so everything below fits u32/i64 exactly.
    let mut remaining = u32::try_from(count.min(u64::from(MAX_RW_COUNT))).unwrap_or(MAX_RW_COUNT);
    let mut at = buffer;
    let mut written = 0u32;
    let mut chunk = [0u8; TTY_CHUNK as usize];
    while remaining > 0 {
        let step = remaining.min(TTY_CHUNK);
        let bytes = &mut chunk[..step as usize];
        if copy_from_user(pages, bytes, at) != 0 {
            return if written > 0 {
                i64::from(written)
            } else {
                error(Errno::EFAULT)
            };
        }
        for (index, line) in bytes.split(|&byte| byte == b'\n').enumerate() {
            if index > 0 {
                console.write(b"\r\n");
            }
            console.write(line);
        }
        written += step;
        at += u64::from(step);
        remaining -= step;
    }
    i64::from(written)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::{Console, MAX_RW_COUNT, NOT_IMPLEMENTED_BY_LINUX, Outcome, TTY_CHUNK, dispatch};
    use crate::usercopy::{TASK_SIZE_MAX, fake::Space};
    use std::vec::Vec;
    use syscalls::{Errno, Sysno};

    #[derive(Default)]
    struct Sink(Vec<u8>);
    impl Console for Sink {
        fn write(&mut self, bytes: &[u8]) {
            self.0.extend_from_slice(bytes);
        }
    }

    const WRITE: u64 = Sysno::write as u64;
    fn neg(errno: Errno) -> Outcome {
        Outcome::Return(-i64::from(errno.into_raw()))
    }
    fn space_with(text: &[u8]) -> Space {
        let mut space = Space::default();
        let mut address = 0x1000;
        for chunk in text.chunks(4096) {
            space.map(address, true);
            space.0.get_mut(&address).unwrap().0[..chunk.len()].copy_from_slice(chunk);
            address += 0x1000;
        }
        space
    }
    fn write_call(space: &mut Space, sink: &mut Sink, fd: u64, buf: u64, count: u64) -> Outcome {
        dispatch(space, sink, WRITE, [fd, buf, count, 0, 0, 0])
    }

    #[test]
    fn table_drift_guard() {
        assert!(NOT_IMPLEMENTED_BY_LINUX.is_sorted());
        for number in NOT_IMPLEMENTED_BY_LINUX {
            assert!(Sysno::new(number as usize).is_some());
        }
        assert_eq!(Sysno::write as usize, 1);
        assert_eq!(Sysno::getpid as usize, 39);
        assert_eq!(Sysno::exit as usize, 60);
        assert_eq!(Sysno::exit_group as usize, 231);
    }

    #[test]
    fn numbers_outside_or_unimplemented_in_linux_are_enosys() {
        let mut space = Space::default();
        let mut sink = Sink::default();
        let call =
            |number: u64, space: &mut Space, sink: &mut Sink| dispatch(space, sink, number, [0; 6]);
        for number in [470, 471, 1000, 337, 423, 0x4000_0001, 0x8000_0001, 134, 183] {
            assert_eq!(
                call(number, &mut space, &mut sink),
                neg(Errno::ENOSYS),
                "{number}"
            );
        }
        // `int nr` semantics: only the low 32 bits count, in both directions.
        assert_eq!(
            call(0x1_0000_0000 | 0x27, &mut space, &mut sink),
            Outcome::Return(1)
        );
        assert_eq!(call(u64::MAX, &mut space, &mut sink), neg(Errno::ENOSYS));
        assert_eq!(sink.0, b"");
    }

    #[test]
    fn implemented_in_linux_but_not_here_is_reported_not_faked() {
        let mut space = Space::default();
        let mut sink = Sink::default();
        let read = dispatch(&mut space, &mut sink, Sysno::read as u64, [0; 6]);
        assert_eq!(read, Outcome::Unimplemented(0));
        let brk = dispatch(&mut space, &mut sink, Sysno::brk as u64, [0; 6]);
        assert_eq!(brk, Outcome::Unimplemented(12));
    }

    #[test]
    fn getpid_exit_and_exit_group_encode_like_linux() {
        let mut space = Space::default();
        let mut sink = Sink::default();
        assert_eq!(
            dispatch(&mut space, &mut sink, Sysno::getpid as u64, [9; 6]),
            Outcome::Return(1)
        );
        for number in [Sysno::exit as u64, Sysno::exit_group as u64] {
            let mut exit =
                |status| dispatch(&mut space, &mut sink, number, [status, 0, 0, 0, 0, 0]);
            assert_eq!(exit(0), Outcome::Exit(0));
            assert_eq!(exit(1), Outcome::Exit(0x100));
            assert_eq!(exit(0xff), Outcome::Exit(0xff00));
            assert_eq!(exit(0x1ff), Outcome::Exit(0xff00));
            assert_eq!(exit(0x1234_5601), Outcome::Exit(0x100));
            assert_eq!(exit(u64::MAX), Outcome::Exit(0xff00));
        }
    }

    #[test]
    fn write_maps_newline_to_crlf_and_counts_input_bytes() {
        let mut space = space_with(b"a\nb\n\nc");
        let mut sink = Sink::default();
        for fd in [0, 1, 2, 0x1_0000_0001] {
            sink.0.clear();
            assert_eq!(
                write_call(&mut space, &mut sink, fd, 0x1000, 6),
                Outcome::Return(6)
            );
            assert_eq!(sink.0, b"a\r\nb\r\n\r\nc");
        }
    }

    #[test]
    fn write_error_precedence_and_zero_count() {
        let mut space = space_with(b"hello");
        let mut sink = Sink::default();
        // fd is checked first, even with a bad buffer.
        assert_eq!(
            write_call(&mut space, &mut sink, 3, u64::MAX, 1),
            neg(Errno::EBADF)
        );
        assert_eq!(
            write_call(&mut space, &mut sink, 1 << 32 | 3, 0x1000, 1),
            neg(Errno::EBADF)
        );
        // access_ok sees the unclamped count.
        assert_eq!(
            write_call(&mut space, &mut sink, 1, 0x1000, TASK_SIZE_MAX),
            neg(Errno::EFAULT)
        );
        assert_eq!(
            write_call(&mut space, &mut sink, 1, 0x1000, u64::MAX),
            neg(Errno::EFAULT)
        );
        // Unmapped buffer: nothing copied -> EFAULT; zero length never faults.
        assert_eq!(
            write_call(&mut space, &mut sink, 1, 0x9000, 1),
            neg(Errno::EFAULT)
        );
        assert_eq!(
            write_call(&mut space, &mut sink, 1, 0x9000, 0),
            Outcome::Return(0)
        );
        assert_eq!(
            write_call(&mut space, &mut sink, 1, TASK_SIZE_MAX, 0),
            Outcome::Return(0)
        );
        assert_eq!(
            write_call(&mut space, &mut sink, 1, TASK_SIZE_MAX + 1, 0),
            neg(Errno::EFAULT)
        );
        assert_eq!(sink.0, b"");
    }

    #[test]
    fn fault_in_a_later_chunk_returns_the_earlier_chunks_only() {
        // 2048-byte chunks; the page at 0x3000 is missing, so bytes
        // [0x2000, 0x3000) are readable. Request 3 pages from 0x1000.
        let mut space = space_with(&[b'x'; 8192]);
        let mut sink = Sink::default();
        let outcome = write_call(&mut space, &mut sink, 1, 0x1000, 3 * 4096);
        assert_eq!(outcome, Outcome::Return(8192));
        assert_eq!(sink.0.len(), 8192);
        // The chunk at [0x2c00, 0x3400) straddles the hole: its readable
        // half is dropped as a whole (copy_from_iter() != size breaks).
        sink.0.clear();
        let outcome = write_call(&mut space, &mut sink, 1, 0x2400, 5000);
        assert_eq!(outcome, Outcome::Return(i64::from(TTY_CHUNK)));
        assert_eq!(sink.0.len(), TTY_CHUNK as usize);
        // First chunk faulting: -EFAULT, nothing written.
        sink.0.clear();
        let outcome = write_call(&mut space, &mut sink, 1, 0x2fff, 2);
        assert_eq!(outcome, neg(Errno::EFAULT));
        assert_eq!(sink.0, b"");
    }

    #[test]
    fn counts_above_max_rw_count_are_clamped_after_access_ok() {
        // Every page is "mapped" by a user space that serves one frame for
        // all addresses, so only the clamp bounds the loop.
        struct Everywhere([u8; 4096]);
        impl crate::usercopy::UserPages for Everywhere {
            fn page(&mut self, _: u64, _: bool) -> Option<&mut [u8; 4096]> {
                Some(&mut self.0)
            }
        }
        struct Counter(u64);
        impl Console for Counter {
            fn write(&mut self, bytes: &[u8]) {
                self.0 += bytes.len() as u64;
            }
        }
        let mut space = Everywhere([b'z'; 4096]);
        let mut sink = Counter(0);
        let outcome = dispatch(
            &mut space,
            &mut sink,
            WRITE,
            [1, 0, u64::from(MAX_RW_COUNT) + 12345, 0, 0, 0],
        );
        assert_eq!(outcome, Outcome::Return(i64::from(MAX_RW_COUNT)));
        assert_eq!(sink.0, u64::from(MAX_RW_COUNT));
    }
}
