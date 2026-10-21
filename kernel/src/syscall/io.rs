// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: fs/read_write.c (`vfs_write`),
// include/linux/fs.h (`MAX_RW_COUNT`), drivers/tty/tty_io.c
// (`iterate_tty_write`). GPL-2.0-only.
//! The sizes of the read/write paths (the console tty's own are in `tty`).

/// `MAX_RW_COUNT = INT_MAX & PAGE_MASK`.
pub const MAX_RW_COUNT: u32 = 0x7fff_f000;
/// `iterate_tty_write`'s default chunk (no `TTY_NO_WRITE_SPLIT`).
pub const TTY_CHUNK: u32 = 2048;

#[cfg(test)]
mod tests {
    use super::{MAX_RW_COUNT, TTY_CHUNK};
    use crate::syscall::{
        Console, Outcome, dispatch, error,
        testing::{Task, task},
    };
    use crate::usercopy::{TASK_SIZE_MAX, UserPages};
    use syscalls::{Errno, Sysno};

    const WRITE: u64 = Sysno::write as u64;
    fn neg(errno: Errno) -> Outcome {
        Outcome::Return(error(errno))
    }
    fn task_with(text: &[u8]) -> Task {
        let mut task = task();
        let mut address = 0x1000;
        for chunk in text.chunks(4096) {
            task.pages.map(address, true);
            task.pages.0.get_mut(&address).unwrap().0[..chunk.len()].copy_from_slice(chunk);
            address += 0x1000;
        }
        task
    }
    fn write_call<P: UserPages, C: Console>(
        task: &mut Task<P, C>,
        fd: u64,
        buf: u64,
        count: u64,
    ) -> Outcome {
        dispatch(task, WRITE, [fd, buf, count, 0, 0, 0])
    }

    #[test]
    fn write_maps_newline_to_crlf_and_counts_input_bytes() {
        let mut task = task_with(b"a\nb\n\nc");
        for fd in [0, 1, 2, 0x1_0000_0001] {
            task.sink.0.clear();
            assert_eq!(write_call(&mut task, fd, 0x1000, 6), Outcome::Return(6));
            assert_eq!(task.sink.0, b"a\r\nb\r\n\r\nc");
        }
    }

    #[test]
    fn write_error_precedence_and_zero_count() {
        let mut task = task_with(b"hello");
        // fd is checked first, even with a bad buffer.
        assert_eq!(write_call(&mut task, 3, u64::MAX, 1), neg(Errno::EBADF));
        assert_eq!(
            write_call(&mut task, 1 << 32 | 3, 0x1000, 1),
            neg(Errno::EBADF)
        );
        // access_ok sees the unclamped count.
        assert_eq!(
            write_call(&mut task, 1, 0x1000, TASK_SIZE_MAX),
            neg(Errno::EFAULT)
        );
        assert_eq!(
            write_call(&mut task, 1, 0x1000, u64::MAX),
            neg(Errno::EFAULT)
        );
        // Unmapped buffer: nothing copied -> EFAULT; zero length never faults.
        assert_eq!(write_call(&mut task, 1, 0x9000, 1), neg(Errno::EFAULT));
        assert_eq!(write_call(&mut task, 1, 0x9000, 0), Outcome::Return(0));
        assert_eq!(
            write_call(&mut task, 1, TASK_SIZE_MAX, 0),
            Outcome::Return(0)
        );
        assert_eq!(
            write_call(&mut task, 1, TASK_SIZE_MAX + 1, 0),
            neg(Errno::EFAULT)
        );
        assert_eq!(task.sink.0, b"");
    }

    #[test]
    fn fault_in_a_later_chunk_returns_the_earlier_chunks_only() {
        // 2048-byte chunks; the page at 0x3000 is missing, so bytes
        // [0x2000, 0x3000) are readable. Request 3 pages from 0x1000.
        let mut task = task_with(&[b'x'; 8192]);
        let outcome = write_call(&mut task, 1, 0x1000, 3 * 4096);
        assert_eq!(outcome, Outcome::Return(8192));
        assert_eq!(task.sink.0.len(), 8192);
        // The chunk at [0x2c00, 0x3400) straddles the hole: its readable
        // half is dropped as a whole (copy_from_iter() != size breaks).
        task.sink.0.clear();
        let outcome = write_call(&mut task, 1, 0x2400, 5000);
        assert_eq!(outcome, Outcome::Return(i64::from(TTY_CHUNK)));
        assert_eq!(task.sink.0.len(), TTY_CHUNK as usize);
        // First chunk faulting: -EFAULT, nothing written.
        task.sink.0.clear();
        let outcome = write_call(&mut task, 1, 0x2fff, 2);
        assert_eq!(outcome, neg(Errno::EFAULT));
        assert_eq!(task.sink.0, b"");
    }

    #[test]
    fn counts_above_max_rw_count_are_clamped_after_access_ok() {
        // Every page is "mapped" by a user space that serves one frame for
        // all addresses, so only the clamp bounds the loop.
        struct Everywhere([u8; 4096]);
        impl UserPages for Everywhere {
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
        let mut task = Task::new(Everywhere([b'z'; 4096]), Counter(0));
        // No output processing: the 2 GiB are not scanned byte by byte.
        task.tty.termios.oflag = 0;
        let outcome = write_call(&mut task, 1, 0, u64::from(MAX_RW_COUNT) + 12345);
        assert_eq!(outcome, Outcome::Return(i64::from(MAX_RW_COUNT)));
        assert_eq!(task.sink.0, u64::from(MAX_RW_COUNT));
    }
}
