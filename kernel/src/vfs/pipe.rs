// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: fs/pipe.c (GPL-2.0:
// `anon_pipe_read`, `anon_pipe_write`, `create_pipe_files`, `alloc_pipe_info`,
// `pipe_release`, `pipe_ioctl` FIONREAD, `pipe_fcntl`, `pipe_poll` 660,
// `round_pipe_size` 1272, `pipe_resize_ring` 1291, `pipe_set_size` 1364),
// include/linux/pipe_fs_i.h (`PIPE_DEF_BUFFERS`, `pipe_buffer`). Copyright of
// the original: Linus Torvalds and contributors.
// Transformation: the ring of `pipe_buffer`s is a vector of at most
// `max_usage` page buffers; waiting is the caller's decision (`syscall::fd`
// sleeps on `sched::PIPE_KEY` and the owner of the scheduler wakes it when
// [`crate::vfs::Vfs::take_pipe_events`] reports a change); no wait queues,
// fasync, watch queue, packet mode or per-user buffer accounting; `splice` into a pipe
// copies the file bytes (the pipe does not share the page cache's pages).
#![forbid(unsafe_code)]
//! Anonymous pipes. The syscall layer moves bytes between user memory and the
//! buffers one page at a time, exactly as `anon_pipe_read`/`anon_pipe_write`
//! copy page by page, so a fault leaves the same bytes consumed or written.

use alloc::vec::Vec;
use syscalls::Errno;

use super::{KResult, PAGE_SIZE, Timespec, try_push};

/// `PIPE_DEF_BUFFERS`: a new pipe holds sixteen pages (`F_GETPIPE_SZ` 65536).
pub const PIPE_DEF_BUFFERS: usize = 16;

/// One page buffer of a pipe (`struct pipe_buffer`), also the unit `splice` moves between pipes.
pub struct PipeBuf {
    page: Vec<u8>,
    offset: usize,
    len: usize,
    /// `PIPE_BUF_FLAG_CAN_MERGE`: set on the buffers `anon_pipe_write` creates, not on
    /// the file pages `splice` puts into a pipe.
    can_merge: bool,
}

pub struct Pipe {
    bufs: Vec<PipeBuf>,
    /// `pipe->readers` / `pipe->writers`: open file ends.
    pub readers: u32,
    pub writers: u32,
    pub max_usage: usize,
    /// pipefs inode facts for `fstat`.
    pub ino: u64,
    pub uid: u32,
    pub gid: u32,
    pub time: Timespec,
}

impl Pipe {
    #[must_use]
    pub fn new(ino: u64, uid: u32, gid: u32, time: Timespec) -> Self {
        Self {
            bufs: Vec::new(),
            readers: 1,
            writers: 1,
            max_usage: PIPE_DEF_BUFFERS,
            ino,
            uid,
            gid,
            time,
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bufs.is_empty()
    }

    /// `pipe_occupancy`: the slots in use.
    #[must_use]
    pub fn slots_used(&self) -> usize {
        self.bufs.len()
    }

    #[must_use]
    pub fn is_full(&self) -> bool {
        self.bufs.len() >= self.max_usage
    }

    /// Bytes buffered (`FIONREAD`).
    #[must_use]
    pub fn available(&self) -> usize {
        self.bufs.iter().map(|buf| buf.len).sum()
    }

    /// `max_usage * PAGE_SIZE` (`F_GETPIPE_SZ`).
    #[must_use]
    pub fn size(&self) -> usize {
        self.max_usage * PAGE_SIZE
    }

    /// The data of the oldest buffer.
    #[must_use]
    pub fn front(&self) -> Option<&[u8]> {
        self.bufs
            .first()
            .map(|buf| &buf.page[buf.offset..buf.offset + buf.len])
    }

    /// Copy up to `max` buffered bytes, oldest first, into `out` (a gather for a write that may
    /// take less; nothing is consumed).
    ///
    /// # Errors
    /// `ENOMEM`.
    pub fn peek(&self, max: usize, out: &mut Vec<u8>) -> KResult<()> {
        let mut left = max;
        for buf in &self.bufs {
            let take = buf.len.min(left);
            out.try_reserve(take).map_err(|_| Errno::ENOMEM)?;
            for &byte in &buf.page[buf.offset..buf.offset + take] {
                // The room was reserved above.
                let _ = out.push_within_capacity(byte);
            }
            left -= take;
            if left == 0 {
                break;
            }
        }
        Ok(())
    }

    /// Consume `count` bytes from the oldest buffers (the "dismiss the fully eaten buffers,
    /// adjust the partial one" loop of `iter_file_splice_write`).
    pub fn consume_bytes(&mut self, mut count: usize) {
        while count > 0 {
            let Some(len) = self.bufs.first().map(|buf| buf.len) else {
                break;
            };
            let take = len.min(count);
            self.consume(take);
            count -= take;
        }
    }

    /// Bytes of the oldest buffer.
    #[must_use]
    pub fn front_len(&self) -> usize {
        self.bufs.first().map_or(0, |buf| buf.len)
    }

    /// Detach the oldest buffer as it is (`splice_pipe_to_pipe` moving a whole buffer).
    pub fn take_front(&mut self) -> Option<PipeBuf> {
        if self.bufs.is_empty() {
            None
        } else {
            Some(self.bufs.remove(0))
        }
    }

    /// A buffer holding the first `len` bytes of the oldest one, which loses them (the page is
    /// copied where Linux takes a reference; the copy does not inherit `CAN_MERGE`).
    ///
    /// # Errors
    /// `ENOMEM`; `EINVAL` if `len` exceeds the oldest buffer or the pipe is empty.
    pub fn split_front(&mut self, len: usize) -> KResult<PipeBuf> {
        let front = self.bufs.first().ok_or(Errno::EINVAL)?;
        if len > front.len {
            return Err(Errno::EINVAL);
        }
        let mut page = Vec::new();
        page.try_reserve_exact(PAGE_SIZE)
            .map_err(|_| Errno::ENOMEM)?;
        for &byte in &front.page {
            page.push_within_capacity(byte).map_err(|_| Errno::ENOMEM)?;
        }
        let copy = PipeBuf {
            page,
            offset: front.offset,
            len,
            can_merge: false,
        };
        self.consume(len);
        Ok(copy)
    }

    /// Append a buffer taken from another pipe.
    ///
    /// # Errors
    /// `ENOMEM`; `EINVAL` when the pipe is full.
    pub fn push_buf(&mut self, buf: PipeBuf) -> KResult<()> {
        if self.is_full() {
            return Err(Errno::EINVAL);
        }
        try_push(&mut self.bufs, buf)
    }

    /// Consume `count` bytes of the oldest buffer; an emptied buffer is released.
    pub fn consume(&mut self, count: usize) {
        if let Some(buf) = self.bufs.first_mut() {
            buf.offset += count;
            buf.len -= count;
            if buf.len == 0 {
                self.bufs.remove(0);
            }
        }
    }

    /// Room left in the newest buffer for a merging write.
    #[must_use]
    pub fn merge_room(&self) -> usize {
        self.bufs.last().map_or(0, |buf| {
            if buf.can_merge {
                PAGE_SIZE - (buf.offset + buf.len)
            } else {
                0
            }
        })
    }

    /// Append to the newest buffer (the `PIPE_BUF_FLAG_CAN_MERGE` path).
    ///
    /// # Errors
    /// `EINVAL` if the data does not fit ([`Pipe::merge_room`] is the check).
    pub fn merge(&mut self, data: &[u8]) -> KResult<()> {
        let room = self.merge_room();
        let buf = self.bufs.last_mut().ok_or(Errno::EINVAL)?;
        if data.len() > room {
            return Err(Errno::EINVAL);
        }
        let end = buf.offset + buf.len;
        buf.page[end..end + data.len()].copy_from_slice(data);
        buf.len += data.len();
        Ok(())
    }

    /// `round_pipe_size`: the capacity in bytes `F_SETPIPE_SZ` gives for a
    /// request of `size`, `None` (`0`: `EINVAL`) above `1 << 31`.
    #[must_use]
    pub fn round_pipe_size(size: u32) -> Option<u32> {
        const PAGE: u32 = PAGE_SIZE as u32;
        if size > 1 << 31 {
            return None;
        }
        // Minimum pipe size, as required by POSIX.
        if size < PAGE {
            return Some(PAGE);
        }
        Some(size.next_power_of_two())
    }

    /// `pipe_resize_ring(pipe, nr_slots)`: the new capacity in pages.
    ///
    /// # Errors
    /// `EBUSY` when more buffers than `nr_slots` hold data.
    pub fn set_slots(&mut self, nr_slots: usize) -> KResult<()> {
        if nr_slots < self.bufs.len() {
            return Err(Errno::EBUSY);
        }
        self.max_usage = nr_slots;
        Ok(())
    }

    /// Add a fresh page buffer holding `data` (at most a page), as `anon_pipe_write`
    /// does: later small writes may merge into it.
    ///
    /// # Errors
    /// `ENOMEM`; `EINVAL` when the pipe is full or `data` exceeds a page.
    pub fn push_page(&mut self, data: &[u8]) -> KResult<()> {
        self.push(data, true)
    }

    /// Add a buffer holding the file bytes `splice` moved in (`splice_folio_into_pipe`):
    /// a later write never merges into it. The bytes are copied, not shared with the
    /// page cache.
    ///
    /// # Errors
    /// As [`Pipe::push_page`].
    pub fn push_spliced(&mut self, data: &[u8]) -> KResult<()> {
        self.push(data, false)
    }

    fn push(&mut self, data: &[u8], can_merge: bool) -> KResult<()> {
        if self.is_full() || data.len() > PAGE_SIZE {
            return Err(Errno::EINVAL);
        }
        let mut page = Vec::new();
        page.try_reserve_exact(PAGE_SIZE)
            .map_err(|_| Errno::ENOMEM)?;
        for &byte in data {
            page.push_within_capacity(byte).map_err(|_| Errno::ENOMEM)?;
        }
        for _ in data.len()..PAGE_SIZE {
            page.push_within_capacity(0).map_err(|_| Errno::ENOMEM)?;
        }
        try_push(
            &mut self.bufs,
            PipeBuf {
                page,
                offset: 0,
                len: data.len(),
                can_merge,
            },
        )
    }
}
