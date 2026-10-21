// SPDX-License-Identifier: GPL-2.0-only
//! Host tests of the syscalls the `dynelf` lane added (`creat`, `fadvise64`, `splice`, `vmsplice`,
//! `copy_file_range`, the `FICLONE` ioctls, the extended attribute family, `getsockname` and
//! `getpeername`, `mremap` through the dispatcher), through [`super::dispatch`] on the real tmpfs
//! rootfs of `testing::Task`. The differential evidence is the `dynelf` oracle group (programs of
//! the host that call all of them) and its `sys-*` checks.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::too_many_lines,
    clippy::many_single_char_names,
    clippy::similar_names,
    clippy::doc_markdown
)]

extern crate std;

use super::Outcome;
use super::testing::Task;
use super::vfs_tests::{BAD, BUF, OUT, PATH, call, cstr, err, fd, get, ok, open, put, t, u32_at};
use crate::vfs::{O_APPEND, O_CREAT, O_DIRECTORY, O_RDONLY, O_RDWR, O_WRONLY};
use std::vec::Vec;
use syscalls::{Errno, Sysno};

const PATH2: u64 = 0x1800;
const FIONREAD: u64 = 0x541b;
const FICLONE: u64 = 0x4004_9409;
const FICLONERANGE: u64 = 0x4020_940d;

fn filled(t: &mut Task, path: &str, bytes: &[u8]) -> u64 {
    let f = fd(open(t, path, O_CREAT | O_RDWR, 0o644));
    for chunk in bytes.chunks(4096) {
        put(t, 0x4000, chunk);
        assert_eq!(
            call(t, Sysno::write, &[f, 0x4000, chunk.len() as u64]),
            ok(chunk.len() as i64)
        );
    }
    assert_eq!(call(t, Sysno::lseek, &[f, 0, 0]), ok(0));
    f
}

/// A pipe: (read end, write end).
fn pipe(t: &mut Task, flags: u64) -> (u64, u64) {
    assert_eq!(call(t, Sysno::pipe2, &[OUT, flags]), ok(0));
    (u64::from(u32_at(t, OUT)), u64::from(u32_at(t, OUT + 4)))
}

fn queued(t: &mut Task, read_end: u64) -> i64 {
    assert_eq!(
        call(t, Sysno::ioctl, &[read_end, FIONREAD, OUT + 64]),
        ok(0)
    );
    i64::from(u32_at(t, OUT + 64))
}

#[test]
fn creat_is_open_with_create_write_truncate() {
    let mut t = t();
    let name = cstr(&mut t, PATH, "/c");
    let f = fd(call(&mut t, Sysno::creat, &[name, 0o640]));
    assert_eq!(call(&mut t, Sysno::write, &[f, BUF, 5]), ok(5));
    // Again: truncated, and the descriptor is write-only.
    let g = fd(call(&mut t, Sysno::creat, &[name, 0o600]));
    assert_eq!(call(&mut t, Sysno::read, &[g, OUT, 1]), err(Errno::EBADF));
    let r = fd(open(&mut t, "/c", O_RDONLY, 0));
    assert_eq!(call(&mut t, Sysno::read, &[r, OUT, 10]), ok(0));
    assert_eq!(
        call(&mut t, Sysno::creat, &[BAD, 0o600]),
        err(Errno::EFAULT)
    );
    // A directory cannot be opened for writing.
    let dir = cstr(&mut t, PATH2, "/");
    assert_eq!(call(&mut t, Sysno::creat, &[dir, 0]), err(Errno::EISDIR));
}

#[test]
fn fadvise64_validates_like_generic_fadvise() {
    let mut t = t();
    let f = filled(&mut t, "/f", b"data");
    // The six POSIX values are accepted and ignored (tmpfs: noop backing device).
    for advice in 0..=5u64 {
        assert_eq!(call(&mut t, Sysno::fadvise64, &[f, 0, 0, advice]), ok(0));
    }
    assert_eq!(
        call(&mut t, Sysno::fadvise64, &[f, 0, 0, 6]),
        err(Errno::EINVAL)
    );
    assert_eq!(
        call(&mut t, Sysno::fadvise64, &[f, 0, 0, u64::MAX]),
        err(Errno::EINVAL)
    );
    // `size_t len` as `loff_t`: a negative length.
    assert_eq!(
        call(&mut t, Sysno::fadvise64, &[f, 0, 1 << 63, 0]),
        err(Errno::EINVAL)
    );
    assert_eq!(
        call(&mut t, Sysno::fadvise64, &[99, 0, 0, 0]),
        err(Errno::EBADF)
    );
    let dir = fd(open(&mut t, "/", O_RDONLY | O_DIRECTORY, 0));
    assert_eq!(call(&mut t, Sysno::fadvise64, &[dir, 0, 0, 3]), ok(0));
    let (r, _) = pipe(&mut t, 0);
    assert_eq!(
        call(&mut t, Sysno::fadvise64, &[r, 0, 0, 0]),
        err(Errno::ESPIPE)
    );
}

#[test]
fn splice_checks_in_order_then_moves_a_file_into_a_pipe() {
    let mut t = t();
    let data: Vec<u8> = (0..6000u32).map(|i| (i % 251) as u8).collect();
    let f = filled(&mut t, "/s", &data);
    let (r, w) = pipe(&mut t, 0);
    // A zero length is 0 before anything is looked at; unknown flags before the descriptors.
    assert_eq!(call(&mut t, Sysno::splice, &[99, 0, 98, 0, 0, 0]), ok(0));
    assert_eq!(
        call(&mut t, Sysno::splice, &[99, 0, 98, 0, 1, 0x10]),
        err(Errno::EINVAL)
    );
    assert_eq!(
        call(&mut t, Sysno::splice, &[99, 0, w, 0, 1, 0]),
        err(Errno::EBADF)
    );
    assert_eq!(
        call(&mut t, Sysno::splice, &[f, 0, 98, 0, 1, 0]),
        err(Errno::EBADF)
    );
    // An offset for a pipe, two non-pipes, a pipe into itself.
    assert_eq!(
        call(&mut t, Sysno::splice, &[f, 0, w, OUT + 8, 1, 0]),
        err(Errno::ESPIPE)
    );
    assert_eq!(
        call(&mut t, Sysno::splice, &[r, OUT + 8, f, 0, 1, 0]),
        err(Errno::ESPIPE)
    );
    let other = fd(open(&mut t, "/o", O_CREAT | O_RDWR, 0o644));
    assert_eq!(
        call(&mut t, Sysno::splice, &[f, 0, other, 0, 1, 0]),
        err(Errno::EINVAL)
    );
    assert_eq!(
        call(&mut t, Sysno::splice, &[r, 0, w, 0, 1, 0]),
        err(Errno::EINVAL),
        "one pipe"
    );
    assert_eq!(
        call(&mut t, Sysno::splice, &[w, 0, r, 0, 1, 0]),
        err(Errno::EBADF),
        "not readable"
    );
    // The offset pointers are read before the modes are checked.
    assert_eq!(
        call(&mut t, Sysno::splice, &[f, BAD, w, 0, 1, 0]),
        err(Errno::EFAULT)
    );
    // File to pipe: from the file position, which moves.
    assert_eq!(
        call(&mut t, Sysno::splice, &[f, 0, w, 0, 1000, 0]),
        ok(1000)
    );
    assert_eq!(call(&mut t, Sysno::lseek, &[f, 0, 1]), ok(1000));
    assert_eq!(queued(&mut t, r), 1000);
    // With an offset: the position stays, the offset is stored back.
    put(&mut t, OUT + 8, &2000i64.to_le_bytes());
    assert_eq!(
        call(&mut t, Sysno::splice, &[f, OUT + 8, w, 0, 500, 0]),
        ok(500)
    );
    assert_eq!(get(&mut t, OUT + 8, 8), 2500i64.to_le_bytes());
    assert_eq!(call(&mut t, Sysno::lseek, &[f, 0, 1]), ok(1000));
    // The pipe holds what was spliced, in order.
    assert_eq!(call(&mut t, Sysno::read, &[r, 0x4000, 1500]), ok(1500));
    let got = get(&mut t, 0x4000, 1500);
    assert_eq!(got[..1000], data[..1000]);
    assert_eq!(got[1000..], data[2000..2500]);
    // A negative offset is refused.
    put(&mut t, OUT + 8, &(-1i64).to_le_bytes());
    assert_eq!(
        call(&mut t, Sysno::splice, &[f, OUT + 8, w, 0, 1, 0]),
        err(Errno::EINVAL)
    );
    // At the end of the file: 0.
    assert_eq!(call(&mut t, Sysno::lseek, &[f, 0, 2]), ok(6000));
    assert_eq!(call(&mut t, Sysno::splice, &[f, 0, w, 0, 100, 0]), ok(0));
}

#[test]
fn splice_moves_buffers_between_pipes_and_drains_a_pipe_into_a_file() {
    let mut t = t();
    let (r1, w1) = pipe(&mut t, 0);
    let (r2, w2) = pipe(&mut t, 0);
    put(&mut t, BUF, b"0123456789");
    assert_eq!(call(&mut t, Sysno::write, &[w1, BUF, 10]), ok(10));
    // Pipe to pipe: the whole buffer, then a part of the next.
    assert_eq!(call(&mut t, Sysno::splice, &[r1, 0, w2, 0, 100, 0]), ok(10));
    assert_eq!((queued(&mut t, r1), queued(&mut t, r2)), (0, 10));
    assert_eq!(call(&mut t, Sysno::write, &[w1, BUF, 10]), ok(10));
    assert_eq!(call(&mut t, Sysno::splice, &[r1, 0, w2, 0, 4, 0]), ok(4));
    assert_eq!((queued(&mut t, r1), queued(&mut t, r2)), (6, 14));
    // Empty input with a writer left: non-blocking is EAGAIN; no writer left: end of file.
    assert_eq!(call(&mut t, Sysno::splice, &[r1, 0, w2, 0, 100, 0]), ok(6));
    assert_eq!(
        call(&mut t, Sysno::splice, &[r1, 0, w2, 0, 100, 2]),
        err(Errno::EAGAIN)
    );
    assert_eq!(call(&mut t, Sysno::close, &[w1]), ok(0));
    assert_eq!(call(&mut t, Sysno::splice, &[r1, 0, w2, 0, 100, 0]), ok(0));
    // The same pipe is EINVAL.
    assert_eq!(
        call(&mut t, Sysno::splice, &[r2, 0, w2, 0, 1, 0]),
        err(Errno::EINVAL)
    );
    // Pipe to file: written at the file position (which moves) or at an offset.
    let f = fd(open(&mut t, "/out", O_CREAT | O_RDWR, 0o644));
    assert_eq!(call(&mut t, Sysno::splice, &[r2, 0, f, 0, 5, 0]), ok(5));
    assert_eq!(call(&mut t, Sysno::lseek, &[f, 0, 1]), ok(5));
    put(&mut t, OUT + 8, &100i64.to_le_bytes());
    assert_eq!(
        call(&mut t, Sysno::splice, &[r2, 0, f, OUT + 8, 100, 0]),
        ok(20 - 5)
    );
    assert_eq!(u32_at(&mut t, OUT + 8), 115);
    assert_eq!(call(&mut t, Sysno::pread64, &[f, 0x4000, 5, 100]), ok(5));
    // Into a read-only description, an append-only file, a closed writer's pipe.
    let ro = fd(open(&mut t, "/out", O_RDONLY, 0));
    assert_eq!(
        call(&mut t, Sysno::splice, &[r2, 0, ro, 0, 1, 0]),
        err(Errno::EBADF)
    );
    let ap = fd(open(&mut t, "/out", O_WRONLY | O_APPEND, 0));
    assert_eq!(
        call(&mut t, Sysno::splice, &[r2, 0, ap, 0, 1, 0]),
        err(Errno::EINVAL)
    );
    assert_eq!(call(&mut t, Sysno::close, &[r2]), ok(0));
    let (r3, w3) = pipe(&mut t, 0);
    assert_eq!(call(&mut t, Sysno::write, &[w3, BUF, 3]), ok(3));
    assert_eq!(
        call(&mut t, Sysno::splice, &[r3, 0, w2, 0, 3, 0]),
        err(Errno::EPIPE)
    );
    let _ = r3;
}

#[test]
fn vmsplice_copies_user_segments_into_and_out_of_a_pipe() {
    let mut t = t();
    let (r, w) = pipe(&mut t, 0);
    put(&mut t, BUF, b"abcdefghij");
    let iov = 0x4000;
    put(&mut t, iov, &BUF.to_le_bytes());
    put(&mut t, iov + 8, &4u64.to_le_bytes());
    put(&mut t, iov + 16, &(BUF + 6).to_le_bytes());
    put(&mut t, iov + 24, &4u64.to_le_bytes());
    assert_eq!(call(&mut t, Sysno::vmsplice, &[w, iov, 2, 0]), ok(8));
    assert_eq!(queued(&mut t, r), 8);
    // Out again: the read end gets the bytes in the user vector.
    let out = 0x4100;
    put(&mut t, out, &(OUT + 128).to_le_bytes());
    put(&mut t, out + 8, &100u64.to_le_bytes());
    assert_eq!(call(&mut t, Sysno::vmsplice, &[r, out, 1, 0]), ok(8));
    assert_eq!(get(&mut t, OUT + 128, 8), b"abcdghij");
    // Errors: flags, descriptor, kind, vector.
    assert_eq!(
        call(&mut t, Sysno::vmsplice, &[w, iov, 2, 0x10]),
        err(Errno::EINVAL)
    );
    assert_eq!(
        call(&mut t, Sysno::vmsplice, &[99, iov, 2, 0]),
        err(Errno::EBADF)
    );
    let f = fd(open(&mut t, "/v", O_CREAT | O_RDWR, 0o644));
    assert_eq!(
        call(&mut t, Sysno::vmsplice, &[f, iov, 2, 0]),
        err(Errno::EBADF)
    );
    assert_eq!(
        call(&mut t, Sysno::vmsplice, &[w, iov, 1025, 0]),
        err(Errno::EINVAL)
    );
    assert_eq!(
        call(&mut t, Sysno::vmsplice, &[w, BAD, 1, 0]),
        err(Errno::EFAULT)
    );
    assert_eq!(call(&mut t, Sysno::vmsplice, &[w, iov, 0, 0]), ok(0));
    // The second segment cannot be read: the first is still spliced.
    put(&mut t, iov + 16, &BAD.to_le_bytes());
    assert_eq!(call(&mut t, Sysno::vmsplice, &[w, iov, 2, 0]), ok(4));
    put(&mut t, iov, &BAD.to_le_bytes());
    assert_eq!(
        call(&mut t, Sysno::vmsplice, &[w, iov, 1, 0]),
        err(Errno::EFAULT)
    );
    // Reading an empty pipe without a writer: 0; with one and O_NONBLOCK semantics: EAGAIN.
    let (r2, w2) = pipe(&mut t, 0);
    assert_eq!(
        call(&mut t, Sysno::vmsplice, &[r2, out, 1, 2]),
        err(Errno::EAGAIN)
    );
    assert_eq!(call(&mut t, Sysno::close, &[w2]), ok(0));
    assert_eq!(call(&mut t, Sysno::vmsplice, &[r2, out, 1, 0]), ok(0));
}

#[test]
fn copy_file_range_copies_within_the_file_system() {
    let mut t = t();
    let data: Vec<u8> = (0..5000u32).map(|i| (i % 253) as u8).collect();
    let src = filled(&mut t, "/a", &data);
    let dst = fd(open(&mut t, "/b", O_CREAT | O_RDWR, 0o644));
    // Both positions move, the result is what was copied.
    assert_eq!(
        call(&mut t, Sysno::copy_file_range, &[src, 0, dst, 0, 3000, 0]),
        ok(3000)
    );
    assert_eq!(call(&mut t, Sysno::lseek, &[src, 0, 1]), ok(3000));
    assert_eq!(call(&mut t, Sysno::lseek, &[dst, 0, 1]), ok(3000));
    // The rest, then end of file.
    assert_eq!(
        call(&mut t, Sysno::copy_file_range, &[src, 0, dst, 0, 3000, 0]),
        ok(2000)
    );
    assert_eq!(
        call(&mut t, Sysno::copy_file_range, &[src, 0, dst, 0, 3000, 0]),
        ok(0)
    );
    assert_eq!(
        call(&mut t, Sysno::pread64, &[dst, 0x4000, 16, 4990]),
        ok(10)
    );
    assert_eq!(get(&mut t, 0x4000, 10), data[4990..5000]);
    // Offsets are read and written back; the positions stay.
    put(&mut t, OUT + 8, &100i64.to_le_bytes());
    put(&mut t, OUT + 16, &9000i64.to_le_bytes());
    assert_eq!(
        call(
            &mut t,
            Sysno::copy_file_range,
            &[src, OUT + 8, dst, OUT + 16, 50, 0]
        ),
        ok(50)
    );
    assert_eq!(get(&mut t, OUT + 8, 8), 150i64.to_le_bytes());
    assert_eq!(get(&mut t, OUT + 16, 8), 9050i64.to_le_bytes());
    assert_eq!(call(&mut t, Sysno::lseek, &[src, 0, 1]), ok(5000));
    // Errors: descriptors, flags, kinds, overlap, overflow.
    assert_eq!(
        call(&mut t, Sysno::copy_file_range, &[99, 0, dst, 0, 1, 0]),
        err(Errno::EBADF)
    );
    assert_eq!(
        call(&mut t, Sysno::copy_file_range, &[src, 0, 99, 0, 1, 0]),
        err(Errno::EBADF)
    );
    assert_eq!(
        call(&mut t, Sysno::copy_file_range, &[src, BAD, dst, 0, 1, 0]),
        err(Errno::EFAULT)
    );
    assert_eq!(
        call(&mut t, Sysno::copy_file_range, &[src, 0, dst, 0, 1, 1]),
        err(Errno::EINVAL)
    );
    let dir = fd(open(&mut t, "/", O_RDONLY | O_DIRECTORY, 0));
    assert_eq!(
        call(&mut t, Sysno::copy_file_range, &[dir, 0, dst, 0, 1, 0]),
        err(Errno::EISDIR)
    );
    let (r, w) = pipe(&mut t, 0);
    assert_eq!(
        call(&mut t, Sysno::copy_file_range, &[src, 0, w, 0, 1, 0]),
        err(Errno::EINVAL)
    );
    let _ = r;
    let ro = fd(open(&mut t, "/b", O_RDONLY, 0));
    assert_eq!(
        call(&mut t, Sysno::copy_file_range, &[src, 0, ro, 0, 1, 0]),
        err(Errno::EBADF)
    );
    let ap = fd(open(&mut t, "/b", O_WRONLY | O_APPEND, 0));
    assert_eq!(
        call(&mut t, Sysno::copy_file_range, &[src, 0, ap, 0, 1, 0]),
        err(Errno::EBADF)
    );
    put(&mut t, OUT + 8, &0i64.to_le_bytes());
    put(&mut t, OUT + 16, &100i64.to_le_bytes());
    assert_eq!(
        call(
            &mut t,
            Sysno::copy_file_range,
            &[src, OUT + 8, src, OUT + 16, 200, 0]
        ),
        err(Errno::EINVAL),
        "overlapping ranges of one file"
    );
    // `pos + count < pos` is evaluated unsigned: -1 wraps, a large positive offset does not.
    put(&mut t, OUT + 16, &(-1i64).to_le_bytes());
    assert_eq!(
        call(
            &mut t,
            Sysno::copy_file_range,
            &[src, OUT + 8, dst, OUT + 16, 100, 0]
        ),
        err(Errno::EOVERFLOW)
    );
}

#[test]
fn file_clone_ioctls_fail_where_the_file_system_cannot_clone() {
    let mut t = t();
    let a = filled(&mut t, "/a", b"abc");
    let b = fd(open(&mut t, "/b", O_CREAT | O_RDWR, 0o644));
    // A bad source, then the generic checks, then tmpfs has no ->remap_file_range.
    assert_eq!(
        call(&mut t, Sysno::ioctl, &[b, FICLONE, 99]),
        err(Errno::EBADF)
    );
    assert_eq!(
        call(&mut t, Sysno::ioctl, &[b, FICLONE, a]),
        err(Errno::EOPNOTSUPP)
    );
    let dir = fd(open(&mut t, "/", O_RDONLY | O_DIRECTORY, 0));
    assert_eq!(
        call(&mut t, Sysno::ioctl, &[b, FICLONE, dir]),
        err(Errno::EISDIR)
    );
    let (r, _w) = pipe(&mut t, 0);
    assert_eq!(
        call(&mut t, Sysno::ioctl, &[b, FICLONE, r]),
        err(Errno::EXDEV)
    );
    let ro = fd(open(&mut t, "/b", O_RDONLY, 0));
    assert_eq!(
        call(&mut t, Sysno::ioctl, &[ro, FICLONE, a]),
        err(Errno::EBADF)
    );
    // FICLONERANGE reads its structure first.
    assert_eq!(
        call(&mut t, Sysno::ioctl, &[b, FICLONERANGE, BAD]),
        err(Errno::EFAULT)
    );
    put(&mut t, OUT, &(a as i64).to_le_bytes());
    put(&mut t, OUT + 8, &[0; 24]);
    assert_eq!(
        call(&mut t, Sysno::ioctl, &[b, FICLONERANGE, OUT]),
        err(Errno::EOPNOTSUPP)
    );
}

#[test]
fn extended_attributes_of_tmpfs_are_empty_and_named_like_linux() {
    let mut t = t();
    let f = filled(&mut t, "/x", b"x");
    let path = cstr(&mut t, PATH, "/x");
    let name = |t: &mut Task, text: &str| cstr(t, PATH2, text);
    // Listing: nothing, whatever the buffer; the three forms; a bad path or descriptor.
    assert_eq!(call(&mut t, Sysno::listxattr, &[path, 0, 0]), ok(0));
    assert_eq!(call(&mut t, Sysno::llistxattr, &[path, OUT, 100]), ok(0));
    assert_eq!(call(&mut t, Sysno::flistxattr, &[f, BAD, 100]), ok(0));
    assert_eq!(
        call(&mut t, Sysno::flistxattr, &[99, OUT, 100]),
        err(Errno::EBADF)
    );
    assert_eq!(
        call(&mut t, Sysno::listxattr, &[BAD, OUT, 1]),
        err(Errno::EFAULT)
    );
    let missing = cstr(&mut t, PATH + 0x100, "/nothing");
    assert_eq!(
        call(&mut t, Sysno::listxattr, &[missing, OUT, 1]),
        err(Errno::ENOENT)
    );
    // Getting: the name is imported first (EFAULT, ERANGE), the target next, then the namespace.
    assert_eq!(
        call(&mut t, Sysno::getxattr, &[path, BAD, OUT, 10]),
        err(Errno::EFAULT)
    );
    let empty = name(&mut t, "");
    assert_eq!(
        call(&mut t, Sysno::getxattr, &[path, empty, OUT, 10]),
        err(Errno::ERANGE)
    );
    let long = std::format!("user.{}", "a".repeat(251));
    let l = name(&mut t, &long);
    assert_eq!(
        call(&mut t, Sysno::getxattr, &[path, l, OUT, 10]),
        err(Errno::ERANGE)
    );
    let n = name(&mut t, "user.k");
    assert_eq!(
        call(&mut t, Sysno::getxattr, &[missing, n, OUT, 10]),
        err(Errno::ENOENT)
    );
    assert_eq!(
        call(&mut t, Sysno::getxattr, &[path, n, OUT, 10]),
        err(Errno::ENODATA)
    );
    assert_eq!(
        call(&mut t, Sysno::lgetxattr, &[path, n, OUT, 0]),
        err(Errno::ENODATA)
    );
    assert_eq!(
        call(&mut t, Sysno::fgetxattr, &[f, n, OUT, 10]),
        err(Errno::ENODATA)
    );
    assert_eq!(
        call(&mut t, Sysno::fgetxattr, &[99, n, OUT, 10]),
        err(Errno::EBADF)
    );
    for (text, want) in [
        ("security.selinux", Errno::ENODATA),
        ("trusted.k", Errno::ENODATA),
        ("system.posix_acl_access", Errno::ENODATA),
        ("system.posix_acl_default", Errno::ENODATA),
        ("system.other", Errno::EOPNOTSUPP),
        ("foo.bar", Errno::EOPNOTSUPP),
        ("user.", Errno::EINVAL),
        ("security.", Errno::EINVAL),
    ] {
        let n = name(&mut t, text);
        assert_eq!(
            call(&mut t, Sysno::getxattr, &[path, n, OUT, 10]),
            err(want),
            "{text}"
        );
    }
    // `user.` on a device node: ENODATA to read, EPERM to write (`xattr_permission`).
    let console = cstr(&mut t, PATH + 0x200, "/dev/console");
    let n = name(&mut t, "user.k");
    assert_eq!(
        call(&mut t, Sysno::getxattr, &[console, n, OUT, 10]),
        err(Errno::ENODATA)
    );
    assert_eq!(
        call(&mut t, Sysno::removexattr, &[console, n]),
        err(Errno::EPERM)
    );
    assert_eq!(
        call(&mut t, Sysno::setxattr, &[console, n, OUT, 1, 0]),
        err(Errno::EPERM)
    );
    let sec = name(&mut t, "security.k");
    assert_eq!(
        call(&mut t, Sysno::getxattr, &[console, sec, OUT, 10]),
        err(Errno::ENODATA)
    );
    // Removing: ENODATA where there is nothing, the same name rules.
    let n = name(&mut t, "user.k");
    assert_eq!(
        call(&mut t, Sysno::removexattr, &[path, n]),
        err(Errno::ENODATA)
    );
    assert_eq!(
        call(&mut t, Sysno::fremovexattr, &[f, n]),
        err(Errno::ENODATA)
    );
    let bad = name(&mut t, "foo.bar");
    assert_eq!(
        call(&mut t, Sysno::removexattr, &[path, bad]),
        err(Errno::EOPNOTSUPP)
    );
    // Setting: flags first, then the name, the size, the value, the target.
    let n = name(&mut t, "user.k");
    assert_eq!(
        call(&mut t, Sysno::setxattr, &[path, n, OUT, 1, 4]),
        err(Errno::EINVAL)
    );
    assert_eq!(
        call(&mut t, Sysno::setxattr, &[path, n, OUT, 70_000, 0]),
        err(Errno::E2BIG)
    );
    assert_eq!(
        call(&mut t, Sysno::setxattr, &[path, n, BAD, 1, 0]),
        err(Errno::EFAULT)
    );
    assert_eq!(
        call(&mut t, Sysno::setxattr, &[path, n, OUT, 1, 2]),
        err(Errno::ENODATA),
        "XATTR_REPLACE of an attribute that is not there"
    );
    // Creating one needs the store, which is not ported: a loud stop, not an answer.
    assert_eq!(
        call(&mut t, Sysno::setxattr, &[path, n, OUT, 1, 0]),
        Outcome::Unimplemented(Sysno::setxattr as u32)
    );
    // The `*at` forms: unknown flags, the descriptor form with an empty path.
    let empty_path = cstr(&mut t, PATH, "");
    assert_eq!(
        call(&mut t, Sysno::listxattrat, &[f, empty_path, 0x1000, OUT, 1]),
        ok(0),
        "AT_EMPTY_PATH names the descriptor"
    );
    assert_eq!(
        call(&mut t, Sysno::listxattrat, &[f, empty_path, 0x200, OUT, 1]),
        err(Errno::EINVAL),
        "AT_REMOVEDIR is not an xattr flag"
    );
    assert_eq!(
        call(&mut t, Sysno::listxattrat, &[f, empty_path, 0, OUT, 1]),
        err(Errno::ENOENT),
        "an empty path without AT_EMPTY_PATH"
    );
    // The symlink: ACL names are EOPNOTSUPP on it, `user.` is ENODATA.
    let target = cstr(&mut t, PATH2, "/x");
    let link = cstr(&mut t, PATH, "/l");
    assert_eq!(call(&mut t, Sysno::symlink, &[target, link]), ok(0));
    let acl = name(&mut t, "system.posix_acl_access");
    assert_eq!(
        call(&mut t, Sysno::lgetxattr, &[link, acl, OUT, 10]),
        err(Errno::EOPNOTSUPP)
    );
    assert_eq!(
        call(&mut t, Sysno::getxattr, &[link, acl, OUT, 10]),
        err(Errno::ENODATA),
        "followed"
    );
    let user = name(&mut t, "user.k");
    assert_eq!(
        call(&mut t, Sysno::lgetxattr, &[link, user, OUT, 10]),
        err(Errno::ENODATA)
    );
}

#[test]
fn socket_name_calls_say_not_a_socket() {
    let mut t = t();
    let f = filled(&mut t, "/n", b"n");
    let (r, _) = pipe(&mut t, 0);
    for sysno in [Sysno::getsockname, Sysno::getpeername] {
        assert_eq!(
            call(&mut t, sysno, &[f, OUT, OUT + 64]),
            err(Errno::ENOTSOCK)
        );
        assert_eq!(call(&mut t, sysno, &[r, 0, 0]), err(Errno::ENOTSOCK));
        assert_eq!(call(&mut t, sysno, &[99, OUT, OUT + 64]), err(Errno::EBADF));
        // `int fd`: the upper half of the register is ignored.
        assert_eq!(
            call(&mut t, sysno, &[(1 << 32) | f, 0, 0]),
            err(Errno::ENOTSOCK)
        );
    }
}
