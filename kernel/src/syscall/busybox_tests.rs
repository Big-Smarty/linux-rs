// SPDX-License-Identifier: GPL-2.0-only
//! Host tests of the syscalls the `busybox` lane added, through [`super::dispatch`] on the real
//! tmpfs rootfs of `testing::Task`: argument decoding, error precedence, user-memory faults and
//! the loud stops. The differential evidence is the `busybox` oracle group.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::too_many_lines,
    clippy::many_single_char_names,
    clippy::similar_names
)]

extern crate std;

use super::vfs_tests::{BAD, BUF, OUT, call, err, fd, get, ok, open, put, t, u32_at};
use crate::vfs::{O_CREAT, O_RDONLY, O_RDWR};
extern crate alloc;
use alloc::vec;
use syscalls::{Errno, Sysno};

/// Writes `iovecs` (base, len) at `at` as `struct iovec[]`.
fn iovecs(t: &mut super::testing::Task, at: u64, list: &[(u64, u64)]) {
    for (i, (base, len)) in list.iter().enumerate() {
        put(t, at + 16 * i as u64, &base.to_le_bytes());
        put(t, at + 16 * i as u64 + 8, &len.to_le_bytes());
    }
}

#[test]
fn writev_gathers_segments_and_keeps_linux_error_order() {
    let mut t = t();
    let f = fd(open(&mut t, "/w", O_CREAT | O_RDWR, 0o644));
    put(&mut t, BUF, b"hello world, gathered");
    let vec = 0x4000;
    iovecs(
        &mut t,
        vec,
        &[(BUF, 5), (BUF + 5, 0), (BUF + 6, 5), (BUF + 11, 10)],
    );
    assert_eq!(call(&mut t, Sysno::writev, &[f, vec, 4]), ok(20));
    assert_eq!(call(&mut t, Sysno::lseek, &[f, 0, 0]), ok(0));
    assert_eq!(call(&mut t, Sysno::read, &[f, OUT, 100]), ok(20));
    assert_eq!(get(&mut t, OUT, 20), b"helloworld, gathered");
    // pwritev at an offset leaves the file position alone.
    iovecs(&mut t, vec, &[(BUF, 2), (BUF + 6, 2)]);
    assert_eq!(call(&mut t, Sysno::lseek, &[f, 3, 0]), ok(3));
    assert_eq!(call(&mut t, Sysno::pwritev, &[f, vec, 2, 0]), ok(4));
    assert_eq!(call(&mut t, Sysno::lseek, &[f, 0, 1]), ok(3));
    assert_eq!(call(&mut t, Sysno::pread64, &[f, OUT, 6, 0]), ok(6));
    assert_eq!(get(&mut t, OUT, 6), b"hewoow");
    // Errors: descriptor first, then the mode, then the vector.
    assert_eq!(
        call(&mut t, Sysno::writev, &[99, vec, 1]),
        err(Errno::EBADF)
    );
    let ro = fd(open(&mut t, "/w", O_RDONLY, 0));
    assert_eq!(
        call(&mut t, Sysno::writev, &[ro, BAD, 1]),
        err(Errno::EBADF)
    );
    assert_eq!(
        call(&mut t, Sysno::writev, &[f, vec, 1025]),
        err(Errno::EINVAL)
    );
    assert_eq!(
        call(&mut t, Sysno::writev, &[f, BAD, 1]),
        err(Errno::EFAULT)
    );
    iovecs(&mut t, vec, &[(BAD, 1)]);
    // The segment is mapped nowhere: access_ok passes, the copy faults at once.
    assert_eq!(
        call(&mut t, Sysno::writev, &[f, vec, 1]),
        err(Errno::EFAULT)
    );
    iovecs(&mut t, vec, &[(u64::MAX - 3, 8)]);
    assert_eq!(
        call(&mut t, Sysno::writev, &[f, vec, 1]),
        err(Errno::EFAULT)
    );
    // No segments, or only empty ones: 0, before any position check.
    assert_eq!(call(&mut t, Sysno::writev, &[f, BAD, 0]), ok(0));
    iovecs(&mut t, vec, &[(BUF, 0)]);
    assert_eq!(call(&mut t, Sysno::writev, &[f, vec, 1]), ok(0));
    assert_eq!(
        call(&mut t, Sysno::pwritev, &[f, vec, 1, (-1i64) as u64]),
        err(Errno::EINVAL)
    );
    // A fault after a first good segment reports the bytes before it.
    iovecs(&mut t, vec, &[(BUF, 3), (BAD, 4)]);
    assert_eq!(call(&mut t, Sysno::lseek, &[f, 0, 2]), ok(20));
    assert_eq!(call(&mut t, Sysno::writev, &[f, vec, 2]), ok(3));
}

#[test]
fn writev_to_a_pipe_and_the_console_and_pwritev_on_a_stream() {
    let mut t = t();
    assert_eq!(call(&mut t, Sysno::pipe2, &[OUT, 0]), ok(0));
    let (r, w) = (
        u64::from(u32_at(&mut t, OUT)),
        u64::from(u32_at(&mut t, OUT + 4)),
    );
    put(&mut t, BUF, b"abcdefgh");
    let vec = 0x4000;
    iovecs(&mut t, vec, &[(BUF + 4, 4), (BUF, 4)]);
    assert_eq!(call(&mut t, Sysno::writev, &[w, vec, 2]), ok(8));
    assert_eq!(call(&mut t, Sysno::read, &[r, 0x3800, 100]), ok(8));
    assert_eq!(get(&mut t, 0x3800, 8), b"efghabcd");
    // A pipe has no positions: pwritev is ESPIPE.
    assert_eq!(
        call(&mut t, Sysno::pwritev, &[w, vec, 2, 0]),
        err(Errno::ESPIPE)
    );
    // A read end cannot be written.
    assert_eq!(call(&mut t, Sysno::writev, &[r, vec, 2]), err(Errno::EBADF));
    // The console: segments are one stream of 2048 byte chunks; ONLCR applies.
    put(&mut t, BUF, b"a\nb");
    iovecs(&mut t, vec, &[(BUF, 2), (BUF + 2, 1)]);
    assert_eq!(call(&mut t, Sysno::writev, &[1, vec, 2]), ok(3));
    assert_eq!(t.sink.0, b"a\r\nb");
}

// ---- names: mkdir, rmdir, unlinkat, symlink, link, rename -------------------------------------

use super::vfs_tests::{PATH, PATH2, cstr, u64_at};
use crate::vfs::{AT_FDCWD, O_APPEND, O_DIRECTORY, O_NONBLOCK, O_WRONLY};

fn path2(t: &mut super::testing::Task, sysno: Sysno, a: &str, b: &str) -> super::Outcome {
    let (a, b) = (cstr(t, PATH, a), cstr(t, PATH2, b));
    call(t, sysno, &[a, b])
}

fn path1(t: &mut super::testing::Task, sysno: Sysno, a: &str, rest: &[u64]) -> super::Outcome {
    let a = cstr(t, PATH, a);
    let mut args = vec![a];
    args.extend_from_slice(rest);
    call(t, sysno, &args)
}

/// `(st_mode, st_nlink, st_size, st_uid, st_gid)` of `path` (follow) or `Err`.
fn stat_of(
    t: &mut super::testing::Task,
    path: &str,
    follow: bool,
) -> Result<(u32, u64, u64, u32, u32), super::Outcome> {
    let at = cstr(t, PATH, path);
    let sysno = if follow { Sysno::stat } else { Sysno::lstat };
    match call(t, sysno, &[at, OUT]) {
        super::Outcome::Return(0) => Ok((
            u32_at(t, OUT + 24),
            u64_at(t, OUT + 16),
            u64_at(t, OUT + 48),
            u32_at(t, OUT + 28),
            u32_at(t, OUT + 32),
        )),
        other => Err(other),
    }
}

#[test]
fn mkdir_rmdir_unlinkat_follow_linux_order() {
    let mut t = t();
    assert_eq!(path1(&mut t, Sysno::mkdir, "/d", &[0o777]), ok(0));
    // Linux's default umask 022 applies; the high bits of a umode_t are cut.
    assert_eq!(stat_of(&mut t, "/d", true).unwrap().0, 0o040_755);
    assert_eq!(
        path1(&mut t, Sysno::mkdir, "/d", &[0o777]),
        err(Errno::EEXIST)
    );
    assert_eq!(
        path1(&mut t, Sysno::mkdir, "/x/y", &[0o777]),
        err(Errno::ENOENT)
    );
    assert_eq!(path1(&mut t, Sysno::mkdir, "", &[0]), err(Errno::ENOENT));
    assert_eq!(
        path1(&mut t, Sysno::mkdir, "/d/", &[0]),
        err(Errno::EEXIST),
        "a trailing slash does not hide the entry"
    );
    assert_eq!(path1(&mut t, Sysno::mkdir, "/e/", &[0o1_0700]), ok(0));
    assert_eq!(stat_of(&mut t, "/e", true).unwrap().0, 0o040_700);
    // mkdirat relative to a descriptor.
    let dir = fd(open(&mut t, "/d", O_RDONLY | O_DIRECTORY, 0));
    let name = cstr(&mut t, PATH2, "sub");
    assert_eq!(call(&mut t, Sysno::mkdirat, &[dir, name, 0o755]), ok(0));
    assert_eq!(stat_of(&mut t, "/d/sub", true).unwrap().1, 2);
    assert_eq!(stat_of(&mut t, "/d", true).unwrap().1, 3, "the new `..`");
    let file = fd(open(&mut t, "/f", O_CREAT | O_WRONLY, 0o644));
    assert_eq!(
        call(&mut t, Sysno::mkdirat, &[file, name, 0o755]),
        err(Errno::ENOTDIR)
    );
    assert_eq!(
        call(&mut t, Sysno::mkdirat, &[99, name, 0o755]),
        err(Errno::EBADF)
    );
    assert_eq!(
        call(&mut t, Sysno::mkdirat, &[(AT_FDCWD as i64) as u64, BAD, 0]),
        err(Errno::EFAULT)
    );
    // rmdir
    assert_eq!(
        path1(&mut t, Sysno::rmdir, "/d", &[]),
        err(Errno::ENOTEMPTY)
    );
    assert_eq!(path1(&mut t, Sysno::rmdir, "/f", &[]), err(Errno::ENOTDIR));
    assert_eq!(path1(&mut t, Sysno::rmdir, "/d/.", &[]), err(Errno::EINVAL));
    assert_eq!(
        path1(&mut t, Sysno::rmdir, "/d/sub/..", &[]),
        err(Errno::ENOTEMPTY)
    );
    assert_eq!(path1(&mut t, Sysno::rmdir, "/", &[]), err(Errno::EBUSY));
    assert_eq!(
        path1(&mut t, Sysno::rmdir, "/none", &[]),
        err(Errno::ENOENT)
    );
    assert_eq!(path1(&mut t, Sysno::rmdir, "/d/sub", &[]), ok(0));
    assert_eq!(stat_of(&mut t, "/d", true).unwrap().1, 2);
    // unlinkat: AT_REMOVEDIR (0x200) is the only flag, checked before the name is read.
    let d = cstr(&mut t, PATH, "d");
    let root = (AT_FDCWD as i64) as u64;
    assert_eq!(
        call(&mut t, Sysno::unlinkat, &[root, BAD, 1]),
        err(Errno::EINVAL)
    );
    assert_eq!(
        call(&mut t, Sysno::unlinkat, &[root, d, 0]),
        err(Errno::EISDIR)
    );
    assert_eq!(call(&mut t, Sysno::unlinkat, &[root, d, 0x200]), ok(0));
    let f = cstr(&mut t, PATH, "f");
    assert_eq!(
        call(&mut t, Sysno::unlinkat, &[root, f, 0x200]),
        err(Errno::ENOTDIR)
    );
    assert_eq!(call(&mut t, Sysno::unlinkat, &[root, f, 0]), ok(0));
    assert_eq!(
        call(&mut t, Sysno::unlinkat, &[root, f, 0]),
        err(Errno::ENOENT)
    );
    // The removed directory is gone for walks through a descriptor to it.
    assert_eq!(
        call(&mut t, Sysno::mkdirat, &[dir, name, 0o755]),
        err(Errno::ENOENT)
    );
}

#[test]
fn symlink_link_and_their_errors() {
    let mut t = t();
    assert_eq!(path2(&mut t, Sysno::symlink, "target", "/s"), ok(0));
    let (mode, nlink, size, ..) = stat_of(&mut t, "/s", false).unwrap();
    assert_eq!((mode, nlink, size), (0o120_777, 1, 6));
    assert_eq!(
        path2(&mut t, Sysno::symlink, "target", "/s"),
        err(Errno::EEXIST)
    );
    assert_eq!(
        path2(&mut t, Sysno::symlink, "", "/s2"),
        err(Errno::ENOENT),
        "the target is read like any name: empty is ENOENT"
    );
    assert_eq!(
        path2(&mut t, Sysno::symlink, "x", "/nodir/s"),
        err(Errno::ENOENT)
    );
    // The target string is stored verbatim.
    assert_eq!(path1(&mut t, Sysno::readlink, "/s", &[OUT, 100]), ok(6));
    assert_eq!(get(&mut t, OUT, 6), b"target");
    // link: counts, directory EPERM, EEXIST, ENOENT in lookup-then-create order.
    let f = fd(open(&mut t, "/f", O_CREAT | O_WRONLY, 0o644));
    assert_eq!(path2(&mut t, Sysno::link, "/f", "/g"), ok(0));
    assert_eq!(stat_of(&mut t, "/f", true).unwrap().1, 2);
    assert_eq!(path2(&mut t, Sysno::link, "/f", "/g"), err(Errno::EEXIST));
    assert_eq!(
        path2(&mut t, Sysno::link, "/none", "/g"),
        err(Errno::ENOENT)
    );
    assert_eq!(
        path2(&mut t, Sysno::link, "/none", "/g"),
        err(Errno::ENOENT)
    );
    assert_eq!(path1(&mut t, Sysno::mkdir, "/dir", &[0o755]), ok(0));
    assert_eq!(
        path2(&mut t, Sysno::link, "/dir", "/dir2"),
        err(Errno::EPERM)
    );
    // A link to a symlink links the symlink itself; AT_SYMLINK_FOLLOW links its target.
    let (a, b) = (cstr(&mut t, PATH, "/s"), cstr(&mut t, PATH2, "/s-link"));
    let root = (AT_FDCWD as i64) as u64;
    assert_eq!(call(&mut t, Sysno::linkat, &[root, a, root, b, 0]), ok(0));
    assert_eq!(stat_of(&mut t, "/s-link", false).unwrap().0, 0o120_777);
    // Flags first, then the old name, then the old lookup, then the new name.
    assert_eq!(
        call(&mut t, Sysno::linkat, &[root, BAD, root, BAD, 0x1]),
        err(Errno::EINVAL)
    );
    assert_eq!(
        call(&mut t, Sysno::linkat, &[root, BAD, root, b, 0]),
        err(Errno::EFAULT)
    );
    assert_eq!(
        call(&mut t, Sysno::linkat, &[root, a, root, BAD, 0]),
        err(Errno::EFAULT)
    );
    // AT_SYMLINK_FOLLOW (0x400) on a dangling link: the target is missing.
    assert_eq!(
        call(&mut t, Sysno::linkat, &[root, a, root, b, 0x400]),
        err(Errno::ENOENT)
    );
    // AT_EMPTY_PATH links an open descriptor (root has CAP_DAC_READ_SEARCH).
    let (empty, g2) = (cstr(&mut t, PATH, ""), cstr(&mut t, PATH2, "/g2"));
    assert_eq!(
        call(&mut t, Sysno::linkat, &[f, empty, root, g2, 0x1000]),
        ok(0)
    );
    assert_eq!(stat_of(&mut t, "/f", true).unwrap().1, 3);
    let empty = cstr(&mut t, PATH2 + 0x200, "");
    assert_eq!(
        call(&mut t, Sysno::linkat, &[f, empty, root, g2, 0]),
        err(Errno::ENOENT),
        "an empty name needs AT_EMPTY_PATH"
    );
    // A file unlinked while open cannot be linked back.
    for name in ["/f", "/g", "/g2"] {
        assert_eq!(path1(&mut t, Sysno::unlink, name, &[]), ok(0));
    }
    let (empty, g2) = (cstr(&mut t, PATH, ""), cstr(&mut t, PATH2, "/g2"));
    assert_eq!(
        call(&mut t, Sysno::linkat, &[f, empty, root, g2, 0x1000]),
        err(Errno::ENOENT)
    );
}

#[test]
fn rename_moves_replaces_and_checks_in_linux_order() {
    let mut t = t();
    for dir in ["/a", "/b", "/a/sub", "/b/full"] {
        assert_eq!(path1(&mut t, Sysno::mkdir, dir, &[0o755]), ok(0));
    }
    assert_eq!(path1(&mut t, Sysno::mkdir, "/b/full/x", &[0o755]), ok(0));
    let f = fd(open(&mut t, "/a/f", O_CREAT | O_WRONLY, 0o644));
    put(&mut t, BUF, b"data");
    assert_eq!(call(&mut t, Sysno::write, &[f, BUF, 4]), ok(4));
    // A file into another directory under a new name: the inode moves, nlink stays.
    assert_eq!(path2(&mut t, Sysno::rename, "/a/f", "/b/g"), ok(0));
    assert_eq!(stat_of(&mut t, "/a/f", true), Err(err(Errno::ENOENT)));
    assert_eq!(stat_of(&mut t, "/b/g", true).unwrap().2, 4);
    // Replacing a file drops the replaced inode.
    assert_eq!(path1(&mut t, Sysno::mknod, "/b/h", &[0o100_644, 0]), ok(0));
    assert_eq!(path2(&mut t, Sysno::rename, "/b/g", "/b/h"), ok(0));
    assert_eq!(stat_of(&mut t, "/b/h", true).unwrap().2, 4);
    // A directory moves: link counts follow, and `..` is the new parent.
    assert_eq!(stat_of(&mut t, "/a", true).unwrap().1, 3);
    assert_eq!(path2(&mut t, Sysno::rename, "/a/sub", "/b/sub"), ok(0));
    assert_eq!(stat_of(&mut t, "/a", true).unwrap().1, 2);
    assert_eq!(stat_of(&mut t, "/b", true).unwrap().1, 4);
    assert_eq!(path1(&mut t, Sysno::chdir, "/b/sub", &[]), ok(0));
    assert_eq!(path1(&mut t, Sysno::stat, "..", &[OUT]), ok(0));
    assert_eq!(u32_at(&mut t, OUT + 24), 0o040_755);
    assert_eq!(path1(&mut t, Sysno::chdir, "/", &[]), ok(0));
    // Directory over directory: only an empty target; a file never replaces one.
    assert_eq!(
        path2(&mut t, Sysno::rename, "/b/sub", "/b/full"),
        err(Errno::ENOTEMPTY)
    );
    assert_eq!(
        path2(&mut t, Sysno::rename, "/b/h", "/b/sub"),
        err(Errno::EISDIR)
    );
    assert_eq!(
        path2(&mut t, Sysno::rename, "/b/sub", "/b/h"),
        err(Errno::ENOTDIR)
    );
    assert_eq!(path1(&mut t, Sysno::mkdir, "/b/empty", &[0o755]), ok(0));
    assert_eq!(path2(&mut t, Sysno::rename, "/b/sub", "/b/empty"), ok(0));
    assert_eq!(stat_of(&mut t, "/b", true).unwrap().1, 4);
    // A directory into its own subtree: EINVAL; its ancestor as the target: ENOTEMPTY.
    assert_eq!(
        path2(&mut t, Sysno::rename, "/b", "/b/full/x/b"),
        err(Errno::EINVAL)
    );
    assert_eq!(
        path2(&mut t, Sysno::rename, "/b/full/x", "/b"),
        err(Errno::ENOTEMPTY)
    );
    // Trailing slashes after a non-directory, missing names, "." and "..".
    assert_eq!(
        path2(&mut t, Sysno::rename, "/b/h/", "/b/i"),
        err(Errno::ENOTDIR)
    );
    assert_eq!(
        path2(&mut t, Sysno::rename, "/b/h", "/b/i/"),
        err(Errno::ENOTDIR)
    );
    assert_eq!(
        path2(&mut t, Sysno::rename, "/b/none", "/b/i"),
        err(Errno::ENOENT)
    );
    assert_eq!(
        path2(&mut t, Sysno::rename, "/b/.", "/b/i"),
        err(Errno::EBUSY)
    );
    assert_eq!(
        path2(&mut t, Sysno::rename, "/b/h", "/b/.."),
        err(Errno::EBUSY)
    );
    assert_eq!(path2(&mut t, Sysno::rename, "/", "/z"), err(Errno::EBUSY));
    assert_eq!(path2(&mut t, Sysno::rename, "", "/z"), err(Errno::ENOENT));
    // The same inode under two names: nothing happens, whatever the names.
    assert_eq!(path2(&mut t, Sysno::link, "/b/h", "/b/h2"), ok(0));
    assert_eq!(path2(&mut t, Sysno::rename, "/b/h", "/b/h2"), ok(0));
    assert!(stat_of(&mut t, "/b/h", true).is_ok());
    assert_eq!(path2(&mut t, Sysno::rename, "/b/h", "/b/h"), ok(0));
    // renameat2 flags: unknown or contradictory ones before anything is read,
    // NOREPLACE and the two not-yet-ported ones after the checks.
    let (a, b) = (cstr(&mut t, PATH, "/b/h"), cstr(&mut t, PATH2, "/b/h2"));
    let root = (AT_FDCWD as i64) as u64;
    for flags in [8u64, 3, 6, 7] {
        assert_eq!(
            call(&mut t, Sysno::renameat2, &[root, BAD, root, BAD, flags]),
            err(Errno::EINVAL),
            "{flags}"
        );
    }
    assert_eq!(
        call(&mut t, Sysno::renameat2, &[root, a, root, b, 1]),
        err(Errno::EEXIST)
    );
    let (none, other) = (cstr(&mut t, PATH, "/b/none"), cstr(&mut t, PATH2, "/b/z"));
    assert_eq!(
        call(&mut t, Sysno::renameat2, &[root, none, root, other, 2]),
        err(Errno::ENOENT),
        "RENAME_EXCHANGE needs both names"
    );
    let (a, other) = (cstr(&mut t, PATH, "/b/h"), cstr(&mut t, PATH2, "/b/z"));
    assert_eq!(
        call(&mut t, Sysno::renameat2, &[root, a, root, other, 1]),
        ok(0),
        "RENAME_NOREPLACE onto a free name"
    );
    // Two names of one inode: `vfs_rename` returns 0 before it looks at the flags.
    let (a, b) = (cstr(&mut t, PATH, "/b/z"), cstr(&mut t, PATH2, "/b/h2"));
    assert_eq!(
        call(&mut t, Sysno::renameat2, &[root, a, root, b, 2]),
        ok(0)
    );
    assert_eq!(path1(&mut t, Sysno::mknod, "/b/o", &[0o100_644, 0]), ok(0));
    let (a, b) = (cstr(&mut t, PATH, "/b/z"), cstr(&mut t, PATH2, "/b/o"));
    assert_eq!(
        call(&mut t, Sysno::renameat2, &[root, a, root, b, 2]),
        super::Outcome::Unimplemented(316)
    );
    assert_eq!(
        call(&mut t, Sysno::renameat2, &[root, a, root, b, 4]),
        super::Outcome::Unimplemented(316)
    );
    // A bad descriptor of the new name is only seen once the old name resolved.
    let (none, other) = (cstr(&mut t, PATH, "/b/none"), cstr(&mut t, PATH2, "/b/z"));
    assert_eq!(
        call(&mut t, Sysno::renameat, &[root, none, 77, other]),
        err(Errno::ENOENT)
    );
    let (a, b) = (cstr(&mut t, PATH, "/b/z"), cstr(&mut t, PATH2, "q"));
    assert_eq!(
        call(&mut t, Sysno::renameat, &[root, a, 77, b]),
        err(Errno::EBADF)
    );
}

// ---- attributes: chmod, chown, utimensat, truncate, fsync, statfs ---------------------------------

/// `(atime, mtime, ctime)` seconds and nanoseconds of `path` from `stat`.
fn times_of(t: &mut super::testing::Task, path: &str) -> [(i64, i64); 3] {
    let at = cstr(t, PATH, path);
    assert_eq!(call(t, Sysno::stat, &[at, OUT]), ok(0));
    [72, 88, 104].map(|o| (u64_at(t, OUT + o) as i64, u64_at(t, OUT + o + 8) as i64))
}

fn timespecs(t: &mut super::testing::Task, at: u64, list: [(i64, i64); 2]) {
    for (i, (sec, nsec)) in list.into_iter().enumerate() {
        put(t, at + 16 * i as u64, &sec.to_le_bytes());
        put(t, at + 16 * i as u64 + 8, &nsec.to_le_bytes());
    }
}

const UTIME_NOW: i64 = (1 << 30) - 1;
const UTIME_OMIT: i64 = (1 << 30) - 2;

#[test]
fn chmod_chown_follow_notify_change() {
    let mut t = t();
    assert_eq!(path1(&mut t, Sysno::mknod, "/f", &[0o100_644, 0]), ok(0));
    assert_eq!(path1(&mut t, Sysno::chmod, "/f", &[0o6755]), ok(0));
    assert_eq!(stat_of(&mut t, "/f", true).unwrap().0, 0o106_755);
    // chown always clears set-user-id on a file, and set-group-id when group-exec is set.
    assert_eq!(path1(&mut t, Sysno::chown, "/f", &[5, 6]), ok(0));
    assert_eq!(
        stat_of(&mut t, "/f", true).unwrap(),
        (0o100_755, 1, 0, 5, 6)
    );
    // -1 leaves an id alone; chown(-1, -1) changes nothing but ctime.
    assert_eq!(path1(&mut t, Sysno::chown, "/f", &[u64::MAX, 9]), ok(0));
    assert_eq!(stat_of(&mut t, "/f", true).unwrap().3, 5);
    assert_eq!(stat_of(&mut t, "/f", true).unwrap().4, 9);
    assert_eq!(
        path1(&mut t, Sysno::chown, "/f", &[0xffff_ffff, 0xffff_ffff]),
        ok(0)
    );
    // A symbolic link takes chown (lchown on the link itself) but not chmod.
    assert_eq!(path2(&mut t, Sysno::symlink, "f", "/l"), ok(0));
    assert_eq!(path1(&mut t, Sysno::lchown, "/l", &[3, 4]), ok(0));
    assert_eq!(stat_of(&mut t, "/l", false).unwrap().3, 3);
    assert_eq!(stat_of(&mut t, "/f", true).unwrap().3, 5);
    assert_eq!(path1(&mut t, Sysno::chown, "/l", &[7, 8]), ok(0));
    assert_eq!(stat_of(&mut t, "/f", true).unwrap().3, 7);
    let l = cstr(&mut t, PATH, "l");
    let root = (AT_FDCWD as i64) as u64;
    assert_eq!(
        call(&mut t, Sysno::fchmodat2, &[root, l, 0o600, 0x100]),
        err(Errno::EOPNOTSUPP),
        "AT_SYMLINK_NOFOLLOW on a link"
    );
    assert_eq!(call(&mut t, Sysno::fchmodat2, &[root, l, 0o600, 0]), ok(0));
    assert_eq!(stat_of(&mut t, "/f", true).unwrap().0, 0o100_600);
    assert_eq!(
        call(&mut t, Sysno::fchmodat2, &[root, l, 0o600, 0x200]),
        err(Errno::EINVAL)
    );
    assert_eq!(
        call(&mut t, Sysno::fchmodat, &[root, BAD, 0o600]),
        err(Errno::EFAULT)
    );
    assert_eq!(
        path1(&mut t, Sysno::chmod, "/none", &[0]),
        err(Errno::ENOENT)
    );
    // Descriptors: O_PATH is refused, a closed one is EBADF.
    let f = fd(open(&mut t, "/f", O_RDWR, 0));
    assert_eq!(call(&mut t, Sysno::fchmod, &[f, 0o640]), ok(0));
    assert_eq!(call(&mut t, Sysno::fchown, &[f, 1, 2]), ok(0));
    assert_eq!(
        stat_of(&mut t, "/f", true).unwrap(),
        (0o100_640, 1, 0, 1, 2)
    );
    assert_eq!(call(&mut t, Sysno::fchmod, &[99, 0]), err(Errno::EBADF));
    assert_eq!(call(&mut t, Sysno::fchown, &[99, 0, 0]), err(Errno::EBADF));
    // An unprivileged caller: only its own files, only to itself or one of its groups.
    t.attrs.cred.euid = 1000;
    t.attrs.cred.egid = 1000;
    assert_eq!(
        path1(&mut t, Sysno::chmod, "/f", &[0o777]),
        err(Errno::EPERM)
    );
    assert_eq!(
        path1(&mut t, Sysno::chown, "/f", &[1000, 1000]),
        err(Errno::EPERM)
    );
    t.attrs.cred.euid = 1;
    assert_eq!(path1(&mut t, Sysno::chmod, "/f", &[0o777]), ok(0));
    assert_eq!(
        path1(&mut t, Sysno::chown, "/f", &[1, 1000]),
        ok(0),
        "its own group"
    );
    assert_eq!(
        path1(&mut t, Sysno::chown, "/f", &[1, 5]),
        err(Errno::EPERM)
    );
    assert_eq!(path1(&mut t, Sysno::chown, "/f", &[1, u64::MAX]), ok(0));
    assert_eq!(
        path1(&mut t, Sysno::chown, "/f", &[2, u64::MAX]),
        err(Errno::EPERM)
    );
}

#[test]
fn utimensat_family_sets_times_with_omit_and_now() {
    let mut t = t();
    assert_eq!(path1(&mut t, Sysno::mknod, "/f", &[0o100_644, 0]), ok(0));
    let root = (AT_FDCWD as i64) as u64;
    let times = 0x2800;
    let path = cstr(&mut t, PATH, "/f");
    timespecs(&mut t, times, [(100, 5), (200, 6)]);
    assert_eq!(
        call(&mut t, Sysno::utimensat, &[root, path, times, 0]),
        ok(0)
    );
    let [a, m, c] = times_of(&mut t, "/f");
    assert_eq!((a, m), ((100, 5), (200, 6)));
    assert_eq!(c, (0, 0), "ctime is the (fake) current time");
    // UTIME_OMIT leaves one alone; UTIME_NOW takes the clock; both OMIT does not even look at the path.
    let path = cstr(&mut t, PATH, "/f");
    timespecs(&mut t, times, [(7, UTIME_OMIT), (8, 9)]);
    assert_eq!(
        call(&mut t, Sysno::utimensat, &[root, path, times, 0]),
        ok(0)
    );
    assert_eq!(times_of(&mut t, "/f")[..2], [(100, 5), (8, 9)]);
    let path = cstr(&mut t, PATH, "/f");
    timespecs(&mut t, times, [(1, UTIME_NOW), (2, UTIME_OMIT)]);
    assert_eq!(
        call(&mut t, Sysno::utimensat, &[root, path, times, 0]),
        ok(0)
    );
    assert_eq!(times_of(&mut t, "/f")[..2], [(0, 0), (8, 9)]);
    timespecs(&mut t, times, [(0, UTIME_OMIT), (0, UTIME_OMIT)]);
    assert_eq!(
        call(&mut t, Sysno::utimensat, &[root, BAD, times, 0x7777]),
        ok(0)
    );
    // Errors: the path first, then the values, then the flags.
    timespecs(&mut t, times, [(0, 1_000_000_000), (0, 0)]);
    assert_eq!(
        call(&mut t, Sysno::utimensat, &[root, path, times, 0]),
        err(Errno::EINVAL)
    );
    timespecs(&mut t, times, [(0, -1), (0, 0)]);
    assert_eq!(
        call(&mut t, Sysno::utimensat, &[root, path, times, 0]),
        err(Errno::EINVAL)
    );
    let none = cstr(&mut t, PATH2, "/none");
    assert_eq!(
        call(&mut t, Sysno::utimensat, &[root, none, times, 0]),
        err(Errno::ENOENT)
    );
    assert_eq!(
        call(&mut t, Sysno::utimensat, &[root, path, times, 0x100 | 0x8]),
        err(Errno::EINVAL)
    );
    assert_eq!(
        call(&mut t, Sysno::utimensat, &[root, path, BAD, 0]),
        err(Errno::EFAULT)
    );
    // A NULL times pointer is "now"; NULL name with a descriptor works on it (no flags then).
    let f = fd(open(&mut t, "/f", O_RDWR, 0));
    timespecs(&mut t, times, [(55, 0), (66, 0)]);
    assert_eq!(call(&mut t, Sysno::utimensat, &[f, 0, times, 0]), ok(0));
    assert_eq!(times_of(&mut t, "/f")[..2], [(55, 0), (66, 0)]);
    assert_eq!(call(&mut t, Sysno::utimensat, &[f, 0, 0, 0]), ok(0));
    assert_eq!(times_of(&mut t, "/f")[..2], [(0, 0), (0, 0)]);
    assert_eq!(
        call(&mut t, Sysno::utimensat, &[f, 0, 0, 0x1000]),
        err(Errno::EINVAL)
    );
    assert_eq!(
        call(&mut t, Sysno::utimensat, &[root, 0, 0, 0]),
        err(Errno::EFAULT)
    );
    assert_eq!(
        call(&mut t, Sysno::utimensat, &[99, 0, 0, 0]),
        err(Errno::EBADF)
    );
    // utimes / futimesat (struct timeval) and utime (struct utimbuf).
    let path = cstr(&mut t, PATH, "/f");
    for (i, v) in [3i64, 400_000, 5, 600_000].into_iter().enumerate() {
        put(&mut t, times + 8 * i as u64, &v.to_le_bytes());
    }
    assert_eq!(call(&mut t, Sysno::utimes, &[path, times]), ok(0));
    assert_eq!(
        times_of(&mut t, "/f")[..2],
        [(3, 400_000_000), (5, 600_000_000)]
    );
    for (i, v) in [3i64, 1_000_000, 5, 0].into_iter().enumerate() {
        put(&mut t, times + 8 * i as u64, &v.to_le_bytes());
    }
    assert_eq!(
        call(&mut t, Sysno::utimes, &[path, times]),
        err(Errno::EINVAL)
    );
    for (i, v) in [11i64, 22].into_iter().enumerate() {
        put(&mut t, times + 8 * i as u64, &v.to_le_bytes());
    }
    assert_eq!(call(&mut t, Sysno::utime, &[path, times]), ok(0));
    assert_eq!(times_of(&mut t, "/f")[..2], [(11, 0), (22, 0)]);
    assert_eq!(call(&mut t, Sysno::futimesat, &[f, 0, 0]), ok(0));
    // A caller that does not own the file: write permission suffices for "now", explicit times need the owner.
    assert_eq!(path1(&mut t, Sysno::chmod, "/f", &[0o666]), ok(0));
    t.attrs.cred.euid = 1000;
    let path = cstr(&mut t, PATH, "/f");
    assert_eq!(call(&mut t, Sysno::utimensat, &[root, path, 0, 0]), ok(0));
    timespecs(&mut t, times, [(1, 1), (2, 2)]);
    assert_eq!(
        call(&mut t, Sysno::utimensat, &[root, path, times, 0]),
        err(Errno::EPERM)
    );
    timespecs(&mut t, times, [(1, UTIME_NOW), (2, UTIME_NOW)]);
    assert_eq!(
        call(&mut t, Sysno::utimensat, &[root, path, times, 0]),
        ok(0),
        "both NOW is the same as NULL"
    );
    timespecs(&mut t, times, [(1, UTIME_NOW), (2, UTIME_OMIT)]);
    assert_eq!(
        call(&mut t, Sysno::utimensat, &[root, path, times, 0]),
        err(Errno::EPERM)
    );
    assert_eq!(path1(&mut t, Sysno::chmod, "/f", &[0]), err(Errno::EPERM));
}

#[test]
fn truncate_fsync_syncfs_and_statfs() {
    let mut t = t();
    let f = fd(open(&mut t, "/f", O_CREAT | O_RDWR, 0o644));
    put(&mut t, BUF, b"0123456789");
    assert_eq!(call(&mut t, Sysno::write, &[f, BUF, 10]), ok(10));
    assert_eq!(path1(&mut t, Sysno::truncate, "/f", &[4]), ok(0));
    assert_eq!(stat_of(&mut t, "/f", true).unwrap().2, 4);
    assert_eq!(path1(&mut t, Sysno::truncate, "/f", &[100]), ok(0));
    assert_eq!(stat_of(&mut t, "/f", true).unwrap().2, 100);
    assert_eq!(
        path1(&mut t, Sysno::truncate, "/f", &[(-1i64) as u64]),
        err(Errno::EINVAL)
    );
    assert_eq!(
        path1(&mut t, Sysno::truncate, "/", &[0]),
        err(Errno::EISDIR)
    );
    assert_eq!(
        path1(&mut t, Sysno::truncate, "/none", &[0]),
        err(Errno::ENOENT)
    );
    assert_eq!(
        path1(&mut t, Sysno::truncate, "/dev/console", &[0]),
        err(Errno::EINVAL)
    );
    assert_eq!(path1(&mut t, Sysno::chmod, "/f", &[0o444]), ok(0));
    t.attrs.cred.euid = 1000;
    assert_eq!(
        path1(&mut t, Sysno::truncate, "/f", &[0]),
        err(Errno::EACCES)
    );
    t.attrs.cred.euid = 0;
    // The size limit: growing past RLIMIT_FSIZE raises SIGXFSZ and fails with EFBIG.
    t.attrs
        .rlimits
        .prlimit(1, Some(crate::task::Rlimit { cur: 150, max: 150 }))
        .unwrap();
    assert_eq!(
        path1(&mut t, Sysno::truncate, "/f", &[151]),
        err(Errno::EFBIG)
    );
    assert_eq!(path1(&mut t, Sysno::truncate, "/f", &[150]), ok(0));
    assert_eq!(
        path1(&mut t, Sysno::truncate, "/f", &[120]),
        ok(0),
        "shrinking is allowed"
    );
    // fsync: files and directories succeed, pipes and devices have no ->fsync.
    let dir = fd(open(&mut t, "/", O_RDONLY | O_DIRECTORY, 0));
    for sysno in [Sysno::fsync, Sysno::fdatasync] {
        assert_eq!(call(&mut t, sysno, &[f]), ok(0));
        assert_eq!(call(&mut t, sysno, &[dir]), ok(0));
        assert_eq!(call(&mut t, sysno, &[0]), err(Errno::EINVAL), "console");
        assert_eq!(call(&mut t, sysno, &[99]), err(Errno::EBADF));
    }
    assert_eq!(call(&mut t, Sysno::pipe2, &[OUT, 0]), ok(0));
    let pipe = u64::from(u32_at(&mut t, OUT));
    assert_eq!(call(&mut t, Sysno::fsync, &[pipe]), err(Errno::EINVAL));
    assert_eq!(call(&mut t, Sysno::syncfs, &[pipe]), ok(0));
    assert_eq!(call(&mut t, Sysno::syncfs, &[99]), err(Errno::EBADF));
    assert_eq!(call(&mut t, Sysno::sync, &[]), ok(0));
    // statfs: tmpfs, a page per block, 255-byte names; a pipe is pipefs.
    let root = cstr(&mut t, PATH, "/");
    assert_eq!(call(&mut t, Sysno::statfs, &[root, OUT]), ok(0));
    let words: std::vec::Vec<u64> = (0..15).map(|i| u64_at(&mut t, OUT + 8 * i)).collect();
    assert_eq!(&words[..2], [0x0102_1994, 4096]);
    assert_eq!(words[3], words[4], "bfree = bavail");
    assert!(words[2] >= words[3] && words[5] >= words[6]);
    assert_eq!((words[8], words[9], words[10]), (255, 4096, 0x20));
    assert_eq!(call(&mut t, Sysno::fstatfs, &[f, OUT]), ok(0));
    assert_eq!(u64_at(&mut t, OUT), 0x0102_1994);
    assert_eq!(call(&mut t, Sysno::fstatfs, &[pipe, OUT]), ok(0));
    assert_eq!(u64_at(&mut t, OUT), 0x5049_5045);
    assert_eq!(call(&mut t, Sysno::fstatfs, &[99, OUT]), err(Errno::EBADF));
    assert_eq!(call(&mut t, Sysno::fstatfs, &[f, BAD]), err(Errno::EFAULT));
    let none = cstr(&mut t, PATH, "/none");
    assert_eq!(
        call(&mut t, Sysno::statfs, &[none, OUT]),
        err(Errno::ENOENT)
    );
}

// ---- sendfile and getrandom -----------------------------------------------------------------------

fn filled(t: &mut super::testing::Task, path: &str, bytes: &[u8]) -> u64 {
    let f = fd(open(t, path, O_CREAT | O_RDWR, 0o644));
    for (n, chunk) in bytes.chunks(4096).enumerate() {
        put(t, 0x4000, chunk);
        let _ = n;
        assert_eq!(
            call(t, Sysno::write, &[f, 0x4000, chunk.len() as u64]),
            ok(chunk.len() as i64)
        );
    }
    assert_eq!(call(t, Sysno::lseek, &[f, 0, 0]), ok(0));
    f
}

#[test]
fn sendfile_copies_files_and_fills_one_pipe_worth() {
    let mut t = t();
    let data: std::vec::Vec<u8> = (0..150_000u32).map(|i| (i % 251) as u8).collect();
    let src = filled(&mut t, "/src", &data);
    let dst = fd(open(&mut t, "/dst", O_CREAT | O_RDWR, 0o644));
    // To a file: everything up to the count (a 16 page pipe at a time, seen as one call).
    assert_eq!(
        call(&mut t, Sysno::sendfile, &[dst, src, 0, 100_000]),
        ok(100_000)
    );
    assert_eq!(
        call(&mut t, Sysno::lseek, &[src, 0, 1]),
        ok(100_000),
        "the input position moved"
    );
    assert_eq!(
        call(&mut t, Sysno::lseek, &[dst, 0, 1]),
        ok(100_000),
        "and the output's"
    );
    assert_eq!(stat_of(&mut t, "/dst", true).unwrap().2, 100_000);
    // Past the end: the rest, then 0.
    assert_eq!(
        call(&mut t, Sysno::sendfile, &[dst, src, 0, 100_000]),
        ok(50_000)
    );
    assert_eq!(
        call(&mut t, Sysno::sendfile, &[dst, src, 0, 100_000]),
        ok(0)
    );
    assert_eq!(call(&mut t, Sysno::pread64, &[dst, OUT, 8, 149_990]), ok(8));
    assert_eq!(get(&mut t, OUT, 8), data[149_990..149_998]);
    // With an offset: the file position stays, the offset comes back updated.
    put(&mut t, 0x2800, &1000i64.to_le_bytes());
    assert_eq!(
        call(&mut t, Sysno::sendfile, &[dst, src, 0x2800, 10]),
        ok(10)
    );
    assert_eq!(u64_at(&mut t, 0x2800), 1010);
    assert_eq!(
        call(&mut t, Sysno::sendfile, &[dst, src, BAD, 10]),
        err(Errno::EFAULT)
    );
    put(&mut t, 0x2800, &(-1i64).to_le_bytes());
    assert_eq!(
        call(&mut t, Sysno::sendfile, &[dst, src, 0x2800, 10]),
        err(Errno::EINVAL)
    );
    // Descriptors: input first (EBADF, must be readable), then the output (must be writable).
    let ro = fd(open(&mut t, "/dst", O_RDONLY, 0));
    assert_eq!(
        call(&mut t, Sysno::sendfile, &[dst, 99, 0, 1]),
        err(Errno::EBADF)
    );
    assert_eq!(
        call(&mut t, Sysno::sendfile, &[99, src, 0, 1]),
        err(Errno::EBADF)
    );
    assert_eq!(
        call(&mut t, Sysno::sendfile, &[ro, src, 0, 1]),
        err(Errno::EBADF)
    );
    let wo = fd(open(&mut t, "/dst", O_WRONLY, 0));
    assert_eq!(
        call(&mut t, Sysno::sendfile, &[dst, wo, 0, 1]),
        err(Errno::EBADF)
    );
    // Count 0 and a count that wraps the position.
    assert_eq!(call(&mut t, Sysno::sendfile, &[dst, src, 0, 0]), ok(0));
    assert_eq!(
        call(&mut t, Sysno::sendfile, &[dst, src, 0, u64::MAX]),
        err(Errno::EINVAL)
    );
    // To a pipe: one call moves at most what the pipe holds (16 pages, less the in-page offset).
    assert_eq!(call(&mut t, Sysno::pipe2, &[OUT, 0]), ok(0));
    let (r, w) = (
        u64::from(u32_at(&mut t, OUT)),
        u64::from(u32_at(&mut t, OUT + 4)),
    );
    assert_eq!(call(&mut t, Sysno::lseek, &[src, 0, 0]), ok(0));
    assert_eq!(
        call(&mut t, Sysno::sendfile, &[w, src, 0, 100_000]),
        ok(65_536)
    );
    // A full pipe with a non-blocking writer: EAGAIN; a pipe as input has no ->splice_read.
    assert_eq!(
        call(&mut t, Sysno::fcntl, &[w, 4, u64::from(O_NONBLOCK)]),
        ok(0)
    );
    assert_eq!(
        call(&mut t, Sysno::sendfile, &[w, src, 0, 10]),
        err(Errno::EAGAIN)
    );
    assert_eq!(call(&mut t, Sysno::read, &[r, 0x3000, 4096]), ok(4096));
    assert_eq!(get(&mut t, 0x3000, 8), data[..8]);
    assert_eq!(
        call(&mut t, Sysno::sendfile, &[dst, r, 0, 10]),
        err(Errno::EINVAL)
    );
    assert_eq!(call(&mut t, Sysno::pipe2, &[0x2900, 0]), ok(0));
    let w2 = u64::from(u32_at(&mut t, 0x2904));
    assert_eq!(
        call(&mut t, Sysno::sendfile, &[w2, r, 0, 10]),
        err(Errno::EINVAL),
        "pipe to pipe"
    );
    assert_eq!(
        call(&mut t, Sysno::sendfile, &[w2, r, 0, 0]),
        ok(0),
        "nothing to read"
    );
    put(&mut t, 0x2800, &0i64.to_le_bytes());
    assert_eq!(
        call(&mut t, Sysno::sendfile, &[dst, r, 0x2800, 10]),
        err(Errno::ESPIPE)
    );
    // To the console: through the tty write path; /dev/null swallows it.
    assert_eq!(call(&mut t, Sysno::lseek, &[src, 0, 0]), ok(0));
    let console = fd(open(&mut t, "/dev/console", O_RDWR, 0));
    assert_eq!(call(&mut t, Sysno::sendfile, &[console, src, 0, 5]), ok(5));
    assert_eq!(t.sink.0, [0, 1, 2, 3, 4], "no newline to expand among them");
    assert_eq!(
        path1(&mut t, Sysno::mknod, "/dev/null", &[0o20_666, (1 << 8) | 3]),
        ok(0)
    );
    assert_eq!(
        path1(&mut t, Sysno::mknod, "/dev/full", &[0o20_666, (1 << 8) | 7]),
        ok(0)
    );
    let null = fd(open(&mut t, "/dev/null", O_RDWR, 0));
    assert_eq!(
        call(&mut t, Sysno::sendfile, &[null, src, 0, 1000]),
        ok(1000)
    );
    // No ->splice_write on /dev/full (EINVAL once there is data to write).
    let full = fd(open(&mut t, "/dev/full", O_RDWR, 0));
    assert_eq!(
        call(&mut t, Sysno::sendfile, &[full, src, 0, 1000]),
        err(Errno::EINVAL)
    );
    // A directory has no ->splice_read, and an appending output is refused.
    let dir = fd(open(&mut t, "/", O_RDONLY | O_DIRECTORY, 0));
    assert_eq!(
        call(&mut t, Sysno::sendfile, &[dst, dir, 0, 10]),
        err(Errno::EINVAL)
    );
    let app = fd(open(&mut t, "/app", O_CREAT | O_WRONLY | O_APPEND, 0o644));
    assert_eq!(
        call(&mut t, Sysno::sendfile, &[app, src, 0, 10]),
        err(Errno::EINVAL)
    );
    // A reader that is gone: SIGPIPE and EPIPE.
    assert_eq!(call(&mut t, Sysno::pipe2, &[0x2900, 0]), ok(0));
    let (r3, w3) = (
        u64::from(u32_at(&mut t, 0x2900)),
        u64::from(u32_at(&mut t, 0x2904)),
    );
    assert_eq!(call(&mut t, Sysno::close, &[r3]), ok(0));
    assert_eq!(
        call(&mut t, Sysno::sendfile, &[w3, src, 0, 10]),
        err(Errno::EPIPE)
    );
}

#[test]
fn getrandom_flags_lengths_and_faults() {
    let mut t = t();
    let call_random = |t: &mut super::testing::Task, buf: u64, len: u64, flags: u64| {
        call(t, Sysno::getrandom, &[buf, len, flags])
    };
    assert_eq!(
        call_random(&mut t, OUT, 16, 8),
        err(Errno::EINVAL),
        "unknown flag"
    );
    assert_eq!(
        call_random(&mut t, OUT, 16, 6),
        err(Errno::EINVAL),
        "INSECURE | RANDOM"
    );
    assert_eq!(
        call_random(&mut t, BAD + (1 << 50), 16, 0),
        err(Errno::EFAULT),
        "access_ok"
    );
    assert_eq!(call_random(&mut t, OUT, 0, 0), ok(0));
    assert_eq!(
        call_random(&mut t, OUT, 7, 1),
        ok(7),
        "NONBLOCK never blocks with a generator"
    );
    assert_eq!(call_random(&mut t, OUT, 32, 2), ok(32));
    assert_eq!(call_random(&mut t, OUT, 100, 4), ok(100));
    let first = get(&mut t, OUT, 100);
    assert_eq!(call_random(&mut t, OUT, 100, 0), ok(100));
    assert_ne!(get(&mut t, OUT, 100), first, "a new call gives new bytes");
    // Sizes around the 32 byte shortcut and the 64 byte blocks.
    for len in [1u64, 31, 32, 33, 63, 64, 65, 4095, 4096, 5000] {
        assert_eq!(call_random(&mut t, 0x1000, len, 0), ok(len as i64), "{len}");
    }
    // A fault after some bytes: the bytes that were copied; none: EFAULT.
    assert_eq!(call_random(&mut t, 0x5000 - 10, 100, 0), ok(10));
    assert_eq!(call_random(&mut t, 0x5000 - 3, 40, 0), ok(3));
    assert_eq!(call_random(&mut t, 0x4fff + 1, 40, 0), err(Errno::EFAULT));
    // A CPU without a generator cannot be answered honestly.
    t.no_hw_random = true;
    assert_eq!(
        call_random(&mut t, OUT, 16, 0),
        super::Outcome::Unimplemented(318)
    );
}
