// SPDX-License-Identifier: GPL-2.0-only
//! `dynelf` group, system call probes: the calls glibc and the host's programs make that the
//! dynamic-ELF lane added (`creat`, `fadvise64`, `splice`, `vmsplice`, `copy_file_range`, the
//! `FICLONE` ioctls, the extended attribute family, the socket calls of a kernel without
//! `CONFIG_NET`, `prctl` `PR_CAPBSET_READ`/`NO_NEW_PRIVS`). Every expected value was first
//! observed on the pinned Linux 6.18.57 (`xtask/oracle/expected.tsv` holds the rows, the run is
//! named in `docs/implementation.md#dynamic-elf-lane`); each check is one raw system call whose
//! errno (or count) is compared with that observation, in the order Linux evaluates its checks.
//!
//! The probes use only files this group creates in the root file system (`/dsp-*`) and the
//! character device nodes `/dev/full` and `/dev/null`.

use syscalls::{Errno, Sysno};

use super::{PAGE, R, T, addr, addr_mut, mmap, sys};

const O_WRONLY: usize = 1;
const O_RDWR: usize = 2;
const O_CREAT: usize = 0o100;
const O_TRUNC: usize = 0o1000;
const O_APPEND: usize = 0o2000;
const O_NONBLOCK: usize = 0o4000;
const O_DIRECTORY: usize = 0o200_000;
const FICLONE: usize = 0x4004_9409;
const FICLONERANGE: usize = 0x4020_940d;
const SPLICE_F_NONBLOCK: usize = 2;
/// An address in the kernel half: `access_ok` fails for it whatever the mappings are.
const BAD: usize = 0xffff_8000_0000_0000;
/// A user address nothing is mapped at in this process.
const UNMAPPED: usize = 0x1000_0000;

fn ok(n: usize) -> R {
    Ok(n)
}

fn open(path: &[u8], flags: usize, mode: usize) -> usize {
    sys(Sysno::open, &[addr(path), flags, mode]).unwrap_or(usize::MAX)
}

fn write_bytes(fd: usize, bytes: &[u8]) {
    let _ = sys(Sysno::write, &[fd, addr(bytes), bytes.len()]);
}

/// `(read end, write end)`.
fn pipe() -> (usize, usize) {
    let mut fds = [0i32; 2];
    let _ = sys(Sysno::pipe2, &[addr_mut(&mut fds), 0]);
    (fds[0] as usize, fds[1] as usize)
}

/// Bytes waiting in a pipe (`FIONREAD`).
fn queued(read_end: usize) -> R {
    let mut n = 0i32;
    sys(Sysno::ioctl, &[read_end, 0x541b, addr_mut(&mut n)]).map(|_| n as usize)
}

fn set_i64(buf: &mut [u8; 8], value: i64) -> usize {
    *buf = value.to_le_bytes();
    addr_mut(buf)
}

fn get_i64(buf: &[u8; 8]) -> i64 {
    i64::from_le_bytes(*buf)
}

pub fn checks(t: &mut T) {
    // /dev/full has no ->splice_write; /dev/null does.
    let _ = sys(
        Sysno::mknod,
        &[addr(b"/dev/full\0"), 0o20_666, (1 << 8) | 7],
    );
    // The default action of SIGPIPE would kill the test: ignore it for the EPIPE probes.
    let mut act = [0u64; 4];
    act[0] = 1; // SIG_IGN
    let _ = sys(Sysno::rt_sigaction, &[13, addr_mut(&mut act), 0, 8]);
    creat_checks(t);
    fadvise_checks(t);
    splice_checks(t);
    vmsplice_checks(t);
    copy_file_range_checks(t);
    clone_ioctl_checks(t);
    xattr_checks(t);
    socket_checks(t);
    prctl_checks(t);
    let mut act = [0u64; 4];
    let _ = sys(Sysno::rt_sigaction, &[13, addr_mut(&mut act), 0, 8]);
}

fn creat_checks(t: &mut T) {
    let f = sys(Sysno::creat, &[addr(b"/dsp-creat\0"), 0o640]).unwrap_or(usize::MAX);
    write_bytes(f, b"hello");
    let g = sys(Sysno::creat, &[addr(b"/dsp-creat\0"), 0o600]).unwrap_or(usize::MAX);
    let mut buf = [0u8; 8];
    t.eq(
        "sys-creat-write-only",
        sys(Sysno::read, &[g, addr_mut(&mut buf), 8]),
        Err(Errno::EBADF),
    );
    let r = open(b"/dsp-creat\0", 0, 0);
    t.eq(
        "sys-creat-truncates",
        sys(Sysno::read, &[r, addr_mut(&mut buf), 8]),
        ok(0),
    );
    t.eq(
        "sys-creat-efault",
        sys(Sysno::creat, &[BAD, 0o600]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "sys-creat-directory",
        sys(Sysno::creat, &[addr(b"/\0"), 0]),
        Err(Errno::EISDIR),
    );
}

fn fadvise_checks(t: &mut T) {
    let f = open(b"/dsp-fadv\0", O_CREAT | O_RDWR | O_TRUNC, 0o644);
    write_bytes(f, b"data");
    for advice in 0..=5usize {
        t.eq(
            format_args!("sys-fadvise-advice-{advice}"),
            sys(Sysno::fadvise64, &[f, 0, 0, advice]),
            ok(0),
        );
    }
    t.eq(
        "sys-fadvise-advice-6",
        sys(Sysno::fadvise64, &[f, 0, 0, 6]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sys-fadvise-advice-huge",
        sys(Sysno::fadvise64, &[f, 0, 0, usize::MAX]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sys-fadvise-negative-length",
        sys(Sysno::fadvise64, &[f, 0, 1 << 63, 0]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sys-fadvise-negative-offset",
        sys(Sysno::fadvise64, &[f, usize::MAX, 0, 0]),
        ok(0),
    );
    t.eq(
        "sys-fadvise-ebadf",
        sys(Sysno::fadvise64, &[99, 0, 0, 0]),
        Err(Errno::EBADF),
    );
    let dir = open(b"/\0", O_DIRECTORY, 0);
    t.eq(
        "sys-fadvise-directory",
        sys(Sysno::fadvise64, &[dir, 0, 0, 3]),
        ok(0),
    );
    let (r, _w) = pipe();
    t.eq(
        "sys-fadvise-pipe",
        sys(Sysno::fadvise64, &[r, 0, 0, 0]),
        Err(Errno::ESPIPE),
    );
    let null = open(b"/dev/null\0", O_RDWR, 0);
    t.eq(
        "sys-fadvise-null",
        sys(Sysno::fadvise64, &[null, 0, 0, 0]),
        ok(0),
    );
    t.eq(
        "sys-fadvise-dontneed-bad-advice-before-fd",
        sys(Sysno::fadvise64, &[99, 0, 0, 6]),
        Err(Errno::EBADF),
    );
}

fn splice_checks(t: &mut T) {
    let a = open(b"/dsp-sp-a\0", O_CREAT | O_RDWR | O_TRUNC, 0o644);
    write_bytes(a, b"0123456789abcdef");
    let _ = sys(Sysno::lseek, &[a, 0, 0]);
    let b = open(b"/dsp-sp-b\0", O_CREAT | O_RDWR | O_TRUNC, 0o644);
    let ro = open(b"/dsp-sp-a\0", 0, 0);
    let wo = open(b"/dsp-sp-b\0", O_WRONLY, 0);
    let ap = open(b"/dsp-sp-b\0", O_WRONLY | O_APPEND, 0);
    let full = open(b"/dev/full\0", O_RDWR, 0);
    let null = open(b"/dev/null\0", O_RDWR, 0);
    let dir = open(b"/\0", O_DIRECTORY, 0);
    let (r, w) = pipe();
    let (r2, w2) = pipe();
    let mut off = [0u8; 8];
    // Order: zero length, flags, the two descriptors, the offsets of pipes, the offsets read.
    t.eq(
        "sys-splice-zero-length",
        sys(Sysno::splice, &[99, 0, 98, 0, 0, 0]),
        ok(0),
    );
    t.eq(
        "sys-splice-flags",
        sys(Sysno::splice, &[99, 0, 98, 0, 1, 0x10]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sys-splice-flags-high-bits",
        sys(Sysno::splice, &[99, 0, w, 0, 1, 1 << 32]),
        Err(Errno::EBADF),
    );
    t.eq(
        "sys-splice-ebadf-in",
        sys(Sysno::splice, &[99, 0, w, 0, 1, 0]),
        Err(Errno::EBADF),
    );
    t.eq(
        "sys-splice-ebadf-out",
        sys(Sysno::splice, &[a, 0, 98, 0, 1, 0]),
        Err(Errno::EBADF),
    );
    t.eq(
        "sys-splice-espipe-in",
        sys(Sysno::splice, &[r, addr_mut(&mut off), a, 0, 1, 0]),
        Err(Errno::ESPIPE),
    );
    t.eq(
        "sys-splice-espipe-out",
        sys(Sysno::splice, &[a, 0, w, addr_mut(&mut off), 1, 0]),
        Err(Errno::ESPIPE),
    );
    t.eq(
        "sys-splice-espipe-before-efault",
        sys(Sysno::splice, &[r, BAD, a, BAD, 1, 0]),
        Err(Errno::ESPIPE),
    );
    t.eq(
        "sys-splice-efault-out-offset",
        sys(Sysno::splice, &[r, 0, a, BAD, 1, 0]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "sys-splice-efault-in-offset",
        sys(Sysno::splice, &[a, BAD, w, 0, 1, 0]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "sys-splice-read-mode-before-offsets",
        sys(Sysno::splice, &[wo, BAD, w, 0, 1, 0]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "sys-splice-input-not-readable",
        sys(Sysno::splice, &[wo, 0, w, 0, 1, 0]),
        Err(Errno::EBADF),
    );
    t.eq(
        "sys-splice-output-not-writable",
        sys(Sysno::splice, &[r, 0, ro, 0, 1, 0]),
        Err(Errno::EBADF),
    );
    t.eq(
        "sys-splice-two-files",
        sys(Sysno::splice, &[a, 0, b, 0, 1, 0]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sys-splice-same-pipe",
        sys(Sysno::splice, &[r, 0, w, 0, 1, 0]),
        Err(Errno::EINVAL),
    );
    // A file into a pipe.
    t.eq(
        "sys-splice-file-to-pipe",
        sys(Sysno::splice, &[a, 0, w, 0, 6, 0]),
        ok(6),
    );
    t.eq(
        "sys-splice-file-to-pipe-position",
        sys(Sysno::lseek, &[a, 0, 1]),
        ok(6),
    );
    set_i64(&mut off, 12);
    t.eq(
        "sys-splice-file-to-pipe-offset",
        sys(Sysno::splice, &[a, addr_mut(&mut off), w, 0, 100, 0]),
        ok(4),
    );
    t.eq("sys-splice-offset-written-back", get_i64(&off), 16);
    t.eq(
        "sys-splice-offset-keeps-position",
        sys(Sysno::lseek, &[a, 0, 1]),
        ok(6),
    );
    t.eq("sys-splice-pipe-holds", queued(r), ok(10));
    set_i64(&mut off, 16);
    t.eq(
        "sys-splice-at-eof",
        sys(Sysno::splice, &[a, addr_mut(&mut off), w, 0, 100, 0]),
        ok(0),
    );
    set_i64(&mut off, -1);
    t.eq(
        "sys-splice-negative-offset-in",
        sys(Sysno::splice, &[a, addr_mut(&mut off), w, 0, 1, 0]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sys-splice-directory-in",
        sys(Sysno::splice, &[dir, 0, w, 0, 1, 0]),
        Err(Errno::EINVAL),
    );
    // A pipe into a file: at the position, at an offset, appending, a device.
    t.eq(
        "sys-splice-pipe-to-file",
        sys(Sysno::splice, &[r, 0, b, 0, 4, 0]),
        ok(4),
    );
    t.eq(
        "sys-splice-pipe-to-file-position",
        sys(Sysno::lseek, &[b, 0, 1]),
        ok(4),
    );
    set_i64(&mut off, 100);
    t.eq(
        "sys-splice-pipe-to-file-offset",
        sys(Sysno::splice, &[r, 0, b, addr_mut(&mut off), 100, 0]),
        ok(6),
    );
    t.eq("sys-splice-pipe-to-file-offset-back", get_i64(&off), 106);
    set_i64(&mut off, -1);
    t.eq(
        "sys-splice-negative-offset-out",
        sys(Sysno::splice, &[r, 0, b, addr_mut(&mut off), 1, 0]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sys-splice-append",
        sys(Sysno::splice, &[r, 0, ap, 0, 1, 0]),
        Err(Errno::EINVAL),
    );
    set_i64(&mut off, 0);
    t.eq(
        "sys-splice-append-with-offset",
        sys(Sysno::splice, &[r, 0, ap, addr_mut(&mut off), 1, 0]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sys-splice-directory-out",
        sys(Sysno::splice, &[r, 0, dir, 0, 1, 0]),
        Err(Errno::EBADF),
    );
    // /dev/full has no ->splice_write: EINVAL at once, empty pipe or not.
    t.eq(
        "sys-splice-full-empty-pipe",
        sys(Sysno::splice, &[r, 0, full, 0, 10, 0]),
        Err(Errno::EINVAL),
    );
    write_bytes(w, b"abc");
    t.eq(
        "sys-splice-full-with-data",
        sys(Sysno::splice, &[r, 0, full, 0, 10, 0]),
        Err(Errno::EINVAL),
    );
    t.eq("sys-splice-full-keeps-data", queued(r), ok(3));
    t.eq(
        "sys-splice-null",
        sys(Sysno::splice, &[r, 0, null, 0, 10, 0]),
        ok(3),
    );
    t.eq("sys-splice-null-drained", queued(r), ok(0));
    // Pipe to pipe.
    write_bytes(w, b"0123456789");
    t.eq(
        "sys-splice-pipe-to-pipe",
        sys(Sysno::splice, &[r, 0, w2, 0, 4, 0]),
        ok(4),
    );
    t.eq(
        "sys-splice-pipe-to-pipe-left",
        (queued(r), queued(r2)),
        (ok(6), ok(4)),
    );
    t.eq(
        "sys-splice-pipe-to-pipe-rest",
        sys(Sysno::splice, &[r, 0, w2, 0, 100, 0]),
        ok(6),
    );
    t.eq(
        "sys-splice-pipe-to-pipe-nonblock",
        sys(Sysno::splice, &[r, 0, w2, 0, 1, SPLICE_F_NONBLOCK]),
        Err(Errno::EAGAIN),
    );
    let mut got = [0u8; 16];
    t.eq(
        "sys-splice-pipe-to-pipe-data",
        sys(Sysno::read, &[r2, addr_mut(&mut got), 16]),
        ok(10),
    );
    t.eq(
        "sys-splice-pipe-to-pipe-bytes",
        &got[..10],
        &b"0123456789"[..],
    );
    let _ = sys(Sysno::close, &[w]);
    t.eq(
        "sys-splice-pipe-to-pipe-eof",
        sys(Sysno::splice, &[r, 0, w2, 0, 100, 0]),
        ok(0),
    );
    t.eq(
        "sys-splice-pipe-to-file-eof",
        sys(Sysno::splice, &[r, 0, b, 0, 100, 0]),
        ok(0),
    );
    let (r3, w3) = pipe();
    let _ = sys(Sysno::close, &[r2]);
    write_bytes(w3, b"xyz");
    t.eq(
        "sys-splice-epipe",
        sys(Sysno::splice, &[r3, 0, w2, 0, 3, 0]),
        Err(Errno::EPIPE),
    );
    // O_NONBLOCK on the input description alone makes the splice non-blocking.
    let (r4, _w4) = pipe();
    let (_r5, w5) = pipe();
    let _ = sys(Sysno::fcntl, &[r4, 4, O_NONBLOCK]);
    t.eq(
        "sys-splice-nonblocking-descriptor",
        sys(Sysno::splice, &[r4, 0, w5, 0, 1, 0]),
        Err(Errno::EAGAIN),
    );
}

/// `struct iovec` array at `at`.
fn iov(buf: &mut [u8; 64], entries: &[(usize, usize)]) -> usize {
    for (i, (base, len)) in entries.iter().enumerate() {
        buf[i * 16..i * 16 + 8].copy_from_slice(&(*base as u64).to_le_bytes());
        buf[i * 16 + 8..i * 16 + 16].copy_from_slice(&(*len as u64).to_le_bytes());
    }
    addr_mut(buf)
}

fn vmsplice_checks(t: &mut T) {
    let f = open(b"/dsp-vm\0", O_CREAT | O_RDWR | O_TRUNC, 0o644);
    let (r, w) = pipe();
    let text = *b"abcdefghij";
    let mut table = [0u8; 64];
    let two = iov(&mut table, &[(addr(&text), 4), (addr(&text) + 6, 4)]);
    t.eq(
        "sys-vmsplice-to-pipe",
        sys(Sysno::vmsplice, &[w, two, 2, 0]),
        ok(8),
    );
    t.eq("sys-vmsplice-queued", queued(r), ok(8));
    let mut out = [0u8; 100];
    let mut table2 = [0u8; 64];
    let one = iov(&mut table2, &[(addr_mut(&mut out), 100)]);
    t.eq(
        "sys-vmsplice-to-user",
        sys(Sysno::vmsplice, &[r, one, 1, 0]),
        ok(8),
    );
    t.eq("sys-vmsplice-bytes", &out[..8], &b"abcdghij"[..]);
    t.eq(
        "sys-vmsplice-flags",
        sys(Sysno::vmsplice, &[w, two, 2, 0x10]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sys-vmsplice-ebadf",
        sys(Sysno::vmsplice, &[99, two, 2, 0]),
        Err(Errno::EBADF),
    );
    t.eq(
        "sys-vmsplice-flags-before-descriptor",
        sys(Sysno::vmsplice, &[99, two, 2, 0x10]),
        Err(Errno::EINVAL),
    );
    // A descriptor that is not a pipe: the vector is imported first.
    t.eq(
        "sys-vmsplice-file",
        sys(Sysno::vmsplice, &[f, two, 2, 0]),
        Err(Errno::EBADF),
    );
    t.eq(
        "sys-vmsplice-file-no-segments",
        sys(Sysno::vmsplice, &[f, two, 0, 0]),
        ok(0),
    );
    let mut empty_table = [0u8; 64];
    let empty = iov(&mut empty_table, &[(addr(&text), 0)]);
    t.eq(
        "sys-vmsplice-file-empty-vector",
        sys(Sysno::vmsplice, &[f, empty, 1, 0]),
        ok(0),
    );
    t.eq(
        "sys-vmsplice-file-bad-vector",
        sys(Sysno::vmsplice, &[f, BAD, 1, 0]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "sys-vmsplice-file-too-many-segments",
        sys(Sysno::vmsplice, &[f, two, 1025, 0]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sys-vmsplice-pipe-too-many-segments",
        sys(Sysno::vmsplice, &[w, two, 1025, 0]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sys-vmsplice-pipe-bad-vector",
        sys(Sysno::vmsplice, &[w, BAD, 1, 0]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "sys-vmsplice-pipe-empty-vector",
        sys(Sysno::vmsplice, &[w, empty, 1, 0]),
        ok(0),
    );
    // A segment in the kernel half is refused when the vector is imported (`access_ok`): nothing
    // is spliced. One that is unmapped only ends the walk: the first one is still spliced.
    let mut half_table = [0u8; 64];
    let half = iov(&mut half_table, &[(addr(&text), 4), (BAD, 4)]);
    t.eq(
        "sys-vmsplice-kernel-half-segment",
        sys(Sysno::vmsplice, &[w, half, 2, 0]),
        Err(Errno::EFAULT),
    );
    let mut hole_table = [0u8; 64];
    let hole = iov(&mut hole_table, &[(addr(&text), 4), (UNMAPPED, 4)]);
    t.eq(
        "sys-vmsplice-partial",
        sys(Sysno::vmsplice, &[w, hole, 2, 0]),
        ok(4),
    );
    let mut hole_table = [0u8; 64];
    let hole = iov(&mut hole_table, &[(UNMAPPED, 4)]);
    t.eq(
        "sys-vmsplice-unmapped-segment",
        sys(Sysno::vmsplice, &[w, hole, 1, 0]),
        Err(Errno::EFAULT),
    );
    let mut bad_table = [0u8; 64];
    let bad = iov(&mut bad_table, &[(BAD, 4)]);
    t.eq(
        "sys-vmsplice-efault-segment",
        sys(Sysno::vmsplice, &[w, bad, 1, 0]),
        Err(Errno::EFAULT),
    );
    let (r2, w2) = pipe();
    t.eq(
        "sys-vmsplice-to-user-nonblock",
        sys(Sysno::vmsplice, &[r2, one, 1, SPLICE_F_NONBLOCK]),
        Err(Errno::EAGAIN),
    );
    let _ = sys(Sysno::close, &[w2]);
    t.eq(
        "sys-vmsplice-to-user-eof",
        sys(Sysno::vmsplice, &[r2, one, 1, 0]),
        ok(0),
    );
    let (r3, w3) = pipe();
    let _ = sys(Sysno::close, &[r3]);
    t.eq(
        "sys-vmsplice-epipe",
        sys(Sysno::vmsplice, &[w3, two, 2, 0]),
        Err(Errno::EPIPE),
    );
}

fn copy_file_range_checks(t: &mut T) {
    let a = open(b"/dsp-cfr-a\0", O_CREAT | O_RDWR | O_TRUNC, 0o644);
    write_bytes(a, b"0123456789abcdefghijklmnopqrstuvwxyz");
    let _ = sys(Sysno::lseek, &[a, 0, 0]);
    let b = open(b"/dsp-cfr-b\0", O_CREAT | O_RDWR | O_TRUNC, 0o644);
    let ro = open(b"/dsp-cfr-b\0", 0, 0);
    let ap = open(b"/dsp-cfr-b\0", O_WRONLY | O_APPEND, 0);
    let dir = open(b"/\0", O_DIRECTORY, 0);
    let proc = open(b"/proc/self/status\0", 0, 0);
    let (r, w) = pipe();
    let mut off_in = [0u8; 8];
    let mut off_out = [0u8; 8];
    macro_rules! cfr {
        ($i:expr, $oi:expr, $o:expr, $oo:expr, $len:expr, $fl:expr) => {
            sys(Sysno::copy_file_range, &[$i, $oi, $o, $oo, $len, $fl])
        };
    }
    t.eq(
        "sys-cfr-ebadf-in",
        cfr!(99, 0, b, 0, 1, 0),
        Err(Errno::EBADF),
    );
    t.eq(
        "sys-cfr-ebadf-out",
        cfr!(a, 0, 99, 0, 1, 0),
        Err(Errno::EBADF),
    );
    t.eq(
        "sys-cfr-ebadf-before-efault",
        cfr!(99, BAD, b, 0, 1, 0),
        Err(Errno::EBADF),
    );
    t.eq(
        "sys-cfr-efault-in",
        cfr!(a, BAD, b, 0, 1, 0),
        Err(Errno::EFAULT),
    );
    t.eq(
        "sys-cfr-efault-out",
        cfr!(a, 0, b, BAD, 1, 0),
        Err(Errno::EFAULT),
    );
    t.eq(
        "sys-cfr-efault-before-flags",
        cfr!(a, BAD, b, 0, 1, 1),
        Err(Errno::EFAULT),
    );
    t.eq("sys-cfr-flags", cfr!(a, 0, b, 0, 1, 1), Err(Errno::EINVAL));
    t.eq(
        "sys-cfr-flags-before-descriptors-mode",
        cfr!(a, 0, ro, 0, 1, 1),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sys-cfr-directory-in",
        cfr!(dir, 0, b, 0, 1, 0),
        Err(Errno::EISDIR),
    );
    t.eq(
        "sys-cfr-directory-out",
        cfr!(a, 0, dir, 0, 1, 0),
        Err(Errno::EISDIR),
    );
    t.eq(
        "sys-cfr-pipe-out",
        cfr!(a, 0, w, 0, 1, 0),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sys-cfr-pipe-in",
        cfr!(r, 0, b, 0, 1, 0),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sys-cfr-read-only-output",
        cfr!(a, 0, ro, 0, 1, 0),
        Err(Errno::EBADF),
    );
    t.eq(
        "sys-cfr-append-output",
        cfr!(a, 0, ap, 0, 1, 0),
        Err(Errno::EBADF),
    );
    t.eq(
        "sys-cfr-other-file-system",
        cfr!(proc, 0, b, 0, 1, 0),
        Err(Errno::EXDEV),
    );
    // Counts and positions.
    t.eq("sys-cfr-zero-length", cfr!(a, 0, b, 0, 0, 0), ok(0));
    t.eq("sys-cfr-copy", cfr!(a, 0, b, 0, 10, 0), ok(10));
    t.eq(
        "sys-cfr-positions",
        (sys(Sysno::lseek, &[a, 0, 1]), sys(Sysno::lseek, &[b, 0, 1])),
        (ok(10), ok(10)),
    );
    set_i64(&mut off_in, 30);
    set_i64(&mut off_out, 100);
    t.eq(
        "sys-cfr-short-at-eof",
        cfr!(a, addr_mut(&mut off_in), b, addr_mut(&mut off_out), 100, 0),
        ok(6),
    );
    t.eq(
        "sys-cfr-offsets-written-back",
        (get_i64(&off_in), get_i64(&off_out)),
        (36, 106),
    );
    t.eq(
        "sys-cfr-offsets-keep-positions",
        (sys(Sysno::lseek, &[a, 0, 1]), sys(Sysno::lseek, &[b, 0, 1])),
        (ok(10), ok(10)),
    );
    t.eq(
        "sys-cfr-at-eof",
        cfr!(a, addr_mut(&mut off_in), b, addr_mut(&mut off_out), 100, 0),
        ok(0),
    );
    t.eq(
        "sys-cfr-eof-offsets-unchanged",
        (get_i64(&off_in), get_i64(&off_out)),
        (36, 106),
    );
    // Overlap, wrap-around, extreme and negative offsets.
    set_i64(&mut off_in, 0);
    set_i64(&mut off_out, 5);
    t.eq(
        "sys-cfr-overlap",
        cfr!(a, addr_mut(&mut off_in), a, addr_mut(&mut off_out), 20, 0),
        Err(Errno::EINVAL),
    );
    set_i64(&mut off_out, -1);
    t.eq(
        "sys-cfr-negative-out-wraps",
        cfr!(a, addr_mut(&mut off_in), b, addr_mut(&mut off_out), 100, 0),
        Err(Errno::EOVERFLOW),
    );
    t.eq(
        "sys-cfr-negative-out-zero-length",
        cfr!(a, addr_mut(&mut off_in), b, addr_mut(&mut off_out), 0, 0),
        Err(Errno::EINVAL),
    );
    set_i64(&mut off_in, i64::MIN);
    set_i64(&mut off_out, 0);
    t.eq(
        "sys-cfr-min-in-zero-length",
        cfr!(a, addr_mut(&mut off_in), b, addr_mut(&mut off_out), 0, 0),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sys-cfr-min-in",
        cfr!(a, addr_mut(&mut off_in), b, addr_mut(&mut off_out), 1, 0),
        Err(Errno::EINVAL),
    );
    set_i64(&mut off_in, 0);
    set_i64(&mut off_out, i64::MAX);
    t.eq(
        "sys-cfr-max-out",
        cfr!(a, addr_mut(&mut off_in), b, addr_mut(&mut off_out), 1, 0),
        Err(Errno::EFBIG),
    );
    set_i64(&mut off_out, i64::MIN);
    t.eq(
        "sys-cfr-min-out",
        cfr!(a, addr_mut(&mut off_in), b, addr_mut(&mut off_out), 1, 0),
        Err(Errno::EINVAL),
    );
    set_i64(&mut off_in, 1);
    set_i64(&mut off_out, 0);
    t.eq(
        "sys-cfr-huge-length-wraps",
        cfr!(
            a,
            addr_mut(&mut off_in),
            b,
            addr_mut(&mut off_out),
            usize::MAX,
            0
        ),
        Err(Errno::EOVERFLOW),
    );
    // A fault storing the input offset still updates the output offset.
    // A read-only anonymous page (an offset of 0): the load works, the store faults.
    let ro_offset = mmap(0, PAGE, 1, 0x22, usize::MAX, 0).unwrap_or(0);
    set_i64(&mut off_out, 200);
    t.eq(
        "sys-cfr-store-fault-in-offset",
        cfr!(a, ro_offset, b, addr_mut(&mut off_out), 4, 0),
        Err(Errno::EFAULT),
    );
    t.eq(
        "sys-cfr-store-fault-updates-out-offset",
        get_i64(&off_out),
        204,
    );
}

fn clone_ioctl_checks(t: &mut T) {
    let a = open(b"/dsp-fc-a\0", O_CREAT | O_RDWR | O_TRUNC, 0o644);
    write_bytes(a, b"abc");
    let b = open(b"/dsp-fc-b\0", O_CREAT | O_RDWR | O_TRUNC, 0o644);
    let ro = open(b"/dsp-fc-b\0", 0, 0);
    let dir = open(b"/\0", O_DIRECTORY, 0);
    let proc = open(b"/proc/self/status\0", 0, 0);
    let (r, _w) = pipe();
    t.eq(
        "sys-ficlone-ebadf",
        sys(Sysno::ioctl, &[b, FICLONE, 99]),
        Err(Errno::EBADF),
    );
    t.eq(
        "sys-ficlone-tmpfs",
        sys(Sysno::ioctl, &[b, FICLONE, a]),
        Err(Errno::EOPNOTSUPP),
    );
    t.eq(
        "sys-ficlone-directory-source",
        sys(Sysno::ioctl, &[b, FICLONE, dir]),
        Err(Errno::EISDIR),
    );
    t.eq(
        "sys-ficlone-pipe-source",
        sys(Sysno::ioctl, &[b, FICLONE, r]),
        Err(Errno::EXDEV),
    );
    t.eq(
        "sys-ficlone-other-file-system",
        sys(Sysno::ioctl, &[b, FICLONE, proc]),
        Err(Errno::EXDEV),
    );
    t.eq(
        "sys-ficlone-read-only-destination",
        sys(Sysno::ioctl, &[ro, FICLONE, a]),
        Err(Errno::EBADF),
    );
    t.eq(
        "sys-ficlone-directory-destination",
        sys(Sysno::ioctl, &[dir, FICLONE, a]),
        Err(Errno::EISDIR),
    );
    t.eq(
        "sys-ficlone-same-file",
        sys(Sysno::ioctl, &[a, FICLONE, a]),
        Err(Errno::EOPNOTSUPP),
    );
    t.eq(
        "sys-ficlonerange-efault",
        sys(Sysno::ioctl, &[b, FICLONERANGE, BAD]),
        Err(Errno::EFAULT),
    );
    let mut range = [0u8; 32];
    range[..8].copy_from_slice(&(a as u64).to_le_bytes());
    t.eq(
        "sys-ficlonerange-tmpfs",
        sys(Sysno::ioctl, &[b, FICLONERANGE, addr_mut(&mut range)]),
        Err(Errno::EOPNOTSUPP),
    );
    range[..8].copy_from_slice(&99u64.to_le_bytes());
    t.eq(
        "sys-ficlonerange-ebadf",
        sys(Sysno::ioctl, &[b, FICLONERANGE, addr_mut(&mut range)]),
        Err(Errno::EBADF),
    );
}

fn xattr_checks(t: &mut T) {
    let f = open(b"/dsp-xa\0", O_CREAT | O_RDWR | O_TRUNC, 0o644);
    write_bytes(f, b"x");
    let mut out = [0u8; 64];
    let o = addr_mut(&mut out);
    let path = addr(b"/dsp-xa\0");
    t.eq(
        "sys-xattr-list",
        (
            sys(Sysno::listxattr, &[path, 0, 0]),
            sys(Sysno::llistxattr, &[path, o, 64]),
            sys(Sysno::flistxattr, &[f, BAD, 100]),
        ),
        (ok(0), ok(0), ok(0)),
    );
    t.eq(
        "sys-xattr-list-ebadf",
        sys(Sysno::flistxattr, &[99, o, 100]),
        Err(Errno::EBADF),
    );
    t.eq(
        "sys-xattr-list-efault",
        sys(Sysno::listxattr, &[BAD, o, 1]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "sys-xattr-list-enoent",
        sys(Sysno::listxattr, &[addr(b"/dsp-nothing\0"), o, 1]),
        Err(Errno::ENOENT),
    );
    t.eq(
        "sys-xattr-get-name-efault",
        sys(Sysno::getxattr, &[path, BAD, o, 10]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "sys-xattr-get-empty-name",
        sys(Sysno::getxattr, &[path, addr(b"\0"), o, 10]),
        Err(Errno::ERANGE),
    );
    let mut long = [b'a'; 260];
    long[..5].copy_from_slice(b"user.");
    long[256] = 0;
    t.eq(
        "sys-xattr-get-long-name",
        sys(Sysno::getxattr, &[path, addr(&long), o, 10]),
        Err(Errno::ERANGE),
    );
    long[255] = 0;
    t.eq(
        "sys-xattr-get-name-255",
        sys(Sysno::getxattr, &[path, addr(&long), o, 10]),
        Err(Errno::ENODATA),
    );
    let user = addr(b"user.k\0");
    t.eq(
        "sys-xattr-get-enoent",
        sys(Sysno::getxattr, &[addr(b"/dsp-nothing\0"), user, o, 10]),
        Err(Errno::ENOENT),
    );
    t.eq(
        "sys-xattr-get-user",
        (
            sys(Sysno::getxattr, &[path, user, o, 10]),
            sys(Sysno::lgetxattr, &[path, user, o, 0]),
            sys(Sysno::fgetxattr, &[f, user, o, 10]),
        ),
        (
            Err(Errno::ENODATA),
            Err(Errno::ENODATA),
            Err(Errno::ENODATA),
        ),
    );
    t.eq(
        "sys-xattr-get-ebadf",
        sys(Sysno::fgetxattr, &[99, user, o, 10]),
        Err(Errno::EBADF),
    );
    for (label, name, want) in [
        ("security", &b"security.selinux\0"[..], Errno::ENODATA),
        ("trusted", &b"trusted.k\0"[..], Errno::ENODATA),
        (
            "acl-access",
            &b"system.posix_acl_access\0"[..],
            Errno::ENODATA,
        ),
        (
            "acl-default",
            &b"system.posix_acl_default\0"[..],
            Errno::ENODATA,
        ),
        ("system-other", &b"system.other\0"[..], Errno::EOPNOTSUPP),
        ("unknown-prefix", &b"foo.bar\0"[..], Errno::EOPNOTSUPP),
        ("user-empty", &b"user.\0"[..], Errno::EINVAL),
        ("security-empty", &b"security.\0"[..], Errno::EINVAL),
    ] {
        t.eq(
            format_args!("sys-xattr-get-{label}"),
            sys(Sysno::getxattr, &[path, addr(name), o, 10]),
            Err(want),
        );
    }
    let console = addr(b"/dev/console\0");
    t.eq(
        "sys-xattr-device-user",
        (
            sys(Sysno::getxattr, &[console, user, o, 10]),
            sys(Sysno::removexattr, &[console, user]),
            sys(Sysno::setxattr, &[console, user, o, 1, 0]),
            sys(Sysno::getxattr, &[console, addr(b"security.k\0"), o, 10]),
        ),
        (
            Err(Errno::ENODATA),
            Err(Errno::EPERM),
            Err(Errno::EPERM),
            Err(Errno::ENODATA),
        ),
    );
    t.eq(
        "sys-xattr-remove",
        (
            sys(Sysno::removexattr, &[path, user]),
            sys(Sysno::fremovexattr, &[f, user]),
            sys(Sysno::removexattr, &[path, addr(b"foo.bar\0")]),
        ),
        (
            Err(Errno::ENODATA),
            Err(Errno::ENODATA),
            Err(Errno::EOPNOTSUPP),
        ),
    );
    t.eq(
        "sys-xattr-set-flags",
        sys(Sysno::setxattr, &[path, user, o, 1, 4]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sys-xattr-set-too-big",
        sys(Sysno::setxattr, &[path, user, o, 70_000, 0]),
        Err(Errno::E2BIG),
    );
    t.eq(
        "sys-xattr-set-value-efault",
        sys(Sysno::setxattr, &[path, user, BAD, 1, 0]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "sys-xattr-set-replace-missing",
        sys(Sysno::setxattr, &[path, user, o, 1, 2]),
        Err(Errno::ENODATA),
    );
    t.eq(
        "sys-xattr-set-name-before-value",
        sys(Sysno::setxattr, &[path, addr(b"foo.bar\0"), o, 1, 0]),
        Err(Errno::EOPNOTSUPP),
    );
    let _ = sys(Sysno::symlink, &[path, addr(b"/dsp-xl\0")]);
    let link = addr(b"/dsp-xl\0");
    let acl = addr(b"system.posix_acl_access\0");
    t.eq(
        "sys-xattr-symlink",
        (
            sys(Sysno::lgetxattr, &[link, acl, o, 10]),
            sys(Sysno::getxattr, &[link, acl, o, 10]),
            sys(Sysno::lgetxattr, &[link, user, o, 10]),
        ),
        (
            Err(Errno::EOPNOTSUPP),
            Err(Errno::ENODATA),
            Err(Errno::ENODATA),
        ),
    );
}

fn socket_checks(t: &mut T) {
    // CONFIG_NET is not set in the reference: every socket call is sys_ni_syscall.
    let f = open(b"/dsp-sock\0", O_CREAT | O_RDWR | O_TRUNC, 0o644);
    let (r, _w) = pipe();
    let mut out = [0u8; 64];
    let o = addr_mut(&mut out);
    for (label, call) in [
        ("getsockname", Sysno::getsockname),
        ("getpeername", Sysno::getpeername),
        ("accept", Sysno::accept),
        ("accept4", Sysno::accept4),
        ("connect", Sysno::connect),
        ("bind", Sysno::bind),
        ("listen", Sysno::listen),
        ("shutdown", Sysno::shutdown),
        ("sendto", Sysno::sendto),
        ("recvfrom", Sysno::recvfrom),
        ("sendmsg", Sysno::sendmsg),
        ("recvmsg", Sysno::recvmsg),
        ("sendmmsg", Sysno::sendmmsg),
        ("recvmmsg", Sysno::recvmmsg),
        ("setsockopt", Sysno::setsockopt),
        ("getsockopt", Sysno::getsockopt),
    ] {
        t.eq(
            format_args!("sys-{label}"),
            (
                sys(call, &[f, o, o + 32, 0, 0, 0]),
                sys(call, &[r, 0, 0, 0, 0, 0]),
                sys(call, &[99, o, o + 32, 0, 0, 0]),
            ),
            (Err(Errno::ENOSYS), Err(Errno::ENOSYS), Err(Errno::ENOSYS)),
        );
    }
    t.eq(
        "sys-socket",
        (
            sys(Sysno::socket, &[1, 1, 0]),
            sys(Sysno::socket, &[2, 1, 0]),
            sys(Sysno::socketpair, &[1, 1, 0, o]),
        ),
        (Err(Errno::ENOSYS), Err(Errno::ENOSYS), Err(Errno::ENOSYS)),
    );
}

fn prctl_checks(t: &mut T) {
    const PR_CAPBSET_READ: usize = 23;
    const PR_SET_NO_NEW_PRIVS: usize = 38;
    const PR_GET_NO_NEW_PRIVS: usize = 39;
    for cap in [0usize, 1, 21, 38, 39, 40] {
        t.eq(
            format_args!("sys-prctl-capbset-read-{cap}"),
            sys(Sysno::prctl, &[PR_CAPBSET_READ, cap]),
            ok(1),
        );
    }
    t.eq(
        "sys-prctl-capbset-read-41",
        sys(Sysno::prctl, &[PR_CAPBSET_READ, 41]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sys-prctl-capbset-read-huge",
        sys(Sysno::prctl, &[PR_CAPBSET_READ, usize::MAX]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sys-prctl-capbset-read-high-bit",
        sys(Sysno::prctl, &[PR_CAPBSET_READ, 1 << 32]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sys-prctl-no-new-privs-get-initial",
        sys(Sysno::prctl, &[PR_GET_NO_NEW_PRIVS]),
        ok(0),
    );
    t.eq(
        "sys-prctl-no-new-privs-set-zero",
        sys(Sysno::prctl, &[PR_SET_NO_NEW_PRIVS, 0]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sys-prctl-no-new-privs-set-two",
        sys(Sysno::prctl, &[PR_SET_NO_NEW_PRIVS, 2]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sys-prctl-no-new-privs-set-extra",
        sys(Sysno::prctl, &[PR_SET_NO_NEW_PRIVS, 1, 1]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sys-prctl-no-new-privs-get-extra",
        sys(Sysno::prctl, &[PR_GET_NO_NEW_PRIVS, 1]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sys-prctl-no-new-privs-still-clear",
        sys(Sysno::prctl, &[PR_GET_NO_NEW_PRIVS]),
        ok(0),
    );
    t.eq(
        "sys-prctl-no-new-privs-set",
        sys(Sysno::prctl, &[PR_SET_NO_NEW_PRIVS, 1]),
        ok(0),
    );
    t.eq(
        "sys-prctl-no-new-privs-get",
        sys(Sysno::prctl, &[PR_GET_NO_NEW_PRIVS]),
        ok(1),
    );
    t.eq(
        "sys-prctl-no-new-privs-set-again",
        sys(Sysno::prctl, &[PR_SET_NO_NEW_PRIVS, 1]),
        ok(0),
    );
}
