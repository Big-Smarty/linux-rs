// SPDX-License-Identifier: GPL-2.0-only
//! Host tests of the file syscalls through [`super::dispatch`]: argument
//! decoding, error precedence, user-memory faults and the loud stops, on a task
//! whose files are the real tmpfs rootfs (`testing::Task`).

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::too_many_lines
)]

extern crate std;

use std::{string::String, vec::Vec};

use super::{
    Outcome, dispatch, error,
    testing::{Task, WaitHook, task, would_hang},
};
use crate::signal::{SIG_IGN, SIGALRM, SIGPIPE, SIGXFSZ, SigSet};
use crate::vfs::{
    AT_EMPTY_PATH, AT_FDCWD, O_APPEND, O_CLOEXEC, O_CREAT, O_DIRECTORY, O_EXCL, O_NONBLOCK,
    O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY, S_IFCHR, S_IFDIR, S_IFREG, mkdev, new_encode_dev,
};
use syscalls::{Errno, Sysno};

pub(super) const PATH: u64 = 0x1000;
pub(super) const PATH2: u64 = 0x1800;
pub(super) const BUF: u64 = 0x2000;
pub(super) const OUT: u64 = 0x3000;
pub(super) const BAD: u64 = 0x9000;

pub(super) fn t() -> Task {
    let mut t = task();
    for page in [0x1000, 0x2000, 0x3000, 0x4000] {
        t.pages.map(page, true);
    }
    t.pages.map(0x5000, false);
    t
}

pub(super) fn call(t: &mut Task, sysno: Sysno, args: &[u64]) -> Outcome {
    let mut full = [0; 6];
    full[..args.len()].copy_from_slice(args);
    dispatch(t, sysno as u64, full)
}

pub(super) fn ok(value: i64) -> Outcome {
    Outcome::Return(value)
}

pub(super) fn err(errno: Errno) -> Outcome {
    Outcome::Return(error(errno))
}

pub(super) fn put(t: &mut Task, at: u64, data: &[u8]) {
    let page = t.pages.0.get_mut(&(at & !0xfff)).unwrap();
    let start = (at & 0xfff) as usize;
    page.0[start..start + data.len()].copy_from_slice(data);
}

pub(super) fn get(t: &mut Task, at: u64, len: usize) -> Vec<u8> {
    let page = t.pages.0.get_mut(&(at & !0xfff)).unwrap();
    let start = (at & 0xfff) as usize;
    page.0[start..start + len].to_vec()
}

pub(super) fn cstr(t: &mut Task, at: u64, text: &str) -> u64 {
    let mut bytes = text.as_bytes().to_vec();
    bytes.push(0);
    put(t, at, &bytes);
    at
}

pub(super) fn open(t: &mut Task, path: &str, flags: u32, mode: u32) -> Outcome {
    let at = cstr(t, PATH, path);
    call(t, Sysno::open, &[at, u64::from(flags), u64::from(mode)])
}

pub(super) fn fd(outcome: Outcome) -> u64 {
    match outcome {
        Outcome::Return(n) if n >= 0 => n as u64,
        other => panic!("{other:?}"),
    }
}

pub(super) fn u64_at(t: &mut Task, at: u64) -> u64 {
    u64::from_le_bytes(get(t, at, 8).try_into().unwrap())
}

pub(super) fn u32_at(t: &mut Task, at: u64) -> u32 {
    u32::from_le_bytes(get(t, at, 4).try_into().unwrap())
}

#[test]
fn read_write_seek_and_stat_a_created_file() {
    let mut t = t();
    let f = fd(open(&mut t, "/f", O_CREAT | O_RDWR, 0o644));
    assert_eq!(f, 3, "descriptors 0-2 are the console");
    put(&mut t, BUF, b"hello");
    assert_eq!(call(&mut t, Sysno::write, &[f, BUF, 5]), ok(5));
    assert_eq!(call(&mut t, Sysno::read, &[f, OUT, 5]), ok(0), "at EOF");
    assert_eq!(call(&mut t, Sysno::lseek, &[f, 1, 0]), ok(1));
    assert_eq!(call(&mut t, Sysno::read, &[f, OUT, 100]), ok(4));
    assert_eq!(get(&mut t, OUT, 4), b"ello");
    assert_eq!(call(&mut t, Sysno::lseek, &[f, 0, 2]), ok(5));
    assert_eq!(
        call(&mut t, Sysno::lseek, &[f, (-6i64) as u64, 1]),
        err(Errno::EINVAL)
    );
    assert_eq!(call(&mut t, Sysno::lseek, &[f, 0, 9]), err(Errno::EINVAL));
    // pread/pwrite ignore and keep the file position.
    assert_eq!(call(&mut t, Sysno::pread64, &[f, OUT, 3, 2]), ok(3));
    assert_eq!(get(&mut t, OUT, 3), b"llo");
    put(&mut t, BUF, b"XY");
    assert_eq!(call(&mut t, Sysno::pwrite64, &[f, BUF, 2, 3]), ok(2));
    assert_eq!(call(&mut t, Sysno::lseek, &[f, 0, 1]), ok(5));
    assert_eq!(
        call(&mut t, Sysno::pread64, &[f, OUT, 1, (-1i64) as u64]),
        err(Errno::EINVAL)
    );
    // fstat: struct stat at OUT.
    assert_eq!(call(&mut t, Sysno::fstat, &[f, OUT]), ok(0));
    assert_eq!(u32_at(&mut t, OUT + 24), S_IFREG | 0o644, "st_mode");
    assert_eq!(u64_at(&mut t, OUT + 48), 5, "st_size");
    assert_eq!(u64_at(&mut t, OUT + 16), 1, "st_nlink");
    assert_eq!(call(&mut t, Sysno::close, &[f]), ok(0));
    assert_eq!(call(&mut t, Sysno::close, &[f]), err(Errno::EBADF));
    assert_eq!(call(&mut t, Sysno::read, &[f, OUT, 1]), err(Errno::EBADF));
}

#[test]
fn argument_errors_come_in_linux_order() {
    let mut t = t();
    let f = fd(open(&mut t, "/f", O_CREAT | O_RDWR, 0o644));
    let ro = fd(open(&mut t, "/f", O_RDONLY, 0));
    let wo = fd(open(&mut t, "/f", O_WRONLY, 0));
    // EBADF (descriptor) precedes EFAULT (buffer); mode checks precede both.
    assert_eq!(call(&mut t, Sysno::write, &[99, BAD, 1]), err(Errno::EBADF));
    assert_eq!(call(&mut t, Sysno::write, &[ro, BAD, 1]), err(Errno::EBADF));
    assert_eq!(call(&mut t, Sysno::read, &[wo, BAD, 1]), err(Errno::EBADF));
    assert_eq!(call(&mut t, Sysno::write, &[f, BAD, 1]), err(Errno::EFAULT));
    assert_eq!(
        call(&mut t, Sysno::read, &[f, u64::MAX, 2]),
        err(Errno::EFAULT)
    );
    // A count that wraps the position is rejected before anything is copied.
    assert_eq!(
        call(&mut t, Sysno::pread64, &[f, BUF, 100, i64::MAX as u64 - 5]),
        err(Errno::EINVAL)
    );
    // `access_ok` precedes it: a count that leaves the address space is EFAULT.
    assert_eq!(
        call(&mut t, Sysno::pread64, &[f, BUF, 1 << 62, 0]),
        err(Errno::EFAULT)
    );
    // Reading a hole in the user buffer after some data returns the short count.
    put(&mut t, BUF, b"abcd");
    assert_eq!(call(&mut t, Sysno::write, &[f, BUF, 4]), ok(4));
    assert_eq!(call(&mut t, Sysno::pread64, &[f, 0x5000 - 2, 4, 0]), ok(2));
}

#[test]
fn append_mode_and_file_limits() {
    let mut t = t();
    let f = fd(open(&mut t, "/f", O_CREAT | O_WRONLY | O_APPEND, 0o644));
    put(&mut t, BUF, b"one");
    assert_eq!(call(&mut t, Sysno::write, &[f, BUF, 3]), ok(3));
    assert_eq!(call(&mut t, Sysno::lseek, &[f, 0, 0]), ok(0));
    assert_eq!(call(&mut t, Sysno::write, &[f, BUF, 3]), ok(3));
    assert_eq!(
        call(&mut t, Sysno::lseek, &[f, 0, 1]),
        ok(6),
        "append moved to the end"
    );
    // `open(2)` always adds O_LARGEFILE on x86-64: 2 GiB is reachable, i64::MAX wraps the position.
    assert_eq!(call(&mut t, Sysno::pwrite64, &[f, BUF, 3, 1 << 31]), ok(3));
    assert_eq!(
        call(&mut t, Sysno::pwrite64, &[f, BUF, 3, i64::MAX as u64]),
        err(Errno::EINVAL)
    );
}

#[test]
fn dup_family_and_fcntl() {
    let mut t = t();
    let f = fd(open(&mut t, "/f", O_CREAT | O_RDWR, 0o644));
    assert_eq!(call(&mut t, Sysno::dup, &[f]), ok(4));
    assert_eq!(call(&mut t, Sysno::dup2, &[f, 10]), ok(10));
    assert_eq!(call(&mut t, Sysno::dup2, &[f, f]), ok(3));
    assert_eq!(call(&mut t, Sysno::dup2, &[77, 77]), err(Errno::EBADF));
    assert_eq!(call(&mut t, Sysno::dup2, &[77, 5]), err(Errno::EBADF));
    assert_eq!(
        call(&mut t, Sysno::dup2, &[f, 1 << 30]),
        err(Errno::EBADF),
        "beyond RLIMIT_NOFILE"
    );
    assert_eq!(call(&mut t, Sysno::dup3, &[f, f, 0]), err(Errno::EINVAL));
    assert_eq!(
        call(&mut t, Sysno::dup3, &[f, 11, 1]),
        err(Errno::EINVAL),
        "unknown flag"
    );
    assert_eq!(
        call(&mut t, Sysno::dup3, &[f, 11, u64::from(O_CLOEXEC)]),
        ok(11)
    );
    assert_eq!(call(&mut t, Sysno::fcntl, &[11, 1, 0]), ok(1), "F_GETFD");
    assert_eq!(call(&mut t, Sysno::fcntl, &[10, 1, 0]), ok(0));
    assert_eq!(call(&mut t, Sysno::fcntl, &[10, 2, 1]), ok(0), "F_SETFD");
    assert_eq!(call(&mut t, Sysno::fcntl, &[10, 1, 0]), ok(1));
    assert_eq!(call(&mut t, Sysno::fcntl, &[f, 0, 20]), ok(20), "F_DUPFD");
    assert_eq!(
        call(&mut t, Sysno::fcntl, &[f, 1030, 21]),
        ok(21),
        "F_DUPFD_CLOEXEC"
    );
    assert_eq!(call(&mut t, Sysno::fcntl, &[21, 1, 0]), ok(1));
    assert_eq!(
        call(&mut t, Sysno::fcntl, &[f, 0, 5000]),
        err(Errno::EINVAL),
        "past RLIMIT_NOFILE"
    );
    // All duplicates share one file description (and its position).
    assert_eq!(call(&mut t, Sysno::lseek, &[f, 7, 0]), ok(7));
    assert_eq!(call(&mut t, Sysno::lseek, &[20, 0, 1]), ok(7));
    // F_GETFL / F_SETFL change only the settable bits.
    let largefile = i64::from(crate::vfs::O_LARGEFILE);
    assert_eq!(
        call(&mut t, Sysno::fcntl, &[f, 3, 0]),
        ok(largefile | i64::from(O_RDWR))
    );
    assert_eq!(
        call(
            &mut t,
            Sysno::fcntl,
            &[f, 4, u64::from(O_NONBLOCK | O_APPEND | O_TRUNC)]
        ),
        ok(0)
    );
    assert_eq!(
        call(&mut t, Sysno::fcntl, &[f, 3, 0]),
        ok(largefile | i64::from(O_RDWR | O_NONBLOCK | O_APPEND))
    );
    assert_eq!(
        call(&mut t, Sysno::fcntl, &[f, 12345, 0]),
        err(Errno::EINVAL)
    );
    assert_eq!(call(&mut t, Sysno::fcntl, &[99, 1, 0]), err(Errno::EBADF));
    // F_SETLK is Linux behaviour this slice has not ported: a loud stop.
    assert_eq!(
        call(&mut t, Sysno::fcntl, &[f, 6, 0]),
        Outcome::Unimplemented(72)
    );
}

#[test]
fn descriptor_table_honours_rlimit_nofile() {
    let mut t = t();
    t.attrs
        .rlimits
        .prlimit(7, Some(crate::task::Rlimit { cur: 5, max: 5 }))
        .unwrap();
    assert_eq!(open(&mut t, "/dev/console", O_RDWR, 0), ok(3));
    assert_eq!(open(&mut t, "/dev/console", O_RDWR, 0), ok(4));
    assert_eq!(open(&mut t, "/dev/console", O_RDWR, 0), err(Errno::EMFILE));
    assert_eq!(call(&mut t, Sysno::dup, &[0]), err(Errno::EMFILE));
    assert_eq!(call(&mut t, Sysno::dup2, &[0, 5]), err(Errno::EBADF));
    assert_eq!(call(&mut t, Sysno::fcntl, &[0, 0, 5]), err(Errno::EINVAL));
    assert_eq!(call(&mut t, Sysno::close, &[3]), ok(0));
    assert_eq!(
        open(&mut t, "/dev/console", O_RDWR, 0),
        ok(3),
        "lowest free"
    );
}

#[test]
fn pipes_transfer_bytes_and_stop_loudly_where_linux_would_sleep() {
    let mut t = t();
    assert_eq!(call(&mut t, Sysno::pipe2, &[OUT, 0]), ok(0));
    let (r, w) = (
        u64::from(u32_at(&mut t, OUT)),
        u64::from(u32_at(&mut t, OUT + 4)),
    );
    assert_eq!((r, w), (3, 4));
    // The write end is not readable, the read end not writable.
    assert_eq!(call(&mut t, Sysno::read, &[w, BUF, 1]), err(Errno::EBADF));
    assert_eq!(call(&mut t, Sysno::write, &[r, BUF, 1]), err(Errno::EBADF));
    put(&mut t, BUF, b"abc");
    assert_eq!(call(&mut t, Sysno::write, &[w, BUF, 3]), ok(3));
    assert_eq!(call(&mut t, Sysno::write, &[w, BUF, 0]), ok(0));
    assert_eq!(
        call(&mut t, Sysno::ioctl, &[r, 0x541b, OUT + 16]),
        ok(0),
        "FIONREAD"
    );
    assert_eq!(u32_at(&mut t, OUT + 16), 3);
    assert_eq!(
        call(&mut t, Sysno::fcntl, &[r, 1032, 0]),
        ok(65536),
        "F_GETPIPE_SZ"
    );
    assert_eq!(call(&mut t, Sysno::read, &[r, OUT + 32, 10]), ok(3));
    assert_eq!(get(&mut t, OUT + 32, 3), b"abc");
    // Empty with a writer: Linux sleeps, and nothing can wake the only task.
    assert!(would_hang(|| call(&mut t, Sysno::read, &[r, OUT + 32, 10])));
    assert_eq!(
        call(&mut t, Sysno::pread64, &[r, OUT + 32, 1, 0]),
        err(Errno::ESPIPE)
    );
    assert_eq!(call(&mut t, Sysno::lseek, &[r, 0, 0]), err(Errno::ESPIPE));
    // Closing the writer gives EOF.
    assert_eq!(call(&mut t, Sysno::close, &[w]), ok(0));
    assert_eq!(call(&mut t, Sysno::read, &[r, OUT + 32, 10]), ok(0));
    // Writing without a reader: -EPIPE and SIGPIPE (`send_sig`), pending because
    // it is neither ignored nor blocked.
    let mut t2 = self::t();
    assert_eq!(call(&mut t2, Sysno::pipe2, &[OUT, 0]), ok(0));
    assert_eq!(call(&mut t2, Sysno::close, &[3]), ok(0));
    assert_eq!(call(&mut t2, Sysno::write, &[4, BUF, 1]), err(Errno::EPIPE));
    assert!(t2.state.pending_set().contains(SIGPIPE));
    // An ignored SIGPIPE is not queued; the write still fails with EPIPE.
    t2.state.flush_signals(!0);
    t2.state.hand.actions[usize::from(SIGPIPE) - 1].handler = SIG_IGN;
    assert_eq!(call(&mut t2, Sysno::write, &[4, BUF, 1]), err(Errno::EPIPE));
    assert!(!t2.state.pending_set().contains(SIGPIPE));
}

#[test]
fn blocking_pipe_and_console_waits_are_interrupted_by_a_signal() {
    let mut t = t();
    assert_eq!(call(&mut t, Sysno::pipe2, &[OUT, 0]), ok(0));
    // A timer is the only thing that can wake the task: with none armed the
    // wait would never end (Linux sleeps forever too).
    assert!(would_hang(|| call(&mut t, Sysno::read, &[3, BUF, 1])));
    assert_eq!(call(&mut t, Sysno::alarm, &[1]), ok(0));
    // `anon_pipe_read`: nothing read, `-ERESTARTSYS` with SIGALRM pending.
    assert_eq!(call(&mut t, Sysno::read, &[3, BUF, 1]), ok(-512));
    assert!(t.state.pending_set().contains(SIGALRM));
    assert_eq!(t.now, 1_000_000_000);
    // A signal that is already pending interrupts at once, without waiting.
    let waits = t.waits;
    assert_eq!(call(&mut t, Sysno::read, &[3, BUF, 1]), ok(-512));
    assert_eq!(
        call(&mut t, Sysno::read, &[0, BUF, 1]),
        ok(-512),
        "n_tty_read"
    );
    assert_eq!(t.waits, waits);
    // `anon_pipe_write` on a full pipe: nothing written restarts, a partial
    // write is returned.
    let mut full = self::t();
    assert_eq!(call(&mut full, Sysno::pipe2, &[OUT, 0]), ok(0));
    put(&mut full, BUF, &[b'x'; 4096]);
    for _ in 0..16 {
        assert_eq!(call(&mut full, Sysno::write, &[4, BUF, 4096]), ok(4096));
    }
    assert!(would_hang(|| call(&mut full, Sysno::write, &[4, BUF, 1])));
    assert_eq!(call(&mut full, Sysno::alarm, &[1]), ok(0));
    assert_eq!(call(&mut full, Sysno::write, &[4, BUF, 1]), ok(-512));
    // Room for exactly one page: the write that then fills it returns the
    // partial count instead of restarting.
    assert_eq!(call(&mut full, Sysno::read, &[3, OUT, 4096]), ok(4096));
    assert_eq!(call(&mut full, Sysno::write, &[4, BUF, 4096 + 1]), ok(4096));
}

#[test]
fn a_wait_whose_only_wakeup_expired_into_nothing_sleeps_forever() {
    // One-shot alarm whose SIGALRM is ignored, then blocked: it fires during
    // the wait, never becomes pending, and nothing else could wake the task.
    for blocked in [false, true] {
        let mut t = t();
        assert_eq!(call(&mut t, Sysno::pipe2, &[OUT, 0]), ok(0));
        if blocked {
            t.state.me.blocked = SigSet(SigSet::bit(SIGALRM));
        } else {
            t.state.hand.actions[usize::from(SIGALRM) - 1].handler = SIG_IGN;
        }
        assert_eq!(call(&mut t, Sysno::alarm, &[1]), ok(0));
        assert!(would_hang(|| call(&mut t, Sysno::read, &[3, BUF, 1])));
        assert_eq!(t.now, 1_000_000_000, "the timer had expired first");
    }
}

#[test]
fn pipe2_flags_and_nonblocking_ends() {
    let mut t = t();
    assert_eq!(
        call(&mut t, Sysno::pipe2, &[OUT, 0x8000_0000]),
        err(Errno::EINVAL)
    );
    assert_eq!(call(&mut t, Sysno::pipe2, &[BAD, 0]), err(Errno::EFAULT));
    assert_eq!(
        call(&mut t, Sysno::fcntl, &[3, 1, 0]),
        err(Errno::EBADF),
        "a failed pipe2 leaks no descriptor"
    );
    assert_eq!(
        call(
            &mut t,
            Sysno::pipe2,
            &[OUT, u64::from(O_NONBLOCK | O_CLOEXEC)]
        ),
        ok(0)
    );
    assert_eq!(call(&mut t, Sysno::fcntl, &[3, 1, 0]), ok(1));
    assert_eq!(
        call(&mut t, Sysno::fcntl, &[3, 3, 0]),
        ok(i64::from(O_NONBLOCK))
    );
    assert_eq!(call(&mut t, Sysno::read, &[3, BUF, 1]), err(Errno::EAGAIN));
    // Fill the pipe: 16 pages, then EAGAIN; a partial write reports its length.
    put(&mut t, BUF, &[1; 8]);
    for _ in 0..16 * 512 {
        assert_eq!(call(&mut t, Sysno::write, &[4, BUF, 8]), ok(8));
    }
    assert_eq!(call(&mut t, Sysno::write, &[4, BUF, 8]), err(Errno::EAGAIN));
}

#[test]
fn memory_devices_behave_like_drivers_mem() {
    let mut t = t();
    let major_minor = |major, minor| u64::from(new_encode_dev(mkdev(major, minor)));
    for (name, dev) in [("/null", (1, 3)), ("/zero", (1, 5)), ("/full", (1, 7))] {
        let at = cstr(&mut t, PATH, name);
        assert_eq!(
            call(
                &mut t,
                Sysno::mknod,
                &[at, u64::from(S_IFCHR | 0o666), major_minor(dev.0, dev.1)]
            ),
            ok(0)
        );
    }
    let null = fd(open(&mut t, "/null", O_RDWR, 0));
    put(&mut t, BUF, b"discard");
    assert_eq!(call(&mut t, Sysno::write, &[null, BUF, 7]), ok(7));
    // The buffer is never touched, only range-checked.
    assert_eq!(call(&mut t, Sysno::write, &[null, BAD, 7]), ok(7));
    assert_eq!(
        call(&mut t, Sysno::write, &[null, u64::MAX - 3, 7]),
        err(Errno::EFAULT)
    );
    assert_eq!(call(&mut t, Sysno::read, &[null, BUF, 7]), ok(0));
    assert_eq!(
        call(&mut t, Sysno::lseek, &[null, 9, 0]),
        ok(0),
        "null_lseek"
    );
    let zero = fd(open(&mut t, "/zero", O_RDWR, 0));
    assert_eq!(call(&mut t, Sysno::read, &[zero, BUF, 7]), ok(7));
    assert_eq!(get(&mut t, BUF, 7), [0; 7]);
    assert_eq!(call(&mut t, Sysno::write, &[zero, BUF, 7]), ok(7));
    let full = fd(open(&mut t, "/full", O_RDWR, 0));
    assert_eq!(
        call(&mut t, Sysno::write, &[full, BUF, 7]),
        err(Errno::ENOSPC)
    );
    assert_eq!(
        call(&mut t, Sysno::write, &[full, BUF, 0]),
        err(Errno::ENOSPC)
    );
    // The node reports its device through stat.
    assert_eq!(call(&mut t, Sysno::fstat, &[null, OUT]), ok(0));
    assert_eq!(u32_at(&mut t, OUT + 24), S_IFCHR | 0o644, "0666 & ~022");
    assert_eq!(u64_at(&mut t, OUT + 40), major_minor(1, 3), "st_rdev");
    // Existing, directory-typed and unprivileged-type mknods.
    let at = cstr(&mut t, PATH, "/null");
    assert_eq!(
        call(&mut t, Sysno::mknod, &[at, u64::from(S_IFCHR | 0o600), 0]),
        err(Errno::EEXIST)
    );
    let at = cstr(&mut t, PATH, "/dir");
    assert_eq!(
        call(&mut t, Sysno::mknod, &[at, u64::from(S_IFDIR | 0o755), 0]),
        err(Errno::EPERM)
    );
}

#[test]
fn console_descriptors_write_through_the_tty_and_block_on_read() {
    let mut t = t();
    put(&mut t, BUF, b"a\nb");
    assert_eq!(call(&mut t, Sysno::write, &[1, BUF, 3]), ok(3));
    assert_eq!(t.sink.0, b"a\r\nb", "ONLCR");
    assert!(would_hang(|| call(&mut t, Sysno::read, &[0, BUF, 1])));
    assert_eq!(
        call(&mut t, Sysno::ioctl, &[0, 0x5401, OUT]),
        ok(0),
        "TCGETS"
    );
    assert_eq!(u32_at(&mut t, OUT), 0o2400);
    assert_eq!(
        call(&mut t, Sysno::ioctl, &[0, 0x5413, OUT]),
        ok(0),
        "TIOCGWINSZ"
    );
    assert_eq!(
        call(&mut t, Sysno::ioctl, &[0, 0x5401, BAD]),
        err(Errno::EFAULT)
    );
    assert_eq!(
        call(&mut t, Sysno::ioctl, &[0, 0x540f, OUT]),
        err(Errno::ENOTTY),
        "TIOCGPGRP"
    );
    // fd 1 is the same open file as fd 0: closing one leaves the other usable.
    assert_eq!(call(&mut t, Sysno::close, &[0]), ok(0));
    assert_eq!(call(&mut t, Sysno::write, &[1, BUF, 1]), ok(1));
    assert_eq!(
        call(&mut t, Sysno::ioctl, &[0, 0x5401, OUT]),
        err(Errno::EBADF)
    );
}

#[test]
fn directories_chdir_getcwd_and_getdents() {
    let mut t = t();
    let env = t.vfs.kernel_env();
    t.vfs.mkdir(&env, b"/sub", 0o755).unwrap();
    t.vfs.mknod(&env, b"/sub/a", S_IFREG | 0o600, 0).unwrap();
    t.vfs.mknod(&env, b"/sub/b", S_IFREG | 0o600, 0).unwrap();
    assert_eq!(call(&mut t, Sysno::getcwd, &[OUT, 64]), ok(2));
    assert_eq!(get(&mut t, OUT, 2), b"/\0");
    let at = cstr(&mut t, PATH, "/sub");
    assert_eq!(call(&mut t, Sysno::chdir, &[at]), ok(0));
    assert_eq!(call(&mut t, Sysno::getcwd, &[OUT, 64]), ok(5));
    assert_eq!(get(&mut t, OUT, 5), b"/sub\0");
    assert_eq!(call(&mut t, Sysno::getcwd, &[OUT, 4]), err(Errno::ERANGE));
    assert_eq!(call(&mut t, Sysno::getcwd, &[BAD, 64]), err(Errno::EFAULT));
    // A relative open resolves against the working directory.
    let a = fd(open(&mut t, "a", O_RDONLY, 0));
    assert_eq!(call(&mut t, Sysno::fstat, &[a, OUT]), ok(0));
    // chdir errors.
    let at = cstr(&mut t, PATH, "a");
    assert_eq!(call(&mut t, Sysno::chdir, &[at]), err(Errno::ENOTDIR));
    let at = cstr(&mut t, PATH, "missing");
    assert_eq!(call(&mut t, Sysno::chdir, &[at]), err(Errno::ENOENT));
    assert_eq!(call(&mut t, Sysno::fchdir, &[a]), err(Errno::ENOTDIR));
    assert_eq!(call(&mut t, Sysno::fchdir, &[99]), err(Errno::EBADF));
    // getdents64 lists newest first and ends with 0.
    let dir = fd(open(&mut t, ".", O_RDONLY | O_DIRECTORY, 0));
    assert_eq!(
        call(&mut t, Sysno::getdents64, &[dir, BUF, 8]),
        err(Errno::EINVAL),
        "too small"
    );
    let n = match call(&mut t, Sysno::getdents64, &[dir, BUF, 4096]) {
        Outcome::Return(n) if n > 0 => n as usize,
        other => panic!("{other:?}"),
    };
    let raw = get(&mut t, BUF, n);
    let mut names = Vec::new();
    let mut at = 0;
    while at < raw.len() {
        let reclen = usize::from(u16::from_le_bytes([raw[at + 16], raw[at + 17]]));
        assert_eq!(reclen % 8, 0, "records are 8-byte aligned");
        let end = raw[at + 19..].iter().position(|&b| b == 0).unwrap();
        names.push((
            String::from_utf8(raw[at + 19..at + 19 + end].to_vec()).unwrap(),
            raw[at + 18],
        ));
        at += reclen;
    }
    assert_eq!(
        names,
        [
            (String::from("."), 4),
            (String::from(".."), 4),
            (String::from("b"), 8),
            (String::from("a"), 8)
        ]
    );
    assert_eq!(call(&mut t, Sysno::getdents64, &[dir, BUF, 4096]), ok(0));
    assert_eq!(call(&mut t, Sysno::lseek, &[dir, 0, 0]), ok(0), "rewind");
    assert!(
        matches!(call(&mut t, Sysno::getdents64, &[dir, BUF, 4096]), Outcome::Return(n) if n > 0)
    );
    assert_eq!(
        call(&mut t, Sysno::getdents64, &[a, BUF, 4096]),
        err(Errno::ENOTDIR)
    );
    assert_eq!(
        call(&mut t, Sysno::read, &[dir, BUF, 1]),
        err(Errno::EISDIR)
    );
    // fchdir back to the root and a path through `..`.
    let root = fd(open(&mut t, "/", O_RDONLY, 0));
    assert_eq!(call(&mut t, Sysno::fchdir, &[root]), ok(0));
    assert_eq!(call(&mut t, Sysno::getcwd, &[OUT, 64]), ok(2));
    // Removing the working directory leaves getcwd with ENOENT (d_unlinked).
    let at = cstr(&mut t, PATH, "/sub");
    assert_eq!(call(&mut t, Sysno::chdir, &[at]), ok(0));
    t.vfs.unlink(&env, b"/sub/a").unwrap();
    t.vfs.unlink(&env, b"/sub/b").unwrap();
    t.vfs.rmdir(&env, b"/sub").unwrap();
    assert_eq!(call(&mut t, Sysno::getcwd, &[OUT, 64]), err(Errno::ENOENT));
}

#[test]
fn path_syscalls_report_errors_in_order() {
    let mut t = t();
    assert_eq!(open(&mut t, "", O_RDONLY, 0), err(Errno::ENOENT));
    assert_eq!(open(&mut t, "/nope", O_RDONLY, 0), err(Errno::ENOENT));
    assert_eq!(
        open(&mut t, "/dev/console/x", O_RDONLY, 0),
        err(Errno::ENOTDIR)
    );
    assert_eq!(open(&mut t, "/dev", O_WRONLY, 0), err(Errno::EISDIR));
    assert_eq!(
        open(&mut t, "/dev", O_RDONLY | O_CREAT, 0o600),
        err(Errno::EISDIR)
    );
    assert_eq!(
        open(&mut t, "/dev/console", O_CREAT | O_EXCL | O_RDWR, 0o600),
        err(Errno::EEXIST)
    );
    assert_eq!(
        call(&mut t, Sysno::open, &[BAD, 0, 0]),
        err(Errno::EFAULT),
        "unmapped pathname"
    );
    assert_eq!(
        call(&mut t, Sysno::open, &[0, 0, 0]),
        err(Errno::EFAULT),
        "NULL pathname"
    );
    // 4096 bytes without a NUL is ENAMETOOLONG; a 256-byte component too.
    put(&mut t, 0x4000, &[b'a'; 4096]);
    t.pages.map(0x6000, true);
    assert_eq!(
        call(&mut t, Sysno::open, &[0x4000, 0, 0]),
        err(Errno::ENAMETOOLONG)
    );
    let mut long = String::from("/");
    long.push_str(&"a".repeat(256));
    assert_eq!(open(&mut t, &long, O_RDONLY, 0), err(Errno::ENAMETOOLONG));
    // openat: relative to a directory descriptor, absolute paths ignore it, a
    // file descriptor as the base is ENOTDIR.
    let dev = fd(open(&mut t, "/dev", O_RDONLY | O_DIRECTORY, 0));
    let console = cstr(&mut t, PATH2, "console");
    let abs = cstr(&mut t, PATH2 + 16, "/root");
    assert!(matches!(
        call(&mut t, Sysno::openat, &[dev, console, u64::from(O_RDONLY), 0]),
        Outcome::Return(n) if n >= 0
    ));
    assert!(matches!(
        call(&mut t, Sysno::openat, &[7, abs, u64::from(O_RDONLY), 0]),
        Outcome::Return(n) if n >= 0
    ));
    assert_eq!(
        call(&mut t, Sysno::openat, &[7, console, 0, 0]),
        err(Errno::EBADF)
    );
    let file = fd(open(&mut t, "/dev/console", O_RDONLY, 0));
    assert_eq!(
        call(&mut t, Sysno::openat, &[file, console, 0, 0]),
        err(Errno::ENOTDIR)
    );
    // AT_FDCWD as a 32-bit -100 in a 64-bit register.
    assert!(matches!(
        call(&mut t, Sysno::openat, &[(AT_FDCWD as u32).into(), abs, 0, 0]),
        Outcome::Return(n) if n >= 0
    ));
}

#[test]
fn unlink_keeps_open_files_alive() {
    let mut t = t();
    let f = fd(open(&mut t, "/f", O_CREAT | O_RDWR, 0o600));
    put(&mut t, BUF, b"still here");
    assert_eq!(call(&mut t, Sysno::write, &[f, BUF, 10]), ok(10));
    let at = cstr(&mut t, PATH, "/f");
    assert_eq!(call(&mut t, Sysno::unlink, &[at]), ok(0));
    assert_eq!(call(&mut t, Sysno::unlink, &[at]), err(Errno::ENOENT));
    assert_eq!(open(&mut t, "/f", O_RDONLY, 0), err(Errno::ENOENT));
    assert_eq!(call(&mut t, Sysno::pread64, &[f, OUT, 10, 0]), ok(10));
    assert_eq!(get(&mut t, OUT, 10), b"still here");
    assert_eq!(call(&mut t, Sysno::fstat, &[f, OUT]), ok(0));
    assert_eq!(u64_at(&mut t, OUT + 16), 0, "st_nlink");
    let at = cstr(&mut t, PATH, "/dev");
    assert_eq!(call(&mut t, Sysno::unlink, &[at]), err(Errno::EISDIR));
    let at = cstr(&mut t, PATH, "/dev/console/");
    assert_eq!(call(&mut t, Sysno::unlink, &[at]), err(Errno::ENOTDIR));
}

#[test]
fn stat_family_agrees_with_itself_and_with_the_console_node() {
    let mut t = t();
    let at = cstr(&mut t, PATH, "/dev/console");
    assert_eq!(call(&mut t, Sysno::stat, &[at, OUT]), ok(0));
    assert_eq!(u32_at(&mut t, OUT + 24), S_IFCHR | 0o600);
    assert_eq!(
        u64_at(&mut t, OUT + 40),
        u64::from(new_encode_dev(mkdev(5, 1)))
    );
    assert_eq!(call(&mut t, Sysno::lstat, &[at, OUT + 256]), ok(0));
    assert_eq!(get(&mut t, OUT, 144), get(&mut t, OUT + 256, 144));
    // newfstatat with AT_EMPTY_PATH on a descriptor, and the flag rules.
    let empty = cstr(&mut t, PATH2, "");
    assert_eq!(
        call(
            &mut t,
            Sysno::newfstatat,
            &[0, empty, OUT + 512, u64::from(AT_EMPTY_PATH)]
        ),
        ok(0)
    );
    assert_eq!(get(&mut t, OUT, 144), get(&mut t, OUT + 512, 144));
    assert_eq!(
        call(&mut t, Sysno::newfstatat, &[0, empty, OUT, 0]),
        err(Errno::ENOENT)
    );
    assert_eq!(
        call(&mut t, Sysno::newfstatat, &[0, at, OUT, 0x8000]),
        err(Errno::EINVAL)
    );
    // statx: mask, mode and device numbers in their own layout.
    assert_eq!(
        call(
            &mut t,
            Sysno::statx,
            &[AT_FDCWD as u32 as u64, at, 0, 0xfff, OUT + 1024]
        ),
        ok(0)
    );
    let mask = u32_at(&mut t, OUT + 1024);
    assert_eq!(mask & 0x7ff, 0x7ff, "STATX_BASIC_STATS");
    assert_eq!(u32_at(&mut t, OUT + 1024 + 28) & 0xffff, S_IFCHR | 0o600);
    assert_eq!(u32_at(&mut t, OUT + 1024 + 128), 5, "stx_rdev_major");
    assert_eq!(u32_at(&mut t, OUT + 1024 + 132), 1, "stx_rdev_minor");
    assert_eq!(
        call(
            &mut t,
            Sysno::statx,
            &[AT_FDCWD as u32 as u64, at, 0, 0x8000_0000, OUT + 1024]
        ),
        err(Errno::EINVAL)
    );
    // Faults copy nothing and report EFAULT after the lookup succeeded.
    assert_eq!(call(&mut t, Sysno::stat, &[at, BAD]), err(Errno::EFAULT));
    assert_eq!(call(&mut t, Sysno::fstat, &[99, OUT]), err(Errno::EBADF));
}

#[test]
fn access_readlink_and_ftruncate() {
    let mut t = t();
    let env = t.vfs.kernel_env();
    t.vfs.symlink(&env, b"/dev/console", b"/link").unwrap();
    let plain = fd(open(&mut t, "/plain", O_CREAT | O_RDWR, 0o644));
    let p = cstr(&mut t, PATH, "/plain");
    assert_eq!(call(&mut t, Sysno::access, &[p, 0]), ok(0), "F_OK");
    assert_eq!(
        call(&mut t, Sysno::access, &[p, 6]),
        ok(0),
        "root reads and writes"
    );
    assert_eq!(
        call(&mut t, Sysno::access, &[p, 1]),
        err(Errno::EACCES),
        "no execute bit"
    );
    assert_eq!(call(&mut t, Sysno::access, &[p, 8]), err(Errno::EINVAL));
    assert_eq!(
        call(&mut t, Sysno::faccessat, &[AT_FDCWD as u32 as u64, p, 4]),
        ok(0)
    );
    assert_eq!(
        call(
            &mut t,
            Sysno::faccessat2,
            &[AT_FDCWD as u32 as u64, p, 4, 0x8000]
        ),
        err(Errno::EINVAL)
    );
    assert_eq!(
        call(
            &mut t,
            Sysno::faccessat2,
            &[AT_FDCWD as u32 as u64, p, 1, 0x200]
        ),
        err(Errno::EACCES),
        "AT_EACCESS"
    );
    // readlink returns the target without a NUL and truncates to the buffer.
    let l = cstr(&mut t, PATH2, "/link");
    assert_eq!(call(&mut t, Sysno::readlink, &[l, OUT, 100]), ok(12));
    assert_eq!(get(&mut t, OUT, 12), b"/dev/console");
    assert_eq!(call(&mut t, Sysno::readlink, &[l, OUT, 4]), ok(4));
    assert_eq!(
        call(&mut t, Sysno::readlink, &[l, OUT, 0]),
        err(Errno::EINVAL)
    );
    assert_eq!(
        call(&mut t, Sysno::readlink, &[p, OUT, 100]),
        err(Errno::EINVAL)
    );
    let missing = cstr(&mut t, PATH2, "/missing");
    assert_eq!(
        call(&mut t, Sysno::readlink, &[missing, OUT, 100]),
        err(Errno::ENOENT)
    );
    // ftruncate.
    put(&mut t, BUF, b"0123456789");
    assert_eq!(call(&mut t, Sysno::write, &[plain, BUF, 10]), ok(10));
    assert_eq!(call(&mut t, Sysno::ftruncate, &[plain, 4]), ok(0));
    assert_eq!(call(&mut t, Sysno::fstat, &[plain, OUT]), ok(0));
    assert_eq!(u64_at(&mut t, OUT + 48), 4);
    assert_eq!(
        call(&mut t, Sysno::ftruncate, &[plain, u64::MAX]),
        err(Errno::EINVAL)
    );
    let ro = fd(open(&mut t, "/plain", O_RDONLY, 0));
    assert_eq!(call(&mut t, Sysno::ftruncate, &[ro, 0]), err(Errno::EINVAL));
    assert_eq!(call(&mut t, Sysno::ftruncate, &[99, 0]), err(Errno::EBADF));
    let dir = fd(open(&mut t, "/dev", O_RDONLY, 0));
    assert_eq!(
        call(&mut t, Sysno::ftruncate, &[dir, 0]),
        err(Errno::EINVAL)
    );
}

#[test]
fn vectored_io_copies_segments_in_order_and_stops_at_a_fault() {
    let mut t = t();
    let f = fd(open(&mut t, "/f", O_CREAT | O_RDWR, 0o644));
    put(&mut t, BUF, b"0123456789");
    assert_eq!(call(&mut t, Sysno::write, &[f, BUF, 10]), ok(10));
    // iovec[2] = { OUT, 4 }, { OUT + 100, 3 }
    let mut iov = Vec::new();
    for (base, len) in [(OUT, 4u64), (OUT + 100, 3)] {
        iov.extend_from_slice(&base.to_le_bytes());
        iov.extend_from_slice(&len.to_le_bytes());
    }
    put(&mut t, 0x4000, &iov);
    assert_eq!(call(&mut t, Sysno::pread64, &[f, OUT, 0, 0]), ok(0));
    assert_eq!(call(&mut t, Sysno::preadv, &[f, 0x4000, 2, 2]), ok(7));
    assert_eq!(get(&mut t, OUT, 4), b"2345");
    assert_eq!(get(&mut t, OUT + 100, 3), b"678");
    assert_eq!(call(&mut t, Sysno::lseek, &[f, 0, 0]), ok(0));
    assert_eq!(call(&mut t, Sysno::readv, &[f, 0x4000, 2]), ok(7));
    assert_eq!(
        call(&mut t, Sysno::lseek, &[f, 0, 1]),
        ok(7),
        "readv advances the position"
    );
    assert_eq!(
        call(&mut t, Sysno::readv, &[f, 0x4000, 1025]),
        err(Errno::EINVAL),
        "UIO_MAXIOV"
    );
    assert_eq!(call(&mut t, Sysno::readv, &[f, BAD, 2]), err(Errno::EFAULT));
    assert_eq!(call(&mut t, Sysno::readv, &[f, 0x4000, 0]), ok(0));
    assert_eq!(
        call(&mut t, Sysno::preadv, &[f, 0x4000, 2, (-1i64) as u64]),
        err(Errno::EINVAL)
    );
    // A segment pointing into unmapped memory fails the whole call at the first byte.
    let mut bad = Vec::new();
    bad.extend_from_slice(&BAD.to_le_bytes());
    bad.extend_from_slice(&4u64.to_le_bytes());
    put(&mut t, 0x4100, &bad);
    assert_eq!(
        call(&mut t, Sysno::readv, &[f, 0x4100, 1]),
        err(Errno::EFAULT)
    );
}

#[test]
fn unported_behaviour_stops_instead_of_answering() {
    let mut t = t();
    let f = fd(open(&mut t, "/f", O_CREAT | O_RDWR, 0o644));
    // Linux implements these; this slice does not: a loud stop, never ENOSYS.
    assert_eq!(
        call(&mut t, Sysno::ioctl, &[f, 0x5451 + 0x100, 0]),
        err(Errno::ENOTTY)
    );
    assert_eq!(
        call(&mut t, Sysno::ioctl, &[0, 0x5415, 0]),
        Outcome::Unimplemented(16)
    );
    // FASYNC: a regular file has no ->fasync, so the bit is ignored; the
    // console has one (SIGIO), which is a loud stop.
    assert_eq!(call(&mut t, Sysno::fcntl, &[f, 4, 0o20000]), ok(0));
    assert_eq!(
        call(&mut t, Sysno::fcntl, &[f, 3, 0]),
        ok(0o100_002),
        "FASYNC not stored"
    );
    assert_eq!(
        call(&mut t, Sysno::fcntl, &[0, 4, 0o20000]),
        Outcome::Unimplemented(72)
    );
}

// ---- review round 1 -----------------------------------------------------------------

fn limit_fsize(t: &mut Task, cur: u64) {
    t.attrs
        .rlimits
        .prlimit(1, Some(crate::task::Rlimit { cur, max: cur }))
        .unwrap();
}

#[test]
fn rlimit_fsize_clamps_writes_and_sends_sigxfsz_with_efbig() {
    let mut t = t();
    let f = fd(open(&mut t, "/f", O_CREAT | O_RDWR, 0o644));
    let app = fd(open(&mut t, "/f", O_WRONLY | O_APPEND, 0));
    limit_fsize(&mut t, 4);
    put(&mut t, BUF, b"0123456789");
    // generic_write_check_limits: a write that starts below the limit is cut.
    assert_eq!(call(&mut t, Sysno::write, &[f, BUF, 10]), ok(4));
    // At the limit: -EFBIG with SIGXFSZ (`send_sig`), each time.
    let sigxfsz = |t: &mut Task| {
        let pending = t.state.pending_set().contains(SIGXFSZ);
        t.state.flush_signals(!0);
        pending
    };
    assert!(!sigxfsz(&mut t));
    assert_eq!(call(&mut t, Sysno::write, &[f, BUF, 10]), err(Errno::EFBIG));
    assert!(sigxfsz(&mut t));
    assert_eq!(
        call(&mut t, Sysno::write, &[app, BUF, 1]),
        err(Errno::EFBIG),
        "O_APPEND starts at the size"
    );
    assert!(sigxfsz(&mut t));
    assert_eq!(call(&mut t, Sysno::pwrite64, &[f, BUF, 10, 2]), ok(2));
    assert!(!sigxfsz(&mut t), "a clamped write sends nothing");
    assert_eq!(
        call(&mut t, Sysno::pwrite64, &[f, BUF, 1, 5]),
        err(Errno::EFBIG)
    );
    assert!(sigxfsz(&mut t));
    // inode_newsize_ok only guards growth.
    assert_eq!(call(&mut t, Sysno::ftruncate, &[f, 4]), ok(0));
    assert_eq!(call(&mut t, Sysno::ftruncate, &[f, 5]), err(Errno::EFBIG));
    assert!(sigxfsz(&mut t));
    assert_eq!(call(&mut t, Sysno::ftruncate, &[f, 1]), ok(0));
    assert_eq!(call(&mut t, Sysno::ftruncate, &[f, 4]), ok(0));
    // Unlimited again.
    limit_fsize(&mut t, u64::MAX);
    assert_eq!(call(&mut t, Sysno::write, &[f, BUF, 10]), ok(10));
    assert_eq!(call(&mut t, Sysno::ftruncate, &[f, 1 << 20]), ok(0));
}

#[test]
fn vfs_ioctls_answer_as_tmpfs_does() {
    let mut t = t();
    let f = fd(open(&mut t, "/f", O_CREAT | O_RDWR, 0o644));
    put(&mut t, BUF, b"hello");
    assert_eq!(call(&mut t, Sysno::write, &[f, BUF, 5]), ok(5));
    // FIOQSIZE is inode_get_bytes(): allocated bytes, not the size.
    assert_eq!(call(&mut t, Sysno::ioctl, &[f, 0x5460, OUT]), ok(0));
    assert_eq!(u64_at(&mut t, OUT), 4096);
    let dir = fd(open(&mut t, "/dev", O_RDONLY | O_DIRECTORY, 0));
    put(&mut t, OUT, &[0xff; 8]);
    assert_eq!(call(&mut t, Sysno::ioctl, &[dir, 0x5460, OUT]), ok(0));
    assert_eq!(u64_at(&mut t, OUT), 0);
    // FS_IOC_GETFLAGS / FS_IOC_FSGETXATTR: shmem_fileattr_get, flags 0.
    put(&mut t, OUT, &[0xff; 32]);
    assert_eq!(call(&mut t, Sysno::ioctl, &[f, 0x8008_6601, OUT]), ok(0));
    assert_eq!(get(&mut t, OUT, 8), [0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]);
    assert_eq!(call(&mut t, Sysno::ioctl, &[dir, 0x801c_581f, OUT]), ok(0));
    assert_eq!(
        get(&mut t, OUT, 32),
        [[0u8; 28].as_slice(), &[0xff; 4]].concat()
    );
    let null = fd(open(&mut t, "/dev/console", O_RDWR, 0));
    assert_eq!(
        call(&mut t, Sysno::ioctl, &[null, 0x8008_6601, OUT]),
        err(Errno::ENOTTY),
        "no ->fileattr_get on a device node"
    );
    // The commands tmpfs answers other than with ENOTTY stop loudly.
    for cmd in [
        0x4008_6602u64,
        0x401c_5820,
        0xc020_660b,
        0x4004_9409,
        0x4020_940d,
        0xc018_9436,
        0x8011_1500,
        0x8081_1501,
        1,
        0x4030_5828,
        0x4030_5839,
    ] {
        assert_eq!(
            call(&mut t, Sysno::ioctl, &[f, cmd, OUT]),
            Outcome::Unimplemented(16),
            "{cmd:#x}"
        );
    }
    // FIGETBSZ is the superblock's block size, pipefs included.
    let mut pair = [0u8; 8];
    put(&mut t, OUT, &pair);
    assert_eq!(call(&mut t, Sysno::pipe2, &[OUT, 0]), ok(0));
    pair.copy_from_slice(&get(&mut t, OUT, 8));
    let read_end = u64::from(u32::from_le_bytes(pair[..4].try_into().unwrap()));
    assert_eq!(call(&mut t, Sysno::ioctl, &[read_end, 2, BUF]), ok(0));
    assert_eq!(u32_at(&mut t, BUF), 4096);
    // ioctl_fsfreeze checks CAP_SYS_ADMIN before asking tmpfs.
    assert_eq!(
        call(&mut t, Sysno::ioctl, &[f, 0xc004_5877, 0]),
        err(Errno::EOPNOTSUPP)
    );
    t.attrs.cred.euid = 1000;
    assert_eq!(
        call(&mut t, Sysno::ioctl, &[f, 0xc004_5878, 0]),
        err(Errno::EPERM)
    );
}

#[test]
fn a_removed_directory_is_dead_for_a_process_still_inside_it() {
    let mut t = t();
    let env = t.vfs.kernel_env();
    t.vfs.mkdir(&env, b"/sub", 0o755).unwrap();
    let at = cstr(&mut t, PATH, "/sub");
    assert_eq!(call(&mut t, Sysno::chdir, &[at]), ok(0));
    let dot = fd(open(&mut t, ".", O_RDONLY | O_DIRECTORY, 0));
    t.vfs.rmdir(&env, b"/sub").unwrap();
    assert_eq!(
        open(&mut t, "x", O_CREAT | O_RDWR, 0o600),
        err(Errno::ENOENT)
    );
    assert_eq!(open(&mut t, "x", O_RDONLY, 0), err(Errno::ENOENT));
    assert_eq!(
        call(&mut t, Sysno::getdents64, &[dot, BUF, 4096]),
        err(Errno::ENOENT)
    );
    let env = crate::vfs::ops::Env {
        start: t.attrs.fs.pwd,
        ..env
    };
    assert_eq!(
        t.vfs.mknod(&env, b"y", S_IFREG | 0o600, 0),
        Err(Errno::ENOENT)
    );
    assert_eq!(t.vfs.mkdir(&env, b"z", 0o700), Err(Errno::ENOENT));
    assert_eq!(t.vfs.symlink(&env, b"t", b"l"), Err(Errno::ENOENT));
}

#[test]
fn truncation_and_noatime_depend_on_the_caller_credentials() {
    let mut t = t();
    let env = t.vfs.kernel_env();
    let inode = t.vfs.mknod(&env, b"/s", S_IFREG | 0o644, 0).unwrap();
    t.vfs.chmod(&env, inode, 0o6777).unwrap();
    let mode = |t: &mut Task| t.vfs.fs.inode(inode).mode & 0o7777;
    assert_eq!(mode(&mut t), 0o6777);
    // root (CAP_FSETID) keeps the set-id bits through O_TRUNC and ftruncate.
    let root = fd(open(&mut t, "/s", O_WRONLY | O_TRUNC, 0));
    assert_eq!(call(&mut t, Sysno::ftruncate, &[root, 0]), ok(0));
    assert_eq!(mode(&mut t), 0o6777);
    // O_NOATIME needs the owner or CAP_FOWNER.
    t.attrs.cred.euid = 1000;
    t.attrs.cred.egid = 1000;
    assert_eq!(
        open(&mut t, "/s", O_RDONLY | 0o1_000_000, 0),
        err(Errno::EPERM)
    );
    let plain = fd(open(&mut t, "/s", O_RDONLY, 0));
    assert_eq!(
        call(&mut t, Sysno::fcntl, &[plain, 4, 0o1_000_000]),
        err(Errno::EPERM)
    );
    // ftruncate by an unprivileged writer clears both bits (setattr_should_drop_suidgid).
    let user = fd(open(&mut t, "/s", O_WRONLY, 0));
    assert_eq!(call(&mut t, Sysno::ftruncate, &[user, 0]), ok(0));
    assert_eq!(mode(&mut t), 0o0777);
    t.vfs.chmod(&env, inode, 0o6777).unwrap();
    let again = fd(open(&mut t, "/s", O_WRONLY | O_TRUNC, 0));
    assert_eq!(mode(&mut t), 0o0777, "O_TRUNC drops them too ({again})");
    // A set-gid file without group execute is dropped only for a non-member.
    t.vfs.chmod(&env, inode, 0o2606).unwrap();
    put(&mut t, BUF, b"x");
    assert_eq!(call(&mut t, Sysno::write, &[user, BUF, 1]), ok(1));
    assert_eq!(mode(&mut t), 0o0606);
}

static TICKS: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(1);

fn ticking_clock() -> crate::vfs::Timespec {
    crate::vfs::Timespec {
        sec: 7,
        nsec: TICKS.fetch_add(1, std::sync::atomic::Ordering::Relaxed) as u32,
    }
}

#[test]
fn timestamps_follow_linux_for_failed_writes_and_for_reads() {
    let mut t = t();
    t.vfs
        .start_timekeeping(ticking_clock, crate::vfs::Timespec { sec: 7, nsec: 0 });
    let f = fd(open(&mut t, "/f", O_CREAT | O_RDWR, 0o644));
    let stamp = |t: &mut Task, fd: u64| {
        assert_eq!(call(t, Sysno::fstat, &[fd, OUT]), ok(0));
        (
            u64_at(t, OUT + 80),
            u64_at(t, OUT + 96),
            u64_at(t, OUT + 112),
        )
    };
    let (a0, m0, c0) = stamp(&mut t, f);
    // file_update_time runs before the copy: a write that then faults still
    // updates mtime and ctime, and leaves atime alone.
    assert_eq!(call(&mut t, Sysno::write, &[f, BAD, 4]), err(Errno::EFAULT));
    let (a1, m1, c1) = stamp(&mut t, f);
    assert_eq!(a1, a0);
    assert!(m1 > m0 && c1 > c0, "{m0} {m1} {c0} {c1}");
    // Every read (even at EOF) updates atime, as without MNT_RELATIME.
    assert_eq!(call(&mut t, Sysno::read, &[f, OUT, 1]), ok(0));
    let (a2, m2, _) = stamp(&mut t, f);
    assert!(a2 > a1);
    assert_eq!(m2, m1);
    // getdents64 and readlink touch the directory and the link.
    let env = t.vfs.kernel_env();
    t.vfs.symlink(&env, b"/f", b"/l").unwrap();
    let dir = fd(open(&mut t, "/", O_RDONLY | O_DIRECTORY, 0));
    let (d0, _, _) = stamp(&mut t, dir);
    assert!(matches!(
        call(&mut t, Sysno::getdents64, &[dir, BUF, 4096]),
        Outcome::Return(n) if n > 0
    ));
    assert!(stamp(&mut t, dir).0 > d0);
    let link = t.vfs.lookup(&env, b"/l", 0).unwrap();
    let before = t.vfs.fs.inode(link).atime;
    let l = cstr(&mut t, PATH2, "/l");
    assert_eq!(call(&mut t, Sysno::readlink, &[l, OUT, 100]), ok(2));
    assert_ne!(t.vfs.fs.inode(link).atime, before);
}

const PROT_READ: u64 = 1;
const PROT_RW: u64 = 3;
const MAP_SHARED: u64 = 1;
const MAP_PRIVATE: u64 = 2;

fn mknod_char(t: &mut Task, path: &str, major: u32, minor: u32) {
    let at = cstr(t, PATH, path);
    let dev = u64::from(new_encode_dev(mkdev(major, minor)));
    assert_eq!(
        call(t, Sysno::mknod, &[at, u64::from(S_IFCHR | 0o666), dev]),
        ok(0)
    );
}

/// src: mm/mmap.c `ksys_mmap_pgoff` (`fget`, `file_mmap_ok`), mm/shmem.c
/// `shmem_mmap`, drivers/char/mem.c `mmap_zero`.
#[test]
fn file_mmap_pins_the_description_and_follows_the_file_kind() {
    let mut t = t();
    let f = fd(open(&mut t, "/f", O_CREAT | O_RDWR, 0o644));
    let content: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
    for (offset, chunk) in content.chunks(1000).enumerate() {
        put(&mut t, BUF, chunk);
        assert_eq!(
            call(
                &mut t,
                Sysno::pwrite64,
                &[f, BUF, 1000, offset as u64 * 1000]
            ),
            ok(1000)
        );
    }
    // A private mapping commits a file VMA and pins the description.
    let Outcome::Return(addr) = call(&mut t, Sysno::mmap, &[0, 8192, PROT_RW, MAP_PRIVATE, f, 0])
    else {
        panic!()
    };
    assert!(addr > 0, "{addr}");
    let vma = *t.mm.find_vma(addr as u64).unwrap();
    let id = vma.file.expect("file-backed VMA");
    assert_eq!(
        (vma.start, vma.end, vma.pgoff),
        (addr as u64, addr as u64 + 8192, 0)
    );
    assert_eq!(t.vfs.pin_count(), 1);
    // The pin keeps the file open after the descriptor is closed.
    assert_eq!(call(&mut t, Sysno::close, &[f]), ok(0));
    assert_eq!(t.vfs.pin_count(), 1);
    // shmem_fault: page 0 is the file, page 1 holds the rest then zeros,
    // page 2 starts at 8192 >= i_size (SIGBUS).
    let mut page = [0u8; 4096];
    t.vfs.fault_page(0, id, 0, &mut page).unwrap();
    assert_eq!(&page[..], &content[..4096]);
    t.vfs.fault_page(0, id, 1, &mut page).unwrap();
    assert_eq!(&page[..904], &content[4096..]);
    assert!(page[904..].iter().all(|&byte| byte == 0));
    assert_eq!(
        t.vfs.fault_page(0, id, 2, &mut page),
        Err(crate::vfs::mapping::FileFault::Bus)
    );
    // The page was copied: writing the file now would differ from Linux's
    // shared page, so the call that does it stops the kernel loudly.
    let again = fd(open(&mut t, "/f", O_RDWR, 0));
    put(&mut t, BUF, b"x");
    assert_eq!(
        call(&mut t, Sysno::write, &[again, BUF, 1]),
        Outcome::Unimplemented(Sysno::write as u32)
    );
    assert_eq!(
        call(&mut t, Sysno::write, &[again, BUF, 1]),
        Outcome::Unimplemented(Sysno::write as u32),
        "the copy stays until the mapping goes"
    );
    // Unmapping drops the pin; afterwards writes are ordinary.
    assert_eq!(call(&mut t, Sysno::munmap, &[addr as u64, 8192]), ok(0));
    assert_eq!(t.vfs.pin_count(), 0);
    assert_eq!(call(&mut t, Sysno::write, &[again, BUF, 1]), ok(1));
}

#[test]
fn file_mmap_checks_come_from_the_descriptor() {
    let mut t = t();
    let f = fd(open(&mut t, "/f", O_CREAT | O_RDWR, 0o644));
    let ro = fd(open(&mut t, "/f", O_RDONLY, 0));
    let wo = fd(open(&mut t, "/f", O_WRONLY, 0));
    let map =
        |t: &mut Task, prot, flags, fd: u64| call(t, Sysno::mmap, &[0, 4096, prot, flags, fd, 0]);
    // fget first; then the model's order (write-only: EACCES; shared writable
    // on a read-only description: EACCES).
    assert_eq!(map(&mut t, PROT_READ, MAP_PRIVATE, 99), err(Errno::EBADF));
    assert_eq!(map(&mut t, PROT_READ, MAP_PRIVATE, wo), err(Errno::EACCES));
    assert_eq!(map(&mut t, PROT_RW, MAP_SHARED, ro), err(Errno::EACCES));
    // Descriptors without ->mmap: directory, console, pipe, null, full.
    let dir = fd(open(&mut t, "/", O_RDONLY | O_DIRECTORY, 0));
    assert_eq!(map(&mut t, PROT_READ, MAP_PRIVATE, dir), err(Errno::ENODEV));
    assert_eq!(map(&mut t, PROT_READ, MAP_PRIVATE, 0), err(Errno::ENODEV));
    mknod_char(&mut t, "/null", 1, 3);
    mknod_char(&mut t, "/full", 1, 7);
    for name in ["/null", "/full"] {
        let node = fd(open(&mut t, name, O_RDWR, 0));
        assert_eq!(
            map(&mut t, PROT_READ, MAP_PRIVATE, node),
            err(Errno::ENODEV)
        );
    }
    assert_eq!(call(&mut t, Sysno::pipe2, &[OUT, 0]), ok(0));
    let pipe = u64::from(u32_at(&mut t, OUT));
    assert_eq!(
        map(&mut t, PROT_READ, MAP_PRIVATE, pipe),
        err(Errno::ENODEV)
    );
    // O_PATH descriptors are refused by fget.
    let at = cstr(&mut t, PATH, "/f");
    let path = fd(call(
        &mut t,
        Sysno::open,
        &[at, u64::from(crate::vfs::O_PATH), 0],
    ));
    assert_eq!(map(&mut t, PROT_READ, MAP_PRIVATE, path), err(Errno::EBADF));
    // A shared writable file mapping needs pages shared with the file: not
    // ported, stops loudly and maps nothing.
    let vmas = t.mm.vmas().len();
    assert_eq!(
        map(&mut t, PROT_RW, MAP_SHARED, f),
        Outcome::Unimplemented(Sysno::mmap as u32)
    );
    assert_eq!((t.mm.vmas().len(), t.vfs.pin_count()), (vmas, 0));
    // A device with a driver we lack stops before any result is guessed.
    mknod_char(&mut t, "/ptmx", 5, 2);
    let tty = fd(open(&mut t, "/ptmx", O_RDWR, 0));
    assert_eq!(
        map(&mut t, PROT_READ, MAP_PRIVATE, tty),
        Outcome::Unimplemented(Sysno::mmap as u32)
    );
}

#[test]
fn private_dev_zero_is_anonymous_and_shared_is_not_ported() {
    let mut t = t();
    mknod_char(&mut t, "/zero", 1, 5);
    let zero = fd(open(&mut t, "/zero", O_RDWR, 0));
    let Outcome::Return(addr) = call(
        &mut t,
        Sysno::mmap,
        &[0, 4096, PROT_RW, MAP_PRIVATE, zero, 0],
    ) else {
        panic!()
    };
    let vma = *t.mm.find_vma(addr as u64).unwrap();
    assert!(vma.file.is_none(), "vma_set_anonymous");
    assert_eq!(t.vfs.pin_count(), 0);
    assert_eq!(
        call(
            &mut t,
            Sysno::mmap,
            &[0, 4096, PROT_RW, MAP_SHARED, zero, 0]
        ),
        Outcome::Unimplemented(Sysno::mmap as u32),
        "shmem_zero_setup"
    );
}

#[test]
fn truncating_a_file_with_a_touched_mapping_stops_loudly() {
    let mut t = t();
    let f = fd(open(&mut t, "/f", O_CREAT | O_RDWR, 0o644));
    assert_eq!(call(&mut t, Sysno::ftruncate, &[f, 100]), ok(0));
    let Outcome::Return(addr) = call(
        &mut t,
        Sysno::mmap,
        &[0, 4096, PROT_READ, MAP_PRIVATE, f, 0],
    ) else {
        panic!()
    };
    // Untouched mapping: no copy exists, so truncation is ordinary.
    assert_eq!(call(&mut t, Sysno::ftruncate, &[f, 200]), ok(0));
    let id = t.mm.find_vma(addr as u64).unwrap().file.unwrap();
    t.vfs.fault_page(0, id, 0, &mut [0; 4096]).unwrap();
    assert_eq!(
        call(&mut t, Sysno::ftruncate, &[f, 50]),
        Outcome::Unimplemented(Sysno::ftruncate as u32)
    );
}

const MAP_FIXED: u64 = 0x10;
const MAP_ANONYMOUS: u64 = 0x20;
const MAP_LOCKED: u64 = 0x2000;
const MAP_POPULATE: u64 = 0x8000;

/// A file of `pages` pages of 0x11, 0x22, ... mapped privately read-write.
fn mapped_file(t: &mut Task, pages: u64) -> (u64, u64) {
    let f = fd(open(t, "/f", O_CREAT | O_RDWR, 0o644));
    for page in 0..pages {
        put(t, BUF, &[0x11 * (page as u8 + 1); 64]);
        assert_eq!(call(t, Sysno::pwrite64, &[f, BUF, 64, page * 4096]), ok(64));
    }
    assert_eq!(call(t, Sysno::ftruncate, &[f, pages * 4096]), ok(0));
    let Outcome::Return(addr) = call(
        t,
        Sysno::mmap,
        &[0, pages * 4096, PROT_RW, MAP_PRIVATE, f, 0],
    ) else {
        panic!()
    };
    (f, addr as u64)
}

/// The copy of a mapped file page is taken while the write's own source buffer
/// is read: only a check after the copy sees it (`fd.rs` `write_regular`).
#[test]
fn a_write_sourced_from_the_files_own_mapping_stops_loudly() {
    let mut t = t();
    let (f, addr) = mapped_file(&mut t, 2);
    assert_eq!(t.vfs.pin_count(), 1);
    // Page 1 of the mapping is untouched, so no copy exists yet.
    assert_eq!(
        call(&mut t, Sysno::pwrite64, &[f, addr + 4096, 32, 0]),
        Outcome::Unimplemented(Sysno::pwrite64 as u32)
    );
    assert!(t.file_pages.contains_key(&(addr + 4096)));
}

/// `write(2)` that copies nothing changes nothing, so it cannot diverge: it is
/// `-EFAULT` even with a copied page (`generic_perform_write` faults first).
#[test]
fn a_write_that_faults_is_not_a_coherence_stop() {
    let mut t = t();
    let (f, addr) = mapped_file(&mut t, 1);
    let mut page = [0u8; 4096];
    let id = t.mm.find_vma(addr).unwrap().file.unwrap();
    t.vfs.fault_page(0, id, 0, &mut page).unwrap();
    assert_eq!(call(&mut t, Sysno::write, &[f, BAD, 8]), err(Errno::EFAULT));
    assert!(!t.vfs.take_coherence_loss());
}

/// A growing `ftruncate` unmaps nothing in `shmem_setattr`.
#[test]
fn growing_a_file_with_a_copied_page_is_ordinary() {
    let mut t = t();
    let (f, addr) = mapped_file(&mut t, 1);
    let id = t.mm.find_vma(addr).unwrap().file.unwrap();
    t.vfs.fault_page(0, id, 0, &mut [0; 4096]).unwrap();
    assert_eq!(call(&mut t, Sysno::ftruncate, &[f, 8192]), ok(0));
    assert_eq!(call(&mut t, Sysno::ftruncate, &[f, 8192]), ok(0));
    assert_eq!(
        call(&mut t, Sysno::ftruncate, &[f, 100]),
        Outcome::Unimplemented(Sysno::ftruncate as u32)
    );
}

/// `shmem_mmap` ends in `file_accessed` (unless `O_NOATIME`).
#[test]
fn mmap_of_a_file_updates_atime_unless_o_noatime() {
    let mut t = t();
    t.vfs
        .start_timekeeping(ticking_clock, crate::vfs::Timespec { sec: 7, nsec: 0 });
    let f = fd(open(&mut t, "/f", O_CREAT | O_RDWR, 0o644));
    let atime = |t: &mut Task| {
        assert_eq!(call(t, Sysno::fstat, &[f, OUT]), ok(0));
        u64_at(t, OUT + 80)
    };
    let before = atime(&mut t);
    let args = |fd| [0, 4096, PROT_READ, MAP_PRIVATE, fd, 0];
    assert!(matches!(call(&mut t, Sysno::mmap, &args(f)), Outcome::Return(a) if a > 0));
    let after = atime(&mut t);
    assert!(after > before, "{before} {after}");
    let quiet = fd(open(&mut t, "/f", O_RDONLY | 0o1_000_000, 0));
    assert!(matches!(call(&mut t, Sysno::mmap, &args(quiet)), Outcome::Return(a) if a > 0));
    assert_eq!(atime(&mut t), after);
}

/// `mm_populate` of a file mapping would copy the pages at `mmap` time.
#[test]
fn populating_a_file_mapping_stops_loudly_and_maps_nothing() {
    let mut t = t();
    let f = fd(open(&mut t, "/f", O_CREAT | O_RDWR, 0o644));
    assert_eq!(call(&mut t, Sysno::ftruncate, &[f, 4096]), ok(0));
    let vmas = t.mm.vmas().len();
    for flag in [MAP_POPULATE, MAP_LOCKED] {
        assert_eq!(
            call(
                &mut t,
                Sysno::mmap,
                &[0, 4096, PROT_RW, MAP_PRIVATE | flag, f, 0]
            ),
            Outcome::Unimplemented(Sysno::mmap as u32)
        );
    }
    assert_eq!((t.mm.vmas().len(), t.vfs.pin_count()), (vmas, 0));
}

/// Read-only `MAP_SHARED` of a file is served as a private mapping
/// (`VM_SHARED` and `VM_MAYWRITE` are cleared by `do_mmap`).
#[test]
fn a_read_only_shared_mapping_of_a_file_is_served() {
    let mut t = t();
    let f = fd(open(&mut t, "/f", O_CREAT | O_RDWR, 0o644));
    put(&mut t, BUF, b"hello");
    assert_eq!(call(&mut t, Sysno::write, &[f, BUF, 5]), ok(5));
    let ro = fd(open(&mut t, "/f", O_RDONLY, 0));
    let Outcome::Return(addr) = call(
        &mut t,
        Sysno::mmap,
        &[0, 4096, PROT_READ, MAP_SHARED, ro, 0],
    ) else {
        panic!()
    };
    assert_eq!(t.vfs.pin_count(), 1);
    let mut head = [0u8; 5];
    assert_eq!(
        crate::usercopy::copy_from_user(&mut t, &mut head, addr as u64),
        0
    );
    assert_eq!(&head, b"hello");
}

/// Every VMA removal drops the pin, not only `munmap` and file `mmap`.
#[test]
fn replacing_a_file_vma_by_map_fixed_releases_the_description() {
    for zero in [false, true] {
        let mut t = t();
        mknod_char(&mut t, "/zero", 1, 5);
        let (f, addr) = mapped_file(&mut t, 1);
        assert_eq!(t.vfs.pin_count(), 1);
        assert_eq!(call(&mut t, Sysno::close, &[f]), ok(0));
        let replaced = if zero {
            let z = fd(open(&mut t, "/zero", O_RDWR, 0));
            call(
                &mut t,
                Sysno::mmap,
                &[addr, 4096, PROT_RW, MAP_PRIVATE | MAP_FIXED, z, 0],
            )
        } else {
            call(
                &mut t,
                Sysno::mmap,
                &[
                    addr,
                    4096,
                    PROT_RW,
                    MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
                    u64::MAX,
                    0,
                ],
            )
        };
        assert_eq!(replaced, ok(addr as i64), "zero={zero}");
        assert_eq!(t.vfs.pin_count(), 0, "zero={zero}");
        assert_eq!(t.vfs.zero_mapped(), zero);
    }
}

/// A partial `munmap` and a second `mmap` of the same description.
#[test]
fn partial_unmap_keeps_the_pin_and_a_second_mmap_shares_it() {
    let mut t = t();
    let (f, addr) = mapped_file(&mut t, 2);
    // Mapping the same description again adds no pin.
    assert!(matches!(
        call(&mut t, Sysno::mmap, &[0, 4096, PROT_READ, MAP_PRIVATE, f, 0]),
        Outcome::Return(a) if a > 0
    ));
    assert_eq!(t.vfs.pin_count(), 1);
    // The first page of the first mapping goes; the rest of it keeps the file.
    assert_eq!(call(&mut t, Sysno::munmap, &[addr, 4096]), ok(0));
    assert_eq!(t.vfs.pin_count(), 1);
}

// ---- pipes between tasks, poll, F_SETPIPE_SZ ----------------------------------

use crate::vfs::{FdTable, Vfs, file::FileKind};
use std::boxed::Box;

/// The pipe behind descriptor `fd`.
fn pipe_of(vfs: &Vfs, fdt: &FdTable, fd: u32) -> crate::vfs::PipeId {
    match vfs.files.get(fdt.get(fd).unwrap()).kind {
        FileKind::Pipe { pipe, .. } => pipe,
        other => panic!("{other:?}"),
    }
}

/// What another task does to descriptor `fd`'s pipe while this one sleeps: push
/// `data` as one buffer.
fn writes(fd: u32, data: &'static [u8]) -> WaitHook {
    Box::new(move |vfs, fdt| {
        let pipe = pipe_of(vfs, fdt, fd);
        vfs.pipe_mut(pipe).push_page(data).unwrap();
    })
}

/// Another task closes descriptor `fd` (the last reference to its end).
fn closes(fd: u32) -> WaitHook {
    Box::new(move |vfs, fdt| {
        let id = fdt.close(fd).unwrap();
        vfs.fput(id);
    })
}

#[test]
fn a_blocked_read_wakes_when_another_task_writes_or_closes() {
    let mut t = t();
    assert_eq!(call(&mut t, Sysno::pipe2, &[OUT, 0]), ok(0));
    // Data: the read returns what arrived (a short read), after one sleep.
    t.on_wait.push(writes(3, b"hi"));
    assert_eq!(call(&mut t, Sysno::read, &[3, OUT + 32, 16]), ok(2));
    assert_eq!(get(&mut t, OUT + 32, 2), b"hi");
    assert_eq!(t.waits, 1);
    // A spurious wake-up (nothing changed) sleeps again; then the writer closes: EOF.
    t.on_wait.push(Box::new(|_, _| {}));
    t.on_wait.push(closes(4));
    assert_eq!(call(&mut t, Sysno::read, &[3, OUT + 32, 16]), ok(0));
    assert_eq!(t.waits, 3);
    assert!(t.vfs.take_pipe_events(), "the close is a pipe event");
    assert!(!t.vfs.take_pipe_events(), "events are reported once");
}

#[test]
fn a_blocked_write_keeps_what_it_wrote_across_sleeps() {
    let mut t = t();
    assert_eq!(call(&mut t, Sysno::pipe2, &[OUT, 0]), ok(0));
    put(&mut t, BUF, &[7; 4096]);
    for _ in 0..16 {
        assert_eq!(call(&mut t, Sysno::write, &[4, BUF, 4096]), ok(4096));
    }
    // Two pages and a bit into a full pipe: room for one page appears, then the
    // reader goes away. One page is written, SIGPIPE is raised, and the partial
    // count (not -EPIPE) is the result.
    t.on_wait.push(Box::new(|vfs, fdt| {
        let pipe = pipe_of(vfs, fdt, 3);
        vfs.pipe_mut(pipe).consume(4096);
    }));
    t.on_wait.push(closes(3));
    put(&mut t, BUF, &[8; 4096]);
    assert_eq!(call(&mut t, Sysno::write, &[4, BUF, 8192 + 100]), ok(4096));
    assert_eq!(t.waits, 2);
    assert!(t.state.pending_set().contains(SIGPIPE));
}

#[test]
fn a_write_of_at_most_a_page_waits_for_room_and_is_never_split() {
    let mut t = t();
    assert_eq!(call(&mut t, Sysno::pipe2, &[OUT, 0]), ok(0));
    put(&mut t, BUF, &[1; 4096]);
    for _ in 0..15 {
        assert_eq!(call(&mut t, Sysno::write, &[4, BUF, 4096]), ok(4096));
    }
    // The sixteenth buffer holds 4095 bytes: one byte of room, which a 100-byte
    // write does not use (`PIPE_BUF` atomicity: all of it in one slot or none).
    assert_eq!(call(&mut t, Sysno::write, &[4, BUF, 4095]), ok(4095));
    t.on_wait.push(Box::new(|vfs, fdt| {
        let pipe = pipe_of(vfs, fdt, 3);
        assert_eq!(
            vfs.pipe_ref(pipe).available(),
            15 * 4096 + 4095,
            "nothing yet"
        );
        vfs.pipe_mut(pipe).consume(4096);
    }));
    assert_eq!(call(&mut t, Sysno::write, &[4, BUF, 100]), ok(100));
    let pipe = pipe_of(&t.vfs, &t.fdt, 3);
    assert_eq!(t.vfs.pipe_ref(pipe).available(), 14 * 4096 + 4095 + 100);
}

#[test]
fn a_blocked_write_to_a_nonblocking_or_signalled_pipe_does_not_sleep() {
    let mut t = t();
    assert_eq!(call(&mut t, Sysno::pipe2, &[OUT, 0]), ok(0));
    put(&mut t, BUF, &[1; 4096]);
    for _ in 0..16 {
        assert_eq!(call(&mut t, Sysno::write, &[4, BUF, 4096]), ok(4096));
    }
    // A signal pending with nothing written restarts the call; the sleep is skipped.
    t.state
        .send_signal(
            SIGALRM,
            crate::signal::info::SigInfo::kernel(SIGALRM),
            crate::signal::state::Target::Process,
        )
        .unwrap();
    let waits = t.waits;
    assert_eq!(call(&mut t, Sysno::write, &[4, BUF, 1]), ok(-512));
    assert_eq!(t.waits, waits);
}

const POLLIN: u16 = 1;
const POLLOUT: u16 = 4;
const POLLERR: u16 = 8;
const POLLHUP: u16 = 0x10;
const POLLNVAL: u16 = 0x20;

/// `struct pollfd` array in user memory at `OUT + 256`.
fn pollfds(t: &mut Task, entries: &[(i32, u16)]) -> u64 {
    let at = OUT + 256;
    let mut bytes = Vec::new();
    for &(fd, events) in entries {
        bytes.extend_from_slice(&fd.to_le_bytes());
        bytes.extend_from_slice(&events.to_le_bytes());
        bytes.extend_from_slice(&0xffffu16.to_le_bytes());
    }
    put(t, at, &bytes);
    at
}

fn revents(t: &mut Task, index: usize) -> u16 {
    let bytes = get(t, OUT + 256 + 8 * index as u64 + 6, 2);
    u16::from_le_bytes([bytes[0], bytes[1]])
}

fn poll(t: &mut Task, entries: &[(i32, u16)], timeout: i32) -> Outcome {
    let at = pollfds(t, entries);
    call(
        t,
        Sysno::poll,
        &[at, entries.len() as u64, u64::from(timeout as u32)],
    )
}

#[test]
fn poll_reports_pipe_console_and_file_events_like_linux() {
    let mut t = t();
    assert_eq!(call(&mut t, Sysno::pipe2, &[OUT, 0]), ok(0));
    // Empty pipe: the write end is writable, the read end is not readable.
    assert_eq!(poll(&mut t, &[(3, POLLIN), (4, POLLOUT)], 0), ok(1));
    assert_eq!((revents(&mut t, 0), revents(&mut t, 1)), (0, POLLOUT));
    // Data: readable; events that were not asked for are masked out.
    put(&mut t, BUF, b"x");
    assert_eq!(call(&mut t, Sysno::write, &[4, BUF, 1]), ok(1));
    assert_eq!(poll(&mut t, &[(3, POLLIN | POLLOUT)], 0), ok(1));
    assert_eq!(revents(&mut t, 0), POLLIN);
    assert_eq!(poll(&mut t, &[(3, POLLOUT)], 0), ok(0));
    // Writer closed: POLLHUP is reported whatever was asked, with the data still readable.
    assert_eq!(call(&mut t, Sysno::close, &[4]), ok(0));
    assert_eq!(poll(&mut t, &[(3, POLLIN)], 0), ok(1));
    assert_eq!(revents(&mut t, 0), POLLIN | POLLHUP);
    assert_eq!(call(&mut t, Sysno::read, &[3, OUT, 1]), ok(1));
    assert_eq!(poll(&mut t, &[(3, 0)], 0), ok(1));
    assert_eq!(revents(&mut t, 0), POLLHUP);
    // A write end with no reader: POLLERR.
    let mut u = self::t();
    assert_eq!(call(&mut u, Sysno::pipe2, &[OUT, 0]), ok(0));
    assert_eq!(call(&mut u, Sysno::close, &[3]), ok(0));
    assert_eq!(poll(&mut u, &[(4, 0)], 0), ok(1));
    assert_eq!(revents(&mut u, 0), POLLERR);
    // A full pipe is not writable.
    let mut full = self::t();
    assert_eq!(call(&mut full, Sysno::pipe2, &[OUT, 0]), ok(0));
    put(&mut full, BUF, &[1; 4096]);
    for _ in 0..16 {
        assert_eq!(call(&mut full, Sysno::write, &[4, BUF, 4096]), ok(4096));
    }
    assert_eq!(poll(&mut full, &[(4, POLLOUT)], 0), ok(0));
    // The console is writable and never readable; a regular file and /dev/null always both.
    assert_eq!(poll(&mut t, &[(0, POLLIN | POLLOUT)], 0), ok(1));
    assert_eq!(revents(&mut t, 0), POLLOUT);
    let f = fd(open(&mut t, "/f", O_CREAT | O_RDWR, 0o644)) as i32;
    assert_eq!(poll(&mut t, &[(f, POLLIN | POLLOUT)], 0), ok(1));
    assert_eq!(revents(&mut t, 0), POLLIN | POLLOUT);
    // Not open: POLLNVAL; negative: skipped (revents 0, not counted); both in one call.
    assert_eq!(
        poll(&mut t, &[(99, POLLIN), (-1, POLLIN), (f, POLLOUT)], 0),
        ok(2)
    );
    assert_eq!(
        (revents(&mut t, 0), revents(&mut t, 1), revents(&mut t, 2)),
        (POLLNVAL, 0, POLLOUT)
    );
    // An O_PATH descriptor is not valid for poll either.
    let p = fd(open(&mut t, "/f", crate::vfs::O_PATH, 0)) as i32;
    assert_eq!(poll(&mut t, &[(p, POLLIN)], 0), ok(1));
    assert_eq!(revents(&mut t, 0), POLLNVAL);
}

#[test]
fn poll_argument_errors() {
    let mut t = t();
    // nfds above RLIMIT_NOFILE (1024): EINVAL before anything is read.
    assert_eq!(
        call(&mut t, Sysno::poll, &[BAD, 1025, 0]),
        err(Errno::EINVAL)
    );
    assert_eq!(call(&mut t, Sysno::poll, &[BAD, 1, 0]), err(Errno::EFAULT));
    // No descriptors: the timeout alone.
    assert_eq!(call(&mut t, Sysno::poll, &[0, 0, 0]), ok(0));
    // The count is a 32-bit `unsigned int` and the timeout an `int`.
    assert_eq!(
        call(&mut t, Sysno::poll, &[0, 1 << 32, 0]),
        ok(0),
        "nfds is truncated to 0"
    );
    // The revents of an unwritable array fault after the poll (an array whose
    // second entry is on an unmapped page: the first entry's revents is stored).
    t.pages.map(0x6000, true);
    let at = 0x6000 + 4096 - 8;
    let mut entry = Vec::new();
    entry.extend_from_slice(&(-1i32).to_le_bytes());
    entry.extend_from_slice(&1u16.to_le_bytes());
    entry.extend_from_slice(&0xffffu16.to_le_bytes());
    put(&mut t, at, &entry);
    assert_eq!(call(&mut t, Sysno::poll, &[at, 2, 0]), err(Errno::EFAULT));
}

#[test]
fn poll_sleeps_until_an_event_the_timeout_or_a_signal() {
    let mut t = t();
    assert_eq!(call(&mut t, Sysno::pipe2, &[OUT, 0]), ok(0));
    // The timeout: 10 ms from now plus the hrtimer slack of a normal task (50 us).
    let start = t.now;
    assert_eq!(poll(&mut t, &[(3, POLLIN)], 10), ok(0));
    assert_eq!(revents(&mut t, 0), 0);
    assert_eq!(t.now - start, 10_000_000 + 50_000);
    // An event: the data another task writes ends the sleep with that one descriptor ready.
    t.on_wait.push(writes(3, b"z"));
    assert_eq!(poll(&mut t, &[(3, POLLIN)], -1), ok(1));
    assert_eq!(revents(&mut t, 0), POLLIN);
    // A spurious wake-up goes back to sleep and the end stays the original one.
    let _ = t.vfs.take_pipe_events();
    let mut u = self::t();
    assert_eq!(call(&mut u, Sysno::pipe2, &[OUT, 0]), ok(0));
    u.on_wait.push(Box::new(|_, _| {}));
    let start = u.now;
    assert_eq!(poll(&mut u, &[(3, POLLIN)], 5), ok(0));
    assert_eq!(u.now - start, 5_000_000 + 50_000);
    assert_eq!(u.waits, 2);
    // Nothing can wake it: it sleeps forever, as Linux does.
    let mut v = self::t();
    assert_eq!(call(&mut v, Sysno::pipe2, &[OUT, 0]), ok(0));
    assert!(would_hang(|| poll(&mut v, &[(3, POLLIN)], -1)));
}

#[test]
fn poll_interrupted_by_a_signal_restarts_with_its_original_end() {
    let mut t = t();
    assert_eq!(call(&mut t, Sysno::pipe2, &[OUT, 0]), ok(0));
    t.script_signal(4_000_000, SIGALRM);
    // -ERESTART_RESTARTBLOCK, and the block holds the array, its length and the end.
    assert_eq!(poll(&mut t, &[(3, POLLIN)], 10), ok(-516));
    let block = *t.clocks.restarts.last().unwrap();
    assert_eq!(
        (block.func, block.rmtp, block.clockid, block.expires_ns),
        (crate::syscall::RestartFn::Poll, OUT + 256, 1, 10_000_000)
    );
    // `restart_syscall` polls again until that end; the timeout runs out: 0.
    t.state.flush_signals(!0);
    assert_eq!(call(&mut t, Sysno::restart_syscall, &[]), ok(0));
    assert_eq!(t.now, 10_000_000 + 50_000);
    // With a signal pending on entry even a zero timeout answers -ERESTARTNOHAND
    // (turned into the restart block): `do_poll` checks `signal_pending` when nothing is ready.
    t.state
        .send_signal(
            SIGALRM,
            crate::signal::info::SigInfo::kernel(SIGALRM),
            crate::signal::state::Target::Process,
        )
        .unwrap();
    assert_eq!(poll(&mut t, &[(3, POLLIN)], 0), ok(-516));
    let block = *t.clocks.restarts.last().unwrap();
    assert_eq!(
        block.expires_ns, 0,
        "a zero timeout restarts as a zero timeout"
    );
    // ... but a ready descriptor wins over the signal.
    assert_eq!(poll(&mut t, &[(3, POLLIN), (0, POLLOUT)], 0), ok(1));
    // No timeout at all is stored as -1.
    t.on_wait.clear();
    t.script_signal(t.now + 1, SIGALRM);
    assert_eq!(poll(&mut t, &[(3, POLLIN)], -1), ok(-516));
    assert_eq!(t.clocks.restarts.last().unwrap().expires_ns, -1);
}

#[test]
fn f_setpipe_sz_rounds_up_to_pages_and_refuses_to_drop_data() {
    let mut t = t();
    assert_eq!(call(&mut t, Sysno::pipe2, &[OUT, 0]), ok(0));
    let set = |t: &mut Task, size: u64| call(t, Sysno::fcntl, &[3, 1031, size]);
    assert_eq!(set(&mut t, 4096), ok(4096));
    assert_eq!(
        call(&mut t, Sysno::fcntl, &[4, 1032, 0]),
        ok(4096),
        "either end"
    );
    assert_eq!(set(&mut t, 5000), ok(8192));
    assert_eq!(set(&mut t, 1), ok(4096), "at least a page");
    assert_eq!(set(&mut t, 0), ok(4096));
    assert_eq!(
        set(&mut t, 1 << 20),
        ok(1 << 20),
        "root may exceed pipe-max-size"
    );
    assert_eq!(set(&mut t, (1 << 31) + 1), err(Errno::EINVAL));
    assert_eq!(set(&mut t, 1 << 31), ok(1 << 31));
    // Two buffers of data: no smaller than two pages.
    assert_eq!(set(&mut t, 65536), ok(65536));
    put(&mut t, BUF, &[1; 4096]);
    for _ in 0..2 {
        assert_eq!(call(&mut t, Sysno::write, &[4, BUF, 4096]), ok(4096));
    }
    assert_eq!(set(&mut t, 4096), err(Errno::EBUSY));
    assert_eq!(set(&mut t, 8192), ok(8192));
    assert_eq!(call(&mut t, Sysno::fcntl, &[3, 1032, 0]), ok(8192));
    // The new room is usable: a third page does not fit in two slots, a smaller pipe is full.
    assert_eq!(
        call(&mut t, Sysno::fcntl, &[4, 4, u64::from(O_NONBLOCK)]),
        ok(0)
    );
    assert_eq!(call(&mut t, Sysno::write, &[4, BUF, 1]), err(Errno::EAGAIN));
    // A file that is not a pipe: EBADF. A non-root task: the accounting it would need is missing.
    let f = fd(open(&mut t, "/f", O_CREAT | O_RDWR, 0o644));
    assert_eq!(
        call(&mut t, Sysno::fcntl, &[f, 1031, 4096]),
        err(Errno::EBADF)
    );
    t.attrs.cred.euid = 1000;
    assert_eq!(
        call(&mut t, Sysno::fcntl, &[3, 1031, 4096]),
        Outcome::Unimplemented(72)
    );
}

#[test]
fn legacy_pipe_is_pipe2_without_flags() {
    let mut t = t();
    assert_eq!(call(&mut t, Sysno::pipe, &[OUT]), ok(0));
    assert_eq!((u32_at(&mut t, OUT), u32_at(&mut t, OUT + 4)), (3, 4));
    assert_eq!(
        call(&mut t, Sysno::fcntl, &[3, 1, 0]),
        ok(0),
        "no close-on-exec"
    );
    assert_eq!(call(&mut t, Sysno::fcntl, &[3, 3, 0]), ok(0), "blocking");
    assert_eq!(call(&mut t, Sysno::pipe, &[BAD]), err(Errno::EFAULT));
}
