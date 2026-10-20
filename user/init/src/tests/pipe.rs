// SPDX-License-Identifier: GPL-2.0-only
//! `pipe` group: pipes and `poll` between tasks, beyond the `proc` rows. A blocked read is woken by
//! a write or by the last writer leaving, a blocked write keeps what it wrote and goes on when a
//! reader drains (and returns the partial count when the reader leaves), small writes stay whole
//! when writers compete, `SIGPIPE` and `EPIPE` reach a writer that is asleep, an interrupted read
//! or write returns `EINTR`/the partial count or restarts (`SA_RESTART`, stop and continue),
//! `poll` over several descriptors, its events, its timeout, the wake-ups of its sleep and its
//! restart after a stop. Linux 6.18.57: `fs/pipe.c` (`anon_pipe_read`, `anon_pipe_write`,
//! `pipe_poll`, `pipe_release`), `fs/select.c` (`do_sys_poll`, `do_poll`, `do_restart_poll`).
//!
//! Every wait is a few tens of milliseconds long and the checks compare outcomes and elapsed
//! times against generous bounds (the lower bound is the timeout the call was given, the upper one
//! seconds above it), so the results do not depend on how the two kernels schedule.

use core::sync::atomic::{AtomicUsize, Ordering::Relaxed};

use syscalls::{Errno, Sysno};

use super::proc::{BAD, SIGCHLD, SIGPIPE, SIGUSR1, nap, reap_all, sigaction, spawn, wait4};
use super::{R, T, addr, addr_mut, fn_addr, sys};

const POLLIN: i16 = 1;
const POLLOUT: i16 = 4;
const POLLERR: i16 = 8;
const POLLHUP: i16 = 0x10;
const POLLNVAL: i16 = 0x20;
const F_SETPIPE_SZ: usize = 1031;
const SA_RESTART: u64 = 0x1000_0000;
const SIGSTOP: usize = 19;
const SIGCONT: usize = 18;
const WUNTRACED: usize = 2;
const CLOCK_MONOTONIC: usize = 1;
const SIG_IGN: u64 = 1;

/// Handler runs counted by the child that installs it.
static HANDLED: AtomicUsize = AtomicUsize::new(0);

extern "C" fn on_signal(_sig: i32) {
    HANDLED.fetch_add(1, Relaxed);
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Pollfd {
    fd: i32,
    events: i16,
    revents: i16,
}

fn pollfd(fd: usize, events: i16) -> Pollfd {
    Pollfd {
        fd: fd as i32,
        events,
        revents: -1,
    }
}

fn poll(fds: &mut [Pollfd], ms: i32) -> R {
    sys(Sysno::poll, &[addr_mut(fds), fds.len(), ms as usize])
}

fn now_ms() -> u64 {
    let mut ts = [0i64; 2];
    let _ = sys(Sysno::clock_gettime, &[CLOCK_MONOTONIC, addr_mut(&mut ts)]);
    (ts[0] as u64) * 1000 + (ts[1] as u64) / 1_000_000
}

/// At least `min` and less than `min + 2000` milliseconds passed since `start`.
fn waited(start: u64, min: u64) -> bool {
    let elapsed = now_ms() - start;
    (min..min + 2000).contains(&elapsed)
}

/// Less than `max` milliseconds passed since `start`.
fn within(start: u64, max: u64) -> bool {
    now_ms() - start < max
}

fn pipe() -> (usize, usize) {
    let mut fds = [0u32; 2];
    let _ = sys(Sysno::pipe2, &[addr_mut(&mut fds), 0]);
    (fds[0] as usize, fds[1] as usize)
}

/// A pipe whose capacity is one page.
fn small_pipe() -> (usize, usize) {
    let (r, w) = pipe();
    let _ = sys(Sysno::fcntl, &[r, F_SETPIPE_SZ, 4096]);
    (r, w)
}

fn close(fd: usize) {
    let _ = sys(Sysno::close, &[fd]);
}

fn write(fd: usize, data: &[u8]) -> R {
    sys(Sysno::write, &[fd, addr(data), data.len()])
}

fn read(fd: usize, buf: &mut [u8]) -> R {
    sys(Sysno::read, &[fd, addr_mut(buf), buf.len()])
}

/// Reads exactly `buf.len()` bytes unless the pipe ends first; the count.
fn read_full(fd: usize, buf: &mut [u8]) -> usize {
    let mut got = 0;
    while got < buf.len() {
        match read(fd, &mut buf[got..]) {
            Ok(n) if n > 0 => got += n,
            _ => break,
        }
    }
    got
}

fn kill(pid: usize, sig: usize) {
    let _ = sys(Sysno::kill, &[pid, sig]);
}

pub fn run() -> bool {
    let mut t = T::new("pipe");
    reap_all();
    poll_events(&mut t);
    poll_timeouts(&mut t);
    blocking_reads(&mut t);
    blocking_writes(&mut t);
    competing_writers(&mut t);
    signals_and_pipes(&mut t);
    poll_wakeups(&mut t);
    poll_restarts(&mut t);
    reap_all();
    t.finish()
}

fn poll_events(t: &mut T) {
    // Several descriptors in one call: the count is the number with an event.
    let (idle_r, _idle_w) = pipe();
    let (data_r, data_w) = pipe();
    let (_room_r, room_w) = pipe();
    let _ = write(data_w, b"abc");
    let mut fds = [
        pollfd(idle_r, POLLIN),
        pollfd(data_r, POLLIN),
        pollfd(room_w, POLLOUT),
    ];
    let ret = poll(&mut fds, 0);
    t.eq(
        "poll-counts-the-ready-descriptors",
        (ret, fds.map(|f| f.revents)),
        (Ok(2), [0, POLLIN, POLLOUT]),
    );
    // Events that were not asked for are not reported; errors and hang-ups always are.
    let mut fds = [pollfd(data_r, POLLOUT), pollfd(data_r, 0)];
    let ret = poll(&mut fds, 0);
    t.eq(
        "poll-reports-only-the-events-asked-for",
        (ret, fds.map(|f| f.revents)),
        (Ok(0), [0, 0]),
    );
    // A write end whose readers are gone: POLLERR, with POLLOUT when asked for (a pipe with
    // room is writable even though the write would fail).
    let (gone_r, gone_w) = pipe();
    close(gone_r);
    let mut fds = [pollfd(gone_w, 0), pollfd(gone_w, POLLOUT)];
    let ret = poll(&mut fds, 0);
    t.eq(
        "poll-write-end-without-readers",
        (ret, fds.map(|f| f.revents)),
        (Ok(2), [POLLERR, POLLERR | POLLOUT]),
    );
    // A read end whose writers are gone: POLLHUP whatever was asked.
    let (hup_r, hup_w) = pipe();
    close(hup_w);
    let mut fds = [pollfd(hup_r, 0), pollfd(hup_r, POLLOUT)];
    let ret = poll(&mut fds, 0);
    t.eq(
        "poll-read-end-without-writers",
        (ret, fds.map(|f| f.revents)),
        (Ok(2), [POLLHUP, POLLHUP]),
    );
    // Files that have no `->poll` are always ready, for what was asked: a regular file, a directory.
    let file = sys(Sysno::open, &[addr(b"/fixture/hello.txt\0"), 0, 0]).unwrap_or(usize::MAX);
    let dir = sys(Sysno::open, &[addr(b"/fixture\0"), 0o200_000, 0]).unwrap_or(usize::MAX);
    let mut fds = [
        pollfd(file, POLLIN | POLLOUT),
        pollfd(file, POLLOUT),
        pollfd(dir, POLLIN),
    ];
    let ret = poll(&mut fds, 0);
    t.eq(
        "poll-files-without-poll-are-always-ready",
        (ret, fds.map(|f| f.revents)),
        (Ok(3), [POLLIN | POLLOUT, POLLOUT, POLLIN]),
    );
    // Not open, negative, and a descriptor opened O_PATH, in one array.
    let path = sys(
        Sysno::open,
        &[addr(b"/fixture/hello.txt\0"), 0o10_000_000, 0],
    )
    .unwrap_or(usize::MAX);
    let mut fds = [
        pollfd(777, POLLIN),
        Pollfd {
            fd: -5,
            events: POLLIN,
            revents: -1,
        },
        pollfd(path, POLLIN),
    ];
    let ret = poll(&mut fds, 0);
    t.eq(
        "poll-invalid-descriptors",
        (ret, fds.map(|f| f.revents)),
        (Ok(2), [POLLNVAL, 0, POLLNVAL]),
    );
    for fd in [
        idle_r, data_r, data_w, room_w, gone_w, hup_r, file, dir, path,
    ] {
        close(fd);
    }
    // Argument errors: a bad array, a count above RLIMIT_NOFILE.
    let mut limit = [0u64; 2];
    let _ = sys(Sysno::getrlimit, &[7, addr_mut(&mut limit)]);
    t.eq(
        "poll-bad-array",
        sys(Sysno::poll, &[BAD, 1, 0]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "poll-more-descriptors-than-the-limit",
        sys(Sysno::poll, &[BAD, limit[0] as usize + 1, 0]),
        Err(Errno::EINVAL),
    );
}

fn poll_timeouts(t: &mut T) {
    let start = now_ms();
    t.eq(
        "poll-without-descriptors-sleeps",
        (sys(Sysno::poll, &[0, 0, 25]), waited(start, 25)),
        (Ok(0), true),
    );
    let (r, w) = pipe();
    let mut fds = [pollfd(r, POLLIN)];
    let start = now_ms();
    let ret = poll(&mut fds, 40);
    t.eq(
        "poll-times-out-after-the-whole-time",
        (ret, fds[0].revents, waited(start, 40)),
        (Ok(0), 0, true),
    );
    // A timeout of zero returns at once.
    let start = now_ms();
    t.eq(
        "poll-zero-timeout-does-not-wait",
        (poll(&mut fds, 0), within(start, 20)),
        (Ok(0), true),
    );
    close(r);
    close(w);
}

fn blocking_reads(t: &mut T) {
    reap_all();
    // A write wakes a sleeping read, which returns what is there (a short read).
    let (r, w) = pipe();
    let c = spawn(|| {
        close(r);
        nap(25);
        let _ = write(w, b"hello");
        0
    });
    let mut buf = [0u8; 100];
    let start = now_ms();
    let got = read(r, &mut buf);
    t.eq(
        "read-wakes-when-another-task-writes",
        (got, &buf[..5], waited(start, 25)),
        (Ok(5), b"hello".as_slice(), true),
    );
    let _ = wait4(c as isize, 0);
    // The sleeping reader does not wait for the writer to sleep or exit: the write itself
    // wakes it, while the writer goes on running (a busy loop of 300 ms, no wait of its own).
    let c = spawn(|| {
        close(r);
        nap(25);
        let _ = write(w, b"!");
        let until = now_ms() + 300;
        while now_ms() < until {}
        0
    });
    let start = now_ms();
    t.eq(
        "write-wakes-the-reader-while-the-writer-keeps-running",
        (read(r, &mut buf), waited(start, 25), within(start, 200)),
        (Ok(1), true, true),
    );
    let _ = wait4(c as isize, 0);
    // The last writer leaving ends the sleep with end of file; a writer that is still there
    // (a child holding its copy of the write end) keeps the read waiting.
    let c = spawn(|| {
        close(r);
        nap(30);
        0
    });
    close(w);
    let start = now_ms();
    t.eq(
        "read-waits-for-the-last-writer-and-then-sees-eof",
        (read(r, &mut buf), waited(start, 30)),
        (Ok(0), true),
    );
    let _ = wait4(c as isize, 0);
    close(r);
    // End of file reaches a reader that is not the parent of the writer that left.
    let (r, w) = pipe();
    let reader = spawn(|| {
        close(w);
        usize::from(read(r, &mut [0u8; 8]) == Ok(0))
    });
    let writer = spawn(|| {
        close(r);
        nap(30);
        0
    });
    close(r);
    close(w);
    let start = now_ms();
    t.eq(
        "eof-reaches-a-reader-that-is-a-sibling-of-the-writer",
        (wait4(reader as isize, 0), waited(start, 25)),
        ((Ok(reader), 1 << 8), true),
    );
    let _ = wait4(writer as isize, 0);
    // ... even when no task is left that the exit would wake otherwise: with `SIGCHLD` ignored
    // the exits are reaped at once and wake nobody, and the parent sleeps through all of it; the
    // writer's exit alone wakes the reader, which has answered in a second pipe by the time the
    // parent looks.
    let (r, w) = pipe();
    let (done_r, done_w) = pipe();
    let _ = sys(Sysno::fcntl, &[done_r, 4, 0o4000]);
    let _ = sigaction(SIGCHLD, SIG_IGN, 0);
    let _ = spawn(|| {
        close(w);
        close(done_r);
        let answer = if read(r, &mut [0u8; 8]) == Ok(0) {
            b'D'
        } else {
            b'x'
        };
        let _ = write(done_w, &[answer]);
        0
    });
    let _ = spawn(|| {
        close(r);
        close(done_r);
        nap(25);
        0
    });
    close(r);
    close(w);
    close(done_w);
    nap(300);
    let mut answer = [0u8; 1];
    t.eq(
        "exit-of-the-last-writer-wakes-a-reader-nobody-else-wakes",
        (read(done_r, &mut answer), answer),
        (Ok(1), *b"D"),
    );
    let _ = sigaction(SIGCHLD, 0, 0);
    close(done_r);
    // Closing one of two descriptors of the write end is not the end of the writers.
    let (r, w) = pipe();
    let dup = sys(Sysno::dup, &[w]).unwrap_or(usize::MAX);
    close(w);
    let _ = sys(Sysno::fcntl, &[r, 4, 0o4000]);
    t.eq(
        "pipe-with-a-duplicate-writer-is-not-at-eof",
        read(r, &mut buf),
        Err(Errno::EAGAIN),
    );
    close(dup);
    t.eq("pipe-without-writers-is-at-eof", read(r, &mut buf), Ok(0));
    close(r);
}

fn blocking_writes(t: &mut T) {
    reap_all();
    let mut data = [0u8; 8192];
    for (i, byte) in data.iter_mut().enumerate() {
        *byte = (i % 251) as u8;
    }
    // A write of two pages into a one-page pipe sleeps until the reader has drained it, then
    // completes: the count is the whole write and the reader sees the bytes in order.
    let (r, w) = small_pipe();
    let c = spawn(|| {
        close(w);
        nap(25);
        let mut got = [0u8; 8192];
        let n = read_full(r, &mut got);
        usize::from(n != 8192 || got != data)
    });
    close(r);
    let start = now_ms();
    t.eq(
        "blocked-write-completes-when-the-reader-drains",
        (write(w, &data), wait4(c as isize, 0), waited(start, 25)),
        (Ok(8192), (Ok(c), 0), true),
    );
    close(w);
    // The reader is already asleep when the writer starts: what the writer copied before it
    // sleeps for room is what wakes the reader, page after page.
    let (r, w) = small_pipe();
    let c = spawn(|| {
        close(r);
        nap(30);
        usize::from(write(w, &data) != Ok(8192))
    });
    close(w);
    let mut got = [0u8; 8192];
    let n = read_full(r, &mut got);
    t.eq(
        "sleeping-reader-and-sleeping-writer-hand-over-pages",
        (n, got == data, wait4(c as isize, 0)),
        (8192, true, (Ok(c), 0)),
    );
    close(r);
    // A reader that leaves while the writer sleeps: the pages written so far are the result.
    let _ = sigaction(SIGPIPE, SIG_IGN, 0);
    let (r, w) = small_pipe();
    let c = spawn(|| {
        close(w);
        nap(10);
        let mut page = [0u8; 4096];
        let _ = read_full(r, &mut page);
        nap(40); // the writer copies the second page and sleeps again meanwhile
        0
    });
    close(r);
    let big = [7u8; 12288];
    t.eq(
        "blocked-write-returns-the-partial-count-when-the-reader-leaves",
        write(w, &big),
        Ok(8192),
    );
    let _ = wait4(c as isize, 0);
    close(w);
    // Nothing written yet when the reader leaves: EPIPE.
    let (r, w) = small_pipe();
    let _ = write(w, &[1u8; 4096]);
    let c = spawn(|| {
        close(r);
        let r = write(w, &[2u8; 100]);
        usize::from(r != Err(Errno::EPIPE))
    });
    nap(30);
    close(r);
    t.eq(
        "blocked-write-sees-epipe-when-the-reader-leaves",
        wait4(c as isize, 0),
        (Ok(c), 0),
    );
    close(w);
    let _ = sigaction(SIGPIPE, 0, 0);
    // The same with SIGPIPE at its default: the sleeping writer dies of it.
    let (r, w) = small_pipe();
    let _ = write(w, &[1u8; 4096]);
    let c = spawn(|| {
        close(r);
        let _ = write(w, &[2u8; 100]);
        0
    });
    nap(30);
    close(r);
    t.eq(
        "blocked-write-dies-of-sigpipe-when-the-reader-leaves",
        wait4(c as isize, 0),
        (Ok(c), SIGPIPE as i32),
    );
    close(w);
}

fn competing_writers(t: &mut T) {
    reap_all();
    // Two writers send 100-byte records through a one-page pipe, so both sleep for room again
    // and again: writes up to `PIPE_BUF` are never split, whoever wakes first.
    let (r, w) = small_pipe();
    let writer = |letter: u8| {
        spawn(move || {
            close(r);
            let record = [letter; 100];
            let mut bad = 0;
            for _ in 0..100 {
                if write(w, &record) != Ok(100) {
                    bad += 1;
                }
            }
            usize::from(bad != 0)
        })
    };
    let (a, b) = (writer(b'A'), writer(b'B'));
    close(w);
    let mut all = [0u8; 20000];
    let mut total = 0;
    while total < all.len() {
        // Reads that do not line up with the records.
        let end = (total + 777).min(all.len());
        match read(r, &mut all[total..end]) {
            Ok(n) if n > 0 => total += n,
            _ => break,
        }
    }
    let whole = all
        .chunks(100)
        .all(|record| record.iter().all(|&b| b == record[0]));
    let from_a = all.chunks(100).filter(|record| record[0] == b'A').count();
    let from_b = all.chunks(100).filter(|record| record[0] == b'B').count();
    t.eq(
        "small-writes-stay-whole-under-contention",
        (total, whole, from_a, from_b),
        (20000, true, 100, 100),
    );
    t.eq(
        "both-writers-finished",
        {
            let mut ends = [wait4(-1, 0), wait4(-1, 0)];
            ends.sort_unstable_by_key(|(r, _)| r.unwrap_or(0));
            ends
        },
        [(Ok(a), 0), (Ok(b), 0)],
    );
    close(r);
}

fn signals_and_pipes(t: &mut T) {
    reap_all();
    // A read interrupted by a handler without SA_RESTART returns EINTR ...
    let (r, w) = pipe();
    let c = spawn(|| {
        close(w);
        HANDLED.store(0, Relaxed);
        let _ = sigaction(SIGUSR1, fn_addr(on_signal as *const ()), 0);
        let mut buf = [0u8; 10];
        let got = read(r, &mut buf);
        usize::from(got == Err(Errno::EINTR)) | HANDLED.load(Relaxed) << 1
    });
    nap(30);
    kill(c, SIGUSR1);
    t.eq(
        "interrupted-read-returns-eintr",
        wait4(c as isize, 0),
        (Ok(c), 3 << 8),
    );
    // ... and with SA_RESTART it runs the handler and sleeps on until there is data.
    let c = spawn(|| {
        close(w);
        HANDLED.store(0, Relaxed);
        let _ = sigaction(SIGUSR1, fn_addr(on_signal as *const ()), SA_RESTART);
        let mut buf = [0u8; 10];
        let got = read(r, &mut buf);
        usize::from(got == Ok(2)) | HANDLED.load(Relaxed) << 1
    });
    nap(30);
    kill(c, SIGUSR1);
    nap(20);
    let _ = write(w, b"xy");
    t.eq(
        "restarted-read-returns-the-data",
        wait4(c as isize, 0),
        (Ok(c), 3 << 8),
    );
    // A stop and a continue are not an interruption the program sees.
    let c = spawn(|| {
        close(w);
        let mut buf = [0u8; 10];
        let got = read(r, &mut buf);
        usize::from(got == Ok(3))
    });
    nap(30);
    kill(c, SIGSTOP);
    let stopped = wait4(c as isize, WUNTRACED);
    nap(10);
    kill(c, SIGCONT);
    nap(10);
    let _ = write(w, b"abc");
    t.eq(
        "read-goes-on-across-a-stop-and-a-continue",
        (stopped.0 == Ok(c), wait4(c as isize, 0)),
        (true, (Ok(c), 1 << 8)),
    );
    close(r);
    close(w);
    // A write interrupted after it copied a page returns that count; with nothing copied it
    // is EINTR.
    let (r, w) = small_pipe();
    let c = spawn(|| {
        close(r);
        HANDLED.store(0, Relaxed);
        let _ = sigaction(SIGUSR1, fn_addr(on_signal as *const ()), 0);
        let got = write(w, &[3u8; 8192]);
        usize::from(got == Ok(4096)) | HANDLED.load(Relaxed) << 1
    });
    nap(30);
    kill(c, SIGUSR1);
    t.eq(
        "interrupted-write-returns-the-partial-count",
        wait4(c as isize, 0),
        (Ok(c), 3 << 8),
    );
    let c = spawn(|| {
        close(r);
        HANDLED.store(0, Relaxed);
        let _ = sigaction(SIGUSR1, fn_addr(on_signal as *const ()), 0);
        let got = write(w, &[3u8; 100]);
        usize::from(got == Err(Errno::EINTR)) | HANDLED.load(Relaxed) << 1
    });
    nap(30);
    kill(c, SIGUSR1);
    t.eq(
        "interrupted-write-with-nothing-copied-is-eintr",
        wait4(c as isize, 0),
        (Ok(c), 3 << 8),
    );
    close(r);
    close(w);
}

fn poll_wakeups(t: &mut T) {
    reap_all();
    // A write by another task ends the sleep.
    let (r, w) = pipe();
    let c = spawn(|| {
        close(r);
        nap(25);
        let _ = write(w, b"x");
        0
    });
    let mut fds = [pollfd(r, POLLIN)];
    let start = now_ms();
    let ret = poll(&mut fds, 2000);
    t.eq(
        "poll-wakes-when-another-task-writes",
        (ret, fds[0].revents, waited(start, 25), within(start, 1500)),
        (Ok(1), POLLIN, true, true),
    );
    let _ = wait4(c as isize, 0);
    close(w);
    let _ = read(r, &mut [0u8; 4]);
    // The last writer leaving: POLLHUP.
    let (r, w) = pipe();
    let c = spawn(|| {
        close(r);
        nap(25);
        0
    });
    close(w);
    let mut fds = [pollfd(r, POLLIN)];
    let start = now_ms();
    let ret = poll(&mut fds, 2000);
    t.eq(
        "poll-wakes-when-the-last-writer-leaves",
        (ret, fds[0].revents, within(start, 1500)),
        (Ok(1), POLLHUP, true),
    );
    let _ = wait4(c as isize, 0);
    close(r);
    // Room made by a reader: POLLOUT; the reader leaving instead: POLLERR.
    let (r, w) = small_pipe();
    let _ = write(w, &[1u8; 4096]);
    let c = spawn(|| {
        close(w);
        nap(25);
        let mut page = [0u8; 4096];
        let _ = read_full(r, &mut page);
        0
    });
    let mut fds = [pollfd(w, POLLOUT)];
    let start = now_ms();
    let ret = poll(&mut fds, 2000);
    t.eq(
        "poll-wakes-when-a-reader-makes-room",
        (ret, fds[0].revents, within(start, 1500)),
        (Ok(1), POLLOUT, true),
    );
    let _ = wait4(c as isize, 0);
    close(r);
    close(w);
    let (r, w) = small_pipe();
    let _ = write(w, &[1u8; 4096]);
    let c = spawn(|| {
        nap(25);
        0
    });
    close(r);
    let mut fds = [pollfd(w, POLLOUT)];
    let start = now_ms();
    let ret = poll(&mut fds, 2000);
    t.eq(
        "poll-wakes-when-the-last-reader-leaves",
        (ret, fds[0].revents, within(start, 1500)),
        (Ok(1), POLLERR, true),
    );
    let _ = wait4(c as isize, 0);
    close(w);
    // Two pipes: the one that gets the data is the one reported.
    let (r1, w1) = pipe();
    let (r2, w2) = pipe();
    let c = spawn(|| {
        close(r1);
        close(r2);
        nap(25);
        let _ = write(w2, b"y");
        0
    });
    let mut fds = [pollfd(r1, POLLIN), pollfd(r2, POLLIN)];
    let ret = poll(&mut fds, 2000);
    t.eq(
        "poll-reports-the-pipe-that-got-the-data",
        (ret, fds.map(|f| f.revents)),
        (Ok(1), [0, POLLIN]),
    );
    let _ = wait4(c as isize, 0);
    for fd in [r1, w1, r2, w2] {
        close(fd);
    }
}

fn poll_restarts(t: &mut T) {
    reap_all();
    // A poll with a timeout that a stop interrupts (-ERESTART_RESTARTBLOCK) goes on to the
    // original end after the continue, not to a fresh timeout from the restart.
    let (r, w) = pipe();
    let c = spawn(|| {
        close(w);
        let mut fds = [pollfd(r, POLLIN)];
        let start = now_ms();
        let ret = poll(&mut fds, 300);
        let took = now_ms() - start;
        usize::from(ret == Ok(0)) | usize::from((290..450).contains(&took)) << 1
    });
    nap(50);
    kill(c, SIGSTOP);
    let stopped = wait4(c as isize, WUNTRACED);
    nap(200);
    kill(c, SIGCONT);
    t.eq(
        "poll-resumes-until-its-original-end",
        (stopped.0 == Ok(c), wait4(c as isize, 0)),
        (true, (Ok(c), 3 << 8)),
    );
    // A handler ends it with EINTR and nothing in revents.
    let c = spawn(|| {
        close(w);
        HANDLED.store(0, Relaxed);
        let _ = sigaction(SIGUSR1, fn_addr(on_signal as *const ()), 0);
        let mut fds = [pollfd(r, POLLIN)];
        let ret = poll(&mut fds, -1);
        usize::from(ret == Err(Errno::EINTR))
            | usize::from(fds[0].revents == 0) << 1
            | HANDLED.load(Relaxed) << 2
    });
    nap(30);
    kill(c, SIGUSR1);
    t.eq(
        "poll-interrupted-by-a-handler-is-eintr",
        wait4(c as isize, 0),
        (Ok(c), 7 << 8),
    );
    // Data arriving after a stop and a continue is found by the restarted call.
    let c = spawn(|| {
        close(w);
        let mut fds = [pollfd(r, POLLIN)];
        let ret = poll(&mut fds, -1);
        usize::from(ret == Ok(1)) | usize::from(fds[0].revents == POLLIN) << 1
    });
    nap(30);
    kill(c, SIGSTOP);
    let _ = wait4(c as isize, WUNTRACED);
    nap(10);
    kill(c, SIGCONT);
    nap(10);
    let _ = write(w, b"z");
    t.eq(
        "poll-without-timeout-resumes-and-finds-the-data",
        wait4(c as isize, 0),
        (Ok(c), 3 << 8),
    );
    close(r);
    close(w);
}
