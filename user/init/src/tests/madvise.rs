// SPDX-License-Identifier: GPL-2.0-only
//! `madvise` group: `madvise(2)` and `process_madvise(2)`. Linux 6.18.57: `mm/madvise.c`
//! (`do_madvise`, `is_valid_madvise`, `madvise_should_skip`, `madvise_walk_vmas`,
//! `madvise_vma_behavior`, `madvise_update_vma`, `madvise_dontneed_free`, `madvise_free_single_vma`,
//! `madvise_remove`, `madvise_populate`, `madvise_guard_install`, `madvise_guard_remove`,
//! `madvise_cold`, `madvise_pageout`, `process_madvise`), `mm/gup.c` (`faultin_page_range`,
//! `check_vma_flags`), `mm/memory.c` (`handle_pte_marker`, `zap_nonpresent_ptes`,
//! `vma_needs_copy`), `mm/mmap.c` (`dup_mmap`), `mm/vma.c` (sticky `VM_MAYBE_GUARD` merging).
//!
//! The configuration of the reference decides which advice exists: `CONFIG_KSM`,
//! `CONFIG_TRANSPARENT_HUGEPAGE` and `CONFIG_MEMORY_FAILURE` are off, so `MADV_MERGEABLE`,
//! `MADV_UNMERGEABLE`, `MADV_HUGEPAGE`, `MADV_NOHUGEPAGE`, `MADV_COLLAPSE`, `MADV_HWPOISON` and
//! `MADV_SOFT_OFFLINE` are `EINVAL`. Every check works in a window of its own (a fixed address a
//! few MiB apart from the others), so neighbouring mappings never merge by accident. User-mode
//! faults are taken in forked children whose `SIGSEGV`/`SIGBUS` handler reports `si_code` and
//! `si_addr` through the exit status. `/proc` is mounted for the VMA lists and the resident-set
//! counters (`RssAnon`, `RssFile`, `RssShmem`).

use core::fmt::{self, Write as _};
use core::sync::atomic::{AtomicUsize, Ordering::Relaxed};

use syscalls::{Errno, Sysno};

use super::proc::{reap_all, sigaction, spawn, wait4};
use super::signal::SA_SIGINFO;
use super::threads::{Control, spawn as spawn_thread};
use super::{
    PAGE, Probe, R, T, TASK_SIZE, addr, addr_mut, all_bytes, die, fn_addr, peek, poke, sys,
};

const P: usize = PAGE;

const NORMAL: usize = 0;
const RANDOM: usize = 1;
const SEQUENTIAL: usize = 2;
const WILLNEED: usize = 3;
const DONTNEED: usize = 4;
const FREE: usize = 8;
const REMOVE: usize = 9;
const DONTFORK: usize = 10;
const DOFORK: usize = 11;
const DONTDUMP: usize = 16;
const DODUMP: usize = 17;
const WIPEONFORK: usize = 18;
const KEEPONFORK: usize = 19;
const COLD: usize = 20;
const PAGEOUT: usize = 21;
const POPULATE_READ: usize = 22;
const POPULATE_WRITE: usize = 23;
const DONTNEED_LOCKED: usize = 24;
const GUARD_INSTALL: usize = 102;
const GUARD_REMOVE: usize = 103;

const PROT_NONE: usize = 0;
const PROT_R: usize = 1;
const PROT_W: usize = 2;
const PROT_RW: usize = 3;
const MAP_SHARED: usize = 0x01;
const MAP_PRIVATE: usize = 0x02;
const MAP_DROPPABLE: usize = 0x08;
const MAP_FIXED: usize = 0x10;
const MAP_ANON: usize = 0x20;
const MAP_LOCKED: usize = 0x2000;
const MAP_FIXED_NOREPLACE: usize = 0x10_0000;
const NOFD: usize = usize::MAX;
const MREMAP_MAYMOVE: usize = 1;
const MREMAP_FIXED: usize = 2;

const O_RDONLY: usize = 0;
const O_RDWR: usize = 2;
const O_CREAT: usize = 0o100;
const O_TRUNC: usize = 0o1000;

const E_NOMEM: R = Err(Errno::ENOMEM);
const E_INVAL: R = Err(Errno::EINVAL);

/// The exit status of a child whose handler saw `SIGSEGV` with `si_code` 1 / 2 at the address it
/// expected (`sig * 16 + si_code`), and `SIGBUS` with `BUS_ADRERR`.
const SEGV_MAPERR: i32 = 11 * 16 + 1;
const SEGV_ACCERR: i32 = 11 * 16 + 2;

fn madv(a: usize, len: usize, advice: usize) -> R {
    sys(Sysno::madvise, &[a, len, advice])
}

/// The base of the window of check `n`.
const fn win(n: usize) -> usize {
    0x2000_0000_0000 + n * 0x100_0000
}

/// Mappings that could not be made (a window still in use): the group fails on the count.
static MAP_FAILS: AtomicUsize = AtomicUsize::new(0);

fn map_at(a: usize, pages: usize, prot: usize, extra: usize) -> usize {
    super::mmap(
        a,
        pages * P,
        prot,
        MAP_PRIVATE | MAP_ANON | MAP_FIXED_NOREPLACE | extra,
        NOFD,
        0,
    )
    .unwrap_or_else(|_| {
        MAP_FAILS.fetch_add(1, Relaxed);
        0
    })
}

/// An anonymous private read/write mapping in window `n`.
fn anon(n: usize, pages: usize) -> usize {
    map_at(win(n), pages, PROT_RW, 0)
}

fn unmap(a: usize, pages: usize) {
    let _ = sys(Sysno::munmap, &[a, pages * P]);
}

fn fill(a: usize, len: usize, v: u8) {
    for i in 0..len {
        poke(a + i, v);
    }
}

fn striped(a: usize, len: usize, v: u8) -> bool {
    all_bytes(a, len, v)
}

fn zeroed(a: usize, len: usize) -> bool {
    all_bytes(a, len, 0)
}

/// Whether `madvise(MADV_NORMAL)` finds the whole range mapped.
fn mapped(a: usize, len: usize) -> bool {
    madv(a, len, NORMAL) == Ok(0)
}

// ---------------------------------------------------------------------------------------------
// Children and faults.

/// Runs `f` in a forked child and returns its raw wait status (`exit code << 8`, or the signal).
fn child(f: impl FnOnce() -> usize) -> i32 {
    reap_all();
    let pid = spawn(f);
    let (r, status) = wait4(pid as isize, 0);
    if r == Ok(pid) { status } else { -1 }
}

/// An exit code as `child` reports it.
const fn exited(code: i32) -> i32 {
    code << 8
}

static EXPECT: AtomicUsize = AtomicUsize::new(0);

extern "C" fn on_fault(sig: i32, info: *const u64, _uc: *mut u64) {
    // SAFETY: `info` is the kernel's siginfo for the running SA_SIGINFO handler (16 words).
    let words = unsafe { [info.add(1).read(), info.add(2).read()] };
    let code = (words[0] & 0xffff_ffff) as usize;
    let address = words[1] as usize;
    die(if address == EXPECT.load(Relaxed) {
        sig as usize * 16 + code
    } else {
        255
    });
}

/// One user access (a byte read or write at `a`) in the calling process: 0 when it works, else
/// the process exits with `sig * 16 + si_code` (255 for an unexpected `si_addr`).
fn touch(a: usize, write: bool) -> usize {
    EXPECT.store(a, Relaxed);
    let _ = sigaction(11, fn_addr(on_fault as *const ()), SA_SIGINFO);
    let _ = sigaction(7, fn_addr(on_fault as *const ()), SA_SIGINFO);
    if write {
        poke(a, 1);
    } else {
        let _ = peek(a);
    }
    0
}

/// The wait status of a child that makes one access.
fn access(a: usize, write: bool) -> i32 {
    child(|| touch(a, write))
}

// ---------------------------------------------------------------------------------------------
// /proc.

struct Text<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> Text<N> {
    const fn new() -> Self {
        Self {
            buf: [0; N],
            len: 0,
        }
    }
    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("?")
    }
}

impl<const N: usize> fmt::Write for Text<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let n = s.len().min(N - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

fn read_file(path: &[u8], buf: &mut [u8]) -> usize {
    let Ok(fd) = sys(Sysno::open, &[addr(path), O_RDONLY, 0]) else {
        return 0;
    };
    let mut have = 0;
    while have < buf.len() {
        match sys(
            Sysno::read,
            &[fd, addr_mut(&mut buf[have..]), buf.len() - have],
        ) {
            Ok(0) | Err(_) => break,
            Ok(n) => have += n,
        }
    }
    let _ = sys(Sysno::close, &[fd]);
    have
}

fn hex(word: &[u8]) -> usize {
    word.iter().fold(0, |n, &c| {
        n * 16 + usize::from(if c <= b'9' { c - b'0' } else { c - b'a' + 10 })
    })
}

/// The lines of `/proc/self/maps` whose start lies in `[lo, hi)`, as `start-end perms;` with the
/// addresses relative to `lo`.
fn maps(lo: usize, hi: usize) -> Text<512> {
    let mut buf = [0u8; 16384];
    let len = read_file(b"/proc/self/maps\0", &mut buf);
    let mut out = Text::new();
    for line in buf[..len].split(|&b| b == b'\n') {
        let Some(dash) = line.iter().position(|&b| b == b'-') else {
            continue;
        };
        let Some(space) = line.iter().position(|&b| b == b' ') else {
            continue;
        };
        let (start, end) = (hex(&line[..dash]), hex(&line[dash + 1..space]));
        if start >= lo && start < hi {
            let perms = core::str::from_utf8(&line[space + 1..space + 5]).unwrap_or("?");
            let _ = write!(out, "{:x}-{:x} {perms};", start - lo, end - lo);
        }
    }
    out
}

/// `(RssAnon, RssFile, RssShmem)` in kB from `/proc/self/status`.
fn rss() -> (usize, usize, usize) {
    let mut buf = [0u8; 8192];
    let len = read_file(b"/proc/self/status\0", &mut buf);
    let field = |key: &[u8]| {
        let text = &buf[..len];
        let Some(at) = text.windows(key.len()).position(|w| w == key) else {
            return usize::MAX;
        };
        text[at + key.len()..]
            .iter()
            .skip_while(|b| !b.is_ascii_digit())
            .take_while(|b| b.is_ascii_digit())
            .fold(0, |n, &d| n * 10 + usize::from(d - b'0'))
    };
    (field(b"RssAnon:"), field(b"RssFile:"), field(b"RssShmem:"))
}

// ---------------------------------------------------------------------------------------------

/// A file of `pages` pages whose page `i` holds the byte `b'A' + i`.
fn make_file(pages: usize) -> usize {
    let fd = sys(
        Sysno::open,
        &[addr(b"/madv-file\0"), O_RDWR | O_CREAT | O_TRUNC, 0o644],
    )
    .unwrap_or(99);
    for i in 0..pages {
        let page = [b'A' + i as u8; P];
        let _ = sys(Sysno::write, &[fd, addr(&page), P]);
    }
    fd
}

fn file_map(a: usize, pages: usize, prot: usize, flags: usize, fd: usize) -> usize {
    super::mmap(a, pages * P, prot, flags | MAP_FIXED_NOREPLACE, fd, 0).unwrap_or_else(|_| {
        MAP_FAILS.fetch_add(1, Relaxed);
        0
    })
}

/// The file again, read-only: a `MAP_SHARED` mapping of it is a read-only shared mapping
/// (`VM_SHARED` and `VM_MAYWRITE` cleared by `do_mmap`).
fn open_ro() -> usize {
    sys(Sysno::open, &[addr(b"/madv-file\0"), O_RDONLY, 0]).unwrap_or(99)
}

pub fn run() -> bool {
    let mut t = T::new("madvise");
    let probe = Probe::new();
    validation(&mut t);
    walk(&mut t);
    dontneed(&mut t);
    free(&mut t);
    remove(&mut t);
    advice_flags(&mut t);
    fork_flags(&mut t);
    guard(&mut t, &probe);
    threads(&mut t, &probe);
    populate(&mut t);
    process_madvise(&mut t);
    t.eq("every-mapping-was-made", MAP_FAILS.load(Relaxed), 0);
    t.finish()
}

fn validation(t: &mut T) {
    let a = anon(0, 4);
    fill(a, 4 * P, 7);
    for advice in [
        5,
        6,
        7,
        12,
        13,
        14,
        15,
        25,
        26,
        50,
        99,
        100,
        101,
        104,
        105,
        1000,
        0xffff_ffff,
        0x8000_0000,
    ] {
        t.eq(
            format_args!("invalid-advice-{advice}"),
            madv(a, P, advice),
            E_INVAL,
        );
    }
    // `int behavior`: the high half of the register is ignored.
    t.eq("advice-is-an-int", madv(a, P, 0x1_0000_0003), Ok(0));
    t.eq(
        "advice-is-an-int-invalid",
        madv(a, P, 0x1_0000_000c),
        E_INVAL,
    );
    t.holds("data-intact", striped(a, 4 * P, 7), "changed", "unchanged");
    // Which advice an ordinary anonymous range accepts, each in a fresh mapping.
    let accepted: [(&str, usize, R); 18] = [
        ("normal", NORMAL, Ok(0)),
        ("random", RANDOM, Ok(0)),
        ("sequential", SEQUENTIAL, Ok(0)),
        ("willneed", WILLNEED, Ok(0)),
        ("dontneed", DONTNEED, Ok(0)),
        ("free", FREE, Ok(0)),
        ("remove", REMOVE, E_INVAL),
        ("dontfork", DONTFORK, Ok(0)),
        ("dofork", DOFORK, Ok(0)),
        ("dontdump", DONTDUMP, Ok(0)),
        ("dodump", DODUMP, Ok(0)),
        ("wipeonfork", WIPEONFORK, Ok(0)),
        ("keeponfork", KEEPONFORK, Ok(0)),
        ("cold", COLD, Ok(0)),
        ("pageout", PAGEOUT, Ok(0)),
        ("dontneed-locked", DONTNEED_LOCKED, Ok(0)),
        ("guard-install", GUARD_INSTALL, Ok(0)),
        ("guard-remove", GUARD_REMOVE, Ok(0)),
    ];
    for (i, (name, advice, want)) in accepted.into_iter().enumerate() {
        let m = anon(1 + i, 2);
        t.eq(format_args!("accepts-{name}"), madv(m, 2 * P, advice), want);
        unmap(m, 2);
    }
    let m = anon(20, 2);
    t.eq(
        "accepts-populate-read",
        madv(m, 2 * P, POPULATE_READ),
        Ok(0),
    );
    t.eq(
        "accepts-populate-write",
        madv(m, 2 * P, POPULATE_WRITE),
        Ok(0),
    );
    unmap(m, 2);
    // Unaligned start: EINVAL before anything is looked at.
    for (name, advice) in [
        ("normal", NORMAL),
        ("dontneed", DONTNEED),
        ("remove", REMOVE),
        ("guard-install", GUARD_INSTALL),
        ("populate-write", POPULATE_WRITE),
    ] {
        t.eq(
            format_args!("unaligned-start-{name}"),
            madv(a + 1, P, advice),
            E_INVAL,
        );
    }
    t.eq(
        "unaligned-start-unmapped",
        madv(a + 1, P, DONTNEED),
        E_INVAL,
    );
    // Length: rounded up; wrapping to zero or past the end of the address space is EINVAL.
    t.eq("len-rounds-up", madv(a, 1, DONTNEED), Ok(0));
    t.eq("len-max", madv(a, usize::MAX, DONTNEED), E_INVAL);
    t.eq(
        "len-wraps-to-zero",
        madv(a, usize::MAX - 4094, NORMAL),
        E_INVAL,
    );
    t.eq(
        "len-overflows",
        madv(a, usize::MAX - 4095, DONTNEED),
        E_INVAL,
    );
    t.eq(
        "start-plus-len-wraps",
        madv(usize::MAX - 4095, P, NORMAL),
        E_INVAL,
    );
    t.eq(
        "start-zero-len-huge",
        madv(0, usize::MAX - 4095, NORMAL),
        E_NOMEM,
    );
    // Length zero: valid advice is a no-op, whatever the range.
    t.eq("len-zero", madv(a, 0, DONTNEED), Ok(0));
    t.eq("len-zero-unmapped", madv(win(30), 0, DONTNEED), Ok(0));
    t.eq("len-zero-invalid-advice", madv(a, 0, 12), E_INVAL);
    t.eq("len-zero-unaligned", madv(a + 1, 0, DONTNEED), E_INVAL);
    t.eq("len-zero-guard", madv(win(30), 0, GUARD_INSTALL), Ok(0));
    t.eq("len-zero-populate", madv(win(30), 0, POPULATE_READ), Ok(0));
    // Beyond the user address space nothing is mapped.
    t.eq("beyond-task-size", madv(TASK_SIZE, P, NORMAL), E_NOMEM);
    t.eq(
        "kernel-half",
        madv(0xffff_8000_0000_0000, P, DONTNEED),
        E_NOMEM,
    );
    t.eq("unmapped-dontneed", madv(win(30), P, DONTNEED), E_NOMEM);
    t.eq("unmapped-guard", madv(win(30), P, GUARD_INSTALL), E_NOMEM);
    t.eq(
        "unmapped-populate",
        madv(win(30), P, POPULATE_READ),
        E_NOMEM,
    );
    unmap(a, 4);
}

fn walk(t: &mut T) {
    // [A A][hole][B B]: both mapped parts are processed, the hole is ENOMEM at the end.
    let a = anon(0, 5);
    fill(a, 5 * P, 9);
    unmap(a + 2 * P, 1);
    t.eq("hole-middle", madv(a, 5 * P, DONTNEED), E_NOMEM);
    t.holds(
        "hole-middle-both-sides-processed",
        zeroed(a, 2 * P) && zeroed(a + 3 * P, 2 * P),
        "not zero",
        "zero",
    );
    // [hole][A A]: the first VMA after the hole is still processed.
    fill(a, 2 * P, 9);
    t.eq("hole-first", madv(a - P, 3 * P, DONTNEED), E_NOMEM);
    t.holds("hole-first-processed", zeroed(a, 2 * P), "not zero", "zero");
    // [A A][hole]: the walk ends at the hole.
    fill(a, 2 * P, 9);
    t.eq("hole-last", madv(a, 3 * P, DONTNEED), E_NOMEM);
    t.holds("hole-last-processed", zeroed(a, 2 * P), "not zero", "zero");
    // Nothing mapped in the range at all.
    t.eq("hole-only", madv(a + 2 * P, P, DONTNEED), E_NOMEM);
    // An error ends the walk at once, with that error, and keeps what was done: [X][locked Y][Z].
    unmap(a, 5);
    let x = anon(1, 1);
    let y = map_at(x + P, 1, PROT_RW, MAP_LOCKED);
    let z = map_at(x + 2 * P, 1, PROT_RW, 0);
    fill(x, 3 * P, 5);
    t.holds(
        "locked-mapping-made",
        y == x + P && z == x + 2 * P,
        (y, z),
        "adjacent",
    );
    t.eq("error-ends-the-walk", madv(x, 3 * P, DONTNEED), E_INVAL);
    t.holds(
        "error-ends-the-walk-effects",
        zeroed(x, P) && striped(y, P, 5) && striped(z, P, 5),
        "unexpected contents",
        "X zero, Y and Z kept",
    );
    // A hole before the failing VMA: the error wins over the remembered ENOMEM.
    unmap(x, 3);
    let u = anon(2, 1);
    let l = map_at(u + 2 * P, 1, PROT_RW, MAP_LOCKED);
    fill(u, P, 3);
    t.holds("locked-after-hole", l == u + 2 * P, l, "mapped");
    t.eq("error-after-hole", madv(u, 3 * P, DONTNEED), E_INVAL);
    t.holds(
        "error-after-hole-first-processed",
        zeroed(u, P),
        "kept",
        "zero",
    );
    unmap(u, 1);
    unmap(l, 1);
}

fn dontneed(t: &mut T) {
    let a = anon(0, 6);
    fill(a, 6 * P, 0x5a);
    t.eq("dontneed-range", madv(a + P, 2 * P, DONTNEED), Ok(0));
    t.holds(
        "dontneed-zeroes-only-the-range",
        striped(a, P, 0x5a) && zeroed(a + P, 2 * P) && striped(a + 3 * P, 3 * P, 0x5a),
        "unexpected contents",
        "page 1-2 zero, rest kept",
    );
    t.eq("dontneed-keeps-mapping", madv(a, 6 * P, NORMAL), Ok(0));
    // Partial pages: the length rounds up to the page.
    t.eq("dontneed-rounds-len", madv(a + 3 * P, 1, DONTNEED), Ok(0));
    t.holds(
        "dontneed-rounds-len-effect",
        zeroed(a + 3 * P, P) && striped(a + 4 * P, 2 * P, 0x5a),
        "unexpected contents",
        "page 3 zero",
    );
    // The zero page (a read fault), then a write.
    let b = anon(1, 2);
    t.holds("zero-page-reads-zero", zeroed(b, 2 * P), "nonzero", "zero");
    t.eq("dontneed-zero-page", madv(b, 2 * P, DONTNEED), Ok(0));
    poke(b, 1);
    t.holds(
        "write-after-dontneed",
        peek(b) == 1 && zeroed(b + 1, P - 1),
        "bad",
        "fresh page",
    );
    // Written pages come back zero, also behind PROT_NONE and read-only.
    fill(b, 2 * P, 3);
    let _ = sys(Sysno::mprotect, &[b, 2 * P, PROT_NONE]);
    t.eq("dontneed-prot-none", madv(b, 2 * P, DONTNEED), Ok(0));
    let _ = sys(Sysno::mprotect, &[b, 2 * P, PROT_RW]);
    t.holds(
        "dontneed-prot-none-zeroed",
        zeroed(b, 2 * P),
        "nonzero",
        "zero",
    );
    fill(b, 2 * P, 4);
    let _ = sys(Sysno::mprotect, &[b, 2 * P, PROT_R]);
    t.eq("dontneed-read-only", madv(b, 2 * P, DONTNEED), Ok(0));
    t.holds(
        "dontneed-read-only-zeroed",
        zeroed(b, 2 * P),
        "nonzero",
        "zero",
    );
    unmap(b, 2);
    // A heap-like VMA split by the range: the pieces on both sides keep their data.
    fill(a, 6 * P, 0x11);
    t.eq("dontneed-middle", madv(a + 2 * P, P, DONTNEED), Ok(0));
    t.holds(
        "dontneed-middle-neighbours",
        striped(a + P, P, 0x11) && zeroed(a + 2 * P, P) && striped(a + 3 * P, P, 0x11),
        "unexpected contents",
        "only page 2 zero",
    );
    unmap(a, 6);
    // Locked mappings: EINVAL unless MADV_DONTNEED_LOCKED.
    let l = map_at(win(2), 2, PROT_RW, MAP_LOCKED);
    fill(l, 2 * P, 6);
    t.eq("locked-dontneed", madv(l, 2 * P, DONTNEED), E_INVAL);
    t.holds(
        "locked-dontneed-kept",
        striped(l, 2 * P, 6),
        "changed",
        "kept",
    );
    t.eq("locked-free", madv(l, 2 * P, FREE), E_INVAL);
    t.eq(
        "locked-dontneed-locked",
        madv(l, 2 * P, DONTNEED_LOCKED),
        Ok(0),
    );
    t.holds(
        "locked-dontneed-locked-zeroed",
        zeroed(l, 2 * P),
        "nonzero",
        "zero",
    );
    unmap(l, 2);
    // A private file mapping: dirty pages revert to the file.
    let fd = make_file(3);
    let f = file_map(win(3), 3, PROT_RW, MAP_PRIVATE, fd);
    t.holds(
        "file-pages",
        f != 0 && striped(f, P, b'A') && striped(f + P, P, b'B') && striped(f + 2 * P, P, b'C'),
        f,
        "A B C",
    );
    fill(f, 3 * P, b'Z');
    t.eq("file-dontneed-one", madv(f + P, P, DONTNEED), Ok(0));
    t.holds(
        "file-dontneed-one-reverts",
        striped(f, P, b'Z') && striped(f + P, P, b'B') && striped(f + 2 * P, P, b'Z'),
        "unexpected contents",
        "Z B Z",
    );
    t.eq("file-dontneed-all", madv(f, 3 * P, DONTNEED), Ok(0));
    t.holds(
        "file-dontneed-all-reverts",
        striped(f, P, b'A') && striped(f + P, P, b'B') && striped(f + 2 * P, P, b'C'),
        "unexpected contents",
        "A B C",
    );
    t.eq(
        "file-dontneed-locked",
        madv(f, 3 * P, DONTNEED_LOCKED),
        Ok(0),
    );
    unmap(f, 3);
    // The same file read-only and shared.
    let ro = open_ro();
    let s = file_map(win(4), 3, PROT_R, MAP_SHARED, ro);
    t.holds(
        "shared-file-pages",
        s != 0 && striped(s + P, P, b'B'),
        s,
        "B",
    );
    t.eq("shared-dontneed", madv(s, 3 * P, DONTNEED), Ok(0));
    t.holds(
        "shared-dontneed-keeps-file",
        striped(s + P, P, b'B'),
        "changed",
        "B",
    );
    unmap(s, 3);
    let _ = sys(Sysno::close, &[ro]);
    let _ = sys(Sysno::close, &[fd]);
    // The parent's pages are not the child's: DONTNEED in a child leaves the parent alone.
    let c = anon(5, 2);
    fill(c, 2 * P, 8);
    let st = child(|| {
        let _ = madv(c, 2 * P, DONTNEED);
        usize::from(zeroed(c, 2 * P))
    });
    t.eq("child-dontneed", st, exited(1));
    t.holds(
        "child-dontneed-parent-kept",
        striped(c, 2 * P, 8),
        "changed",
        "kept",
    );
    unmap(c, 2);
}

fn free(t: &mut T) {
    let a = anon(0, 4);
    fill(a, 4 * P, 0x33);
    t.eq("free", madv(a, 4 * P, FREE), Ok(0));
    // Without memory pressure the pages stay as they were; Linux frees them lazily.
    t.holds(
        "free-keeps-data-without-pressure",
        striped(a, 4 * P, 0x33),
        "changed",
        "kept",
    );
    poke(a, 0x44);
    t.eq("free-after-write", madv(a, P, FREE), Ok(0));
    t.eq("free-after-write-keeps", peek(a), 0x44);
    // A zero-page mapping and an untouched range.
    let b = anon(1, 2);
    t.eq("free-untouched", madv(b, 2 * P, FREE), Ok(0));
    t.holds("free-untouched-zero", zeroed(b, 2 * P), "nonzero", "zero");
    // Not anonymous: EINVAL.
    let fd = make_file(2);
    let f = file_map(win(2), 2, PROT_RW, MAP_PRIVATE, fd);
    t.eq("free-file", madv(f, 2 * P, FREE), E_INVAL);
    let ro = open_ro();
    let s = file_map(win(3), 2, PROT_R, MAP_SHARED, ro);
    t.eq("free-shared-file", madv(s, 2 * P, FREE), E_INVAL);
    // The walk: anonymous first, file second.
    let m = anon(4, 1);
    let f2 = file_map(m + P, 1, PROT_RW, MAP_PRIVATE, fd);
    t.holds("free-mixed-made", f2 == m + P, f2, "adjacent");
    t.eq("free-mixed", madv(m, 2 * P, FREE), E_INVAL);
    t.eq("free-mixed-file-first", madv(f2, P, FREE), E_INVAL);
    t.eq(
        "free-prot-none",
        {
            let n = anon(5, 1);
            let _ = sys(Sysno::mprotect, &[n, P, PROT_NONE]);
            let r = madv(n, P, FREE);
            unmap(n, 1);
            r
        },
        Ok(0),
    );
    unmap(a, 4);
    unmap(b, 2);
    unmap(f, 2);
    unmap(s, 2);
    unmap(m, 2);
    let _ = sys(Sysno::close, &[ro]);
    let _ = sys(Sysno::close, &[fd]);
}

fn remove(t: &mut T) {
    let a = anon(0, 2);
    t.eq("remove-anonymous", madv(a, 2 * P, REMOVE), E_INVAL);
    let l = map_at(win(1), 1, PROT_RW, MAP_LOCKED);
    t.eq("remove-locked", madv(l, P, REMOVE), E_INVAL);
    let fd = make_file(2);
    let f = file_map(win(2), 2, PROT_RW, MAP_PRIVATE, fd);
    t.eq(
        "remove-private-file",
        madv(f, 2 * P, REMOVE),
        Err(Errno::EACCES),
    );
    // A shared mapping of a descriptor that cannot write is not shared-and-writable either.
    let ro = open_ro();
    let s = file_map(win(3), 2, PROT_R, MAP_SHARED, ro);
    t.eq(
        "remove-shared-read-only-file",
        madv(s, 2 * P, REMOVE),
        Err(Errno::EACCES),
    );
    // The first error decides, a hole after it does not.
    t.eq("remove-hole", madv(win(9), P, REMOVE), E_NOMEM);
    t.eq(
        "remove-first-error-wins",
        {
            let m = map_at(win(5), 1, PROT_RW, 0);
            let g = file_map(m + P, 1, PROT_RW, MAP_PRIVATE, fd);
            let r = madv(m, 2 * P, REMOVE);
            unmap(m, 1 + usize::from(g != 0));
            r
        },
        E_INVAL,
    );
    unmap(a, 2);
    unmap(l, 1);
    unmap(f, 2);
    unmap(s, 2);
    let _ = sys(Sysno::close, &[ro]);
    let _ = sys(Sysno::close, &[fd]);
}

/// Advice that only changes VMA flags (`madvise_update_vma`): the VMAs split and merge, which
/// `/proc/self/maps` shows.
fn advice_flags(t: &mut T) {
    let mounted = sys(
        Sysno::mount,
        &[addr(b"proc\0"), addr(b"/proc\0"), addr(b"proc\0"), 0, 0],
    );
    t.eq("mount-proc", mounted, Ok(0));
    let a = anon(0, 6);
    view(t, a, "one-vma", "0-6000 rw-p;");
    t.eq("random-middle", madv(a + 2 * P, P, RANDOM), Ok(0));
    view(
        t,
        a,
        "random-splits",
        "0-2000 rw-p;2000-3000 rw-p;3000-6000 rw-p;",
    );
    t.eq(
        "sequential-same-page",
        madv(a + 2 * P, P, SEQUENTIAL),
        Ok(0),
    );
    view(
        t,
        a,
        "sequential-keeps-the-split",
        "0-2000 rw-p;2000-3000 rw-p;3000-6000 rw-p;",
    );
    t.eq("normal-same-page", madv(a + 2 * P, P, NORMAL), Ok(0));
    view(t, a, "normal-merges-back", "0-6000 rw-p;");
    t.eq("random-all", madv(a, 6 * P, RANDOM), Ok(0));
    view(t, a, "random-all-one-vma", "0-6000 rw-p;");
    t.eq("normal-edge", madv(a, P, NORMAL), Ok(0));
    view(t, a, "normal-edge-splits", "0-1000 rw-p;1000-6000 rw-p;");
    t.eq("normal-rest", madv(a + P, 5 * P, NORMAL), Ok(0));
    view(t, a, "normal-rest-merges", "0-6000 rw-p;");
    // WILLNEED, COLD and PAGEOUT leave the VMAs alone.
    t.eq("willneed-middle", madv(a + 2 * P, P, WILLNEED), Ok(0));
    t.eq("cold-middle", madv(a + 2 * P, P, COLD), Ok(0));
    t.eq("pageout-middle", madv(a + 2 * P, P, PAGEOUT), Ok(0));
    view(t, a, "no-split-by-willneed-cold-pageout", "0-6000 rw-p;");
    // DONTDUMP / DODUMP / DONTFORK / DOFORK / WIPEONFORK / KEEPONFORK change the flags too.
    for (name, set, clear) in [
        ("dontdump", DONTDUMP, DODUMP),
        ("dontfork", DONTFORK, DOFORK),
        ("wipeonfork", WIPEONFORK, KEEPONFORK),
    ] {
        t.eq(format_args!("{name}-set"), madv(a + P, 2 * P, set), Ok(0));
        view(
            t,
            a,
            format_args!("{name}-splits"),
            "0-1000 rw-p;1000-3000 rw-p;3000-6000 rw-p;",
        );
        t.eq(
            format_args!("{name}-set-again"),
            madv(a + P, 2 * P, set),
            Ok(0),
        );
        view(
            t,
            a,
            format_args!("{name}-set-again-same"),
            "0-1000 rw-p;1000-3000 rw-p;3000-6000 rw-p;",
        );
        t.eq(
            format_args!("{name}-clear"),
            madv(a + P, 2 * P, clear),
            Ok(0),
        );
        view(t, a, format_args!("{name}-clear-merges"), "0-6000 rw-p;");
    }
    // Different flags on neighbouring pages do not merge; clearing one merges what remains.
    t.eq("mixed-1", madv(a, P, DONTFORK), Ok(0));
    t.eq("mixed-2", madv(a + P, P, DONTDUMP), Ok(0));
    t.eq("mixed-3", madv(a + 2 * P, P, DONTFORK), Ok(0));
    view(
        t,
        a,
        "mixed-three",
        "0-1000 rw-p;1000-2000 rw-p;2000-3000 rw-p;3000-6000 rw-p;",
    );
    t.eq("mixed-4", madv(a + 3 * P, 3 * P, DONTFORK), Ok(0));
    view(
        t,
        a,
        "mixed-merge-left",
        "0-1000 rw-p;1000-2000 rw-p;2000-6000 rw-p;",
    );
    t.eq("mixed-5", madv(a + P, P, DONTFORK), Ok(0));
    view(
        t,
        a,
        "mixed-flags-differ",
        "0-1000 rw-p;1000-2000 rw-p;2000-6000 rw-p;",
    );
    t.eq("mixed-clear-dump", madv(a, 6 * P, DODUMP), Ok(0));
    view(t, a, "mixed-clear-merges-both-sides", "0-6000 rw-p;");
    t.eq("mixed-clear", madv(a, 6 * P, DOFORK), Ok(0));
    view(t, a, "mixed-clear-one-vma", "0-6000 rw-p;");
    unmap(a, 6);
    // Locked mappings: COLD and PAGEOUT are EINVAL, WILLNEED is not.
    let l = map_at(win(1), 2, PROT_RW, MAP_LOCKED);
    t.eq("locked-cold", madv(l, 2 * P, COLD), E_INVAL);
    t.eq("locked-pageout", madv(l, 2 * P, PAGEOUT), E_INVAL);
    t.eq("locked-willneed", madv(l, 2 * P, WILLNEED), Ok(0));
    t.eq("locked-random", madv(l, 2 * P, RANDOM), Ok(0));
    t.eq("locked-dontfork", madv(l, 2 * P, DONTFORK), Ok(0));
    t.eq("locked-wipeonfork", madv(l, 2 * P, WIPEONFORK), Ok(0));
    unmap(l, 2);
    // Holes: the part that exists is processed, the result is ENOMEM.
    let h = anon(2, 4);
    unmap(h + P, 1);
    t.eq("hole-random", madv(h, 4 * P, RANDOM), E_NOMEM);
    view(t, h, "hole-random-applied", "0-1000 rw-p;2000-4000 rw-p;");
    t.eq("hole-cold", madv(h, 4 * P, COLD), E_NOMEM);
    t.eq("hole-willneed", madv(h, 4 * P, WILLNEED), E_NOMEM);
    unmap(h, 4);
    // Files.
    let fd = make_file(2);
    let f = file_map(win(3), 2, PROT_RW, MAP_PRIVATE, fd);
    t.eq("file-willneed", madv(f, 2 * P, WILLNEED), Ok(0));
    t.eq("file-cold", madv(f, 2 * P, COLD), Ok(0));
    t.eq("file-pageout", madv(f, 2 * P, PAGEOUT), Ok(0));
    t.eq("file-sequential", madv(f, 2 * P, SEQUENTIAL), Ok(0));
    t.eq("file-dontdump", madv(f, 2 * P, DONTDUMP), Ok(0));
    t.eq("file-wipeonfork", madv(f, 2 * P, WIPEONFORK), E_INVAL);
    t.eq("file-keeponfork", madv(f, 2 * P, KEEPONFORK), Ok(0));
    t.eq("file-dontfork", madv(f, 2 * P, DONTFORK), Ok(0));
    t.eq(
        "file-dontfork-child",
        child(|| usize::from(madv(f, 2 * P, NORMAL) == E_NOMEM)),
        exited(1),
    );
    t.eq("file-dofork", madv(f, 2 * P, DOFORK), Ok(0));
    t.eq(
        "file-dofork-child",
        child(|| usize::from(striped(f, P, b'A'))),
        exited(1),
    );
    let ro = open_ro();
    let s = file_map(win(4), 2, PROT_R, MAP_SHARED, ro);
    t.eq("shared-wipeonfork", madv(s, 2 * P, WIPEONFORK), E_INVAL);
    t.eq("shared-pageout", madv(s, 2 * P, PAGEOUT), Ok(0));
    t.eq("shared-cold", madv(s, 2 * P, COLD), Ok(0));
    // What paging out leaves behind: the pages are still there afterwards.
    fill(f, P, b'Q');
    t.eq(
        "pageout-dirty-private-file-page",
        madv(f, 2 * P, PAGEOUT),
        Ok(0),
    );
    t.holds(
        "pageout-keeps-dirty-data",
        peek(f) == b'Q' && striped(f + P, P, b'B'),
        peek(f),
        "Q",
    );
    unmap(f, 2);
    unmap(s, 2);
    let _ = sys(Sysno::close, &[ro]);
    let _ = sys(Sysno::close, &[fd]);
    // MAP_DROPPABLE: wiped on fork and not dumped by construction.
    let d = super::mmap(
        win(5),
        2 * P,
        PROT_RW,
        MAP_DROPPABLE | MAP_ANON | MAP_FIXED_NOREPLACE,
        NOFD,
        0,
    );
    t.holds("droppable-mapped", d == Ok(win(5)), d, "mapped");
    t.eq(
        "droppable-keeponfork",
        madv(win(5), 2 * P, KEEPONFORK),
        E_INVAL,
    );
    t.eq("droppable-dodump", madv(win(5), 2 * P, DODUMP), E_INVAL);
    t.eq("droppable-dontdump", madv(win(5), 2 * P, DONTDUMP), Ok(0));
    t.eq(
        "droppable-wipeonfork",
        madv(win(5), 2 * P, WIPEONFORK),
        Ok(0),
    );
    t.eq("droppable-dontneed", madv(win(5), 2 * P, DONTNEED), Ok(0));
    unmap(win(5), 2);
}

/// The VMAs of the window of `a` against the expected list.
fn view(t: &mut T, a: usize, name: impl fmt::Display, want: &str) {
    t.eq(name, maps(a, a + 0x100_0000).as_str(), want);
}

fn fork_flags(t: &mut T) {
    // DONTFORK: the child has no such range; the parent keeps it.
    let a = anon(0, 6);
    fill(a, 6 * P, 0x21);
    t.eq("dontfork", madv(a + 2 * P, 2 * P, DONTFORK), Ok(0));
    let st = child(|| {
        usize::from(striped(a, 2 * P, 0x21))
            | usize::from(striped(a + 4 * P, 2 * P, 0x21)) << 1
            | usize::from(madv(a + 2 * P, 2 * P, NORMAL) == E_NOMEM) << 2
            | usize::from(madv(a + 2 * P, P, NORMAL) == E_NOMEM) << 3
            | usize::from(madv(a + 3 * P, P, NORMAL) == E_NOMEM) << 4
    });
    t.eq("dontfork-child-view", st, exited(0x1f));
    t.eq(
        "dontfork-child-fault",
        child(|| touch(a + 2 * P + 8, false)),
        exited(SEGV_MAPERR),
    );
    t.holds(
        "dontfork-parent-kept",
        striped(a, 6 * P, 0x21),
        "changed",
        "kept",
    );
    t.eq("dofork", madv(a + 2 * P, 2 * P, DOFORK), Ok(0));
    let st = child(|| usize::from(striped(a, 6 * P, 0x21)));
    t.eq("dofork-child-view", st, exited(1));
    // The flag is inherited: a child of a child.
    t.eq("dontfork-again", madv(a, P, DONTFORK), Ok(0));
    let st = child(|| {
        let first = madv(a, P, NORMAL) == E_NOMEM;
        let grandchild = child(|| usize::from(madv(a + P, P, NORMAL) == Ok(0)));
        usize::from(first) | usize::from(grandchild == exited(1)) << 1
    });
    t.eq("dontfork-two-generations", st, exited(3));
    unmap(a, 6);

    // WIPEONFORK: the child sees zeroes, the parent its data; a write of the child stays its own.
    let w = anon(1, 4);
    fill(w, 4 * P, 0x61);
    t.eq("wipeonfork", madv(w + P, 2 * P, WIPEONFORK), Ok(0));
    let st = child(|| {
        let view = usize::from(striped(w, P, 0x61))
            | usize::from(zeroed(w + P, 2 * P)) << 1
            | usize::from(striped(w + 3 * P, P, 0x61)) << 2;
        fill(w + P, 2 * P, 0x77);
        // A child of the wiping child is wiped again.
        let grand = child(|| usize::from(zeroed(w + P, 2 * P)));
        view | usize::from(striped(w + P, 2 * P, 0x77)) << 3 | usize::from(grand == exited(1)) << 4
    });
    t.eq("wipeonfork-child-view", st, exited(0x1f));
    t.holds(
        "wipeonfork-parent-kept",
        striped(w, 4 * P, 0x61),
        "changed",
        "kept",
    );
    t.eq("keeponfork", madv(w + P, 2 * P, KEEPONFORK), Ok(0));
    let st = child(|| usize::from(striped(w, 4 * P, 0x61)));
    t.eq("keeponfork-child-view", st, exited(1));
    t.eq(
        "wipeonfork-prot-none",
        {
            let _ = sys(Sysno::mprotect, &[w, P, PROT_NONE]);
            let r = madv(w, P, WIPEONFORK);
            let _ = sys(Sysno::mprotect, &[w, P, PROT_RW]);
            r
        },
        Ok(0),
    );
    t.eq(
        "wipeonfork-then-dontfork",
        {
            let _ = madv(w, 4 * P, WIPEONFORK);
            madv(w + P, P, DONTFORK)
        },
        Ok(0),
    );
    let st = child(|| {
        usize::from(zeroed(w, P))
            | usize::from(madv(w + P, P, NORMAL) == E_NOMEM) << 1
            | usize::from(zeroed(w + 2 * P, 2 * P)) << 2
    });
    t.eq("wipeonfork-and-dontfork", st, exited(7));
    unmap(w, 4);
}

fn guard(t: &mut T, probe: &Probe) {
    // Install over a range that is partly populated: populated pages go, the rest stays.
    let a = anon(0, 8);
    fill(a, 6 * P, 0x41);
    t.eq("install", madv(a + P, 4 * P, GUARD_INSTALL), Ok(0));
    t.eq("read-before", access(a, false), exited(0));
    for (i, name) in ["first", "second", "third", "fourth"]
        .into_iter()
        .enumerate()
    {
        t.eq(
            format_args!("read-guard-{name}"),
            access(a + (1 + i) * P + 7, false),
            exited(SEGV_MAPERR),
        );
    }
    t.eq(
        "write-guard",
        access(a + 2 * P + 9, true),
        exited(SEGV_MAPERR),
    );
    t.eq("read-after", access(a + 5 * P, false), exited(0));
    t.eq("read-untouched-after", access(a + 7 * P, false), exited(0));
    t.holds(
        "install-keeps-outside",
        striped(a, P, 0x41) && striped(a + 5 * P, P, 0x41),
        "changed",
        "kept",
    );
    // The kernel's own accesses fail the same way: EFAULT, and a copy stops at the guard.
    t.holds(
        "kernel-read-guard",
        !probe.readable(a + P, P) && !probe.readable(a + 2 * P, 1),
        "readable",
        "EFAULT",
    );
    t.holds(
        "kernel-write-guard",
        !probe.writable(a + 3 * P, P),
        "writable",
        "EFAULT",
    );
    t.holds(
        "kernel-access-outside",
        probe.readable(a, P) && probe.writable(a + 5 * P, P),
        "refused",
        "fine",
    );
    let mut fds = [0u32; 2];
    let _ = sys(Sysno::pipe2, &[addr_mut(&mut fds), 0]);
    t.eq(
        "write-stops-at-guard",
        sys(Sysno::write, &[fds[1] as usize, a, 2 * P]),
        Ok(P),
    );
    t.eq(
        "write-starting-at-guard",
        sys(Sysno::write, &[fds[1] as usize, a + P, P]),
        Err(Errno::EFAULT),
    );
    let _ = sys(Sysno::close, &[fds[0] as usize]);
    let _ = sys(Sysno::close, &[fds[1] as usize]);
    // Installing again changes nothing; markers survive DONTNEED, FREE, WILLNEED, COLD, PAGEOUT.
    t.eq("install-again", madv(a + P, 4 * P, GUARD_INSTALL), Ok(0));
    // A page that only ever mapped the zero page takes the marker too.
    let z = anon(10, 2);
    t.holds("zero-page-read", zeroed(z, 2 * P), "nonzero", "zero");
    t.eq(
        "install-over-zero-page",
        madv(z, 2 * P, GUARD_INSTALL),
        Ok(0),
    );
    t.eq("zero-page-guard", access(z + P, false), exited(SEGV_MAPERR));
    unmap(z, 2);
    t.eq(
        "install-overlap",
        madv(a + 3 * P, 3 * P, GUARD_INSTALL),
        Ok(0),
    );
    t.eq("dontneed-over-guard", madv(a, 8 * P, DONTNEED), Ok(0));
    t.eq("free-over-guard", madv(a, 8 * P, FREE), Ok(0));
    t.eq("willneed-over-guard", madv(a, 8 * P, WILLNEED), Ok(0));
    t.eq("cold-over-guard", madv(a, 8 * P, COLD), Ok(0));
    t.eq("pageout-over-guard", madv(a, 8 * P, PAGEOUT), Ok(0));
    t.eq(
        "still-guard-after-dontneed",
        access(a + 2 * P, false),
        exited(SEGV_MAPERR),
    );
    t.eq(
        "still-guard-after-overlap",
        access(a + 5 * P, false),
        exited(SEGV_MAPERR),
    );
    // Remove: the pages are fresh zero pages again.
    t.eq("remove", madv(a + 2 * P, 2 * P, GUARD_REMOVE), Ok(0));
    t.eq("removed-read", access(a + 2 * P, false), exited(0));
    t.eq("removed-write", access(a + 3 * P, true), exited(0));
    t.holds("removed-zero", zeroed(a + 2 * P, 2 * P), "nonzero", "zero");
    t.eq(
        "kept-guard-before",
        access(a + P, false),
        exited(SEGV_MAPERR),
    );
    t.eq(
        "kept-guard-after",
        access(a + 4 * P, false),
        exited(SEGV_MAPERR),
    );
    t.eq("remove-where-none", madv(a, P, GUARD_REMOVE), Ok(0));
    t.eq("remove-all", madv(a, 8 * P, GUARD_REMOVE), Ok(0));
    t.eq("removed-everything", access(a + P, false), exited(0));
    t.eq(
        "removed-everything-last",
        access(a + 4 * P, true),
        exited(0),
    );
    // Holes: the mapped parts are processed, the result is ENOMEM.
    unmap(a + 2 * P, 1);
    t.eq("install-over-hole", madv(a, 4 * P, GUARD_INSTALL), E_NOMEM);
    t.eq(
        "install-over-hole-first",
        access(a + 3 * P, false),
        exited(SEGV_MAPERR),
    );
    t.eq(
        "install-over-hole-before",
        access(a, false),
        exited(SEGV_MAPERR),
    );
    t.eq("remove-over-hole", madv(a, 4 * P, GUARD_REMOVE), E_NOMEM);
    t.eq(
        "remove-over-hole-applied",
        access(a + 3 * P, false),
        exited(0),
    );
    t.eq(
        "install-in-hole",
        madv(a + 2 * P, P, GUARD_INSTALL),
        E_NOMEM,
    );
    unmap(a, 8);

    // Protection: access errors win over the marker; the marker survives mprotect.
    let b = anon(1, 3);
    t.eq("install-prot", madv(b, 3 * P, GUARD_INSTALL), Ok(0));
    let _ = sys(Sysno::mprotect, &[b, 3 * P, PROT_NONE]);
    t.eq("guard-prot-none", access(b + P, false), exited(SEGV_ACCERR));
    let _ = sys(Sysno::mprotect, &[b, 3 * P, PROT_RW]);
    t.eq(
        "guard-after-mprotect",
        access(b + P, false),
        exited(SEGV_MAPERR),
    );
    let _ = sys(Sysno::mprotect, &[b + P, P, PROT_R]);
    t.eq(
        "guard-read-only-write",
        access(b + P, true),
        exited(SEGV_ACCERR),
    );
    t.eq(
        "guard-read-only-read",
        access(b + P, false),
        exited(SEGV_MAPERR),
    );
    t.eq(
        "guard-read-only-neighbour",
        access(b, false),
        exited(SEGV_MAPERR),
    );
    // Locked mappings take no new guard but may lose theirs.
    let l = map_at(win(2), 2, PROT_RW, MAP_LOCKED);
    t.eq("guard-install-locked", madv(l, 2 * P, GUARD_INSTALL), E_INVAL);
    t.eq("guard-remove-locked", madv(l, 2 * P, GUARD_REMOVE), Ok(0));
    unmap(l, 2);
    // A guard disappears with the mapping.
    unmap(b, 3);
    let b2 = anon(1, 3);
    t.eq("after-munmap-no-guard", access(b2 + P, true), exited(0));
    unmap(b2, 3);

    // mremap moves the markers with the pages.
    let m = anon(3, 4);
    let _ = madv(m + P, P, GUARD_INSTALL);
    let moved = sys(
        Sysno::mremap,
        &[m, 4 * P, 4 * P, MREMAP_MAYMOVE | MREMAP_FIXED, win(4)],
    );
    t.eq("mremap-moves", moved, Ok(win(4)));
    t.eq(
        "mremap-moved-guard",
        access(win(4) + P, false),
        exited(SEGV_MAPERR),
    );
    t.eq("mremap-moved-page", access(win(4), true), exited(0));
    t.eq(
        "mremap-source-gone",
        access(m + P, false),
        exited(SEGV_MAPERR),
    );
    unmap(win(4), 4);

    // Fork: the child has the guard, a DONTFORK range has nothing, WIPEONFORK drops the guard.
    let f = anon(5, 6);
    let _ = madv(f + P, P, GUARD_INSTALL);
    let _ = madv(f + 3 * P, P, GUARD_INSTALL);
    let _ = madv(f + 5 * P, P, GUARD_INSTALL);
    let _ = madv(f + 3 * P, P, WIPEONFORK);
    let _ = madv(f + 5 * P, P, DONTFORK);
    t.eq(
        "fork-child-guard",
        child(|| touch(f + P + 5, false)),
        exited(SEGV_MAPERR),
    );
    t.eq(
        "fork-child-wiped-guard",
        child(|| touch(f + 3 * P, true)),
        exited(0),
    );
    t.eq(
        "fork-child-dontfork-guard",
        child(|| touch(f + 5 * P, false)),
        exited(SEGV_MAPERR),
    );
    t.eq(
        "fork-parent-guard",
        access(f + P, true),
        exited(SEGV_MAPERR),
    );
    // (Not through `access`, which forks: the copy of a wiped page has no guard.)
    t.holds(
        "fork-parent-wiped-guard",
        !probe.readable(f + 3 * P, 1) && !probe.writable(f + 3 * P, 1),
        "readable",
        "EFAULT",
    );
    t.eq(
        "fork-parent-dontfork-guard",
        access(f + 5 * P, true),
        exited(SEGV_MAPERR),
    );
    t.eq(
        "fork-child-removes-its-own",
        child(|| {
            let _ = madv(f + P, P, GUARD_REMOVE);
            touch(f + P, true)
        }),
        exited(0),
    );
    t.eq(
        "fork-child-removal-private",
        access(f + P, false),
        exited(SEGV_MAPERR),
    );
    unmap(f, 6);

    // A VMA that has seen a guard still merges with its neighbours (VM_MAYBE_GUARD is sticky).
    let g = anon(6, 2);
    t.eq("guard-for-merge", madv(g, P, GUARD_INSTALL), Ok(0));
    let g2 = map_at(g + 2 * P, 2, PROT_RW, 0);
    t.holds("guard-neighbour-mapped", g2 == g + 2 * P, g2, "adjacent");
    t.eq(
        "guard-vma-merges-with-a-new-neighbour",
        maps(g, g + 0x100_0000).as_str(),
        "0-4000 rw-p;",
    );
    t.eq(
        "guard-merged-vma-keeps-guard",
        access(g, false),
        exited(SEGV_MAPERR),
    );
    t.eq(
        "guard-merged-vma-neighbour-page",
        access(g + P, true),
        exited(0),
    );
    // Splitting keeps the marker on the page it was on.
    let _ = sys(Sysno::mprotect, &[g + P, P, PROT_R]);
    t.eq(
        "guard-vma-splits",
        maps(g, g + 0x100_0000).as_str(),
        "0-1000 rw-p;1000-2000 r--p;2000-4000 rw-p;",
    );
    t.eq("guard-split-keeps", access(g, true), exited(SEGV_MAPERR));
    unmap(g, 4);

    // File pages: the guard hides the page, removing it brings the file back.
    let fd = make_file(3);
    let p = file_map(win(7), 3, PROT_RW, MAP_PRIVATE, fd);
    t.holds(
        "guard-file-page-read",
        striped(p + P, P, b'B'),
        "other",
        "B",
    );
    t.eq("guard-install-file", madv(p + P, P, GUARD_INSTALL), Ok(0));
    t.eq(
        "guard-file-hides",
        access(p + P, false),
        exited(SEGV_MAPERR),
    );
    t.holds(
        "guard-file-neighbours",
        striped(p, P, b'A') && striped(p + 2 * P, P, b'C'),
        "other",
        "A C",
    );
    t.eq("guard-remove-file", madv(p + P, P, GUARD_REMOVE), Ok(0));
    t.holds("guard-file-back", striped(p + P, P, b'B'), "other", "B");
    t.eq(
        "guard-install-file-again",
        madv(p, 3 * P, GUARD_INSTALL),
        Ok(0),
    );
    t.eq("guard-file-dontneed", madv(p, 3 * P, DONTNEED), Ok(0));
    t.eq(
        "guard-file-dontneed-keeps",
        access(p + 2 * P, false),
        exited(SEGV_MAPERR),
    );
    unmap(p, 3);
    let ro = open_ro();
    let q = file_map(win(8), 2, PROT_R, MAP_SHARED, ro);
    t.eq(
        "guard-install-shared-file",
        madv(q, 2 * P, GUARD_INSTALL),
        Ok(0),
    );
    t.eq(
        "guard-shared-file-hides",
        access(q + 8, false),
        exited(SEGV_MAPERR),
    );
    t.eq(
        "guard-remove-shared-file",
        madv(q, 2 * P, GUARD_REMOVE),
        Ok(0),
    );
    t.holds("guard-shared-file-back", striped(q, P, b'A'), "other", "A");
    unmap(q, 2);
    let _ = sys(Sysno::close, &[ro]);
    let _ = sys(Sysno::close, &[fd]);
}

/// The address space is shared by the threads of a process: advice from one is seen by all.
fn threads(t: &mut T, probe: &Probe) {
    fn worker(control: &'static Control) -> usize {
        let a = control.arg;
        usize::from(madv(a + P, P, DONTNEED) == Ok(0))
            | usize::from(madv(a + 2 * P, P, GUARD_INSTALL) == Ok(0)) << 1
            | usize::from(madv(a + 3 * P, P, DONTFORK) == Ok(0)) << 2
    }
    let a = anon(13, 4);
    fill(a, 4 * P, 5);
    let thread = spawn_thread(worker, a);
    t.eq("thread-advice", thread.join(), 7);
    t.holds(
        "thread-dontneed-is-seen",
        striped(a, P, 5) && zeroed(a + P, P) && striped(a + 3 * P, P, 5),
        "unexpected contents",
        "page 1 zero",
    );
    t.holds(
        "thread-guard-is-seen",
        !probe.readable(a + 2 * P, 1) && probe.readable(a + P, 1),
        "readable",
        "EFAULT",
    );
    t.eq(
        "thread-dontfork-is-seen",
        child(|| usize::from(madv(a + 3 * P, P, NORMAL) == E_NOMEM)),
        exited(1),
    );
    unmap(a, 4);
}

fn populate(t: &mut T) {
    let a = anon(0, 8);
    let _ = rss();
    let (r0, ..) = rss();
    t.eq("populate-write", madv(a, 4 * P, POPULATE_WRITE), Ok(0));
    let (r1, ..) = rss();
    t.eq("populate-write-resident", r1 - r0, 16);
    t.eq(
        "populate-read",
        madv(a + 4 * P, 2 * P, POPULATE_READ),
        Ok(0),
    );
    let (r2, ..) = rss();
    t.eq("populate-read-maps-the-zero-page", r2 - r1, 0);
    t.eq(
        "populate-write-after-read",
        madv(a + 4 * P, 2 * P, POPULATE_WRITE),
        Ok(0),
    );
    let (r3, ..) = rss();
    t.eq("populate-write-replaces-the-zero-page", r3 - r2, 8);
    t.eq("populate-twice", madv(a, 6 * P, POPULATE_WRITE), Ok(0));
    let (r4, ..) = rss();
    t.eq("populate-twice-no-growth", r4 - r3, 0);
    t.holds("populate-reads-zero", zeroed(a, 6 * P), "nonzero", "zero");
    t.eq(
        "populate-read-resident",
        madv(a + 6 * P, 2 * P, POPULATE_READ),
        Ok(0),
    );
    let (r5, ..) = rss();
    t.eq("populate-read-no-growth", r5 - r4, 0);
    unmap(a, 8);

    // The resident-set counter follows every way of dropping a page.
    let c = anon(11, 8);
    let anon_kb = || rss().0 as isize;
    let c0 = anon_kb();
    t.eq("rss-populate", madv(c, 8 * P, POPULATE_WRITE), Ok(0));
    t.eq("rss-populate-charged", anon_kb() - c0, 32);
    t.eq("rss-free", madv(c, 8 * P, FREE), Ok(0));
    t.eq("rss-free-keeps-pages", anon_kb() - c0, 32);
    t.eq("rss-dontneed", madv(c + P, 2 * P, DONTNEED), Ok(0));
    t.eq("rss-dontneed-uncharged", anon_kb() - c0, 24);
    t.eq(
        "rss-guard-install",
        madv(c + 2 * P, 3 * P, GUARD_INSTALL),
        Ok(0),
    );
    t.eq("rss-guard-install-uncharged", anon_kb() - c0, 16);
    t.eq("rss-dontneed-keeps-guards", madv(c, 8 * P, DONTNEED), Ok(0));
    t.eq("rss-dontneed-all-uncharged", anon_kb() - c0, 0);
    t.eq(
        "rss-populate-around-guards",
        madv(c, 8 * P, POPULATE_WRITE),
        Err(Errno::EFAULT),
    );
    t.eq("rss-populate-stops-at-the-guard", anon_kb() - c0, 8);
    unmap(c, 8);
    t.eq("rss-munmap-uncharged", anon_kb() - c0, 0);

    // Permissions: the VMA must allow the access, else EINVAL (not EFAULT).
    let ro = map_at(win(1), 2, PROT_R, 0);
    t.eq(
        "populate-write-read-only",
        madv(ro, 2 * P, POPULATE_WRITE),
        E_INVAL,
    );
    t.eq(
        "populate-read-read-only",
        madv(ro, 2 * P, POPULATE_READ),
        Ok(0),
    );
    let none = map_at(win(2), 2, PROT_NONE, 0);
    t.eq(
        "populate-read-prot-none",
        madv(none, 2 * P, POPULATE_READ),
        E_INVAL,
    );
    t.eq(
        "populate-write-prot-none",
        madv(none, 2 * P, POPULATE_WRITE),
        E_INVAL,
    );
    let wo = map_at(win(3), 2, PROT_W, 0);
    t.eq(
        "populate-read-write-only",
        madv(wo, 2 * P, POPULATE_READ),
        E_INVAL,
    );
    t.eq(
        "populate-write-write-only",
        madv(wo, 2 * P, POPULATE_WRITE),
        Ok(0),
    );
    // Holes: ENOMEM at once, after what came before.
    let h = anon(4, 6);
    unmap(h + 2 * P, 1);
    let (h0, ..) = rss();
    t.eq("populate-hole", madv(h, 6 * P, POPULATE_WRITE), E_NOMEM);
    let (h1, ..) = rss();
    t.eq("populate-hole-prefix-done", h1 - h0, 8);
    t.eq(
        "populate-hole-first",
        madv(h + 2 * P, 2 * P, POPULATE_WRITE),
        E_NOMEM,
    );
    // The first failing VMA stops it with its own error.
    let m = anon(5, 2);
    let n = map_at(m + 2 * P, 2, PROT_NONE, 0);
    t.holds("populate-mixed-made", n == m + 2 * P, n, "adjacent");
    let (m0, ..) = rss();
    t.eq("populate-mixed", madv(m, 4 * P, POPULATE_WRITE), E_INVAL);
    let (m1, ..) = rss();
    t.eq("populate-mixed-prefix-done", m1 - m0, 8);
    // Locked and file mappings.
    let fd = make_file(3);
    let f = file_map(win(6), 3, PROT_RW, MAP_PRIVATE, fd);
    let (_, _, sh0) = rss();
    t.eq("populate-read-file", madv(f, 3 * P, POPULATE_READ), Ok(0));
    let (_, _, sh1) = rss();
    t.eq("populate-read-file-resident", sh1 - sh0, 12);
    let (a2, ..) = rss();
    t.eq("populate-write-file", madv(f, 2 * P, POPULATE_WRITE), Ok(0));
    let (a3, _, sh3) = rss();
    t.eq("populate-write-file-copies", (a3 - a2, sh1 - sh3), (8, 8));
    t.holds(
        "populate-file-data",
        striped(f, P, b'A') && striped(f + 2 * P, P, b'C'),
        "other",
        "A C",
    );
    // The shared read-only file mapping.
    let ro = open_ro();
    let s = file_map(win(7), 3, PROT_R, MAP_SHARED, ro);
    t.eq(
        "populate-read-shared-file",
        madv(s, 3 * P, POPULATE_READ),
        Ok(0),
    );
    t.eq(
        "populate-write-shared-file",
        madv(s, 3 * P, POPULATE_WRITE),
        E_INVAL,
    );
    unmap(f, 3);
    unmap(s, 3);
    let _ = sys(Sysno::close, &[ro]);
    let _ = sys(Sysno::close, &[fd]);
    // A file mapping that reaches past the end of the file: SIGBUS-ing pages are EFAULT.
    let fd = make_file(1);
    let beyond = file_map(win(8), 3, PROT_R, MAP_PRIVATE, fd);
    t.eq(
        "populate-past-eof",
        madv(beyond, 3 * P, POPULATE_READ),
        Err(Errno::EFAULT),
    );
    unmap(beyond, 3);
    let _ = sys(Sysno::close, &[fd]);
    // Guards: EFAULT.
    let g = anon(9, 4);
    let _ = madv(g + 2 * P, P, GUARD_INSTALL);
    let (g0, ..) = rss();
    t.eq(
        "populate-read-guard",
        madv(g, 4 * P, POPULATE_READ),
        Err(Errno::EFAULT),
    );
    t.eq(
        "populate-write-guard",
        madv(g, 4 * P, POPULATE_WRITE),
        Err(Errno::EFAULT),
    );
    let (g1, ..) = rss();
    t.eq("populate-guard-prefix-done", g1 - g0, 8);
    unmap(ro, 2);
    unmap(none, 2);
    unmap(wo, 2);
    unmap(h, 6);
    unmap(m, 4);
    unmap(g, 4);
}

fn process_madvise(t: &mut T) {
    let a = anon(0, 2);
    let iov = [a, 2 * P];
    let pm = |pidfd: usize, vec: usize, vlen: usize, advice: usize, flags: usize| {
        sys(Sysno::process_madvise, &[pidfd, vec, vlen, advice, flags])
    };
    t.eq(
        "flags-first",
        pm(usize::MAX, addr(&iov), 1, COLD, 1),
        E_INVAL,
    );
    t.eq(
        "flags-first-bad-vec",
        pm(usize::MAX, 0xdead_0000_0000, 5000, COLD, 0x8000_0000),
        E_INVAL,
    );
    t.eq(
        "vlen-too-big",
        pm(usize::MAX, addr(&iov), 1025, COLD, 0),
        E_INVAL,
    );
    t.eq(
        "bad-vec",
        pm(0, 0xdead_0000_0000, 1, COLD, 0),
        Err(Errno::EFAULT),
    );
    t.eq(
        "bad-iov-base",
        pm(0, addr(&[0xdead_0000_0000_0000usize, P]), 1, COLD, 0),
        Err(Errno::EFAULT),
    );
    // `copy_iovec_from_user` reads every segment (a negative length is EINVAL) before any base
    // is checked.
    t.eq(
        "negative-iov-len",
        pm(0, addr(&[a, usize::MAX]), 1, COLD, 0),
        E_INVAL,
    );
    t.eq(
        "iov-copy-before-access-check",
        pm(
            0,
            addr(&[0xdead_0000_0000_0000usize, 8, a, usize::MAX]),
            2,
            COLD,
            0,
        ),
        E_INVAL,
    );
    t.eq(
        "unreadable-second-iov",
        pm(0, TASK_SIZE - 16, 2, COLD, 0),
        Err(Errno::EFAULT),
    );
    // One segment is `import_ubuf`: its length is clamped before the range is checked.
    t.eq(
        "huge-single-iov-len-is-clamped",
        pm(0, addr(&[a, 1usize << 62]), 1, COLD, 0),
        Err(Errno::EBADF),
    );
    t.eq(
        "huge-iov-len-in-a-vector",
        pm(0, addr(&[a, 1usize << 62, a, 8]), 2, COLD, 0),
        Err(Errno::EFAULT),
    );
    // `unsigned nr_segs`: the upper half of `vlen` is dropped.
    t.eq(
        "vlen-is-an-unsigned",
        pm(0, addr(&iov), 0x1_0000_0001, COLD, 0),
        Err(Errno::EBADF),
    );
    t.eq(
        "vlen-is-an-unsigned-zero",
        pm(0, 0xdead_0000_0000, 0x1_0000_0000, COLD, 0),
        Err(Errno::EBADF),
    );
    t.eq(
        "bad-pidfd",
        pm(usize::MAX, addr(&iov), 1, COLD, 0),
        Err(Errno::EBADF),
    );
    t.eq(
        "closed-pidfd",
        pm(77, addr(&iov), 1, COLD, 0),
        Err(Errno::EBADF),
    );
    t.eq(
        "console-is-no-pidfd",
        pm(0, addr(&iov), 1, COLD, 0),
        Err(Errno::EBADF),
    );
    t.eq("empty-vector", pm(0, 0, 0, COLD, 0), Err(Errno::EBADF));
    t.eq(
        "advice-after-pidfd",
        pm(0, addr(&iov), 1, 12, 0),
        Err(Errno::EBADF),
    );
    unmap(a, 2);
}
