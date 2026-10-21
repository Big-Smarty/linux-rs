// SPDX-License-Identifier: GPL-2.0-only
//! Oracle syscall suite: black-box checks of Linux-visible behaviour, run unchanged on the pinned
//! Linux 6.18.57 (the oracle, `target/linux-reference`) and on this kernel. Each check prints one
//! line `init: test <group>.<name> ok` or `init: test <group>.<name> FAIL got=<v> want=<v>`;
//! a group ends with `init: tests <group> passed=<n> failed=<m>`. A failing check does not stop
//! the group, so one run shows every divergence. Expected lines: `xtask/oracle/expected.tsv`.
//!
//! Contract of this module (the one deliberate unsafe boundary): [`sys`] is a *safe* raw
//! `syscall` wrapper. The tests exist to pass hostile arguments (bad pointers, huge lengths,
//! unaligned addresses) to the kernel, which validates them with fault-aware usercopy and
//! answers an errno; they never hand the kernel an address they own as a Rust reference except
//! through [`addr`]/[`addr_mut`], and calls that can unmap memory (`munmap`, `mmap(MAP_FIXED)`,
//! `brk`) only name regions the same test created. A kernel bug can still corrupt the process,
//! which is the failure these tests report.
// The checks compare kernel words with fixed-width ABI fields; the casts are the ABI.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::items_after_statements,
    clippy::struct_field_names,
    clippy::needless_pass_by_value,
    clippy::unreadable_literal,
    clippy::many_single_char_names,
    clippy::doc_markdown,
    clippy::manual_is_multiple_of,
    clippy::cast_lossless
)]

use core::fmt::{self, Debug, Write as _};
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};
use syscalls::{Errno, Sysno};

use crate::exit;

pub mod busybox;
pub mod fork;
pub mod fs;
pub mod ids;
pub mod jobctl;
pub mod mm;
pub mod names;
pub mod pipe;
pub mod proc;
pub mod procfs;
pub mod signal;
pub mod smoke;
pub mod time;
pub mod tty;
pub mod ttyin;
pub mod xstate;

pub type R = Result<usize, Errno>;

/// Kernel uptime in whole seconds when the bare-metal suite started this group
/// (`argv[2]`, see `docs/bare-metal-suite.md`); `u64::MAX` outside the suite
/// (the oracle reference and the harness cells pass no such word).
static SUITE_START_S: AtomicU64 = AtomicU64::new(u64::MAX);
/// Bytes of RAM the suite's memory map declares (`argv[3]`); `u64::MAX` outside it.
static SUITE_RAM: AtomicU64 = AtomicU64::new(u64::MAX);

fn decimal(word: &[u8]) -> Option<u64> {
    core::str::from_utf8(word).ok()?.parse().ok()
}

/// Record the `argv[2]` and `argv[3]` words of a suite group: decimal numbers
/// (start uptime in seconds, RAM bytes), else ignored.
pub fn set_suite_args(uptime: &[u8], ram: Option<&[u8]>) {
    if let Some(seconds) = decimal(uptime) {
        SUITE_START_S.store(seconds, Ordering::Relaxed);
    }
    if let Some(bytes) = ram.and_then(decimal) {
        SUITE_RAM.store(bytes, Ordering::Relaxed);
    }
}

fn stored(cell: &AtomicU64) -> Option<u64> {
    match cell.load(Ordering::Relaxed) {
        u64::MAX => None,
        value => Some(value),
    }
}

/// The suite's group start uptime in seconds; `None` when not run by the suite.
pub fn suite_start() -> Option<u64> {
    stored(&SUITE_START_S)
}

/// The most RAM a machine can have: the 512 MiB of the reference VM outside the
/// suite, the memory map's declared RAM inside it.
pub fn ram_ceiling() -> u64 {
    stored(&SUITE_RAM).unwrap_or(512 << 20)
}

pub const PAGE: usize = 4096;
/// Highest user address + 1 on x86-64 with 4-level paging (`TASK_SIZE_MAX`).
pub const TASK_SIZE: usize = 0x7fff_ffff_f000;

/// Raw system call with up to six word arguments (missing ones are zero); see the module contract.
pub fn sys(nr: Sysno, args: &[usize]) -> R {
    let mut a = [0usize; 6];
    a[..args.len()].copy_from_slice(args);
    // SAFETY: per the module contract, the arguments are integers or addresses of live test
    // buffers, or deliberately invalid addresses the kernel rejects with EFAULT; no Rust
    // reference is handed over except via the exposed-provenance helpers below.
    unsafe { syscalls::syscall6(nr, a[0], a[1], a[2], a[3], a[4], a[5]) }
}

/// Address of a function (for handler / restorer fields of `rt_sigaction`).
pub fn fn_addr(f: *const ()) -> u64 {
    f.expose_provenance() as u64
}

/// Address of `r` for a syscall argument (exposes provenance: the kernel may read it).
pub fn addr<T: ?Sized>(r: &T) -> usize {
    ptr::from_ref(r).cast::<u8>().expose_provenance()
}

/// Address of `r` for a syscall argument the kernel may write through.
pub fn addr_mut<T: ?Sized>(r: &mut T) -> usize {
    ptr::from_mut(r).cast::<u8>().expose_provenance()
}

/// Read one byte at an arbitrary mapped address (callers know it is mapped and readable).
pub fn peek(a: usize) -> u8 {
    // SAFETY: callers pass an address inside a mapping the test created with read permission.
    unsafe { ptr::with_exposed_provenance::<u8>(a).read_volatile() }
}

/// Write one byte at an arbitrary mapped address (callers know it is mapped and writable).
pub fn poke(a: usize, v: u8) {
    // SAFETY: callers pass an address inside a mapping the test created with write permission.
    unsafe { ptr::with_exposed_provenance_mut::<u8>(a).write_volatile(v) }
}

/// Whether every byte of `[a, a + len)` equals `v`.
pub fn all_bytes(a: usize, len: usize, v: u8) -> bool {
    (0..len).all(|i| peek(a + i) == v)
}

pub fn getpid() -> usize {
    sys(Sysno::getpid, &[]).unwrap_or(usize::MAX)
}

pub fn gettid() -> usize {
    sys(Sysno::gettid, &[]).unwrap_or(usize::MAX)
}

/// `exit_group(code)`; used by forked children.
pub fn die(code: usize) -> ! {
    exit(code)
}

/// A line buffered in full and written with one `write(2)`, so a result line is never split by
/// concurrent kernel console output; overlong lines are truncated (checks stay far below this).
struct Line {
    buf: [u8; 384],
    len: usize,
}

impl fmt::Write for Line {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let n = s.len().min(self.buf.len() - 1 - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

/// Prints one line (a newline is appended).
pub fn emit(args: fmt::Arguments<'_>) {
    let mut line = Line {
        buf: [0; 384],
        len: 0,
    };
    let _ = line.write_fmt(args);
    line.buf[line.len] = b'\n';
    let _ = sys(Sysno::write, &[1, addr(&line.buf), line.len + 1]);
}

macro_rules! line {
    ($($arg:tt)*) => { $crate::tests::emit(format_args!($($arg)*)) };
}

/// One test group's counters and reporting.
pub struct T {
    group: &'static str,
    passed: u32,
    failed: u32,
}

impl T {
    pub fn new(group: &'static str) -> Self {
        Self {
            group,
            passed: 0,
            failed: 0,
        }
    }

    fn pass(&mut self, name: impl fmt::Display) {
        self.passed += 1;
        line!("init: test {}.{name} ok", self.group);
    }

    /// `got == want`.
    pub fn eq<V: PartialEq + Debug>(&mut self, name: impl fmt::Display, got: V, want: V) {
        if got == want {
            self.pass(name);
        } else {
            self.failed += 1;
            line!(
                "init: test {}.{name} FAIL got={got:?} want={want:?}",
                self.group
            );
        }
    }

    /// A predicate; `got` and `want` describe the observation and the requirement.
    pub fn holds(&mut self, name: impl fmt::Display, cond: bool, got: impl Debug, want: &str) {
        if cond {
            self.pass(name);
        } else {
            self.failed += 1;
            line!(
                "init: test {}.{name} FAIL got={got:?} want={want}",
                self.group
            );
        }
    }

    /// The checks passed and failed so far.
    pub fn counts(&self) -> (u32, u32) {
        (self.passed, self.failed)
    }

    /// Adds the counts of checks another process of the group printed (a child that ran part of
    /// the group and handed its totals back).
    pub fn add(&mut self, passed: u32, failed: u32) {
        self.passed += passed;
        self.failed += failed;
    }

    /// A recorded observation that is not a pass/fail check (for example the `/dev` listing).
    pub fn info(&self, name: impl fmt::Display, args: fmt::Arguments<'_>) {
        line!("init: info {}.{name} {args}", self.group);
    }

    /// Prints the group summary; true when nothing failed.
    pub fn finish(self) -> bool {
        line!(
            "init: tests {} passed={} failed={}",
            self.group,
            self.passed,
            self.failed
        );
        self.failed == 0
    }
}

/// A group's verdict ends the process with status 1 when any check failed; the caller prints
/// `init: ok` otherwise.
pub fn conclude(ok: bool) {
    if !ok {
        exit(1);
    }
}

/// A pipe pair used to probe whether an address range is readable or writable without faulting:
/// the kernel answers EFAULT instead of delivering SIGSEGV.
pub struct Probe {
    read_fd: usize,
    write_fd: usize,
}

impl Probe {
    pub fn new() -> Self {
        let mut fds = [0u32; 2];
        let _ = sys(Sysno::pipe2, &[addr_mut(&mut fds), 0o4000]);
        Self {
            read_fd: fds[0] as usize,
            write_fd: fds[1] as usize,
        }
    }

    fn drain(&self) {
        let mut scratch = [0u8; 64];
        while let Ok(n) = sys(Sysno::read, &[self.read_fd, addr_mut(&mut scratch), 64]) {
            if n == 0 {
                break;
            }
        }
    }

    /// `[a, a + len)` can be read by the kernel on the process's behalf (one byte per page).
    pub fn readable(&self, a: usize, len: usize) -> bool {
        let ok = (0..len.div_ceil(PAGE)).all(|page| {
            let at = if page == 0 {
                a
            } else {
                (a & !(PAGE - 1)) + page * PAGE
            };
            sys(Sysno::write, &[self.write_fd, at, 1]) == Ok(1)
        });
        self.drain();
        ok
    }

    /// `[a, a + len)` can be written by the kernel on the process's behalf (one byte per page).
    /// Non-destructive: a readable byte is written back unchanged.
    pub fn writable(&self, a: usize, len: usize) -> bool {
        let ok = (0..len.div_ceil(PAGE)).all(|page| {
            let at = if page == 0 {
                a
            } else {
                (a & !(PAGE - 1)) + page * PAGE
            };
            if sys(Sysno::write, &[self.write_fd, at, 1]) != Ok(1) {
                let _ = sys(Sysno::write, &[self.write_fd, addr(b"x"), 1]);
            }
            let ok = sys(Sysno::read, &[self.read_fd, at, 1]) == Ok(1);
            self.drain();
            ok
        });
        self.drain();
        ok
    }
}

/// `madvise(MADV_NORMAL)`: Ok when the whole range is mapped, ENOMEM when any part is not.
pub fn mapped(a: usize, len: usize) -> R {
    sys(Sysno::madvise, &[a, len, 0])
}

pub fn mmap(a: usize, len: usize, prot: usize, flags: usize, fd: usize, off: usize) -> R {
    sys(Sysno::mmap, &[a, len, prot, flags, fd, off])
}

/// Dispatch of the `argv[1]` test modes; false when `mode` names no group.
pub fn run_mode(mode: &[u8]) -> bool {
    let ok = match mode {
        b"mm" => mm::run(),
        b"ids" => ids::run(),
        b"time" => time::run(),
        b"signal" => signal::run(),
        // The kernel-test smoke case of the signal wiring (not an oracle group): see `smoke`.
        b"signals" => {
            smoke::run();
            return true;
        }
        b"fork" => fork::run(),
        // The leak check of the fork lane (not an oracle group): see `fork::forkleak`.
        b"forkleak" => {
            fork::forkleak();
            return true;
        }
        // Candidate-only exhaustion check of the fork lane: see `fork::forkbomb`.
        b"forkbomb" => {
            fork::forkbomb();
            return true;
        }
        b"fs" => fs::run(),
        b"names" => names::run(),
        // `AT_EMPTY_PATH` with a pipe: a record of the pinned Linux only (this kernel stops).
        b"pipeempty" => names::pipe_empty_path(),
        b"proc" => proc::run(),
        b"jobctl" => jobctl::run(),
        b"pipe" => pipe::run(),
        // The extended CPU state (needs AVX-512 and PKU: a KVM `-cpu host` group): see `xstate`.
        b"xstate" => xstate::run(),
        b"tty" => tty::run(),
        b"ttyin" => ttyin::run(),
        b"ttykbd" => ttyin::run_kbd(),
        // Real BusyBox commands (needs the second initramfs module and, on the host, AVX-512).
        // `busybox` is the group name the bare-metal suite passes (`-- <group> <uptime> <ram>`).
        b"bbrun" | b"busybox" => busybox::run(),
        b"procfs" => procfs::run(),
        // Reference-only (the pinned Linux; this kernel has no `setuid` family): the permission
        // matrix of /proc. Prints `info` rows, no checks: see `procfs::perm_probe`.
        b"procperm" => {
            procfs::perm_probe();
            return true;
        }
        _ => return false,
    };
    conclude(ok);
    true
}
