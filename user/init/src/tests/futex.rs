// SPDX-License-Identifier: GPL-2.0-only
//! `futex` group: `futex(2)` (`FUTEX_WAIT`, `WAKE`, `REQUEUE`, `CMP_REQUEUE`, `WAKE_OP`,
//! `WAIT_BITSET`, `WAKE_BITSET`, the private and clock flags, timeouts and their restart,
//! the argument checks of the priority-inheritance operations), `futex_waitv`/`futex_wake`/
//! `futex_wait`/`futex_requeue` argument checks, `set_robust_list`/`get_robust_list` and the
//! walk of the robust list at thread exit. Linux 6.18.57: `kernel/futex/{syscalls,core,
//! waitwake,requeue,pi}.c`, `include/uapi/linux/futex.h`.
//!
//! Waiters are threads ([`super::threads`]): a waiter makes one `futex` call and records its
//! result and the order in which waiters returned. The main thread starts waiters one at a
//! time with a short sleep after each so that they are queued in the order they were started
//! (the queue is FIFO within one priority), and it sleeps once more after waking so that the
//! woken ones have recorded their results. Everything else is a single call with its result.

use core::sync::atomic::{
    AtomicIsize, AtomicU32, AtomicUsize,
    Ordering::{Relaxed, SeqCst},
};

use syscalls::{Errno, Sysno};

use super::proc::{BAD, nap, reap_all, sigaction};
use super::threads::{
    FUTEX_WAIT, FUTEX_WAKE, H_COUNT, Thread, record, set_and_wake, spawn, tgkill, wait_for,
};
use super::{PAGE, R, T, addr, addr_mut, fn_addr, poke, sys};

const FUTEX_FD: usize = 2;
const FUTEX_REQUEUE: usize = 3;
const FUTEX_CMP_REQUEUE: usize = 4;
const FUTEX_WAKE_OP: usize = 5;
const FUTEX_LOCK_PI: usize = 6;
const FUTEX_UNLOCK_PI: usize = 7;
const FUTEX_TRYLOCK_PI: usize = 8;
const FUTEX_WAIT_BITSET: usize = 9;
const FUTEX_WAKE_BITSET: usize = 10;
const FUTEX_WAIT_REQUEUE_PI: usize = 11;
const FUTEX_CMP_REQUEUE_PI: usize = 12;
const FUTEX_LOCK_PI2: usize = 13;
const PRIVATE: usize = 128;
const REALTIME: usize = 256;
const ANY: usize = 0xffff_ffff;
const TASK_SIZE: usize = 0x7fff_ffff_f000;
/// A user address in range that nothing maps.
const FAR: usize = 0x1000_0000_0000;
const SA_RESTART: u64 = 0x1000_0000;
const SA_SIGINFO: u64 = 4;
const SIGUSR1: usize = 10;

const MONOTONIC: usize = 1;
const CLOCK_REALTIME: usize = 0;

fn fx(uaddr: usize, op: usize, val: usize, timeout: usize, uaddr2: usize, val3: usize) -> R {
    sys(Sysno::futex, &[uaddr, op, val, timeout, uaddr2, val3])
}

/// The 32-bit word `i` of the test page.
fn word(i: usize) -> &'static AtomicU32 {
    // SAFETY: `PAGE_BASE` is the address of a mapped, writable, never unmapped anonymous page
    // (`run`) and `i < 1024`; a `u32` at a 4-aligned offset is a valid `AtomicU32`.
    unsafe { &*((PAGE_BASE.load(Relaxed) + 4 * i) as *const AtomicU32) }
}

fn at(i: usize) -> usize {
    PAGE_BASE.load(Relaxed) + 4 * i
}

static PAGE_BASE: AtomicUsize = AtomicUsize::new(0);

fn clock(id: usize) -> i64 {
    let mut ts = [0i64; 2];
    let _ = sys(Sysno::clock_gettime, &[id, addr_mut(&mut ts)]);
    ts[0] * 1_000_000_000 + ts[1]
}

fn timespec(ns: i64) -> [i64; 2] {
    [ns.div_euclid(1_000_000_000), ns.rem_euclid(1_000_000_000)]
}

/// `FUTEX_OP(op, oparg, cmp, cmparg)`.
fn wake_op(op: u32, oparg: u32, cmp: u32, cmparg: u32) -> usize {
    ((op & 0xf) << 28 | (cmp & 0xf) << 24 | (oparg & 0xfff) << 12 | (cmparg & 0xfff)) as usize
}

const OP_SET: u32 = 0;
const OP_ADD: u32 = 1;
const OP_OR: u32 = 2;
const OP_ANDN: u32 = 3;
const OP_XOR: u32 = 4;
const OP_SHIFT: u32 = 8;
const CMP_EQ: u32 = 0;
const CMP_NE: u32 = 1;
const CMP_LT: u32 = 2;
const CMP_LE: u32 = 3;
const CMP_GT: u32 = 4;
const CMP_GE: u32 = 5;

// ---------------------------------------------------------------------------------------------
// Waiters.

struct Slot {
    uaddr: AtomicUsize,
    op: AtomicUsize,
    val: AtomicUsize,
    timeout: AtomicUsize,
    uaddr2: AtomicUsize,
    val3: AtomicUsize,
    /// The call's result: the value, or minus the errno.
    result: AtomicIsize,
    /// 1-based position among the waiters that returned.
    order: AtomicUsize,
    done: AtomicU32,
}

static SLOTS: [Slot; 8] = [const {
    Slot {
        uaddr: AtomicUsize::new(0),
        op: AtomicUsize::new(0),
        val: AtomicUsize::new(0),
        timeout: AtomicUsize::new(0),
        uaddr2: AtomicUsize::new(0),
        val3: AtomicUsize::new(0),
        result: AtomicIsize::new(0),
        order: AtomicUsize::new(0),
        done: AtomicU32::new(0),
    }
}; 8];
static ORDER: AtomicUsize = AtomicUsize::new(0);

fn encode(r: R) -> isize {
    r.map_or_else(|e| -(e.into_raw() as isize), |v| v as isize)
}

fn neg(e: Errno) -> isize {
    -(e.into_raw() as isize)
}

fn waiter(c: &'static super::threads::Control) -> usize {
    let s = &SLOTS[c.arg];
    let r = fx(
        s.uaddr.load(SeqCst),
        s.op.load(SeqCst),
        s.val.load(SeqCst),
        s.timeout.load(SeqCst),
        s.uaddr2.load(SeqCst),
        s.val3.load(SeqCst),
    );
    s.result.store(encode(r), SeqCst);
    s.order.store(ORDER.fetch_add(1, SeqCst) + 1, SeqCst);
    set_and_wake(&s.done, 1);
    0
}

/// Starts waiter `i` on `uaddr` and gives it time to reach its sleep.
fn begin(i: usize, uaddr: usize, op: usize, val: usize, val3: usize) -> Thread {
    let s = &SLOTS[i];
    s.uaddr.store(uaddr, SeqCst);
    s.op.store(op, SeqCst);
    s.val.store(val, SeqCst);
    s.val3.store(val3, SeqCst);
    s.timeout.store(0, SeqCst);
    s.uaddr2.store(0, SeqCst);
    s.result.store(0, SeqCst);
    s.order.store(0, SeqCst);
    s.done.store(0, SeqCst);
    let th = spawn(waiter, i);
    nap(10);
    th
}

/// A new scenario: no waiter has returned yet.
fn fresh() {
    ORDER.store(0, SeqCst);
    for s in &SLOTS {
        s.done.store(0, SeqCst);
        s.order.store(0, SeqCst);
        s.result.store(0, SeqCst);
        s.timeout.store(0, SeqCst);
    }
}

fn order(i: usize) -> usize {
    SLOTS[i].order.load(SeqCst)
}

fn result(i: usize) -> isize {
    SLOTS[i].result.load(SeqCst)
}

fn done(i: usize) -> bool {
    SLOTS[i].done.load(SeqCst) == 1
}

/// Lets woken waiters run and record.
fn settle() {
    nap(10);
}

fn finish(threads: &[Thread]) {
    for th in threads {
        th.join();
    }
}

// ---------------------------------------------------------------------------------------------

pub fn run() -> bool {
    let mut t = T::new("futex");
    reap_all();
    let page = super::mmap(0, PAGE, 3, 0x22, usize::MAX, 0).unwrap_or(0);
    poke(page, 0);
    PAGE_BASE.store(page, SeqCst);
    arguments(&mut t);
    timeouts(&mut t);
    wakeups(&mut t);
    bitsets(&mut t);
    requeue(&mut t);
    wake_op_checks(&mut t);
    keys(&mut t);
    signals(&mut t);
    robust(&mut t);
    pi_arguments(&mut t);
    futex2(&mut t);
    reap_all();
    t.finish()
}

fn arguments(t: &mut T) {
    let w = at(0);
    word(0).store(1, SeqCst);
    t.eq("wait-value-mismatch", fx(w, FUTEX_WAIT, 0, 0, 0, 0), Err(Errno::EAGAIN));
    t.eq(
        "wait-value-mismatch-private",
        fx(w, FUTEX_WAIT | PRIVATE, 0, 0, 0, 0),
        Err(Errno::EAGAIN),
    );
    t.eq("wait-null", fx(0, FUTEX_WAIT, 1, 0, 0, 0), Err(Errno::EFAULT));
    t.eq(
        "wait-null-private",
        fx(0, FUTEX_WAIT | PRIVATE, 1, 0, 0, 0),
        Err(Errno::EFAULT),
    );
    t.eq("wait-unaligned", fx(w + 1, FUTEX_WAIT, 1, 0, 0, 0), Err(Errno::EINVAL));
    t.eq(
        "wait-unaligned-private",
        fx(w + 2, FUTEX_WAIT | PRIVATE, 1, 0, 0, 0),
        Err(Errno::EINVAL),
    );
    t.eq(
        "wait-kernel-address",
        fx(BAD, FUTEX_WAIT, 1, 0, 0, 0),
        Err(Errno::EFAULT),
    );
    t.eq(
        "wait-kernel-address-private",
        fx(BAD, FUTEX_WAIT | PRIVATE, 1, 0, 0, 0),
        Err(Errno::EFAULT),
    );
    t.eq(
        "wait-last-address",
        fx(TASK_SIZE, FUTEX_WAIT, 1, 0, 0, 0),
        Err(Errno::EFAULT),
    );
    t.eq("wait-unmapped", fx(FAR, FUTEX_WAIT, 1, 0, 0, 0), Err(Errno::EFAULT));
    t.eq(
        "wait-unmapped-private",
        fx(FAR, FUTEX_WAIT | PRIVATE, 1, 0, 0, 0),
        Err(Errno::EFAULT),
    );
    // The timeout is read and checked before anything else.
    t.eq(
        "wait-timeout-pointer-first",
        fx(BAD, FUTEX_WAIT, 1, BAD, 0, 0),
        Err(Errno::EFAULT),
    );
    let big = [0i64, 1_000_000_000];
    t.eq(
        "wait-timeout-nsec-too-big",
        fx(w, FUTEX_WAIT, 1, addr(&big), 0, 0),
        Err(Errno::EINVAL),
    );
    t.eq(
        "wait-timeout-checked-before-alignment",
        fx(w + 1, FUTEX_WAIT, 1, addr(&big), 0, 0),
        Err(Errno::EINVAL),
    );
    let negative = [-1i64, 0];
    t.eq(
        "wait-timeout-negative",
        fx(w, FUTEX_WAIT, 1, addr(&negative), 0, 0),
        Err(Errno::EINVAL),
    );
    let minus_nsec = [0i64, -1];
    t.eq(
        "wait-timeout-negative-nsec",
        fx(w, FUTEX_WAIT, 1, addr(&minus_nsec), 0, 0),
        Err(Errno::EINVAL),
    );
    // Commands that do not exist, the removed FUTEX_FD, and the clock flag on commands without it.
    t.eq("unknown-command", fx(w, 14, 1, 0, 0, 0), Err(Errno::ENOSYS));
    t.eq(
        "unknown-command-private",
        fx(w, 99 | PRIVATE, 1, 0, 0, 0),
        Err(Errno::ENOSYS),
    );
    t.eq("huge-command", fx(w, 0x10000, 1, 0, 0, 0), Err(Errno::ENOSYS));
    t.eq("futex-fd-is-gone", fx(w, FUTEX_FD, 1, 0, 0, 0), Err(Errno::ENOSYS));
    for (name, op) in [
        ("wait", FUTEX_WAIT),
        ("wake", FUTEX_WAKE),
        ("requeue", FUTEX_REQUEUE),
        ("cmp-requeue", FUTEX_CMP_REQUEUE),
        ("wake-op", FUTEX_WAKE_OP),
        ("lock-pi", FUTEX_LOCK_PI),
        ("unlock-pi", FUTEX_UNLOCK_PI),
        ("trylock-pi", FUTEX_TRYLOCK_PI),
        ("wake-bitset", FUTEX_WAKE_BITSET),
        ("cmp-requeue-pi", FUTEX_CMP_REQUEUE_PI),
    ] {
        t.eq(
            format_args!("clock-realtime-on-{name}"),
            fx(w, op | REALTIME, 1, 0, 0, 0),
            Err(Errno::ENOSYS),
        );
    }
    // The wake side.
    t.eq("wake-nobody", fx(w, FUTEX_WAKE, 5, 0, 0, 0), Ok(0));
    t.eq("wake-zero", fx(w, FUTEX_WAKE, 0, 0, 0, 0), Ok(0));
    t.eq("wake-bitset-zero", fx(w, FUTEX_WAKE_BITSET, 1, 0, 0, 0), Err(Errno::EINVAL));
    t.eq("wait-bitset-zero", fx(w, FUTEX_WAIT_BITSET, 1, 0, 0, 0), Err(Errno::EINVAL));
    t.eq(
        "wait-bitset-zero-beats-mismatch",
        fx(w, FUTEX_WAIT_BITSET, 0, 0, 0, 0),
        Err(Errno::EINVAL),
    );
    t.eq("wake-unaligned", fx(w + 1, FUTEX_WAKE, 1, 0, 0, 0), Err(Errno::EINVAL));
    t.eq(
        "wake-unaligned-private",
        fx(w + 3, FUTEX_WAKE | PRIVATE, 1, 0, 0, 0),
        Err(Errno::EINVAL),
    );
    t.eq(
        "wake-kernel-address",
        fx(BAD, FUTEX_WAKE | PRIVATE, 1, 0, 0, 0),
        Err(Errno::EFAULT),
    );
    t.eq(
        "wake-kernel-address-shared",
        fx(BAD, FUTEX_WAKE, 1, 0, 0, 0),
        Err(Errno::EFAULT),
    );
    // A private key needs no page, a shared one pins the page.
    t.eq(
        "wake-unmapped-private",
        fx(FAR, FUTEX_WAKE | PRIVATE, 1, 0, 0, 0),
        Ok(0),
    );
    t.eq("wake-unmapped-shared", fx(FAR, FUTEX_WAKE, 1, 0, 0, 0), Err(Errno::EFAULT));
    // `access_ok` accepts the first address past the user range for a word-sized access (the
    // x86-64 `valid_user_address` is `<=`), and the private key needs nothing more.
    t.eq(
        "wake-last-address-private",
        fx(TASK_SIZE, FUTEX_WAKE | PRIVATE, 1, 0, 0, 0),
        Ok(0),
    );
    // Requeue and wake-op validate their arguments before they look at the words.
    t.eq(
        "requeue-negative-wake",
        fx(w, FUTEX_REQUEUE, usize::MAX >> 32, 1, at(1), 0),
        Err(Errno::EINVAL),
    );
    t.eq(
        "requeue-negative-requeue",
        fx(w, FUTEX_REQUEUE, 1, usize::MAX >> 32, at(1), 0),
        Err(Errno::EINVAL),
    );
    t.eq(
        "cmp-requeue-negative",
        fx(w, FUTEX_CMP_REQUEUE, usize::MAX >> 32, 1, at(1), 1),
        Err(Errno::EINVAL),
    );
    t.eq(
        "cmp-requeue-mismatch",
        fx(w, FUTEX_CMP_REQUEUE, 1, 1, at(1), 0),
        Err(Errno::EAGAIN),
    );
    t.eq(
        "requeue-unaligned-target",
        fx(w, FUTEX_REQUEUE, 1, 1, at(1) + 1, 0),
        Err(Errno::EINVAL),
    );
    t.eq(
        "requeue-unaligned-source",
        fx(w + 1, FUTEX_REQUEUE, 1, 1, at(1), 0),
        Err(Errno::EINVAL),
    );
    t.eq(
        "requeue-unmapped-target",
        fx(w, FUTEX_REQUEUE, 1, 1, FAR, 0),
        Err(Errno::EFAULT),
    );
    t.eq(
        "requeue-kernel-target",
        fx(w, FUTEX_REQUEUE, 1, 1, BAD, 0),
        Err(Errno::EFAULT),
    );
    t.eq(
        "requeue-unmapped-target-private",
        fx(w, FUTEX_REQUEUE | PRIVATE, 1, 1, FAR, 0),
        Ok(0),
    );
    t.eq(
        "requeue-to-itself",
        fx(w, FUTEX_REQUEUE, 1, 1, w, 0),
        Ok(0),
    );
    t.eq(
        "cmp-requeue-to-itself",
        fx(w, FUTEX_CMP_REQUEUE, 1, 1, w, 1),
        Ok(0),
    );
    word(0).store(0, SeqCst);
}

fn timeouts(t: &mut T) {
    let w = at(2);
    word(2).store(0, SeqCst);
    let started = clock(MONOTONIC);
    let twenty_ms = timespec(20_000_000);
    let r = fx(w, FUTEX_WAIT, 0, addr(&twenty_ms), 0, 0);
    let waited = clock(MONOTONIC) - started;
    t.eq("wait-times-out", r, Err(Errno::ETIMEDOUT));
    t.holds(
        "wait-timeout-is-relative-and-long-enough",
        (20_000_000..2_000_000_000).contains(&waited),
        waited,
        "between 20 ms and 2 s",
    );
    let zero = [0i64, 0];
    t.eq(
        "wait-zero-timeout",
        fx(w, FUTEX_WAIT, 0, addr(&zero), 0, 0),
        Err(Errno::ETIMEDOUT),
    );
    // Absolute deadlines (monotonic by default, realtime with the flag).
    let started = clock(MONOTONIC);
    let deadline = timespec(started + 20_000_000);
    let r = fx(w, FUTEX_WAIT_BITSET, 0, addr(&deadline), 0, ANY);
    let waited = clock(MONOTONIC) - started;
    t.eq("wait-bitset-monotonic-deadline", r, Err(Errno::ETIMEDOUT));
    t.holds(
        "wait-bitset-monotonic-waits-until-the-deadline",
        (19_000_000..2_000_000_000).contains(&waited),
        waited,
        "about 20 ms",
    );
    let started = clock(CLOCK_REALTIME);
    let deadline = timespec(started + 20_000_000);
    let begin = clock(MONOTONIC);
    let r = fx(w, FUTEX_WAIT_BITSET | REALTIME, 0, addr(&deadline), 0, ANY);
    let waited = clock(MONOTONIC) - begin;
    t.eq("wait-bitset-realtime-deadline", r, Err(Errno::ETIMEDOUT));
    t.holds(
        "wait-bitset-realtime-waits-until-the-deadline",
        (19_000_000..2_000_000_000).contains(&waited),
        waited,
        "about 20 ms",
    );
    let past = timespec(1);
    t.eq(
        "wait-bitset-deadline-in-the-past",
        fx(w, FUTEX_WAIT_BITSET, 0, addr(&past), 0, ANY),
        Err(Errno::ETIMEDOUT),
    );
    t.eq(
        "wait-bitset-realtime-deadline-in-the-past",
        fx(w, FUTEX_WAIT_BITSET | REALTIME, 0, addr(&past), 0, ANY),
        Err(Errno::ETIMEDOUT),
    );
    t.eq(
        "wait-mismatch-beats-an-expired-deadline",
        fx(w, FUTEX_WAIT_BITSET, 1, addr(&past), 0, ANY),
        Err(Errno::EAGAIN),
    );
    t.eq(
        "wait-bitset-unmapped-with-deadline",
        fx(BAD, FUTEX_WAIT_BITSET | PRIVATE, 0, addr(&past), 0, ANY),
        Err(Errno::EFAULT),
    );
    // A timeout that is not reached because of a wake-up.
    let w = at(3);
    word(3).store(0, SeqCst);
    fresh();
    static TEN_S: [i64; 2] = [10, 0];
    let th = {
        let s = &SLOTS[1];
        s.uaddr.store(w, SeqCst);
        s.op.store(FUTEX_WAIT, SeqCst);
        s.val.store(0, SeqCst);
        s.val3.store(0, SeqCst);
        s.timeout.store(addr(&TEN_S), SeqCst);
        s.uaddr2.store(0, SeqCst);
        s.done.store(0, SeqCst);
        s.order.store(0, SeqCst);
        let th = spawn(waiter, 1);
        nap(10);
        th
    };
    t.eq("wake-before-the-timeout", fx(w, FUTEX_WAKE, 1, 0, 0, 0), Ok(1));
    settle();
    t.eq("woken-waiter-with-timeout-returns-0", result(1), 0);
    finish(&[th]);
}

fn wakeups(t: &mut T) {
    let w = at(4);
    word(4).store(0, SeqCst);
    fresh();
    let ths: [Thread; 4] = core::array::from_fn(|i| begin(i, w, FUTEX_WAIT, 0, 0));
    t.eq("nobody-woke-by-itself", (0..4).filter(|&i| done(i)).count(), 0);
    // A different word of the same page wakes nobody.
    t.eq("wake-another-word", fx(at(5), FUTEX_WAKE, 10, 0, 0, 0), Ok(0));
    t.eq("wake-one", fx(w, FUTEX_WAKE, 1, 0, 0, 0), Ok(1));
    settle();
    t.eq("first-in-first-woken", (order(0), done(1)), (1, false));
    t.eq("wake-two", fx(w, FUTEX_WAKE, 2, 0, 0, 0), Ok(2));
    settle();
    // Which ones a call wakes is queue order; the order in which they then run is the
    // scheduler's (EEVDF there), so only the set is compared.
    t.eq("wake-in-queue-order", [done(0), done(1), done(2), done(3)], [true, true, true, false]);
    t.eq("wake-more-than-waiting", fx(w, FUTEX_WAKE, 100, 0, 0, 0), Ok(1));
    settle();
    t.eq("queue-order-complete", [done(0), done(1), done(2), done(3)], [true; 4]);
    t.eq("each-waiter-recorded-once", (0..4).map(order).sum::<usize>(), 10);
    t.eq("nobody-left", fx(w, FUTEX_WAKE, 1, 0, 0, 0), Ok(0));
    t.eq("woken-waiters-return-zero", [result(0), result(1), result(2), result(3)], [0; 4]);
    finish(&ths);
    // A negative count wakes one (`int nr_wake`, `++ret >= nr_wake`).
    fresh();
    let ths = [begin(0, w, FUTEX_WAIT, 0, 0), begin(1, w, FUTEX_WAIT, 0, 0)];
    t.eq(
        "wake-negative-count",
        fx(w, FUTEX_WAKE, usize::MAX >> 32, 0, 0, 0),
        Ok(1),
    );
    settle();
    t.eq("negative-count-woke-the-first", (done(0), done(1)), (true, false));
    t.eq("wake-the-rest", fx(w, FUTEX_WAKE, i32::MAX as usize, 0, 0, 0), Ok(1));
    finish(&ths);
    // A wake before the wait is lost: the value check is the protocol.
    t.eq("wake-then-wait-sleeps-not", fx(w, FUTEX_WAKE, 1, 0, 0, 0), Ok(0));
}

fn bitsets(t: &mut T) {
    let w = at(6);
    word(6).store(0, SeqCst);
    fresh();
    let ths = [
        begin(0, w, FUTEX_WAIT_BITSET, 0, 1),
        begin(1, w, FUTEX_WAIT_BITSET, 0, 2),
        begin(2, w, FUTEX_WAIT_BITSET, 0, 6),
    ];
    t.eq(
        "wake-bitset-without-common-bits",
        fx(w, FUTEX_WAKE_BITSET, 10, 0, 0, 8),
        Ok(0),
    );
    t.eq(
        "wake-bitset-one-bit",
        fx(w, FUTEX_WAKE_BITSET, 10, 0, 0, 2),
        Ok(2),
    );
    settle();
    t.eq(
        "wake-bitset-woke-the-matching",
        (done(0), done(1), done(2)),
        (false, true, true),
    );
    t.eq("wake-matches-any-bit", fx(w, FUTEX_WAKE, 10, 0, 0, 0), Ok(1));
    settle();
    t.eq("all-bitset-waiters-returned", (done(0), result(0)), (true, 0));
    finish(&ths);
}

fn requeue(t: &mut T) {
    let (a, b) = (at(7), at(8));
    word(7).store(0, SeqCst);
    word(8).store(0, SeqCst);
    fresh();
    let ths: [Thread; 4] = core::array::from_fn(|i| begin(i, a, FUTEX_WAIT, 0, 0));
    t.eq(
        "cmp-requeue-wakes-one-moves-two",
        fx(a, FUTEX_CMP_REQUEUE, 1, 2, b, 0),
        Ok(3),
    );
    settle();
    t.eq("cmp-requeue-woke-the-first", (done(0), done(1), done(2), done(3)), (true, false, false, false));
    t.eq("requeued-sleep-on-the-target", fx(b, FUTEX_WAKE, 10, 0, 0, 0), Ok(2));
    settle();
    t.eq("source-keeps-the-rest", fx(a, FUTEX_WAKE, 10, 0, 0, 0), Ok(1));
    settle();
    t.eq("every-requeued-waiter-returned", [done(0), done(1), done(2), done(3)], [true; 4]);
    t.eq("requeued-waiters-return-zero", [result(0), result(1), result(2), result(3)], [0; 4]);
    finish(&ths);
    // FUTEX_REQUEUE does not compare; it returns woken plus requeued as well.
    fresh();
    let ths: [Thread; 3] = core::array::from_fn(|i| begin(i, a, FUTEX_WAIT, 0, 0));
    t.eq("requeue-all", fx(a, FUTEX_REQUEUE, 0, 10, b, 0), Ok(3));
    t.eq("source-is-empty", fx(a, FUTEX_WAKE, 10, 0, 0, 0), Ok(0));
    t.eq("target-has-them-all", fx(b, FUTEX_WAKE, 10, 0, 0, 0), Ok(3));
    settle();
    finish(&ths);
    // A mismatch moves nobody.
    fresh();
    let th = begin(0, a, FUTEX_WAIT, 0, 0);
    t.eq(
        "cmp-requeue-mismatch-moves-nobody",
        fx(a, FUTEX_CMP_REQUEUE, 1, 1, b, 7),
        Err(Errno::EAGAIN),
    );
    t.eq("the-waiter-is-still-there", fx(a, FUTEX_WAKE, 1, 0, 0, 0), Ok(1));
    finish(&[th]);
    // A private waiter is requeued with the private flag only.
    fresh();
    let th = begin(0, a, FUTEX_WAIT | PRIVATE, 0, 0);
    t.eq(
        "requeue-private",
        fx(a, FUTEX_CMP_REQUEUE | PRIVATE, 0, 1, b, 0),
        Ok(1),
    );
    t.eq(
        "requeued-private-is-not-shared",
        fx(b, FUTEX_WAKE, 1, 0, 0, 0),
        Ok(0),
    );
    t.eq(
        "requeued-private-wakes-private",
        fx(b, FUTEX_WAKE | PRIVATE, 1, 0, 0, 0),
        Ok(1),
    );
    finish(&[th]);
}

fn wake_op_checks(t: &mut T) {
    let (a, b) = (at(9), at(10));
    word(9).store(0, SeqCst);
    word(10).store(5, SeqCst);
    fresh();
    let ths = [
        begin(0, a, FUTEX_WAIT, 0, 0),
        begin(1, a, FUTEX_WAIT, 0, 0),
        begin(2, b, FUTEX_WAIT, 5, 0),
        begin(3, b, FUTEX_WAIT, 5, 0),
    ];
    // *b += 1; wake one on a; if the old *b was 5, wake one on b as well.
    t.eq(
        "wake-op-add-eq-true",
        fx(a, FUTEX_WAKE_OP, 1, 1, b, wake_op(OP_ADD, 1, CMP_EQ, 5)),
        Ok(2),
    );
    t.eq("wake-op-add-stored", word(10).load(SeqCst), 6);
    settle();
    t.eq("wake-op-woke-one-of-each", (done(0), done(1), done(2), done(3)), (true, false, true, false));
    // *b = 9; the old value 6 is not != 6: only the first futex is woken.
    t.eq(
        "wake-op-set-ne-false",
        fx(a, FUTEX_WAKE_OP, 1, 1, b, wake_op(OP_SET, 9, CMP_NE, 6)),
        Ok(1),
    );
    t.eq("wake-op-set-stored", word(10).load(SeqCst), 9);
    // *b |= 2 (old 9 > 3): none left on a, the last waiter of b is woken.
    t.eq(
        "wake-op-or-gt-true",
        fx(a, FUTEX_WAKE_OP, 1, 5, b, wake_op(OP_OR, 2, CMP_GT, 3)),
        Ok(1),
    );
    settle();
    finish(&ths);
    // Side effects and comparisons without waiters.
    word(10).store(11, SeqCst);
    let side = |op: u32, oparg: u32, cmp: u32, cmparg: u32| {
        fx(a, FUTEX_WAKE_OP, 0, 0, b, wake_op(op, oparg, cmp, cmparg))
    };
    t.eq("wake-op-andn", (side(OP_ANDN, 1, CMP_EQ, 0), word(10).load(SeqCst)), (Ok(0), 10));
    t.eq("wake-op-xor", (side(OP_XOR, 3, CMP_LT, 0), word(10).load(SeqCst)), (Ok(0), 9));
    t.eq(
        "wake-op-oparg-shift",
        (side(OP_SET | OP_SHIFT, 4, CMP_LE, 0), word(10).load(SeqCst)),
        (Ok(0), 16),
    );
    t.eq(
        "wake-op-add-negative",
        (side(OP_ADD, 0xfff, CMP_GE, 0), word(10).load(SeqCst)),
        (Ok(0), 15),
    );
    // Operations and comparisons that do not exist: the operation of the first has been done.
    t.eq(
        "wake-op-bad-operation",
        (side(5, 1, CMP_EQ, 0), word(10).load(SeqCst)),
        (Err(Errno::ENOSYS), 15),
    );
    t.eq(
        "wake-op-bad-comparison-after-the-operation",
        (side(OP_SET, 3, 6, 0), word(10).load(SeqCst)),
        (Err(Errno::ENOSYS), 3),
    );
    t.eq(
        "wake-op-unaligned-target",
        fx(a, FUTEX_WAKE_OP, 0, 0, b + 1, wake_op(OP_SET, 1, CMP_EQ, 0)),
        Err(Errno::EINVAL),
    );
    t.eq(
        "wake-op-unmapped-target",
        fx(a, FUTEX_WAKE_OP, 0, 0, FAR, wake_op(OP_SET, 1, CMP_EQ, 0)),
        Err(Errno::EFAULT),
    );
    t.eq(
        "wake-op-unaligned-source",
        fx(a + 2, FUTEX_WAKE_OP, 0, 0, b, wake_op(OP_SET, 1, CMP_EQ, 0)),
        Err(Errno::EINVAL),
    );
}

fn keys(t: &mut T) {
    let w = at(11);
    word(11).store(0, SeqCst);
    fresh();
    // The private flag is part of the key: a private wake does not reach a shared waiter on
    // the same address and the reverse (`FUT_OFF_MMSHARED`), though both are this process.
    let th = begin(0, w, FUTEX_WAIT, 0, 0);
    t.eq("private-wake-misses-shared-waiter", fx(w, FUTEX_WAKE | PRIVATE, 1, 0, 0, 0), Ok(0));
    t.eq("shared-wake-finds-shared-waiter", fx(w, FUTEX_WAKE, 1, 0, 0, 0), Ok(1));
    finish(&[th]);
    let th = begin(0, w, FUTEX_WAIT | PRIVATE, 0, 0);
    t.eq("shared-wake-misses-private-waiter", fx(w, FUTEX_WAKE, 1, 0, 0, 0), Ok(0));
    t.eq("private-wake-finds-private-waiter", fx(w, FUTEX_WAKE | PRIVATE, 1, 0, 0, 0), Ok(1));
    finish(&[th]);
}

fn handler_flags(flags: u64) {
    let _ = sigaction(SIGUSR1, fn_addr(record as *const ()), SA_SIGINFO | flags);
}

fn signals(t: &mut T) {
    let w = at(12);
    word(12).store(0, SeqCst);
    // Without a timeout and with SA_RESTART the wait restarts after the handler.
    handler_flags(SA_RESTART);
    super::threads::forget();
    fresh();
    let th = begin(0, w, FUTEX_WAIT, 0, 0);
    t.eq("tgkill-a-waiter", tgkill(th.tid, SIGUSR1), Ok(0));
    settle();
    t.eq(
        "restarted-wait-still-sleeps",
        (H_COUNT.load(SeqCst), done(0)),
        (1, false),
    );
    t.eq("restarted-wait-is-woken", fx(w, FUTEX_WAKE, 1, 0, 0, 0), Ok(1));
    settle();
    t.eq("restarted-wait-returns-zero", (done(0), result(0)), (true, 0));
    finish(&[th]);
    // Without SA_RESTART it fails with EINTR.
    handler_flags(0);
    super::threads::forget();
    fresh();
    let th = begin(0, w, FUTEX_WAIT, 0, 0);
    let _ = tgkill(th.tid, SIGUSR1);
    settle();
    t.eq(
        "interrupted-wait",
        (H_COUNT.load(SeqCst), done(0), result(0)),
        (1, true, neg(Errno::EINTR)),
    );
    finish(&[th]);
    // With a timeout it is a restart block: a handler ends it with EINTR even with SA_RESTART.
    handler_flags(SA_RESTART);
    super::threads::forget();
    static TEN_S: [i64; 2] = [10, 0];
    fresh();
    let s = &SLOTS[1];
    s.uaddr.store(w, SeqCst);
    s.op.store(FUTEX_WAIT, SeqCst);
    s.val.store(0, SeqCst);
    s.val3.store(0, SeqCst);
    s.timeout.store(addr(&TEN_S), SeqCst);
    s.uaddr2.store(0, SeqCst);
    s.done.store(0, SeqCst);
    s.order.store(0, SeqCst);
    let begin_ns = clock(MONOTONIC);
    let th = spawn(waiter, 1);
    nap(10);
    let _ = tgkill(th.tid, SIGUSR1);
    settle();
    t.eq(
        "timed-wait-interrupted",
        (H_COUNT.load(SeqCst), done(1), result(1)),
        (1, true, neg(Errno::EINTR)),
    );
    t.holds(
        "timed-wait-ended-early",
        clock(MONOTONIC) - begin_ns < 5_000_000_000,
        clock(MONOTONIC) - begin_ns,
        "well under the 10 s timeout",
    );
    finish(&[th]);
    let _ = sigaction(SIGUSR1, 0, 0);
}

// ---- robust lists --------------------------------------------------------------------------

/// `struct robust_list_head`: the list's first pointer, the offset from an entry to its futex
/// word, the pending entry.
#[repr(C)]
struct RobustHead {
    next: AtomicUsize,
    offset: AtomicIsize,
    pending: AtomicUsize,
}

/// A user lock: the list link then the futex word (offset 8).
#[repr(C)]
struct Lock {
    next: AtomicUsize,
    futex: AtomicU32,
    pad: u32,
}

static HEAD: RobustHead = RobustHead {
    next: AtomicUsize::new(0),
    offset: AtomicIsize::new(8),
    pending: AtomicUsize::new(0),
};
static LOCKS: [Lock; 4] = [const {
    Lock {
        next: AtomicUsize::new(0),
        futex: AtomicU32::new(0),
        pad: 0,
    }
}; 4];
static ROBUST_GOT: [AtomicUsize; 6] = [const { AtomicUsize::new(0) }; 6];

const FUTEX_WAITERS: u32 = 0x8000_0000;
const FUTEX_OWNER_DIED: u32 = 0x4000_0000;

fn robust(t: &mut T) {
    // The registered head and its length are per thread; a new thread has none.
    let mut head = 1usize;
    let mut len = 1usize;
    t.eq(
        "get-robust-list-initial",
        (sys(Sysno::get_robust_list, &[0, addr_mut(&mut head), addr_mut(&mut len)]), head, len),
        (Ok(0), 0, 24),
    );
    t.eq("set-robust-list-bad-length", sys(Sysno::set_robust_list, &[addr(&HEAD), 16]), Err(Errno::EINVAL));
    t.eq("set-robust-list", sys(Sysno::set_robust_list, &[addr(&HEAD), 24]), Ok(0));
    t.eq(
        "get-robust-list",
        (sys(Sysno::get_robust_list, &[0, addr_mut(&mut head), addr_mut(&mut len)]), head, len),
        (Ok(0), addr(&HEAD), 24),
    );
    let me = super::getpid();
    t.eq(
        "get-robust-list-by-pid",
        (sys(Sysno::get_robust_list, &[me, addr_mut(&mut head), addr_mut(&mut len)]), head),
        (Ok(0), addr(&HEAD)),
    );
    t.eq(
        "get-robust-list-no-such-task",
        sys(Sysno::get_robust_list, &[0x3fff_fff0, addr_mut(&mut head), addr_mut(&mut len)]),
        Err(Errno::ESRCH),
    );
    t.eq(
        "get-robust-list-bad-length-pointer",
        sys(Sysno::get_robust_list, &[0, addr_mut(&mut head), BAD]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "get-robust-list-bad-head-pointer",
        sys(Sysno::get_robust_list, &[0, BAD, addr_mut(&mut len)]),
        Err(Errno::EFAULT),
    );
    let _ = sys(Sysno::set_robust_list, &[0, 24]);
    // A thread starts without a list and reads another's.
    let th = spawn(
        |_| {
            let (mut head, mut len) = (1usize, 1usize);
            let r = sys(Sysno::get_robust_list, &[0, addr_mut(&mut head), addr_mut(&mut len)]);
            ROBUST_GOT[0].store(head, SeqCst);
            ROBUST_GOT[1].store(len, SeqCst);
            ROBUST_GOT[2].store(r.unwrap_or(usize::MAX), SeqCst);
            let _ = sys(Sysno::set_robust_list, &[addr(&HEAD), 24]);
            wait_for(&THREAD_GO, 1);
            0
        },
        0,
    );
    nap(10);
    t.eq(
        "new-thread-has-no-robust-list",
        (ROBUST_GOT[0].load(SeqCst), ROBUST_GOT[1].load(SeqCst), ROBUST_GOT[2].load(SeqCst)),
        (0, 24, 0),
    );
    t.eq(
        "get-robust-list-of-another-thread",
        (sys(Sysno::get_robust_list, &[th.tid, addr_mut(&mut head), addr_mut(&mut len)]), head),
        (Ok(0), addr(&HEAD)),
    );
    set_and_wake(&THREAD_GO, 1);
    th.join();
    THREAD_GO.store(0, SeqCst);

    fresh();
    // Exit of a thread holding locks: owner-died is set, the waiters bit stays, one waiter
    // is woken (always a shared-key wake), locks of other owners are untouched.
    for lock in &LOCKS {
        lock.futex.store(0, SeqCst);
    }
    HEAD.pending.store(0, SeqCst);
    let th = spawn(
        |c| {
            let tid = super::gettid() as u32;
            // List: HEAD -> L0 -> L1 -> L2 -> HEAD; L3 is the pending entry.
            let chain = [&LOCKS[0], &LOCKS[1], &LOCKS[2]];
            HEAD.next.store(addr(chain[0]), SeqCst);
            for (i, lock) in chain.iter().enumerate() {
                let next = chain.get(i + 1).map_or(addr(&HEAD), |l| addr(*l));
                lock.next.store(next, SeqCst);
            }
            LOCKS[0].futex.store(tid, SeqCst);
            LOCKS[1].futex.store(tid | FUTEX_WAITERS, SeqCst);
            LOCKS[2].futex.store(tid + 100, SeqCst);
            LOCKS[3].futex.store(tid, SeqCst);
            HEAD.pending.store(addr(&LOCKS[3]), SeqCst);
            let _ = sys(Sysno::set_robust_list, &[addr(&HEAD), 24]);
            set_and_wake(&THREAD_GO, 1);
            wait_for(&THREAD_GO, 2);
            c.arg
        },
        0,
    );
    wait_for(&THREAD_GO, 1);
    let tid = th.tid as u32;
    // A waiter on the lock with the waiters bit (shared futex, as pthread_mutex robust locks).
    let waiting = begin(0, addr(&LOCKS[1].futex), FUTEX_WAIT, (tid | FUTEX_WAITERS) as usize, 0);
    set_and_wake(&THREAD_GO, 2);
    th.join();
    settle();
    t.eq(
        "robust-owned-lock-is-marked",
        LOCKS[0].futex.load(SeqCst),
        FUTEX_OWNER_DIED,
    );
    t.eq(
        "robust-lock-with-waiters-keeps-the-bit",
        LOCKS[1].futex.load(SeqCst),
        FUTEX_OWNER_DIED | FUTEX_WAITERS,
    );
    t.eq("robust-waiter-was-woken", (done(0), result(0)), (true, 0));
    t.eq(
        "robust-lock-of-another-owner-untouched",
        LOCKS[2].futex.load(SeqCst),
        tid + 100,
    );
    t.eq(
        "robust-pending-entry-is-handled",
        LOCKS[3].futex.load(SeqCst),
        FUTEX_OWNER_DIED,
    );
    finish(&[waiting]);
    HEAD.next.store(0, SeqCst);
}

static THREAD_GO: AtomicU32 = AtomicU32::new(0);

// ---- priority inheritance: the checks that come before the lock itself ---------------------

fn pi_arguments(t: &mut T) {
    let w = at(20);
    word(20).store(0, SeqCst);
    for (name, op) in [
        ("lock-pi", FUTEX_LOCK_PI),
        ("lock-pi2", FUTEX_LOCK_PI2),
        ("trylock-pi", FUTEX_TRYLOCK_PI),
        ("unlock-pi", FUTEX_UNLOCK_PI),
    ] {
        // `futex_unlock_pi` reads the word and compares the owner before it builds the key.
        let unaligned = if op == FUTEX_UNLOCK_PI { Errno::EPERM } else { Errno::EINVAL };
        t.eq(format_args!("{name}-unaligned"), fx(w + 1, op, 0, 0, 0, 0), Err(unaligned));
        t.eq(format_args!("{name}-null"), fx(0, op, 0, 0, 0, 0), Err(Errno::EFAULT));
        t.eq(
            format_args!("{name}-kernel-address"),
            fx(TASK_SIZE, op, 0, 0, 0, 0),
            Err(Errno::EFAULT),
        );
    }
    t.eq(
        "lock-pi-timeout-pointer",
        fx(w, FUTEX_LOCK_PI, 0, BAD, 0, 0),
        Err(Errno::EFAULT),
    );
    t.eq(
        "lock-pi-negative-timeout",
        fx(w, FUTEX_LOCK_PI, 0, addr(&[-1i64, 0]), 0, 0),
        Err(Errno::EINVAL),
    );
    // Uncontended: the word is taken with the caller's tid and released again.
    let me = super::gettid() as u32;
    t.eq("unlock-pi-not-owner", fx(w, FUTEX_UNLOCK_PI, 0, 0, 0, 0), Err(Errno::EPERM));
    t.eq("trylock-pi-free", (fx(w, FUTEX_TRYLOCK_PI, 0, 0, 0, 0), word(20).load(SeqCst)), (Ok(0), me));
    t.eq("trylock-pi-owned-by-self", fx(w, FUTEX_TRYLOCK_PI, 0, 0, 0, 0), Err(Errno::EDEADLK));
    t.eq("lock-pi-owned-by-self", fx(w, FUTEX_LOCK_PI, 0, 0, 0, 0), Err(Errno::EDEADLK));
    t.eq("unlock-pi-owner", (fx(w, FUTEX_UNLOCK_PI, 0, 0, 0, 0), word(20).load(SeqCst)), (Ok(0), 0));
    t.eq("lock-pi-free", (fx(w, FUTEX_LOCK_PI, 0, 0, 0, 0), word(20).load(SeqCst)), (Ok(0), me));
    t.eq("unlock-pi-again", (fx(w, FUTEX_UNLOCK_PI, 0, 0, 0, 0), word(20).load(SeqCst)), (Ok(0), 0));
    // The requeue operations check their arguments.
    t.eq(
        "wait-requeue-pi-same-word",
        fx(w, FUTEX_WAIT_REQUEUE_PI, 0, 0, w, 0),
        Err(Errno::EINVAL),
    );
    t.eq(
        "cmp-requeue-pi-same-word",
        fx(w, FUTEX_CMP_REQUEUE_PI, 1, 1, w, 0),
        Err(Errno::EINVAL),
    );
}

// ---- futex2 --------------------------------------------------------------------------------

/// `struct futex_waitv`.
#[repr(C)]
#[derive(Clone, Copy)]
struct WaitV {
    val: u64,
    uaddr: u64,
    flags: u32,
    reserved: u32,
}

const FUTEX2_U32: u32 = 2;
const FUTEX2_PRIVATE: u32 = 128;

fn futex2(t: &mut T) {
    let w = at(21);
    word(21).store(3, SeqCst);
    let one = |flags: u32, val: u64| WaitV {
        val,
        uaddr: w as u64,
        flags,
        reserved: 0,
    };
    let v = [one(FUTEX2_U32 | FUTEX2_PRIVATE, 0)];
    let waitv = |v: &[WaitV], n: usize, flags: usize, timeout: usize, clockid: usize| {
        sys(Sysno::futex_waitv, &[addr(v), n, flags, timeout, clockid])
    };
    t.eq("waitv-flags", waitv(&v, 1, 1, 0, 0), Err(Errno::EINVAL));
    t.eq("waitv-none", waitv(&v, 0, 0, 0, 0), Err(Errno::EINVAL));
    t.eq("waitv-too-many", waitv(&v, 129, 0, 0, 0), Err(Errno::EINVAL));
    t.eq("waitv-null", sys(Sysno::futex_waitv, &[0, 1, 0, 0, 0]), Err(Errno::EINVAL));
    t.eq("waitv-unreadable", sys(Sysno::futex_waitv, &[BAD, 1, 0, 0, 0]), Err(Errno::EFAULT));
    let bad_flags = [one(0x3, 0)];
    t.eq("waitv-size-not-u32", waitv(&bad_flags, 1, 0, 0, 0), Err(Errno::EINVAL));
    let bad_flags = [one(FUTEX2_U32 | 0x1000, 0)];
    t.eq("waitv-unknown-flag", waitv(&bad_flags, 1, 0, 0, 0), Err(Errno::EINVAL));
    let mut reserved = v;
    reserved[0].reserved = 1;
    t.eq("waitv-reserved", waitv(&reserved, 1, 0, 0, 0), Err(Errno::EINVAL));
    let big_val = [one(FUTEX2_U32, 1 << 32)];
    t.eq("waitv-value-wider-than-the-futex", waitv(&big_val, 1, 0, 0, 0), Err(Errno::EINVAL));
    let ts = timespec(1);
    t.eq("waitv-bad-clock", waitv(&v, 1, 0, addr(&ts), 5), Err(Errno::EINVAL));
    t.eq("waitv-timeout-unreadable", waitv(&v, 1, 0, BAD, MONOTONIC), Err(Errno::EFAULT));
    t.eq("waitv-value-mismatch", waitv(&v, 1, 0, 0, 0), Err(Errno::EAGAIN));
    let mismatch = [one(FUTEX2_U32 | FUTEX2_PRIVATE, 4)];
    let past = timespec(1);
    t.eq("waitv-expired-deadline", waitv(&[one(FUTEX2_U32 | FUTEX2_PRIVATE, 3)], 1, 0, addr(&past), MONOTONIC), Err(Errno::ETIMEDOUT));
    t.eq("waitv-mismatch-beats-deadline", waitv(&mismatch, 1, 0, addr(&past), MONOTONIC), Err(Errno::EAGAIN));
    let unaligned = [WaitV {
        val: 0,
        uaddr: (w + 1) as u64,
        flags: FUTEX2_U32 | FUTEX2_PRIVATE,
        reserved: 0,
    }];
    t.eq("waitv-unaligned", waitv(&unaligned, 1, 0, 0, 0), Err(Errno::EINVAL));
    // futex_wake / futex_wait / futex_requeue.
    let wake = |uaddr: usize, mask: usize, nr: usize, flags: usize| {
        sys(Sysno::futex_wake, &[uaddr, mask, nr, flags])
    };
    t.eq("futex-wake-nobody", wake(w, 1, 1, (FUTEX2_U32 | FUTEX2_PRIVATE) as usize), Ok(0));
    t.eq("futex-wake-flags", wake(w, 1, 1, 0x1000), Err(Errno::EINVAL));
    t.eq("futex-wake-size", wake(w, 1, 1, 0), Err(Errno::EINVAL));
    t.eq("futex-wake-mask-zero", wake(w, 0, 1, FUTEX2_U32 as usize), Err(Errno::EINVAL));
    t.eq("futex-wake-mask-wide", wake(w, 1 << 32, 1, FUTEX2_U32 as usize), Err(Errno::EINVAL));
    t.eq("futex-wake-unaligned", wake(w + 1, 1, 1, FUTEX2_U32 as usize), Err(Errno::EINVAL));
    t.eq("futex-wake-unmapped", wake(BAD, 1, 1, FUTEX2_U32 as usize), Err(Errno::EFAULT));
    let wait = |uaddr: usize, val: usize, mask: usize, flags: usize, timeout: usize, clockid: usize| {
        sys(Sysno::futex_wait, &[uaddr, val, mask, flags, timeout, clockid])
    };
    t.eq("futex-wait-mismatch", wait(w, 4, 1, FUTEX2_U32 as usize, 0, 0), Err(Errno::EAGAIN));
    t.eq("futex-wait-flags", wait(w, 3, 1, 0x1000, 0, 0), Err(Errno::EINVAL));
    t.eq("futex-wait-size", wait(w, 3, 1, 1, 0, 0), Err(Errno::EINVAL));
    t.eq("futex-wait-val-wide", wait(w, 1 << 32, 1, FUTEX2_U32 as usize, 0, 0), Err(Errno::EINVAL));
    t.eq("futex-wait-mask-wide", wait(w, 3, 1 << 32, FUTEX2_U32 as usize, 0, 0), Err(Errno::EINVAL));
    t.eq("futex-wait-bad-clock", wait(w, 3, 1, FUTEX2_U32 as usize, addr(&ts), 9), Err(Errno::EINVAL));
    t.eq("futex-wait-deadline", wait(w, 3, 1, (FUTEX2_U32 | FUTEX2_PRIVATE) as usize, addr(&past), MONOTONIC), Err(Errno::ETIMEDOUT));
    t.eq("futex-wait-mask-zero", wait(w, 3, 0, FUTEX2_U32 as usize, 0, 0), Err(Errno::EINVAL));
    let pair = [one(FUTEX2_U32 | FUTEX2_PRIVATE, 3), WaitV { uaddr: at(22) as u64, ..one(FUTEX2_U32 | FUTEX2_PRIVATE, 3) }];
    let requeue = |p: &[WaitV; 2], flags: usize, wake: usize, req: usize| {
        sys(Sysno::futex_requeue, &[addr(p), flags, wake, req])
    };
    t.eq("futex-requeue-nobody", requeue(&pair, 0, 1, 1), Ok(0));
    t.eq("futex-requeue-flags", requeue(&pair, 1, 1, 1), Err(Errno::EINVAL));
    t.eq("futex-requeue-null", sys(Sysno::futex_requeue, &[0, 0, 1, 1]), Err(Errno::EINVAL));
    let mut mixed = pair;
    mixed[1].flags = FUTEX2_U32;
    t.eq("futex-requeue-different-flags", requeue(&mixed, 0, 1, 1), Err(Errno::EINVAL));
    let mut mismatch = pair;
    mismatch[0].val = 4;
    t.eq("futex-requeue-mismatch", requeue(&mismatch, 0, 1, 1), Err(Errno::EAGAIN));
    t.eq("futex-requeue-negative", requeue(&pair, 0, usize::MAX >> 32, 1), Err(Errno::EINVAL));
}
