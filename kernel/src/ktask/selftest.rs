// SPDX-License-Identifier: GPL-2.0-only
//! Scheduler self-tests of the QEMU suite (`test=sched-switch` and
//! `test=kstack-overflow`; `docs/kernel-tooling.md`). Kernel threads only: the
//! register switch, the run queue, keyed and signal wake-ups, the timer queue,
//! the stack pool and its guard pages, with the same code paths the user task
//! runs on. Nothing here is built outside `qemu-self-test`.

use super::{
    Ordering, RQ, SLOTS, SWITCHES, SchedId, TaskState, WaitKey, current, idle_loop, schedule,
    signal_wake_up, sleep_current, spawn, state, wake_up_key,
};
use crate::{
    cpu::{self, FxImage, PtRegs},
    services, timer,
};
use core::{
    arch::naked_asm,
    hint::black_box,
    sync::atomic::{AtomicBool, AtomicU64},
};
use kernel::{memory::Virtual, sched::CLASS_TEST};

const ROUNDS: u64 = 256;
/// Threads of the main run: two sleepers, a keyed and a signalled waiter, the
/// controller and the ping-pong pair.
const THREADS: u64 = 7;

static TURN: AtomicU64 = AtomicU64::new(0);
static ORDER_BAD: AtomicU64 = AtomicU64::new(0);
static REG_BAD: AtomicU64 = AtomicU64::new(0);
static FPU_BAD: AtomicU64 = AtomicU64::new(0);
static CTRL_BAD: AtomicU64 = AtomicU64::new(0);
static TIME_BAD: AtomicU64 = AtomicU64::new(0);
/// Threads that ran to completion.
static DONE: AtomicU64 = AtomicU64::new(0);
/// Order in which the two timed sleepers woke: the rank each recorded (1-based).
static WAKE_RANK: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
static WOKEN: AtomicU64 = AtomicU64::new(0);
static FLAG: AtomicBool = AtomicBool::new(false);
static SIGNAL_FLAG: AtomicBool = AtomicBool::new(false);
static KEYED_WAKES: AtomicU64 = AtomicU64::new(0);
static SIGNAL_WAKES: AtomicU64 = AtomicU64::new(0);
static KEYED_ID: AtomicU64 = AtomicU64::new(0);
static SIGNALLED_ID: AtomicU64 = AtomicU64::new(0);

const KEY_WAITED: WaitKey = WaitKey::new(CLASS_TEST, 1);
const KEY_OTHER: WaitKey = WaitKey::new(CLASS_TEST, 2);

fn spawn_thread(func: extern "C" fn(usize), arg: usize, owns_fpu: bool) -> SchedId {
    crate::unwrap(
        spawn(Some(func), arg, PtRegs::default(), owns_fpu).map_err(|_| "no slot"),
        "spawn-kthread",
    )
}

extern "C" fn yield_now() {
    schedule();
}

// Test-only boundary: the registers a context switch must preserve.
//
// Why asm: ordinary Rust cannot put chosen values in the SysV callee-saved
// registers across a call, which is exactly what a switch to another task and
// back must preserve, and the `register_probe!` family in `cpu` calls a naked
// stub rather than a Rust function. Prerequisites: CPL0, IF=0; `rdi` = a seed,
// `rsi` = an `extern "C" fn()` that may switch tasks (`yield_now`). Effects:
// loads RBX, RBP, R12-R15 with `seed + 1..=6`, calls the function, then
// compares each register with its value (the seed lives on this task's own
// stack, so it survives even a switch that mixes registers up). Returns 1 in
// RAX when all six are intact, else 0. Clobbers the caller-saved registers and
// flags; restores the callee-saved ones it borrowed. Memory: one stack slot.
// Stack: 6 pushes + 1 slot, so RSP is 16-aligned at the CALL (entry is 8 mod
// 16, minus 56 bytes). No red zone, no unwind, privilege CPL0.
#[unsafe(naked)]
unsafe extern "C" fn callee_saved_probe(_seed: u64, _switch: extern "C" fn()) -> u64 {
    naked_asm!(
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "sub rsp, 8",
        "mov [rsp], rdi",
        "lea rbx, [rdi + 1]",
        "lea rbp, [rdi + 2]",
        "lea r12, [rdi + 3]",
        "lea r13, [rdi + 4]",
        "lea r14, [rdi + 5]",
        "lea r15, [rdi + 6]",
        "call rsi",
        "mov rdi, [rsp]",
        "xor eax, eax",
        "lea rcx, [rdi + 1]",
        "cmp rbx, rcx",
        "jne 2f",
        "lea rcx, [rdi + 2]",
        "cmp rbp, rcx",
        "jne 2f",
        "lea rcx, [rdi + 3]",
        "cmp r12, rcx",
        "jne 2f",
        "lea rcx, [rdi + 4]",
        "cmp r13, rcx",
        "jne 2f",
        "lea rcx, [rdi + 5]",
        "cmp r14, rcx",
        "jne 2f",
        "lea rcx, [rdi + 6]",
        "cmp r15, rcx",
        "jne 2f",
        "mov eax, 1",
        "2:",
        "add rsp, 8",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        "ret",
    );
}

/// One half of the ping-pong: strict alternation through `schedule()`, with
/// register and FP canaries that differ per thread.
extern "C" fn pingpong(me: usize) {
    let seed = 0x0123_4567_89ab_0000u64 | ((me as u64 + 1) << 12);
    for round in 0..ROUNDS {
        if TURN.load(Ordering::Relaxed) != me as u64 {
            ORDER_BAD.fetch_add(1, Ordering::Relaxed);
        }
        TURN.store(1 - me as u64, Ordering::Relaxed);
        // XMM0 = a pattern private to this thread and round.
        let mut want = FxImage::initial();
        let pattern = (seed ^ round).to_le_bytes();
        want.0[160..168].copy_from_slice(&pattern);
        want.0[168..176].copy_from_slice(&pattern.map(|b| !b));
        cpu::fpu_restore(&want);
        // SAFETY: CPL0, IF=0 (kernel threads run masked); the probe borrows the
        // callee-saved registers and restores them.
        let intact = unsafe { callee_saved_probe(seed ^ round, yield_now) };
        if intact != 1 {
            REG_BAD.fetch_add(1, Ordering::Relaxed);
        }
        let mut got = FxImage::ZERO;
        cpu::fpu_save(&mut got);
        if got.0[160..176] != want.0[160..176] {
            FPU_BAD.fetch_add(1, Ordering::Relaxed);
        }
    }
    DONE.fetch_add(1, Ordering::Relaxed);
}

/// A timed sleeper: 3 ms (`which` 0) or 1 ms (1), woken by the timer queue.
extern "C" fn sleeper(which: usize) {
    let ms = [3, 1][which];
    let start = timer::ktime_get_ns();
    let until = start + ms * 1_000_000;
    while timer::ktime_get_ns() < until {
        sleep_current(WaitKey::NONE, Some(until));
    }
    if timer::ktime_get_ns() - start < ms * 1_000_000 {
        TIME_BAD.fetch_add(1, Ordering::Relaxed);
    }
    WAKE_RANK[which].store(WOKEN.fetch_add(1, Ordering::Relaxed) + 1, Ordering::Relaxed);
    DONE.fetch_add(1, Ordering::Relaxed);
}

/// Sleeps on `KEY_WAITED` until `FLAG`: every wake-up is counted, spurious
/// ones included.
extern "C" fn keyed_waiter(_: usize) {
    while !FLAG.load(Ordering::Relaxed) {
        sleep_current(KEY_WAITED, None);
        KEYED_WAKES.fetch_add(1, Ordering::Relaxed);
    }
    DONE.fetch_add(1, Ordering::Relaxed);
}

/// Sleeps on no key until `SIGNAL_FLAG`: only a signal wake-up ends its sleeps.
extern "C" fn signalled(_: usize) {
    while !SIGNAL_FLAG.load(Ordering::Relaxed) {
        sleep_current(WaitKey::NONE, None);
        SIGNAL_WAKES.fetch_add(1, Ordering::Relaxed);
    }
    DONE.fetch_add(1, Ordering::Relaxed);
}

fn bad_if(condition: bool) {
    if condition {
        CTRL_BAD.fetch_add(1, Ordering::Relaxed);
    }
}

extern "C" fn controller(_: usize) {
    for _ in 0..8 {
        schedule();
    }
    let keyed = SchedId::from_raw(KEYED_ID.load(Ordering::Relaxed));
    let signalled = SchedId::from_raw(SIGNALLED_ID.load(Ordering::Relaxed));
    bad_if(state(keyed) != Some(TaskState::Interruptible));
    bad_if(state(signalled) != Some(TaskState::Interruptible));
    // The wrong key, the empty key and a signal wake-up of a keyed sleeper:
    // only the last wakes it, and it goes back to sleep (spurious wake-up).
    bad_if(wake_up_key(KEY_OTHER) != 0 || wake_up_key(WaitKey::NONE) != 0);
    bad_if(state(keyed) != Some(TaskState::Interruptible));
    bad_if(!signal_wake_up(keyed));
    for _ in 0..4 {
        schedule();
    }
    bad_if(KEYED_WAKES.load(Ordering::Relaxed) != 1);
    bad_if(state(keyed) != Some(TaskState::Interruptible));
    // The right key wakes it once more.
    bad_if(wake_up_key(KEY_WAITED) != 1);
    for _ in 0..4 {
        schedule();
    }
    bad_if(KEYED_WAKES.load(Ordering::Relaxed) != 2);
    // A keyed sleeper's condition becomes true: key wake-up ends it for good.
    FLAG.store(true, Ordering::Relaxed);
    bad_if(wake_up_key(KEY_WAITED) != 1);
    // The unkeyed sleeper is woken by a signal wake-up (and not by the key).
    bad_if(wake_up_key(KEY_WAITED) != 0);
    SIGNAL_FLAG.store(true, Ordering::Relaxed);
    bad_if(!signal_wake_up(signalled));
    DONE.fetch_add(1, Ordering::Relaxed);
}

extern "C" fn nop(_: usize) {
    DONE.fetch_add(1, Ordering::Relaxed);
}

fn fail_if(condition: bool, label: &str) {
    if condition {
        crate::log!("FAIL sched-switch {}\n", label);
        crate::fail();
    }
}

/// Run `count` copies of `nop` to completion; `Err(i)` where the i-th spawn failed.
fn run_nops(count: usize) -> Result<[Option<SchedId>; SLOTS], usize> {
    let before = DONE.load(Ordering::Relaxed);
    let mut ids = [None; SLOTS];
    for (i, id) in ids.iter_mut().enumerate().take(count) {
        match spawn(Some(nop), 0, PtRegs::default(), false) {
            Ok(spawned) => *id = Some(spawned),
            Err(_) => return Err(i),
        }
    }
    idle_loop(|| DONE.load(Ordering::Relaxed) == before + count as u64);
    Ok(ids)
}

/// The `sched-switch` case. Context: the boot context after `ktask::init`, the
/// tick running, before the user task exists.
pub fn sched_switch() {
    let pool = cpu::KSTACK_SLOTS;
    // The guard pages: every pool slot has one, unmapped, with its usable part
    // mapped, and a read of one faults at the exact instruction.
    {
        let tables = services::TABLES.lock();
        for slot in 0..pool {
            let guard = tables.lookup(Virtual(cpu::kstack_guard(slot)));
            let lowest = tables.lookup(Virtual(cpu::kstack_lowest(slot)));
            fail_if(!matches!(guard, Ok(None)), "guard-mapped");
            fail_if(!matches!(lowest, Ok(Some(_))), "stack-unmapped");
        }
    }
    // SAFETY: IF=0, the IDT and tables are ours, the guard of pool stack 0 was
    // just seen unmapped, and no other fault permit is armed.
    fail_if(
        !unsafe { cpu::fault_test(cpu::kstack_guard(0), 0) },
        "guard-fault",
    );

    // Threads: ping-pong pair, two timed sleepers, a keyed and a signalled
    // sleeper and the controller that wakes them. FIFO order of creation.
    let switches_before = SWITCHES.load(Ordering::Relaxed);
    spawn_thread(sleeper, 0, false);
    spawn_thread(sleeper, 1, false);
    KEYED_ID.store(
        spawn_thread(keyed_waiter, 0, false).to_raw(),
        Ordering::Relaxed,
    );
    SIGNALLED_ID.store(
        spawn_thread(signalled, 0, false).to_raw(),
        Ordering::Relaxed,
    );
    spawn_thread(controller, 0, false);
    spawn_thread(pingpong, 0, true);
    spawn_thread(pingpong, 1, true);
    idle_loop(|| DONE.load(Ordering::Relaxed) == THREADS);
    let switches = SWITCHES.load(Ordering::Relaxed) - switches_before;

    fail_if(ORDER_BAD.load(Ordering::Relaxed) != 0, "pingpong-order");
    fail_if(switches < 2 * ROUNDS, "switch-count");
    fail_if(
        REG_BAD.load(Ordering::Relaxed) != 0,
        "callee-saved-registers",
    );
    fail_if(FPU_BAD.load(Ordering::Relaxed) != 0, "fpu-isolation");
    fail_if(TIME_BAD.load(Ordering::Relaxed) != 0, "sleep-short");
    fail_if(
        WAKE_RANK[1].load(Ordering::Relaxed) != 1 || WAKE_RANK[0].load(Ordering::Relaxed) != 2,
        "timer-order",
    );
    fail_if(CTRL_BAD.load(Ordering::Relaxed) != 0, "wake-ups");
    fail_if(SIGNAL_WAKES.load(Ordering::Relaxed) != 1, "signal-wake");

    // Exit, free and reuse: all stacks come back, a stale handle names nothing,
    // and the pool is exactly as large as advertised.
    fail_if(RQ.lock().nr_active() != 0, "threads-left");
    let Ok(first) = run_nops(pool) else {
        fail_if(true, "pool-too-small");
        return;
    };
    fail_if(run_nops(pool + 1) != Err(pool), "pool-not-exhausted");
    // The failed attempt spawned `pool` threads before refusing the next.
    idle_loop(|| RQ.lock().nr_active() == 0);
    fail_if(
        first.iter().flatten().any(|&id| state(id).is_some()),
        "stale-handle",
    );
    let again = run_nops(pool);
    fail_if(again.is_err(), "pool-not-recycled");
    let again = again.unwrap_or([None; SLOTS]);
    fail_if(first[0] == again[0], "generation-reused");
    fail_if(
        first[0].map(SchedId::index) != again[0].map(SchedId::index),
        "slot-not-reused",
    );
    fail_if(current() != RQ.lock().idle(), "idle-not-current");
    crate::log!(
        "CHECK sched-switch ok threads=7 switches=ok regs=callee-saved fpu=isolated order=fifo timers=ordered wake=keyed,signal,spurious stacks=recycled pool=exhausted,reused guards=unmapped guard_fault=exact\n"
    );
}

/// Recurse until the stack runs out. Each frame touches its buffer, so the
/// compiler's stack probes and the guard page see real use.
#[inline(never)]
extern "C" fn recurse(depth: usize) -> usize {
    let mut buffer = [0u8; 2048];
    buffer[depth % 2048] = 1;
    black_box(&mut buffer);
    if black_box(depth) == usize::MAX {
        return 0;
    }
    recurse(depth + 1) + usize::from(buffer[(depth + 1) % 2048])
}

extern "C" fn overflow(_: usize) {
    black_box(recurse(0));
}

/// The `kstack-overflow` case: a kernel thread overflows its stack. The case
/// passes when the kernel stops with `FAIL kernel stack overflow` (the fault on
/// the guard page, escalated to #DF because the exception frame has no room
/// either); returning from here would be the failure.
pub fn kstack_overflow() {
    spawn_thread(overflow, 0, false);
    idle_loop(|| false);
}
