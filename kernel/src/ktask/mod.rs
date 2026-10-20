// SPDX-License-Identifier: GPL-2.0-only
// Linux 6.18.57 (commit 2ff600d29ee478d0a8d46ef8a58afb5e038fe692), all GPL-2.0:
// kernel/sched/core.c (`schedule` 7025, `__schedule` 6801, `context_switch` 5293,
// `finish_task_switch` 5168, `schedule_tail` 5262, `do_task_dead` 6953,
// `wake_up_new_task` 4831), arch/x86/kernel/process_64.c (`__switch_to`,
// `save_fsgs`, `load_seg_legacy`), arch/x86/kernel/process.c (`ret_from_fork`
// 151, `copy_thread`), arch/x86/include/asm/switch_to.h (`switch_to_asm`,
// `struct inactive_task_frame`, `update_task_stack`), kernel/sched/idle.c
// (`do_idle` 276), kernel/sched/wait.c (`prepare_to_wait_event`),
// kernel/time/sleep_timeout.c (`schedule_hrtimeout_range`).
// Transformation: one CPU; the task stack is a slot of a static pool whose index
// is the scheduler slot; a task is a `kernel::sched::SchedId` plus a `Thread`
// register context, with no `task_struct` (the task-model lane adds its own state
// keyed by the same `SchedId`); the idle task is the boot context on the boot
// stack; the timer queue replaces per-task `hrtimer`s.
//! Kernel tasks: stacks, the register switch, the idle loop and sleeping.
//!
//! The pure scheduling decisions are `kernel::sched::Rq`; this module owns what
//! needs the hardware: the stack pool (`cpu::KSTACKS`), the saved register
//! context of each task ([`Thread`]), `TSS.RSP0`, the first-run frame, the
//! timer-queue/clockevent coupling and the idle loop.
//!
//! # Contexts and locks
//! * `schedule()` runs in task context with interrupts masked and **no lock
//!   guard of this module held**. The single user process still reaches it with
//!   its `PROCESS` and `TABLES` guards alive (the blocking syscalls of
//!   `userspace`); that is sound only because no other task takes them, and the
//!   task-model lane removes it (seam, below).
//! * Lock classes (acquire left to right, never the reverse):
//!   `TIMERQ -> TIMER_HW`; `RQ` is a leaf and may be taken under any lock, from
//!   hardirq too. `TIMERQ` and `RQ` are never held together: expiry drains the
//!   queue under `TIMERQ`, releases it, and only then wakes under `RQ`.
//! * Interrupt handlers reach this module through [`timer_interrupt`] and
//!   [`scheduler_tick`] only; both take `TIMERQ`/`RQ` with interrupts already
//!   masked and allocate nothing (all storage is reserved in [`init`]).
//!
//! # The seam for the task-model lane
//! A task is a [`SchedId`]; the model stores one per task and keeps its own state
//! (`Process`, credentials, files, mm) keyed by it. It calls
//! * [`spawn_user`] with the `PtRegs` of the new task's first return to ring 3
//!   (fork builds the child's from the parent's, `ax = 0`) and gets the id back;
//! * [`sleep_current`] for every blocking wait (`signal::Task::wait` is its only
//!   caller today), [`wake_up_key`] / [`signal_wake_up`] / [`wake_up_task`] to
//!   end one, and [`exit_current`] at the end of `do_exit`;
//! * [`current`] to find out who it is running as.
//!
//! Per-task context that switches with the task (user FP state, segment
//! registers and bases, the bad-iret depth, `TSS.RSP0`) is saved and restored
//! here; address-space switching (`switch_mm`) and the accounting hooks
//! (`sched_in`/`sched_out`) are the model lane's to add to [`context_switch`].
//! shortcut: `CpuAccount`, `PROCESS` and `TABLES` are still process-wide
//! singletons; they become per-task with the model lane.
#![allow(
    clippy::cast_possible_truncation,
    reason = "stack addresses and slot indices are bounded by the pool"
)]

#[cfg(feature = "qemu-self-test")]
pub mod selftest;

use crate::{
    cpu::{self, FxImage, PtRegs, Segments},
    services::Service,
    timer,
};
use core::{
    cell::UnsafeCell,
    mem::size_of,
    ptr,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use kernel::sched::{
    NoSlot, Rq, SchedId, Switch, TaskState, WaitKey, WakeMode, timerq::TimerQueue,
};

/// Scheduler slots: the idle task (slot 0, on the boot stack) and one per pool
/// stack (slot `n` runs on `KSTACKS[n - 1]`).
const SLOTS: usize = cpu::KSTACK_SLOTS + 1;

/// `STACK_END_MAGIC` (include/uapi/linux/magic.h): the lowest usable word of a
/// task stack, checked on every switch-out.
const STACK_END_MAGIC: u64 = 0x57AC_6E9D;

/// The `RQ` lock class: the run queue. A leaf; see the module docs.
static RQ: Service<Rq> = Service::new();

/// What a timer-queue entry does on expiry. The task-model lane adds the real
/// interval timer (`ITIMER_REAL`) of a task here.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Timer {
    /// Make a sleeping task runnable.
    Wake(SchedId),
}

/// The `TIMERQ` lock class: absolute wake-up times. Held with `TIMER_HW` only.
static TIMERQ: Service<TimerQueue<Timer>> = Service::new();

/// [`init`] ran: the tick and timer handlers may use the queues.
static READY: AtomicBool = AtomicBool::new(false);

/// The task that just left the CPU, as `SchedId::to_raw`, for the next task's
/// [`finish_task_switch`] (Linux returns it in `rax` from `__switch_to`).
const NO_PREV: u64 = u64::MAX;
static SWITCH_PREV: AtomicU64 = AtomicU64::new(NO_PREV);

/// Context switches performed (the self-test asserts the ping-pong reached the
/// switch).
#[cfg(feature = "qemu-self-test")]
static SWITCHES: AtomicU64 = AtomicU64::new(0);

/// The register context of one task: what is saved while it is off the CPU.
struct Thread {
    /// Saved kernel `rsp` (`thread.sp`): points at six callee-saved slots and
    /// a return address, pushed by `switch_to_asm` or built by [`spawn`].
    sp: u64,
    /// Whether the task owns user FP and segment state (a ring-3 task). Kernel
    /// threads and idle leave the live registers alone, like `PF_KTHREAD`.
    user: bool,
    fx: FxImage,
    segments: Segments,
    /// `BAD_IRET_DEPTH` of this task while it is off the CPU.
    bad_iret_depth: u64,
}

impl Thread {
    const NEW: Self = Self {
        sp: 0,
        user: false,
        fx: FxImage::ZERO,
        segments: Segments {
            ds: 0,
            es: 0,
            fs: 0,
            gs: 0,
            fs_base: 0,
            gs_base: 0,
        },
        bad_iret_depth: 0,
    };
}

/// All register contexts, indexed by scheduler slot.
struct Threads(UnsafeCell<[Thread; SLOTS]>);

// SAFETY: a `Thread` is touched only (a) by `spawn`, while its slot is unowned
// (just handed out by `Rq::add_task`, not yet queued, so no other flow can name
// it), and (b) by `context_switch`, whose preconditions are IF=0 on the single
// CPU, so the two tasks involved are the only flows that exist and the running
// one is the caller. There is no other accessor and no reference outlives such
// a section.
unsafe impl Sync for Threads {}

static THREADS: Threads = Threads(UnsafeCell::new([Thread::NEW; SLOTS]));

fn thread(slot: usize) -> *mut Thread {
    assert!(slot < SLOTS, "scheduler slot out of range");
    // SAFETY: in bounds (asserted); pointer arithmetic on the static array.
    unsafe { THREADS.0.get().cast::<Thread>().add(slot) }
}

/// The top of the kernel stack of scheduler slot `slot`.
fn stack_top(slot: usize) -> u64 {
    match slot.checked_sub(1) {
        Some(pool) => cpu::kstack_top(pool),
        None => cpu::boot_stack_top(),
    }
}

/// Reserve the scheduler's storage and make the boot context the idle task.
/// Once per boot: a second call (the bare-metal suite starts one process per
/// group) finds the scheduler installed and keeps it; [`reset_group`] returns
/// it to its initial state between groups.
///
/// # Errors
/// An allocation failed (the kernel heap is exhausted).
pub fn init() -> Result<(), &'static str> {
    if READY.load(Ordering::Acquire) {
        return Ok(());
    }
    let rq = Rq::new(SLOTS).map_err(|_| "run queue")?;
    // One timed wake-up per task (`sleep_current` re-arms the task's own entry).
    let timers = TimerQueue::new(SLOTS).map_err(|_| "timer queue")?;
    RQ.install(rq);
    TIMERQ.install(timers);
    READY.store(true, Ordering::Release);
    Ok(())
}

/// The end of a bare-metal-suite group: forget every task, timed wake-up and
/// pending switch, so the next group starts on a scheduler as [`init`] left it.
/// The group's tasks are dead or abandoned (their stacks are pool slots whose
/// first-run frame the next [`spawn`] rewrites); nothing else refers to them.
///
/// Context: BSP, IF=0, the idle task (the boot stack) is current, no `RQ` or
/// `TIMERQ` guard held. `userspace::teardown` has cleared the clockevent's
/// wake-up words (`timer::clear_waits`).
#[cfg(feature = "baremetal-suite")]
pub fn reset_group() {
    RQ.lock().reset();
    TIMERQ.lock().clear();
    SWITCH_PREV.store(NO_PREV, Ordering::Relaxed);
    cpu::swap_bad_iret_depth(0);
}

/// Whether the boot context (the idle task) is current. The suite's group end
/// uses it to know whether it can switch away (a task) or already is where
/// teardown runs.
#[cfg(feature = "baremetal-suite")]
pub fn in_idle() -> bool {
    let rq = RQ.lock();
    rq.curr() == rq.idle()
}

/// Whether the locks of this module are free (see `Service::is_free`): the
/// suite ends a stopped group only if the abandoned stack cannot still hold
/// them.
#[cfg(feature = "baremetal-suite")]
pub fn locks_free() -> bool {
    RQ.is_free() && TIMERQ.is_free()
}

/// The first-run frame of a task, built at the top of its stack: what
/// `switch_to_asm` pops, the address it `ret`s to, and the `pt_regs` for the
/// return to ring 3 (Linux's `struct fork_frame` = `inactive_task_frame` +
/// `pt_regs`, `arch/x86/include/asm/switch_to.h`).
#[repr(C)]
struct ForkFrame {
    /// r15, r14, r13, r12, rbx, rbp: the order `switch_to_asm` pops them.
    callee_saved: [u64; 6],
    ret: u64,
    regs: PtRegs,
}

/// `PtRegs` is 168 bytes and the stack top is 16-aligned, so the register
/// frame starts 8 mod 16: after `ret_from_fork_asm`'s `sub rsp, 8` the CALL is
/// 16-aligned (see its proof).
const _: () = assert!(size_of::<ForkFrame>().is_multiple_of(16) && size_of::<PtRegs>() % 16 == 8);

/// Create a task that starts at `ret_from_fork_asm`: a ring-3 task when
/// `func` is `None` (it returns to user mode with `regs`), else a kernel thread
/// running `func(arg)` and exiting when it returns. `user` is whether it owns
/// user FP/segment state.
fn spawn(
    func: Option<extern "C" fn(usize)>,
    arg: usize,
    regs: PtRegs,
    user: bool,
) -> Result<SchedId, NoSlot> {
    let id = RQ.lock().add_task()?;
    let slot = id.index();
    let pool = slot - 1; // slot 0 is idle and never handed out
    let top = cpu::kstack_top(pool);
    let frame = (top - size_of::<ForkFrame>() as u64) as *mut ForkFrame;
    // SAFETY: `add_task` handed this slot out exclusively (module `Threads`
    // argument (a)): no queue, no `Thread` use and no stack frame refers to
    // pool stack `pool`, whose memory is the static, mapped, 8-aligned pool.
    // `frame` lies wholly inside its usable part (the frame is 224 bytes at the
    // 16-aligned top; the usable part is 64 KiB), the magic word is its lowest
    // usable word, and `thread(slot)` is in bounds. Only plain integer data is
    // written, and `sp` is the address of the finished frame.
    unsafe {
        ptr::write(
            frame,
            ForkFrame {
                // r15, r14, r13, r12 = arg, rbx = func, rbp = 0 (ends traces).
                callee_saved: [
                    0,
                    0,
                    0,
                    arg as u64,
                    func.map_or(0, |f| f as *const () as u64),
                    0,
                ],
                ret: cpu::ret_from_fork_asm as *const () as u64,
                regs,
            },
        );
        ptr::write_volatile(cpu::kstack_lowest(pool) as *mut u64, STACK_END_MAGIC);
        let thread = thread(slot);
        *thread = Thread {
            sp: frame as u64,
            user,
            fx: FxImage::initial(),
            segments: Segments::default(),
            bad_iret_depth: 0,
        };
    }
    let queued = RQ.lock().wake_up_new_task(id);
    debug_assert!(queued, "a fresh task is runnable");
    Ok(id)
}

/// Create a ring-3 task whose first run returns to user mode with `regs`
/// (`copy_thread` + `wake_up_new_task`). It owns user FP state (initial image)
/// and segment state (null selectors, zero bases).
///
/// # Errors
/// [`NoSlot`] when the stack pool is exhausted (fork's `-EAGAIN`).
///
/// # Panics
/// Before [`init`].
pub fn spawn_user(regs: PtRegs) -> Result<SchedId, NoSlot> {
    spawn(None, 0, regs, true)
}

/// Start the first user task and become the idle task (`rest_init`'s
/// `cpu_startup_entry`). Returns when that task is gone and nothing else is
/// runnable: never in a normal boot (the death of init ends it), once per group
/// in the bare-metal suite, whose group end leaves the CPU for good with
/// [`exit_current`]. `bound` receives the init task's handle before the first
/// switch (the task model's [`Waker`](kernel::task::exit::Waker) learns which
/// scheduling handle is init); it runs with IF clear and no scheduler lock held.
///
/// # Safety
/// BSP at CPL0, IF clear, after `cpu::install_descriptors`,
/// `cpu::enable_syscalls` and `cpu::init_user_fpu`; the active tree maps `entry`
/// (executable) and `sp` (writable) for the user; everything the syscall and
/// fault paths use is in statics (`PROCESS`, `services`); the caller's frame
/// stays on the boot stack, which only idle uses from here on.
pub unsafe fn start_init(entry: u64, sp: u64, bound: impl FnOnce(SchedId)) {
    // SAFETY: forwarded caller contract (BSP, CPL0, no ring-3 task yet).
    unsafe { cpu::prepare_user_segments() };
    let regs = PtRegs {
        ip: entry,
        cs: kernel::signal::USER_CS,
        // IF set, IOPL 0, TF/NT/RF/AC/VM clear, bit 1 fixed.
        flags: 0x202,
        sp,
        ss: kernel::signal::USER_DS,
        // Not inside a system call (the interrupt stubs push -1 as well).
        orig_ax: u64::MAX,
        ..PtRegs::default()
    };
    let init = crate::unwrap(spawn_user(regs).map_err(|_| "no task slot"), "spawn-init");
    bound(init);
    idle_loop(|| state(init).is_none());
}

/// `current`, as a handle.
///
/// # Panics
/// Before [`init`].
#[cfg_attr(
    not(feature = "qemu-self-test"),
    allow(
        dead_code,
        reason = "seam for the task-model lane; exercised by the self-test"
    )
)]
pub fn current() -> SchedId {
    RQ.lock().curr()
}

/// A task's scheduling state; `None` for a handle that no longer names a task.
#[cfg_attr(
    not(feature = "qemu-self-test"),
    allow(
        dead_code,
        reason = "seam for the task-model lane; exercised by the self-test"
    )
)]
pub fn state(id: SchedId) -> Option<TaskState> {
    RQ.lock().state(id)
}

/// `__wake_up(key, mode, nr_exclusive)`: see [`Rq::wake_up_key`] for the order
/// and the counting; how many woke.
pub fn wake_up_key(key: WaitKey, mode: WakeMode, nr_exclusive: usize) -> usize {
    RQ.lock().wake_up_key(key, mode, nr_exclusive)
}

/// `signal_wake_up`: wake an interruptible sleeper (the signal sender calls it
/// after queueing the signal). Whether it was asleep.
pub fn signal_wake_up(id: SchedId) -> bool {
    RQ.lock().wake_interruptible(id)
}

/// `schedule()`: give the CPU to the next runnable task, or to idle. A caller
/// that is still runnable (a yield, or a preemption point) goes to the back of
/// the queue; one that put itself to sleep first ([`sleep_current`]) does not.
/// Returns when this task is chosen again.
///
/// Context: task context (never idle's own loop body from a handler), IF=0, no
/// `RQ`/`TIMERQ` guard held. May be called with unrelated locks held only if
/// no other task can ever want them (module docs).
///
/// # Panics
/// With interrupts enabled or before [`init`]; and (as a loud stop) when the
/// current task's stack end marker was overwritten.
pub fn schedule() {
    assert!(!cpu::interrupts_enabled(), "schedule() with interrupts on");
    let switch = {
        let mut rq = RQ.lock();
        check_stack_end(rq.curr());
        rq.schedule()
    };
    if let Some(switch) = switch {
        context_switch(switch);
    }
}

/// Whether the tick asked for a reschedule (`need_resched`).
fn resched_pending() -> bool {
    RQ.lock().need_resched()
}

/// `exit_to_user_mode_loop`'s `TIF_NEED_RESCHED` step, at the return to ring 3:
/// the tick asked for a reschedule because another task is runnable
/// (`CONFIG_PREEMPT_VOLUNTARY` preempts only here, never in ring 0), so give it
/// the CPU; this task continues when it is chosen again, with everything
/// re-examined by the caller's loop. `interrupted`: the return is from an
/// interrupt or exception (`pt_regs.orig_ax == -1`), not from a system call.
///
/// Context: task, IF=0, on this task's own kernel stack, no lock held (an
/// interrupt handler's frame is fine: the entry stub's frame lives on the
/// task's stack and the interrupt was acknowledged before this call).
pub fn preempt_user(interrupted: bool) {
    if !resched_pending() {
        return;
    }
    #[cfg(feature = "qemu-self-test")]
    let before = SWITCHES.load(Ordering::Relaxed);
    schedule();
    #[cfg(feature = "qemu-self-test")]
    if interrupted && SWITCHES.load(Ordering::Relaxed) != before {
        selftest::note_user_preemption();
    }
    #[cfg(not(feature = "qemu-self-test"))]
    let _ = interrupted;
}

/// `STACK_END_MAGIC` check of a task's stack: a corrupted marker means the
/// stack grew through its whole usable part; the guard page was missed or the
/// frame jumped over it.
fn check_stack_end(id: SchedId) {
    let Some(pool) = id.index().checked_sub(1) else {
        return; // idle: the boot stack has its own guard check
    };
    // SAFETY: pool stack `pool` is static, mapped memory; its lowest usable word
    // is 8-aligned and was initialised by `spawn` before the task ran; this is
    // a plain volatile read.
    let magic = unsafe { ptr::read_volatile(cpu::kstack_lowest(pool) as *const u64) };
    if magic != STACK_END_MAGIC {
        crate::log!(
            "FAIL kernel stack end marker overwritten slot={} magic={:#x}\n",
            pool,
            magic
        );
        crate::fail();
    }
}

/// The register half of `schedule()`: `context_switch`, `switch_to` and
/// `finish_task_switch` of Linux. Runs on the previous task's stack up to
/// `switch_to_asm` and on the next task's stack after it.
///
/// Context: IF=0, single CPU, `RQ` not held; `switch` names two live slots
/// whose `Thread`s are in the states [`spawn`] or an earlier switch left.
fn context_switch(switch: Switch) {
    let (prev, next) = (switch.prev.index(), switch.next.index());
    #[cfg(feature = "qemu-self-test")]
    SWITCHES.fetch_add(1, Ordering::Relaxed);
    let (prev_thread, next_thread) = (thread(prev), thread(next));
    // SAFETY: module `Threads` argument (b): IF=0 and the single CPU make this
    // flow the only one; `prev_thread` is the running task's and `next_thread`
    // a task that is off the CPU (`Rq::schedule` never returns the current one
    // as next), so the two places are distinct and nothing else reads them. The
    // FP and segment operations need CPL0 and `init_user_fpu` (every `user`
    // thread exists only after it). `next`'s `sp` is the one its own switch-out
    // stored or `spawn` built. `set_kernel_stack` gets the 16-aligned top of
    // `next`'s mapped stack. `SWITCH_PREV` is read exactly once, by
    // `finish_task_switch` of whichever task resumes.
    unsafe {
        if (*prev_thread).user {
            cpu::fpu_save(&mut (*prev_thread).fx);
            (*prev_thread).segments = Segments::save();
        }
        (*prev_thread).bad_iret_depth = cpu::swap_bad_iret_depth((*next_thread).bad_iret_depth);
        if (*next_thread).user {
            cpu::fpu_restore(&(*next_thread).fx);
            (*next_thread).segments.load();
        }
        cpu::set_kernel_stack(stack_top(next));
        SWITCH_PREV.store(switch.prev.to_raw(), Ordering::Relaxed);
        cpu::switch_to_asm(ptr::addr_of_mut!((*prev_thread).sp), (*next_thread).sp);
    }
    // The task chosen by some later `schedule()` resumes here.
    finish_task_switch();
}

/// `finish_task_switch`: the first thing a task does after getting the CPU. A
/// task that died is released now, because only now has its stack stopped being
/// the running one (`put_task_stack` of `TASK_DEAD`).
fn finish_task_switch() {
    let prev = SWITCH_PREV.swap(NO_PREV, Ordering::Relaxed);
    if prev != NO_PREV {
        RQ.lock().free(SchedId::from_raw(prev));
    }
}

/// First Rust code of a new task, called by `ret_from_fork_asm` (Linux's
/// `ret_from_fork`). A kernel thread runs `func(arg)` and exits; a user task
/// does its exit-to-user work (pending signals, timers, a pending reschedule)
/// and returns, after which the asm tail enters ring 3 with `regs`.
pub(crate) extern "C" fn ret_from_fork(
    regs: &mut PtRegs,
    func: Option<extern "C" fn(usize)>,
    arg: usize,
) {
    finish_task_switch();
    if let Some(func) = func {
        func(arg);
        exit_current();
    }
    crate::userspace::exit_to_user(regs);
}

/// `do_task_dead`: the current task is finished. It leaves the CPU for good;
/// the next task releases its slot and stack ([`finish_task_switch`]).
pub fn exit_current() -> ! {
    RQ.lock().exit_current();
    schedule();
    // A dead task is never queued, so `schedule` cannot return here.
    crate::log!("FAIL dead task resumed\n");
    crate::fail()
}

/// Arm `me`'s timed wake-up at `at_ns` and publish the queue head.
fn arm_wake(me: SchedId, at_ns: u64) {
    let mut queue = TIMERQ.lock();
    // The queue holds one entry per task and has a slot for each (`init`).
    assert!(
        queue.insert(at_ns, Timer::Wake(me)).is_ok(),
        "timer queue overflow"
    );
    timer::set_wake_deadline_ns(queue.next_expiry());
}

fn disarm_wake(me: SchedId) {
    let mut queue = TIMERQ.lock();
    if queue.cancel(Timer::Wake(me)) {
        timer::set_wake_deadline_ns(queue.next_expiry());
    }
}

/// One interruptible sleep of the current task (`prepare_to_wait_event` +
/// `schedule` + `finish_wait`; `schedule_hrtimeout` with `wake_at_ns`): it
/// leaves the CPU until [`wake_up_key`] on `key`, a signal wake-up
/// ([`signal_wake_up`]), the monotonic clock reaching `wake_at_ns`, or any
/// other wake-up, then returns so the caller re-checks its condition. A
/// `wake_at_ns` already reached returns at once. `WaitKey::NONE` waits for none
/// of the keys.
///
/// Context: task, IF=0 on entry and exit. The caller has checked its condition
/// and its signals with IF=0 just before, so nothing can wake it between that
/// check and the state change below (single CPU, no preemption of ring 0).
///
/// # Panics
/// Before [`init`], or from the idle task.
pub fn sleep_current(key: WaitKey, wake_at_ns: Option<u64>) {
    debug_assert!(
        !cpu::interrupts_enabled(),
        "sleep_current with interrupts on"
    );
    if wake_at_ns.is_some_and(|at| at <= timer::ktime_get_ns()) {
        return;
    }
    let me = RQ.lock().curr();
    if let Some(at) = wake_at_ns {
        arm_wake(me, at);
    }
    RQ.lock().prepare_to_wait(key, TaskState::Interruptible);
    schedule();
    RQ.lock().finish_wait();
    if wake_at_ns.is_some() {
        disarm_wake(me);
    }
}

/// Wake the sleepers whose timers expired by `now_ns` and publish the new queue
/// head. Both the timer interrupt and the idle loop call it; `in_irq` selects
/// the interrupt-context publication (the handler's own `rearm` programs the
/// clockevent).
fn expire_timers(now_ns: u64, in_irq: bool) {
    loop {
        let mut due = [None; 8];
        let mut count = 0;
        let head = {
            let mut queue = TIMERQ.lock();
            while count < due.len() {
                let Some(entry) = queue.pop_due(now_ns) else {
                    break;
                };
                due[count] = Some(entry);
                count += 1;
            }
            queue.next_expiry()
        };
        if in_irq {
            timer::publish_wake_deadline_ns(head);
        } else {
            timer::set_wake_deadline_ns(head);
        }
        for entry in due.into_iter().flatten() {
            match entry {
                Timer::Wake(id) => {
                    RQ.lock().try_to_wake_up(id);
                }
            }
        }
        if count < due.len() {
            return;
        }
    }
}

/// Timer interrupt (hardirq, IF=0): wake what is due. A no-op before [`init`]
/// (the boot-time proofs tick without a scheduler).
pub fn timer_interrupt(now_ns: u64) {
    if READY.load(Ordering::Acquire) {
        expire_timers(now_ns, true);
    }
}

/// `sched_tick` (hardirq, IF=0): charge the running task's slice. A no-op
/// before [`init`].
pub fn scheduler_tick() {
    if READY.load(Ordering::Acquire) {
        RQ.lock().tick();
    }
}

/// `do_idle` on the boot stack as the idle task: run whatever is runnable,
/// otherwise halt until an interrupt. Returns when `done()` holds with nothing
/// runnable (the self-test), never for `|| false`.
///
/// The queue is drained before every halt, so a deadline that was already due
/// when it was published (and thus never armed in the clockevent) still wakes
/// its sleeper. `timer::idle` is `sti; hlt` with its one-instruction interrupt
/// shadow, so a wake-up cannot slip between the check and the halt.
///
/// # Panics
/// If the current task is not idle.
pub fn idle_loop(done: impl Fn() -> bool) {
    {
        let rq = RQ.lock();
        assert!(rq.curr() == rq.idle(), "idle_loop outside the idle task");
    }
    loop {
        expire_timers(timer::ktime_get_ns(), false);
        if RQ.lock().has_runnable() {
            schedule();
            continue;
        }
        if done() {
            return;
        }
        timer::idle();
    }
}
