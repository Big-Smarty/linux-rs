// SPDX-License-Identifier: GPL-2.0-only
//! Persistent kernel services: state that must outlive `kernel_main`'s frame
//! (the boot stack becomes the idle task's, init runs on a pool stack) and be
//! reachable from the syscall and fault paths, in statics with explicit
//! synchronization.
//!
//! # Objects
//! | static | owner of | writers | readers |
//! | --- | --- | --- | --- |
//! | [`BOOT`] | the immutable loader handoff | `kernel_main`, once | any context, lock-free |
//! | [`FRAMES`] | the physical frame allocator (`'static`: it borrows [`BOOT`]) | task context | task context |
//! | [`TABLES`] | the kernel-only page tables: the template every task's tree copies its kernel half from, and the tree CR3 holds while no task's may be | `userspace::start`, once | task context |
//! | `userspace::PROCESS` | what every task shares: the task list and the VFS | task context | task context |
//! | `userspace::LOCALS` | the page tables, memory model, descriptor table and attributes of each task, reached only by that task | the task itself (its creator before it runs) | the task itself |
//! | `ktask::RQ` | the run queue: task states, wait keys, FIFO order (`kernel::sched::Rq`) | task context, tick/timer hardirq | task context, hardirq |
//! | `ktask::TIMERQ` | absolute wake-up times of sleeping tasks (`kernel::sched::timerq`) | task context, timer hardirq | task context, hardirq |
//!
//! # Lock order (the shared DAG; acquire left to right, never the reverse)
//! `userspace::PROCESS` -> `heap` -> [`FRAMES`], and `PROCESS` -> `TIMER_HW` (a
//! leaf: the clockevent programming of `timer::set_itimer_ns`, called with
//! `PROCESS` held). [`TABLES`] is taken alone (a copy of its kernel half, a
//! group load) and before [`FRAMES`]. The scheduler adds two classes (`ktask`):
//! `RQ` is a **leaf that may be taken under any lock and from hardirq** (it only
//! mutates the queue and returns; wakers call out of nothing), and `TIMERQ` ->
//! `TIMER_HW` (arming the clockevent for the queue head under the queue lock).
//! `TIMERQ` and `RQ` are never held together: the expiry drains due entries
//! under `TIMERQ`, releases it, then wakes under `RQ`. So the edges are
//! `PROCESS`/`heap` -> `RQ`, `PROCESS` -> `TIMERQ` -> `TIMER_HW`, and no edge
//! leaves `RQ`. [`FRAMES`] is a leaf: it calls nothing that locks. A table
//! operation takes the frame allocator as an argument, so callers pass the
//! [`FRAMES`] guard; the tables a task edits are those of its `mm`
//! (`userspace::MmStruct`, a counted slot of `Process`, so under `PROCESS`), and a
//! copy of them for a fork is made by the parent with `FRAMES` held and no heap
//! allocation. `PROCESS` is held across a
//! user-memory copy: the copy resolves each page first (`usercopy`), and a
//! non-resident one is faulted in on the spot (`userspace::Syscall::page` ->
//! `handle_user_fault`), which reserves heap storage, then takes [`FRAMES`] as
//! the leaf, i.e. the order above and nothing else (the kernel never
//! dereferences a user address, so no hardware fault occurs under a lock). No
//! lock is held across a callback. A `/proc` read (`userspace::host_info`) takes
//! two more leaves under `PROCESS`: `LOAD` (the load-average samples) and the
//! `cpu_facts` cache (the CPUID snapshot of `/proc/cpuinfo`); each calls out of
//! nothing, so the edges are `PROCESS` -> `LOAD` and `PROCESS` -> `cpu_facts`,
//! and no edge leaves either.
//!
//! # Lock-order DAG for the task lane (designed before the code that needs it)
//! The task list ([`kernel::task::Tasklist`]: tasks, pids, process groups,
//! sessions, credential snapshots, the signal objects of every task) is
//! **inside** `PROCESS` and has no lock of its own, so it takes part in
//! the order above as part of `PROCESS`. The order the design in
//! `docs/subsystems/process.md#lock-order-and-non-parity-table-for-the-task-lane`
//! commits to, which every later task/scheduler/VFS change extends, is:
//!
//! ```text
//! TASKLIST -> VFS -> heap -> FRAMES        (TASKLIST = tasklist_lock + siglock + pidmap_lock)
//! TABLES -> FRAMES                          (the kernel template tree; a task's own tables are no lock)
//! TASKLIST -> TIMERQ -> TIMER_HW
//! any lock -> RQ                           (RQ: scheduler run queue, a leaf, callable from hardirq)
//! ```
//!
//! `VFS -> TASKLIST` is forbidden (a pipe write sends `SIGPIPE` after the VFS
//! borrow ends), `TIMERQ -> TASKLIST` is forbidden (expiry drains under
//! `TIMERQ`, acts after releasing it), and no guard may be alive across
//! `schedule()`. Until the VFS is promoted out of `Process` (its comment in
//! `userspace`), `PROCESS` stands for `TASKLIST` and `VFS` together; nothing
//! in the task model calls out under it, so the promotion only splits the
//! lock. [`kernel::task::exit::Waker`] is the seam through which the model
//! asks for wake-ups: an implementation may take `RQ` and nothing else.
//! The binary's implementation is `userspace::SchedWaker`: `child_event` wakes
//! the parent's `wait_chldexit` key and `signal_wake` wakes the task, both
//! through `ktask` (`RQ` only).
//!
//! **No guard is alive across `schedule()`.** A system call takes `PROCESS`
//! lazily (`userspace::Shared`) and `Task::wait` drops it before the task
//! leaves the CPU (`sleep_current`), so another task can run system calls while
//! this one sleeps; the next access takes it again and re-reads everything, as
//! Linux's `wait_event` does. The borrow checker enforces it: every view of the
//! shared state borrows the `Syscall` mutably and `wait` takes `&mut self`. What
//! only the running task touches (`TaskLocal`) is not under any lock, and its
//! per-slot busy flag turns a second simultaneous access into a loud stop. No
//! interrupt or exception handler that can run in ring 0 takes `PROCESS`, the
//! heap or [`FRAMES`]: the timer, spurious and error vectors touch only atomics,
//! the clockevent (`TIMER_HW`) and the scheduler queues, and `exit_to_user` is
//! reached only from CPL3 entries, where no kernel lock is held. A handler that
//! needs process state (an IRQ that wakes a reader, a VFS completion) must queue
//! the work and let the waking task take the lock.
//!
//! `userspace::VFORK_DONE` (the flag a `vfork` child sets for its sleeping parent, by the
//! parent's slot) is a leaf under `PROCESS`: nothing is acquired while it is held, and the
//! wake-up of the parent is made after the guard is dropped (`PROCESS` -> `VFORK_DONE`, then
//! `PROCESS` -> `RQ`). The address spaces, descriptor tables and filesystem contexts that tasks
//! share by `clone` flag, and the futex queue, are fields of `Process` and so under `PROCESS`
//! (no lock of their own): `PROCESS` -> heap -> `FRAMES` covers their allocation, which is
//! reserved before any `FRAMES` guard is taken.
//!
//! The bare-metal suite (`baremetal-suite` only) adds `baremetal::ARCHIVES`
//! in front of the chain: it is held across `userspace::load_group`, so the
//! order is `ARCHIVES` -> [`TABLES`] -> `heap` -> [`FRAMES`]; nothing takes it
//! while holding any of them. `baremetal::RESULTS` is a leaf.
//!
//! # The rule that is easy to break
//! [`FRAMES`] is a leaf, and the heap takes it to grow. So **never allocate
//! from the heap (`Vec::try_reserve`, `Box::try_new`, ...) while holding a
//! [`FRAMES`] guard**: the heap lock is held first by the allocation, the
//! grow path then needs `FRAMES`, which the caller holds, and a spinlock with
//! interrupts masked would spin forever. Reserve heap memory first, then lock
//! `FRAMES` (e.g. `try_reserve` the VMA `Vec`, then call `mm_map_anon`). The
//! grow path does not spin: it uses [`Service::try_lock`] and panics (a
//! `FAIL panic` line, then the boot stops) when `FRAMES` is held, which on
//! one CPU can only be this violation.
//! shortcut: with SMP a held `FRAMES` may belong to another CPU and the grow
//! path must spin unless the owner is the current CPU (record the owner CPU).
//!
//! # Contexts
//! Every lock is [`IrqMutex`]: it disables local interrupts for the critical
//! section, so a handler can never deadlock against an interrupted holder on
//! one CPU (except inside the halt of a blocking wait: see above). NMI, #DF and #MC are not excluded and MUST NOT take these locks.
//! shortcut: single CPU; the spinlock inside already excludes other CPUs but
//! per-CPU state, TLB shootdown (see `paging`) and lock-class diagnostics are
//! not built, upgrade with SMP bring-up.

use crate::{
    cpu::{IrqSpinGuard, IrqSpinLock},
    memory::Allocator,
    paging::Tables,
};
use core::{
    cell::UnsafeCell,
    mem::MaybeUninit,
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicU8, Ordering},
};
use kernel::boot::BootInfo;

/// A mutex that also masks local interrupts while held.
pub struct IrqMutex<T> {
    lock: IrqSpinLock,
    value: UnsafeCell<T>,
}

// SAFETY: `value` is reached only through a guard, which holds `lock`: the
// atomic spinlock excludes other CPUs and the interrupt mask excludes handlers
// and (with no scheduler) every other context on this CPU. `T: Send` is what
// makes handing the payload to whichever CPU takes the lock sound.
unsafe impl<T: Send> Sync for IrqMutex<T> {}

impl<T> IrqMutex<T> {
    pub const fn new(value: T) -> Self {
        Self {
            lock: IrqSpinLock::new(),
            value: UnsafeCell::new(value),
        }
    }

    /// Mask local interrupts and take the lock. Must not be called again by the
    /// holder (not reentrant: the second call would spin forever; use
    /// [`IrqMutex::try_lock`] where a bug could make that happen).
    pub fn lock(&self) -> IrqMutexGuard<'_, T> {
        let guard = self.lock.lock();
        // SAFETY: the lock is held for the guard's whole lifetime, so this is
        // the only reference to the payload; it dies before the lock does
        // (`IrqMutexGuard`'s field order).
        let value = unsafe { &mut *self.value.get() };
        IrqMutexGuard {
            value,
            _held: guard,
        }
    }
}

impl<T> IrqMutex<T> {
    /// Take the lock if it is free; interrupts are restored on failure.
    pub fn try_lock(&self) -> Option<IrqMutexGuard<'_, T>> {
        let guard = self.lock.try_lock()?;
        // SAFETY: as in `lock`.
        let value = unsafe { &mut *self.value.get() };
        Some(IrqMutexGuard {
            value,
            _held: guard,
        })
    }
}

#[must_use = "dropping the guard releases the lock and restores interrupts"]
pub struct IrqMutexGuard<'a, T> {
    value: &'a mut T,
    // Dropped after `value` is dead: unlock, then restore IF (cpu.rs ordering).
    _held: IrqSpinGuard<'a>,
}

impl<T> Deref for IrqMutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.value
    }
}
impl<T> DerefMut for IrqMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.value
    }
}

/// An [`IrqMutex`] whose payload is installed once, after static
/// initialization. Using it before `install` is a kernel bug and panics.
pub struct Service<T>(IrqMutex<Option<T>>);

impl<T: Send> Service<T> {
    pub const fn new() -> Self {
        Self(IrqMutex::new(None))
    }

    /// # Panics
    /// If a value is already installed.
    pub fn install(&self, value: T) {
        let mut slot = self.0.lock();
        assert!(slot.is_none(), "kernel service installed twice");
        *slot = Some(value);
    }

    /// # Panics
    /// If nothing was installed yet.
    pub fn lock(&self) -> ServiceGuard<'_, T> {
        let guard = self.0.lock();
        assert!(guard.is_some(), "kernel service used before install");
        ServiceGuard(guard)
    }

    /// Remove the installed value so the service can be installed again: the
    /// bare-metal suite (one fresh process per test group) and `userspace::start`
    /// (the published page tables become init's own). The caller drops the
    /// value after the lock is released.
    pub fn take(&self) -> Option<T> {
        self.0.lock().take()
    }

    /// Whether the lock is free right now (an uninstalled service is free). The
    /// suite asks before it ends a group after a kernel stop: a lock still held
    /// by the abandoned stack could never be released.
    #[cfg(feature = "baremetal-suite")]
    pub fn is_free(&self) -> bool {
        self.0.try_lock().is_some()
    }

    /// Whether a value was installed. A held lock means it was (the holder
    /// found it installed), so this never spins and never panics.
    pub fn is_installed(&self) -> bool {
        self.0.try_lock().is_none_or(|slot| slot.is_some())
    }

    /// Like [`Service::lock`] but `None` when the service is locked. On this
    /// single-CPU cell, with interrupts masked inside every critical section,
    /// `None` can only mean the caller already holds it: a lock-order bug.
    ///
    /// # Panics
    /// If nothing was installed yet.
    pub fn try_lock(&self) -> Option<ServiceGuard<'_, T>> {
        let guard = self.0.try_lock()?;
        assert!(guard.is_some(), "kernel service used before install");
        Some(ServiceGuard(guard))
    }
}

#[must_use = "dropping the guard releases the lock and restores interrupts"]
pub struct ServiceGuard<'a, T>(IrqMutexGuard<'a, Option<T>>);

impl<T> Deref for ServiceGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        match &*self.0 {
            Some(value) => value,
            None => unreachable!("checked non-empty when locked"),
        }
    }
}
impl<T> DerefMut for ServiceGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        match &mut *self.0 {
            Some(value) => value,
            None => unreachable!("checked non-empty when locked"),
        }
    }
}

/// Write-once, lock-free-read storage with a `'static` borrow.
pub struct Once<T> {
    state: AtomicU8,
    value: UnsafeCell<MaybeUninit<T>>,
}

const EMPTY: u8 = 0;
const WRITING: u8 = 1;
const READY: u8 = 2;

// SAFETY: the payload is written exactly once, by the thread that moved
// `state` EMPTY -> WRITING, and published with a Release store of READY;
// readers Acquire-load READY before forming a shared reference and the
// payload is never mutated afterwards. Sharing `&T` needs `T: Sync`, moving
// the value in needs `T: Send`.
unsafe impl<T: Send + Sync> Sync for Once<T> {}

impl<T> Once<T> {
    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(EMPTY),
            value: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    /// # Panics
    /// If called a second time (a kernel bug: there is one handoff).
    pub fn init(&'static self, value: T) -> &'static T {
        let first =
            self.state
                .compare_exchange(EMPTY, WRITING, Ordering::Acquire, Ordering::Relaxed);
        assert!(first.is_ok(), "kernel service installed twice");
        // SAFETY: the transition above makes this the only writer, and no
        // reader dereferences before READY.
        let slot = unsafe { (*self.value.get()).write(value) };
        self.state.store(READY, Ordering::Release);
        slot
    }

    /// # Panics
    /// If `init` has not completed.
    pub fn get(&'static self) -> &'static T {
        assert!(
            self.state.load(Ordering::Acquire) == READY,
            "kernel service used before install"
        );
        // SAFETY: READY (Acquire) happens-after the initializing write and the
        // value is immutable and never dropped from here on.
        unsafe { (*self.value.get()).assume_init_ref() }
    }
}

/// The loader handoff, installed once by `kernel_main`.
pub static BOOT: Once<BootInfo> = Once::new();
/// The physical frame allocator. It borrows [`BOOT`], hence `'static`.
pub static FRAMES: Service<Allocator<'static>> = Service::new();
/// The published page tables: the single address space (kernel half plus the
/// user half of the one process), see `paging` for the update rules.
pub static TABLES: Service<Tables> = Service::new();

/// The loader handoff.
///
/// # Panics
/// Before `kernel_main` installs it.
pub fn boot() -> &'static BootInfo {
    BOOT.get()
}
