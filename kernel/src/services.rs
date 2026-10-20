// SPDX-License-Identifier: GPL-2.0-only
//! Persistent kernel services: state that must outlive `kernel_main`'s frame
//! (the boot stack is reused as init's kernel stack) and be reachable from the
//! syscall and fault paths, in statics with explicit synchronization.
//!
//! # Objects
//! | static | owner of | writers | readers |
//! | --- | --- | --- | --- |
//! | [`BOOT`] | the immutable loader handoff | `kernel_main`, once | any context, lock-free |
//! | [`FRAMES`] | the physical frame allocator (`'static`: it borrows [`BOOT`]) | task context | task context |
//! | [`TABLES`] | the published page tables (the one address space) | task context | task context |
//!
//! # Lock order (the shared DAG; acquire left to right, never the reverse)
//! `userspace::PROCESS` -> [`TABLES`] -> `heap` -> [`FRAMES`], and `PROCESS` ->
//! `TIMER_HW` (a leaf: the clockevent programming of `timer::set_itimer_ns` /
//! `wait_event`, called with `PROCESS` held). [`FRAMES`] is a
//! leaf: it calls nothing that locks. A table operation takes the frame
//! allocator as an argument, so callers lock [`TABLES`] first and pass the
//! [`FRAMES`] guard. `PROCESS` and [`TABLES`] ARE held across a user-memory
//! copy: the copy resolves each page first (`usercopy`), and a non-resident
//! one is faulted in on the spot (`userspace::Syscall::page` ->
//! `handle_user_fault`), which reserves heap storage, then takes [`FRAMES`] as
//! the leaf, i.e. the order above and nothing else (the kernel never
//! dereferences a user address, so no hardware fault occurs under a lock). No
//! lock is held across a callback.
//!
//! One exception, the blocking system calls (`pause`, `rt_sigsuspend`,
//! `rt_sigtimedwait`, `nanosleep`, later blocking `read`): `Task::wait` halts
//! (`sti; hlt`) with `PROCESS` and `TABLES` held, so interrupts are enabled
//! while two `IrqMutex` guards are alive. That is sound only because **no
//! interrupt or exception handler that can run in ring 0 takes `PROCESS`,
//! `TABLES`, the heap or `FRAMES`**: the timer, spurious and error vectors
//! touch only atomics and the clockevent (`TIMER_HW`), and `exit_to_user` is
//! reached only from CPL3 entries, where no kernel lock is held. A handler
//! that needs process state (an IRQ that wakes a reader, a VFS completion)
//! must queue the work and let the waking task take the lock.
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

    /// Remove the installed value so the service can be installed again. Only
    /// the bare-metal suite uses it (one fresh process per test group); the
    /// caller drops the value after the lock is released.
    #[cfg(feature = "baremetal-suite")]
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
