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
//! `userspace::PROCESS` -> [`TABLES`] -> `heap` -> [`FRAMES`]. [`FRAMES`] is a
//! leaf: it calls nothing that locks. A table operation takes the frame
//! allocator as an argument, so callers lock [`TABLES`] first and pass the
//! [`FRAMES`] guard. No lock is held across a user-memory copy that could
//! fault (the kernel never touches user addresses, see `usercopy`), a callback
//! or a blocking operation; nothing here sleeps.
//!
//! # Contexts
//! Every lock is [`IrqMutex`]: it disables local interrupts for the critical
//! section, so a handler can never deadlock against an interrupted holder on
//! one CPU. NMI, #DF and #MC are not excluded and MUST NOT take these locks.
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
    /// holder (not reentrant: the second call would spin forever).
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
