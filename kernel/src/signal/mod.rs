// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: kernel/signal.c,
// include/linux/signal.h, include/linux/signal_types.h,
// include/linux/sched/signal.h, arch/x86/kernel/signal.c,
// arch/x86/kernel/signal_64.c, arch/x86/kernel/fpu/signal.c,
// arch/x86/include/asm/{sigframe,signal,sighandling,ptrace,segment}.h,
// arch/x86/include/uapi/asm/{sigcontext,signal,ucontext}.h,
// include/uapi/asm-generic/{signal,signal-defs,siginfo,ucontext}.h,
// arch/x86/kernel/traps.c, arch/x86/mm/fault.c, kernel/exit.c. All GPL-2.0
// (uapi headers GPL-2.0 WITH Linux-syscall-note).
// Transformation: one thread group of one thread (pid == tgid == tid), so the
// per-thread/shared queues, `siglock`, wakeups, ptrace, posix
// timers, signalfd, `sigtimedwait` and the x32/ia32 frames are not modelled;
// x86_64 native frames (FXSR-only state under `noxsave`, the XSAVE standard format otherwise) are.
#![forbid(unsafe_code)]
//! Linux signal semantics for `x86_64` as pure, host-tested logic (`WP-M3.4`).
//!
//! Nothing here touches hardware: user memory goes through the one
//! [`crate::usercopy`] mechanism, FPU/segment facts through the [`Cpu`] trait,
//! and the register file is [`Regs`], which the binary uses as its `PtRegs`
//! (one type). The binary implements [`Cpu`] (`XSAVE`/`XRSTOR`/`FXSAVE`/`FXRSTOR`/`PKRU`/`LAR`) and
//! [`Task`], calls [`deliver::handle_pending_signals`] on every return to user
//! mode and the `sys_*` functions of [`syscalls`], [`wait`] and [`itimer`] from
//! the syscall dispatcher.
//!
//! # Contract
//! * Context: task context of the one user task; no sleeping, no allocation,
//!   no locks. [`State`] is the combination of `sighand`, `signal_struct` and
//!   the task's signal fields that Linux protects with `siglock`; the caller
//!   serialises access (one task, one CPU today).
//! * Locking: if a second task or CPU appears, `State` needs its `siglock`
//!   (IRQ-safe spinlock) above `tasklist_lock`'s successors exactly as in
//!   `kernel/signal.c`; the lock order is then recorded in the process plan.
//! * Errors are returned as `-errno` in `i64`, exactly the value Linux puts in
//!   `rax`.

pub mod deliver;
pub mod frame;
pub mod info;
pub mod itimer;
pub mod jobctl;
pub mod state;
pub mod syscalls;
pub mod wait;

#[cfg(test)]
mod linux_frames;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod xsave_tests;

pub use crate::exec::report::{SIGBUS, SIGFPE, SIGILL, SIGSEGV, SIGTRAP};

pub const SIGHUP: u8 = 1;
pub const SIGINT: u8 = 2;
pub const SIGQUIT: u8 = 3;
pub const SIGABRT: u8 = 6;
pub const SIGKILL: u8 = 9;
pub const SIGUSR1: u8 = 10;
pub const SIGUSR2: u8 = 12;
pub const SIGPIPE: u8 = 13;
pub const SIGALRM: u8 = 14;
pub const SIGTERM: u8 = 15;
pub const SIGCHLD: u8 = 17;
pub const SIGCONT: u8 = 18;
pub const SIGSTOP: u8 = 19;
pub const SIGTSTP: u8 = 20;
pub const SIGTTIN: u8 = 21;
pub const SIGTTOU: u8 = 22;
pub const SIGURG: u8 = 23;
pub const SIGXCPU: u8 = 24;
pub const SIGXFSZ: u8 = 25;
pub const SIGWINCH: u8 = 28;
pub const SIGSYS: u8 = 31;
/// `SIGRTMIN` of the kernel (`arch/x86/include/uapi/asm/signal.h`).
pub const SIGRTMIN: u8 = 32;
/// `_NSIG` (`arch/x86/include/asm/signal.h`); also `SIGRTMAX`.
pub const NSIG: u8 = 64;

/// `SIG_DFL` / `SIG_IGN` (`include/uapi/asm-generic/signal-defs.h`).
pub const SIG_DFL: u64 = 0;
pub const SIG_IGN: u64 = 1;

pub const SA_NOCLDSTOP: u64 = 0x1;
pub const SA_NOCLDWAIT: u64 = 0x2;
pub const SA_SIGINFO: u64 = 0x4;
pub const SA_EXPOSE_TAGBITS: u64 = 0x800;
pub const SA_RESTORER: u64 = 0x0400_0000;
pub const SA_ONSTACK: u64 = 0x0800_0000;
pub const SA_RESTART: u64 = 0x1000_0000;
pub const SA_NODEFER: u64 = 0x4000_0000;
pub const SA_RESETHAND: u64 = 0x8000_0000;
/// Internal, never user-visible (`include/linux/signal_types.h`).
pub const SA_IMMUTABLE: u64 = 0x0080_0000;
/// `UAPI_SA_FLAGS`: the only bits `rt_sigaction` keeps or reports.
pub const UAPI_SA_FLAGS: u64 = SA_NOCLDSTOP
    | SA_NOCLDWAIT
    | SA_SIGINFO
    | SA_ONSTACK
    | SA_RESTART
    | SA_NODEFER
    | SA_RESETHAND
    | SA_EXPOSE_TAGBITS
    | SA_RESTORER;

pub const SS_ONSTACK: u32 = 1;
pub const SS_DISABLE: u32 = 2;
pub const SS_AUTODISARM: u32 = 1 << 31;
/// `SS_FLAG_BITS`: flag bits that ride along with the mode.
pub const SS_FLAG_BITS: u32 = SS_AUTODISARM;
/// `MINSIGSTKSZ` (`arch/x86/include/uapi/asm/signal.h`).
pub const MINSIGSTKSZ: u64 = 2048;

/// A signal set: `sigset_t` with `_NSIG_WORDS == 1`. Bit `n - 1` is signal `n`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SigSet(pub u64);

impl SigSet {
    pub const EMPTY: Self = Self(0);

    /// `sigmask(sig)`; 0 for a number outside `1..=64`, so that every set
    /// operation is total (callers still range-check what user space sends).
    #[must_use]
    pub const fn bit(sig: u8) -> u64 {
        if sig == 0 || sig > NSIG {
            0
        } else {
            1 << (sig - 1)
        }
    }
    #[must_use]
    pub const fn contains(self, sig: u8) -> bool {
        self.0 & Self::bit(sig) != 0
    }
    pub const fn add(&mut self, sig: u8) {
        self.0 |= Self::bit(sig);
    }
    pub const fn remove(&mut self, sig: u8) {
        self.0 &= !Self::bit(sig);
    }
    /// `sigdelsetmask(set, sigmask(SIGKILL) | sigmask(SIGSTOP))`.
    #[must_use]
    pub const fn without_unblockable(self) -> Self {
        Self(self.0 & !(Self::bit(SIGKILL) | Self::bit(SIGSTOP)))
    }
}

/// `N` bytes of `bytes` at `at`, for decoding little-endian fields.
pub(crate) fn le<const N: usize>(bytes: &[u8], at: usize) -> [u8; N] {
    let mut out = [0; N];
    out.copy_from_slice(&bytes[at..at + N]);
    out
}

/// `siginmask(sig, mask)` for the `SIG_KERNEL_*` masks: only classic signals.
pub(crate) const fn in_mask(sig: u8, mask: u64) -> bool {
    sig > 0 && sig < SIGRTMIN && SigSet::bit(sig) & mask != 0
}
const KERNEL_ONLY: u64 = SigSet::bit(SIGKILL) | SigSet::bit(SIGSTOP);
const KERNEL_STOP: u64 =
    SigSet::bit(SIGSTOP) | SigSet::bit(SIGTSTP) | SigSet::bit(SIGTTIN) | SigSet::bit(SIGTTOU);
const KERNEL_COREDUMP: u64 = SigSet::bit(SIGQUIT)
    | SigSet::bit(SIGILL)
    | SigSet::bit(SIGTRAP)
    | SigSet::bit(SIGABRT)
    | SigSet::bit(SIGFPE)
    | SigSet::bit(SIGSEGV)
    | SigSet::bit(SIGBUS)
    | SigSet::bit(SIGSYS)
    | SigSet::bit(SIGXCPU)
    | SigSet::bit(SIGXFSZ);
const KERNEL_IGNORE: u64 =
    SigSet::bit(SIGCONT) | SigSet::bit(SIGCHLD) | SigSet::bit(SIGWINCH) | SigSet::bit(SIGURG);
/// `SYNCHRONOUS_MASK` (`kernel/signal.c`): dequeued before everything else.
const SYNCHRONOUS: u64 = SigSet::bit(SIGSEGV)
    | SigSet::bit(SIGBUS)
    | SigSet::bit(SIGILL)
    | SigSet::bit(SIGTRAP)
    | SigSet::bit(SIGFPE)
    | SigSet::bit(SIGSYS);

#[must_use]
pub const fn sig_kernel_only(sig: u8) -> bool {
    in_mask(sig, KERNEL_ONLY)
}
#[must_use]
pub const fn sig_kernel_stop(sig: u8) -> bool {
    in_mask(sig, KERNEL_STOP)
}
#[must_use]
pub const fn sig_kernel_coredump(sig: u8) -> bool {
    in_mask(sig, KERNEL_COREDUMP)
}
#[must_use]
pub const fn sig_kernel_ignore(sig: u8) -> bool {
    in_mask(sig, KERNEL_IGNORE)
}

/// `valid_signal(sig)` for the `int` the syscalls receive: `0..=_NSIG`.
#[must_use]
pub const fn valid_signal(sig: i32) -> bool {
    sig >= 0 && sig <= NSIG as i32
}

/// The kernel `struct sigaction` of `x86_64` (`__ARCH_HAS_SA_RESTORER` layout:
/// handler, flags, restorer, mask), 32 bytes, as `rt_sigaction` exchanges it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SigAction {
    pub handler: u64,
    pub flags: u64,
    pub restorer: u64,
    pub mask: SigSet,
}

impl SigAction {
    pub const SIZE: usize = 32;

    #[must_use]
    pub fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut out = [0; Self::SIZE];
        out[0..8].copy_from_slice(&self.handler.to_le_bytes());
        out[8..16].copy_from_slice(&self.flags.to_le_bytes());
        out[16..24].copy_from_slice(&self.restorer.to_le_bytes());
        out[24..32].copy_from_slice(&self.mask.0.to_le_bytes());
        out
    }

    #[must_use]
    pub fn from_bytes(bytes: &[u8; Self::SIZE]) -> Self {
        let word = |at: usize| u64::from_le_bytes(le(bytes, at));
        Self {
            handler: word(0),
            flags: word(8),
            restorer: word(16),
            mask: SigSet(word(24)),
        }
    }

    /// `sig_handler_ignored`: explicitly, or implicitly by the default action.
    #[must_use]
    pub const fn ignored(&self, sig: u8) -> bool {
        self.handler == SIG_IGN || (self.handler == SIG_DFL && sig_kernel_ignore(sig))
    }
}

/// `current->sas_ss_{sp,size,flags}`. The flags are the *stored* ones: the
/// mode the user passed plus `SS_AUTODISARM`, `SS_DISABLE` after a reset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AltStack {
    pub sp: u64,
    pub size: u64,
    pub flags: u32,
}

impl AltStack {
    /// `sas_ss_reset`.
    pub const RESET: Self = Self {
        sp: 0,
        size: 0,
        flags: SS_DISABLE,
    };

    /// `__on_sig_stack` (stack grows down).
    #[must_use]
    pub const fn contains(&self, sp: u64) -> bool {
        sp > self.sp && sp.wrapping_sub(self.sp) <= self.size
    }
    /// `on_sig_stack`: `SS_AUTODISARM` makes the answer always "no".
    #[must_use]
    pub const fn on_stack(&self, sp: u64) -> bool {
        self.flags & SS_AUTODISARM == 0 && self.contains(sp)
    }
    /// `sas_ss_flags(sp)`.
    #[must_use]
    pub const fn ss_flags(&self, sp: u64) -> u32 {
        if self.size == 0 {
            SS_DISABLE
        } else if self.on_stack(sp) {
            SS_ONSTACK
        } else {
            0
        }
    }
}

/// `struct pt_regs` (`arch/x86/include/asm/ptrace.h`), lowest address first:
/// exactly the frame the binary's entry stubs push and `iretq` consumes, and
/// the binary's `PtRegs` (`pub use ... as PtRegs`), so a handler entry or
/// `rt_sigreturn` edits the live return frame in place.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Regs {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub bp: u64,
    pub bx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub ax: u64,
    pub cx: u64,
    pub dx: u64,
    pub si: u64,
    pub di: u64,
    pub orig_ax: u64,
    pub ip: u64,
    pub cs: u64,
    pub flags: u64,
    pub sp: u64,
    pub ss: u64,
}

/// `__USER_CS` / `__USER_DS` of `x86_64` (`arch/x86/include/asm/segment.h`:
/// GDT entries 6 and 5, RPL 3).
pub const USER_CS: u64 = 0x33;
pub const USER_DS: u64 = 0x2b;

/// What the signal code needs from the CPU, supplied by the binary.
///
/// The user FPU/`XSAVE` state is live in the registers whenever the kernel runs (the kernel is
/// soft-float and saves a task's state only when it is switched out), so the signal code asks
/// the CPU for it. Every method that moves state works on the *standard* format of
/// [`crate::xstate::Config`], which is what the user-space signal frame holds.
pub trait Cpu {
    /// The enabled extended state: save instruction, component placement, sizes (fixed after
    /// boot).
    fn xstate(&self) -> crate::xstate::Config;
    /// `XSAVE` (all enabled components, standard format) of the live state into `area`, or
    /// `FXSAVE` into its first 512 bytes without `XSAVE`: the hardware's own writes, so only
    /// the bytes `XSAVE` writes change. The caller made the header zero (and for `FXSAVE`
    /// pre-filled nothing): reserved legacy bytes the hardware leaves alone keep their value.
    fn xsave(&mut self, area: &mut crate::xstate::XsaveArea);
    /// `XRSTOR` of the standard-format `area` with request mask `rfbm`; `false` when the CPU
    /// refuses the area (the `#GP` of a bad header or reserved `MXCSR` bit, which the binary
    /// recovers from). On `false` the registers are indeterminate: the caller resets them.
    fn xrstor(&mut self, area: &crate::xstate::XsaveArea, rfbm: u64) -> bool;
    /// `FXRSTOR` of the first 512 bytes of `area` (the legacy restore of a frame with no valid
    /// `XSAVE` description, and the only restore without `XSAVE`); `false` for a reserved
    /// `MXCSR` bit (`#GP`). The 64-byte alignment rule of `XRSTOR` does not apply.
    fn fxrstor(&mut self, area: &crate::xstate::XsaveArea) -> bool;
    /// `os_xrstor(&init_fpstate, mask)`: put the components in `mask` into their initial
    /// configuration (including `PKRU` to 0 when it is in `mask`).
    fn restore_init(&mut self, mask: u64);
    /// `fpu__clear_user_states`: user FPU state back to the init state, `PKRU` to
    /// `init_pkru_value`.
    fn fpu_reset(&mut self);
    /// `read_pkru()`: 0 without `OSPKE`.
    fn read_pkru(&self) -> u32;
    /// `write_pkru()`: nothing without `OSPKE`.
    fn write_pkru(&mut self, pkru: u32);
    /// The `lar` test of `force_valid_ss`. The access rights are masked with
    /// `AR_DPL_MASK | AR_S | AR_P | AR_TYPE_MASK` (`AR_TYPE_MASK` = bits 9-11,
    /// so the accessed bit is ignored) and must equal DPL 3, S, P with type
    /// `RWDATA` (`1 << 9`) or `RWDATA_EXPDOWN` (`3 << 9`): raw descriptor types
    /// 2, 3, 6 and 7. A failing `lar` (`ZF` clear) counts as access rights 0.
    fn ss_is_valid_user_data(&self, ss: u16) -> bool;
}

pub use crate::sched::WaitKey;
pub use state::{Ids, State, TaskSignals};

/// The task the signal syscalls and the blocking waits run for: the binary's
/// process (and the host tests' fake). `parts` hands out the two disjoint
/// borrows the pure functions need.
pub trait Task {
    /// The user-memory view (`crate::usercopy`) the signal code writes frames
    /// and results through: for a task whose address space can fault pages in,
    /// the view that does (a kernel access to a non-resident page takes the
    /// fault Linux would).
    type Pages<'a>: crate::usercopy::UserPages
    where
        Self: 'a;
    /// The signal state alone.
    fn state(&mut self) -> State<'_>;
    /// The signal state and user memory, borrowed together.
    fn parts(&mut self) -> (State<'_>, Self::Pages<'_>);
    /// `CLOCK_MONOTONIC` in nanoseconds (`ktime_get`).
    fn now_ns(&self) -> u64;
    /// `schedule()` for one wake-up: sleep (interruptibly) on `key` until a
    /// wake-up of that key, a signal, the monotonic clock reaching `deadline_ns`
    /// (`None`: no deadline) or any other wake-up, then return; the caller
    /// re-checks its condition, so a spurious return is harmless. A deadline
    /// already reached returns at once. The implementation arms the
    /// `ITIMER_REAL` expiry of `State::itimer` as a wake-up source too. Context:
    /// task, interrupts masked on entry and exit.
    fn wait(&mut self, key: WaitKey, deadline_ns: Option<u64>);
    /// `regs->sp` at syscall entry (`sigaltstack`'s `on_sig_stack` argument).
    fn user_sp(&self) -> u64;
    /// `frame::rt_sigreturn` on the entry registers, the state and user memory
    /// (the binary owns the registers and the `Cpu`).
    fn rt_sigreturn(&mut self) -> frame::Sigreturn;
}
