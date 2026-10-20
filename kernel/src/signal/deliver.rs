// SPDX-License-Identifier: GPL-2.0-only
// Linux 6.18.57 (commit 2ff600d29ee478d0a8d46ef8a58afb5e038fe692):
// kernel/signal.c: `get_signal` 2885-3141, `signal_delivered`/
// `signal_setup_done` 3143-3174; arch/x86/kernel/signal.c: `handle_signal`
// 151-199, `get_nr_restart_syscall`, `arch_do_signal_or_restart` 214-253;
// arch/x86/include/asm/syscall.h (`syscall_get_nr`, `syscall_get_error`);
// include/linux/errno.h (`ERESTART*`); kernel/exit.c (`do_group_exit`);
// include/linux/sched/signal.h:540 (`restore_saved_sigmask`). All GPL-2.0.
#![forbid(unsafe_code)]
//! Choosing the next signal, syscall restart rules and handler entry.
//!
//! # Contract
//! * Called from the return-to-user path with the task's `pt_regs` after a
//!   syscall, interrupt or exception, only when [`State::signal_pending`] (or
//!   a restart is possible; calling it when nothing is pending is harmless
//!   and applies the restart rules, as `arch_do_signal_or_restart` does).
//! * Not modelled, named blockers: ptrace stops, group stop/job control (a
//!   default stop action is returned as [`Outcome::Stop`] and must not be
//!   treated as success), core dumps (`RLIMIT_CORE` 0 for init: the exit code
//!   is just the signal), `TIF_SINGLESTEP`, uprobes, cgroup freezer.

use super::{
    AltStack, Cpu, Regs, SA_NODEFER, SA_RESETHAND, SA_RESTART, SIG_DFL, SIG_IGN, SIGKILL,
    SS_AUTODISARM, SigSet,
    frame::{Ksig, enter_handler, setup_rt_frame},
    sig_kernel_coredump, sig_kernel_ignore, sig_kernel_only, sig_kernel_stop,
    state::State,
};
use crate::usercopy::UserPages;

pub const ERESTARTSYS: i64 = 512;
pub const ERESTARTNOINTR: i64 = 513;
pub const ERESTARTNOHAND: i64 = 514;
pub const ERESTART_RESTARTBLOCK: i64 = 516;
const EINTR: i64 = 4;
/// `__NR_restart_syscall` (`x86_64`).
pub const NR_RESTART_SYSCALL: u64 = 219;
const MAX_ERRNO: u64 = 4095;

/// `syscall_get_nr(current, regs) != -1`: did this entry come from a syscall?
/// (`syscall_get_nr` returns `int`.)
#[must_use]
pub const fn from_syscall(regs: &Regs) -> bool {
    #[allow(clippy::cast_possible_truncation)]
    let nr = regs.orig_ax as i32;
    nr != -1
}

/// `syscall_get_error`: `rax` if it is in `-4095..=-1`, else 0.
#[must_use]
pub const fn syscall_error(regs: &Regs) -> i64 {
    if regs.ax >= MAX_ERRNO.wrapping_neg() {
        #[allow(clippy::cast_possible_wrap)]
        {
            regs.ax as i64
        }
    } else {
        0
    }
}

/// The restart rules of `handle_signal`: what an interrupted syscall returns
/// when a handler is about to run. `ERESTART_RESTARTBLOCK` and
/// `ERESTARTNOHAND` become `-EINTR`; `ERESTARTSYS` does too unless the handler
/// has `SA_RESTART`; `ERESTARTNOINTR` and an `SA_RESTART` `ERESTARTSYS` back up
/// over the 2-byte `syscall` instruction and reload the syscall number.
pub fn restart_for_handler(regs: &mut Regs, action_flags: u64) {
    if !from_syscall(regs) {
        return;
    }
    match syscall_error(regs) {
        e if e == -ERESTART_RESTARTBLOCK || e == -ERESTARTNOHAND => {
            regs.ax = EINTR.wrapping_neg().cast_unsigned();
        }
        e if e == -ERESTARTSYS && action_flags & SA_RESTART == 0 => {
            regs.ax = EINTR.wrapping_neg().cast_unsigned();
        }
        e if e == -ERESTARTSYS || e == -ERESTARTNOINTR => {
            regs.ax = regs.orig_ax;
            regs.ip = regs.ip.wrapping_sub(2);
        }
        _ => {}
    }
}

/// The restart rules of `arch_do_signal_or_restart` when no handler runs:
/// every `ERESTART*` restarts; `ERESTART_RESTARTBLOCK` through
/// `restart_syscall`.
pub fn restart_without_handler(regs: &mut Regs) {
    if !from_syscall(regs) {
        return;
    }
    match syscall_error(regs) {
        e if e == -ERESTARTNOHAND || e == -ERESTARTSYS || e == -ERESTARTNOINTR => {
            regs.ax = regs.orig_ax;
            regs.ip = regs.ip.wrapping_sub(2);
        }
        e if e == -ERESTART_RESTARTBLOCK => {
            regs.ax = NR_RESTART_SYSCALL;
            regs.ip = regs.ip.wrapping_sub(2);
        }
        _ => {}
    }
}

/// What `get_signal` decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GetSignal {
    /// Nothing to act on.
    None,
    /// Run a handler.
    Handler(Ksig),
    /// The process dies: `do_group_exit`'s code (the signal number, or the
    /// code recorded when the group exit started). `core` means Linux would
    /// attempt a core dump for this signal.
    Fatal { exit_code: u32, core: bool },
    /// The default action is a group stop (not modelled further).
    Stop(u8),
}

/// `get_signal` for the one task.
pub fn get_signal(state: &mut State) -> GetSignal {
    loop {
        // Has this task already been marked for death?
        if let Some(code) = state.group_exit {
            state.remove_private(SIGKILL);
            return GetSignal::Fatal {
                exit_code: code,
                core: false,
            };
        }
        // Faults first so the saved ip is the faulting instruction.
        let (sig, info) = if let Some(info) = state.dequeue_synchronous() {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            (info.signo as u8, info)
        } else if let Some(next) = state.dequeue_signal() {
            next
        } else {
            return GetSignal::None;
        };
        let action = state.actions[usize::from(sig) - 1];
        if action.handler == SIG_IGN {
            continue;
        }
        if action.handler != SIG_DFL {
            if action.flags & SA_RESETHAND != 0 {
                state.actions[usize::from(sig) - 1].handler = SIG_DFL;
            }
            return GetSignal::Handler(Ksig { sig, info, action });
        }
        // Default action.
        if sig_kernel_ignore(sig) {
            continue;
        }
        // Global init gets no signals it doesn't want.
        if state.unkillable && !sig_kernel_only(sig) {
            continue;
        }
        if sig_kernel_stop(sig) {
            // shortcut: group stop / job control is not modelled; the caller must
            // treat this as unimplemented until the scheduler step exists.
            return GetSignal::Stop(sig);
        }
        let exit_code = state.group_exit_code(u32::from(sig));
        return GetSignal::Fatal {
            exit_code,
            core: sig_kernel_coredump(sig),
        };
    }
}

/// `signal_delivered`: the saved mask now lives in the frame; block the
/// handler's `sa_mask` and (unless `SA_NODEFER`) the signal itself; an
/// `SS_AUTODISARM` stack is disarmed for the handler.
fn signal_delivered(state: &mut State, ksig: &Ksig) {
    state.saved_sigmask = None;
    let mut blocked = SigSet(state.blocked.0 | ksig.action.mask.0);
    if ksig.action.flags & SA_NODEFER == 0 {
        blocked.add(ksig.sig);
    }
    state.set_blocked(blocked);
    if state.altstack.flags & SS_AUTODISARM != 0 {
        state.altstack = AltStack::RESET;
    }
}

/// What the return path must do after [`do_signal_or_restart`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Return to user mode with `regs` as they are (possibly restarted).
    Resume,
    /// `regs` now enter a handler; return to user mode.
    Handled,
    /// The frame could not be built: SIGSEGV was forced and is pending, so
    /// call [`do_signal_or_restart`] again before returning to user mode.
    FrameFailed,
    /// Exit the process with this `exit_code` (`do_exit`).
    Exit { exit_code: u32, core: bool },
    /// Default group stop for this signal.
    Stop(u8),
}

/// `handle_signal`: restart bookkeeping, frame, then the delivered/failed
/// epilogue (`signal_setup_done`).
fn handle_signal<P: UserPages, C: Cpu>(
    state: &mut State,
    regs: &mut Regs,
    ksig: &Ksig,
    pages: &mut P,
    cpu: &mut C,
) -> Outcome {
    restart_for_handler(regs, ksig.action.flags);
    if setup_rt_frame(state, regs, ksig, pages, cpu).is_ok() {
        enter_handler(regs, cpu);
        signal_delivered(state, ksig);
        Outcome::Handled
    } else {
        state.force_sigsegv(ksig.sig);
        Outcome::FrameFailed
    }
}

/// `exit_to_user_mode_loop`'s signal part: `arch_do_signal_or_restart` runs
/// again while signals remain deliverable, so several pending, unblocked
/// signals each push a frame before any handler runs (the newest frame, i.e.
/// the highest-numbered signal, runs first; the oracle's
/// `order-unmasked-handlers-run-newest-frame-first`). The final outcome is
/// returned; `Exit`/`Stop` end the loop at once.
pub fn handle_pending_signals<P: UserPages, C: Cpu>(
    state: &mut State,
    regs: &mut Regs,
    pages: &mut P,
    cpu: &mut C,
) -> Outcome {
    loop {
        let outcome = do_signal_or_restart(state, regs, pages, cpu);
        if matches!(outcome, Outcome::Handled | Outcome::FrameFailed) && state.signal_pending() {
            continue;
        }
        return outcome;
    }
}

/// `arch_do_signal_or_restart`: one signal. The return path must use
/// [`handle_pending_signals`] unless it loops itself.
pub fn do_signal_or_restart<P: UserPages, C: Cpu>(
    state: &mut State,
    regs: &mut Regs,
    pages: &mut P,
    cpu: &mut C,
) -> Outcome {
    match get_signal(state) {
        GetSignal::Handler(ksig) => handle_signal(state, regs, &ksig, pages, cpu),
        GetSignal::Fatal { exit_code, core } => Outcome::Exit { exit_code, core },
        GetSignal::Stop(sig) => Outcome::Stop(sig),
        GetSignal::None => {
            restart_without_handler(regs);
            // restore_saved_sigmask: no handler consumed the saved mask.
            if let Some(mask) = state.saved_sigmask.take() {
                state.set_blocked(mask);
            }
            Outcome::Resume
        }
    }
}
