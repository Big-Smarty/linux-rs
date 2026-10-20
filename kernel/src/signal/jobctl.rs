// SPDX-License-Identifier: GPL-2.0-only
// Linux 6.18.57 (commit 2ff600d29ee478d0a8d46ef8a58afb5e038fe692), all
// GPL-2.0: kernel/signal.c (`task_set_jobctl_pending` 280, `task_clear_jobctl_pending`
// 332, `task_participate_group_stop` 361, `prepare_signal` 895-968,
// `wants_signal` 970-985, `do_signal_stop` 2636-2722, `get_signal` 2885-3141),
// include/linux/sched/jobctl.h (`JOBCTL_*`), include/linux/sched/signal.h
// (`SIGNAL_*` flags 260-279, `signal_set_stop_flags`).
// Transformation: one thread per group, so `group_stop_count` is 0 or 1 and
// "the last thread to stop notifies the parent" is always this thread; no
// ptrace (`JOBCTL_TRAP_*`, `JOBCTL_TRACED`), no cgroup freezer and no
// `group_exec_task`. The state lives in [`ThreadSignal::jobctl`] and
// [`SignalStruct::job_flags`]/[`SignalStruct::group_stop_count`]; waking the
// stopped task and telling the parent are the task list's and the scheduler's
// (`task::Tasklist::signal_stop`, `ktask::stop_current`).
#![forbid(unsafe_code)]
//! Group stop and continue: the state half of job control.
//!
//! # Contract
//! * Context: as [`State`]: the caller serialises (the `PROCESS` lock of the
//!   binary).
//! * `JOBCTL_STOPPED` mirrors "the task is in `TASK_STOPPED`" (`do_signal_stop`
//!   sets it with the state; `SIGCONT` clears it with the wake-up). The
//!   scheduler's state is the authority for sleeping; this bit answers
//!   `task_is_stopped()` for `wants_signal`.
//! * `SIGNAL_STOP_STOPPED` (a stop is in effect, what `wait` reports with
//!   [`SignalStruct::stop_code`]) and `SIGNAL_STOP_CONTINUED` (what
//!   `WCONTINUED` reports) are cleared and set only here, so a stop is
//!   reported once.

use super::{SIGCONT, SigSet, sig_kernel_stop, state::State};

/// `CLD_*` (`si_code` of `SIGCHLD`, `include/uapi/asm-generic/siginfo.h`).
pub const CLD_EXITED: i32 = 1;
pub const CLD_KILLED: i32 = 2;
pub const CLD_DUMPED: i32 = 3;
pub const CLD_STOPPED: i32 = 5;
pub const CLD_CONTINUED: i32 = 6;

/// `JOBCTL_STOP_SIGMASK`: the signal number of the last group stop.
pub const JOBCTL_STOP_SIGMASK: u32 = 0xffff;
/// `JOBCTL_STOP_DEQUEUED`: a stop signal was dequeued and not yet acted on.
pub const JOBCTL_STOP_DEQUEUED: u32 = 1 << 16;
/// `JOBCTL_STOP_PENDING`: this task should stop for a group stop.
pub const JOBCTL_STOP_PENDING: u32 = 1 << 17;
/// `JOBCTL_STOP_CONSUME`: this task consumes `group_stop_count` when it stops.
pub const JOBCTL_STOP_CONSUME: u32 = 1 << 18;
/// `JOBCTL_PENDING_MASK` without the ptrace traps this kernel lacks.
pub const JOBCTL_PENDING_MASK: u32 = JOBCTL_STOP_PENDING;
/// `JOBCTL_STOPPED`: set by `do_signal_stop`, cleared by `SIGCONT`.
pub const JOBCTL_STOPPED: u32 = 1 << 26;

/// `SIGNAL_STOP_STOPPED`: a job-control stop is in effect.
pub const SIGNAL_STOP_STOPPED: u32 = 0x1;
/// `SIGNAL_STOP_CONTINUED`: `SIGCONT` since the last `WCONTINUED` report.
pub const SIGNAL_STOP_CONTINUED: u32 = 0x2;
/// `SIGNAL_CLD_STOPPED`: the parent owes a stop notification.
pub const SIGNAL_CLD_STOPPED: u32 = 0x10;
/// `SIGNAL_CLD_CONTINUED`: the parent owes a continue notification.
pub const SIGNAL_CLD_CONTINUED: u32 = 0x20;
/// `SIGNAL_CLD_MASK`.
pub const SIGNAL_CLD_MASK: u32 = SIGNAL_CLD_STOPPED | SIGNAL_CLD_CONTINUED;
/// `SIGNAL_STOP_MASK`: the bits `signal_set_stop_flags` replaces.
pub const SIGNAL_STOP_MASK: u32 = SIGNAL_CLD_MASK | SIGNAL_STOP_STOPPED | SIGNAL_STOP_CONTINUED;

/// What `do_signal_stop` decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignalStop {
    /// No stop: the group stop was cancelled (a `SIGCONT` or `SIGKILL` came
    /// between the dequeue and now). The caller carries on with the next signal.
    NotStopped,
    /// The task is committed to stop: `JOBCTL_STOPPED` is set. `notify`: this
    /// task completed a fresh group stop, so the parent is told `CLD_STOPPED`
    /// (`do_notify_parent_cldstop`) before the task sleeps.
    Stop { notify: bool },
}

impl State<'_> {
    /// `task_set_jobctl_pending`: set `mask`; a no-op (`false`) when the task
    /// is being killed or is exiting. A stop signal number in `mask` replaces
    /// the previous one.
    pub fn task_set_jobctl_pending(&mut self, mask: u32) -> bool {
        if self.fatal_signal_pending() || self.exiting {
            return false;
        }
        if mask & JOBCTL_STOP_SIGMASK != 0 {
            self.me.jobctl &= !JOBCTL_STOP_SIGMASK;
        }
        self.me.jobctl |= mask;
        true
    }

    /// `task_clear_jobctl_pending`: clearing `JOBCTL_STOP_PENDING` clears the
    /// other stop bits (consume, dequeued) with it.
    pub fn task_clear_jobctl_pending(&mut self, mask: u32) {
        let mut mask = mask;
        if mask & JOBCTL_STOP_PENDING != 0 {
            mask |= JOBCTL_STOP_CONSUME | JOBCTL_STOP_DEQUEUED;
        }
        self.me.jobctl &= !mask;
    }

    /// `signal_set_stop_flags`: replace the stop bits of `signal->flags`.
    pub fn signal_set_stop_flags(&mut self, flags: u32) {
        debug_assert!(self.sig.group_exit.is_none(), "stop flags in a group exit");
        self.sig.job_flags = (self.sig.job_flags & !SIGNAL_STOP_MASK) | flags;
    }

    /// `task_participate_group_stop`: the task has `JOBCTL_STOP_PENDING` and
    /// takes part in the group stop; whether it completed a fresh one (the
    /// parent is to be told).
    pub fn task_participate_group_stop(&mut self) -> bool {
        let consume = self.me.jobctl & JOBCTL_STOP_CONSUME != 0;
        self.task_clear_jobctl_pending(JOBCTL_STOP_PENDING);
        if !consume {
            return false;
        }
        // `WARN_ON_ONCE(group_stop_count == 0)`: never, the caller counted this task.
        self.sig.group_stop_count = self.sig.group_stop_count.saturating_sub(1);
        if self.sig.group_stop_count == 0 && self.sig.job_flags & SIGNAL_STOP_STOPPED == 0 {
            self.signal_set_stop_flags(SIGNAL_STOP_STOPPED);
            return true;
        }
        false
    }

    /// `do_signal_stop(signr)` up to the sleep: start a group stop with `signr`
    /// when none is in progress, then take part in it. `signr` is the stop
    /// signal just dequeued (`JOBCTL_STOP_DEQUEUED` is set by the dequeue).
    pub fn do_signal_stop(&mut self, signr: u8) -> SignalStop {
        if self.me.jobctl & JOBCTL_STOP_PENDING == 0 {
            let gstop = JOBCTL_STOP_PENDING | JOBCTL_STOP_CONSUME;
            // A stop signal whose `SIGCONT`/`SIGKILL` already overruled it.
            if self.me.jobctl & JOBCTL_STOP_DEQUEUED == 0 || self.sig.group_exit.is_some() {
                return SignalStop::NotStopped;
            }
            // "Don't generate group_exit_code" when a stop is already in effect.
            if self.sig.job_flags & SIGNAL_STOP_STOPPED == 0 {
                self.sig.stop_code = u32::from(signr);
            }
            self.sig.group_stop_count = 0;
            if self.task_set_jobctl_pending(u32::from(signr) | gstop) {
                self.sig.group_stop_count += 1;
            }
        }
        // No other thread: the only participant is the last to stop.
        let notify = self.task_participate_group_stop();
        self.me.jobctl |= JOBCTL_STOPPED;
        SignalStop::Stop { notify }
    }

    /// The `SIGNAL_CLD_MASK` check at the top of `get_signal`: the notification
    /// a stopped (or continued) task owes its parent after waking. Clears the
    /// bits and returns the `CLD_*` code to report (`CLD_CONTINUED` wins over
    /// `CLD_STOPPED`), if any.
    pub fn take_cld_notification(&mut self) -> Option<i32> {
        let flags = self.sig.job_flags;
        if flags & SIGNAL_CLD_MASK == 0 {
            return None;
        }
        self.sig.job_flags &= !SIGNAL_CLD_MASK;
        Some(if flags & SIGNAL_CLD_CONTINUED != 0 {
            CLD_CONTINUED
        } else {
            CLD_STOPPED
        })
    }

    /// The job-control part of `prepare_signal` for `sig`: the side effects
    /// of stop and continue signals at generation time, whatever happens to
    /// the signal itself. Returns whether the stopped task must be woken
    /// (`SIGCONT` ended a stop: `wake_up_state(t, __TASK_STOPPED)`).
    pub(super) fn job_control_effects(&mut self, sig: u8) -> bool {
        if sig_kernel_stop(sig) {
            // A stop signal: remove SIGCONT from all queues.
            self.flush_signals(SigSet::bit(SIGCONT));
            return false;
        }
        if sig != SIGCONT {
            return false;
        }
        // Remove all stop signals from all queues, wake all threads.
        self.flush_signals(super::KERNEL_STOP);
        self.task_clear_jobctl_pending(JOBCTL_PENDING_MASK);
        let was_stopped = self.me.jobctl & JOBCTL_STOPPED != 0;
        self.me.jobctl &= !JOBCTL_STOPPED;
        // Notify the parent with CLD_CONTINUED if we were stopped. In the
        // middle of a group stop the stop is pretended finished and then
        // continued; SIGCHLD does not queue, so only CLD_STOPPED is reported.
        let why = if self.sig.job_flags & SIGNAL_STOP_STOPPED != 0 {
            SIGNAL_CLD_CONTINUED
        } else if self.sig.group_stop_count != 0 {
            SIGNAL_CLD_STOPPED
        } else {
            0
        };
        if why != 0 {
            self.signal_set_stop_flags(why | SIGNAL_STOP_CONTINUED);
            self.sig.group_stop_count = 0;
            self.sig.stop_code = 0;
        }
        was_stopped
    }

    /// `wants_signal(sig, p)` for the one thread: the signal is not blocked,
    /// the task is not exiting, and (`SIGKILL` always wants) it is not stopped
    /// and either runs or has nothing pending yet (`task_curr(p) ||
    /// !task_sigpending(p)`). `pending_before` is `task_sigpending(p)`: the
    /// flag as it was when the signal was generated, before this signal's own
    /// queueing (Linux sets it afterwards, in `signal_wake_up`).
    #[must_use]
    pub fn wants_signal(&self, sig: u8, pending_before: bool) -> bool {
        if self.me.blocked.contains(sig) || self.exiting {
            return false;
        }
        if sig == super::SIGKILL {
            return true;
        }
        if self.me.jobctl & JOBCTL_STOPPED != 0 {
            return false;
        }
        self.curr || !pending_before
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signal::{
        SIG_DFL, SIGKILL, SIGTERM, SIGTSTP, SIGUSR1,
        info::SigInfo,
        state::{State, Target},
    };

    fn plain() -> State<'static> {
        State::standalone(5, 0, 100)
    }

    fn send(state: &mut State<'_>, sig: u8) {
        state
            .send_signal(sig, SigInfo::from_kill(sig, false, 1, 0), Target::Process)
            .unwrap();
    }

    /// A task that dequeued stop signal `sig`, as `get_signal` does before `do_signal_stop`.
    fn dequeued(state: &mut State<'_>, sig: u8) {
        send(state, sig);
        assert_eq!(state.dequeue_signal().unwrap().0, sig);
        assert_ne!(state.me.jobctl & JOBCTL_STOP_DEQUEUED, 0, "the marker");
    }

    #[test]
    fn a_stop_signal_starts_a_group_stop_that_the_parent_hears_about_once() {
        let mut s = plain();
        dequeued(&mut s, SIGTSTP);
        assert_eq!(s.do_signal_stop(SIGTSTP), SignalStop::Stop { notify: true });
        // kernel/signal.c task_participate_group_stop: the stop is in effect, its signal is the
        // code `wait` reports, and the pending/consume/dequeued bits are gone.
        assert_eq!(s.sig.job_flags, SIGNAL_STOP_STOPPED);
        assert_eq!(s.sig.stop_code, u32::from(SIGTSTP));
        assert_eq!(s.sig.group_stop_count, 0);
        assert_eq!(s.me.jobctl, JOBCTL_STOPPED | u32::from(SIGTSTP));
        // A second stop signal while stopped: no new notification, the code stays.
        dequeued(&mut s, super::super::SIGSTOP);
        assert_eq!(
            s.do_signal_stop(super::super::SIGSTOP),
            SignalStop::Stop { notify: false }
        );
        assert_eq!(
            s.sig.stop_code,
            u32::from(SIGTSTP),
            "group_exit_code is kept"
        );
    }

    #[test]
    fn a_stop_that_sigcont_or_sigkill_overruled_does_not_happen() {
        let mut s = plain();
        // No dequeued stop signal (SIGCONT cleared the marker): nothing to stop for.
        assert_eq!(s.do_signal_stop(SIGTSTP), SignalStop::NotStopped);
        assert_eq!((s.sig.job_flags, s.me.jobctl), (0, 0));
        // A group exit under way.
        dequeued(&mut s, SIGTSTP);
        s.start_group_exit(9);
        assert_eq!(s.do_signal_stop(SIGTSTP), SignalStop::NotStopped);
        // The marker is set by dequeuing, and only by a stop signal.
        let mut s = plain();
        s.hand.actions[usize::from(SIGUSR1) - 1].handler = 0x1000;
        send(&mut s, SIGUSR1);
        s.dequeue_signal().unwrap();
        assert_eq!(s.me.jobctl & JOBCTL_STOP_DEQUEUED, 0);
    }

    #[test]
    fn sigcont_ends_the_stop_clears_its_code_and_owes_the_parent_one_notification() {
        let mut s = plain();
        dequeued(&mut s, SIGTSTP);
        let _ = s.do_signal_stop(SIGTSTP);
        // The default action of SIGCONT is to be ignored: the effects happen anyway.
        send(&mut s, SIGCONT);
        assert_eq!(s.pending_set().0, 0);
        assert_eq!(s.me.jobctl & JOBCTL_STOPPED, 0);
        assert_eq!(s.sig.stop_code, 0);
        assert_eq!(
            s.sig.job_flags,
            SIGNAL_CLD_CONTINUED | SIGNAL_STOP_CONTINUED
        );
        // `get_signal` takes the CLD bits (once); STOP_CONTINUED stays for `WCONTINUED`.
        assert_eq!(s.take_cld_notification(), Some(CLD_CONTINUED));
        assert_eq!(s.sig.job_flags, SIGNAL_STOP_CONTINUED);
        assert_eq!(s.take_cld_notification(), None);
        // A SIGCONT to a task that never stopped changes no flag.
        let mut r = plain();
        send(&mut r, SIGCONT);
        assert_eq!(r.sig.job_flags, 0);
    }

    #[test]
    fn sigcont_in_the_middle_of_a_group_stop_reports_a_stop() {
        // kernel/signal.c prepare_signal: "we pretend it was already finished, and then
        // continued. Since SIGCHLD doesn't queue we report only CLD_STOPPED".
        let mut s = plain();
        s.sig.group_stop_count = 1;
        s.me.jobctl = JOBCTL_STOP_PENDING | JOBCTL_STOP_CONSUME | u32::from(SIGTSTP);
        send(&mut s, SIGCONT);
        assert_eq!(s.sig.group_stop_count, 0);
        assert_eq!(s.me.jobctl & (JOBCTL_STOP_PENDING | JOBCTL_STOP_CONSUME), 0);
        assert_eq!(s.take_cld_notification(), Some(CLD_STOPPED));
        assert_eq!(s.sig.job_flags, SIGNAL_STOP_CONTINUED);
    }

    #[test]
    fn stop_and_continue_signals_discard_each_other_and_the_dequeued_marker() {
        let mut s = plain();
        s.me.blocked.add(SIGTSTP);
        s.me.blocked.add(SIGCONT);
        send(&mut s, SIGTSTP);
        s.me.jobctl |= JOBCTL_STOP_DEQUEUED;
        send(&mut s, SIGCONT);
        assert!(!s.pending_set().contains(SIGTSTP));
        assert!(s.pending_set().contains(SIGCONT), "blocked: stays pending");
        assert_eq!(s.me.jobctl & JOBCTL_STOP_DEQUEUED, 0);
        send(&mut s, SIGTSTP);
        assert!(!s.pending_set().contains(SIGCONT));
    }

    #[test]
    fn wants_signal_follows_the_state_of_the_task() {
        let mut s = plain();
        assert!(s.wants_signal(SIGTERM, false));
        assert_eq!(s.wants_signal(SIGTERM, true), s.curr);
        // Not the running task, and a signal already waits for it: it will dequeue both.
        s.curr = false;
        assert!(!s.wants_signal(SIGTERM, true));
        assert!(s.wants_signal(SIGTERM, false));
        assert!(s.wants_signal(SIGKILL, true));
        s.curr = true;
        s.me.jobctl |= JOBCTL_STOPPED;
        assert!(!s.wants_signal(SIGTERM, false), "stopped");
        assert!(
            s.wants_signal(SIGKILL, false),
            "only SIGKILL gets through a stop"
        );
        s.me.jobctl = 0;
        s.me.blocked.add(SIGTERM);
        assert!(!s.wants_signal(SIGTERM, false));
        s.me.blocked = crate::signal::SigSet::EMPTY;
        s.exiting = true;
        assert!(!s.wants_signal(SIGKILL, false), "PF_EXITING");
    }

    #[test]
    fn a_terminating_signal_waits_for_a_stopped_task_but_sigkill_does_not() {
        let mut s = plain();
        dequeued(&mut s, SIGTSTP);
        let _ = s.do_signal_stop(SIGTSTP);
        send(&mut s, SIGTERM);
        assert_eq!(s.sig.group_exit, None, "queued, not fatal yet");
        assert!(s.pending_set().contains(SIGTERM));
        assert!(!s.fatal_signal_pending());
        send(&mut s, SIGKILL);
        assert_eq!(s.sig.group_exit, Some(u32::from(SIGKILL)));
        assert!(s.fatal_signal_pending());
        // The group exit drops the stop state and the pending stop bits.
        assert_eq!((s.sig.job_flags, s.sig.stop_code), (0, 0));
    }

    #[test]
    fn a_fatal_signal_behind_a_pending_one_leaves_the_decision_to_the_task() {
        // `wants_signal`: `task_curr(p) || !task_sigpending(p)`. A task off the CPU with a
        // handled signal already pending dequeues the new one in its turn.
        let mut s = plain();
        s.curr = false;
        s.hand.actions[usize::from(SIGUSR1) - 1].handler = 0x1000;
        send(&mut s, SIGUSR1);
        send(&mut s, SIGTERM);
        assert_eq!(s.sig.group_exit, None);
        assert_eq!(s.dequeue_signal().unwrap().0, SIGUSR1);
        assert_eq!(s.dequeue_signal().unwrap().0, SIGTERM);
        // The running task, or one with nothing pending, goes down at once.
        let mut r = plain();
        r.curr = false;
        send(&mut r, SIGTERM);
        assert_eq!(r.sig.group_exit, Some(u32::from(SIGTERM)));
        assert_eq!(r.hand.actions[usize::from(SIGTERM) - 1].handler, SIG_DFL);
    }

    #[test]
    fn jobctl_bits_cannot_be_set_on_a_dying_task() {
        let mut s = plain();
        assert!(s.task_set_jobctl_pending(JOBCTL_STOP_PENDING | 0x13));
        assert_eq!(s.me.jobctl, JOBCTL_STOP_PENDING | 0x13);
        // A new signal number replaces the old one.
        assert!(s.task_set_jobctl_pending(20));
        assert_eq!(s.me.jobctl & JOBCTL_STOP_SIGMASK, 20);
        s.task_clear_jobctl_pending(JOBCTL_STOP_PENDING);
        assert_eq!(
            s.me.jobctl, 20,
            "clearing PENDING clears CONSUME and DEQUEUED with it"
        );
        s.exiting = true;
        assert!(!s.task_set_jobctl_pending(JOBCTL_STOP_PENDING));
    }
}
