// SPDX-License-Identifier: GPL-2.0-only
// Linux 6.18.57 (commit 2ff600d29ee478d0a8d46ef8a58afb5e038fe692):
// kernel/signal.c: `sig_task_ignored`/`sig_ignored` 84-129, `next_signal`
// 203-247, `collect_signal`/`dequeue_signal` 591-690,
// `dequeue_synchronous_signal` 692-736, `sigqueue_alloc`/`sig_get_ucounts`
// 402-451, `flush_sigqueue_mask` 773, `prepare_signal` 895-968,
// `complete_signal` 987-1059, `legacy_queue` 1061, `__send_signal_locked`
// 1090-1200, `send_signal_locked` 1217-1262, `force_sig_info_to_task`
// 1331-1373, `force_sig*` 1691-1760, `kernel/exit.c:1100` (`do_group_exit`),
// include/linux/sched/signal.h:565-615. All GPL-2.0.
#![forbid(unsafe_code)]
//! Per-process signal state and the send side of `kernel/signal.c`.
//!
//! # Contract
//! * One thread: `tsk->pending` is [`Target::Thread`], `shared_pending` is
//!   [`Target::Process`]; both are drained by the same task, private first.
//! * Allocation: queued `siginfo` lives in two fixed arrays of
//!   [`QUEUE_CAPACITY`]; no allocation. A classic signal (1..=31) has at most
//!   one entry per queue (`legacy_queue`), so [`CLASSIC_SLOTS`] slots are
//!   reserved for them and a classic `siginfo` (a forced fault's included) is
//!   never lost. Real-time signals share [`RT_QUEUE_CAPACITY`] slots per
//!   queue; a full RT quota behaves like `sigqueue_alloc` failing (the signal
//!   bit is still set, the `siginfo` is lost, `-EAGAIN` for user-queued
//!   real-time signals).
//!   shortcut: the RT pending limit is `min(RLIMIT_SIGPENDING, 64 per queue)`;
//!   it becomes the plain rlimit once the heap-backed queue replaces the
//!   arrays (fallible `try_reserve`, never an infallible push).
//! * `wants_signal`: the task is assumed running or already due to dequeue (it
//!   is the only thread), so a signal wakes it iff it is not blocked. Sleep and
//!   stop states belong to the scheduler step.

use super::{
    AltStack, KERNEL_IGNORE, KERNEL_STOP, NSIG, SA_IMMUTABLE, SIG_DFL, SIG_IGN, SIGALRM, SIGCONT,
    SIGKILL, SIGRTMIN, SYNCHRONOUS, SigAction, SigSet, in_mask,
    info::{Fault, Layout, SI_KERNEL, SI_USER, SigInfo},
    itimer::RealTimer,
    sig_kernel_coredump, sig_kernel_only, sig_kernel_stop,
};
use syscalls::Errno;

/// Real-time `siginfo` entries per pending queue (see the module contract).
pub const RT_QUEUE_CAPACITY: usize = 64;
/// One slot per classic signal `1..=31`.
pub const CLASSIC_SLOTS: usize = 31;
/// Array size of a pending queue.
pub const QUEUE_CAPACITY: usize = RT_QUEUE_CAPACITY + CLASSIC_SLOTS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// `PIDTYPE_PID`: `tsk->pending` (tkill, tgkill, forced faults).
    Thread,
    /// `PIDTYPE_TGID`: `signal->shared_pending` (kill).
    Process,
}

/// `enum sig_handler` of `force_sig_info_to_task`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Handler {
    /// Use the current handler if the signal is reachable.
    Current,
    /// Always default semantics.
    SigDfl,
    /// Only visible as the exit code: default and immutable.
    Exit,
}

#[derive(Clone, Debug)]
struct Pending {
    signal: SigSet,
    queue: [SigInfo; QUEUE_CAPACITY],
    len: usize,
}

impl Pending {
    fn new() -> Self {
        Self {
            signal: SigSet::EMPTY,
            queue: [SigInfo::default(); QUEUE_CAPACITY],
            len: 0,
        }
    }

    fn entries(&self) -> &[SigInfo] {
        &self.queue[..self.len]
    }

    fn remove(&mut self, index: usize) -> SigInfo {
        let info = self.queue[index];
        self.queue.copy_within(index + 1..self.len, index);
        self.len -= 1;
        info
    }

    /// `next_signal`: lowest unblocked pending signal, synchronous ones first.
    fn next_signal(&self, blocked: SigSet) -> Option<u8> {
        let mut ready = self.signal.0 & !blocked.0;
        if ready == 0 {
            return None;
        }
        if ready & SYNCHRONOUS != 0 {
            ready &= SYNCHRONOUS;
        }
        u8::try_from(ready.trailing_zeros() + 1).ok()
    }

    /// `collect_signal`: take the first queued `siginfo` of `sig`; clear the
    /// pending bit unless another entry of `sig` remains. Without an entry
    /// (fast-pathed standard signal or lost to a full queue) the info is
    /// synthesised as `SI_USER` from pid 0, uid 0.
    fn collect(&mut self, sig: u8) -> SigInfo {
        let mut positions = self
            .entries()
            .iter()
            .enumerate()
            .filter(|(_, q)| q.signo == i32::from(sig))
            .map(|(i, _)| i);
        let first = positions.next();
        let another = positions.next().is_some();
        if !another {
            self.signal.remove(sig);
        }
        match first {
            Some(index) => self.remove(index),
            None => SigInfo::kill(sig, SI_USER, 0, 0),
        }
    }

    /// `flush_sigqueue_mask`.
    fn flush(&mut self, mask: u64) {
        self.signal.0 &= !mask;
        let mut kept = 0;
        for i in 0..self.len {
            let q = self.queue[i];
            let hit = (1..=i32::from(NSIG)).contains(&q.signo) && mask & (1 << (q.signo - 1)) != 0;
            if !hit {
                self.queue[kept] = q;
                kept += 1;
            }
        }
        self.len = kept;
    }
}

/// `current->restart_block.fn`: what `restart_syscall` (219) runs.
///
/// A syscall that returns `-ERESTART_RESTARTBLOCK` stores its continuation
/// here; every signal handler entry that reaches `rt_sigreturn` resets it
/// (`restore_sigcontext`: `do_no_restart_syscall`). The time lane adds the
/// `nanosleep` variant (`clockid`, absolute expiry) when `nanosleep` lands.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RestartBlock {
    /// `do_no_restart_syscall`: `restart_syscall` returns `-EINTR`.
    #[default]
    NoRestart,
}

/// `thread.{trap_nr,error_code,cr2}`: what the sigcontext reports.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ArchInfo {
    pub trap_nr: u64,
    pub error_code: u64,
    pub cr2: u64,
}

/// `sighand` + `signal_struct` + the task's signal fields.
#[derive(Clone, Debug)]
pub struct State {
    /// `sighand->action[]`, index `sig - 1`.
    pub actions: [SigAction; NSIG as usize],
    /// `current->blocked`; never contains SIGKILL or SIGSTOP.
    pub blocked: SigSet,
    /// `current->real_blocked`: the mask `rt_sigtimedwait` temporarily
    /// unblocks from; it only keeps those signals from being treated as
    /// ignored (`sig_ignored`) while the task waits for them.
    pub real_blocked: SigSet,
    /// `current->saved_sigmask` when `TIF_RESTORE_SIGMASK` is set.
    pub saved_sigmask: Option<SigSet>,
    /// `current->sas_ss_*`.
    pub altstack: AltStack,
    /// `thread.trap_nr/error_code/cr2`.
    pub arch: ArchInfo,
    /// `signal->group_exit_code` while `SIGNAL_GROUP_EXIT` is set.
    pub group_exit: Option<u32>,
    /// `is_global_init(current)`.
    pub global_init: bool,
    /// `SIGNAL_UNKILLABLE`.
    pub unkillable: bool,
    /// `task_pid_vnr`; equal to `tgid` for the one thread.
    pub pid: i32,
    /// `task_tgid_vnr`: `si_pid` of what this process sends.
    pub tgid: i32,
    /// `current_uid()`: `si_uid` of what this process sends.
    pub uid: u32,
    /// `RLIMIT_SIGPENDING` of the owner.
    pub rlimit_sigpending: u64,
    /// `signal->real_timer` / `it_real_incr` (`ITIMER_REAL`).
    pub itimer: RealTimer,
    /// `current->restart_block`.
    pub restart: RestartBlock,
    /// `CLOCK_MONOTONIC` as of the last [`State::sync_timers`]: the `now` of
    /// the interval-timer re-arm that `dequeue_signal` performs.
    pub now_ns: u64,
    private: Pending,
    shared: Pending,
}

impl State {
    /// The signal state of a newly created process (init at boot, a forked
    /// child before it inherits): default actions, nothing blocked or pending,
    /// altstack disabled (`sas_ss_reset`). `execve` is [`State::flush_on_exec`],
    /// not this.
    #[must_use]
    pub fn new(pid: i32, uid: u32, rlimit_sigpending: u64) -> Self {
        Self {
            actions: [SigAction::default(); NSIG as usize],
            blocked: SigSet::EMPTY,
            real_blocked: SigSet::EMPTY,
            saved_sigmask: None,
            altstack: AltStack::RESET,
            arch: ArchInfo::default(),
            group_exit: None,
            global_init: false,
            unkillable: false,
            pid,
            tgid: pid,
            uid,
            rlimit_sigpending,
            itimer: RealTimer::default(),
            restart: RestartBlock::NoRestart,
            now_ns: 0,
            private: Pending::new(),
            shared: Pending::new(),
        }
    }

    /// What `execve` does to the signal state (`begin_new_exec`,
    /// `flush_signal_handlers(me, 0)`): every handler goes back to `SIG_DFL`
    /// except `SIG_IGN`, which is kept; flags, restorer and `sa_mask` are
    /// cleared; the altstack address and size are zeroed (its flags are not).
    /// The blocked mask, `saved_sigmask` and all pending signals are kept.
    pub fn flush_on_exec(&mut self) {
        for action in &mut self.actions {
            if action.handler != SIG_IGN {
                action.handler = SIG_DFL;
            }
            action.flags = 0;
            action.restorer = 0;
            action.mask = SigSet::EMPTY;
        }
        self.altstack.sp = 0;
        self.altstack.size = 0;
    }

    /// The global init: pid 1, `SIGNAL_UNKILLABLE` (`copy_process`, child reaper).
    #[must_use]
    pub fn new_init(rlimit_sigpending: u64) -> Self {
        let mut state = Self::new(1, 0, rlimit_sigpending);
        state.global_init = true;
        state.unkillable = true;
        state
    }

    fn pending(&self, target: Target) -> &Pending {
        match target {
            Target::Thread => &self.private,
            Target::Process => &self.shared,
        }
    }
    fn pending_mut(&mut self, target: Target) -> &mut Pending {
        match target {
            Target::Thread => &mut self.private,
            Target::Process => &mut self.shared,
        }
    }

    /// `rt_sigpending`'s source: signals pending in either queue.
    #[must_use]
    pub const fn pending_set(&self) -> SigSet {
        SigSet(self.private.signal.0 | self.shared.signal.0)
    }

    /// `task_sigpending()` after `recalc_sigpending`: is there anything
    /// `get_signal` would act on?
    #[must_use]
    pub fn signal_pending(&self) -> bool {
        self.group_exit.is_some() || self.pending_set().0 & !self.blocked.0 != 0
    }

    /// `set_current_blocked`: SIGKILL and SIGSTOP are never blocked.
    pub fn set_blocked(&mut self, new: SigSet) {
        self.blocked = new.without_unblockable();
    }

    /// `flush_sigqueue_mask` on both queues.
    pub fn flush_signals(&mut self, mask: u64) {
        self.private.flush(mask);
        self.shared.flush(mask);
    }

    /// `sig_task_ignored`.
    fn task_ignores(&self, sig: u8, force: bool) -> bool {
        let action = &self.actions[usize::from(sig) - 1];
        if self.global_init && sig_kernel_only(sig) {
            return true;
        }
        if self.unkillable && action.handler == SIG_DFL && !(force && sig_kernel_only(sig)) {
            return true;
        }
        action.ignored(sig)
    }

    /// `sig_ignored`: blocked signals (also `real_blocked` ones) are never ignored.
    fn ignores(&self, sig: u8, force: bool) -> bool {
        !self.blocked.contains(sig)
            && !self.real_blocked.contains(sig)
            && self.task_ignores(sig, force)
    }

    /// `prepare_signal`: stop/continue side effects at generation time, then
    /// "should this signal be queued at all".
    fn prepare_signal(&mut self, sig: u8, force: bool) -> bool {
        if self.group_exit.is_some() {
            return false; // dying: drop (no core_state modelled)
        }
        if sig_kernel_stop(sig) {
            self.flush_signals(SigSet::bit(SIGCONT));
        } else if sig == SIGCONT {
            self.flush_signals(KERNEL_STOP);
        }
        !self.ignores(sig, force)
    }

    /// `sig_fatal`.
    fn sig_fatal(&self, sig: u8) -> bool {
        // `siginmask` is false for real-time signals: a default RT signal is fatal.
        !in_mask(sig, KERNEL_IGNORE | KERNEL_STOP)
            && self.actions[usize::from(sig) - 1].handler == SIG_DFL
    }

    /// `complete_signal` for a single thread.
    fn complete_signal(&mut self, sig: u8) {
        // shortcut: `wants_signal` is "not blocked" (task assumed running); the
        // scheduler step adds sleeping/stopped/exiting states.
        if self.blocked.contains(sig) {
            return; // does not want it; it dequeues when unblocked
        }
        // `!sigismember(&t->real_blocked, sig)`: a signal `rt_sigtimedwait` is
        // waiting for (blocked beforehand) never takes the group down.
        if self.sig_fatal(sig)
            && self.group_exit.is_none()
            && !self.real_blocked.contains(sig)
            && !sig_kernel_coredump(sig)
        {
            // Start the group exit: the exit code is the signal itself.
            self.group_exit = Some(u32::from(sig));
            self.private.signal.add(SIGKILL);
        }
    }

    /// `send_signal_locked` / `__send_signal_locked`. `sig` is `1..=64`.
    /// Kernel-internal senders (`SEND_SIG_NOINFO`, `SEND_SIG_PRIV`) pass the
    /// equivalent concrete `info` (`SI_USER` from the sender, `SI_KERNEL`); both
    /// have `si_code >= 0`, so they take the same rlimit-exempt path as in Linux.
    ///
    /// # Errors
    /// `EAGAIN` when a real-time signal sent with `si_code != SI_USER` cannot
    /// be queued (limit reached).
    pub fn send_signal(&mut self, sig: u8, info: SigInfo, target: Target) -> Result<(), Errno> {
        // send_signal_locked: SI_KERNEL signals with pid/uid layouts force.
        let force = matches!(info.layout(), Layout::Kill | Layout::Chld | Layout::Rt)
            && info.code == SI_KERNEL;
        if !self.prepare_signal(sig, force) {
            return Ok(());
        }
        // legacy_queue: at most one classic signal pending.
        if sig < SIGRTMIN && self.pending(target).signal.contains(sig) {
            return Ok(());
        }
        if sig != SIGKILL {
            let override_rlimit = sig < SIGRTMIN && info.code >= 0;
            let counted = (self.private.len + self.shared.len) as u64 + 1;
            let allowed = override_rlimit || counted <= self.rlimit_sigpending;
            let pending = self.pending_mut(target);
            // Classic signals have at most one entry (legacy_queue above), so
            // their reserved slots never run out; only RT entries are capped.
            let room = sig < SIGRTMIN
                || pending
                    .entries()
                    .iter()
                    .filter(|q| q.signo >= i32::from(SIGRTMIN))
                    .count()
                    < RT_QUEUE_CAPACITY;
            if allowed && room {
                pending.queue[pending.len] = info;
                pending.len += 1;
            } else if sig >= SIGRTMIN && info.code != SI_USER {
                return Err(Errno::EAGAIN);
            }
            // else: silent loss of the siginfo, the signal is still sent.
        }
        self.pending_mut(target).signal.add(sig);
        self.complete_signal(sig);
        Ok(())
    }

    /// `send_sig(sig, current, 0)`: the kernel sending `sig` to this thread on
    /// behalf of the current task (`SIGPIPE` from a pipe or socket write, `SIGXFSZ`,
    /// ...). The siginfo is `SEND_SIG_NOINFO`: `SI_USER` with this process's pid
    /// and uid. `sig` is `1..=64`.
    pub fn send_sig(&mut self, sig: u8) {
        let info = SigInfo::kill(sig, SI_USER, self.tgid, self.uid);
        // Only a real-time signal sent with `si_code < 0` can fail; `SI_USER` is >= 0.
        let _ = self.send_signal(sig, info, Target::Thread);
    }

    /// `force_sig_info_to_task` on the current task.
    pub fn force_sig_info(&mut self, info: SigInfo, handler: Handler) {
        let Ok(sig) = u8::try_from(info.signo) else {
            return;
        };
        if sig == 0 || sig > NSIG {
            return;
        }
        let blocked = self.blocked.contains(sig);
        let action = &mut self.actions[usize::from(sig) - 1];
        let ignored = action.handler == SIG_IGN;
        if blocked || ignored || handler != Handler::Current {
            action.handler = SIG_DFL;
            if handler == Handler::Exit {
                action.flags |= SA_IMMUTABLE;
            }
            if blocked {
                self.blocked.remove(sig);
            }
        }
        // No ptrace here: a default-handled forced signal makes init killable.
        if self.actions[usize::from(sig) - 1].handler == SIG_DFL {
            self.unkillable = false;
        }
        // Forced signals use PIDTYPE_PID; an `EAGAIN` can only come from
        // user-queued real-time signals, never from this path.
        let _ = self.send_signal(sig, info, Target::Thread);
    }

    /// `force_sig`: `SI_KERNEL`.
    pub fn force_sig(&mut self, sig: u8) {
        self.force_sig_info(SigInfo::kernel(sig), Handler::Current);
    }

    /// `force_fatal_sig`: default action regardless of the handler.
    pub fn force_fatal_sig(&mut self, sig: u8) {
        self.force_sig_info(SigInfo::kernel(sig), Handler::SigDfl);
    }

    /// `force_exit_sig`: default, immutable action.
    pub fn force_exit_sig(&mut self, sig: u8) {
        self.force_sig_info(SigInfo::kernel(sig), Handler::Exit);
    }

    /// `force_sigsegv(sig)`: a failure while handling `sig`.
    pub fn force_sigsegv(&mut self, sig: u8) {
        if sig == super::SIGSEGV {
            self.force_fatal_sig(super::SIGSEGV);
        } else {
            self.force_sig(super::SIGSEGV);
        }
    }

    /// A synchronous exception from user mode: record the architecture info
    /// the sigcontext will show, then `force_sig_info` (`do_trap`,
    /// `__bad_area_nosemaphore`, ...).
    pub fn force_fault(&mut self, fault: &Fault) {
        self.arch.trap_nr = fault.trap_nr;
        self.arch.error_code = fault.error_code;
        if let Some(cr2) = fault.cr2 {
            self.arch.cr2 = cr2;
        }
        if let Some(info) = fault.info {
            self.force_sig_info(info, Handler::Current);
        }
    }

    /// `dequeue_synchronous_signal`: a fault signal (positive `si_code`) from
    /// the private queue, before anything else. Like Linux it does not re-check
    /// that the chosen entry's signal is unblocked.
    pub fn dequeue_synchronous(&mut self) -> Option<SigInfo> {
        if (self.private.signal.0 & !self.blocked.0) & SYNCHRONOUS == 0 {
            return None;
        }
        let p = &mut self.private;
        let index = p.entries().iter().position(|q| {
            q.code > SI_USER
                && (1..=i32::from(NSIG)).contains(&q.signo)
                && (1u64 << (q.signo - 1)) & SYNCHRONOUS != 0
        })?;
        let signo = p.queue[index].signo;
        let again = p.entries()[index + 1..].iter().any(|q| q.signo == signo);
        if !again {
            p.signal.0 &= !(1u64 << (signo - 1));
        }
        Some(p.remove(index))
    }

    /// `dequeue_signal(&current->blocked, ..)`: private queue first, then the
    /// shared one.
    pub fn dequeue_signal(&mut self) -> Option<(u8, SigInfo)> {
        self.dequeue_signal_masked(self.blocked)
    }

    /// `dequeue_signal(mask, ..)`: `mask` is the set to skip (`rt_sigtimedwait`
    /// passes the complement of the awaited set). A `SIGALRM` taken from the
    /// shared queue restarts a fired interval timer
    /// (`posixtimer_rearm_itimer`).
    pub fn dequeue_signal_masked(&mut self, mask: SigSet) -> Option<(u8, SigInfo)> {
        for target in [Target::Thread, Target::Process] {
            let pending = self.pending_mut(target);
            if let Some(sig) = pending.next_signal(mask) {
                let info = pending.collect(sig);
                if target == Target::Process && sig == SIGALRM {
                    self.itimer.rearm(self.now_ns);
                }
                return Some((sig, info));
            }
        }
        None
    }

    /// Bring the timers up to `now` (`CLOCK_MONOTONIC` ns): an expired
    /// `ITIMER_REAL` sends `SIGALRM` to the process (`it_real_fn`:
    /// `kill_pid_info(SIGALRM, SEND_SIG_PRIV)`, so `SI_KERNEL`, pid 0, uid 0).
    /// Called on every kernel exit and after every wake-up, before the pending
    /// set is examined.
    pub fn sync_timers(&mut self, now: u64) {
        self.now_ns = now;
        if self.itimer.expire(now) {
            // Only a real-time signal sent with `si_code < 0` can fail.
            let _ = self.send_signal(SIGALRM, SigInfo::kernel(SIGALRM), Target::Process);
        }
    }

    /// `sigdelset(&current->pending.signal, sig)`.
    pub fn remove_private(&mut self, sig: u8) {
        self.private.signal.remove(sig);
    }

    /// `do_group_exit(code)`: the exit code of the dying process.
    pub fn group_exit_code(&mut self, code: u32) -> u32 {
        *self.group_exit.get_or_insert(code)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unreadable_literal,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::cast_lossless,
        clippy::similar_names,
        clippy::too_many_lines,
        clippy::decimal_bitwise_operands,
        clippy::items_after_statements,
        clippy::many_single_char_names,
        clippy::too_many_arguments
    )]
    use super::*;
    use crate::signal::{
        SIGCHLD, SIGHUP, SIGSEGV, SIGSTOP, SIGTERM, SIGTSTP, SIGUSR1,
        info::{SEGV_MAPERR, SI_QUEUE, SI_TKILL},
    };

    fn user(sig: u8) -> SigInfo {
        SigInfo::from_kill(sig, false, 1, 0)
    }
    fn plain() -> State {
        State::new(5, 0, 100)
    }

    #[test]
    fn standard_signals_coalesce_rt_signals_queue() {
        // legacy_queue: kernel/signal.c:1061.
        let mut s = plain();
        s.actions[usize::from(SIGUSR1) - 1].handler = 0x1000;
        s.actions[39].handler = 0x1000; // RT signals are fatal by default
        s.blocked.add(SIGUSR1);
        s.send_signal(SIGUSR1, user(SIGUSR1), Target::Process)
            .unwrap();
        s.send_signal(
            SIGUSR1,
            SigInfo::kill(SIGUSR1, SI_TKILL, 9, 9),
            Target::Process,
        )
        .unwrap();
        assert_eq!(s.shared.len, 1);
        for v in 0..3 {
            s.send_signal(40, SigInfo::rt(40, SI_QUEUE, 1, 0, v), Target::Process)
                .unwrap();
        }
        assert_eq!(s.shared.len, 4);
        s.blocked = SigSet::EMPTY;
        // Lowest number first, then RT entries in FIFO order, bit cleared on the last.
        assert_eq!(s.dequeue_signal().unwrap().0, SIGUSR1);
        for v in 0..3u64 {
            let (sig, info) = s.dequeue_signal().unwrap();
            assert_eq!(sig, 40);
            assert_eq!(&info.to_bytes()[24..32], &v.to_le_bytes());
        }
        assert!(s.dequeue_signal().is_none());
        assert_eq!(s.pending_set(), SigSet::EMPTY);
    }

    #[test]
    fn rt_queue_limit_and_overflow_rules() {
        // __send_signal_locked: kernel/signal.c:1136-1180.
        let mut s = State::new(5, 0, 2);
        s.blocked.add(40);
        s.blocked.add(41);
        let q = |v| SigInfo::rt(40, SI_QUEUE, 1, 0, v);
        s.send_signal(40, q(1), Target::Process).unwrap();
        s.send_signal(40, q(2), Target::Process).unwrap();
        // Third sigqueue()-style send: EAGAIN, nothing added.
        assert_eq!(s.send_signal(40, q(3), Target::Process), Err(Errno::EAGAIN));
        assert_eq!(s.shared.len, 2);
        // kill() of an RT signal (SI_USER) never fails: signal sent, info lost.
        s.send_signal(41, user(41), Target::Process).unwrap();
        assert!(s.shared.signal.contains(41));
        assert_eq!(s.shared.len, 2);
        s.blocked = SigSet::EMPTY;
        s.dequeue_signal().unwrap();
        s.dequeue_signal().unwrap();
        // 41 now dequeues with synthesised SI_USER, pid 0, uid 0.
        let (sig, info) = s.dequeue_signal().unwrap();
        assert_eq!((sig, info), (41, SigInfo::kill(41, SI_USER, 0, 0)));
        // Classic signals sent with si_code >= 0 bypass the limit.
        let mut s = State::new(5, 0, 0);
        s.blocked.add(SIGUSR1);
        s.send_signal(SIGUSR1, user(SIGUSR1), Target::Process)
            .unwrap();
        assert_eq!(s.shared.len, 1);
        // SI_TKILL (< 0) does not bypass it: signal pending, info lost.
        let mut s = State::new(5, 0, 0);
        s.blocked.add(SIGUSR1);
        s.send_signal(
            SIGUSR1,
            SigInfo::from_kill(SIGUSR1, true, 5, 0),
            Target::Thread,
        )
        .unwrap();
        assert_eq!(
            (s.private.len, s.private.signal.contains(SIGUSR1)),
            (0, true)
        );
    }

    #[test]
    fn synchronous_signals_dequeue_first() {
        // next_signal: SYNCHRONOUS_MASK wins over lower numbers (kernel/signal.c:203).
        let mut s = plain();
        s.blocked.add(SIGHUP);
        s.blocked.add(SIGSEGV);
        s.actions[usize::from(SIGSEGV) - 1].handler = 0x2000;
        s.actions[usize::from(SIGUSR1) - 1].handler = 0x2000;
        s.send_signal(SIGHUP, user(SIGHUP), Target::Thread).unwrap();
        s.send_signal(SIGUSR1, user(SIGUSR1), Target::Thread)
            .unwrap();
        s.send_signal(
            SIGSEGV,
            SigInfo::fault(SIGSEGV, SEGV_MAPERR, 8),
            Target::Thread,
        )
        .unwrap();
        s.blocked = SigSet::EMPTY;
        s.actions[0].handler = 0x3000;
        assert_eq!(s.dequeue_synchronous().unwrap().signo, i32::from(SIGSEGV));
        assert!(s.dequeue_synchronous().is_none());
        assert_eq!(s.dequeue_signal().unwrap().0, SIGHUP);
        assert_eq!(s.dequeue_signal().unwrap().0, SIGUSR1);
        // Private before shared.
        s.actions[usize::from(SIGTERM) - 1].handler = 0x4000;
        s.actions[usize::from(SIGUSR1) - 1].handler = 0x4000;
        s.send_signal(SIGUSR1, user(SIGUSR1), Target::Process)
            .unwrap();
        s.send_signal(SIGTERM, user(SIGTERM), Target::Thread)
            .unwrap();
        assert_eq!(s.dequeue_signal().unwrap().0, SIGTERM);
        assert_eq!(s.dequeue_signal().unwrap().0, SIGUSR1);
    }

    #[test]
    fn ignored_signals_are_dropped_at_generation_unless_blocked() {
        let mut s = plain();
        // Default-ignored: SIGCHLD vanishes; blocked it stays pending.
        s.send_signal(SIGCHLD, user(SIGCHLD), Target::Process)
            .unwrap();
        assert_eq!(s.pending_set(), SigSet::EMPTY);
        s.blocked.add(SIGCHLD);
        s.send_signal(SIGCHLD, user(SIGCHLD), Target::Process)
            .unwrap();
        assert!(s.pending_set().contains(SIGCHLD));
        // SIG_IGN explicit.
        s.actions[usize::from(SIGUSR1) - 1].handler = SIG_IGN;
        s.send_signal(SIGUSR1, user(SIGUSR1), Target::Process)
            .unwrap();
        assert!(!s.pending_set().contains(SIGUSR1));
    }

    #[test]
    fn global_init_drops_default_and_kernel_only_signals() {
        // sig_task_ignored: kernel/signal.c:84-103.
        let mut init = State::new_init(100);
        for sig in [SIGTERM, SIGHUP, SIGUSR1, SIGKILL, SIGSTOP, SIGTSTP] {
            init.send_signal(sig, user(sig), Target::Process).unwrap();
            assert_eq!(init.pending_set(), SigSet::EMPTY, "{sig}");
        }
        assert_eq!(init.group_exit, None);
        // With a handler installed the signal is queued; SIGKILL/SIGSTOP still not.
        init.actions[usize::from(SIGTERM) - 1].handler = 0x1000;
        init.send_signal(SIGTERM, user(SIGTERM), Target::Process)
            .unwrap();
        assert!(init.pending_set().contains(SIGTERM));
        init.send_signal(SIGKILL, user(SIGKILL), Target::Process)
            .unwrap();
        assert!(!init.pending_set().contains(SIGKILL));
        // Even SI_KERNEL (force) SIGKILL: is_global_init && sig_kernel_only wins.
        init.send_signal(SIGKILL, SigInfo::kernel(SIGKILL), Target::Process)
            .unwrap();
        assert!(!init.pending_set().contains(SIGKILL));
        // A non-init process is killed immediately: group exit with the signal.
        let mut p = plain();
        p.send_signal(SIGTERM, user(SIGTERM), Target::Process)
            .unwrap();
        assert_eq!(p.group_exit, Some(15));
        // Later signals are dropped while dying.
        p.actions[usize::from(SIGUSR1) - 1].handler = 0x1000;
        p.send_signal(SIGUSR1, user(SIGUSR1), Target::Process)
            .unwrap();
        assert!(!p.pending_set().contains(SIGUSR1));
    }

    #[test]
    fn forced_segv_kills_init_and_unblocks() {
        // force_sig_info_to_task: kernel/signal.c:1331-1373.
        let mut init = State::new_init(100);
        init.blocked.add(SIGSEGV);
        init.force_sig_info(SigInfo::fault(SIGSEGV, SEGV_MAPERR, 0x10), Handler::Current);
        assert!(!init.blocked.contains(SIGSEGV));
        assert!(!init.unkillable);
        assert_eq!(init.actions[usize::from(SIGSEGV) - 1].handler, SIG_DFL);
        assert_eq!(
            init.dequeue_synchronous().unwrap(),
            SigInfo::fault(SIGSEGV, SEGV_MAPERR, 0x10)
        );
        // A handled SIGSEGV keeps init unkillable and stays handled.
        let mut init = State::new_init(100);
        init.actions[usize::from(SIGSEGV) - 1].handler = 0x1000;
        init.force_sig(SIGSEGV);
        assert!(init.unkillable);
        assert_eq!(init.actions[usize::from(SIGSEGV) - 1].handler, 0x1000);
        // SIG_IGN is replaced by SIG_DFL.
        let mut init = State::new_init(100);
        init.actions[usize::from(SIGSEGV) - 1].handler = SIG_IGN;
        init.force_sig(SIGSEGV);
        assert_eq!(init.actions[usize::from(SIGSEGV) - 1].handler, SIG_DFL);
        assert!(init.pending_set().contains(SIGSEGV));
        // force_sigsegv(SIGSEGV) resets even a handler (force_fatal_sig).
        let mut init = State::new_init(100);
        init.actions[usize::from(SIGSEGV) - 1].handler = 0x1000;
        init.force_sigsegv(SIGSEGV);
        assert_eq!(init.actions[usize::from(SIGSEGV) - 1].handler, SIG_DFL);
        assert!(!init.unkillable);
        // force_exit_sig marks the action immutable.
        let mut p = plain();
        p.force_exit_sig(SIGSEGV);
        assert_ne!(p.actions[usize::from(SIGSEGV) - 1].flags & SA_IMMUTABLE, 0);
    }

    #[test]
    fn stop_and_cont_flush_each_other() {
        // prepare_signal: kernel/signal.c:895-960.
        let mut s = plain();
        s.blocked.add(SIGCONT);
        s.blocked.add(SIGTSTP);
        s.send_signal(SIGCONT, user(SIGCONT), Target::Process)
            .unwrap();
        s.send_signal(SIGTSTP, user(SIGTSTP), Target::Process)
            .unwrap();
        assert!(!s.pending_set().contains(SIGCONT));
        assert!(s.pending_set().contains(SIGTSTP));
        s.send_signal(SIGCONT, user(SIGCONT), Target::Process)
            .unwrap();
        assert!(!s.pending_set().contains(SIGTSTP));
        assert!(s.pending_set().contains(SIGCONT));
        assert_eq!(s.shared.len, 1);
    }

    #[test]
    fn collect_keeps_bit_while_more_entries() {
        let mut p = Pending::new();
        p.signal.add(40);
        for v in 0..2 {
            p.queue[p.len] = SigInfo::rt(40, SI_QUEUE, 1, 0, v);
            p.len += 1;
        }
        p.collect(40);
        assert!(p.signal.contains(40));
        p.collect(40);
        assert!(!p.signal.contains(40));
    }

    #[test]
    fn group_exit_code_is_sticky() {
        let mut s = plain();
        assert_eq!(s.group_exit_code(11), 11);
        assert_eq!(s.group_exit_code(9), 11);
    }
}
