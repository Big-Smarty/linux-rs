// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: kernel/signal.c (the syscall
// entry points), kernel/time/itimer.c, arch/x86/kernel/signal_64.c
// (`rt_sigreturn`); the logic lives in `crate::signal`. GPL-2.0-only.
#![forbid(unsafe_code)]
//! Signal syscalls: `rt_sigaction`, `rt_sigprocmask`, `rt_sigpending`,
//! `sigaltstack`, `kill`, `tkill`, `tgkill`, `rt_sigqueueinfo`,
//! `rt_tgsigqueueinfo`, `rt_sigreturn`, `rt_sigsuspend`, `rt_sigtimedwait`,
//! `pause`, `restart_syscall`, `setitimer`, `getitimer` and `alarm`.
//!
//! The pure decisions are in [`crate::signal`]; this file only maps the raw
//! argument registers onto them. Two Linux behaviours stop loudly as
//! [`Outcome::Unimplemented`] instead of guessing: `kill(0, ..)` /
//! `kill(-1, ..)` (they depend on kernel threads and a process table that do
//! not exist) and the CPU-time interval timers (`ITIMER_VIRTUAL`,
//! `ITIMER_PROF`, which need the time lane's CPU accounting).

use super::{Context, Outcome};
use crate::signal::{
    itimer::{sys_alarm, sys_getitimer, sys_setitimer},
    syscalls::{
        sys_kill, sys_rt_sigaction, sys_rt_sigpending, sys_rt_sigprocmask, sys_rt_sigqueueinfo,
        sys_rt_tgsigqueueinfo, sys_sigaltstack, sys_tgkill, sys_tkill,
    },
    wait::{sys_pause, sys_restart_syscall, sys_rt_sigsuspend, sys_rt_sigtimedwait},
};
use syscalls::Sysno;

pub(super) fn dispatch<C: Context>(ctx: &mut C, sysno: Sysno, a: [u64; 6]) -> Option<Outcome> {
    let number = sysno as u32;
    let unimplemented =
        |value: Option<i64>| Some(value.map_or(Outcome::Unimplemented(number), Outcome::Return));
    let value = match sysno {
        Sysno::rt_sigaction => {
            let (state, pages) = ctx.parts();
            sys_rt_sigaction(state, pages, a[0], a[1], a[2], a[3])
        }
        Sysno::rt_sigprocmask => {
            let (state, pages) = ctx.parts();
            sys_rt_sigprocmask(state, pages, a[0], a[1], a[2], a[3])
        }
        Sysno::rt_sigpending => {
            let (state, pages) = ctx.parts();
            sys_rt_sigpending(state, pages, a[0], a[1])
        }
        Sysno::sigaltstack => {
            let sp = ctx.user_sp();
            let (state, pages) = ctx.parts();
            sys_sigaltstack(state, pages, a[0], a[1], sp)
        }
        Sysno::kill => return unimplemented(sys_kill(ctx.parts().0, a[0], a[1])),
        Sysno::tkill => sys_tkill(ctx.parts().0, a[0], a[1]),
        Sysno::tgkill => sys_tgkill(ctx.parts().0, a[0], a[1], a[2]),
        Sysno::rt_sigqueueinfo => {
            let (state, pages) = ctx.parts();
            sys_rt_sigqueueinfo(state, pages, a[0], a[1], a[2])
        }
        Sysno::rt_tgsigqueueinfo => {
            let (state, pages) = ctx.parts();
            sys_rt_tgsigqueueinfo(state, pages, a[0], a[1], a[2], a[3])
        }
        // The syscall's value is the restored `rax` (0 after a bad frame).
        #[allow(clippy::cast_possible_wrap)]
        Sysno::rt_sigreturn => ctx.rt_sigreturn().ret as i64,
        Sysno::rt_sigsuspend => sys_rt_sigsuspend(ctx, a[0], a[1]),
        Sysno::rt_sigtimedwait => sys_rt_sigtimedwait(ctx, a[0], a[1], a[2], a[3]),
        Sysno::pause => sys_pause(ctx),
        Sysno::restart_syscall => sys_restart_syscall(ctx.parts().0),
        Sysno::setitimer => return unimplemented(sys_setitimer(ctx, a[0], a[1], a[2])),
        Sysno::getitimer => return unimplemented(sys_getitimer(ctx, a[0], a[1])),
        Sysno::alarm => sys_alarm(ctx, a[0]),
        _ => return None,
    };
    Some(Outcome::Return(value))
}

#[cfg(test)]
mod tests {
    use super::super::{Outcome, dispatch, error, testing::task};
    use crate::{
        signal::{
            SA_RESTORER, SA_SIGINFO, SIGALRM, SIGUSR1, SIGUSR2, SigAction, SigSet, info::SigInfo,
            state::Target,
        },
        usercopy::copy_from_user,
    };
    use syscalls::{Errno, Sysno};

    const PAGE: u64 = 0x1000;
    fn neg(errno: Errno) -> Outcome {
        Outcome::Return(error(errno))
    }
    fn call(t: &mut super::super::testing::Task, no: Sysno, a: &[u64]) -> Outcome {
        let mut args = [0u64; 6];
        args[..a.len()].copy_from_slice(a);
        dispatch(t, no as u64, args)
    }
    fn put(t: &mut super::super::testing::Task, at: u64, bytes: &[u8]) {
        assert_eq!(crate::usercopy::copy_to_user(t, at, bytes), 0);
    }
    fn get<const N: usize>(t: &mut super::super::testing::Task, at: u64) -> [u8; N] {
        let mut out = [0u8; N];
        assert_eq!(copy_from_user(t, &mut out, at), 0);
        out
    }
    fn mapped() -> super::super::testing::Task {
        let mut t = task();
        t.pages.map(PAGE, true);
        t
    }
    fn itimerval(interval: (i64, i64), value: (i64, i64)) -> [u8; 32] {
        let mut raw = [0u8; 32];
        for (i, v) in [interval.0, interval.1, value.0, value.1]
            .into_iter()
            .enumerate()
        {
            raw[8 * i..8 * i + 8].copy_from_slice(&v.to_le_bytes());
        }
        raw
    }

    #[test]
    fn group_covers_exactly_the_signal_syscalls() {
        let mut t = mapped();
        for no in [
            Sysno::getpid,
            Sysno::write,
            Sysno::exit,
            Sysno::mmap,
            Sysno::rt_sigaction,
        ] {
            let claimed = super::dispatch(&mut t, no, [0; 6]).is_some();
            assert_eq!(claimed, no == Sysno::rt_sigaction, "{no:?}");
        }
        // kill(0 / -1) is a loud stop, never a guess.
        assert_eq!(
            call(&mut t, Sysno::kill, &[0, 9]),
            Outcome::Unimplemented(Sysno::kill as u32)
        );
        assert_eq!(
            call(&mut t, Sysno::kill, &[u64::MAX, 9]),
            Outcome::Unimplemented(Sysno::kill as u32)
        );
        // CPU-time interval timers wait for the time lane.
        assert_eq!(
            call(&mut t, Sysno::setitimer, &[1, 0, 0]),
            Outcome::Unimplemented(Sysno::setitimer as u32)
        );
        assert_eq!(
            call(&mut t, Sysno::getitimer, &[2, PAGE]),
            Outcome::Unimplemented(Sysno::getitimer as u32)
        );
        assert_eq!(
            call(&mut t, Sysno::getitimer, &[3, PAGE]),
            neg(Errno::EINVAL)
        );
    }

    #[test]
    fn sigaction_kill_and_pending_reach_the_state() {
        let mut t = mapped();
        let act = SigAction {
            handler: 0x4000,
            flags: SA_SIGINFO | SA_RESTORER,
            restorer: 0x5000,
            mask: SigSet(0),
        };
        put(&mut t, PAGE, &act.to_bytes());
        let sig = u64::from(SIGUSR1);
        assert_eq!(
            call(&mut t, Sysno::rt_sigaction, &[sig, PAGE, 0, 8]),
            Outcome::Return(0)
        );
        assert_eq!(t.state.actions[usize::from(SIGUSR1) - 1], act);
        // Block it, send it to ourselves, see it pending, unblock.
        put(&mut t, PAGE + 64, &SigSet::bit(SIGUSR1).to_le_bytes());
        assert_eq!(
            call(&mut t, Sysno::rt_sigprocmask, &[0, PAGE + 64, 0, 8]),
            Outcome::Return(0)
        );
        assert_eq!(call(&mut t, Sysno::kill, &[1, sig]), Outcome::Return(0));
        assert_eq!(
            call(&mut t, Sysno::rt_sigpending, &[PAGE + 128, 8]),
            Outcome::Return(0)
        );
        assert_eq!(
            get::<8>(&mut t, PAGE + 128),
            SigSet::bit(SIGUSR1).to_le_bytes()
        );
        assert_eq!(call(&mut t, Sysno::tgkill, &[1, 2, sig]), neg(Errno::ESRCH));
        assert_eq!(call(&mut t, Sysno::tkill, &[1, 65]), neg(Errno::EINVAL));
    }

    #[test]
    fn pause_sleeps_until_a_signal_and_asks_for_a_restart() {
        let mut t = mapped();
        t.script_signal(5_000, SIGUSR1);
        assert_eq!(call(&mut t, Sysno::pause, &[]), Outcome::Return(-514));
        assert_eq!(t.now, 5_000);
        assert!(t.state.pending_set().contains(SIGUSR1));
        // Already pending (unblocked): returns without waiting.
        let waits = t.waits;
        assert_eq!(call(&mut t, Sysno::pause, &[]), Outcome::Return(-514));
        assert_eq!(t.waits, waits);
    }

    #[test]
    fn sigsuspend_swaps_the_mask_and_keeps_the_old_one_for_the_return_path() {
        let mut t = mapped();
        t.state
            .set_blocked(SigSet(SigSet::bit(SIGUSR1) | SigSet::bit(SIGUSR2)));
        put(&mut t, PAGE, &0u64.to_le_bytes());
        t.script_signal(1_000, SIGUSR2);
        assert_eq!(
            call(&mut t, Sysno::rt_sigsuspend, &[PAGE, 8]),
            Outcome::Return(-514)
        );
        assert_eq!(t.state.blocked, SigSet::EMPTY);
        assert_eq!(
            t.state.saved_sigmask,
            Some(SigSet(SigSet::bit(SIGUSR1) | SigSet::bit(SIGUSR2)))
        );
        // Order: size, then the fault, before anything changes.
        let before = t.state.blocked;
        assert_eq!(
            call(&mut t, Sysno::rt_sigsuspend, &[PAGE, 4]),
            neg(Errno::EINVAL)
        );
        assert_eq!(
            call(&mut t, Sysno::rt_sigsuspend, &[0x9000, 8]),
            neg(Errno::EFAULT)
        );
        assert_eq!(t.state.blocked, before);
    }

    #[test]
    fn sleep_until_reports_the_time_left_when_a_signal_interrupts() {
        use crate::signal::wait::sleep_until;
        let mut t = mapped();
        // Deadline reached: None, even when a signal is pending as well.
        assert_eq!(sleep_until(&mut t, 5_000), None);
        assert_eq!(t.now, 5_000);
        // A signal at 8 us of a 20 us sleep: 12 us left.
        t.script_signal(8_000, SIGUSR1);
        assert_eq!(sleep_until(&mut t, 20_000), Some(12_000));
        assert_eq!(t.now, 8_000);
        // Still pending: returns at once with what is left.
        let waits = t.waits;
        assert_eq!(sleep_until(&mut t, 9_000), Some(1_000));
        assert_eq!(t.waits, waits);
        // The interval timer interrupts a sleep too.
        let mut t = mapped();
        put(&mut t, PAGE, &itimerval((0, 0), (0, 3)));
        assert_eq!(
            call(&mut t, Sysno::setitimer, &[0, PAGE, 0]),
            Outcome::Return(0)
        );
        assert_eq!(sleep_until(&mut t, 1_000_000), Some(1_000_000 - 3_000));
    }

    #[test]
    fn sigtimedwait_poll_timeout_and_wakeup() {
        let mut t = mapped();
        let set = SigSet(SigSet::bit(SIGUSR1));
        put(&mut t, PAGE, &set.0.to_le_bytes());
        let timeout = |t: &mut super::super::testing::Task, sec: i64, nsec: i64| {
            let mut raw = [0u8; 16];
            raw[..8].copy_from_slice(&sec.to_le_bytes());
            raw[8..].copy_from_slice(&nsec.to_le_bytes());
            put(t, PAGE + 256, &raw);
        };
        let wait = |t: &mut super::super::testing::Task, info: u64, ts: u64| {
            call(t, Sysno::rt_sigtimedwait, &[PAGE, info, ts, 8])
        };
        // Zero timeout: poll, EAGAIN, no sleeping.
        timeout(&mut t, 0, 0);
        assert_eq!(wait(&mut t, 0, PAGE + 256), neg(Errno::EAGAIN));
        assert_eq!(t.waits, 0);
        // 10 ms timeout elapses: EAGAIN after exactly the timeout.
        timeout(&mut t, 0, 10_000_000);
        let start = t.now;
        assert_eq!(wait(&mut t, 0, PAGE + 256), neg(Errno::EAGAIN));
        assert_eq!(t.now - start, 10_000_000);
        assert_eq!(t.state.blocked, SigSet::EMPTY, "mask restored");
        // A signal arriving during the wait is taken without running a handler.
        t.state.set_blocked(set);
        timeout(&mut t, 5, 0);
        t.script_signal(t.now + 20_000_000, SIGUSR1);
        let start = t.now;
        assert_eq!(wait(&mut t, PAGE + 512, PAGE + 256), Outcome::Return(10));
        assert_eq!(t.now - start, 20_000_000);
        assert_eq!(t.state.blocked, set, "blocked again afterwards");
        assert_eq!(t.state.pending_set(), SigSet::EMPTY, "consumed");
        let info = get::<128>(&mut t, PAGE + 512);
        assert_eq!(info[0..4], 10i32.to_le_bytes());
        // Argument order: size, set fault, timeout fault, then nsec.
        assert_eq!(
            call(&mut t, Sysno::rt_sigtimedwait, &[PAGE, 0, 0, 4]),
            neg(Errno::EINVAL)
        );
        assert_eq!(
            call(&mut t, Sysno::rt_sigtimedwait, &[0x9000, 0, PAGE + 256, 8]),
            neg(Errno::EFAULT)
        );
        assert_eq!(
            call(&mut t, Sysno::rt_sigtimedwait, &[PAGE, 0, 0x9000, 8]),
            neg(Errno::EFAULT)
        );
        timeout(&mut t, 0, 1_000_000_000);
        assert_eq!(wait(&mut t, 0, PAGE + 256), neg(Errno::EINVAL));
        timeout(&mut t, -1, 0);
        assert_eq!(wait(&mut t, 0, PAGE + 256), neg(Errno::EINVAL));
    }

    #[test]
    fn sigtimedwait_is_interrupted_by_another_unblocked_signal() {
        let mut t = mapped();
        put(&mut t, PAGE, &SigSet::bit(SIGUSR1).to_le_bytes());
        t.script_signal(1_000, SIGUSR2);
        // No timeout: waits until something wakes it; USR2 is not awaited.
        assert_eq!(
            call(&mut t, Sysno::rt_sigtimedwait, &[PAGE, 0, 0, 8]),
            neg(Errno::EINTR)
        );
        assert!(t.state.pending_set().contains(SIGUSR2));
    }

    #[test]
    fn real_itimer_expiry_wakes_a_wait_and_the_interval_rearms_on_dequeue() {
        let mut t = mapped();
        put(&mut t, PAGE, &itimerval((0, 30_000), (0, 20_000)));
        assert_eq!(
            call(&mut t, Sysno::setitimer, &[0, PAGE, PAGE + 64]),
            Outcome::Return(0)
        );
        assert_eq!(get::<32>(&mut t, PAGE + 64), itimerval((0, 0), (0, 0)));
        // pause: woken by the timer at 20 ms with SIGALRM from the kernel.
        assert_eq!(call(&mut t, Sysno::pause, &[]), Outcome::Return(-514));
        assert_eq!(t.now, 20_000_000);
        let (sig, info) = t.state.dequeue_signal().expect("SIGALRM pending");
        assert_eq!((sig, info), (SIGALRM, SigInfo::kernel(SIGALRM)));
        // Dequeue re-armed the interval timer on its grid: 20 + 30 ms.
        assert_eq!(t.state.itimer.next_event(), Some(50_000_000));
        assert_eq!(
            call(&mut t, Sysno::getitimer, &[0, PAGE + 128]),
            Outcome::Return(0)
        );
        assert_eq!(
            get::<32>(&mut t, PAGE + 128),
            itimerval((0, 30_000), (0, 30_000))
        );
        // alarm: replaces it, reports the rest rounded like Linux, and a
        // zero-second alarm cancels.
        assert_eq!(call(&mut t, Sysno::alarm, &[2]), Outcome::Return(1));
        assert_eq!(call(&mut t, Sysno::alarm, &[0]), Outcome::Return(2));
        assert_eq!(t.state.itimer.next_event(), None);
        assert_eq!(call(&mut t, Sysno::alarm, &[0]), Outcome::Return(0));
    }

    #[test]
    fn setitimer_validates_before_arming_and_orders_its_errors() {
        let mut t = mapped();
        // value unreadable / not canonical -> before the `which` check.
        assert_eq!(
            call(&mut t, Sysno::setitimer, &[7, 0x9000, 0]),
            neg(Errno::EFAULT)
        );
        put(&mut t, PAGE, &itimerval((0, 0), (0, 1_000_000)));
        assert_eq!(
            call(&mut t, Sysno::setitimer, &[7, PAGE, 0]),
            neg(Errno::EINVAL)
        );
        put(&mut t, PAGE, &itimerval((-1, 0), (0, 5)));
        assert_eq!(
            call(&mut t, Sysno::setitimer, &[0, PAGE, 0]),
            neg(Errno::EINVAL)
        );
        put(&mut t, PAGE, &itimerval((0, 0), (1, 5)));
        assert_eq!(
            call(&mut t, Sysno::setitimer, &[7, PAGE, 0]),
            neg(Errno::EINVAL)
        );
        assert_eq!(t.state.itimer.next_event(), None, "nothing armed by errors");
        // A bad `ovalue` is reported after the timer is armed.
        assert_eq!(
            call(&mut t, Sysno::setitimer, &[0, PAGE, 0x9000]),
            neg(Errno::EFAULT)
        );
        assert!(t.state.itimer.next_event().is_some());
        // NULL value disarms.
        assert_eq!(
            call(&mut t, Sysno::setitimer, &[0, 0, 0]),
            Outcome::Return(0)
        );
        assert_eq!(t.state.itimer.next_event(), None);
    }

    #[test]
    fn restart_syscall_without_a_block_is_eintr_and_sigreturn_is_wired() {
        let mut t = mapped();
        assert_eq!(call(&mut t, Sysno::restart_syscall, &[]), neg(Errno::EINTR));
        t.state
            .send_signal(SIGUSR1, SigInfo::kernel(SIGUSR1), Target::Thread)
            .unwrap();
        // The fake's rt_sigreturn reports the restored rax it was given.
        t.sigreturn_ret = 77;
        assert_eq!(call(&mut t, Sysno::rt_sigreturn, &[]), Outcome::Return(77));
    }
}
