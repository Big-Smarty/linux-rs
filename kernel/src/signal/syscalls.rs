// SPDX-License-Identifier: GPL-2.0-only
// Linux 6.18.57 (commit 2ff600d29ee478d0a8d46ef8a58afb5e038fe692):
// kernel/signal.c: `rt_sigprocmask` 3396, `do_sigpending`/`rt_sigpending`
// 3451-3480, `check_kill_permission` 827-864, `kill` 4027, `do_send_specific`
// 4197, `do_tkill`/`tgkill`/`tkill` 4226-4268, `do_sigaction` 4380,
// `do_sigaltstack`/`sigaltstack` 4468-4535, `rt_sigaction` 4707,
// `kill_something_info` 1628; arch/x86/kernel/signal.c:340-439
// (`sigaltstack_size_valid`). All GPL-2.0.
#![forbid(unsafe_code)]
#![allow(
    clippy::similar_names,
    reason = "uss/uoss, tgid/tid are the Linux argument names"
)]
//! The signal syscalls as pure functions over [`State`] and user memory.
//!
//! Every function returns the value Linux leaves in `rax`. Integer arguments
//! arrive as the raw register and are truncated to the C type exactly as the
//! syscall wrapper does (`int` -> low 32 bits); `size_t` and pointers are
//! used whole. User memory is touched only through `copy_{from,to}_user`.

use super::{
    AltStack, MINSIGSTKSZ, SS_DISABLE, SS_FLAG_BITS, SS_ONSTACK, SigAction, SigSet, UAPI_SA_FLAGS,
    info::{SI_TKILL, SigInfo, known_layout},
    sig_kernel_only,
    state::State,
    state::Target,
    valid_signal,
};
use crate::usercopy::{UserPages, copy_from_user, copy_to_user};
use syscalls::Errno;

#[inline]
fn err(errno: Errno) -> i64 {
    -i64::from(errno.into_raw())
}

/// `copy_from_user` of exactly `N` bytes; `None` is `-EFAULT`.
pub(super) fn get_user<P: UserPages, const N: usize>(
    pages: &mut P,
    address: u64,
) -> Option<[u8; N]> {
    let mut bytes = [0; N];
    (copy_from_user(pages, &mut bytes, address) == 0).then_some(bytes)
}

/// `copy_to_user`; `false` is `-EFAULT`. Bytes before a fault are written.
pub(super) fn put_user<P: UserPages>(pages: &mut P, address: u64, bytes: &[u8]) -> bool {
    copy_to_user(pages, address, bytes) == 0
}

#[allow(clippy::cast_possible_truncation)]
const fn int(register: u64) -> i32 {
    register as i32
}

/// `rt_sigaction(sig, act, oact, sigsetsize)`.
///
/// Order: `sigsetsize != 8` -> `EINVAL`; read `act` (`EFAULT`); `do_sigaction`
/// (`EINVAL` for an invalid or 0 signal, for SIGKILL/SIGSTOP when `act` is
/// given, and for an `SA_IMMUTABLE` action); write `oact` (`EFAULT`, after the
/// new action is already installed, as in Linux).
pub fn sys_rt_sigaction<P: UserPages>(
    state: &mut State,
    pages: &mut P,
    sig: u64,
    act: u64,
    oact: u64,
    sigsetsize: u64,
) -> i64 {
    if sigsetsize != 8 {
        return err(Errno::EINVAL);
    }
    let new = if act == 0 {
        None
    } else {
        match get_user::<_, { SigAction::SIZE }>(pages, act) {
            Some(bytes) => Some(SigAction::from_bytes(&bytes)),
            None => return err(Errno::EFAULT),
        }
    };
    let sig = int(sig);
    let old = match do_sigaction(state, sig, new) {
        Ok(old) => old,
        Err(errno) => return err(errno),
    };
    if oact != 0 && !put_user(pages, oact, &old.to_bytes()) {
        return err(Errno::EFAULT);
    }
    0
}

/// `do_sigaction`: returns the previous action (flags limited to
/// `UAPI_SA_FLAGS`).
///
/// # Errors
/// `EINVAL` as described at [`sys_rt_sigaction`].
pub fn do_sigaction(
    state: &mut State,
    sig: i32,
    new: Option<SigAction>,
) -> Result<SigAction, Errno> {
    if !valid_signal(sig) || sig < 1 {
        return Err(Errno::EINVAL);
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let sig = sig as u8;
    if new.is_some() && sig_kernel_only(sig) {
        return Err(Errno::EINVAL);
    }
    let slot = &mut state.actions[usize::from(sig) - 1];
    if slot.flags & super::SA_IMMUTABLE != 0 {
        return Err(Errno::EINVAL);
    }
    let mut old = *slot;
    old.flags &= UAPI_SA_FLAGS;
    if let Some(mut act) = new {
        act.flags &= UAPI_SA_FLAGS;
        act.mask = act.mask.without_unblockable();
        *slot = act;
        // POSIX 3.3.1.3: ignoring a pending signal discards it, blocked or not.
        if act.ignored(sig) {
            state.flush_signals(SigSet::bit(sig));
        }
    }
    Ok(old)
}

/// `rt_sigprocmask(how, nset, oset, sigsetsize)`.
///
/// Order: size (`EINVAL`), read `nset` (`EFAULT`), apply `how` (`EINVAL` for
/// anything but 0/1/2, nothing changes), write the *old* mask to `oset`
/// (`EFAULT`, the new mask is already in force). SIGKILL/SIGSTOP are removed
/// from the set before it is applied.
pub fn sys_rt_sigprocmask<P: UserPages>(
    state: &mut State,
    pages: &mut P,
    how: u64,
    nset: u64,
    oset: u64,
    sigsetsize: u64,
) -> i64 {
    if sigsetsize != 8 {
        return err(Errno::EINVAL);
    }
    let old = state.blocked;
    if nset != 0 {
        let Some(bytes) = get_user::<_, 8>(pages, nset) else {
            return err(Errno::EFAULT);
        };
        let set = SigSet(u64::from_le_bytes(bytes)).without_unblockable();
        let new = match int(how) {
            0 => SigSet(old.0 | set.0),  // SIG_BLOCK
            1 => SigSet(old.0 & !set.0), // SIG_UNBLOCK
            2 => set,                    // SIG_SETMASK
            _ => return err(Errno::EINVAL),
        };
        state.set_blocked(new);
    }
    if oset != 0 && !put_user(pages, oset, &old.0.to_le_bytes()) {
        return err(Errno::EFAULT);
    }
    0
}

/// `rt_sigpending(uset, sigsetsize)`: `blocked & (private | shared)`, the low
/// `sigsetsize` bytes of it. `sigsetsize > 8` is `EINVAL`; smaller sizes
/// truncate the answer (including 0, which copies nothing and succeeds).
pub fn sys_rt_sigpending<P: UserPages>(
    state: &State,
    pages: &mut P,
    uset: u64,
    sigsetsize: u64,
) -> i64 {
    if sigsetsize > 8 {
        return err(Errno::EINVAL);
    }
    let set = state.blocked.0 & state.pending_set().0;
    #[allow(clippy::cast_possible_truncation)]
    let len = sigsetsize as usize;
    if put_user(pages, uset, &set.to_le_bytes()[..len]) {
        0
    } else {
        err(Errno::EFAULT)
    }
}

/// `sigaltstack_size_valid`: with `CONFIG_DYNAMIC_SIGFRAME=y`, unless the FPU
/// state is dynamically sized or `strict_sas_size` is on, any size passes.
/// The declared configuration (`noxsave`) has neither, so this is `true`;
/// the strict rule compares against the worst-case frame minus the default FPU
/// state plus the user FPU state (512 bytes under FXSR-only).
#[must_use]
pub const fn sigaltstack_size_valid(size: u64, strict: bool) -> bool {
    if !strict {
        return true; // !fpu_state_size_dynamic() && !strict_sigaltstack_size
    }
    size > super::frame::MAX_FRAME_SIZE - super::frame::FPU_DEFAULT_STATE_SIZE
        + super::frame::FXSAVE_SIZE as u64
}

/// `strict_sigaltstack_size` (`CONFIG_STRICT_SIGALTSTACK_SIZE` is off and no
/// `strict_sas_size` boot parameter).
pub const STRICT_SIGALTSTACK_SIZE: bool = false;

/// `stack_t` as the syscall exchanges it: `ss_sp`, `ss_flags` (+4 padding),
/// `ss_size`; 24 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StackT {
    pub sp: u64,
    pub flags: u32,
    pub size: u64,
}

impl StackT {
    pub const SIZE: usize = 24;

    #[must_use]
    pub fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut out = [0; Self::SIZE];
        out[0..8].copy_from_slice(&self.sp.to_le_bytes());
        out[8..12].copy_from_slice(&self.flags.to_le_bytes());
        out[16..24].copy_from_slice(&self.size.to_le_bytes());
        out
    }
    #[must_use]
    pub fn from_bytes(b: &[u8; Self::SIZE]) -> Self {
        Self {
            sp: u64::from_le_bytes(super::le(b, 0)),
            flags: u32::from_le_bytes(super::le(b, 8)),
            size: u64::from_le_bytes(super::le(b, 16)),
        }
    }
}

/// `do_sigaltstack(ss, oss, sp, min_ss_size)`. `sp` is the user stack pointer.
///
/// # Errors
/// `EPERM` while running on the alternate stack, `EINVAL` for a bad mode,
/// `ENOMEM` for a size below `min_ss_size` (or failing
/// [`sigaltstack_size_valid`]). The old stack is computed first and returned
/// even on error, like `oss` in Linux, but callers only publish it on success.
pub fn do_sigaltstack(
    state: &mut State,
    new: Option<StackT>,
    sp: u64,
    min_ss_size: u64,
) -> (StackT, Result<(), Errno>) {
    let st = state.altstack;
    let old = StackT {
        sp: st.sp,
        flags: st.ss_flags(sp) | (st.flags & SS_FLAG_BITS),
        size: st.size,
    };
    let Some(StackT {
        sp: ss_sp,
        flags,
        size,
    }) = new
    else {
        return (old, Ok(()));
    };
    if st.on_stack(sp) {
        return (old, Err(Errno::EPERM));
    }
    let mode = flags & !SS_FLAG_BITS;
    if mode != SS_DISABLE && mode != SS_ONSTACK && mode != 0 {
        return (old, Err(Errno::EINVAL));
    }
    // No change requested: return before any size check.
    if st.sp == ss_sp && st.size == size && st.flags == flags {
        return (old, Ok(()));
    }
    let (ss_sp, size) = if mode == SS_DISABLE {
        (0, 0)
    } else {
        if size < min_ss_size || !sigaltstack_size_valid(size, STRICT_SIGALTSTACK_SIZE) {
            return (old, Err(Errno::ENOMEM));
        }
        (ss_sp, size)
    };
    state.altstack = AltStack {
        sp: ss_sp,
        size,
        flags,
    };
    (old, Ok(()))
}

/// `sigaltstack(uss, uoss)`; `sp` is `regs->sp` at syscall entry.
/// Order: read `uss` (`EFAULT`), `do_sigaltstack`, write `uoss` (`EFAULT`, only
/// when the call succeeded; the new stack is then already installed).
pub fn sys_sigaltstack<P: UserPages>(
    state: &mut State,
    pages: &mut P,
    uss: u64,
    uoss: u64,
    sp: u64,
) -> i64 {
    let new = if uss == 0 {
        None
    } else {
        match get_user::<_, { StackT::SIZE }>(pages, uss) {
            Some(bytes) => Some(StackT::from_bytes(&bytes)),
            None => return err(Errno::EFAULT),
        }
    };
    let (old, result) = do_sigaltstack(state, new, sp, MINSIGSTKSZ);
    if let Err(errno) = result {
        return err(errno);
    }
    if uoss != 0 && !put_user(pages, uoss, &old.to_bytes()) {
        return err(Errno::EFAULT);
    }
    0
}

/// `check_kill_permission` for a sender in the target's own thread group:
/// only `valid_signal` applies (no credential check, no LSM/audit hooks yet).
fn check_kill_permission(sig: i32) -> Result<(), Errno> {
    if valid_signal(sig) {
        Ok(())
    } else {
        Err(Errno::EINVAL)
    }
}

/// Deliver `info` as `sig` (0 only probes) to this process. `Err` is `EAGAIN`
/// from an RT queue overflow.
fn send_info(state: &mut State, sig: i32, info: SigInfo, thread: bool) -> Result<(), Errno> {
    check_kill_permission(sig)?;
    if sig == 0 {
        return Ok(()); // existence/permission probe
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let sig = sig as u8;
    let target = if thread {
        Target::Thread
    } else {
        Target::Process
    };
    state.send_signal(sig, info, target)
}

/// `kill`/`tkill` source info (`prepare_kill_siginfo`) then [`send_info`].
fn send_to_self(state: &mut State, sig: i32, thread: bool) -> Result<(), Errno> {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let info = SigInfo::from_kill(sig as u8, thread, state.tgid, state.uid);
    send_info(state, sig, info, thread)
}

fn status(result: Result<(), Errno>) -> i64 {
    result.map_or_else(err, |()| 0)
}

/// `kill(pid, sig)`. `None` means the target selection (`pid == 0`: the
/// caller's process group, `pid == -1`: every process) depends on a process
/// table this model does not have; the caller reports an unimplemented
/// syscall instead of guessing.
///
/// shortcut: a positive `pid` other than this process is `ESRCH` and a
/// `pid < -1` (a process group other than init's, which has pgid <= 1) is
/// `ESRCH`; that is exact for a system with one process and wrong the moment a
/// second exists. Upgrade with the pid table (`find_vpid`, `__kill_pgrp_info`).
pub fn sys_kill(state: &mut State, pid: u64, sig: u64) -> Option<i64> {
    let (pid, sig) = (int(pid), int(sig));
    Some(if pid > 0 {
        if pid == state.tgid {
            status(send_to_self(state, sig, false))
        } else {
            err(Errno::ESRCH)
        }
    } else if pid == i32::MIN || pid < -1 {
        err(Errno::ESRCH)
    } else {
        return None;
    })
}

/// `do_send_specific`: find the task, then permission, then send. `info` is
/// `None` for tkill/tgkill (kill-style source info).
fn send_specific(state: &mut State, tgid: i32, tid: i32, sig: i32, info: Option<SigInfo>) -> i64 {
    if tid == state.pid && (tgid <= 0 || tgid == state.tgid) {
        status(match info {
            None => send_to_self(state, sig, true),
            Some(info) => send_info(state, sig, info, true),
        })
    } else {
        err(Errno::ESRCH)
    }
}

/// `tgkill(tgid, pid, sig)`: `EINVAL` for a non-positive id, `ESRCH` when the
/// thread is not in that group, `EINVAL` for a bad signal.
pub fn sys_tgkill(state: &mut State, tgid: u64, tid: u64, sig: u64) -> i64 {
    let (tgid, tid) = (int(tgid), int(tid));
    if tid <= 0 || tgid <= 0 {
        return err(Errno::EINVAL);
    }
    send_specific(state, tgid, tid, int(sig), None)
}

/// `tkill(pid, sig)`.
pub fn sys_tkill(state: &mut State, tid: u64, sig: u64) -> i64 {
    let tid = int(tid);
    if tid <= 0 {
        return err(Errno::EINVAL);
    }
    send_specific(state, 0, tid, int(sig), None)
}

/// `__copy_siginfo_from_user(signo, ..)`: 48 bytes (`EFAULT`), `si_signo`
/// overwritten, and for a `(signo, si_code)` the kernel has no layout for the
/// 80 expansion bytes must be readable (`EFAULT`) and zero (`E2BIG`).
fn copy_siginfo_from_user<P: UserPages>(
    pages: &mut P,
    signo: i32,
    uinfo: u64,
) -> Result<SigInfo, Errno> {
    let mut raw = [0u8; SigInfo::SIZE];
    if copy_from_user(pages, &mut raw[..48], uinfo) != 0 {
        return Err(Errno::EFAULT);
    }
    let info = SigInfo::from_user(&raw, signo);
    if !known_layout(signo, info.code) {
        if copy_from_user(pages, &mut raw[48..], uinfo.wrapping_add(48)) != 0 {
            return Err(Errno::EFAULT);
        }
        if raw[48..].iter().any(|&b| b != 0) {
            return Err(Errno::E2BIG);
        }
    }
    Ok(info)
}

/// "Not even root can pretend to send signals from the kernel, nor impersonate
/// a kill()/tgkill()": user codes `>= 0` and `SI_TKILL` only to oneself.
fn queueinfo_perm(info: &SigInfo, state: &State, pid: i32) -> Result<(), Errno> {
    if (info.code >= 0 || info.code == SI_TKILL) && state.pid != pid {
        Err(Errno::EPERM)
    } else {
        Ok(())
    }
}

/// `rt_sigqueueinfo(pid, sig, uinfo)`: copy and validate the user info, the
/// `EPERM` rule, then `kill_proc_info`: a `pid <= 0` or any pid but this
/// process is `ESRCH` (no group semantics here), then `EINVAL` for a bad signal.
/// The sender-supplied pid/uid/value are delivered as given.
pub fn sys_rt_sigqueueinfo<P: UserPages>(
    state: &mut State,
    pages: &mut P,
    pid: u64,
    sig: u64,
    uinfo: u64,
) -> i64 {
    let (pid, sig) = (int(pid), int(sig));
    let info = match copy_siginfo_from_user(pages, sig, uinfo) {
        Ok(info) => info,
        Err(errno) => return err(errno),
    };
    if let Err(errno) = queueinfo_perm(&info, state, pid) {
        return err(errno);
    }
    if pid != state.tgid {
        return err(Errno::ESRCH);
    }
    status(send_info(state, sig, info, false))
}

/// `rt_tgsigqueueinfo(tgid, pid, sig, uinfo)`: copy, then `EINVAL` for
/// non-positive ids, `EPERM`, and `do_send_specific`.
pub fn sys_rt_tgsigqueueinfo<P: UserPages>(
    state: &mut State,
    pages: &mut P,
    tgid: u64,
    tid: u64,
    sig: u64,
    uinfo: u64,
) -> i64 {
    let (tgid, tid, sig) = (int(tgid), int(tid), int(sig));
    let info = match copy_siginfo_from_user(pages, sig, uinfo) {
        Ok(info) => info,
        Err(errno) => return err(errno),
    };
    if tid <= 0 || tgid <= 0 {
        return err(Errno::EINVAL);
    }
    if let Err(errno) = queueinfo_perm(&info, state, tid) {
        return err(errno);
    }
    send_specific(state, tgid, tid, sig, Some(info))
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
    extern crate std;
    use super::*;
    use crate::{
        signal::{
            SA_ONSTACK, SA_RESTORER, SA_SIGINFO, SIG_IGN, SIGHUP, SIGKILL, SIGTERM, SIGUSR1,
            SS_AUTODISARM,
        },
        usercopy::fake::Space,
    };

    const EINVAL: i64 = -22;
    const EFAULT: i64 = -14;
    const EPERM: i64 = -1;
    const ESRCH: i64 = -3;
    const ENOMEM: i64 = -12;
    const EAGAIN: i64 = -11;

    fn space() -> Space {
        let mut s = Space::default();
        s.map(0x1000, true);
        s.map(0x2000, false); // read-only
        s
    }
    fn init() -> State {
        State::new_init(1000)
    }
    fn put(s: &mut Space, at: u64, b: &[u8]) {
        assert_eq!(copy_to_user(s, at, b), 0);
    }
    fn get(s: &mut Space, at: u64, n: usize) -> std::vec::Vec<u8> {
        let mut b = std::vec![0; n];
        assert_eq!(copy_from_user(s, &mut b, at), 0);
        b
    }

    #[test]
    fn rt_sigaction_check_order() {
        let mut st = init();
        let mut sp = space();
        // sigsetsize first, even with a bad pointer and bad signal.
        assert_eq!(
            sys_rt_sigaction(&mut st, &mut sp, 999, 0xdead_0000, 0, 4),
            EINVAL
        );
        // Then copy_from_user(act): EFAULT beats the invalid signal 999.
        assert_eq!(
            sys_rt_sigaction(&mut st, &mut sp, 999, 0x9000, 0, 8),
            EFAULT
        );
        // Then the signal checks.
        let act = SigAction {
            handler: 0x4000,
            flags: 0,
            restorer: 0,
            mask: SigSet(0),
        };
        put(&mut sp, 0x1000, &act.to_bytes());
        for sig in [0u64, 65, 0xffff_ffff, 1 << 32 | 0xffff_ffff] {
            assert_eq!(
                sys_rt_sigaction(&mut st, &mut sp, sig, 0x1000, 0, 8),
                EINVAL,
                "{sig}"
            );
        }
        // SIGKILL/SIGSTOP: EINVAL with act, queryable without.
        assert_eq!(sys_rt_sigaction(&mut st, &mut sp, 9, 0x1000, 0, 8), EINVAL);
        assert_eq!(sys_rt_sigaction(&mut st, &mut sp, 19, 0x1000, 0, 8), EINVAL);
        assert_eq!(sys_rt_sigaction(&mut st, &mut sp, 9, 0, 0x1100, 8), 0);
        // sig is `int`: the high half of the register is ignored.
        assert_eq!(
            sys_rt_sigaction(&mut st, &mut sp, 1 << 40 | 10, 0x1000, 0, 8),
            0
        );
        assert_eq!(st.actions[9].handler, 0x4000);
    }

    #[test]
    fn rt_sigaction_masks_flags_and_reports_old() {
        let mut st = init();
        let mut sp = space();
        let act = SigAction {
            handler: 0x4000,
            flags: SA_SIGINFO | SA_RESTORER | SA_ONSTACK | 0x1_0000_0000 | 0x2000_0000 | 0x400,
            restorer: 0x5000,
            mask: SigSet(u64::MAX),
        };
        put(&mut sp, 0x1000, &act.to_bytes());
        assert_eq!(sys_rt_sigaction(&mut st, &mut sp, 10, 0x1000, 0x1100, 8), 0);
        // Old action was the default.
        assert_eq!(
            get(&mut sp, 0x1100, 32)[..],
            SigAction::default().to_bytes()
        );
        let k = st.actions[9];
        assert_eq!(k.flags, SA_SIGINFO | SA_RESTORER | SA_ONSTACK); // UAPI_SA_FLAGS only
        assert_eq!(k.mask, SigSet(!(SigSet::bit(9) | SigSet::bit(19))));
        // Reading back returns what was stored.
        assert_eq!(sys_rt_sigaction(&mut st, &mut sp, 10, 0, 0x1100, 8), 0);
        assert_eq!(get(&mut sp, 0x1100, 32)[..], k.to_bytes());
        // oact fault happens after the action is installed.
        let act2 = SigAction {
            handler: 0x6000,
            ..act
        };
        put(&mut sp, 0x1000, &act2.to_bytes());
        assert_eq!(
            sys_rt_sigaction(&mut st, &mut sp, 10, 0x1000, 0x2000, 8),
            EFAULT
        );
        assert_eq!(st.actions[9].handler, 0x6000);
    }

    #[test]
    fn rt_sigaction_ignore_discards_pending() {
        let mut st = State::new(5, 0, 100);
        st.blocked.add(SIGUSR1);
        st.blocked.add(SIGHUP);
        st.send_signal(
            SIGUSR1,
            SigInfo::from_kill(10, false, 1, 0),
            Target::Process,
        )
        .unwrap();
        st.send_signal(SIGHUP, SigInfo::from_kill(1, false, 1, 0), Target::Process)
            .unwrap();
        let mut sp = space();
        let ign = SigAction {
            handler: crate::signal::SIG_IGN,
            ..SigAction::default()
        };
        put(&mut sp, 0x1000, &ign.to_bytes());
        assert_eq!(sys_rt_sigaction(&mut st, &mut sp, 10, 0x1000, 0, 8), 0);
        assert!(!st.pending_set().contains(SIGUSR1));
        assert!(st.pending_set().contains(SIGHUP));
        // SIG_DFL on a default-ignored signal also discards it.
        st.blocked.add(crate::signal::SIGCHLD);
        st.actions[16].handler = 0x1234;
        st.send_signal(17, SigInfo::from_kill(17, false, 1, 0), Target::Process)
            .unwrap();
        assert!(st.pending_set().contains(17));
        put(&mut sp, 0x1000, &SigAction::default().to_bytes());
        assert_eq!(sys_rt_sigaction(&mut st, &mut sp, 17, 0x1000, 0, 8), 0);
        assert!(!st.pending_set().contains(17));
    }

    fn handled(sig: u8) -> State {
        let mut st = State::new(7, 0, 100_000);
        st.actions[usize::from(sig) - 1].handler = 0x1000;
        st.blocked.add(sig);
        st
    }
    fn drain(st: &mut State) -> usize {
        st.blocked = SigSet::EMPTY;
        let mut n = 0;
        while st.dequeue_signal().is_some() {
            n += 1;
        }
        n
    }

    #[test]
    fn tkill_pends_privately_so_sig_ign_flushes_it() {
        // tkill -> tsk->pending, flushed by `flush_sigqueue_mask` on SIG_IGN.
        let mut st = handled(SIGUSR1);
        assert_eq!(sys_tkill(&mut st, 7, 10), 0);
        assert!(st.pending_set().contains(SIGUSR1));
        let mut sp = space();
        put(
            &mut sp,
            0x1000,
            &SigAction {
                handler: SIG_IGN,
                ..SigAction::default()
            }
            .to_bytes(),
        );
        assert_eq!(sys_rt_sigaction(&mut st, &mut sp, 10, 0x1000, 0, 8), 0);
        assert_eq!(st.pending_set(), SigSet::EMPTY);
    }

    #[test]
    fn kill_and_tkill_queue_separately_but_sigqueueinfo_is_process_wide() {
        // legacy_queue looks at the target queue only (kernel/signal.c:1061):
        // kill (shared) + tkill (private) deliver twice.
        let mut st = handled(SIGUSR1);
        assert_eq!(sys_kill(&mut st, 7, 10), Some(0));
        assert_eq!(sys_tkill(&mut st, 7, 10), 0);
        assert_eq!(drain(&mut st), 2);
        // rt_sigqueueinfo targets the process like kill: coalesces with it.
        let mut st = handled(SIGUSR1);
        let mut sp = space();
        let mut info = [0u8; 128];
        info[8..12].copy_from_slice(&(-1i32).to_le_bytes()); // SI_QUEUE
        put(&mut sp, 0x1000, &info);
        assert_eq!(sys_kill(&mut st, 7, 10), Some(0));
        assert_eq!(sys_rt_sigqueueinfo(&mut st, &mut sp, 7, 10, 0x1000), 0);
        assert_eq!(drain(&mut st), 1);
    }

    #[test]
    fn rt_tkill_queue_holds_64_entries_then_eagain() {
        // The array cap is 64 RT entries per queue (shortcut in state.rs).
        let mut st = handled(40);
        for n in 0..70u32 {
            let want = if n < 64 { 0 } else { EAGAIN };
            assert_eq!(sys_tkill(&mut st, 7, 40), want, "tkill {n}");
        }
        assert_eq!(drain(&mut st), 64);
    }

    #[test]
    fn rt_sigaction_immutable_is_einval() {
        let mut st = init();
        st.force_exit_sig(11);
        let mut sp = space();
        assert_eq!(sys_rt_sigaction(&mut st, &mut sp, 11, 0, 0x1000, 8), EINVAL);
    }

    #[test]
    fn rt_sigprocmask_semantics() {
        let mut st = init();
        let mut sp = space();
        let set = |sp: &mut Space, bits: u64| put(sp, 0x1000, &bits.to_le_bytes());
        assert_eq!(
            sys_rt_sigprocmask(&mut st, &mut sp, 0, 0x1000, 0, 16),
            EINVAL
        );
        set(&mut sp, 0b1110_0000_0000 | SigSet::bit(9) | SigSet::bit(19));
        // SIG_BLOCK never blocks KILL/STOP.
        assert_eq!(
            sys_rt_sigprocmask(&mut st, &mut sp, 0, 0x1000, 0x1100, 8),
            0
        );
        assert_eq!(st.blocked, SigSet(0b1110_0000_0000));
        assert_eq!(get(&mut sp, 0x1100, 8)[..], 0u64.to_le_bytes());
        // SIG_UNBLOCK.
        set(&mut sp, 0b0110_0000_0000);
        assert_eq!(
            sys_rt_sigprocmask(&mut st, &mut sp, 1, 0x1000, 0x1100, 8),
            0
        );
        assert_eq!(st.blocked, SigSet(0b1000_0000_0000));
        assert_eq!(
            get(&mut sp, 0x1100, 8)[..],
            0b1110_0000_0000u64.to_le_bytes()
        );
        // SIG_SETMASK.
        set(&mut sp, u64::MAX);
        assert_eq!(sys_rt_sigprocmask(&mut st, &mut sp, 2, 0x1000, 0, 8), 0);
        assert_eq!(st.blocked, SigSet(u64::MAX).without_unblockable());
        // Bad `how`: EINVAL, nothing changed, nset still read first (EFAULT wins).
        let before = st.blocked;
        assert_eq!(
            sys_rt_sigprocmask(&mut st, &mut sp, 3, 0x1000, 0, 8),
            EINVAL
        );
        assert_eq!(
            sys_rt_sigprocmask(&mut st, &mut sp, 3, 0x9000, 0, 8),
            EFAULT
        );
        assert_eq!(st.blocked, before);
        // `how` is an int.
        assert_eq!(
            sys_rt_sigprocmask(&mut st, &mut sp, 1 << 32 | 2, 0x1000, 0, 8),
            0
        );
        // nset NULL: query only. oset fault comes after the change.
        set(&mut sp, 0);
        assert_eq!(
            sys_rt_sigprocmask(&mut st, &mut sp, 2, 0x1000, 0x2000, 8),
            EFAULT
        );
        assert_eq!(st.blocked, SigSet::EMPTY);
        assert_eq!(sys_rt_sigprocmask(&mut st, &mut sp, 99, 0, 0x1100, 8), 0);
    }

    #[test]
    fn rt_sigpending_truncates_and_checks_size() {
        let mut st = State::new(5, 0, 100);
        st.blocked = SigSet(0xffff_ffff_ffff);
        let mk = |sig| SigInfo::from_kill(sig, false, 1, 0);
        st.send_signal(10, mk(10), Target::Process).unwrap();
        st.send_signal(40, mk(40), Target::Thread).unwrap();
        st.blocked = SigSet(1 << 9); // only 10 blocked
        let mut sp = space();
        assert_eq!(sys_rt_sigpending(&st, &mut sp, 0x1000, 9), EINVAL);
        assert_eq!(sys_rt_sigpending(&st, &mut sp, 0x1000, 8), 0);
        assert_eq!(get(&mut sp, 0x1000, 8)[..], (1u64 << 9).to_le_bytes());
        st.blocked = SigSet(u64::MAX);
        put(&mut sp, 0x1010, &[0xaa; 8]);
        assert_eq!(sys_rt_sigpending(&st, &mut sp, 0x1010, 2), 0);
        let b = get(&mut sp, 0x1010, 8);
        assert_eq!(b[..8], [0x00, 0x02, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa]);
        // Size 0 copies nothing; faulting address still fails for size > 0.
        assert_eq!(sys_rt_sigpending(&st, &mut sp, 0x9000, 0), 0);
        assert_eq!(sys_rt_sigpending(&st, &mut sp, 0x9000, 8), EFAULT);
    }

    #[test]
    fn sigaltstack_rules() {
        let mut st = init();
        let mut sp = space();
        let put_ss = |sp: &mut Space, ss: StackT| put(sp, 0x1000, &ss.to_bytes());
        let ss = |sp_, flags, size| StackT {
            sp: sp_,
            flags,
            size,
        };
        // Initial state: disabled.
        assert_eq!(sys_sigaltstack(&mut st, &mut sp, 0, 0x1100, 0x7000), 0);
        assert_eq!(
            get(&mut sp, 0x1100, 24)[..],
            ss(0, SS_DISABLE, 0).to_bytes()
        );
        // Too small -> ENOMEM; exactly MINSIGSTKSZ is fine (no AT_MINSIGSTKSZ rule).
        put_ss(&mut sp, ss(0x10_0000, 0, 2047));
        assert_eq!(sys_sigaltstack(&mut st, &mut sp, 0x1000, 0, 0x7000), ENOMEM);
        put_ss(&mut sp, ss(0x10_0000, 0, 2048));
        assert_eq!(sys_sigaltstack(&mut st, &mut sp, 0x1000, 0, 0x7000), 0);
        assert_eq!(
            st.altstack,
            AltStack {
                sp: 0x10_0000,
                size: 2048,
                flags: 0
            }
        );
        // Bad mode -> EINVAL (checked before size).
        put_ss(&mut sp, ss(0x10_0000, 4, 1));
        assert_eq!(sys_sigaltstack(&mut st, &mut sp, 0x1000, 0, 0x7000), EINVAL);
        // On the alternate stack: EPERM beats EINVAL.
        assert_eq!(
            sys_sigaltstack(&mut st, &mut sp, 0x1000, 0, 0x10_0000 + 100),
            EPERM
        );
        // Report: SS_ONSTACK while on it, old values even with a NULL uss.
        assert_eq!(
            sys_sigaltstack(&mut st, &mut sp, 0, 0x1100, 0x10_0000 + 100),
            0
        );
        assert_eq!(
            get(&mut sp, 0x1100, 24)[..],
            ss(0x10_0000, SS_ONSTACK, 2048).to_bytes()
        );
        // sp == top is on the stack, sp == base is not (`sp > sas_ss_sp`).
        assert_eq!(st.altstack.ss_flags(0x10_0000 + 2048), SS_ONSTACK);
        assert_eq!(st.altstack.ss_flags(0x10_0000), 0);
        // Unchanged request returns before size checks; DISABLE zeroes the rest.
        put_ss(&mut sp, ss(0x10_0000, 0, 2048));
        assert_eq!(sys_sigaltstack(&mut st, &mut sp, 0x1000, 0, 0x7000), 0);
        put_ss(&mut sp, ss(0xabc, SS_DISABLE, 77));
        assert_eq!(sys_sigaltstack(&mut st, &mut sp, 0x1000, 0, 0x7000), 0);
        assert_eq!(
            st.altstack,
            AltStack {
                sp: 0,
                size: 0,
                flags: SS_DISABLE
            }
        );
        // AUTODISARM: stored, reported, and "never on the stack".
        put_ss(&mut sp, ss(0x20_0000, SS_AUTODISARM, 4096));
        assert_eq!(sys_sigaltstack(&mut st, &mut sp, 0x1000, 0, 0x7000), 0);
        assert_eq!(st.altstack.flags, SS_AUTODISARM);
        assert!(!st.altstack.on_stack(0x20_0000 + 10));
        assert_eq!(
            sys_sigaltstack(&mut st, &mut sp, 0x1000, 0x1100, 0x20_0000 + 10),
            0
        );
        assert_eq!(
            get(&mut sp, 0x1100, 24)[..],
            ss(0x20_0000, SS_AUTODISARM, 4096).to_bytes()
        );
        // Faults: uss unreadable -> EFAULT; uoss unwritable after success.
        assert_eq!(sys_sigaltstack(&mut st, &mut sp, 0x9000, 0, 0x7000), EFAULT);
        assert_eq!(sys_sigaltstack(&mut st, &mut sp, 0, 0x2000, 0x7000), EFAULT);
    }

    #[test]
    fn sigaltstack_strict_rule_uses_frame_size() {
        // 0x5a0 - 624 + 512 = 1328: strict mode needs size > 1328.
        assert!(!sigaltstack_size_valid(1328, true));
        assert!(sigaltstack_size_valid(1329, true));
        assert!(sigaltstack_size_valid(1, false));
    }

    #[test]
    fn kill_family_on_one_process() {
        let mut init = init();
        // Default-action signals are dropped for init but kill() succeeds.
        assert_eq!(sys_kill(&mut init, 1, 15), Some(0));
        assert_eq!(init.pending_set(), SigSet::EMPTY);
        // Signal 0 probes; invalid signals are EINVAL only once the target exists.
        assert_eq!(sys_kill(&mut init, 1, 0), Some(0));
        assert_eq!(sys_kill(&mut init, 1, 65), Some(EINVAL));
        assert_eq!(sys_kill(&mut init, 1, 0xffff_ffff), Some(EINVAL));
        assert_eq!(sys_kill(&mut init, 2, 65), Some(ESRCH));
        assert_eq!(sys_kill(&mut init, 77, 9), Some(ESRCH));
        assert_eq!(sys_kill(&mut init, (-5i32) as u32 as u64, 9), Some(ESRCH));
        assert_eq!(sys_kill(&mut init, i32::MIN as u32 as u64, 9), Some(ESRCH));
        assert_eq!(sys_kill(&mut init, 0, 9), None);
        assert_eq!(sys_kill(&mut init, (-1i32) as u32 as u64, 9), None);
        // pid is an int: the high bits do not select another process.
        assert_eq!(sys_kill(&mut init, 1 << 32 | 77, 0), Some(ESRCH));

        // A handled signal sent by kill carries SI_USER, pid=tgid, uid.
        let mut p = State::new(7, 1000, 100);
        p.actions[14].handler = 0x1000; // SIGTERM
        assert_eq!(sys_kill(&mut p, 7, 15), Some(0));
        let (sig, info) = p.dequeue_signal().unwrap();
        assert_eq!(sig, SIGTERM);
        assert_eq!(info, SigInfo::kill(15, 0, 7, 1000));
        // tkill/tgkill: SI_TKILL, private queue.
        assert_eq!(sys_tkill(&mut p, 7, 15), 0);
        assert_eq!(
            p.dequeue_signal().unwrap().1,
            SigInfo::kill(15, -6, 7, 1000)
        );
        assert_eq!(sys_tgkill(&mut p, 7, 7, 15), 0);
        assert_eq!(sys_tgkill(&mut p, 8, 7, 15), ESRCH);
        assert_eq!(sys_tgkill(&mut p, 7, 8, 15), ESRCH);
        assert_eq!(sys_tgkill(&mut p, 0, 7, 15), EINVAL);
        assert_eq!(sys_tgkill(&mut p, 7, 0, 15), EINVAL);
        assert_eq!(sys_tkill(&mut p, 0, 15), EINVAL);
        assert_eq!(sys_tkill(&mut p, (-1i32) as u32 as u64, 15), EINVAL);
        assert_eq!(sys_tkill(&mut p, 8, 15), ESRCH);
        assert_eq!(sys_tkill(&mut p, 7, 99), EINVAL);
        assert_eq!(sys_tkill(&mut p, 8, 99), ESRCH); // task lookup precedes the signal check
        // tgkill with a stale tgid is ESRCH even though the tid exists.
        assert_eq!(sys_tgkill(&mut p, 9, 7, 0), ESRCH);
        assert_eq!(sys_tgkill(&mut p, 7, 7, 0), 0);
    }

    #[test]
    fn sigqueueinfo_order_and_payload() {
        let mut p = State::new(7, 1000, 100);
        p.actions[9].handler = 0x1000; // SIGUSR1
        let mut sp = space();
        let mut info = [0u8; 128];
        info[0..4].copy_from_slice(&0x77i32.to_le_bytes());
        info[8..12].copy_from_slice(&(-1i32).to_le_bytes()); // SI_QUEUE
        info[16..20].copy_from_slice(&1i32.to_le_bytes());
        info[24..32].copy_from_slice(&0x1234_5678_9abc_def0u64.to_le_bytes());
        put(&mut sp, 0x1000, &info);
        // Copy first (EFAULT beats everything), then EPERM, ESRCH, EINVAL.
        assert_eq!(sys_rt_sigqueueinfo(&mut p, &mut sp, 7, 10, 0x9000), EFAULT);
        let mut user = info;
        user[8..12].copy_from_slice(&0i32.to_le_bytes()); // SI_USER
        put(&mut sp, 0x1100, &user);
        assert_eq!(
            sys_rt_sigqueueinfo(&mut p, &mut sp, 99_999, 10, 0x1100),
            EPERM
        );
        assert_eq!(
            sys_rt_sigqueueinfo(&mut p, &mut sp, 99_999, 10, 0x1000),
            ESRCH
        );
        assert_eq!(sys_rt_sigqueueinfo(&mut p, &mut sp, 0, 10, 0x1000), ESRCH);
        assert_eq!(sys_rt_sigqueueinfo(&mut p, &mut sp, 7, 65, 0x1000), EINVAL);
        assert_eq!(sys_rt_sigqueueinfo(&mut p, &mut sp, 7, 0, 0x1000), 0);
        assert!(!p.signal_pending());
        // Delivery keeps the sender's pid and value, replaces si_signo.
        assert_eq!(sys_rt_sigqueueinfo(&mut p, &mut sp, 7, 10, 0x1000), 0);
        let (sig, got) = p.dequeue_signal().unwrap();
        assert_eq!(sig, 10);
        let b = got.to_bytes();
        assert_eq!(b[0..4], 10i32.to_le_bytes());
        assert_eq!(b[8..12], (-1i32).to_le_bytes());
        assert_eq!(b[16..20], 1i32.to_le_bytes());
        assert_eq!(b[24..32], 0x1234_5678_9abc_def0u64.to_le_bytes());
        // Unknown layout (SI_USER-impersonating code 100 on SIGUSR1): expansion must be zero.
        let mut odd = info;
        odd[8..12].copy_from_slice(&100i32.to_le_bytes());
        odd[100] = 1;
        put(&mut sp, 0x1000, &odd);
        assert_eq!(sys_rt_sigqueueinfo(&mut p, &mut sp, 7, 10, 0x1000), -7); // E2BIG
        // SI_TKILL is impersonation; it is allowed to oneself only.
        let mut tk = info;
        tk[8..12].copy_from_slice(&(-6i32).to_le_bytes());
        put(&mut sp, 0x1000, &tk);
        assert_eq!(sys_rt_sigqueueinfo(&mut p, &mut sp, 8, 10, 0x1000), EPERM);
        // tgsigqueueinfo: EINVAL for ids, ESRCH on mismatch, delivery private.
        put(&mut sp, 0x1000, &info);
        assert_eq!(
            sys_rt_tgsigqueueinfo(&mut p, &mut sp, 7, 0, 10, 0x1000),
            EINVAL
        );
        assert_eq!(
            sys_rt_tgsigqueueinfo(&mut p, &mut sp, 0, 7, 10, 0x1000),
            EINVAL
        );
        assert_eq!(
            sys_rt_tgsigqueueinfo(&mut p, &mut sp, 9, 7, 10, 0x1000),
            ESRCH
        );
        assert_eq!(sys_rt_tgsigqueueinfo(&mut p, &mut sp, 7, 7, 10, 0x1000), 0);
        assert_eq!(p.dequeue_signal().unwrap().1.code, -1);
    }

    #[test]
    fn tkill_of_rt_signal_can_eagain_kill_cannot() {
        let mut p = State::new(7, 0, 1);
        p.blocked.add(40);
        assert_eq!(sys_tkill(&mut p, 7, 40), 0);
        assert_eq!(sys_tkill(&mut p, 7, 40), EAGAIN);
        assert_eq!(sys_kill(&mut p, 7, 40), Some(0));
        assert!(p.pending_set().contains(40));
    }

    #[test]
    fn fatal_default_kills_non_init() {
        let mut p = State::new(7, 0, 100);
        assert_eq!(sys_kill(&mut p, 7, 15), Some(0));
        assert_eq!(p.group_exit, Some(15));
        let mut p = State::new(7, 0, 100);
        assert_eq!(sys_kill(&mut p, 7, SIGKILL.into()), Some(0));
        assert_eq!(p.group_exit, Some(9));
    }
}
