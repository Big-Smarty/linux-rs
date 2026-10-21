// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: kernel/fork.c (`kernel_clone`
// 2570-2650, `copy_process` 1934-2085 for the argument checks and their
// order, `SYSCALL_DEFINE0(fork)` 2691, `vfork` 2707, `clone` 2736,
// `copy_clone_args_from_user` 2756-2822, `clone3_stack_valid` 2832,
// `clone3_args_valid` 2853, `SYSCALL_DEFINE2(clone3)` 2892), include/uapi/
// linux/sched.h (`CLONE_*`, `struct clone_args`), include/linux/sched/task.h
// (`CLONE_LEGACY_FLAGS`), include/linux/uaccess.h (`copy_struct_from_user`).
// All GPL-2.0-only / GPL-2.0 WITH Linux-syscall-note.
// Transformation: the arguments become a plain [`CloneArgs`]; `copy_process`'
// early `-EINVAL` checks are one pure function in Linux's order; what the
// kernel does not (yet) implement is a named [`Unsupported`] verdict after
// the checks, never a guess. One PID namespace and no ptrace: the two
// namespace-dependent checks of `copy_process` cannot fail.
#![forbid(unsafe_code)]
//! `fork`, `vfork`, `clone` and `clone3` arguments: parsing, the `copy_process`
//! validation order and the decision whether the request is the plain
//! process copy this kernel implements.
//!
//! Context: task context; no locks, no allocation. User memory is read only
//! through [`crate::usercopy`].

use crate::{
    signal::SIGCHLD,
    usercopy::{UserPages, access_ok, copy_from_user},
};
use syscalls::Errno;

pub const CSIGNAL: u64 = 0xff;
pub const CLONE_VM: u64 = 0x100;
pub const CLONE_FS: u64 = 0x200;
pub const CLONE_FILES: u64 = 0x400;
pub const CLONE_SIGHAND: u64 = 0x800;
pub const CLONE_PIDFD: u64 = 0x1000;
pub const CLONE_PTRACE: u64 = 0x2000;
pub const CLONE_VFORK: u64 = 0x4000;
pub const CLONE_PARENT: u64 = 0x8000;
pub const CLONE_THREAD: u64 = 0x1_0000;
pub const CLONE_NEWNS: u64 = 0x2_0000;
pub const CLONE_SYSVSEM: u64 = 0x4_0000;
pub const CLONE_SETTLS: u64 = 0x8_0000;
pub const CLONE_PARENT_SETTID: u64 = 0x10_0000;
pub const CLONE_CHILD_CLEARTID: u64 = 0x20_0000;
pub const CLONE_DETACHED: u64 = 0x40_0000;
pub const CLONE_UNTRACED: u64 = 0x80_0000;
pub const CLONE_CHILD_SETTID: u64 = 0x100_0000;
pub const CLONE_NEWUSER: u64 = 0x1000_0000;
pub const CLONE_NEWPID: u64 = 0x2000_0000;
pub const CLONE_CLEAR_SIGHAND: u64 = 0x1_0000_0000;
pub const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;
/// `CLONE_NEWTIME`: shares bit 7 with `CSIGNAL`, valid for `clone3` only.
pub const CLONE_NEWTIME: u64 = 0x80;
/// `CLONE_LEGACY_FLAGS`.
const CLONE_LEGACY_FLAGS: u64 = 0xffff_ffff;

/// `CLONE_ARGS_SIZE_VER0/1/2` and `PAGE_SIZE`.
const SIZE_VER0: u64 = 64;
const SIZE_VER2: u64 = 88;
const SIZE_VER2_BYTES: usize = 88;
/// `MAX_PID_NS_LEVEL * sizeof(pid_t)`.
const SET_TID_BYTES: usize = 128;
const PAGE_SIZE: u64 = 4096;
/// `MAX_PID_NS_LEVEL`.
const MAX_PID_NS_LEVEL: u64 = 32;
/// `_NSIG`.
const NSIG: u64 = 64;

/// `struct kernel_clone_args` (the fields this kernel reads).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CloneArgs {
    pub flags: u64,
    pub pidfd: u64,
    pub child_tid: u64,
    pub parent_tid: u64,
    pub exit_signal: u64,
    /// The child's user stack pointer (`stack` of `clone`; `clone3` adds
    /// `stack_size`, as `clone3_stack_valid` does); 0 keeps the parent's.
    pub stack: u64,
    pub tls: u64,
    pub set_tid_size: u64,
    pub cgroup: u64,
}

/// What the binary needs to build a plain copy of the calling process: the
/// part of [`CloneArgs`] that survived [`CloneArgs::request`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForkRequest {
    /// `args->exit_signal`.
    pub exit_signal: u8,
    /// The child's initial `rsp`, 0 for the parent's.
    pub child_sp: u64,
    /// `CLONE_CLEAR_SIGHAND`: `flush_signal_handlers(tsk, 0)` in the child (`SIG_IGN` is kept).
    pub clear_sighand: bool,
    /// `CLONE_CHILD_CLEARTID`'s pointer (the child's `clear_child_tid`), 0 if
    /// the flag is clear.
    pub clear_child_tid: u64,
    /// `CLONE_PARENT_SETTID`'s pointer: the child's tid is stored there by `kernel_clone` before
    /// the child can run (the store's failure is ignored); 0 if the flag is clear.
    pub parent_settid: u64,
    /// `CLONE_CHILD_SETTID`'s pointer (the child's `set_child_tid`: its tid is stored there
    /// when it first runs), 0 if the flag is clear.
    pub set_child_tid: u64,
    /// `CLONE_VM`: the child runs in the caller's address space (`mmget`): shared, counted, until
    /// the child's `execve` or exit.
    pub share_vm: bool,
    /// `CLONE_VFORK`: the caller sleeps until the child has released its address space
    /// (`wait_for_vfork_done`).
    pub vfork: bool,
    /// `CLONE_THREAD`: the child is a thread of the caller's group.
    pub thread: bool,
    /// `CLONE_SIGHAND`: the child shares the caller's signal dispositions.
    pub share_sighand: bool,
    /// `CLONE_FILES`: the child shares the caller's descriptor table.
    pub share_files: bool,
    /// `CLONE_FS`: the child shares the caller's root, working directory and umask.
    pub share_fs: bool,
    /// `CLONE_SETTLS`: the child's `%fs` base (`tls`), else `None`.
    pub tls: Option<u64>,
}

impl ForkRequest {
    /// A plain `fork` with `exit_signal`: nothing shared, no thread-id words.
    #[must_use]
    pub const fn plain(exit_signal: u8) -> Self {
        Self {
            exit_signal,
            child_sp: 0,
            clear_sighand: false,
            clear_child_tid: 0,
            parent_settid: 0,
            set_child_tid: 0,
            share_vm: false,
            vfork: false,
            thread: false,
            share_sighand: false,
            share_files: false,
            share_fs: false,
            tls: None,
        }
    }
}

/// A request that passed Linux's checks but asks for something this kernel
/// does not implement: the caller stops loudly ([`crate::syscall::Outcome::Unimplemented`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unsupported;

/// The flags `copy_process` is implemented for: tracing flags (the caller is never traced),
/// the ignored `CLONE_DETACHED`, the three `*_TID` flags handled by the caller or by
/// [`ForkRequest`], the sharing flags (`CLONE_VM`, `FS`, `FILES`, `SIGHAND`, `THREAD`), `SETTLS`
/// and `VFORK`. `CLONE_SYSVSEM` shares `sysvsem.undo_list`, which only a System V semaphore
/// operation can observe; those system calls stop the kernel loudly, so accepting the flag
/// cannot be told from sharing the list (shortcut: the first of `semop`, `semtimedop` or `semget`
/// to be ported MUST implement the shared undo list and `exit_sem`).
const SUPPORTED_FLAGS: u64 = CLONE_PTRACE
    | CLONE_UNTRACED
    | CLONE_DETACHED
    | CLONE_PARENT_SETTID
    | CLONE_CHILD_SETTID
    | CLONE_CHILD_CLEARTID
    | CLONE_CLEAR_SIGHAND
    | CLONE_VFORK
    | CLONE_VM
    | CLONE_FS
    | CLONE_FILES
    | CLONE_SIGHAND
    | CLONE_THREAD
    | CLONE_SYSVSEM
    | CLONE_SETTLS;

impl CloneArgs {
    /// `SYSCALL_DEFINE0(fork)`.
    #[must_use]
    pub const fn fork() -> Self {
        Self {
            exit_signal: SIGCHLD as u64,
            ..Self::zero()
        }
    }

    /// `SYSCALL_DEFINE0(vfork)`.
    #[must_use]
    pub const fn vfork() -> Self {
        Self {
            flags: CLONE_VFORK | CLONE_VM,
            exit_signal: SIGCHLD as u64,
            ..Self::zero()
        }
    }

    const fn zero() -> Self {
        Self {
            flags: 0,
            pidfd: 0,
            child_tid: 0,
            parent_tid: 0,
            exit_signal: 0,
            stack: 0,
            tls: 0,
            set_tid_size: 0,
            cgroup: 0,
        }
    }

    /// `SYSCALL_DEFINE5(clone)` (the default argument order, x86-64): the low
    /// 32 bits of `clone_flags` are the flags (without `CSIGNAL`) and the
    /// exit signal.
    #[must_use]
    pub const fn from_clone(
        clone_flags: u64,
        newsp: u64,
        parent_tid: u64,
        child_tid: u64,
        tls: u64,
    ) -> Self {
        let low = clone_flags & 0xffff_ffff;
        Self {
            flags: low & !CSIGNAL,
            pidfd: parent_tid,
            child_tid,
            parent_tid,
            exit_signal: low & CSIGNAL,
            stack: newsp,
            tls,
            ..Self::zero()
        }
    }

    /// `SYSCALL_DEFINE2(clone3)` up to `kernel_clone`: `copy_clone_args_from_user`
    /// then `clone3_args_valid`.
    ///
    /// # Errors
    /// `E2BIG`, `EINVAL`, `EFAULT` in Linux's order.
    pub fn from_clone3<P: UserPages>(pages: &mut P, uargs: u64, size: u64) -> Result<Self, Errno> {
        if size > PAGE_SIZE {
            return Err(Errno::E2BIG);
        }
        if size < SIZE_VER0 {
            return Err(Errno::EINVAL);
        }
        // copy_struct_from_user(&args, sizeof(args), uargs, usize)
        let ksize = SIZE_VER2;
        let mut raw = [0u8; SIZE_VER2_BYTES];
        let copy = size.min(ksize);
        if size > ksize {
            check_zeroed(pages, uargs.wrapping_add(ksize), size - ksize)?;
        }
        let used = usize::try_from(copy).map_err(|_| Errno::EINVAL)?;
        if copy_from_user(pages, &mut raw[..used], uargs) != 0 {
            return Err(Errno::EFAULT);
        }
        let word = |index: usize| {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&raw[index * 8..index * 8 + 8]);
            u64::from_le_bytes(bytes)
        };
        let (flags, pidfd, child_tid, parent_tid, exit_signal) =
            (word(0), word(1), word(2), word(3), word(4));
        let (stack, stack_size, tls, set_tid, set_tid_size, cgroup) =
            (word(5), word(6), word(7), word(8), word(9), word(10));
        if set_tid_size > MAX_PID_NS_LEVEL {
            return Err(Errno::EINVAL);
        }
        if set_tid == 0 && set_tid_size > 0 {
            return Err(Errno::EINVAL);
        }
        if set_tid != 0 && set_tid_size == 0 {
            return Err(Errno::EINVAL);
        }
        // The high 32 bits must be clear and it must be a valid signal.
        if exit_signal & !CSIGNAL != 0 || exit_signal > NSIG {
            return Err(Errno::EINVAL);
        }
        if flags & CLONE_INTO_CGROUP != 0 && (cgroup > i32::MAX as u64 || size < SIZE_VER2) {
            return Err(Errno::EINVAL);
        }
        if set_tid != 0 {
            // copy_from_user(kset_tid, set_tid, size * sizeof(pid_t))
            let mut scratch = [0u8; SET_TID_BYTES];
            let bytes = usize::try_from(set_tid_size * 4).map_err(|_| Errno::EINVAL)?;
            if copy_from_user(pages, &mut scratch[..bytes], set_tid) != 0 {
                return Err(Errno::EFAULT);
            }
        }
        let mut args = Self {
            flags,
            pidfd,
            child_tid,
            parent_tid,
            exit_signal,
            stack,
            tls,
            set_tid_size,
            cgroup,
        };
        // clone3_args_valid
        if flags & !(CLONE_LEGACY_FLAGS | CLONE_CLEAR_SIGHAND | CLONE_INTO_CGROUP) != 0 {
            return Err(Errno::EINVAL);
        }
        if flags & (CLONE_DETACHED | (CSIGNAL & !CLONE_NEWTIME)) != 0 {
            return Err(Errno::EINVAL);
        }
        if flags & (CLONE_SIGHAND | CLONE_CLEAR_SIGHAND) == (CLONE_SIGHAND | CLONE_CLEAR_SIGHAND) {
            return Err(Errno::EINVAL);
        }
        if flags & (CLONE_THREAD | CLONE_PARENT) != 0 && exit_signal != 0 {
            return Err(Errno::EINVAL);
        }
        // clone3_stack_valid
        if stack == 0 {
            if stack_size > 0 {
                return Err(Errno::EINVAL);
            }
        } else {
            if stack_size == 0 || !access_ok(stack, stack_size) {
                return Err(Errno::EINVAL);
            }
            args.stack = stack + stack_size;
        }
        Ok(args)
    }

    /// The checks `kernel_clone` and the top of `copy_process` make before
    /// anything is allocated, in Linux's order. `current_unkillable` is
    /// `current->signal->flags & SIGNAL_UNKILLABLE` (global init).
    ///
    /// # Errors
    /// `EINVAL`.
    pub fn validate(&self, current_unkillable: bool) -> Result<(), Errno> {
        let f = self.flags;
        // kernel_clone: CLONE_PIDFD and CLONE_PARENT_SETTID may not share a slot.
        if f & CLONE_PIDFD != 0 && f & CLONE_PARENT_SETTID != 0 && self.pidfd == self.parent_tid {
            return Err(Errno::EINVAL);
        }
        // copy_process
        let invalid = (f & (CLONE_NEWNS | CLONE_FS) == CLONE_NEWNS | CLONE_FS)
            || (f & (CLONE_NEWUSER | CLONE_FS) == CLONE_NEWUSER | CLONE_FS)
            || (f & CLONE_THREAD != 0 && f & CLONE_SIGHAND == 0)
            || (f & CLONE_SIGHAND != 0 && f & CLONE_VM == 0)
            || (f & CLONE_PARENT != 0 && current_unkillable)
            || (f & CLONE_THREAD != 0 && f & (CLONE_NEWUSER | CLONE_NEWPID) != 0)
            || (f & CLONE_PIDFD != 0 && f & CLONE_DETACHED != 0);
        if invalid { Err(Errno::EINVAL) } else { Ok(()) }
    }

    /// Whether the (validated) request is one this kernel implements: a copy of the process,
    /// a `vfork`, a child that shares its parent's address space, descriptor table, filesystem
    /// context or dispositions, or a thread of its group.
    ///
    /// # Errors
    /// [`Unsupported`] for anything else: namespaces, `CLONE_PARENT`, `CLONE_PIDFD`, a
    /// requested thread id, a cgroup, `CLONE_IO`.
    pub fn request(&self) -> Result<ForkRequest, Unsupported> {
        if self.flags & !SUPPORTED_FLAGS != 0 || self.set_tid_size != 0 {
            return Err(Unsupported);
        }
        let flag = |bit: u64, pointer: u64| if self.flags & bit != 0 { pointer } else { 0 };
        Ok(ForkRequest {
            exit_signal: u8::try_from(self.exit_signal).map_err(|_| Unsupported)?,
            child_sp: self.stack,
            clear_sighand: self.flags & CLONE_CLEAR_SIGHAND != 0,
            clear_child_tid: flag(CLONE_CHILD_CLEARTID, self.child_tid),
            parent_settid: flag(CLONE_PARENT_SETTID, self.parent_tid),
            set_child_tid: flag(CLONE_CHILD_SETTID, self.child_tid),
            share_vm: self.flags & CLONE_VM != 0,
            vfork: self.flags & CLONE_VFORK != 0,
            thread: self.flags & CLONE_THREAD != 0,
            share_sighand: self.flags & CLONE_SIGHAND != 0,
            share_files: self.flags & CLONE_FILES != 0,
            share_fs: self.flags & CLONE_FS != 0,
            tls: (self.flags & CLONE_SETTLS != 0).then_some(self.tls),
        })
    }

    /// `CLONE_PARENT_SETTID`'s pointer, if set.
    #[must_use]
    pub const fn parent_settid(&self) -> Option<u64> {
        if self.flags & CLONE_PARENT_SETTID != 0 {
            Some(self.parent_tid)
        } else {
            None
        }
    }
}

/// `check_zeroed_user(from, size)`: `Ok` when every byte is zero, `E2BIG`
/// otherwise, `EFAULT` when it cannot be read.
fn check_zeroed<P: UserPages>(pages: &mut P, from: u64, size: u64) -> Result<(), Errno> {
    let mut at = from;
    let mut left = size;
    let mut chunk = [0u8; 256];
    while left > 0 {
        let n = left.min(chunk.len() as u64);
        let n_usize = usize::try_from(n).map_err(|_| Errno::EFAULT)?;
        if copy_from_user(pages, &mut chunk[..n_usize], at) != 0 {
            return Err(Errno::EFAULT);
        }
        if chunk[..n_usize].iter().any(|&b| b != 0) {
            return Err(Errno::E2BIG);
        }
        at = at.wrapping_add(n);
        left -= n;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usercopy::{copy_to_user, fake::Space};

    fn args(flags: u64) -> CloneArgs {
        CloneArgs {
            flags,
            exit_signal: SIGCHLD.into(),
            ..CloneArgs::zero()
        }
    }

    #[test]
    fn fork_vfork_and_clone_map_their_arguments() {
        assert_eq!(CloneArgs::fork().flags, 0);
        assert_eq!(CloneArgs::fork().exit_signal, 17);
        assert_eq!(CloneArgs::vfork().flags, CLONE_VFORK | CLONE_VM);
        // The low 32 bits only; CSIGNAL is the exit signal, not a flag.
        let c = CloneArgs::from_clone(0xdead_0000_0000_0000 | 0x11, 0x7000, 0xa, 0xb, 0xc);
        assert_eq!(
            (
                c.flags,
                c.exit_signal,
                c.stack,
                c.parent_tid,
                c.pidfd,
                c.child_tid,
                c.tls
            ),
            (0, 0x11, 0x7000, 0xa, 0xa, 0xb, 0xc)
        );
    }

    #[test]
    fn validate_follows_copy_process_order() {
        assert_eq!(args(0).validate(false), Ok(()));
        // kernel_clone: the pidfd slot shared with parent_tid.
        let mut a = args(CLONE_PIDFD | CLONE_PARENT_SETTID);
        a.pidfd = 5;
        a.parent_tid = 5;
        assert_eq!(a.validate(false), Err(Errno::EINVAL));
        a.parent_tid = 6;
        assert_eq!(a.validate(false), Ok(()));
        for flags in [
            CLONE_NEWNS | CLONE_FS,
            CLONE_NEWUSER | CLONE_FS,
            CLONE_THREAD,
            CLONE_SIGHAND,
            CLONE_THREAD | CLONE_NEWPID | CLONE_SIGHAND | CLONE_VM,
            CLONE_PIDFD | CLONE_DETACHED,
        ] {
            assert_eq!(
                args(flags).validate(false),
                Err(Errno::EINVAL),
                "{flags:#x}"
            );
        }
        // CLONE_PARENT is refused for global init only.
        assert_eq!(args(CLONE_PARENT).validate(true), Err(Errno::EINVAL));
        assert_eq!(args(CLONE_PARENT).validate(false), Ok(()));
        // A thread with its dependencies passes the checks (and is a request).
        let thread = args(CLONE_THREAD | CLONE_SIGHAND | CLONE_VM);
        assert_eq!(thread.validate(false), Ok(()));
        assert!(thread.request().is_ok());
    }

    #[test]
    fn the_requests_the_kernel_implements() {
        let r = args(0).request().unwrap();
        assert_eq!(
            (
                r.exit_signal,
                r.child_sp,
                r.clear_sighand,
                r.clear_child_tid
            ),
            (17, 0, false, 0)
        );
        let mut a = args(CLONE_CHILD_CLEARTID | CLONE_PARENT_SETTID | CLONE_CLEAR_SIGHAND);
        a.child_tid = 0x1234;
        a.stack = 0x8000;
        a.exit_signal = 0xfe;
        let r = a.request().unwrap();
        assert_eq!(
            (
                r.exit_signal,
                r.child_sp,
                r.clear_sighand,
                r.clear_child_tid
            ),
            (0xfe, 0x8000, true, 0x1234)
        );
        // vfork: the child borrows the address space, the caller waits; CLONE_VFORK alone only waits.
        for (flags, share_vm, vfork) in [
            (CLONE_VFORK | CLONE_VM, true, true),
            (CLONE_VFORK, false, true),
        ] {
            let r = args(flags).request().unwrap();
            assert_eq!((r.share_vm, r.vfork), (share_vm, vfork), "{flags:#x}");
        }
        // The sharing flags, alone and as `pthread_create` passes them.
        let r = args(CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SETTLS | CLONE_CHILD_SETTID)
            .request()
            .unwrap();
        assert_eq!(
            (r.share_vm, r.share_fs, r.share_files, r.tls, r.set_child_tid),
            (true, true, true, Some(0), 0)
        );
        let pthread = CLONE_VM
            | CLONE_FS
            | CLONE_FILES
            | CLONE_SIGHAND
            | CLONE_THREAD
            | CLONE_SYSVSEM
            | CLONE_SETTLS
            | CLONE_PARENT_SETTID
            | CLONE_CHILD_CLEARTID;
        let mut a = args(pthread);
        a.child_tid = 0x30;
        a.tls = 0x77;
        let r = a.request().unwrap();
        assert_eq!(
            (r.thread, r.share_sighand, r.clear_child_tid, r.tls),
            (true, true, 0x30, Some(0x77))
        );
        for flags in [
            CLONE_PIDFD,
            CLONE_INTO_CGROUP,
            CLONE_NEWNS,
            CLONE_PARENT,
            0x8000_0000,
        ] {
            assert_eq!(args(flags).request(), Err(Unsupported), "{flags:#x}");
        }
        assert_eq!(
            CloneArgs {
                set_tid_size: 1,
                ..args(0)
            }
            .request(),
            Err(Unsupported)
        );
        // CLONE_CHILD_SETTID: the pointer is kept for the child's first return (glibc's fork).
        let mut a = args(CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID);
        a.child_tid = 0x2468;
        let r = a.request().unwrap();
        assert_eq!((r.set_child_tid, r.clear_child_tid), (0x2468, 0x2468));
        assert_eq!(args(0).request().unwrap().set_child_tid, 0);
        assert_eq!(args(CLONE_PARENT_SETTID).parent_settid(), Some(0));
        assert_eq!(args(0).parent_settid(), None);
    }

    fn put_args(space: &mut Space, words: &[u64], at: u64) {
        let mut bytes = [0u8; 4096];
        for (i, w) in words.iter().enumerate() {
            bytes[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        assert_eq!(copy_to_user(space, at, &bytes[..words.len() * 8]), 0);
    }

    #[test]
    fn clone3_parses_sizes_and_validates_like_the_kernel() {
        let mut s = Space::default();
        s.map(0x1000, true);
        s.map(0x2000, true);
        let mut words = [0u64; 11];
        words[4] = 17; // exit_signal
        put_args(&mut s, &words, 0x1000);
        // Size errors.
        assert_eq!(
            CloneArgs::from_clone3(&mut s, 0x1000, 63),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            CloneArgs::from_clone3(&mut s, 0x1000, 4097),
            Err(Errno::E2BIG)
        );
        // A VER0-sized struct reads the first 64 bytes, the rest is zero.
        let a = CloneArgs::from_clone3(&mut s, 0x1000, 64).unwrap();
        assert_eq!((a.flags, a.exit_signal, a.stack), (0, 17, 0));
        assert_eq!(CloneArgs::from_clone3(&mut s, 0x1000, 88).unwrap(), a);
        // Unreadable memory.
        assert_eq!(
            CloneArgs::from_clone3(&mut s, 0x9000, 88),
            Err(Errno::EFAULT)
        );
        // A larger struct needs zero trailing bytes (E2BIG), readable (EFAULT).
        assert!(CloneArgs::from_clone3(&mut s, 0x1000, 96).is_ok());
        assert_eq!(copy_to_user(&mut s, 0x1000 + 90, &[1]), 0);
        assert_eq!(
            CloneArgs::from_clone3(&mut s, 0x1000, 96),
            Err(Errno::E2BIG)
        );
        assert_eq!(
            CloneArgs::from_clone3(&mut s, 0x2ff0, 0x200),
            Err(Errno::EFAULT)
        );
        put_args(&mut s, &words, 0x1000);
        // Field errors.
        let mut bad = |index: usize, value: u64| {
            let mut w = words;
            w[index] = value;
            put_args(&mut s, &w, 0x1000);
            CloneArgs::from_clone3(&mut s, 0x1000, 88)
        };
        assert_eq!(bad(9, 33), Err(Errno::EINVAL), "set_tid_size > 32");
        assert_eq!(bad(9, 1), Err(Errno::EINVAL), "size without pointer");
        assert_eq!(bad(8, 0x2000), Err(Errno::EINVAL), "pointer without size");
        assert_eq!(bad(4, 65), Err(Errno::EINVAL), "invalid signal");
        assert_eq!(bad(4, 1 << 32 | 0x11), Err(Errno::EINVAL), "high bits");
        assert!(
            bad(0, CLONE_INTO_CGROUP).is_ok(),
            "parsed; unsupported later"
        );
        assert_eq!(bad(0, 1 << 34), Err(Errno::EINVAL), "unknown flag");
        assert_eq!(bad(0, CLONE_DETACHED), Err(Errno::EINVAL));
        assert_eq!(bad(0, 0x10), Err(Errno::EINVAL), "CSIGNAL bits as flags");
        assert_eq!(
            bad(0, CLONE_SIGHAND | CLONE_CLEAR_SIGHAND | CLONE_VM),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            bad(0, CLONE_PARENT),
            Err(Errno::EINVAL),
            "exit signal with PARENT"
        );
        assert!(bad(0, CLONE_NEWTIME).is_ok(), "bit 7 is CLONE_NEWTIME here");
        // Stacks: pointer and size together; the child starts at the top.
        assert_eq!(bad(5, 0x1000), Err(Errno::EINVAL), "stack without size");
        assert_eq!(bad(6, 16), Err(Errno::EINVAL), "size without stack");
        let mut w = words;
        w[5] = 0x1000;
        w[6] = 0x800;
        put_args(&mut s, &w, 0x1000);
        assert_eq!(
            CloneArgs::from_clone3(&mut s, 0x1000, 88).unwrap().stack,
            0x1800
        );
        w[5] = crate::usercopy::TASK_SIZE_MAX - 8;
        put_args(&mut s, &w, 0x1000);
        assert_eq!(
            CloneArgs::from_clone3(&mut s, 0x1000, 88),
            Err(Errno::EINVAL),
            "stack beyond TASK_SIZE_MAX"
        );
        // set_tid entries must be readable.
        let mut w = words;
        w[8] = 0x9000;
        w[9] = 1;
        put_args(&mut s, &w, 0x1000);
        assert_eq!(
            CloneArgs::from_clone3(&mut s, 0x1000, 88),
            Err(Errno::EFAULT)
        );
    }
}
