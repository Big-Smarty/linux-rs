// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: arch/x86/entry/syscall_64.c
// (`do_syscall_x64`: the number is an `int`, compared as `unsigned int`),
// arch/x86/entry/syscalls/syscall_64.tbl. The per-group files carry their own
// provenance (`io`: fs/read_write.c, drivers/tty; `memory`: mm/mmap.c,
// mm/mprotect.c, mm/madvise.c; `process`: kernel/exit.c, kernel/sys.c). All
// GPL-2.0-only. Syscall names/numbers come from the `syscalls` crate
// (BSD-2-Clause), whose x86_64 table was compared against the pinned tbl.
// Transformation: the VFS/tty stack is reduced to the one open file the init
// process owns (/dev/console on fds 0-2) with its default termios.
#![forbid(unsafe_code)]
//! The syscall layer as pure functions over a [`Context`].
//!
//! Context: task context, one task, one CPU; nothing here sleeps or allocates
//! unless a group says so. A syscall number that Linux 6.18.57 does not
//! implement returns `-ENOSYS`; a number it implements that no group handles
//! is reported as [`Outcome::Unimplemented`] so the caller stops loudly instead
//! of faking success or a broad `ENOSYS`.
//!
//! # Adding a syscall group
//! One file per group (`io`, `process`, ...): a `pub(super) fn dispatch<C:
//! Context>(ctx: &mut C, sysno: Sysno, args: [u64; 6]) -> Option<Outcome>`
//! that matches only its own numbers and returns `None` for everything else,
//! plus one line in [`dispatch`] below. A group needs more of the task than
//! [`Context`] offers by adding methods to the trait (the binary's `Process`
//! implements it; tests use `testing::Task`), never by reaching for globals.

mod ids;
mod io;
mod memory;
mod process;
#[cfg(test)]
mod testing;
mod time;

use crate::{
    config,
    mm::{Env, FileInfo, Mm, UserPages as PageTables},
    task::Attributes,
    usercopy::UserPages,
};
use syscalls::{Errno, Sysno};

pub use io::{MAX_RW_COUNT, TTY_CHUNK};
pub use process::exit_code;
pub use time::{ClockState, Clocks, Kclock, RestartBlock, RestartFn, clockid_to_kclock};

/// `Sysno` values the `syscalls` crate lists for `x86_64` that the pinned
/// 6.18.57 `syscall_64.tbl` leaves without an entry point or maps to
/// `sys_ni_syscall`: Linux answers these with `-ENOSYS`, so they are not
/// "implemented but missing". Derived by comparing the crate's table with the
/// pinned file; `table_drift_guard` keeps the list sorted and valid.
const NOT_IMPLEMENTED_BY_LINUX: [u32; 17] = [
    134, 156, 174, 177, 178, 180, 181, 182, 183, 184, 185, 205, 211, 212, 214, 215, 236,
];

/// Byte sink for the console tty (serial and framebuffer in the kernel).
pub trait Console {
    fn write(&mut self, bytes: &[u8]);
}

/// Everything a syscall may touch: the calling task's user memory (the one
/// user-copy mechanism, `usercopy`) and its identity and devices. The binary
/// implements it for its `Process`; host tests for a fake.
pub trait Context: UserPages + Clocks {
    /// init's `/dev/console`.
    fn console(&mut self) -> &mut dyn Console;
    /// `task_tgid_vnr(current)`: what `getpid` returns.
    fn tgid(&self) -> u32;
    /// `task_pid_vnr(current)`: what `gettid` returns.
    fn tid(&self) -> u32;
    /// The identity, limits, filesystem context and small per-task state of the
    /// caller (`task`); see [`Attributes`].
    fn attrs(&mut self) -> &mut Attributes;
    /// The user `%fs` base as the CPU holds it (`x86_fsbase_read_cpu`).
    fn fs_base(&self) -> u64;
    /// `loadseg(FS, 0)` then `x86_fsbase_write_cpu`: select the null segment
    /// and write the base. The caller has checked `base < TASK_SIZE_MAX`.
    fn set_fs_base(&mut self, base: u64);
    /// The user `%gs` base (`x86_gsbase_read_cpu_inactive`).
    fn gs_base(&self) -> u64;
    /// `loadseg(GS, 0)` then `x86_gsbase_write_cpu_inactive`.
    fn set_gs_base(&mut self, base: u64);
    /// Clock and memory totals for `sysinfo`.
    fn machine(&self) -> Machine;
    /// `!boot_cpu_has(X86_FEATURE_CPUID_FAULT)`, true only when the CPU is
    /// known to lack CPUID faulting (`set_cpuid_mode` then returns `-ENODEV`).
    /// False means present or not determinable.
    fn cpuid_fault_absent(&self) -> bool;
    /// `current->mm`: the VMA set, the rules' limits and the page tables the
    /// memory syscalls edit.
    fn address_space(&mut self) -> AddressSpace<'_>;
    /// `fget(fd)` for `mmap`: the facts `do_mmap` reads from the open file, or
    /// `None` for a closed descriptor (`-EBADF`). The default is the file table
    /// of init today: fds 0-2 are `/dev/console`. The VFS owner overrides it.
    fn mmap_file(&mut self, fd: u32) -> Option<FileInfo> {
        io::console_file(fd)
    }
}

/// What `sysinfo` reads from the machine rather than from the task.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Machine {
    /// `ktime_get_boottime_ts64` in nanoseconds.
    pub uptime_ns: u64,
    /// `totalram_pages()`, in 4 KiB pages.
    pub total_pages: u64,
    /// `NR_FREE_PAGES`, in 4 KiB pages.
    pub free_pages: u64,
    /// `get_avenrun(loads, 0, SI_LOAD_SHIFT - FSHIFT)`: see [`crate::loadavg`].
    pub loads: [u64; 3],
}

/// The calling task's address space for the memory syscalls (`current->mm`).
pub struct AddressSpace<'a> {
    pub mm: &'a mut Mm,
    pub env: &'a Env,
    /// The page tables behind `mm`; the binary's view locks the frame
    /// allocator per operation, after the model reserved its heap storage.
    pub pages: &'a mut dyn PageTables,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Value for `rax`: the result, or `-errno`.
    Return(i64),
    /// The init task exits with this `exit_code` (`(status & 0xff) << 8`).
    Exit(u32),
    /// A syscall inside Linux's table that this slice does not implement.
    Unimplemented(u32),
}

fn error(errno: Errno) -> i64 {
    -i64::from(errno.into_raw())
}

/// Dispatch one syscall. `number` is the raw `rax`; Linux reads it as `int`,
/// so the upper 32 bits are ignored. Arguments beyond a syscall's arity are
/// ignored, and `unsigned int` parameters are truncated, exactly as in Linux.
pub fn dispatch<C: Context>(ctx: &mut C, number: u64, args: [u64; 6]) -> Outcome {
    #[allow(clippy::cast_possible_truncation)]
    let number = number as u32;
    let Some(sysno) = Sysno::new(number as usize) else {
        return Outcome::Return(error(Errno::ENOSYS));
    };
    // Table holes and `sys_ni_syscall`, then the declared configuration's
    // COND_SYSCALLs (`config::DECLARED`): all `-ENOSYS` in Linux too.
    if NOT_IMPLEMENTED_BY_LINUX.binary_search(&number).is_ok()
        || config::is_disabled_syscall(number)
    {
        return Outcome::Return(error(Errno::ENOSYS));
    }
    // One line per group, in table order of their first number.
    io::dispatch(ctx, sysno, args)
        .or_else(|| memory::dispatch(ctx, sysno, args))
        .or_else(|| process::dispatch(ctx, sysno, args))
        .or_else(|| ids::dispatch(ctx, sysno, args))
        .or_else(|| time::dispatch(ctx, sysno, args))
        // shortcut: single-init only. A syscall Linux implements but this slice
        // does not ends the kernel (explicitly, never as success or ENOSYS);
        // with a second task this must become the real syscall or an error
        // returned to that task, since a user must never be able to stop the kernel.
        .unwrap_or(Outcome::Unimplemented(number))
}

#[cfg(test)]
mod tests {
    use super::{NOT_IMPLEMENTED_BY_LINUX, Outcome, dispatch, error, testing::task};
    use syscalls::{Errno, Sysno};

    fn neg(errno: Errno) -> Outcome {
        Outcome::Return(error(errno))
    }

    #[test]
    fn table_drift_guard() {
        assert!(NOT_IMPLEMENTED_BY_LINUX.is_sorted());
        for number in NOT_IMPLEMENTED_BY_LINUX {
            assert!(Sysno::new(number as usize).is_some());
        }
        assert_eq!(Sysno::write as usize, 1);
        assert_eq!(Sysno::getpid as usize, 39);
        assert_eq!(Sysno::exit as usize, 60);
        assert_eq!(Sysno::exit_group as usize, 231);
    }

    #[test]
    fn numbers_outside_or_unimplemented_in_linux_are_enosys() {
        let mut task = task();
        let mut call = |number: u64| dispatch(&mut task, number, [0; 6]);
        for number in [470, 471, 1000, 337, 423, 0x4000_0001, 0x8000_0001, 134, 183] {
            assert_eq!(call(number), neg(Errno::ENOSYS), "{number}");
        }
        // `int nr` semantics: only the low 32 bits count, in both directions.
        assert_eq!(call(0x1_0000_0000 | 0x27), Outcome::Return(1));
        assert_eq!(call(u64::MAX), neg(Errno::ENOSYS));
        assert_eq!(task.sink.0, b"");
    }

    #[test]
    fn declared_config_syscalls_are_enosys_not_unimplemented() {
        let mut task = task();
        for number in [
            Sysno::rseq,
            Sysno::map_shadow_stack,
            Sysno::uretprobe,
            Sysno::uprobe,
        ] {
            let outcome = dispatch(&mut task, number as u64, [0; 6]);
            assert_eq!(outcome, neg(Errno::ENOSYS), "{number:?}");
        }
        // Everything else Linux implements still stops loudly.
        let outcome = dispatch(&mut task, Sysno::mremap as u64, [0; 6]);
        assert_eq!(outcome, Outcome::Unimplemented(25));
    }

    #[test]
    fn implemented_in_linux_but_not_here_is_reported_not_faked() {
        let mut task = task();
        let read = dispatch(&mut task, Sysno::read as u64, [0; 6]);
        assert_eq!(read, Outcome::Unimplemented(0));
        let mremap = dispatch(&mut task, Sysno::mremap as u64, [0; 6]);
        assert_eq!(mremap, Outcome::Unimplemented(25));
    }
}
