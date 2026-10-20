// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: kernel/sys.c (`getpriority`,
// `getresuid`, `getresgid`, `gettid`, `getppid`, `getuid`..`getegid`,
// `getpgid`, `getpgrp`, `getsid`, `newuname` with `override_release` and
// `override_architecture`, `do_prlimit`, `getrlimit`, `prlimit64`,
// `setrlimit`, `umask`, `prctl`, `do_sysinfo`), kernel/groups.c (`getgroups`),
// kernel/exec_domain.c (`personality`), kernel/fork.c (`set_tid_address`),
// kernel/futex/syscalls.c (`set_robust_list`), kernel/sched/syscalls.c
// (`sched_getscheduler`, `sched_{get,set}affinity`, `sched_get_priority_*`),
// arch/x86/kernel/process.c and process_64.c (`arch_prctl`,
// `do_arch_prctl_64`), fs/d_path.c (`getcwd`), include/uapi/linux/prctl.h,
// include/uapi/linux/personality.h, include/linux/uts.h. All GPL-2.0-only.
// Transformation: one task, one CPU, one user namespace and no LSM: lookups by
// pid succeed only for the caller, credentials never change, and `prctl`
// options Linux implements but this slice does not stop the kernel instead of
// answering.
//! Identity and process-attribute syscalls: ids, process-tree ids, `uname`,
//! `arch_prctl`, resource limits, `umask`, `getcwd`, CPU affinity, `sysinfo`,
//! `personality`, the `prctl` options init uses and the pointers libc registers
//! at startup (`set_tid_address`, `set_robust_list`).
//!
//! Context: task context, no sleeping, no allocation; user memory only through
//! `usercopy`. State lives in [`crate::task::Attributes`] (`ctx.attrs()`).

use super::{Context, Outcome};
use crate::task::{Attributes, COMM_LEN, LimitError, RLIM_INFINITY, RLIMIT_CPU, Rlimit};
use crate::usercopy::{TASK_SIZE_MAX, copy_from_user, copy_to_user, put_user, strncpy_from_user};
use syscalls::{Errno, Sysno};

/// Why a call did not produce a value.
enum Stop {
    Errno(Errno),
    /// Linux implements this case and the slice does not: the kernel stops.
    Unimplemented,
}

impl From<Errno> for Stop {
    fn from(errno: Errno) -> Self {
        Self::Errno(errno)
    }
}

impl From<LimitError> for Stop {
    fn from(error: LimitError) -> Self {
        Self::Errno(match error {
            LimitError::Invalid => Errno::EINVAL,
            LimitError::Permission => Errno::EPERM,
        })
    }
}

type Res = Result<i64, Stop>;

/// `int` syscall parameters are the low 32 bits of the register.
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn int(arg: u64) -> i32 {
    arg as u32 as i32
}

/// `unsigned int` parameters likewise.
#[allow(clippy::cast_possible_truncation)]
fn uint(arg: u64) -> u32 {
    arg as u32
}

pub(super) fn dispatch<C: Context>(ctx: &mut C, sysno: Sysno, args: [u64; 6]) -> Option<Outcome> {
    let [a0, a1, a2, a3, a4, _] = args;
    let result: Res = match sysno {
        Sysno::getppid => Ok(i64::from(ctx.attrs().ppid)),
        Sysno::getuid => Ok(i64::from(ctx.attrs().cred.uid)),
        Sysno::geteuid => Ok(i64::from(ctx.attrs().cred.euid)),
        Sysno::getgid => Ok(i64::from(ctx.attrs().cred.gid)),
        Sysno::getegid => Ok(i64::from(ctx.attrs().cred.egid)),
        Sysno::gettid => Ok(i64::from(ctx.tid())),
        Sysno::getpgrp => Ok(i64::from(ctx.attrs().pgid)),
        Sysno::getpgid => find_task(ctx, int(a0)).map(|()| i64::from(ctx.attrs().pgid)),
        Sysno::getsid => find_task(ctx, int(a0)).map(|()| i64::from(ctx.attrs().sid)),
        Sysno::getresuid => {
            let cred = ctx.attrs().cred;
            put_ids(ctx, [a0, a1, a2], [cred.uid, cred.euid, cred.suid])
        }
        Sysno::getresgid => {
            let cred = ctx.attrs().cred;
            put_ids(ctx, [a0, a1, a2], [cred.gid, cred.egid, cred.sgid])
        }
        Sysno::getgroups => getgroups(ctx, int(a0), a1),
        Sysno::getpriority => getpriority(ctx, int(a0), int(a1)),
        Sysno::set_tid_address => {
            ctx.attrs().clear_child_tid = a0;
            Ok(i64::from(ctx.tid()))
        }
        Sysno::set_robust_list => set_robust_list(ctx, a0, a1),
        Sysno::personality => Ok(personality(ctx, uint(a0))),
        Sysno::sched_getscheduler => sched_getscheduler(ctx, int(a0)),
        Sysno::sched_get_priority_max => sched_priority(int(a0), 99),
        Sysno::sched_get_priority_min => sched_priority(int(a0), 1),
        Sysno::sched_getaffinity => sched_getaffinity(ctx, int(a0), uint(a1), a2),
        Sysno::sched_setaffinity => sched_setaffinity(ctx, int(a0), uint(a1), a2),
        Sysno::getrlimit => getrlimit(ctx, uint(a0), a1),
        Sysno::setrlimit => setrlimit(ctx, uint(a0), a1),
        Sysno::prlimit64 => prlimit64(ctx, int(a0), uint(a1), a2, a3),
        Sysno::umask => {
            let fs = &mut ctx.attrs().fs;
            let old = core::mem::replace(&mut fs.umask, uint(a0) & 0o777);
            Ok(i64::from(old))
        }
        Sysno::getcwd => getcwd(ctx, a0, a1),
        Sysno::uname => uname(ctx, a0),
        Sysno::sysinfo => sysinfo(ctx, a0),
        Sysno::arch_prctl => arch_prctl(ctx, int(a0), a1),
        Sysno::prctl => prctl(ctx, int(a0), [a1, a2, a3, a4]),
        _ => return None,
    };
    match result {
        Ok(value) => Some(Outcome::Return(value)),
        Err(Stop::Errno(errno)) => Some(Outcome::Return(super::error(errno))),
        Err(Stop::Unimplemented) => None,
    }
}

/// `find_task_by_vpid`: with one task only the caller exists (`pid` is a
/// `pid_t`; `0` callers handle themselves).
fn find_task<C: Context>(ctx: &C, pid: i32) -> Result<(), Stop> {
    if pid == 0 || u32::try_from(pid) == Ok(ctx.tid()) {
        Ok(())
    } else {
        Err(Errno::ESRCH.into())
    }
}

/// `getresuid`/`getresgid`: three `put_user`s in order; the first failure is
/// `-EFAULT` and earlier stores stay.
fn put_ids<C: Context>(ctx: &mut C, pointers: [u64; 3], values: [u32; 3]) -> Res {
    for (pointer, value) in pointers.into_iter().zip(values) {
        if !put_user(ctx, pointer, &value.to_le_bytes()) {
            return Err(Errno::EFAULT.into());
        }
    }
    Ok(0)
}

fn getgroups<C: Context>(ctx: &mut C, size: i32, list: u64) -> Res {
    if size < 0 {
        return Err(Errno::EINVAL.into());
    }
    let groups = ctx.attrs().cred.groups;
    let count = i64::try_from(groups.len()).map_err(|_| Errno::EINVAL)?;
    if size != 0 {
        if count > i64::from(size) {
            return Err(Errno::EINVAL.into());
        }
        for (index, gid) in (0u64..).zip(groups) {
            if !put_user(ctx, list.wrapping_add(4 * index), &gid.to_le_bytes()) {
                return Err(Errno::EFAULT.into());
            }
        }
    }
    Ok(count)
}

/// `nice_to_rlimit(task_nice(p))` of a task at the default nice 0 (nothing
/// changes it: `setpriority` is not implemented and stops the kernel).
///
/// Exact for `PRIO_PROCESS`. For `PRIO_PGRP` (own group) and `PRIO_USER`
/// (own uid) Linux returns the maximum of `20 - nice` over *every* task in the
/// group or of that uid (kernel/sys.c getpriority), and a booted 6.18 has
/// kernel threads of uid 0 and of init's group with nice -20 (the
/// high-priority `kworker/*H`), so it reports 40 there. This kernel has no
/// kernel threads, so it would print 20: a different value than the pin. Those
/// two successful cases therefore stop the kernel loudly (`Unimplemented`)
/// until kernel threads exist; the error cases (`ESRCH`, `EINVAL`) are exact.
const NICE_TO_RLIMIT_DEFAULT: i64 = 20;

fn getpriority<C: Context>(ctx: &mut C, which: i32, who: i32) -> Res {
    match which {
        // PRIO_PROCESS
        0 => find_task(ctx, who).map(|()| NICE_TO_RLIMIT_DEFAULT),
        // PRIO_PGRP: init's group is `init_struct_pid`, which has no number, so
        // only "my group" (0) names it; any other number has no tasks.
        1 if who == 0 => Err(Stop::Unimplemented),
        // PRIO_USER: `who == 0` means the caller's uid; a uid other than the
        // caller's (the only uid with tasks) has no `user_struct`.
        2 if who == 0 || u32::try_from(who) == Ok(ctx.attrs().cred.uid) => Err(Stop::Unimplemented),
        1 | 2 => Err(Errno::ESRCH.into()),
        _ => Err(Errno::EINVAL.into()),
    }
}

fn set_robust_list<C: Context>(ctx: &mut C, head: u64, len: u64) -> Res {
    // `sizeof(struct robust_list_head)`: next pointer, futex_offset, pending.
    if len != 24 {
        return Err(Errno::EINVAL.into());
    }
    ctx.attrs().robust_list = head;
    Ok(0)
}

const UNAME26: u32 = 0x002_0000;
const PER_MASK: u32 = 0xff;
const PER_LINUX32: u32 = 0x0008;

fn personality<C: Context>(ctx: &mut C, new: u32) -> i64 {
    let attrs = ctx.attrs();
    let old = attrs.personality;
    if new != u32::MAX {
        attrs.personality = new;
    }
    i64::from(old)
}

/// `sched_get_priority_{max,min}`: `fifo_rr` for `SCHED_FIFO`/`SCHED_RR`, 0 for
/// the other policies Linux knows (`SCHED_OTHER`, `BATCH`, `IDLE`, `DEADLINE`,
/// `EXT`), `-EINVAL` otherwise (including `4`, which is unused).
fn sched_priority(policy: i32, fifo_rr: i64) -> Res {
    match policy {
        1 | 2 => Ok(fifo_rr),
        0 | 3 | 5..=7 => Ok(0),
        _ => Err(Errno::EINVAL.into()),
    }
}

fn sched_getscheduler<C: Context>(ctx: &mut C, pid: i32) -> Res {
    if pid < 0 {
        return Err(Errno::EINVAL.into());
    }
    // `p->policy` is `SCHED_NORMAL`; `sched_reset_on_fork` is clear.
    find_task(ctx, pid).map(|()| 0)
}

/// `cpumask_size()` with `nr_cpu_ids == 1`: one `unsigned long`.
const CPUMASK_BYTES: u32 = 8;

fn sched_getaffinity<C: Context>(ctx: &mut C, pid: i32, len: u32, mask: u64) -> Res {
    // `(len * BITS_PER_BYTE) < nr_cpu_ids` in `unsigned int` arithmetic: a
    // length whose bit count wraps to 0 is refused too.
    if len.wrapping_mul(8) == 0 || len & (CPUMASK_BYTES - 1) != 0 {
        return Err(Errno::EINVAL.into());
    }
    find_task(ctx, pid)?;
    let returned = len.min(CPUMASK_BYTES);
    // Only CPU 0 is possible, online and allowed.
    let bits = 1u64.to_le_bytes();
    if copy_to_user(ctx, mask, &bits[..returned as usize]) != 0 {
        return Err(Errno::EFAULT.into());
    }
    Ok(i64::from(returned))
}

fn sched_setaffinity<C: Context>(ctx: &mut C, pid: i32, len: u32, mask: u64) -> Res {
    // `get_user_cpu_mask`: a short mask is zero-extended, a long one truncated.
    let mut bits = [0u8; CPUMASK_BYTES as usize];
    let copy = len.min(CPUMASK_BYTES) as usize;
    if copy_from_user(ctx, &mut bits[..copy], mask) != 0 {
        return Err(Errno::EFAULT.into());
    }
    find_task(ctx, pid)?;
    // The mask is intersected with the cpuset's CPUs ({0}); no CPU left is
    // `-EINVAL`, anything else leaves the task on CPU 0.
    if u64::from_le_bytes(bits) & 1 == 0 {
        return Err(Errno::EINVAL.into());
    }
    Ok(0)
}

fn rlimit_bytes(limit: Rlimit) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&limit.cur.to_le_bytes());
    bytes[8..].copy_from_slice(&limit.max.to_le_bytes());
    bytes
}

fn get_rlimit_arg<C: Context>(ctx: &mut C, pointer: u64) -> Result<Rlimit, Stop> {
    let mut bytes = [0u8; 16];
    if copy_from_user(ctx, &mut bytes, pointer) != 0 {
        return Err(Errno::EFAULT.into());
    }
    let word = |at: usize| u64::from_le_bytes(core::array::from_fn(|i| bytes[at + i]));
    Ok(Rlimit {
        cur: word(0),
        max: word(8),
    })
}

/// `do_prlimit` on the caller. A finite `RLIMIT_CPU` also arms the process CPU
/// timer in Linux (`update_rlimit_cpu`), which does not exist here: after the
/// ordinary validation it stops the kernel instead of storing a limit nothing
/// would enforce (nothing is stored in that case).
fn do_prlimit<C: Context>(ctx: &mut C, resource: u32, new: Option<Rlimit>) -> Result<Rlimit, Stop> {
    let attrs: &mut Attributes = ctx.attrs();
    let mut trial = attrs.rlimits;
    let old = trial.prlimit(resource, new)?;
    if let Some(new) = new
        && resource as usize == RLIMIT_CPU
        && new.cur != RLIM_INFINITY
    {
        return Err(Stop::Unimplemented);
    }
    attrs.rlimits = trial;
    Ok(old)
}

fn getrlimit<C: Context>(ctx: &mut C, resource: u32, pointer: u64) -> Res {
    let old = do_prlimit(ctx, resource, None)?;
    if copy_to_user(ctx, pointer, &rlimit_bytes(old)) != 0 {
        return Err(Errno::EFAULT.into());
    }
    Ok(0)
}

fn setrlimit<C: Context>(ctx: &mut C, resource: u32, pointer: u64) -> Res {
    let new = get_rlimit_arg(ctx, pointer)?;
    do_prlimit(ctx, resource, Some(new)).map(|_| 0)
}

fn prlimit64<C: Context>(ctx: &mut C, pid: i32, resource: u32, new: u64, old: u64) -> Res {
    let new = if new == 0 {
        None
    } else {
        Some(get_rlimit_arg(ctx, new)?)
    };
    find_task(ctx, pid)?;
    let previous = do_prlimit(ctx, resource, new)?;
    // The old value is written after the new one took effect, as in Linux.
    if old != 0 && copy_to_user(ctx, old, &rlimit_bytes(previous)) != 0 {
        return Err(Errno::EFAULT.into());
    }
    Ok(0)
}

/// `PATH_MAX`.
const PATH_MAX: usize = 4096;

/// `getcwd` on the root directory the working directory text names
/// (`task::FsContext`): the path, a NUL, and the length including the NUL.
fn getcwd<C: Context>(ctx: &mut C, buffer: u64, size: u64) -> Res {
    let cwd = ctx.attrs().fs.cwd;
    let len = cwd.len() + 1;
    if len > PATH_MAX {
        return Err(Errno::ENAMETOOLONG.into());
    }
    if len as u64 > size {
        return Err(Errno::ERANGE.into());
    }
    // The path, then its NUL: the bytes before an inaccessible page are
    // written either way, exactly as one `copy_to_user` of both would.
    if copy_to_user(ctx, buffer, cwd) != 0
        || copy_to_user(ctx, buffer + cwd.len() as u64, &[0]) != 0
    {
        return Err(Errno::EFAULT.into());
    }
    Ok(i64::try_from(len).unwrap_or(i64::MAX))
}

/// `UTS_RELEASE`: the pinned release string. `uname -r` of a kernel built from
/// the pinned tag without `CONFIG_LOCALVERSION`; the oracle's own build
/// printed the same.
pub const UTS_RELEASE: &[u8] = b"6.18.57";
/// `LINUX_VERSION_PATCHLEVEL + 60` (18 + 60), as `override_release` prints it.
const UNAME26_PATCH: &[u8] = b"78";
/// `UTS_VERSION`: Linux prints `#<build number> <config flags> <build date>`;
/// this kernel has no build counter or date source, so it names itself.
const UTS_VERSION: &[u8] = b"#1 linux-rs";
const NEW_UTS_LEN: usize = 65;
const UTS_FIELDS: [&[u8]; 6] = [
    b"Linux",    // UTS_SYSNAME
    b"(none)",   // CONFIG_DEFAULT_HOSTNAME
    UTS_RELEASE, // UTS_RELEASE
    UTS_VERSION, // UTS_VERSION
    b"x86_64",   // UTS_MACHINE
    b"(none)",   // UTS_DOMAINNAME
];

fn uname<C: Context>(ctx: &mut C, name: u64) -> Res {
    let mut utsname = [[0u8; NEW_UTS_LEN]; 6];
    for (field, text) in utsname.iter_mut().zip(UTS_FIELDS) {
        field[..text.len()].copy_from_slice(text);
    }
    if copy_to_user(ctx, name, utsname.as_flattened()) != 0 {
        return Err(Errno::EFAULT.into());
    }
    let personality = ctx.attrs().personality;
    if personality & UNAME26 != 0 {
        // `override_release`: "2.6.<PATCHLEVEL + 60>" plus whatever follows the
        // leading digits-and-dots of the release (at most two dots).
        let mut rest = UTS_RELEASE;
        let mut dots = 0;
        while let [byte, tail @ ..] = rest {
            if *byte == b'.' {
                dots += 1;
                if dots >= 3 {
                    break;
                }
            } else if !byte.is_ascii_digit() {
                break;
            }
            rest = tail;
        }
        let mut text = [0u8; NEW_UTS_LEN];
        let mut length = 0;
        for part in [b"2.6.".as_slice(), UNAME26_PATCH, rest] {
            let take = part.len().min(NEW_UTS_LEN - 1 - length);
            text[length..length + take].copy_from_slice(&part[..take]);
            length += take;
        }
        // `copy_to_user(release, buf, copy + 1)`: the string and its NUL.
        if copy_to_user(ctx, name + 2 * NEW_UTS_LEN as u64, &text[..=length]) != 0 {
            return Err(Errno::EFAULT.into());
        }
    }
    if personality & PER_MASK == PER_LINUX32
        && copy_to_user(ctx, name + 4 * NEW_UTS_LEN as u64, b"i686\0\0") != 0
    {
        return Err(Errno::EFAULT.into());
    }
    Ok(0)
}

/// `struct sysinfo` on x86-64: 112 bytes.
const SYSINFO_BYTES: usize = 112;

/// `do_sysinfo`. `uptime` is the boot clock rounded up to whole seconds;
/// `loads` are `avenrun << (SI_LOAD_SHIFT - FSHIFT)` from [`Machine::loads`];
/// `procs` is `nr_threads`, which counts the one task this kernel has (Linux's
/// count includes kernel threads); there is no swap, no highmem, no shared
/// memory and no buffer cache. The page counts are scaled to bytes with
/// `mem_unit` 1 unless that would overflow 64 bits, in which case they stay in
/// pages with `mem_unit` 4096, as `do_sysinfo` does.
fn sysinfo<C: Context>(ctx: &mut C, pointer: u64) -> Res {
    let machine = ctx.machine();
    let seconds = machine.uptime_ns.div_ceil(1_000_000_000);
    let scaled = machine.total_pages.leading_zeros() >= 12;
    let (shift, mem_unit) = if scaled { (12, 1u32) } else { (0, 4096) };
    let mut info = [0u8; SYSINFO_BYTES];
    let mut put = |at: usize, bytes: &[u8]| info[at..at + bytes.len()].copy_from_slice(bytes);
    put(0, &seconds.to_le_bytes());
    for (index, load) in machine.loads.iter().enumerate() {
        put(8 + 8 * index, &load.to_le_bytes());
    }
    put(32, &(machine.total_pages << shift).to_le_bytes());
    put(40, &(machine.free_pages << shift).to_le_bytes());
    put(80, &1u16.to_le_bytes());
    put(104, &mem_unit.to_le_bytes());
    if copy_to_user(ctx, pointer, &info) != 0 {
        return Err(Errno::EFAULT.into());
    }
    Ok(0)
}

const ARCH_SET_GS: i32 = 0x1001;
const ARCH_SET_FS: i32 = 0x1002;
const ARCH_GET_FS: i32 = 0x1003;
const ARCH_GET_GS: i32 = 0x1004;
const ARCH_GET_CPUID: i32 = 0x1011;
const ARCH_SET_CPUID: i32 = 0x1012;
const ARCH_GET_XCOMP_SUPP: i32 = 0x1021;
const ARCH_REQ_XCOMP_GUEST_PERM: i32 = 0x1025;

/// `arch_prctl` (arch/x86/kernel/process.c:1063, `do_arch_prctl_64`).
/// `ARCH_SET_CPUID` is `-ENODEV` on a CPU known to lack CPUID faulting
/// ([`Context::cpuid_fault_absent`]); with faulting present, or not
/// determinable, it and the `XCOMP` family (xstate permission model) stop the
/// kernel. `ARCH_MAP_VDSO_*`
/// (`CONFIG_CHECKPOINT_RESTORE`), the `ADDRESS_MASKING` options and the
/// `SHSTK` options (`shstk_prctl` is a `-EINVAL` stub without
/// `X86_USER_SHADOW_STACK`) all fall to the `default: -EINVAL` of the pinned
/// reference configuration (`# CONFIG_CHECKPOINT_RESTORE is not set`, no
/// `CONFIG_ADDRESS_MASKING`, `# CONFIG_X86_USER_SHADOW_STACK is not set`).
fn arch_prctl<C: Context>(ctx: &mut C, option: i32, arg2: u64) -> Res {
    match option {
        // `!test_thread_flag(TIF_NOCPUID)`: CPUID is not faulting.
        ARCH_GET_CPUID => Ok(1),
        // `set_cpuid_mode`: without CPUID faulting the answer is `-ENODEV`.
        ARCH_SET_CPUID if ctx.cpuid_fault_absent() => Err(Errno::ENODEV.into()),
        ARCH_SET_CPUID | ARCH_GET_XCOMP_SUPP..=ARCH_REQ_XCOMP_GUEST_PERM => {
            Err(Stop::Unimplemented)
        }
        ARCH_SET_GS | ARCH_SET_FS => {
            if arg2 >= TASK_SIZE_MAX {
                return Err(Errno::EPERM.into());
            }
            if option == ARCH_SET_FS {
                ctx.set_fs_base(arg2);
            } else {
                ctx.set_gs_base(arg2);
            }
            Ok(0)
        }
        ARCH_GET_FS | ARCH_GET_GS => {
            let base = if option == ARCH_GET_FS {
                ctx.fs_base()
            } else {
                ctx.gs_base()
            };
            if put_user(ctx, arg2, &base.to_le_bytes()) {
                Ok(0)
            } else {
                Err(Errno::EFAULT.into())
            }
        }
        _ => Err(Errno::EINVAL.into()),
    }
}

const PR_GET_DUMPABLE: i32 = 3;
const PR_GET_TIMING: i32 = 13;
const PR_SET_TIMING: i32 = 14;
const PR_SET_NAME: i32 = 15;
const PR_GET_NAME: i32 = 16;
const PR_GET_TIMERSLACK: i32 = 30;
const PR_GET_NO_NEW_PRIVS: i32 = 39;
/// `SUID_DUMP_USER`: an `mm` is dumpable unless `PR_SET_DUMPABLE` or a
/// set-id exec says otherwise (neither exists here).
const SUID_DUMP_USER: i64 = 1;
/// `init_task.timer_slack_ns` (`init/init_task.c:146`); `PR_SET_TIMERSLACK` is
/// not implemented, so it stays the default.
const TIMER_SLACK_NS: i64 = 50_000;

/// `PR_*` options whose handler on x86-64 under the pinned reference
/// configuration is nothing but `-EINVAL` (`kernel/sys.c:84-159` defaults for
/// the architecture hooks x86 does not define, the explicit `MPX` returns, and
/// the weak shadow-stack hooks, `X86_USER_SHADOW_STACK` being off): `UNALIGN`
/// 5-6, `FPEMU` 9-10, `FPEXC` 11-12, `ENDIAN` 19-20, `MPX` 43-44, `FP_MODE`
/// 45-46, `SVE` 50-51, `PAC` 54, 60-61, `TAGGED_ADDR` 55-56, `SME` 63-64,
/// `RISCV` 69-71, `PPC` `DEXCR` 72-73, `SHADOW_STACK` 74-76. `SCHED_CORE` (62)
/// and `SET/GET_MEMORY_MERGE` (67-68) have no `case` in the switch because
/// `# CONFIG_SCHED_CORE` and `# CONFIG_KSM` are not set (sys.c:2790-2794,
/// 2819-2838), so they reach `default: -EINVAL`. Every argument check on the
/// other paths also ends in `-EINVAL`. `PR_SET_PTRACER` (0x59616d61)
/// is Yama's; the reference configuration has `# CONFIG_SECURITY_YAMA is not
/// set`, so it reaches the switch's `default: -EINVAL` too. (A declared
/// configuration that enabled Yama would make it stateful.)
fn prctl_is_plain_einval(option: i32) -> bool {
    matches!(
        option,
        5 | 6 | 9..=12 | 19 | 20 | 43..=46 | 50 | 51 | 54..=56 | 60..=64 | 67..=76 | 0x5961_6d61
    )
}

/// Whether `option` is a `PR_*` number of `include/uapi/linux/prctl.h` (or one
/// the capabilities LSM claims before the switch) that has real behaviour and
/// state: an unimplemented one must not be answered with the `-EINVAL` that
/// every other number gets.
fn known_prctl_option(option: i32) -> bool {
    // 17-18 and 48-49 are unassigned; `PR_SET_PTRACER`, `PR_SET_VMA` and
    // `PR_GET_AUXV` are the three 32-bit magic numbers.
    matches!(
        option,
        1..=16 | 19..=47 | 50..=78 | 0x5961_6d61 | 0x5356_4d41 | 0x4155_5856
    )
}

/// `prctl`: the options init uses, the two timing options (constants) and the
/// options that are plain `-EINVAL` on this architecture. Every other option
/// Linux implements stops the kernel; every number Linux does not know is
/// `-EINVAL`.
fn prctl<C: Context>(ctx: &mut C, option: i32, args: [u64; 4]) -> Res {
    match option {
        PR_GET_DUMPABLE => Ok(SUID_DUMP_USER),
        PR_GET_TIMERSLACK => Ok(TIMER_SLACK_NS),
        PR_GET_NO_NEW_PRIVS => {
            if args.iter().any(|&arg| arg != 0) {
                return Err(Errno::EINVAL.into());
            }
            Ok(0)
        }
        PR_SET_NAME => {
            // `comm[15] = 0`; `strncpy_from_user(comm, arg2, 15)`; the name is
            // the bytes up to the first NUL, zero-padded (`strscpy_pad`).
            let mut name = [0u8; COMM_LEN];
            if strncpy_from_user(ctx, &mut name[..COMM_LEN - 1], args[0]).is_none() {
                return Err(Errno::EFAULT.into());
            }
            let length = name.iter().position(|&byte| byte == 0).unwrap_or(COMM_LEN);
            name[length..].fill(0);
            ctx.attrs().comm = name;
            Ok(0)
        }
        PR_GET_NAME => {
            let comm = ctx.attrs().comm;
            if copy_to_user(ctx, args[0], &comm) != 0 {
                return Err(Errno::EFAULT.into());
            }
            Ok(0)
        }
        // `PR_TIMING_STATISTICAL` (0) is the only timing method.
        PR_SET_TIMING if args[0] != 0 => Err(Errno::EINVAL.into()),
        PR_GET_TIMING | PR_SET_TIMING => Ok(0),
        option if prctl_is_plain_einval(option) => Err(Errno::EINVAL.into()),
        option if known_prctl_option(option) => Err(Stop::Unimplemented),
        _ => Err(Errno::EINVAL.into()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::too_many_lines, clippy::items_after_statements)]
    extern crate std;
    use crate::syscall::{
        Machine, Outcome, dispatch, error,
        testing::{Task, task},
    };
    use crate::task::Rlimit;
    use crate::usercopy::TASK_SIZE_MAX;
    use std::vec::Vec;
    use syscalls::{Errno, Sysno};

    const BUF: u64 = 0x1000;
    const BAD: u64 = 0xdead_0000_0000;

    fn user_task() -> Task {
        let mut task = task();
        task.pages.map(0x1000, true);
        task.pages.map(0x2000, true);
        task
    }
    fn call(task: &mut Task, sysno: Sysno, args: &[u64]) -> Outcome {
        let mut full = [0; 6];
        full[..args.len()].copy_from_slice(args);
        dispatch(task, sysno as u64, full)
    }
    fn ok(value: i64) -> Outcome {
        Outcome::Return(value)
    }
    fn err(errno: Errno) -> Outcome {
        Outcome::Return(error(errno))
    }
    fn bytes(task: &mut Task, at: u64, len: usize) -> Vec<u8> {
        let page = task.pages.0.get_mut(&(at & !0xfff)).unwrap();
        let start = (at & 0xfff) as usize;
        page.0[start..start + len].to_vec()
    }
    fn word(task: &mut Task, at: u64) -> u64 {
        u64::from_le_bytes(bytes(task, at, 8).try_into().unwrap())
    }
    fn put(task: &mut Task, at: u64, data: &[u8]) {
        let page = task.pages.0.get_mut(&(at & !0xfff)).unwrap();
        let start = (at & 0xfff) as usize;
        page.0[start..start + data.len()].copy_from_slice(data);
    }

    #[test]
    fn ids_and_the_process_tree() {
        let mut t = user_task();
        for sysno in [Sysno::getuid, Sysno::geteuid, Sysno::getgid, Sysno::getegid] {
            assert_eq!(call(&mut t, sysno, &[]), ok(0));
        }
        assert_eq!(call(&mut t, Sysno::gettid, &[]), ok(1));
        assert_eq!(call(&mut t, Sysno::getppid, &[]), ok(0));
        assert_eq!(call(&mut t, Sysno::getpgrp, &[]), ok(0));
        for sysno in [Sysno::getpgid, Sysno::getsid] {
            assert_eq!(call(&mut t, sysno, &[0]), ok(0));
            assert_eq!(call(&mut t, sysno, &[1]), ok(0));
            assert_eq!(call(&mut t, sysno, &[99_999]), err(Errno::ESRCH));
            // `pid_t` is an int: the upper half of the register is ignored.
            assert_eq!(call(&mut t, sysno, &[1 << 32 | 1]), ok(0));
            assert_eq!(
                call(&mut t, sysno, &[u64::from(u32::MAX)]),
                err(Errno::ESRCH)
            );
        }
    }

    #[test]
    fn getres_ids_store_in_order_and_fault_per_pointer() {
        let mut t = user_task();
        put(&mut t, BUF, &[7; 12]);
        assert_eq!(
            call(&mut t, Sysno::getresuid, &[BUF, BUF + 4, BUF + 8]),
            ok(0)
        );
        assert_eq!(bytes(&mut t, BUF, 12), [0; 12]);
        put(&mut t, BUF, &[7; 12]);
        // The second pointer faults: the first store stays, the third never happens.
        assert_eq!(
            call(&mut t, Sysno::getresgid, &[BUF, BAD, BUF + 8]),
            err(Errno::EFAULT)
        );
        assert_eq!(bytes(&mut t, BUF, 12), [0, 0, 0, 0, 7, 7, 7, 7, 7, 7, 7, 7]);
        assert_eq!(
            call(&mut t, Sysno::getresuid, &[BAD, BAD, BAD]),
            err(Errno::EFAULT)
        );
    }

    #[test]
    fn getgroups_counts_and_validates_like_groups_c() {
        let mut t = user_task();
        assert_eq!(call(&mut t, Sysno::getgroups, &[0, 0]), ok(0));
        // No groups: nothing is stored, so a bad pointer is fine.
        assert_eq!(call(&mut t, Sysno::getgroups, &[4, BAD]), ok(0));
        assert_eq!(
            call(&mut t, Sysno::getgroups, &[u64::MAX, 0]),
            err(Errno::EINVAL)
        );
        assert_eq!(
            call(&mut t, Sysno::getgroups, &[1 << 31, 0]),
            err(Errno::EINVAL)
        );
        static GROUPS: [u32; 2] = [10, 20];
        t.attrs.cred.groups = &GROUPS;
        assert_eq!(call(&mut t, Sysno::getgroups, &[0, BAD]), ok(2));
        assert_eq!(
            call(&mut t, Sysno::getgroups, &[1, BUF]),
            err(Errno::EINVAL)
        );
        assert_eq!(call(&mut t, Sysno::getgroups, &[2, BUF]), ok(2));
        assert_eq!(bytes(&mut t, BUF, 8), [10, 0, 0, 0, 20, 0, 0, 0]);
        assert_eq!(
            call(&mut t, Sysno::getgroups, &[2, BAD]),
            err(Errno::EFAULT)
        );
    }

    #[test]
    fn startup_pointers_personality_and_priorities() {
        let mut t = user_task();
        assert_eq!(call(&mut t, Sysno::set_tid_address, &[BUF]), ok(1));
        assert_eq!(t.attrs.clear_child_tid, BUF);
        assert_eq!(call(&mut t, Sysno::set_tid_address, &[0]), ok(1));
        assert_eq!(call(&mut t, Sysno::set_robust_list, &[0x1000, 24]), ok(0));
        assert_eq!(t.attrs.robust_list, 0x1000);
        assert_eq!(
            call(&mut t, Sysno::set_robust_list, &[0x2000, 16]),
            err(Errno::EINVAL)
        );
        assert_eq!(t.attrs.robust_list, 0x1000);

        assert_eq!(call(&mut t, Sysno::personality, &[0xffff_ffff]), ok(0));
        assert_eq!(call(&mut t, Sysno::personality, &[0x1_ffff_ffff]), ok(0));
        assert_eq!(call(&mut t, Sysno::personality, &[0x2_0008]), ok(0));
        assert_eq!(
            call(&mut t, Sysno::personality, &[0xffff_ffff]),
            ok(0x2_0008)
        );
        assert_eq!(call(&mut t, Sysno::personality, &[0]), ok(0x2_0008));

        assert_eq!(call(&mut t, Sysno::getpriority, &[0, 0]), ok(20));
        assert_eq!(call(&mut t, Sysno::getpriority, &[0, 1]), ok(20));
        assert_eq!(call(&mut t, Sysno::getpriority, &[0, 2]), err(Errno::ESRCH));
        // Linux answers 40 here (nice -20 kernel threads); we have none, so stop.
        assert_eq!(
            call(&mut t, Sysno::getpriority, &[1, 0]),
            Outcome::Unimplemented(140)
        );
        assert_eq!(call(&mut t, Sysno::getpriority, &[1, 1]), err(Errno::ESRCH));
        assert_eq!(
            call(&mut t, Sysno::getpriority, &[2, 0]),
            Outcome::Unimplemented(140)
        );
        assert_eq!(call(&mut t, Sysno::getpriority, &[2, 1]), err(Errno::ESRCH));
        assert_eq!(
            call(&mut t, Sysno::getpriority, &[2, u64::from(u32::MAX)]),
            err(Errno::ESRCH)
        );
        for which in [3, 9, u64::from(u32::MAX), 1 << 31] {
            assert_eq!(
                call(&mut t, Sysno::getpriority, &[which, 0]),
                err(Errno::EINVAL)
            );
        }
    }

    #[test]
    fn scheduler_queries() {
        let mut t = user_task();
        assert_eq!(call(&mut t, Sysno::sched_getscheduler, &[0]), ok(0));
        assert_eq!(call(&mut t, Sysno::sched_getscheduler, &[1]), ok(0));
        assert_eq!(
            call(&mut t, Sysno::sched_getscheduler, &[99_999]),
            err(Errno::ESRCH)
        );
        assert_eq!(
            call(&mut t, Sysno::sched_getscheduler, &[u64::from(u32::MAX)]),
            err(Errno::EINVAL)
        );
        // policy: FIFO 1, RR 2, NORMAL 0, BATCH 3, (4 unused), IDLE 5, DEADLINE 6, EXT 7.
        let max = [0, 99, 99, 0, -1, 0, 0, 0, -1];
        let min = [0, 1, 1, 0, -1, 0, 0, 0, -1];
        for (policy, (&max, &min)) in max.iter().zip(&min).enumerate() {
            let (want_max, want_min) = if max < 0 {
                (err(Errno::EINVAL), err(Errno::EINVAL))
            } else {
                (ok(max), ok(min))
            };
            assert_eq!(
                call(&mut t, Sysno::sched_get_priority_max, &[policy as u64]),
                want_max,
                "{policy}"
            );
            assert_eq!(
                call(&mut t, Sysno::sched_get_priority_min, &[policy as u64]),
                want_min,
                "{policy}"
            );
        }
        assert_eq!(
            call(&mut t, Sysno::sched_get_priority_max, &[u64::MAX]),
            err(Errno::EINVAL)
        );
    }

    #[test]
    fn affinity_is_one_cpu() {
        let mut t = user_task();
        put(&mut t, BUF, &[0xff; 16]);
        assert_eq!(
            call(&mut t, Sysno::sched_getaffinity, &[0, 128, BUF]),
            ok(8)
        );
        assert_eq!(bytes(&mut t, BUF, 9), [1, 0, 0, 0, 0, 0, 0, 0, 0xff]);
        assert_eq!(call(&mut t, Sysno::sched_getaffinity, &[1, 8, BUF]), ok(8));
        assert_eq!(
            call(&mut t, Sysno::sched_getaffinity, &[0, 4, BUF]),
            err(Errno::EINVAL)
        );
        assert_eq!(
            call(&mut t, Sysno::sched_getaffinity, &[0, 12, BUF]),
            err(Errno::EINVAL)
        );
        assert_eq!(
            call(&mut t, Sysno::sched_getaffinity, &[0, 0, BUF]),
            err(Errno::EINVAL)
        );
        // `len * 8` wraps to 0 in `unsigned int`: Linux refuses this length too.
        assert_eq!(
            call(&mut t, Sysno::sched_getaffinity, &[0, 1 << 29, BUF]),
            err(Errno::EINVAL)
        );
        assert_eq!(
            call(&mut t, Sysno::sched_getaffinity, &[99_999, 8, BUF]),
            err(Errno::ESRCH)
        );
        assert_eq!(
            call(&mut t, Sysno::sched_getaffinity, &[0, 8, BAD]),
            err(Errno::EFAULT)
        );
        // The length check precedes the pid lookup.
        assert_eq!(
            call(&mut t, Sysno::sched_getaffinity, &[99_999, 4, BUF]),
            err(Errno::EINVAL)
        );

        put(&mut t, BUF, &1u64.to_le_bytes());
        assert_eq!(call(&mut t, Sysno::sched_setaffinity, &[0, 8, BUF]), ok(0));
        // A second CPU in the mask is dropped (CPU 0 remains); bit 0 alone decides.
        put(&mut t, BUF, &3u64.to_le_bytes());
        assert_eq!(call(&mut t, Sysno::sched_setaffinity, &[0, 8, BUF]), ok(0));
        put(&mut t, BUF, &0u64.to_le_bytes());
        assert_eq!(
            call(&mut t, Sysno::sched_setaffinity, &[0, 8, BUF]),
            err(Errno::EINVAL)
        );
        put(&mut t, BUF, &2u64.to_le_bytes());
        assert_eq!(
            call(&mut t, Sysno::sched_setaffinity, &[0, 8, BUF]),
            err(Errno::EINVAL)
        );
        // A short mask is zero-extended (an empty one is refused after the pid check) ...
        assert_eq!(
            call(&mut t, Sysno::sched_setaffinity, &[0, 1, BUF]),
            err(Errno::EINVAL)
        );
        put(&mut t, BUF, &[1]);
        assert_eq!(call(&mut t, Sysno::sched_setaffinity, &[0, 1, BUF]), ok(0));
        // ... and `len == 0` reads nothing, so the pointer is never touched.
        assert_eq!(
            call(&mut t, Sysno::sched_setaffinity, &[0, 0, BAD]),
            err(Errno::EINVAL)
        );
        assert_eq!(
            call(&mut t, Sysno::sched_setaffinity, &[0, 8, BAD]),
            err(Errno::EFAULT)
        );
        // EFAULT precedes ESRCH, as `get_user_cpu_mask` runs first.
        assert_eq!(
            call(&mut t, Sysno::sched_setaffinity, &[99_999, 8, BAD]),
            err(Errno::EFAULT)
        );
        assert_eq!(
            call(&mut t, Sysno::sched_setaffinity, &[99_999, 8, BUF]),
            err(Errno::ESRCH)
        );
    }

    fn uts(t: &mut Task, field: usize) -> Vec<u8> {
        let all = bytes(t, BUF, 390);
        let field = &all[field * 65..(field + 1) * 65];
        field[..field.iter().position(|&b| b == 0).unwrap()].to_vec()
    }

    #[test]
    fn uname_fills_every_field_and_zero_pads() {
        let mut t = user_task();
        put(&mut t, BUF, &[0xaa; 390]);
        assert_eq!(call(&mut t, Sysno::uname, &[BUF]), ok(0));
        let all = bytes(&mut t, BUF, 390);
        for (field, want) in [
            "Linux",
            "(none)",
            "6.18.57",
            "#1 linux-rs",
            "x86_64",
            "(none)",
        ]
        .iter()
        .enumerate()
        {
            assert_eq!(uts(&mut t, field), want.as_bytes());
            assert!(
                all[field * 65 + want.len()..(field + 1) * 65]
                    .iter()
                    .all(|&b| b == 0)
            );
        }
        assert_eq!(call(&mut t, Sysno::uname, &[BAD]), err(Errno::EFAULT));
        assert_eq!(call(&mut t, Sysno::uname, &[0]), err(Errno::EFAULT));
        // Bytes up to the hole are written, as `copy_to_user` does.
        assert_eq!(
            call(&mut t, Sysno::uname, &[0x3000 - 100]),
            err(Errno::EFAULT)
        );
        assert_eq!(
            call(&mut t, Sysno::uname, &[TASK_SIZE_MAX - 389]),
            err(Errno::EFAULT)
        );
    }

    #[test]
    fn personality_changes_what_uname_reports() {
        let mut t = user_task();
        t.attrs.personality = 0x2_0000; // UNAME26
        assert_eq!(call(&mut t, Sysno::uname, &[BUF]), ok(0));
        assert_eq!(uts(&mut t, 2), b"2.6.78");
        assert_eq!(uts(&mut t, 4), b"x86_64");
        t.attrs.personality = 0x0008 | 0x40_0000; // PER_LINUX32 | another flag
        assert_eq!(call(&mut t, Sysno::uname, &[BUF]), ok(0));
        assert_eq!(uts(&mut t, 2), b"6.18.57");
        assert_eq!(uts(&mut t, 4), b"i686");
    }

    #[test]
    fn arch_prctl_matches_process_64() {
        let mut t = user_task();
        const GET_FS: u64 = 0x1003;
        const GET_GS: u64 = 0x1004;
        let get = |t: &mut Task, code| {
            put(t, BUF, &[0xff; 8]);
            (call(t, Sysno::arch_prctl, &[code, BUF]), word(t, BUF))
        };
        assert_eq!(get(&mut t, GET_FS), (ok(0), 0));
        assert_eq!(
            call(&mut t, Sysno::arch_prctl, &[0x1002, 0x1234_5000]),
            ok(0)
        );
        assert_eq!(
            call(&mut t, Sysno::arch_prctl, &[0x1001, 0x2345_6000]),
            ok(0)
        );
        assert_eq!(get(&mut t, GET_FS), (ok(0), 0x1234_5000));
        assert_eq!(get(&mut t, GET_GS), (ok(0), 0x2345_6000));
        let last = TASK_SIZE_MAX - 1;
        assert_eq!(call(&mut t, Sysno::arch_prctl, &[0x1002, last]), ok(0));
        for bad in [TASK_SIZE_MAX, 1 << 47, 0xffff_8000_0000_0000, u64::MAX] {
            assert_eq!(
                call(&mut t, Sysno::arch_prctl, &[0x1002, bad]),
                err(Errno::EPERM)
            );
            assert_eq!(
                call(&mut t, Sysno::arch_prctl, &[0x1001, bad]),
                err(Errno::EPERM)
            );
        }
        assert_eq!(get(&mut t, GET_FS), (ok(0), last));
        assert_eq!(
            call(&mut t, Sysno::arch_prctl, &[GET_FS, BAD]),
            err(Errno::EFAULT)
        );
        assert_eq!(
            call(&mut t, Sysno::arch_prctl, &[GET_GS, 0]),
            err(Errno::EFAULT)
        );
        // A store that straddles into an unmapped page changes nothing.
        put(&mut t, 0x2ff8, &[0x55; 8]);
        assert_eq!(
            call(&mut t, Sysno::arch_prctl, &[GET_FS, 0x3000 - 4]),
            err(Errno::EFAULT)
        );
        assert_eq!(bytes(&mut t, 0x2ffc, 4), [0x55; 4]);
        for code in [
            0,
            1,
            0x1fff,
            u64::MAX,
            0x2001,
            0x2003,
            0x4001,
            0x4004,
            0x5001,
            0x5005,
            0x1013,
            0x1020,
            0x1026,
        ] {
            assert_eq!(
                call(&mut t, Sysno::arch_prctl, &[code, 0]),
                err(Errno::EINVAL),
                "{code:#x}"
            );
        }
        // `int option`: only the low 32 bits count.
        assert_eq!(
            call(&mut t, Sysno::arch_prctl, &[0x1_0000_1003, BUF]),
            ok(0)
        );
        assert_eq!(call(&mut t, Sysno::arch_prctl, &[0x1011, 0]), ok(1));
        // CPUID faulting control (when the CPU may have it) and the xstate
        // permission calls are Linux's, not ours.
        for code in [0x1012, 0x1021, 0x1022, 0x1023, 0x1024, 0x1025] {
            assert_eq!(
                call(&mut t, Sysno::arch_prctl, &[code, 0]),
                Outcome::Unimplemented(158)
            );
        }
        // A CPU without CPUID faulting: `set_cpuid_mode` is `-ENODEV`.
        t.cpuid_fault_absent = true;
        assert_eq!(
            call(&mut t, Sysno::arch_prctl, &[0x1012, 0]),
            err(Errno::ENODEV)
        );
        assert_eq!(
            call(&mut t, Sysno::arch_prctl, &[0x1021, 0]),
            Outcome::Unimplemented(158)
        );
    }

    fn limit(t: &mut Task, resource: u64) -> (Outcome, Rlimit) {
        let outcome = call(t, Sysno::getrlimit, &[resource, BUF]);
        let (cur, max) = (word(t, BUF), word(t, BUF + 8));
        (outcome, Rlimit { cur, max })
    }

    #[test]
    fn rlimits_default_set_and_read_back() {
        let mut t = user_task();
        const INF: u64 = u64::MAX;
        t.attrs = crate::task::Attributes::init(2000);
        let defaults = [
            (INF, INF),
            (INF, INF),
            (INF, INF),
            (8 << 20, INF),
            (0, INF),
            (INF, INF),
            (1000, 1000),
            (1024, 4096),
            (8 << 20, 8 << 20),
            (INF, INF),
            (INF, INF),
            (1000, 1000),
            (819_200, 819_200),
            (0, 0),
            (0, 0),
            (INF, INF),
        ];
        for (resource, (cur, max)) in defaults.into_iter().enumerate() {
            assert_eq!(
                limit(&mut t, resource as u64),
                (ok(0), Rlimit { cur, max }),
                "{resource}"
            );
            // prlimit64 reads the same value.
            assert_eq!(
                call(&mut t, Sysno::prlimit64, &[0, resource as u64, 0, BUF + 16]),
                ok(0)
            );
            assert_eq!((word(&mut t, BUF + 16), word(&mut t, BUF + 24)), (cur, max));
        }
        assert_eq!(limit(&mut t, 16).0, err(Errno::EINVAL));
        assert_eq!(limit(&mut t, 1 << 32 | 16).0, err(Errno::EINVAL));
        assert_eq!(limit(&mut t, 1 << 32).0, ok(0));
        assert_eq!(
            call(&mut t, Sysno::getrlimit, &[7, BAD]),
            err(Errno::EFAULT)
        );

        // prlimit64 returns the old value and stores the new one.
        put(
            &mut t,
            BUF + 32,
            &[0, 16, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0],
        );
        assert_eq!(
            call(&mut t, Sysno::prlimit64, &[0, 4, BUF + 32, BUF + 48]),
            ok(0)
        );
        assert_eq!((word(&mut t, BUF + 48), word(&mut t, BUF + 56)), (0, INF));
        assert_eq!(
            limit(&mut t, 4),
            (
                ok(0),
                Rlimit {
                    cur: 4096,
                    max: 8192
                }
            )
        );
        // The old value is copied out after the store: a bad old pointer is
        // EFAULT, the new limit is in force anyway.
        put(
            &mut t,
            BUF + 32,
            &[1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0],
        );
        assert_eq!(
            call(&mut t, Sysno::prlimit64, &[0, 4, BUF + 32, BAD]),
            err(Errno::EFAULT)
        );
        assert_eq!(limit(&mut t, 4), (ok(0), Rlimit { cur: 1, max: 2 }));
        // setrlimit: raising the hard limit needs CAP_SYS_RESOURCE, which init has.
        put(
            &mut t,
            BUF + 32,
            &[3, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0],
        );
        assert_eq!(call(&mut t, Sysno::setrlimit, &[4, BUF + 32]), ok(0));
        assert_eq!(limit(&mut t, 4), (ok(0), Rlimit { cur: 3, max: 9 }));
        assert_eq!(
            call(&mut t, Sysno::setrlimit, &[4, BAD]),
            err(Errno::EFAULT)
        );
        // Errors: cur > max, nr_open, bad resource; none stores anything.
        put(
            &mut t,
            BUF + 32,
            &[10, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0],
        );
        assert_eq!(
            call(&mut t, Sysno::prlimit64, &[0, 4, BUF + 32, 0]),
            err(Errno::EINVAL)
        );
        let big = (1u64 << 21).to_le_bytes();
        put(&mut t, BUF + 32, &2048u64.to_le_bytes());
        put(&mut t, BUF + 40, &big);
        assert_eq!(
            call(&mut t, Sysno::prlimit64, &[0, 7, BUF + 32, 0]),
            err(Errno::EPERM)
        );
        assert_eq!(
            call(&mut t, Sysno::prlimit64, &[0, 99, BUF + 32, 0]),
            err(Errno::EINVAL)
        );
        assert_eq!(
            limit(&mut t, 7),
            (
                ok(0),
                Rlimit {
                    cur: 1024,
                    max: 4096
                }
            )
        );
        // Pointers are read before the pid is looked up, which comes before the resource check.
        assert_eq!(
            call(&mut t, Sysno::prlimit64, &[99_999, 99, BAD, 0]),
            err(Errno::EFAULT)
        );
        assert_eq!(
            call(&mut t, Sysno::prlimit64, &[99_999, 99, 0, 0]),
            err(Errno::ESRCH)
        );
        assert_eq!(call(&mut t, Sysno::prlimit64, &[1, 7, 0, 0]), ok(0));
        assert_eq!(call(&mut t, Sysno::prlimit64, &[0, 7, 0, 0]), ok(0));
        // `pid_t` truncation: 1 << 32 is pid 0.
        assert_eq!(call(&mut t, Sysno::prlimit64, &[1 << 32, 7, 0, 0]), ok(0));
    }

    #[test]
    fn a_finite_cpu_limit_stops_instead_of_storing() {
        let mut t = user_task();
        put(
            &mut t,
            BUF,
            &[5, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0],
        );
        assert_eq!(
            call(&mut t, Sysno::setrlimit, &[0, BUF]),
            Outcome::Unimplemented(160)
        );
        assert_eq!(
            call(&mut t, Sysno::prlimit64, &[0, 0, BUF, 0]),
            Outcome::Unimplemented(302)
        );
        assert_eq!(
            limit(&mut t, 0),
            (
                ok(0),
                Rlimit {
                    cur: u64::MAX,
                    max: u64::MAX
                }
            )
        );
        // Validation still comes first, and an infinite soft limit arms no timer.
        put(
            &mut t,
            BUF,
            &[9, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0],
        );
        assert_eq!(
            call(&mut t, Sysno::setrlimit, &[0, BUF]),
            err(Errno::EINVAL)
        );
        put(&mut t, BUF, &[255; 8]);
        put(&mut t, BUF + 8, &[255; 8]);
        assert_eq!(call(&mut t, Sysno::setrlimit, &[0, BUF]), ok(0));
    }

    #[test]
    fn umask_and_getcwd() {
        let mut t = user_task();
        assert_eq!(call(&mut t, Sysno::umask, &[0o077]), ok(0o022));
        assert_eq!(call(&mut t, Sysno::umask, &[0o027]), ok(0o077));
        assert_eq!(call(&mut t, Sysno::umask, &[0o177_777]), ok(0o027));
        assert_eq!(call(&mut t, Sysno::umask, &[0o022]), ok(0o777));
        // `int mask`: the upper register half is ignored, negative values keep the low bits.
        assert_eq!(call(&mut t, Sysno::umask, &[u64::MAX]), ok(0o022));
        assert_eq!(call(&mut t, Sysno::umask, &[0]), ok(0o777));

        put(&mut t, BUF, &[0xaa; 8]);
        assert_eq!(call(&mut t, Sysno::getcwd, &[BUF, 64]), ok(2));
        assert_eq!(bytes(&mut t, BUF, 3), [b'/', 0, 0xaa]);
        assert_eq!(call(&mut t, Sysno::getcwd, &[BUF, 2]), ok(2));
        assert_eq!(call(&mut t, Sysno::getcwd, &[BUF, 1]), err(Errno::ERANGE));
        assert_eq!(call(&mut t, Sysno::getcwd, &[BUF, 0]), err(Errno::ERANGE));
        assert_eq!(call(&mut t, Sysno::getcwd, &[BAD, 64]), err(Errno::EFAULT));
        assert_eq!(call(&mut t, Sysno::getcwd, &[0, 64]), err(Errno::EFAULT));
        // The size is checked before the buffer is touched.
        assert_eq!(call(&mut t, Sysno::getcwd, &[BAD, 1]), err(Errno::ERANGE));
    }

    #[test]
    fn sysinfo_reports_scaled_counters() {
        let mut t = user_task();
        t.machine = Machine {
            uptime_ns: 2_000_000_001,
            total_pages: 1000,
            free_pages: 250,
            loads: [5280, 1088, 352],
        };
        put(&mut t, BUF, &[0xaa; 112]);
        assert_eq!(call(&mut t, Sysno::sysinfo, &[BUF]), ok(0));
        let info = bytes(&mut t, BUF, 112);
        let field = |at: usize| u64::from_le_bytes(info[at..at + 8].try_into().unwrap());
        assert_eq!(field(0), 3, "uptime is rounded up");
        assert_eq!([field(8), field(16), field(24)], [5280, 1088, 352]);
        assert_eq!((field(32), field(40)), (1000 * 4096, 250 * 4096));
        assert_eq!([field(48), field(56), field(64), field(72)], [0; 4]);
        assert_eq!(&info[80..84], [1, 0, 0, 0]);
        assert_eq!([field(88), field(96)], [0; 2]);
        assert_eq!(&info[104..108], [1, 0, 0, 0]);
        assert!(
            info[84..88].iter().chain(&info[108..]).all(|&b| b == 0),
            "padding is zeroed"
        );
        t.machine.uptime_ns = 5_000_000_000;
        assert_eq!(call(&mut t, Sysno::sysinfo, &[BUF]), ok(0));
        assert_eq!(word(&mut t, BUF), 5);
        // 2^52 pages or more cannot be scaled to bytes: pages with mem_unit 4096.
        t.machine.total_pages = 1 << 52;
        t.machine.free_pages = 7;
        assert_eq!(call(&mut t, Sysno::sysinfo, &[BUF]), ok(0));
        assert_eq!(
            (word(&mut t, BUF + 32), word(&mut t, BUF + 40)),
            (1 << 52, 7)
        );
        assert_eq!(bytes(&mut t, BUF + 104, 4), [0, 16, 0, 0]);
        t.machine.total_pages = (1 << 52) - 1;
        assert_eq!(call(&mut t, Sysno::sysinfo, &[BUF]), ok(0));
        assert_eq!(word(&mut t, BUF + 32), ((1 << 52) - 1) << 12);
        assert_eq!(bytes(&mut t, BUF + 104, 4), [1, 0, 0, 0]);
        assert_eq!(call(&mut t, Sysno::sysinfo, &[BAD]), err(Errno::EFAULT));
    }

    #[test]
    fn prctl_options_names_and_unknown_numbers() {
        let mut t = user_task();
        assert_eq!(call(&mut t, Sysno::prctl, &[16, BUF]), ok(0));
        assert_eq!(bytes(&mut t, BUF, 16), *b"init\0\0\0\0\0\0\0\0\0\0\0\0");
        put(&mut t, 0x2000, b"oracle-test-with-long-name\0");
        assert_eq!(call(&mut t, Sysno::prctl, &[15, 0x2000]), ok(0));
        assert_eq!(call(&mut t, Sysno::prctl, &[16, BUF]), ok(0));
        assert_eq!(bytes(&mut t, BUF, 16), *b"oracle-test-wit\0");
        put(&mut t, 0x2000, b"ab\0cdefghijklmnopqrstuvwxyz");
        assert_eq!(call(&mut t, Sysno::prctl, &[15, 0x2000]), ok(0));
        assert_eq!(call(&mut t, Sysno::prctl, &[16, BUF]), ok(0));
        assert_eq!(bytes(&mut t, BUF, 16), *b"ab\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
        // A name whose NUL lies past the unmapped page boundary faults; a short one at the end does not.
        put(&mut t, 0x2ffe, b"x\0");
        assert_eq!(call(&mut t, Sysno::prctl, &[15, 0x2ffe]), ok(0));
        put(&mut t, 0x2ff0, &[b'y'; 16]);
        assert_eq!(call(&mut t, Sysno::prctl, &[15, 0x2ff1]), ok(0));
        assert_eq!(
            call(&mut t, Sysno::prctl, &[15, 0x2fff]),
            err(Errno::EFAULT)
        );
        assert_eq!(call(&mut t, Sysno::prctl, &[15, BAD]), err(Errno::EFAULT));
        assert_eq!(call(&mut t, Sysno::prctl, &[16, BAD]), err(Errno::EFAULT));

        assert_eq!(call(&mut t, Sysno::prctl, &[3]), ok(1));
        assert_eq!(call(&mut t, Sysno::prctl, &[30]), ok(50_000));
        assert_eq!(call(&mut t, Sysno::prctl, &[39]), ok(0));
        for extra in 1..5 {
            let mut args = [39, 0, 0, 0, 0];
            args[extra] = 1;
            assert_eq!(call(&mut t, Sysno::prctl, &args), err(Errno::EINVAL));
        }
        // `int option`: the register's upper half is ignored.
        assert_eq!(call(&mut t, Sysno::prctl, &[0x1_0000_0003]), ok(1));
        for option in [0u64, 17, 18, 48, 49, 79, 0x7fff_0000, 0x8000_0000, u64::MAX] {
            assert_eq!(
                call(&mut t, Sysno::prctl, &[option]),
                err(Errno::EINVAL),
                "{option:#x}"
            );
        }
        // Timing: a constant method.
        assert_eq!(call(&mut t, Sysno::prctl, &[13]), ok(0));
        assert_eq!(call(&mut t, Sysno::prctl, &[14, 0]), ok(0));
        assert_eq!(call(&mut t, Sysno::prctl, &[14, 1]), err(Errno::EINVAL));
        // Architecture hooks x86-64 does not define, and Yama's option without Yama.
        for option in (5u64..=6)
            .chain(9..=12)
            .chain(19..=20)
            .chain(43..=46)
            .chain([50, 51, 54, 55, 56])
            .chain(60..=64)
            .chain(67..=76)
            .chain([0x5961_6d61])
        {
            assert_eq!(
                call(&mut t, Sysno::prctl, &[option, 1, 2, 3, 4]),
                err(Errno::EINVAL),
                "{option:#x}"
            );
        }
        // Options with real behaviour that this slice does not have.
        for option in [
            1u64,
            4,
            22,
            25,
            52,
            77,
            78,
            35,
            38,
            41,
            47,
            0x5356_4d41,
            0x4155_5856,
        ] {
            assert_eq!(
                call(&mut t, Sysno::prctl, &[option]),
                Outcome::Unimplemented(157),
                "{option:#x}"
            );
        }
    }
}
