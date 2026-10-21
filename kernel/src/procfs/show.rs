// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: fs/proc/array.c (GPL-2.0:
// `proc_pid_status`, `task_state`, `task_sig`, `task_cap`, `task_seccomp`,
// `do_task_stat`, `proc_pid_statm`, `render_sigset_t`, `task_state_array`),
// fs/proc/task_mmu.c (`task_mem`, `task_statm`, `task_vsize`,
// `show_vma_header_prefix`, `show_map_vma`, `get_vma_name`), fs/proc/base.c
// (`proc_pid_limits`, `lnames`, `proc_pid_personality`, `proc_pid_wchan`,
// `get_mm_cmdline`, `get_mm_proctitle`, `environ_read`, `comm_show`,
// `do_proc_readlink`, `proc_self_get_link`, `proc_thread_self_get_link`),
// fs/proc/fd.c (`seq_show`), fs/proc/version.c, fs/proc/uptime.c,
// fs/proc/loadavg.c, fs/proc/stat.c (`show_stat`), fs/proc/meminfo.c,
// fs/proc/cmdline.c, fs/proc/proc_sysctl.c, kernel/sysctl.c, kernel/utsname_sysctl.c,
// fs/filesystems.c (`filesystems_proc_show`), kernel/time/time.c
// (`nsec_to_clock_t`), lib/seq_buf.c / fs/seq_file.c (`seq_put_decimal_ull`,
// `seq_put_decimal_ull_width`, `seq_put_hex_ll`, `seq_pad`), include/linux/sched/loadavg.h
// (`LOAD_INT`, `LOAD_FRAC`). All GPL-2.0.
// Copyright of the originals: Linus Torvalds and the procfs authors.
// Transformation: every `show` function writes into a [`Seq`] from plain
// data ([`Show`]): the task list, the VFS, the views the tasks published and
// the machine's counters ([`HostInfo`]); nothing here touches hardware.
#![forbid(unsafe_code)]
//! The text of the files of `/proc`.
//!
//! # Contract
//! * Context: task context under the `vfs` lock class; no sleeping.
//! * Allocation: fallible through [`Seq`]; `ENOMEM` on failure.
//! * Output formats are Linux's byte for byte; a value this kernel has no
//!   source for is stated where it is printed (`shortcut:`), never invented
//!   silently.

use alloc::vec::Vec;
use core::fmt::Write as _;
use syscalls::Errno;

use super::{Caller, Global, Kind, ProcNode, Sys};
use crate::{
    mm::{VmFlags, Vma},
    sched::{SchedId, TaskState},
    seq::{self, Seq},
    task::{RLIM_INFINITY, RLIM_NLIMITS, TaskId, Tasklist, tasklist::ExitState},
    vfs::{InodeId, KResult, Vfs, mount::FILESYSTEMS},
};

/// `USER_HZ`: the unit of `/proc` times (`nsec_to_clock_t`).
pub const USER_HZ: u64 = 100;
/// The page size.
const PAGE: u64 = 4096;
/// `CAP_LAST_CAP` bitmask (`0x1ffffffffff`): every capability of the
/// reference configuration.
const CAP_FULL: u64 = (1 << 41) - 1;

/// What the machine contributes to the global files; the binary fills it.
pub struct HostInfo {
    pub uptime_ns: u64,
    /// The idle time of the CPUs in nanoseconds.
    pub idle_ns: u64,
    pub total_pages: u64,
    pub free_pages: u64,
    /// `avenrun` in `FSHIFT` (11 bits) fixed point.
    pub avenrun: [u64; 3],
    /// The kernel command line, without a trailing newline.
    pub cmdline: Vec<u8>,
    /// `nr_running()`.
    pub nr_running: u64,
    /// The highest pid handed out (`idr_get_cursor - 1`).
    pub last_pid: i32,
    /// `total_forks`.
    pub forks: u64,
    /// `nr_context_switches()`.
    pub ctxt: u64,
    /// `getboottime64`: the wall clock at boot, seconds.
    pub boot_real_s: i64,
    /// `kernel_cpustat` in nanoseconds: user, nice, system, idle, iowait, irq,
    /// softirq, steal, guest, `guest_nice`.
    pub cpustat: [u64; 10],
    /// The count of each interrupt (`kstat_irqs`), index = irq number.
    pub irqs: Vec<u64>,
    /// `arch_irq_stat()`: the interrupts of the architecture's own lines.
    pub arch_irqs: u64,
    /// `kstat_softirqs`: HI TIMER `NET_TX` `NET_RX` BLOCK `IRQ_POLL` TASKLET SCHED HRTIMER RCU.
    pub softirqs: [u64; 10],
    /// The foreground process group of the console tty (`tty_get_pgrp`).
    pub tty_pgrp: i32,
    /// Memory facts beyond free/total: `(shmem pages, kernel stack kB, heap kB)`.
    pub shmem_pages: u64,
    pub kernel_stack_kb: u64,
    pub slab_kb: u64,
    /// `(anon, mapped-file)` pages of all tasks.
    pub anon_pages: u64,
    pub mapped_pages: u64,
    pub pagetable_kb: u64,
    /// `task->state` of a scheduling handle.
    pub sched_state: fn(SchedId) -> Option<TaskState>,
    /// `(utime, stime)` in nanoseconds of the task with the handle, as
    /// `task_cputime_adjusted`.
    pub cpu_time: fn(SchedId) -> (u64, u64),
    /// The uname fields `(sysname, release, version, hostname, domainname)`.
    pub uts: [&'static [u8]; 5],
    /// The CPUID facts of `/proc/cpuinfo` (read by the binary: only the code
    /// that executes `cpuid` sees the CPU).
    pub cpu: super::cpuinfo::CpuFacts,
    /// Registered character devices `(major, name)`.
    pub chrdevs: Vec<(u32, &'static str)>,
    /// `max_threads` (`/proc/sys/kernel/threads-max`).
    pub threads_max: u64,
    /// `pid_max`.
    pub pid_max: u64,
    /// `vm.max_map_count`, `mmap_min_addr`, `overcommit_memory`.
    pub max_map_count: u64,
    pub mmap_min_addr: u64,
    pub overcommit_memory: u64,
    /// The `compile_by@host`, compiler and `UTS_VERSION` text of `/proc/version`.
    pub compile_by: &'static [u8],
    pub compiler: &'static [u8],
}

/// What a `show` call reads, so that the caller builds no more than that.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShowScope {
    /// The files of one thread group: the caller's own view is brought up to
    /// date first when it is the one shown.
    Pid(i32),
    /// The global files: the caller's own view is brought up to date first,
    /// so the machine-wide sums of [`HostInfo`] (`cpustat`, `anon_pages`,
    /// `mapped_pages`, `pagetable_kb`, which the procfs state keeps as running
    /// totals of the published views) include its current figures.
    Machine,
    /// Nothing about any task (the sysctls, a task-existence check).
    Plain,
}

impl ShowScope {
    /// The scope the file of `node` needs.
    #[must_use]
    pub fn of(node: ProcNode) -> Self {
        match node.kind {
            Kind::Global => Self::Machine,
            Kind::SysFile => Self::Plain,
            _ => Self::Pid(node.tgid),
        }
    }
}

/// The inputs of a `show` function.
pub struct Show<'a> {
    pub vfs: &'a Vfs,
    pub tasks: &'a Tasklist,
    pub host: &'a HostInfo,
    pub caller: Caller,
    /// The caller's root directory (`fs->root`).
    pub root: InodeId,
}

fn nsec_to_clock_t(ns: u64) -> u64 {
    ns / (1_000_000_000 / USER_HZ)
}

/// `seq_put_decimal_ull_width(m, delim, v, 8)`: right-aligned in 8 columns.
fn dec8(seq: &mut Seq, delim: &str, value: u64) -> KResult<()> {
    seq::print(seq, format_args!("{delim}{value:>8}"))
}

/// Text of a regular node, written to `seq`.
///
/// # Errors
/// `ESRCH` when the node's pid is gone, `ENOMEM`, `EINVAL` for a node that is
/// not a regular file.
pub fn read(show: &Show<'_>, node: ProcNode, seq: &mut Seq) -> KResult<()> {
    match node.kind {
        Kind::Global => global(show, node, seq),
        Kind::SysFile => sysctl(show, node, seq),
        Kind::Mounts => {
            pid_task(show, node)?;
            show.vfs.show_mounts(root_of(show, node), seq)
        }
        Kind::Mountinfo => {
            pid_task(show, node)?;
            show.vfs.show_mountinfo(root_of(show, node), seq)
        }
        Kind::Status => status(show, node, seq),
        Kind::Stat => stat(show, node, seq),
        Kind::Statm => statm(show, node, seq),
        Kind::Comm => {
            let (_, view) = pid_view(show, node)?;
            seq.put(view.comm_bytes())?;
            seq.putc(b'\n')
        }
        Kind::Personality => {
            let (_, view) = pid_view(show, node)?;
            seq::print(seq, format_args!("{:08x}\n", view.attrs.personality))
        }
        Kind::Limits => limits(show, node, seq),
        Kind::Wchan => wchan(show, node, seq),
        Kind::Maps => maps(show, node, seq),
        Kind::FdinfoFile => fdinfo(show, node, seq),
        _ => Err(Errno::EINVAL),
    }
}

/// `proc_pid_wchan`: `0`, or (`CONFIG_KALLSYMS=y`) the name of the function a
/// sleeping task other than the caller waits in when the caller may ptrace it.
///
/// shortcut: this kernel has no symbol table and no stack unwinder, so the
/// name of a sleeping task's wait function cannot be produced: that case stops
/// loudly (`Outcome::Unimplemented`) instead of printing `0`. Upgrade with a
/// symbol table of the kernel image and an unwinder (`__get_wchan`). A
/// task that is running, the caller itself (`get_wchan` returns 0), a zombie
/// (its stack is gone) and a caller that may not ptrace it print `0` as Linux
/// does.
fn wchan(show: &Show<'_>, node: ProcNode, seq: &mut Seq) -> KResult<()> {
    let (task, _) = pid_view(show, node)?;
    let permitted = show
        .vfs
        .fs
        .ns
        .proc
        .facts(node.tgid)
        .is_some_and(|facts| show.caller.ptrace_may_access(facts));
    let sleeping = matches!(state_text(show, task).as_bytes()[0], b'S' | b'D' | b'T');
    if permitted && sleeping && node.tgid != show.caller.tgid {
        show.vfs.fs.ns.note_unimplemented();
        return Ok(());
    }
    seq.putc(b'0')
}

/// The `fs->root` the mount tables are shown against: the target's, else the
/// caller's.
fn root_of(show: &Show<'_>, node: ProcNode) -> InodeId {
    show.vfs
        .fs
        .ns
        .proc
        .view(node.tgid)
        .and_then(super::view::TaskView::root)
        .unwrap_or(show.root)
}

/// `get_pid_task`: the task of the node's pid, or `ESRCH`.
fn pid_task(show: &Show<'_>, node: ProcNode) -> KResult<TaskId> {
    show.tasks.find_task_by_vpid(node.tgid).ok_or(Errno::ESRCH)
}

fn pid_view<'a>(show: &'a Show<'_>, node: ProcNode) -> KResult<(TaskId, &'a super::TaskView)> {
    let task = pid_task(show, node)?;
    let view = show.vfs.fs.ns.proc.view(node.tgid).ok_or(Errno::ESRCH)?;
    Ok((task, view))
}

// ---- /proc/<pid>/status ------------------------------------------------------------------

/// `get_task_state`.
fn state_text(show: &Show<'_>, task: TaskId) -> &'static str {
    let Some(t) = show.tasks.task(task) else {
        return "X (dead)";
    };
    match t.exit_state {
        ExitState::Zombie => return "Z (zombie)",
        ExitState::Dead => return "X (dead)",
        ExitState::Live => {}
    }
    match t.sched.and_then(|sched| (show.host.sched_state)(sched)) {
        None | Some(TaskState::Running) => "R (running)",
        Some(TaskState::Interruptible) => "S (sleeping)",
        Some(TaskState::Uninterruptible) => "D (disk sleep)",
        Some(TaskState::Stopped) => "T (stopped)",
        Some(TaskState::Dead) => "X (dead)",
    }
}

/// `render_sigset_t`.
fn sigset(seq: &mut Seq, header: &str, set: u64) -> KResult<()> {
    seq.puts(header)?;
    // _NSIG = 64: sixteen hex digits, highest signals first.
    for shift in (0..16).rev() {
        let digit = ((set >> (shift * 4)) & 0xf) as u8;
        seq.putc(b"0123456789abcdef"[usize::from(digit)])?;
    }
    seq.putc(b'\n')
}

#[allow(clippy::too_many_lines)] // one straight list of the lines of `status`
fn status(show: &Show<'_>, node: ProcNode, seq: &mut Seq) -> KResult<()> {
    let (task, view) = pid_view(show, node)?;
    let t = show.tasks.task(task).ok_or(Errno::ESRCH)?;
    seq.puts("Name:\t")?;
    // proc_task_name(escape): the characters "\n\\" are written as C escapes.
    for &byte in view.comm_bytes() {
        match byte {
            b'\n' => seq.puts("\\n")?,
            b'\\' => seq.puts("\\\\")?,
            other => seq.putc(other)?,
        }
    }
    seq.putc(b'\n')?;
    // task_state
    if let Some(umask) = view.has_fs.then_some(view.attrs.fs.umask) {
        seq::print(seq, format_args!("Umask:\t{umask:04o}\n"))?;
    }
    let cred = view.attrs.cred;
    seq::print(
        seq,
        format_args!(
            "State:\t{}\nTgid:\t{}\nNgid:\t0\nPid:\t{}\nPPid:\t{}\nTracerPid:\t0\n",
            state_text(show, task),
            show.tasks.task_tgid_vnr(task),
            show.tasks.task_pid_vnr(task),
            show.tasks.task_ppid_vnr(task),
        ),
    )?;
    // The filesystem ids follow the effective ones (`fsuid`/`fsgid`).
    seq::print(
        seq,
        format_args!(
            "Uid:\t{}\t{}\t{}\t{}\nGid:\t{}\t{}\t{}\t{}\nFDSize:\t{}\nGroups:\t",
            cred.uid,
            cred.euid,
            cred.suid,
            cred.euid,
            cred.gid,
            cred.egid,
            cred.sgid,
            cred.egid,
            if view.has_files { view.max_fds } else { 0 },
        ),
    )?;
    for (index, group) in cred.groups.iter().enumerate() {
        seq::print(
            seq,
            format_args!("{}{group}", if index > 0 { " " } else { "" }),
        )?;
    }
    // Trailing space shouldn't have been added in the first place.
    seq.putc(b' ')?;
    let (pid, pgrp, sid) = (
        show.tasks.task_pid_vnr(task),
        show.tasks.task_pgrp_vnr(task),
        show.tasks.task_session_vnr(task),
    );
    seq::print(
        seq,
        format_args!(
            "\nNStgid:\t{}\nNSpid:\t{pid}\nNSpgid:\t{pgrp}\nNSsid:\t{sid}\nKthread:\t0\n",
            show.tasks.task_tgid_vnr(task),
        ),
    )?;
    if let Some(mm) = show.vfs.fs.ns.proc.mm_of(node.tgid) {
        // task_mem
        let total_rss = mm.rss_anon + mm.rss_file + mm.rss_shmem;
        let hiwater_vm = mm.hiwater_vm.max(mm.total_vm);
        let hiwater_rss = mm.hiwater_rss.max(total_rss);
        let text = ((mm.end_code + PAGE - 1) & !(PAGE - 1))
            .saturating_sub(mm.start_code & !(PAGE - 1))
            .min(mm.exec_vm << 12);
        let lib = (mm.exec_vm << 12) - text;
        let kb = |pages: u64| pages << 2;
        dec8(seq, "VmPeak:\t", kb(hiwater_vm))?;
        dec8(seq, " kB\nVmSize:\t", kb(mm.total_vm))?;
        dec8(seq, " kB\nVmLck:\t", kb(mm.locked_vm))?;
        dec8(seq, " kB\nVmPin:\t", 0)?;
        dec8(seq, " kB\nVmHWM:\t", kb(hiwater_rss))?;
        dec8(seq, " kB\nVmRSS:\t", kb(total_rss))?;
        dec8(seq, " kB\nRssAnon:\t", kb(mm.rss_anon))?;
        dec8(seq, " kB\nRssFile:\t", kb(mm.rss_file))?;
        dec8(seq, " kB\nRssShmem:\t", kb(mm.rss_shmem))?;
        dec8(seq, " kB\nVmData:\t", kb(mm.data_vm))?;
        dec8(seq, " kB\nVmStk:\t", kb(mm.stack_vm))?;
        dec8(seq, " kB\nVmExe:\t", text >> 10)?;
        dec8(seq, " kB\nVmLib:\t", lib >> 10)?;
        dec8(seq, " kB\nVmPTE:\t", mm.pgtables_bytes >> 10)?;
        dec8(seq, " kB\nVmSwap:\t", 0)?;
        seq.puts(" kB\n")?;
        // hugetlb_report_usage, task_core_dumping, task_thp_status, task_untag_mask
        seq.puts("HugetlbPages:\t")?;
        dec8(seq, "", 0)?;
        seq.puts(" kB\nCoreDumping:\t0\nTHP_enabled:\t0\nuntag_mask:\t0xffffffffffffffff\n")?;
    }
    // task_sig
    let sets = show.tasks.signal_sets(task).ok_or(Errno::ESRCH)?;
    let queued: usize = show
        .tasks
        .processes()
        .filter(|&other| {
            show.tasks
                .task(other)
                .is_some_and(|o| o.cred.uid == t.cred.uid)
        })
        .filter_map(|other| show.tasks.signal_sets(other))
        .map(|s| s.queued)
        .sum();
    seq::print(
        seq,
        format_args!(
            "Threads:\t1\nSigQ:\t{queued}/{}\n",
            view.attrs.rlimits.get(crate::task::RLIMIT_SIGPENDING).cur,
        ),
    )?;
    sigset(seq, "SigPnd:\t", sets.pending)?;
    sigset(seq, "ShdPnd:\t", sets.shared_pending)?;
    sigset(seq, "SigBlk:\t", sets.blocked)?;
    sigset(seq, "SigIgn:\t", sets.ignored)?;
    sigset(seq, "SigCgt:\t", sets.caught)?;
    // task_cap. shortcut: capability sets are not modelled; a task holds all
    // of them iff its effective uid is 0 (`Cred::of_task`), none otherwise;
    // the bounding set is always full.
    let held = if cred.euid == 0 { CAP_FULL } else { 0 };
    seq::print(
        seq,
        format_args!(
            "CapInh:\t{:016x}\nCapPrm:\t{held:016x}\nCapEff:\t{held:016x}\nCapBnd:\t{CAP_FULL:016x}\nCapAmb:\t{:016x}\n",
            0, 0
        ),
    )?;
    // task_seccomp
    seq.puts("NoNewPrivs:\t0\nSeccomp:\t0\n")?;
    seq.puts("Speculation_Store_Bypass:\t")?;
    seq.puts(super::bugs::ssb_text())?;
    seq.puts("\nSpeculationIndirectBranch:\t")?;
    seq.puts(super::bugs::ib_text())?;
    seq.putc(b'\n')?;
    // task_cpus_allowed: one CPU, one memory node.
    seq.puts("Cpus_allowed:\t1\nCpus_allowed_list:\t0\n")?;
    seq.puts("Mems_allowed:\t00000000,00000001\nMems_allowed_list:\t0\n")?;
    seq::print(
        seq,
        format_args!(
            "voluntary_ctxt_switches:\t{}\nnonvoluntary_ctxt_switches:\t{}\n",
            view.nvcsw, view.nivcsw
        ),
    )
}

// ---- /proc/<pid>/stat, statm ------------------------------------------------------------------

#[allow(clippy::too_many_lines)] // one straight list of the 52 fields of `do_task_stat`
fn stat(show: &Show<'_>, node: ProcNode, seq: &mut Seq) -> KResult<()> {
    let (task, view) = pid_view(show, node)?;
    let t = show.tasks.task(task).ok_or(Errno::ESRCH)?;
    let permitted = show
        .vfs
        .fs
        .ns
        .proc
        .facts(node.tgid)
        .is_some_and(|facts| show.caller.ptrace_may_access(facts));
    let state = state_text(show, task).as_bytes()[0];
    let sets = show.tasks.signal_sets(task).ok_or(Errno::ESRCH)?;
    let (mut utime, mut stime) = (t.utime_ns, t.stime_ns);
    if t.exit_state == ExitState::Live
        && let Some(sched) = t.sched
    {
        (utime, stime) = (show.host.cpu_time)(sched);
    }
    let mm = show.vfs.fs.ns.proc.mm_of(node.tgid);
    let (tty_nr, tty_pgrp): (i64, i64) = if t.ctty {
        // new_encode_dev(ttyS0 = 4:64)
        (4 << 8 | 64, i64::from(show.host.tty_pgrp))
    } else {
        (0, -1)
    };
    let rss = mm.map_or(0, |m| m.rss_anon + m.rss_file + m.rss_shmem);
    let wchan = u64::from(permitted && state != b'R');
    let rsslim = view.attrs.rlimits.get(5).cur;
    seq::print(seq, format_args!("{} (", show.tasks.task_pid_vnr(task)))?;
    let comm = view.comm_bytes();
    seq.put(&comm[..comm.len().min(64)])?;
    seq.puts(") ")?;
    seq.putc(state)?;
    // Each remaining field is " <decimal>", in `do_task_stat`'s order.
    let mut field = |v: i128| -> KResult<()> { seq::print(seq, format_args!(" {v}")) };
    field(i128::from(show.tasks.task_ppid_vnr(task)))?;
    field(i128::from(show.tasks.task_pgrp_vnr(task)))?;
    field(i128::from(show.tasks.task_session_vnr(task)))?;
    field(i128::from(tty_nr))?;
    field(i128::from(tty_pgrp))?;
    // `do_exit` marks a zombie `PF_EXITPIDONE` (0x8) and `PF_NOFREEZE` (0x8000).
    let exited = if t.exit_state == ExitState::Live {
        0
    } else {
        0x8008
    };
    field(i128::from(t.flags | view.flags | exited))?;
    field(i128::from(view.min_flt))?; // min_flt
    field(0)?; // cmin_flt
    field(i128::from(view.maj_flt))?; // maj_flt
    field(0)?; // cmaj_flt
    field(i128::from(nsec_to_clock_t(utime)))?;
    field(i128::from(nsec_to_clock_t(stime)))?;
    field(i128::from(nsec_to_clock_t(t.cutime_ns)))?;
    field(i128::from(nsec_to_clock_t(t.cstime_ns)))?;
    field(i128::from(20 + view.nice))?; // priority
    field(i128::from(view.nice))?;
    field(1)?; // num_threads
    field(0)?; // itrealvalue
    field(i128::from(nsec_to_clock_t(view.start_boottime_ns)))?;
    field(i128::from(mm.map_or(0, |m| m.total_vm * PAGE)))?; // vsize
    field(i128::from(rss))?;
    field(i128::from(rsslim))?;
    field(i128::from(
        mm.map_or(0, |m| if permitted { m.start_code } else { 1 }),
    ))?;
    field(i128::from(
        mm.map_or(0, |m| if permitted { m.end_code } else { 1 }),
    ))?;
    field(i128::from(if permitted {
        mm.map_or(0, |m| m.start_stack)
    } else {
        0
    }))?;
    field(0)?; // kstkesp
    field(0)?; // kstkeip
    // The signal information here is obsolete: 31-bit decimals.
    field(i128::from(sets.pending & 0x7fff_ffff))?;
    field(i128::from(sets.blocked & 0x7fff_ffff))?;
    field(i128::from(sets.ignored & 0x7fff_ffff))?;
    field(i128::from(sets.caught & 0x7fff_ffff))?;
    field(i128::from(wchan))?;
    field(0)?; // nswap
    field(0)?; // cnswap
    field(i128::from(t.exit_signal))?;
    field(0)?; // task_cpu
    field(i128::from(view.rt_priority))?;
    field(i128::from(view.policy))?;
    field(0)?; // delayacct_blkio_ticks
    field(0)?; // gtime
    field(0)?; // cgtime
    match mm {
        Some(m) if permitted => {
            for v in [
                m.start_data,
                m.end_data,
                m.start_brk,
                m.arg_start,
                m.arg_end,
                m.env_start,
                m.env_end,
            ] {
                field(i128::from(v))?;
            }
        }
        _ => seq.puts(" 0 0 0 0 0 0 0")?,
    }
    let exit_code = if permitted {
        i128::from(t.exit_code)
    } else {
        0
    };
    seq::print(seq, format_args!(" {exit_code}\n"))
}

fn statm(show: &Show<'_>, node: ProcNode, seq: &mut Seq) -> KResult<()> {
    pid_view(show, node)?;
    let Some(mm) = show.vfs.fs.ns.proc.mm_of(node.tgid) else {
        return seq.put(b"0 0 0 0 0 0 0\n");
    };
    let shared = mm.rss_file + mm.rss_shmem;
    let text =
        ((mm.end_code + PAGE - 1) & !(PAGE - 1)).saturating_sub(mm.start_code & !(PAGE - 1)) >> 12;
    let data = mm.data_vm + mm.stack_vm;
    let resident = shared + mm.rss_anon;
    seq::print(
        seq,
        format_args!("{} {resident} {shared} {text} 0 {data} 0\n", mm.total_vm),
    )
}

// ---- limits -----------------------------------------------------------------------------------------

fn limits(show: &Show<'_>, node: ProcNode, seq: &mut Seq) -> KResult<()> {
    const NAMES: [(&str, &str); RLIM_NLIMITS] = [
        ("Max cpu time", "seconds"),
        ("Max file size", "bytes"),
        ("Max data size", "bytes"),
        ("Max stack size", "bytes"),
        ("Max core file size", "bytes"),
        ("Max resident set", "bytes"),
        ("Max processes", "processes"),
        ("Max open files", "files"),
        ("Max locked memory", "bytes"),
        ("Max address space", "bytes"),
        ("Max file locks", "locks"),
        ("Max pending signals", "signals"),
        ("Max msgqueue size", "bytes"),
        ("Max nice priority", ""),
        ("Max realtime priority", ""),
        ("Max realtime timeout", "us"),
    ];
    let (_, view) = pid_view(show, node)?;
    seq.puts("Limit                     Soft Limit           Hard Limit           Units     \n")?;
    for (index, (name, unit)) in NAMES.iter().enumerate() {
        let limit = view.attrs.rlimits.get(index);
        let fmt = |seq: &mut Seq, value: u64, last: bool| -> KResult<()> {
            if value == RLIM_INFINITY {
                seq::print(seq, format_args!("{:<20}", "unlimited"))?;
            } else {
                seq::print(seq, format_args!("{value:<20}"))?;
            }
            if !last {
                seq.putc(b' ')?;
            }
            Ok(())
        };
        seq::print(seq, format_args!("{name:<25} "))?;
        fmt(seq, limit.cur, false)?;
        fmt(seq, limit.max, false)?;
        if unit.is_empty() {
            seq.putc(b'\n')?;
        } else {
            seq::print(seq, format_args!("{unit:<10}\n"))?;
        }
    }
    Ok(())
}

// ---- maps ---------------------------------------------------------------------------------------------

/// `seq_pad(m, ' ')` for a line that started at `start`: pad to `width`, then
/// one separator.
fn pad_to(line: &mut Seq, start: usize, width: usize) -> KResult<()> {
    while line.len() - start < width {
        line.putc(b' ')?;
    }
    line.putc(b' ')
}

fn maps(show: &Show<'_>, node: ProcNode, seq: &mut Seq) -> KResult<()> {
    pid_view(show, node)?;
    let Some(mm) = show.vfs.fs.ns.proc.mm_of(node.tgid) else {
        return Ok(());
    };
    for vma in mm.vmas.iter() {
        show_map_vma(show, mm, vma, seq)?;
        seq.end_record()?;
    }
    // The vsyscall page (`gate_vma`): `--xp` at `VSYSCALL_ADDR`
    // (CONFIG_LEGACY_VSYSCALL_XONLY).
    let start = seq.len();
    seq.puts("ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0 ")?;
    pad_to(seq, start, 25 + 8 * 6 - 1)?;
    seq.puts("[vsyscall]\n")?;
    seq.end_record()
}

fn show_map_vma(show: &Show<'_>, mm: &super::MmView, vma: &Vma, seq: &mut Seq) -> KResult<()> {
    let start = seq.len();
    let flags = vma.flags;
    let file = vma.file.and_then(|id| {
        show.vfs
            .files
            .try_get(crate::vfs::FileId::from_index(u32::try_from(id).ok()?))
    });
    let (dev, ino, pgoff) = match file.and_then(|f| f.inode) {
        Some(inode) => {
            let attr = show.vfs.fs.getattr(inode);
            (attr.dev, attr.ino, vma.pgoff << 12)
        }
        None => (0, 0, 0),
    };
    seq::print(
        seq,
        format_args!(
            "{:08x}-{:08x} {}{}{}{} {:08x} {:02x}:{:02x} {} ",
            vma.start,
            vma.end,
            if flags.contains(VmFlags::READ) {
                'r'
            } else {
                '-'
            },
            if flags.contains(VmFlags::WRITE) {
                'w'
            } else {
                '-'
            },
            if flags.contains(VmFlags::EXEC) {
                'x'
            } else {
                '-'
            },
            if flags.contains(VmFlags::MAYSHARE) {
                's'
            } else {
                'p'
            },
            pgoff,
            crate::vfs::major(dev),
            crate::vfs::minor(dev),
            ino,
        ),
    )?;
    // get_vma_name
    if let Some(file) = file {
        pad_to(seq, start, 25 + 8 * 6 - 1)?;
        let path = file_path(show, file)?;
        // seq_path(m, path, "\n"): the path with newlines escaped.
        seq.escape(&path, b"\n")?;
    } else if vma.start < mm.brk && vma.end > mm.start_brk {
        pad_to(seq, start, 25 + 8 * 6 - 1)?;
        seq.puts("[heap]")?;
    } else if vma.start <= mm.start_stack && vma.end >= mm.start_stack {
        pad_to(seq, start, 25 + 8 * 6 - 1)?;
        seq.puts("[stack]")?;
    }
    seq.putc(b'\n')
}

/// `d_path` of an open file, with ` (deleted)` for an unlinked one.
fn file_path(show: &Show<'_>, file: &crate::vfs::file::File) -> KResult<Vec<u8>> {
    let (mut path, _) = show.vfs.file_path(show.root, file)?;
    if show.vfs.file_deleted(file) {
        for &byte in b" (deleted)" {
            path.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
            let _ = path.push_within_capacity(byte);
        }
    }
    Ok(path)
}

// ---- fdinfo ---------------------------------------------------------------------------------------------

fn fdinfo(show: &Show<'_>, node: ProcNode, seq: &mut Seq) -> KResult<()> {
    let (_, view) = pid_view(show, node)?;
    let entry = view.fd(node.sub).ok_or(Errno::ENOENT)?;
    let file = show
        .vfs
        .files
        .get_checked(entry.file, entry.serial)
        .ok_or(Errno::ENOENT)?;
    let mut flags = file.flags;
    if entry.cloexec {
        flags |= crate::vfs::O_CLOEXEC;
    }
    let (mnt_id, ino) = match (file.inode, file.kind) {
        (Some(inode), _) => (show.vfs.mnt_id_of(inode), show.vfs.fs.getattr(inode).ino),
        // An anonymous inode: pipefs.
        (None, crate::vfs::file::FileKind::Pipe { pipe, .. }) => {
            (show.vfs.pipe_mnt_id(), show.vfs.pipe_ref(pipe).ino)
        }
        (None, _) => (0, 0),
    };
    seq::print(
        seq,
        format_args!(
            "pos:\t{}\nflags:\t0{:o}\nmnt_id:\t{mnt_id}\nino:\t{ino}\n",
            file.pos, flags
        ),
    )
}

// ---- global files ----------------------------------------------------------------------------------------

fn global(show: &Show<'_>, node: ProcNode, seq: &mut Seq) -> KResult<()> {
    let (_, which) = super::ROOT_ENTRIES[node.sub as usize];
    let host = show.host;
    match which {
        Global::Sys => Err(Errno::EISDIR),
        Global::Version => {
            // linux_proc_banner
            seq.put(host.uts[0])?;
            seq.puts(" version ")?;
            seq.put(host.uts[1])?;
            seq.puts(" (")?;
            seq.put(host.compile_by)?;
            seq.puts(") (")?;
            seq.put(host.compiler)?;
            seq.puts(") ")?;
            seq.put(host.uts[2])?;
            seq.putc(b'\n')
        }
        Global::Filesystems => {
            // shortcut: only the two filesystems this kernel implements are registered; the
            // reference's list has more (`rootfs`, `sysfs`, `devpts`, ...). Upgrade with each
            // `register_filesystem` of a ported filesystem.
            for (name, nodev) in FILESYSTEMS {
                seq::print(
                    seq,
                    format_args!("{}\t{name}\n", if nodev { "nodev" } else { "" }),
                )?;
            }
            Ok(())
        }
        Global::Cmdline => {
            seq.put(&host.cmdline)?;
            seq.putc(b'\n')
        }
        Global::Uptime => {
            let up = host.uptime_ns;
            let idle = host.idle_ns;
            seq::print(
                seq,
                format_args!(
                    "{}.{:02} {}.{:02}\n",
                    up / 1_000_000_000,
                    up % 1_000_000_000 / 10_000_000,
                    idle / 1_000_000_000,
                    idle % 1_000_000_000 / 10_000_000,
                ),
            )
        }
        Global::Loadavg => {
            // LOAD_INT / LOAD_FRAC with FSHIFT 11
            let int = |x: u64| x >> 11;
            let frac = |x: u64| ((x & 2047) * 100) >> 11;
            let [a, b, c] = host.avenrun;
            seq::print(
                seq,
                format_args!(
                    "{}.{:02} {}.{:02} {}.{:02} {}/{} {}\n",
                    int(a),
                    frac(a),
                    int(b),
                    frac(b),
                    int(c),
                    frac(c),
                    host.nr_running,
                    show.tasks.nr_threads(),
                    host.last_pid,
                ),
            )
        }
        Global::Stat => stat_global(show, seq),
        Global::Meminfo => meminfo(show, seq),
        Global::Cpuinfo => super::cpuinfo::render(&host.cpu, seq),
        Global::Devices => devices(show, seq),
    }
}

fn stat_global(show: &Show<'_>, seq: &mut Seq) -> KResult<()> {
    let host = show.host;
    let cpu = host.cpustat.map(nsec_to_clock_t);
    for prefix in ["cpu ", "cpu0"] {
        seq.puts(prefix)?;
        if prefix == "cpu " {
            seq.putc(b' ')?;
        }
        for value in cpu {
            seq::print(seq, format_args!(" {value}"))?;
        }
        seq.putc(b'\n')?;
    }
    let total: u64 = host.irqs.iter().sum::<u64>() + host.arch_irqs;
    seq::print(seq, format_args!("intr {total}"))?;
    for count in &host.irqs {
        seq::print(seq, format_args!(" {count}"))?;
    }
    let soft: u64 = host.softirqs.iter().sum();
    seq::print(
        seq,
        format_args!(
            "\nctxt {}\nbtime {}\nprocesses {}\nprocs_running {}\nprocs_blocked 0\nsoftirq {soft}",
            host.ctxt, host.boot_real_s, host.forks, host.nr_running,
        ),
    )?;
    for count in host.softirqs {
        seq::print(seq, format_args!(" {count}"))?;
    }
    seq.putc(b'\n')
}

fn meminfo(show: &Show<'_>, seq: &mut Seq) -> KResult<()> {
    let h = show.host;
    let kb = |pages: u64| pages << 2;
    let total = kb(h.total_pages);
    let free = kb(h.free_pages);
    // si_mem_available: free plus the reclaimable page cache (tmpfs pages
    // are not reclaimable without swap), minus the low-water reserve (none).
    let available = free;
    let rows: [(&str, u64); 16] = [
        ("MemTotal", total),
        ("MemFree", free),
        ("MemAvailable", available),
        ("Buffers", 0),
        ("Cached", kb(h.shmem_pages)),
        ("SwapCached", 0),
        ("Active", 0),
        ("Inactive", kb(h.anon_pages + h.shmem_pages)),
        ("Active(anon)", 0),
        ("Inactive(anon)", kb(h.anon_pages)),
        ("Active(file)", 0),
        ("Inactive(file)", 0),
        ("Unevictable", 0),
        ("Mlocked", 0),
        ("SwapTotal", 0),
        ("SwapFree", 0),
    ];
    for (name, value) in rows {
        meminfo_row(seq, name, value)?;
    }
    for (name, value) in [
        ("Dirty", 0),
        ("Writeback", 0),
        ("AnonPages", kb(h.anon_pages)),
        ("Mapped", kb(h.mapped_pages)),
        ("Shmem", kb(h.shmem_pages)),
        ("KReclaimable", 0),
        ("Slab", h.slab_kb),
        ("SReclaimable", 0),
        ("SUnreclaim", h.slab_kb),
        ("KernelStack", h.kernel_stack_kb),
        ("PageTables", h.pagetable_kb),
        ("SecPageTables", 0),
        ("NFS_Unstable", 0),
        ("Bounce", 0),
        ("WritebackTmp", 0),
        ("CommitLimit", total / 2),
        ("Committed_AS", kb(h.anon_pages)),
        ("VmallocTotal", 34_359_738_367),
        ("VmallocUsed", 0),
        ("VmallocChunk", 0),
        ("Percpu", 0),
        ("Balloon", 0),
    ] {
        meminfo_row(seq, name, value)?;
    }
    seq.puts("HugePages_Total:       0\nHugePages_Free:        0\nHugePages_Rsvd:        0\nHugePages_Surp:        0\n")?;
    meminfo_row(seq, "Hugepagesize", 2048)?;
    meminfo_row(seq, "Hugetlb", 0)?;
    // shortcut: the kernel direct map is not classified by page size here.
    meminfo_row(seq, "DirectMap4k", 0)?;
    // Linux prints DirectMap1G only when the direct map uses 1 GiB pages; this one never does.
    meminfo_row(seq, "DirectMap2M", total)
}

/// `show_val_kb`: `%-15s %8lu kB` after the name and a colon.
fn meminfo_row(seq: &mut Seq, name: &str, kb: u64) -> KResult<()> {
    let mut label = Seq::new();
    label.puts(name)?;
    label.putc(b':')?;
    seq::print(
        seq,
        format_args!(
            "{:<15} {kb:>8} kB\n",
            core::str::from_utf8(label.as_bytes()).unwrap_or("?")
        ),
    )
}

fn devices(show: &Show<'_>, seq: &mut Seq) -> KResult<()> {
    seq.puts("Character devices:\n")?;
    for (major, name) in &show.host.chrdevs {
        seq::print(seq, format_args!("{major:3} {name}\n"))?;
    }
    seq.puts("\nBlock devices:\n")?;
    // shortcut: the character devices are the five this kernel serves and the block list is
    // empty (the reference lists its registered majors and the extended block major `blkext`);
    // the group checks the shape and the lines it can derive. Upgrade with the device
    // registries (`register_chrdev`, `register_blkdev`).
    Ok(())
}

// ---- sysctl -----------------------------------------------------------------------------------------------

fn sysctl(show: &Show<'_>, node: ProcNode, seq: &mut Seq) -> KResult<()> {
    let h = show.host;
    let entry = super::SYSCTLS[node.sub as usize];
    let number = |seq: &mut Seq, v: u64| seq::print(seq, format_args!("{v}\n"));
    match entry.which {
        Sys::Dir => Err(Errno::EISDIR),
        Sys::OsType => {
            seq.put(h.uts[0])?;
            seq.putc(b'\n')
        }
        Sys::OsRelease => {
            seq.put(h.uts[1])?;
            seq.putc(b'\n')
        }
        Sys::Version => {
            seq.put(h.uts[2])?;
            seq.putc(b'\n')
        }
        Sys::Hostname => {
            seq.put(h.uts[3])?;
            seq.putc(b'\n')
        }
        Sys::Domainname => {
            seq.put(h.uts[4])?;
            seq.putc(b'\n')
        }
        Sys::PidMax => number(seq, h.pid_max),
        Sys::ThreadsMax => number(seq, h.threads_max),
        Sys::NgroupsMax => number(seq, 65536),
        Sys::CapLastCap => number(seq, 40),
        Sys::OverflowUid | Sys::OverflowGid => number(seq, 65534),
        Sys::RandomizeVaSpace => number(seq, 0),
        Sys::MaxMapCount => number(seq, h.max_map_count),
        Sys::MmapMinAddr => number(seq, h.mmap_min_addr),
        Sys::OvercommitMemory => number(seq, h.overcommit_memory),
    }
}

// ---- links ------------------------------------------------------------------------------------------------------

/// `readlink` of a link node (`do_proc_readlink` / `proc_*_get_link`).
///
/// # Errors
/// `ENOENT`, `EACCES`, `ENOMEM`.
pub fn readlink(show: &Show<'_>, node: ProcNode) -> KResult<Vec<u8>> {
    let mut seq = Seq::new();
    match node.kind {
        Kind::SelfLink => {
            // proc_self_get_link
            if show.caller.tgid == 0 {
                return Err(Errno::ENOENT);
            }
            write!(seq, "{}", show.caller.tgid).map_err(|_| Errno::ENOMEM)?;
        }
        Kind::ThreadSelf => {
            if show.caller.tgid == 0 {
                return Err(Errno::ENOENT);
            }
            write!(seq, "{0}/task/{0}", show.caller.tgid).map_err(|_| Errno::ENOMEM)?;
        }
        Kind::MountsLink => seq.puts("self/mounts")?,
        Kind::FdLink | Kind::Cwd | Kind::RootLink | Kind::Exe => {
            return magic_path(show, node);
        }
        _ => return Err(Errno::EINVAL),
    }
    Ok(seq.into_vec())
}

/// `proc_pid_readlink`: the `d_path` of where the link leads.
fn magic_path(show: &Show<'_>, node: ProcNode) -> KResult<Vec<u8>> {
    let env = crate::vfs::Env {
        root: show.root,
        start: show.root,
        cred: show.caller.cred,
        umask: 0,
        tgid: show.caller.tgid,
    };
    let target = super::magic_target(&show.vfs.fs.ns.proc, &show.vfs.files, &env, node)?;
    let view = show.vfs.fs.ns.proc.view(node.tgid).ok_or(Errno::ENOENT)?;
    let root = view.root().unwrap_or(show.root);
    match target {
        super::Magic::Inode(inode) => {
            // The file's own dentry when it has one (a name, or ` (deleted)`).
            let entry = match node.kind {
                Kind::Exe => view.exe,
                Kind::FdLink => view.fd(node.sub).copied(),
                _ => None,
            };
            if let Some(entry) = entry
                && let Some(file) = show.vfs.files.get_checked(entry.file, entry.serial)
            {
                return file_path(show, file);
            }
            let (path, _) = show.vfs.fs.d_path(root, inode)?;
            Ok(path)
        }
        super::Magic::Anonymous => {
            let entry = view.fd(node.sub).ok_or(Errno::ENOENT)?;
            let file = show
                .vfs
                .files
                .get_checked(entry.file, entry.serial)
                .ok_or(Errno::ENOENT)?;
            let mut seq = Seq::new();
            if let crate::vfs::file::FileKind::Pipe { pipe, .. } = file.kind {
                // `dynamic_dname`: pipefs names its inodes `pipe:[ino]`.
                write!(seq, "pipe:[{}]", show.vfs.pipe_ref(pipe).ino).map_err(|_| Errno::ENOMEM)?;
            } else {
                seq.puts("anon_inode:[unknown]")?;
            }
            Ok(seq.into_vec())
        }
    }
}

impl HostInfo {
    /// A machine with nothing counted yet (host tests).
    #[must_use]
    pub fn blank() -> Self {
        #[allow(clippy::unnecessary_wraps)] // the field is a `fn(SchedId) -> Option<TaskState>`
        fn running(_: SchedId) -> Option<TaskState> {
            Some(TaskState::Running)
        }
        fn no_time(_: SchedId) -> (u64, u64) {
            (0, 0)
        }
        Self {
            uptime_ns: 0,
            idle_ns: 0,
            total_pages: 0,
            free_pages: 0,
            avenrun: [0; 3],
            cmdline: Vec::new(),
            nr_running: 1,
            last_pid: 1,
            forks: 1,
            ctxt: 0,
            boot_real_s: 0,
            cpustat: [0; 10],
            irqs: Vec::new(),
            arch_irqs: 0,
            softirqs: [0; 10],
            tty_pgrp: 0,
            shmem_pages: 0,
            kernel_stack_kb: 0,
            slab_kb: 0,
            anon_pages: 0,
            mapped_pages: 0,
            pagetable_kb: 0,
            sched_state: running,
            cpu_time: no_time,
            uts: [b"Linux", b"6.18.57", b"#1 linux-rs", b"(none)", b"(none)"],
            cpu: super::cpuinfo::CpuFacts::EMPTY,
            chrdevs: Vec::new(),
            threads_max: 0,
            pid_max: 32768,
            max_map_count: 65530,
            mmap_min_addr: 4096,
            overcommit_memory: 0,
            compile_by: b"linux-rs@build",
            compiler: b"rustc",
        }
    }
}
