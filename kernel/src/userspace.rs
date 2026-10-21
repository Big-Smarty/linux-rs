// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692 (all GPL-2.0): kernel/fork.c
// (`copy_process` 1934-2480, `kernel_clone` 2570, `dup_mm`/`dup_mmap`,
// `copy_files`, `copy_fs`, `copy_sighand`, `copy_signal`), fs/file.c (`dup_fd`,
// `close_files`), fs/fs_struct.c (`copy_fs_struct`, `exit_fs`), kernel/exit.c
// (`do_exit`, `exit_mm`, `exit_notify`, `release_task`), kernel/sched/core.c
// (`wake_up_new_task`, `do_task_dead`, `sched_cancel_fork`), arch/x86/mm/fault.c
// (`show_signal_msg`), arch/x86/kernel/traps.c (`show_signal`), kernel/signal.c
// (`unhandled_signal`).
// Transformation: a task's state is split into what every task shares (the task
// list and the VFS, under one lock taken on demand and dropped before a sleep)
// and what only it touches (`TaskLocal`); `copy_process`' unwinding is the
// sequence of undo steps in `Syscall::fork`; the address space is copied
// eagerly (no copy-on-write); the kernel stack is a pool slot.
//! Freestanding half of the first-userspace exec path (decision A18): it owns
//! the frames and the page tables, feeds them from the pure plan in `exec`,
//! then runs init: ring-3 entry, the syscall and exception handlers called by
//! `cpu.rs`, and init's death.
//!
//! State used after ring 3 starts lives in statics (`PROCESS`, `LOCALS` here,
//! `BOOT`, `FRAMES` and `TABLES` in `services`), never in `kernel_main`'s
//! frame, whose boot stack becomes the idle task's. What every task shares
//! (the task list, the VFS) is under the `PROCESS` lock, taken on demand and
//! never held while a task sleeps; what only the running task touches (its page
//! tables, memory model, descriptor table, attributes) is its [`TaskLocal`].
//!
//! Context: BSP, interrupts off, before the owned CR3 is published. The module
//! payloads are only readable while the loader mapping epoch is active, so the
//! file bytes are copied into freshly allocated user frames here and no
//! payload borrow survives this function. These table writes happen to precede
//! `Tables::activate`; `paging`'s update rules permit user-half edits after it.
//!
//! shortcut: frames and tables of a failed load are not returned; any failure
//! is fatal for the boot (Linux panics when init cannot be started). Upgrade
//! when `execve` of a second process exists.
//! shortcut: the file's owner and setuid/setgid bits are ignored; init always
//! runs with uid/gid 0 and no secure-exec (a root-owned initramfs).
//! shortcut: `/init` is read whole into a temporary vector and copied into
//! frames (Linux maps page-cache pages); upgrade with file-backed `mmap`.
//!
//! The rootfs (`vfs`) is built and unpacked here, before the owned tables are
//! activated (the module payloads are only readable then), so its timestamps
//! carry `vfs::tmpfs::UNSET_TIME` until `start` fixes them with the running
//! clock.

// The suite loads from retained archives, not from `BootInfo` modules.
#[cfg_attr(feature = "baremetal-suite", allow(unused_imports))]
use crate::{
    boot::{BootError, BootInfo},
    console, cpu, fpu, ktask,
    memory::{Error as MemoryError, PAGE, PAGE_BYTES, Physical},
    paging::{self, Tables, UserSpace},
    services::{self, Service, ServiceGuard},
    timer,
};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    arch::x86_64::{__cpuid, __cpuid_count, _rdrand64_step, _rdseed64_step, _rdtsc},
    cell::UnsafeCell,
    iter,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use kernel::{
    cputime::CpuSample,
    exec::{
        args::{ArgsError, InitArgv, Word},
        load::{Pager, exec_file, insert_stack, map_segments},
        plan::{LoadError, LoadPlan, Unsupported},
        report::{
            self, BadFrame, ExecFailed, FileRegion, InitDeath, NO_INIT, NO_ROOT, NO_ROOT_PANIC,
            Segfault, TrapLine,
        },
        script,
        stack::{self, ARG_PAGES, Aux, ENVP, STACK_START, STACK_TOP, StackError},
    },
    image::elf::Elf,
    loadavg::LoadAvg,
    mm::{self, Env, FaultOutcome, Mm, PF_WRITE},
    procfs::{
        Caller,
        show::{HostInfo, Show, ShowScope},
        view::{Collect, TaskView},
    },
    ratelimit::RateLimit,
    sched::{CLASS_VFORK, PIPE_KEY, SchedId, TaskState, WaitKey, WakeMode},
    signal::{
        self, SIGSTOP, State,
        deliver::{self, Outcome as SignalOutcome},
        frame::Sigreturn,
        info,
    },
    syscall::{
        self, AddressSpace, ClockState, Clocks, Console, Context, ExecAux, Files, Machine, Outcome,
        RestartBlock, Tasks,
    },
    task::{
        self, Attributes, TaskId, Tasklist,
        exit::{ExitPrep, Waker, chldexit_key},
        fork::ForkRequest,
        jobctl::StopPlan,
        tasklist::ForkParams,
    },
    usercopy::{self, UserPages},
    vfs::{
        self, FdTable, FileId, MAY_EXEC, O_LARGEFILE, O_RDONLY, Timespec, Vfs, initramfs::Unpacker,
        mapping::FileFault, ops::OpenFlags, path::LOOKUP_FOLLOW,
    },
};
use syscalls::Errno;

pub const FILENAME: &[u8] = b"/init";
/// `allocate_order(2)` below backs exactly the argument pages.
const _: () = assert!(ARG_PAGES == 4);

pub enum Error {
    /// The rootfs has no `/init`: Linux ends in `NO_INIT`.
    NoInit,
    /// No `/init`, and boot module `module` is compressed: Linux (gzip and the
    /// other `RD_*` decompressors are configured) would have unpacked it and
    /// possibly found an `/init`, but no decompressor is ported. Not Linux's
    /// `NO_INIT`: the boot stops loudly instead of imitating a Linux failure.
    CompressedModule(usize),
    /// The rootfs itself could not be built (`default_rootfs` failed or no memory).
    Vfs(Errno),
    /// Linux `execve` failure; the errno is what `Failed to execute` prints.
    Exec(Errno),
    /// `/init` failed to execute and one of Linux's fallback inits exists in
    /// the archives; running it is outside this slice.
    Fallback {
        errno: i32,
        path: &'static [u8],
    },
    Load(LoadError),
    Args(ArgsError),
    Stack(StackError),
    Boot(BootError),
    Memory(MemoryError),
    Paging(paging::Error),
}
impl core::fmt::Debug for Error {
    // Manual, like `paging::Error`: payloads must be read to be reported.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoInit => f.write_str("NoInit"),
            Self::CompressedModule(module) => {
                f.debug_tuple("CompressedModule").field(module).finish()
            }
            Self::Vfs(errno) => f.debug_tuple("Vfs").field(errno).finish(),
            Self::Exec(errno) => f.debug_tuple("Exec").field(errno).finish(),
            Self::Fallback { errno, path } => f
                .debug_struct("Fallback")
                .field("errno", errno)
                .field("path", &core::str::from_utf8(path).unwrap_or("?"))
                .finish(),
            Self::Load(error) => f.debug_tuple("Load").field(error).finish(),
            Self::Args(error) => f.debug_tuple("Args").field(error).finish(),
            Self::Stack(error) => f.debug_tuple("Stack").field(error).finish(),
            Self::Boot(error) => f.debug_tuple("Boot").field(error).finish(),
            Self::Memory(error) => f.debug_tuple("Memory").field(error).finish(),
            Self::Paging(error) => f.debug_tuple("Paging").field(error).finish(),
        }
    }
}
impl From<BootError> for Error {
    fn from(value: BootError) -> Self {
        Self::Boot(value)
    }
}
impl From<MemoryError> for Error {
    fn from(value: MemoryError) -> Self {
        Self::Memory(value)
    }
}
impl From<paging::Error> for Error {
    fn from(value: paging::Error) -> Self {
        Self::Paging(value)
    }
}
impl From<LoadError> for Error {
    fn from(value: LoadError) -> Self {
        Self::Load(value)
    }
}
impl From<StackError> for Error {
    fn from(value: StackError) -> Self {
        Self::Stack(value)
    }
}
impl From<ArgsError> for Error {
    fn from(value: ArgsError) -> Self {
        Self::Args(value)
    }
}

/// Everything later stages need once `/init` is mapped. Plain data; the mapped
/// pages live in the tables: the published ones (`services::TABLES`, taken by
/// `start`) at boot, or `tables` when the loader built a tree of its own.
pub struct Loaded {
    /// The unpacked rootfs; moves into [`Process`] when init starts.
    pub vfs: Vfs,
    /// The page tables the loader mapped `/init` into, when it made its own
    /// (the bare-metal suite: one fresh tree per group); `None` at boot, where
    /// the published tree is init's.
    pub tables: Option<Tables>,
    /// The open file `/init` was read from (`bprm->file`); the VMAs of its
    /// segments pin it when init starts; the reference itself then stays as
    /// the task's `mm->exe_file` ([`Owned::exe_file`]).
    pub exec: FileId,
    pub entry: u64,
    pub sp: u64,
    pub loads: usize,
    pub argc: u64,
    /// The address space the loader built (VMAs, `start_brk`, data bounds).
    pub mm: Mm,
    /// The limits and sysctls its rules read.
    pub env: Env,
}

fn weak_random() -> [u8; 16] {
    // SAFETY: RDTSC executes at CPL0 on every x86-64 CPU and reads no memory.
    stack::weak_random(unsafe { _rdtsc() })
}

/// 64 bits from `RDSEED` (CPUID.7.0:EBX bit 18), else `RDRAND` (CPUID.1:ECX bit 30); each is
/// retried ten times, Intel's guidance for a transient failure. `None` when neither exists
/// or both keep failing.
fn hw_random_u64() -> Option<u64> {
    #[target_feature(enable = "rdrand")]
    fn rdrand() -> Option<u64> {
        let mut value = 0;
        (_rdrand64_step(&mut value) == 1).then_some(value)
    }
    #[target_feature(enable = "rdseed")]
    fn rdseed() -> Option<u64> {
        let mut value = 0;
        (_rdseed64_step(&mut value) == 1).then_some(value)
    }
    if __cpuid(0).eax >= 7 && __cpuid_count(7, 0).ebx & (1 << 18) != 0 {
        // SAFETY: CPUID.7.0:EBX.RDSEED was just checked.
        if let Some(value) = (0..10).find_map(|_| unsafe { rdseed() }) {
            return Some(value);
        }
    }
    if __cpuid(1).ecx & (1 << 30) != 0 {
        // SAFETY: CPUID.1:ECX.RDRAND was just checked.
        return (0..10).find_map(|_| unsafe { rdrand() });
    }
    None
}

/// RDRAND when present (CPUID.1:ECX bit 30), else a documented weak seed.
fn random_bytes() -> [u8; 16] {
    #[target_feature(enable = "rdrand")]
    fn rdrand() -> Option<u64> {
        let mut value = 0;
        (_rdrand64_step(&mut value) == 1).then_some(value)
    }
    if __cpuid(1).ecx & (1 << 30) != 0 {
        let mut out = [0; 16];
        for half in out.as_chunks_mut::<8>().0 {
            // SAFETY: CPUID.1:ECX.RDRAND was just checked.
            // Intel's guidance is to retry a bounded number of times on failure.
            let Some(value) = (0..10).find_map(|_| unsafe { rdrand() }) else {
                return weak_random();
            };
            *half = value.to_le_bytes();
        }
        return out;
    }
    weak_random()
}

/// Find, validate and map `/init`, build its stack, and return the entry state.
///
/// # Errors
/// [`Error::NoInit`] when absent (the caller reproduces Linux's panic), the
/// Linux `execve` errno or an explicit unsupported case otherwise.
#[cfg(not(feature = "baremetal-suite"))]
pub fn load(boot: &BootInfo, tables: &mut Tables) -> Result<Loaded, Error> {
    let (vfs, compressed) = build_rootfs(boot)?;
    load_rootfs(boot.command_line(), vfs, compressed, tables)
}

/// [`load`] after the rootfs exists: the shared tail of the boot path and of
/// the bare-metal suite's per-group loads.
fn load_rootfs(
    command_line: &[u8],
    vfs: Vfs,
    compressed: Option<usize>,
    tables: &mut Tables,
) -> Result<Loaded, Error> {
    let fallback = first_fallback(&vfs);
    match load_init(command_line, vfs, tables) {
        Ok(loaded) => Ok(loaded),
        Err(Error::NoInit) if compressed.is_some() => {
            Err(Error::CompressedModule(compressed.unwrap_or_default()))
        }
        Err(Error::Exec(errno) | Error::Load(LoadError::Errno(errno))) if fallback.is_some() => {
            Err(Error::Fallback {
                errno: errno.into_raw(),
                path: fallback.unwrap_or_default(),
            })
        }
        Err(error) => Err(error),
    }
}

/// `kernel_init`'s fallbacks after a failed `/init` (init/main.c:1499-1502).
const FALLBACKS: [&[u8]; 4] = [b"/sbin/init", b"/etc/init", b"/bin/init", b"/bin/sh"];

/// The clock of the rootfs until timekeeping runs: every timestamp it hands out
/// is [`vfs::tmpfs::UNSET_TIME`] and `start` replaces those with real time.
fn early_clock() -> Timespec {
    vfs::tmpfs::UNSET_TIME
}

/// The rootfs as `rootfs_initcall` leaves it: tmpfs (`init_rootfs`: no
/// `root=`), the builtin initramfs (`/dev`, `/dev/console`, `/root`), then every
/// boot module unpacked in order (`populate_rootfs`). A module the unpacker
/// stops on keeps the entries before the stop, as in Linux; compressed modules
/// are skipped (decompression is not ported; the boot log already warned).
#[cfg(not(feature = "baremetal-suite"))]
fn build_rootfs(boot: &BootInfo) -> Result<(Vfs, Option<usize>), Error> {
    let mut rootfs = new_rootfs()?;
    for index in 0..boot.module_count() {
        let span = boot.module_span(index)?;
        // SAFETY: trusted initialized immutable file storage, BSP only, no
        // DMA/AP/firmware writer or reclaim, loader CR3 still active (`load`
        // runs before the owned tables are activated). The borrow ends within
        // this iteration; the unpacker copies what it keeps.
        let bytes = unsafe { boot.module_bytes(span) }?;
        rootfs.unpack(index, bytes);
    }
    Ok((rootfs.vfs, rootfs.compressed))
}

/// A rootfs under construction: the `rootfs_initcall` state between modules.
struct Rootfs {
    vfs: Vfs,
    unpacker: Unpacker,
    compressed: Option<usize>,
}

fn new_rootfs() -> Result<Rootfs, Error> {
    // shmem_default_max_blocks / _max_inodes: both half the RAM's pages
    // (`min3(nr_pages - totalhigh, nr_pages / 2, ...)` for the inodes).
    let pages = services::FRAMES.lock().total() as u64;
    let mut vfs = Vfs::new(pages / 2, pages / 2, early_clock).map_err(Error::Vfs)?;
    vfs.default_rootfs().map_err(Error::Vfs)?;
    Ok(Rootfs {
        vfs,
        unpacker: Unpacker::new(),
        compressed: None,
    })
}

impl Rootfs {
    /// `unpack_to_rootfs` of boot module `index`.
    fn unpack(&mut self, index: usize, bytes: &[u8]) {
        if let Some(message) = self.unpacker.unpack(&mut self.vfs, bytes) {
            // CONFIG_BLK_DEV_RAM=n (`do_populate_rootfs`): the unpacker's own
            // message; the entries before the failure stay in the tree.
            if message == vfs::initramfs::NOT_PORTED {
                self.compressed.get_or_insert(index);
                crate::log!("WARN module={}: {}\n", index, message);
            } else {
                crate::log!("Initramfs unpacking failed: {}\n", message);
            }
        }
    }
}

/// The kernel thread's view of the rootfs for `init_*` and `kernel_execve`.
fn exec_open() -> OpenFlags {
    // open_exec_flags: O_LARGEFILE | O_RDONLY, MAY_EXEC, LOOKUP_FOLLOW.
    OpenFlags {
        flags: O_LARGEFILE | O_RDONLY,
        mode: 0,
        acc_mode: MAY_EXEC,
        follow: true,
        directory: false,
        cloexec: false,
    }
}

/// `do_open_execat` + `kernel_read` of the whole file; the open file stays
/// open (`bprm->file`) for the caller to hand to the VMAs or `fput`.
fn open_exec_file(vfs: &mut Vfs, path: &[u8]) -> Result<(Vec<u8>, FileId), Errno> {
    let env = vfs.kernel_env();
    let file = vfs.open(&env, path, &exec_open())?;
    let inode = vfs.files.get(file).inode;
    let bytes = match inode {
        // do_open_execat: only regular files execute.
        Some(inode) if vfs.fs.inode(inode).is_reg() => vfs.fs.read_all(inode),
        _ => Err(Errno::EACCES),
    };
    match bytes {
        Ok(bytes) => Ok((bytes, file)),
        Err(errno) => {
            vfs.fput(file);
            Err(errno)
        }
    }
}

/// [`open_exec_file`] for a caller that only needs the bytes.
fn open_exec(vfs: &mut Vfs, path: &[u8]) -> Result<Vec<u8>, Errno> {
    let (bytes, file) = open_exec_file(vfs, path)?;
    vfs.fput(file);
    Ok(bytes)
}

/// The first fallback init present in the rootfs.
fn first_fallback(vfs: &Vfs) -> Option<&'static [u8]> {
    let env = vfs.kernel_env();
    FALLBACKS
        .into_iter()
        .find(|path| vfs.lookup(&env, path, LOOKUP_FOLLOW).is_ok())
}

/// `load_script`: `-ENOENT` when the interpreter is not in the rootfs (what
/// `open_exec` returns), otherwise an explicit unsupported failure.
fn script_failure(vfs: &mut Vfs, interpreter: &[u8]) -> Error {
    interpreter_failure(vfs, interpreter, Unsupported::Script)
}

/// The shared tail of `load_script` and `load_elf_binary`'s `PT_INTERP` scan:
/// `open_exec(interpreter)` fails with its `errno` exactly as Linux does; an
/// interpreter that opens is `unsupported`.
fn interpreter_failure(vfs: &mut Vfs, interpreter: &[u8], unsupported: Unsupported) -> Error {
    if interpreter.is_empty() {
        return Error::Exec(Errno::ENOENT);
    }
    match open_exec(vfs, interpreter) {
        Err(errno) => Error::Exec(errno),
        Ok(_) => Error::Load(LoadError::Unsupported(unsupported)),
    }
}

fn load_init(command_line: &[u8], mut vfs: Vfs, tables: &mut Tables) -> Result<Loaded, Error> {
    // kernel_init_freeable: `init_eaccess(ramdisk_execute_command)` failing sends
    // Linux to `prepare_namespace`; any lookup failure counts.
    let env = vfs.kernel_env();
    if vfs.lookup(&env, FILENAME, LOOKUP_FOLLOW).is_err() {
        return Err(Error::NoInit);
    }
    let (file_bytes, exec) = open_exec_file(&mut vfs, FILENAME).map_err(Error::Exec)?;
    let file = file_bytes.as_slice();
    match script::interpreter(file) {
        Err(errno) => return Err(Error::Exec(errno)),
        Ok(Some(interpreter)) => return Err(script_failure(&mut vfs, interpreter)),
        Ok(None) => {}
    }
    let plan = match LoadPlan::new(file) {
        Err(LoadError::Unsupported(Unsupported::Interpreter)) => {
            // The plan checked the header and the `PT_INTERP` bytes (Linux
            // order); the interpreter is now looked up in the archives.
            let path = Elf::linux_x86_64(file)
                .ok()
                .and_then(|elf| elf.interpreter().ok().flatten())
                .unwrap_or_default();
            return Err(interpreter_failure(
                &mut vfs,
                path,
                Unsupported::Interpreter,
            ));
        }
        other => other?,
    };

    // The address space is built by the one mapping-rule mechanism (`mm`):
    // the shared zero page, the stack VMA, then every `PT_LOAD` (the loader
    // installs the file pages it owns as it goes). The model's vectors are
    // reserved from the heap before each `FRAMES` guard, which the table view
    // takes per operation (`services`).
    let total_pages = services::FRAMES.lock().total() as u64;
    // The suite loads one init per group into the same tables (`teardown`).
    if !tables.has_zero_page() {
        tables.init_zero_page(&mut services::FRAMES.lock())?;
    }
    let mut env = Env::init(total_pages, 0);
    env.ospke = fpu::config().ospke;
    let mut mm = Mm::new(&env);
    insert_stack(&mut mm, &env, plan.exec_stack)?;
    map_segments(
        &plan,
        file,
        &exec_file(u64::from(exec.index())),
        &mut mm,
        &env,
        &mut tables.user_space(),
    )?;

    // No heap allocation while `FRAMES` is held (`services`): everything that
    // grows a vector happened above.
    let mut allocator = services::FRAMES.lock();
    let allocator = &mut *allocator;
    // The argument block lives in the top ARG_PAGES pages: one contiguous
    // frame so `stack::build` can write it as a single window.
    let mut top = allocator.allocate_order(2)?;
    let argv = InitArgv::parse(command_line)?;
    let aux = Aux {
        hwcap: __cpuid(1).edx,
        phdr: plan.phdr,
        phnum: plan.phnum,
        entry: plan.entry,
        random: random_bytes(),
    };
    let built = stack::build(
        top.bytes(),
        FILENAME,
        iter::once(Word::plain(FILENAME)).chain(argv),
        ENVP.iter().copied(),
        &aux,
    )?;
    mm.record_stack(
        built.sp,
        built.arg_start,
        built.arg_end,
        built.env_start,
        built.env_end,
    );
    let top = top.into_reserved();
    // SAFETY: `top` is the live order-two reservation just made; no token,
    // reference or mapping of it exists yet. Afterwards each page is its own
    // order-zero reservation, as `map_user` requires for later unmapping.
    unsafe { allocator.split_reserved_order(top, 2)? };
    for page in 0..ARG_PAGES as u64 {
        let address = STACK_TOP - (ARG_PAGES as u64 - page) * PAGE;
        let physical = Physical(top.0 + page * PAGE);
        tables.map_user(allocator, address, physical, true, plan.exec_stack)?;
    }
    // The 32 expansion pages below the arguments are demand-zero (Linux's
    // `setup_arg_pages` expands the VMA, it does not fault the pages in).

    Ok(Loaded {
        vfs,
        tables: None,
        exec,
        entry: plan.entry,
        sp: built.sp,
        loads: plan.segments().len(),
        argc: built.argc,
        mm,
        env,
    })
}

/// The task model's [`Waker`] on the scheduler's wait queues: `child_event` is
/// `__wake_up_parent` (`__wake_up_sync_key` on the parent's `wait_chldexit`,
/// `TASK_INTERRUPTIBLE`, one exclusive waiter), `signal_wake` is
/// `signal_wake_up(t, resume)` on the task's scheduling handle (which the task
/// list keeps, `Tasklist::set_sched`; `resume` also ends a job-control stop),
/// and `wake_stopped` is `SIGCONT`'s `wake_up_state(t, __TASK_STOPPED)`. All
/// take `RQ`, a leaf that any lock may precede (`services`).
struct SchedWaker;

impl Waker for SchedWaker {
    fn child_event(&mut self, parent: TaskId) {
        ktask::wake_up_key(chldexit_key(parent), WakeMode::Interruptible, 1);
    }
    fn signal_wake(&mut self, _task: TaskId, sched: Option<SchedId>, resume: bool) {
        if let Some(sched) = sched {
            ktask::signal_wake_up(sched, resume);
        }
    }
    fn wake_stopped(&mut self, _task: TaskId, sched: Option<SchedId>) {
        if let Some(sched) = sched {
            ktask::wake_stopped(sched);
        }
    }
}

/// A pipe changed (data written or consumed, an end closed, the capacity
/// changed) since the last look: wake its sleepers (`wake_up_interruptible` on
/// `rd_wait`/`wr_wait`, and the `poll` sleepers, which share the key). The
/// pure VFS only counts the changes ([`Vfs::take_pipe_events`]); this runs
/// before a task sleeps itself (what it just wrote may be what the others wait
/// for), when a system call ends, and when a task exits. Takes `RQ` under the
/// caller's `PROCESS` lock, which the lock order allows.
fn wake_sleepers(process: &mut Process) {
    let Process {
        tasks, vfs, tty, ..
    } = process;
    // The count of files on the console tty (`tty->count`) and its last close.
    syscall::tty::housekeeping(vfs, tty, tasks);
    if vfs.take_pipe_events() {
        ktask::wake_up_key(PIPE_KEY, WakeMode::Interruptible, 0);
    }
    // A change of the tty (input, output drained, termios) wakes its readers
    // and writers, and the `poll` sleepers, who share the pipes' key.
    if tty.take_events() {
        ktask::wake_up_key(kernel::sched::TTY_KEY, WakeMode::Interruptible, 0);
        ktask::wake_up_key(PIPE_KEY, WakeMode::Interruptible, 0);
    }
}

/// The tty's view of the machine for the input path: the task list (the
/// foreground group gets `SIGINT` & co.), the wake-up path and the UART's sink.
struct TtyHost<'a> {
    tasks: &'a mut Tasklist,
    wake: &'a mut SchedWaker,
    sink: &'a mut ConsoleSink,
}

impl kernel::tty::Host for TtyHost<'_> {
    fn kill_pgrp(&mut self, pgrp: task::pid::PidRef, sig: u8) {
        // `kill_pgrp(pgrp, sig, 1)`; an empty group is `ESRCH`, ignored.
        let _ = self.tasks.kill_pgrp_ref(pgrp, sig, self.wake);
    }
    fn transmit(&mut self, bytes: &[u8]) {
        self.sink.write(bytes);
    }
}

/// The input interrupts' entry into the process state: run `f` with the console
/// tty and a host that can signal and transmit, then wake the sleepers it woke.
///
/// Context: hardirq (IF=0), the interrupted code is ring 3 or the idle halt, so the
/// lock is free (`services`). A lock that is held anyway is a bug: the closure is
/// not run and the bytes it would have queued are lost (a keyboard scancode), or
/// stay in the UART whose edge-triggered IRQ then never fires again (serial).
#[cfg_attr(
    feature = "baremetal-suite",
    allow(dead_code, reason = "only the console tty's input interrupts use it")
)]
pub(crate) fn with_tty<R>(
    f: impl FnOnce(&mut kernel::tty::Tty, &mut dyn kernel::tty::Host) -> R,
) -> Option<R> {
    if !PROCESS.is_installed() {
        return None;
    }
    let mut guard = PROCESS.try_lock()?;
    let process = &mut *guard;
    let result = {
        let Process {
            tasks, wake, tty, ..
        } = &mut *process;
        let mut host = TtyHost {
            tasks,
            wake,
            sink: &mut ConsoleSink,
        };
        f(tty, &mut host)
    };
    wake_sleepers(process);
    Some(result)
}

/// What every task shares: the task list (parentage, pids, groups, sessions,
/// credential snapshots and the signal objects of all tasks) and the VFS (the
/// mounted rootfs, open file descriptions, pipes, mapping pins). One lock,
/// `PROCESS`, stands for `TASKLIST` and `VFS` of the lock-order DAG
/// (`services`): `PROCESS` -> heap -> `FRAMES`, and `PROCESS` -> `TIMER_HW`
/// (a leaf, the interval-timer programming of `exit_to_user`).
///
/// **No guard of it is alive across `schedule()`**: a [`Syscall`] takes it
/// lazily ([`Shared`]) and its [`Context::wait`](signal::Task::wait) drops it
/// before the task leaves the CPU, so another task can run a system call
/// meanwhile. State only the running task touches is in [`TaskLocal`].
pub struct Process {
    /// The task list (see above).
    pub tasks: Tasklist,
    /// Wake-ups of other tasks' sleepers, through the scheduler.
    wake: SchedWaker,
    /// The mounted rootfs, open files and pipes.
    pub vfs: Vfs,
    /// The console tty (`ttyS0`): termios, line discipline, controlling
    /// terminal state. Under the same lock as the task list and the VFS: job
    /// control reads both, and the input interrupt takes this lock to run the
    /// line discipline (`ttyin`).
    pub tty: kernel::tty::Tty,
    /// `printk_ratelimit_state`: the limiter of the `show_unhandled_signals`
    /// lines (global in Linux).
    printk_ratelimit: RateLimit,
}

static PROCESS: Service<Process> = Service::new();

/// Load-average state at init start; `sysinfo` replays it to the boot clock
/// ([`LoadAvg::loads_at`]), so there is no tick hook. A leaf lock of its own:
/// [`Context::machine`] takes `&self`.
static LOAD: Service<LoadAvg> = Service::new();

/// The root of the kernel-only page tables ([`services::TABLES`] holds that
/// tree for the life of the system): what CR3 holds while no task's address
/// space may be loaded (`exit_mm`, a group teardown). 0 before `start`.
static KERNEL_ROOT: AtomicU64 = AtomicU64::new(0);

/// The boot clock in jiffies, the unit of the load-average windows. The
/// periodic tick is masked before init starts, so `timer::ticks()` does not
/// advance; the boot clock (`ktime_get_boottime_ns`) does.
fn jiffies_of(boot_ns: u64) -> u64 {
    boot_ns / kernel::time::TICK_NSEC
}

/// `!X86_FEATURE_CPUID_FAULT`, decided only where CPUID can prove it. AMD sets
/// the feature from `X86_FEATURE_GP_ON_USER_CPUID`, CPUID `0x80000021` EAX bit
/// 17 (arch/x86/kernel/cpu/amd.c:536, common.c:1046). Intel reads
/// `MSR_PLATFORM_INFO` with `rdmsrq_safe` (intel.c:488); there is no fault
/// fixup here to make that read safe, so Intel and every other vendor are
/// "not determinable" (false) and `ARCH_SET_CPUID` stops loudly instead.
/// shortcut: AMD-only proof; upgrade with an MSR-read fixup mechanism.
fn cpuid_fault_absent() -> bool {
    let amd = raw_cpuid::CpuId::new()
        .get_vendor_info()
        .is_some_and(|vendor| vendor.as_str() == "AuthenticAMD");
    // `__cpuid` is unconditionally available on x86_64 (CPUID is baseline).
    let gp_on_user_cpuid =
        __cpuid(0x8000_0000).eax >= 0x8000_0021 && __cpuid(0x8000_0021).eax & (1 << 17) != 0;
    amd && !gp_on_user_cpuid
}

/// The tick found the running task in user mode (`user`) or in the kernel on
/// its behalf, `periods` ticks long; called from the timer interrupt. The
/// per-task accounts are in `ktask` (`CPU_TIME`), all atomics.
pub fn account_ticks(user: bool, periods: u64) {
    ktask::charge_tick(user, periods);
}

/// Ring-3 page faults the address-space model resolved (`page_fault`); the
/// self-test build reports it when init exits, as evidence that demand paging
/// of init's own bss/stack through the real tables returned to user mode.
#[cfg(all(feature = "qemu-self-test", not(feature = "baremetal-suite")))]
static USER_FAULTS_HANDLED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// What only the running task touches (`task_struct` fields that no other task
/// reads, `mm`, `files`, `fs`): reached through [`current_local`] and never
/// under a lock. Another task needing something of it would put it in
/// [`Process`] (the credential snapshot, the signal objects and the process
/// tree already are).
pub struct TaskLocal {
    /// `mm->pgd`: the task's page tables, whose root is its CR3.
    tables: Tables,
    own: Owned,
}

/// The part of [`TaskLocal`] that is not the page tables (kept apart so a
/// system call can hold the user-memory view of the tables next to it).
struct Owned {
    /// `current`'s place in the task list, and its scheduling handle.
    me: TaskId,
    sched: SchedId,
    /// `task_tgid_vnr` / `task_pid_vnr` (a one-thread group: equal).
    tgid: u32,
    tid: u32,
    /// Credentials, rlimits, filesystem context, comm, personality and the
    /// user pointers libc registers (`task::Attributes`, the identity group).
    attrs: Attributes,
    /// `current->restart_block.nanosleep`, written by the sleeping syscalls and
    /// run by `restart_syscall`.
    restart: RestartBlock,
    /// The VMA set, program break and statistics (`mm_struct`); the page
    /// tables are `TaskLocal::tables`. It reserves its `Vec` storage (heap)
    /// before any `FRAMES` guard is taken (`services`).
    space: Mm,
    /// The rlimits and sysctls the mapping rules read (`Env`).
    /// shortcut: fixed `INIT_RLIMITS`; `setrlimit`/`prlimit64` must update it
    /// (or derive it from the credentials group's limits) when they land.
    env: Env,
    /// `mm->exe_file`: the open description the image was loaded from (its
    /// `FileInfo::id` is `exec`).
    exe_file: FileId,
    /// `FileInfo::id` of that description: the only file whose name the fault
    /// report knows.
    exec: u64,
    /// `current->files`.
    fdt: FdTable,
    /// The key of the mappings' pins in the VFS (`Vfs::pin`): the identity of the address
    /// space in use. A fresh one for every address space ([`next_pin_owner`]); a `vfork` child
    /// works on its parent's until its `execve` or exit.
    pin_owner: u32,
    /// `current->vfork_done` (`CLONE_VFORK`): the parent sleeping until this task's `execve`
    /// or exit, and whether this task works in the parent's address space.
    vfork_parent: Option<Lender>,
    /// `bprm->mm`: the fresh address space a `vfork` child's `execve` moves to, made before
    /// the point of no return ([`Context::exec_prepare_mm`]).
    pending_mm: Option<(Tables, Mm)>,
    /// This task's address space is in use by its `vfork` child (the tree and VMA set in
    /// `TaskLocal` are placeholders): its pins must outlive this task's exit.
    lent_out: bool,
    /// The counters `/proc/<pid>/{stat,status}` show.
    stats: Stats,
}

/// The parent of a `vfork` child.
#[derive(Clone, Copy)]
struct Lender {
    sched: SchedId,
    /// The child works in the parent's address space (`CLONE_VM`).
    lent: bool,
}

/// `task_struct`'s `start_boottime`, `min_flt`, `maj_flt`, `nvcsw` and `nivcsw`.
#[derive(Clone, Copy, Default)]
struct Stats {
    start_ns: u64,
    min_flt: u64,
    maj_flt: u64,
    nvcsw: u64,
    nivcsw: u64,
}

impl Stats {
    /// A task created now.
    fn started() -> Self {
        Self {
            start_ns: timer::ktime_get_boottime_ns(),
            ..Self::default()
        }
    }
}

impl Owned {
    /// The key of this task's address space in the VFS pin table.
    fn owner(&self) -> u32 {
        self.pin_owner
    }
}

/// A fresh identity for an address space (`Vfs::pin`'s owner key): never a scheduling slot,
/// which a later task reuses while a borrowed address space can outlive its first user.
fn next_pin_owner() -> u32 {
    static NEXT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// What a `vfork` child gives back (`complete_vfork_done`): the parent's address space when it
/// had borrowed it.
struct Done {
    lent: Option<Lent>,
}

struct Lent {
    tables: Tables,
    space: Mm,
}

/// `vfork_done` of each sleeping parent, by its scheduling slot. A leaf lock: nothing else is
/// taken while it is held.
static VFORK_DONE: services::IrqMutex<[Option<Done>; ktask::SLOTS]> =
    services::IrqMutex::new([const { None }; ktask::SLOTS]);

/// A `vfork` child that died while its own `vfork` child still worked in the address space it
/// had borrowed: the lender it owes that address space to, by the dead task's slot. The grandchild's
/// [`complete_vfork`] hands the address space on to it. A leaf lock like [`VFORK_DONE`].
/// shortcut: one entry per slot, so a slot reused by another such task before the grandchild
/// finishes would overwrite it; slots are only reused after the reaper ran, which needs the
/// dead task's parent to get the CPU (a `vfork` lender sleeps until this entry is consumed).
static VFORK_FORWARD: services::IrqMutex<[Option<Lender>; ktask::SLOTS]> =
    services::IrqMutex::new([const { None }; ktask::SLOTS]);

#[allow(
    clippy::cast_possible_truncation,
    reason = "a slot index is below the pool size"
)]
fn vfork_done_key(parent: SchedId) -> WaitKey {
    WaitKey::new(CLASS_VFORK, parent.index() as u32)
}

/// `complete_vfork_done`, called by the child when it execs or exits: the parent wakes (and
/// takes back its address space). A parent that no longer exists (it was killed while it
/// waited) cannot take it: the address space is freed here, with the mappings' pins it left.
fn complete_vfork(lender: Lender, key: u32, lent: Option<Lent>, vfs: &mut Vfs) {
    let alive = matches!(ktask::state(lender.sched), Some(state) if state != TaskState::Dead);
    // Taken as its own statement: an `if let` scrutinee guard lives through the whole branch
    // (edition 2024), and the recursion below must run with `VFORK_FORWARD` released.
    let next = if alive {
        None
    } else {
        VFORK_FORWARD.lock()[lender.sched.index()].take()
    };
    if alive {
        VFORK_DONE.lock()[lender.sched.index()] = Some(Done { lent });
        ktask::wake_up_key(vfork_done_key(lender.sched), WakeMode::Normal, 0);
    } else if let Some(next) = next {
        // The lender died borrowing: the address space goes to whom it borrowed it from.
        complete_vfork(next, key, lent, vfs);
    } else if let Some(lent) = lent {
        vfs.unpin_all(key);
        destroy_tables(lent.tables);
        drop(lent.space);
    }
}

/// The [`TaskLocal`] of every scheduler slot that has a user task.
struct Locals([LocalSlot; ktask::SLOTS]);

struct LocalSlot {
    cell: UnsafeCell<Option<Box<TaskLocal>>>,
    /// A [`LocalGuard`] exists.
    busy: AtomicBool,
}

// SAFETY: a cell is touched only (a) through the one `LocalGuard` that holds
// `busy` (taken by `current_local`, so by the task running in that slot), (b)
// by `install_local`/`take_local`, which assert `busy` is clear, and only the
// creator of a task that is not runnable yet (before `wake_up_new_task`) or the
// task itself (when it exits) or the group teardown with no task running call
// them. The single CPU and IF=0 order everything else; a `TaskLocal` is not
// shared between tasks, so `Send` is what moving it between stacks needs.
unsafe impl Sync for Locals {}

static LOCALS: Locals = Locals(
    [const {
        LocalSlot {
            cell: UnsafeCell::new(None),
            busy: AtomicBool::new(false),
        }
    }; ktask::SLOTS],
);

/// Exclusive access to the running task's [`TaskLocal`] for as long as it
/// lives. A second one for the same task is a kernel bug and stops loudly.
struct LocalGuard {
    slot: usize,
    local: &'static mut TaskLocal,
}

impl core::ops::Deref for LocalGuard {
    type Target = TaskLocal;
    fn deref(&self) -> &TaskLocal {
        self.local
    }
}
impl core::ops::DerefMut for LocalGuard {
    fn deref_mut(&mut self) -> &mut TaskLocal {
        self.local
    }
}
impl Drop for LocalGuard {
    fn drop(&mut self) {
        LOCALS.0[self.slot].busy.store(false, Ordering::Release);
    }
}

/// The running user task's [`TaskLocal`].
///
/// Context: task, from a kernel entry of a user task (system call, exception,
/// interrupt from ring 3) or its exit path; every entry point takes it once
/// and passes it down.
fn current_local() -> LocalGuard {
    let slot = ktask::current().index();
    let entry = &LOCALS.0[slot];
    if entry.busy.swap(true, Ordering::Acquire) {
        crate::log!("FAIL task state entered twice slot={}\n", slot);
        crate::fail();
    }
    // SAFETY: `busy` was clear and is now ours, so no other reference to this
    // cell exists (see `Locals`); the box is never moved or freed while the
    // guard lives (`take_local` asserts `busy` is clear). The `'static`
    // lifetime is bounded by the guard's, which clears `busy` on drop.
    let local = unsafe { (*entry.cell.get()).as_deref_mut() };
    let Some(local) = local else {
        entry.busy.store(false, Ordering::Release);
        crate::log!("FAIL no task state for the running task slot={}\n", slot);
        crate::fail();
    };
    LocalGuard { slot, local }
}

/// Publish the state of a task that cannot run yet (a forked child before
/// `wake_up_new_task`, init before its first switch).
fn install_local(slot: usize, local: Box<TaskLocal>) {
    let entry = &LOCALS.0[slot];
    assert!(!entry.busy.load(Ordering::Acquire), "task state in use");
    // SAFETY: not busy (asserted) and the caller is the only flow that can
    // name the slot (see `Locals`).
    let old = unsafe { (*entry.cell.get()).replace(local) };
    assert!(old.is_none(), "task state installed twice");
}

/// Take the state of the task that is exiting (or of any task at a group
/// teardown), leaving the slot empty.
fn take_local(slot: usize) -> Option<Box<TaskLocal>> {
    let entry = &LOCALS.0[slot];
    assert!(!entry.busy.load(Ordering::Acquire), "task state in use");
    // SAFETY: as `install_local`.
    unsafe { (*entry.cell.get()).take() }
}

/// The most `cmdline`/`environ` bytes copied for other readers at `execve`
/// (`ARG_MAX`'s order of magnitude: the exec path caps the block far below).
const MAX_PUBLISHED_ARGS: u64 = 2 << 20;

/// Publish what `/proc/<pid>/*` shows of `own` for the readers of other tasks
/// (see `procfs::view`): called by the task itself when it is about to leave
/// the CPU (a sleep, a preemption, a stop), when it reads its own entries, and
/// for a new child.
///
/// Context: task, `PROCESS` held by the caller (`vfs` lock class); allocates
/// fallibly (`ENOMEM` leaves the previous view in place).
fn publish(process: &mut Process, own: &Owned, space: &mut UserSpace<'_>) -> Result<(), Errno> {
    let tgid = own.tgid.cast_signed();
    // The argument and environment bytes are copied when the layout changes
    // (an `execve`) and kept otherwise.
    let layout = (own.space.arg_start, own.space.env_end);
    let kept = process.vfs.fs.ns.proc.view(tgid).and_then(|view| {
        let mm = view.mm.as_ref()?;
        ((mm.arg_start, mm.env_end) == layout && !view.args().is_empty())
            .then(|| view.args.clone())
            .flatten()
    });
    let args = if kept.is_some() {
        kept
    } else {
        let len = layout.1.saturating_sub(layout.0).min(MAX_PUBLISHED_ARGS);
        let mut bytes = Vec::new();
        if len > 0 && layout.0 != 0 {
            let len = usize::try_from(len).map_err(|_| Errno::ENOMEM)?;
            bytes.try_reserve_exact(len).map_err(|_| Errno::ENOMEM)?;
            for _ in 0..len {
                let _ = bytes.push_within_capacity(0);
            }
            let missing = usercopy::copy_from_user(space, &mut bytes, layout.0);
            bytes.truncate(len - missing);
        }
        if bytes.is_empty() {
            None
        } else {
            Some(Arc::try_new(bytes).map_err(|_| Errno::ENOMEM)?)
        }
    };
    let rss = space.rss(own.space.vmas());
    let view = TaskView::collect(Collect {
        attrs: &own.attrs,
        fdt: &own.fdt,
        files: &process.vfs.files,
        mm: Some(&own.space),
        exe: Some(own.exe_file),
        rss,
        pgtables_bytes: space.table_bytes(),
        min_flt: own.stats.min_flt,
        maj_flt: own.stats.maj_flt,
        nvcsw: own.stats.nvcsw,
        nivcsw: own.stats.nivcsw,
        start_boottime_ns: own.stats.start_ns,
        flags: 0,
        args,
    })?;
    process.vfs.fs.ns.proc.publish(tgid, view)
}

/// [`publish`] for the running task, taking its state and `PROCESS`.
fn publish_current() {
    let mut local = current_local();
    let TaskLocal { tables, own } = &mut *local;
    let mut process = PROCESS.lock();
    let _ = publish(&mut process, own, &mut tables.user_space());
}

/// The machine's counters for the global files of /proc.
///
/// Context: task; takes `FRAMES` and `LOAD` (leaf locks) while `process` is held.
#[allow(clippy::too_many_lines)] // one straight list of the counters /proc shows
fn host_info(process: &Process, own: &Owned, machine: bool) -> Result<HostInfo, Errno> {
    let up = timer::ktime_get_boottime_ns();
    let now = timer::ktime_get_ns();
    let (total_pages, free_pages) = {
        let frames = services::FRAMES.lock();
        (frames.total() as u64, frames.available() as u64)
    };
    // `get_avenrun(loads, FIXED_1/200, 0)`-style: the sysinfo scale is
    // `<< (SI_LOAD_SHIFT - FSHIFT)` = `<< 5` of the FSHIFT fixed point.
    let loads = LOAD.lock().loads_at(
        jiffies_of(up),
        i64::try_from(ktask::nr_active()).unwrap_or(i64::MAX),
    );
    let avenrun = loads.map(|v| v >> 5);
    let mut cmdline = Vec::new();
    let line = services::boot().command_line();
    cmdline
        .try_reserve_exact(line.len())
        .map_err(|_| Errno::ENOMEM)?;
    for &byte in line {
        let _ = cmdline.push_within_capacity(byte);
    }
    // The CPU time of all tasks; the idle time is what is left of the uptime.
    let (mut user, mut system) = (0u64, 0u64);
    let (mut anon, mut mapped, mut tables_bytes) = (0u64, 0u64, 0u64);
    // Summed only for the global files (`ShowScope::Machine`).
    for id in process
        .tasks
        .processes()
        .take(if machine { usize::MAX } else { 0 })
    {
        let Some(task) = process.tasks.task(id) else {
            continue;
        };
        let (u, s) = match task.sched {
            Some(sched) if task.exit_state == task::tasklist::ExitState::Live => {
                ktask::cpu_account(sched).adjusted(now)
            }
            _ => (task.utime_ns, task.stime_ns),
        };
        user += u;
        system += s;
        if let Some(mm) = process
            .vfs
            .fs
            .ns
            .proc
            .view(process.tasks.task_tgid_vnr(id))
            .and_then(|view| view.mm.as_ref())
        {
            anon += mm.rss_anon;
            mapped += mm.rss_file + mm.rss_shmem;
            tables_bytes += mm.pgtables_bytes;
        }
    }
    let idle = up.saturating_sub(user + system);
    let mut irqs = Vec::new();
    irqs.try_reserve_exact(16).map_err(|_| Errno::ENOMEM)?;
    for irq in 0..16 {
        let _ = irqs.push_within_capacity(cpu::isa_irq_count(irq));
    }
    let mut chrdevs = Vec::new();
    chrdevs
        .try_reserve_exact(CHRDEVS.len())
        .map_err(|_| Errno::ENOMEM)?;
    for entry in CHRDEVS {
        let _ = chrdevs.push_within_capacity(entry);
    }
    let real = timer::ktime_get_real();
    Ok(HostInfo {
        uptime_ns: up,
        idle_ns: idle,
        total_pages,
        free_pages,
        avenrun,
        cmdline,
        nr_running: u64::try_from(ktask::nr_active()).unwrap_or(0),
        last_pid: process.tasks.last_pid(),
        forks: process.tasks.forks(),
        ctxt: ktask::context_switches(),
        boot_real_s: real.sec - i64::try_from(up / 1_000_000_000).unwrap_or(0),
        cpustat: [user, 0, system, idle, 0, 0, 0, 0, 0, 0],
        irqs,
        arch_irqs: cpu::arch_irq_stat(),
        softirqs: [0; 10],
        tty_pgrp: process.tty.ctrl.pgrp.map_or(0, |pgrp| pgrp.nr),
        shmem_pages: process.vfs.fs.tmpfs_pages(),
        kernel_stack_kb: u64::try_from(ktask::tasks_in_use()).unwrap_or(0) * 64,
        slab_kb: (crate::kalloc::requested_bytes() as u64) >> 10,
        anon_pages: anon,
        mapped_pages: mapped,
        pagetable_kb: tables_bytes >> 10,
        sched_state: ktask::state,
        cpu_time: |sched| ktask::cpu_account(sched).adjusted(timer::ktime_get_ns()),
        uts: [
            b"Linux",
            syscall::UTS_RELEASE,
            syscall::UTS_VERSION,
            b"(none)",
            b"(none)",
        ],
        cpu: cpu_facts(),
        chrdevs,
        threads_max: task::max_threads(total_pages),
        pid_max: 32768,
        max_map_count: u64::from(own.env.max_map_count),
        mmap_min_addr: 4096,
        overcommit_memory: 0,
        compile_by: b"linux-rs@build",
        compiler: COMPILER,
    })
}

/// The `LINUX_COMPILER` of /proc/version: the pinned toolchain.
const COMPILER: &[u8] =
    b"rustc 1.101.0-nightly (5c543b0b8c73c7b72bc8284ced4fb22ead15734d) LLVM 23.1.1";

/// The character devices this kernel serves, `(major, name)` as
/// /proc/devices lists them (`register_chrdev` names).
const CHRDEVS: [(u32, &str); 5] = [
    (1, "mem"),
    (4, "/dev/vc/0"),
    (4, "tty"),
    (4, "ttyS"),
    (5, "/dev/tty"),
];

/// The system-wide state a system call touches, taken on first use and
/// dropped before the task sleeps (see [`Process`]). Taking it again after a
/// sleep re-reads everything, as Linux's `wait_event` does.
#[derive(Default)]
struct Shared {
    guard: Option<ServiceGuard<'static, Process>>,
}

impl Shared {
    fn get(&mut self) -> &mut Process {
        self.guard.get_or_insert_with(|| PROCESS.lock())
    }
    fn release(&mut self) {
        self.guard = None;
    }
}

/// Syscall context: the task's own state (`own`, and the user-memory view of
/// its page tables), the shared state taken on demand, the entry registers
/// and the console.
struct Syscall<'a> {
    own: &'a mut Owned,
    space: UserSpace<'a>,
    shared: Shared,
    regs: &'a mut cpu::PtRegs,
    sink: ConsoleSink,
}

/// `handle_mm_fault` for one user address: the model's decision, and for a
/// page of a private file mapping (`NeedsFile`) `shmem_fault` + `do_cow_fault`:
/// a private frame holding the file page ([`Vfs::fault_page`]; `SIGBUS` past
/// `i_size`), mapped with the VMA's protection. `owner` is the faulting
/// task's mapping-pin key.
fn user_fault(
    mm: &mut Mm,
    env: &Env,
    vfs: &mut Vfs,
    owner: u32,
    space: &mut UserSpace<'_>,
    address: u64,
    error: u64,
) -> FaultOutcome {
    let outcome = mm.handle_user_fault(env, space, address, error);
    let FaultOutcome::NeedsFile { address, .. } = outcome else {
        return outcome;
    };
    let page = address & !(PAGE - 1);
    // The model only reports `NeedsFile` for an address inside a file VMA.
    let Some(vma) = mm.find_vma(page).copied() else {
        crate::log!(
            "FAIL mm file fault outside any VMA address={:#x}\n",
            address
        );
        crate::fail();
    };
    let Some(file) = vma.file else {
        crate::log!(
            "FAIL mm file fault in an anonymous VMA address={:#x}\n",
            address
        );
        crate::fail();
    };
    let mut bytes = [0u8; PAGE_BYTES];
    let pgoff = vma.pgoff + ((page - vma.start) >> 12);
    match vfs.fault_page(owner, file, pgoff, &mut bytes) {
        Err(FileFault::Bus) => FaultOutcome::Bus { address },
        Ok(()) => match space.install(page, mm::page_prot(vma.flags), &bytes) {
            Ok(()) => FaultOutcome::Handled,
            Err(mm::OutOfMemory) => FaultOutcome::Oom,
        },
    }
}

/// The user-memory view of the kernel: a kernel access to a user page that is
/// not resident takes the fault Linux would, `exc_page_fault` ->
/// `do_user_addr_fault` with the kernel-mode error code (no `X86_PF_USER`) on a
/// user address. A fault the model resolves is retried (once: it must now
/// succeed); any refusal is the exception-table fixup, i.e. a short copy and
/// `-EFAULT`, with no signal (`__bad_area_nosemaphore` only signals in user
/// mode; OOM, SIGBUS and the vsyscall page behave the same for a kernel-mode
/// access). No lock is taken here that the syscall does not already hold
/// (`PROCESS`, taken by [`Shared::get`] for the VFS): only `FRAMES` (a leaf)
/// below it.
///
/// It borrows the fields of the task's state the fault needs, so the signal
/// code (frame writes, `rt_sigreturn`, the signal syscalls) can hold it next to
/// the task list; [`Syscall`]'s own [`UserPages`] is the same view.
struct FaultPages<'a, 'b> {
    mm: &'a mut Mm,
    env: &'a Env,
    vfs: &'a mut Vfs,
    owner: u32,
    space: &'a mut UserSpace<'b>,
    /// `current->min_flt`: a fault the kernel itself took on the task's behalf counts too
    /// (`mm_account_fault`).
    faults: &'a mut u64,
}

/// The `State` view of a task's signal objects (`me` is in the task list for as
/// long as it runs).
fn current_signals(tasks: &mut Tasklist, me: TaskId) -> State<'_> {
    if let Some(state) = tasks.signal_state_as(me, true) {
        state
    } else {
        crate::log!("FAIL current task is not in the task list\n");
        crate::fail();
    }
}

impl<'a, 'b> FaultPages<'a, 'b> {
    fn of(
        process: &'a mut Process,
        own: &'a mut Owned,
        space: &'a mut UserSpace<'b>,
    ) -> (State<'a>, Self) {
        let owner = own.owner();
        (
            current_signals(&mut process.tasks, own.me),
            Self {
                mm: &mut own.space,
                env: &own.env,
                vfs: &mut process.vfs,
                owner,
                space,
                faults: &mut own.stats.min_flt,
            },
        )
    }

    /// `page` by value: the returned borrow lives as long as the view's.
    fn into_page(self, page: u64, write: bool) -> Option<&'a mut [u8; PAGE_BYTES]> {
        // Present-but-read-only (write) is `X86_PF_PROT`, an absent page is
        // not; the model's decision does not depend on it for a write.
        let error = if write { PF_WRITE } else { 0 };
        // The protection keys apply to the kernel's own accesses on the task's behalf
        // (`copy_from_user`/`copy_to_user`/`put_user`, the `XSAVE` into a signal frame; Documentation/
        // core-api/protection-keys.rst: "like with a read()"): the hardware reports a PK fault, and
        // `access_error` finds it before anything is populated, so it ends in the fixup (a short
        // copy, `-EFAULT`) whether or not the page is resident. All memory is key 0.
        if self.env.ospke && mm::pkru_denies_key0(error, fpu::read_pkru()) {
            return None;
        }
        if !self.space.resident(page, write) {
            match user_fault(
                self.mm, self.env, self.vfs, self.owner, self.space, page, error,
            ) {
                FaultOutcome::Handled => *self.faults += 1,
                _ => return None,
            }
        }
        self.space.page(page, write)
    }
}

impl UserPages for FaultPages<'_, '_> {
    fn page(&mut self, page: u64, write: bool) -> Option<&mut [u8; PAGE_BYTES]> {
        FaultPages {
            mm: &mut *self.mm,
            env: self.env,
            vfs: &mut *self.vfs,
            owner: self.owner,
            space: &mut *self.space,
            faults: &mut *self.faults,
        }
        .into_page(page, write)
    }
}

impl UserPages for Syscall<'_> {
    fn page(&mut self, page: u64, write: bool) -> Option<&mut [u8; PAGE_BYTES]> {
        let owner = self.own.owner();
        FaultPages {
            mm: &mut self.own.space,
            env: &self.own.env,
            vfs: &mut self.shared.get().vfs,
            owner,
            space: &mut self.space,
            faults: &mut self.own.stats.min_flt,
        }
        .into_page(page, write)
    }
}

/// Kernel-object leak check of the self-test builds (`-- forkleak`): the number
/// of live objects a fork/exit/wait round must leave unchanged, sampled at the
/// quiescent point of a `fork` entry (the previous child is gone, its stack slot
/// released) after the warm-up rounds, and again when init dies. The free-RAM
/// comparison of the init program sees only whole frames; this sees a leaked
/// file reference, inode pin, task slot or heap byte too.
#[cfg(feature = "qemu-self-test")]
mod leak {
    use super::{AtomicU64, Ordering, Process, ktask};
    use crate::services::IrqMutex;

    #[derive(Clone, Copy, PartialEq, Eq)]
    struct Snapshot {
        heap: usize,
        files: usize,
        file_refs: u64,
        pins: usize,
        root_refs: u32,
        slots: usize,
        threads: u32,
    }

    /// The fork whose entry state is the baseline: two warm-up rounds precede it.
    const BASELINE_FORK: u64 = 3;
    static FORKS: AtomicU64 = AtomicU64::new(0);
    static BASELINE: IrqMutex<Option<Snapshot>> = IrqMutex::new(None);

    fn sample(process: &Process) -> Snapshot {
        Snapshot {
            // The pid table grows with the highest pid number (until the cursor wraps).
            heap: crate::kalloc::requested_bytes() - process.tasks.pid_table_bytes(),
            files: process.vfs.files.open_count(),
            file_refs: process.vfs.files.total_refs(),
            pins: process.vfs.pin_count(),
            root_refs: process.vfs.fs.inode_refs(process.vfs.fs.root()),
            slots: ktask::tasks_in_use(),
            threads: process.tasks.nr_threads(),
        }
    }

    /// A fork is starting (`PROCESS` held by the caller).
    pub(super) fn at_fork(process: &Process) {
        if FORKS.fetch_add(1, Ordering::Relaxed) + 1 == BASELINE_FORK {
            *BASELINE.lock() = Some(sample(process));
        }
    }

    /// Init is dying: print how the objects moved since the baseline.
    pub(super) fn report(process: &Process) {
        let (Some(was), now) = (*BASELINE.lock(), sample(process)) else {
            return;
        };
        crate::log!(
            "CHECK fork-objects forks={} heap={}/{} files={}/{} file_refs={}/{} pins={}/{} root_refs={}/{} slots={}/{} threads={}/{}\n",
            FORKS.load(Ordering::Relaxed),
            was.heap,
            now.heap,
            was.files,
            now.files,
            was.file_refs,
            now.file_refs,
            was.pins,
            now.pins,
            was.root_refs,
            now.root_refs,
            was.slots,
            now.slots,
            was.threads,
            now.threads,
        );
    }
}

impl Syscall<'_> {
    /// `kernel_clone` / `copy_process` / `wake_up_new_task` for a plain
    /// process copy, in the order of `copy_process` (the argument checks and
    /// the pending-signal restart are the syscall layer's).
    ///
    /// Everything the child needs is built first, each step undone by the
    /// ones after it on failure; the child becomes visible to the rest of the
    /// system (the task list) only when nothing else can fail, and runnable
    /// last. The address space is copied eagerly (shortcut S2 of the process
    /// lane: copy-on-write is the upgrade).
    ///
    /// `CLONE_VM | CLONE_VFORK` (`vfork`): the child gets no copy but the parent's own address
    /// space (`copy_mm` shares it, `mm->mm_users`): its tree and VMA set move to the child,
    /// the parent keeps an empty tree and VMA set as placeholders, and `wait_for_vfork_done`
    /// puts the parent to sleep until the child's `execve` or exit hands them back. The two
    /// never run at once, which is the whole sharing a `vfork` child may rely on.
    ///
    /// Context: task, IF=0, on the parent's kernel stack; takes `PROCESS`
    /// (-> heap, -> `FRAMES` through the page-table copy).
    #[allow(
        clippy::too_many_lines,
        reason = "one fork, in the order of copy_process, each failure undoing the steps before it"
    )]
    fn fork(&mut self, request: &ForkRequest) -> Result<i32, Errno> {
        let parent = self.own.me;
        let params = ForkParams::of(&self.own.attrs, request);
        #[cfg(feature = "qemu-self-test")]
        leak::at_fork(self.shared.get());
        // dup_task_struct: the child's state block, so that no later step
        // loses what it holds to an allocation failure. It comes first, as in
        // Linux (kernel/fork.c:2020): ENOMEM beats the limits' EAGAIN.
        let block = Box::<TaskLocal>::try_new_uninit().map_err(|_| Errno::ENOMEM)?;
        // ... and the child's FPU state, a copy of ours (`fpu_clone`; Linux's lives inside the
        // task structure, so it fails there too).
        let xstate = fpu::XBuf::from_live().map_err(|_| Errno::ENOMEM)?;
        // copy_process: RLIMIT_NPROC and max_threads (fork.c:2059, 2072).
        self.shared.get().tasks.fork_allowed(parent, params)?;
        // copy_mm: the VMA model, then the pages; or, for a vfork, only the placeholder tree.
        let memory = if request.share_vm {
            let placeholder = self.space.empty_tree().map_err(|error| {
                if matches!(error, paging::Error::Memory(_)) {
                    Errno::ENOMEM
                } else {
                    crate::log!("FAIL vfork placeholder tree error={:?}\n", error);
                    crate::fail()
                }
            })?;
            ChildMemory::Lend { placeholder }
        } else {
            let space = self.own.space.dup(&self.own.env)?;
            let tables = self.space.fork_tables().map_err(|error| {
                if matches!(error, paging::Error::Memory(_)) {
                    Errno::ENOMEM
                } else {
                    crate::log!("FAIL fork page tables error={:?}\n", error);
                    crate::fail()
                }
            });
            match tables {
                Ok(tables) => ChildMemory::Copy { space, tables },
                Err(errno) => {
                    drop(space);
                    return Err(errno);
                }
            }
        };
        // sched_fork + copy_thread: slot, kernel stack, the child's registers
        // (`ax` = 0, the requested stack), FP and segment state, its CR3.
        let mut regs = *self.regs;
        regs.ax = 0;
        if request.child_sp != 0 {
            regs.sp = request.child_sp;
        }
        let root = match &memory {
            ChildMemory::Copy { tables, .. } => tables.root_address(),
            ChildMemory::Lend { .. } => self.space.root_address(),
        };
        let Ok(sched) = ktask::prepare_fork(regs, root, xstate) else {
            memory.discard();
            return Err(Errno::EAGAIN);
        };
        let child_owner = if request.share_vm {
            self.own.pin_owner
        } else {
            next_pin_owner()
        };
        // copy_files / copy_fs / the mapping and executable references.
        let process = self.shared.get();
        let fdt = match process.vfs.dup_fd(&self.own.fdt) {
            Ok(fdt) => fdt,
            Err(errno) => {
                ktask::cancel_new_task(sched);
                memory.discard();
                return Err(errno);
            }
        };
        if !request.share_vm
            && let Err(errno) = process.vfs.pin_clone(self.own.owner(), child_owner)
        {
            let mut fdt = fdt;
            process.vfs.close_files(&mut fdt);
            ktask::cancel_new_task(sched);
            memory.discard();
            return Err(errno);
        }
        let fs = process.vfs.dup_fs(&self.own.attrs.fs);
        process.vfs.files.dup(self.own.exe_file);
        // The point of no failure but the task list's: publish the child.
        let child = match process.tasks.fork(parent, params) {
            Ok(child) => child,
            Err(errno) => {
                let mut fdt = fdt;
                process.vfs.close_files(&mut fdt);
                process.vfs.put_fs(&fs);
                if !request.share_vm {
                    process.vfs.unpin_all(child_owner);
                }
                process.vfs.fput(self.own.exe_file);
                ktask::cancel_new_task(sched);
                memory.discard();
                return Err(errno);
            }
        };
        let pid = process.tasks.task_pid_vnr(child);
        process.tasks.set_sched(child, sched);
        let mut attrs = self.own.attrs;
        attrs.fs = fs;
        // copy_process: `clear_child_tid` per CLONE_CHILD_CLEARTID, no robust list.
        attrs.clear_child_tid = request.clear_child_tid;
        attrs.robust_list = 0;
        let tid = pid.cast_unsigned();
        let (mut tables, space) = match memory {
            ChildMemory::Copy { space, tables } => (tables, space),
            ChildMemory::Lend { placeholder } => {
                // The child takes the real tree and VMA set, the parent the placeholders.
                let tables = self.space.replace_tables(placeholder);
                let space = core::mem::replace(&mut self.own.space, Mm::new(&self.own.env));
                self.own.lent_out = true;
                (tables, space)
            }
        };
        let own = Owned {
            me: child,
            sched,
            tgid: tid,
            tid,
            attrs,
            restart: RestartBlock::NONE,
            space,
            env: self.own.env,
            exe_file: self.own.exe_file,
            exec: self.own.exec,
            fdt,
            pin_owner: child_owner,
            vfork_parent: request.vfork.then_some(Lender {
                sched: self.own.sched,
                lent: request.share_vm,
            }),
            pending_mm: None,
            lent_out: false,
            stats: Stats::started(),
        };
        // The child is visible to /proc from now on: its first view, taken
        // from the state it was just given (the parent may read it before the
        // child ever runs). A refusal leaves the child without a view until
        // it first leaves the CPU; the files of /proc then answer `ESRCH`.
        let _ = publish(process, &own, &mut tables.user_space());
        let local = Box::write(block, TaskLocal { tables, own });
        install_local(sched.index(), local);
        // wake_up_new_task: the child is on the run queue; it first runs when
        // the parent next gives up the CPU.
        ktask::wake_up_new_task(sched);
        if request.vfork {
            self.wait_for_vfork_done();
        }
        Ok(pid)
    }

    /// `wait_for_vfork_done`: sleep until the child has execed or exited (`TASK_KILLABLE`: only a
    /// fatal signal ends the wait early), then take back the address space it borrowed. A parent
    /// that stops waiting because it is being killed leaves the borrowed address space to the
    /// child, who frees it when it lets go ([`complete_vfork`]).
    fn wait_for_vfork_done(&mut self) {
        let me = self.own.sched;
        loop {
            let done = VFORK_DONE.lock()[me.index()].take();
            if let Some(Done { lent }) = done {
                if let Some(Lent { tables, space }) = lent {
                    let placeholder = self.space.replace_tables(tables);
                    let placeholder_space = core::mem::replace(&mut self.own.space, space);
                    self.own.lent_out = false;
                    destroy_tables(placeholder);
                    drop(placeholder_space);
                }
                return;
            }
            // An `ITIMER_REAL` that expired is `SIGALRM` sent (possibly fatal) before the next
            // sleep; left stale, `wait` returns at once and the child never runs.
            let _ = signal::wait::signal_pending_synced(self);
            if signal::Task::state(self).fatal_signal_pending() {
                return;
            }
            signal::Task::wait(self, vfork_done_key(me), None);
        }
    }
}

/// The address space a forked child starts with.
enum ChildMemory {
    /// `dup_mmap`: its own copy.
    Copy { space: Mm, tables: Tables },
    /// `CLONE_VM | CLONE_VFORK`: the parent's, moved in once the fork cannot fail any more;
    /// meanwhile the parent's empty replacement.
    Lend { placeholder: Tables },
}

impl ChildMemory {
    /// The fork failed: free what was made.
    fn discard(self) {
        match self {
            Self::Copy { tables, .. } => destroy_tables(tables),
            Self::Lend { placeholder } => destroy_tables(placeholder),
        }
    }
}

/// Free a page-table tree that no task owns (a failed fork): the frame
/// allocator is a leaf below everything the caller holds.
fn destroy_tables(tables: Tables) {
    tables.destroy_user(&mut services::FRAMES.lock());
}

impl Context for Syscall<'_> {
    fn tty_parts(&mut self) -> syscall::TtyParts<'_> {
        let me = self.own.me;
        let process = self.shared.get();
        let Process {
            tasks, wake, tty, ..
        } = process;
        // The flip buffer's flush: input that arrived since the last look.
        crate::ttyin::flush(
            tty,
            &mut TtyHost {
                tasks,
                wake,
                sink: &mut self.sink,
            },
        );
        syscall::TtyParts {
            tty,
            tasks: Tasks {
                list: tasks,
                current: me,
                wake,
            },
            console: &mut self.sink,
        }
    }
    fn tgid(&self) -> u32 {
        self.own.tgid
    }
    fn tid(&self) -> u32 {
        self.own.tid
    }
    fn tasks(&mut self) -> Tasks<'_> {
        let process = self.shared.get();
        Tasks {
            list: &mut process.tasks,
            current: self.own.me,
            wake: &mut process.wake,
        }
    }
    fn replace_exe_file(&mut self, file: FileId) -> Option<FileId> {
        self.own.exec = u64::from(file.index());
        Some(core::mem::replace(&mut self.own.exe_file, file))
    }
    fn exec_aux(&mut self) -> ExecAux {
        ExecAux {
            hwcap: __cpuid(1).edx,
            random: random_bytes(),
        }
    }
    fn hw_random(&mut self) -> Option<u64> {
        hw_random_u64()
    }
    fn start_thread(&mut self, ip: u64, sp: u64) {
        // flush_thread: the FPU returns to its initial state, TLS bases to 0.
        signal::Cpu::fpu_reset(&mut fpu::UserCpu::new());
        cpu::set_user_fs_base(0);
        cpu::set_user_gs_base(0);
        // start_thread: the same initial user state `enter_user` builds (every
        // general register zero, `ELF_PLAT_INIT`); `orig_ax` keeps the number
        // of the system call that is returning.
        *self.regs = cpu::PtRegs {
            ip,
            sp,
            cs: signal::USER_CS,
            ss: signal::USER_DS,
            flags: 0x202,
            orig_ax: self.regs.orig_ax,
            ..cpu::PtRegs::default()
        };
    }
    fn attrs(&mut self) -> &mut Attributes {
        &mut self.own.attrs
    }
    fn fs_base(&self) -> u64 {
        cpu::user_fs_base()
    }
    fn set_fs_base(&mut self, base: u64) {
        cpu::set_user_fs_base(base);
    }
    fn gs_base(&self) -> u64 {
        cpu::user_gs_base()
    }
    fn set_gs_base(&mut self, base: u64) {
        cpu::set_user_gs_base(base);
    }
    fn cpuid_fault_absent(&self) -> bool {
        cpuid_fault_absent()
    }
    fn xstate(&self) -> kernel::xstate::Config {
        *fpu::config()
    }
    fn machine(&self) -> Machine {
        // `ktime_get_boottime_ns` is the boot clock `do_sysinfo` reads.
        let uptime_ns = crate::timer::ktime_get_boottime_ns();
        // Lock order: `FRAMES` and `LOAD` are leaves. The load averages are
        // replayed from the start state to the boot clock.
        let frames = services::FRAMES.lock();
        let loads = LOAD.lock().loads_at(
            jiffies_of(uptime_ns),
            i64::try_from(ktask::nr_active()).unwrap_or(i64::MAX),
        );
        Machine {
            uptime_ns,
            total_pages: frames.total() as u64,
            free_pages: frames.available() as u64,
            loads,
        }
    }
    fn address_space(&mut self) -> AddressSpace<'_> {
        AddressSpace {
            mm: &mut self.own.space,
            env: &self.own.env,
            pages: &mut self.space,
        }
    }
    fn files(&mut self) -> Files<'_> {
        let owner = self.own.owner();
        Files {
            vfs: &mut self.shared.get().vfs,
            fdt: &mut self.own.fdt,
            fs: &mut self.own.attrs.fs,
            owner,
        }
    }
    fn copy_process(&mut self, request: &ForkRequest) -> Result<i32, Errno> {
        self.fork(request)
    }
    fn exec_prepare_mm(&mut self) -> Result<(), Errno> {
        if !self.own.vfork_parent.is_some_and(|lender| lender.lent) || self.own.pending_mm.is_some()
        {
            return Ok(());
        }
        // bprm_mm_init: the new mm, its tree and VMA set.
        let tables = self.space.empty_tree().map_err(|error| {
            if matches!(error, paging::Error::Memory(_)) {
                Errno::ENOMEM
            } else {
                crate::log!("FAIL exec tree error={:?}\n", error);
                crate::fail()
            }
        })?;
        self.own.pending_mm = Some((tables, Mm::new(&self.own.env)));
        Ok(())
    }
    fn exec_switch_mm(&mut self) {
        // exec_mmap -> exec_mm_release -> mm_release: `complete_vfork_done`.
        let Some(lender) = self.own.vfork_parent.take() else {
            return;
        };
        let lent = if lender.lent {
            let Some((tables, space)) = self.own.pending_mm.take() else {
                crate::log!("FAIL vfork child's exec without its new address space\n");
                crate::fail();
            };
            let root = tables.root_address();
            let borrowed_tables = self.space.replace_tables(tables);
            let borrowed_space = core::mem::replace(&mut self.own.space, space);
            // SAFETY: `root` is the live tree `empty_tree` made from this task's own, so its
            // kernel half is the published one and maps this code, the stack and the heap; the
            // BSP runs with IF=0 inside a system call; no PCID or global translations exist.
            unsafe { cpu::activate_tables(root) };
            ktask::set_current_cr3(root);
            Some(Lent {
                tables: borrowed_tables,
                space: borrowed_space,
            })
        } else {
            None
        };
        let key = self.own.pin_owner;
        if lender.lent {
            self.own.pin_owner = next_pin_owner();
        }
        complete_vfork(lender, key, lent, &mut self.shared.get().vfs);
    }
    fn sync_proc(&mut self) {
        let process = self.shared.get();
        // Nothing reads the mirror or a view before a procfs is mounted.
        if !process.vfs.fs.ns.has_proc() {
            return;
        }
        // A refusal keeps the previous mirror: lookups of the newest pids may
        // miss until memory is available.
        let _ = process.vfs.sync_proc(&process.tasks);
        // A walk or a directory read through the caller's own `/proc/<pid>` sees its published
        // view: bring that up to date when a descriptor, the root, the working directory or the
        // executable changed since it was taken. Only those parts are rebuilt: the address space
        // is published when a file of `/proc` is read, and when the task leaves the CPU.
        let tgid = self.own.tgid.cast_signed();
        let (fs, exe, fd_gen) = (
            self.own.attrs.fs,
            self.own.exe_file,
            self.own.fdt.generation(),
        );
        let stale = process.vfs.fs.ns.proc.view(tgid).is_none_or(|v| {
            v.fd_gen != fd_gen
                || v.attrs.fs.root != fs.root
                || v.attrs.fs.pwd != fs.pwd
                || v.exe.map(|e| e.file) != Some(exe)
        });
        if !stale {
            return;
        }
        if process.vfs.fs.ns.proc.view(tgid).is_none() {
            let _ = publish(process, self.own, &mut self.space);
            return;
        }
        let vfs = &mut process.vfs;
        let files = &vfs.files;
        if let Some(view) = vfs.fs.ns.proc.view_mut(tgid) {
            let _ = view.refresh_files(&self.own.attrs, &self.own.fdt, files, exe);
        }
    }
    fn with_show<R>(
        &mut self,
        scope: ShowScope,
        f: impl FnOnce(&Show<'_>) -> R,
    ) -> Result<R, Errno> {
        // The caller's own view is current before anyone reads it: when its
        // own files are shown, or every task's counters are summed.
        let mine = self.own.tgid.cast_signed();
        if matches!(scope, ShowScope::Machine) || scope == ShowScope::Pid(mine) {
            publish(self.shared.get(), self.own, &mut self.space)?;
        }
        let process = self.shared.get();
        let host = host_info(process, self.own, scope == ShowScope::Machine)?;
        let caller = Caller {
            tgid: self.own.tgid.cast_signed(),
            cred: vfs::Cred::of_task(&self.own.attrs.cred),
        };
        let show = Show {
            vfs: &process.vfs,
            tasks: &process.tasks,
            host: &host,
            caller,
            root: self.own.attrs.fs.root,
        };
        Ok(f(&show))
    }
    fn mm_args(&mut self) -> Option<(u64, u64, u64, u64)> {
        let mm = &self.own.space;
        Some((mm.arg_start, mm.arg_end, mm.env_start, mm.env_end))
    }
}

impl Clocks for Syscall<'_> {
    fn clock_state(&self) -> ClockState {
        timer::clock_state()
    }
    fn set_realtime(&mut self, offset: i64, real_ns: i64) {
        // IF is clear for the whole syscall (SYSCALL_MASK), the clock's writer rule.
        timer::set_realtime(offset, real_ns);
    }
    fn set_restart_block(&mut self, block: RestartBlock) {
        self.own.restart = block;
    }
    fn restart_block(&self) -> RestartBlock {
        self.own.restart
    }
    fn cpu_sample(&self) -> CpuSample {
        ktask::cpu_account(self.own.sched).sample(timer::ktime_get_ns())
    }
    fn cpu_adjusted(&mut self) -> (u64, u64) {
        ktask::cpu_account(self.own.sched).adjusted(timer::ktime_get_ns())
    }
    fn sleep_until(&mut self, deadline_ns: u64) -> Option<u64> {
        // `do_nanosleep`: asleep until the deadline or a pending signal.
        signal::wait::sleep_until(self, deadline_ns)
    }
    // shortcut: init is root with every capability; credentials come with the
    // ids/capability work, which replaces these two with `capable(...)`.
    fn capable_sys_time(&self) -> bool {
        true
    }
    fn capable_wake_alarm(&self) -> bool {
        true
    }
    fn alarm_rtc(&self) -> bool {
        timer::rtc_present()
    }
}

impl<'a> signal::Task for Syscall<'a> {
    type Pages<'b>
        = FaultPages<'b, 'a>
    where
        Self: 'b;
    fn state(&mut self) -> State<'_> {
        current_signals(&mut self.shared.get().tasks, self.own.me)
    }
    fn parts(&mut self) -> (State<'_>, FaultPages<'_, 'a>) {
        FaultPages::of(self.shared.get(), &mut *self.own, &mut self.space)
    }
    fn now_ns(&self) -> u64 {
        timer::ktime_get_ns()
    }
    fn wait(&mut self, key: WaitKey, deadline_ns: Option<u64>) {
        // The interval timer is a wake-up source of every sleep: it rides on the
        // task's timed wake-up (the queue holds one entry per task), and the
        // woken loop's `sync_timers` turns the expiry into `SIGALRM`.
        let wake_at = [deadline_ns, self.state().sig.itimer.next_event()]
            .into_iter()
            .flatten()
            .min();
        // What this call changed in a pipe may be what the sleepers wait for.
        if let Some(process) = self.shared.guard.as_mut() {
            wake_sleepers(process);
        }
        // Other tasks run while this one sleeps: what /proc shows of it is
        // published now, since only the task itself can see its state.
        self.own.stats.nvcsw += 1;
        let _ = publish(self.shared.get(), self.own, &mut self.space);
        // No lock is held while the task is off the CPU: another task runs
        // system calls meanwhile. The time until it is chosen again is not
        // the task's (the switch marks it off the CPU).
        self.shared.release();
        ktask::sleep_current(key, wake_at);
    }
    fn user_sp(&self) -> u64 {
        self.regs.sp
    }
    fn rt_sigreturn(&mut self) -> Sigreturn {
        let (mut state, mut pages) =
            FaultPages::of(self.shared.get(), &mut *self.own, &mut self.space);
        let result = signal::frame::rt_sigreturn(
            &mut state,
            self.regs,
            &mut pages,
            &mut fpu::UserCpu::new(),
        );
        // `restore_sigcontext`'s first statement: a pending restarted system
        // call now returns -EINTR; a frame refused before it resets nothing.
        if result.reached_sigcontext {
            self.own.restart = RestartBlock::NONE;
        }
        if result.bad_frame {
            // `signal_fault`: printed before the SIGSEGV is forced; `regs` are
            // whatever the failed `restore_sigcontext` left, as in Linux.
            let process = self.shared.get();
            if printk_ratelimit(process, self.own, "signal_fault") {
                let line = BadFrame {
                    pid: self.own.tid.cast_signed(),
                    ip: self.regs.ip,
                    sp: self.regs.sp,
                    orig_ax: self.regs.orig_ax,
                    region: region_of(process, self.own, self.regs.ip),
                };
                crate::log!("{}\n", line);
            }
        }
        result
    }
}

/// The UART of the console tty: the same sinks as `log!`.
pub(crate) struct ConsoleSink;
impl Console for ConsoleSink {
    fn write(&mut self, bytes: &[u8]) {
        console::write_bytes(bytes);
    }
}

/// The pieces of a task's state; the box itself is freed on return (this
/// function returns, `do_exit` does not: a box left to its scope would leak).
fn into_parts(boxed: Box<TaskLocal>) -> (Tables, Owned) {
    let TaskLocal { tables, own } = *boxed;
    (tables, own)
}

/// `exit_mm`, the address-space half of [`do_exit`]: `tables` is the task's tree as it leaves
/// its slot (a placeholder while `own.lent_out`).
fn exit_mm(mut tables: Tables, own: &mut Owned, vfs: &mut Vfs) {
    let owner = own.owner();
    // exit_mm: a `vfork` child that never execed gives the address space it borrowed back
    // (`mm_release`); everything else frees its own, and a vfork child's wake-up of its parent
    // follows. A fresh address space made for an `execve` that did not happen goes too.
    let borrowed = own.vfork_parent.take();
    if let Some((fresh, _)) = own.pending_mm.take() {
        destroy_tables(fresh);
    }
    // This task's own `vfork` child may have finished while the task was on its way out (a fatal
    // signal ends the wait early): the address space it lent is back, take it.
    if own.lent_out {
        let back = VFORK_DONE.lock()[own.sched.index()].take();
        if let Some(Done {
            lent: Some(Lent {
                tables: real,
                space,
            }),
        }) = back
        {
            destroy_tables(core::mem::replace(&mut tables, real));
            drop(core::mem::replace(&mut own.space, space));
            own.lent_out = false;
        }
    }
    match borrowed {
        // Its own `vfork` child still works in the address space this task borrowed: what is
        // left here are placeholders. The borrowed space cannot go back yet; the child's
        // completion forwards it to the lender, who keeps sleeping until then.
        Some(lender) if lender.lent && own.lent_out => {
            destroy_tables(tables);
            VFORK_FORWARD.lock()[own.sched.index()] = Some(lender);
        }
        Some(lender) if lender.lent => {
            let space = core::mem::replace(&mut own.space, Mm::new(&own.env));
            complete_vfork(lender, owner, Some(Lent { tables, space }), vfs);
        }
        other => {
            destroy_tables(tables);
            // The mappings' pins go with the address space, unless a vfork child still has it.
            if !own.lent_out {
                vfs.unpin_all(owner);
            }
            if let Some(lender) = other {
                complete_vfork(lender, owner, None, vfs);
            }
        }
    }
}

/// `do_exit` of the calling task: `exit` (`group` false) or `do_group_exit`
/// (`exit_group`, a fatal signal). The last thread of global init panics
/// (`init_died`); any other task releases its address space, descriptors and
/// working directory, tells its parent, hands its children to init and leaves
/// the CPU for good (`do_task_dead`).
///
/// Context: task, IF=0, no lock held, on the task's own kernel stack.
fn do_exit(code: u32, group: bool, signaled: bool) -> ! {
    let slot = ktask::current().index();
    let me = current_local().own.me;
    let mut shared = PROCESS.lock();
    let code = if group {
        shared.tasks.do_group_exit(me, code)
    } else {
        code
    };
    match shared.tasks.exit_prepare(me, code, signaled) {
        ExitPrep::InitDied { exitcode } => {
            #[cfg(feature = "qemu-self-test")]
            leak::report(&shared);
            drop(shared);
            init_died(exitcode)
        }
        ExitPrep::Proceed { .. } => {}
    }
    drop(shared);
    // The task state leaves its slot: nothing can reach it after this.
    let Some(boxed) = take_local(slot) else {
        crate::log!("FAIL exiting task has no state slot={}\n", slot);
        crate::fail();
    };
    let (tables, mut own) = into_parts(boxed);
    // exit_mm: CR3 moves to the kernel tree before the user tree is freed.
    let kernel = KERNEL_ROOT.load(Ordering::Acquire);
    // SAFETY: `kernel` is the root of the kernel-only tree kept in
    // `services::TABLES` from `start` on (never freed); IF=0 on the BSP; the
    // kernel half it maps is the published one, so this code, the stack and
    // the heap stay mapped; no PCID or global translations exist.
    unsafe { cpu::activate_tables(kernel) };
    ktask::set_current_cr3(kernel);
    let mut shared = PROCESS.lock();
    let owner = own.owner();
    exit_mm(tables, &mut own, &mut shared.vfs);
    // exit_files / exit_fs: the executable's reference, every descriptor, the root and working
    // directory.
    shared.vfs.fput(own.exe_file);
    shared.vfs.close_files(&mut own.fdt);
    shared.vfs.put_fs(&own.attrs.fs);
    // The address space, descriptors and filesystem context are gone for /proc.
    shared.vfs.fs.ns.proc.exit(own.tgid.cast_signed());
    // `disassociate_ctty(1)` of a session leader (after `exit_files`, before
    // `exit_notify`), and the tty's last close if this exit was it.
    {
        let Process {
            tasks,
            wake,
            vfs,
            tty,
            ..
        } = &mut *shared;
        syscall::tty::housekeeping(vfs, tty, tasks);
        let console_open = vfs.tty_files().1 > 0;
        let hung = kernel::tty::jobctl::disassociate_ctty(
            tty,
            tasks,
            own.me,
            wake,
            &mut crate::ttyin::Wire(&mut ConsoleSink),
            true,
            console_open,
        );
        if hung {
            vfs.tty_hangup_files();
        }
    }
    // An end of a pipe closed with the last descriptor wakes the other side.
    wake_sleepers(&mut shared);
    // The task's CPU time is what its parent's wait reports (cputime_adjust).
    let (utime, stime) = ktask::cpu_account(own.sched).adjusted(timer::ktime_get_ns());
    if let Some(task) = shared.tasks.task_mut(own.me) {
        task.utime_ns = utime;
        task.stime_ns = stime;
    }
    // exit_notify: reparent the children, SIGCHLD to the parent, auto-reap.
    let Process { tasks, wake, .. } = &mut *shared;
    if tasks.exit_notify(own.me, wake).is_err() {
        crate::log!("FAIL exit_notify refused a task that was exiting\n");
        crate::fail();
    }
    drop(shared);
    // A parent killed while its vfork child waited has an address space coming back that no
    // one will take: free it (the child frees it itself when the parent is already gone).
    let mine = own.sched.index();
    let orphan = VFORK_DONE.lock()[mine].take();
    if let Some(Done {
        lent: Some(Lent { tables, space }),
    }) = orphan
    {
        destroy_tables(tables);
        drop(space);
        PROCESS.lock().vfs.unpin_all(owner);
    }
    drop(own);
    // do_task_dead: the next task releases this one's slot and stack.
    ktask::exit_current()
}

/// `kernel/exit.c`: init exiting for any reason panics. In a `qemu-self-test`
/// build the result mirrors the exit code; the default build halts.
///
/// The bare-metal suite deviates deliberately (test profile only, decision
/// A21): Linux's panic line is still printed for the record, but the death
/// only ends the group's run and the next group starts on a fresh rootfs.
#[cfg(feature = "baremetal-suite")]
fn init_died(code: u32) -> ! {
    crate::log!("{}\n", InitDeath(code));
    crate::baremetal::init_exited(code)
}

#[cfg(not(feature = "baremetal-suite"))]
fn init_died(code: u32) -> ! {
    #[cfg(feature = "qemu-self-test")]
    if code == 0 {
        crate::log!(
            "CHECK user-faults ok handled={}\n",
            USER_FAULTS_HANDLED.load(core::sync::atomic::Ordering::Relaxed)
        );
        ktask::selftest::preempt_report();
        ktask::selftest::stack_report();
    }
    crate::log!("{}\n", InitDeath(code));
    #[cfg(feature = "qemu-self-test")]
    {
        if code == 0 {
            crate::log!("RESULT success\n");
            cpu::exit(true);
        }
        crate::log!("FAIL init exitcode={:#010x}\n", code);
        cpu::exit(false);
    }
    #[cfg(not(feature = "qemu-self-test"))]
    cpu::halt()
}

/// Called by `syscall_entry` with the saved registers; writes the result into
/// `regs.ax`, then runs the exit-to-user work (pending signals). Interrupts are
/// off and the CPU is on the running task's kernel stack.
pub extern "C" fn syscall(regs: &mut cpu::PtRegs) {
    #[cfg(feature = "qemu-self-test")]
    let entry = ktask::selftest::entry_begin();
    let args = [regs.di, regs.si, regs.dx, regs.r10, regs.r8, regs.r9];
    let number = regs.orig_ax;
    let outcome = {
        let mut local = current_local();
        let TaskLocal { tables, own } = &mut *local;
        let mut context = Syscall {
            space: tables.user_space(),
            own,
            shared: Shared::default(),
            regs: &mut *regs,
            sink: ConsoleSink,
        };
        let outcome = syscall::dispatch(&mut context, number, args);
        if let Some(process) = context.shared.guard.as_mut() {
            wake_sleepers(process);
        }
        outcome
    };
    match outcome {
        Outcome::Return(value) => regs.ax = value.cast_unsigned(),
        Outcome::Exit { code, group } => do_exit(code, group, false),
        Outcome::Unimplemented(number) => {
            crate::log!("FAIL syscall unimplemented nr={}\n", number);
            crate::fail();
        }
    }
    exit_to_user(regs);
    #[cfg(feature = "qemu-self-test")]
    ktask::selftest::entry_end(entry, Some(number), 0);
}

/// `exit_to_user_mode_loop` + `arch_do_signal_or_restart`: before every return
/// to ring 3 (syscall, exception or interrupt from CPL3) bring the timers up
/// to date, deliver pending signals (a handler entry or `rt_sigreturn` has
/// rewritten `regs`, which `iretq` then installs: no `sysret` path exists) and
/// arm the clockevent for the interval timer.
///
/// A frame the CPU refuses to `iretq` to (a hostile `rt_sigreturn` frame or
/// handler address) is not predicted here: the refused `iretq` faults at
/// `cpu::iret_site` and `cpu::fixup_bad_iret` turns that into a user exception
/// (Linux's `.Lerror_bad_iret`), which comes back through this function.
///
/// Context: interrupts masked, task context of a user task; takes `PROCESS`
/// (the shared lock order). A fatal signal never returns: it ends the task
/// ([`do_exit`]), and init's death panics, as Linux's `do_exit` does for pid 1.
pub fn exit_to_user(regs: &mut cpu::PtRegs) {
    // A job-control stop ended: `get_signal` carries on in the same call after
    // `schedule()` returns (`goto relock`), so the restart rules of
    // `arch_do_signal_or_restart` still run for a system call interrupted before
    // the stop, though no signal is pending any more.
    let mut after_stop = false;
    loop {
        // `exit_to_user_mode_loop`: `TIF_NEED_RESCHED` first; this task continues,
        // with everything re-examined below, when it is chosen again. What
        // /proc shows of it is published before it leaves the CPU.
        if ktask::resched_wanted() {
            publish_current();
        }
        let switches = ktask::context_switches();
        ktask::preempt_user(regs.orig_ax == u64::MAX);
        if ktask::context_switches() != switches {
            current_local().own.stats.nivcsw += 1;
        }
        let mut local = current_local();
        let TaskLocal { tables, own } = &mut *local;
        let mut process = PROCESS.lock();
        // `get_signal`'s `SIGNAL_CLD_MASK` step: a task that woke from a stop
        // owes its parent the continue notification.
        {
            let Process { tasks, wake, .. } = &mut *process;
            tasks.notify_job_control(own.me, wake);
        }
        // Nothing to expire or dequeue: skip the clock read (`now_ns` is only
        // used when a pending SIGALRM leaves the queue).
        let pending = {
            let mut state = current_signals(&mut process.tasks, own.me);
            if state.sig.itimer.next_event().is_some() || state.signal_pending() {
                state.sync_timers(timer::ktime_get_ns());
            }
            state.signal_pending()
        } || core::mem::take(&mut after_stop);
        if pending {
            let outcome = {
                let mut space = tables.user_space();
                let (mut state, mut pages) = FaultPages::of(&mut process, own, &mut space);
                deliver::handle_pending_signals(
                    &mut state,
                    regs,
                    &mut pages,
                    &mut fpu::UserCpu::new(),
                )
            };
            match outcome {
                // `handle_pending_signals` loops while a forced SIGSEGV is pending.
                SignalOutcome::Resume | SignalOutcome::Handled | SignalOutcome::FrameFailed => {
                    #[cfg(feature = "qemu-self-test")]
                    if matches!(outcome, SignalOutcome::Handled) {
                        ktask::selftest::note_signal_frame();
                    }
                }
                SignalOutcome::Exit { exit_code, .. } => {
                    drop(process);
                    drop(local);
                    // get_signal: PF_SIGNALED, then do_group_exit(signr).
                    do_exit(exit_code, true, true);
                }
                SignalOutcome::Stop(sig) => {
                    // The default action of a stop signal. "The job control
                    // signals do nothing in an orphaned pgrp, but SIGSTOP always
                    // works": the dequeued signal is dropped (`goto relock`).
                    if sig != SIGSTOP && process.tasks.is_pgrp_orphaned(own.me) {
                        after_stop = true;
                        continue;
                    }
                    let me = own.me;
                    let Process { tasks, wake, .. } = &mut *process;
                    if let StopPlan::Stop { fatal } = tasks.signal_stop(me, sig, wake) {
                        let _ = publish(&mut process, own, &mut tables.user_space());
                        // `set_special_state(TASK_STOPPED)` and `schedule()`: no
                        // guard is held while the task is off the CPU, and a
                        // fatal signal already pending keeps it running (it
                        // dies in the next pass). `SIGCONT` or `SIGKILL` wakes
                        // it; the next pass is the `relock` that tells the
                        // parent about the continue.
                        drop(process);
                        drop(local);
                        if !fatal {
                            ktask::stop_current();
                        }
                    }
                    after_stop = true;
                    continue;
                }
            }
        }
        // Wake the CPU for the next interval-timer expiry while ring 3 runs.
        let expiry = current_signals(&mut process.tasks, own.me)
            .sig
            .itimer
            .next_event();
        timer::set_itimer_ns(expiry);
        // `rearm` drops an expiry that fell between the `sync_timers` above and
        // its own clock read (or while a frame was built): nothing would wake
        // ring 3 for it. Take another pass, which expires it and sends SIGALRM.
        if expiry.is_some_and(|at| at <= timer::ktime_get_ns()) {
            continue;
        }
        return;
    }
}

/// `printk_ratelimit()` called from `func`: ten lines per five seconds, and the
/// "callbacks suppressed" line (named after the caller) when it re-opens.
fn printk_ratelimit(process: &mut Process, task: &Owned, func: &str) -> bool {
    // The lines this limiter guards name the program `init` (`report`); after
    // an `execve` of another program they would be wrong, so stop instead.
    if task.attrs.comm[..5] != *b"init\0" {
        crate::log!(
            "FAIL fault report names only init (comm of the faulting program differs) func={}\n",
            func
        );
        crate::fail();
    }
    let jiffies = timer::ktime_get_ns() / kernel::time::TICK_NSEC;
    let verdict = process.printk_ratelimit.check(jiffies);
    if verdict.suppressed > 0 {
        crate::log!("{}: {} callbacks suppressed\n", func, verdict.suppressed);
    }
    verdict.allowed
}

/// `show_signal` / `show_signal_msg`: Linux prints the fault line when
/// `show_unhandled_signals && unhandled_signal(current, sig) && printk_ratelimit()`
/// (always for the global init, for any other task when `sig` has the default
/// or ignore disposition and the task is not already dying).
/// `message` is whether this fault has a line at all (a page fault that ends in
/// `SIGSEGV`, or a vector with a `show_signal` message). The limiter allows ten
/// lines per five seconds and reports the suppressed ones when it re-opens.
/// shortcut: no `Code:` line (`show_opcodes`) after the `segfault at` line.
fn show_unhandled_signal(
    process: &mut Process,
    task: &Owned,
    regs: &cpu::PtRegs,
    vector: u64,
    error: u64,
    address: u64,
) {
    let message = u8::try_from(vector)
        .ok()
        .and_then(report::user_exception)
        .and_then(|signal| signal.message);
    if vector != 14 && message.is_none() {
        return;
    }
    // The signal this vector raises (`show_signal`'s `signr`; `SIGSEGV` for
    // `show_signal_msg`).
    let signr = if vector == 14 {
        signal::SIGSEGV
    } else {
        u8::try_from(vector)
            .ok()
            .and_then(report::user_exception)
            .map_or(signal::SIGSEGV, |signal| signal.signal)
    };
    if !current_signals(&mut process.tasks, task.me).unhandled_signal(signr) {
        return;
    }
    let func = if vector == 14 {
        "show_signal_msg"
    } else {
        "show_signal"
    };
    if !printk_ratelimit(process, task, func) {
        return;
    }
    let region = region_of(process, task, regs.ip);
    let pid = task.tid.cast_signed();
    if vector == 14 {
        let line = Segfault {
            pid,
            address,
            ip: regs.ip,
            sp: regs.sp,
            error,
            region,
        };
        crate::log!("{}\n", line);
    } else if let Some((kind, desc)) = message {
        let line = TrapLine {
            pid,
            kind,
            desc,
            ip: regs.ip,
            sp: regs.sp,
            error,
            region,
        };
        crate::log!("{}\n", line);
    }
}

/// Force the signal of a synchronous user-mode fault (`force_sig_*`) and print
/// what `show_signal` / `show_signal_msg` print for it (`do_sigbus` prints
/// nothing, a refused page access prints the `segfault at` line). `Fault`'s
/// absent siginfo is a spurious `#MF`/`#XM` that raises nothing.
fn force(
    process: &mut Process,
    task: &Owned,
    regs: &cpu::PtRegs,
    fault: info::Fault,
    vector: u64,
    error: u64,
    address: u64,
) -> bool {
    let Some(signo) = fault.info.map(|i| i.signo) else {
        return false;
    };
    if vector != 14 || signo == i32::from(signal::SIGSEGV) {
        show_unhandled_signal(process, task, regs, vector, error, address);
    }
    current_signals(&mut process.tasks, task.me).force_fault(&fault);
    true
}

/// The signal of a non-page-fault exception (`exc_*` in traps.c).
fn raise_fault(
    process: &mut Process,
    task: &Owned,
    regs: &cpu::PtRegs,
    vector: u64,
    error: u64,
) -> bool {
    let vector8 = u8::try_from(vector).unwrap_or(u8::MAX);
    // #DB reports DR6 (cleared again, as `debug_read_clear_dr6`); #MF/#XM
    // read the saved FPU state (`fpu__exception_code`).
    let dr6 = if vector8 == info::X86_TRAP_DB {
        cpu::take_dr6()
    } else {
        0
    };
    let fpe = match vector8 {
        info::X86_TRAP_MF | info::X86_TRAP_XF => fpu::fpu_exception_code(vector8),
        _ => 0,
    };
    let fault = info::exception(vector8, error, regs.ip, dr6, fpe);
    fault.is_some_and(|fault| force(process, task, regs, fault, vector, error, 0))
}

/// Called by the IDT entry for an exception raised in ring 3: a page fault the
/// address-space model resolves retries the instruction, every other one
/// becomes a forced signal (default action: terminate, handlers run); the
/// return to ring 3 then delivers it. A vector that is not a plain user fault
/// (NMI, #DF, #MC, #NM, ...) is a kernel failure, never a user death.
pub fn exception(regs: &mut cpu::PtRegs, vector: u64, error: u64, address: u64) {
    #[cfg(feature = "qemu-self-test")]
    let entry = ktask::selftest::entry_begin();
    let raised = {
        let mut local = current_local();
        let TaskLocal { tables, own } = &mut *local;
        let mut process = PROCESS.lock();
        if vector == 14 {
            page_fault(&mut process, tables, own, regs, error, address)
        } else {
            raise_fault(&mut process, own, regs, vector, error)
        }
    };
    if !raised {
        crate::log!(
            "FAIL user exception vector={} error={:#x} rip={:#x}\n",
            vector,
            error,
            regs.ip
        );
        crate::fail();
    }
    exit_to_user(regs);
    #[cfg(feature = "qemu-self-test")]
    ktask::selftest::entry_end(entry, None, vector);
}

/// `print_vma_addr`'s file part for `ip`: Linux prints the basename of the
/// VMA's file, and [`FileRegion`] knows only `init`. A fault in a VMA of any
/// other file would print a wrong name, so it stops loudly instead (also for a
/// possible `/dev/zero` mapping, see below).
/// shortcut: resolve the name from the description's dentry when a program
/// other than `/init` can run.
fn region_of(process: &Process, task: &Owned, ip: u64) -> Option<FileRegion> {
    let Some(region) = FileRegion::of(&task.space, ip) else {
        // A private /dev/zero VMA keeps no `vm_file` here but Linux prints
        // ` in zero[...]` for it: once one was made, an anonymous `ip` cannot
        // be told from it.
        if process.vfs.zero_mapped() && task.space.find_vma(ip).is_some_and(|vma| vma.start <= ip) {
            crate::log!(
                "FAIL mm user fault in an anonymous mapping after a /dev/zero mapping ip={:#x} (vm_file of mmap_zero not kept)\n",
                ip
            );
            crate::fail();
        }
        return None;
    };
    if task.space.find_vma(ip).and_then(|vma| vma.file) != Some(task.exec) {
        crate::log!(
            "FAIL mm user fault in a mapped file other than /init ip={:#x} (file name resolution not ported)\n",
            ip
        );
        crate::fail();
    }
    Some(region)
}

/// A page fault taken in ring 3 (`exc_page_fault` -> `do_user_addr_fault`).
/// Context: the faulting task, interrupts off, `PROCESS` held by the caller
/// (`TaskLocal` is the task's own); takes `FRAMES` (and the heap) below it.
/// Returns `true`: the fault was resolved or its signal is forced and
/// delivered on the way out.
///
/// Outcomes and what Linux does (6.18.57, arch/x86/mm/fault.c):
/// * `Handled`: return to user, the instruction retries.
/// * `Segv`: `force_sig_fault(SIGSEGV, SEGV_MAPERR|SEGV_ACCERR, address)`; the
///   `init[<pid>]: segfault at ...` line (`show_signal_msg`) is printed if the
///   signal would then kill the task.
/// * `Bus`: `do_sigbus` -> `force_sig_fault(SIGBUS, BUS_ADRERR, address)` (no
///   console line for `SIGBUS` itself).
/// * `Oom`, `PgtableBad`, `Vsyscall`: Linux runs the OOM killer (which finds
///   init unkillable and panics), oopses and kills the task, or emulates the
///   vsyscall page. None is implemented: a loud `FAIL mm ...` stop, never a
///   signal that did not happen.
/// * `NeedsFile` (a page of a private file mapping) is resolved by
///   [`user_fault`] into `Handled`, `Bus` or `Oom`.
fn page_fault(
    process: &mut Process,
    tables: &mut Tables,
    own: &mut Owned,
    regs: &cpu::PtRegs,
    error: u64,
    address: u64,
) -> bool {
    let ip = regs.ip;
    let owner = own.owner();
    let mut space = tables.user_space();
    // `access_error` consults the task's `PKRU` before it populates anything.
    let env = Env {
        pkru: fpu::read_pkru(),
        ..own.env
    };
    let outcome = user_fault(
        &mut own.space,
        &env,
        &mut process.vfs,
        owner,
        &mut space,
        address,
        error | mm::PF_USER,
    );
    let kind = match outcome {
        FaultOutcome::Handled => {
            own.stats.min_flt += 1;
            #[cfg(all(feature = "qemu-self-test", not(feature = "baremetal-suite")))]
            USER_FAULTS_HANDLED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            return true;
        }
        FaultOutcome::Segv { code, address } => {
            // `bad_area_access_error`: with protection keys, an access error that the PKRU
            // caused (a hardware PK fault, or an access the PKRU denies for the VMA's key, 0
            // here) is SEGV_PKUERR with that key; the key is in the zero-filled `_pkey` field.
            let pkuerr =
                code == mm::SegvCode::AccErr && env.ospke && mm::pkru_denies_key0(error, env.pkru);
            let code = if pkuerr {
                info::SEGV_PKUERR
            } else {
                code as i32
            };
            (info::PageFault::Segv(code), address)
        }
        FaultOutcome::Bus { address } => (info::PageFault::Bus, address),
        FaultOutcome::Oom => {
            crate::log!(
                "FAIL mm out of memory in a user fault (Linux: pagefault_out_of_memory finds no killable task and panics) address={:#x} ip={:#x}\n",
                address,
                ip
            );
            crate::fail();
        }
        FaultOutcome::PgtableBad => {
            crate::log!(
                "FAIL mm reserved bit in a user PTE (Linux: pgtable_bad oops, SIGKILL) address={:#x} ip={:#x}\n",
                address,
                ip
            );
            crate::fail();
        }
        FaultOutcome::Vsyscall {
            address,
            error_code,
        } => {
            crate::log!(
                "FAIL mm vsyscall page fetch unimplemented (Linux emulates gettimeofday/time/getcpu there) address={:#x} error={:#x} ip={:#x}\n",
                address,
                error_code,
                ip
            );
            crate::fail();
        }
        FaultOutcome::NeedsFile { .. } => unreachable!("resolved by user_fault"),
    };
    let fault = info::page_fault(kind.0, kind.1, error);
    force(process, own, regs, fault, 14, error, kind.1)
}

/// One system call through the dispatcher in the self-test (stops loudly on an
/// unimplemented number).
#[cfg(all(feature = "boot-proofs", not(feature = "baremetal-suite")))]
fn call(context: &mut Syscall<'_>, number: syscalls::Sysno, args: [u64; 6]) -> i64 {
    match syscall::dispatch(context, number as u64, args) {
        Outcome::Return(value) => value,
        _ => crate::unwrap(Err::<i64, _>("mm-usercopy-syscall"), "mm-usercopy"),
    }
}

/// `PROT_NONE` round trip of [`mm_usercopy_faults`] on pages `a` and `a + P`
/// (which hold `pattern` across their boundary).
#[cfg(all(feature = "boot-proofs", not(feature = "baremetal-suite")))]
fn mm_usercopy_protnone(context: &mut Syscall<'_>, a: u64, pattern: [u8; 8]) {
    use kernel::mm::{PROT_NONE, PROT_READ, PROT_WRITE};
    use kernel::usercopy::{copy_from_user, copy_to_user};
    use syscalls::Sysno;

    const P: u64 = PAGE;
    // PROT_NONE keeps the frame and its data: the entry is not present, holds
    // the complemented frame bits (Linux's L1TF guard), the kernel is refused,
    // and protecting back restores the same bytes (the un-inverted frame).
    let before = context.space.raw_entry(a + P);
    crate::require(
        call(context, Sysno::mprotect, [a, 2 * P, PROT_NONE, 0, 0, 0]) == 0,
        "mm-usercopy-protnone",
    );
    crate::require(
        paging::UserSpace::protnone_guard(before, context.space.raw_entry(a + P)),
        "mm-usercopy-protnone-inverted",
    );
    let mut refused = [0xffu8; 8];
    crate::require(
        copy_from_user(context, &mut refused, a + P - 4) == 8 && refused == [0; 8],
        "mm-usercopy-protnone-refused",
    );
    crate::require(
        copy_to_user(context, a + P, &[1]) == 1,
        "mm-usercopy-protnone-write-refused",
    );
    crate::require(
        call(
            context,
            Sysno::mprotect,
            [a, 2 * P, PROT_READ | PROT_WRITE, 0, 0, 0],
        ) == 0,
        "mm-usercopy-protnone-restore",
    );
    let mut kept = [0u8; 8];
    crate::require(
        copy_from_user(context, &mut kept, a + P - 4) == 0 && kept == pattern,
        "mm-usercopy-protnone-data",
    );
}

/// `MAP_FIXED` replacement of [`mm_usercopy_faults`] over the two touched pages at `a`.
#[cfg(all(feature = "boot-proofs", not(feature = "baremetal-suite")))]
fn mm_usercopy_fixed(context: &mut Syscall<'_>, a: u64) {
    use kernel::mm::{
        MAP_ANONYMOUS, MAP_FIXED, MAP_PRIVATE, PROT_READ, PROT_WRITE, Pte, UserPages as _,
    };
    use kernel::usercopy::copy_from_user;
    use syscalls::Sysno;

    const P: u64 = PAGE;
    // `MAP_FIXED` over two touched private pages drops their frames (the final
    // accounting would show a leak) and leaves demand-zero pages.
    crate::require(
        context.space.lookup(a) != Pte::Absent && context.space.lookup(a + P) != Pte::Absent,
        "mm-usercopy-fixed-before",
    );
    crate::require(
        call(
            context,
            Sysno::mmap,
            [
                a,
                2 * P,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                u64::MAX,
                0,
            ],
        )
        .cast_unsigned()
            == a,
        "mm-usercopy-fixed",
    );
    crate::require(
        context.space.lookup(a) == Pte::Absent && context.space.lookup(a + P) == Pte::Absent,
        "mm-usercopy-fixed-unmapped",
    );
    let mut fresh = [0xffu8; 8];
    crate::require(
        copy_from_user(context, &mut fresh, a + P - 4) == 0 && fresh == [0; 8],
        "mm-usercopy-fixed-zero",
    );
}

/// The kernel-access cases of [`check_mm_usercopy`]: `a` is three writable
/// anonymous pages whose last is `PROT_NONE`, `b` one untouched read-only page.
#[cfg(all(feature = "boot-proofs", not(feature = "baremetal-suite")))]
fn mm_usercopy_faults(context: &mut Syscall<'_>, a: u64, b: u64) {
    use kernel::mm::{Pte, UserPages as _};
    use kernel::usercopy::{copy_from_user, copy_to_user};

    const P: u64 = PAGE;
    // A write across two untouched writable pages faults both in (write fault
    // on an absent page: a private zeroed frame each), then reads them back.
    let pattern = [1u8, 2, 3, 4, 5, 6, 7, 8];
    crate::require(
        copy_to_user(context, a + P - 4, &pattern) == 0,
        "mm-usercopy-write",
    );
    let mut back = [0u8; 8];
    crate::require(
        copy_from_user(context, &mut back, a + P - 4) == 0,
        "mm-usercopy-read",
    );
    crate::require(back == pattern, "mm-usercopy-readback");
    crate::require(
        context.space.lookup(a) == Pte::Anon { writable: true }
            && context.space.lookup(a + P) == Pte::Anon { writable: true },
        "mm-usercopy-private-frames",
    );
    mm_usercopy_protnone(context, a, pattern);
    // A read of an untouched readable page maps the shared zero page; a write
    // to that read-only mapping is refused (EFAULT: nothing copied) and keeps it.
    let mut zeros = [0xffu8; 8];
    crate::require(
        copy_from_user(context, &mut zeros, b) == 0,
        "mm-usercopy-zero-read",
    );
    crate::require(
        zeros == [0; 8] && context.space.lookup(b) == Pte::ZeroPage,
        "mm-usercopy-zero-page",
    );
    crate::require(copy_to_user(context, b, &[1]) == 1, "mm-usercopy-readonly");
    crate::require(
        context.space.lookup(b) == Pte::ZeroPage,
        "mm-usercopy-readonly-kept",
    );
    // The PROT_NONE page after the writable ones: the copy stops at the hole
    // (bytes before it are copied, the rest is reported), and a read of the
    // hole alone copies nothing and zero-fills the destination.
    crate::require(
        copy_to_user(context, a + 2 * P - 2, &[9; 6]) == 4,
        "mm-usercopy-short-write",
    );
    let mut tail = [0xffu8; 6];
    crate::require(
        copy_from_user(context, &mut tail, a + 2 * P - 2) == 4,
        "mm-usercopy-short-read",
    );
    crate::require(tail == [9, 9, 0, 0, 0, 0], "mm-usercopy-short-read-bytes");
    let mut hole = [0xffu8; 8];
    crate::require(
        copy_from_user(context, &mut hole, a + 2 * P) == 8,
        "mm-usercopy-hole",
    );
    crate::require(hole == [0; 8], "mm-usercopy-hole-zeroed");
    crate::require(
        copy_to_user(context, a + 2 * P, &[1]) == 1,
        "mm-usercopy-hole-write",
    );
    // An address above TASK_SIZE_MAX is refused by the range check, not faulted.
    crate::require(
        copy_to_user(context, kernel::usercopy::TASK_SIZE_MAX - 1, &[1, 2]) == 2,
        "mm-usercopy-range",
    );
    mm_usercopy_fixed(context, a);
}

/// QEMU proof of the kernel-access page-fault path through the real syscall
/// context, tables and frame allocator, without ring 3: the memory syscalls
/// create the mappings, then the one user-copy mechanism faults pages in
/// (`__do_page_fault` of a kernel access to user memory) with Linux's
/// short-copy results. Context: BSP, IF clear, `PROCESS` installed, no lock held.
#[cfg(all(feature = "boot-proofs", not(feature = "baremetal-suite")))]
fn check_mm_usercopy(local: &mut TaskLocal) {
    use kernel::mm::{
        MAP_ANONYMOUS, MAP_PRIVATE, PROT_NONE, PROT_READ, PROT_WRITE, Pte, UserPages as _, VmFlags,
    };
    use kernel::usercopy::{copy_from_user, copy_to_user};
    use syscalls::Sysno;

    const P: u64 = PAGE;
    let TaskLocal { tables, own } = local;
    let data_frames = |table_pages: usize| services::FRAMES.lock().allocated() - table_pages;
    let (frames0, vm0) = (data_frames(tables.pages), own.space.total_vm);
    // The self-test makes its calls from the kernel: no entry registers.
    let mut regs = cpu::PtRegs::default();
    let mut context = Syscall {
        space: tables.user_space(),
        own,
        shared: Shared::default(),
        regs: &mut regs,
        sink: ConsoleSink,
    };
    let anonymous = MAP_PRIVATE | MAP_ANONYMOUS;
    let a = call(
        &mut context,
        Sysno::mmap,
        [0, 3 * P, PROT_READ | PROT_WRITE, anonymous, u64::MAX, 0],
    )
    .cast_unsigned();
    let b = call(
        &mut context,
        Sysno::mmap,
        [0, P, PROT_READ, anonymous, u64::MAX, 0],
    )
    .cast_unsigned();
    crate::require(
        a.is_multiple_of(P) && b.is_multiple_of(P) && a < kernel::usercopy::TASK_SIZE_MAX,
        "mm-usercopy-mmap",
    );
    crate::require(
        call(
            &mut context,
            Sysno::mprotect,
            [a + 2 * P, P, PROT_NONE, 0, 0, 0],
        ) == 0,
        "mm-usercopy-mprotect",
    );
    mm_usercopy_faults(&mut context, a, b);
    crate::require(
        call(&mut context, Sysno::munmap, [a, 3 * P, 0, 0, 0, 0]) == 0,
        "mm-usercopy-munmap-a",
    );
    crate::require(
        call(&mut context, Sysno::munmap, [b, P, 0, 0, 0, 0]) == 0,
        "mm-usercopy-munmap-b",
    );
    // A kernel access one page below the growable stack VMA expands it
    // (`expand_downwards` through the fault path) and maps a private frame:
    // the only accounting change left, one frame and one page.
    let top = context
        .own
        .space
        .vmas()
        .iter()
        .find(|vma| vma.flags.intersects(VmFlags::GROWSDOWN))
        .map(|vma| vma.start);
    let grown = crate::unwrap(top.ok_or("no stack VMA"), "mm-usercopy-stack-vma") - P;
    crate::require(
        copy_to_user(&mut context, grown, &[7]) == 0,
        "mm-usercopy-stack-grow",
    );
    let mut byte = [0u8];
    crate::require(
        copy_from_user(&mut context, &mut byte, grown) == 0 && byte == [7],
        "mm-usercopy-stack-readback",
    );
    crate::require(
        context
            .own
            .space
            .find_vma(grown)
            .is_some_and(|vma| vma.start == grown && vma.flags.intersects(VmFlags::GROWSDOWN))
            && context.space.lookup(grown) == (Pte::Anon { writable: true }),
        "mm-usercopy-stack-vma-grown",
    );
    let vm_now = context.own.space.total_vm;
    drop(context);
    crate::require(
        data_frames(tables.pages) == frames0 + 1 && vm_now == vm0 + 1,
        "mm-usercopy-accounting",
    );
    crate::log!(
        "CHECK mm-usercopy ok fault_in=read,write short_write=4 hole=8 readonly=refused zero_page=shared range=refused protnone=inverted,restored fixed=replaced stack=grown unmap=restored\n"
    );
}

/// Exercise the one user-copy mechanism on the real owned tables.
fn check_user_image(init: &Loaded, space: &mut UserSpace<'_>) {
    let mut word = [0u8; 8];
    crate::require(
        usercopy::copy_from_user(space, &mut word, init.sp) == 0,
        "user-stack-readable",
    );
    crate::require(u64::from_le_bytes(word) == init.argc, "user-argc");
    // Writable-path walk: store the value that is already there.
    crate::require(
        usercopy::copy_to_user(space, init.sp, &word) == 0,
        "user-stack-writable",
    );
    crate::require(
        usercopy::copy_from_user(space, &mut word, STACK_START - 8) == 8 && word == [0; 8],
        "user-below-stack-unmapped",
    );
    crate::require(
        usercopy::copy_from_user(space, &mut word, usercopy::TASK_SIZE_MAX - 4) == 8,
        "user-range-limit",
    );
    crate::require(
        FileRegion::of(&init.mm, init.entry).is_some(),
        "user-entry-file-backed",
    );
    let audit = crate::unwrap(space.audit(), "user-isolation-audit");
    crate::log!(
        "CHECK userspace-audit ok user_pages={} user_tables={} kernel_entries={} kernel_user_bits=0 above_task_size=0\n",
        audit.user_pages,
        audit.user_tables,
        audit.kernel_entries
    );
    crate::log!(
        "CHECK userspace-image ok entry={:#x} sp={:#x} loads={} brk={:#x} argc={}\n",
        init.entry,
        init.sp,
        init.loads,
        init.mm.start_brk,
        init.argc
    );
}

/// End of the boot after a failed init: in a `qemu-self-test` build a failing
/// result with the harness's debug-exit, otherwise halt.
fn stop(label: &str) -> ! {
    // The suite ends only the group's run (`baremetal::fatal`).
    #[cfg(feature = "baremetal-suite")]
    {
        crate::log!("FAIL {}\n", label);
        crate::fail()
    }
    #[cfg(all(feature = "qemu-self-test", not(feature = "baremetal-suite")))]
    {
        crate::log!("FAIL {}\n", label);
        cpu::exit(false);
    }
    #[cfg(not(any(feature = "qemu-self-test", feature = "baremetal-suite")))]
    {
        let _ = label;
        cpu::halt()
    }
}

/// `init/main.c` `run_init_process`: prints one line per attempted init.
fn run_lines(paths: impl Iterator<Item = &'static str>) {
    for path in paths {
        crate::log!("Run {} as init process\n", path);
    }
}

const FALLBACK_NAMES: [&str; 4] = ["/sbin/init", "/etc/init", "/bin/init", "/bin/sh"];

/// Start init, or end the boot the way Linux does when it cannot.
///
/// Returns only when init's task has left the CPU for good and nothing else is
/// runnable, which in the bare-metal suite is the end of a group (the caller
/// tears the process down and starts the next); in any other boot init's death
/// ends the boot, so a return is the caller's failure to report.
pub fn run(user: Result<Loaded, Error>) {
    match user {
        Ok(init) => start(init),
        Err(Error::NoInit) => {
            // Linux: `init_eaccess("/init")` fails, `prepare_namespace` finds no
            // root device and panics (init/do_mounts.c:236).
            for line in NO_ROOT {
                crate::log!("{}\n", line);
            }
            crate::log!("{}\n", NO_ROOT_PANIC);
            stop("no-root");
        }
        Err(Error::CompressedModule(module)) => {
            crate::log!(
                "FAIL initramfs module={} is compressed and no /init was unpacked: decompressor not ported\n",
                module
            );
            crate::fail();
        }
        Err(Error::Exec(errno) | Error::Load(LoadError::Errno(errno))) => {
            // `kernel_init`: `Failed to execute`, then every fallback fails
            // with ENOENT (silently) because none exists in the archives.
            crate::log!("Run /init as init process\n");
            crate::log!("{}\n", ExecFailed(-errno.into_raw()));
            run_lines(FALLBACK_NAMES.into_iter());
            crate::log!("{}\n", NO_INIT);
            stop("no-init");
        }
        Err(Error::Fallback { errno, path }) => {
            crate::log!("Run /init as init process\n");
            crate::log!("{}\n", ExecFailed(-errno));
            run_lines(
                FALLBACK_NAMES
                    .into_iter()
                    .take_while(|name| name.as_bytes() != path),
            );
            crate::log!(
                "FAIL fallback init present path={} unsupported\n",
                core::str::from_utf8(path).unwrap_or("?")
            );
            stop("fallback-init");
        }
        Err(error) => {
            crate::log!("FAIL userspace error={:?}\n", error);
            crate::fail();
        }
    }
}

/// The bare-metal suite's group load (decision A21): a fresh rootfs from the
/// retained archive copies, then `/init` with `-- <group> <uptime_s> <ram>` as
/// its arguments (`uptime_s`: whole seconds of boot time at the group's start,
/// so the group's uptime bounds count from there; `ram`: bytes of RAM the
/// memory map declares, the ceiling of `ids.sysinfo-ram` on any machine).
/// The module payloads are unreadable once the owned tables are active, so the
/// suite keeps heap copies (`baremetal::retain_archives`).
///
/// Context: BSP, IF clear, no group running, no lock held. Locks `TABLES`
/// for the load (`TABLES` -> heap -> `FRAMES`, the documented order).
#[cfg(feature = "baremetal-suite")]
pub fn load_group(
    archives: &[Vec<u8>],
    group: &str,
    uptime_s: u64,
    ram_bytes: u64,
) -> Result<Loaded, Error> {
    /// Decimal digits of `value` right-aligned in `digits`; the start index.
    fn decimal(digits: &mut [u8; 20], mut value: u64) -> usize {
        let mut start = digits.len();
        loop {
            start -= 1;
            digits[start] = b'0' + u8::try_from(value % 10).unwrap_or(0);
            value /= 10;
            if value == 0 {
                return start;
            }
        }
    }
    let mut rootfs = new_rootfs()?;
    for (index, bytes) in archives.iter().enumerate() {
        rootfs.unpack(index, bytes);
    }
    // "-- <group> <decimal uptime> <decimal ram>", at most 20 digits each.
    let (mut up, mut ram) = ([0u8; 20], [0u8; 20]);
    let (up_start, ram_start) = (decimal(&mut up, uptime_s), decimal(&mut ram, ram_bytes));
    let (up, ram) = (&up[up_start..], &ram[ram_start..]);
    let mut line = Vec::new();
    line.try_reserve_exact(5 + group.len() + up.len() + ram.len())
        .map_err(|_| Error::Vfs(Errno::ENOMEM))?;
    for &byte in b"-- "
        .iter()
        .chain(group.as_bytes())
        .chain(b" ")
        .chain(up)
        .chain(b" ")
        .chain(ram)
    {
        let _ = line.push_within_capacity(byte);
    }
    // The group's tree: an empty user half over the kernel tree that
    // `services::TABLES` keeps (which also owns the shared zero page).
    // `TABLES` -> `FRAMES`, the documented order.
    let mut tables = {
        let mut template = services::TABLES.lock();
        let mut frames = services::FRAMES.lock();
        if !template.has_zero_page() {
            template.init_zero_page(&mut frames)?;
        }
        template.fork_template(&mut frames)?
    };
    match load_rootfs(&line, rootfs.vfs, rootfs.compressed, &mut tables) {
        Ok(mut loaded) => {
            loaded.tables = Some(tables);
            Ok(loaded)
        }
        Err(error) => {
            // No task owns the tree yet: its pages and tables go back.
            tables.destroy_user(&mut services::FRAMES.lock());
            Err(error)
        }
    }
}

/// End of a group's run: free the address space of every task that is left
/// (init's and its children's: `exit_mmap`), then drop the shared state
/// (rootfs, open files, task list). The kernel stacks of the abandoned tasks
/// are reset by `ktask::reset_group`; what only those stacks held (a heap block
/// a task was using when its group was cut off) is lost, which a group ended by
/// a kernel stop or a time bound can do.
///
/// Context: BSP, IF clear on the boot stack (the idle task), `PROCESS`, `TABLES`
/// and `FRAMES` free (the suite checks [`locks_free`] after a kernel stop).
#[cfg(feature = "baremetal-suite")]
pub fn teardown() {
    let process = PROCESS.take();
    // No task's tree may be the loaded one when it is freed.
    let kernel = KERNEL_ROOT.load(Ordering::Acquire);
    if kernel != 0 {
        // SAFETY: the kernel-only tree in `services::TABLES` (alive for the life
        // of the system); IF=0 on the BSP; its kernel half is the published
        // one, so everything this code runs on stays mapped.
        unsafe { cpu::activate_tables(kernel) };
    }
    for (slot, entry) in LOCALS.0.iter().enumerate() {
        // An abandoned task's guard never dropped: nothing runs now.
        entry.busy.store(false, Ordering::Release);
        if let Some(local) = take_local(slot) {
            let TaskLocal { tables, own } = *local;
            tables.destroy_user(&mut services::FRAMES.lock());
            drop(own);
        }
    }
    drop(process);
    let _ = LOAD.take();
    // The group's signal state (handlers, queues, `ITIMER_REAL`) died with it;
    // its clockevent wake-ups must not outlive it.
    timer::clear_waits();
}

/// Whether every lock a group's teardown takes is free (see `Service::is_free`).
#[cfg(feature = "baremetal-suite")]
pub fn locks_free() -> bool {
    PROCESS.is_free()
        && LOAD.is_free()
        && ktask::locks_free()
        && services::TABLES.is_free()
        && services::FRAMES.is_free()
        && crate::kalloc::lock_free()
}

/// init's page tables: the group's own tree (the suite), or the published
/// one, which a kernel-only tree then replaces in `services::TABLES` as the
/// template every later tree copies its kernel half from and the tree CR3
/// holds while no task's may be (`exit_mm`).
fn take_init_tables(init: &mut Loaded) -> Tables {
    let tables = if let Some(tables) = init.tables.take() {
        tables
    } else {
        let Some(published) = services::TABLES.take() else {
            crate::log!("FAIL published page tables missing at init start\n");
            crate::fail();
        };
        let template = crate::unwrap(
            published
                .fork_template(&mut services::FRAMES.lock())
                .map_err(|_| "kernel-only tables"),
            "kernel-tables",
        );
        services::TABLES.install(template);
        published
    };
    KERNEL_ROOT.store(services::TABLES.lock().root_address(), Ordering::Release);
    tables
}

#[allow(clippy::too_many_lines, reason = "init's boot sequence, in order")]
fn start(mut init: Loaded) {
    let mut tables = take_init_tables(&mut init);
    check_user_image(&init, &mut tables.user_space());
    crate::log!("Run /init as init process\n");
    // SAFETY: BSP, CPL0, IF clear (nothing since the timer test re-enabled it
    // except the guarded sections, which restore it off), descriptors installed
    // in `kernel_main` before this point.
    let enabled = unsafe { cpu::enable_syscalls() };
    crate::unwrap(enabled, "syscall-msrs");
    // SAFETY: as above; only supervisor mappings exist besides init's pages.
    let protection = unsafe { cpu::enable_user_protection() };
    // `nofsgsbase` (AT_HWCAP2 = 0) holds only while CR4.FSGSBASE is clear.
    crate::require(!cpu::fsgsbase_enabled(), "cr4-fsgsbase-clear");
    // SAFETY: as above; `kernel_main` enabled the FPU before the loader built `/init`'s stack
    // (`AT_MINSIGSTKSZ` needs the XSAVE size), so this only reloads the initial registers of
    // this group.
    crate::unwrap(unsafe { fpu::init(fpu::Options::default()) }, "user-fpu");
    crate::log!(
        "CHECK userspace exec path=/init entry={:#x} loads={} sp={:#x} smep={} smap={}\n",
        init.entry,
        init.loads,
        init.sp,
        protection.smep,
        protection.smap
    );
    let (entry, sp) = (init.entry, init.sp);
    // `fork_init`: RLIMIT_NPROC and RLIMIT_SIGPENDING derive from memory.
    // shortcut: Linux uses `memblock_estimated_nr_free_pages()` (memblock memory
    // minus early reservations); this is every page the frame allocator
    // manages, so the limits equal Linux's only for the same page count. Upgrade
    // with a memblock-equivalent estimate.
    let managed_pages = services::FRAMES.lock().total() as u64;
    // `sched_init`: the first load window starts when the scheduler does.
    // shortcut: that is when init starts here, not at kernel entry.
    LOAD.install(LoadAvg::new(jiffies_of(
        crate::timer::ktime_get_boottime_ns(),
    )));
    // The tick (masked after the boot proofs) runs again so user/system time accrues.
    timer::resume_tick();
    // Timekeeping runs now: replace the placeholders of the unpack-time stamps,
    // then follow the real wall clock.
    init.vfs
        .start_timekeeping(timer::ktime_get_real, timer::ktime_get_real());
    let mut fdt = FdTable::default();
    // console_on_rootfs: descriptors 0-2 are one /dev/console open file.
    if init.vfs.console_on_rootfs(&mut fdt).is_err() {
        crate::log!("Warning: unable to open an initial console.\n");
    }
    let mut attrs = Attributes::init(task::max_threads(managed_pages));
    attrs.fs = init.vfs.new_fs_struct(0o022);
    let max_threads = task::max_threads(managed_pages);
    let (tasks, me) = crate::unwrap(
        Tasklist::new(
            u32::try_from(max_threads).unwrap_or(u32::MAX),
            &attrs.cred,
            max_threads / 2,
        )
        .map_err(|_| "out of memory"),
        "task-list",
    );
    let tty = crate::unwrap(
        kernel::tty::Tty::new().map_err(|_| "out of memory"),
        "console-tty",
    );
    init.vfs.set_ram_pages(managed_pages);
    init.vfs.fs.ns.proc.cmdline_size =
        i64::try_from(services::boot().command_line().len()).unwrap_or(0) + 1;
    PROCESS.install(Process {
        tasks,
        wake: SchedWaker,
        vfs: init.vfs,
        tty,
        printk_ratelimit: RateLimit::printk(kernel::time::HZ),
    });
    // The console tty's input devices raise interrupts that take the process
    // state installed above. Not in the bare-metal suite: its groups run on a
    // machine whose keyboard and serial line are not assumed.
    #[cfg(not(feature = "baremetal-suite"))]
    // SAFETY: BSP, IF clear (see the SAFETY comment above `enable_syscalls`),
    // the timer and the IDT are initialised, `PROCESS` is installed.
    unsafe {
        crate::ttyin::init();
    }
    // init's own state. Its scheduling handle is known only when the task is
    // created (`bound` below), the placeholder is the idle slot.
    let mut local = crate::unwrap(
        Box::try_new(TaskLocal {
            tables,
            own: Owned {
                me,
                sched: SchedId::from_raw(0),
                tgid: 1,
                tid: 1,
                attrs,
                restart: RestartBlock::NONE,
                space: init.mm,
                env: init.env,
                exe_file: init.exec,
                exec: u64::from(init.exec.index()),
                fdt,
                pin_owner: next_pin_owner(),
                vfork_parent: None,
                pending_mm: None,
                lent_out: false,
                stats: Stats::started(),
            },
        })
        .map_err(|_| "init task state"),
        "init-state",
    );
    // Not in the suite: it runs once per group and the `mm` group covers the
    // user-copy faults from ring 3.
    #[cfg(all(feature = "boot-proofs", not(feature = "baremetal-suite")))]
    check_mm_usercopy(&mut local);
    crate::unwrap(ktask::init(), "scheduler");
    #[cfg(feature = "qemu-self-test")]
    match crate::services::boot().test {
        kernel::boot::TestMode::SchedSwitch => ktask::selftest::sched_switch(),
        kernel::boot::TestMode::KstackOverflow => ktask::selftest::kstack_overflow(),
        kernel::boot::TestMode::SchedPreempt => ktask::selftest::start_preempt_hog(),
        _ => {}
    }
    let cr3 = local.tables.root_address();
    // SAFETY: descriptors and syscall MSRs are installed above; init's tree
    // maps `entry` (executable) and `sp` (writable, user) and its kernel half
    // is the published one; all state used by the syscall/fault paths is in
    // `PROCESS`, `LOCALS` (installed by `bound` before the first switch) and
    // `services`; `kernel_main`'s frame stays on the boot stack, which is
    // idle's from here on.
    unsafe {
        ktask::start_init(entry, sp, cr3, |sched| {
            local.own.sched = sched;
            let mut process = PROCESS.lock();
            process.tasks.set_sched(me, sched);
            // The segments' VMAs hold /init (`vm_file`). The loader's reference
            // (`bprm->file`) stays as `mm->exe_file` for the life of the task, so
            // `exec` can never name a recycled description.
            crate::unwrap(process.vfs.reserve_pin(), "exec-pin");
            process
                .vfs
                .pin(local.own.owner(), u64::from(init.exec.index()));
            // init's first view for /proc.
            let tables = &mut local.tables;
            let own = &local.own;
            let _ = publish(&mut process, own, &mut tables.user_space());
            drop(process);
            install_local(sched.index(), local);
        });
    }
}

/// The CPU facts of `/proc/cpuinfo`: `cpuid` is read once (it can cost a VM
/// exit per leaf); the TSC frequency is refreshed on every call.
fn cpu_facts() -> kernel::procfs::cpuinfo::CpuFacts {
    static FACTS: crate::services::IrqMutex<Option<kernel::procfs::cpuinfo::CpuFacts>> =
        crate::services::IrqMutex::new(None);
    let mut slot = FACTS.lock();
    let mut facts = *slot.get_or_insert_with(|| {
        kernel::procfs::cpuinfo::CpuFacts::read(|leaf, sub| {
            let r = raw_cpuid::native_cpuid::cpuid_count(leaf, sub);
            [r.eax, r.ebx, r.ecx, r.edx]
        })
    });
    facts.tsc_khz = timer::tsc_khz();
    facts
}
