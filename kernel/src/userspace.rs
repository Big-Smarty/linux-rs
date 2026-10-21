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
    arena::{Arena, Id},
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
    futex::{FutexWaker, Futexes},
    image::elf::ET_DYN,
    loadavg::LoadAvg,
    mm::{self, Env, FaultOutcome, Mm, PF_WRITE},
    procfs::{
        Caller, MmTotals,
        show::{HostInfo, Show, ShowScope},
        view::Collect,
    },
    ratelimit::RateLimit,
    sched::{CLASS_FUTEX, CLASS_VFORK, PIPE_KEY, POLL_KEY, SchedId, TaskState, WaitKey, WakeMode},
    signal::{
        self, SIGSTOP, State,
        deliver::{self, Outcome as SignalOutcome},
        frame::Sigreturn,
        info,
    },
    syscall::{
        self, AddressSpace, ClockState, Clocks, Console, Context, ExecAux, Files, FutexParts,
        Machine, Outcome, RestartBlock, Tasks,
    },
    task::{
        self, Attributes, Rlimits, TaskId, Tasklist,
        exit::{ExitPrep, Waker, chldexit_key, de_thread_key},
        fork::ForkRequest,
        jobctl::StopPlan,
        tasklist::CloneParams,
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

/// Where the lowest string of `/init`'s argument block starts (`bprm->p` after `copy_strings`):
/// the block laid out once into the heap, because `setup_arg_pages` sizes the stack VMA by the
/// pages the strings use and the VMA must exist before anything is mapped.
fn probe_arg_start(argv: &InitArgv<'_>, aux: &Aux) -> Result<u64, Error> {
    let mut scratch = alloc::vec::Vec::new();
    scratch
        .try_reserve_exact(stack::WINDOW_BYTES)
        .map_err(|_| Error::Vfs(Errno::ENOMEM))?;
    while scratch.len() < stack::WINDOW_BYTES {
        scratch
            .push_within_capacity(0u8)
            .map_err(|_| Error::Vfs(Errno::ENOMEM))?;
    }
    let built = stack::build(
        &mut scratch,
        FILENAME,
        iter::once(Word::plain(FILENAME)).chain(argv.clone()),
        ENVP.iter().copied(),
        aux,
    )?;
    Ok(built.arg_start)
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
    let plan = LoadPlan::new(file)?;
    if plan.has_interpreter {
        // The plan checked the header and the `PT_INTERP` bytes (Linux
        // order); the interpreter is now looked up in the archives.
        let path = LoadPlan::interpreter(file).unwrap_or_default();
        return Err(interpreter_failure(
            &mut vfs,
            path,
            Unsupported::Interpreter,
        ));
    }
    // shortcut: the boot loader places `ET_EXEC` images only; `execve` (`syscall::exec`)
    // places `ET_DYN` ones and interpreters through the same `exec::load`. Upgrade by
    // building `/init` through that path too.
    if plan.file_type == ET_DYN {
        return Err(Error::Load(LoadError::Unsupported(
            Unsupported::SharedObject,
        )));
    }

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
    // `setup_arg_pages` sizes the stack VMA by the argument pages, so the block is laid out
    // once (into the heap) to learn where its strings start, before anything is mapped.
    let argv = InitArgv::parse(command_line)?;
    let aux = Aux {
        hwcap: __cpuid(1).edx,
        phdr: plan.phdr,
        phnum: plan.phnum,
        entry: plan.entry,
        base: 0,
        random: random_bytes(),
    };
    let arg_start = probe_arg_start(&argv, &aux)?;
    let rlim_stack = kernel::task::Rlimits::init(0)
        .get(kernel::task::RLIMIT_STACK)
        .cur;
    insert_stack(
        &mut mm,
        &env,
        plan.exec_stack,
        stack::stack_vma_start(arg_start, rlim_stack),
    )?;
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
    fn de_thread_event(&mut self, task: TaskId) {
        ktask::wake_up_key(de_thread_key(task), WakeMode::Normal, 0);
    }
}

/// A pipe changed (data written or consumed, an end closed, the capacity
/// changed) since the last look: wake its sleepers (`wake_up_interruptible` on
/// `rd_wait`/`wr_wait`) and the `poll` sleepers (their own key, so a tty or mount
/// event never wakes a pipe reader). The
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
    let pipes = vfs.take_pipe_events();
    // A change of the mount table wakes the `poll` sleepers on `mounts`/`mountinfo`.
    let mounts = vfs.take_mount_events();
    if pipes {
        ktask::wake_up_key(PIPE_KEY, WakeMode::Interruptible, 0);
    }
    // A change of the tty (input, output drained, termios) wakes its readers
    // and writers, and the `poll` sleepers.
    let console = tty.take_events();
    if console {
        ktask::wake_up_key(kernel::sched::TTY_KEY, WakeMode::Interruptible, 0);
    }
    if pipes || mounts || console {
        ktask::wake_up_key(POLL_KEY, WakeMode::Interruptible, 0);
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
/// credential snapshots and the signal objects of all tasks), the VFS (the
/// mounted rootfs, open file descriptions, pipes, mapping pins) and the three
/// objects tasks share by `clone` flag: address spaces ([`MmStruct`],
/// `CLONE_VM`), descriptor tables ([`FilesStruct`], `CLONE_FILES`) and
/// filesystem contexts ([`FsShared`], `CLONE_FS`), each a counted arena slot a
/// task names by id. One lock, `PROCESS`, stands for `TASKLIST` and `VFS` of the
/// lock-order DAG (`services`) and covers them all: `PROCESS` -> heap ->
/// `FRAMES`, and `PROCESS` -> `TIMER_HW` (a leaf, the interval-timer
/// programming of `exit_to_user`).
///
/// **No guard of it is alive across `schedule()`**: a [`Syscall`] takes it
/// lazily ([`Shared`]) and its [`Context::wait`](signal::Task::wait) drops it
/// before the task leaves the CPU, so another task can run a system call
/// meanwhile, on the same address space and descriptors if it is a thread of
/// the same group. State only the running task touches is in [`TaskLocal`].
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
    /// The futex hash: every waiting task of every address space.
    futex: Futexes,
    /// The wake-up of a futex waiter a waker took out of the queue.
    futex_wake: SchedFutexWaker,
    /// Every live `mm_struct`.
    mms: Arena<MmStruct>,
    /// Every live `files_struct`.
    files_structs: Arena<FilesStruct>,
    /// Every live `fs_struct`.
    fs_structs: Arena<FsShared>,
}

/// `struct mm_struct`: an address space and what hangs off it, shared by the tasks that
/// were cloned with `CLONE_VM` (a `vfork` child, the threads of a group).
struct MmStruct {
    /// `mm->pgd`: the page tables, whose root is the CR3 of every task that uses it.
    tables: Tables,
    /// The VMA set, program break and statistics. It reserves its `Vec` storage (heap)
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
    /// The key of the mappings' pins in the VFS (`Vfs::pin`): the identity of the address
    /// space, fresh for every one ([`next_pin_owner`]) and the key private futexes use.
    pin_owner: u32,
    /// `mm->mm_users`: the tasks working in it.
    users: u32,
    /// The thread groups (`tgid`, each once) whose tasks work in it: `/proc/<tgid>` of each
    /// shows this address space, so the view of every one is brought up to date when any task
    /// changes it ([`refresh_sharers`]).
    groups: Vec<i32>,
}

/// Bring the `/proc` views of the thread groups that share `mm` up to date, except for
/// `except` (the caller's own, which the caller publishes).
fn refresh_sharers(vfs: &mut Vfs, mm: &mut MmStruct, except: i32) {
    if mm.groups.iter().all(|&group| group == except) {
        return;
    }
    let (rss, bytes) = {
        let space = mm.tables.user_space();
        (space.rss(), space.table_bytes())
    };
    for &group in &mm.groups {
        if group != except {
            let _ = vfs.fs.ns.proc.publish_mm(group, &mm.space, rss, bytes);
        }
    }
}

/// `struct files_struct`: a descriptor table shared by `CLONE_FILES`.
struct FilesStruct {
    fdt: FdTable,
    /// `files->count`.
    users: u32,
}

/// `struct fs_struct`: root, working directory and umask, shared by `CLONE_FS`.
struct FsShared {
    fs: vfs::FsStruct,
    /// `fs->users`.
    users: u32,
}

type MmId = Id<MmStruct>;
type FilesId = Id<FilesStruct>;
type FsId = Id<FsShared>;

impl Process {
    /// The address space `id` names. A task's ids stay valid for as long as it exists.
    fn mm(&mut self, id: MmId) -> &mut MmStruct {
        must(&mut self.mms, id)
    }

    fn mm_ref(&self, id: MmId) -> &MmStruct {
        let Some(mm) = self.mms.get(id) else {
            crate::log!("FAIL a task works in an address space that does not exist\n");
            crate::fail();
        };
        mm
    }
}

/// `futex_wake`'s `wake_up_q` on the scheduler: the waiter named by its slot is woken from its
/// `CLASS_FUTEX` sleep (`RQ`, a leaf under `PROCESS`).
struct SchedFutexWaker;

impl FutexWaker for SchedFutexWaker {
    fn wake(&mut self, owner: u32) {
        ktask::wake_up_key(WaitKey::new(CLASS_FUTEX, owner), WakeMode::Interruptible, 0);
    }
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
/// reads): reached through [`current_local`] and never under a lock. Another task needing
/// something of it would put it in [`Process`] (the credential snapshot, the signal
/// objects and the process tree already are). The address space, descriptor table and
/// filesystem context it works in are [`Process`]'s too ([`Owned::mm`] and friends): the
/// task's thread-group siblings use them as well.
pub struct TaskLocal {
    own: Owned,
}

/// The part of [`TaskLocal`] that is the task's own.
struct Owned {
    /// `current`'s place in the task list, and its scheduling handle.
    me: TaskId,
    sched: SchedId,
    /// `task_tgid_vnr` / `task_pid_vnr` (equal for a thread-group leader).
    tgid: u32,
    tid: u32,
    /// Credentials, rlimits, comm, personality and the user pointers libc registers
    /// (`task::Attributes`, the identity group).
    attrs: Attributes,
    /// `current->restart_block.nanosleep`, written by the sleeping syscalls and
    /// run by `restart_syscall`.
    restart: RestartBlock,
    /// `current->mm`, `current->files`, `current->fs`.
    mm: MmId,
    files: FilesId,
    fs: FsId,
    /// `current->vfork_done` (`CLONE_VFORK`): the parent sleeping until this task's `execve`
    /// or exit.
    vfork_parent: Option<Lender>,
    /// `bprm->mm`: the fresh address space the `execve` of a task that shares its own moves to,
    /// made before the point of no return ([`Context::exec_prepare`]), with the executable
    /// that becomes its `exe_file`.
    pending_mm: Option<PendingMm>,
    /// `current->set_child_tid` (`CLONE_CHILD_SETTID`): the child stores its tid there when
    /// it first runs (`schedule_tail`).
    set_child_tid: u64,
    /// The counters `/proc/<pid>/{stat,status}` show.
    stats: Stats,
}

/// A fresh address space made for an `execve` before it commits.
struct PendingMm {
    tables: Tables,
    space: Mm,
    /// Room for the one group that will use it.
    groups: Vec<i32>,
    /// `set_mm_exe_file`, once the exec knows its file.
    exe: Option<FileId>,
}

/// The parent of a `vfork` child.
#[derive(Clone, Copy)]
struct Lender {
    sched: SchedId,
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

/// A fresh identity for an address space (`Vfs::pin`'s owner key): never a scheduling slot,
/// which a later task reuses while an address space can outlive its first user.
fn next_pin_owner() -> u32 {
    static NEXT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// `vfork_done` of each sleeping parent, by its scheduling slot: set by the child when it execs
/// or exits (`complete_vfork_done`), consumed by the parent. A leaf lock: nothing else is
/// taken while it is held.
static VFORK_DONE: services::IrqMutex<[bool; ktask::SLOTS]> =
    services::IrqMutex::new([false; ktask::SLOTS]);

#[allow(
    clippy::cast_possible_truncation,
    reason = "a slot index is below the pool size"
)]
fn vfork_done_key(parent: SchedId) -> WaitKey {
    WaitKey::new(CLASS_VFORK, parent.index() as u32)
}

/// `complete_vfork_done`, called by the child when it execs or exits: the parent wakes. A
/// parent that no longer exists (it was killed while it waited) has nothing to wake; the flag
/// of its slot is cleared by the next task that waits there before its child can run.
fn complete_vfork(lender: Lender) {
    let alive = matches!(ktask::state(lender.sched), Some(state) if state != TaskState::Dead);
    if alive {
        VFORK_DONE.lock()[lender.sched.index()] = true;
        ktask::wake_up_key(vfork_done_key(lender.sched), WakeMode::Normal, 0);
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

/// `schedule_tail`: the first thing a new task does in its own context. `CLONE_CHILD_SETTID`
/// stores its tid at the address the clone named; a failing store is ignored (`put_user`).
pub fn schedule_tail() {
    let slot = ktask::current().index();
    // SAFETY: only reads whether the slot has state; a task that is running has not given it
    // up (module `Locals`), and the kernel threads and self-test tasks without state are not
    // in user mode, so there is nothing to store.
    let present = unsafe { (*LOCALS.0[slot].cell.get()).is_some() };
    if !present {
        return;
    }
    let mut local = current_local();
    let own = &mut local.own;
    let at = core::mem::take(&mut own.set_child_tid);
    if at == 0 {
        return;
    }
    let tid = own.tid;
    let mut process = PROCESS.lock();
    let (_, mut pages) = FaultPages::of(&mut process, own);
    let _ = usercopy::put_user(&mut pages, at, &tid.to_le_bytes());
}

/// The most `cmdline`/`environ` bytes copied for other readers at `execve`
/// (`ARG_MAX`'s order of magnitude: the exec path caps the block far below).
const MAX_PUBLISHED_ARGS: u64 = 2 << 20;

/// Publish what `/proc/<pid>/*` shows of `own` for the readers of other tasks
/// (see `procfs::view`): called by the task itself when it is about to leave
/// the CPU (a sleep, a preemption, a stop), when it reads its own entries, and
/// for a new child. A thread of a group publishes the group's view, from the
/// address space, descriptors and filesystem context it shares with the others.
///
/// Context: task, `PROCESS` held by the caller (`vfs` lock class); allocates
/// fallibly (`ENOMEM` leaves the previous view in place). The time is
/// proportional to what changed since the task's last publication: the
/// descriptors replay the table's change log, the VMA vector is shared until
/// its stamp moves, and the resident-page and page-table figures are counters
/// (`procfs::view`).
fn publish(process: &mut Process, own: &Owned) -> Result<(), Errno> {
    let Process {
        tasks,
        vfs,
        mms,
        files_structs,
        fs_structs,
        ..
    } = process;
    // `signal->rlim` is the group's: any of its threads publishes the same.
    let Some(&rlimits) = tasks.rlimits(own.me) else {
        return Err(Errno::ESRCH);
    };
    let (Some(mm), Some(files), Some(fs)) = (
        mms.get_mut(own.mm),
        files_structs.get(own.files),
        fs_structs.get(own.fs),
    ) else {
        return Err(Errno::ESRCH);
    };
    let tgid = own.tgid.cast_signed();
    // A thread that is not the leader refreshes only what the group shares, the address space
    // and the descriptors: the identity, counters and times of the view are the leader's.
    if own.tid != own.tgid
        && let Some(attrs) = vfs.fs.ns.proc.view(tgid).map(|view| view.attrs)
    {
        refresh_sharers(vfs, mm, tgid);
        let (rss, bytes) = {
            let space = mm.tables.user_space();
            (space.rss(), space.table_bytes())
        };
        vfs.fs.ns.proc.publish_mm(tgid, &mm.space, rss, bytes)?;
        let table = &vfs.files;
        if let Some(view) = vfs.fs.ns.proc.view_mut(tgid) {
            view.refresh_files(&attrs, &rlimits, fs.fs, &files.fdt, table, mm.exe_file)?;
        }
        return Ok(());
    }
    let mut space = mm.tables.user_space();
    // The argument and environment bytes are copied when the layout changes
    // (an `execve`) and kept otherwise.
    let layout = (mm.space.arg_start, mm.space.env_end);
    let kept = vfs.fs.ns.proc.view(tgid).and_then(|view| {
        let same_image = view
            .mm
            .as_ref()
            .is_some_and(|mm| (mm.arg_start, mm.env_end) == layout);
        (same_image && !view.args().is_empty())
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
            let missing = usercopy::copy_from_user(&mut space, &mut bytes, layout.0);
            bytes.truncate(len - missing);
        }
        if bytes.is_empty() {
            None
        } else {
            Some(Arc::try_new(bytes).map_err(|_| Errno::ENOMEM)?)
        }
    };
    // The self-test builds prove the counters against the walks they replaced.
    #[cfg(feature = "qemu-self-test")]
    space.check_counters(mm.space.vmas());
    // The groups that share the address space (a `vfork` parent, a `CLONE_VM` child) show it.
    refresh_sharers(vfs, mm, tgid);
    let (rss, pgtables_bytes) = {
        let space = mm.tables.user_space();
        (space.rss(), space.table_bytes())
    };
    vfs.fs.ns.proc.publish_update(
        tgid,
        Collect {
            attrs: &own.attrs,
            rlimits: &rlimits,
            fs: fs.fs,
            fdt: &files.fdt,
            files: &vfs.files,
            mm: Some(&mm.space),
            exe: Some(mm.exe_file),
            rss,
            pgtables_bytes,
            min_flt: own.stats.min_flt,
            maj_flt: own.stats.maj_flt,
            nvcsw: own.stats.nvcsw,
            nivcsw: own.stats.nivcsw,
            start_boottime_ns: own.stats.start_ns,
            flags: 0,
            args,
        },
    )
}

/// [`publish`] for the running task, taking its state and `PROCESS`.
fn publish_current() {
    let local = current_local();
    let mut process = PROCESS.lock();
    let _ = publish(&mut process, &local.own);
}

/// The machine's counters for the global files of /proc.
///
/// Context: task; takes `FRAMES` and `LOAD` (leaf locks) while `process` is held.
#[allow(clippy::too_many_lines)] // one straight list of the counters /proc shows
fn host_info(process: &Process, own: &Owned) -> Result<HostInfo, Errno> {
    let max_map_count = process.mm_ref(own.mm).env.max_map_count;
    let up = timer::ktime_get_boottime_ns();
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
    // `kernel_cpustat`: the tick-accounted time of all tasks (the exited ones
    // included); the idle time is what is left of the uptime. The address-space
    // figures are the sums the published views keep.
    let (user, system) = ktask::kcpustat();
    let idle = up.saturating_sub(user + system);
    let MmTotals {
        anon_pages: anon,
        mapped_pages: mapped,
        pgtables_bytes: tables_bytes,
    } = process.vfs.fs.ns.proc.totals();
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
        max_map_count: u64::from(max_map_count),
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

/// Syscall context: the task's own state (`own`), the shared state taken on demand (the
/// address space, descriptors and filesystem context are in it, named by `own`), the entry
/// registers and the console.
struct Syscall<'a> {
    own: &'a mut Owned,
    shared: Shared,
    regs: &'a mut cpu::PtRegs,
    sink: ConsoleSink,
}

/// `handle_mm_fault` for one user address: the model's decision, and for a
/// page of a private file mapping (`NeedsFile`) `shmem_fault` + `do_read_fault`
/// / `do_cow_fault`: a private frame holding the file page ([`Vfs::fault_page`];
/// `SIGBUS` past `i_size`). A read fault maps it read-only (`do_read_fault`
/// maps the page-cache page without `FAULT_FLAG_WRITE`, so `RssShmem`; the
/// first write takes the write-protect fault that copies it), a write fault
/// with the VMA's protection (`do_cow_fault`, `RssAnon`). `owner` is the
/// faulting task's mapping-pin key.
fn user_fault(
    mm: &mut Mm,
    env: &Env,
    vfs: &mut Vfs,
    owner: u32,
    space: &mut Tables,
    address: u64,
    error: u64,
) -> FaultOutcome {
    let outcome = mm.handle_user_fault(env, space, address, error);
    let FaultOutcome::NeedsFile { address, write } = outcome else {
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
        Ok(()) => {
            let mut prot = mm::page_prot(vma.flags);
            prot.write &= write;
            match space.install(page, prot, true, &bytes) {
                Ok(()) => FaultOutcome::Handled,
                Err(mm::OutOfMemory) => FaultOutcome::Oom,
            }
        }
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
struct FaultPages<'a> {
    mm: &'a mut Mm,
    env: &'a Env,
    vfs: &'a mut Vfs,
    owner: u32,
    tables: &'a mut Tables,
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

impl<'a> FaultPages<'a> {
    /// The task list and the user-memory view of the address space `own` works in.
    fn split(process: &'a mut Process, own: &'a mut Owned) -> (&'a mut Tasklist, Self) {
        let Process {
            tasks, vfs, mms, ..
        } = process;
        let Some(MmStruct {
            tables,
            space,
            env,
            pin_owner,
            ..
        }) = mms.get_mut(own.mm)
        else {
            crate::log!("FAIL a task works in an address space that does not exist\n");
            crate::fail();
        };
        (
            tasks,
            Self {
                mm: space,
                env,
                vfs,
                owner: *pin_owner,
                tables,
                faults: &mut own.stats.min_flt,
            },
        )
    }

    fn of(process: &'a mut Process, own: &'a mut Owned) -> (State<'a>, Self) {
        let me = own.me;
        let (tasks, pages) = Self::split(process, own);
        (current_signals(tasks, me), pages)
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
        if !self.tables.user_space().resident(page, write) {
            match user_fault(
                self.mm,
                self.env,
                self.vfs,
                self.owner,
                self.tables,
                page,
                error,
            ) {
                FaultOutcome::Handled => *self.faults += 1,
                _ => return None,
            }
        }
        self.tables.page(page, write)
    }
}

impl UserPages for FaultPages<'_> {
    fn page(&mut self, page: u64, write: bool) -> Option<&mut [u8; PAGE_BYTES]> {
        FaultPages {
            mm: &mut *self.mm,
            env: self.env,
            vfs: &mut *self.vfs,
            owner: self.owner,
            tables: &mut *self.tables,
            faults: &mut *self.faults,
        }
        .into_page(page, write)
    }
}

impl UserPages for Syscall<'_> {
    fn page(&mut self, page: u64, write: bool) -> Option<&mut [u8; PAGE_BYTES]> {
        let (_, pages) = FaultPages::split(self.shared.get(), &mut *self.own);
        pages.into_page(page, write)
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
        mms: usize,
        file_tables: usize,
        fs_contexts: usize,
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
            mms: process.mms.len(),
            file_tables: process.files_structs.len(),
            fs_contexts: process.fs_structs.len(),
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
            "CHECK fork-objects forks={} heap={}/{} files={}/{} file_refs={}/{} pins={}/{} root_refs={}/{} slots={}/{} threads={}/{} mms={}/{} file_tables={}/{} fs_contexts={}/{}\n",
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
            was.mms,
            now.mms,
            was.file_tables,
            now.file_tables,
            was.fs_contexts,
            now.fs_contexts,
        );
    }
}

/// A page-table error of a copy or a fresh tree: only exhaustion is a legitimate failure.
fn tables_errno(error: &paging::Error, what: &str) -> Errno {
    if matches!(error, paging::Error::Memory(_)) {
        Errno::ENOMEM
    } else {
        crate::log!("FAIL {} error={:?}\n", what, error);
        crate::fail()
    }
}

/// `copy_process`' unwinding of the steps after the child's kernel stack: everything the child
/// was given is released in the reverse order it was taken. Each argument is what exists so
/// far (`None`: not made yet, or shared with the parent and so not the child's to release).
fn fork_undo(
    vfs: &mut Vfs,
    sched: SchedId,
    copied: Option<(Mm, Tables)>,
    fdt: Option<FdTable>,
    fs: Option<vfs::FsStruct>,
    pins: Option<(u32, FileId)>,
) {
    if let Some(mut fdt) = fdt {
        vfs.close_files(&mut fdt);
    }
    if let Some(fs) = fs {
        vfs.put_fs(&fs);
    }
    if let Some((owner, exe)) = pins {
        vfs.unpin_all(owner);
        vfs.fput(exe);
    }
    ktask::cancel_new_task(sched);
    if let Some((space, tables)) = copied {
        destroy_tables(tables);
        drop(space);
    }
}

impl Syscall<'_> {
    /// `kernel_clone` / `copy_process` / `wake_up_new_task` for `fork`, `vfork`, `clone` and
    /// `clone3`, in the order of `copy_process` (the argument checks and the pending-signal
    /// restart are the syscall layer's).
    ///
    /// Everything the child needs is built first, each step undone by the ones after it on
    /// failure ([`fork_undo`]); the child becomes visible to the rest of the system (the task
    /// list) only when nothing else can fail, and runnable last. An object the request shares
    /// (`CLONE_VM`, `CLONE_FILES`, `CLONE_FS`) is named by the same id and counted; one it does
    /// not is a copy, in a reserved arena slot so that publishing it cannot fail. The address
    /// space is copied eagerly (shortcut S2 of the process lane: copy-on-write is the upgrade).
    ///
    /// `CLONE_VFORK`: `wait_for_vfork_done` puts the parent to sleep until the child's `execve`
    /// or exit (`complete_vfork`).
    ///
    /// Context: task, IF=0, on the parent's kernel stack; takes `PROCESS`
    /// (-> heap, -> `FRAMES` through the page-table copy).
    #[allow(
        clippy::too_many_lines,
        reason = "one fork, in the order of copy_process, each failure undoing the steps before it"
    )]
    fn fork(&mut self, request: &ForkRequest) -> Result<i32, Errno> {
        let parent = self.own.me;
        let params = CloneParams::of(request);
        #[cfg(feature = "qemu-self-test")]
        leak::at_fork(self.shared.get());
        // dup_task_struct: the child's state block, so that no later step
        // loses what it holds to an allocation failure. It comes first, as in
        // Linux (kernel/fork.c:2020): ENOMEM beats the limits' EAGAIN.
        let block = Box::<TaskLocal>::try_new_uninit().map_err(|_| Errno::ENOMEM)?;
        // ... and the child's FPU state, a copy of ours (`fpu_clone`; Linux's lives inside the
        // task structure, so it fails there too).
        let xstate = fpu::XBuf::from_live().map_err(|_| Errno::ENOMEM)?;
        let (mm_id, files_id, fs_id) = (self.own.mm, self.own.files, self.own.fs);
        // The address space is shared with a new process: what `/proc` shows of the parent
        // (the argument bytes, the layout) is brought up to date with the image it runs now,
        // as Linux's files read the live `mm`.
        if request.share_vm && !request.thread {
            let _ = publish(self.shared.get(), self.own);
        }
        let process = self.shared.get();
        // copy_process: RLIMIT_NPROC and max_threads (fork.c:2059, 2072).
        process.tasks.fork_allowed(parent)?;
        // The arena slots of the objects that are copied.
        let enomem = |_| Errno::ENOMEM;
        if !request.share_files {
            process.files_structs.try_reserve(1).map_err(enomem)?;
        }
        if !request.share_fs {
            process.fs_structs.try_reserve(1).map_err(enomem)?;
        }
        if !request.share_vm {
            process.mms.try_reserve(1).map_err(enomem)?;
        }
        let Process {
            tasks,
            vfs,
            mms,
            files_structs,
            fs_structs,
            ..
        } = &mut *process;
        if request.vfork {
            // The flag of a vfork whose parent stopped waiting is stale: clear it before the
            // child can run.
            VFORK_DONE.lock()[self.own.sched.index()] = false;
        }
        // copy_mm: the VMA model, then the pages; or the parent's, counted.
        let parent_mm = must(mms, mm_id);
        // The room for the child's group in the list of the groups that use the address space.
        let mut groups = Vec::new();
        if !request.share_vm {
            groups.try_reserve_exact(1).map_err(enomem)?;
        } else if !request.thread {
            parent_mm.groups.try_reserve(1).map_err(enomem)?;
        }
        let copied = if request.share_vm {
            None
        } else {
            let space = parent_mm.space.dup(&parent_mm.env)?;
            match parent_mm.tables.user_space().fork_tables() {
                Ok(tables) => Some((space, tables)),
                Err(error) => {
                    drop(space);
                    return Err(tables_errno(&error, "fork page tables"));
                }
            }
        };
        let (parent_pin, exe_file, exec) =
            (parent_mm.pin_owner, parent_mm.exe_file, parent_mm.exec);
        let root = copied.as_ref().map_or_else(
            || parent_mm.tables.root_address(),
            |(_, tables)| tables.root_address(),
        );
        // sched_fork + copy_thread: slot, kernel stack, the child's registers
        // (`ax` = 0, the requested stack), FP and segment state (`%fs` base for
        // `CLONE_SETTLS`), its CR3.
        let mut regs = *self.regs;
        regs.ax = 0;
        if request.child_sp != 0 {
            regs.sp = request.child_sp;
        }
        // copy_thread -> set_new_tls -> do_arch_prctl_64(ARCH_SET_FS): a base in the kernel half
        // is `EPERM`.
        if request
            .tls
            .is_some_and(|base| base >= usercopy::TASK_SIZE_MAX)
        {
            if let Some((space, tables)) = copied {
                destroy_tables(tables);
                drop(space);
            }
            return Err(Errno::EPERM);
        }
        let Ok(sched) = ktask::prepare_fork(regs, root, xstate, request.tls) else {
            if let Some((space, tables)) = copied {
                destroy_tables(tables);
                drop(space);
            }
            return Err(Errno::EAGAIN);
        };
        let child_pin = if request.share_vm {
            parent_pin
        } else {
            next_pin_owner()
        };
        // copy_files / copy_fs / the mapping and executable references.
        let new_fdt = if request.share_files {
            None
        } else {
            match vfs.dup_fd(&must(files_structs, files_id).fdt) {
                Ok(fdt) => Some(fdt),
                Err(errno) => {
                    fork_undo(vfs, sched, copied, None, None, None);
                    return Err(errno);
                }
            }
        };
        if !request.share_vm
            && let Err(errno) = vfs.pin_clone(parent_pin, child_pin)
        {
            fork_undo(vfs, sched, copied, new_fdt, None, None);
            return Err(errno);
        }
        let new_fs = (!request.share_fs).then(|| vfs.dup_fs(&must(fs_structs, fs_id).fs));
        if !request.share_vm {
            vfs.files.dup(exe_file);
        }
        let pins = (!request.share_vm).then_some((child_pin, exe_file));
        // The point of no failure but the task list's: publish the child.
        let child = match tasks.clone_task(parent, params) {
            Ok(child) => child,
            Err(errno) => {
                fork_undo(vfs, sched, copied, new_fdt, new_fs, pins);
                return Err(errno);
            }
        };
        let pid = tasks.task_pid_vnr(child);
        tasks.set_sched(child, sched);
        let child_mm = if let Some((space, tables)) = copied {
            let env = must(mms, mm_id).env;
            let _ = groups.push_within_capacity(pid);
            let made = mms.insert_reserved(MmStruct {
                tables,
                space,
                env,
                exe_file,
                exec,
                pin_owner: child_pin,
                users: 1,
                groups,
            });
            let Ok(id) = made else {
                crate::log!("FAIL a reserved address-space slot is gone\n");
                crate::fail();
            };
            id
        } else {
            let shared = must(mms, mm_id);
            shared.users += 1;
            if !request.thread {
                let _ = shared.groups.push_within_capacity(pid);
            }
            mm_id
        };
        let child_files = if let Some(fdt) = new_fdt {
            let made = files_structs.insert_reserved(FilesStruct { fdt, users: 1 });
            let Ok(id) = made else {
                crate::log!("FAIL a reserved descriptor-table slot is gone\n");
                crate::fail();
            };
            id
        } else {
            must(files_structs, files_id).users += 1;
            files_id
        };
        let child_fs = if let Some(fs) = new_fs {
            let made = fs_structs.insert_reserved(FsShared { fs, users: 1 });
            let Ok(id) = made else {
                crate::log!("FAIL a reserved filesystem-context slot is gone\n");
                crate::fail();
            };
            id
        } else {
            must(fs_structs, fs_id).users += 1;
            fs_id
        };
        let mut attrs = self.own.attrs;
        // copy_process: `clear_child_tid` per CLONE_CHILD_CLEARTID (the robust list starts empty:
        // it is the task list's).
        attrs.clear_child_tid = request.clear_child_tid;
        let tid = pid.cast_unsigned();
        let own = Owned {
            me: child,
            sched,
            tgid: if request.thread { self.own.tgid } else { tid },
            tid,
            attrs,
            restart: RestartBlock::NONE,
            mm: child_mm,
            files: child_files,
            fs: child_fs,
            vfork_parent: request.vfork.then_some(Lender {
                sched: self.own.sched,
            }),
            pending_mm: None,
            set_child_tid: request.set_child_tid,
            stats: Stats::started(),
        };
        // kernel_clone: `CLONE_PARENT_SETTID` is stored before the child can run; a failing
        // store is ignored.
        if request.parent_settid != 0 {
            let _ = usercopy::put_user(self, request.parent_settid, &pid.to_le_bytes());
        }
        // A new process is visible to /proc from now on: its first view, taken
        // from the state it was just given (the parent may read it before the
        // child ever runs). A refusal leaves the child without a view until
        // it first leaves the CPU; the files of /proc then answer `ESRCH`. A thread shares
        // its group's.
        if !request.thread {
            let _ = publish(self.shared.get(), &own);
        }
        let local = Box::write(block, TaskLocal { own });
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
    /// fatal signal ends the wait early).
    fn wait_for_vfork_done(&mut self) {
        let me = self.own.sched;
        loop {
            if core::mem::take(&mut VFORK_DONE.lock()[me.index()]) {
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

/// An object of an arena that a task names and so must exist.
fn must<T>(arena: &mut Arena<T>, id: Id<T>) -> &mut T {
    let Some(object) = arena.get_mut(id) else {
        crate::log!("FAIL a task names a shared object that does not exist\n");
        crate::fail();
    };
    object
}

/// Free a page-table tree that no task owns (a failed fork or exec, the last user of an
/// address space leaving): the frame allocator is a leaf below everything the caller holds.
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
    fn futex(&mut self) -> FutexParts<'_> {
        let (id, owner, tid) = (self.own.mm, self.own.sched.index(), self.own.tid);
        let Process {
            futex,
            futex_wake,
            mms,
            ..
        } = self.shared.get();
        let mm = must(mms, id);
        FutexParts {
            queue: futex,
            waker: futex_wake,
            #[allow(
                clippy::cast_possible_truncation,
                reason = "a slot index is below the pool size"
            )]
            owner: owner as u32,
            mm: u64::from(mm.pin_owner),
            mm_users: mm.users,
            tid,
        }
    }
    fn replace_exe_file(&mut self, file: FileId) -> Option<FileId> {
        if let Some(pending) = self.own.pending_mm.as_mut() {
            // `set_mm_exe_file(bprm->mm, ...)`: the new address space of an exec that leaves
            // the old one to its other users; the old one keeps its file.
            pending.exe = Some(file);
            return None;
        }
        let id = self.own.mm;
        let mm = self.shared.get().mm(id);
        mm.exec = u64::from(file.index());
        Some(core::mem::replace(&mut mm.exe_file, file))
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
        let id = self.own.mm;
        let MmStruct {
            tables, space, env, ..
        } = self.shared.get().mm(id);
        AddressSpace {
            mm: space,
            env,
            pages: tables,
        }
    }
    fn files(&mut self) -> Files<'_> {
        let (mm, files, fs) = (self.own.mm, self.own.files, self.own.fs);
        let Process {
            vfs,
            mms,
            files_structs,
            fs_structs,
            ..
        } = self.shared.get();
        Files {
            vfs,
            fdt: &mut must(files_structs, files).fdt,
            fs: &mut must(fs_structs, fs).fs,
            owner: must(mms, mm).pin_owner,
        }
    }
    fn copy_process(&mut self, request: &ForkRequest) -> Result<i32, Errno> {
        self.fork(request)
    }
    fn exec_prepare(&mut self) -> Result<(), Errno> {
        if self.own.pending_mm.is_some() {
            return Ok(());
        }
        let id = self.own.mm;
        let Process { mms, .. } = self.shared.get();
        if must(mms, id).users <= 1 {
            return Ok(());
        }
        // bprm_mm_init: the new mm, its tree and VMA set, and the arena slot it will take.
        mms.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
        let old = must(mms, id);
        let tables = old
            .tables
            .user_space()
            .empty_tree()
            .map_err(|error| tables_errno(&error, "exec tree"))?;
        let space = Mm::new(&old.env);
        let mut groups = Vec::new();
        groups.try_reserve_exact(1).map_err(|_| Errno::ENOMEM)?;
        self.own.pending_mm = Some(PendingMm {
            tables,
            space,
            groups,
            exe: None,
        });
        Ok(())
    }
    fn exec_unshare_files(&mut self) -> Result<(), Errno> {
        let id = self.own.files;
        let Process {
            vfs, files_structs, ..
        } = self.shared.get();
        if must(files_structs, id).users <= 1 {
            return Ok(());
        }
        files_structs.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
        let fdt = vfs.dup_fd(&must(files_structs, id).fdt)?;
        must(files_structs, id).users -= 1;
        let Ok(new) = files_structs.insert_reserved(FilesStruct { fdt, users: 1 }) else {
            crate::log!("FAIL a reserved descriptor-table slot is gone\n");
            crate::fail();
        };
        self.own.files = new;
        Ok(())
    }
    fn exec_switch_mm(&mut self) -> Result<(), Errno> {
        let (id, me) = (self.own.mm, self.own.me);
        let Process {
            tasks, vfs, mms, ..
        } = self.shared.get();
        let old = must(mms, id);
        match self.own.pending_mm.take() {
            // exec_mmap: the address space has other users (a `vfork` parent, a `CLONE_VM`
            // sibling): this task moves to the fresh one and leaves them the old.
            Some(PendingMm {
                tables,
                space,
                mut groups,
                exe: Some(exe_file),
            }) if old.users > 1 => {
                let root = tables.root_address();
                let tgid = self.own.tgid.cast_signed();
                old.users -= 1;
                old.groups.retain(|&group| group != tgid);
                // The groups that stay behind show the address space as this task left it.
                refresh_sharers(vfs, old, tgid);
                let env = old.env;
                let _ = groups.push_within_capacity(tgid);
                let made = mms.insert_reserved(MmStruct {
                    tables,
                    space,
                    env,
                    exe_file,
                    exec: u64::from(exe_file.index()),
                    pin_owner: next_pin_owner(),
                    users: 1,
                    groups,
                });
                let Ok(new) = made else {
                    crate::log!("FAIL a reserved address-space slot is gone\n");
                    crate::fail();
                };
                self.own.mm = new;
                // SAFETY: `root` is the live tree `empty_tree` made from this task's own, so
                // its kernel half is the published one and maps this code, the stack and the
                // heap; the BSP runs with IF=0 inside a system call; no PCID or global
                // translations exist. The old tree is not freed (it has other users).
                unsafe { cpu::activate_tables(root) };
                ktask::set_current_cr3(root);
            }
            Some(PendingMm { exe: None, .. }) if old.users > 1 => {
                crate::log!("FAIL exec of a shared address space without its executable\n");
                crate::fail();
            }
            None if old.users > 1 => {
                crate::log!("FAIL exec of a shared address space without a fresh one\n");
                crate::fail();
            }
            // The other users are gone by now (`de_thread`): the old address space is this
            // task's alone and the exec replaces its image in place; the fresh one is not
            // needed.
            Some(PendingMm {
                tables, space, exe, ..
            }) => {
                destroy_tables(tables);
                drop(space);
                if let Some(file) = exe {
                    old.exec = u64::from(file.index());
                    let previous = core::mem::replace(&mut old.exe_file, file);
                    vfs.fput(previous);
                }
            }
            None => {}
        }
        // exec_mm_release -> mm_release: `complete_vfork_done`.
        if let Some(lender) = self.own.vfork_parent.take() {
            complete_vfork(lender);
        }
        // unshare_sighand: the dispositions are this process's alone from now on.
        tasks.unshare_sighand(me)
    }
    fn thread_ids_changed(&mut self) {
        let me = self.own.me;
        let tasks = &self.shared.get().tasks;
        self.own.tid = tasks.task_pid_vnr(me).cast_unsigned();
        self.own.tgid = tasks.task_tgid_vnr(me).cast_unsigned();
    }
    fn sync_proc(&mut self) {
        let process = self.shared.get();
        // Nothing reads the mirror or a view before a procfs is mounted.
        if !process.vfs.fs.ns.has_proc() {
            process.vfs.fs.ns.proc.prune(&process.tasks);
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
        let Process {
            tasks,
            vfs,
            mms,
            files_structs,
            fs_structs,
            ..
        } = process;
        let (exe, fs) = (
            must(mms, self.own.mm).exe_file,
            must(fs_structs, self.own.fs).fs,
        );
        let fdt = &must(files_structs, self.own.files).fdt;
        let fd_stamp = fdt.stamp();
        let stale = vfs.fs.ns.proc.view(tgid).is_none_or(|v| {
            v.fd_stamp != fd_stamp
                || v.fs.root != fs.root
                || v.fs.pwd != fs.pwd
                || v.exe.map(|e| e.file) != Some(exe)
        });
        if !stale {
            return;
        }
        let Some(view_attrs) = vfs.fs.ns.proc.view(tgid).map(|view| view.attrs) else {
            let _ = publish(self.shared.get(), self.own);
            return;
        };
        // A thread that is not the leader leaves the identity of the view to the leader.
        let attrs = if self.own.tid == self.own.tgid {
            self.own.attrs
        } else {
            view_attrs
        };
        let files = &vfs.files;
        let Some(&rlimits) = tasks.rlimits(self.own.me) else {
            return;
        };
        if let Some(view) = vfs.fs.ns.proc.view_mut(tgid) {
            let _ = view.refresh_files(&attrs, &rlimits, fs, fdt, files, exe);
        }
    }
    fn with_show<R>(
        &mut self,
        scope: ShowScope,
        f: impl FnOnce(&Show<'_>) -> R,
    ) -> Result<R, Errno> {
        // The caller's own view is current before anyone reads it: when its
        // own files are shown, or every task's counters are summed.
        // A task that shares its address space with another process (a `vfork` child, a
        // `CLONE_VM` child) publishes it for both: the files of the other show what this task
        // did to it.
        let mine = self.own.tgid.cast_signed();
        let shared_mm = self.shared.get().mm_ref(self.own.mm).groups.len() > 1;
        if matches!(scope, ShowScope::Machine) || scope == ShowScope::Pid(mine) || shared_mm {
            publish(self.shared.get(), self.own)?;
        }
        let process = self.shared.get();
        let root = process.fs_structs.get(self.own.fs).map(|fs| fs.fs.root);
        let Some(root) = root else {
            return Err(Errno::ESRCH);
        };
        let host = host_info(process, self.own)?;
        let caller = Caller {
            tgid: self.own.tgid.cast_signed(),
            cred: vfs::Cred::of_task(&self.own.attrs.cred),
        };
        let show = Show {
            vfs: &process.vfs,
            tasks: &process.tasks,
            host: &host,
            caller,
            root,
        };
        Ok(f(&show))
    }
    fn mm_args(&mut self) -> Option<(u64, u64, u64, u64)> {
        let id = self.own.mm;
        let mm = &self.shared.get().mm(id).space;
        Some((mm.arg_start, mm.arg_end, mm.env_start, mm.env_end))
    }
}

impl Syscall<'_> {
    /// `thread_group_cputime` and `thread_group_cputime_adjusted` of the group `member` is in: every
    /// live thread's account, the times the finished threads left in the group and those of a
    /// thread that is exiting (folded by `do_exit` before the thread is released). The sample
    /// and the `(utime, stime)` pair `times(2)` reports.
    /// shortcut: a finished thread's runtime is its adjusted `utime + stime`, which is equal
    /// to `sum_exec_runtime` by construction (`cputime_adjust`), but its tick-accounted user
    /// and system parts are the adjusted ones, so `CPUCLOCK_VIRT` of a group that lost a
    /// thread is the adjusted figure.
    fn group_cpu(&mut self, member: TaskId) -> (CpuSample, (u64, u64)) {
        let now = timer::ktime_get_ns();
        let tasks = &self.shared.get().tasks;
        let (mut user, mut system) = tasks.dead_cputime(member);
        let mut sample = CpuSample {
            runtime_ns: user + system,
            user_ns: user,
            system_ns: system,
        };
        for thread in tasks.threads(member) {
            let Some(task) = tasks.task(thread) else {
                continue;
            };
            let (part, (u, s)) = thread_cpu(task, now);
            sample.runtime_ns += part.runtime_ns;
            sample.user_ns += part.user_ns;
            sample.system_ns += part.system_ns;
            user += u;
            system += s;
        }
        (sample, (user, system))
    }
}

/// One thread's CPU time at `now`: the account of a live task (its sample, and the adjusted
/// `(utime, stime)`), or what an exited one left in its task structure.
fn thread_cpu(task: &task::tasklist::TaskStruct, now: u64) -> (CpuSample, (u64, u64)) {
    match task.sched {
        Some(sched) if task.exit_state == task::tasklist::ExitState::Live => {
            let account = ktask::cpu_account(sched);
            (account.sample(now), account.adjusted(now))
        }
        _ => (
            CpuSample {
                runtime_ns: task.utime_ns + task.stime_ns,
                user_ns: task.utime_ns,
                system_ns: task.stime_ns,
            },
            (task.utime_ns, task.stime_ns),
        ),
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
    fn group_cpu_sample(&mut self) -> CpuSample {
        self.group_cpu(self.own.me).0
    }
    fn cpu_sample_of(&mut self, task: TaskId) -> CpuSample {
        let now = timer::ktime_get_ns();
        // The caller resolved `task` under the same lock hold: it is in the list.
        self.shared.get().tasks.task(task).map_or(
            CpuSample {
                runtime_ns: 0,
                user_ns: 0,
                system_ns: 0,
            },
            |t| thread_cpu(t, now).0,
        )
    }
    fn group_cpu_sample_of(&mut self, task: TaskId) -> CpuSample {
        self.group_cpu(task).0
    }
    fn cpu_adjusted(&mut self) -> (u64, u64) {
        self.group_cpu(self.own.me).1
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

impl signal::Task for Syscall<'_> {
    type Pages<'b>
        = FaultPages<'b>
    where
        Self: 'b;
    fn state(&mut self) -> State<'_> {
        current_signals(&mut self.shared.get().tasks, self.own.me)
    }
    fn parts(&mut self) -> (State<'_>, FaultPages<'_>) {
        FaultPages::of(self.shared.get(), &mut *self.own)
    }
    fn now_ns(&self) -> u64 {
        timer::ktime_get_ns()
    }
    fn sync_timers(&mut self, now: u64) {
        let Process { tasks, wake, .. } = self.shared.get();
        tasks.sync_timers(self.own.me, now, wake);
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
        let _ = publish(self.shared.get(), self.own);
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
        let (mut state, mut pages) = FaultPages::of(self.shared.get(), &mut *self.own);
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

/// The task's own state; the box itself is freed on return (`do_exit` does not return: a box
/// left to its scope would leak).
fn into_own(boxed: Box<TaskLocal>) -> Owned {
    let TaskLocal { own } = *boxed;
    own
}

/// `mmput`: the task lets go of its address space; the last user frees it and the pins its
/// mappings held (`exit_mmap`).
fn mmput(process: &mut Process, id: MmId, group_gone: Option<i32>) {
    let Process { vfs, mms, .. } = process;
    let mm = must(mms, id);
    if let Some(tgid) = group_gone {
        mm.groups.retain(|&group| group != tgid);
    }
    mm.users -= 1;
    if mm.users > 0 {
        // The groups that stay show the address space as this task left it.
        refresh_sharers(vfs, mm, -1);
        return;
    }
    let Some(MmStruct {
        tables,
        space,
        exe_file,
        pin_owner,
        ..
    }) = mms.remove(id)
    else {
        return;
    };
    vfs.unpin_all(pin_owner);
    destroy_tables(tables);
    drop(space);
    vfs.fput(exe_file);
}

/// `exit_mm`, the address-space half of [`do_exit`], after `mm_release` ran in the task's own
/// context: a `vfork` parent wakes, an address space made for an `execve` that did not happen
/// goes, and the task's use of its own ends.
fn exit_mm(process: &mut Process, own: &mut Owned, group_gone: Option<i32>) {
    if let Some(lender) = own.vfork_parent.take() {
        complete_vfork(lender);
    }
    if let Some(pending) = own.pending_mm.take() {
        destroy_tables(pending.tables);
        drop(pending.space);
        if let Some(file) = pending.exe {
            process.vfs.fput(file);
        }
    }
    mmput(process, own.mm, group_gone);
}

/// `exit_files` and `exit_fs`: the task lets go of its descriptor table and filesystem context;
/// the last user closes the descriptors and drops the root and working directory.
fn exit_files_fs(process: &mut Process, own: &Owned) {
    let Process {
        vfs,
        files_structs,
        fs_structs,
        ..
    } = process;
    let files = must(files_structs, own.files);
    files.users -= 1;
    if files.users == 0
        && let Some(FilesStruct { mut fdt, .. }) = files_structs.remove(own.files)
    {
        vfs.close_files(&mut fdt);
    }
    let fs = must(fs_structs, own.fs);
    fs.users -= 1;
    if fs.users == 0
        && let Some(FsShared { fs, .. }) = fs_structs.remove(own.fs)
    {
        vfs.put_fs(&fs);
    }
}

/// The tty half of `do_exit`: the console's last close, and `disassociate_ctty(1)` when the
/// group is dead.
fn exit_tty(process: &mut Process, me: TaskId, group_dead: bool) {
    let Process {
        tasks,
        wake,
        vfs,
        tty,
        ..
    } = process;
    syscall::tty::housekeeping(vfs, tty, tasks);
    let console_open = vfs.tty_files().1 > 0;
    let hung = group_dead
        && kernel::tty::jobctl::disassociate_ctty(
            tty,
            tasks,
            me,
            wake,
            &mut crate::ttyin::Wire(&mut ConsoleSink),
            true,
            console_open,
        );
    if hung {
        vfs.tty_hangup_files();
    }
}

/// `do_exit` of the calling task: `exit` (`group` false) or `do_group_exit`
/// (`exit_group`, a fatal signal). The last thread of global init panics
/// (`init_died`); any other task releases its address space, descriptors and
/// working directory (each when it was the last user), tells its parent (the
/// last thread of a group; a leader that has threads left stays a zombie
/// unannounced), hands its children to init and leaves the CPU for good
/// (`do_task_dead`).
///
/// Context: task, IF=0, no lock held, on the task's own kernel stack.
fn do_exit(code: u32, group: bool, signaled: bool) -> ! {
    let slot = ktask::current().index();
    let me = current_local().own.me;
    let mut shared = PROCESS.lock();
    let Process { tasks, wake, .. } = &mut *shared;
    let code = if group {
        tasks.do_group_exit(me, code, wake)
    } else {
        code
    };
    let group_dead = match tasks.exit_prepare(me, code, signaled, wake) {
        ExitPrep::InitDied { exitcode } => {
            #[cfg(feature = "qemu-self-test")]
            leak::report(&shared);
            drop(shared);
            init_died(exitcode)
        }
        ExitPrep::Proceed { group_dead } => group_dead,
    };
    drop(shared);
    // exit_mm -> mm_release: the robust list is walked and `clear_child_tid` written and
    // woken, in the task's own address space and with the task's own context.
    {
        let mut local = current_local();
        // The exit makes its calls from the kernel: no entry registers.
        let mut regs = cpu::PtRegs::default();
        let mut context = Syscall {
            own: &mut local.own,
            shared: Shared::default(),
            regs: &mut regs,
            sink: ConsoleSink,
        };
        syscall::mm_release(&mut context);
        if let Some(process) = context.shared.guard.as_mut() {
            wake_sleepers(process);
        }
    }
    // The task state leaves its slot: nothing can reach it after this.
    let Some(boxed) = take_local(slot) else {
        crate::log!("FAIL exiting task has no state slot={}\n", slot);
        crate::fail();
    };
    let mut own = into_own(boxed);
    // exit_mm: CR3 moves to the kernel tree before the user tree is freed.
    let kernel = KERNEL_ROOT.load(Ordering::Acquire);
    // SAFETY: `kernel` is the root of the kernel-only tree kept in
    // `services::TABLES` from `start` on (never freed); IF=0 on the BSP; the
    // kernel half it maps is the published one, so this code, the stack and
    // the heap stay mapped; no PCID or global translations exist.
    unsafe { cpu::activate_tables(kernel) };
    ktask::set_current_cr3(kernel);
    let mut shared = PROCESS.lock();
    let tgid = own.tgid.cast_signed();
    exit_mm(&mut shared, &mut own, group_dead.then_some(tgid));
    // exit_files / exit_fs: the descriptors and the root and working directory, when this was
    // the last task to use them.
    exit_files_fs(&mut shared, &own);
    // The address space, descriptors and filesystem context are gone for /proc when the last
    // thread of the group is.
    if group_dead {
        shared.vfs.fs.ns.proc.exit(tgid);
    }
    // `disassociate_ctty(1)` of a session leader (after `exit_files`, before
    // `exit_notify`), and the tty's last close if this exit was it.
    exit_tty(&mut shared, own.me, group_dead);
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
    if tasks.exit_notify(own.me, group_dead, wake).is_err() {
        crate::log!("FAIL exit_notify refused a task that was exiting\n");
        crate::fail();
    }
    drop(shared);
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
        let mut context = Syscall {
            own: &mut local.own,
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
        let own = &mut local.own;
        let mut process = PROCESS.lock();
        // `get_signal`'s `SIGNAL_CLD_MASK` step: a task that woke from a stop
        // owes its parent the continue notification.
        {
            let Process { tasks, wake, .. } = &mut *process;
            tasks.notify_job_control(own.me, wake);
        }
        // Nothing to expire or dequeue: skip the clock read (`now_ns` is only
        // used when a pending SIGALRM leaves the queue).
        let due = {
            let state = current_signals(&mut process.tasks, own.me);
            state.sig.itimer.next_event().is_some() || state.signal_pending()
        };
        if due {
            // `it_real_fn` sends the group's `SIGALRM` to its leader, whichever thread looks.
            let Process { tasks, wake, .. } = &mut *process;
            tasks.sync_timers(own.me, timer::ktime_get_ns(), wake);
        }
        let pending = current_signals(&mut process.tasks, own.me).signal_pending()
            || core::mem::take(&mut after_stop);
        if pending {
            let outcome = {
                let (mut state, mut pages) = FaultPages::of(&mut process, own);
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
                    // A thread that was told to join a stop in progress stops with the others.
                    let joined = current_signals(&mut process.tasks, own.me).me.jobctl
                        & signal::jobctl::JOBCTL_STOP_PENDING
                        != 0;
                    if sig != SIGSTOP && !joined && process.tasks.is_pgrp_orphaned(own.me) {
                        after_stop = true;
                        continue;
                    }
                    let me = own.me;
                    let Process { tasks, wake, .. } = &mut *process;
                    if let StopPlan::Stop { fatal } = tasks.signal_stop(me, sig, wake) {
                        let _ = publish(&mut process, own);
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
        let own = &mut local.own;
        let mut process = PROCESS.lock();
        if vector == 14 {
            page_fault(&mut process, own, regs, error, address)
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
    let MmStruct { space, exec, .. } = process.mm_ref(task.mm);
    let Some(region) = FileRegion::of(space, ip) else {
        // A private /dev/zero VMA keeps no `vm_file` here but Linux prints
        // ` in zero[...]` for it: once one was made, an anonymous `ip` cannot
        // be told from it.
        if process.vfs.zero_mapped() && space.find_vma(ip).is_some_and(|vma| vma.start <= ip) {
            crate::log!(
                "FAIL mm user fault in an anonymous mapping after a /dev/zero mapping ip={:#x} (vm_file of mmap_zero not kept)\n",
                ip
            );
            crate::fail();
        }
        return None;
    };
    if space.find_vma(ip).and_then(|vma| vma.file) != Some(*exec) {
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
    own: &mut Owned,
    regs: &cpu::PtRegs,
    error: u64,
    address: u64,
) -> bool {
    let ip = regs.ip;
    let Process { vfs, mms, .. } = &mut *process;
    let MmStruct {
        tables,
        space,
        env,
        pin_owner,
        ..
    } = must(mms, own.mm);
    // `access_error` consults the task's `PKRU` before it populates anything.
    let env = Env {
        pkru: fpu::read_pkru(),
        ..*env
    };
    let outcome = user_fault(
        space,
        &env,
        vfs,
        *pin_owner,
        tables,
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

/// The address space of the self-test's task, for a short look.
#[cfg(all(feature = "boot-proofs", not(feature = "baremetal-suite")))]
fn with_mm<R>(context: &mut Syscall<'_>, f: impl FnOnce(&mut MmStruct) -> R) -> R {
    let id = context.own.mm;
    f(context.shared.get().mm(id))
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
    let before = with_mm(context, |mm| mm.tables.user_space().raw_entry(a + P));
    crate::require(
        call(context, Sysno::mprotect, [a, 2 * P, PROT_NONE, 0, 0, 0]) == 0,
        "mm-usercopy-protnone",
    );
    crate::require(
        paging::UserSpace::protnone_guard(
            before,
            with_mm(context, |mm| mm.tables.user_space().raw_entry(a + P)),
        ),
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
        with_mm(context, |mm| {
            let space = mm.tables.user_space();
            space.lookup(a) != Pte::Absent && space.lookup(a + P) != Pte::Absent
        }),
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
        with_mm(context, |mm| {
            let space = mm.tables.user_space();
            space.lookup(a) == Pte::Absent && space.lookup(a + P) == Pte::Absent
        }),
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
        with_mm(context, |mm| {
            let space = mm.tables.user_space();
            space.lookup(a) == Pte::Anon { writable: true }
                && space.lookup(a + P) == Pte::Anon { writable: true }
        }),
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
        zeros == [0; 8] && with_mm(context, |mm| mm.tables.user_space().lookup(b)) == Pte::ZeroPage,
        "mm-usercopy-zero-page",
    );
    crate::require(copy_to_user(context, b, &[1]) == 1, "mm-usercopy-readonly");
    crate::require(
        with_mm(context, |mm| mm.tables.user_space().lookup(b)) == Pte::ZeroPage,
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
    let own = &mut local.own;
    let data_frames = |table_pages: usize| services::FRAMES.lock().allocated() - table_pages;
    let (pages0, vm0) = {
        let process = PROCESS.lock();
        let mm = process.mm_ref(own.mm);
        (mm.tables.pages, mm.space.total_vm)
    };
    let frames0 = data_frames(pages0);
    // The self-test makes its calls from the kernel: no entry registers.
    let mut regs = cpu::PtRegs::default();
    let mut context = Syscall {
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
    let top = with_mm(&mut context, |mm| {
        mm.space
            .vmas()
            .iter()
            .find(|vma| vma.flags.intersects(VmFlags::GROWSDOWN))
            .map(|vma| vma.start)
    });
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
        with_mm(&mut context, |mm| {
            mm.space
                .find_vma(grown)
                .is_some_and(|vma| vma.start == grown && vma.flags.intersects(VmFlags::GROWSDOWN))
                && mm.tables.user_space().lookup(grown) == (Pte::Anon { writable: true })
        }),
        "mm-usercopy-stack-vma-grown",
    );
    let (pages_now, vm_now) = with_mm(&mut context, |mm| (mm.tables.pages, mm.space.total_vm));
    drop(context);
    crate::require(
        data_frames(pages_now) == frames0 + 1 && vm_now == vm0 + 1,
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
/// suite keeps heap copies (`baremetal::retain_archives`). Module 0 is the
/// harness archive every group unpacks; module 1, the `busybox` group's program
/// and data files, is unpacked for that group only, as the oracle's own boots do:
/// its `/bin`, `/bb` and `/tmp` would change the root directory that `fs.stat-root`
/// and `fs.getdents-root-order` of the other groups compare with the pinned Linux's.
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
    let wanted = if group == "busybox" {
        archives.len()
    } else {
        1
    };
    for (index, bytes) in archives.iter().enumerate().take(wanted) {
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
            let TaskLocal { own } = *local;
            // An address space made for an `execve` that did not happen.
            if let Some(pending) = own.pending_mm {
                destroy_tables(pending.tables);
            }
        }
    }
    // The address space of every task that is left (`exit_mmap`).
    if let Some(mut process) = process {
        loop {
            let next = process.mms.iter().next().map(|(id, _)| id);
            let Some(mm) = next.and_then(|id| process.mms.remove(id)) else {
                break;
            };
            destroy_tables(mm.tables);
        }
    }
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
    let attrs = Attributes::init();
    let init_fs = init.vfs.new_fs_struct(0o022);
    let max_threads = task::max_threads(managed_pages);
    let (tasks, me) = crate::unwrap(
        Tasklist::new(
            u32::try_from(max_threads).unwrap_or(u32::MAX),
            &attrs.cred,
            Rlimits::init(max_threads),
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
    // One waiter per scheduler slot at most (`futex_wait`), as the queue sizes itself.
    let futex = crate::unwrap(
        Futexes::new(ktask::SLOTS).map_err(|_| "out of memory"),
        "futex-queues",
    );
    let cr3 = tables.root_address();
    let mut mms = Arena::new();
    let mut files_structs = Arena::new();
    let mut fs_structs = Arena::new();
    let mut groups = Vec::new();
    crate::unwrap(
        groups.try_reserve_exact(1).map_err(|_| "out of memory"),
        "init-groups",
    );
    let _ = groups.push_within_capacity(1);
    let (mm_id, files_id, fs_id) = {
        let made = (
            mms.try_insert(MmStruct {
                tables,
                space: init.mm,
                env: init.env,
                exe_file: init.exec,
                exec: u64::from(init.exec.index()),
                pin_owner: next_pin_owner(),
                users: 1,
                groups,
            }),
            files_structs.try_insert(FilesStruct { fdt, users: 1 }),
            fs_structs.try_insert(FsShared {
                fs: init_fs,
                users: 1,
            }),
        );
        let (Ok(mm), Ok(files), Ok(fs)) = made else {
            crate::log!("FAIL init's shared objects: out of memory\n");
            crate::fail();
        };
        (mm, files, fs)
    };
    PROCESS.install(Process {
        tasks,
        wake: SchedWaker,
        vfs: init.vfs,
        tty,
        printk_ratelimit: RateLimit::printk(kernel::time::HZ),
        futex,
        futex_wake: SchedFutexWaker,
        mms,
        files_structs,
        fs_structs,
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
            own: Owned {
                me,
                sched: SchedId::from_raw(0),
                tgid: 1,
                tid: 1,
                attrs,
                restart: RestartBlock::NONE,
                mm: mm_id,
                files: files_id,
                fs: fs_id,
                vfork_parent: None,
                pending_mm: None,
                set_child_tid: 0,
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
            let owner = process.mm_ref(local.own.mm).pin_owner;
            process.vfs.pin(owner, u64::from(init.exec.index()));
            // init's first view for /proc.
            let _ = publish(&mut process, &local.own);
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
