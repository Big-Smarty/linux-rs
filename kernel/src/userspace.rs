// SPDX-License-Identifier: GPL-2.0-only
//! Freestanding half of the first-userspace exec path (decision A18): it owns
//! the frames and the page tables, feeds them from the pure plan in `exec`,
//! then runs init: ring-3 entry, the syscall and exception handlers called by
//! `cpu.rs`, and init's death.
//!
//! State used after ring 3 starts lives in statics (`PROCESS` here, `BOOT`,
//! `FRAMES` and `TABLES` in `services`), never in `kernel_main`'s frame, whose
//! stack is reused as init's kernel stack.
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

use crate::{
    boot::{BootError, BootInfo},
    console, cpu,
    memory::{Error as MemoryError, PAGE, PAGE_BYTES, Physical},
    paging::{self, Tables, UserSpace},
    services::{self, Service},
    timer,
};
use alloc::{boxed::Box, vec::Vec};
use core::{
    arch::x86_64::{__cpuid, _rdrand64_step, _rdtsc},
    iter,
};
use kernel::{
    cputime::{CpuAccount, CpuSample},
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
    ratelimit::RateLimit,
    signal::{
        self, State,
        deliver::{self, Outcome as SignalOutcome},
        frame::Sigreturn,
        info,
    },
    syscall::{
        self, AddressSpace, ClockState, Clocks, Console, Context, Files, Machine, Outcome,
        RestartBlock,
    },
    task::{self, Attributes},
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
/// pages live in the tables, which belong in `services::TABLES` before ring 3.
pub struct Loaded {
    /// The unpacked rootfs; moves into [`Process`] when init starts.
    pub vfs: Vfs,
    /// The open file `/init` was read from (`bprm->file`); the VMAs of its
    /// segments pin it when init starts; the reference itself then stays as
    /// the process's `mm->exe_file` ([`Process::exec`]).
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
pub fn load(boot: &BootInfo, tables: &mut Tables) -> Result<Loaded, Error> {
    let (vfs, compressed) = build_rootfs(boot)?;
    let fallback = first_fallback(&vfs);
    match load_init(boot, vfs, tables) {
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
fn build_rootfs(boot: &BootInfo) -> Result<(Vfs, Option<usize>), Error> {
    // shmem_default_max_blocks / _max_inodes: both half the RAM's pages
    // (`min3(nr_pages - totalhigh, nr_pages / 2, ...)` for the inodes).
    let pages = services::FRAMES.lock().total() as u64;
    let mut vfs = Vfs::new(pages / 2, pages / 2, early_clock).map_err(Error::Vfs)?;
    let mut compressed = None;
    vfs.default_rootfs().map_err(Error::Vfs)?;
    let mut unpacker = Unpacker::new();
    for index in 0..boot.module_count() {
        let span = boot.module_span(index)?;
        // SAFETY: trusted initialized immutable file storage, BSP only, no
        // DMA/AP/firmware writer or reclaim, loader CR3 still active (`load`
        // runs before the owned tables are activated). The borrow ends within
        // this iteration; the unpacker copies what it keeps.
        let bytes = unsafe { boot.module_bytes(span) }?;
        if let Some(message) = unpacker.unpack(&mut vfs, bytes) {
            // CONFIG_BLK_DEV_RAM=n (`do_populate_rootfs`): the unpacker's own
            // message; the entries before the failure stay in the tree.
            if message == vfs::initramfs::NOT_PORTED {
                compressed.get_or_insert(index);
                crate::log!("WARN module={}: {}\n", index, message);
            } else {
                crate::log!("Initramfs unpacking failed: {}\n", message);
            }
        }
    }
    Ok((vfs, compressed))
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

fn load_init(boot: &BootInfo, mut vfs: Vfs, tables: &mut Tables) -> Result<Loaded, Error> {
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
    tables.init_zero_page(&mut services::FRAMES.lock())?;
    let env = Env::init(total_pages, 0);
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
    let argv = InitArgv::parse(boot.command_line())?;
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
        exec,
        entry: plan.entry,
        sp: built.sp,
        loads: plan.segments().len(),
        argc: built.argc,
        mm,
        env,
    })
}

/// The one process: what the syscall and fault paths need once init runs
/// (frames, boot info and the heap are in `services`/`kalloc`). Later syscall
/// groups extend it (file table, credentials, signals, ...); exactly one is
/// reachable until tasks exist.
///
/// Lock order: `PROCESS` -> `TABLES` -> heap -> `FRAMES` (`services`), and
/// `PROCESS` -> `TIMER_HW` (a leaf, taken by `sleep_until`'s timer wait). The
/// handler holds `PROCESS` for the whole syscall (a single task cannot
/// re-enter), so a field needs no lock of its own.
pub struct Process {
    /// Task id; `pid == tgid` for the single-threaded init.
    pub pid: u32,
    /// Thread-group id: what `getpid` reports.
    pub tgid: u32,
    /// The address space (`mm`): the published page tables.
    pub mm: &'static Service<Tables>,
    /// Credentials, rlimits, filesystem context, comm, personality and the
    /// user pointers libc registers (`task::Attributes`, the identity group).
    pub attrs: Attributes,
    /// Load-average state at init start; `sysinfo` replays it to the boot
    /// clock ([`LoadAvg::loads_at`]), so there is no tick hook and no lock.
    pub load: LoadAvg,
    /// `current->restart_block.nanosleep`, written by the sleeping syscalls and
    /// run by `restart_syscall`.
    pub restart: RestartBlock,
    /// The VMA set, program break and statistics (`mm_struct`); the page
    /// tables are behind `mm`. It reserves its `Vec` storage (heap) before any
    /// `FRAMES` guard is taken (`services`).
    pub space: Mm,
    /// The rlimits and sysctls the mapping rules read (`Env`).
    /// shortcut: fixed `INIT_RLIMITS`; `setrlimit`/`prlimit64` must update it
    /// (or derive it from the credentials group's limits) when they land.
    pub env: Env,
    /// `FileInfo::id` of the open description `/init` was loaded from
    /// (`mm->exe_file`): the only file whose name the fault report knows.
    pub exec: u64,
    /// The mounted rootfs, open files and pipes.
    /// shortcut: one process, so the system-wide VFS lives here; with tasks it
    /// becomes its own service (lock class `vfs` between `PROCESS` and `TABLES`).
    pub vfs: Vfs,
    /// `current->files`.
    pub fdt: FdTable,
    /// `sighand` + `signal_struct` + the task's signal fields (the pure model
    /// in `kernel::signal`), boxed because the two pending queues are ~16 KiB.
    pub signal: Box<State>,
    /// `printk_ratelimit_state`: the limiter of the `show_unhandled_signals`
    /// lines (global in Linux; one process here).
    printk_ratelimit: RateLimit,
}

static PROCESS: Service<Process> = Service::new();

/// `nr_running + nr_uninterruptible` of the one CPU: init is always runnable
/// (running or preempted by the tick) because no syscall blocks yet and the
/// kernel never halts while init exists.
/// shortcut: a constant, though `nanosleep`/`clock_nanosleep` now sleep (Linux
/// counts a sleeping task in neither `nr_running` nor `nr_uninterruptible`, so
/// `sysinfo` loads over-count while init sleeps); replace with the runqueue's
/// counters when a second task or a blocking syscall (futex, wait4, I/O) exists.
const NR_ACTIVE: i64 = 1;

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

/// CPU-time accounting of the (only) task. Lives outside `PROCESS` because the
/// tick interrupt writes it while a syscall holds the `PROCESS` lock; it is all
/// atomics (`cputime`). shortcut: one task; moves into the task struct with the
/// scheduler.
static CPUTIME: CpuAccount = CpuAccount::new();

/// The tick found init running (`user`: in ring 3, else in the kernel on its
/// behalf) for `periods` ticks; called from the timer interrupt.
pub fn account_ticks(user: bool, periods: u64) {
    CPUTIME.tick(user, periods);
}

/// Ring-3 page faults the address-space model resolved (`page_fault`); the
/// self-test build reports it when init exits, as evidence that demand paging
/// of init's own bss/stack through the real tables returned to user mode.
#[cfg(feature = "qemu-self-test")]
static USER_FAULTS_HANDLED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Syscall context: the process plus its user-memory view (a borrow of the
/// locked tables, so no map/unmap can run mid-syscall), the entry registers
/// and the console.
struct Syscall<'a> {
    process: &'a mut Process,
    space: UserSpace<'a>,
    regs: &'a mut cpu::PtRegs,
    tty: Tty,
}

/// `handle_mm_fault` for one user address: the model's decision, and for a
/// page of a private file mapping (`NeedsFile`) `shmem_fault` + `do_cow_fault`:
/// a private frame holding the file page ([`Vfs::fault_page`]; `SIGBUS` past
/// `i_size`), mapped with the VMA's protection.
fn user_fault(
    mm: &mut Mm,
    env: &Env,
    vfs: &mut Vfs,
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
    match vfs.fault_page(file, pgoff, &mut bytes) {
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
/// access). No lock is held across the fault that is not already held by the
/// syscall (`PROCESS`, `TABLES`): the handler takes neither again and only
/// `FRAMES` (a leaf) below them.
///
/// It borrows the fields of [`Process`] the fault needs, so the signal code
/// (frame writes, `rt_sigreturn`, the signal syscalls) can hold it next to
/// `&mut process.signal`; [`Syscall`]'s own [`UserPages`] is the same view.
struct FaultPages<'a, 'b> {
    mm: &'a mut Mm,
    env: &'a Env,
    vfs: &'a mut Vfs,
    space: &'a mut UserSpace<'b>,
}

impl<'a, 'b> FaultPages<'a, 'b> {
    fn of(process: &'a mut Process, space: &'a mut UserSpace<'b>) -> (&'a mut State, Self) {
        (
            &mut *process.signal,
            Self {
                mm: &mut process.space,
                env: &process.env,
                vfs: &mut process.vfs,
                space,
            },
        )
    }

    /// `page` by value: the returned borrow lives as long as the view's.
    fn into_page(self, page: u64, write: bool) -> Option<&'a mut [u8; PAGE_BYTES]> {
        if !self.space.resident(page, write) {
            // Present-but-read-only (write) is `X86_PF_PROT`, an absent page is
            // not; the model's decision does not depend on it for a write.
            let error = if write { PF_WRITE } else { 0 };
            match user_fault(self.mm, self.env, self.vfs, self.space, page, error) {
                FaultOutcome::Handled => {}
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
            space: &mut *self.space,
        }
        .into_page(page, write)
    }
}

impl UserPages for Syscall<'_> {
    fn page(&mut self, page: u64, write: bool) -> Option<&mut [u8; PAGE_BYTES]> {
        FaultPages {
            mm: &mut self.process.space,
            env: &self.process.env,
            vfs: &mut self.process.vfs,
            space: &mut self.space,
        }
        .into_page(page, write)
    }
}

impl Context for Syscall<'_> {
    fn console(&mut self) -> &mut dyn Console {
        &mut self.tty
    }
    fn tgid(&self) -> u32 {
        self.process.tgid
    }
    fn tid(&self) -> u32 {
        self.process.pid
    }
    fn attrs(&mut self) -> &mut Attributes {
        &mut self.process.attrs
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
    fn machine(&self) -> Machine {
        // `ktime_get_boottime_ns` is the boot clock `do_sysinfo` reads.
        let uptime_ns = crate::timer::ktime_get_boottime_ns();
        // Lock order: `FRAMES` is the leaf below `PROCESS` -> `TABLES` -> heap.
        // The load averages take no lock: they are replayed from `Process::load`.
        let frames = services::FRAMES.lock();
        Machine {
            uptime_ns,
            total_pages: frames.total() as u64,
            free_pages: frames.available() as u64,
            loads: self.process.load.loads_at(jiffies_of(uptime_ns), NR_ACTIVE),
        }
    }
    fn address_space(&mut self) -> AddressSpace<'_> {
        AddressSpace {
            mm: &mut self.process.space,
            env: &self.process.env,
            pages: &mut self.space,
        }
    }
    fn files(&mut self) -> Files<'_> {
        let process = &mut *self.process;
        Files {
            vfs: &mut process.vfs,
            fdt: &mut process.fdt,
            fs: &mut process.attrs.fs,
        }
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
        self.process.restart = block;
    }
    fn restart_block(&self) -> RestartBlock {
        self.process.restart
    }
    fn cpu_sample(&self) -> CpuSample {
        CPUTIME.sample(timer::ktime_get_ns())
    }
    fn cpu_adjusted(&mut self) -> (u64, u64) {
        CPUTIME.adjusted(timer::ktime_get_ns())
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
    fn state(&mut self) -> &mut State {
        &mut self.process.signal
    }
    fn parts(&mut self) -> (&mut State, FaultPages<'_, 'a>) {
        FaultPages::of(self.process, &mut self.space)
    }
    fn now_ns(&self) -> u64 {
        timer::ktime_get_ns()
    }
    fn wait(&mut self, deadline_ns: Option<u64>) {
        // The task leaves the CPU for the wait (`schedule()`): the halted CPU is
        // idle time, not the task's.
        CPUTIME.sleep_begin(timer::ktime_get_ns());
        // The interval timer is a wake-up source of every sleep.
        timer::set_itimer_ns(self.process.signal.itimer.next_event());
        timer::wait_event(deadline_ns);
        CPUTIME.sleep_end(timer::ktime_get_ns());
    }
    fn user_sp(&self) -> u64 {
        self.regs.sp
    }
    fn rt_sigreturn(&mut self) -> Sigreturn {
        let (state, mut pages) = FaultPages::of(self.process, &mut self.space);
        let result =
            signal::frame::rt_sigreturn(state, self.regs, &mut pages, &mut cpu::UserCpu::new());
        // `restore_sigcontext`'s first statement: a pending restarted system
        // call now returns -EINTR; a frame refused before it resets nothing.
        if result.reached_sigcontext {
            self.process.restart = RestartBlock::NONE;
        }
        if result.bad_frame {
            // `signal_fault`: printed before the SIGSEGV is forced; `regs` are
            // whatever the failed `restore_sigcontext` left, as in Linux.
            if printk_ratelimit(self.process, "signal_fault") {
                let line = BadFrame {
                    ip: self.regs.ip,
                    sp: self.regs.sp,
                    orig_ax: self.regs.orig_ax,
                    region: region_of(self.process, self.regs.ip),
                };
                crate::log!("{}\n", line);
            }
        }
        result
    }
}

/// init's `/dev/console`: the same sinks as `log!`.
struct Tty;
impl Console for Tty {
    fn write(&mut self, bytes: &[u8]) {
        console::write_bytes(bytes);
    }
}

/// `kernel/exit.c`: init exiting for any reason panics. In a `qemu-self-test`
/// build the result mirrors the exit code; the default build halts.
fn init_died(code: u32) -> ! {
    #[cfg(feature = "qemu-self-test")]
    if code == 0 {
        crate::log!(
            "CHECK user-faults ok handled={}\n",
            USER_FAULTS_HANDLED.load(core::sync::atomic::Ordering::Relaxed)
        );
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
/// off and the CPU is on the `BOOT_STACK` top.
pub extern "C" fn syscall(regs: &mut cpu::PtRegs) {
    let args = [regs.di, regs.si, regs.dx, regs.r10, regs.r8, regs.r9];
    let number = regs.orig_ax;
    let outcome = {
        let mut process = PROCESS.lock();
        let mm = process.mm;
        let mut tables = mm.lock();
        let mut context = Syscall {
            space: tables.user_space(),
            process: &mut process,
            regs: &mut *regs,
            tty: Tty,
        };
        syscall::dispatch(&mut context, number, args)
    };
    match outcome {
        Outcome::Return(value) => regs.ax = value.cast_unsigned(),
        Outcome::Exit(code) => init_died(code),
        Outcome::Unimplemented(number) => {
            crate::log!("FAIL syscall unimplemented nr={}\n", number);
            crate::fail();
        }
        Outcome::Blocked(number) => {
            // Linux would sleep and nothing can wake the only task.
            crate::log!("FAIL syscall would block forever nr={}\n", number);
            crate::fail();
        }
    }
    exit_to_user(regs);
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
/// Context: interrupts masked, task context of the one process; takes
/// `PROCESS` then `TABLES` (the shared lock order). A fatal signal never
/// returns: init's death panics, as Linux's `do_exit` does for pid 1.
pub fn exit_to_user(regs: &mut cpu::PtRegs) {
    loop {
        let mut process = PROCESS.lock();
        // Nothing to expire or dequeue: skip the clock read (`now_ns` is only
        // used when a pending SIGALRM leaves the queue).
        if process.signal.itimer.next_event().is_some() || process.signal.signal_pending() {
            process.signal.sync_timers(timer::ktime_get_ns());
        }
        if process.signal.signal_pending() {
            let mm = process.mm;
            let mut tables = mm.lock();
            let mut space = tables.user_space();
            let (state, mut pages) = FaultPages::of(&mut process, &mut space);
            let outcome =
                deliver::handle_pending_signals(state, regs, &mut pages, &mut cpu::UserCpu::new());
            drop(tables);
            match outcome {
                // `handle_pending_signals` loops while a forced SIGSEGV is pending.
                SignalOutcome::Resume | SignalOutcome::Handled | SignalOutcome::FrameFailed => {}
                SignalOutcome::Exit { exit_code, .. } => {
                    drop(process);
                    init_died(exit_code);
                }
                SignalOutcome::Stop(sig) => {
                    crate::log!("FAIL signal stop unimplemented sig={}\n", sig);
                    crate::fail();
                }
            }
        }
        // Wake the CPU for the next interval-timer expiry while ring 3 runs.
        let expiry = process.signal.itimer.next_event();
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
fn printk_ratelimit(process: &mut Process, func: &str) -> bool {
    let jiffies = timer::ktime_get_ns() / kernel::time::TICK_NSEC;
    let verdict = process.printk_ratelimit.check(jiffies);
    if verdict.suppressed > 0 {
        crate::log!("{}: {} callbacks suppressed\n", func, verdict.suppressed);
    }
    verdict.allowed
}

/// `show_signal` / `show_signal_msg`: Linux prints the fault line when
/// `show_unhandled_signals && unhandled_signal(current, sig) && printk_ratelimit()`;
/// for the global init `unhandled_signal` is always true, handler or not.
/// `message` is whether this fault has a line at all (a page fault that ends in
/// `SIGSEGV`, or a vector with a `show_signal` message). The limiter allows ten
/// lines per five seconds and reports the suppressed ones when it re-opens.
/// shortcut: no `Code:` line (`show_opcodes`) after the `segfault at` line.
fn show_unhandled_signal(
    process: &mut Process,
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
    let func = if vector == 14 {
        "show_signal_msg"
    } else {
        "show_signal"
    };
    if !printk_ratelimit(process, func) {
        return;
    }
    let region = region_of(process, regs.ip);
    if vector == 14 {
        let line = Segfault {
            address,
            ip: regs.ip,
            sp: regs.sp,
            error,
            region,
        };
        crate::log!("{}\n", line);
    } else if let Some((kind, desc)) = message {
        let line = TrapLine {
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
        show_unhandled_signal(process, regs, vector, error, address);
    }
    process.signal.force_fault(&fault);
    true
}

/// The signal of a non-page-fault exception (`exc_*` in traps.c).
fn raise_fault(process: &mut Process, regs: &cpu::PtRegs, vector: u64, error: u64) -> bool {
    let vector8 = u8::try_from(vector).unwrap_or(u8::MAX);
    // #DB reports DR6 (cleared again, as `debug_read_clear_dr6`); #MF/#XM
    // read the saved FPU state (`fpu__exception_code`).
    let dr6 = if vector8 == info::X86_TRAP_DB {
        cpu::take_dr6()
    } else {
        0
    };
    let fpe = match vector8 {
        info::X86_TRAP_MF | info::X86_TRAP_XF => cpu::fpu_exception_code(vector8),
        _ => 0,
    };
    let fault = info::exception(vector8, error, regs.ip, dr6, fpe);
    fault.is_some_and(|fault| force(process, regs, fault, vector, error, 0))
}

/// Called by the IDT entry for an exception raised in ring 3: a page fault the
/// address-space model resolves retries the instruction, every other one
/// becomes a forced signal (default action: terminate, handlers run); the
/// return to ring 3 then delivers it. A vector that is not a plain user fault
/// (NMI, #DF, #MC, #NM, ...) is a kernel failure, never a user death.
pub fn exception(regs: &mut cpu::PtRegs, vector: u64, error: u64, address: u64) {
    let mut guard = PROCESS.lock();
    let raised = if vector == 14 {
        page_fault(&mut guard, regs, error, address)
    } else {
        raise_fault(&mut guard, regs, vector, error)
    };
    drop(guard);
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
}

/// `print_vma_addr`'s file part for `ip`: Linux prints the basename of the
/// VMA's file, and [`FileRegion`] knows only `init`. A fault in a VMA of any
/// other file would print a wrong name, so it stops loudly instead (also for a
/// possible `/dev/zero` mapping, see below).
/// shortcut: resolve the name from the description's dentry when a program
/// other than `/init` can run.
fn region_of(process: &Process, ip: u64) -> Option<FileRegion> {
    let Some(region) = FileRegion::of(&process.space, ip) else {
        // A private /dev/zero VMA keeps no `vm_file` here but Linux prints
        // ` in zero[...]` for it: once one was made, an anonymous `ip` cannot
        // be told from it.
        if process.vfs.zero_mapped()
            && process
                .space
                .find_vma(ip)
                .is_some_and(|vma| vma.start <= ip)
        {
            crate::log!(
                "FAIL mm user fault in an anonymous mapping after a /dev/zero mapping ip={:#x} (vm_file of mmap_zero not kept)\n",
                ip
            );
            crate::fail();
        }
        return None;
    };
    if process.space.find_vma(ip).and_then(|vma| vma.file) != Some(process.exec) {
        crate::log!(
            "FAIL mm user fault in a mapped file other than /init ip={:#x} (file name resolution not ported)\n",
            ip
        );
        crate::fail();
    }
    Some(region)
}

/// A page fault taken in ring 3 (`exc_page_fault` -> `do_user_addr_fault`).
/// Context: the faulting task, interrupts off, `PROCESS` held by the caller;
/// takes `TABLES` (-> heap, `FRAMES` inside). Returns `true`: the fault was
/// resolved or its signal is forced and delivered on the way out.
///
/// Outcomes and what Linux does (6.18.57, arch/x86/mm/fault.c):
/// * `Handled`: return to user, the instruction retries.
/// * `Segv`: `force_sig_fault(SIGSEGV, SEGV_MAPERR|SEGV_ACCERR, address)`; the
///   `init[1]: segfault at ...` line (`show_signal_msg`) is printed if the
///   signal then kills init.
/// * `Bus`: `do_sigbus` -> `force_sig_fault(SIGBUS, BUS_ADRERR, address)` (no
///   console line for `SIGBUS` itself).
/// * `Oom`, `PgtableBad`, `Vsyscall`: Linux runs the OOM killer (which finds
///   init unkillable and panics), oopses and kills the task, or emulates the
///   vsyscall page. None is implemented: a loud `FAIL mm ...` stop, never a
///   signal that did not happen.
/// * `NeedsFile` (a page of a private file mapping) is resolved by
///   [`user_fault`] into `Handled`, `Bus` or `Oom`.
fn page_fault(process: &mut Process, regs: &cpu::PtRegs, error: u64, address: u64) -> bool {
    let (ip, mm) = (regs.ip, process.mm);
    let mut tables = mm.lock();
    let mut space = tables.user_space();
    let outcome = user_fault(
        &mut process.space,
        &process.env,
        &mut process.vfs,
        &mut space,
        address,
        error | mm::PF_USER,
    );
    drop(tables);
    let kind = match outcome {
        FaultOutcome::Handled => {
            #[cfg(feature = "qemu-self-test")]
            USER_FAULTS_HANDLED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            return true;
        }
        FaultOutcome::Segv { code, address } => (info::PageFault::Segv(code as i32), address),
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
    force(process, regs, fault, 14, error, kind.1)
}

/// One system call through the dispatcher in the self-test (stops loudly on an
/// unimplemented number).
#[cfg(feature = "qemu-self-test")]
fn call(context: &mut Syscall<'_>, number: syscalls::Sysno, args: [u64; 6]) -> i64 {
    match syscall::dispatch(context, number as u64, args) {
        Outcome::Return(value) => value,
        _ => crate::unwrap(Err::<i64, _>("mm-usercopy-syscall"), "mm-usercopy"),
    }
}

/// `PROT_NONE` round trip of [`mm_usercopy_faults`] on pages `a` and `a + P`
/// (which hold `pattern` across their boundary).
#[cfg(feature = "qemu-self-test")]
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
#[cfg(feature = "qemu-self-test")]
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
#[cfg(feature = "qemu-self-test")]
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
#[cfg(feature = "qemu-self-test")]
fn check_mm_usercopy() {
    use kernel::mm::{
        MAP_ANONYMOUS, MAP_PRIVATE, PROT_NONE, PROT_READ, PROT_WRITE, Pte, UserPages as _, VmFlags,
    };
    use kernel::usercopy::{copy_from_user, copy_to_user};
    use syscalls::Sysno;

    const P: u64 = PAGE;
    let mut guard = PROCESS.lock();
    let mm = guard.mm;
    let mut tables = mm.lock();
    let data_frames = |tables: &Tables| services::FRAMES.lock().allocated() - tables.pages;
    let (frames0, vm0) = (data_frames(&tables), guard.space.total_vm);
    // The self-test makes its calls from the kernel: no entry registers.
    let mut regs = cpu::PtRegs::default();
    let mut context = Syscall {
        space: tables.user_space(),
        process: &mut guard,
        regs: &mut regs,
        tty: Tty,
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
        .process
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
            .process
            .space
            .find_vma(grown)
            .is_some_and(|vma| vma.start == grown && vma.flags.intersects(VmFlags::GROWSDOWN))
            && context.space.lookup(grown) == (Pte::Anon { writable: true }),
        "mm-usercopy-stack-vma-grown",
    );
    crate::require(
        data_frames(&tables) == frames0 + 1 && guard.space.total_vm == vm0 + 1,
        "mm-usercopy-accounting",
    );
    drop(tables);
    drop(guard);
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
    #[cfg(feature = "qemu-self-test")]
    {
        crate::log!("FAIL {}\n", label);
        cpu::exit(false);
    }
    #[cfg(not(feature = "qemu-self-test"))]
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
pub fn run(user: Result<Loaded, Error>) -> ! {
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

fn start(mut init: Loaded) -> ! {
    check_user_image(&init, &mut services::TABLES.lock().user_space());
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
    // SAFETY: as above; x87/SSE for ring 3 and Linux's initial FP state.
    crate::unwrap(unsafe { cpu::init_user_fpu() }, "user-fpu");
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
    let load = LoadAvg::new(jiffies_of(crate::timer::ktime_get_boottime_ns()));
    // The task starts running: `sum_exec_runtime` counts from here, and the tick
    // (masked after the boot proofs) runs again so user/system time accrues.
    CPUTIME.start(timer::ktime_get_ns());
    timer::resume_tick();
    // Timekeeping runs now: replace the placeholders of the unpack-time stamps,
    // then follow the real wall clock.
    init.vfs
        .start_timekeeping(timer::ktime_get_real, timer::ktime_get_real());
    // The segments' VMAs hold /init (`vm_file`). The loader's reference
    // (`bprm->file`) stays as `mm->exe_file` for the life of the process, so
    // `Process::exec` can never name a recycled description.
    crate::unwrap(init.vfs.reserve_pin(), "exec-pin");
    init.vfs.pin(u64::from(init.exec.index()));
    let mut fdt = FdTable::default();
    // console_on_rootfs: descriptors 0-2 are one /dev/console open file.
    if init.vfs.console_on_rootfs(&mut fdt).is_err() {
        crate::log!("Warning: unable to open an initial console.\n");
    }
    let mut attrs = Attributes::init(task::max_threads(managed_pages));
    attrs.fs = init.vfs.new_fs_struct(0o022);
    let signal = crate::unwrap(
        Box::try_new(State::new_init(task::max_threads(managed_pages) / 2))
            .map_err(|_| "out of memory"),
        "signal-state",
    );
    PROCESS.install(Process {
        pid: 1,
        tgid: 1,
        mm: &services::TABLES,
        attrs,
        load,
        restart: RestartBlock::NONE,
        space: init.mm,
        env: init.env,
        exec: u64::from(init.exec.index()),
        vfs: init.vfs,
        fdt,
        signal,
        printk_ratelimit: RateLimit::printk(kernel::time::HZ),
    });
    #[cfg(feature = "qemu-self-test")]
    check_mm_usercopy();
    // SAFETY: descriptors and syscall MSRs are installed above; the owned tree
    // is active and maps `entry` (executable) and `sp` (writable, user); all
    // state used by the syscall/fault paths is in `PROCESS` and `services`; `kernel_main`'s
    // frame is abandoned, its stack top is TSS.RSP0.
    unsafe { cpu::enter_user(entry, sp) }
}
