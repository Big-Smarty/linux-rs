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

use crate::{
    boot::{BootError, BootInfo},
    console, cpu,
    memory::{Allocator, Error as MemoryError, PAGE, PAGE_BYTES, Physical},
    paging::{self, LoadSpace, Tables, UserSpace},
    services::{self, Service},
    timer,
};
use core::{
    arch::x86_64::{__cpuid, _rdrand64_step, _rdtsc},
    iter,
};
use kernel::{
    cputime::{CpuAccount, CpuSample},
    exec::{
        args::{ArgsError, InitArgv, Word},
        find::{FindError, InitEntry, Search},
        load::{exec_file, insert_stack, map_segments},
        plan::{LoadError, LoadPlan, Unsupported},
        report::{
            self, ExecFailed, FileRegion, InitDeath, NO_INIT, NO_ROOT, NO_ROOT_PANIC, Segfault,
            TrapLine,
        },
        script,
        stack::{self, ARG_PAGES, Aux, ENVP, STACK_START, STACK_TOP, StackError},
    },
    image::{cpio::FileType, elf::Elf},
    loadavg::LoadAvg,
    mm::{self, Env, FaultOutcome, Mm, PF_WRITE},
    syscall::{
        self, AddressSpace, ClockState, Clocks, Console, Context, Machine, Outcome, RestartBlock,
        RestartFn,
    },
    task::{self, Attributes},
    usercopy::{self, UserPages},
};
use syscalls::Errno;

pub const FILENAME: &[u8] = b"/init";
/// `allocate_order(2)` below backs exactly the argument pages.
const _: () = assert!(ARG_PAGES == 4);

pub enum Error {
    /// No archive provides `/init`: Linux ends in `NO_INIT`.
    NoInit,
    HardLink(FindError),
    /// `/init` is a symlink; resolving it is outside this slice.
    Symlink,
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
            Self::HardLink(error) => f.debug_tuple("HardLink").field(error).finish(),
            Self::Symlink => f.write_str("Symlink"),
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
pub fn load(
    boot: &BootInfo,
    allocator: &mut Allocator<'_>,
    tables: &mut Tables,
) -> Result<Loaded, Error> {
    let fallback = first_fallback(boot);
    match load_init(boot, allocator, tables) {
        Err(Error::Exec(errno) | Error::Load(LoadError::Errno(errno))) if fallback.is_some() => {
            Err(Error::Fallback {
                errno: errno.into_raw(),
                path: fallback.unwrap_or_default(),
            })
        }
        other => other,
    }
}

/// `kernel_init`'s fallbacks after a failed `/init` (init/main.c:1499-1502).
const FALLBACKS: [&[u8]; 4] = [b"/sbin/init", b"/etc/init", b"/bin/init", b"/bin/sh"];

/// The latest archive entry for `path`, across all boot modules.
fn locate(boot: &BootInfo, path: &[u8]) -> Result<Option<InitEntry>, Error> {
    let mut search = Search::new(path);
    for index in 0..boot.module_count() {
        let span = boot.module_span(index)?;
        // SAFETY: trusted initialized immutable file storage, BSP only, no
        // DMA/AP/firmware writer or reclaim, loader CR3 still active (callers
        // run before the owned tables are activated). The borrow ends within
        // this iteration.
        let bytes = unsafe { boot.module_bytes(span) }?;
        search.scan(index, bytes).map_err(Error::HardLink)?;
    }
    Ok(search.entry())
}

/// The first fallback init present in the archives; an untrackable entry
/// counts as present (it is reported, never silently skipped).
fn first_fallback(boot: &BootInfo) -> Option<&'static [u8]> {
    FALLBACKS
        .into_iter()
        .find(|path| !matches!(locate(boot, path), Ok(None)))
}

/// Why `exec` of a regular-file candidate fails before the ELF is read.
fn check_executable(entry: &InitEntry) -> Result<(), Error> {
    match entry.kind {
        FileType::Regular => {}
        FileType::Symlink => return Err(Error::Symlink),
        // do_open_execat: only regular files execute.
        _ => return Err(Error::Exec(Errno::EACCES)),
    }
    // root passes DAC for exec only when some execute bit is set.
    if entry.mode & 0o111 == 0 {
        return Err(Error::Exec(Errno::EACCES));
    }
    Ok(())
}

/// `load_script`: `-ENOENT` when the interpreter is not in the rootfs (what
/// `open_exec` returns), otherwise an explicit unsupported failure.
fn script_failure(boot: &BootInfo, interpreter: &[u8]) -> Error {
    interpreter_failure(boot, interpreter, Unsupported::Script)
}

/// The shared tail of `load_script` and `load_elf_binary`'s `PT_INTERP` scan:
/// `open_exec(interpreter)` fails `-ENOENT` (or the access error) exactly as
/// Linux does; an interpreter that exists is `unsupported`.
fn interpreter_failure(boot: &BootInfo, interpreter: &[u8], unsupported: Unsupported) -> Error {
    if interpreter.is_empty() {
        return Error::Exec(Errno::ENOENT);
    }
    match locate(boot, interpreter) {
        Ok(None) => Error::Exec(Errno::ENOENT),
        Ok(Some(entry)) => match check_executable(&entry) {
            Err(error) => error,
            Ok(()) => Error::Load(LoadError::Unsupported(unsupported)),
        },
        Err(error) => error,
    }
}

fn load_init(
    boot: &BootInfo,
    allocator: &mut Allocator<'_>,
    tables: &mut Tables,
) -> Result<Loaded, Error> {
    let init = locate(boot, FILENAME)?.ok_or(Error::NoInit)?;
    check_executable(&init)?;

    let span = boot.module_span(init.module)?;
    // SAFETY: as in `locate`; the slice and `file` end before this function returns.
    let module = unsafe { boot.module_bytes(span) }?;
    let file = module
        .get(init.offset..)
        .and_then(|rest| rest.get(..init.length))
        .ok_or(BootError::Address)?;
    match script::interpreter(file) {
        Err(errno) => return Err(Error::Exec(errno)),
        Ok(Some(interpreter)) => return Err(script_failure(boot, interpreter)),
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
            return Err(interpreter_failure(boot, path, Unsupported::Interpreter));
        }
        other => other?,
    };

    // The address space is built by the one mapping-rule mechanism (`mm`):
    // the shared zero page, the stack VMA, then every `PT_LOAD` (the loader
    // installs the file pages it owns as it goes). The model's vectors come
    // from the boot arena (`kalloc`): `FRAMES` does not exist yet.
    tables.init_zero_page(allocator)?;
    let env = Env::init(allocator.total() as u64, 0);
    let mut mm = Mm::new(&env);
    insert_stack(&mut mm, &env, plan.exec_stack)?;
    let mut space = LoadSpace {
        tables: &mut *tables,
        allocator: &mut *allocator,
    };
    map_segments(&plan, file, &exec_file(1), &mut mm, &env, &mut space)?;

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
    /// `current->restart_block.nanosleep`, written by the sleeping syscalls.
    #[allow(dead_code, reason = "read by restart_syscall (signal lane)")]
    pub restart: RestartBlock,
    /// The VMA set, program break and statistics (`mm_struct`); the page
    /// tables are behind `mm`. It reserves its `Vec` storage (heap) before any
    /// `FRAMES` guard is taken (`services`).
    pub space: Mm,
    /// The rlimits and sysctls the mapping rules read (`Env`).
    /// shortcut: fixed `INIT_RLIMITS`; `setrlimit`/`prlimit64` must update it
    /// (or derive it from the credentials group's limits) when they land.
    pub env: Env,
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

/// Syscall context: the process plus its user-memory view (a borrow of the
/// locked tables, so no map/unmap can run mid-syscall) and the console.
struct Syscall<'a> {
    process: &'a mut Process,
    space: UserSpace<'a>,
    tty: Tty,
}

/// A kernel access to a user page that is not resident takes the fault Linux
/// would: `exc_page_fault` -> `do_user_addr_fault` with the kernel-mode error
/// code (no `X86_PF_USER`) on a user address. A fault the model resolves is
/// retried (once: it must now succeed); any refusal is the exception-table
/// fixup, i.e. a short copy and `-EFAULT`, with no signal (`__bad_area_nosemaphore`
/// only signals in user mode; OOM, SIGBUS and the vsyscall page behave the
/// same for a kernel-mode access). A file page we cannot supply stops loudly.
/// No lock is held across the fault that is not already held by the syscall
/// (`PROCESS`, `TABLES`): the handler takes neither again and only `FRAMES`
/// (a leaf) below them.
impl UserPages for Syscall<'_> {
    fn page(&mut self, page: u64, write: bool) -> Option<&mut [u8; PAGE_BYTES]> {
        if !self.space.resident(page, write) {
            // Present-but-read-only (write) is `X86_PF_PROT`, an absent page is
            // not; the model's decision does not depend on it for a write.
            let error = if write { PF_WRITE } else { 0 };
            let process = &mut *self.process;
            match process
                .space
                .handle_user_fault(&process.env, &mut self.space, page, error)
            {
                FaultOutcome::Handled => {}
                FaultOutcome::NeedsFile { address, write } => {
                    crate::log!(
                        "FAIL mm unimplemented file-backed fault address={:#x} write={} (kernel access)\n",
                        address,
                        write
                    );
                    crate::fail();
                }
                _ => return None,
            }
        }
        self.space.page(page, write)
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
    fn cpu_sample(&self) -> CpuSample {
        CPUTIME.sample(timer::ktime_get_ns())
    }
    fn cpu_adjusted(&mut self) -> (u64, u64) {
        CPUTIME.adjusted(timer::ktime_get_ns())
    }
    fn sleep_until(&mut self, deadline_ns: u64) -> Option<u64> {
        // The task leaves the CPU for the wait (`schedule()`): the halted CPU is
        // idle time, not the task's. Nothing can interrupt the wait yet (no signals).
        CPUTIME.sleep_begin(timer::ktime_get_ns());
        timer::wait_until_ns(deadline_ns);
        CPUTIME.sleep_end(timer::ktime_get_ns());
        None
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
/// `regs.ax`. Interrupts are off and the CPU is on the `BOOT_STACK` top.
pub extern "C" fn syscall(regs: &mut cpu::PtRegs) {
    let args = [regs.di, regs.si, regs.dx, regs.r10, regs.r8, regs.r9];
    let mut process = PROCESS.lock();
    let mm = process.mm;
    let mut tables = mm.lock();
    let mut context = Syscall {
        space: tables.user_space(),
        process: &mut process,
        tty: Tty,
    };
    let outcome = syscall::dispatch(&mut context, regs.orig_ax, args);
    drop(tables);
    drop(process);
    match outcome {
        Outcome::Return(value) => regs.ax = value.cast_unsigned(),
        Outcome::Exit(code) => init_died(code),
        Outcome::Unimplemented(number) => {
            crate::log!("FAIL syscall unimplemented nr={}\n", number);
            crate::fail();
        }
    }
}

/// Called by the IDT entry for an exception raised in ring 3. A page fault
/// the address-space model resolves returns (the entry code `iretq`s to the
/// faulting instruction); everything else is fatal to init: no signal handler
/// can exist yet, so the signal's default action (terminate) runs, the exit
/// code is the signal number, and init's death panics.
pub fn exception(vector: u64, error: u64, ip: u64, sp: u64, address: u64) {
    if vector == 14 {
        page_fault(error, ip, sp, address);
        return;
    }
    let region = FileRegion::of(&PROCESS.lock().space, ip);
    let signal = u8::try_from(vector).ok().and_then(report::user_exception);
    let Some(signal) = signal else {
        crate::log!(
            "FAIL user exception vector={} error={:#x} rip={:#x}\n",
            vector,
            error,
            ip
        );
        crate::fail();
    };
    if let Some((kind, desc)) = signal.message {
        let line = TrapLine {
            kind,
            desc,
            ip,
            sp,
            error,
            region,
        };
        crate::log!("{}\n", line);
    }
    init_died(report::signal_exit_code(signal.signal));
}

/// A page fault taken in ring 3 (`exc_page_fault` -> `do_user_addr_fault`).
/// Context: the faulting task, interrupts off, no lock held (the fault came
/// from ring 3). Locks `PROCESS` -> `TABLES` (-> heap, `FRAMES` inside).
///
/// Outcomes and what Linux does (6.18.57, arch/x86/mm/fault.c) once signals
/// exist; until then the default action of the signal is carried out directly:
/// * `Handled`: return to user, the instruction retries.
/// * `Segv`: `force_sig_fault(SIGSEGV, SEGV_MAPERR|SEGV_ACCERR, address)` after
///   `show_signal_msg` (the `init[1]: segfault at ...` line); init has no
///   handler, so it dies with exit code 11.
/// * `Bus`: `do_sigbus` -> `SIGBUS` (no console line), exit code 7.
/// * `Oom`, `PgtableBad`, `Vsyscall`, `NeedsFile`: Linux runs the OOM killer
///   (which finds init unkillable and panics), oopses and kills the task,
///   emulates the vsyscall page, or reads the page cache. None is implemented:
///   a loud `FAIL mm ...` stop, never a signal that did not happen.
fn page_fault(error: u64, ip: u64, sp: u64, address: u64) {
    let mut guard = PROCESS.lock();
    let process = &mut *guard;
    let mut tables = process.mm.lock();
    let mut space = tables.user_space();
    let outcome =
        process
            .space
            .handle_user_fault(&process.env, &mut space, address, error | mm::PF_USER);
    drop(space);
    drop(tables);
    match outcome {
        FaultOutcome::Handled => {}
        FaultOutcome::Segv { address, .. } => {
            // Both refusals (MAPERR, ACCERR) print the same line; the code only
            // reaches siginfo, which no handler can read yet.
            let line = Segfault {
                address,
                ip,
                sp,
                error,
                region: FileRegion::of(&process.space, ip),
            };
            drop(guard);
            crate::log!("{}\n", line);
            init_died(report::signal_exit_code(report::SIGSEGV));
        }
        FaultOutcome::Bus { .. } => {
            drop(guard);
            init_died(report::signal_exit_code(report::SIGBUS));
        }
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
        FaultOutcome::NeedsFile { address, write } => {
            crate::log!(
                "FAIL mm unimplemented file-backed fault address={:#x} write={} ip={:#x}\n",
                address,
                write,
                ip
            );
            crate::fail();
        }
    }
}

/// QEMU proof of the kernel-access page-fault path through the real syscall
/// context, tables and frame allocator, without ring 3: the memory syscalls
/// create the mappings, then the one user-copy mechanism faults pages in
/// (`__do_page_fault` of a kernel access to user memory) with Linux's
/// short-copy results. Context: BSP, IF clear, `PROCESS` installed, no lock held.
#[cfg(feature = "qemu-self-test")]
fn check_mm_usercopy() {
    use kernel::mm::{
        MAP_ANONYMOUS, MAP_PRIVATE, PROT_NONE, PROT_READ, PROT_WRITE, Pte, UserPages as _,
    };
    use kernel::usercopy::{copy_from_user, copy_to_user};
    use syscalls::Sysno;

    const P: u64 = PAGE;
    let mut guard = PROCESS.lock();
    let mm = guard.mm;
    let mut tables = mm.lock();
    let data_frames = |tables: &Tables| services::FRAMES.lock().allocated() - tables.pages;
    let (frames0, vm0) = (data_frames(&tables), guard.space.total_vm);
    let mut context = Syscall {
        space: tables.user_space(),
        process: &mut guard,
        tty: Tty,
    };
    let mut call =
        |context: &mut Syscall<'_>, number: Sysno, args: [u64; 6]| match syscall::dispatch(
            context,
            number as u64,
            args,
        ) {
            Outcome::Return(value) => value,
            _ => crate::unwrap(Err::<i64, _>("mm-usercopy-syscall"), "mm-usercopy"),
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
        a % P == 0 && b % P == 0 && a < kernel::usercopy::TASK_SIZE_MAX,
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
    // A write across two untouched writable pages faults both in (write fault
    // on an absent page: a private zeroed frame each), then reads them back.
    let pattern = [1u8, 2, 3, 4, 5, 6, 7, 8];
    crate::require(
        copy_to_user(&mut context, a + P - 4, &pattern) == 0,
        "mm-usercopy-write",
    );
    let mut back = [0u8; 8];
    crate::require(
        copy_from_user(&mut context, &mut back, a + P - 4) == 0,
        "mm-usercopy-read",
    );
    crate::require(back == pattern, "mm-usercopy-readback");
    crate::require(
        context.space.lookup(a) == Pte::Anon { writable: true }
            && context.space.lookup(a + P) == Pte::Anon { writable: true },
        "mm-usercopy-private-frames",
    );
    // A read of an untouched readable page maps the shared zero page; a write
    // to that read-only mapping is refused (EFAULT: nothing copied) and keeps it.
    let mut zeros = [0xffu8; 8];
    crate::require(
        copy_from_user(&mut context, &mut zeros, b) == 0,
        "mm-usercopy-zero-read",
    );
    crate::require(
        zeros == [0; 8] && context.space.lookup(b) == Pte::ZeroPage,
        "mm-usercopy-zero-page",
    );
    crate::require(
        copy_to_user(&mut context, b, &[1]) == 1,
        "mm-usercopy-readonly",
    );
    crate::require(
        context.space.lookup(b) == Pte::ZeroPage,
        "mm-usercopy-readonly-kept",
    );
    // The PROT_NONE page after the writable ones: the copy stops at the hole
    // (bytes before it are copied, the rest is reported), and a read of the
    // hole alone copies nothing and zero-fills the destination.
    crate::require(
        copy_to_user(&mut context, a + 2 * P - 2, &[9; 6]) == 4,
        "mm-usercopy-short-write",
    );
    let mut tail = [0xffu8; 6];
    crate::require(
        copy_from_user(&mut context, &mut tail, a + 2 * P - 2) == 4,
        "mm-usercopy-short-read",
    );
    crate::require(tail == [9, 9, 0, 0, 0, 0], "mm-usercopy-short-read-bytes");
    let mut hole = [0xffu8; 8];
    crate::require(
        copy_from_user(&mut context, &mut hole, a + 2 * P) == 8,
        "mm-usercopy-hole",
    );
    crate::require(hole == [0; 8], "mm-usercopy-hole-zeroed");
    crate::require(
        copy_to_user(&mut context, a + 2 * P, &[1]) == 1,
        "mm-usercopy-hole-write",
    );
    // An address above TASK_SIZE_MAX is refused by the range check, not faulted.
    crate::require(
        copy_to_user(&mut context, kernel::usercopy::TASK_SIZE_MAX - 1, &[1, 2]) == 2,
        "mm-usercopy-range",
    );
    crate::require(
        call(&mut context, Sysno::munmap, [a, 3 * P, 0, 0, 0, 0]) == 0,
        "mm-usercopy-munmap-a",
    );
    crate::require(
        call(&mut context, Sysno::munmap, [b, P, 0, 0, 0, 0]) == 0,
        "mm-usercopy-munmap-b",
    );
    drop(context);
    crate::require(
        data_frames(&tables) == frames0 && guard.space.total_vm == vm0,
        "mm-usercopy-accounting",
    );
    drop(tables);
    drop(guard);
    crate::log!(
        "CHECK mm-usercopy ok fault_in=read,write short_write=4 hole=8 readonly=refused zero_page=shared range=refused unmap=restored\n"
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

fn start(init: Loaded) -> ! {
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
    PROCESS.install(Process {
        pid: 1,
        tgid: 1,
        mm: &services::TABLES,
        attrs: Attributes::init(task::max_threads(managed_pages)),
        load,
        restart: RestartBlock {
            func: RestartFn::None,
            clockid: 0,
            expires_ns: 0,
            rmtp: 0,
        },
        space: init.mm,
        env: init.env,
    });
    #[cfg(feature = "qemu-self-test")]
    check_mm_usercopy();
    // SAFETY: descriptors and syscall MSRs are installed above; the owned tree
    // is active and maps `entry` (executable) and `sp` (writable, user); all
    // state used by the syscall/fault paths is in `PROCESS` and `services`; `kernel_main`'s
    // frame is abandoned, its stack top is TSS.RSP0.
    unsafe { cpu::enter_user(entry, sp) }
}
