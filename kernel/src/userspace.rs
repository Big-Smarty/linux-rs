// SPDX-License-Identifier: GPL-2.0-only
//! Freestanding half of the first-userspace exec path (decision A18): it owns
//! the frames and the page tables, feeds them from the pure plan in `exec`,
//! then runs init: ring-3 entry, the syscall and exception handlers called by
//! `cpu.rs`, and init's death.
//!
//! State used after ring 3 starts lives in statics (`STATE`), never in
//! `kernel_main`'s frame, whose stack is reused as init's kernel stack.
//!
//! Context: BSP, interrupts off, before the owned CR3 is published. The module
//! payloads are only readable while the loader mapping epoch is active, so the
//! file bytes are copied into freshly allocated user frames here and no
//! payload borrow survives this function. Every table write precedes
//! `Tables::activate`, so the "all software table writes happen before CR3
//! publication" invariant of `paging` holds unchanged.
//!
//! shortcut: frames and tables of a failed load are not returned; any failure
//! is fatal for the boot (Linux panics when init cannot be started). Upgrade
//! when `execve` of a second process exists.
//! shortcut: the file's owner and setuid/setgid bits are ignored; init always
//! runs with uid/gid 0 and no secure-exec (a root-owned initramfs).

use crate::{
    boot::{BootError, BootInfo},
    console, cpu,
    memory::{Allocator, Error as MemoryError, PAGE, Physical},
    paging::{self, Tables, UserSpace},
};
use core::{
    arch::x86_64::{__cpuid, _rdrand64_step, _rdtsc},
    cell::UnsafeCell,
    iter,
};
use kernel::{
    exec::{
        args::{ArgsError, InitArgv, Word},
        find::{FindError, InitEntry, Search},
        plan::{LoadError, LoadPlan, Unsupported, Vmas},
        report::{
            self, ExecFailed, InitDeath, NO_INIT, NO_ROOT, NO_ROOT_PANIC, Segfault, TrapLine,
        },
        script,
        stack::{self, ARG_PAGES, Aux, ENVP, EXPAND_PAGES, STACK_START, STACK_TOP, StackError},
    },
    image::{cpio::FileType, elf::Elf},
    sync::RawSpinLock,
    syscall::{self, Console, Outcome},
    usercopy,
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

/// Everything later stages need once `/init` is mapped. Plain data apart from
/// the unique `UserSpace`; belongs in a static before ring 3 is entered.
pub struct Loaded {
    pub entry: u64,
    pub sp: u64,
    pub loads: usize,
    pub brk: u64,
    pub argc: u64,
    pub vmas: Vmas,
    pub space: UserSpace,
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

    for segment in plan.segments() {
        for page in 0..segment.pages() {
            let prot = segment.page_prot(page);
            if !prot.accessible() {
                continue; // PROT_NONE: accounted for, never present.
            }
            let mut frame = allocator.allocate()?;
            segment.fill_page(file, page, frame.bytes());
            let physical = frame.into_reserved();
            tables.map_user(
                allocator,
                segment.start + page * PAGE,
                physical,
                prot.write,
                prot.exec,
            )?;
        }
    }

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
    for page in 0..ARG_PAGES as u64 {
        let address = STACK_TOP - (ARG_PAGES as u64 - page) * PAGE;
        let physical = Physical(top.0 + page * PAGE);
        tables.map_user(allocator, address, physical, true, plan.exec_stack)?;
    }
    for page in 0..EXPAND_PAGES as u64 {
        let physical = allocator.allocate()?.into_reserved();
        tables.map_user(
            allocator,
            STACK_START + page * PAGE,
            physical,
            true,
            plan.exec_stack,
        )?;
    }

    Ok(Loaded {
        entry: plan.entry,
        sp: built.sp,
        loads: plan.segments().len(),
        brk: plan.brk,
        argc: built.argc,
        vmas: plan.vmas,
        // SAFETY: this is the only handle ever created, and no other reference
        // to a user frame exists (frames were handed to `map_user` as raw
        // physical addresses); the tree is published by the caller and kept.
        space: unsafe { tables.user_space() },
    })
}

/// What the syscall and fault paths need once init runs.
struct State {
    space: UserSpace,
    vmas: Vmas,
}

/// A `State` shared with entry code. Single CPU: the only accessors are the
/// syscall handler and the fatal exception handler, which cannot interleave
/// (a syscall runs with IF/TF cleared and ring 0 takes no user exception);
/// `LOCK` makes that explicit and keeps the access sound if that changes.
struct Shared(UnsafeCell<Option<State>>);
// SAFETY: every access goes through `with`/`install`, which hold `LOCK`.
unsafe impl Sync for Shared {}
static LOCK: RawSpinLock = RawSpinLock::new();
static STATE: Shared = Shared(UnsafeCell::new(None));

fn install(state: State) {
    let _owner = LOCK.lock();
    // SAFETY: `LOCK` is held, so this is the only access to the cell.
    unsafe { *STATE.0.get() = Some(state) };
}

fn with<R>(f: impl FnOnce(&mut State) -> R) -> Option<R> {
    let _owner = LOCK.lock();
    // SAFETY: `LOCK` is held, so this is the only access to the cell.
    unsafe { (*STATE.0.get()).as_mut().map(f) }
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
    let Some(outcome) =
        with(|state| syscall::dispatch(&mut state.space, &mut Tty, regs.orig_ax, args))
    else {
        crate::log!("FAIL syscall before init state\n");
        crate::fail();
    };
    match outcome {
        Outcome::Return(value) => regs.ax = value.cast_unsigned(),
        Outcome::Exit(code) => init_died(code),
        Outcome::Unimplemented(number) => {
            crate::log!("FAIL syscall unimplemented nr={}\n", number);
            crate::fail();
        }
    }
}

/// Called by the IDT entry for an exception raised in ring 3. Fatal to init:
/// no signal handler can exist yet, so the signal's default action (terminate)
/// runs, the exit code is the signal number, and init's death panics.
pub fn exception(vector: u64, error: u64, ip: u64, sp: u64, address: u64) -> ! {
    let Some(vmas) = with(|state| state.vmas) else {
        crate::log!("FAIL user exception before init state vector={}\n", vector);
        crate::fail();
    };
    if vector == 14 {
        let line = Segfault {
            address,
            ip,
            sp,
            error,
            vmas: &vmas,
        };
        crate::log!("{}\n", line);
        init_died(report::signal_exit_code(report::SIGSEGV));
    }
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
            vmas: &vmas,
        };
        crate::log!("{}\n", line);
    }
    init_died(report::signal_exit_code(signal.signal));
}

/// Exercise the one user-copy mechanism on the real owned tables.
fn check_user_image(init: &mut Loaded) {
    let mut word = [0u8; 8];
    crate::require(
        usercopy::copy_from_user(&mut init.space, &mut word, init.sp) == 0,
        "user-stack-readable",
    );
    crate::require(u64::from_le_bytes(word) == init.argc, "user-argc");
    // Writable-path walk: store the value that is already there.
    crate::require(
        usercopy::copy_to_user(&mut init.space, init.sp, &word) == 0,
        "user-stack-writable",
    );
    crate::require(
        usercopy::copy_from_user(&mut init.space, &mut word, STACK_START - 8) == 8
            && word == [0; 8],
        "user-below-stack-unmapped",
    );
    crate::require(
        usercopy::copy_from_user(&mut init.space, &mut word, usercopy::TASK_SIZE_MAX - 4) == 8,
        "user-range-limit",
    );
    crate::require(
        init.vmas.find(init.entry).is_some(),
        "user-entry-file-backed",
    );
    let audit = crate::unwrap(init.space.audit(), "user-isolation-audit");
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
        init.brk,
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

fn start(mut init: Loaded) -> ! {
    check_user_image(&mut init);
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
    install(State {
        space: init.space,
        vmas: init.vmas,
    });
    // SAFETY: descriptors and syscall MSRs are installed above; the owned tree
    // is active and maps `entry` (executable) and `sp` (writable, user); all
    // state used by the syscall/fault paths is in `STATE`; `kernel_main`'s
    // frame is abandoned, its stack top is TSS.RSP0.
    unsafe { cpu::enter_user(entry, sp) }
}
