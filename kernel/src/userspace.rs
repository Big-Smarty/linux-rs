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
        find::{FindError, InitSearch},
        plan::{LoadError, LoadPlan, Vmas},
        report::{self, ExecFailed, InitDeath, NO_INIT, Segfault, TrapLine},
        stack::{self, ARG_PAGES, Aux, ENVP, EXPAND_PAGES, STACK_START, STACK_TOP, StackError},
    },
    image::cpio::FileType,
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
    let mut search = InitSearch::new();
    for index in 0..boot.module_count() {
        let span = boot.module_span(index)?;
        // SAFETY: trusted initialized immutable file storage, BSP only, no
        // DMA/AP/firmware writer or reclaim, loader CR3 still active (the
        // caller activates the owned tables only after we return). The borrow
        // ends within this iteration.
        let bytes = unsafe { boot.module_bytes(span) }?;
        search.scan(index, bytes).map_err(Error::HardLink)?;
    }
    let init = search.entry().ok_or(Error::NoInit)?;
    match init.kind {
        FileType::Regular => {}
        FileType::Symlink => return Err(Error::Symlink),
        // do_open_execat: only regular files execute.
        _ => return Err(Error::Exec(Errno::EACCES)),
    }
    // root passes DAC for exec only when some execute bit is set.
    if init.mode & 0o111 == 0 {
        return Err(Error::Exec(Errno::EACCES));
    }

    let span = boot.module_span(init.module)?;
    // SAFETY: as above; the slice and `file` end before this function returns.
    let module = unsafe { boot.module_bytes(span) }?;
    let file = module
        .get(init.offset..)
        .and_then(|rest| rest.get(..init.length))
        .ok_or(BootError::Address)?;
    let plan = LoadPlan::new(file)?;

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
    crate::log!(
        "CHECK userspace-image ok entry={:#x} sp={:#x} loads={} brk={:#x} argc={}\n",
        init.entry,
        init.sp,
        init.loads,
        init.brk,
        init.argc
    );
}

/// `init/main.c` `run_init_process` for the fallbacks after `/init` failed.
fn try_fallbacks() -> ! {
    for path in ["/sbin/init", "/etc/init", "/bin/init", "/bin/sh"] {
        crate::log!("Run {} as init process\n", path);
    }
    crate::log!("{}\n", NO_INIT);
    #[cfg(feature = "qemu-self-test")]
    {
        crate::log!("FAIL no-init\n");
        cpu::exit(false);
    }
    #[cfg(not(feature = "qemu-self-test"))]
    cpu::halt()
}

/// Start init, or end the boot the way Linux does when it cannot. Returns only
/// in a `qemu-self-test` build without any `/init` (see below).
///
/// shortcut: the pre-generated external QEMU fixtures carry no `/init`, and
/// their cases expect `RESULT success` after the bootstrap checkpoint, so that
/// one condition logs a warning and returns there. It must go once the
/// harness supplies `/init`: the default (physical) build already panics with
/// Linux's text.
pub fn run(user: Result<Loaded, Error>) {
    match user {
        Ok(init) => start(init),
        Err(Error::NoInit) => no_init(),
        Err(Error::Exec(errno) | Error::Load(LoadError::Errno(errno))) => {
            exec_failed(errno.into_raw());
        }
        Err(error) => {
            crate::log!("FAIL userspace error={:?}\n", error);
            crate::fail();
        }
    }
}

fn no_init() {
    #[cfg(feature = "qemu-self-test")]
    crate::log!("WARN userspace: no /init in any boot module, skipping ring 3\n");
    // Linux: `init_eaccess("/init")` fails, then the fallbacks.
    #[cfg(not(feature = "qemu-self-test"))]
    {
        crate::log!("check access for rdinit=/init failed: -2, ignoring\n");
        try_fallbacks()
    }
}

/// `kernel_init`: `Failed to execute /init (error N)` then the fallbacks.
fn exec_failed(errno: i32) -> ! {
    crate::log!("Run /init as init process\n");
    crate::log!("{}\n", ExecFailed(-errno));
    try_fallbacks()
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
