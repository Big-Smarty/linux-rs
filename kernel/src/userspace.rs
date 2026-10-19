// SPDX-License-Identifier: GPL-2.0-only
//! Freestanding half of the first-userspace exec path (decision A18): it owns
//! the frames and the page tables, and feeds them from the pure plan in
//! `exec`. Nothing here enters ring 3.
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
    memory::{Allocator, Error as MemoryError, PAGE, Physical},
    paging::{self, Tables, UserSpace},
};
use core::{
    arch::x86_64::{__cpuid, _rdrand64_step, _rdtsc},
    iter,
};
use kernel::{
    exec::{
        args::{ArgsError, InitArgv, Word},
        find::{FindError, InitSearch},
        plan::{LoadError, LoadPlan, Vmas},
        stack::{self, ARG_PAGES, Aux, ENVP, EXPAND_PAGES, STACK_START, STACK_TOP, StackError},
    },
    image::cpio::FileType,
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
