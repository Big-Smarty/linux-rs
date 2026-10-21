// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: fs/exec.c (`do_open_execat`
// 765-804, `count` 327, `bprm_stack_limits` 399-443, `copy_strings` 449-534,
// `copy_string_kernel`, `alloc_bprm` 1427-1500, `do_execveat_common`
// 1807-1890, `begin_new_exec` 1114-1323, `__set_task_comm` 1070-1094),
// fs/binfmt_elf.c (`load_elf_binary`), include/uapi/linux/binfmts.h
// (`MAX_ARG_STRLEN`, `MAX_ARG_STRINGS`), include/linux/binfmts.h. All
// GPL-2.0-only.
// Transformation: `struct linux_binprm` is [`Prepared`]: the strings are
// copied into kernel vectors (not into the new mm's stack pages) and the stack
// block is built into a kernel buffer before the point of no return, so every
// failure up to it leaves the old image untouched without a second mm; the
// commit then installs that block. See the module contract for the limits.
#![forbid(unsafe_code)]
//! The pure half of `execve`: opening the executable, bounding and copying
//! `argv`/`envp`, validating the image and building the new stack block, in
//! the errno order of `do_execveat_common`. The binary-independent commit
//! (`begin_new_exec`) is in `syscall::exec`.
//!
//! # Contract
//! * Allocation: every vector is reserved with `try_reserve`; the copy of an
//!   argument string is bounded by `MAX_ARG_STRLEN` and the argument block by
//!   [`ARG_BLOCK_MAX`].
//! * shortcut: the whole argument block (filename, `envp`, `argv` strings and
//!   the vectors) must fit the four-page window [`ARG_PAGES`] that the boot
//!   loader also uses; Linux accepts up to
//!   `max(min(3/4 * _STK_LIM, RLIMIT_STACK / 4), ARG_MAX)` = 2 MiB. A larger
//!   block is `E2BIG` here and succeeds there. Upgrade with a window sized by
//!   the block (the stack VMA itself is sized like Linux's: [`super::stack::stack_vma_start`]).
//! * shortcut: setuid/setgid bits, `ETXTBSY` (`exe_file_deny_write_access`) and
//!   the reading of the file through a page cache are not modelled (the whole
//!   file is read into a vector, like the boot loader).

use super::{
    args::Word,
    plan::{InterpPlan, LoadError, LoadPlan},
    stack::{ARG_PAGES, Aux, Built, StackError, WINDOW_BYTES},
};
use crate::{
    memory::PAGE,
    usercopy::{UserPages, copy_from_user, strncpy_from_user},
    vfs::{
        FileId, MAY_EXEC, O_LARGEFILE, O_RDONLY, Vfs,
        ops::{Env, OpenFlags},
        try_copy,
    },
};
use alloc::vec::Vec;
use syscalls::Errno;

/// `MAX_ARG_STRLEN` (`PAGE_SIZE * 32`).
pub const MAX_ARG_STRLEN: usize = 32 * 4096;
/// `MAX_ARG_STRINGS`.
pub const MAX_ARG_STRINGS: usize = 0x7fff_ffff;
/// `ARG_MAX`.
pub const ARG_MAX: u64 = 32 * PAGE;
/// `_STK_LIM`.
const STK_LIM: u64 = 8 * 1024 * 1024;
/// The most bytes of strings and vectors the window can hold (see the module
/// contract).
pub const ARG_BLOCK_MAX: usize = WINDOW_BYTES;
const _: () = assert!(ARG_PAGES == 4);

/// `open_exec_flags`: `O_LARGEFILE | O_RDONLY`, `MAY_EXEC`; `follow` is
/// cleared by `AT_SYMLINK_NOFOLLOW`.
#[must_use]
pub fn exec_open(follow: bool) -> OpenFlags {
    OpenFlags {
        flags: O_LARGEFILE | O_RDONLY,
        mode: 0,
        acc_mode: MAY_EXEC,
        follow,
        directory: false,
        cloexec: false,
    }
}

/// `do_open_execat` + `kernel_read` of the whole file; the open file stays
/// open (`bprm->file`) for the caller to hand to the VMAs or `fput`.
///
/// # Errors
/// The `open(2)` errors in Linux's order, `EACCES` for a non-regular file.
pub fn open_exec_file(
    vfs: &mut Vfs,
    env: &Env,
    path: &[u8],
    follow: bool,
) -> Result<(Vec<u8>, FileId), Errno> {
    let file = vfs.open(env, path, &exec_open(follow))?;
    let inode = vfs.files.get(file).inode;
    let bytes = match inode {
        // do_open_execat: only regular files execute (a procfs file has no execute bit, so
        // `MAY_EXEC` already failed at the open; a procfs directory opens but is not regular).
        Some(inode) if !inode.is_proc() && vfs.fs.inode(inode).is_reg() => vfs.fs.read_all(inode),
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

/// The interpreter of an image that names one: `open_exec(elf_interpreter)`, then the header
/// read and checks of `load_elf_binary` (`EIO` for a short file, `ELIBBAD`). The path is a C
/// string: Linux hands it to `open_exec` as is, so an empty one names the working directory
/// (`path_init` on `""` for a kernel string) and fails as a directory.
///
/// `path` is relative to the caller's root and working directory (`env`).
///
/// # Errors
/// The `open_exec` errors in `open(2)`'s order, `EACCES` for a non-regular file, then the
/// interpreter checks; the open file is released on every error.
pub fn open_interpreter(
    vfs: &mut Vfs,
    env: &Env,
    path: &[u8],
) -> Result<(Vec<u8>, FileId, InterpPlan), LoadError> {
    let path = if path.is_empty() { b"." } else { path };
    let (bytes, file) = open_exec_file(vfs, env, path, true).map_err(LoadError::Errno)?;
    match InterpPlan::new(&bytes) {
        Ok(plan) => Ok((bytes, file, plan)),
        Err(error) => {
            vfs.fput(file);
            Err(error)
        }
    }
}

// ---- argument vectors ----------------------------------------------------------

/// `get_user_arg_ptr`: the `nr`th pointer of a user vector.
fn arg_ptr<P: UserPages>(pages: &mut P, vector: u64, nr: usize) -> Result<u64, Errno> {
    let at = vector.wrapping_add(8 * nr as u64);
    let mut word = [0u8; 8];
    if copy_from_user(pages, &mut word, at) != 0 {
        return Err(Errno::EFAULT);
    }
    Ok(u64::from_le_bytes(word))
}

/// `count(argv, MAX_ARG_STRINGS)`: the number of strings of a NULL-terminated
/// user vector (a NULL vector is empty). `interrupted` is polled now and then
/// (`fatal_signal_pending`); true gives `ERESTARTNOHAND`.
///
/// # Errors
/// `EFAULT` (unreadable vector), `E2BIG`, or [`CountError::Restart`].
pub fn count<T: UserPages>(
    pages: &mut T,
    vector: u64,
    mut interrupted: impl FnMut(&mut T) -> bool,
) -> Result<usize, CountError> {
    if vector == 0 {
        return Ok(0);
    }
    let mut i = 0usize;
    loop {
        if arg_ptr(pages, vector, i).map_err(CountError::Errno)? == 0 {
            return Ok(i);
        }
        if i >= MAX_ARG_STRINGS {
            return Err(CountError::Errno(Errno::E2BIG));
        }
        i += 1;
        if i.is_multiple_of(1024) && interrupted(pages) {
            return Err(CountError::Restart);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CountError {
    Errno(Errno),
    /// `-ERESTARTNOHAND`: a fatal signal arrived.
    Restart,
}

/// `bprm_stack_limits`: how many bytes of strings the vectors leave room for,
/// given `RLIMIT_STACK` and the string counts (`argc` is at least 1: an empty
/// `argv` gets an empty first string).
///
/// # Errors
/// `E2BIG`.
pub fn string_budget(rlim_stack_cur: u64, argc: usize, envc: usize) -> Result<u64, Errno> {
    // "Limit to 1/4 of the max stack size or 3/4 of _STK_LIM (whichever is
    // smaller)", but always at least ARG_MAX.
    let limit = (STK_LIM / 4 * 3).min(rlim_stack_cur / 4).max(ARG_MAX);
    let pointers = argc
        .max(1)
        .checked_add(envc)
        .and_then(|n| n.checked_mul(8))
        .and_then(|n| u64::try_from(n).ok())
        .ok_or(Errno::E2BIG)?;
    if limit <= pointers {
        return Err(Errno::E2BIG);
    }
    // The window is the tighter bound in this kernel (module contract).
    Ok((limit - pointers).min(ARG_BLOCK_MAX as u64))
}

/// A set of copied strings, in `copy_strings` order (last string first).
pub struct Strings {
    /// The strings, `strings[0]` is the last one copied (the first of the
    /// original vector is the final element).
    reversed: Vec<Vec<u8>>,
    bytes: u64,
}

impl Strings {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            reversed: Vec::new(),
            bytes: 0,
        }
    }

    /// Bytes copied so far, NULs included (`bprm->p` moved this far).
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    /// The strings in their original order.
    pub fn words(&self) -> impl Iterator<Item = Word<'_>> + Clone {
        self.reversed.iter().rev().map(|s| Word::plain(s))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.reversed.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.reversed.is_empty()
    }

    /// `remove_arg_zero`: drop the first string of the vector (the last copied)
    /// and return the bytes it took (NUL included), for the caller's budget.
    pub fn pop_first(&mut self) -> u64 {
        let Some(first) = self.reversed.pop() else {
            return 0;
        };
        let freed = first.len() as u64 + 1;
        self.bytes = self.bytes.saturating_sub(freed);
        freed
    }

    /// Copy one string (`copy_string_kernel`'s accounting) from `bytes`.
    ///
    /// # Errors
    /// `E2BIG` past `budget` (cumulative with `used`), `ENOMEM`.
    pub fn push_kernel(&mut self, bytes: &[u8], budget: u64, used: &mut u64) -> Result<(), Errno> {
        let len = bytes.len() as u64 + 1;
        if len > MAX_ARG_STRLEN as u64 {
            return Err(Errno::E2BIG);
        }
        *used += len;
        if *used > budget {
            return Err(Errno::E2BIG);
        }
        let copy = try_copy(bytes)?;
        self.reversed.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
        self.reversed
            .push_within_capacity(copy)
            .map_err(|_| Errno::ENOMEM)?;
        self.bytes = *used;
        Ok(())
    }

    /// `copy_strings(argc, vector, bprm)`: the `count` strings of a user
    /// vector, last first.
    ///
    /// # Errors
    /// `EFAULT` for an unreadable pointer or string, `E2BIG`, `ENOMEM`.
    pub fn copy_user<P: UserPages>(
        &mut self,
        pages: &mut P,
        vector: u64,
        count: usize,
        budget: u64,
        used: &mut u64,
    ) -> Result<(), Errno> {
        let mut index = count;
        while index > 0 {
            index -= 1;
            let pointer = arg_ptr(pages, vector, index)?;
            let string = user_string(pages, pointer)?;
            self.push_kernel(&string, budget, used)?;
        }
        Ok(())
    }
}

impl Default for Strings {
    fn default() -> Self {
        Self::new()
    }
}

/// `strnlen_user(str, MAX_ARG_STRLEN)` + the copy: the string without its NUL.
fn user_string<P: UserPages>(pages: &mut P, pointer: u64) -> Result<Vec<u8>, Errno> {
    const CHUNK: usize = 256;
    let mut out = Vec::new();
    loop {
        let mut chunk = [0u8; CHUNK];
        let len = strncpy_from_user(pages, &mut chunk, pointer.wrapping_add(out.len() as u64))
            .ok_or(Errno::EFAULT)?;
        if out.len() + len >= MAX_ARG_STRLEN {
            return Err(Errno::E2BIG);
        }
        out.try_reserve(len).map_err(|_| Errno::ENOMEM)?;
        for &byte in &chunk[..len] {
            out.push_within_capacity(byte).map_err(|_| Errno::ENOMEM)?;
        }
        if len < CHUNK {
            return Ok(out);
        }
    }
}

/// The interpreter of a [`Prepared`] image (`bprm->interpreter`): the open file, its bytes and
/// the plan made from them.
pub struct PreparedInterp {
    pub file: FileId,
    pub bytes: Vec<u8>,
    pub plan: InterpPlan,
}

/// The new image, fully validated, with its stack block built: what
/// `begin_new_exec` and `load_elf_binary` install after the point of no
/// return.
pub struct Prepared {
    pub file: FileId,
    pub bytes: Vec<u8>,
    pub plan: LoadPlan,
    pub interp: Option<PreparedInterp>,
    /// The top [`ARG_PAGES`] pages of the stack, ready to be installed.
    pub window: Vec<u8>,
    pub built: Built,
    /// `bprm->rlim_stack.rlim_cur`, which sizes the stack VMA (`setup_arg_pages`).
    pub rlim_stack: u64,
    /// `task_struct::comm` for the new image.
    pub comm: [u8; crate::task::COMM_LEN],
}

/// `kbasename(filename)` truncated to `TASK_COMM_LEN - 1`, NUL padded.
#[must_use]
pub fn comm_of(filename: &[u8]) -> [u8; crate::task::COMM_LEN] {
    let base = filename.rsplit(|&b| b == b'/').next().unwrap_or(filename);
    let mut comm = [0; crate::task::COMM_LEN];
    let len = base.len().min(crate::task::COMM_LEN - 1);
    comm[..len].copy_from_slice(&base[..len]);
    comm
}

/// Build the stack block of an accepted image into a zeroed kernel buffer.
///
/// # Errors
/// `E2BIG` when the block does not fit the window, `ENOMEM`.
pub fn build_window(
    filename: &[u8],
    argv: &Strings,
    envp: &Strings,
    aux: &Aux,
) -> Result<(Vec<u8>, Built), Errno> {
    let mut window = Vec::new();
    window
        .try_reserve_exact(WINDOW_BYTES)
        .map_err(|_| Errno::ENOMEM)?;
    while window.len() < WINDOW_BYTES {
        window.push_within_capacity(0).map_err(|_| Errno::ENOMEM)?;
    }
    // An empty `argv` gets "" as argv[0] ("confused userspace programs").
    let empty = [Word::plain(b"")];
    let built = if argv.is_empty() {
        super::stack::build(
            &mut window,
            filename,
            empty.iter().copied(),
            envp.words(),
            aux,
        )
    } else {
        super::stack::build(&mut window, filename, argv.words(), envp.words(), aux)
    };
    match built {
        Ok(built) => Ok((window, built)),
        Err(StackError::TooBig) => Err(Errno::E2BIG),
    }
}
