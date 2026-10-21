// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: fs/exec.c (`SYSCALL_DEFINE3
// (execve)`, `SYSCALL_DEFINE5(execveat)` 2028-2046, `do_execveat_common`
// 1807-1890, `bprm_execve` 1753-1805, `begin_new_exec` 1114-1323,
// `alloc_bprm` 1427-1500, `do_open_execat`), fs/binfmt_elf.c
// (`load_elf_binary`, `ELF_PLAT_INIT`, `start_thread`), kernel/signal.c
// (`flush_signal_handlers`), kernel/fork.c (`mm_release`). GPL-2.0-only.
// Transformation: see `exec::bprm`. The old mm is unmapped and a fresh `Mm`
// built in place (`exec_mmap`), because this kernel has one address space per
// run; the caller's registers become the new image's initial state in place.
#![forbid(unsafe_code)]
//! `execve` and `execveat`.
//!
//! Everything up to the point of no return only reads: the path walk and
//! permission checks (`ENOENT`, `EACCES`, `ENOTDIR`, ...), the argument
//! vectors (`EFAULT`, `E2BIG`), the binary format (`ENOEXEC`), then the new
//! stack block is built in a kernel buffer. [`commit`] is `begin_new_exec`: a
//! failure there kills the task with `SIGSEGV` and never returns to the old
//! image.
//!
//! * `execveat` with `AT_EMPTY_PATH` and an empty path (execution of an open
//!   descriptor) is `Unimplemented`: the name `comm` and `/dev/fd/N` take from
//!   the dentry is not resolved yet.
//! * shortcut: user page-table pages of the replaced image are not freed
//!   (only the frames of its mappings), and the robust-futex list of the old
//!   image is dropped without the `exit_robust_list` walk. Upgrade with
//!   per-task page-table roots and the futex lane.

use super::{
    AddressSpace, Context, Files, Outcome, error,
    fs::{env_for, getname},
};
use crate::{
    exec::{
        bprm::{
            CountError, Prepared, Strings, build_window, comm_of, count, open_exec_file,
            plan_image, string_budget,
        },
        load::{exec_file, insert_stack, map_segments},
        plan::LoadError,
        stack::{ARG_PAGES, Aux, STACK_TOP},
    },
    memory::{PAGE, PAGE_BYTES},
    mm::{Mm, PageProt, TASK_SIZE},
    signal::{SIGSEGV, deliver::ERESTARTNOHAND},
    task::RLIMIT_STACK,
    vfs::{AT_EMPTY_PATH, AT_FDCWD, AT_SYMLINK_NOFOLLOW},
};
use alloc::vec::Vec;
use syscalls::{Errno, Sysno};

/// `AT_EXECVE_CHECK` (`include/uapi/linux/fcntl.h`).
const AT_EXECVE_CHECK: u32 = 0x1_0000;

pub(super) fn dispatch<C: Context>(ctx: &mut C, sysno: Sysno, a: [u64; 6]) -> Option<Outcome> {
    #[allow(clippy::cast_possible_truncation)]
    Some(match sysno {
        Sysno::execve => execveat(ctx, sysno, AT_FDCWD, a[0], a[1], a[2], 0, false),
        Sysno::execveat => execveat(ctx, sysno, a[0] as i32, a[1], a[2], a[3], a[4] as u32, true),
        _ => return None,
    })
}

fn fail(errno: Errno) -> Outcome {
    Outcome::Return(error(errno))
}

#[allow(clippy::too_many_arguments)]
fn execveat<C: Context>(
    ctx: &mut C,
    sysno: Sysno,
    dfd: i32,
    filename: u64,
    argv: u64,
    envp: u64,
    flags: u32,
    at: bool,
) -> Outcome {
    // getname / getname_uflags: the path is copied before anything else.
    let empty_ok = at && flags & AT_EMPTY_PATH != 0;
    let path = match getname(ctx, filename, empty_ok) {
        Ok(path) => path,
        Err(errno) => return fail(errno),
    };
    // do_open_execat
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH | AT_EXECVE_CHECK) != 0 {
        return fail(Errno::EINVAL);
    }
    if path.is_empty() {
        return Outcome::Unimplemented(sysno as u32);
    }
    let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
    let opened = env_for(ctx, dfd, &path)
        .and_then(|env| open_exec_file(ctx.files().vfs, &env, &path, follow));
    let (mut bytes, mut file) = match opened {
        Ok(opened) => opened,
        Err(errno) => return fail(errno),
    };
    // `file` is the description to release on every failure: a script replaces it
    // with its interpreter's.
    match prepare(ctx, dfd, &path, argv, envp, flags, &mut file, &mut bytes) {
        Ok(None) => {
            // AT_EXECVE_CHECK: the checks passed, nothing is executed.
            ctx.files().vfs.fput(file);
            Outcome::Return(0)
        }
        Ok(Some(prepared)) => commit(ctx, sysno, &prepared),
        Err(Prep::Errno(errno)) => {
            ctx.files().vfs.fput(file);
            fail(errno)
        }
        Err(Prep::Restart) => {
            ctx.files().vfs.fput(file);
            Outcome::Return(-ERESTARTNOHAND)
        }
        Err(Prep::Unsupported) => {
            ctx.files().vfs.fput(file);
            Outcome::Unimplemented(sysno as u32)
        }
    }
}

enum Prep {
    Errno(Errno),
    Restart,
    Unsupported,
}

impl From<Errno> for Prep {
    fn from(errno: Errno) -> Self {
        Self::Errno(errno)
    }
}

impl From<CountError> for Prep {
    fn from(error: CountError) -> Self {
        match error {
            CountError::Errno(errno) => Self::Errno(errno),
            CountError::Restart => Self::Restart,
        }
    }
}

impl From<LoadError> for Prep {
    fn from(error: LoadError) -> Self {
        match error {
            LoadError::Errno(errno) => Self::Errno(errno),
            LoadError::Unsupported(_) => Self::Unsupported,
        }
    }
}

/// `do_execveat_common` after `alloc_bprm`, up to `bprm_execve`'s point of no
/// return. `Ok(None)` is `AT_EXECVE_CHECK`.
#[allow(clippy::too_many_arguments)]
fn prepare<C: Context>(
    ctx: &mut C,
    dfd: i32,
    path: &[u8],
    argv: u64,
    envp: u64,
    flags: u32,
    file: &mut crate::vfs::FileId,
    bytes: &mut Vec<u8>,
) -> Result<Option<Prepared>, Prep> {
    // bprm->filename: the path as given, or the /dev/fd name of a path
    // relative to a descriptor.
    let relative = !(dfd == AT_FDCWD || path.first() == Some(&b'/'));
    let filename = if relative {
        dev_fd_name(dfd, path)?
    } else {
        crate::vfs::try_copy(path)?
    };
    // BINPRM_FLAGS_PATH_INACCESSIBLE: the script's own name will not exist after
    // the exec (`/dev/fd/N/..` against a close-on-exec descriptor).
    #[allow(clippy::cast_sign_loss)]
    let inaccessible = relative && ctx.files().fdt.cloexec(dfd as u32);
    // `fatal_signal_pending(current)`: a group exit is under way.
    let fatal = |c: &mut C| c.state().sig.group_exit.is_some();
    let arg_count = count(ctx, argv, fatal)?;
    let env_count = count(ctx, envp, fatal)?;
    let rlim_stack = ctx.attrs().rlimits.get(RLIMIT_STACK).cur;
    let budget = string_budget(rlim_stack, arg_count, env_count)?;
    let mut used = 0u64;
    let mut name = Strings::new();
    name.push_kernel(&filename, budget, &mut used)?;
    let mut env = Strings::new();
    env.copy_user(ctx, envp, env_count, budget, &mut used)?;
    let mut arg_strings = Strings::new();
    arg_strings.copy_user(ctx, argv, arg_count, budget, &mut used)?;
    if arg_count == 0 {
        // "" as argv[0], so programs that start at argv[1] do not walk envp.
        arg_strings.push_kernel(b"", budget, &mut used)?;
    }
    // `bprm->is_check`: stop after the checks that precede the format.
    let probe = Aux {
        hwcap: 0,
        phdr: 0,
        phnum: 0,
        entry: 0,
        random: [0; 16],
    };
    // The block must fit before the format is looked at (copy_strings fails
    // with E2BIG before `search_binary_handler` can say ENOEXEC).
    build_window(&filename, &arg_strings, &env, &probe)?;
    if flags & AT_EXECVE_CHECK != 0 {
        return Ok(None);
    }
    // exec_binprm: the binary formats, still before `begin_new_exec`. A `#!`
    // script (`load_script`) rewrites the argument vector and restarts with
    // its interpreter, at most six times (`depth > 5` is `ELOOP`).
    let mut interp = crate::vfs::try_copy(&filename)?;
    let mut depth = 0;
    let plan = loop {
        if depth > 5 {
            return Err(Errno::ELOOP.into());
        }
        depth += 1;
        let Some(line) = crate::exec::script::parse(bytes)? else {
            break plan_image(ctx.files().vfs, bytes)?;
        };
        if inaccessible {
            return Err(Errno::ENOENT.into());
        }
        // remove_arg_zero, then copy_string_kernel of the script's name, the
        // optional argument and the interpreter, in front of the arguments.
        used -= arg_strings.pop_first();
        arg_strings.push_kernel(&interp, budget, &mut used)?;
        if let Some(arg) = line.arg {
            arg_strings.push_kernel(arg, budget, &mut used)?;
        }
        arg_strings.push_kernel(line.name, budget, &mut used)?;
        interp = crate::vfs::try_copy(line.name)?;
        // open_exec(i_name): relative to the caller's root and working directory.
        let opened = env_for(ctx, AT_FDCWD, line.name)
            .and_then(|env| open_exec_file(ctx.files().vfs, &env, line.name, true));
        let (next_bytes, next_file) = opened?;
        ctx.files().vfs.fput(*file);
        *file = next_file;
        *bytes = next_bytes;
    };
    let machine = ctx.exec_aux();
    let aux = Aux {
        hwcap: machine.hwcap,
        phdr: plan.phdr,
        phnum: plan.phnum,
        entry: plan.entry,
        random: machine.random,
    };
    let (window, built) = build_window(&filename, &arg_strings, &env, &aux)?;
    // Everything the commit cannot afford to fail on is reserved now.
    ctx.files().vfs.reserve_pin()?;
    ctx.exec_prepare_mm()?;
    Ok(Some(Prepared {
        file: *file,
        bytes: core::mem::take(bytes),
        plan,
        window,
        built,
        comm: comm_of(&filename),
    }))
}

/// `"/dev/fd/%d/%s"` (`alloc_bprm` for a path relative to a descriptor).
fn dev_fd_name(fd: i32, path: &[u8]) -> Result<Vec<u8>, Errno> {
    let mut digits = [0u8; 11];
    let mut at = digits.len();
    let mut n = i64::from(fd).unsigned_abs();
    loop {
        at -= 1;
        digits[at] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    let mut name = Vec::new();
    let sign: &[u8] = if fd < 0 { b"-" } else { b"" };
    let parts: [&[u8]; 4] = [b"/dev/fd/", sign, &digits[at..], b"/"];
    name.try_reserve(8 + 1 + (digits.len() - at) + 1 + path.len())
        .map_err(|_| Errno::ENOMEM)?;
    for part in parts.iter().copied().chain([path]) {
        for &byte in part {
            name.push_within_capacity(byte).map_err(|_| Errno::ENOMEM)?;
        }
    }
    Ok(name)
}

/// `begin_new_exec` and the tail of `load_elf_binary`: the point of no return.
/// The old image is gone when the first step runs; every failure from here on
/// is fatal to the task.
fn commit<C: Context>(ctx: &mut C, sysno: Sysno, p: &Prepared) -> Outcome {
    // Close-on-exec descriptors (`do_close_on_exec`).
    {
        let Files { vfs, fdt, .. } = ctx.files();
        vfs.do_close_on_exec(fdt);
    }
    // exec_mm_release: the old mm's `clear_child_tid` and robust list.
    {
        let attrs = ctx.attrs();
        attrs.clear_child_tid = 0;
        attrs.robust_list = 0;
    }
    // set_mm_exe_file: the new file is `mm->exe_file`.
    let id = u64::from(p.file.index());
    if let Some(old) = ctx.replace_exe_file(p.file) {
        ctx.files().vfs.fput(old);
    }
    // exec_mmap: a caller that borrows its address space (`vfork`) leaves it for its
    // owner and takes the fresh one; any other task's old image is unmapped below.
    ctx.exec_switch_mm();
    // The old image's mappings go, a fresh address space replaces
    // the VMA set; then `setup_arg_pages` and `elf_load`.
    let mapped = {
        let AddressSpace { mm, env, pages } = ctx.address_space();
        let unmapped = mm.munmap(env, &mut *pages, 0, TASK_SIZE);
        // A failed munmap keeps the old mm (its VMAs still describe the live
        // frames and PTEs, which dropping it would leak); the task dies below.
        if unmapped.is_ok() {
            *mm = Mm::new(env);
        }
        unmapped.map_err(LoadError::Errno).and_then(|()| {
            insert_stack(mm, env, p.plan.exec_stack)?;
            map_segments(&p.plan, &p.bytes, &exec_file(id), mm, env, &mut *pages)?;
            mm.record_stack(
                p.built.sp,
                p.built.arg_start,
                p.built.arg_end,
                p.built.env_start,
                p.built.env_end,
            );
            install_arguments(p, pages)
        })
    };
    super::memory::unpin_unmapped(ctx);
    if let Err(error) = mapped {
        // bprm_execve: "ensure the code never returns to the userspace process".
        ctx.state().force_fatal_sig(SIGSEGV);
        return match error {
            LoadError::Errno(errno) => fail(errno),
            LoadError::Unsupported(_) => Outcome::Unimplemented(sysno as u32),
        };
    }
    let Files { vfs, owner, .. } = ctx.files();
    vfs.pin(owner, id);
    // flush_signal_handlers(me, 0) and the new name.
    ctx.state().flush_on_exec();
    ctx.attrs().comm = p.comm;
    let cred = ctx.attrs().cred;
    let tasks = ctx.tasks();
    tasks.list.exec_committed(tasks.current, &cred);
    // flush_thread + start_thread.
    ctx.start_thread(p.plan.entry, p.built.sp);
    Outcome::Return(0)
}

/// The argument pages: private frames holding the prepared block, writable
/// (and executable only for `PT_GNU_STACK` with `PF_X`), as the boot loader maps
/// them.
fn install_arguments(
    p: &Prepared,
    pages: &mut dyn crate::exec::load::Pager,
) -> Result<(), LoadError> {
    for page in 0..ARG_PAGES {
        let address = STACK_TOP - (ARG_PAGES - page) as u64 * PAGE;
        let from = page * PAGE_BYTES;
        let bytes: &[u8; PAGE_BYTES] = p
            .window
            .get(from..from + PAGE_BYTES)
            .and_then(|s| s.try_into().ok())
            .ok_or(LoadError::Errno(Errno::EFAULT))?;
        pages
            .install(
                address,
                PageProt {
                    accessible: true,
                    write: true,
                    exec: p.plan.exec_stack,
                },
                bytes,
            )
            .map_err(|_| LoadError::Errno(Errno::ENOMEM))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::cast_lossless,
        clippy::unreadable_literal,
        clippy::similar_names,
        clippy::many_single_char_names,
        clippy::too_many_lines,
        clippy::assert_is_empty,
        clippy::manual_assert_eq
    )]
    extern crate std;
    use super::*;
    use crate::{
        exec::plan::tests::{EXEC, Ph, elf, oracle},
        signal::{SA_RESTART, SIG_IGN, SIGUSR1, SIGUSR2, SigAction, SigSet},
        syscall::{
            dispatch,
            testing::{Task, task},
        },
        usercopy::copy_to_user,
        vfs::{O_CLOEXEC, O_CREAT, O_RDWR},
    };
    use std::vec;

    const PATH: u64 = 0x1000;
    const ARGV: u64 = 0x2000;
    const ENVP: u64 = 0x2800;
    const STRS: u64 = 0x3000;
    const BAD: u64 = 0x9000_0000;

    fn t() -> Task {
        let mut t = task();
        for page in 1..=0x1f {
            t.pages.map(page * 0x1000, true);
        }
        t
    }

    fn put(t: &mut Task, at: u64, data: &[u8]) {
        assert_eq!(copy_to_user(t, at, data), 0, "{at:#x}");
    }

    fn cstr(t: &mut Task, at: u64, text: &str) -> u64 {
        let mut bytes = text.as_bytes().to_vec();
        bytes.push(0);
        put(t, at, &bytes);
        at
    }

    /// A NULL-terminated pointer vector at `at` over strings stored from `STRS`.
    fn vector(t: &mut Task, at: u64, strings: &[&str]) -> u64 {
        let mut cursor = STRS + (at & 0xf00) * 4;
        let mut words = vec![];
        for s in strings {
            words.push(cstr(t, cursor, s));
            cursor += s.len() as u64 + 1;
        }
        words.push(0);
        let bytes: std::vec::Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        put(t, at, &bytes);
        at
    }

    /// Create `path` with `mode` and contents `data` through the syscalls.
    fn install(t: &mut Task, path: &str, mode: u64, data: &[u8]) {
        let at = cstr(t, PATH, path);
        let Outcome::Return(f) = dispatch(
            t,
            Sysno::open as u64,
            [at, u64::from(O_CREAT | O_RDWR), mode, 0, 0, 0],
        ) else {
            panic!()
        };
        let f = u64::try_from(f).unwrap_or_else(|_| panic!("open {path}: {f}"));
        for chunk in data.chunks(0x1000) {
            put(t, 0x1e000, chunk);
            let r = dispatch(
                t,
                Sysno::write as u64,
                [f, 0x1e000, chunk.len() as u64, 0, 0, 0],
            );
            assert_eq!(r, Outcome::Return(chunk.len() as i64));
        }
        assert_eq!(
            dispatch(t, Sysno::close as u64, [f, 0, 0, 0, 0, 0]),
            Outcome::Return(0)
        );
    }

    fn execve(t: &mut Task, path: &str, argv: &[&str], envp: &[&str]) -> Outcome {
        let p = cstr(t, PATH, path);
        let a = vector(t, ARGV, argv);
        let e = vector(t, ENVP, envp);
        dispatch(t, Sysno::execve as u64, [p, a, e, 0, 0, 0])
    }

    fn neg(errno: Errno) -> Outcome {
        Outcome::Return(error(errno))
    }

    #[test]
    fn failures_before_the_point_of_no_return_follow_do_execveat_common() {
        let mut t = t();
        install(&mut t, "/plain", 0o644, b"data");
        install(&mut t, "/script-ish", 0o755, b"not an elf at all");
        install(&mut t, "/empty", 0o755, b"");
        let argv = ["/init", "execd", "third arg"];
        let envp = ["EXEC=1"];
        // alloc_bprm -> do_open_execat, before argv is looked at.
        assert_eq!(
            execve(&mut t, "/nonexistent", &argv, &envp),
            neg(Errno::ENOENT)
        );
        assert_eq!(execve(&mut t, "/plain", &argv, &envp), neg(Errno::EACCES));
        assert_eq!(execve(&mut t, "/root", &argv, &envp), neg(Errno::EACCES));
        assert_eq!(
            execve(&mut t, "/plain/x", &argv, &envp),
            neg(Errno::ENOTDIR)
        );
        assert_eq!(execve(&mut t, "", &argv, &envp), neg(Errno::ENOENT));
        // Executable but not a recognised format: ENOEXEC, also when empty.
        assert_eq!(
            execve(&mut t, "/script-ish", &argv, &envp),
            neg(Errno::ENOEXEC)
        );
        assert_eq!(execve(&mut t, "/empty", &argv, &envp), neg(Errno::ENOEXEC));
        // The path is copied first: EFAULT beats everything else.
        let a = vector(&mut t, ARGV, &argv);
        let e = vector(&mut t, ENVP, &envp);
        assert_eq!(
            dispatch(&mut t, Sysno::execve as u64, [BAD, a, e, 0, 0, 0]),
            neg(Errno::EFAULT)
        );
        // Open errors beat vector errors (argv is looked at afterwards) ...
        let p = cstr(&mut t, PATH, "/nonexistent");
        assert_eq!(
            dispatch(&mut t, Sysno::execve as u64, [p, BAD, BAD, 0, 0, 0]),
            neg(Errno::ENOENT)
        );
        // ... and vector errors beat the binary format.
        let p = cstr(&mut t, PATH, "/script-ish");
        assert_eq!(
            dispatch(&mut t, Sysno::execve as u64, [p, BAD, e, 0, 0, 0]),
            neg(Errno::EFAULT)
        );
        assert_eq!(
            dispatch(&mut t, Sysno::execve as u64, [p, a, BAD, 0, 0, 0]),
            neg(Errno::EFAULT)
        );
        // A bad string pointer inside an otherwise good vector.
        let bad_string = ARGV + 0x100;
        put(&mut t, bad_string, &BAD.to_le_bytes());
        put(&mut t, bad_string + 8, &0u64.to_le_bytes());
        assert_eq!(
            dispatch(&mut t, Sysno::execve as u64, [p, bad_string, e, 0, 0, 0]),
            neg(Errno::EFAULT)
        );
        // NULL argv / envp are empty vectors (then the format decides).
        assert_eq!(
            dispatch(&mut t, Sysno::execve as u64, [p, 0, 0, 0, 0, 0]),
            neg(Errno::ENOEXEC)
        );
        // ENAMETOOLONG: 4096 bytes without a NUL.
        put(&mut t, 0x10000, &[b'a'; 4096]);
        assert_eq!(
            dispatch(&mut t, Sysno::execve as u64, [0x10000, a, e, 0, 0, 0]),
            neg(Errno::ENAMETOOLONG)
        );
        // Nothing was executed: still the same task, no fd closed.
        assert!(t.started.is_none());
    }

    #[test]
    fn oversized_argument_blocks_are_e2big_before_the_format_is_checked() {
        let mut t = t();
        install(&mut t, "/notelf", 0o755, b"not an elf");
        let p = cstr(&mut t, PATH, "/notelf");
        // One string beyond MAX_ARG_STRLEN (131072 with its NUL).
        let mut vec = vec![b'x'; 140_000];
        vec.push(0);
        // Map enough pages for the string.
        for page in 0x20..0x50 {
            t.pages.map(page * 0x1000, true);
        }
        put(&mut t, 0x20000, &vec);
        put(&mut t, ARGV, &0x20000u64.to_le_bytes());
        put(&mut t, ARGV + 8, &0u64.to_le_bytes());
        assert_eq!(
            dispatch(&mut t, Sysno::execve as u64, [p, ARGV, 0, 0, 0, 0]),
            neg(Errno::E2BIG)
        );
        // Strings that fit the string limit but not the argument window.
        let chunk = vec![b'y'; 5000];
        let mut words = std::vec::Vec::new();
        for i in 0..4u64 {
            let at = 0x30000 + i * 0x2000;
            put(&mut t, at, &chunk);
            put(&mut t, at + 5000, &[0]);
            words.extend_from_slice(&at.to_le_bytes());
        }
        words.extend_from_slice(&0u64.to_le_bytes());
        put(&mut t, ARGV + 0x100, &words);
        assert_eq!(
            dispatch(&mut t, Sysno::execve as u64, [p, ARGV + 0x100, 0, 0, 0, 0]),
            neg(Errno::E2BIG),
            "20000 bytes do not fit the four-page window (shortcut)"
        );
    }

    #[test]
    fn execveat_checks_flags_after_the_path_and_resolves_against_the_descriptor() {
        let mut t = t();
        install(&mut t, "/prog", 0o755, b"x");
        let argv = vector(&mut t, ARGV, &["prog"]);
        let p = cstr(&mut t, PATH, "prog");
        let call = |t: &mut Task, fd: i32, path: u64, flags: u64| {
            dispatch(
                t,
                Sysno::execveat as u64,
                [fd as u32 as u64, path, argv, 0, flags, 0],
            )
        };
        // Relative to the cwd: found, then not an ELF.
        assert_eq!(call(&mut t, AT_FDCWD, PATH, 0), neg(Errno::ENOEXEC));
        let missing = cstr(&mut t, PATH + 0x100, "nonexistent");
        assert_eq!(call(&mut t, AT_FDCWD, missing, 0), neg(Errno::ENOENT));
        // Unknown flag bits: EINVAL, but only once the path was copied.
        assert_eq!(
            call(&mut t, AT_FDCWD, PATH, 0x8000_0000),
            neg(Errno::EINVAL)
        );
        assert_eq!(call(&mut t, AT_FDCWD, BAD, 0x8000_0000), neg(Errno::EFAULT));
        // A closed descriptor with a relative path: EBADF.
        assert_eq!(call(&mut t, 77, PATH, 0), neg(Errno::EBADF));
        // A directory descriptor: the path resolves under it.
        let root = cstr(&mut t, PATH + 0x200, "/");
        let Outcome::Return(dir) = dispatch(
            &mut t,
            Sysno::open as u64,
            [root, u64::from(crate::vfs::O_RDONLY), 0, 0, 0, 0],
        ) else {
            panic!()
        };
        let dir = i32::try_from(dir).unwrap();
        assert_eq!(call(&mut t, dir, PATH, 0), neg(Errno::ENOEXEC));
        // AT_EMPTY_PATH with an empty name is a loud stop, with a name it is
        // the ordinary lookup.
        let empty = cstr(&mut t, PATH + 0x300, "");
        assert_eq!(
            call(&mut t, dir, empty, 0x1000),
            Outcome::Unimplemented(Sysno::execveat as u32)
        );
        assert_eq!(call(&mut t, AT_FDCWD, empty, 0), neg(Errno::ENOENT));
        assert_eq!(call(&mut t, dir, PATH, 0x1000), neg(Errno::ENOEXEC));
        // AT_EXECVE_CHECK: permission and strings are checked, nothing runs.
        assert_eq!(call(&mut t, AT_FDCWD, PATH, 0x1_0000), Outcome::Return(0));
        let plain = {
            install(&mut t, "/plain", 0o644, b"x");
            cstr(&mut t, PATH + 0x400, "/plain")
        };
        assert_eq!(call(&mut t, AT_FDCWD, plain, 0x1_0000), neg(Errno::EACCES));
        let _ = p;
        // The relative-to-descriptor name is /dev/fd/N/path (AT_EXECFN).
        assert_eq!(dev_fd_name(5, b"a/b").unwrap(), b"/dev/fd/5/a/b");
        assert_eq!(dev_fd_name(0, b"x").unwrap(), b"/dev/fd/0/x");
    }

    #[test]
    fn a_successful_exec_replaces_the_image_and_keeps_what_linux_keeps() {
        let mut t = t();
        install(&mut t, "/bin-init", 0o755, &oracle());
        // State exec must treat: descriptors, signals, mask, name, ids.
        let keep = |t: &mut Task, flags: u32| {
            let at = cstr(t, PATH + 0x500, "/");
            let Outcome::Return(fd) = dispatch(
                t,
                Sysno::open as u64,
                [at, u64::from(crate::vfs::O_RDONLY | flags), 0, 0, 0, 0],
            ) else {
                panic!()
            };
            fd
        };
        let inherited = keep(&mut t, 0);
        let closed = keep(&mut t, O_CLOEXEC);
        t.state.hand.actions[usize::from(SIGUSR1) - 1] = SigAction {
            handler: 0x1234,
            flags: SA_RESTART,
            restorer: 5,
            mask: SigSet(7),
        };
        t.state.hand.actions[usize::from(SIGUSR2) - 1].handler = SIG_IGN;
        t.state.set_blocked(SigSet(SigSet::bit(SIGUSR1)));
        t.state.me.altstack.sp = 0x7000;
        t.state.me.altstack.size = 0x2000;
        t.attrs.clear_child_tid = 0x1111;
        t.attrs.robust_list = 0x2222;
        t.attrs.fs.umask = 0o77;
        // A previous image: one mapping that must disappear.
        {
            let crate::syscall::AddressSpace { mm, env, pages } = Context::address_space(&mut t);
            mm.mmap(env, pages, 0, 0x2000, 3, 0x22, 0, None).unwrap();
            assert!(!mm.vmas().is_empty());
        }
        let old_exe = t.vfs.fs.root();
        let _ = old_exe;
        t.tasks.task_mut(t.current).unwrap().flags |= crate::task::tasklist::PF_FORKNOEXEC;
        let outcome = execve(&mut t, "/bin-init", &["/bin-init", "a b"], &["K=V"]);
        assert_eq!(outcome, Outcome::Return(0));
        // start_thread: the ELF entry and a 16-byte aligned user stack.
        let (ip, sp) = t.started.unwrap();
        assert_eq!(ip, 0x2047d0);
        assert_eq!(sp % 16, 0);
        assert!(sp < crate::exec::stack::STACK_TOP && sp > crate::exec::stack::STACK_START);
        // Descriptors: CLOEXEC closed, the others stay.
        assert_eq!(t.fdt.get(closed as u32), None);
        assert!(t.fdt.get(inherited as u32).is_some());
        // Signals: handlers reset, SIG_IGN kept, mask kept, altstack cleared.
        assert_eq!(
            t.state.hand.actions[usize::from(SIGUSR1) - 1],
            SigAction::default()
        );
        assert_eq!(
            t.state.hand.actions[usize::from(SIGUSR2) - 1].handler,
            SIG_IGN
        );
        assert_eq!(t.state.me.blocked, SigSet(SigSet::bit(SIGUSR1)));
        assert_eq!((t.state.me.altstack.sp, t.state.me.altstack.size), (0, 0));
        // Attributes: name, cleared user pointers; umask and cwd are kept.
        assert_eq!(&t.attrs.comm[..9], b"bin-init\0");
        assert_eq!((t.attrs.clear_child_tid, t.attrs.robust_list), (0, 0));
        assert_eq!(t.attrs.fs.umask, 0o77);
        // The address space is the new image's: the old mapping is gone, the
        // stack VMA and the program's segments are in.
        let vmas = t.mm.vmas();
        assert!(vmas.iter().all(|v| v.start != 0x10000 || v.file.is_some()));
        assert!(vmas.iter().any(|v| v.end == crate::exec::stack::STACK_TOP));
        assert!(vmas.iter().any(|v| v.start == 0x200000));
        assert_eq!(t.mm.start_brk, 0x20d000);
        // exe_file replaced; the task list knows the exec happened.
        assert!(t.exe.is_some());
        assert_eq!(
            t.tasks.task(t.current).unwrap().flags & crate::task::tasklist::PF_FORKNOEXEC,
            0
        );
        // Re-exec from a task that already ran an image works the same way and
        // returns the previous exe_file for release.
        let first = t.exe;
        assert_eq!(execve(&mut t, "/bin-init", &["x"], &[]), Outcome::Return(0));
        assert_ne!(t.exe, first);
    }

    /// `execveat` up to the point of no return: the `argv` strings the new image would start
    /// with (read from the prepared stack block) and the file it would load, or the error.
    fn exec_argv(
        t: &mut Task,
        dfd: i32,
        path: &str,
        argv: &[&str],
        envp: &[&str],
    ) -> Result<(std::vec::Vec<std::string::String>, crate::vfs::FileId), Errno> {
        let name = cstr(t, PATH, path);
        let a = vector(t, ARGV, argv);
        let e = vector(t, ENVP, envp);
        let path = getname(t, name, false)?;
        let env = env_for(t, dfd, &path)?;
        let (mut bytes, mut file) = open_exec_file(t.files().vfs, &env, &path, true)?;
        let prepared = match prepare(t, dfd, &path, a, e, 0, &mut file, &mut bytes) {
            Ok(Some(prepared)) => prepared,
            Ok(None) => unreachable!("no AT_EXECVE_CHECK"),
            Err(Prep::Errno(errno)) => {
                t.files().vfs.fput(file);
                return Err(errno);
            }
            Err(Prep::Restart | Prep::Unsupported) => panic!("unexpected restart or stop"),
        };
        // The window is the top of the stack: `argc`, then the `argv` pointers.
        let base = crate::exec::stack::STACK_TOP - prepared.window.len() as u64;
        let word = |at: u64| {
            let at = (at - base) as usize;
            u64::from_le_bytes(prepared.window[at..at + 8].try_into().unwrap())
        };
        let argc = word(prepared.built.sp);
        let strings = (0..argc)
            .map(|i| {
                let from = (word(prepared.built.sp + 8 + 8 * i) - base) as usize;
                let len = prepared.window[from..]
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap();
                std::string::String::from_utf8(prepared.window[from..from + len].to_vec()).unwrap()
            })
            .collect();
        Ok((strings, prepared.file))
    }

    fn argv_of(
        t: &mut Task,
        path: &str,
        argv: &[&str],
    ) -> Result<std::vec::Vec<std::string::String>, Errno> {
        exec_argv(t, AT_FDCWD, path, argv, &["K=V"]).map(|(argv, _)| argv)
    }

    #[test]
    fn a_script_runs_its_interpreter_with_the_rewritten_argument_vector() {
        let mut t = t();
        install(&mut t, "/interp", 0o755, &oracle());
        install(&mut t, "/s", 0o755, b"#!/interp -x  arg  \nbody");
        install(&mut t, "/plain-interp", 0o755, b"#!/interp\n");
        install(&mut t, "/s2", 0o755, b"#!/s\n");
        // argv[0] is replaced by the interpreter, its one argument (the rest of the line,
        // trimmed) and the script's name, ahead of the remaining arguments.
        assert_eq!(
            argv_of(&mut t, "/s", &["ignored", "one", "two"]).unwrap(),
            ["/interp", "-x  arg", "/s", "one", "two"]
        );
        assert_eq!(
            argv_of(&mut t, "/plain-interp", &["x"]).unwrap(),
            ["/interp", "/plain-interp"]
        );
        // An interpreter that is itself a script: `bprm->interp` is the previous interpreter's name.
        assert_eq!(
            argv_of(&mut t, "/s2", &["/s2", "y"]).unwrap(),
            ["/interp", "-x  arg", "/s", "/s2", "y"]
        );
        // No argv at all: the empty argv[0] that is replaced.
        assert_eq!(
            argv_of(&mut t, "/s", &[]).unwrap(),
            ["/interp", "-x  arg", "/s"]
        );
        // The program loaded is the interpreter's file, not the script's.
        let (_, file) = exec_argv(&mut t, AT_FDCWD, "/s", &["s"], &[]).unwrap();
        let loaded = t.vfs.files.get(file).inode.unwrap();
        let (_, direct) = exec_argv(&mut t, AT_FDCWD, "/interp", &["i"], &[]).unwrap();
        assert_eq!(t.vfs.files.get(direct).inode.unwrap(), loaded);
        // And an exec of it really runs, under the script's name.
        assert_eq!(
            execve(&mut t, "/s", &["ignored", "one"], &["K=V"]),
            Outcome::Return(0)
        );
        assert_eq!(&t.attrs.comm[..2], b"s\0");
    }

    #[test]
    fn script_failures_are_the_interpreters_open_errors() {
        let mut t = t();
        install(&mut t, "/interp", 0o755, &oracle());
        install(&mut t, "/missing", 0o755, b"#!/nowhere\n");
        install(&mut t, "/noexec", 0o755, b"#!/data\n");
        install(&mut t, "/data", 0o644, b"x");
        install(&mut t, "/loop", 0o755, b"#!/loop\n");
        install(&mut t, "/blank", 0o755, b"#!   \n");
        install(&mut t, "/dir-interp", 0o755, b"#!/\n");
        assert_eq!(argv_of(&mut t, "/missing", &["m"]), Err(Errno::ENOENT));
        assert_eq!(argv_of(&mut t, "/noexec", &["m"]), Err(Errno::EACCES));
        assert_eq!(argv_of(&mut t, "/blank", &["m"]), Err(Errno::ENOEXEC));
        assert_eq!(argv_of(&mut t, "/dir-interp", &["m"]), Err(Errno::EACCES));
        // A script that names itself: six rewrites, then ELOOP.
        assert_eq!(argv_of(&mut t, "/loop", &["l"]), Err(Errno::ELOOP));
        assert_eq!(execve(&mut t, "/loop", &["l"], &[]), neg(Errno::ELOOP));
        assert!(t.started.is_none());
        // A script reached through a close-on-exec directory descriptor will not exist after the
        // exec, so the interpreter could not open it: ENOENT before anything is rewritten.
        install(&mut t, "/s", 0o755, b"#!/interp\n");
        let open_root = |t: &mut Task, flags: u32| {
            let root = cstr(t, PATH + 0x800, "/");
            let Outcome::Return(fd) = dispatch(
                t,
                Sysno::open as u64,
                [root, u64::from(crate::vfs::O_RDONLY | flags), 0, 0, 0, 0],
            ) else {
                panic!()
            };
            fd as i32
        };
        let cloexec = open_root(&mut t, O_CLOEXEC);
        assert_eq!(
            exec_argv(&mut t, cloexec, "s", &["s"], &[]).map(|_| ()),
            Err(Errno::ENOENT)
        );
        // Without close-on-exec it runs, and the script is named `/dev/fd/N/s`.
        let plain = open_root(&mut t, 0);
        assert_eq!(
            exec_argv(&mut t, plain, "s", &["s"], &[]).unwrap().0,
            [
                std::string::String::from("/interp"),
                std::format!("/dev/fd/{plain}/s")
            ]
        );
    }

    #[test]
    fn a_mapping_failure_after_the_point_of_no_return_kills_the_task() {
        // An ELF whose first segment collides with the stack VMA: elf_load's
        // MAP_FIXED_NOREPLACE fails with -EEXIST after begin_new_exec, so the
        // errno is returned but the task is already doomed.
        let mut t = t();
        let mut image = elf(
            EXEC,
            0x1000,
            &[Ph {
                kind: 1,
                flags: 5,
                offset: 0,
                vaddr: 0x7fff_ffff_f000 - 0x24000,
                filesz: 0x100,
                memsz: 0x30000,
            }],
            0x1000,
        );
        image.resize(0x2000, 0);
        install(&mut t, "/overlap", 0o755, &image);
        let outcome = execve(&mut t, "/overlap", &["o"], &[]);
        assert_eq!(outcome, neg(Errno::EEXIST));
        // The old image is gone and SIGSEGV is forced: the task dies on its
        // way back to user mode.
        assert!(t.state.me.blocked == SigSet::EMPTY);
        assert!(t.state.pending_set().contains(crate::signal::SIGSEGV));
        assert!(t.started.is_none());
    }
}
