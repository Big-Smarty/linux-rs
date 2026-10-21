// SPDX-License-Identifier: GPL-2.0-only
//! `threads` group: `clone`/`clone3` with `CLONE_THREAD` and the sharing flags, one `mm`,
//! `files_struct`, `fs_struct` and `sighand` for the group, thread ids against process ids,
//! thread-directed and process-directed signals, `exit` against `exit_group`, the zombie
//! leader, `execve` from a non-leader thread, `clear_child_tid`, per-thread FPU state.
//! Linux 6.18.57: `kernel/fork.c` (`copy_process`, `copy_files`, `copy_fs`, `copy_sighand`,
//! `copy_signal`, `copy_mm`), `kernel/exit.c` (`do_exit`, `exit_notify`, `release_task`,
//! `wait_consider_task`, `forget_original_parent`), `kernel/signal.c` (`complete_signal`,
//! `wants_signal`, `zap_other_threads`), `fs/exec.c` (`de_thread`), `kernel/futex/core.c`
//! (`futex_exit_release`).
//!
//! Threads are made with a raw `clone` (no libc): [`spawn_with`] maps a stack, puts a control
//! block at its top ([`Control`]: the function to run, its result, the words that
//! `CLONE_PARENT_SETTID` and `CLONE_CHILD_{SET,CLEAR}TID` write) and enters [`clone_raw`].
//! Joining is the kernel's `CLONE_CHILD_CLEARTID` store and wake-up on the control block's
//! word, so the order of everything the checks observe is enforced by futexes and never by
//! timing; the few `nap`s below only let a thread that is already past its last
//! synchronisation point reach a sleep. Fatal signals, `exit_group` and `execve` from
//! threads happen in `fork`ed subject processes, so global init (this program) is never
//! the victim.
//!
//! Assembly proof (AGENTS.md rule 3) for the two `asm!` blocks of [`clone_raw`] and
//! [`clone3_raw`]: they run in user mode (CPL 3) and need nothing beyond x86-64. `clone`
//! returns twice, once in each thread, and the child has a different stack, so the code after
//! the `syscall` instruction cannot be Rust that returns into the parent's frame: the child
//! must call the entry function on its new stack and never come back. No intrinsic or safe Rust
//! construct expresses a call made on a stack that exists only after the instruction.
//! Registers: `rax` = number in, result out; `rdi`, `rsi`, `rdx`, `r10`, `r8` the `clone`
//! arguments (flags, stack, parent_tid, child_tid, tls); `rcx` and `r11` are clobbered by
//! `syscall`; `entry` and `arg` are compiler-chosen registers that the kernel preserves, so
//! the child still has them. Flags: clobbered by `test`. Stack: the parent's is untouched by
//! the asm; the child's `rsp` is the 16-byte-aligned top the caller passes and the `call`
//! pushes one return address, so the entry sees `rsp % 16 == 8` as the `SysV` ABI requires.
//! Memory: the blocks read and write nothing themselves. Control flow: the entry is
//! `extern "C" fn -> !` (it ends with `exit`), `ud2` traps if it somehow returned; there is no
//! unwinding (panic=abort). The remaining `asm!` blocks (`read_fs0`, `current_xmm`, ...) are
//! single `mov` instructions with the contract written at each.

use core::arch::asm;
use core::sync::atomic::{
    AtomicU32, AtomicUsize,
    Ordering::{Relaxed, SeqCst},
};

use syscalls::{Errno, Sysno};

const SIGCONT: usize = 18;
const SIGSTOP: usize = 19;
const WUNTRACED: usize = 2;
const WCONTINUED: usize = 8;

use super::proc::{
    BAD, SIGCHLD, SIGKILL, SIGTERM, SIGUSR1, SIGUSR2, WNOHANG, nap, reap_all, wait4,
};
use super::proc::{sigaction, spawn as fork_child};
use super::signal::{KSigaction, SA_SIGINFO, bit};
use super::{PAGE, R, T, addr, addr_mut, fn_addr, getpid, gettid, peek, poke, sys};

pub(super) const CLONE_VM: usize = 0x100;
pub(super) const CLONE_FS: usize = 0x200;
pub(super) const CLONE_FILES: usize = 0x400;
pub(super) const CLONE_SIGHAND: usize = 0x800;
pub(super) const CLONE_THREAD: usize = 0x1_0000;
pub(super) const CLONE_NEWNS: usize = 0x2_0000;
pub(super) const CLONE_SYSVSEM: usize = 0x4_0000;
pub(super) const CLONE_SETTLS: usize = 0x8_0000;
pub(super) const CLONE_PARENT_SETTID: usize = 0x10_0000;
pub(super) const CLONE_CHILD_CLEARTID: usize = 0x20_0000;
pub(super) const CLONE_CHILD_SETTID: usize = 0x100_0000;
pub(super) const CLONE_VFORK: usize = 0x4000;
pub(super) const CLONE_NEWUSER: usize = 0x1000_0000;
pub(super) const CLONE_NEWPID: usize = 0x2000_0000;

/// What `pthread_create` passes (glibc 2.40, `sysdeps/unix/sysv/linux/createthread.c`).
pub(super) const THREAD_FLAGS: usize = CLONE_VM
    | CLONE_FS
    | CLONE_FILES
    | CLONE_SIGHAND
    | CLONE_THREAD
    | CLONE_SYSVSEM
    | CLONE_SETTLS
    | CLONE_PARENT_SETTID
    | CLONE_CHILD_CLEARTID;

const ARCH_GET_FS: usize = 0x1003;
const SS_DISABLE: u32 = 2;
const STACK_BYTES: usize = 16 * PAGE;
const SI_USER: usize = 0;
const SI_TKILL: usize = 0xffff_fffa;
/// `__WNOTHREAD`.
const WNOTHREAD: usize = 0x2000_0000;
const TASK_SIZE: usize = 0x7fff_ffff_f000;

pub(super) const FUTEX_WAIT: usize = 0;
pub(super) const FUTEX_WAKE: usize = 1;

/// `futex(2)` on a word of this program.
pub(super) fn futex(
    word: &AtomicU32,
    op: usize,
    val: usize,
    arg: usize,
    word2: usize,
    val3: usize,
) -> R {
    sys(Sysno::futex, &[addr(word), op, val, arg, word2, val3])
}

/// Stores `value` and wakes every sleeper on `word`.
pub(super) fn set_and_wake(word: &AtomicU32, value: u32) {
    word.store(value, SeqCst);
    let _ = futex(word, FUTEX_WAKE, i32::MAX as usize, 0, 0, 0);
}

/// Sleeps until `*word == value`.
pub(super) fn wait_for(word: &AtomicU32, value: u32) {
    loop {
        let seen = word.load(SeqCst);
        if seen == value {
            return;
        }
        let _ = futex(word, FUTEX_WAIT, seen as usize, 0, 0, 0);
    }
}

/// Sleeps for ever (a signal or `exit_group` ends it).
pub(super) fn sleep_forever() -> ! {
    static NEVER: AtomicU32 = AtomicU32::new(0);
    loop {
        let _ = futex(&NEVER, FUTEX_WAIT, 0, 0, 0, 0);
    }
}

/// The block at the top of a thread's mapping: what the thread runs and what the kernel and the
/// thread write back. `tls[0]` is the thread's own `%fs:0` word (a self pointer, as the thread
/// control block of a libc).
#[repr(C, align(16))]
pub(super) struct Control {
    f: fn(&'static Control) -> usize,
    pub(super) arg: usize,
    result: AtomicUsize,
    /// `CLONE_PARENT_SETTID` target.
    pub(super) ptid: AtomicU32,
    /// `CLONE_CHILD_SETTID` / `CLONE_CHILD_CLEARTID` target (the join word).
    pub(super) ctid: AtomicU32,
    tls: [AtomicUsize; 4],
}

/// A thread (or `CLONE_VM` child): its mapping and its tid as `clone` returned it.
#[derive(Clone, Copy)]
pub(super) struct Thread {
    pub(super) tid: usize,
    base: usize,
}

impl Thread {
    pub(super) fn control(&self) -> &'static Control {
        // SAFETY: the block is inside the mapping `spawn_with` made and initialised; it stays
        // mapped until `join` or `reap` unmaps it, and the program does not touch a thread
        // after that.
        unsafe { &*((self.base + STACK_BYTES - size_of::<Control>()) as *const Control) }
    }

    /// Waits for the kernel's `CLONE_CHILD_CLEARTID` store and wake-up; the thread's result.
    pub(super) fn join(&self) -> usize {
        wait_for(&self.control().ctid, 0);
        let result = self.control().result.load(SeqCst);
        let _ = sys(Sysno::munmap, &[self.base, STACK_BYTES]);
        result
    }

    /// Waits for a `CLONE_VM` child process (no thread flags): its status and result.
    pub(super) fn reap(&self) -> (R, i32, usize) {
        let (r, status) = wait4(self.tid as isize, 0);
        let result = self.control().result.load(SeqCst);
        let _ = sys(Sysno::munmap, &[self.base, STACK_BYTES]);
        (r, status, result)
    }
}

/// The entry of every thread: runs the control block's function, then `exit(0)`.
extern "C" fn thread_entry(control: usize) -> ! {
    // SAFETY: `control` is the address of the `Control` that `spawn_with` placed at the top of
    // this thread's mapping before the `clone` (the child's `rdi` is set from it); it is live
    // until the joiner unmaps the mapping, which only happens after this thread's `exit`.
    let c = unsafe { &*(control as *const Control) };
    let result = (c.f)(c);
    c.result.store(result, SeqCst);
    exit_thread(0)
}

/// Maps a stack and places the control block; the mapping base and the block.
fn map_thread(
    f: fn(&'static Control) -> usize,
    arg: usize,
) -> Result<(usize, &'static Control), Errno> {
    let base = super::mmap(0, STACK_BYTES, 3, 0x22, usize::MAX, 0)?;
    let at = base + STACK_BYTES - size_of::<Control>();
    let control = at as *mut Control;
    // SAFETY: `at` is inside the fresh anonymous read/write mapping, 16-byte aligned (the
    // mapping is page aligned and `Control` is `align(16)`), and nothing else refers to it yet.
    unsafe {
        control.write(Control {
            f,
            arg,
            result: AtomicUsize::new(0),
            ptid: AtomicU32::new(0),
            ctid: AtomicU32::new(0),
            tls: [
                AtomicUsize::new(at + core::mem::offset_of!(Control, tls)),
                AtomicUsize::new(0),
                AtomicUsize::new(0),
                AtomicUsize::new(0),
            ],
        });
        Ok((base, &*control))
    }
}

/// `clone(flags, stack, ptid, ctid, tls)` that runs `entry(arg)` on `stack` in the child.
#[inline(never)]
pub(super) fn clone_raw(
    flags: usize,
    stack: usize,
    ptid: usize,
    ctid: usize,
    tls: usize,
    entry: extern "C" fn(usize) -> !,
    arg: usize,
) -> R {
    let ret: usize;
    // SAFETY: see the module's assembly proof; `stack` is the 16-byte-aligned top of a mapping
    // that only the child uses, and `entry` never returns.
    unsafe {
        asm!(
            "syscall",
            "test rax, rax",
            "jnz 2f",
            "mov rdi, {arg}",
            "call {entry}",
            "ud2",
            "2:",
            entry = in(reg) entry as usize,
            arg = in(reg) arg,
            inlateout("rax") Sysno::clone as usize => ret,
            in("rdi") flags,
            in("rsi") stack,
            in("rdx") ptid,
            in("r10") ctid,
            in("r8") tls,
            out("rcx") _,
            out("r11") _,
        );
    }
    Errno::from_ret(ret)
}

/// `struct clone_args` up to `tls` (`CLONE_ARGS_SIZE_VER0` is 64 bytes).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct CloneArgs {
    pub(super) flags: u64,
    pub(super) pidfd: u64,
    pub(super) child_tid: u64,
    pub(super) parent_tid: u64,
    pub(super) exit_signal: u64,
    pub(super) stack: u64,
    pub(super) stack_size: u64,
    pub(super) tls: u64,
}

/// `clone3(&args, size)`; the child runs `entry(arg)` on the stack the arguments name.
#[inline(never)]
pub(super) fn clone3_raw(
    args: &CloneArgs,
    size: usize,
    entry: extern "C" fn(usize) -> !,
    arg: usize,
) -> R {
    let ret: usize;
    // SAFETY: as `clone_raw`; the kernel reads `args` (a live reference) and the child's `rsp`
    // is `stack + stack_size` of the caller's mapping, 16-byte aligned.
    unsafe {
        asm!(
            "syscall",
            "test rax, rax",
            "jnz 2f",
            "mov rdi, {arg}",
            "call {entry}",
            "ud2",
            "2:",
            entry = in(reg) entry as usize,
            arg = in(reg) arg,
            inlateout("rax") Sysno::clone3 as usize => ret,
            in("rdi") addr(args),
            in("rsi") size,
            out("rcx") _,
            out("r11") _,
        );
    }
    Errno::from_ret(ret)
}

/// Where the kernel writes the tids and which TLS block the thread gets.
#[derive(Clone, Copy)]
pub(super) struct Wiring {
    pub(super) ptid: Option<usize>,
    pub(super) ctid: Option<usize>,
    pub(super) tls: Option<usize>,
    /// `CLONE_PARENT_SETTID` writes `Control::ptid` instead of the join word (`pthread`
    /// points both at one word, so the join word is non-zero as soon as `clone` returns).
    pub(super) split: bool,
}

impl Wiring {
    pub(super) const NORMAL: Self = Self {
        ptid: None,
        ctid: None,
        tls: None,
        split: false,
    };
}

/// Starts a thread running `f(control)` with `flags`; the pointers `CLONE_*TID` and
/// `CLONE_SETTLS` use are the control block's unless `wiring` overrides them.
pub(super) fn spawn_wired(
    flags: usize,
    wiring: Wiring,
    f: fn(&'static Control) -> usize,
    arg: usize,
) -> Result<Thread, Errno> {
    let (base, control) = map_thread(f, arg)?;
    let top = core::ptr::from_ref::<Control>(control) as usize;
    let result = clone_raw(
        flags,
        top,
        wiring.ptid.unwrap_or(if wiring.split {
            core::ptr::from_ref(&control.ptid) as usize
        } else {
            core::ptr::from_ref(&control.ctid) as usize
        }),
        wiring
            .ctid
            .unwrap_or(core::ptr::from_ref(&control.ctid) as usize),
        wiring
            .tls
            .unwrap_or(core::ptr::from_ref(&control.tls) as usize),
        thread_entry,
        top,
    );
    match result {
        Ok(tid) => Ok(Thread { tid, base }),
        Err(e) => {
            let _ = sys(Sysno::munmap, &[base, STACK_BYTES]);
            Err(e)
        }
    }
}

pub(super) fn spawn_with(
    flags: usize,
    f: fn(&'static Control) -> usize,
    arg: usize,
) -> Result<Thread, Errno> {
    spawn_wired(flags, Wiring::NORMAL, f, arg)
}

/// A `pthread_create`-style thread (a failed `clone` is a tid of 0).
pub(super) fn spawn(f: fn(&'static Control) -> usize, arg: usize) -> Thread {
    spawn_with(THREAD_FLAGS, f, arg).unwrap_or(Thread { tid: 0, base: 0 })
}

/// A thread that sleeps until the program ends or a signal kills it.
fn sleeper(_: &'static Control) -> usize {
    sleep_forever()
}

pub(super) fn tgkill(tid: usize, sig: usize) -> R {
    sys(Sysno::tgkill, &[getpid(), tid, sig])
}

pub(super) fn exit_thread(code: usize) -> ! {
    loop {
        let _ = sys(Sysno::exit, &[code]);
    }
}

pub(super) fn exit_group(code: usize) -> ! {
    loop {
        let _ = sys(Sysno::exit_group, &[code]);
    }
}

pub(super) fn pipe() -> (usize, usize) {
    let mut fds = [0u32; 2];
    let _ = sys(Sysno::pipe2, &[addr_mut(&mut fds), 0]);
    (fds[0] as usize, fds[1] as usize)
}

pub(super) fn close(fd: usize) -> R {
    sys(Sysno::close, &[fd])
}

pub(super) fn raw_errno<V>(r: Result<V, Errno>) -> usize {
    r.map_or_else(|e| e.into_raw() as usize, |_| 0)
}

// ---------------------------------------------------------------------------------------------
// Signal handler records.

pub(super) static H_TID: AtomicUsize = AtomicUsize::new(0);
pub(super) static H_COUNT: AtomicUsize = AtomicUsize::new(0);
pub(super) static H_SIG: AtomicUsize = AtomicUsize::new(0);
pub(super) static H_CODE: AtomicUsize = AtomicUsize::new(0);
pub(super) static H_PID: AtomicUsize = AtomicUsize::new(0);

pub(super) extern "C" fn record(sig: i32, info: *const u64, _uc: *mut u64) {
    // SAFETY: `info` is the kernel's siginfo for the running SA_SIGINFO handler (16 words).
    let words = unsafe { [info.add(1).read(), info.add(2).read()] };
    H_TID.store(gettid(), SeqCst);
    H_SIG.store(sig as usize, SeqCst);
    H_CODE.store((words[0] & 0xffff_ffff) as usize, SeqCst);
    H_PID.store((words[1] & 0xffff_ffff) as usize, SeqCst);
    H_COUNT.fetch_add(1, SeqCst);
}

pub(super) fn install(sig: usize) {
    let _ = sigaction(sig, fn_addr(record as *const ()), SA_SIGINFO);
}

pub(super) fn default_action(sig: usize) {
    let _ = sigaction(sig, 0, 0);
}

pub(super) fn forget() {
    for cell in [&H_TID, &H_COUNT, &H_SIG, &H_CODE, &H_PID] {
        cell.store(0, SeqCst);
    }
}

pub(super) fn procmask(how: usize, set: u64) -> u64 {
    let mut old = 0u64;
    let _ = sys(
        Sysno::rt_sigprocmask,
        &[how, addr(&set), addr_mut(&mut old), 8],
    );
    old
}

fn mask_now() -> u64 {
    let mut old = 0u64;
    let _ = sys(Sysno::rt_sigprocmask, &[0, 0, addr_mut(&mut old), 8]);
    old
}

fn pending_now() -> u64 {
    let mut set = 0u64;
    let _ = sys(Sysno::rt_sigpending, &[addr_mut(&mut set), 8]);
    set
}

/// The `fn` field of `rt_sigaction`'s old action.
fn handler_of(sig: usize) -> u64 {
    let mut old = KSigaction::default();
    let _ = sys(Sysno::rt_sigaction, &[sig, 0, addr_mut(&mut old), 8]);
    old.handler
}

// ---------------------------------------------------------------------------------------------

pub fn run() -> bool {
    let mut t = T::new("threads");
    reap_all();
    let _ = sys(Sysno::chdir, &[addr(b"/\0")]);
    install(SIGUSR1);
    install(SIGUSR2);
    identity(&mut t);
    arguments(&mut t);
    sharing(&mut t);
    delivery(&mut t);
    lifecycle(&mut t);
    fpu(&mut t);
    cpu_time(&mut t);
    stress(&mut t);
    reap_all();
    t.finish()
}

static SEEN: [AtomicUsize; 12] = [const { AtomicUsize::new(0) }; 12];
static GATE: AtomicU32 = AtomicU32::new(0);
static READY: AtomicU32 = AtomicU32::new(0);

fn fs_base() -> usize {
    let mut fs = 0usize;
    let _ = sys(Sysno::arch_prctl, &[ARCH_GET_FS, addr_mut(&mut fs)]);
    fs
}

fn read_fs0() -> usize {
    let word: usize;
    // SAFETY: reads the word at `%fs:0`; only called by threads made with `CLONE_SETTLS`
    // whose `tls` points at `Control::tls` (a mapped, readable self pointer). User mode, no
    // flag or stack effects, memory is only read.
    unsafe {
        asm!("mov {word}, fs:[0]", word = out(reg) word, options(nostack, preserves_flags, readonly));
    }
    word
}

fn identity(t: &mut T) {
    let me = getpid();
    let main_fs = fs_base();
    let ppid = sys(Sysno::getppid, &[]).unwrap_or(0);
    let pgid = sys(Sysno::getpgid, &[0]).unwrap_or(0);
    let sid = sys(Sysno::getsid, &[0]).unwrap_or(0);
    // CLONE_CHILD_SETTID as well, so that the thread can read its own tid word at start. The
    // join word starts as 0 and the thread stores its tid there when it first runs, so the
    // join waits for the thread to say it is done (a join before the first run would see 0).
    READY.store(0, SeqCst);
    let th = spawn_wired(
        THREAD_FLAGS | CLONE_CHILD_SETTID,
        Wiring {
            split: true,
            ..Wiring::NORMAL
        },
        |c| {
            SEEN[0].store(getpid(), SeqCst);
            SEEN[1].store(gettid(), SeqCst);
            SEEN[2].store(sys(Sysno::getppid, &[]).unwrap_or(usize::MAX), SeqCst);
            SEEN[3].store(sys(Sysno::getpgid, &[0]).unwrap_or(usize::MAX), SeqCst);
            SEEN[4].store(sys(Sysno::getsid, &[0]).unwrap_or(usize::MAX), SeqCst);
            SEEN[5].store(c.ctid.load(SeqCst) as usize, SeqCst);
            SEEN[6].store(fs_base(), SeqCst);
            SEEN[7].store(read_fs0(), SeqCst);
            SEEN[8].store(
                sys(Sysno::set_tid_address, &[addr(&c.ctid)]).unwrap_or(usize::MAX),
                SeqCst,
            );
            set_and_wake(&READY, 1);
            7
        },
        0,
    )
    .unwrap_or(Thread { tid: 0, base: 0 });
    wait_for(&READY, 1);
    t.holds(
        "clone-thread-returns-tid",
        th.tid != 0 && th.tid != me,
        th.tid,
        "a tid different from the pid",
    );
    t.holds(
        "tid-is-a-new-pid",
        th.tid > me,
        (me, th.tid),
        "a pid after the process's",
    );
    t.eq(
        "parent-settid",
        th.control().ptid.load(SeqCst) as usize,
        th.tid,
    );
    t.eq("join-result", th.join(), 7);
    t.eq("thread-getpid", SEEN[0].load(SeqCst), me);
    t.eq("thread-gettid", SEEN[1].load(SeqCst), th.tid);
    t.eq("thread-getppid", SEEN[2].load(SeqCst), ppid);
    t.eq("thread-getpgid", SEEN[3].load(SeqCst), pgid);
    t.eq("thread-getsid", SEEN[4].load(SeqCst), sid);
    t.eq(
        "child-settid-before-first-instruction",
        SEEN[5].load(SeqCst),
        th.tid,
    );
    let tls = SEEN[6].load(SeqCst);
    t.holds(
        "thread-fs-base-is-tls",
        tls != 0 && tls != main_fs,
        tls,
        "the tls pointer",
    );
    t.eq("thread-fs0-reads-tls-block", SEEN[7].load(SeqCst), tls);
    t.eq("set-tid-address-returns-tid", SEEN[8].load(SeqCst), th.tid);
    t.eq("main-fs-base-unchanged", fs_base(), main_fs);
    t.eq(
        "set-tid-address-in-main-is-pid",
        sys(Sysno::set_tid_address, &[0]),
        Ok(me),
    );
    t.eq("main-gettid", gettid(), me);
    t.eq("tgkill-joined-thread", tgkill(th.tid, 0), Err(Errno::ESRCH));
    t.eq(
        "tgkill-wrong-group",
        sys(Sysno::tgkill, &[me + 1000, me, 0]),
        Err(Errno::ESRCH),
    );
    t.eq("tgkill-self-probe", tgkill(me, 0), Ok(0));
    t.eq(
        "tgkill-bad-tid",
        sys(Sysno::tgkill, &[me, 0, 0]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "tkill-bad-tid",
        sys(Sysno::tkill, &[0, 0]),
        Err(Errno::EINVAL),
    );
    // A thread that keeps running when the thread that made it exits.
    static LATE: AtomicUsize = AtomicUsize::new(0);
    let outer = spawn(
        |_| {
            let inner = spawn(
                |_| {
                    wait_for(&READY, 1);
                    LATE.store(gettid(), SeqCst);
                    0
                },
                0,
            );
            SEEN[9].store(inner.tid, SeqCst);
            // Hand the inner thread's join to main by leaving it unjoined.
            SEEN[10].store(inner.base, SeqCst);
            0
        },
        0,
    );
    outer.join();
    let inner = Thread {
        tid: SEEN[9].load(SeqCst),
        base: SEEN[10].load(SeqCst),
    };
    set_and_wake(&READY, 1);
    inner.join();
    t.eq(
        "thread-of-an-exited-thread-runs",
        LATE.load(SeqCst),
        inner.tid,
    );
    READY.store(0, SeqCst);
}

fn arguments(t: &mut T) {
    let me = getpid();
    let flags = |extra: usize| sys(Sysno::clone, &[extra, 0, 0, 0, 0]);
    let group = CLONE_THREAD | CLONE_SIGHAND | CLONE_VM;
    t.eq(
        "thread-with-newpid",
        flags(group | CLONE_NEWPID),
        Err(Errno::EINVAL),
    );
    t.eq(
        "thread-with-newuser",
        flags(group | CLONE_NEWUSER),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sighand-with-newns-and-fs",
        flags(CLONE_SIGHAND | CLONE_VM | CLONE_NEWNS | CLONE_FS),
        Err(Errno::EINVAL),
    );
    t.eq(
        "thread-sighand-without-vm",
        flags(CLONE_THREAD | CLONE_SIGHAND),
        Err(Errno::EINVAL),
    );
    // A TLS pointer in the kernel half is refused by `set_new_tls` after the process is built.
    let bad_tls = spawn_wired(
        THREAD_FLAGS,
        Wiring {
            tls: Some(TASK_SIZE),
            ..Wiring::NORMAL
        },
        |_| 0,
        0,
    );
    t.eq(
        "settls-kernel-address",
        bad_tls.map(|th| th.join()),
        Err(Errno::EPERM),
    );
    // A tid word the kernel cannot write is not an error: the stores are `put_user`s whose
    // result `kernel_clone`, `schedule_tail` and `mm_release` ignore.
    static DONE: AtomicU32 = AtomicU32::new(0);
    let odd = spawn_wired(
        THREAD_FLAGS | CLONE_CHILD_SETTID,
        Wiring {
            ptid: Some(BAD),
            ctid: Some(BAD),
            tls: None,
            split: false,
        },
        |_| {
            set_and_wake(&DONE, 1);
            0
        },
        0,
    );
    t.holds("unwritable-tid-words", odd.is_ok(), odd.map(|_| ()), "Ok");
    wait_for(&DONE, 1);
    DONE.store(0, SeqCst);
    // `CLONE_*` exit signal bits of a legacy `clone` are ignored for a thread: no SIGCHLD.
    forget();
    install(SIGCHLD);
    let quiet = spawn_with(THREAD_FLAGS | SIGCHLD, |_| 0, 0);
    t.holds(
        "thread-with-exit-signal",
        quiet.is_ok(),
        quiet.map(|_| ()),
        "Ok",
    );
    if let Ok(th) = quiet {
        th.join();
    }
    nap(10);
    t.eq("thread-exit-sends-no-sigchld", H_COUNT.load(SeqCst), 0);
    default_action(SIGCHLD);
    // clone3: a thread with its stack and size, and the checks that concern threads.
    static CLONE3_GATE: AtomicU32 = AtomicU32::new(0);
    let mapping = super::mmap(0, STACK_BYTES, 3, 0x22, usize::MAX, 0).unwrap_or(0);
    let control = (mapping + STACK_BYTES - size_of::<Control>()) as *mut Control;
    // SAFETY: inside the fresh mapping, aligned as above, nothing else refers to it.
    let control: &'static Control = unsafe {
        control.write(Control {
            f: |c| {
                SEEN[0].store(gettid(), SeqCst);
                SEEN[1].store(read_fs0(), SeqCst);
                wait_for(&CLONE3_GATE, 1);
                c.arg
            },
            arg: 11,
            result: AtomicUsize::new(0),
            ptid: AtomicU32::new(0),
            ctid: AtomicU32::new(0),
            tls: [const { AtomicUsize::new(0) }; 4],
        });
        &*control
    };
    control.tls[0].store(addr(&control.tls), SeqCst);
    let mut args = CloneArgs {
        flags: (THREAD_FLAGS & !CLONE_SYSVSEM | CLONE_CHILD_SETTID) as u64,
        child_tid: addr(&control.ctid) as u64,
        parent_tid: addr(&control.ctid) as u64,
        stack: mapping as u64,
        stack_size: (STACK_BYTES - size_of::<Control>()) as u64,
        tls: addr(&control.tls) as u64,
        ..CloneArgs::default()
    };
    let started = clone3_raw(&args, 64, thread_entry, addr(control));
    t.holds("clone3-thread", started.is_ok(), started, "a tid");
    let tid = started.unwrap_or(0);
    // The word as the call left it, sampled before the thread is let go to finish.
    let at_return = control.ctid.load(SeqCst) as usize;
    set_and_wake(&CLONE3_GATE, 1);
    wait_for(&control.ctid, 0);
    t.eq("clone3-thread-ran", SEEN[0].load(SeqCst), tid);
    t.eq("clone3-thread-parent-settid", at_return, tid);
    t.eq("clone3-thread-result", control.result.load(SeqCst), 11);
    t.eq(
        "clone3-thread-tls",
        SEEN[1].load(SeqCst),
        addr(&control.tls),
    );
    // The same arguments with an exit signal: `CLONE_THREAD` takes none.
    args.exit_signal = SIGCHLD as u64;
    t.eq(
        "clone3-thread-with-exit-signal",
        clone3_raw(&args, 64, thread_entry, addr(control)),
        Err(Errno::EINVAL),
    );
    let _ = sys(Sysno::munmap, &[mapping, STACK_BYTES]);
    t.eq("still-one-process", getpid(), me);
}

static SHARED_WORD: AtomicUsize = AtomicUsize::new(0);
static MAPPED: AtomicUsize = AtomicUsize::new(0);
static FDS: [AtomicUsize; 4] = [const { AtomicUsize::new(0) }; 4];

fn sharing(t: &mut T) {
    // One mm.
    let th = spawn(
        |_| {
            SHARED_WORD.store(42, SeqCst);
            let page = super::mmap(0, PAGE, 3, 0x22, usize::MAX, 0).unwrap_or(0);
            poke(page, 0x5a);
            MAPPED.store(page, SeqCst);
            1
        },
        0,
    );
    th.join();
    t.eq("thread-store-visible", SHARED_WORD.load(SeqCst), 42);
    let page = MAPPED.load(SeqCst);
    t.holds(
        "thread-mapping-visible",
        page != 0 && peek(page) == 0x5a,
        page,
        "a page holding 0x5a",
    );
    let unmapper = spawn(
        |_| usize::from(sys(Sysno::munmap, &[MAPPED.load(SeqCst), PAGE]).is_ok()),
        0,
    );
    t.eq("thread-munmap-ok", unmapper.join(), 1);
    t.eq(
        "thread-munmap-visible",
        sys(Sysno::madvise, &[page, PAGE, 0]),
        Err(Errno::ENOMEM),
    );

    // One files_struct for CLONE_FILES: a descriptor the thread makes and one it closes.
    let (p0, p1) = pipe();
    FDS[0].store(p0, SeqCst);
    FDS[1].store(p1, SeqCst);
    let th = spawn(
        |_| {
            let (a, b) = pipe();
            FDS[2].store(a, SeqCst);
            FDS[3].store(b, SeqCst);
            usize::from(close(FDS[0].load(SeqCst)).is_ok())
        },
        0,
    );
    t.eq("thread-closed-fd", th.join(), 1);
    t.eq(
        "closed-by-thread-gone-in-main",
        sys(Sysno::fcntl, &[p0, 1]),
        Err(Errno::EBADF),
    );
    let (a, b) = (FDS[2].load(SeqCst), FDS[3].load(SeqCst));
    t.eq(
        "thread-pipe-usable-in-main",
        (sys(Sysno::write, &[b, addr(b"q"), 1]), {
            let mut byte = [0u8; 1];
            let r = sys(Sysno::read, &[a, addr_mut(&mut byte), 1]);
            (r, byte)
        }),
        (Ok(1), (Ok(1), *b"q")),
    );
    let _ = (close(a), close(b), close(p1));
    // Without CLONE_FILES a CLONE_VM child has its own table: closing there leaves ours.
    let (q0, q1) = pipe();
    FDS[0].store(q0, SeqCst);
    let kid = spawn_with(
        CLONE_VM | SIGCHLD,
        |_| usize::from(close(FDS[0].load(SeqCst)).is_ok()),
        0,
    )
    .unwrap_or(Thread { tid: 0, base: 0 });
    let (waited, status, closed) = kid.reap();
    t.eq(
        "vm-child-has-its-own-fd-table",
        (waited, status, closed, sys(Sysno::fcntl, &[q0, 1])),
        (Ok(kid.tid), 0, 1, Ok(0)),
    );
    let _ = (close(q0), close(q1));

    // One fs_struct for CLONE_FS.
    let _ = sys(Sysno::umask, &[0o022]);
    let th = spawn(
        |_| {
            let _ = sys(Sysno::chdir, &[addr(b"/dev\0")]);
            sys(Sysno::umask, &[0o077]).unwrap_or(usize::MAX)
        },
        0,
    );
    t.eq("thread-umask-returns-old", th.join(), 0o022);
    let mut cwd = [0u8; 16];
    let n = sys(Sysno::getcwd, &[addr_mut(&mut cwd), 16]).unwrap_or(0);
    t.eq("thread-chdir-seen-by-main", &cwd[..n], b"/dev\0".as_slice());
    t.eq(
        "thread-umask-seen-by-main",
        sys(Sysno::umask, &[0o022]),
        Ok(0o077),
    );
    let _ = sys(Sysno::chdir, &[addr(b"/\0")]);
    let kid = spawn_with(
        CLONE_VM | SIGCHLD,
        |_| {
            let _ = sys(Sysno::chdir, &[addr(b"/dev\0")]);
            sys(Sysno::umask, &[0o077]).unwrap_or(usize::MAX)
        },
        0,
    )
    .unwrap_or(Thread { tid: 0, base: 0 });
    let (_, _, old) = kid.reap();
    let mut cwd = [0u8; 16];
    let n = sys(Sysno::getcwd, &[addr_mut(&mut cwd), 16]).unwrap_or(0);
    t.eq(
        "vm-child-has-its-own-fs",
        (old, &cwd[..n], sys(Sysno::umask, &[0o022])),
        (0o022, b"/\0".as_slice(), Ok(0o022)),
    );
    // With CLONE_FS but not CLONE_THREAD.
    let kid = spawn_with(
        CLONE_VM | CLONE_FS | SIGCHLD,
        |_| {
            let _ = sys(Sysno::umask, &[0o027]);
            0
        },
        0,
    )
    .unwrap_or(Thread { tid: 0, base: 0 });
    let _ = kid.reap();
    t.eq(
        "fs-shared-without-thread",
        sys(Sysno::umask, &[0o022]),
        Ok(0o027),
    );

    // One sighand for CLONE_SIGHAND.
    default_action(SIGUSR2);
    let th = spawn(
        |_| {
            install(SIGUSR2);
            0
        },
        0,
    );
    th.join();
    t.eq(
        "thread-sigaction-seen-by-main",
        handler_of(SIGUSR2),
        fn_addr(record as *const ()),
    );
    default_action(SIGUSR2);
    let kid = spawn_with(
        CLONE_VM | SIGCHLD,
        |_| {
            install(SIGUSR2);
            0
        },
        0,
    )
    .unwrap_or(Thread { tid: 0, base: 0 });
    let _ = kid.reap();
    t.eq("vm-child-has-its-own-sighand", handler_of(SIGUSR2), 0);
    let kid = spawn_with(
        CLONE_VM | CLONE_SIGHAND | SIGCHLD,
        |_| {
            install(SIGUSR2);
            0
        },
        0,
    )
    .unwrap_or(Thread { tid: 0, base: 0 });
    let (waited, status, _) = kid.reap();
    t.eq(
        "sighand-shared-without-thread",
        (waited, status, handler_of(SIGUSR2)),
        (Ok(kid.tid), 0, fn_addr(record as *const ())),
    );
    install(SIGUSR2);
    // The mask is per task and inherited at clone.
    procmask(2, bit(SIGUSR2));
    let th = spawn(
        |_| {
            let inherited = mask_now() & bit(SIGUSR2) != 0;
            procmask(2, 0);
            usize::from(inherited) | usize::from(mask_now() & bit(SIGUSR2) == 0) << 1
        },
        0,
    );
    t.eq("thread-inherits-mask-and-owns-it", th.join(), 3);
    t.eq(
        "main-mask-unchanged",
        mask_now() & bit(SIGUSR2),
        bit(SIGUSR2),
    );
    procmask(2, 0);
    // The alternate stack is reset in a CLONE_VM child (`sas_ss_reset`), kept in main.
    let alt = super::mmap(0, 8192, 3, 0x22, usize::MAX, 0).unwrap_or(0);
    let ss: [u64; 3] = [alt as u64, 0, 8192];
    let _ = sys(Sysno::sigaltstack, &[addr(&ss), 0]);
    let th = spawn(
        |_| {
            let mut old = [0u64; 3];
            let _ = sys(Sysno::sigaltstack, &[0, addr_mut(&mut old)]);
            (old[1] & 0xffff_ffff) as usize
        },
        0,
    );
    t.eq("thread-altstack-reset", th.join(), SS_DISABLE as usize);
    let mut mine = [0u64; 3];
    let _ = sys(Sysno::sigaltstack, &[0, addr_mut(&mut mine)]);
    t.eq("main-altstack-kept", (mine[0], mine[2]), (alt as u64, 8192));
    let off: [u64; 3] = [0, u64::from(SS_DISABLE), 0];
    let _ = sys(Sysno::sigaltstack, &[addr(&off), 0]);
}

fn delivery(t: &mut T) {
    let me = getpid();
    forget();
    // A thread-directed signal interrupts the targeted thread's futex wait; the handler runs in
    // that thread, with the sender's tgid.
    static RESULT: AtomicUsize = AtomicUsize::new(0);
    READY.store(0, SeqCst);
    GATE.store(0, SeqCst);
    let th = spawn(
        |_| {
            set_and_wake(&READY, 1);
            RESULT.store(raw_errno(futex(&GATE, FUTEX_WAIT, 0, 0, 0, 0)), SeqCst);
            0
        },
        0,
    );
    wait_for(&READY, 1);
    nap(30);
    t.eq("tgkill-thread", tgkill(th.tid, SIGUSR1), Ok(0));
    th.join();
    t.eq("handler-ran-in-target-thread", H_TID.load(SeqCst), th.tid);
    t.eq(
        "handler-siginfo",
        (
            H_COUNT.load(SeqCst),
            H_SIG.load(SeqCst),
            H_CODE.load(SeqCst),
            H_PID.load(SeqCst),
        ),
        (1, SIGUSR1, SI_TKILL, me),
    );
    t.eq(
        "futex-wait-interrupted-by-handler",
        RESULT.load(SeqCst),
        Errno::EINTR.into_raw() as usize,
    );

    // A process-directed signal that the leader blocks goes to a thread that does not.
    forget();
    READY.store(0, SeqCst);
    GATE.store(0, SeqCst);
    let th = spawn(
        |_| {
            set_and_wake(&READY, 1);
            let _ = futex(&GATE, FUTEX_WAIT, 0, 0, 0, 0);
            0
        },
        0,
    );
    wait_for(&READY, 1);
    nap(30);
    procmask(0, bit(SIGUSR1));
    t.eq("kill-process", sys(Sysno::kill, &[me, SIGUSR1]), Ok(0));
    nap(10);
    t.eq(
        "blocked-leader-passes-signal-to-thread",
        (
            H_TID.load(SeqCst),
            H_COUNT.load(SeqCst),
            H_CODE.load(SeqCst),
        ),
        (th.tid, 1, SI_USER),
    );
    set_and_wake(&GATE, 1);
    th.join();
    procmask(1, bit(SIGUSR1));

    // ... and the leader is tried first when nothing blocks the signal: a thread sends it to
    // the process while the leader sleeps.
    forget();
    READY.store(0, SeqCst);
    GATE.store(0, SeqCst);
    let th = spawn(
        |_| {
            nap(30);
            let _ = sys(Sysno::kill, &[getpid(), SIGUSR1]);
            0
        },
        0,
    );
    let r = futex(&GATE, FUTEX_WAIT, 0, 0, 0, 0);
    t.eq("leader-sleeping-is-interrupted", r, Err(Errno::EINTR));
    t.eq(
        "unblocked-leader-takes-process-signal",
        (H_TID.load(SeqCst), H_COUNT.load(SeqCst)),
        (me, 1),
    );
    th.join();

    // Pending sets: a private signal is the thread's, a shared one is every thread's.
    forget();
    READY.store(0, SeqCst);
    GATE.store(0, SeqCst);
    static PENDING: [AtomicUsize; 4] = [const { AtomicUsize::new(0) }; 4];
    let th = spawn(
        |_| {
            procmask(0, bit(SIGUSR2));
            set_and_wake(&READY, 1);
            wait_for(&READY, 2);
            PENDING[0].store(pending_now() as usize, SeqCst);
            set_and_wake(&READY, 3);
            wait_for(&READY, 4);
            PENDING[1].store(pending_now() as usize, SeqCst);
            set_and_wake(&READY, 5);
            wait_for(&READY, 6);
            procmask(1, bit(SIGUSR2));
            0
        },
        0,
    );
    wait_for(&READY, 1);
    procmask(0, bit(SIGUSR2));
    let _ = tgkill(th.tid, SIGUSR2);
    set_and_wake(&READY, 2);
    wait_for(&READY, 3);
    let main_private = pending_now();
    let _ = sys(Sysno::kill, &[me, SIGUSR2]);
    set_and_wake(&READY, 4);
    wait_for(&READY, 5);
    let main_shared = pending_now();
    t.eq(
        "private-pending-is-the-threads",
        (
            PENDING[0].load(SeqCst) as u64 & bit(SIGUSR2),
            main_private & bit(SIGUSR2),
        ),
        (bit(SIGUSR2), 0),
    );
    t.eq(
        "shared-pending-is-every-threads",
        (
            PENDING[1].load(SeqCst) as u64 & bit(SIGUSR2),
            main_shared & bit(SIGUSR2),
        ),
        (bit(SIGUSR2), bit(SIGUSR2)),
    );
    // The main thread unblocks first: it takes the shared signal. The thread then takes its own.
    procmask(1, bit(SIGUSR2));
    t.eq(
        "unblocking-main-takes-the-shared-one",
        (H_COUNT.load(SeqCst), H_TID.load(SeqCst)),
        (1, me),
    );
    set_and_wake(&READY, 6);
    th.join();
    t.eq(
        "unblocking-thread-takes-its-own",
        (H_COUNT.load(SeqCst), H_TID.load(SeqCst)),
        (2, th.tid),
    );

    // `rt_sigtimedwait` in a thread: a process-directed signal then a thread-directed one.
    forget();
    procmask(0, bit(SIGUSR1));
    static WAITED: [AtomicUsize; 6] = [const { AtomicUsize::new(0) }; 6];
    READY.store(0, SeqCst);
    let th = spawn(
        |_| {
            for round in 0..2 {
                let set = bit(SIGUSR1);
                let mut info = [0i32; 32];
                let five = [5i64, 0];
                set_and_wake(&READY, 1 + 2 * round as u32);
                let got = sys(
                    Sysno::rt_sigtimedwait,
                    &[addr(&set), addr_mut(&mut info), addr(&five), 8],
                );
                WAITED[3 * round].store(got.unwrap_or(usize::MAX), SeqCst);
                WAITED[3 * round + 1].store(info[2] as u32 as usize, SeqCst);
                WAITED[3 * round + 2].store(info[4] as u32 as usize, SeqCst);
            }
            0
        },
        0,
    );
    wait_for(&READY, 1);
    nap(20);
    let _ = sys(Sysno::kill, &[me, SIGUSR1]);
    wait_for(&READY, 3);
    nap(20);
    let _ = tgkill(th.tid, SIGUSR1);
    th.join();
    t.eq(
        "thread-sigwait-process-signal",
        (
            WAITED[0].load(SeqCst),
            WAITED[1].load(SeqCst),
            WAITED[2].load(SeqCst),
        ),
        (SIGUSR1, SI_USER, me),
    );
    t.eq(
        "thread-sigwait-thread-signal",
        (
            WAITED[3].load(SeqCst),
            WAITED[4].load(SeqCst),
            WAITED[5].load(SeqCst),
        ),
        (SIGUSR1, SI_TKILL, me),
    );
    t.eq("sigwait-consumed-the-signals", H_COUNT.load(SeqCst), 0);
    procmask(1, bit(SIGUSR1));

    // SIGCHLD of a child the thread forked goes to that thread (`do_notify_parent` signals
    // `tsk->parent`).
    forget();
    install(SIGCHLD);
    static KID: AtomicUsize = AtomicUsize::new(0);
    let th = spawn(
        |_| {
            let kid = fork_child(|| 0);
            KID.store(kid, SeqCst);
            for _ in 0..200 {
                if H_COUNT.load(SeqCst) != 0 {
                    break;
                }
                nap(1);
            }
            let _ = wait4(kid as isize, 0);
            0
        },
        0,
    );
    th.join();
    t.eq(
        "sigchld-goes-to-the-forking-thread",
        (
            H_COUNT.load(SeqCst),
            H_TID.load(SeqCst),
            H_CODE.load(SeqCst),
            H_PID.load(SeqCst),
        ),
        (1, th.tid, 1, KID.load(SeqCst)),
    );
    default_action(SIGCHLD);
    reap_all();
}

// ---- processes whose threads end in every way -----------------------------------------------

static PIPES: [AtomicUsize; 4] = [const { AtomicUsize::new(0) }; 4];
static LEADER_WORD: AtomicU32 = AtomicU32::new(0);

fn write_byte(fd: usize) {
    let _ = sys(Sysno::write, &[fd, addr(b"x"), 1]);
}

fn read_byte(fd: usize) -> R {
    let mut byte = [0u8; 1];
    sys(Sysno::read, &[fd, addr_mut(&mut byte), 1])
}

fn lifecycle(t: &mut T) {
    reap_all();
    // exit_group from a thread ends the process with its code while the others sleep.
    let sub = fork_child(|| {
        let _ = spawn(sleeper, 0);
        let _ = spawn(
            |_| {
                nap(20);
                exit_group(9)
            },
            0,
        );
        sleep_forever()
    });
    t.eq(
        "exit-group-from-thread",
        wait4(sub as isize, 0),
        (Ok(sub), 9 << 8),
    );
    t.eq("no-children-left", wait4(-1, WNOHANG).0, Err(Errno::ECHILD));

    // exit of the leader leaves a zombie that wait cannot reap until the last thread has gone;
    // the group's code is the last thread's (`synchronize_group_exit`).
    let (a_r, a_w) = pipe();
    let (b_r, b_w) = pipe();
    PIPES[0].store(a_w, SeqCst);
    PIPES[1].store(b_r, SeqCst);
    let sub = fork_child(|| {
        LEADER_WORD.store(1, SeqCst);
        let _ = sys(Sysno::set_tid_address, &[addr(&LEADER_WORD)]);
        let _ = spawn(
            |_| {
                // The kernel clears and wakes the leader's word when the leader exits.
                wait_for(&LEADER_WORD, 0);
                write_byte(PIPES[0].load(SeqCst));
                let _ = read_byte(PIPES[1].load(SeqCst));
                exit_thread(3)
            },
            0,
        );
        exit_thread(7)
    });
    let _ = read_byte(a_r);
    t.eq(
        "zombie-leader-is-not-waitable",
        wait4(sub as isize, WNOHANG).0,
        Ok(0),
    );
    write_byte(b_w);
    t.eq(
        "last-thread-sets-the-group-status",
        wait4(sub as isize, 0),
        (Ok(sub), 3 << 8),
    );
    // The leader as the last one to exit: its own code.
    let sub = fork_child(|| {
        let th = spawn(|_| exit_thread(5), 0);
        th.join();
        exit_thread(7)
    });
    t.eq(
        "last-leader-sets-the-group-status",
        wait4(sub as isize, 0),
        (Ok(sub), 7 << 8),
    );
    let _ = (close(a_r), close(a_w), close(b_r), close(b_w));

    // Fatal signals take the whole group down.
    let sub = fork_child(|| {
        let _ = spawn(sleeper, 0);
        let _ = spawn(sleeper, 0);
        let _ = sys(Sysno::kill, &[getpid(), SIGTERM]);
        sleep_forever()
    });
    t.eq(
        "sigterm-ends-the-group",
        wait4(sub as isize, 0),
        (Ok(sub), SIGTERM as i32),
    );
    // Sent by a thread to a process whose leader blocks it: the thread takes it and the group dies.
    let sub = fork_child(|| {
        let _ = spawn(
            |_| {
                nap(20);
                let _ = sys(Sysno::kill, &[getpid(), SIGTERM]);
                sleep_forever()
            },
            0,
        );
        procmask(0, bit(SIGTERM));
        sleep_forever()
    });
    t.eq(
        "sigterm-blocked-in-the-leader-ends-the-group",
        wait4(sub as isize, 0),
        (Ok(sub), SIGTERM as i32),
    );
    // SIGKILL addressed to the leader's tid by another thread.
    let sub = fork_child(|| {
        let _ = spawn(
            |_| {
                let _ = tgkill(getpid(), SIGKILL);
                sleep_forever()
            },
            0,
        );
        sleep_forever()
    });
    t.eq(
        "tgkill-sigkill-ends-the-group",
        wait4(sub as isize, 0),
        (Ok(sub), SIGKILL as i32),
    );
    // A fault in a thread is delivered to that thread and its default action ends the group.
    let sub = fork_child(|| {
        let _ = spawn(sleeper, 0);
        let _ = spawn(
            |_| {
                // SAFETY: deliberately faulting: a volatile store to the null page; the point
                // of the check is the SIGSEGV this raises.
                unsafe { core::ptr::null_mut::<u8>().write_volatile(1) };
                0
            },
            0,
        );
        sleep_forever()
    });
    t.eq(
        "sigsegv-in-a-thread-ends-the-group",
        wait4(sub as isize, 0),
        (Ok(sub), 11),
    );
    // exit_group by the leader while threads are blocked in system calls.
    let sub = fork_child(|| {
        let _ = spawn(sleeper, 0);
        let _ = spawn(sleeper, 0);
        nap(20);
        exit_group(4)
    });
    t.eq(
        "exit-group-from-leader",
        wait4(sub as isize, 0),
        (Ok(sub), 4 << 8),
    );

    // execve from a thread that is not the leader: the others are gone, the thread has the
    // leader's pid, and the parent waits for the pid it knew.
    // The new image prints the banner of every `/init`: its output goes to a pipe.
    let (image_r, image_w) = pipe();
    PIPES[1].store(image_w, SeqCst);
    let sub = fork_child(|| {
        let _ = sys(Sysno::dup3, &[PIPES[1].load(SeqCst), 1, 0]);
        let _ = spawn(sleeper, 0);
        let _ = spawn(
            |_| {
                let (mut pid_text, mut tid_text) = ([0u8; 24], [0u8; 24]);
                decimal(getpid(), &mut pid_text);
                decimal(gettid(), &mut tid_text);
                let argv: [usize; 5] = [
                    addr(b"init\0"),
                    addr(b"thrimage\0"),
                    addr(&pid_text),
                    addr(&tid_text),
                    0,
                ];
                let envp: [usize; 1] = [0];
                let _ = sys(Sysno::execve, &[addr(b"/init\0"), addr(&argv), addr(&envp)]);
                1
            },
            0,
        );
        sleep_forever()
    });
    t.eq(
        "exec-from-a-thread",
        wait4(sub as isize, 0),
        (Ok(sub), 0x1f << 8),
    );
    let _ = (close(image_r), close(image_w));

    // Children belong to the group: a thread waits for the leader's child; with __WNOTHREAD it
    // cannot.
    let (c_r, c_w) = pipe();
    PIPES[0].store(c_r, SeqCst);
    let kid = fork_child(|| {
        let _ = read_byte(PIPES[0].load(SeqCst));
        4
    });
    static WAIT_RESULT: [AtomicUsize; 3] = [const { AtomicUsize::new(0) }; 3];
    static KID_PID: AtomicUsize = AtomicUsize::new(0);
    KID_PID.store(kid, SeqCst);
    READY.store(0, SeqCst);
    let th = spawn(
        |_| {
            let (r, _) = wait4(-1, WNOTHREAD | WNOHANG);
            WAIT_RESULT[0].store(raw_errno(r), SeqCst);
            set_and_wake(&READY, 1);
            wait_for(&READY, 2);
            let (r, status) = wait4(KID_PID.load(SeqCst) as isize, 0);
            WAIT_RESULT[1].store(r.unwrap_or(usize::MAX), SeqCst);
            WAIT_RESULT[2].store(status as usize, SeqCst);
            0
        },
        0,
    );
    wait_for(&READY, 1);
    write_byte(c_w);
    set_and_wake(&READY, 2);
    th.join();
    t.eq(
        "thread-waits-for-the-groups-child",
        (
            WAIT_RESULT[0].load(SeqCst),
            WAIT_RESULT[1].load(SeqCst),
            WAIT_RESULT[2].load(SeqCst),
        ),
        (Errno::ECHILD.into_raw() as usize, kid, 4 << 8),
    );
    let _ = (close(c_r), close(c_w));

    // A thread's children are adopted by another thread when it exits, not by init.
    let (d_r, d_w) = pipe();
    PIPES[0].store(d_r, SeqCst);
    static ADOPTED: AtomicUsize = AtomicUsize::new(0);
    PIPES[2].store(getpid(), SeqCst);
    let th = spawn(
        |_| {
            let kid = fork_child(|| {
                let _ = read_byte(PIPES[0].load(SeqCst));
                let me_ppid = sys(Sysno::getppid, &[]).unwrap_or(0);
                // The group's pid is the parent's tgid whichever thread adopted it.
                if me_ppid == PIPES[2].load(SeqCst) {
                    6
                } else {
                    99
                }
            });
            ADOPTED.store(kid, SeqCst);
            0
        },
        0,
    );
    th.join();
    write_byte(d_w);
    t.eq(
        "children-of-an-exited-thread-stay-in-the-group",
        wait4(ADOPTED.load(SeqCst) as isize, 0),
        (Ok(ADOPTED.load(SeqCst)), 6 << 8),
    );
    let _ = (close(d_r), close(d_w));

    // A group stop covers every thread, the parent hears of it once, and the continue and a
    // later fatal signal reach all of them.
    let sub = fork_child(|| {
        let _ = spawn(sleeper, 0);
        let _ = spawn(sleeper, 0);
        sleep_forever()
    });
    nap(40);
    let _ = sys(Sysno::kill, &[sub, SIGSTOP]);
    t.eq(
        "group-stop-is-reported",
        wait4(sub as isize, WUNTRACED),
        (Ok(sub), 0x137f),
    );
    t.eq(
        "group-stop-is-reported-once",
        wait4(sub as isize, WUNTRACED | WNOHANG),
        (Ok(0), -1),
    );
    let _ = sys(Sysno::kill, &[sub, SIGCONT]);
    t.eq(
        "group-continue-is-reported",
        wait4(sub as isize, WCONTINUED),
        (Ok(sub), 0xffff),
    );
    let _ = sys(Sysno::kill, &[sub, SIGKILL]);
    t.eq(
        "group-is-killed-after-the-continue",
        wait4(sub as isize, 0),
        (Ok(sub), 9),
    );
    reap_all();
}

/// `n` as NUL-terminated decimal text in `out`.
fn decimal(mut n: usize, out: &mut [u8; 24]) {
    let mut digits = [0u8; 24];
    let mut len = 0;
    while n > 0 {
        digits[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }
    for i in 0..len {
        out[i] = digits[len - 1 - i];
    }
}

/// `threadleak` mode: 202 clones that share the address space, one per round, in four shapes
/// (a thread, a `CLONE_VM` child with its own `SIGCHLD`, a `vfork`, a thread with
/// `CLONE_CHILD_SETTID`), each joined or waited for. Prints the records of `forkleak`: the counts
/// and the free RAM `sysinfo` reports before and after (after two warm-up rounds); the kernel
/// prints its live-object counts when init exits and the harness requires them unchanged.
pub fn threadleak() {
    fn free_ram() -> u64 {
        let mut info = [0u64; 14];
        let _ = sys(Sysno::sysinfo, &[addr_mut(&mut info)]);
        info[5]
    }
    fn round(n: usize) -> bool {
        let work: fn(&'static Control) -> usize = |c| c.arg + 1;
        match n % 4 {
            0 => spawn_with(THREAD_FLAGS, work, n).is_ok_and(|th| th.join() == n + 1),
            1 => spawn_with(CLONE_VM | CLONE_FS | CLONE_FILES | SIGCHLD, work, n).is_ok_and(|th| {
                let (r, status, result) = th.reap();
                r == Ok(th.tid) && status == 0 && result == n + 1
            }),
            2 => spawn_with(CLONE_VM | CLONE_VFORK | SIGCHLD, work, n).is_ok_and(|th| {
                let (r, status, result) = th.reap();
                r == Ok(th.tid) && status == 0 && result == n + 1
            }),
            _ => spawn_with(THREAD_FLAGS | CLONE_CHILD_SETTID, work, n)
                .is_ok_and(|th| th.join() == n + 1),
        }
    }
    let warm = round(0) && round(1);
    let before = free_ram();
    let mut reaped = 0usize;
    for n in 2..202 {
        reaped += usize::from(round(n));
    }
    let after = free_ram();
    let none_left = wait4(-1, WNOHANG).0 == Err(Errno::ECHILD);
    super::emit(format_args!(
        "init: forkleak warm={warm} rounds=200 reaped={reaped} none_left={none_left}"
    ));
    super::emit(format_args!(
        "init: forkleak free_ram before={before} after={after}"
    ));
    if !(warm && reaped == 200 && none_left) {
        crate::exit(1);
    }
}

/// The image `execve`d by a non-leader thread of the `lifecycle` check: exits with a bit per
/// fact (31 when it is the whole group's leader with the old leader's pid).
pub fn image(argv: crate::Strings) -> ! {
    let number = |index: usize| {
        argv.iter().nth(index).map_or(0, |text| {
            text.iter()
                .fold(0usize, |n, d| n * 10 + usize::from(d - b'0'))
        })
    };
    let (old_pid, old_tid) = (number(2), number(3));
    let facts = [
        getpid() == old_pid,
        gettid() == getpid(),
        old_tid != old_pid,
        sys(Sysno::tgkill, &[getpid(), old_tid, 0]) == Err(Errno::ESRCH),
        fs_base() == 0,
    ];
    let status = facts
        .iter()
        .enumerate()
        .fold(0usize, |bits, (i, ok)| bits | usize::from(*ok) << i);
    exit_group(status)
}

// ---- per-thread FPU state ----------------------------------------------------------------

fn set_xmm3(value: u64) {
    // SAFETY: loads XMM3 from a general register. The target is soft-float, so the compiler
    // keeps nothing live in XMM registers and this clobbers no value it relies on; no memory,
    // flag or stack effects; SSE2 is part of x86-64.
    unsafe {
        asm!("movq xmm3, {v}", v = in(reg) value, options(nomem, nostack, preserves_flags));
    }
}

fn xmm3() -> u64 {
    let value: u64;
    // SAFETY: as `set_xmm3`; reads XMM3 into a general register.
    unsafe {
        asm!("movq {v}, xmm3", v = out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}

static TURN: AtomicU32 = AtomicU32::new(0);
static FPU_RESULT: [AtomicUsize; 2] = [const { AtomicUsize::new(0) }; 2];
const ROUNDS: u32 = 100;

fn fpu(t: &mut T) {
    // A new thread starts with its creator's FPU registers (`fpu_clone`) and then owns them.
    set_xmm3(0xaaaa_aaaa_aaaa_aaaa);
    TURN.store(0, SeqCst);
    let th = spawn(
        |_| {
            FPU_RESULT[0].store(usize::from(xmm3() == 0xaaaa_aaaa_aaaa_aaaa), SeqCst);
            let mut ok = true;
            for round in 0..ROUNDS {
                set_xmm3(0x2000_0000_0000_0000 | u64::from(round));
                wait_for(&TURN, 2 * round + 1);
                ok &= xmm3() == 0x2000_0000_0000_0000 | u64::from(round);
                set_and_wake(&TURN, 2 * round + 2);
            }
            FPU_RESULT[1].store(usize::from(ok), SeqCst);
            0
        },
        0,
    );
    let mut ok = true;
    for round in 0..ROUNDS {
        set_xmm3(0x1000_0000_0000_0000 | u64::from(round));
        set_and_wake(&TURN, 2 * round + 1);
        wait_for(&TURN, 2 * round + 2);
        ok &= xmm3() == 0x1000_0000_0000_0000 | u64::from(round);
    }
    th.join();
    t.eq(
        "thread-starts-with-creators-fpu",
        FPU_RESULT[0].load(SeqCst),
        1,
    );
    t.eq(
        "thread-fpu-survives-switches",
        FPU_RESULT[1].load(SeqCst),
        1,
    );
    t.eq("main-fpu-survives-switches", usize::from(ok), 1);
    set_xmm3(0);
}

// ---- many threads, one lock ---------------------------------------------------------------

static LOCK: AtomicU32 = AtomicU32::new(0);
static TOTAL: AtomicUsize = AtomicUsize::new(0);

/// A `futex`-based mutex (Drepper, "Futexes are tricky", mutex2).
fn lock(word: &AtomicU32) {
    let Err(mut c) = word.compare_exchange(0, 1, SeqCst, SeqCst) else {
        return;
    };
    if c != 2 {
        c = word.swap(2, SeqCst);
    }
    while c != 0 {
        let _ = futex(word, FUTEX_WAIT, 2, 0, 0, 0);
        c = word.swap(2, SeqCst);
    }
}

fn unlock(word: &AtomicU32) {
    if word.fetch_sub(1, SeqCst) != 1 {
        word.store(0, SeqCst);
        let _ = futex(word, FUTEX_WAKE, 1, 0, 0, 0);
    }
}

fn stress(t: &mut T) {
    const THREADS: usize = 6;
    const ITERATIONS: usize = 100;
    let mut all = [Thread { tid: 0, base: 0 }; THREADS];
    for th in &mut all {
        *th = spawn(
            |_| {
                for _ in 0..ITERATIONS {
                    lock(&LOCK);
                    // Not an atomic read-modify-write: lost updates show a broken lock.
                    let seen = TOTAL.load(Relaxed);
                    if seen % 25 == 0 {
                        // Sleep holding the lock so that the others queue on the futex.
                        nap(1);
                    }
                    TOTAL.store(seen + 1, Relaxed);
                    unlock(&LOCK);
                }
                ITERATIONS
            },
            0,
        );
    }
    let sum: usize = all.iter().map(Thread::join).sum();
    t.eq(
        "mutex-keeps-every-update",
        TOTAL.load(SeqCst),
        THREADS * ITERATIONS,
    );
    t.eq("every-thread-ran-to-the-end", sum, THREADS * ITERATIONS);
    t.holds(
        "distinct-tids",
        all.iter()
            .enumerate()
            .all(|(i, a)| all[..i].iter().all(|b| b.tid != a.tid) && a.tid != 0),
        all.map(|th| th.tid),
        "six different tids",
    );
}

// ---- CPU time of a group ------------------------------------------------------------------

/// `CLOCK_PROCESS_CPUTIME_ID` sums the group's threads, the finished ones included
/// (`thread_group_cputime`); `CLOCK_THREAD_CPUTIME_ID` is the caller's own; `times(2)` reports
/// the group (`thread_group_cputime_adjusted`).
fn cpu_time(t: &mut T) {
    const PROCESS_CPUTIME: usize = 2;
    const THREAD_CPUTIME: usize = 3;
    const BURN_NS: u64 = 40_000_000;
    fn clock(id: usize) -> u64 {
        let mut ts = [0i64; 2];
        let _ = sys(Sysno::clock_gettime, &[id, addr_mut(&mut ts)]);
        ts[0].cast_unsigned() * 1_000_000_000 + ts[1].cast_unsigned()
    }
    fn ticks() -> u64 {
        let mut tms = [0u64; 4];
        let _ = sys(Sysno::times, &[addr_mut(&mut tms)]);
        tms[0] + tms[1]
    }
    static OWN: AtomicUsize = AtomicUsize::new(0);
    let (process_before, ticks_before) = (clock(PROCESS_CPUTIME), ticks());
    let th = spawn(
        |_| {
            let start = clock(THREAD_CPUTIME);
            while clock(THREAD_CPUTIME) - start < BURN_NS {}
            OWN.store((clock(THREAD_CPUTIME) - start) as usize, SeqCst);
            0
        },
        0,
    );
    th.join();
    let own = OWN.load(SeqCst) as u64;
    t.holds(
        "thread-burned-its-share",
        own >= BURN_NS,
        own,
        "at least 40 ms of its own clock",
    );
    let process_after = clock(PROCESS_CPUTIME);
    t.holds(
        "process-cpu-clock-keeps-a-finished-thread",
        process_after - process_before >= own,
        (process_after - process_before, own),
        "the group's clock grew by at least the thread's time",
    );
    t.holds(
        "thread-cpu-clock-is-the-callers-own",
        clock(THREAD_CPUTIME) <= process_after,
        clock(THREAD_CPUTIME),
        "no more than the process clock",
    );
    t.holds(
        "times-includes-a-finished-thread",
        ticks() - ticks_before >= 3,
        ticks() - ticks_before,
        "at least 3 ticks of 10 ms",
    );
}
