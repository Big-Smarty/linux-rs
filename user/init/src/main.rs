// SPDX-License-Identifier: GPL-2.0-only
//! First userspace program: a static, libc-free Linux `x86_64` `/init` that
//! checks the process-entry contract (stack, auxv, a few syscall errors) and
//! reports on stdout. It runs unchanged on real Linux, which makes it an
//! oracle for the kernel's `execve` and `write`/`exit_group` behaviour.
#![no_std]
#![no_main]

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
compile_error!(
    "init requires --target x86_64-unknown-none; host tools/tests do not enable freestanding"
);

// Links the reviewed scalar `memset`/`memcpy` the compiler emits calls to.
use linux_rs_runtime as _;

use core::arch::{asm, naked_asm};
use core::fmt::{self, Debug, Display, Write};
use core::{panic::PanicInfo, ptr, slice};
use syscalls::{Errno, Sysno, raw};

macro_rules! auxv_keys {
    ($($name:ident = $value:expr),* $(,)?) => {
        $(const $name: usize = $value;)*
        /// `Display` of an auxv key: its `AT_*` name, or `AT_<n>` if unknown.
        struct AtName(usize);
        impl Display for AtName {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self.0 {
                    $($name => f.write_str(stringify!($name)),)*
                    other => write!(f, "AT_{other}"),
                }
            }
        }
    };
}

// include/uapi/linux/auxvec.h and arch/x86/include/uapi/asm/auxvec.h at v6.18.57.
auxv_keys! {
    AT_NULL = 0, AT_IGNORE = 1, AT_EXECFD = 2, AT_PHDR = 3, AT_PHENT = 4, AT_PHNUM = 5,
    AT_PAGESZ = 6, AT_BASE = 7, AT_FLAGS = 8, AT_ENTRY = 9, AT_NOTELF = 10, AT_UID = 11,
    AT_EUID = 12, AT_GID = 13, AT_EGID = 14, AT_PLATFORM = 15, AT_HWCAP = 16, AT_CLKTCK = 17,
    AT_SECURE = 23, AT_BASE_PLATFORM = 24, AT_RANDOM = 25, AT_HWCAP2 = 26,
    AT_RSEQ_FEATURE_SIZE = 27, AT_RSEQ_ALIGN = 28, AT_HWCAP3 = 29, AT_HWCAP4 = 30,
    AT_EXECFN = 31, AT_SYSINFO = 32, AT_SYSINFO_EHDR = 33, AT_MINSIGSTKSZ = 51,
}

/// Kernel limit on one argv/envp string (`MAX_ARG_STRLEN`), so a scan is bounded.
const MAX_STRING: usize = 32 * 4096;

/// Leading fields of the ELF64 header; the linker places the header in the first
/// loaded segment and names it `__ehdr_start`.
#[repr(C)]
struct Ehdr {
    ident: [u8; 16],
    kind: u16,
    machine: u16,
    version: u32,
    entry: usize,
    phoff: usize,
    shoff: usize,
    flags: u32,
    ehsize: u16,
    phentsize: u16,
    phnum: u16,
}

unsafe extern "C" {
    static __ehdr_start: Ehdr;
}

/// Raw `write(2)`. Safe to call with any pointer: the kernel copies with fault
/// handling and answers EFAULT, so no memory of this process is accessed.
fn write(fd: usize, buf: usize, len: usize) -> Result<usize, Errno> {
    // SAFETY: `write` reads, never writes, process memory and only via the kernel's
    // checked user copy; it cannot invalidate any Rust object.
    unsafe { syscalls::syscall3(Sysno::write, fd, buf, len) }
}

/// stdout as `fmt::Write`; write errors are dropped (there is nowhere to report them).
struct Out;

impl Write for Out {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let mut rest = s.as_bytes();
        while !rest.is_empty() {
            match write(1, rest.as_ptr().expose_provenance(), rest.len()) {
                Ok(0) => return Err(fmt::Error),
                Ok(n) => rest = rest.get(n..).ok_or(fmt::Error)?,
                Err(Errno::EINTR) => {}
                Err(_) => return Err(fmt::Error),
            }
        }
        Ok(())
    }
}

macro_rules! out {
    ($($arg:tt)*) => {{ let _ = writeln!(Out, $($arg)*); }};
}

mod tests;

fn exit(code: usize) -> ! {
    loop {
        // SAFETY: exit_group takes no pointers and never returns.
        let _ = unsafe { syscalls::syscall1(Sysno::exit_group, code) };
    }
}

fn fail(check: impl Display, got: impl Debug) -> ! {
    out!("init: FAIL {check} got={got:?}");
    exit(1)
}

fn expect<T: Copy + PartialEq + Debug>(check: impl Display, got: T, want: T) {
    if got != want {
        fail(check, got);
    }
}

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    out!("init: FAIL panic");
    exit(1)
}

/// Unquoted, lossy-UTF-8 text of a byte string (`Debug` so it composes with `fail`).
struct Lossy<'a>(&'a [u8]);

impl Debug for Lossy<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for chunk in self.0.utf8_chunks() {
            f.write_str(chunk.valid())?;
            if !chunk.invalid().is_empty() {
                f.write_char(char::REPLACEMENT_CHARACTER)?;
            }
        }
        Ok(())
    }
}

/// The NUL-terminated string at `addr`, or `None` if it is null or has no NUL
/// within `MAX_STRING` bytes.
///
/// # Safety
///
/// Every byte up to the NUL (or `MAX_STRING`) must be readable and stay
/// unmodified for the rest of the process.
unsafe fn cstr(addr: usize) -> Option<&'static [u8]> {
    if addr == 0 {
        return None;
    }
    let start = ptr::with_exposed_provenance::<u8>(addr);
    for len in 0..MAX_STRING {
        // SAFETY: in range by the caller's contract.
        if unsafe { start.add(len).read() } == 0 {
            // SAFETY: the `len` bytes before the NUL were just read.
            return Some(unsafe { slice::from_raw_parts(start, len) });
        }
    }
    None
}

/// The pointer words of an argv/envp array of process-stack strings; a bad
/// string reads as empty. The pointers come from the initial stack, so `iter`
/// relies on `Stack::new`'s contract.
#[derive(Clone, Copy)]
struct Strings(&'static [usize]);

impl Strings {
    fn iter(self) -> impl Iterator<Item = &'static [u8]> {
        // SAFETY: `Stack::new` guarantees these are valid process-stack strings.
        self.0
            .iter()
            .map(|&p| unsafe { cstr(p) }.unwrap_or_default())
    }
}

impl Strings {
    /// The environment Linux gives init when the command line adds none
    /// (`envp_init` in `init/main.c`).
    fn is_kernel_default(self) -> bool {
        self.iter().eq([b"HOME=/".as_slice(), b"TERM=linux"])
    }
}

impl Debug for Strings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, s) in self.iter().enumerate() {
            if i > 0 {
                f.write_char(',')?;
            }
            Lossy(s).fmt(f)?;
        }
        Ok(())
    }
}

/// The initial process stack: `argc`, `argv[]`, NULL, `envp[]`, NULL, auxv pairs, `AT_NULL`.
struct Stack {
    sp: usize,
    argc: usize,
    argv: Strings,
    envp: Strings,
    auxv: &'static [[usize; 2]],
}

impl Stack {
    /// # Safety
    ///
    /// `sp` must be the stack pointer at process entry (System V x86-64 ABI
    /// process initialization), which stays valid for the process lifetime.
    // shortcut: assumes 8-byte-aligned sp and a correct layout; a malformed
    // stack faults instead of being reported, fine while only Linux builds it.
    unsafe fn new(sp: *const usize) -> Self {
        /// Words before the first zero word.
        // SAFETY (caller): a zero word exists after `p`, within the stack.
        unsafe fn words(p: *const usize) -> usize {
            let mut n = 0;
            while unsafe { p.add(n).read() } != 0 {
                n += 1;
            }
            n
        }
        // SAFETY: the layout is the caller's contract; each array is followed by
        // its terminator, which `+ 1` steps over.
        unsafe {
            let argv = sp.add(1);
            let argv_len = words(argv);
            let envp = argv.add(argv_len + 1);
            let envp_len = words(envp);
            let auxv = envp.add(envp_len + 1).cast::<[usize; 2]>();
            let mut auxv_len = 0;
            while auxv.add(auxv_len).read()[0] != AT_NULL {
                auxv_len += 1;
            }
            Self {
                sp: sp.addr(),
                argc: sp.read(),
                argv: Strings(slice::from_raw_parts(argv, argv_len)),
                envp: Strings(slice::from_raw_parts(envp, envp_len)),
                auxv: slice::from_raw_parts(auxv, auxv_len),
            }
        }
    }

    fn find(&self, key: usize) -> Option<usize> {
        self.auxv
            .iter()
            .find(|pair| pair[0] == key)
            .map(|pair| pair[1])
    }

    /// The value of auxv `key`; a missing entry is a failed check, not a panic.
    fn aux(&self, key: usize) -> usize {
        self.find(key)
            .unwrap_or_else(|| fail(AtName(key), "missing"))
    }

    /// The string an auxv entry points at (empty if absent or unterminated).
    fn aux_string(&self, key: usize) -> Lossy<'static> {
        // SAFETY: as in `run`, a bad kernel-provided string faults; the summary
        // line is printed before any check so the fault is visible.
        Lossy(
            self.find(key)
                .and_then(|addr| unsafe { cstr(addr) })
                .unwrap_or_default(),
        )
    }
}

impl Debug for Stack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "argc={} argv0={:?} pid={} rsp_mod16={} auxv=",
            self.argc,
            Lossy(self.argv.iter().next().unwrap_or_default()),
            pid(),
            self.sp % 16
        )?;
        for (i, &[key, value]) in self.auxv.iter().enumerate() {
            let separator = if i > 0 { "," } else { "" };
            write!(f, "{separator}{}:", AtName(key))?;
            // Stack/vDSO addresses legitimately differ between runs and kernels.
            if matches!(key, AT_SYSINFO_EHDR | AT_RANDOM | AT_EXECFN | AT_PLATFORM) {
                f.write_char('*')?;
            } else {
                write!(f, "{value:#x}")?;
            }
        }
        write!(
            f,
            " execfn={:?} platform={:?} envp=",
            self.aux_string(AT_EXECFN),
            self.aux_string(AT_PLATFORM)
        )?;
        // Print entries only when they are exactly the kernel's default init
        // environment (see `Strings::is_kernel_default`). Any other environment,
        // including a pid-1 one in a container's PID namespace, may hold secrets
        // and is reduced to its entry count.
        if pid() == 1 && self.envp.is_kernel_default() {
            write!(f, "{:?}", self.envp)
        } else {
            write!(f, "{}", self.envp.0.len())
        }
    }
}

fn pid() -> usize {
    // SAFETY: getpid takes no arguments, cannot fail and touches no memory.
    unsafe { syscalls::syscall0(Sysno::getpid) }.unwrap_or(usize::MAX)
}

fn run(stack: &Stack) {
    // An `execve`d image of the `proc` oracle tests prints no pid-dependent summary.
    if stack.argv.iter().nth(1) == Some(b"execd".as_slice()) {
        tests::proc::execd(stack.argv, stack.envp);
    }
    // The image of the `fork` group's exec-id check: also silent, and exits with a signal number.
    if stack.argv.iter().nth(1) == Some(b"execsig".as_slice()) {
        tests::fork::execsig(stack.argv);
    }
    // The image of the `jobctl` group's `setpgid`-after-`execve` check: silent too.
    if stack.argv.iter().nth(1) == Some(b"jobwait".as_slice()) {
        tests::jobctl::jobwait();
    }
    out!("init: {stack:?}");

    expect("rsp_mod16", stack.sp % 16, 0);
    if stack.argc < 1 {
        fail("argc", stack.argc);
    }
    expect("argv_terminator", stack.argv.0.len(), stack.argc);
    expect(AtName(AT_PAGESZ), stack.aux(AT_PAGESZ), 4096);
    // SAFETY: the linker defines `__ehdr_start` as the start of the loaded ELF header.
    let ehdr = unsafe { &*ptr::addr_of!(__ehdr_start) };
    expect(
        AtName(AT_PHDR),
        stack.aux(AT_PHDR),
        ptr::from_ref(ehdr).addr() + ehdr.phoff,
    );
    expect(AtName(AT_PHENT), stack.aux(AT_PHENT), 56);
    expect(
        AtName(AT_PHNUM),
        stack.aux(AT_PHNUM),
        usize::from(ehdr.phnum),
    );
    let start: unsafe extern "C" fn() -> ! = entry;
    expect(AtName(AT_ENTRY), stack.aux(AT_ENTRY), start as usize);
    expect(AtName(AT_SECURE), stack.aux(AT_SECURE), 0);
    let random = stack.aux(AT_RANDOM);
    if random == 0 {
        fail(AtName(AT_RANDOM), "null");
    }
    for offset in 0..16 {
        // SAFETY: the 16 bytes are the kernel's AT_RANDOM block; an unreadable
        // one faults, which is the failure this check exists to expose.
        let _ = unsafe {
            ptr::with_exposed_provenance::<u8>(random)
                .add(offset)
                .read_volatile()
        };
    }
    for key in [AT_EXECFN, AT_PLATFORM] {
        // SAFETY: as above, a bad kernel-provided string faults.
        if unsafe { cstr(stack.aux(key)) }.is_none() {
            fail(AtName(key), "unreadable");
        }
    }

    let buf = b"x".as_ptr().expose_provenance();
    expect("write_zero_length", write(1, buf, 0), Ok(0));
    expect("write_null", write(1, 0, 1), Err(Errno::EFAULT));
    expect("write_low_address", write(1, 8, 5), Err(Errno::EFAULT));
    // Above any RLIMIT_NOFILE, so it is never open and nothing can be written.
    expect(
        "write_bad_fd",
        write(0x7fff_ffff, buf, 1),
        Err(Errno::EBADF),
    );
    expect(
        "write_fd_minus_one",
        write(usize::MAX, buf, 1),
        Err(Errno::EBADF),
    );
    // SAFETY: an undefined syscall number takes no arguments and touches no memory.
    let unknown = Errno::from_ret(unsafe { raw::syscall0(100_000) });
    expect("syscall_100000", unknown, Err(Errno::ENOSYS));

    // As the kernel's own init (init/main.c argv_init/envp_init defaults); a
    // command line `rdinit=`, `init=`, `key=value` or `--` word changes these.
    if pid() == 1 {
        let argv0 = stack.argv.iter().next().unwrap_or_default();
        if argv0 != b"/init" {
            fail("pid1_argv0", Lossy(argv0));
        }
        if !stack.envp.is_kernel_default() {
            // Count only: this pid 1 may be a PID-namespace one with a real environment.
            fail("pid1_envp", stack.envp.0.len());
        }
    }

    if let Some(word) = stack.argv.iter().nth(2) {
        tests::set_suite_args(word, stack.argv.iter().nth(3));
    }
    match stack.argv.iter().nth(1) {
        // A group that never ends: only the bare-metal suite's time bound stops it.
        // It leaves an `ITIMER_REAL` armed (2 ms interval; SIGALRM is dropped for
        // init), which the suite's group teardown must not carry into the next group.
        Some(b"spin") => {
            out!("init: spinning on purpose");
            let itimerval: [i64; 4] = [0, 2000, 0, 2000];
            // SAFETY: `itimerval` is a live 32-byte `struct itimerval`; a null old value.
            let armed = unsafe {
                syscalls::syscall3(
                    Sysno::setitimer,
                    0,
                    ptr::from_ref(&itimerval).expose_provenance(),
                    0,
                )
            };
            expect("spin-itimer", armed, Ok(0));
            loop {
                core::hint::spin_loop();
            }
        }
        // Group ends in the context of a child: init sleeps in `wait4` while the child
        // spins, so the group's time bound finds the child on the CPU (the suite must
        // end the whole group, not just that task), and `orphan` exits init while the
        // child still spins (the next group must still start).
        Some(b"spinchild") => {
            out!("init: child spinning on purpose");
            fork_spinner();
            // SAFETY: wait4 for any child, no status pointer, no options, no rusage.
            let _ = unsafe { syscalls::syscall4(Sysno::wait4, usize::MAX, 0, 0, 0) };
        }
        Some(b"orphan") => {
            out!("init: leaving an orphan spinning");
            fork_spinner();
        }
        // Every task asleep and nothing to wake it: init reads an empty pipe whose write
        // end it holds itself, as Linux would sleep on it forever. The suite's time bound
        // must end the group from the idle CPU.
        Some(b"block") => {
            out!("init: blocking on an empty pipe on purpose");
            let mut fds = [0u32; 2];
            // SAFETY: `fds` is a live 8-byte buffer for the two descriptors; a one-byte
            // read into a live stack byte.
            let (made, read) = unsafe {
                let made = syscalls::syscall2(
                    Sysno::pipe2,
                    ptr::from_mut(&mut fds).expose_provenance(),
                    0,
                );
                let mut byte = 0u8;
                let read = syscalls::syscall3(
                    Sysno::read,
                    fds[0] as usize,
                    ptr::from_mut(&mut byte).expose_provenance(),
                    1,
                );
                (made, read)
            };
            expect("block-pipe", made, Ok(0));
            fail("block", read);
        }
        Some(b"fault") => {
            out!("init: faulting on purpose");
            // SAFETY: not sound, deliberately: the read of address 0 must raise SIGSEGV.
            let _ = unsafe { ptr::null::<u8>().read_volatile() };
            fail("fault", "returned");
        }
        // A syscall inside Linux's table that the first kernel slice does not
        // implement: the candidate kernel stops with `FAIL syscall unimplemented
        // nr=9`. Real Linux returns EINVAL for this zero-length mmap (the memory
        // syscalls are implemented now: the kernel-test case uses `io_uring`).
        Some(b"mmap") => {
            out!("init: calling mmap");
            // SAFETY: length 0 maps nothing; the call takes no pointers.
            let result = Errno::from_ret(unsafe {
                raw::syscall6(Sysno::mmap as usize, 0, 0, 3, 0x22, usize::MAX, 0)
            });
            fail("mmap", result);
        }
        // io_uring_setup(2) is in Linux's table (`CONFIG_IO_URING=y` in the reference
        // configuration) and far from anything this kernel implements: the
        // candidate stops with `FAIL syscall unimplemented nr=425`. Real Linux
        // answers EFAULT for the null `io_uring_params` pointer.
        Some(b"io_uring") => {
            out!("init: calling io_uring_setup");
            // SAFETY: entries 0 and a null params pointer; the call touches no memory
            // of this process (Linux rejects the null pointer, never dereferencing it).
            let result =
                Errno::from_ret(unsafe { raw::syscall2(Sysno::io_uring_setup as usize, 0, 0) });
            fail("io_uring_setup", result);
        }
        // rseq(2) is -ENOSYS in the candidate's declared configuration
        // (CONFIG_RSEQ=n); a Linux with RSEQ=y answers EINVAL for these arguments.
        Some(b"rseq") => {
            // SAFETY: a null rseq area with flags 0 and length 0 is rejected by the kernel.
            let result =
                Errno::from_ret(unsafe { raw::syscall4(Sysno::rseq as usize, 0, 0, 0, 0) });
            expect("rseq", result, Err(Errno::ENOSYS));
            out!("init: rseq enosys");
        }
        Some(b"sse") => fpu_checks(),
        Some(b"demand") => {
            demand_paging();
            out!("init: demand ok");
        }
        // Oracle syscall suite groups (`user/init/src/tests`): `mm ids time signal fs proc fork jobctl pipe`.
        Some(mode) if tests::run_mode(mode) => {}
        _ => {}
    }
    out!("init: ok");
}

/// Forks a child that spins for ever; returns its pid in the parent.
fn fork_spinner() -> usize {
    // SAFETY: fork takes no arguments and no pointers; the child touches nothing shared.
    match Errno::from_ret(unsafe { raw::syscall0(Sysno::fork as usize) }) {
        Ok(0) => loop {
            core::hint::spin_loop();
        },
        Ok(pid) => pid,
        Err(error) => fail("fork", error),
    }
}

/// Page faults taken by init itself, in ring 3: demand-zero read and write faults on a fresh
/// anonymous mapping (zero page, then a private frame replacing it), and stack growth far below
/// the initial stack VMA. Every access must retry transparently; a refused fault would end init
/// with SIGSEGV instead of `init: demand ok`.
fn demand_paging() {
    const PAGE: usize = 4096;
    // SAFETY: an anonymous private read/write mapping of three pages; no pointer is passed.
    let mapped = Errno::from_ret(unsafe {
        raw::syscall6(Sysno::mmap as usize, 0, 3 * PAGE, 3, 0x22, usize::MAX, 0)
    });
    let Ok(base) = mapped else {
        fail("demand_mmap", mapped);
    };
    let pages = ptr::with_exposed_provenance_mut::<u8>(base);
    // SAFETY: `base..base + 3 * PAGE` is the live private mapping made above; every access is
    // one byte inside it, and nothing else aliases it.
    unsafe {
        expect("demand_read_zero", pages.add(PAGE).read_volatile(), 0);
        pages.add(PAGE).write_volatile(0x5a);
        expect(
            "demand_write_after_zero",
            pages.add(PAGE).read_volatile(),
            0x5a,
        );
        pages.write_volatile(0xa5);
        expect("demand_write_absent", pages.read_volatile(), 0xa5);
        expect("demand_untouched", pages.add(2 * PAGE).read_volatile(), 0);
    }
    expect("demand_stack", grow_stack(), 0x77);
}

/// Touch the lowest page of a 320 KiB frame, far below the initial stack VMA (the argument
/// pages plus Linux's 128 KiB expansion), so ring-3 faults must grow it.
#[inline(never)]
fn grow_stack() -> u8 {
    let mut frame = [0u8; 320 * 1024];
    let frame = core::hint::black_box(&mut frame);
    // SAFETY: indices 0 and the last are inside the array; volatile so the stores happen.
    unsafe {
        ptr::addr_of_mut!(frame[0]).write_volatile(0x77);
        ptr::addr_of_mut!(frame[frame.len() - 1]).write_volatile(0x11);
        ptr::addr_of!(frame[0]).read_volatile()
    }
}

/// Initial x87/SSE state and arithmetic: Linux gives a new task FCW 0x37f,
/// MXCSR 0x1f80 and zero registers (`fpstate_init_fxstate`), and even with
/// `noxsave` x87/SSE keep working through FXSR. The target is soft-float, so
/// the instructions are written explicitly; no register operand is named (the
/// compiler never allocates XMM/x87 here, so nothing live is clobbered).
fn fpu_checks() {
    let mut fcw = 0u16;
    let mut mxcsr = 0u32;
    let (mut xmm5, mut xmm15) = (u64::MAX, u64::MAX);
    // SAFETY: stores through two valid local pointers and reads XMM registers
    // into general registers; user mode, no other side effects.
    unsafe {
        asm!(
            "fnstcw word ptr [{fcw}]",
            "stmxcsr dword ptr [{mxcsr}]",
            "movq {a}, xmm5",
            "movq {b}, xmm15",
            fcw = in(reg) ptr::addr_of_mut!(fcw),
            mxcsr = in(reg) ptr::addr_of_mut!(mxcsr),
            a = out(reg) xmm5,
            b = out(reg) xmm15,
            options(nostack, preserves_flags),
        );
    }
    expect("fpu_fcw", fcw, 0x37f);
    expect("fpu_mxcsr", mxcsr, 0x1f80);
    expect("xmm5", xmm5, 0);
    expect("xmm15", xmm15, 0);
    let mut two = 0i32;
    let nine: i64;
    // SAFETY: x87: 1 + 1 stored as an integer through a valid local pointer;
    // SSE2: (double)3 squared, truncated. No memory besides `two`.
    unsafe {
        asm!(
            "fld1",
            "fld1",
            "faddp st(1), st",
            "fistp dword ptr [{two}]",
            "cvtsi2sd xmm0, {three}",
            "mulsd xmm0, xmm0",
            "cvttsd2si {nine}, xmm0",
            two = in(reg) ptr::addr_of_mut!(two),
            three = in(reg) 3i64,
            nine = out(reg) nine,
            options(nostack, preserves_flags),
        );
    }
    expect("x87_add", two, 2);
    expect("sse2_mul", nine, 9);
    out!("init: sse ok");
}

extern "C" fn start_rust(sp: *const usize) -> ! {
    // The first line is also the first checked write.
    const HELLO: &str = "init: hello from userspace\n";
    expect(
        "write",
        write(1, HELLO.as_ptr().expose_provenance(), HELLO.len()),
        Ok(HELLO.len()),
    );
    // SAFETY: `entry` passes the stack pointer at process entry.
    run(&unsafe { Stack::new(sp) });
    exit(0)
}

/// Process entry point named by the ELF header.
///
/// `asm!` proof (AGENTS.md rule 3):
/// * Why asm: at entry the kernel hands over only `rsp`, with no return address
///   and no calling-convention registers; Rust cannot read `rsp` before a
///   prologue, and `naked` is the only way to forbid one. No intrinsic exists.
/// * Prerequisites: x86-64 Linux `execve` entry state (`SysV` psABI 3.4.1):
///   `rsp` -> `argc`, `rsp % 16 == 0`; `rdx` (atexit hint, zero on Linux) is ignored.
/// * Registers: reads `rsp`; writes `rbp` (zeroed as the outermost frame, per
///   psABI), `rdi` (`start_rust` argument = initial `rsp`, so the stack layout
///   and its alignment are reported unmodified), `rsp` (aligned down so a
///   misaligned kernel stack is reported by a check instead of misaligning
///   Rust code). Clobbers flags (`and`). Everything else is dead at entry.
/// * Memory: `call` pushes one return address on the stack just aligned; no
///   other memory is touched. Interrupts/privilege: user mode, unaffected.
/// * Control flow: `start_rust` never returns (`exit_group`); `ud2` traps if it
///   somehow did. No unwinding: `start_rust` is `extern "C"`, panic=abort.
#[unsafe(export_name = "_start")]
#[unsafe(naked)]
unsafe extern "C" fn entry() -> ! {
    naked_asm!(
        "xor ebp, ebp",
        "mov rdi, rsp",
        "and rsp, -16",
        "call {start_rust}",
        "ud2",
        start_rust = sym start_rust,
    )
}
