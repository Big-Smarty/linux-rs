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

use core::arch::naked_asm;
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
            match write(1, rest.as_ptr().addr(), rest.len()) {
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
            " execfn={:?} platform={:?} envp={:?}",
            self.aux_string(AT_EXECFN),
            self.aux_string(AT_PLATFORM),
            self.envp
        )
    }
}

fn pid() -> usize {
    // SAFETY: getpid takes no arguments, cannot fail and touches no memory.
    unsafe { syscalls::syscall0(Sysno::getpid) }.unwrap_or(usize::MAX)
}

fn run(stack: &Stack) {
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

    let buf = b"x".as_ptr().addr();
    expect("write_zero_length", write(1, buf, 0), Ok(0));
    expect("write_null", write(1, 0, 1), Err(Errno::EFAULT));
    expect("write_low_address", write(1, 8, 5), Err(Errno::EFAULT));
    expect("write_closed_fd", write(5, buf, 1), Err(Errno::EBADF));
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
        if !stack.envp.iter().eq([b"HOME=/".as_slice(), b"TERM=linux"]) {
            fail("pid1_envp", stack.envp);
        }
    }

    if stack.argv.iter().nth(1) == Some(b"fault") {
        out!("init: faulting on purpose");
        // SAFETY: not sound, deliberately: the read of address 0 must raise SIGSEGV.
        let _ = unsafe { ptr::null::<u8>().read_volatile() };
        fail("fault", "returned");
    }
    out!("init: ok");
}

extern "C" fn start_rust(sp: *const usize) -> ! {
    // The first line is also the first checked write.
    const HELLO: &str = "init: hello from userspace\n";
    expect(
        "write",
        write(1, HELLO.as_ptr().addr(), HELLO.len()),
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
