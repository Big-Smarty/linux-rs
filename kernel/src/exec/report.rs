// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: init/main.c (`kernel_init`
// panic text, `run_init_process`), kernel/exit.c (`do_exit`: "Attempted to kill
// init!"), kernel/panic.c (`vpanic` strips one trailing newline),
// arch/x86/mm/fault.c (`show_signal_msg`, `sanitize_error_code`),
// arch/x86/kernel/traps.c (`show_signal`, `do_trap`, `exc_*`),
// mm/memory.c (`print_vma_addr`). All GPL-2.0 / GPL-2.0-only.
// Transformation: printk formatting becomes `Display` implementations; signal
// delivery is reduced to "the signal is fatal to init".
#![forbid(unsafe_code)]
//! Exact diagnostic text for init that cannot be started or dies.
//!
//! shortcut: the following line `Code: ...` (`show_opcodes`) and the register
//! dump of the panic backtrace are not printed; they are diagnostics, not
//! interface. CPU/core/socket are fixed to the BSP (`0 (core 0, socket 0)`).

use crate::{mm::Mm, usercopy::TASK_SIZE_MAX};
use core::fmt;

pub const SIGILL: u8 = 4;
pub const SIGTRAP: u8 = 5;
pub const SIGBUS: u8 = 7;
pub const SIGFPE: u8 = 8;
pub const SIGSEGV: u8 = 11;

/// `panic("No working init found. ...")` after every candidate failed.
pub const NO_INIT: &str = "Kernel panic - not syncing: No working init found.  Try passing init= option to kernel. See Linux Documentation/admin-guide/init.rst for guidance.";

/// What Linux 6.18.57 prints, in order, when `init_eaccess("/init")` fails and
/// `prepare_namespace` finds no root device (no `root=`): observed with the
/// pinned reference kernel in QEMU, then `NO_ROOT_PANIC`. The reference kernel
/// also lists its block filesystems after the last line; that list depends on
/// the kernel configuration and this kernel has none, so it is omitted.
pub const NO_ROOT: [&str; 4] = [
    "check access for rdinit=/init failed: -2, ignoring",
    "/dev/root: Can't open blockdev",
    "VFS: Cannot open root device \"\" or unknown-block(0,0): error -6",
    "Please append a correct \"root=\" boot option; here are the available partitions:",
];
pub const NO_ROOT_PANIC: &str =
    "Kernel panic - not syncing: VFS: Unable to mount root fs on unknown-block(0,0)";

/// `pr_err("Failed to execute %s (error %d)\n")` for `/init`.
pub struct ExecFailed(pub i32);
impl fmt::Display for ExecFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Failed to execute /init (error {})", self.0)
    }
}

/// `panic("Attempted to kill init! exitcode=0x%08x\n")`; the panic core strips
/// the format's own trailing newline.
pub struct InitDeath(pub u32);
impl fmt::Display for InitDeath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Kernel panic - not syncing: Attempted to kill init! exitcode=0x{:08x}",
            self.0
        )
    }
}

/// Exit code of a task killed by `signal`: the number itself. Core dumps are
/// off (`RLIMIT_CORE` is 0 for init), so bit 7 stays clear.
#[must_use]
pub const fn signal_exit_code(signal: u8) -> u32 {
    signal as u32
}

/// The file-backed VMA that contains an address (`print_vma_addr`'s
/// `vma_lookup` with `vma->vm_file`). The name printed is the file's basename,
/// `init` for `/init`, the only file there is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileRegion {
    pub start: u64,
    pub end: u64,
    pub pgoff: u64,
}

impl FileRegion {
    /// `vma_lookup(mm, address)` restricted to file-backed VMAs.
    #[must_use]
    pub fn of(mm: &Mm, address: u64) -> Option<Self> {
        mm.find_vma(address)
            .filter(|v| v.start <= address && v.file.is_some())
            .map(|v| Self {
                start: v.start,
                end: v.end,
                pgoff: v.pgoff,
            })
    }
}

/// `" in init[offset,start+length]"` when the address lies in a file-backed
/// region (`print_vma_addr`); nothing otherwise.
struct InVma(Option<FileRegion>, u64);
impl fmt::Display for InVma {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Some(vma) = self.0 else {
            return Ok(());
        };
        write!(
            f,
            " in init[{:x},{:x}+{:x}]",
            self.1 - vma.start + vma.pgoff * crate::memory::PAGE,
            vma.start,
            vma.end - vma.start
        )
    }
}

/// x86 page-fault error-code bits.
pub const PF_PROT: u64 = 1;

/// `show_signal_msg`: `init[1]: segfault at ...` (one line, no newline).
pub struct Segfault {
    pub address: u64,
    pub ip: u64,
    pub sp: u64,
    pub error: u64,
    /// The file-backed VMA containing `ip` (`FileRegion::of`).
    pub region: Option<FileRegion>,
}
impl fmt::Display for Segfault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // sanitize_error_code: kernel addresses always look like protection faults.
        let error = if self.address >= TASK_SIZE_MAX {
            self.error | PF_PROT
        } else {
            self.error
        };
        write!(
            f,
            "init[1]: segfault at {:x} ip {:016x} sp {:016x} error {:x}{} likely on CPU 0 (core 0, socket 0)",
            self.address,
            self.ip,
            self.sp,
            error,
            InVma(self.region, self.ip)
        )
    }
}

/// What a user-mode exception becomes in Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserSignal {
    pub signal: u8,
    /// `show_signal`'s `type` and `desc`, when Linux prints a line.
    pub message: Option<(&'static str, &'static str)>,
}

/// Classify a non-page-fault exception raised in user mode (`exc_*` in
/// traps.c). `None` for vectors that are not a plain fatal signal for init
/// here (NMI, #DF, #MC, #NM, ...): the caller must treat those as a kernel
/// failure, never as a user death.
#[must_use]
pub const fn user_exception(vector: u8) -> Option<UserSignal> {
    let (signal, message) = match vector {
        0 => (SIGFPE, Some(("trap ", "divide error"))),
        // exc_debug_user -> send_sigtrap: no show_signal line.
        1 => (SIGTRAP, None),
        3 => (SIGTRAP, Some(("trap ", "int3"))),
        4 => (SIGSEGV, Some(("trap ", "overflow"))),
        5 => (SIGSEGV, Some(("trap ", "bounds"))),
        6 => (SIGILL, Some(("trap ", "invalid opcode"))),
        10 => (SIGSEGV, Some(("trap ", "invalid TSS"))),
        11 => (SIGBUS, Some(("trap ", "segment not present"))),
        12 => (SIGBUS, Some(("trap ", "stack segment"))),
        // gp_user_force_sig_segv: type "", desc GPFSTR.
        13 => (SIGSEGV, Some(("", "general protection fault"))),
        // math_error / simd_math_error send SIGFPE without a message.
        16 | 19 => (SIGFPE, None),
        17 => (SIGBUS, Some(("trap ", "alignment check"))),
        _ => return None,
    };
    Some(UserSignal { signal, message })
}

/// `show_signal`: `traps: init[1] <type><desc> ip:%lx sp:%lx error:%lx[ in init[...]]`
/// (`traps.c` defines `pr_fmt` as `"traps: " fmt`; the pinned reference prints
/// `traps: init[1] trap int3 ip:...`).
pub struct TrapLine {
    pub kind: &'static str,
    pub desc: &'static str,
    pub ip: u64,
    pub sp: u64,
    pub error: u64,
    /// The file-backed VMA containing `ip` (`FileRegion::of`).
    pub region: Option<FileRegion>,
}
impl fmt::Display for TrapLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "traps: init[1] {}{} ip:{:x} sp:{:x} error:{:x}{}",
            self.kind,
            self.desc,
            self.ip,
            self.sp,
            self.error,
            InVma(self.region, self.ip)
        )
    }
}

/// `signal_fault`: `init[1] bad frame in rt_sigreturn frame:%p ip:%lx sp:%lx orax:%lx[ in init[...]]`
/// (`arch/x86/kernel/signal.c:368-383`; `me->comm` is `init`, pid 1, and the line
/// is `KERN_EMERG` for pid 1).
///
/// shortcut: `%p` is printed as the pinned kernel prints it before its pointer-hash
/// key exists, `(____ptrval____)` (observed for init on the reference kernel under
/// TCG); once the kernel has entropy (observed under KVM) the value is a per-boot
/// keyed hash of the frame address that no other kernel can reproduce.
pub struct BadFrame {
    pub ip: u64,
    pub sp: u64,
    pub orig_ax: u64,
    /// The file-backed VMA containing `ip` (`FileRegion::of`).
    pub region: Option<FileRegion>,
}
impl fmt::Display for BadFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "init[1] bad frame in rt_sigreturn frame:(____ptrval____) ip:{:x} sp:{:x} orax:{:x}{}",
            self.ip,
            self.sp,
            self.orig_ax,
            InVma(self.region, self.ip)
        )
    }
}

#[cfg(test)]
mod tests;
