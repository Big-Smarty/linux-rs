// SPDX-License-Identifier: GPL-2.0-only
// Linux 6.18.57 (commit 2ff600d29ee478d0a8d46ef8a58afb5e038fe692):
// include/uapi/asm-generic/siginfo.h (layout, `SI_*`/`*_*` codes),
// kernel/signal.c:3500-3578 (`siginfo_layout`, `copy_siginfo_to_user`),
// kernel/signal.c:4015-4021 (`prepare_kill_siginfo`),
// arch/x86/kernel/traps.c (`do_trap`, `exc_*`, `math_error`),
// arch/x86/kernel/ptrace.c:1408 (`send_sigtrap`), arch/x86/include/asm/traps.h
// (`get_si_code`), arch/x86/mm/fault.c (`__bad_area_nosemaphore`, `do_sigbus`,
// `sanitize_error_code`, `set_signal_archinfo`), arch/x86/kernel/fpu/core.c
// (`fpu__exception_code`). All GPL-2.0.
#![forbid(unsafe_code)]
//! `siginfo_t` as the bytes user space sees (128, little endian) and the
//! `siginfo` each synchronous x86 exception produces.

use super::{SIGBUS, SIGFPE, SIGILL, SIGSEGV, SIGTRAP};
use crate::{exec::report::PF_PROT, usercopy::TASK_SIZE_MAX};

pub const SI_USER: i32 = 0;
pub const SI_KERNEL: i32 = 0x80;
pub const SI_QUEUE: i32 = -1;
pub const SI_TIMER: i32 = -2;
pub const SI_SIGIO: i32 = -5;
pub const SI_TKILL: i32 = -6;

pub const ILL_ILLOPN: i32 = 2;
pub const FPE_INTDIV: i32 = 1;
pub const FPE_FLTDIV: i32 = 3;
pub const FPE_FLTOVF: i32 = 4;
pub const FPE_FLTUND: i32 = 5;
pub const FPE_FLTRES: i32 = 6;
pub const FPE_FLTINV: i32 = 7;
pub const SEGV_MAPERR: i32 = 1;
pub const SEGV_ACCERR: i32 = 2;
pub const SEGV_BNDERR: i32 = 3;
pub const SEGV_PKUERR: i32 = 4;
pub const BUS_ADRALN: i32 = 1;
pub const BUS_ADRERR: i32 = 2;
pub const BUS_MCEERR_AR: i32 = 4;
pub const BUS_MCEERR_AO: i32 = 5;
pub const TRAP_BRKPT: i32 = 1;
pub const TRAP_TRACE: i32 = 2;
pub const TRAP_HWBKPT: i32 = 4;
pub const TRAP_PERF: i32 = 6;

/// `NSIGPOLL`: the limit of the generic (non signal-specific) `si_code`s.
const NSIGPOLL: i32 = 6;

/// `enum siginfo_layout` (without the sparc/alpha-only `SIL_FAULT_TRAPNO`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout {
    Kill,
    Timer,
    Poll,
    Fault,
    FaultMceerr,
    FaultBnderr,
    FaultPkuerr,
    FaultPerfEvent,
    Chld,
    Rt,
    Sys,
}

/// Per-signal `si_code` limit for the signals that own their codes
/// (`sig_sicodes[]`), with the layout they select.
const fn specific(sig: u8) -> Option<(i32, Layout)> {
    Some(match sig {
        SIGILL => (11, Layout::Fault),
        SIGFPE => (15, Layout::Fault),
        SIGSEGV => (10, Layout::Fault),
        SIGBUS => (5, Layout::Fault),
        SIGTRAP => (6, Layout::Fault),
        super::SIGCHLD => (6, Layout::Chld),
        29 => (6, Layout::Poll), // SIGPOLL == SIGIO
        super::SIGSYS => (2, Layout::Sys),
        _ => return None,
    })
}

/// `siginfo_layout(sig, si_code)`.
#[must_use]
pub fn layout(sig: u8, code: i32) -> Layout {
    if code > SI_USER && code < SI_KERNEL {
        match specific(sig) {
            Some((limit, layout)) if code <= limit => {
                if sig == SIGBUS && (BUS_MCEERR_AR..=BUS_MCEERR_AO).contains(&code) {
                    Layout::FaultMceerr
                } else if sig == SIGSEGV && code == SEGV_BNDERR {
                    Layout::FaultBnderr
                } else if sig == SIGSEGV && code == SEGV_PKUERR {
                    Layout::FaultPkuerr
                } else if sig == SIGTRAP && code == TRAP_PERF {
                    Layout::FaultPerfEvent
                } else {
                    layout
                }
            }
            _ if code <= NSIGPOLL => Layout::Poll,
            _ => Layout::Kill,
        }
    } else if code == SI_TIMER {
        Layout::Timer
    } else if code == SI_SIGIO {
        Layout::Poll
    } else if code < 0 {
        Layout::Rt
    } else {
        Layout::Kill
    }
}

/// `SI_DETHREAD` and `SI_ASYNCNL`.
const SI_DETHREAD: i32 = -7;
const SI_ASYNCNL: i32 = -60;

/// `known_siginfo_layout(sig, si_code)`: does the kernel know how large the
/// `_sifields` of this combination are? If not, `rt_sigqueueinfo` insists that
/// the 80 expansion bytes are zero.
#[must_use]
pub fn known_layout(sig: i32, code: i32) -> bool {
    if code == SI_KERNEL {
        true
    } else if code > SI_USER {
        match u8::try_from(sig).ok().and_then(specific) {
            Some((limit, _)) => code <= limit,
            None => code <= NSIGPOLL,
        }
    } else {
        code >= SI_DETHREAD || code == SI_ASYNCNL
    }
}

/// `kernel_siginfo_t`: the first 48 bytes of `siginfo_t`. `body` is
/// `_sifields` (32 bytes) already encoded; the constructors fill it so that
/// no uninitialised or stale byte can reach user space.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SigInfo {
    pub signo: i32,
    pub errno: i32,
    pub code: i32,
    /// Bytes 12..16 (between `si_code` and `_sifields`): zero for everything
    /// the kernel builds; `rt_sigqueueinfo` passes the caller's through, as
    /// `copy_siginfo_to_user` copies the whole `kernel_siginfo`.
    pub pad: [u8; 4],
    pub body: [u8; 32],
}

impl SigInfo {
    /// `sizeof(siginfo_t)`.
    pub const SIZE: usize = 128;

    fn with(signo: u8, code: i32, put: impl FnOnce(&mut [u8; 32])) -> Self {
        let mut info = Self {
            signo: i32::from(signo),
            errno: 0,
            code,
            pad: [0; 4],
            body: [0; 32],
        };
        put(&mut info.body);
        info
    }

    /// `_kill`: `si_pid`, `si_uid` (`SI_USER`, `SI_TKILL`, `SI_KERNEL` with 0/0).
    #[must_use]
    pub fn kill(signo: u8, code: i32, pid: i32, uid: u32) -> Self {
        Self::with(signo, code, |b| {
            b[0..4].copy_from_slice(&pid.to_le_bytes());
            b[4..8].copy_from_slice(&uid.to_le_bytes());
        })
    }

    /// `prepare_kill_siginfo`: `kill(2)` is `SI_USER`, `tkill`/`tgkill` `SI_TKILL`.
    #[must_use]
    pub fn from_kill(signo: u8, thread_directed: bool, tgid: i32, uid: u32) -> Self {
        let code = if thread_directed { SI_TKILL } else { SI_USER };
        Self::kill(signo, code, tgid, uid)
    }

    /// `force_sig` / `SEND_SIG_PRIV`: `SI_KERNEL`, pid 0, uid 0.
    #[must_use]
    pub fn kernel(signo: u8) -> Self {
        Self::kill(signo, SI_KERNEL, 0, 0)
    }

    /// `_rt`: pid, uid and `sigval` (`rt_sigqueueinfo`, `SI_QUEUE`).
    #[must_use]
    pub fn rt(signo: u8, code: i32, pid: i32, uid: u32, value: u64) -> Self {
        Self::with(signo, code, |b| {
            b[0..4].copy_from_slice(&pid.to_le_bytes());
            b[4..8].copy_from_slice(&uid.to_le_bytes());
            b[8..16].copy_from_slice(&value.to_le_bytes());
        })
    }

    /// `_sigfault`: `si_addr` (`force_sig_fault`).
    #[must_use]
    pub fn fault(signo: u8, code: i32, addr: u64) -> Self {
        Self::with(signo, code, |b| {
            b[0..8].copy_from_slice(&addr.to_le_bytes());
        })
    }

    /// `__copy_siginfo_from_user` before the expansion check: the first 48
    /// bytes of a user `siginfo_t`, with `si_signo` replaced by `signo`.
    #[must_use]
    pub fn from_user(bytes: &[u8; Self::SIZE], signo: i32) -> Self {
        let word = |at: usize| i32::from_le_bytes(super::le(bytes, at));
        Self {
            signo,
            errno: word(4),
            code: word(8),
            pad: super::le(bytes, 12),
            body: super::le(bytes, 16),
        }
    }

    #[must_use]
    pub fn layout(&self) -> Layout {
        layout(u8::try_from(self.signo).unwrap_or(0), self.code)
    }

    /// `copy_siginfo_to_user`: the 48 `kernel_siginfo` bytes (header padding
    /// zero, as `clear_siginfo` leaves it) and 80 zero bytes of expansion.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0; Self::SIZE];
        out[0..4].copy_from_slice(&self.signo.to_le_bytes());
        out[4..8].copy_from_slice(&self.errno.to_le_bytes());
        out[8..12].copy_from_slice(&self.code.to_le_bytes());
        out[12..16].copy_from_slice(&self.pad);
        out[16..48].copy_from_slice(&self.body);
        out
    }
}

/// A synchronous fault: the signal plus the `thread.{trap_nr,error_code,cr2}`
/// the x86 handler records for the sigcontext (`trapno`, `err`, `cr2`).
/// `cr2` is `Some` only for page faults; other faults leave the old value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault {
    /// `None` for a spurious `#MF`/`#XM`: Linux updates `trap_nr`/`error_code`
    /// (`math_error`) and returns without a signal.
    pub info: Option<SigInfo>,
    pub trap_nr: u64,
    pub error_code: u64,
    pub cr2: Option<u64>,
}

pub const X86_TRAP_DE: u8 = 0;
pub const X86_TRAP_DB: u8 = 1;
pub const X86_TRAP_BP: u8 = 3;
pub const X86_TRAP_OF: u8 = 4;
pub const X86_TRAP_BR: u8 = 5;
pub const X86_TRAP_UD: u8 = 6;
pub const X86_TRAP_TS: u8 = 10;
pub const X86_TRAP_NP: u8 = 11;
pub const X86_TRAP_SS: u8 = 12;
pub const X86_TRAP_GP: u8 = 13;
pub const X86_TRAP_PF: u8 = 14;
pub const X86_TRAP_MF: u8 = 16;
pub const X86_TRAP_AC: u8 = 17;
pub const X86_TRAP_XF: u8 = 19;
/// `X86_PF_USER`.
pub const PF_USER: u64 = 4;

/// `DR_STEP` / `DR_TRAP0..3` of `%dr6`.
const DR_STEP: u64 = 0x4000;
const DR_TRAP_BITS: u64 = 0xf;

/// `get_si_code(dr6)`.
#[must_use]
pub const fn debug_si_code(dr6: u64) -> i32 {
    if dr6 & DR_STEP != 0 {
        TRAP_TRACE
    } else if dr6 & DR_TRAP_BITS != 0 {
        TRAP_HWBKPT
    } else {
        TRAP_BRKPT
    }
}

/// `fpu__exception_code` for FXSR state: `control`/`status` are the x87 `cwd`
/// and `swd` (vector 16), `mxcsr` the MXCSR (vector 19). Zero means a spurious
/// exception that Linux retries without a signal.
#[must_use]
pub fn fpu_exception_code(trap_nr: u8, cwd: u16, swd: u16, mxcsr: u32) -> i32 {
    let err = if trap_nr == X86_TRAP_MF {
        u32::from(swd & !cwd)
    } else {
        !(mxcsr >> 7) & mxcsr
    };
    if err & 0x001 != 0 {
        FPE_FLTINV
    } else if err & 0x004 != 0 {
        FPE_FLTDIV
    } else if err & 0x008 != 0 {
        FPE_FLTOVF
    } else if err & 0x012 != 0 {
        FPE_FLTUND
    } else if err & 0x020 != 0 {
        FPE_FLTRES
    } else {
        0
    }
}

/// What a user-mode exception other than #PF raises. `ip` is the faulting
/// instruction pointer (`regs->ip`, no uprobes here); `error_code` is the
/// hardware error code for vectors that push one; `dr6` is used by vector 1;
/// `fpe_code` is [`fpu_exception_code`] for vectors 16 and 19. `None` for a
/// vector that is not a plain user fault (and for a spurious FPU exception, which returns a [`Fault`] without `info`).
#[must_use]
pub fn exception(vector: u8, error_code: u64, ip: u64, dr6: u64, fpe_code: i32) -> Option<Fault> {
    // `do_trap`: a zero `sicode` is `force_sig` (SI_KERNEL), else `force_sig_fault`.
    let trap = |sig, code, addr: u64, ec| {
        let info = if code == 0 {
            SigInfo::kernel(sig)
        } else {
            SigInfo::fault(sig, code, addr)
        };
        Some(Fault {
            info: Some(info),
            trap_nr: u64::from(vector),
            error_code: ec,
            cr2: None,
        })
    };
    match vector {
        X86_TRAP_DE => trap(SIGFPE, FPE_INTDIV, ip, 0),
        // exc_debug_user -> send_sigtrap(regs, 0, get_si_code(dr6)): addr = ip.
        X86_TRAP_DB => trap(SIGTRAP, debug_si_code(dr6), ip, 0),
        X86_TRAP_BP => trap(SIGTRAP, 0, 0, 0),
        X86_TRAP_OF | X86_TRAP_BR => trap(SIGSEGV, 0, 0, 0),
        X86_TRAP_UD => trap(SIGILL, ILL_ILLOPN, ip, 0),
        X86_TRAP_NP | X86_TRAP_SS => trap(SIGBUS, 0, 0, error_code),
        // gp_user_force_sig_segv.
        X86_TRAP_TS | X86_TRAP_GP => trap(SIGSEGV, 0, 0, error_code),
        X86_TRAP_AC => trap(SIGBUS, BUS_ADRALN, 0, error_code),
        // math_error: error_code is 0 and si_addr the instruction pointer.
        X86_TRAP_MF | X86_TRAP_XF if fpe_code != 0 => trap(SIGFPE, fpe_code, ip, 0),
        // Spurious: no signal, but `thread.trap_nr`/`error_code` are updated.
        X86_TRAP_MF | X86_TRAP_XF => Some(Fault {
            info: None,
            trap_nr: u64::from(vector),
            error_code: 0,
            cr2: None,
        }),
        _ => None,
    }
}

/// How a page fault from user mode ends in a signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageFault {
    /// `bad_area*`: `SEGV_MAPERR` or `SEGV_ACCERR`.
    Segv(i32),
    /// `do_sigbus` without hardware poison: `BUS_ADRERR`.
    Bus,
}

/// `__bad_area_nosemaphore` / `do_sigbus` for a user-mode fault at `address`
/// with hardware `error_code`: sanitise the code, record `trap_nr`/`error_code`/
/// `cr2`, and build the `_sigfault` siginfo.
#[must_use]
pub fn page_fault(kind: PageFault, address: u64, error_code: u64) -> Fault {
    let mut error = error_code;
    if address >= TASK_SIZE_MAX {
        error |= PF_PROT; // sanitize_error_code
    }
    let info = match kind {
        PageFault::Segv(code) => SigInfo::fault(SIGSEGV, code, address),
        PageFault::Bus => SigInfo::fault(SIGBUS, BUS_ADRERR, address),
    };
    Fault {
        info: Some(info),
        trap_nr: u64::from(X86_TRAP_PF),
        error_code: error | PF_USER,
        cr2: Some(address),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unreadable_literal,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::cast_lossless,
        clippy::similar_names,
        clippy::too_many_lines,
        clippy::decimal_bitwise_operands,
        clippy::items_after_statements,
        clippy::many_single_char_names,
        clippy::too_many_arguments
    )]
    extern crate std;
    use super::*;
    use crate::signal::{SIGCHLD, SIGTERM};

    #[test]
    fn kill_siginfo_bytes() {
        // include/uapi/asm-generic/siginfo.h: signo@0 errno@4 code@8 _pid@16 _uid@20.
        let bytes = SigInfo::from_kill(SIGTERM, false, 1, 0).to_bytes();
        assert_eq!(bytes[0..4], 15i32.to_le_bytes());
        assert_eq!(bytes[4..8], [0; 4]);
        assert_eq!(bytes[8..12], [0; 4]); // SI_USER
        assert_eq!(bytes[12..16], [0; 4]); // padding
        assert_eq!(bytes[16..20], 1i32.to_le_bytes());
        assert_eq!(bytes[20..24], [0; 4]);
        assert!(bytes[24..].iter().all(|&b| b == 0));
        let tkill = SigInfo::from_kill(SIGTERM, true, 1, 1000).to_bytes();
        assert_eq!(tkill[8..12], (-6i32).to_le_bytes()); // SI_TKILL
        assert_eq!(tkill[20..24], 1000u32.to_le_bytes());
    }

    #[test]
    fn kernel_and_fault_siginfo_bytes() {
        let k = SigInfo::kernel(SIGSEGV).to_bytes();
        assert_eq!(k[8..12], 0x80i32.to_le_bytes());
        assert!(k[16..].iter().all(|&b| b == 0));
        let f = SigInfo::fault(SIGSEGV, SEGV_ACCERR, 0xdead_beef_1000).to_bytes();
        assert_eq!(f[0..4], 11i32.to_le_bytes());
        assert_eq!(f[8..12], 2i32.to_le_bytes());
        assert_eq!(f[16..24], 0xdead_beef_1000u64.to_le_bytes());
        assert!(f[24..].iter().all(|&b| b == 0));
        assert_eq!(f.len(), 128);
    }

    #[test]
    fn user_siginfo_round_trips_and_known_layouts() {
        let mut raw = [0u8; 128];
        raw[0..4].copy_from_slice(&0x77i32.to_le_bytes());
        raw[4..8].copy_from_slice(&5i32.to_le_bytes());
        raw[8..12].copy_from_slice(&SI_QUEUE.to_le_bytes());
        raw[12..16].copy_from_slice(&[1, 2, 3, 4]);
        raw[16..48].copy_from_slice(&[9; 32]);
        let info = SigInfo::from_user(&raw, 10);
        assert_eq!((info.signo, info.errno, info.code), (10, 5, -1));
        let out = info.to_bytes();
        assert_eq!(out[0..4], 10i32.to_le_bytes());
        assert_eq!(
            out[4..],
            raw[4..48]
                .iter()
                .chain(&[0u8; 80])
                .copied()
                .collect::<std::vec::Vec<_>>()[..]
        );
        // kernel/signal.c:3514-3531.
        assert!(known_layout(10, SI_KERNEL));
        assert!(known_layout(10, SI_QUEUE));
        assert!(known_layout(10, SI_DETHREAD));
        assert!(!known_layout(10, -8));
        assert!(known_layout(10, SI_ASYNCNL));
        assert!(known_layout(11, 10));
        assert!(!known_layout(11, 11));
        assert!(known_layout(10, 6));
        assert!(!known_layout(10, 7));
        assert!(!known_layout(-1, 7));
    }

    #[test]
    fn rt_siginfo_has_sigval_at_24() {
        let r = SigInfo::rt(40, SI_QUEUE, 7, 9, 0x1122_3344_5566_7788).to_bytes();
        assert_eq!(r[8..12], (-1i32).to_le_bytes());
        assert_eq!(r[16..20], 7i32.to_le_bytes());
        assert_eq!(r[20..24], 9u32.to_le_bytes());
        assert_eq!(r[24..32], 0x1122_3344_5566_7788u64.to_le_bytes());
    }

    #[test]
    fn layouts_follow_siginfo_layout() {
        // kernel/signal.c:3533-3571.
        assert_eq!(layout(SIGSEGV, SEGV_MAPERR), Layout::Fault);
        assert_eq!(layout(SIGSEGV, SEGV_BNDERR), Layout::FaultBnderr);
        assert_eq!(layout(SIGSEGV, SEGV_PKUERR), Layout::FaultPkuerr);
        assert_eq!(layout(SIGBUS, BUS_MCEERR_AO), Layout::FaultMceerr);
        assert_eq!(layout(SIGTRAP, TRAP_PERF), Layout::FaultPerfEvent);
        assert_eq!(layout(SIGCHLD, 3), Layout::Chld);
        assert_eq!(layout(SIGSEGV, SI_KERNEL), Layout::Kill);
        assert_eq!(layout(SIGSEGV, SI_USER), Layout::Kill);
        assert_eq!(layout(SIGTERM, SI_TKILL), Layout::Rt);
        assert_eq!(layout(SIGTERM, SI_QUEUE), Layout::Rt);
        assert_eq!(layout(SIGTERM, SI_TIMER), Layout::Timer);
        assert_eq!(layout(SIGTERM, SI_SIGIO), Layout::Poll);
        // Positive code past the signal's own limit: SIGSEGV code 11.
        assert_eq!(layout(SIGSEGV, 11), Layout::Kill);
        // Non signal-specific signal with a small positive code: poll layout.
        assert_eq!(layout(SIGTERM, 3), Layout::Poll);
        assert_eq!(layout(SIGTERM, 7), Layout::Kill);
        assert_eq!(layout(super::super::SIGSYS, 5), Layout::Poll);
    }

    #[test]
    fn exceptions_map_as_in_traps_c() {
        let f = exception(X86_TRAP_DE, 0, 0x401000, 0, 0).unwrap();
        assert_eq!(f.info, Some(SigInfo::fault(SIGFPE, FPE_INTDIV, 0x401000)));
        assert_eq!((f.trap_nr, f.error_code, f.cr2), (0, 0, None));
        let f = exception(X86_TRAP_UD, 0, 0x401002, 0, 0).unwrap();
        assert_eq!(f.info, Some(SigInfo::fault(SIGILL, ILL_ILLOPN, 0x401002)));
        // int3 / overflow / bounds: force_sig -> SI_KERNEL.
        assert_eq!(
            exception(3, 0, 5, 0, 0).unwrap().info,
            Some(SigInfo::kernel(SIGTRAP))
        );
        assert_eq!(
            exception(4, 0, 5, 0, 0).unwrap().info,
            Some(SigInfo::kernel(SIGSEGV))
        );
        assert_eq!(
            exception(5, 0, 5, 0, 0).unwrap().info,
            Some(SigInfo::kernel(SIGSEGV))
        );
        // #GP carries the error code into the sigcontext.
        let f = exception(13, 0x18, 5, 0, 0).unwrap();
        assert_eq!(f.info, Some(SigInfo::kernel(SIGSEGV)));
        assert_eq!((f.trap_nr, f.error_code), (13, 0x18));
        assert_eq!(
            exception(11, 9, 5, 0, 0).unwrap().info,
            Some(SigInfo::kernel(SIGBUS))
        );
        assert_eq!(
            exception(12, 9, 5, 0, 0).unwrap().info,
            Some(SigInfo::kernel(SIGBUS))
        );
        assert_eq!(
            exception(10, 9, 5, 0, 0).unwrap().info,
            Some(SigInfo::kernel(SIGSEGV))
        );
        let f = exception(17, 0, 5, 0, 0).unwrap();
        assert_eq!(f.info, Some(SigInfo::fault(SIGBUS, BUS_ADRALN, 0)));
        // #DB: si_code from dr6, addr = ip.
        assert_eq!(
            exception(1, 0, 0x77, DR_STEP, 0).unwrap().info,
            Some(SigInfo::fault(SIGTRAP, TRAP_TRACE, 0x77))
        );
        assert_eq!(debug_si_code(1), TRAP_HWBKPT);
        assert_eq!(debug_si_code(0), TRAP_BRKPT);
        // Math faults need a code; a spurious one raises nothing.
        // Spurious: arch info is still updated (math_error), no signal.
        let f = exception(16, 0, 5, 0, 0).unwrap();
        assert_eq!((f.info, f.trap_nr, f.error_code), (None, 16, 0));
        assert_eq!(exception(19, 0, 5, 0, 0).unwrap().info, None);
        let f = exception(19, 0, 0x99, 0, FPE_FLTDIV).unwrap();
        assert_eq!(f.info, Some(SigInfo::fault(SIGFPE, FPE_FLTDIV, 0x99)));
        // NMI, #DF, #MC, #NM are not plain user faults.
        for v in [2, 7, 8, 18] {
            assert!(exception(v, 0, 0, 0, 0).is_none());
        }
    }

    #[test]
    fn fpu_codes() {
        // x87: unmasked invalid-operation bit set in swd.
        assert_eq!(fpu_exception_code(16, 0x37e, 0x0001, 0), FPE_FLTINV);
        assert_eq!(fpu_exception_code(16, 0x37b, 0x0004, 0), FPE_FLTDIV);
        assert_eq!(fpu_exception_code(16, 0x37f, 0x003f, 0), 0); // all masked
        // SIMD: unmasked divide-by-zero (bit 2, mask bit 9 clear).
        assert_eq!(fpu_exception_code(19, 0, 0, 0x1d84), FPE_FLTDIV);
        assert_eq!(fpu_exception_code(19, 0, 0, 0x1f80), 0);
        assert_eq!(fpu_exception_code(19, 0, 0, 0x1b80 | 0x08), FPE_FLTOVF);
    }

    #[test]
    fn page_faults() {
        let f = page_fault(PageFault::Segv(SEGV_MAPERR), 0x10, 0x6);
        assert_eq!(f.info, Some(SigInfo::fault(SIGSEGV, SEGV_MAPERR, 0x10)));
        assert_eq!((f.trap_nr, f.error_code, f.cr2), (14, 0x6, Some(0x10)));
        // Kernel addresses always look like protection faults, with the user bit.
        let f = page_fault(PageFault::Segv(SEGV_MAPERR), TASK_SIZE_MAX, 0x4);
        assert_eq!(f.error_code, 0x5);
        let f = page_fault(PageFault::Bus, 0x2000, 0x0);
        assert_eq!(f.info, Some(SigInfo::fault(SIGBUS, BUS_ADRERR, 0x2000)));
        assert_eq!(f.error_code, 0x4);
    }
}
