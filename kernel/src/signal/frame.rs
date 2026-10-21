// SPDX-License-Identifier: GPL-2.0-only
// Linux 6.18.57 (commit 2ff600d29ee478d0a8d46ef8a58afb5e038fe692):
// arch/x86/kernel/signal.c:35-190 (`get_sigframe`, `init_sigframe_size`),
// arch/x86/kernel/signal_64.c:25-355 (`force_valid_ss`, `restore_sigcontext`,
// `__unsafe_setup_sigcontext`, `x64_setup_rt_frame`, `rt_sigreturn`),
// arch/x86/kernel/fpu/signal.c (`copy_fpstate_to_sigframe`,
// `save_xstate_epilog`, `fpu__restore_sig`, `fpu__alloc_mathframe`,
// `fpu__get_fpstate_size`), kernel/signal.c:4538-4556 (`restore_altstack`,
// `__save_altstack`), include/linux/signal.h:460 (`unsafe_save_altstack`),
// arch/x86/include/asm/{sigframe,sighandling}.h,
// arch/x86/include/uapi/asm/{sigcontext,ucontext}.h,
// include/uapi/asm-generic/ucontext.h. All GPL-2.0.
// arch/x86/kernel/fpu/xstate.h (`xsave_to_user_sigframe`, `xrstor_from_user_sigframe`,
// `update_pkru_in_sigframe`, `set_xfeature_in_sigframe`). All GPL-2.0.
// Transformation: only the native x86_64 frame (XSAVE standard format, or FXSAVE under
// `noxsave`), no shadow stack, no FRED, no single-step bookkeeping. The hardware `XSAVE` writes
// into a kernel area and exactly the bytes it writes are copied out; `XRSTOR` runs on a kernel
// area filled with exactly the bytes it reads (see `restore_fpu`).
#![forbid(unsafe_code)]
//! The `x86_64` `rt_sigframe`: building it on `handle_signal` and undoing it in
//! `rt_sigreturn`.
//!
//! # Frame layout (offsets from the handler's `rsp`, which is `frame`)
//! ```text
//!   0 pretcode (= sa_restorer)          8 uc_flags      16 uc_link (0)
//!  24 uc_stack: ss_sp, ss_flags(+4 pad), ss_size
//!  48 sigcontext (256): r8..r15 di si bp bx dx ax cx sp ip flags
//!     cs gs fs ss (u16 each) err trapno oldmask cr2 fpstate reserved1[8]
//! 304 uc_sigmask                      312 siginfo (128)        440 end
//! ```
//! The FPU state sits below the frame at `round_down(sp - sigframe_size, 64)`, in the
//! [`crate::xstate`] standard format (`sigframe_size` is 512 under `noxsave`).
//!
//! Bytes Linux never stores (the 4 padding bytes after `ss_flags`, the 64
//! `reserved1` bytes and `siginfo` when `SA_SIGINFO` is clear) are not stored
//! here either: they keep whatever the user stack held, exactly as in Linux.
//!
//! # Contract
//! * Context: task context after `get_signal`; allocation-free; the user
//!   memory is written through `copy_to_user`, so a partly written frame on a
//!   fault is the same partial state Linux leaves (the caller then forces
//!   SIGSEGV).
//! * `unsafe`: none. The FPU and `lar` facts come from [`Cpu`].

use super::{
    Cpu, MINSIGSTKSZ, Regs, SA_ONSTACK, SA_RESTORER, SA_SIGINFO, SIGSEGV, SS_ONSTACK, SigAction,
    SigSet, USER_CS, USER_DS,
    info::SigInfo,
    state::State,
    syscalls::{StackT, do_sigaltstack, get_user, put_user},
};
use crate::usercopy::{UserPages, access_ok, copy_from_user};
use crate::xstate::{
    self, Config, FP_XSTATE_MAGIC1, FP_XSTATE_MAGIC2, FP_XSTATE_MAGIC2_SIZE, FXSAVE_SIZE,
    MASK_FPSSE, MASK_PKRU, SW_RESERVED_OFFSET, SW_RESERVED_SIZE, XREGS_SIZE, XSAVE_HDR_OFFSET,
    XSAVE_HDR_SIZE, XsaveArea,
};

pub const UC_FP_XSTATE: u64 = 1;
pub const UC_SIGCONTEXT_SS: u64 = 2;
pub const UC_STRICT_RESTORE_SS: u64 = 4;

/// `FIX_EFLAGS`: the flags `rt_sigreturn` lets user space change.
pub const FIX_EFLAGS: u64 = 0x4_0000 // AC
    | 0x800 // OF
    | 0x400 // DF
    | 0x100 // TF
    | 0x80 // SF
    | 0x40 // ZF
    | 0x10 // AF
    | 0x4 // PF
    | 0x1 // CF
    | 0x1_0000; // RF
const EFLAGS_DF: u64 = 0x400;
const EFLAGS_RF: u64 = 0x1_0000;
const EFLAGS_TF: u64 = 0x100;

/// Red zone skipped below `rsp` (`get_sigframe`, not for ia32 frames).
pub const REDZONE: u64 = 128;

// Frame offsets (see the module documentation).
pub const FRAME_SIZE: u64 = 440;
const UC: u64 = 8;
const UC_FLAGS: u64 = UC;
const UC_LINK: u64 = UC + 8;
const UC_STACK: u64 = UC + 16;
const UC_MCONTEXT: u64 = UC + 40;
const UC_SIGMASK: u64 = UC + 296;
pub const INFO: u64 = UC + 304;
/// `offsetof(struct sigcontext, reserved1)`: what `restore_sigcontext` reads.
const SC_READ: usize = 192;

/// A signal chosen for delivery (`struct ksignal`): the action is a copy made
/// before `SA_RESETHAND` reset the installed one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ksig {
    pub sig: u8,
    pub info: SigInfo,
    pub action: SigAction,
}

/// `-EFAULT`: the frame could not be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameFault;

/// `force_valid_ss`: keep `regs->ss` only if it is a valid 64-bit user data
/// segment, else `__USER_DS`.
fn force_valid_ss<C: Cpu>(regs: &mut Regs, cpu: &C) {
    #[allow(clippy::cast_possible_truncation)]
    if !cpu.ss_is_valid_user_data(regs.ss as u16) {
        regs.ss = USER_DS;
    }
}

/// `user_64bit_mode`: the only long-mode CPL-3 selector.
const fn user_64bit_mode(regs: &Regs) -> bool {
    regs.cs == USER_CS
}

/// `get_sigframe` + `copy_fpstate_to_sigframe` for a native `x86_64` frame.
/// Returns the frame address and the FXSAVE image address, or `None` for Linux's bogus `(void __user *)-1`
/// (altstack overflow, FPU area not writable).
fn get_sigframe<P: UserPages, C: Cpu>(
    state: &State,
    regs: &Regs,
    flags: u64,
    pages: &mut P,
    cpu: &mut C,
) -> Option<(u64, u64)> {
    let alt = state.me.altstack;
    let nested_altstack = alt.on_stack(regs.sp);
    let mut entering_altstack = false;
    let mut sp = regs.sp.wrapping_sub(REDZONE);
    if flags & SA_ONSTACK != 0 && alt.ss_flags(sp) == 0 {
        sp = alt.sp.wrapping_add(alt.size);
        entering_altstack = true;
    }
    // fpu__alloc_mathframe: the standard-format area, 64-byte aligned.
    let math_size = cpu.xstate().sigframe_size() as u64;
    let buf_fx = sp.wrapping_sub(math_size) & !63;
    sp = buf_fx.wrapping_sub(FRAME_SIZE);
    // round_down(sp, 16) - 8: (sp + 8) is 16-aligned at handler entry.
    sp = (sp & !15).wrapping_sub(8);
    if (nested_altstack || entering_altstack) && !alt.contains(sp) {
        return None;
    }
    // sig_prepare_pkru: enable all pkeys so that the stacks are writable, and give the frame the
    // `PKRU` the signal interrupted.
    let pkru = cpu.read_pkru();
    cpu.write_pkru(0);
    if !copy_fpstate_to_sigframe(buf_fx, pkru, pages, cpu) {
        // Restore PKRU to the original, user-defined value.
        cpu.write_pkru(pkru);
        return None;
    }
    Some((sp, buf_fx))
}

/// `copy_fpstate_to_sigframe` for a 64-bit frame: the live state in the standard format at
/// `buf` (header cleared first, `XSAVE` writes, `PKRU` and `FPSSE` forced into `xstate_bv`,
/// `_fpx_sw_bytes`, the trailing magic word). `false` when any part is not writable.
#[allow(
    clippy::cast_possible_truncation,
    reason = "the sizes in `_fpx_sw_bytes` are at most `AREA_MAX`"
)]
fn copy_fpstate_to_sigframe<P: UserPages, C: Cpu>(
    buf: u64,
    pkru: u32,
    pages: &mut P,
    cpu: &mut C,
) -> bool {
    let cfg = cpu.xstate();
    if !access_ok(buf, cfg.sigframe_size() as u64) {
        return false;
    }
    let xsave = cfg.use_xsave();
    if xsave {
        // Clear the xsave header first, so that reserved fields are initialized to zero.
        if !put_user(pages, buf + XSAVE_HDR_OFFSET as u64, &[0; XSAVE_HDR_SIZE]) {
            return false;
        }
    }
    // The instruction writes into a kernel area; bytes it does not write must keep the stack's
    // contents (the reserved bytes of the legacy area), so start from them.
    let mut area = XsaveArea::zeroed();
    if copy_from_user(pages, &mut area.0[..FXSAVE_SIZE], buf) != 0 {
        return false;
    }
    cpu.xsave(&mut area);
    let bytes = &mut area.0;
    if xsave {
        let mut bv = u64::from_le_bytes(super::le(bytes, XSAVE_HDR_OFFSET));
        // update_pkru_in_sigframe: mark PKRU in use and give the frame the interrupted value.
        if let (true, Some(offset)) = (cfg.ospke, cfg.pkru_offset()) {
            bv |= MASK_PKRU;
            bytes[offset..offset + 4].copy_from_slice(&pkru.to_le_bytes());
        }
        // save_xstate_epilog: always FP and SSE, so a legacy program's changes are captured.
        bv |= MASK_FPSSE;
        bytes[XSAVE_HDR_OFFSET..XSAVE_HDR_OFFSET + 8].copy_from_slice(&bv.to_le_bytes());
    }
    // save_sw_bytes: `struct _fpx_sw_bytes` in the software-reserved bytes of the legacy area.
    let mut sw = [0u8; SW_RESERVED_SIZE];
    sw[0..4].copy_from_slice(&FP_XSTATE_MAGIC1.to_le_bytes());
    sw[4..8].copy_from_slice(&((cfg.user_size + FP_XSTATE_MAGIC2_SIZE) as u32).to_le_bytes());
    sw[8..16].copy_from_slice(&cfg.features.to_le_bytes());
    sw[16..20].copy_from_slice(&(cfg.user_size as u32).to_le_bytes());
    bytes[SW_RESERVED_OFFSET..SW_RESERVED_OFFSET + SW_RESERVED_SIZE].copy_from_slice(&sw);
    if !put_user(pages, buf, &bytes[..FXSAVE_SIZE]) {
        return false;
    }
    if !xsave {
        return true;
    }
    if !put_user(
        pages,
        buf + XSAVE_HDR_OFFSET as u64,
        &bytes[XSAVE_HDR_OFFSET..XREGS_SIZE],
    ) {
        return false;
    }
    for (offset, size) in cfg.ranges(cfg.features) {
        if !put_user(pages, buf + offset as u64, &bytes[offset..offset + size]) {
            return false;
        }
    }
    // The trailing magic word.
    put_user(
        pages,
        buf + cfg.user_size as u64,
        &FP_XSTATE_MAGIC2.to_le_bytes(),
    )
}

/// `x64_setup_rt_frame` and the register setup that follows it. On success
/// `regs` enters the handler; on `Err` `regs` is untouched except for the
/// partial writes to user memory.
///
/// # Errors
/// [`FrameFault`] for a missing `SA_RESTORER`, an unusable stack or any user
/// access that fails; the caller then force-sends SIGSEGV.
pub fn setup_rt_frame<P: UserPages, C: Cpu>(
    state: &State,
    regs: &mut Regs,
    ksig: &Ksig,
    pages: &mut P,
    cpu: &mut C,
) -> Result<(), FrameFault> {
    let flags = ksig.action.flags;
    // x86-64 should always use SA_RESTORER.
    if flags & SA_RESTORER == 0 {
        return Err(FrameFault);
    }
    let (frame, fpstate) = get_sigframe(state, regs, flags, pages, cpu).ok_or(FrameFault)?;
    // user_access_begin(frame, sizeof(*frame)).
    if !access_ok(frame, FRAME_SIZE) {
        return Err(FrameFault);
    }
    // frame_uc_flags: UC_FP_XSTATE when the frame holds XSAVE state (`boot_cpu_has(XSAVE)`).
    let uc_flags = UC_SIGCONTEXT_SS
        | if cpu.xstate().use_xsave() {
            UC_FP_XSTATE
        } else {
            0
        }
        | if user_64bit_mode(regs) {
            UC_STRICT_RESTORE_SS
        } else {
            0
        };
    let put = |pages: &mut P, at: u64, bytes: &[u8]| -> Result<(), FrameFault> {
        if put_user(pages, frame.wrapping_add(at), bytes) {
            Ok(())
        } else {
            Err(FrameFault)
        }
    };
    let alt = state.me.altstack;
    put(pages, UC_FLAGS, &uc_flags.to_le_bytes())?;
    put(pages, UC_LINK, &0u64.to_le_bytes())?;
    // unsafe_save_altstack: the *stored* flags, padding untouched.
    put(pages, UC_STACK, &alt.sp.to_le_bytes())?;
    put(pages, UC_STACK + 8, &alt.flags.to_le_bytes())?;
    put(pages, UC_STACK + 16, &alt.size.to_le_bytes())?;
    put(pages, 0, &ksig.action.restorer.to_le_bytes())?;
    let mask = state.me.saved_sigmask.unwrap_or(state.me.blocked).0;
    let sc = UC_MCONTEXT;
    // __unsafe_setup_sigcontext, field by field in Linux's order.
    let words: [(u64, u64); 16] = [
        (64, regs.di),
        (72, regs.si),
        (80, regs.bp),
        (120, regs.sp),
        (88, regs.bx),
        (96, regs.dx),
        (112, regs.cx),
        (104, regs.ax),
        (0, regs.r8),
        (8, regs.r9),
        (16, regs.r10),
        (24, regs.r11),
        (32, regs.r12),
        (40, regs.r13),
        (48, regs.r14),
        (56, regs.r15),
    ];
    for (offset, value) in words {
        put(pages, sc + offset, &value.to_le_bytes())?;
    }
    put(pages, sc + 160, &state.me.arch.trap_nr.to_le_bytes())?; // trapno
    put(pages, sc + 152, &state.me.arch.error_code.to_le_bytes())?; // err
    put(pages, sc + 128, &regs.ip.to_le_bytes())?;
    put(pages, sc + 136, &regs.flags.to_le_bytes())?;
    #[allow(clippy::cast_possible_truncation)]
    {
        put(pages, sc + 144, &(regs.cs as u16).to_le_bytes())?;
        put(pages, sc + 146, &0u16.to_le_bytes())?; // gs
        put(pages, sc + 148, &0u16.to_le_bytes())?; // fs
        put(pages, sc + 150, &(regs.ss as u16).to_le_bytes())?;
    }
    put(pages, sc + 184, &fpstate.to_le_bytes())?;
    put(pages, sc + 168, &mask.to_le_bytes())?; // oldmask = sig[0]
    put(pages, sc + 176, &state.me.arch.cr2.to_le_bytes())?;
    put(pages, UC_SIGMASK, &mask.to_le_bytes())?;
    if flags & SA_SIGINFO != 0 {
        put(pages, INFO, &ksig.info.to_bytes())?;
    }

    // Registers for the handler.
    regs.di = u64::from(ksig.sig);
    regs.ax = 0; // handlers declared without prototypes
    regs.si = frame.wrapping_add(INFO);
    regs.dx = frame.wrapping_add(UC);
    regs.ip = ksig.action.handler;
    regs.sp = frame;
    regs.cs = USER_CS;
    if regs.ss != USER_DS {
        force_valid_ss(regs, cpu);
    }
    Ok(())
}

/// Result of `rt_sigreturn`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sigreturn {
    /// The syscall's return value, i.e. the restored `rax` (0 on a bad frame).
    pub ret: u64,
    /// `badframe`: SIGSEGV has been forced.
    pub bad_frame: bool,
    /// `restore_sigcontext` was entered: its first statement resets
    /// `restart_block.fn`, which the caller owns (`Clocks::set_restart_block`).
    pub reached_sigcontext: bool,
}

/// `fpu__restore_sig(buf, 0)`. A null pointer resets the FPU. Any failure (range, unreadable
/// page, a state the CPU refuses) resets it too and reports `false`.
fn restore_fpu<P: UserPages, C: Cpu>(buf: u64, pages: &mut P, cpu: &mut C) -> bool {
    if buf == 0 {
        cpu.fpu_reset();
        return true;
    }
    let ok = __fpu_restore_sig(buf, pages, cpu);
    if !ok {
        cpu.fpu_reset();
    }
    ok
}

/// `fpu__restore_sig` after the null check and `__fpu_restore_sig`/`check_xstate_in_sigframe`.
fn __fpu_restore_sig<P: UserPages, C: Cpu>(buf: u64, pages: &mut P, cpu: &mut C) -> bool {
    let cfg = cpu.xstate();
    if !access_ok(buf, cfg.sigframe_size() as u64) {
        return false;
    }
    let (mut fx_only, mut ufeatures) = (false, MASK_FPSSE);
    if cfg.use_xsave() {
        let Some(sw) = get_user::<_, SW_RESERVED_SIZE>(pages, buf + SW_RESERVED_OFFSET as u64)
        else {
            return false;
        };
        let magic1 = u32::from_le_bytes(super::le(&sw, 0));
        let extended_size = u32::from_le_bytes(super::le(&sw, 4)) as usize;
        let xfeatures = u64::from_le_bytes(super::le(&sw, 8));
        let xstate_size = u32::from_le_bytes(super::le(&sw, 16)) as usize;
        // The first magic word and the sizes, then the second magic word at the end of the
        // layout (detects a program that copied only the legacy part). Anything wrong is not an
        // error: the frame is taken as a legacy FXSAVE one (`setfx`).
        let described = magic1 == FP_XSTATE_MAGIC1
            && xstate_size >= XREGS_SIZE
            && xstate_size <= cfg.user_size
            && xstate_size <= extended_size;
        let genuine = if described {
            let Some(magic2) = get_user::<_, 4>(pages, buf + xstate_size as u64) else {
                return false;
            };
            u32::from_le_bytes(magic2) == FP_XSTATE_MAGIC2
        } else {
            false
        };
        if genuine {
            ufeatures = xfeatures;
        }
        fx_only = !genuine;
    }
    restore_fpregs_from_user(buf, ufeatures, fx_only, &cfg, pages, cpu)
}

/// `restore_fpregs_from_user` and `__restore_fpregs_from_user`: restore the described
/// components, then the initial state for the enabled ones that were not.
///
/// What the CPU reads is exactly what the kernel area is filled with: the legacy area and the
/// header, then the components named by both the request and the header's `xstate_bv` (the CPU
/// reads no more, so a buffer that ends after the last restored component is valid). A
/// compacted header (`xcomp_bv` bit 63) makes the CPU use other offsets; that case reads the
/// whole area.
/// shortcut: the compacted-header read set is the whole `user_size`, a superset of what the
/// CPU reads; a buffer shorter than that with a compacted header is refused here and restored
/// by Linux. Upgrade by walking `Config::compacted_offset` over `xcomp_bv`.
fn restore_fpregs_from_user<P: UserPages, C: Cpu>(
    buf: u64,
    ufeatures: u64,
    fx_only: bool,
    cfg: &Config,
    pages: &mut P,
    cpu: &mut C,
) -> bool {
    let xrestore = ufeatures & cfg.features;
    let mut area = XsaveArea::zeroed();
    if cfg.use_xsave() && !fx_only {
        // XRSTOR: the operand must be 64-byte aligned (#GP before any access).
        if !buf.is_multiple_of(xstate::XSAVE_ALIGNMENT as u64) {
            return false;
        }
        if copy_from_user(pages, &mut area.0[..XREGS_SIZE], buf) != 0 {
            return false;
        }
        let xstate_bv = u64::from_le_bytes(super::le(&area.0, XSAVE_HDR_OFFSET));
        let xcomp_bv = u64::from_le_bytes(super::le(&area.0, XSAVE_HDR_OFFSET + 8));
        if xcomp_bv & xstate::XCOMP_BV_COMPACTED_FORMAT != 0 {
            if copy_from_user(
                pages,
                &mut area.0[XREGS_SIZE..cfg.user_size],
                buf + XREGS_SIZE as u64,
            ) != 0
            {
                return false;
            }
        } else {
            for (offset, size) in cfg.ranges(xstate_bv & xrestore) {
                if copy_from_user(
                    pages,
                    &mut area.0[offset..offset + size],
                    buf + offset as u64,
                ) != 0
                {
                    return false;
                }
            }
        }
        if !cpu.xrstor(&area, xrestore) {
            return false;
        }
    } else {
        // FXRSTOR: 16-byte aligned, the 512-byte legacy area (x87, SSE, MXCSR).
        if !buf.is_multiple_of(16)
            || copy_from_user(pages, &mut area.0[..FXSAVE_SIZE], buf) != 0
            || !cpu.fxrstor(&area)
        {
            return false;
        }
    }
    if cfg.use_xsave() {
        let init_bv = cfg.features & !xrestore;
        if init_bv != 0 {
            cpu.restore_init(init_bv);
        }
    }
    true
}

/// `restore_sigcontext`.
fn restore_sigcontext<P: UserPages, C: Cpu>(
    regs: &mut Regs,
    usc: u64,
    uc_flags: u64,
    pages: &mut P,
    cpu: &mut C,
) -> bool {
    let Some(sc) = get_user::<_, SC_READ>(pages, usc) else {
        return false;
    };
    let w = |at: usize| u64::from_le_bytes(super::le(&sc, at));
    let h = |at: usize| u64::from(u16::from_le_bytes(super::le(&sc, at)));
    regs.r8 = w(0);
    regs.r9 = w(8);
    regs.r10 = w(16);
    regs.r11 = w(24);
    regs.r12 = w(32);
    regs.r13 = w(40);
    regs.r14 = w(48);
    regs.r15 = w(56);
    regs.di = w(64);
    regs.si = w(72);
    regs.bp = w(80);
    regs.bx = w(88);
    regs.dx = w(96);
    regs.ax = w(104);
    regs.cx = w(112);
    regs.sp = w(120);
    regs.ip = w(128);
    // Get CS/SS and force CPL3.
    regs.cs = h(144) | 3;
    regs.ss = h(150) | 3;
    regs.flags = (regs.flags & !FIX_EFLAGS) | (w(136) & FIX_EFLAGS);
    regs.orig_ax = u64::MAX; // disable syscall checks
    // Fix up SS for old DOSEMU and CRIU.
    if uc_flags & UC_STRICT_RESTORE_SS == 0 && user_64bit_mode(regs) {
        force_valid_ss(regs, cpu);
    }
    restore_fpu(w(184), pages, cpu)
}

/// The `rt_sigreturn` syscall. `regs.sp` is the stack pointer at syscall
/// entry: `frame + 8`, because the handler's `ret` popped `pretcode`.
///
/// Order as in Linux: range check, read `uc_sigmask` and `uc_flags`, install
/// the mask (SIGKILL/SIGSTOP stripped), restore the altstack (all errors but
/// `EFAULT` ignored, so e.g. returning from a handler that runs on the stack
/// leaves it untouched), then the registers and FPU. A failure at any step
/// leaves the earlier steps applied and forces SIGSEGV.
pub fn rt_sigreturn<P: UserPages, C: Cpu>(
    state: &mut State,
    regs: &mut Regs,
    pages: &mut P,
    cpu: &mut C,
) -> Sigreturn {
    let frame = regs.sp.wrapping_sub(8);
    let mut reached_sigcontext = false;
    let ok = (|| {
        if !access_ok(frame, FRAME_SIZE) {
            return false;
        }
        let Some(mask) = get_user::<_, 8>(pages, frame + UC_SIGMASK) else {
            return false;
        };
        let Some(flags) = get_user::<_, 8>(pages, frame + UC_FLAGS) else {
            return false;
        };
        state.set_blocked(SigSet(u64::from_le_bytes(mask)));
        let Some(stack) = get_user::<_, { StackT::SIZE }>(pages, frame + UC_STACK) else {
            return false;
        };
        // squash all but EFAULT
        let _ = do_sigaltstack(
            state,
            Some(StackT::from_bytes(&stack)),
            regs.sp,
            MINSIGSTKSZ,
        );
        // restore_sigcontext's first line resets `restart_block.fn` to
        // `do_no_restart_syscall`: the caller (`Task::rt_sigreturn`) owns the
        // block and learns of this point through `reached_sigcontext`.
        reached_sigcontext = true;
        restore_sigcontext(
            regs,
            frame + UC_MCONTEXT,
            u64::from_le_bytes(flags),
            pages,
            cpu,
        )
    })();
    if ok {
        Sigreturn {
            ret: regs.ax,
            bad_frame: false,
            reached_sigcontext,
        }
    } else {
        // signal_fault -> force_sig(SIGSEGV)
        state.force_sig(SIGSEGV);
        Sigreturn {
            ret: 0,
            bad_frame: true,
            reached_sigcontext,
        }
    }
}

/// After a successful frame: `regs->flags &= ~(DF|RF|TF)` (ABI function entry,
/// no RF/recursive TF) and `fpu__clear_user_states`.
pub fn enter_handler<C: Cpu>(regs: &mut Regs, cpu: &mut C) {
    regs.flags &= !(EFLAGS_DF | EFLAGS_RF | EFLAGS_TF);
    cpu.fpu_reset();
}

const _: () = {
    assert!(SS_ONSTACK == 1);
};
