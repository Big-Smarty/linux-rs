// SPDX-License-Identifier: GPL-2.0-only
// Host tests of frame construction, delivery and `rt_sigreturn`. Expected
// bytes are derived from `repr(C)` mirrors of the uapi structures
// (arch/x86/include/uapi/asm/sigcontext.h, include/uapi/asm-generic/ucontext.h,
// arch/x86/include/asm/sigframe.h) via `offset_of!`, not from the constants
// under test. No Linux oracle for the `signal` group existed when these were
// written (see docs/implementation.md "Signal model").
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
    clippy::too_many_arguments,
    clippy::struct_field_names,
    clippy::assert_is_empty
)]
extern crate std;

use super::{
    Cpu, Regs, SA_NODEFER, SA_ONSTACK, SA_RESETHAND, SA_RESTART, SA_RESTORER, SA_SIGINFO, SIG_IGN,
    SIGCHLD, SIGKILL, SIGSEGV, SIGSTOP, SIGTERM, SIGTSTP, SIGUSR1, SS_AUTODISARM, SS_DISABLE,
    SigAction, SigSet, USER_CS, USER_DS,
    deliver::{
        ERESTART_RESTARTBLOCK, ERESTARTNOHAND, ERESTARTNOINTR, ERESTARTSYS, GetSignal, Outcome,
        do_signal_or_restart, get_signal, handle_pending_signals, restart_for_handler,
        restart_without_handler,
    },
    frame::{FIX_EFLAGS, FRAME_SIZE, INFO, MAX_FRAME_SIZE, rt_sigreturn},
    info::{SEGV_MAPERR, SI_QUEUE, SigInfo},
    linux_frames,
    state::{State, Target},
    syscalls::StackT,
};
use crate::usercopy::{copy_from_user, copy_to_user, fake::Space};
use core::mem::{offset_of, size_of};
use std::{vec, vec::Vec};

#[repr(C)]
struct MStackT {
    ss_sp: u64,
    ss_flags: i32,
    ss_size: u64,
}
#[repr(C)]
struct MSigContext {
    r: [u64; 8], // r8..r15
    di: u64,
    si: u64,
    bp: u64,
    bx: u64,
    dx: u64,
    ax: u64,
    cx: u64,
    sp: u64,
    ip: u64,
    flags: u64,
    cs: u16,
    gs: u16,
    fs: u16,
    ss: u16,
    err: u64,
    trapno: u64,
    oldmask: u64,
    cr2: u64,
    fpstate: u64,
    reserved1: [u64; 8],
}
#[repr(C)]
struct MUContext {
    uc_flags: u64,
    uc_link: u64,
    uc_stack: MStackT,
    uc_mcontext: MSigContext,
    uc_sigmask: u64,
}
#[repr(C)]
struct MRtSigframe {
    pretcode: u64,
    uc: MUContext,
    info: [u8; 128],
}
#[repr(C)]
struct MSigaction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

#[test]
fn constants_match_the_uapi_layout() {
    assert_eq!(size_of::<MRtSigframe>() as u64, FRAME_SIZE);
    assert_eq!(offset_of!(MRtSigframe, uc), 8);
    assert_eq!(offset_of!(MRtSigframe, uc.uc_flags), 8);
    assert_eq!(offset_of!(MRtSigframe, uc.uc_link), 16);
    assert_eq!(offset_of!(MRtSigframe, uc.uc_stack), 24);
    assert_eq!(offset_of!(MRtSigframe, uc.uc_mcontext), 48);
    assert_eq!(offset_of!(MRtSigframe, uc.uc_sigmask), 304);
    assert_eq!(offset_of!(MRtSigframe, info) as u64, INFO);
    assert_eq!(size_of::<MSigContext>(), 256);
    assert_eq!(offset_of!(MSigContext, reserved1), 192);
    assert_eq!(offset_of!(MSigContext, fpstate), 184);
    assert_eq!(size_of::<MStackT>(), StackT::SIZE);
    assert_eq!(size_of::<MSigaction>(), SigAction::SIZE);
    assert_eq!(FIX_EFLAGS, 0x50DD5); // AC|OF|DF|TF|SF|ZF|AF|PF|CF|RF
    // The worst-case frame equals the AT_MINSIGSTKSZ the oracle reports.
    assert_eq!(MAX_FRAME_SIZE, 0x5a0);
}

struct FakeCpu {
    image: [u8; 512],
    restored: Vec<[u8; 512]>,
    resets: usize,
    valid_ss: Vec<u16>,
    mask: u32,
}

impl FakeCpu {
    fn new() -> Self {
        let mut image = [0u8; 512];
        for (i, b) in image.iter_mut().enumerate() {
            *b = (i % 251) as u8 | 1;
        }
        image[24..28].copy_from_slice(&0x1f80u32.to_le_bytes()); // MXCSR default
        Self {
            image,
            restored: Vec::new(),
            resets: 0,
            valid_ss: vec![USER_DS as u16],
            mask: 0xffbf,
        }
    }
}
impl Cpu for FakeCpu {
    fn fxsave(&mut self) -> [u8; 512] {
        self.image
    }
    fn mxcsr_mask(&self) -> u32 {
        self.mask
    }
    fn fxrstor(&mut self, image: &[u8; 512]) {
        self.restored.push(*image);
    }
    fn fpu_reset(&mut self) {
        self.resets += 1;
    }
    fn ss_is_valid_user_data(&self, ss: u16) -> bool {
        self.valid_ss.contains(&ss)
    }
}

const STACK_LO: u64 = 0x7_0000;
const STACK_TOP: u64 = 0x7_8000;

fn user_space() -> Space {
    let mut s = Space::default();
    for page in (STACK_LO..=STACK_TOP + 0x1000).step_by(0x1000) {
        s.map(page, true);
    }
    s
}
fn fill(s: &mut Space, lo: u64, hi: u64, byte: u8) {
    let v = vec![byte; (hi - lo) as usize];
    assert_eq!(copy_to_user(s, lo, &v), 0);
}
fn read(s: &mut Space, at: u64, n: usize) -> Vec<u8> {
    let mut v = vec![0; n];
    assert_eq!(copy_from_user(s, &mut v, at), 0);
    v
}

fn regs() -> Regs {
    Regs {
        r15: 0x15,
        r14: 0x14,
        r13: 0x13,
        r12: 0x12,
        bp: 0xb9,
        bx: 0xb8,
        r11: 0x11,
        r10: 0x10,
        r9: 0x9,
        r8: 0x8,
        ax: 0xa5,
        cx: 0xc5,
        dx: 0xd5,
        si: 0x51,
        di: 0xd1,
        orig_ax: u64::MAX,
        ip: 0x40_1234,
        cs: USER_CS,
        flags: 0x246 | 0x400, // IF|ZF|PF + DF
        sp: STACK_TOP,
        ss: USER_DS,
    }
}

fn handler_state() -> State {
    let mut st = State::new(5, 0, 1000);
    st.actions[usize::from(SIGUSR1) - 1] = SigAction {
        handler: 0x40_1000,
        flags: SA_SIGINFO | SA_RESTORER,
        restorer: 0x40_2000,
        mask: SigSet(1 << 11), // SIGUSR2
    };
    st.arch.trap_nr = 14;
    st.arch.error_code = 6;
    st.arch.cr2 = 0xdead_b000;
    st
}

fn send(st: &mut State, sig: u8) {
    st.send_signal(sig, SigInfo::from_kill(sig, false, 1, 77), Target::Process)
        .unwrap();
}

/// Expected frame bytes from the mirror struct; `base` has the stale stack
/// content the unwritten fields must keep.
#[allow(clippy::too_many_lines)]
fn expected_frame(
    base: u8,
    r: &Regs,
    st: &State,
    ksig_info: &SigInfo,
    fp: u64,
    mask: u64,
) -> Vec<u8> {
    let mut f = vec![base; size_of::<MRtSigframe>()];
    let mut put = |off: usize, bytes: &[u8]| f[off..off + bytes.len()].copy_from_slice(bytes);
    let sc = offset_of!(MRtSigframe, uc.uc_mcontext);
    let sco = |o: usize| sc + o;
    put(0, &0x40_2000u64.to_le_bytes());
    put(offset_of!(MRtSigframe, uc.uc_flags), &6u64.to_le_bytes()); // SS | STRICT
    put(offset_of!(MRtSigframe, uc.uc_link), &0u64.to_le_bytes());
    let stk = offset_of!(MRtSigframe, uc.uc_stack);
    put(
        stk + offset_of!(MStackT, ss_sp),
        &st.altstack.sp.to_le_bytes(),
    );
    put(
        stk + offset_of!(MStackT, ss_flags),
        &st.altstack.flags.to_le_bytes(),
    );
    put(
        stk + offset_of!(MStackT, ss_size),
        &st.altstack.size.to_le_bytes(),
    );
    for (i, v) in [r.r8, r.r9, r.r10, r.r11, r.r12, r.r13, r.r14, r.r15]
        .into_iter()
        .enumerate()
    {
        put(sco(offset_of!(MSigContext, r) + 8 * i), &v.to_le_bytes());
    }
    for (o, v) in [
        (offset_of!(MSigContext, di), r.di),
        (offset_of!(MSigContext, si), r.si),
        (offset_of!(MSigContext, bp), r.bp),
        (offset_of!(MSigContext, bx), r.bx),
        (offset_of!(MSigContext, dx), r.dx),
        (offset_of!(MSigContext, ax), r.ax),
        (offset_of!(MSigContext, cx), r.cx),
        (offset_of!(MSigContext, sp), r.sp),
        (offset_of!(MSigContext, ip), r.ip),
        (offset_of!(MSigContext, flags), r.flags),
        (offset_of!(MSigContext, err), st.arch.error_code),
        (offset_of!(MSigContext, trapno), st.arch.trap_nr),
        (offset_of!(MSigContext, oldmask), mask),
        (offset_of!(MSigContext, cr2), st.arch.cr2),
        (offset_of!(MSigContext, fpstate), fp),
    ] {
        put(sco(o), &v.to_le_bytes());
    }
    put(
        sco(offset_of!(MSigContext, cs)),
        &(r.cs as u16).to_le_bytes(),
    );
    put(sco(offset_of!(MSigContext, gs)), &0u16.to_le_bytes());
    put(sco(offset_of!(MSigContext, fs)), &0u16.to_le_bytes());
    put(
        sco(offset_of!(MSigContext, ss)),
        &(r.ss as u16).to_le_bytes(),
    );
    put(offset_of!(MRtSigframe, uc.uc_sigmask), &mask.to_le_bytes());
    put(offset_of!(MRtSigframe, info), &ksig_info.to_bytes());
    f
}

#[test]
fn handler_frame_is_byte_exact_and_sigreturn_restores() {
    let mut st = handler_state();
    let mut space = user_space();
    let mut cpu = FakeCpu::new();
    fill(&mut space, STACK_LO, STACK_TOP + 0x1000, 0xaa);
    let before = regs();
    let mut r = before;
    send(&mut st, SIGUSR1);
    assert!(st.signal_pending());
    assert_eq!(
        do_signal_or_restart(&mut st, &mut r, &mut space, &mut cpu),
        Outcome::Handled
    );

    // Stack math: sp - 128, FXSAVE at round_down(. - 512, 64), frame below,
    // aligned so that (frame + 8) % 16 == 0.
    let buf_fx = (STACK_TOP - 128 - 512) & !63;
    let frame = ((buf_fx - FRAME_SIZE) & !15) - 8;
    assert_eq!((frame + 8) % 16, 0);
    assert_eq!(r.sp, frame);
    assert_eq!((r.di, r.si, r.dx, r.ax), (10, frame + INFO, frame + 8, 0));
    assert_eq!((r.ip, r.cs, r.ss), (0x40_1000, USER_CS, USER_DS));
    assert_eq!(r.flags, 0x246); // DF cleared
    assert_eq!(cpu.resets, 1);
    assert_eq!(st.blocked, SigSet((1 << 11) | (1 << 9)));

    let info = SigInfo::from_kill(SIGUSR1, false, 1, 77);
    let want = expected_frame(0xaa, &before, &st_at_signal(), &info, buf_fx, 0);
    assert_eq!(read(&mut space, frame, 440), want);

    // The FXSAVE image: hardware bytes, then _fpx_sw_bytes at 464.
    let image = read(&mut space, buf_fx, 512);
    assert_eq!(image[..464], cpu.image[..464]);
    let mut sw = [0u8; 48];
    sw[0..4].copy_from_slice(&0x4650_5853u32.to_le_bytes()); // FP_XSTATE_MAGIC1
    sw[4..8].copy_from_slice(&516u32.to_le_bytes()); // extended_size
    sw[16..20].copy_from_slice(&512u32.to_le_bytes()); // xstate_size
    assert_eq!(image[464..], sw);
    // Memory between the image and the frame / above the image is untouched.
    assert_eq!(read(&mut space, buf_fx + 512, 8), vec![0xaa; 8]);

    // Handler returns: `ret` popped pretcode, so sp = frame + 8, orig_ax = -1.
    let mut ret = Regs {
        sp: frame + 8,
        ax: 0x1111,
        orig_ax: 5,
        flags: 0x3202,
        cs: 0x2b,
        ..r
    };
    ret.r15 = 0xbad;
    let out = rt_sigreturn(&mut st, &mut ret, &mut space, &mut cpu);
    assert_eq!(
        out,
        super::frame::Sigreturn {
            ret: 0xa5,
            bad_frame: false
        }
    );
    let mut want_regs = before;
    want_regs.orig_ax = u64::MAX;
    assert_eq!(ret.r15, want_regs.r15);
    assert_eq!((ret.ax, ret.sp, ret.ip), (0xa5, STACK_TOP, 0x40_1234));
    assert_eq!((ret.cs, ret.ss, ret.orig_ax), (USER_CS, USER_DS, u64::MAX));
    // Flags: FIX_EFLAGS bits come from the frame (DF set again), the rest
    // (IF, IOPL, NT, ...) from the current regs.
    assert_eq!(ret.flags, (0x3202 & !0x50DD5) | (0x646 & 0x50DD5));
    assert_eq!(st.blocked, SigSet::EMPTY);
    assert_eq!(cpu.restored, vec![cpu.image_with_sw(&sw)]);
}

impl FakeCpu {
    fn image_with_sw(&self, sw: &[u8; 48]) -> [u8; 512] {
        let mut i = self.image;
        i[464..].copy_from_slice(sw);
        i
    }
}

fn st_at_signal() -> State {
    handler_state()
}

#[test]
fn siginfo_is_only_written_with_sa_siginfo() {
    let mut st = handler_state();
    st.actions[usize::from(SIGUSR1) - 1].flags = SA_RESTORER;
    let mut space = user_space();
    let mut cpu = FakeCpu::new();
    fill(&mut space, STACK_LO, STACK_TOP + 0x1000, 0xaa);
    let mut r = regs();
    send(&mut st, SIGUSR1);
    do_signal_or_restart(&mut st, &mut r, &mut space, &mut cpu);
    assert_eq!(read(&mut space, r.si, 128), vec![0xaa; 128]);
    // reserved1 and the stack_t padding are never stored either.
    let sc = r.sp + 48;
    assert_eq!(read(&mut space, sc + 192, 64), vec![0xaa; 64]);
    assert_eq!(read(&mut space, r.sp + 24 + 12, 4), vec![0xaa; 4]);
}

#[test]
fn handler_flags_nodefer_resethand_restart() {
    // SA_NODEFER: signal not added to the mask. SA_RESETHAND: handler reset,
    // flags kept. sa_mask never blocks SIGKILL/SIGSTOP.
    let mut st = handler_state();
    st.actions[usize::from(SIGUSR1) - 1].flags |= SA_NODEFER | SA_RESETHAND;
    st.actions[usize::from(SIGUSR1) - 1].mask = SigSet(u64::MAX);
    let mut space = user_space();
    let mut cpu = FakeCpu::new();
    let mut r = regs();
    send(&mut st, SIGUSR1);
    assert_eq!(
        do_signal_or_restart(&mut st, &mut r, &mut space, &mut cpu),
        Outcome::Handled
    );
    assert_eq!(st.blocked, SigSet(u64::MAX).without_unblockable());
    let k = st.actions[usize::from(SIGUSR1) - 1];
    assert_eq!(k.handler, 0);
    assert_ne!(k.flags & SA_RESTORER, 0);
    // The frame still reports the pre-delivery mask (empty).
    assert_eq!(read(&mut space, r.sp + 304, 8), vec![0; 8]);
}

#[test]
fn saved_sigmask_goes_into_the_frame_and_is_cleared() {
    let mut st = handler_state();
    st.blocked = SigSet(0b1000);
    st.saved_sigmask = Some(SigSet(0b100000));
    let mut space = user_space();
    let mut cpu = FakeCpu::new();
    let mut r = regs();
    send(&mut st, SIGUSR1);
    do_signal_or_restart(&mut st, &mut r, &mut space, &mut cpu);
    assert_eq!(read(&mut space, r.sp + 304, 8), 0b100000u64.to_le_bytes());
    assert_eq!(st.saved_sigmask, None);
    // The handler runs with blocked | sa_mask | sig, not the saved mask.
    assert_eq!(st.blocked, SigSet(0b1000 | (1 << 11) | (1 << 9)));
}

#[test]
fn missing_restorer_or_bad_stack_forces_sigsegv() {
    // x64_setup_rt_frame: no SA_RESTORER -> -EFAULT -> force_sigsegv(sig).
    let mut st = State::new_init(1000);
    st.actions[usize::from(SIGUSR1) - 1] = SigAction {
        handler: 0x40_1000,
        ..SigAction::default()
    };
    let mut space = user_space();
    let mut cpu = FakeCpu::new();
    let mut r = regs();
    send(&mut st, SIGUSR1);
    assert_eq!(
        do_signal_or_restart(&mut st, &mut r, &mut space, &mut cpu),
        Outcome::FrameFailed
    );
    assert_eq!(r, regs()); // nothing changed, no FPU reset
    assert_eq!(cpu.resets, 0);
    assert!(!st.blocked.contains(SIGUSR1));
    // SIGSEGV is now pending (init made killable) and fatal.
    assert_eq!(
        do_signal_or_restart(&mut st, &mut r, &mut space, &mut cpu),
        Outcome::Exit {
            exit_code: 11,
            core: true
        }
    );

    // Unmapped stack page: partial failure, same result.
    let mut st = State::new_init(1000);
    st.actions[usize::from(SIGUSR1) - 1] = SigAction {
        handler: 0x40_1000,
        flags: SA_RESTORER | SA_SIGINFO,
        restorer: 0x40_2000,
        mask: SigSet::EMPTY,
    };
    let mut r = Regs {
        sp: 0x20_0000,
        ..regs()
    };
    send(&mut st, SIGUSR1);
    assert_eq!(
        do_signal_or_restart(&mut st, &mut r, &mut space, &mut cpu),
        Outcome::FrameFailed
    );
    assert_eq!(r.sp, 0x20_0000);
    // A kernel-range stack fails access_ok with no write at all.
    let mut st = State::new_init(1000);
    st.actions[usize::from(SIGUSR1) - 1] = SigAction {
        handler: 0x40_1000,
        flags: SA_RESTORER,
        restorer: 0x40_2000,
        mask: SigSet::EMPTY,
    };
    let mut r = Regs {
        sp: 0xffff_8000_0000_0000,
        ..regs()
    };
    send(&mut st, SIGUSR1);
    assert_eq!(
        do_signal_or_restart(&mut st, &mut r, &mut space, &mut cpu),
        Outcome::FrameFailed
    );
}

#[test]
fn sigsegv_handler_failure_is_fatal_without_recursion() {
    // force_sigsegv(SIGSEGV) = force_fatal_sig: default action even though
    // a SIGSEGV handler exists.
    let mut st = State::new_init(1000);
    st.actions[usize::from(SIGSEGV) - 1] = SigAction {
        handler: 0x40_1000,
        flags: SA_RESTORER,
        restorer: 0x40_2000,
        mask: SigSet::EMPTY,
    };
    let mut space = user_space();
    let mut cpu = FakeCpu::new();
    let mut r = Regs {
        sp: 0x20_0000,
        ..regs()
    };
    st.force_fault(&crate::signal::info::page_fault(
        crate::signal::info::PageFault::Segv(SEGV_MAPERR),
        0x10,
        6,
    ));
    assert_eq!(
        do_signal_or_restart(&mut st, &mut r, &mut space, &mut cpu),
        Outcome::FrameFailed
    );
    assert_eq!(
        do_signal_or_restart(&mut st, &mut r, &mut space, &mut cpu),
        Outcome::Exit {
            exit_code: 11,
            core: true
        }
    );
}

#[test]
fn altstack_selection_and_overflow() {
    let alt_lo = 0x7_0000;
    let alt_size = 0x2000;
    let mut st = handler_state();
    st.actions[usize::from(SIGUSR1) - 1].flags |= SA_ONSTACK;
    st.altstack = crate::signal::AltStack {
        sp: alt_lo,
        size: alt_size,
        flags: 0,
    };
    let mut space = user_space();
    let mut cpu = FakeCpu::new();
    // Normal stack elsewhere: sp = 0x7_f000.
    let mut r = Regs {
        sp: 0x7_9000,
        ..regs()
    };
    space.map(0x7_9000 - 0x1000, true);
    send(&mut st, SIGUSR1);
    do_signal_or_restart(&mut st, &mut r, &mut space, &mut cpu);
    let top = alt_lo + alt_size;
    let buf_fx = (top - 512) & !63;
    let frame = ((buf_fx - FRAME_SIZE) & !15) - 8;
    assert_eq!(r.sp, frame);
    // uc_stack in the frame: the stored stack, flags 0 (not SS_ONSTACK).
    assert_eq!(read(&mut space, frame + 24, 8), alt_lo.to_le_bytes());
    assert_eq!(read(&mut space, frame + 32, 4), 0u32.to_le_bytes());
    assert_eq!(read(&mut space, frame + 40, 8), alt_size.to_le_bytes());

    // Nested signal while on the altstack: keeps going down the same stack,
    // 128-byte red zone included.
    st.blocked = SigSet::EMPTY;
    let mut inner = Regs { sp: frame, ..r };
    send(&mut st, SIGUSR1);
    do_signal_or_restart(&mut st, &mut inner, &mut space, &mut cpu);
    let buf2 = (frame - 128 - 512) & !63;
    assert_eq!(inner.sp, ((buf2 - FRAME_SIZE) & !15) - 8);

    // Too small a stack: sp falls below the base -> bogus frame -> SIGSEGV.
    let mut st = handler_state();
    st.actions[usize::from(SIGUSR1) - 1].flags |= SA_ONSTACK;
    st.altstack = crate::signal::AltStack {
        sp: alt_lo,
        size: 0x100,
        flags: 0,
    };
    let mut r = Regs {
        sp: 0x7_9000,
        ..regs()
    };
    send(&mut st, SIGUSR1);
    assert_eq!(
        do_signal_or_restart(&mut st, &mut r, &mut space, &mut cpu),
        Outcome::FrameFailed
    );

    // SA_ONSTACK with the stack disabled uses the normal stack.
    let mut st = handler_state();
    st.actions[usize::from(SIGUSR1) - 1].flags |= SA_ONSTACK;
    let mut r = regs();
    send(&mut st, SIGUSR1);
    do_signal_or_restart(&mut st, &mut r, &mut space, &mut cpu);
    assert!(r.sp < STACK_TOP && r.sp > STACK_TOP - 2048);
}

#[test]
fn autodisarm_disarms_for_the_handler_and_rearms_on_return() {
    let mut st = handler_state();
    st.actions[usize::from(SIGUSR1) - 1].flags |= SA_ONSTACK;
    let arm = crate::signal::AltStack {
        sp: 0x7_0000,
        size: 0x2000,
        flags: SS_AUTODISARM,
    };
    st.altstack = arm;
    let mut space = user_space();
    let mut cpu = FakeCpu::new();
    let mut r = Regs {
        sp: 0x7_9000,
        ..regs()
    };
    space.map(0x7_8000, true);
    send(&mut st, SIGUSR1);
    do_signal_or_restart(&mut st, &mut r, &mut space, &mut cpu);
    assert_eq!(st.altstack.flags, SS_DISABLE);
    assert_eq!(st.altstack.size, 0);
    // The frame recorded the armed stack (with SS_AUTODISARM).
    assert_eq!(read(&mut space, r.sp + 32, 4), SS_AUTODISARM.to_le_bytes());
    // sigreturn restores it (do_sigaltstack is not "on stack" while disarmed).
    let mut ret = Regs { sp: r.sp + 8, ..r };
    rt_sigreturn(&mut st, &mut ret, &mut space, &mut cpu);
    assert_eq!(st.altstack, arm);
}

#[test]
fn sigreturn_does_not_restore_altstack_while_running_on_it() {
    // restore_altstack squashes EPERM from do_sigaltstack.
    let mut st = handler_state();
    st.actions[usize::from(SIGUSR1) - 1].flags |= SA_ONSTACK;
    let alt = crate::signal::AltStack {
        sp: 0x7_0000,
        size: 0x2000,
        flags: 0,
    };
    st.altstack = alt;
    let mut space = user_space();
    let mut cpu = FakeCpu::new();
    let mut r = Regs {
        sp: 0x7_9000,
        ..regs()
    };
    space.map(0x7_8000, true);
    send(&mut st, SIGUSR1);
    do_signal_or_restart(&mut st, &mut r, &mut space, &mut cpu);
    // Handler changed nothing; frame holds the same stack; EPERM is ignored.
    let mut ret = Regs { sp: r.sp + 8, ..r };
    assert!(!rt_sigreturn(&mut st, &mut ret, &mut space, &mut cpu).bad_frame);
    assert_eq!(st.altstack, alt);
}

#[test]
fn frame_alignment_holds_for_every_stack_pointer() {
    let mut cpu = FakeCpu::new();
    for sp in STACK_TOP - 64..STACK_TOP {
        let mut st = handler_state();
        let mut space = user_space();
        let mut r = Regs { sp, ..regs() };
        send(&mut st, SIGUSR1);
        do_signal_or_restart(&mut st, &mut r, &mut space, &mut cpu);
        assert_eq!((r.sp + 8) % 16, 0, "sp {sp:#x}");
        assert!(r.sp + FRAME_SIZE <= sp - 128, "frame below the red zone");
    }
}

#[test]
fn ss_is_kept_only_if_valid() {
    let mut cpu = FakeCpu::new();
    let mut st = handler_state();
    let mut space = user_space();
    let mut r = Regs { ss: 0x1b, ..regs() };
    send(&mut st, SIGUSR1);
    do_signal_or_restart(&mut st, &mut r, &mut space, &mut cpu);
    assert_eq!(r.ss, USER_DS); // 0x1b is not a valid data segment
    // The frame still shows the interrupted ss.
    assert_eq!(read(&mut space, r.sp + 48 + 150, 2), 0x1bu16.to_le_bytes());
    cpu.valid_ss.push(0x1b);
    let mut st = handler_state();
    let mut r = Regs { ss: 0x1b, ..regs() };
    send(&mut st, SIGUSR1);
    do_signal_or_restart(&mut st, &mut r, &mut space, &mut cpu);
    assert_eq!(r.ss, 0x1b);
}

fn frame_for_return(st: &mut State, cpu: &mut FakeCpu, space: &mut Space) -> (Regs, u64) {
    let mut r = regs();
    send(st, SIGUSR1);
    do_signal_or_restart(st, &mut r, space, cpu);
    let frame = r.sp;
    (
        Regs {
            sp: frame + 8,
            ..regs()
        },
        frame,
    )
}

#[test]
fn sigreturn_validates_like_restore_sigcontext() {
    let mut cpu = FakeCpu::new();
    let sc = 48u64;
    // cs/ss are forced to CPL 3; IOPL/NT/IF/VM never come from the frame.
    let mut st = handler_state();
    let mut space = user_space();
    let (mut ret, frame) = frame_for_return(&mut st, &mut cpu, &mut space);
    let poke =
        |space: &mut Space, off: u64, b: &[u8]| assert_eq!(copy_to_user(space, frame + off, b), 0);
    poke(&mut space, sc + 144, &0x10u16.to_le_bytes()); // cs
    poke(&mut space, sc + 150, &0x28u16.to_le_bytes()); // ss
    poke(&mut space, sc + 136, &u64::MAX.to_le_bytes()); // flags
    ret.flags = 0x202;
    assert!(!rt_sigreturn(&mut st, &mut ret, &mut space, &mut cpu).bad_frame);
    // cs != USER_CS: not 64-bit mode, so force_valid_ss is skipped.
    assert_eq!((ret.cs, ret.ss), (0x13, 0x2b));
    assert_eq!(ret.flags, 0x202 | 0x50DD5);

    // UC_STRICT_RESTORE_SS clear and cs == USER_CS: an invalid ss becomes
    // USER_DS; with it set, ss is left alone.
    let mut st = handler_state();
    let mut space = user_space();
    let (mut ret, frame) = frame_for_return(&mut st, &mut cpu, &mut space);
    assert_eq!(copy_to_user(&mut space, frame + 8, &2u64.to_le_bytes()), 0); // no STRICT
    assert_eq!(
        copy_to_user(&mut space, frame + 48 + 150, &0x18u16.to_le_bytes()),
        0
    );
    rt_sigreturn(&mut st, &mut ret, &mut space, &mut cpu);
    assert_eq!((ret.cs, ret.ss), (USER_CS, USER_DS));
    let mut st = handler_state();
    let mut space = user_space();
    let (mut ret, frame) = frame_for_return(&mut st, &mut cpu, &mut space);
    assert_eq!(
        copy_to_user(&mut space, frame + 48 + 150, &0x18u16.to_le_bytes()),
        0
    );
    rt_sigreturn(&mut st, &mut ret, &mut space, &mut cpu);
    assert_eq!(ret.ss, 0x1b); // 0x18 | 3, kept: STRICT_RESTORE_SS
}

#[test]
fn sigreturn_mask_is_applied_even_when_a_later_step_fails() {
    let mut cpu = FakeCpu::new();
    let mut st = handler_state();
    let mut space = user_space();
    let (mut ret, frame) = frame_for_return(&mut st, &mut cpu, &mut space);
    // Mask with KILL/STOP set is stripped; bad fpstate (reserved MXCSR bit) fails.
    let mask = SigSet::bit(SIGKILL) | SigSet::bit(SIGSTOP) | SigSet::bit(SIGUSR1);
    assert_eq!(
        copy_to_user(&mut space, frame + 304, &mask.to_le_bytes()),
        0
    );
    let fp = u64::from_le_bytes(read(&mut space, frame + 48 + 184, 8).try_into().unwrap());
    assert_eq!(
        copy_to_user(&mut space, fp + 24, &0xffff_ffffu32.to_le_bytes()),
        0
    );
    let out = rt_sigreturn(&mut st, &mut ret, &mut space, &mut cpu);
    assert_eq!(
        out,
        super::frame::Sigreturn {
            ret: 0,
            bad_frame: true
        }
    );
    assert_eq!(st.blocked, SigSet(SigSet::bit(SIGUSR1)));
    assert!(cpu.restored.is_empty());
    assert!(cpu.resets >= 2, "fpu reset on the failed restore");
    // SIGSEGV is pending, forced from kernel (SI_KERNEL).
    assert!(st.signal_pending());
    // SI_KERNEL (0x80) > SI_USER, so a forced SIGSEGV is synchronous.
    assert_eq!(st.dequeue_synchronous(), Some(SigInfo::kernel(SIGSEGV)));
}

#[test]
fn sigreturn_fpstate_cases() {
    let mut cpu = FakeCpu::new();
    let sc_fp = 48 + 184;
    for (label, fp, ok) in [
        ("null resets and succeeds", Some(0u64), true),
        ("unaligned", Some(0x7_7d81), false),
        ("unmapped", Some(0x20_0000), false),
        ("kernel pointer", Some(0xffff_8000_0000_0000), false),
        ("aligned, in range", None, true),
    ] {
        let mut st = handler_state();
        let mut space = user_space();
        let (mut ret, frame) = frame_for_return(&mut st, &mut cpu, &mut space);
        if let Some(fp) = fp {
            assert_eq!(
                copy_to_user(&mut space, frame + sc_fp, &fp.to_le_bytes()),
                0
            );
        }
        let resets = cpu.resets;
        let out = rt_sigreturn(&mut st, &mut ret, &mut space, &mut cpu);
        assert_eq!(out.bad_frame, !ok, "{label}");
        if fp == Some(0) {
            assert_eq!(cpu.resets, resets + 1);
        }
    }
}

#[test]
fn sigreturn_with_unreadable_frame_forces_sigsegv() {
    let mut cpu = FakeCpu::new();
    let mut st = State::new_init(1000);
    let mut space = user_space();
    let mut r = Regs {
        sp: 0x30_0000,
        ..regs()
    };
    let out = rt_sigreturn(&mut st, &mut r, &mut space, &mut cpu);
    assert_eq!(
        out,
        super::frame::Sigreturn {
            ret: 0,
            bad_frame: true
        }
    );
    assert_eq!(r.sp, 0x30_0000, "registers untouched on a bad frame");
    assert_eq!(
        do_signal_or_restart(&mut st, &mut r, &mut space, &mut cpu),
        Outcome::Exit {
            exit_code: 11,
            core: true
        }
    );
    // sp wrapping around (frame range check).
    let mut r = Regs { sp: 4, ..regs() };
    assert!(rt_sigreturn(&mut State::new(5, 0, 5), &mut r, &mut space, &mut cpu).bad_frame);
}

fn sys_regs(error: i64) -> Regs {
    Regs {
        orig_ax: 7,
        ax: error.wrapping_neg() as u64,
        ip: 0x40_0102,
        ..regs()
    }
}

#[test]
fn restart_rules() {
    // handle_signal (arch/x86/kernel/signal.c:156-174).
    let after = |error: i64, flags: u64| {
        let mut r = sys_regs(error);
        restart_for_handler(&mut r, flags);
        (r.ax as i64, r.ip)
    };
    assert_eq!(after(ERESTARTNOHAND, SA_RESTART), (-4, 0x40_0102));
    assert_eq!(after(ERESTART_RESTARTBLOCK, SA_RESTART), (-4, 0x40_0102));
    assert_eq!(after(ERESTARTSYS, 0), (-4, 0x40_0102));
    assert_eq!(after(ERESTARTSYS, SA_RESTART), (7, 0x40_0100));
    assert_eq!(after(ERESTARTNOINTR, 0), (7, 0x40_0100));
    assert_eq!(after(4, 0), (-4, 0x40_0102)); // plain -EINTR untouched
    // Not from a syscall (orig_ax = -1): nothing happens.
    let mut r = Regs {
        orig_ax: u64::MAX,
        ..sys_regs(ERESTARTSYS)
    };
    restart_for_handler(&mut r, SA_RESTART);
    assert_eq!((r.ax as i64, r.ip), (-ERESTARTSYS, 0x40_0102));
    // syscall_get_nr is an int: only the low 32 bits count.
    let mut r = Regs {
        orig_ax: 0xffff_ffff,
        ..sys_regs(ERESTARTSYS)
    };
    restart_for_handler(&mut r, SA_RESTART);
    assert_eq!(r.ip, 0x40_0102);
    let mut r = Regs {
        orig_ax: 0x1_0000_0007,
        ..sys_regs(ERESTARTSYS)
    };
    restart_for_handler(&mut r, SA_RESTART);
    assert_eq!((r.ax, r.ip), (0x1_0000_0007, 0x40_0100));
    // Values outside -4095..-1 are not errors.
    let mut r = Regs {
        ax: (-4096i64) as u64,
        ..sys_regs(0)
    };
    restart_for_handler(&mut r, SA_RESTART);
    assert_eq!(r.ip, 0x40_0102);

    // arch_do_signal_or_restart without a handler (:224-247).
    let none = |error: i64| {
        let mut r = sys_regs(error);
        restart_without_handler(&mut r);
        (r.ax, r.ip)
    };
    for e in [ERESTARTNOHAND, ERESTARTSYS, ERESTARTNOINTR] {
        assert_eq!(none(e), (7, 0x40_0100));
    }
    assert_eq!(none(ERESTART_RESTARTBLOCK), (219, 0x40_0100));
    assert_eq!(none(4), (4u64.wrapping_neg(), 0x40_0102));
}

#[test]
fn no_signal_restarts_and_restores_saved_mask() {
    let mut st = handler_state();
    st.saved_sigmask = Some(SigSet(0b10));
    st.blocked = SigSet(0b1);
    let mut space = user_space();
    let mut cpu = FakeCpu::new();
    let mut r = sys_regs(ERESTARTSYS);
    assert_eq!(
        do_signal_or_restart(&mut st, &mut r, &mut space, &mut cpu),
        Outcome::Resume
    );
    assert_eq!((r.ax, r.ip), (7, 0x40_0100));
    assert_eq!((st.blocked, st.saved_sigmask), (SigSet(0b10), None));
}

#[test]
fn handler_entry_applies_restart_before_the_frame() {
    // ERESTARTSYS + SA_RESTART: the frame records the backed-up ip and the
    // restored syscall number in rax; EINTR otherwise.
    let mut st = handler_state();
    st.actions[usize::from(SIGUSR1) - 1].flags |= SA_RESTART;
    let mut space = user_space();
    let mut cpu = FakeCpu::new();
    let mut r = sys_regs(ERESTARTSYS);
    send(&mut st, SIGUSR1);
    do_signal_or_restart(&mut st, &mut r, &mut space, &mut cpu);
    let sc = r.sp + 48;
    assert_eq!(read(&mut space, sc + 128, 8), 0x40_0100u64.to_le_bytes());
    assert_eq!(read(&mut space, sc + 104, 8), 7u64.to_le_bytes());
    let mut st = handler_state();
    let mut r = sys_regs(ERESTARTSYS);
    send(&mut st, SIGUSR1);
    do_signal_or_restart(&mut st, &mut r, &mut space, &mut cpu);
    assert_eq!(read(&mut space, r.sp + 48 + 104, 8), (-4i64).to_le_bytes());
}

#[test]
fn failed_frame_keeps_restart_adjustment() {
    // handle_signal adjusts regs before setup_rt_frame; a failure keeps it.
    let mut st = State::new_init(1000);
    st.actions[usize::from(SIGUSR1) - 1] = SigAction {
        handler: 0x1000,
        ..SigAction::default()
    };
    let mut space = user_space();
    let mut cpu = FakeCpu::new();
    let mut r = sys_regs(ERESTARTNOINTR);
    send(&mut st, SIGUSR1);
    assert_eq!(
        do_signal_or_restart(&mut st, &mut r, &mut space, &mut cpu),
        Outcome::FrameFailed
    );
    assert_eq!((r.ax, r.ip), (7, 0x40_0100));
}

#[test]
fn get_signal_default_actions() {
    // Non-init: fatal default; ignore; stop; handler; SIG_IGN.
    let mut st = State::new(5, 0, 100);
    st.blocked.add(SIGTERM);
    send(&mut st, SIGTERM);
    st.blocked = SigSet::EMPTY;
    // Group exit was not started (blocked): get_signal reports the fatal signal.
    assert_eq!(
        get_signal(&mut st),
        GetSignal::Fatal {
            exit_code: 15,
            core: false
        }
    );
    assert_eq!(st.group_exit, Some(15));

    let mut st = State::new(5, 0, 100);
    st.blocked.add(SIGTSTP);
    send(&mut st, SIGTSTP);
    st.blocked = SigSet::EMPTY;
    assert_eq!(get_signal(&mut st), GetSignal::Stop(SIGTSTP));

    // Default-ignore signal that was queued blocked is dropped at delivery.
    let mut st = State::new(5, 0, 100);
    st.blocked.add(SIGCHLD);
    send(&mut st, SIGCHLD);
    st.blocked = SigSet::EMPTY;
    assert_eq!(get_signal(&mut st), GetSignal::None);
    assert!(!st.signal_pending());

    // SIG_IGN installed while pending... through sa_handler directly.
    let mut st = State::new(5, 0, 100);
    st.blocked.add(SIGUSR1);
    send(&mut st, SIGUSR1);
    st.blocked = SigSet::EMPTY;
    st.actions[usize::from(SIGUSR1) - 1].handler = SIG_IGN;
    assert_eq!(get_signal(&mut st), GetSignal::None);

    // Core signals request a dump; the exit code is still the number.
    let mut st = State::new(5, 0, 100);
    st.force_fault(&crate::signal::info::page_fault(
        crate::signal::info::PageFault::Segv(SEGV_MAPERR),
        0x10,
        6,
    ));
    assert_eq!(
        get_signal(&mut st),
        GetSignal::Fatal {
            exit_code: 11,
            core: true
        }
    );
}

#[test]
fn init_never_acts_on_default_signals_but_dies_of_forced_ones() {
    // get_signal: SIGNAL_UNKILLABLE && !sig_kernel_only -> continue.
    let mut init = State::new_init(100);
    init.blocked.add(SIGTERM);
    send(&mut init, SIGTERM); // queued because blocked
    init.blocked = SigSet::EMPTY;
    assert_eq!(get_signal(&mut init), GetSignal::None);
    // Forced SIGSEGV (a fault): init becomes killable and dies with 11.
    init.force_fault(&crate::signal::info::page_fault(
        crate::signal::info::PageFault::Segv(SEGV_MAPERR),
        0x10,
        6,
    ));
    assert_eq!(
        get_signal(&mut init),
        GetSignal::Fatal {
            exit_code: 11,
            core: true
        }
    );
    assert_eq!(
        crate::exec::report::signal_exit_code(11),
        init.group_exit_code(0)
    );
}

#[test]
fn faults_are_delivered_before_other_signals() {
    let mut st = handler_state();
    st.actions[usize::from(SIGSEGV) - 1] = SigAction {
        handler: 0x40_3000,
        flags: SA_SIGINFO | SA_RESTORER,
        restorer: 0x40_2000,
        mask: SigSet::EMPTY,
    };
    st.blocked.add(SIGUSR1);
    send(&mut st, SIGUSR1);
    st.blocked = SigSet::EMPTY;
    st.force_fault(&crate::signal::info::page_fault(
        crate::signal::info::PageFault::Segv(SEGV_MAPERR),
        0x1234,
        6,
    ));
    let mut space = user_space();
    let mut cpu = FakeCpu::new();
    let mut r = regs();
    do_signal_or_restart(&mut st, &mut r, &mut space, &mut cpu);
    assert_eq!((r.ip, r.di), (0x40_3000, 11));
    // The handler gets the fault siginfo with si_addr, and the sigcontext
    // shows trapno 14, err 6|4, cr2.
    let info = read(&mut space, r.si, 128);
    assert_eq!(info[16..24], 0x1234u64.to_le_bytes());
    let sc = r.sp + 48;
    assert_eq!(read(&mut space, sc + 160, 8), 14u64.to_le_bytes());
    assert_eq!(read(&mut space, sc + 152, 8), 6u64.to_le_bytes());
    assert_eq!(read(&mut space, sc + 176, 8), 0x1234u64.to_le_bytes());
}

#[test]
fn stop_signals_are_never_queued_for_init_by_kill() {
    let mut init = State::new_init(100);
    send(&mut init, SIGSTOP);
    send(&mut init, SIGKILL);
    assert!(!init.signal_pending());
}

#[test]
fn pending_signals_stack_frames_newest_first() {
    // Oracle init-reference-005 signal.order-*: handlers that block nothing
    // all get a frame before any runs (highest number on top); handlers whose
    // sa_mask blocks the rest run one at a time, lowest first.
    let sigs = [1u8, 10, 12, 34]; // HUP, USR1, USR2, RT2
    for (mask, expect_top, frames) in [(0u64, 34u8, 4usize), (u64::MAX, 1, 1)] {
        let mut st = State::new(5, 0, 100);
        for s in sigs {
            st.actions[usize::from(s) - 1] = SigAction {
                handler: 0x40_1000 + u64::from(s),
                flags: SA_SIGINFO | SA_RESTORER,
                restorer: 0x40_2000,
                mask: SigSet(mask),
            };
            st.blocked.add(s);
        }
        for s in sigs.iter().rev() {
            send(&mut st, *s);
        }
        st.blocked = SigSet::EMPTY;
        let mut space = user_space();
        let mut cpu = FakeCpu::new();
        let mut r = regs();
        assert_eq!(
            handle_pending_signals(&mut st, &mut r, &mut space, &mut cpu),
            Outcome::Handled
        );
        assert_eq!(r.di, u64::from(expect_top));
        assert_eq!(r.ip, 0x40_1000 + u64::from(expect_top));
        assert_eq!(cpu.resets, frames);
        assert!(!st.signal_pending());
    }
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

/// Rebuild, with this model, the frame the pinned Linux 6.18.57 built for the
/// probe in `target/linux-reference/sigframe-probe-001/` and compare every
/// byte (frame and FXSAVE area), then `rt_sigreturn` the real frame.
fn replay_linux_frame(frame_hex: &str, fp_hex: &str, frame_addr: u64, sig: u8, altstack: bool) {
    let want = unhex(frame_hex);
    let fp = unhex(fp_hex);
    let q = |o: usize| u64::from_le_bytes(want[o..o + 8].try_into().unwrap());
    let sc = 48;
    // The interrupted context, from the real sigcontext.
    let before = Regs {
        r8: q(sc),
        r9: q(sc + 8),
        r10: q(sc + 16),
        r11: q(sc + 24),
        r12: q(sc + 32),
        r13: q(sc + 40),
        r14: q(sc + 48),
        r15: q(sc + 56),
        di: q(sc + 64),
        si: q(sc + 72),
        bp: q(sc + 80),
        bx: q(sc + 88),
        dx: q(sc + 96),
        ax: q(sc + 104),
        cx: q(sc + 112),
        sp: q(sc + 120),
        ip: q(sc + 128),
        flags: q(sc + 136),
        cs: u64::from(u16::from_le_bytes(
            want[sc + 144..sc + 146].try_into().unwrap(),
        )),
        ss: u64::from(u16::from_le_bytes(
            want[sc + 150..sc + 152].try_into().unwrap(),
        )),
        orig_ax: 62, // kill(2), returned 0: no restart
    };
    let mut st = State::new(1, 0, 15_000);
    st.actions[usize::from(sig) - 1] = SigAction {
        handler: 0x20_10a0,
        flags: SA_SIGINFO | SA_RESTORER | if altstack { SA_ONSTACK } else { 0 },
        restorer: q(0),
        mask: SigSet(if altstack { 0 } else { 1 << 11 }),
    };
    st.blocked = SigSet(1); // the probe blocked SIGHUP
    if altstack {
        st.altstack = crate::signal::AltStack {
            sp: q(24),
            size: q(40),
            flags: 0,
        };
    }
    let mut space = Space::default();
    for page in (0x20_0000..0x21_0000u64).step_by(0x1000) {
        space.map(page, true);
    }
    for page in (0x7fff_ffff_d000u64..0x7fff_ffff_f000).step_by(0x1000) {
        space.map(page, true);
    }
    let mut cpu = FakeCpu::new();
    cpu.image.copy_from_slice(&fp);
    cpu.mask = 0xffff; // MXCSR_MASK the real FXSAVE stored at bytes 28..32
    let mut r = before;
    st.send_signal(sig, SigInfo::from_kill(sig, false, 1, 0), Target::Process)
        .unwrap();
    assert_eq!(
        handle_pending_signals(&mut st, &mut r, &mut space, &mut cpu),
        Outcome::Handled
    );
    assert_eq!(r.sp, frame_addr);
    assert_eq!(read(&mut space, frame_addr, 440), want, "rt_sigframe");
    let fpstate = q(sc + 184);
    assert_eq!(
        read(&mut space, fpstate, 512),
        fp,
        "FXSAVE area incl. _fpx_sw_bytes"
    );
    assert_eq!(
        (r.di, r.si, r.dx),
        (u64::from(sig), frame_addr + 312, frame_addr + 8)
    );

    // The real frame returns exactly what was interrupted.
    let mut back = Regs {
        sp: frame_addr + 8,
        ax: 0x99,
        r15: 0xbad,
        ..before
    };
    let out = rt_sigreturn(&mut st, &mut back, &mut space, &mut cpu);
    assert_eq!(
        out,
        super::frame::Sigreturn {
            ret: before.ax,
            bad_frame: false
        }
    );
    assert_eq!(
        back,
        Regs {
            orig_ax: u64::MAX,
            ..before
        }
    );
    assert_eq!(st.blocked, SigSet(1));
    assert_eq!(cpu.restored, vec![<[u8; 512]>::try_from(&fp[..]).unwrap()]);
}

#[test]
fn model_reproduces_the_pinned_linux_frame_on_the_normal_stack() {
    // uc_flags 6, _fpx_sw_bytes { 0x46505853, 516, xfeatures 0, 512 }, fpstate
    // at round_down(sp - 640, 64), frame 440 bytes below, rsp % 16 == 8.
    replay_linux_frame(
        linux_frames::PLAIN_FRAME,
        linux_frames::PLAIN_FPSTATE,
        linux_frames::PLAIN_FRAME_ADDR,
        10,
        false,
    );
}

#[test]
fn model_reproduces_the_pinned_linux_frame_on_the_altstack() {
    // Frame at the top of the altstack; uc_stack shows the armed stack with flags 0.
    replay_linux_frame(
        linux_frames::ALTSTACK_FRAME,
        linux_frames::ALTSTACK_FPSTATE,
        linux_frames::ALTSTACK_FRAME_ADDR,
        12,
        true,
    );
}

#[test]
fn linux_dump_pins_the_fp_facts() {
    // Literal facts read off the dump (probe-tcg.log), independent of the code.
    let f = unhex(linux_frames::PLAIN_FRAME);
    let p = unhex(linux_frames::PLAIN_FPSTATE);
    assert_eq!(&f[8..16], &6u64.to_le_bytes()); // uc_flags
    assert_eq!(&p[464..468], &0x4650_5853u32.to_le_bytes());
    assert_eq!(&p[468..472], &516u32.to_le_bytes());
    assert_eq!(&p[472..480], &[0; 8]); // xfeatures
    assert_eq!(&p[480..484], &512u32.to_le_bytes());
    assert_eq!(&p[484..512], &[0; 28]);
    assert_eq!(&p[24..28], &0x1f80u32.to_le_bytes()); // MXCSR
}

#[test]
fn default_rt_signal_is_fatal_like_any_default_action() {
    // sig_fatal uses siginmask(), which is false for real-time signals:
    // include/linux/signal.h:451.
    let mut st = State::new(5, 0, 100);
    st.actions[usize::from(SIGUSR1) - 1].handler = 0x1000;
    st.blocked.add(SIGUSR1);
    send(&mut st, SIGUSR1);
    st.blocked = SigSet::EMPTY;
    send(&mut st, 40);
    assert_eq!(st.group_exit, Some(40));
    // The pending handled signal never runs: the death mark comes first.
    assert_eq!(
        get_signal(&mut st),
        GetSignal::Fatal {
            exit_code: 40,
            core: false
        }
    );
    // Later signals are dropped.
    let mut st = State::new(5, 0, 100);
    send(&mut st, 33);
    send(&mut st, SIGTERM);
    assert_eq!(st.group_exit, Some(33));
    // A caught or ignored RT signal is not fatal.
    let mut st = State::new(5, 0, 100);
    st.actions[39].handler = SIG_IGN;
    send(&mut st, 40);
    assert_eq!((st.group_exit, st.signal_pending()), (None, false));
    // init ignores a default-action RT signal, unless it is blocked first.
    let mut init = State::new_init(100);
    send(&mut init, 40);
    assert!(!init.signal_pending());
    init.blocked.add(40);
    send(&mut init, 40);
    init.blocked = SigSet::EMPTY;
    assert_eq!(get_signal(&mut init), GetSignal::None);
}

#[test]
fn sig_fatal_by_class() {
    // default action, per kernel/signal.c masks: ignore/stop signals are not
    // fatal, everything else (incl. all real-time signals) is.
    for sig in 1..=64u8 {
        let mut st = State::new(5, 0, 100);
        st.send_signal(sig, SigInfo::from_kill(sig, false, 1, 0), Target::Process)
            .unwrap();
        let ignored_or_stop = [SIGCHLD, 18, 23, 28, SIGSTOP, SIGTSTP, 21, 22].contains(&sig);
        let want = if ignored_or_stop {
            None
        } else {
            Some(u32::from(sig))
        };
        // SIGSEGV etc. are fatal too (their coredump flag only affects delivery).
        let want = if matches!(sig, 3 | 4 | 5 | 6 | 7 | 8 | 11 | 24 | 25 | 31) {
            None
        } else {
            want
        };
        assert_eq!(st.group_exit, want, "signal {sig}");
        if want.is_none() && !ignored_or_stop {
            // coredump signals are not marked at generation, only at delivery
            assert!(st.signal_pending(), "signal {sig}");
        }
    }
}

#[test]
fn sigset_bit_is_total() {
    assert_eq!(SigSet::bit(0), 0);
    assert_eq!(SigSet::bit(65), 0);
    assert_eq!(SigSet::bit(1), 1);
    assert_eq!(SigSet::bit(64), 1 << 63);
    let mut s = SigSet::EMPTY;
    s.add(0);
    s.add(200);
    assert_eq!(s, SigSet::EMPTY);
    assert!(!s.contains(0));
}

#[test]
fn exec_keeps_ignored_blocked_and_pending() {
    // flush_signal_handlers(me, 0) in begin_new_exec; fs/exec.c:1234,1275.
    let mut st = handler_state();
    st.actions[usize::from(SIGUSR1) - 1].handler = SIG_IGN;
    st.actions[usize::from(SIGUSR1) - 1].flags = SA_RESTART;
    st.actions[11].handler = 0x1234;
    st.actions[11].mask = SigSet(5);
    st.blocked = SigSet(0b1000);
    st.send_signal(
        SIGUSR1 + 1,
        SigInfo::from_kill(SIGUSR1 + 1, false, 1, 0),
        Target::Process,
    )
    .ok();
    st.altstack = crate::signal::AltStack {
        sp: 0x1000,
        size: 0x2000,
        flags: SS_AUTODISARM,
    };
    st.flush_on_exec();
    assert_eq!(
        st.actions[usize::from(SIGUSR1) - 1],
        SigAction {
            handler: SIG_IGN,
            ..SigAction::default()
        }
    );
    assert_eq!(st.actions[11], SigAction::default());
    assert_eq!(st.blocked, SigSet(0b1000));
    assert_eq!(
        st.altstack,
        crate::signal::AltStack {
            sp: 0,
            size: 0,
            flags: SS_AUTODISARM
        }
    );
}

#[test]
fn spurious_math_fault_updates_arch_info_without_a_signal() {
    let mut st = State::new(5, 0, 100);
    let f = crate::signal::info::exception(16, 0, 0x40, 0, 0).unwrap();
    st.force_fault(&f);
    assert_eq!((st.arch.trap_nr, st.arch.error_code), (16, 0));
    assert!(!st.signal_pending());
}

fn segv_handler_state() -> State {
    let mut st = handler_state();
    st.actions[usize::from(SIGSEGV) - 1] = SigAction {
        handler: 0x40_3000,
        flags: SA_SIGINFO | SA_RESTORER,
        restorer: 0x40_2000,
        mask: SigSet::EMPTY,
    };
    st
}

#[test]
fn a_full_rt_quota_never_loses_a_fault_siginfo() {
    // Classic signals have reserved slots (legacy_queue allows one entry each),
    // so a forced fault bypasses the RT cap like `override_rlimit` in
    // `__send_signal_locked` (kernel/signal.c:1126).
    let mut st = segv_handler_state();
    st.blocked.add(40);
    for v in 0..64 {
        let info = SigInfo::rt(40, SI_QUEUE, 1, 0, v);
        st.send_signal(40, info, Target::Thread).unwrap();
    }
    let info = SigInfo::rt(40, SI_QUEUE, 1, 0, 64);
    assert_eq!(
        st.send_signal(40, info, Target::Thread),
        Err(::syscalls::Errno::EAGAIN)
    );
    st.force_fault(&crate::signal::info::page_fault(
        crate::signal::info::PageFault::Segv(SEGV_MAPERR),
        0xdead000,
        6,
    ));
    let (mut space, mut cpu, mut r) = (user_space(), FakeCpu::new(), regs());
    do_signal_or_restart(&mut st, &mut r, &mut space, &mut cpu);
    assert_eq!((r.ip, r.di), (0x40_3000, 11));
    let info = read(&mut space, r.si, 128);
    assert_eq!(info[0..4], 11i32.to_le_bytes());
    assert_eq!(info[8..12], SEGV_MAPERR.to_le_bytes());
    assert_eq!(info[16..24], 0xdead000u64.to_le_bytes());
}
