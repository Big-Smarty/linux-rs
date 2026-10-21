// SPDX-License-Identifier: GPL-2.0-only
// Host tests of the XSAVE signal frame: a software model of `XSAVE`/`XRSTOR` stands in for the
// CPU. The expectations are the observations of the pinned Linux 6.18.57 on the AMD Zen 5
// workstation (`user/init` group `xstate`, `xtask/oracle/expected.tsv`) and the SDM's `#GP` rules
// for `XRSTOR`; the kernel under KVM reproduces the same group line for line.
#![allow(
    clippy::unreadable_literal,
    clippy::cast_possible_truncation,
    clippy::too_many_lines,
    clippy::items_after_statements,
    clippy::assert_is_empty
)]
extern crate std;

use super::{
    Cpu, Regs, SA_RESTORER, SA_SIGINFO, SIGSEGV, SIGUSR1, SigAction, SigSet, USER_DS,
    deliver::{Outcome, do_signal_or_restart},
    frame::rt_sigreturn,
    state::State,
    tests::{STACK_LO, STACK_TOP, fill, handler_state, read, regs, send, user_space},
};
use crate::usercopy::{copy_to_user, fake::Space};
use crate::xstate::{
    Config, FP_XSTATE_MAGIC1, FP_XSTATE_MAGIC2, MASK_FPSSE, MASK_PKRU, XsaveArea, zen5,
};
use std::{vec, vec::Vec};

const PKRU_USER: u32 = 0x5555_5544;

/// The CPU's registers as a standard-format image plus `PKRU`; records what the frame code asks.
struct XCpu {
    config: Config,
    /// Legacy area (bytes 0..416 are hardware-written) and component bytes; `bv` is `XINUSE`.
    image: Vec<u8>,
    bv: u64,
    pkru: u32,
    pkru_writes: Vec<u32>,
    /// `(rfbm, area)` of every `XRSTOR` the frame code made.
    xrstors: Vec<(u64, Vec<u8>)>,
    fxrstors: Vec<Vec<u8>>,
    inits: Vec<u64>,
    resets: usize,
}

impl XCpu {
    fn new(config: &Config) -> Self {
        // Distinct non-zero bytes everywhere the hardware writes.
        let mut image = vec![0u8; 4096];
        for (i, b) in image.iter_mut().enumerate().take(416) {
            *b = (i % 253) as u8 | 1;
        }
        image[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
        for (offset, size) in config.ranges(config.features) {
            for (i, b) in image[offset..offset + size].iter_mut().enumerate() {
                *b = ((offset + i) % 241) as u8 | 1;
            }
        }
        Self {
            config: *config,
            image,
            bv: config.features & !MASK_PKRU,
            pkru: PKRU_USER,
            pkru_writes: Vec::new(),
            xrstors: Vec::new(),
            fxrstors: Vec::new(),
            inits: Vec::new(),
            resets: 0,
        }
    }
}

impl Cpu for XCpu {
    fn xstate(&self) -> Config {
        self.config
    }
    fn xsave(&mut self, area: &mut XsaveArea) {
        // XSAVE writes the x87/SSE state, the header's XSTATE_BV and every enabled component;
        // the reserved bytes of the legacy area (416..464) it leaves alone.
        area.0[..416].copy_from_slice(&self.image[..416]);
        area.0[512..520].copy_from_slice(&self.bv.to_le_bytes());
        for (offset, size) in self.config.ranges(self.config.features) {
            area.0[offset..offset + size].copy_from_slice(&self.image[offset..offset + size]);
        }
        // The PKRU slot holds the live PKRU at the moment of the XSAVE.
        if let Some(offset) = self.config.pkru_offset() {
            area.0[offset..offset + 4].copy_from_slice(&self.pkru.to_le_bytes());
        }
    }
    fn xrstor(&mut self, area: &XsaveArea, rfbm: u64) -> bool {
        let size = self.config.user_size;
        // The #GP conditions of XRSTOR in the standard format.
        let bv = u64::from_le_bytes(area.0[512..520].try_into().unwrap());
        let mxcsr = u32::from_le_bytes(area.0[24..28].try_into().unwrap());
        if bv & !self.config.features != 0
            || area.0[520..536].iter().any(|&b| b != 0)
            || (rfbm & 6 != 0 && mxcsr & !self.config.mxcsr_mask != 0)
        {
            return false;
        }
        self.xrstors.push((rfbm, area.0[..size].to_vec()));
        self.image[..416].copy_from_slice(&area.0[..416]);
        for (offset, len) in self.config.ranges(rfbm) {
            self.image[offset..offset + len].copy_from_slice(&area.0[offset..offset + len]);
        }
        true
    }
    fn fxrstor(&mut self, area: &XsaveArea) -> bool {
        let mxcsr = u32::from_le_bytes(area.0[24..28].try_into().unwrap());
        if mxcsr & !self.config.mxcsr_mask != 0 {
            return false;
        }
        self.fxrstors.push(area.0[..512].to_vec());
        true
    }
    fn restore_init(&mut self, mask: u64) {
        self.inits.push(mask);
    }
    fn fpu_reset(&mut self) {
        self.resets += 1;
    }
    fn read_pkru(&self) -> u32 {
        self.pkru
    }
    fn write_pkru(&mut self, pkru: u32) {
        if pkru != self.pkru {
            self.pkru = pkru;
            self.pkru_writes.push(pkru);
        }
    }
    fn ss_is_valid_user_data(&self, ss: u16) -> bool {
        ss == USER_DS as u16
    }
}

/// An Intel-style layout (AVX-512 and PKRU at their fixed Skylake-X offsets, 2696 bytes): holes
/// between the components, unlike the dense AMD one.
fn skylake() -> Config {
    let leaf = |leaf: u32, sub: u32| match (leaf, sub) {
        (0xd, 0) => [0xe7 | 0x200, 0xa88, 0xa88, 0],
        (0xd, 1) => [0xf, 0x988, 0, 0],
        (0xd, 2) => [0x100, 0x240, 0, 0],
        (0xd, 5) => [0x40, 0x440, 0, 0],
        (0xd, 6) => [0x200, 0x480, 0, 0],
        (0xd, 7) => [0x400, 0x680, 0, 0],
        (0xd, 9) => [0x8, 0xa80, 0, 0],
        _ => [0; 4],
    };
    Config::build(0x2e7, leaf, 0xffff, true).unwrap()
}

fn word(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

/// Delivers `SIGUSR1` on a space whose stack bytes are all 0xaa; returns the state, space, the
/// frame address, the fpstate address and the registers the handler starts with.
fn deliver(cpu: &mut XCpu) -> (State<'static>, Space, u64, u64, Regs) {
    let mut st = handler_state();
    let mut space = user_space();
    fill(&mut space, STACK_LO, STACK_TOP + 0x1000, 0xaa);
    let mut r = regs();
    send(&mut st, SIGUSR1);
    assert_eq!(
        do_signal_or_restart(&mut st, &mut r, &mut space, cpu),
        Outcome::Handled
    );
    let frame = r.sp;
    let fpstate = word(&read(&mut space, frame + 48 + 184, 8), 0);
    (st, space, frame, fpstate, r)
}

#[test]
fn the_frame_is_the_xsave_standard_format_where_linux_puts_it() {
    let mut cpu = XCpu::new(&zen5());
    let (_, mut space, frame, fp, handler_regs) = deliver(&mut cpu);
    // fpu__alloc_mathframe: round_down(sp - 128 - (2440 + 4), 64); the handler frame is 456
    // bytes below (the user's xstate group checks the same numbers on the pinned Linux).
    assert_eq!(fp, (STACK_TOP - 128 - 2444) & !63);
    assert_eq!(frame, fp - 456);
    assert_eq!(handler_regs.sp, frame);
    // uc_flags: UC_FP_XSTATE | UC_SIGCONTEXT_SS | UC_STRICT_RESTORE_SS.
    assert_eq!(word(&read(&mut space, frame + 8, 8), 0), 7);
    let area = read(&mut space, fp, 2444 + 64);
    assert_eq!(area[..416], cpu.image[..416], "x87 and SSE");
    // The reserved bytes of the legacy area keep the stack's contents.
    assert!(area[416..464].iter().all(|&b| b == 0xaa));
    // _fpx_sw_bytes.
    assert_eq!(area[464..468], FP_XSTATE_MAGIC1.to_le_bytes());
    assert_eq!(area[468..472], 2444u32.to_le_bytes());
    assert_eq!(word(&area, 472), 0x2e7);
    assert_eq!(area[480..484], 2440u32.to_le_bytes());
    assert!(area[484..512].iter().all(|&b| b == 0));
    // The header: XSTATE_BV is XINUSE plus FPSSE and PKRU; nothing else.
    assert_eq!(
        word(&area, 512),
        (0x2e7 & !MASK_PKRU) | MASK_FPSSE | MASK_PKRU
    );
    assert!(area[520..576].iter().all(|&b| b == 0));
    // Components, then the PKRU the signal interrupted, then the trailing magic word.
    for (offset, size) in cpu.config.ranges(0x2e7 & !MASK_PKRU) {
        assert_eq!(
            area[offset..offset + size],
            cpu.image[offset..offset + size]
        );
    }
    assert_eq!(area[2432..2436], PKRU_USER.to_le_bytes());
    assert_eq!(area[2440..2444], FP_XSTATE_MAGIC2.to_le_bytes());
    assert!(
        area[2444..].iter().all(|&b| b == 0xaa),
        "nothing after the magic word"
    );
    // PKRU: all keys enabled while the frame was written, then the default for the handler
    // (`fpu__clear_user_states`, which the binary's `fpu_reset` implements).
    assert_eq!(cpu.pkru_writes, [0]);
    assert_eq!(cpu.resets, 1);
}

#[test]
fn bytes_the_instruction_does_not_write_keep_the_stack_contents() {
    // Holes between the components of an Intel-style layout.
    let mut cpu = XCpu::new(&skylake());
    let (_, mut space, _, fp, _) = deliver(&mut cpu);
    let area = read(&mut space, fp, 2696 + 4);
    assert!(
        area[832..1088].iter().all(|&b| b == 0xaa),
        "the hole before the opmask state"
    );
    assert_eq!(area[1088..1152], cpu.image[1088..1152]);
    assert_eq!(area[2688..2692], PKRU_USER.to_le_bytes());
    assert_eq!(
        area[2692..2696],
        cpu.image[2692..2696],
        "the rest of the 8-byte component"
    );
    assert_eq!(area[2696..2700], FP_XSTATE_MAGIC2.to_le_bytes());
    // 732 + 15 + (2696 + 4 + 112) + 63, rounded up to 16: the AT_MINSIGSTKSZ of an AVX-512 Intel.
    assert_eq!(skylake().max_frame_size(), 3632);
}

#[test]
fn sigreturn_restores_every_described_component_and_nothing_is_initialised() {
    let mut cpu = XCpu::new(&zen5());
    let (mut st, mut space, frame, _, _) = deliver(&mut cpu);
    let mut ret = Regs {
        sp: frame + 8,
        ..regs()
    };
    let out = rt_sigreturn(&mut st, &mut ret, &mut space, &mut cpu);
    assert!(!out.bad_frame);
    assert_eq!(cpu.xrstors.len(), 1);
    assert_eq!(
        cpu.xrstors[0].0, 0x2e7,
        "the request is what the frame describes"
    );
    assert!(cpu.inits.is_empty());
    assert!(cpu.fxrstors.is_empty());
    // The area handed to XRSTOR is the frame's bytes.
    let (_, sent) = &cpu.xrstors[0];
    assert_eq!(sent[..416], cpu.image[..416]);
    assert_eq!(
        word(sent, 512),
        (0x2e7 & !MASK_PKRU) | MASK_FPSSE | MASK_PKRU
    );
    // fpu__clear_user_states ran once, for the handler's entry; nothing on the way back.
    assert_eq!(cpu.resets, 1);
}

/// Edit the frame in user memory, then `rt_sigreturn`; the CPU model and the outcome.
fn edit_and_return(edit: impl FnOnce(&mut Space, u64, u64)) -> (XCpu, bool) {
    let mut cpu = XCpu::new(&zen5());
    let (mut st, mut space, frame, fp, _) = deliver(&mut cpu);
    edit(&mut space, frame, fp);
    let mut ret = Regs {
        sp: frame + 8,
        ..regs()
    };
    let out = rt_sigreturn(&mut st, &mut ret, &mut space, &mut cpu);
    (cpu, out.bad_frame)
}

fn poke(space: &mut Space, at: u64, bytes: &[u8]) {
    assert_eq!(copy_to_user(space, at, bytes), 0);
}

#[test]
fn a_frame_without_valid_magic_is_restored_as_a_legacy_frame() {
    // The trailing magic word, the leading one and an oversized xstate_size all fall back to
    // FXRSTOR, then every other enabled component goes to its initial state (PKRU included).
    for edit in [
        (|s: &mut Space, _: u64, fp: u64| poke(s, fp + 2440, &[0; 4])) as fn(&mut Space, u64, u64),
        |s, _, fp| poke(s, fp + 464, &[0; 4]),
        |s, _, fp| poke(s, fp + 480, &9000u32.to_le_bytes()),
        |s, _, fp| poke(s, fp + 468, &600u32.to_le_bytes()), // xstate_size > extended_size
    ] {
        let (cpu, bad) = edit_and_return(edit);
        assert!(!bad);
        assert!(cpu.xrstors.is_empty());
        assert_eq!(cpu.fxrstors.len(), 1);
        assert_eq!(cpu.inits, [0x2e7 & !3], "everything but x87 and SSE");
        assert_eq!(cpu.resets, 1);
    }
}

#[test]
fn the_described_features_limit_the_restore_and_the_rest_is_initialised() {
    let (cpu, bad) = edit_and_return(|s, _, fp| poke(s, fp + 472, &7u64.to_le_bytes()));
    assert!(!bad);
    assert_eq!(cpu.xrstors.len(), 1);
    assert_eq!(cpu.xrstors[0].0, 7);
    assert_eq!(cpu.inits, [0x2e7 & !7]);
}

#[test]
fn what_the_cpu_refuses_forces_sigsegv_after_the_reset() {
    for (label, edit) in [
        (
            "reserved header byte",
            (|s: &mut Space, _: u64, fp: u64| poke(s, fp + 512 + 16, &[1]))
                as fn(&mut Space, u64, u64),
        ),
        ("component outside XCR0", |s, _, fp| {
            poke(s, fp + 512, &(0x2e7u64 | 8).to_le_bytes());
        }),
        ("bit 63 of xstate_bv", |s, _, fp| {
            poke(s, fp + 512, &(0x2e7u64 | 1 << 63).to_le_bytes());
        }),
        ("reserved MXCSR bit", |s, _, fp| {
            poke(s, fp + 24, &0x8000_0000u32.to_le_bytes());
        }),
        ("fpstate not 64-byte aligned", |s, frame, fp| {
            let copy = read(s, fp, 2444);
            poke(s, fp + 8, &copy);
            poke(s, frame + 48 + 184, &(fp + 8).to_le_bytes());
        }),
    ] {
        let (cpu, bad) = edit_and_return(edit);
        assert!(bad, "{label}");
        assert_eq!(
            cpu.resets, 2,
            "{label}: the handler entry and the failed restore"
        );
        assert!(cpu.inits.is_empty(), "{label}");
    }
}

#[test]
fn the_cpu_reads_no_more_than_the_request_names() {
    // A buffer whose last readable byte is the end of the AVX state (832): the first 836 bytes
    // of the frame, described as FPSSE|AVX with the magic word right after.
    fn short(s: &mut Space, frame: u64, fp: u64) {
        let mut area = read(s, fp, 836);
        area[464..468].copy_from_slice(&FP_XSTATE_MAGIC1.to_le_bytes());
        area[468..472].copy_from_slice(&836u32.to_le_bytes());
        area[472..480].copy_from_slice(&7u64.to_le_bytes());
        area[480..484].copy_from_slice(&832u32.to_le_bytes());
        area[832..836].copy_from_slice(&FP_XSTATE_MAGIC2.to_le_bytes());
        // 64-aligned, ends 64 bytes before the end of the mapped stack, so the next page is
        // beyond it: place it at the end of the last mapped page.
        let end = STACK_TOP + 0x2000;
        let at = end - 896;
        poke(s, at, &area);
        poke(s, frame + 48 + 184, &at.to_le_bytes());
    }
    let mut cpu = XCpu::new(&zen5());
    let (mut st, mut space, frame, fp, _) = deliver(&mut cpu);
    short(&mut space, frame, fp);
    // Unmap the page after the buffer: reading beyond 896 bytes would fault.
    space.0.remove(&(STACK_TOP + 0x2000));
    let mut ret = Regs {
        sp: frame + 8,
        ..regs()
    };
    assert!(!rt_sigreturn(&mut st, &mut ret, &mut space, &mut cpu).bad_frame);
    assert_eq!(cpu.xrstors[0].0, 7);
    // The same buffer, described as holding everything, needs the opmask state that is not there.
    let mut cpu = XCpu::new(&zen5());
    let (mut st, mut space, frame, fp, _) = deliver(&mut cpu);
    short(&mut space, frame, fp);
    let at = word(&read(&mut space, frame + 48 + 184, 8), 0);
    poke(&mut space, at + 472, &0x2e7u64.to_le_bytes());
    poke(&mut space, at + 512, &0x2e7u64.to_le_bytes());
    space.0.remove(&(STACK_TOP + 0x2000));
    let mut ret = Regs {
        sp: frame + 8,
        ..regs()
    };
    assert!(rt_sigreturn(&mut st, &mut ret, &mut space, &mut cpu).bad_frame);
}

#[test]
fn a_frame_that_cannot_be_written_restores_the_pkru_and_forces_sigsegv() {
    // The stack page is read-only: the header of the area cannot be cleared.
    let mut cpu = XCpu::new(&zen5());
    let mut st = handler_state();
    let mut space = Space::default();
    let top = 0x4_0000u64;
    space.map(top - 0x1000, false);
    let mut r = Regs { sp: top, ..regs() };
    send(&mut st, SIGUSR1);
    let out = do_signal_or_restart(&mut st, &mut r, &mut space, &mut cpu);
    assert_ne!(out, Outcome::Handled);
    // sig_prepare_pkru wrote 0; the failed copy wrote the interrupted value back.
    assert_eq!(cpu.pkru_writes, [0, PKRU_USER]);
    assert_eq!(cpu.pkru, PKRU_USER);
    let _ = (
        SigAction::default(),
        SigSet::EMPTY,
        SA_RESTORER,
        SA_SIGINFO,
        SIGSEGV,
    );
}
