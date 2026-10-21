// SPDX-License-Identifier: GPL-2.0-only
// Linux 6.18.57 (commit 2ff600d29ee478d0a8d46ef8a58afb5e038fe692), all GPL-2.0:
// arch/x86/kernel/fpu/core.c (`fpu_clone` 622-690, `restore_fpregs_from_init_fpstate` 774-784,
// `fpu__clear_user_states` 828-862, `fpu_flush_thread` 865, `switch_fpu_prepare`/`finish`,
// `fpstate_init_user` 551-565), arch/x86/kernel/fpu/xstate.c (`fpu__init_cpu_xstate` 262-290,
// `setup_init_fpu_buf` 349-385, `fpu__init_system_xstate` 805-1010), arch/x86/kernel/fpu/init.c,
// arch/x86/kernel/fpu/xstate.h (`os_xsave`, `os_xrstor`, `XSTATE_OP`, `XSTATE_XSAVE`,
// `XSTATE_XRESTORE`), arch/x86/kernel/fpu/signal.c (`restore_fpregs_from_user`),
// arch/x86/kernel/cpu/common.c (`setup_pku` 523-541, `x86_nofsgsbase_setup`),
// arch/x86/kernel/process_64.c (`x86_pkru_load` 375-390), arch/x86/include/asm/{pkru,fpu/xcr}.h.
// Transformation: one CPU; the live registers are always the running task's (the kernel is
// soft-float), so there is no `TIF_NEED_FPU_LOAD`/`last_cpu` laziness: state is saved when a task
// is switched out and restored when it is switched in, eagerly. No supervisor state, no dynamic
// (AMX) state, no `fpstate` realloc.
//! The user FPU and `XSAVE` state: enabling it, the per-task save buffers, and the
//! [`kernel::signal::Cpu`] the signal frame code runs on.
//!
//! # Contract
//! * [`init`] runs once per group on the boot CPU at CPL0 with interrupts masked, before ring 3
//!   (it sets `CR4.OSFXSR/OSXSAVE/PKE`, `XCR0` and `IA32_XSS`). Everything else here needs it.
//! * While a ring-3 task is current, its user state is **in the registers**: ring 0 never
//!   touches x87/SSE/AVX/opmask (soft-float target), interrupts and system calls leave them
//!   alone. [`save`] copies them into the task's [`XBuf`] when it is switched out, [`restore`]
//!   loads them when it is switched in, so each task sees only its own.
//! * `PKRU` is not in the buffer's restore (`XFEATURE_MASK_USER_RESTORE` excludes it): it is
//!   switched eagerly with the task's saved value ([`pkru_switch`]).
//! * Lock order: nothing here takes a lock; [`XBuf::initial`] and [`XBuf::from_live`] allocate
//!   (heap lock, task context only).
//!
//! Unsafe boundaries: the XSAVE-family intrinsics, `RDPKRU`/`WRPKRU`, the `XRSTOR` whose `#GP`
//! is recovered at a known address, and the one-time publication of the configuration.

use crate::cpu::{Error, PtRegs};
use alloc::vec::Vec;
use core::{
    arch::{asm, naked_asm, x86_64 as arch},
    cell::UnsafeCell,
    mem::MaybeUninit,
    ptr,
    sync::atomic::{AtomicBool, Ordering},
};
use kernel::xstate::{
    self, Config, INIT_PKRU, MXCSR_DEFAULT, SaveMode, XSAVE_HDR_OFFSET, XsaveArea,
};
use raw_cpuid::CpuId;
use x86_64::registers::{
    control::{Cr0, Cr0Flags, Cr4, Cr4Flags},
    model_specific::{Efer, EferFlags, Msr},
    xcontrol::XCr0,
};

/// `MSR_IA32_XSS` (arch/x86/include/asm/msr-index.h).
const MSR_IA32_XSS: u32 = 0xda0;

/// What the command line asks for.
#[derive(Clone, Copy, Debug, Default)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "one flag per boot option (noxsave, noxsaveopt, noxsaves, nopku)"
)]
pub struct Options {
    /// `noxsave`: `X86_FEATURE_XSAVE` cleared, so no AVX, no PKU, `FXSAVE` state only.
    pub noxsave: bool,
    /// `nopku`: no protection keys (`pku_disabled`).
    pub nopku: bool,
    /// `noxsaveopt`: `X86_FEATURE_XSAVEOPT` cleared (the task save falls back to `XSAVE`).
    pub noxsaveopt: bool,
    /// `noxsaves`: `X86_FEATURE_XSAVES` cleared (the task save falls back to `XSAVEC`).
    pub noxsaves: bool,
}

impl Options {
    /// The kernel part of the loader command line (`noxsave`, `noxsaveopt`, `noxsaves`,
    /// `nopku`; arch/x86/kernel/cpu/common.c:1719-1727).
    pub fn from_boot(boot: &crate::boot::BootInfo) -> Self {
        Self {
            noxsave: boot.has_option(b"noxsave"),
            nopku: boot.has_option(b"nopku"),
            noxsaveopt: boot.has_option(b"noxsaveopt"),
            noxsaves: boot.has_option(b"noxsaves"),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The legacy (FXSAVE) image: the initial state of a CPU without XSAVE, a probe for MXCSR_MASK,
// and what the exception-code and self-test helpers read and write.

/// A 512-byte `FXSAVE` image.
#[repr(C, align(16))]
#[derive(Clone)]
pub(crate) struct FxImage(pub(crate) [u8; 512]);

impl FxImage {
    pub(crate) const ZERO: Self = Self([0; 512]);

    /// `fpstate_init_fxstate`: FCW 0x37f, MXCSR 0x1f80, everything else zero (x87 empty,
    /// XMM0-15 zero).
    const INITIAL: Self = {
        let mut bytes = [0u8; 512];
        bytes[0] = 0x7f;
        bytes[1] = 0x03;
        let mxcsr = MXCSR_DEFAULT.to_le_bytes();
        bytes[24] = mxcsr[0];
        bytes[25] = mxcsr[1];
        Self(bytes)
    };
}

/// `FXSAVE64` of the live x87/XMM state.
///
/// # Safety
/// CPUID.1:EDX.FXSR, `CR4.OSFXSR=1`, `CR0.EM=0` and `TS=0`; CPL0.
#[target_feature(enable = "fxsr")]
unsafe fn fxsave_live(image: &mut FxImage) {
    // SAFETY: `image` is 512 bytes, 16-byte aligned and exclusively borrowed, so FXSAVE's
    // 512-byte store stays inside it; the caller gives the CPU state FXSAVE requires. 64-bit
    // form, as Linux (`fxsaveq`).
    unsafe { arch::_fxsave64(image.0.as_mut_ptr()) };
}

/// `FXRSTOR64` of `image`.
///
/// # Safety
/// As [`fxsave_live`], and `image` holds no reserved MXCSR bit (else #GP).
#[target_feature(enable = "fxsr")]
unsafe fn fxrstor_live(image: *const u8) {
    // SAFETY: the caller passes 512 readable, 16-byte aligned bytes; the MXCSR condition is its
    // contract.
    unsafe { arch::_fxrstor64(image) };
}

/// `fpu__exception_code` input: the live x87/MXCSR control and status for a `#MF`/`#XM`.
pub fn fpu_exception_code(vector: u8) -> i32 {
    let mut image = FxImage::ZERO;
    // SAFETY: `init` ran (a ring-3 exception implies a running task): FXSR, OSFXSR, EM=TS=0.
    unsafe { fxsave_live(&mut image) };
    let word = |at: usize| u16::from_le_bytes([image.0[at], image.0[at + 1]]);
    let mxcsr = u32::from_le_bytes([image.0[24], image.0[25], image.0[26], image.0[27]]);
    kernel::signal::info::fpu_exception_code(vector, word(0), word(2), mxcsr)
}

/// Self-test helper: put `pattern` in XMM0 (and the initial legacy state elsewhere).
#[cfg(feature = "qemu-self-test")]
pub(crate) fn selftest_set_xmm0(pattern: [u8; 16]) {
    let mut image = FxImage::INITIAL.clone();
    image.0[160..176].copy_from_slice(&pattern);
    // SAFETY: CPL0 after `init`; the image is the initial state with only XMM0 changed (no
    // reserved MXCSR bit).
    unsafe { fxrstor_live(image.0.as_ptr()) };
}

/// Self-test helper: the live XMM0.
#[cfg(feature = "qemu-self-test")]
pub(crate) fn selftest_xmm0() -> [u8; 16] {
    let mut image = FxImage::ZERO;
    // SAFETY: as `fpu_exception_code`.
    unsafe { fxsave_live(&mut image) };
    image.0[160..176].try_into().unwrap_or([0; 16])
}

// ---------------------------------------------------------------------------------------------
// Save buffers.

/// 64 bytes, 64-byte aligned: the unit a save buffer is made of, so that a `Vec` of them is a
/// zero-initialised, 64-byte aligned, exactly sized byte area without a custom allocator.
#[repr(C, align(64))]
#[derive(Clone, Copy)]
struct Line([u8; 64]);

/// A task's saved user state (`fpu->fpstate`): `kernel_size` bytes in the format of
/// `Config::mode`, 64-byte aligned, allocated fallibly from the heap.
pub(crate) struct XBuf {
    lines: Vec<Line>,
}

/// The heap could not provide a save buffer (`-ENOMEM` for the operation that needed it).
#[derive(Debug)]
pub(crate) struct NoMemory;

impl XBuf {
    /// An all-zero buffer for `config`.
    fn zeroed(config: &Config) -> Result<Self, NoMemory> {
        let count = config.kernel_size.div_ceil(64);
        let mut lines = Vec::new();
        lines.try_reserve_exact(count).map_err(|_| NoMemory)?;
        for _ in 0..count {
            lines
                .push_within_capacity(Line([0; 64]))
                .map_err(|_| NoMemory)?;
        }
        Ok(Self { lines })
    }

    fn as_ptr(&self) -> *const u8 {
        self.lines.as_ptr().cast()
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.lines.as_mut_ptr().cast()
    }

    /// A buffer holding the initial state (`fpstate_init_user`/`init_fpstate`): what a new task
    /// that does not copy its parent's state starts with.
    pub(crate) fn initial() -> Result<Self, NoMemory> {
        let init = &installed().init;
        let mut buf = Self::zeroed(&installed().config)?;
        buf.lines.copy_from_slice(&init.lines);
        Ok(buf)
    }

    /// A buffer holding a copy of the calling task's live state (`fpu_clone`'s
    /// `save_fpregs_to_fpstate(dst)`).
    ///
    /// Context: a ring-3 task in the kernel, IF=0, its state still live.
    pub(crate) fn from_live() -> Result<Self, NoMemory> {
        let mut buf = Self::zeroed(&installed().config)?;
        // The header's `xcomp_bv` must be set before the first XRSTORS/XRSTOR of a compacted
        // buffer even if nothing is ever saved into it; XSAVES/XSAVEC write it themselves, the
        // other modes use 0.
        if installed().config.use_xsave() {
            buf.set_xcomp_bv(installed().config.kernel_xcomp_bv());
        }
        save(&mut buf);
        Ok(buf)
    }

    /// `xstate_init_xcomp_bv`.
    fn set_xcomp_bv(&mut self, value: u64) {
        let header = &mut self.lines[XSAVE_HDR_OFFSET / 64].0;
        header[8..16].copy_from_slice(&value.to_le_bytes());
    }
}

// ---------------------------------------------------------------------------------------------
// The configuration, published once.

struct Installed {
    config: Config,
    /// `init_fpstate`: the state of a task that has done nothing, in the buffers' format.
    init: XBuf,
}

struct Slot(UnsafeCell<MaybeUninit<Installed>>);

// SAFETY: written exactly once by `init` on the boot CPU, with interrupts masked and before any
// task exists (`READY` is stored with Release afterwards), and only read through `installed`,
// which checks `READY` with Acquire. Never mutated after publication.
unsafe impl Sync for Slot {}

static SLOT: Slot = Slot(UnsafeCell::new(MaybeUninit::uninit()));
static READY: AtomicBool = AtomicBool::new(false);

fn installed() -> &'static Installed {
    assert!(READY.load(Ordering::Acquire), "FPU used before fpu::init");
    // SAFETY: `READY` (Acquire) pairs with the Release store after the write in `init`; the
    // value is initialised and immutable from then on.
    unsafe { (*SLOT.0.get()).assume_init_ref() }
}

/// The enabled extended state.
pub(crate) fn config() -> &'static Config {
    &installed().config
}

// ---------------------------------------------------------------------------------------------
// Instructions.

/// `XSAVE`-family store of the live state into `area` (`os_xsave`, `XSTATE_XSAVE`).
///
/// # Safety
/// `init` ran for `config`; CPL0; `area` is 64-byte aligned (16 for `FXSAVE`), writable for
/// `config.kernel_size` bytes, and exclusively borrowed.
unsafe fn os_xsave(config: &Config, area: *mut u8) {
    let mask = config.save_mask();
    // SAFETY: each arm needs the CPU feature `config.mode` was chosen from (CPUID), enabled in
    // `init` (CR4.OSXSAVE, XCR0; IA32_XSS = 0 for XSAVES); the area contract is this
    // function's.
    unsafe {
        match config.mode {
            SaveMode::Fxsave => fxsave_to(area),
            SaveMode::Xsave => do_xsave(area, mask),
            SaveMode::Xsaveopt => do_xsaveopt(area, mask),
            SaveMode::Xsavec => do_xsavec(area, mask),
            SaveMode::Xsaves => do_xsaves(area, mask),
        }
    }
}

/// `XRSTOR`/`XRSTORS` of a kernel-format area (`os_xrstor`, `XSTATE_XRESTORE`): `XRSTORS`
/// exactly when the buffers were written by `XSAVES`.
///
/// # Safety
/// As [`os_xsave`], and `area` holds a valid state of the buffers' format (written by
/// [`os_xsave`], or the initial image): an invalid header would raise `#GP` in ring 0.
unsafe fn os_xrstor(config: &Config, area: *const u8, mask: u64) {
    // SAFETY: as above.
    unsafe {
        match config.mode {
            SaveMode::Fxsave => fxrstor_live(area),
            SaveMode::Xsave | SaveMode::Xsaveopt | SaveMode::Xsavec => do_xrstor(area, mask),
            SaveMode::Xsaves => do_xrstors(area, mask),
        }
    }
}

#[target_feature(enable = "fxsr")]
unsafe fn fxsave_to(area: *mut u8) {
    // SAFETY: `os_xsave`'s contract.
    unsafe { arch::_fxsave64(area) };
}

#[target_feature(enable = "xsave")]
unsafe fn do_xsave(area: *mut u8, mask: u64) {
    // SAFETY: `os_xsave`'s contract.
    unsafe { arch::_xsave64(area, mask) };
}

#[target_feature(enable = "xsave,xsaveopt")]
unsafe fn do_xsaveopt(area: *mut u8, mask: u64) {
    // SAFETY: `os_xsave`'s contract.
    unsafe { arch::_xsaveopt64(area, mask) };
}

#[target_feature(enable = "xsave,xsavec")]
unsafe fn do_xsavec(area: *mut u8, mask: u64) {
    // SAFETY: `os_xsave`'s contract.
    unsafe { arch::_xsavec64(area, mask) };
}

#[target_feature(enable = "xsave,xsaves")]
unsafe fn do_xsaves(area: *mut u8, mask: u64) {
    // SAFETY: `os_xsave`'s contract.
    unsafe { arch::_xsaves64(area, mask) };
}

#[target_feature(enable = "xsave")]
unsafe fn do_xrstor(area: *const u8, mask: u64) {
    // SAFETY: `os_xrstor`'s contract.
    unsafe { arch::_xrstor64(area, mask) };
}

#[target_feature(enable = "xsave,xsaves")]
unsafe fn do_xrstors(area: *const u8, mask: u64) {
    // SAFETY: `os_xrstor`'s contract.
    unsafe { arch::_xrstors64(area, mask) };
}

/// `switch_fpu_prepare`/`save_fpregs_to_fpstate`: the running task's live state into `buf`.
pub(crate) fn save(buf: &mut XBuf) {
    let config = &installed().config;
    // SAFETY: `init` ran; the task is a ring-3 task whose state is live; `buf` is a buffer of
    // `kernel_size` bytes made for this configuration, exclusively borrowed.
    unsafe { os_xsave(config, buf.as_mut_ptr()) };
}

/// `switch_fpu_finish`/`restore_fpregs_from_fpstate`: `buf` becomes the live state (everything
/// but `PKRU`).
pub(crate) fn restore(buf: &XBuf) {
    let config = &installed().config;
    // SAFETY: `buf` was produced by `save`/`initial`/`from_live` for this configuration, so its
    // header is valid for the instruction chosen by the same mode.
    unsafe { os_xrstor(config, buf.as_ptr(), config.restore_mask()) };
}

/// `RDPKRU`.
///
/// # Safety
/// `CR4.PKE=1` (else `#UD`); CPL0.
unsafe fn rdpkru() -> u32 {
    let value: u32;
    // Why asm: `RDPKRU` has no `core::arch` intrinsic (checked in the pinned stdarch). Needs
    // CR4.PKE; ECX = 0; writes EAX (PKRU) and EDX (zeroed); no memory, stack or flags effect.
    // SAFETY: the caller's contract.
    unsafe {
        asm!("rdpkru", in("ecx") 0, out("eax") value, out("edx") _, options(nomem, nostack, preserves_flags));
    }
    value
}

/// `WRPKRU`.
///
/// # Safety
/// `CR4.PKE=1`; CPL0.
unsafe fn wrpkru(value: u32) {
    // Why asm: no intrinsic. ECX = EDX = 0 required; EAX = the new PKRU; changes the access
    // rights of user pages for *subsequent* accesses (not `nomem`: a compiler fence for them);
    // no stack or flags effect. Kernel mappings are unaffected (PKRU applies to user pages only).
    // SAFETY: the caller's contract.
    unsafe {
        asm!("wrpkru", in("eax") value, in("ecx") 0, in("edx") 0, options(nostack, preserves_flags));
    }
}

/// `read_pkru()`: the live `PKRU`, 0 without protection keys.
pub(crate) fn read_pkru() -> u32 {
    if installed().config.ospke {
        // SAFETY: `ospke` means `init` set CR4.PKE; CPL0.
        unsafe { rdpkru() }
    } else {
        0
    }
}

/// `write_pkru()`: avoids the write when the value does not change.
pub(crate) fn write_pkru(value: u32) {
    if installed().config.ospke && value != read_pkru() {
        // SAFETY: as `read_pkru`.
        unsafe { wrpkru(value) };
    }
}

/// `x86_pkru_load`: save the leaving task's `PKRU` in `prev`, load the entering task's.
///
/// Context: a context switch, IF=0. A no-op without protection keys.
pub(crate) fn pkru_switch(prev: &mut u32, next: u32) {
    if installed().config.ospke {
        // SAFETY: `ospke` means CR4.PKE is set; CPL0.
        unsafe {
            *prev = rdpkru();
            if *prev != next {
                wrpkru(next);
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// XRSTOR whose #GP is an answer (the `rt_sigreturn` frame is the user's).
//
// Why asm: a `#GP` raised by `XRSTOR` of a hostile header or MXCSR must come back as a
// recoverable error, like Linux's `XSTATE_OP` extable entry (`EX_TYPE_FAULT_MCE_SAFE`); the
// CPU, not a model of its rules, decides. That needs the faulting instruction at a known
// address and a known resume address, which no intrinsic and no safe construct provides (the
// same technique and reasoning as `iret_site` in `cpu.rs`). The three functions below are the
// whole mechanism:
//  * `xrstor_checked_entry(area, rfbm) -> u64`: moves RFBM into EDX:EAX, jumps to the site.
//  * `xrstor_site`: the instruction `XRSTOR64 [rdi]`; on success `eax` = 0 and `ret` returns to
//    the caller of the entry (the jump pushed nothing).
//  * `xrstor_failed`: where a `#GP` at the site resumes, with `rsp` unchanged: returns 1.
// Prerequisites: CPL0, CR4.OSXSAVE=1, XCR0 initialised; `rdi` = 64-byte aligned readable area
// (misalignment is a `#GP` as well, answered as failure); IF masked (single CPU, the handler
// edit below cannot interleave with another use). Clobbers: rax, rdx; flags (`shr`, `xor`).
// Memory: reads the area; the CPU may rewrite registers it restores. Stack: none used.
// Control flow: returns to the Rust caller either way; no unwind. The exception handler
// (`cpu::interrupt_handler`, vector 13, CPL0) calls `fixup_xrstor`, which moves the saved RIP
// from the site to `xrstor_failed`, so the `iretq` resumes there.
#[unsafe(naked)]
unsafe extern "C" fn xrstor_checked_entry(area: *const u8, rfbm: u64) -> u64 {
    naked_asm!(
        "mov rax, rsi",
        "mov rdx, rsi",
        "shr rdx, 32",
        "jmp {site}",
        site = sym xrstor_site,
    )
}

#[unsafe(naked)]
unsafe extern "C" fn xrstor_site() -> u64 {
    naked_asm!("xrstor64 [rdi]", "xor eax, eax", "ret")
}

#[unsafe(naked)]
unsafe extern "C" fn xrstor_failed() -> u64 {
    naked_asm!("mov eax, 1", "ret")
}

/// `fixup_exception` for the one `XRSTOR` of [`xrstor_checked`]: a `#GP` at CPL0 whose RIP is
/// the site resumes at the failure return. Returns whether it was that.
pub(crate) fn fixup_xrstor(regs: &mut PtRegs) -> bool {
    if regs.ip != xrstor_site as *const () as u64 {
        return false;
    }
    // SAFETY: `regs` is the live exception frame the entry stub built on the kernel stack;
    // volatile commits the edit to that frame, which `iretq` then restores (as the other
    // recoveries in `cpu::interrupt_handler`). `xrstor_failed` is a valid code address and the
    // saved RSP still holds the return address of `xrstor_checked_entry`'s caller.
    unsafe {
        ptr::write_volatile(
            ptr::addr_of_mut!(regs.ip),
            xrstor_failed as *const () as u64,
        );
    }
    true
}

/// `XRSTOR` of the standard-format `area` with request mask `rfbm`; `false` when the CPU raised
/// `#GP` (a header or MXCSR it refuses, or a misaligned operand).
fn xrstor_checked(area: &XsaveArea, rfbm: u64) -> bool {
    // SAFETY: the mechanism's prerequisites above: CPL0 after `init` (so OSXSAVE/XCR0 are set;
    // `UserCpu::xrstor` is only reached with `use_xsave()`); `XsaveArea` is 64-byte aligned and
    // readable for its whole length.
    unsafe { xrstor_checked_entry(area.0.as_ptr(), rfbm) == 0 }
}

// ---------------------------------------------------------------------------------------------
// Enabling.

/// What `init` found: logged by the caller as a `CHECK` line.
#[derive(Clone, Copy, Debug)]
pub struct Summary {
    pub config: Config,
    /// Why the kernel runs with `FXSAVE` state although the CPU has `XSAVE`, if it does.
    pub fallback: Option<&'static str>,
}

/// One CPUID leaf (`cpuid_count`), through the audited `raw-cpuid` reader.
fn leaf(l: u32, s: u32) -> [u32; 4] {
    let r = raw_cpuid::native_cpuid::cpuid_count(l, s);
    [r.eax, r.ebx, r.ecx, r.edx]
}

/// Make x87/SSE/AVX usable from ring 3 the way Linux does (`fpu__init_cpu_generic`,
/// `fpu__init_cpu_xstate`, `setup_pku`) and give the registers Linux's initial state, so no
/// firmware or loader residue is visible to ring 3. `#MF`/`#XM` then reach ring 3 as `SIGFPE`
/// through `exec::report`.
///
/// Idempotent: the bare-metal suite starts one process per group, a second call only reloads the
/// initial state.
///
/// # Errors
/// [`Error::Cpu`] without FPU, FXSR, SSE and SSE2, or when the save buffer of the initial state
/// cannot be allocated.
///
/// # Safety
/// CPL0 on the BSP, IF clear, heap installed, before any ring-3 task runs.
pub unsafe fn init(options: Options) -> Result<Summary, Error> {
    if READY.load(Ordering::Acquire) {
        let summary = Summary {
            config: installed().config,
            fallback: None,
        };
        // SAFETY: the caller's contract; `READY` means everything below was already enabled.
        unsafe { reset_registers() };
        return Ok(summary);
    }
    let cpuid = CpuId::new();
    let supported = cpuid.get_feature_info().is_some_and(|features| {
        features.has_fpu()
            && features.has_fxsave_fxstor()
            && features.has_sse()
            && features.has_sse2()
    });
    if !supported {
        return Err(Error::Cpu);
    }
    // On AMD, EFER.FFXSR makes FXRSTOR at CPL0 skip the XMM registers, so firmware XMM values
    // would survive into ring 3: clear it first.
    // SAFETY: CPL0; `update` preserves every other EFER bit and FFXSR is only an optimisation
    // of FXSAVE/FXRSTOR.
    unsafe {
        Efer::update(|flags| flags.remove(EferFlags::FAST_FXSAVE_FXRSTOR));
    }
    // SAFETY: the CPUID bits above were checked; OSFXSR/OSXMMEXCPT are reserved-free CR4 bits
    // when FXSR/SSE exist; other bits are preserved. MP and NE (native x87 error reporting,
    // `#MF`) as Linux's CR0 state; EM and TS cleared so ring 3 never takes `#NM`.
    unsafe {
        Cr4::update(|flags| {
            flags.insert(Cr4Flags::OSFXSR | Cr4Flags::OSXMMEXCPT_ENABLE);
        });
        Cr0::update(|flags| {
            flags.remove(Cr0Flags::EMULATE_COPROCESSOR | Cr0Flags::TASK_SWITCHED);
            flags.insert(Cr0Flags::MONITOR_COPROCESSOR | Cr0Flags::NUMERIC_ERROR);
        });
        // SAFETY: OSFXSR set, EM clear, FXSR checked; the image is the architectural initial
        // legacy state.
        fxrstor_live(FxImage::INITIAL.0.as_ptr());
    }
    // Linux `fpu__init_system_mxcsr`: the MXCSR bits this CPU accepts come from an FXSAVE
    // image's MXCSR_MASK field (0 means the architectural 0xffbf).
    let mut probe = FxImage::ZERO;
    // SAFETY: the state FXSAVE needs was just established above.
    unsafe { fxsave_live(&mut probe) };
    let mask = u32::from_le_bytes([probe.0[28], probe.0[29], probe.0[30], probe.0[31]]);
    let mxcsr_mask = if mask == 0 { 0xffbf } else { mask };

    let mut fallback = None;
    let config = if !options.noxsave && cpuid.get_feature_info().is_some_and(|f| f.has_xsave()) {
        match enable_xsave(options, mxcsr_mask) {
            Ok(config) => config,
            Err(reason) => {
                fallback = Some(reason);
                Config::fxsave(mxcsr_mask)
            }
        }
    } else {
        Config::fxsave(mxcsr_mask)
    };
    // The initial state, in the buffers' format.
    let init = initial_buffer(&config).map_err(|NoMemory| Error::Cpu)?;
    xstate::install(&config);
    // SAFETY: single-writer, before `READY` (see `Slot`).
    unsafe {
        (*SLOT.0.get()).write(Installed { config, init });
    }
    READY.store(true, Ordering::Release);
    // SAFETY: the caller's contract.
    unsafe { reset_registers() };
    Ok(Summary { config, fallback })
}

/// The initial state in the save buffers' format: zero (every component in its initial
/// configuration, `XSTATE_BV` = 0) with the legacy area as the CPU's initial state
/// (`setup_init_fpu_buf`).
fn initial_buffer(config: &Config) -> Result<XBuf, NoMemory> {
    let mut buf = XBuf::zeroed(config)?;
    // `fpstate_init_user` (arch/x86/kernel/fpu/init.c:135): FCW and MXCSR of the legacy area. The
    // standard-format `XRSTOR` loads MXCSR from memory whatever `XSTATE_BV` says, so the
    // restore below needs the architectural value there.
    buf.lines[..8]
        .iter_mut()
        .zip(FxImage::INITIAL.0.as_chunks::<64>().0)
        .for_each(|(line, bytes)| line.0 = *bytes);
    if !config.use_xsave() {
        return Ok(buf);
    }
    buf.set_xcomp_bv(config.kernel_xcomp_bv());
    // SAFETY: CPL0 after the XSAVE enabling of `init`; the buffer has the zero header (XSTATE_BV
    // = 0) the instruction needs, `kernel_xcomp_bv` for a compacted mode.
    unsafe {
        os_xrstor(config, buf.as_ptr(), config.restore_mask());
        // All components are now in their initial configuration; read the legacy part back so
        // the buffer holds the CPU's non-zero initial values (FCW, MXCSR). Only the legacy area:
        // XSAVEC/XSAVES skip components in the initial configuration.
        fxsave_to(buf.as_mut_ptr());
    }
    Ok(buf)
}

/// Put every user register in its initial state (`fpu__clear_user_states` without the
/// bookkeeping).
///
/// # Safety
/// After `READY`; CPL0.
unsafe fn reset_registers() {
    let installed = installed();
    let config = &installed.config;
    // SAFETY: the initial buffer is valid for the configured instruction (`initial_buffer`).
    unsafe { os_xrstor(config, installed.init.as_ptr(), config.restore_mask()) };
    write_pkru(INIT_PKRU);
}

/// The XSAVE half of `init`.
fn enable_xsave(options: Options, mxcsr_mask: u32) -> Result<Config, &'static str> {
    // `setup_clear_cpu_cap(X86_FEATURE_XSAVEOPT/XSAVES)`: the save instructions are chosen from
    // CPUID.(0xd,1):EAX, so the options clear their bits there (bit 0 XSAVEOPT, bit 3 XSAVES).
    let l = |leaf_nr: u32, sub: u32| {
        let mut out = leaf(leaf_nr, sub);
        if (leaf_nr, sub) == (0xd, 1) {
            if options.noxsaveopt {
                out[0] &= !1;
            }
            if options.noxsaves {
                out[0] &= !8;
            }
        }
        out
    };
    let (l1, l7, l7_1) = (l(1, 0), l(7, 0), l(7, 1));
    // `setup_pku`: protection keys when the CPU has them and `nopku` was not given.
    let pku = !options.nopku && l7[2] >> 3 & 1 == 1;
    if pku {
        // SAFETY: CPL0; CR4.PKE is reserved-free when CPUID.7:ECX.PKU is set; other bits kept.
        unsafe {
            Cr4::update(|flags| flags.insert(Cr4Flags::PROTECTION_KEY_USER));
            wrpkru(INIT_PKRU);
        }
    }
    let undo = |reason| {
        // SAFETY: CPL0; clears only the bits set above, so nothing depends on them.
        unsafe {
            Cr4::update(|flags| {
                flags.remove(Cr4Flags::OSXSAVE | Cr4Flags::PROTECTION_KEY_USER);
            });
        }
        reason
    };
    let probe = xstate::Cpu {
        xsave: true,
        avx: l1[2] >> 28 & 1 == 1,
        avx512f: l7[1] >> 16 & 1 == 1,
        mpx: l7[1] >> 14 & 1 == 1,
        apx: l7_1[3] >> 21 & 1 == 1,
        ospke: pku,
    };
    let features = Config::features(l(0xd, 0), probe).map_err(|d| undo(reason(d)))?;
    // SAFETY: CPL0, CPUID.1:ECX.XSAVE set; XCR0 gets only components CPUID lists as supported
    // (x87 and SSE among them, AVX512 as a group, MPX as a group: `Config::features`).
    unsafe {
        Cr4::update(|flags| flags.insert(Cr4Flags::OSXSAVE));
        XCr0::write_raw(features);
        // `fpu__init_cpu_xstate`: IA32_XSS holds the supervisor features to manage; none here.
        if l(0xd, 1)[0] & 8 != 0 {
            Msr::new(MSR_IA32_XSS).write(0);
        }
    }
    Config::build(features, l, mxcsr_mask, pku).map_err(|d| undo(reason(d)))
}

fn reason(disabled: xstate::Disabled) -> &'static str {
    match disabled {
        xstate::Disabled::NoFpSse => "CPUID lists no x87/SSE xstate",
        xstate::Disabled::ApxAndMpx => "APX and MPX state both enumerated",
        xstate::Disabled::BadComponent(_) => "a component is supervisor state or empty",
        xstate::Disabled::SizeMismatch { .. } => "CPU sizes disagree with the component table",
        xstate::Disabled::TooBig(_) => "the save area exceeds 4 KiB",
    }
}

// ---------------------------------------------------------------------------------------------
// The signal frame code's view of the CPU.

/// The CPU facts the signal model needs ([`kernel::signal::Cpu`]): the user FPU state (live in
/// the registers whenever the kernel runs) and the segment test of `force_valid_ss`.
pub struct UserCpu(());

impl UserCpu {
    /// # Panics
    /// Before [`init`] (a kernel bug: ring 3 cannot run yet).
    #[must_use]
    pub fn new() -> Self {
        assert!(READY.load(Ordering::Acquire), "user FPU used before init");
        Self(())
    }
}

impl kernel::signal::Cpu for UserCpu {
    fn xstate(&self) -> Config {
        *config()
    }

    fn xsave(&mut self, area: &mut XsaveArea) {
        let config = config();
        // SAFETY: `UserCpu::new` checked `READY`; CPL0; `area` is a 64-byte aligned, exclusively
        // borrowed `AREA_MAX`-byte buffer, and `user_size <= AREA_MAX` (`Config::build`).
        // Standard format (XSAVE), the mask the frame carries.
        unsafe {
            if config.use_xsave() {
                do_xsave(area.0.as_mut_ptr(), config.features);
            } else {
                fxsave_to(area.0.as_mut_ptr());
            }
        }
    }

    fn xrstor(&mut self, area: &XsaveArea, rfbm: u64) -> bool {
        xrstor_checked(area, rfbm)
    }

    fn fxrstor(&mut self, area: &XsaveArea) -> bool {
        let mxcsr = u32::from_le_bytes([area.0[24], area.0[25], area.0[26], area.0[27]]);
        if mxcsr & !config().mxcsr_mask != 0 {
            return false; // FXRSTOR would #GP
        }
        // SAFETY: `READY`; the MXCSR condition was just checked; `XsaveArea` is 64-aligned and
        // 4 KiB, at least the 512 bytes read.
        unsafe { fxrstor_live(area.0.as_ptr()) };
        true
    }

    fn restore_init(&mut self, mask: u64) {
        let installed = installed();
        // SAFETY: the initial buffer is valid for the configured instruction.
        unsafe { os_xrstor(&installed.config, installed.init.as_ptr(), mask) };
    }

    fn fpu_reset(&mut self) {
        // SAFETY: `READY` (checked by `new`), CPL0.
        unsafe { reset_registers() };
    }

    fn read_pkru(&self) -> u32 {
        read_pkru()
    }

    fn write_pkru(&mut self, pkru: u32) {
        write_pkru(pkru);
    }

    // `force_valid_ss`'s `lar` (arch/x86/kernel/signal_64.c:28-48).
    //
    // Why asm: LAR (load access rights) has no Rust intrinsic and the x86_64
    // crate has no wrapper; reading the GDT descriptor by hand would reimplement
    // the hardware's selector walk (TI bit, LDT, limits, DPL/RPL rules) and
    // could disagree with it. Prerequisites: none beyond long mode; LAR with a
    // register operand takes no fault for any 16-bit value (a null, out of
    // range, LDT or system selector just clears ZF). Inputs: the selector in a
    // 16-bit register. Outputs: the access-rights dword in a 32-bit register,
    // preset to 0 and left untouched when LAR fails, so a failure reads as
    // rights 0 (Linux zeroes it explicitly). Clobbers: ZF (flags are not
    // declared preserved); no other register. Memory: none read or written
    // (`nomem`), no stack (`nostack`), no red zone, no side effect on any
    // descriptor. Privilege/context: any CPL, IF and preemption irrelevant. No
    // control flow, no unwind.
    fn ss_is_valid_user_data(&self, ss: u16) -> bool {
        // AR_DPL_MASK | AR_S | AR_P | AR_TYPE_MASK (the accessed bit 8 is not in
        // the mask): DPL 3, S, P and type read-write data or its expand-down form.
        const MASK: u32 = (3 << 13) | (1 << 12) | (1 << 15) | (7 << 9);
        const DPL3_S_P: u32 = (3 << 13) | (1 << 12) | (1 << 15);
        let mut rights: u32 = 0;
        // SAFETY: the instruction only reads the descriptor table entry the
        // selector names (architecturally, not through Rust memory) and writes
        // the register operand and ZF, as described above.
        unsafe {
            asm!(
                "lar {rights:e}, {selector:x}",
                rights = inout(reg) rights,
                selector = in(reg) ss,
                options(nomem, nostack),
            );
        }
        matches!(rights & MASK, v if v == DPL3_S_P | (1 << 9) || v == DPL3_S_P | (3 << 9))
    }
}

/// The `PKRU` a new task that is not a copy starts with.
pub(crate) const NEW_TASK_PKRU: u32 = INIT_PKRU;

const _: () = assert!(core::mem::size_of::<Line>() == 64 && core::mem::align_of::<Line>() == 64);
