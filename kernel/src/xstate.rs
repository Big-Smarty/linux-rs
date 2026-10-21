// SPDX-License-Identifier: GPL-2.0-only
// Linux 6.18.57 (commit 2ff600d29ee478d0a8d46ef8a58afb5e038fe692), all GPL-2.0:
// arch/x86/kernel/fpu/xstate.c (`xsave_cpuid_features` 63-80, `setup_xstate_cache` 247-282,
// `validate_user_xstate_header` 393-418, `xstate_calculate_size` 470-488,
// `paranoid_xstate_size_valid` 497-522, `get_xsave_size_user`/`init_xstate_size` 700-756,
// `fpu__init_system_xstate` 805-1010), arch/x86/kernel/fpu/init.c (`fpu__init_system_xstate_size_legacy`),
// arch/x86/kernel/fpu/signal.c (`fpu__get_fpstate_size`, `xstate_sigframe_size`),
// arch/x86/kernel/signal.c (`init_sigframe_size` 187-210), arch/x86/include/asm/fpu/xstate.h
// (`XFEATURE_MASK_*`), arch/x86/include/asm/fpu/types.h (`enum xfeature`),
// arch/x86/include/asm/pkru.h and arch/x86/mm/pkeys.c:121 (`init_pkru_value`).
// Transformation: the CPUID-driven part of the x86-64 user extended-state set-up as a pure
// function of CPUID leaves, so host tests can run it on recorded leaves; sizes, offsets and the
// frame arithmetic only. Dynamic (AMX) state, supervisor state (CET, PASID) and the per-task
// permission model are not ported: they are masked out of the enabled set (see `Config::features`).
#![forbid(unsafe_code)]
//! The user extended CPU state (`XSAVE` area) of the declared configuration: which components
//! are enabled, where the standard format puts them, how big a task's save buffer and a signal
//! frame are.
//!
//! Hardware access (`XSETBV`, `XSAVE*`, `XRSTOR*`, `RDPKRU`) is the binary's (`fpu.rs`); this
//! module is the arithmetic both the binary and the signal frame code ([`crate::signal`]) share.
//!
//! # Contract
//! * A [`Config`] is built once at boot, on the boot CPU, before ring 3 runs, and is immutable
//!   after; [`install`] publishes the numbers other pure modules need (`AT_MINSIGSTKSZ`).
//! * "noxsave" ([`Config::fxsave`]) is the configuration of every CPU without `XSAVE`, of the
//!   `noxsave` boot option, and of a CPU whose enumeration Linux itself rejects: `FXSAVE` state
//!   only, `_fpx_sw_bytes.xfeatures` 0, `AT_MINSIGSTKSZ` 0x5a0.
//! * `unsafe`: none.

use core::sync::atomic::{AtomicU64, Ordering};

/// `enum xfeature` masks (arch/x86/include/asm/fpu/types.h:100-149).
pub const MASK_FP: u64 = 1 << 0;
pub const MASK_SSE: u64 = 1 << 1;
pub const MASK_YMM: u64 = 1 << 2;
pub const MASK_BNDREGS: u64 = 1 << 3;
pub const MASK_BNDCSR: u64 = 1 << 4;
pub const MASK_OPMASK: u64 = 1 << 5;
pub const MASK_ZMM_HI256: u64 = 1 << 6;
pub const MASK_HI16_ZMM: u64 = 1 << 7;
pub const MASK_PKRU: u64 = 1 << 9;
pub const MASK_XTILE_CFG: u64 = 1 << 17;
pub const MASK_XTILE_DATA: u64 = 1 << 18;
pub const MASK_APX: u64 = 1 << 19;
pub const MASK_FPSSE: u64 = MASK_FP | MASK_SSE;

/// `XFEATURE_MAX`: component numbers are below this.
pub const XFEATURE_MAX: usize = 20;
/// `XFEATURE_XTILE_DATA`: the one component with a permission request (`ARCH_REQ_XCOMP_PERM`).
pub const XFEATURE_XTILE_DATA: u64 = 18;
pub const XFEATURE_PKRU: usize = 9;

/// `XFEATURE_MASK_USER_SUPPORTED` (arch/x86/include/asm/fpu/xstate.h:26-37).
pub const USER_SUPPORTED: u64 = MASK_FP
    | MASK_SSE
    | MASK_YMM
    | MASK_OPMASK
    | MASK_ZMM_HI256
    | MASK_HI16_ZMM
    | MASK_PKRU
    | MASK_BNDREGS
    | MASK_BNDCSR
    | MASK_XTILE_CFG
    | MASK_XTILE_DATA
    | MASK_APX;
/// `XFEATURE_MASK_USER_RESTORE`: what is restored on return to user space (`PKRU` is switched
/// eagerly, not through the buffer).
pub const USER_RESTORE: u64 = USER_SUPPORTED & !MASK_PKRU;
/// The components this kernel never enables: AMX tile state needs the dynamic-state (`XFD`)
/// permission model, which is not ported. A named blocker, see `docs/implementation.md`.
pub const UNSUPPORTED: u64 = MASK_XTILE_CFG | MASK_XTILE_DATA;

/// `FXSAVE_SIZE`, `XSAVE_HDR_SIZE`, `XSAVE_HDR_OFFSET`, `XSAVE_ALIGNMENT`.
pub const FXSAVE_SIZE: usize = 512;
pub const XSAVE_HDR_SIZE: usize = 64;
pub const XSAVE_HDR_OFFSET: usize = FXSAVE_SIZE;
pub const XSAVE_ALIGNMENT: usize = 64;
/// `sizeof(struct xregs_state)`: legacy area plus header.
pub const XREGS_SIZE: usize = FXSAVE_SIZE + XSAVE_HDR_SIZE;
/// The software-reserved bytes of the legacy area (`struct _fpx_sw_bytes` at byte 464).
pub const SW_RESERVED_OFFSET: usize = 464;
pub const SW_RESERVED_SIZE: usize = 48;

/// `FP_XSTATE_MAGIC1`, `FP_XSTATE_MAGIC2`, `FP_XSTATE_MAGIC2_SIZE`.
pub const FP_XSTATE_MAGIC1: u32 = 0x4650_5853;
pub const FP_XSTATE_MAGIC2: u32 = 0x4650_5845;
pub const FP_XSTATE_MAGIC2_SIZE: usize = 4;
/// `XCOMP_BV_COMPACTED_FORMAT`.
pub const XCOMP_BV_COMPACTED_FORMAT: u64 = 1 << 63;

/// `init_pkru_value` (arch/x86/mm/pkeys.c:121-130): every key but 0 access-disabled.
pub const INIT_PKRU: u32 = 0x5555_5554;
/// `MXCSR_DEFAULT`.
pub const MXCSR_DEFAULT: u32 = 0x1f80;

/// The largest standard-format area this kernel handles (a stack buffer in the signal paths).
/// The enabled set without AMX is below 3 KiB on every known CPU (2440 bytes on AMD Zen 5, 2696
/// with Intel's AVX-512 layout); a CPU that needs more is refused ([`Disabled::TooBig`]).
pub const AREA_MAX: usize = 4096;

/// A 64-byte aligned, zero-initialised standard-format area (the operand of `XSAVE`/`XRSTOR`).
#[repr(C, align(64))]
#[derive(Clone)]
pub struct XsaveArea(pub [u8; AREA_MAX]);

impl XsaveArea {
    #[must_use]
    pub const fn zeroed() -> Self {
        Self([0; AREA_MAX])
    }
}

/// `sizeof(struct sigframe_ia32)`: pretcode 4 + sig 4 + `sigcontext_32` 88 + `_fpstate_32` 624 +
/// extramask 4 + retcode 8 (`MAX_FRAME_SIGINFO_UCTXT_SIZE` under `CONFIG_IA32_EMULATION=y`).
const SIGFRAME_IA32_SIZE: u64 = 4 + 4 + 88 + 624 + 4 + 8;
/// `sizeof(struct fregs_state)`, added to every frame size for ia32 emulation when `FXSR` is used.
const FREGS_SIZE: u64 = 112;

/// A raw CPUID leaf: eax, ebx, ecx, edx.
pub type Leaf = [u32; 4];

/// How the kernel saves a task's state (`XSAVE`, `XSAVEOPT`, `XSAVEC`, `XSAVES` or, without
/// `XSAVE`, `FXSAVE`): the `ALTERNATIVE_3` of `XSTATE_XSAVE`
/// (arch/x86/kernel/fpu/xstate.h:127-143).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaveMode {
    Fxsave,
    Xsave,
    Xsaveopt,
    Xsavec,
    Xsaves,
}

/// Placement of one component in the standard format (`CPUID.(0xd, n)`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Component {
    pub offset: u32,
    pub size: u32,
    /// `XSTATE_FLAG_ALIGNED64`: 64-byte aligned in the compacted format.
    pub aligned64: bool,
}

/// Why the extended state is not enabled although the CPU has `XSAVE`: Linux prints a message and
/// continues with `FXSAVE` (`fpu__init_disable_system_xstate`); so does this kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disabled {
    /// CPUID does not list x87 and SSE among the features.
    NoFpSse,
    /// APX and MPX state enumerated together.
    ApxAndMpx,
    /// An enabled component is supervisor state or has a zero size.
    BadComponent(usize),
    /// The sizes the CPU reports differ from the ones computed from the components.
    SizeMismatch {
        user: (u32, usize),
        kernel: (u32, usize),
    },
    /// The area does not fit [`AREA_MAX`].
    TooBig(usize),
}

/// What the CPU and the boot command line decide (inputs of [`Config::features`]).
#[allow(
    clippy::struct_excessive_bools,
    reason = "one flag per CPU feature that owns a component"
)]
#[derive(Clone, Copy, Debug)]
pub struct Cpu {
    /// `XSAVE` usable: `CPUID.1:ECX.XSAVE` and no `noxsave`.
    pub xsave: bool,
    pub avx: bool,
    pub avx512f: bool,
    pub mpx: bool,
    pub apx: bool,
    /// `CR4.PKE` was set (`X86_FEATURE_OSPKE`).
    pub ospke: bool,
}

/// The enabled user extended state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    pub mode: SaveMode,
    /// `fpu_user_cfg.max_features == default_features`: the value of `XCR0`; 0 without `XSAVE`.
    pub features: u64,
    /// `fpu_user_cfg.max_size == default_size`: size of the standard format area (512 without
    /// `XSAVE`).
    pub user_size: usize,
    /// `fpu_kernel_cfg.default_size`: size of a task's save buffer.
    pub kernel_size: usize,
    components: [Component; XFEATURE_MAX],
    /// `mxcsr_feature_mask`.
    pub mxcsr_mask: u32,
    /// `X86_FEATURE_OSPKE`: `PKRU` is switched and saved in signal frames.
    pub ospke: bool,
    /// `CPUID.(0xd,0)` lists AMX tile data, which this kernel does not enable (a named blocker):
    /// Linux enables it in `XCR0` with `XFD`, so `ARCH_GET_XCOMP_SUPP` and a tile-data permission
    /// request differ here, and `arch_prctl` stops loudly for them instead of answering.
    pub amx: bool,
}

/// Value of the maximum frame size when no `XSAVE` state exists (the default of every host
/// test): `init_sigframe_size` for 512 + 112 bytes of FPU state.
const NOXSAVE_MAX_FRAME: u64 =
    (SIGFRAME_IA32_SIZE + 15 + (FXSAVE_SIZE as u64 + FREGS_SIZE) + 63 + 15) & !15;
static MAX_FRAME_SIZE: AtomicU64 = AtomicU64::new(NOXSAVE_MAX_FRAME);
static FPU_USER_SIZE: AtomicU64 = AtomicU64::new(FXSAVE_SIZE as u64);
static FPU_DEFAULT_STATE_SIZE: AtomicU64 = AtomicU64::new(FXSAVE_SIZE as u64 + FREGS_SIZE);

/// Publish the numbers derived from `config` that pure modules read (`get_sigframe_size()`,
/// `fpu_user_cfg.max_size`). Called once at boot.
pub fn install(config: &Config) {
    MAX_FRAME_SIZE.store(config.max_frame_size(), Ordering::Relaxed);
    FPU_USER_SIZE.store(config.user_size as u64, Ordering::Relaxed);
    FPU_DEFAULT_STATE_SIZE.store(config.fpstate_size(), Ordering::Relaxed);
}

/// `get_sigframe_size()`: the worst-case signal frame, `AT_MINSIGSTKSZ`.
#[must_use]
pub fn max_frame_size() -> u64 {
    MAX_FRAME_SIZE.load(Ordering::Relaxed)
}

/// `fpu_user_cfg.max_size`.
#[must_use]
pub fn fpu_user_size() -> u64 {
    FPU_USER_SIZE.load(Ordering::Relaxed)
}

/// `fpu_default_state_size` (`init_sigframe_size`): the FPU part of the worst-case frame.
#[must_use]
pub fn fpu_default_state_size() -> u64 {
    FPU_DEFAULT_STATE_SIZE.load(Ordering::Relaxed)
}

impl Config {
    /// The `FXSAVE`-only configuration (`noxsave`).
    #[must_use]
    pub const fn fxsave(mxcsr_mask: u32) -> Self {
        Self {
            mode: SaveMode::Fxsave,
            features: 0,
            user_size: FXSAVE_SIZE,
            kernel_size: FXSAVE_SIZE,
            components: [Component {
                offset: 0,
                size: 0,
                aligned64: false,
            }; XFEATURE_MAX],
            mxcsr_mask,
            ospke: false,
            amx: false,
        }
    }

    /// `fpu__init_system_xstate`, first half: the user components this kernel enables in `XCR0`,
    /// from the CPU's support (`leaf0` is `CPUID.(0xd, 0)`).
    ///
    /// # Errors
    /// [`Disabled::NoFpSse`] and [`Disabled::ApxAndMpx`], Linux's `goto out_disable`.
    pub fn features(leaf0: Leaf, cpu: Cpu) -> Result<u64, Disabled> {
        let mut max = u64::from(leaf0[0]) | u64::from(leaf0[3]) << 32;
        if max & MASK_FPSSE != MASK_FPSSE {
            return Err(Disabled::NoFpSse);
        }
        if max & MASK_APX != 0 && max & (MASK_BNDREGS | MASK_BNDCSR) != 0 {
            return Err(Disabled::ApxAndMpx);
        }
        // `xsave_cpuid_features`: a component needs the CPU feature that owns it. AVX-512 is
        // not made to depend on AVX here, as in Linux: `cpuid-deps.c:54` applies only when a
        // feature is force-cleared, not when the CPUID leaves are inconsistent (AVX hidden,
        // AVX-512F listed). Then `XSETBV` gets XCR0[7:5] without XCR0[2:1] and raises #GP: the
        // pinned Linux panics in `fpu__init_system_xstate` (`-cpu host,-avx`, KVM; evidence
        // `init-reference-013/linux-xstate-host_avx.log`) and this kernel stops loudly too.
        for (mask, present) in [
            (MASK_YMM, cpu.avx),
            (MASK_BNDREGS | MASK_BNDCSR, cpu.mpx),
            (MASK_OPMASK | MASK_ZMM_HI256 | MASK_HI16_ZMM, cpu.avx512f),
            (MASK_PKRU, cpu.ospke),
            (MASK_APX, cpu.apx),
        ] {
            if !present {
                max &= !mask;
            }
        }
        // User components only; no supervisor state (the declared configuration has neither
        // `X86_USER_SHADOW_STACK` nor `INTEL_IOMMU_SVM`) and no AMX (not ported).
        Ok(max & USER_SUPPORTED & !UNSUPPORTED)
    }

    /// `fpu__init_system_xstate`, second half: sizes, offsets and the save instruction, once
    /// `XCR0` holds `features` and `IA32_XSS` is 0. `cpuid` answers `(leaf, subleaf)`.
    ///
    /// # Errors
    /// The reasons Linux disables `XSAVE` after enabling it: [`Disabled::BadComponent`],
    /// [`Disabled::SizeMismatch`] (`paranoid_xstate_size_valid`) and [`Disabled::TooBig`].
    #[allow(
        clippy::cast_possible_truncation,
        reason = "component numbers are below XFEATURE_MAX"
    )]
    pub fn build(
        features: u64,
        cpuid: impl Fn(u32, u32) -> Leaf,
        mxcsr_mask: u32,
        ospke: bool,
    ) -> Result<Self, Disabled> {
        let mut components = [Component::default(); XFEATURE_MAX];
        for (nr, slot) in components.iter_mut().enumerate().skip(2) {
            if features >> nr & 1 == 0 {
                continue;
            }
            let leaf = cpuid(0xd, nr as u32);
            // ECX bit 0: supervisor state (offset invalid); bit 1: 64-byte aligned.
            if leaf[2] & 1 != 0 || leaf[0] == 0 {
                return Err(Disabled::BadComponent(nr));
            }
            *slot = Component {
                offset: leaf[1],
                size: leaf[0],
                aligned64: leaf[2] & 2 != 0,
            };
        }
        let sub1 = cpuid(0xd, 1);
        let mode = if sub1[0] & 8 != 0 {
            SaveMode::Xsaves
        } else if sub1[0] & 2 != 0 {
            SaveMode::Xsavec
        } else if sub1[0] & 1 != 0 {
            SaveMode::Xsaveopt
        } else {
            SaveMode::Xsave
        };
        let mut config = Self {
            mode,
            features,
            user_size: 0,
            kernel_size: 0,
            components,
            mxcsr_mask,
            ospke,
            amx: cpuid(0xd, 0)[0] & 1 << 18 != 0,
        };
        config.user_size = config.calculate_size(features, false);
        config.kernel_size = config.calculate_size(features, config.compacted());
        // `paranoid_xstate_size_valid`: the CPU's own sizes (`CPUID.(0xd,0).EBX` for the user
        // format, `CPUID.(0xd,1).EBX` for the compacted one) must agree.
        let (hw_user, hw_kernel) = (cpuid(0xd, 0)[1], sub1[1]);
        if hw_user as usize != config.user_size
            || (config.compacted() && hw_kernel as usize != config.kernel_size)
        {
            return Err(Disabled::SizeMismatch {
                user: (hw_user, config.user_size),
                kernel: (hw_kernel, config.kernel_size),
            });
        }
        if config.user_size > AREA_MAX || config.kernel_size > AREA_MAX {
            return Err(Disabled::TooBig(config.user_size.max(config.kernel_size)));
        }
        Ok(config)
    }

    /// `X86_FEATURE_XCOMPACTED`: the kernel buffers use the compacted format.
    #[must_use]
    pub const fn compacted(&self) -> bool {
        matches!(self.mode, SaveMode::Xsavec | SaveMode::Xsaves)
    }

    /// `use_xsave()`.
    #[must_use]
    pub const fn use_xsave(&self) -> bool {
        !matches!(self.mode, SaveMode::Fxsave)
    }

    /// Placement of component `nr` (2 and above) in the standard format.
    #[must_use]
    pub fn component(&self, nr: usize) -> Component {
        self.components.get(nr).copied().unwrap_or_default()
    }

    /// `xfeature_get_offset` in the compacted format whose `xcomp_bv` is `xcomp_bv`.
    #[must_use]
    pub fn compacted_offset(&self, xcomp_bv: u64, nr: usize) -> usize {
        let mut offset = XREGS_SIZE;
        for (i, c) in self.components.iter().enumerate().skip(2) {
            if xcomp_bv >> i & 1 == 0 {
                continue;
            }
            if c.aligned64 {
                offset = offset.next_multiple_of(XSAVE_ALIGNMENT);
            }
            if i == nr {
                break;
            }
            offset += c.size as usize;
        }
        offset
    }

    /// `xstate_calculate_size`.
    #[must_use]
    pub fn calculate_size(&self, features: u64, compacted: bool) -> usize {
        let Some(topmost) = (63usize).checked_sub(features.leading_zeros() as usize) else {
            return XREGS_SIZE;
        };
        if topmost <= 1 {
            return XREGS_SIZE;
        }
        if compacted {
            return self.compacted_offset(features, topmost)
                + self.components[topmost].size as usize;
        }
        // Standard format: the component with the highest offset ends the area (offsets need
        // not follow the component number).
        (2..XFEATURE_MAX)
            .filter(|&nr| features >> nr & 1 == 1)
            .map(|nr| (self.components[nr].offset + self.components[nr].size) as usize)
            .max()
            .unwrap_or(XREGS_SIZE)
    }

    /// Standard-format `(offset, size)` of every enabled extended component in `mask`, in
    /// component order.
    pub fn ranges(&self, mask: u64) -> impl Iterator<Item = (usize, usize)> + '_ {
        (2..XFEATURE_MAX)
            .filter(move |&nr| (mask & self.features) >> nr & 1 == 1)
            .map(|nr| {
                (
                    self.components[nr].offset as usize,
                    self.components[nr].size as usize,
                )
            })
    }

    /// `xstate_sigframe_size`: the area plus the trailing magic word.
    #[must_use]
    pub const fn sigframe_size(&self) -> usize {
        self.user_size
            + if self.use_xsave() {
                FP_XSTATE_MAGIC2_SIZE
            } else {
                0
            }
    }

    /// `fpu__get_fpstate_size`: the frame's FPU part for the worst case (`IA32_EMULATION=y`).
    #[must_use]
    pub const fn fpstate_size(&self) -> u64 {
        self.sigframe_size() as u64 + FREGS_SIZE
    }

    /// `init_sigframe_size`: `get_sigframe_size()`, `AT_MINSIGSTKSZ`.
    #[must_use]
    pub const fn max_frame_size(&self) -> u64 {
        (SIGFRAME_IA32_SIZE + 15 + self.fpstate_size() + 63 + 15) & !15
    }

    /// Standard-format offset of the `PKRU` component, if it is enabled.
    #[must_use]
    pub fn pkru_offset(&self) -> Option<usize> {
        (self.features & MASK_PKRU != 0).then(|| self.components[XFEATURE_PKRU].offset as usize)
    }

    /// The header `xcomp_bv` of a kernel save buffer (`xstate_init_xcomp_bv`): 0 in the
    /// standard format, `COMPACTED | features` in the compacted one.
    #[must_use]
    pub const fn kernel_xcomp_bv(&self) -> u64 {
        if self.compacted() {
            XCOMP_BV_COMPACTED_FORMAT | self.features
        } else {
            0
        }
    }

    /// The components the kernel saves for a task: all enabled (`PKRU` included, though it is
    /// restored eagerly, `x86_pkru_load`).
    #[must_use]
    pub const fn save_mask(&self) -> u64 {
        self.features
    }

    /// The components restored when a task gets the CPU (`XFEATURE_MASK_FPSTATE`): everything but
    /// `PKRU`.
    #[must_use]
    pub const fn restore_mask(&self) -> u64 {
        self.features & USER_RESTORE
    }

    /// `ARCH_GET_XCOMP_SUPP`: `fpu_user_cfg.max_features | legacy_features` (FXSR sets
    /// `legacy_features` to x87 and SSE).
    #[must_use]
    pub const fn xcomp_supported(&self) -> u64 {
        self.features | MASK_FPSSE
    }

    /// `ARCH_GET_XCOMP_PERM`/`ARCH_GET_XCOMP_GUEST_PERM`: the permitted components
    /// (`fpu_kernel_cfg.default_features & XFEATURE_MASK_USER_SUPPORTED`); no permission is ever
    /// added because no dynamic component is enabled.
    #[must_use]
    pub const fn xcomp_permitted(&self) -> u64 {
        self.features & USER_SUPPORTED
    }

    /// `ARCH_REQ_XCOMP_PERM`/`ARCH_REQ_XCOMP_GUEST_PERM` (`xstate_request_perm`): the only
    /// facility with a permission request is AMX tile data (component 18), which this
    /// configuration never has; any other index below `XFEATURE_MAX` is `-EOPNOTSUPP`, above it
    /// `-EINVAL`. The request never succeeds here, so the answer is the error itself (the
    /// success of `xstate_request_perm`, 0 when the permission is already held, exists only with
    /// a dynamic component; it becomes a `Result` the day AMX does).
    #[must_use]
    pub fn xcomp_request(&self, idx: u64) -> XcompError {
        if idx >= XFEATURE_MAX as u64 {
            return XcompError::Invalid;
        }
        // `xstate_prctl_req[idx]` is 0 for everything but XFEATURE_XTILE_DATA, and the CPU
        // (`fpu_user_cfg.max_features`) lacks that one too.
        XcompError::NotSupported
    }
}

/// The errors of `xstate_request_perm` this configuration can reach.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XcompError {
    /// `-EINVAL`: the index is not an xfeature number.
    Invalid,
    /// `-EOPNOTSUPP`: no such facility, or the CPU lacks it.
    NotSupported,
}

/// The configuration of the AMD Zen 5 workstation (Linux's `0x2e7`, 2440 bytes, `XSAVES`), for
/// the tests of every module that builds frames or answers `arch_prctl`.
#[cfg(test)]
#[must_use]
pub(crate) fn zen5() -> Config {
    tests::build_zen5()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[allow(
        clippy::cast_possible_truncation,
        reason = "component masks below bit 32 in these leaves"
    )]
    const fn low(mask: u64) -> u32 {
        mask as u32
    }

    /// `CPUID.(0xd, n)` of the AMD Zen 5 workstation (`cpuid -r`-style dump taken on it while it
    /// ran Linux 7.2; EBX of sub-leaf 1 there counts the CET supervisor state the host enables,
    /// the value here is for `IA32_XSS` = 0).
    fn zen5(leaf: u32, sub: u32) -> Leaf {
        match (leaf, sub) {
            (0xd, 0) => [0x2e7, 0x988, 0x988, 0],
            (0xd, 1) => [0xf, 0x988, 0x1800, 0],
            (0xd, 2) => [0x100, 0x240, 0, 0],
            (0xd, 5) => [0x40, 0x340, 0, 0],
            (0xd, 6) => [0x200, 0x380, 0, 0],
            (0xd, 7) => [0x400, 0x580, 0, 0],
            (0xd, 9) => [0x8, 0x980, 0, 0],
            _ => [0; 4],
        }
    }

    pub(super) fn build_zen5() -> Config {
        Config::build(0x2e7, zen5, 0xffff, true).unwrap()
    }

    const ALL: Cpu = Cpu {
        xsave: true,
        avx: true,
        avx512f: true,
        mpx: false,
        apx: false,
        ospke: true,
    };

    #[test]
    fn zen5_enables_what_linux_enabled() {
        let features = Config::features(zen5(0xd, 0), ALL).unwrap();
        assert_eq!(features, 0x2e7);
        let config = Config::build(features, zen5, 0xffff, true).unwrap();
        assert_eq!(config.mode, SaveMode::Xsaves);
        assert!(config.compacted());
        // The sizes of the AT_MINSIGSTKSZ the pinned Linux printed on this CPU (0xd30).
        assert_eq!(config.user_size, 2440);
        assert_eq!(config.kernel_size, 2440);
        assert_eq!(config.sigframe_size(), 2444);
        assert_eq!(config.max_frame_size(), 0xd30);
        assert_eq!(config.pkru_offset(), Some(0x980));
        assert_eq!(config.xcomp_supported(), 0x2e7);
        assert_eq!(config.xcomp_permitted(), 0x2e7);
        assert_eq!(config.restore_mask(), 0x2e7 & !MASK_PKRU);
        // The standard format places the components exactly where CPUID said.
        assert_eq!(
            config.ranges(config.features).collect::<Vec<_>>(),
            [(576, 256), (832, 64), (896, 512), (1408, 1024), (2432, 8)]
        );
    }

    #[test]
    fn compacted_offsets_follow_the_header() {
        let config = Config::build(0x2e7, zen5, 0xffff, true).unwrap();
        // No component is 64-byte aligned on this CPU: the compacted format is dense.
        let xcomp = 0x2e7;
        assert_eq!(config.compacted_offset(xcomp, 2), 576);
        assert_eq!(config.compacted_offset(xcomp, 5), 576 + 256);
        assert_eq!(config.compacted_offset(xcomp, 6), 576 + 256 + 64);
        assert_eq!(config.compacted_offset(xcomp, 7), 576 + 256 + 64 + 512);
        assert_eq!(
            config.compacted_offset(xcomp, 9),
            576 + 256 + 64 + 512 + 1024
        );
        assert_eq!(config.calculate_size(0x2e7, true), 2440);
        assert_eq!(config.calculate_size(MASK_FPSSE, false), XREGS_SIZE);
        assert_eq!(
            config.calculate_size(MASK_FPSSE | MASK_YMM, false),
            576 + 256
        );
    }

    #[test]
    fn missing_cpu_features_clear_their_components() {
        let leaf0 = [0x2e7 | low(MASK_BNDREGS), 0, 0, 0];
        let none = Cpu {
            xsave: true,
            avx: false,
            avx512f: false,
            mpx: false,
            apx: false,
            ospke: false,
        };
        assert_eq!(Config::features(leaf0, none), Ok(MASK_FPSSE));
        let avx = Cpu { avx: true, ..none };
        assert_eq!(Config::features(leaf0, avx), Ok(MASK_FPSSE | MASK_YMM));
        // AMX is enumerated but never enabled; PKRU needs OSPKE.
        let amx = [0x2e7 | low(MASK_XTILE_CFG | MASK_XTILE_DATA), 0, 0, 0];
        assert_eq!(Config::features(amx, ALL), Ok(0x2e7));
        let no_pku = Cpu {
            ospke: false,
            ..ALL
        };
        assert_eq!(Config::features(zen5(0xd, 0), no_pku), Ok(0xe7));
    }

    #[test]
    fn amx_in_the_enumeration_is_recorded_but_not_enabled() {
        assert!(!build_zen5().amx);
        let with_amx = |leaf, sub| {
            let mut l = zen5(leaf, sub);
            if (leaf, sub) == (0xd, 0) {
                l[0] |= low(MASK_XTILE_CFG | MASK_XTILE_DATA);
            }
            l
        };
        let features = Config::features(with_amx(0xd, 0), ALL).unwrap();
        assert_eq!(features, 0x2e7, "tile state is never enabled");
        let config = Config::build(features, with_amx, 0xffff, true).unwrap();
        assert!(config.amx);
        assert_eq!((config.user_size, config.xcomp_supported()), (2440, 0x2e7));
    }

    #[test]
    fn enumeration_linux_rejects_is_rejected() {
        assert_eq!(Config::features([1, 0, 0, 0], ALL), Err(Disabled::NoFpSse));
        let both = [low(MASK_FPSSE | MASK_APX | MASK_BNDREGS), 0, 0, 0];
        assert_eq!(Config::features(both, ALL), Err(Disabled::ApxAndMpx));
        // A size the CPU does not confirm.
        let lying = |leaf, sub| {
            let mut l = zen5(leaf, sub);
            if (leaf, sub) == (0xd, 0) {
                l[1] += 64;
            }
            l
        };
        assert!(matches!(
            Config::build(0x2e7, lying, 0xffff, true),
            Err(Disabled::SizeMismatch { .. })
        ));
        // A supervisor component is not a user component.
        let supervisor = |leaf, sub| {
            let mut l = zen5(leaf, sub);
            if (leaf, sub) == (0xd, 9) {
                l[2] = 1;
            }
            l
        };
        assert_eq!(
            Config::build(0x2e7, supervisor, 0xffff, true),
            Err(Disabled::BadComponent(9))
        );
    }

    #[test]
    fn xsaveopt_and_plain_xsave_keep_the_standard_format() {
        let opt = |leaf, sub| {
            let mut l = zen5(leaf, sub);
            if (leaf, sub) == (0xd, 1) {
                l[0] = 1;
            }
            l
        };
        let config = Config::build(0x2e7, opt, 0xffff, true).unwrap();
        assert_eq!(config.mode, SaveMode::Xsaveopt);
        assert!(!config.compacted());
        assert_eq!(config.kernel_xcomp_bv(), 0);
        let plain = |leaf, sub| {
            let mut l = zen5(leaf, sub);
            if (leaf, sub) == (0xd, 1) {
                l[0] = 0;
            }
            l
        };
        assert_eq!(
            Config::build(0x2e7, plain, 0xffff, true).unwrap().mode,
            SaveMode::Xsave
        );
        let compacted = Config::build(0x2e7, zen5, 0xffff, true).unwrap();
        assert_eq!(compacted.kernel_xcomp_bv(), 1 << 63 | 0x2e7);
    }

    #[test]
    fn the_fxsave_configuration_is_the_one_before_xsave_existed() {
        let config = Config::fxsave(0xffbf);
        assert!(!config.use_xsave());
        assert_eq!(
            (config.features, config.user_size, config.kernel_size),
            (0, 512, 512)
        );
        assert_eq!(config.sigframe_size(), 512);
        assert_eq!(config.max_frame_size(), 0x5a0);
        assert_eq!(config.xcomp_supported(), 3);
        assert_eq!(config.xcomp_permitted(), 0);
        assert_eq!(max_frame_size(), 0x5a0, "the default before `install`");
        assert_eq!(fpu_user_size(), 512);
    }

    #[test]
    fn xcomp_requests_match_xstate_request_perm() {
        let config = Config::build(0x2e7, zen5, 0xffff, true).unwrap();
        for idx in [0, 2, 9, 17, 18, 19] {
            assert_eq!(config.xcomp_request(idx), XcompError::NotSupported, "{idx}");
        }
        for idx in [20, 63, 64, u64::MAX] {
            assert_eq!(config.xcomp_request(idx), XcompError::Invalid, "{idx}");
        }
    }
}
