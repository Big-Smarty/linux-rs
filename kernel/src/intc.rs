// SPDX-License-Identifier: GPL-2.0-only
//! Pure interrupt-controller model for x86: the local APIC mode decision, LVT /
//! SPIV / IOAPIC redirection-entry encodings and the vector assignment. The
//! privileged register access is in the freestanding binary (`apic.rs`); this
//! module is host-tested.
//!
//! Provenance (Linux 6.18.57, GPL-2.0-only; a Rust re-expression):
//! - The x2APIC decision mirrors `check_x2apic`, `setup_nox2apic`,
//!   `x2apic_disable`/`x2apic_enable`/`try_to_enable_x2apic`
//!   (arch/x86/kernel/apic/apic.c:1696-1875) for a machine WITHOUT interrupt
//!   remapping, which this kernel does not have.
//! - Vectors: `arch/x86/include/asm/irq_vectors.h:44` (`ISA_IRQ_VECTOR`), :54
//!   (`SPURIOUS_APIC_VECTOR`), :62 (`ERROR_APIC_VECTOR`), :98
//!   (`LOCAL_TIMER_VECTOR`).
//! - Register layout: arch/x86/include/asm/apicdef.h and the SDM Vol.3 ch.12.

/// ISA IRQ n is delivered at `ISA_IRQ_VECTOR_BASE + n` (8259 remap and IOAPIC).
pub const ISA_IRQ_VECTOR_BASE: u8 = 0x30;
pub const LOCAL_TIMER_VECTOR: u8 = 0xec;
pub const ERROR_VECTOR: u8 = 0xfe;
pub const SPURIOUS_VECTOR: u8 = 0xff;

// IA32_APIC_BASE bits (arch/x86/include/asm/msr-index.h).
pub const BASE_BSP: u64 = 1 << 8;
pub const BASE_EXTD: u64 = 1 << 10;
pub const BASE_EN: u64 = 1 << 11;
pub const BASE_ADDRESS: u64 = 0x000f_ffff_ffff_f000;

/// A local APIC register: an architectural 16-byte aligned offset inside the
/// 4 KiB register page, usable both as an xAPIC MMIO offset and (shifted) as an
/// x2APIC MSR. The field is private: only the constants below and [`LapicReg::isr`]
/// exist, so safe code cannot name an out-of-page offset or an arbitrary MSR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LapicReg(u32);

impl LapicReg {
    /// xAPIC MMIO offset from the page base.
    #[must_use]
    pub const fn offset(self) -> u32 {
        self.0
    }
    /// x2APIC MSR (`APIC_BASE_MSR + (reg >> 4)`), always in `0x800..0x840`.
    #[must_use]
    pub const fn x2apic_msr(self) -> u32 {
        0x800 + (self.0 >> 4)
    }
    /// In-service register `index` (0..8, 32 vectors each); `None` otherwise.
    #[must_use]
    pub const fn isr(index: u32) -> Option<Self> {
        if index < 8 {
            Some(Self(0x100 + 0x10 * index))
        } else {
            None
        }
    }
}

// xAPIC register offsets (apicdef.h).
pub const REG_ID: LapicReg = LapicReg(0x20);
pub const REG_VERSION: LapicReg = LapicReg(0x30);
pub const REG_TPR: LapicReg = LapicReg(0x80);
pub const REG_EOI: LapicReg = LapicReg(0xb0);
pub const REG_SPIV: LapicReg = LapicReg(0xf0);
pub const REG_ESR: LapicReg = LapicReg(0x280);
pub const REG_LVT_CMCI: LapicReg = LapicReg(0x2f0);
pub const REG_LVT_TIMER: LapicReg = LapicReg(0x320);
pub const REG_LVT_THERMAL: LapicReg = LapicReg(0x330);
pub const REG_LVT_PERF: LapicReg = LapicReg(0x340);
pub const REG_LVT_LINT0: LapicReg = LapicReg(0x350);
pub const REG_LVT_LINT1: LapicReg = LapicReg(0x360);
pub const REG_LVT_ERROR: LapicReg = LapicReg(0x370);
pub const REG_TIMER_INITIAL: LapicReg = LapicReg(0x380);
pub const REG_TIMER_CURRENT: LapicReg = LapicReg(0x390);
pub const REG_TIMER_DIVIDE: LapicReg = LapicReg(0x3e0);

/// Whether `address` is addressable with `width_bits` physical address bits
/// (CPUID 0x80000008 EAX[7:0]); a page-table entry above it has reserved bits
/// set and faults on first use.
#[must_use]
pub const fn physical_address_valid(address: u64, width_bits: u32) -> bool {
    width_bits >= 64 || address >> width_bits == 0
}
pub const MSR_TSC_DEADLINE: u32 = 0x6e0;

pub const LVT_MASKED: u32 = 1 << 16;
pub const LVT_DM_FIXED: u32 = 0;
pub const LVT_DM_NMI: u32 = 4 << 8;
pub const LVT_DM_EXTINT: u32 = 7 << 8;
pub const LVT_TIMER_PERIODIC: u32 = 1 << 17;
pub const LVT_TIMER_TSC_DEADLINE: u32 = 2 << 17;
pub const SPIV_ENABLE: u32 = 1 << 8;
/// `APIC_TDR_DIV_16`.
pub const TIMER_DIVIDE_BY_16: u32 = 0x3;

/// Local APIC timer mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimerMode {
    OneShot,
    Periodic,
    TscDeadline,
}

/// LVT timer register value at [`LOCAL_TIMER_VECTOR`].
#[must_use]
pub const fn lvt_timer(mode: TimerMode, masked: bool) -> u32 {
    let mode_bits = match mode {
        TimerMode::OneShot => 0,
        TimerMode::Periodic => LVT_TIMER_PERIODIC,
        TimerMode::TscDeadline => LVT_TIMER_TSC_DEADLINE,
    };
    LOCAL_TIMER_VECTOR as u32 | mode_bits | if masked { LVT_MASKED } else { 0 }
}

/// Number of LVT entries minus one, from the version register (`GET_APIC_MAXLVT`).
#[must_use]
pub const fn max_lvt(version: u32) -> u32 {
    (version >> 16) & 0xff
}

/// Delivery status / polarity / trigger of one IOAPIC redirection entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Redirection {
    pub vector: u8,
    pub active_low: bool,
    pub level: bool,
    pub masked: bool,
    /// Physical-mode destination APIC id (8 bits without interrupt remapping).
    pub destination: u8,
}
impl Redirection {
    /// The all-masked reset form Linux writes for unused pins (`clear_IO_APIC_pin`).
    pub const MASKED: Self = Self {
        vector: 0,
        active_low: false,
        level: false,
        masked: true,
        destination: 0,
    };
    /// Low dword: fixed delivery, physical destination mode.
    #[must_use]
    pub const fn low(&self) -> u32 {
        self.vector as u32
            | if self.active_low { 1 << 13 } else { 0 }
            | if self.level { 1 << 15 } else { 0 }
            | if self.masked { 1 << 16 } else { 0 }
    }
    /// High dword: destination in bits 24..32.
    #[must_use]
    pub const fn high(&self) -> u32 {
        (self.destination as u32) << 24
    }
}
/// IOAPIC indirect register index of redirection entry `pin` (low dword).
#[must_use]
pub const fn ioapic_redirection_register(pin: u32) -> u32 {
    0x10 + 2 * pin
}
/// Most redirection entries reachable through the 8-bit IOREGSEL: register
/// `0x10 + 2*pin + 1 <= 0xff` gives pin <= 119. Larger values of the (8-bit)
/// maximum-entry field would alias the ID/version registers.
pub const IOAPIC_MAX_PINS: u32 = 120;
/// Pin count from the IOAPIC version register (bits 16..24 are max entry),
/// clamped to what the register window can address.
#[must_use]
pub const fn ioapic_pins(version: u32) -> u32 {
    let pins = ((version >> 16) & 0xff) + 1;
    if pins > IOAPIC_MAX_PINS {
        IOAPIC_MAX_PINS
    } else {
        pins
    }
}

/// Everything the local APIC mode decision depends on.
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent CPUID/MSR/boot-option facts, each a Linux input"
)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ApicInputs {
    /// CPUID.1:EDX.APIC / CPUID.1:ECX.x2APIC.
    pub cpu_has_apic: bool,
    pub cpu_has_x2apic: bool,
    /// Current `IA32_APIC_BASE` value.
    pub base_msr: u64,
    /// `x2apic_hw_locked()`: `IA32_XAPIC_DISABLE_STATUS` reports legacy mode off.
    pub hw_locked: bool,
    /// BSP APIC ID (CPUID 0xB, else leaf 1).
    pub bsp_id: u32,
    /// Boot options `nolapic` / `nox2apic`.
    pub nolapic: bool,
    pub nox2apic: bool,
    /// `x86_init.hyper.x2apic_available()`: a recognised hypervisor (KVM).
    pub hypervisor_x2apic: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApicMode {
    /// No local APIC use: legacy 8259/PIT path.
    Disabled,
    Xapic,
    X2apic,
}

/// Mode plus the exact `IA32_APIC_BASE` writes, in order, that realise it from
/// the current value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApicPlan {
    pub mode: ApicMode,
    pub writes: [Option<u64>; 2],
    /// Why the mode was chosen (printed in the boot record).
    pub reason: &'static str,
}

fn plan(mode: ApicMode, writes: [Option<u64>; 2], reason: &'static str) -> ApicPlan {
    ApicPlan {
        mode,
        writes,
        reason,
    }
}

/// `__x2apic_disable`: clear EXTD+EN then restore EN (xAPIC), per SDM 12.12.5.
fn x2apic_off(base: u64) -> [Option<u64>; 2] {
    [Some(base & !(BASE_EXTD | BASE_EN)), Some(base & !BASE_EXTD)]
}

/// Decide the local APIC mode for the single boot CPU.
///
/// Linux without interrupt remapping (`enable_IR_x2apic` -> `try_to_enable_x2apic`):
/// - firmware-enabled x2APIC is noted (`check_x2apic`: state ON, or LOCKED);
/// - `nox2apic` or "no hypervisor x2apic" then tries `x2apic_disable()`, which
///   switches back to xAPIC unless the APIC ID is >= 255 (Linux PANICS there;
///   we stay in x2APIC instead, a documented difference) or the mode is hardware
///   locked (stays x2APIC);
/// - a recognised hypervisor (KVM) with x2APIC support and firmware not enabled
///   gets `x2apic_enable()`.
#[must_use]
pub fn plan_apic_mode(i: &ApicInputs) -> ApicPlan {
    let base = i.base_msr;
    let firmware_x2apic = base & BASE_EXTD != 0;
    if i.nolapic || !i.cpu_has_apic {
        let reason = if i.nolapic { "nolapic" } else { "no-apic" };
        if firmware_x2apic && !i.hw_locked {
            // Clearing EXTD and EN in one write leaves exactly the disabled xAPIC
            // state the legacy PIC path runs with.
            return plan(
                ApicMode::Disabled,
                [Some(base & !(BASE_EXTD | BASE_EN)), None],
                reason,
            );
        }
        if firmware_x2apic {
            // A locked x2APIC cannot be left; the caller must refuse the PIC path.
            return plan(
                ApicMode::X2apic,
                [None, None],
                "locked-x2apic-cannot-disable",
            );
        }
        let writes = if base & BASE_EN != 0 {
            [Some(base & !BASE_EN), None]
        } else {
            [None, None]
        };
        return plan(ApicMode::Disabled, writes, reason);
    }
    if firmware_x2apic {
        let can_leave = i.bsp_id < 255 && !i.hw_locked;
        let want_xapic = i.nox2apic || !i.hypervisor_x2apic;
        if want_xapic && can_leave {
            return plan(
                ApicMode::Xapic,
                x2apic_off(base),
                if i.nox2apic {
                    "nox2apic"
                } else {
                    "no-interrupt-remapping"
                },
            );
        }
        let reason = if i.hw_locked {
            "firmware-locked"
        } else if i.bsp_id >= 255 {
            "apic-id-above-254"
        } else {
            "firmware-hypervisor"
        };
        return plan(ApicMode::X2apic, [None, None], reason);
    }
    let enable_en = if base & BASE_EN == 0 {
        Some(base | BASE_EN)
    } else {
        None
    };
    if i.cpu_has_x2apic && i.hypervisor_x2apic && !i.nox2apic {
        // x2apic_enable(): EN must be set before EXTD.
        return plan(
            ApicMode::X2apic,
            [enable_en, Some(base | BASE_EN | BASE_EXTD)],
            "hypervisor",
        );
    }
    plan(ApicMode::Xapic, [enable_en, None], "default")
}

/// Whether the 8259 pair is assumed present: MADT `PCAT_COMPAT` skips probing
/// (`probe_8259A`); otherwise the mask register must read back the probe value.
#[must_use]
pub fn has_legacy_pic(pcat_compat: bool, probe_readback: impl FnOnce() -> bool) -> bool {
    pcat_compat || probe_readback()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs(base: u64) -> ApicInputs {
        ApicInputs {
            cpu_has_apic: true,
            cpu_has_x2apic: true,
            base_msr: base,
            ..ApicInputs::default()
        }
    }
    const XAPIC: u64 = 0xfee0_0000 | BASE_EN | BASE_BSP;
    const X2: u64 = XAPIC | BASE_EXTD;

    #[test]
    fn bare_metal_firmware_xapic_stays() {
        let p = plan_apic_mode(&inputs(XAPIC));
        assert_eq!((p.mode, p.writes), (ApicMode::Xapic, [None, None]));
    }
    #[test]
    fn bare_metal_firmware_x2apic_returns_to_xapic_like_linux_without_ir() {
        let p = plan_apic_mode(&inputs(X2));
        assert_eq!(p.mode, ApicMode::Xapic);
        assert_eq!(p.writes, [Some(XAPIC & !BASE_EN), Some(XAPIC)]);
        assert_eq!(p.reason, "no-interrupt-remapping");
    }
    #[test]
    fn firmware_x2apic_stays_when_locked_or_id_too_large_or_hypervisor() {
        let mut i = inputs(X2);
        i.hw_locked = true;
        assert_eq!(plan_apic_mode(&i).mode, ApicMode::X2apic);
        assert_eq!(plan_apic_mode(&i).reason, "firmware-locked");
        let mut i = inputs(X2);
        i.bsp_id = 255;
        assert_eq!(plan_apic_mode(&i).reason, "apic-id-above-254");
        let mut i = inputs(X2);
        i.bsp_id = 254;
        assert_eq!(plan_apic_mode(&i).mode, ApicMode::Xapic);
        let mut i = inputs(X2);
        i.hypervisor_x2apic = true;
        let p = plan_apic_mode(&i);
        assert_eq!((p.mode, p.writes), (ApicMode::X2apic, [None, None]));
        // nox2apic beats the hypervisor and disables firmware x2APIC.
        i.nox2apic = true;
        assert_eq!(plan_apic_mode(&i).mode, ApicMode::Xapic);
    }
    #[test]
    fn hypervisor_enables_x2apic_in_the_architectural_order() {
        let mut i = inputs(XAPIC);
        i.hypervisor_x2apic = true;
        let p = plan_apic_mode(&i);
        assert_eq!(p.mode, ApicMode::X2apic);
        assert_eq!(p.writes, [None, Some(XAPIC | BASE_EXTD)]);
        // Firmware left the APIC fully disabled: EN first, then EXTD.
        let mut i = inputs(0xfee0_0000);
        i.hypervisor_x2apic = true;
        assert_eq!(
            plan_apic_mode(&i).writes,
            [
                Some(0xfee0_0000 | BASE_EN),
                Some(0xfee0_0000 | BASE_EN | BASE_EXTD)
            ]
        );
        i.nox2apic = true;
        assert_eq!(plan_apic_mode(&i).mode, ApicMode::Xapic);
        // No CPUID x2APIC: never.
        let mut i = inputs(XAPIC);
        i.cpu_has_x2apic = false;
        i.hypervisor_x2apic = true;
        assert_eq!(plan_apic_mode(&i).mode, ApicMode::Xapic);
    }
    #[test]
    fn nolapic_and_missing_apic_use_the_pic_path() {
        let mut i = inputs(XAPIC);
        i.nolapic = true;
        let p = plan_apic_mode(&i);
        assert_eq!(
            (p.mode, p.writes),
            (ApicMode::Disabled, [Some(XAPIC & !BASE_EN), None])
        );
        // Already off: nothing to write.
        let mut i = inputs(0xfee0_0000);
        i.nolapic = true;
        assert_eq!(plan_apic_mode(&i).writes, [None, None]);
        // From x2APIC: leave x2 mode first, then drop EN.
        let mut i = inputs(X2);
        i.nolapic = true;
        let p = plan_apic_mode(&i);
        assert_eq!(p.mode, ApicMode::Disabled);
        assert_eq!(p.writes, [Some(XAPIC & !BASE_EN), None]);
        i.hw_locked = true;
        assert_eq!(plan_apic_mode(&i).mode, ApicMode::X2apic);
        let mut i = inputs(XAPIC);
        i.cpu_has_apic = false;
        assert_eq!(plan_apic_mode(&i).mode, ApicMode::Disabled);
    }

    #[test]
    fn encodings() {
        assert_eq!(REG_EOI.x2apic_msr(), 0x80b);
        assert_eq!(REG_LVT_TIMER.x2apic_msr(), 0x832);
        assert_eq!(REG_TIMER_DIVIDE.x2apic_msr(), 0x83e);
        assert_eq!(REG_SPIV.x2apic_msr(), 0x80f);
        assert_eq!(LapicReg::isr(7).unwrap().offset(), 0x170);
        assert_eq!(LapicReg::isr(8), None);
        // Every nameable register is 16-byte aligned, in the page, in the MSR window.
        for r in [
            REG_ID,
            REG_VERSION,
            REG_TPR,
            REG_EOI,
            REG_SPIV,
            REG_ESR,
            REG_LVT_CMCI,
            REG_LVT_TIMER,
            REG_LVT_THERMAL,
            REG_LVT_PERF,
            REG_LVT_LINT0,
            REG_LVT_LINT1,
            REG_LVT_ERROR,
            REG_TIMER_INITIAL,
            REG_TIMER_CURRENT,
            REG_TIMER_DIVIDE,
        ] {
            assert!(r.offset() % 16 == 0 && r.offset() < 0x400);
            assert!((0x800..0x840).contains(&r.x2apic_msr()));
        }
        assert_eq!(lvt_timer(TimerMode::OneShot, false), 0xec);
        assert_eq!(lvt_timer(TimerMode::TscDeadline, false), 0x4_00ec);
        assert_eq!(lvt_timer(TimerMode::Periodic, true), 0x3_00ec);
        assert_eq!(max_lvt(0x0005_0014), 5);
        let rte = Redirection {
            vector: 0x30,
            active_low: false,
            level: false,
            masked: false,
            destination: 3,
        };
        assert_eq!((rte.low(), rte.high()), (0x30, 0x0300_0000));
        let level_low = Redirection {
            active_low: true,
            level: true,
            masked: true,
            ..rte
        };
        assert_eq!(level_low.low(), 0x30 | 1 << 13 | 1 << 15 | 1 << 16);
        assert_eq!(Redirection::MASKED.low(), 1 << 16);
        assert_eq!(ioapic_redirection_register(2), 0x14);
        assert_eq!(ioapic_pins(0x0017_0020), 24);
        // A bogus max-entry byte must not reach registers that alias ID/version.
        assert_eq!(ioapic_pins(0x00ff_0020), IOAPIC_MAX_PINS);
        assert_eq!(ioapic_pins(0x0077_0020), 120);
        assert_eq!(ioapic_pins(0x0078_0020), IOAPIC_MAX_PINS);
        assert!(ioapic_redirection_register(IOAPIC_MAX_PINS - 1) < 0xff);
        assert!(physical_address_valid(0xfee0_0000, 36));
        assert!(!physical_address_valid(1 << 40, 36));
        assert!(physical_address_valid(u64::MAX, 64));
        assert!(physical_address_valid((1 << 40) - 1, 40));
        assert!(has_legacy_pic(true, || unreachable!(
            "PCAT_COMPAT skips the probe"
        )));
        assert!(has_legacy_pic(false, || true));
        assert!(!has_legacy_pic(false, || false));
    }
}
