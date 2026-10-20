// SPDX-License-Identifier: GPL-2.0-only
//! Interrupt-controller hardware: local APIC (xAPIC MMIO or x2APIC MSRs), IOAPIC
//! and the dual 8259. Decisions and encodings are in `kernel::intc` (host
//! tested); this file only touches registers.
//!
//! Provenance (Linux 6.18.57, GPL-2.0-only; Rust re-expression):
//! - `init_lapic`: `setup_local_APIC` + `end_local_APIC_setup`/`lapic_setup_esr`
//!   (arch/x86/kernel/apic/apic.c:1499-1657) and `clear_local_APIC` masking.
//! - `ioapic_init`: `clear_IO_APIC` (all pins masked, `arch/x86/kernel/apic/io_apic.c`).
//! - 8259: `init_8259A`, `probe_8259A`, `spurious_8259A_irq`
//!   (arch/x86/kernel/i8259.c), vector base `ISA_IRQ_VECTOR(0)` = 0x30.
//!
//! Differences recorded in docs/implementation.md ("Interrupt controllers and
//! timekeeping"): no APIC-driver ops table (flat physical destination only), no
//! interrupt remapping, no ExtINT-through-LINT0 timer fallback chain of
//! `check_timer`, BSP only.

use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use kernel::{
    boot::TestMode,
    firmware::{IsaRoute, MAX_IOAPICS, Madt, Polarity, Trigger},
    intc::{
        self, ApicInputs, ApicMode, ApicPlan, ERROR_VECTOR, ISA_IRQ_VECTOR_BASE, Redirection,
        SPURIOUS_VECTOR,
    },
};
use raw_cpuid::{CpuId, Hypervisor, native_cpuid::cpuid_count};
use x86_64::registers::model_specific::Msr;

use crate::{cpu, mmio};

const MSR_APIC_BASE: u32 = 0x1b;
const MSR_ARCH_CAPABILITIES: u32 = 0x10a;
const MSR_XAPIC_DISABLE_STATUS: u32 = 0xbd;
const ARCH_CAP_XAPIC_DISABLE: u64 = 1 << 21;

#[derive(Debug)]
pub enum Error {
    /// The mode transition did not take effect in `IA32_APIC_BASE`.
    Mode,
    /// xAPIC mode without a mapped register page.
    Mapping,
    /// The local APIC identification/version registers read as nonsense.
    Registers,
}

static MODE: AtomicU8 = AtomicU8::new(0);
static LAPIC_VA: AtomicU64 = AtomicU64::new(0);

/// Current local APIC mode (Disabled until [`init_lapic`] succeeds).
#[must_use]
pub fn mode() -> ApicMode {
    match MODE.load(Ordering::Acquire) {
        1 => ApicMode::Xapic,
        2 => ApicMode::X2apic,
        _ => ApicMode::Disabled,
    }
}

fn rdmsr(msr: u32) -> u64 {
    // SAFETY: callers name MSRs whose presence the same function checked via
    // CPUID (APIC_BASE: CPUID.1:EDX.APIC; x2APIC registers: after EXTD was read
    // back set; ARCH_CAPABILITIES/XAPIC_DISABLE_STATUS: CPUID.7 and the bit
    // below). CPL0, no memory effects.
    unsafe { Msr::new(msr).read() }
}
fn wrmsr(msr: u32, value: u64) {
    // SAFETY: as `rdmsr`; the values written are built by `kernel::intc` from
    // the current register contents (reserved bits preserved) or are documented
    // register values.
    unsafe { Msr::new(msr).write(value) }
}

/// Register read in the active mode. Reading before [`init_lapic`] returns 0.
#[must_use]
pub fn lapic_read(reg: u32) -> u32 {
    match mode() {
        // SAFETY: MODE=Xapic is published only after LAPIC_VA names a mapped UC
        // page (init_lapic), `reg` is an architectural 16-byte aligned offset.
        ApicMode::Xapic => unsafe {
            mmio::read32(LAPIC_VA.load(Ordering::Relaxed) + u64::from(reg))
        },
        // Registers are 32 bits wide; the MSR's high half is reserved zero.
        ApicMode::X2apic => u32::try_from(rdmsr(intc::x2apic_msr(reg)) & 0xffff_ffff).unwrap_or(0),
        ApicMode::Disabled => 0,
    }
}
pub fn lapic_write(reg: u32, value: u32) {
    match mode() {
        // SAFETY: as `lapic_read`; `value` is a valid register encoding.
        ApicMode::Xapic => unsafe {
            mmio::write32(LAPIC_VA.load(Ordering::Relaxed) + u64::from(reg), value);
        },
        ApicMode::X2apic => wrmsr(intc::x2apic_msr(reg), u64::from(value)),
        ApicMode::Disabled => {}
    }
}
/// Acknowledge the in-service interrupt. Callable from any vector handler: a
/// single register write, no lock.
pub fn eoi() {
    lapic_write(intc::REG_EOI, 0);
}

/// `x2apic_hw_locked()`: the platform disabled legacy xAPIC mode in hardware.
fn x2apic_hw_locked() -> bool {
    // CPUID.(EAX=7,ECX=0):EDX[29] enumerates IA32_ARCH_CAPABILITIES.
    if cpuid_count(0, 0).eax >= 7 && cpuid_count(7, 0).edx & (1 << 29) != 0 {
        let capabilities = rdmsr(MSR_ARCH_CAPABILITIES);
        if capabilities & ARCH_CAP_XAPIC_DISABLE != 0 {
            return rdmsr(MSR_XAPIC_DISABLE_STATUS) & 1 != 0;
        }
    }
    false
}

/// The BSP's APIC ID from CPUID without touching the APIC: x2APIC ID of
/// leaf 0xB when present, else the 8-bit initial ID of leaf 1.
fn cpuid_apic_id() -> u32 {
    if cpuid_count(0, 0).eax >= 0xb {
        let leaf = cpuid_count(0xb, 0);
        if leaf.ebx & 0xffff != 0 {
            return leaf.edx;
        }
    }
    cpuid_count(1, 0).ebx >> 24
}

/// Everything decided before paging is finalized.
pub struct Prepared {
    pub plan: ApicPlan,
    pub inputs: ApicInputs,
    /// xAPIC register page physical address (`IA32_APIC_BASE` authoritative);
    /// 0 unless the plan's mode is xAPIC.
    pub lapic_phys: u64,
    /// MADT's address, only to report a mismatch with the MSR.
    pub madt_lapic: Option<u64>,
    pub hypervisor_kvm: bool,
}

/// Read-only discovery plus the Linux-equivalent mode decision. In QEMU
/// self-test builds `test` may first simulate a firmware x2APIC handoff.
pub fn prepare(madt: Option<&Madt>, nolapic: bool, nox2apic: bool, test: TestMode) -> Prepared {
    let cpuid = CpuId::new();
    let features = cpuid.get_feature_info();
    let cpu_has_apic = features
        .as_ref()
        .is_some_and(raw_cpuid::FeatureInfo::has_apic);
    let cpu_has_x2apic = features
        .as_ref()
        .is_some_and(raw_cpuid::FeatureInfo::has_x2apic);
    #[cfg(feature = "qemu-self-test")]
    if test == TestMode::FirmwareX2apic && cpu_has_apic && cpu_has_x2apic {
        let base = rdmsr(MSR_APIC_BASE);
        let base = base | intc::BASE_EN;
        wrmsr(MSR_APIC_BASE, base);
        wrmsr(MSR_APIC_BASE, base | intc::BASE_EXTD);
    }
    let kvm = features
        .as_ref()
        .is_some_and(raw_cpuid::FeatureInfo::has_hypervisor)
        && cpuid
            .get_hypervisor_info()
            .is_some_and(|h| h.identify() == Hypervisor::KVM);
    let base = if cpu_has_apic {
        rdmsr(MSR_APIC_BASE)
    } else {
        0
    };
    let inputs = ApicInputs {
        cpu_has_apic,
        cpu_has_x2apic,
        base_msr: base,
        hw_locked: cpu_has_apic && cpu_has_x2apic && x2apic_hw_locked(),
        bsp_id: cpuid_apic_id(),
        nolapic,
        nox2apic,
        // Linux: x86_init.hyper.x2apic_available() is kvm_para_available() on KVM.
        // `force-x2apic` stands in for it under TCG, which Linux cannot detect.
        hypervisor_x2apic: kvm
            || (cfg!(feature = "qemu-self-test") && test == TestMode::ForceX2apic),
    };
    let plan = intc::plan_apic_mode(&inputs);
    // The base address field is untouched by every planned transition.
    let lapic_phys = if plan.mode == ApicMode::Xapic {
        base & intc::BASE_ADDRESS
    } else {
        0
    };
    Prepared {
        plan,
        inputs,
        lapic_phys,
        madt_lapic: madt.map(|m| m.lapic_address),
        hypervisor_kvm: kvm,
    }
}

/// What [`init_lapic`] observed, for the boot record.
pub struct LapicInfo {
    pub id: u32,
    pub version: u32,
    pub max_lvt: u32,
    pub extint_enabled: bool,
}

/// Switch the BSP's local APIC into the planned mode and program it like
/// `setup_local_APIC`: soft-disabled while every LVT is masked, TPR 0x10 (no
/// vectors 0-31), stale in-service bits acknowledged, then SPIV = enable|0xff;
/// LINT0 `ExtINT` and LINT1 NMI per Linux; error vector unmasked.
///
/// # Safety
/// BSP at CPL0 with IF clear, after `Tables::activate`. `lapic_va` is the
/// direct-map address of the mapped UC xAPIC page at `prep.lapic_phys` (required
/// iff the plan is xAPIC). `prep` was built on this CPU. No other agent touches
/// the APIC. `ioapic_routes_irqs`: an IOAPIC will carry interrupts, so a
/// firmware-masked LINT0 stays masked (Linux `!value` rule).
pub unsafe fn init_lapic(
    prep: &Prepared,
    lapic_va: Option<u64>,
    ioapic_routes_irqs: bool,
) -> Result<Option<LapicInfo>, Error> {
    for write in prep.plan.writes.into_iter().flatten() {
        wrmsr(MSR_APIC_BASE, write);
    }
    if prep.plan.mode == ApicMode::Disabled {
        return Ok(None);
    }
    let base = rdmsr(MSR_APIC_BASE);
    let wants_x2 = prep.plan.mode == ApicMode::X2apic;
    if base & intc::BASE_EN == 0 || (base & intc::BASE_EXTD != 0) != wants_x2 {
        return Err(Error::Mode);
    }
    if wants_x2 {
        MODE.store(2, Ordering::Release);
    } else {
        LAPIC_VA.store(lapic_va.ok_or(Error::Mapping)?, Ordering::Relaxed);
        MODE.store(1, Ordering::Release);
    }
    let id = if wants_x2 {
        lapic_read(intc::REG_ID)
    } else {
        lapic_read(intc::REG_ID) >> 24
    };
    let version = lapic_read(intc::REG_VERSION);
    let max_lvt = intc::max_lvt(version);
    if version.trailing_zeros() >= 8 || version == u32::MAX || max_lvt < 2 {
        MODE.store(0, Ordering::Release);
        return Err(Error::Registers);
    }
    // Firmware's LINT0 state decides ExtINT (read before masking everything).
    let lint0_masked_by_firmware = lapic_read(intc::REG_LVT_LINT0) & intc::LVT_MASKED != 0;
    // Soft-disable, then mask every LVT (clear_local_APIC).
    let spiv = lapic_read(intc::REG_SPIV);
    lapic_write(intc::REG_SPIV, spiv & !intc::SPIV_ENABLE);
    lapic_write(
        intc::REG_LVT_TIMER,
        intc::LVT_MASKED | u32::from(intc::LOCAL_TIMER_VECTOR),
    );
    lapic_write(intc::REG_LVT_LINT0, intc::LVT_MASKED);
    lapic_write(intc::REG_LVT_LINT1, intc::LVT_MASKED);
    if max_lvt >= 3 {
        lapic_write(
            intc::REG_LVT_ERROR,
            intc::LVT_MASKED | u32::from(ERROR_VECTOR),
        );
    }
    if max_lvt >= 4 {
        lapic_write(intc::REG_LVT_PERF, intc::LVT_MASKED);
    }
    if max_lvt >= 5 {
        lapic_write(intc::REG_LVT_THERMAL, intc::LVT_MASKED);
    }
    if max_lvt >= 6 {
        lapic_write(intc::REG_LVT_CMCI, intc::LVT_MASKED);
    }
    // TPR: accept everything except vectors 0-31 (Linux never changes it).
    lapic_write(intc::REG_TPR, (lapic_read(intc::REG_TPR) & !0xff) | 0x10);
    // apic_clear_isr: acknowledge anything the previous owner left in service.
    // shortcut: bounded at 256 EOIs, the architectural ISR capacity; Linux also
    // drains IRR (apic_pending_intr_clear); upgrade with kexec/kdump support.
    for _ in 0..256 {
        let in_service = (0..8).any(|i| lapic_read(intc::REG_ISR + 0x10 * i) != 0);
        if !in_service {
            break;
        }
        eoi();
    }
    lapic_write(
        intc::REG_SPIV,
        (spiv & !0x1ff) | intc::SPIV_ENABLE | u32::from(SPURIOUS_VECTOR),
    );
    // LINT0: virtual-wire ExtINT stays enabled if firmware left it unmasked or no
    // IOAPIC will route interrupts (`!value || ioapic_is_disabled`).
    let extint = !lint0_masked_by_firmware || !ioapic_routes_irqs;
    lapic_write(
        intc::REG_LVT_LINT0,
        intc::LVT_DM_EXTINT | if extint { 0 } else { intc::LVT_MASKED },
    );
    // LINT1: NMI on the BSP.
    lapic_write(intc::REG_LVT_LINT1, intc::LVT_DM_NMI);
    // lapic_setup_esr: error vector unmasked, ESR cleared (write 0, then read).
    if max_lvt >= 3 {
        lapic_write(intc::REG_ESR, 0);
        let _ = lapic_read(intc::REG_ESR);
        lapic_write(intc::REG_LVT_ERROR, u32::from(ERROR_VECTOR));
    }
    Ok(Some(LapicInfo {
        id,
        version,
        max_lvt,
        extint_enabled: extint,
    }))
}

static ERRORS: AtomicU64 = AtomicU64::new(0);
static LAST_ERROR: AtomicU64 = AtomicU64::new(0);
static SPURIOUS: AtomicU64 = AtomicU64::new(0);

/// APIC error vector body (`smp_error_interrupt`): latch and clear the ESR,
/// acknowledge. No logging in interrupt context; counters are read later.
pub fn error_interrupt() {
    lapic_write(intc::REG_ESR, 0);
    let esr = lapic_read(intc::REG_ESR);
    LAST_ERROR.store(u64::from(esr), Ordering::Relaxed);
    ERRORS.fetch_add(1, Ordering::Relaxed);
    eoi();
}
/// Spurious vector body: never acknowledged (SDM 12.9).
pub fn spurious_interrupt() {
    SPURIOUS.fetch_add(1, Ordering::Relaxed);
}
/// (APIC errors, last ESR, spurious interrupts) seen so far.
#[must_use]
pub fn error_counters() -> (u64, u64, u64) {
    (
        ERRORS.load(Ordering::Relaxed),
        LAST_ERROR.load(Ordering::Relaxed),
        SPURIOUS.load(Ordering::Relaxed),
    )
}

// ---------------------------------------------------------------------------
// IOAPIC

const IOREGSEL: u64 = 0x00;
const IOWIN: u64 = 0x10;

/// Mapped IOAPICs in MADT order; a zero address means "not mapped/absent".
pub struct Ioapics {
    va: [u64; MAX_IOAPICS],
    pins: [u32; MAX_IOAPICS],
    gsi_base: [u32; MAX_IOAPICS],
    count: usize,
}

/// # Safety
/// `va` is a mapped UC IOAPIC register page, BSP IF clear, no concurrent user.
unsafe fn io_read(va: u64, register: u32) -> u32 {
    // SAFETY: forwarded; the select/window pair is one indivisible sequence
    // because IF is clear and only the BSP touches the IOAPIC.
    unsafe {
        mmio::write32(va + IOREGSEL, register);
        mmio::read32(va + IOWIN)
    }
}
/// # Safety
/// As [`io_read`]; `value` is a valid register value.
unsafe fn io_write(va: u64, register: u32, value: u32) {
    // SAFETY: forwarded.
    unsafe {
        mmio::write32(va + IOREGSEL, register);
        mmio::write32(va + IOWIN, value);
    }
}

impl Ioapics {
    #[must_use]
    pub fn count(&self) -> usize {
        self.pins[..self.count].iter().filter(|&&p| p != 0).count()
    }
    #[must_use]
    pub fn pins_total(&self) -> u32 {
        self.pins[..self.count].iter().sum()
    }

    /// Write a redirection entry (high dword first, as Linux, so a masked low
    /// word never exposes a half-written destination).
    ///
    /// # Safety
    /// BSP IF clear; `index`/`pin` came from [`Ioapics::locate`].
    unsafe fn write_entry(&self, index: usize, pin: u32, entry: Redirection) {
        let register = intc::ioapic_redirection_register(pin);
        // SAFETY: the page at va[index] is mapped (locate only returns mapped ones).
        unsafe {
            io_write(self.va[index], register + 1, entry.high());
            io_write(self.va[index], register, entry.low());
        }
    }

    /// The IOAPIC and pin carrying `gsi`.
    #[must_use]
    pub fn locate(&self, gsi: u32) -> Option<(usize, u32)> {
        (0..self.count).find_map(|i| {
            let pin = gsi.checked_sub(self.gsi_base[i])?;
            (self.va[i] != 0 && pin < self.pins[i]).then_some((i, pin))
        })
    }

    /// Route `route` (an ISA IRQ's GSI) to `vector` on `destination` unmasked.
    ///
    /// # Safety
    /// BSP IF clear, after [`ioapic_init`].
    pub unsafe fn route(
        &self,
        route: IsaRoute,
        vector: u8,
        destination: u8,
    ) -> Option<(usize, u32)> {
        let (index, pin) = self.locate(route.gsi)?;
        // SAFETY: located pin of a mapped IOAPIC; IF clear per contract.
        unsafe {
            self.write_entry(
                index,
                pin,
                Redirection {
                    vector,
                    active_low: route.polarity == Polarity::ActiveLow,
                    level: route.trigger == Trigger::Level,
                    masked: false,
                    destination,
                },
            );
        }
        Some((index, pin))
    }

    /// Mask one pin again, keeping its configuration.
    ///
    /// # Safety
    /// As [`Ioapics::route`]; `(index, pin)` came from it.
    pub unsafe fn mask(&self, index: usize, pin: u32) {
        let register = intc::ioapic_redirection_register(pin);
        // SAFETY: mapped IOAPIC page, IF clear; sets only the mask bit.
        unsafe {
            let low = io_read(self.va[index], register);
            io_write(self.va[index], register, low | intc::LVT_MASKED);
        }
    }
}

/// Probe every mapped IOAPIC's pin count and mask all pins (`clear_IO_APIC`).
///
/// # Safety
/// BSP IF clear. Each `Some(va)` is the mapped UC page of the MADT IOAPIC at
/// the same index.
pub unsafe fn ioapic_init(madt: &Madt, vas: &[Option<u64>]) -> Ioapics {
    let mut set = Ioapics {
        va: [0; MAX_IOAPICS],
        pins: [0; MAX_IOAPICS],
        gsi_base: [0; MAX_IOAPICS],
        count: 0,
    };
    for (index, io) in madt.ioapics().iter().enumerate() {
        set.count = index + 1;
        set.gsi_base[index] = io.gsi_base;
        let Some(Some(va)) = vas.get(index).copied() else {
            continue;
        };
        // SAFETY: caller's contract for each mapped page.
        let version = unsafe { io_read(va, 1) };
        // An absent/unresponsive device reads all-ones; a real one has a version byte.
        if version == u32::MAX || version.trailing_zeros() >= 8 {
            continue;
        }
        set.va[index] = va;
        set.pins[index] = intc::ioapic_pins(version);
        for pin in 0..set.pins[index] {
            // SAFETY: pin < pin count of the mapped IOAPIC just probed.
            unsafe { set.write_entry(index, pin, Redirection::MASKED) };
        }
    }
    set
}

// ---------------------------------------------------------------------------
// 8259A pair

const PIC_MASTER: u16 = 0x20;
const PIC_SLAVE: u16 = 0xa0;

/// `probe_8259A`: mask all but the cascade, read the mask back.
pub fn pic_probe() -> bool {
    let probe = !(1u8 << 2);
    cpu::out_byte(PIC_SLAVE + 1, 0xff);
    cpu::out_byte(PIC_MASTER + 1, probe);
    cpu::in_byte(PIC_MASTER + 1) == probe
}

/// `init_8259A(0)` at vector base [`ISA_IRQ_VECTOR_BASE`], then mask everything
/// (Linux's `mask_all` in APIC mode, and the idle state before any `unmask`).
pub fn pic_init_masked() {
    cpu::out_byte(PIC_MASTER, 0x11);
    cpu::io_wait();
    cpu::out_byte(PIC_SLAVE, 0x11);
    cpu::io_wait();
    cpu::out_byte(PIC_MASTER + 1, ISA_IRQ_VECTOR_BASE);
    cpu::io_wait();
    cpu::out_byte(PIC_SLAVE + 1, ISA_IRQ_VECTOR_BASE + 8);
    cpu::io_wait();
    cpu::out_byte(PIC_MASTER + 1, 4);
    cpu::io_wait();
    cpu::out_byte(PIC_SLAVE + 1, 2);
    cpu::io_wait();
    cpu::out_byte(PIC_MASTER + 1, 1);
    cpu::io_wait();
    cpu::out_byte(PIC_SLAVE + 1, 1);
    cpu::io_wait();
    cpu::out_byte(PIC_MASTER + 1, 0xff);
    cpu::out_byte(PIC_SLAVE + 1, 0xff);
}
/// Unmask only ISA IRQ0 (the PIT) on the master.
pub fn pic_unmask_irq0() {
    cpu::out_byte(PIC_MASTER + 1, 0xfe);
}
pub fn pic_mask_all() {
    cpu::out_byte(PIC_MASTER + 1, 0xff);
    cpu::out_byte(PIC_SLAVE + 1, 0xff);
}
/// Non-specific EOI of the master for IRQ0.
pub fn pic_eoi_irq0() {
    cpu::out_byte(PIC_MASTER, 0x20);
}

/// `spurious_8259A_irq` for IRQ7 (`slave` false) / IRQ15 (`slave` true):
/// true if the line was not really in service and must be ignored. A spurious
/// slave interrupt still acknowledges the master's cascade line.
pub fn pic_spurious(slave: bool) -> bool {
    let port = if slave { PIC_SLAVE } else { PIC_MASTER };
    cpu::out_byte(port, 0x0b); // OCW3: read in-service register
    let spurious = cpu::in_byte(port) & 0x80 == 0;
    if spurious && slave {
        cpu::out_byte(PIC_MASTER, 0x20);
    }
    spurious
}
