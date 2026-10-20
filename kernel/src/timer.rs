// SPDX-License-Identifier: GPL-2.0-only
//! Time hardware and the boot CPU's clock: TSC calibration, HPET / ACPI PM timer
//! references, CMOS RTC, the tick clockevent (LAPIC TSC-deadline or one-shot, or
//! the legacy PIT) and the monotonic/boottime/realtime getters later syscalls
//! use. Conversions and decisions are in `kernel::time` / `kernel::intc`.
//!
//! Provenance (Linux 6.18.57, GPL-2.0-only; Rust re-expressions):
//! - TSC order and sanity: arch/x86/kernel/tsc.c (`native_calibrate_tsc`,
//!   `quick_pit_calibrate` l.538-660, `tsc_read_refs` l.358, the HPET/PM-timer
//!   reference path l.758-935, 1% refinement l.1316-1390).
//! - HPET start: arch/x86/kernel/hpet.c (`hpet_enable` l.991-1053 clears
//!   ENABLE and `LEGACY_REPL`, resets and restarts the counter).
//! - LAPIC clockevent: arch/x86/kernel/apic/apic.c (`lapic_next_deadline`,
//!   `lapic_next_event`, `calibrate_APIC_clock` l.791-945, divider 16).
//! - CMOS time: arch/x86/kernel/rtc.c `mach_get_cmos_time` and
//!   drivers/rtc/rtc-mc146818-lib.c `mc146818_avoid_UIP`/`mc146818_get_time`.
//! - Tick: `CONFIG_HZ=1000`, tick emulated on a one-shot device
//!   (kernel/time/tick-sched.c, no idle tick stop yet).

use core::{
    arch::x86_64::{_mm_lfence, _rdtsc},
    sync::atomic::{AtomicBool, AtomicI64, AtomicU8, AtomicU64, Ordering, fence},
};
use kernel::{
    boot::BootInfo,
    firmware::{Acpi, Fadt, MAX_IOAPICS, Madt},
    intc::{self, ApicMode, ISA_IRQ_VECTOR_BASE, TimerMode},
    memory::Allocator,
    time::{
        self, Clock, Cyc2Ns, HZ, NSEC_PER_MSEC, ReferenceError, RtcRegisters, TICK_NSEC, Timespec,
        TscSource,
    },
};
use raw_cpuid::{CpuId, native_cpuid::cpuid_count};
use x86_64::registers::model_specific::Msr;

use crate::{apic, cpu, mmio, paging};

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// CPUID reports no TSC.
    NoTsc,
    /// No source produced a TSC frequency (PIT, HPET and PM timer all unusable).
    Calibration,
    /// The local APIC timer did not calibrate and no other tick source exists.
    Clockevent,
    /// The tick interrupt did not arrive within the bounded wait.
    TickStalled,
    /// The legacy path was requested but no 8259 pair exists.
    NoLegacyPic,
    /// The planned APIC mode could not be established.
    Apic,
    /// The TSC did not advance while measuring tick periods.
    Stalled,
}

// ---------------------------------------------------------------------------
// TSC

/// `rdtsc_ordered()`: LFENCE first so the read cannot execute early, as Linux
/// does for every clock read.
#[must_use]
pub fn rdtsc() -> u64 {
    // SAFETY: `_mm_lfence` is declared `#[target_feature(enable = "sse2")]`;
    // this soft-float target cannot enable SSE2 on our own functions, so it is
    // an out-of-line call that executes only `lfence` (no XMM/MMX state, no
    // memory, no stack effect). LFENCE's only exception is #UD without
    // CPUID.01H:EDX.SSE2, which every x86-64 CPU has; it is not gated by
    // CR0.EM/TS or CR4.OSFXSR. `_rdtsc` needs CPUID.1:EDX.TSC (checked in
    // `init`) and CR4.TSD is irrelevant at CPL0. The intrinsics have side
    // effects, so the compiler keeps the fence before the read, as Linux's
    // `rdtsc_ordered()`.
    unsafe {
        _mm_lfence();
        _rdtsc()
    }
}

/// Busy-wait `us` microseconds on the calibrated TSC.
fn udelay(us: u64) {
    let cycles = TSC_KHZ.load(Ordering::Relaxed) * us / 1000;
    let start = rdtsc();
    while rdtsc().wrapping_sub(start) < cycles {
        core::hint::spin_loop();
    }
}

/// TSC rate the suite assumes for its busy-waits when calibration produced
/// none (2 GHz: within 0.4x to 2.5x of every x86-64 part, so a page stays up
/// for a readable time instead of flashing past).
#[cfg(feature = "baremetal-suite")]
const FALLBACK_TSC_KHZ: u64 = 2_000_000;

/// The calibrated TSC rate, or [`FALLBACK_TSC_KHZ`] before/without calibration.
#[cfg(feature = "baremetal-suite")]
#[must_use]
pub fn tsc_khz_or_assumed() -> u64 {
    match TSC_KHZ.load(Ordering::Relaxed) {
        0 => FALLBACK_TSC_KHZ,
        khz => khz,
    }
}

/// Busy-wait `ms` milliseconds on the raw TSC: needs neither the published
/// clock nor any interrupt, so the suite's screens work after a timer failure.
#[cfg(feature = "baremetal-suite")]
pub fn spin_ms(ms: u64) {
    let cycles = tsc_khz_or_assumed().saturating_mul(ms);
    let start = rdtsc();
    while rdtsc().wrapping_sub(start) < cycles {
        core::hint::spin_loop();
    }
}

/// Whether `init` published the monotonic clock (false after a calibration
/// failure: `ktime_get_ns` is then a constant and no sleep can end).
#[cfg(feature = "baremetal-suite")]
#[must_use]
pub fn clock_published() -> bool {
    CLOCK_MUL.load(Ordering::Relaxed) != 0
}

// ---------------------------------------------------------------------------
// Published state

static TSC_KHZ: AtomicU64 = AtomicU64::new(0);
/// Jiffies at HZ=1000.
static TICKS: AtomicU64 = AtomicU64::new(0);
/// ISA IRQ0 deliveries (PIT through IOAPIC or 8259).
static IRQ0: AtomicU64 = AtomicU64::new(0);

const EVENT_NONE: u8 = 0;
const EVENT_PIT: u8 = 1;
const EVENT_LAPIC_ONESHOT: u8 = 2;
const EVENT_LAPIC_DEADLINE: u8 = 3;
static EVENT: AtomicU8 = AtomicU8::new(EVENT_NONE);
static RTC_OK: AtomicBool = AtomicBool::new(false);
static TICK_ON: AtomicBool = AtomicBool::new(false);
static PIT_RUNNING: AtomicBool = AtomicBool::new(false);
/// Set once `init` saw the clockevent deliver ticks; halting waits depend on it.
static TICK_VERIFIED: AtomicBool = AtomicBool::new(false);
static LAPIC_MULT: AtomicU64 = AtomicU64::new(0);
/// Monotonic time of the next emulated periodic tick.
static NEXT_TICK_NS: AtomicU64 = AtomicU64::new(0);
/// Pending `wait_until_ns` deadline, `u64::MAX` when none.
static DEADLINE_NS: AtomicU64 = AtomicU64::new(u64::MAX);
/// The process's `ITIMER_REAL` expiry (`signal::itimer`), `u64::MAX` when
/// disarmed. Only the wake-up is programmed here; the expiry is acted on by
/// `State::sync_timers` at the next kernel exit or wake-up.
static ITIMER_NS: AtomicU64 = AtomicU64::new(u64::MAX);

/// The earliest wanted wake-up other than the tick.
fn event_deadline() -> u64 {
    DEADLINE_NS
        .load(Ordering::Relaxed)
        .min(ITIMER_NS.load(Ordering::Relaxed))
}

// A sequence-counted clock: readers (any context, including the tick IRQ)
// never block; the single writer is `init` (and a future refinement) with
// interrupts off.
static CLOCK_SEQ: AtomicU64 = AtomicU64::new(0);
static CLOCK_MUL: AtomicU64 = AtomicU64::new(0);
static CLOCK_SHIFT: AtomicU64 = AtomicU64::new(0);
static CLOCK_OFFSET: AtomicU64 = AtomicU64::new(0);
static CLOCK_REAL_OFFSET: AtomicI64 = AtomicI64::new(0);
static CLOCK_SETTOD_REAL: AtomicI64 = AtomicI64::new(0);

fn clock_publish(clock: &Clock) {
    let scale = clock.scale();
    CLOCK_SEQ.fetch_add(1, Ordering::Acquire); // odd: write in progress
    CLOCK_MUL.store(u64::from(scale.mul), Ordering::Relaxed);
    CLOCK_SHIFT.store(u64::from(scale.shift), Ordering::Relaxed);
    CLOCK_OFFSET.store(scale.offset, Ordering::Relaxed);
    CLOCK_REAL_OFFSET.store(clock.real_offset_ns(), Ordering::Relaxed);
    CLOCK_SETTOD_REAL.store(clock.settod_real_ns(), Ordering::Relaxed);
    CLOCK_SEQ.fetch_add(1, Ordering::Release);
}
fn clock_load() -> Clock {
    loop {
        let before = CLOCK_SEQ.load(Ordering::Acquire);
        if before & 1 != 0 {
            core::hint::spin_loop();
            continue;
        }
        let scale = Cyc2Ns {
            mul: u32::try_from(CLOCK_MUL.load(Ordering::Relaxed)).unwrap_or(0),
            shift: u32::try_from(CLOCK_SHIFT.load(Ordering::Relaxed)).unwrap_or(0),
            offset: CLOCK_OFFSET.load(Ordering::Relaxed),
        };
        let real_offset = CLOCK_REAL_OFFSET.load(Ordering::Relaxed);
        let settod = CLOCK_SETTOD_REAL.load(Ordering::Relaxed);
        fence(Ordering::Acquire);
        if CLOCK_SEQ.load(Ordering::Relaxed) == before {
            return Clock::from_parts(scale, real_offset, settod);
        }
    }
}

/// `CLOCK_MONOTONIC` in nanoseconds (0 at `init`); never goes backwards on the
/// single boot CPU.
#[must_use]
pub fn ktime_get_ns() -> u64 {
    clock_load().monotonic_ns(rdtsc())
}
/// `CLOCK_BOOTTIME`: equal to monotonic until suspend exists.
#[must_use]
pub fn ktime_get_boottime_ns() -> u64 {
    clock_load().boottime_ns(rdtsc())
}
/// `CLOCK_REALTIME`: the CMOS time at boot plus monotonic time.
#[must_use]
pub fn ktime_get_real() -> Timespec {
    clock_load().realtime(rdtsc())
}
/// Everything the syscall layer needs to read every clock consistently.
#[must_use]
pub fn clock_state() -> kernel::syscall::ClockState {
    let clock = clock_load();
    kernel::syscall::ClockState {
        mono_ns: clock.monotonic_ns(rdtsc()),
        // No suspend: `CLOCK_BOOTTIME` is `CLOCK_MONOTONIC`.
        boot_offset_ns: 0,
        real_offset_ns: clock.real_offset_ns(),
        settod_real_ns: clock.settod_real_ns(),
    }
}
/// `do_settimeofday64`'s store: replace the realtime offset and record the
/// value that was set (`xtime`, which the coarse readers return until a tick).
///
/// Context: task context with IF clear (the syscall entry masks it), BSP. The
/// sequence-counted clock has one writer; an interrupt arriving mid-write on
/// this CPU would spin on the odd sequence forever, hence IF must be clear.
/// Takes no lock itself; it runs under the `PROCESS` lock like the syscall.
pub fn set_realtime(offset: i64, real_ns: i64) {
    debug_assert!(!cpu::interrupts_enabled(), "clock writer needs IF clear");
    let mut clock = clock_load();
    clock.set_realtime(offset, real_ns);
    clock_publish(&clock);
}
/// Whether the CMOS RTC answered at boot: the wakeup-capable RTC that
/// `alarmtimer_get_rtcdev` needs on this platform.
#[must_use]
pub fn rtc_present() -> bool {
    RTC_OK.load(Ordering::Relaxed)
}
#[must_use]
pub fn ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}
#[must_use]
pub fn tsc_khz() -> u64 {
    TSC_KHZ.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Clockevent: arm, tick and deadline wait

fn lapic_arm(target_ns: u64) {
    let tsc = rdtsc();
    let clock = clock_load();
    let delta_ns = target_ns.saturating_sub(clock.monotonic_ns(tsc));
    if EVENT.load(Ordering::Relaxed) == EVENT_LAPIC_DEADLINE {
        let cycles =
            u64::try_from(u128::from(delta_ns) * u128::from(tsc_khz()) / u128::from(NSEC_PER_MSEC))
                .unwrap_or(u64::MAX);
        // The LVT is rewritten on every arm: a shutdown masked it, and changing
        // the timer mode would clear the deadline anyway. The MSR write must not
        // be reordered before it (`weak_wrmsr_fence`; SeqCst fence is MFENCE).
        apic::lapic_write(
            intc::REG_LVT_TIMER,
            intc::lvt_timer(TimerMode::TscDeadline, false),
        );
        fence(Ordering::SeqCst);
        // lapic_next_deadline: absolute TSC value; a value in the past fires at once.
        // SAFETY: MSR 0x6E0 exists because EVENT_LAPIC_DEADLINE is only selected
        // when CPUID.1:ECX.TSC_Deadline was set; CPL0.
        unsafe { Msr::new(intc::MSR_TSC_DEADLINE).write(tsc.wrapping_add(cycles.max(1))) };
    } else {
        // lapic_next_event: min 0xF ticks, max 0x7FFFFFFF (apic.c:741-746).
        let ticks =
            time::ns_to_ticks(delta_ns, LAPIC_MULT.load(Ordering::Relaxed)).clamp(0xf, 0x7fff_ffff);
        apic::lapic_write(
            intc::REG_LVT_TIMER,
            intc::lvt_timer(TimerMode::OneShot, false),
        );
        apic::lapic_write(intc::REG_TIMER_INITIAL, ticks as u32);
    }
}
fn lapic_shutdown() {
    // Disarm while the LVT still names the mode that owns the counter, then mask:
    // the MSR/count write after a mode change would be the order the SDM leaves
    // unspecified (Vol.3 10.5.4.1: writing 0 to IA32_TSC_DEADLINE disarms;
    // changing the timer mode clears it), so this order needs no such argument.
    if EVENT.load(Ordering::Relaxed) == EVENT_LAPIC_DEADLINE {
        // SAFETY: as in `lapic_arm`; zero disarms the deadline.
        unsafe { Msr::new(intc::MSR_TSC_DEADLINE).write(0) };
    } else {
        apic::lapic_write(intc::REG_TIMER_INITIAL, 0);
    }
    apic::lapic_write(
        intc::REG_LVT_TIMER,
        intc::lvt_timer(TimerMode::OneShot, true),
    );
}

/// Program the LAPIC for the earlier of the next tick (if ticking) and any
/// pending deadline, or shut it down. Interrupts must be off.
fn rearm(now_ns: u64) {
    if EVENT.load(Ordering::Relaxed) == EVENT_PIT {
        pit_rearm(now_ns);
        return;
    }
    let mut target = if TICK_ON.load(Ordering::Relaxed) {
        NEXT_TICK_NS.load(Ordering::Relaxed)
    } else {
        u64::MAX
    };
    let deadline = event_deadline();
    if deadline > now_ns {
        target = target.min(deadline);
    }
    if target == u64::MAX {
        lapic_shutdown();
    } else {
        lapic_arm(target);
    }
}

/// Legacy path: the PIT only has a periodic mode here, so a pending deadline
/// is served at tick granularity (up to 1 ms late, never early) by running the
/// PIT while a tick or a deadline is wanted, as Linux does without one-shot
/// hardware; it is stopped and masked otherwise.
fn pit_rearm(now_ns: u64) {
    let deadline = event_deadline();
    let wanted = TICK_ON.load(Ordering::Relaxed) || (deadline != u64::MAX && deadline > now_ns);
    if wanted && !PIT_RUNNING.swap(true, Ordering::Relaxed) {
        pit_start_periodic();
        apic::pic_unmask_irq0();
    } else if !wanted && PIT_RUNNING.swap(false, Ordering::Relaxed) {
        pit_stop();
        apic::pic_mask_all();
    }
}

/// `user` is whether the tick interrupted ring 3 (`user_mode(regs)`), which
/// `account_process_tick` needs to classify the tick's CPU time.
fn tick_bookkeeping(now_ns: u64, user: bool) {
    if !TICK_ON.load(Ordering::Relaxed) {
        return;
    }
    let next = NEXT_TICK_NS.load(Ordering::Relaxed);
    if now_ns >= next {
        // hrtimer_forward: count every missed period, never fewer than one.
        let periods = (now_ns - next) / TICK_NSEC + 1;
        TICKS.fetch_add(periods, Ordering::Relaxed);
        NEXT_TICK_NS.store(next + periods * TICK_NSEC, Ordering::Relaxed);
        crate::userspace::account_ticks(user, periods);
    }
}

/// Vector 0xec body; `user` as in [`tick_bookkeeping`].
pub fn lapic_timer_interrupt(user: bool) {
    apic::eoi();
    let now = ktime_get_ns();
    tick_bookkeeping(now, user);
    cpu::irq_lock_probe();
    rearm(now);
    // After the EOI and the re-arm: a timed-out group abandons this frame.
    #[cfg(feature = "baremetal-suite")]
    if crate::baremetal::expired() {
        crate::baremetal::timeout();
    }
}

/// Vector 0x30 body: ISA IRQ0, delivered by the 8259 (legacy path) or the IOAPIC.
pub fn isa_irq0_interrupt(user: bool) {
    if apic::mode() == ApicMode::Disabled {
        apic::pic_eoi_irq0();
    } else {
        apic::eoi();
    }
    IRQ0.fetch_add(1, Ordering::Relaxed);
    if EVENT.load(Ordering::Relaxed) == EVENT_PIT && TICK_ON.load(Ordering::Relaxed) {
        TICKS.fetch_add(1, Ordering::Relaxed);
        crate::userspace::account_ticks(user, 1);
        cpu::irq_lock_probe();
    }
    #[cfg(feature = "baremetal-suite")]
    if crate::baremetal::expired() {
        crate::baremetal::timeout();
    }
}

/// Restart the periodic tick after the boot proofs masked it, for the task that
/// is about to run (`tick_sched` keeps the tick while a task runs; only idle
/// stops it). A clockevent that never proved tick delivery stays off. Context:
/// BSP, IF clear.
pub fn resume_tick() {
    if !TICK_VERIFIED.load(Ordering::Relaxed) {
        return;
    }
    cpu::timer_transaction(|| {
        TICK_ON.store(true, Ordering::Relaxed);
        NEXT_TICK_NS.store(ktime_get_ns() + TICK_NSEC, Ordering::Relaxed);
        rearm(ktime_get_ns());
    });
}

/// Stop the tick and the clockevent (Linux `clockevents_shutdown`). A pending
/// deadline wait keeps the LAPIC armed only for itself.
pub fn mask_timer() {
    cpu::timer_transaction(|| {
        TICK_ON.store(false, Ordering::Relaxed);
        if EVENT.load(Ordering::Relaxed) != EVENT_NONE {
            rearm(ktime_get_ns());
        }
    });
}

/// Halt until the next interrupt; IF is 0 on return. Only for a clockevent that
/// has been shown to deliver (`TICK_VERIFIED`): a halted CPU whose timer is dead
/// never wakes. Before that proof (and if bring-up failed) it spins for 100 us
/// with IF=1 instead, so no wait can hang on a source that never worked.
fn idle() {
    if TICK_VERIFIED.load(Ordering::Relaxed) {
        cpu::wait_for_interrupt();
    } else {
        cpu::interrupts_on();
        udelay(100);
        cpu::interrupts_off();
    }
}

/// Sleep on the monotonic clock until `deadline_ns` (absolute `CLOCK_MONOTONIC`),
/// halting between interrupts, as `hrtimer_nanosleep` does for one waiter.
/// Context: task, interrupts off on entry and exit, BSP only; one waiter at a
/// time. Returns immediately for a deadline in the past.
///
/// Contract: halting is used only after `init` verified tick delivery; a
/// clockevent that dies *afterwards* hangs the halted CPU (as it would Linux's
/// idle loop). Callers that must survive that use the bounded spin forms
/// (`wait_for_ticks`, `poll_periods`), which is what the boot proofs do.
pub fn wait_until_ns(deadline_ns: u64) {
    while ktime_get_ns() < deadline_ns {
        // The suite's per-group bound ends a sleep that the clock never wakes.
        #[cfg(feature = "baremetal-suite")]
        if crate::baremetal::expired() {
            DEADLINE_NS.store(u64::MAX, Ordering::Relaxed);
            crate::baremetal::timeout();
        }
        cpu::timer_transaction(|| {
            DEADLINE_NS.store(deadline_ns, Ordering::Relaxed);
            rearm(ktime_get_ns());
        });
        idle();
    }
    cpu::timer_transaction(|| {
        DEADLINE_NS.store(u64::MAX, Ordering::Relaxed);
        rearm(ktime_get_ns());
    });
}

/// Program (or clear) the wake-up for the process's `ITIMER_REAL` expiry.
/// Called before the CPU can take an interrupt that matters: before halting in
/// [`wait_event`] and before the return to ring 3. Context: task or interrupt
/// return path, interrupts masked, BSP.
pub fn set_itimer_ns(expiry: Option<u64>) {
    let expiry = expiry.unwrap_or(u64::MAX);
    // Every syscall exit republishes; reprogramming the clockevent (an MSR or
    // MMIO write, a VM exit under virtualization) only when it changed.
    if ITIMER_NS.load(Ordering::Relaxed) == expiry {
        return;
    }
    cpu::timer_transaction(|| {
        ITIMER_NS.store(expiry, Ordering::Relaxed);
        if EVENT.load(Ordering::Relaxed) != EVENT_NONE {
            rearm(ktime_get_ns());
        }
    });
}

/// Forget every wake-up the finished process programmed (a sleep deadline that
/// a timed-out group abandoned, its `ITIMER_REAL` expiry), so the next group
/// starts with no stale clockevent. Context: BSP, interrupts masked, no task.
#[cfg(feature = "baremetal-suite")]
pub fn clear_waits() {
    cpu::timer_transaction(|| {
        DEADLINE_NS.store(u64::MAX, Ordering::Relaxed);
        ITIMER_NS.store(u64::MAX, Ordering::Relaxed);
        if EVENT.load(Ordering::Relaxed) != EVENT_NONE {
            rearm(ktime_get_ns());
        }
    });
}

/// One interruptible sleep: halt until the next interrupt (a signal source or
/// the clockevent armed for `deadline_ns` or the interval timer) and return, so
/// the caller can re-check its condition; a deadline already reached returns at
/// once. Context: task, interrupts masked on entry and exit, BSP. The caller
/// checks its wake condition with interrupts masked just before, and the halt is
/// `sti; hlt`, so a wake-up between the check and the halt is not lost.
pub fn wait_event(deadline_ns: Option<u64>) {
    let deadline = deadline_ns.unwrap_or(u64::MAX);
    if EVENT.load(Ordering::Relaxed) != EVENT_NONE {
        cpu::timer_transaction(|| {
            DEADLINE_NS.store(deadline, Ordering::Relaxed);
            rearm(ktime_get_ns());
        });
    }
    // `rearm` ignores a wake-up that is already due: do not halt for it.
    if ktime_get_ns() < event_deadline() {
        idle();
    }
    if EVENT.load(Ordering::Relaxed) != EVENT_NONE {
        cpu::timer_transaction(|| {
            DEADLINE_NS.store(u64::MAX, Ordering::Relaxed);
            rearm(ktime_get_ns());
        });
    }
}

/// Block `ns` nanoseconds (the `nanosleep` primitive).
pub fn sleep_ns(ns: u64) {
    wait_until_ns(ktime_get_ns().saturating_add(ns));
}

// ---------------------------------------------------------------------------
// PIT (8254)

const PIT_CH0: u16 = 0x40;
const PIT_CH2: u16 = 0x42;
const PIT_MODE: u16 = 0x43;
const PIT_GATE: u16 = 0x61;

fn pit_start_periodic() {
    // LATCH = (CLOCK_TICK_RATE + HZ/2) / HZ = 1193; mode 2 (rate generator).
    let latch = u16::try_from((time::PIT_TICK_RATE + HZ / 2) / HZ).unwrap_or(u16::MAX);
    cpu::out_byte(PIT_MODE, 0x34);
    let [low, high] = latch.to_le_bytes();
    cpu::out_byte(PIT_CH0, low);
    cpu::out_byte(PIT_CH0, high);
}
fn pit_stop() {
    // pit_shutdown: mode 0 with count 0 (one terminal count after 65536 ticks,
    // which the masked 8259/IOAPIC pin never delivers).
    cpu::out_byte(PIT_MODE, 0x30);
    cpu::out_byte(PIT_CH0, 0);
    cpu::out_byte(PIT_CH0, 0);
}

fn pit_verify_msb(value: u8) -> bool {
    let _ = cpu::in_byte(PIT_CH2); // ignore the LSB
    cpu::in_byte(PIT_CH2) == value
}
/// `pit_expect_msb`: returns (success, TSC at the last matching read, error term).
fn pit_expect_msb(value: u8) -> (bool, u64, u64) {
    let (mut tsc, mut previous, mut count) = (0u64, 0u64, 0u32);
    while count < 50_000 {
        if !pit_verify_msb(value) {
            break;
        }
        previous = tsc;
        tsc = rdtsc();
        count += 1;
    }
    (count > 5, tsc, rdtsc().wrapping_sub(previous))
}
/// Quick-PIT attempts before falling back to the reference clocks (Linux makes one
/// and then runs the slower `pit_calibrate_tsc` loops).
const PIT_ATTEMPTS: u32 = 3;
const MAX_QUICK_PIT_ITERATIONS: u64 = 50 * time::PIT_TICK_RATE / 1000 / 256;

/// `quick_pit_calibrate`: kHz or None (not accurate to 500 ppm / PIT unusable).
fn quick_pit_calibrate() -> Option<u64> {
    cpu::out_byte(PIT_GATE, (cpu::in_byte(PIT_GATE) & !0x02) | 0x01);
    cpu::out_byte(PIT_MODE, 0xb0); // channel 2, mode 0, binary
    cpu::out_byte(PIT_CH2, 0xff);
    cpu::out_byte(PIT_CH2, 0xff);
    pit_verify_msb(0);
    let (ok, tsc, d1) = pit_expect_msb(0xff);
    if !ok {
        return None;
    }
    for i in 1..=MAX_QUICK_PIT_ITERATIONS {
        let (ok, stamp, d2) = pit_expect_msb(0xff - u8::try_from(i).unwrap_or(u8::MAX));
        if !ok {
            return None;
        }
        let delta = stamp.wrapping_sub(tsc);
        if i == 1 && d1 + d2 >= delta.saturating_mul(MAX_QUICK_PIT_ITERATIONS) >> 11 {
            return None;
        }
        if d1 + d2 >= delta >> 11 {
            continue;
        }
        if !pit_verify_msb(0xfe - u8::try_from(i).unwrap_or(u8::MAX)) {
            return None;
        }
        return time::pit_quick_khz(delta, i);
    }
    None
}

// ---------------------------------------------------------------------------
// HPET and ACPI PM timer references

#[derive(Clone, Copy)]
struct HpetClock {
    va: u64,
    period_fs: u32,
}
#[derive(Clone, Copy)]
enum Reference {
    Hpet(HpetClock),
    PmTimer { port: u16, width_bits: u32 },
}

const HPET_PERIOD: u64 = 0x04;
const HPET_CFG: u64 = 0x10;
const HPET_COUNTER: u64 = 0xf0;
const HPET_CFG_ENABLE: u32 = 1;
const HPET_CFG_LEGACY: u32 = 2;
const HPET_MIN_PERIOD: u32 = 100_000;
const HPET_MAX_PERIOD: u32 = 100_000_000;

/// `hpet_enable` essentials: validate the period, stop and clear the counter,
/// disable legacy replacement (it would steal the PIT's IRQ0), restart, and
/// check that it counts.
///
/// # Safety
/// `va` is the mapped UC HPET register block, BSP IF clear.
unsafe fn hpet_start(va: u64) -> Option<HpetClock> {
    // SAFETY: forwarded; 32-bit accesses at architectural offsets.
    unsafe {
        let period_fs = mmio::read32(va + HPET_PERIOD);
        if !(HPET_MIN_PERIOD..=HPET_MAX_PERIOD).contains(&period_fs) {
            return None;
        }
        let config = mmio::read32(va + HPET_CFG) & !(HPET_CFG_ENABLE | HPET_CFG_LEGACY);
        mmio::write32(va + HPET_CFG, config);
        mmio::write32(va + HPET_COUNTER, 0);
        mmio::write32(va + HPET_COUNTER + 4, 0);
        mmio::write32(va + HPET_CFG, config | HPET_CFG_ENABLE);
        let first = mmio::read32(va + HPET_COUNTER);
        // hpet_counting(): the counter must move within 200 reads.
        let counting = (0..200).any(|_| mmio::read32(va + HPET_COUNTER) != first);
        counting.then_some(HpetClock { va, period_fs })
    }
}

fn read_reference(reference: &Reference) -> u32 {
    match *reference {
        // SAFETY: HpetClock exists only after `hpet_start` validated the mapping.
        Reference::Hpet(h) => unsafe { mmio::read32(h.va + HPET_COUNTER) },
        Reference::PmTimer { port, width_bits } => {
            let value = cpu::in_dword(port);
            if width_bits >= 32 {
                value
            } else {
                value & ((1 << width_bits) - 1)
            }
        }
    }
}
/// `tsc_read_refs`: a reference read bracketed by TSC reads, retried when the
/// bracket is wider than the disturbance threshold (an SMI or VM exit).
fn read_refs(reference: &Reference) -> Option<(u64, u32)> {
    let khz = tsc_khz();
    let threshold = if khz != 0 { khz >> 5 } else { 0x20000 };
    for _ in 0..5 {
        let t1 = rdtsc();
        let value = read_reference(reference);
        let t2 = rdtsc();
        if t2.wrapping_sub(t1) < threshold {
            return Some((t2, value));
        }
    }
    None
}
/// TSC kHz from `reference` over ~50 ms (`CAL2_MS`): wait on the reference
/// itself, so the TSC rate need not be known. The wait is bounded in elapsed
/// TSC time ([`time::REFERENCE_LIMIT_CYCLES`]), so a stopped HPET or a PM-timer
/// port that reads a constant is reported (`WARN`) after a fraction of a second
/// instead of freezing boot behind an uncached read loop.
fn calibrate_against(reference: &Reference) -> Result<u64, ReferenceError> {
    let (name, target, width_bits) = match *reference {
        Reference::Hpet(h) => (
            "hpet",
            50_000_000u64 * 1_000_000 / u64::from(h.period_fs),
            32,
        ),
        Reference::PmTimer { width_bits, .. } => {
            ("pmtimer", time::PMTMR_TICKS_PER_SEC / 20, width_bits)
        }
    };
    let mask = if width_bits >= 32 {
        u64::from(u32::MAX)
    } else {
        (1 << width_bits) - 1
    };
    let result = time::wait_reference(
        || read_refs(reference),
        target,
        mask,
        time::REFERENCE_LIMIT_CYCLES,
    );
    let ((tsc1, ref1), (tsc2, ref2)) = result.inspect_err(|error| {
        crate::log!(
            "WARN tsc reference={} calibration failed: {:?}\n",
            name,
            error
        );
    })?;
    let delta = tsc2.wrapping_sub(tsc1);
    match *reference {
        Reference::Hpet(h) => time::calc_hpet_ref(delta, ref1, ref2, h.period_fs),
        Reference::PmTimer { width_bits, .. } => {
            time::calc_pmtimer_ref(delta, ref1, ref2, width_bits)
        }
    }
    .ok_or(ReferenceError::Stuck)
}

// ---------------------------------------------------------------------------
// CMOS RTC

fn cmos_read(register: u8) -> u8 {
    cpu::out_byte(0x70, register);
    cpu::in_byte(0x71)
}

/// `mach_get_cmos_time`: the wall clock in seconds, or 0 if the RTC does not
/// settle within 1 s (`mc146818_get_time(&tm, 1000)` failing).
fn rtc_read(century_register: u8) -> (i64, bool) {
    const UIP: u8 = 0x80;
    for _ in 0..10_000 {
        let seconds = cmos_read(0x00);
        if cmos_read(0x0a) & UIP != 0 {
            udelay(100);
            continue;
        }
        if seconds != cmos_read(0x00) {
            continue;
        }
        let regs = RtcRegisters {
            seconds,
            minutes: cmos_read(0x02),
            hours: cmos_read(0x04),
            day: cmos_read(0x07),
            month: cmos_read(0x08),
            year: cmos_read(0x09),
            century: if century_register != 0 {
                cmos_read(century_register)
            } else {
                0
            },
        };
        if cmos_read(0x0a) & UIP != 0 {
            udelay(100);
            continue;
        }
        if seconds != cmos_read(0x00) {
            continue;
        }
        return (time::rtc_to_time64(regs), true);
    }
    (0, false)
}

// ---------------------------------------------------------------------------
// Platform bring-up

/// Virtual addresses of the mapped device pages (direct map + physical).
pub struct Mmio {
    pub lapic: Option<u64>,
    pub ioapics: [Option<u64>; MAX_IOAPICS],
    pub hpet: Option<u64>,
    /// Device pages that could not be mapped (reported, never fatal).
    pub failed: usize,
}

/// CPUID 0x80000008 `MAXPHYADDR`; 36 (the PAE minimum) when the leaf is absent.
fn physical_address_bits() -> u32 {
    if cpuid_count(0x8000_0000, 0).eax >= 0x8000_0008 {
        (cpuid_count(0x8000_0008, 0).eax & 0xff).clamp(32, 52)
    } else {
        36
    }
}

/// Map the ACPI-described device pages uncached before CR3 publication.
pub fn map_mmio(
    boot: &BootInfo,
    allocator: &mut Allocator<'_>,
    tables: &mut paging::Tables,
    prepared: &apic::Prepared,
    acpi: &Acpi,
    noapic: bool,
) -> Mmio {
    let mut mmio = Mmio {
        lapic: None,
        ioapics: [None; MAX_IOAPICS],
        hpet: None,
        failed: 0,
    };
    let mut done = [0u64; MAX_IOAPICS + 2];
    let mut mapped = 0;
    // A device page above the CPU's physical-address width would produce a PTE
    // with reserved bits set and fault on first use: report it as absent.
    let width = physical_address_bits();
    let mut map = |physical: u64, mmio_failed: &mut usize| -> Option<u64> {
        let page = physical & !0xfff;
        if !intc::physical_address_valid(page | 0xfff, width) {
            *mmio_failed += 1;
            return None;
        }
        if !done[..mapped].contains(&page) {
            if tables.map_mmio(boot, allocator, page).is_err() {
                *mmio_failed += 1;
                return None;
            }
            done[mapped] = page;
            mapped += 1;
        }
        boot.direct_map.checked_add(physical)
    };
    if prepared.lapic_phys != 0 {
        mmio.lapic = map(prepared.lapic_phys, &mut mmio.failed);
    }
    if !noapic && let Some(madt) = &acpi.madt {
        for (slot, io) in mmio.ioapics.iter_mut().zip(madt.ioapics()) {
            *slot = map(u64::from(io.address), &mut mmio.failed);
        }
    }
    if let Some(hpet) = &acpi.hpet {
        mmio.hpet = map(hpet.address, &mut mmio.failed);
    }
    mmio
}

/// Boot options (Linux early parameters of the same names).
#[derive(Clone, Copy)]
pub struct Options {
    pub nolapic: bool,
    pub noapic: bool,
    pub nox2apic: bool,
}
impl Options {
    #[must_use]
    pub fn from_boot(boot: &BootInfo) -> Self {
        Self {
            nolapic: boot.has_option(b"nolapic"),
            noapic: boot.has_option(b"noapic"),
            nox2apic: boot.has_option(b"nox2apic"),
        }
    }
}

struct TscResult {
    khz: u64,
    source: TscSource,
    refined: bool,
    reference_khz: u64,
    /// Quick-PIT attempts made (0 when another source decided first).
    pit_tries: u32,
}

fn vendor_is_intel() -> bool {
    CpuId::new()
        .get_vendor_info()
        .is_some_and(|v| v.as_str() == "GenuineIntel")
}

/// TSC frequency in Linux's order: CPUID 0x15, CPUID 0x16, quick PIT, then the
/// HPET / PM-timer reference alone; PIT and CPUID results are refined (within
/// 1%) against the reference, CPUID 0x15 with a reported crystal is final.
fn calibrate_tsc(has_pit: bool, reference: Option<Reference>) -> Option<TscResult> {
    let intel = vendor_is_intel();
    let max_leaf = cpuid_count(0, 0).eax;
    let base_mhz = (max_leaf >= 0x16).then(|| cpuid_count(0x16, 0).eax & 0xffff);
    let early = if max_leaf >= 0x15 {
        let leaf = cpuid_count(0x15, 0);
        time::tsc_khz_from_cpuid15(intel, leaf.eax, leaf.ebx, leaf.ecx, base_mhz, false)
    } else {
        None
    };
    let mut pit_tries = 0u32;
    let (mut khz, source) = if let Some(c) = early {
        if c.known_freq {
            return Some(TscResult {
                khz: c.tsc_khz,
                source: TscSource::Cpuid15,
                refined: false,
                reference_khz: 0,
                pit_tries: 0,
            });
        }
        (c.tsc_khz, TscSource::Cpuid15)
    } else if let Some(k) = base_mhz.and_then(|m| time::cpu_khz_from_cpuid16(intel, m)) {
        (k, TscSource::Cpuid16)
    } else if let Some(k) = (0..PIT_ATTEMPTS)
        .take_while(|_| has_pit)
        .find_map(|attempt| {
            pit_tries = attempt + 1;
            quick_pit_calibrate()
        })
    {
        (k, TscSource::PitQuick)
    } else {
        // pit_hpet_ptimer_calibrate_cpu without the PIT: reference alone.
        let reference = reference?;
        let source = match reference {
            Reference::Hpet(_) => TscSource::Hpet,
            Reference::PmTimer { .. } => TscSource::PmTimer,
        };
        // Up to three runs, keeping the lowest (Linux's choice); a disturbed run is
        // retried, a stuck reference ends the attempt at once.
        let mut best: Option<u64> = None;
        for _ in 0..3 {
            match calibrate_against(&reference) {
                Ok(k) => best = Some(best.map_or(k, |b| b.min(k))),
                Err(ReferenceError::Disturbed) => {}
                Err(ReferenceError::Stuck) => break,
            }
        }
        return Some(TscResult {
            khz: best?,
            source,
            refined: true,
            reference_khz: best?,
            pit_tries,
        });
    };
    // tsc_refine_calibration_work: accept the reference only within 1%.
    TSC_KHZ.store(khz, Ordering::Relaxed); // the disturbance threshold uses it
    let mut refined = false;
    let mut reference_khz = 0;
    if let Some(reference) = reference
        && let Ok(r) = calibrate_against(&reference)
    {
        reference_khz = r;
        if time::refine_is_acceptable(khz, r) {
            khz = r;
            refined = true;
        }
    }
    Some(TscResult {
        khz,
        source,
        refined,
        reference_khz,
        pit_tries,
    })
}

/// LAPIC timer bus clocks per tick, calibrated against the TSC for 50 ms with
/// divider 16 (`calibrate_APIC_clock` uses the tick IRQ over 100 ms instead).
fn calibrate_lapic_timer() -> Option<u64> {
    apic::lapic_write(intc::REG_TIMER_DIVIDE, intc::TIMER_DIVIDE_BY_16);
    apic::lapic_write(
        intc::REG_LVT_TIMER,
        intc::lvt_timer(TimerMode::OneShot, true),
    );
    apic::lapic_write(intc::REG_TIMER_INITIAL, u32::MAX);
    let window = tsc_khz() * 50;
    let start = rdtsc();
    while rdtsc().wrapping_sub(start) < window {
        core::hint::spin_loop();
    }
    let current = apic::lapic_read(intc::REG_TIMER_CURRENT);
    let elapsed = rdtsc().wrapping_sub(start);
    apic::lapic_write(intc::REG_TIMER_INITIAL, 0);
    let period = time::lapic_period_from_tsc(u64::from(u32::MAX - current), elapsed, tsc_khz())?;
    // Linux rejects a period below 1000000/HZ clocks as a broken timer.
    (period >= 1_000_000 / HZ).then_some(period)
}

/// Facts for the boot records that `init` establishes.
pub struct Report {
    pub apic_mode: ApicMode,
    pub event: &'static str,
    pub ioapic_timer: Option<bool>,
}

fn event_name() -> &'static str {
    match EVENT.load(Ordering::Relaxed) {
        EVENT_PIT => "pit-periodic",
        EVENT_LAPIC_ONESHOT => "lapic-oneshot",
        EVENT_LAPIC_DEADLINE => "lapic-deadline",
        _ => "none",
    }
}

/// The interrupt controllers as `init_controllers` left them.
struct Controllers {
    has_pic: bool,
    ioapics: Option<apic::Ioapics>,
    lapic: Option<apic::LapicInfo>,
    mode: ApicMode,
}

/// 8259, IOAPICs (all pins masked) and the local APIC, in Linux's order.
///
/// # Safety
/// As [`init`].
unsafe fn init_controllers(
    prepared: &apic::Prepared,
    acpi: &Acpi,
    mmio: &Mmio,
    options: Options,
) -> Result<Controllers, Error> {
    let fadt: Fadt = acpi.fadt.unwrap_or_default();
    // Legacy PIC presence: PCAT_COMPAT skips the probe (probe_8259A); a
    // hardware-reduced platform has none. The PIT is assumed with the PIC.
    let has_pic = !fadt.hardware_reduced && intc::has_legacy_pic(acpi.legacy_pic, apic::pic_probe);
    if has_pic {
        apic::pic_init_masked();
    }
    let noapic = options.noapic || prepared.plan.mode == ApicMode::Disabled;
    let ioapics = match (acpi.madt.as_ref(), noapic) {
        // SAFETY: each Some(va) in `mmio.ioapics` is the mapped UC page of the
        // MADT IOAPIC at the same index; IF clear per this function's contract.
        (Some(m), false) => Some(unsafe { apic::ioapic_init(m, &mmio.ioapics) }),
        _ => None,
    };
    let ioapic_count = ioapics.as_ref().map_or(0, apic::Ioapics::count);
    // SAFETY: contract of this function; lapic page mapped iff the plan is xAPIC.
    let lapic = unsafe { apic::init_lapic(prepared, mmio.lapic, ioapic_count != 0) }
        .map_err(|_| Error::Apic)?;
    let mode = apic::mode();
    crate::log!(
        "CHECK apic ok mode={} reason={} id={} version={:#x} maxlvt={} extint={} lapic_base={:#x} madt_lapic={:#x} cpuid_apic_id={} cpu_x2apic={} kvm={} nox2apic={} nolapic={} locked={} pic={} ioapics={} ioapic_pins={} errors={:?}\n",
        mode_name(mode),
        prepared.plan.reason,
        lapic.as_ref().map_or(0, |l| l.id),
        lapic.as_ref().map_or(0, |l| l.version),
        lapic.as_ref().map_or(0, |l| l.max_lvt),
        lapic.as_ref().is_some_and(|l| l.extint_enabled),
        prepared.inputs.base_msr & intc::BASE_ADDRESS,
        prepared.madt_lapic.unwrap_or(0),
        prepared.inputs.bsp_id,
        prepared.inputs.cpu_has_x2apic,
        prepared.hypervisor_kvm,
        options.nox2apic,
        options.nolapic,
        prepared.inputs.hw_locked,
        has_pic,
        ioapic_count,
        ioapics.as_ref().map_or(0, apic::Ioapics::pins_total),
        apic::error_counters()
    );
    Ok(Controllers {
        has_pic,
        ioapics,
        lapic,
        mode,
    })
}

fn mode_name(mode: ApicMode) -> &'static str {
    match mode {
        ApicMode::Disabled => "legacy-pic",
        ApicMode::Xapic => "xapic",
        ApicMode::X2apic => "x2apic",
    }
}

/// HPET reference, TSC calibration, RTC and the published clock.
///
/// # Safety
/// As [`init`].
unsafe fn init_clock(mmio: &Mmio, fadt: Fadt, has_pic: bool) -> Result<(), Error> {
    // SAFETY: `mmio.hpet` is the mapped UC page of the ACPI HPET block.
    let hpet = mmio.hpet.and_then(|va| unsafe { hpet_start(va) });
    let reference = hpet.map(Reference::Hpet).or_else(|| {
        (fadt.pm_timer_port != 0).then_some(Reference::PmTimer {
            port: fadt.pm_timer_port,
            width_bits: if fadt.pm_timer_32bit { 32 } else { 24 },
        })
    });
    let cpuid_tsc = cpuid_count(0x8000_0007, 0).edx & (1 << 8) != 0;
    // Our own sanity floor (Linux has none): no real TSC runs below 100 MHz, so a
    // smaller value means a broken reference, reported instead of published.
    let tsc = calibrate_tsc(has_pic, reference)
        .filter(|t| t.khz >= 100_000)
        .ok_or(Error::Calibration)?;
    TSC_KHZ.store(tsc.khz, Ordering::Relaxed);
    let tsc_start = rdtsc();
    let (wall, rtc_ok) = rtc_read(fadt.century);
    RTC_OK.store(rtc_ok, Ordering::Relaxed);
    // Monotonic time is zero at the TSC sample taken just before the RTC read;
    // the RTC is whole seconds, so realtime is the RTC second + monotonic.
    let khz = u32::try_from(tsc.khz).map_err(|_| Error::Calibration)?;
    clock_publish(&Clock::new(khz, tsc_start, wall));
    crate::log!(
        "CHECK tsc ok khz={} source={} pit_tries={} refined={} reference_khz={} invariant={} hpet_hz={} pm_timer={:#x} rtc={} wall={}\n",
        tsc.khz,
        tsc.source.name(),
        tsc.pit_tries,
        tsc.refined,
        tsc.reference_khz,
        cpuid_tsc,
        hpet.map_or(0, |h| 1_000_000_000_000_000 / u64::from(h.period_fs)),
        fadt.pm_timer_port,
        rtc_ok,
        wall
    );
    Ok(())
}

/// Bring up the interrupt controllers, TSC clock and tick. Prints the `CHECK`
/// records for the discovered topology, mode, frequencies and tick.
///
/// # Errors
/// No TSC, no calibration source, an unestablishable APIC mode, no usable tick
/// device, or a tick that never arrives.
///
/// # Safety
/// BSP at CPL0, IF clear, after `Tables::activate` (the device pages in `mmio`
/// are mapped) and `cpu::install_descriptors`. Called once; no AP, no DMA.
pub unsafe fn init(
    prepared: &apic::Prepared,
    acpi: &Acpi,
    mmio: &Mmio,
    options: Options,
) -> Result<Report, Error> {
    if !CpuId::new().get_feature_info().is_some_and(|f| f.has_tsc()) {
        return Err(Error::NoTsc);
    }
    // SAFETY: this function's contract.
    let controllers = unsafe { init_controllers(prepared, acpi, mmio, options) }?;
    let Controllers {
        has_pic,
        ioapics,
        lapic,
        mode: apic_mode,
    } = controllers;
    // SAFETY: this function's contract.
    unsafe { init_clock(mmio, acpi.fadt.unwrap_or_default(), has_pic) }?;

    // Tick source.
    let mut ioapic_timer = None;
    let kind = if apic_mode == ApicMode::Disabled {
        if !has_pic {
            return Err(Error::NoLegacyPic);
        }
        EVENT_PIT
    } else {
        // IRQ0 through the IOAPIC proves routing (check_timer's first attempt).
        if let (Some(set), Some(m), true) = (&ioapics, acpi.madt.as_ref(), has_pic) {
            let destination = lapic.as_ref().map_or(0, |l| l.id);
            ioapic_timer = Some(
                u8::try_from(destination).is_ok_and(|d| d < 255)
                    // SAFETY: IF clear on entry; set is initialized above.
                    && unsafe { ioapic_irq0_check(set, m, u8::try_from(destination).unwrap_or(0)) },
            );
        }
        if CpuId::new()
            .get_feature_info()
            .is_some_and(|f| f.has_tsc_deadline())
        {
            EVENT_LAPIC_DEADLINE
        } else {
            let period = calibrate_lapic_timer().ok_or(Error::Clockevent)?;
            LAPIC_MULT.store(time::lapic_mult(period), Ordering::Relaxed);
            crate::log!(
                "CHECK lapic-timer ok bus_khz={} divider=16 period_clocks={}\n",
                period * HZ / 1000,
                period
            );
            EVENT_LAPIC_ONESHOT
        }
    };
    EVENT.store(kind, Ordering::Release);
    start_tick(kind);
    let delivered = wait_for_ticks(3, 100);
    crate::log!(
        "CHECK clockevent {} event={} hz={} mult={}\n",
        if delivered { "ok" } else { "stalled" },
        event_name(),
        HZ,
        LAPIC_MULT.load(Ordering::Relaxed),
    );
    TICK_VERIFIED.store(delivered, Ordering::Relaxed);
    if !delivered {
        return Err(Error::TickStalled);
    }
    Ok(Report {
        apic_mode,
        event: event_name(),
        ioapic_timer,
    })
}

/// Program and start the periodic tick on the chosen device.
fn start_tick(kind: u8) {
    cpu::timer_transaction(|| {
        TICKS.store(0, Ordering::Relaxed);
        TICK_ON.store(true, Ordering::Relaxed);
        match kind {
            EVENT_PIT => rearm(0),
            EVENT_LAPIC_DEADLINE => {
                NEXT_TICK_NS.store(ktime_get_ns() + TICK_NSEC, Ordering::Relaxed);
                rearm(ktime_get_ns());
            }
            _ => {
                apic::lapic_write(intc::REG_TIMER_DIVIDE, intc::TIMER_DIVIDE_BY_16);
                NEXT_TICK_NS.store(ktime_get_ns() + TICK_NSEC, Ordering::Relaxed);
                rearm(ktime_get_ns());
            }
        }
    });
}

/// Enable interrupts and spin on the TSC until `count` ticks arrived or
/// `limit_ms` passed; IF is 0 on return.
pub fn wait_for_ticks(count: u64, limit_ms: u64) -> bool {
    let start_ticks = ticks();
    let window = tsc_khz() * limit_ms;
    let start = rdtsc();
    cpu::interrupts_on();
    let mut ok = false;
    while rdtsc().wrapping_sub(start) < window {
        if ticks() - start_ticks >= count {
            ok = true;
            break;
        }
        core::hint::spin_loop();
    }
    cpu::interrupts_off();
    ok
}

/// Route PIT IRQ0 through the IOAPIC pin the MADT names and count deliveries
/// over 20 ms (Linux `timer_irq_works` waits ~10 ticks). Leaves the pin and the
/// PIT masked/stopped.
///
/// # Safety
/// BSP, IF clear, LAPIC enabled, `set` initialised, `destination` the BSP id.
unsafe fn ioapic_irq0_check(set: &apic::Ioapics, madt: &Madt, destination: u8) -> bool {
    let Some(route) = madt.isa_route(0) else {
        return false;
    };
    // SAFETY: contract of this function.
    let Some((index, pin)) = (unsafe { set.route(route, ISA_IRQ_VECTOR_BASE, destination) }) else {
        return false;
    };
    let before = IRQ0.load(Ordering::Relaxed);
    pit_start_periodic();
    cpu::interrupts_on();
    let window = tsc_khz() * 20;
    let start = rdtsc();
    while rdtsc().wrapping_sub(start) < window {
        core::hint::spin_loop();
    }
    cpu::interrupts_off();
    pit_stop();
    // SAFETY: (index, pin) came from `route`.
    unsafe { set.mask(index, pin) };
    IRQ0.load(Ordering::Relaxed) - before >= 3
}

// ---------------------------------------------------------------------------
// Tick-period observation (used by the IRQ-guard and mask proofs)

/// Spin on the TSC for `periods` tick periods and return the number of tick
/// interrupts delivered meanwhile. Does not change IF: with IF clear it measures
/// a blocked interval (delta 0), with IF set it counts deliveries. The finite
/// bound is a failure limit, not an oracle.
///
/// # Errors
/// [`Error::Stalled`] if the TSC does not advance.
pub fn poll_periods(periods: u64) -> Result<u64, Error> {
    let before = ticks();
    let span = tsc_khz() * (periods * TICK_NSEC / NSEC_PER_MSEC);
    let start = rdtsc();
    let mut spins = 0u64;
    loop {
        let elapsed = rdtsc().wrapping_sub(start);
        if elapsed >= span {
            return Ok(ticks() - before);
        }
        spins += 1;
        if spins > 4_000_000_000 {
            return Err(Error::Stalled);
        }
        core::hint::spin_loop();
    }
}

/// [`poll_periods`] with interrupts enabled for the duration; IF is 0 on return.
///
/// # Errors
/// As [`poll_periods`].
pub fn observe_periods(periods: u64) -> Result<u64, Error> {
    cpu::interrupts_on();
    let result = poll_periods(periods);
    cpu::interrupts_off();
    result
}

// ---------------------------------------------------------------------------
// Timekeeping proof

/// What [`timekeeping_selftest`] measured.
pub struct TimekeepingProof {
    pub waited_ns: u64,
    pub real_minus_mono_ns: i64,
    pub boot_minus_mono_ns: u64,
    pub monotonic_steps: u64,
}

/// Exercise the getters and the deadline wait: a 20 ms sleep must take at least
/// 20 ms and (on a loaded host) not absurdly longer; monotonic never goes
/// backwards across many reads; realtime advances in step with monotonic;
/// boottime equals monotonic.
#[must_use]
pub fn timekeeping_selftest() -> Option<TimekeepingProof> {
    let mut last = ktime_get_ns();
    let mut steps = 0;
    for _ in 0..1000 {
        let now = ktime_get_ns();
        if now < last {
            return None;
        }
        steps += u64::from(now > last);
        last = now;
    }
    // One TSC sample feeds both clocks, so their relation is exact rather than
    // dependent on how long two separate reads take.
    let sample = || {
        let clock = clock_load();
        let tsc = rdtsc();
        (clock.monotonic_ns(tsc), clock.realtime(tsc))
    };
    let (mono_start, real_start) = sample();
    sleep_ns(20 * NSEC_PER_MSEC);
    let (mono_end, real_end) = sample();
    let boot = ktime_get_boottime_ns();
    let real_public = ktime_get_real();
    let waited = mono_end.checked_sub(mono_start)?;
    let real_delta = (i128::from(real_end.sec) - i128::from(real_start.sec)) * 1_000_000_000
        + i128::from(real_end.nsec)
        - i128::from(real_start.nsec);
    let skew = i64::try_from(real_delta - i128::from(waited)).ok()?;
    // 20 ms minimum (the deadline wait never returns early); 500 ms ceiling is
    // a failure limit for host scheduling noise, not a latency claim.
    let ok = (20 * NSEC_PER_MSEC..=500 * NSEC_PER_MSEC).contains(&waited)
        && skew == 0
        && (real_public.sec, real_public.nsec) >= (real_end.sec, real_end.nsec)
        && boot >= mono_end
        && boot - mono_end < NSEC_PER_MSEC;
    ok.then_some(TimekeepingProof {
        waited_ns: waited,
        real_minus_mono_ns: skew,
        boot_minus_mono_ns: boot - mono_end,
        monotonic_steps: steps,
    })
}
