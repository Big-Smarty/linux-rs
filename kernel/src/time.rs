// SPDX-License-Identifier: GPL-2.0-only
//! Pure time arithmetic shared by the freestanding timekeeping code and its host
//! tests: mult/shift conversions, TSC/HPET/PM-timer calibration math, CMOS RTC
//! decoding and the monotonic/realtime/boottime clock core.
//!
//! Provenance (Linux 6.18.57, GPL-2.0-only; Rust re-expressions, not line ports):
//! - `clocks_calc_mult_shift`: kernel/time/clocksource.c:59-87.
//! - `Cyc2Ns`: arch/x86/kernel/tsc.c:126-185 (`__cycles_2_ns`, `__set_cyc2ns_scale`).
//! - `tsc_khz_from_cpuid15`/`cpu_khz_from_cpuid16`: tsc.c:663-750.
//! - `pit_quick_khz`/`calc_hpet_ref`/`calc_pmtimer_ref`/`refine_is_acceptable`:
//!   tsc.c:380-412, 640-660 and the 1% window of `tsc_refine_calibration_work`
//!   (tsc.c:1316-1390).
//! - `Calibration`: the order of `native_calibrate_cpu_early` /
//!   `pit_hpet_ptimer_calibrate_cpu` (tsc.c:758-935).
//! - `rtc_to_time64`/`mktime64`: drivers/rtc/rtc-mc146818-lib.c:154-197 with the
//!   x86 `RTC_ALWAYS_BCD` and kernel/time/time.c:449 `mktime64`.
//! - Lapic clockevent scaling: arch/x86/kernel/apic/apic.c:735-746 (`div_sc`).
//!
//! No unsafe code, no allocation; every conversion is exact in `u128`.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "the conversions deliberately mirror Linux's fixed-width C arithmetic (u32 mult, u64 ns, wrapping mktime64); each narrowing is bounded by the preceding mask, shift or range check"
)]

/// Reference-configuration tick rate (`CONFIG_HZ=1000`).
pub const HZ: u64 = 1000;
pub const NSEC_PER_SEC: u64 = 1_000_000_000;
pub const NSEC_PER_MSEC: u64 = 1_000_000;
/// `TICK_NSEC` for `HZ=1000`.
pub const TICK_NSEC: u64 = NSEC_PER_SEC / HZ;
/// 8254 input clock (include/linux/timex.h `PIT_TICK_RATE`).
pub const PIT_TICK_RATE: u64 = 1_193_182;
/// ACPI PM timer frequency (`drivers/clocksource/acpi_pm.c`: `PMTMR_TICKS_PER_SEC`).
pub const PMTMR_TICKS_PER_SEC: u64 = 3_579_545;
/// LAPIC timer divider programmed by Linux (`APIC_DIVISOR`, apic.c:259).
pub const APIC_DIVISOR: u64 = 16;

/// `(a * mul) >> shift` with a 128-bit intermediate (`mul_u64_u32_shr`).
#[must_use]
pub fn mul_u64_u32_shr(a: u64, mul: u32, shift: u32) -> u64 {
    ((u128::from(a) * u128::from(mul)) >> shift) as u64
}

/// `(ticks << shift) / nsec` (`div_sc`, include/linux/clockchips.h).
#[must_use]
pub fn div_sc(ticks: u64, nsec: u64, shift: u32) -> u64 {
    if nsec == 0 {
        return 0;
    }
    ((u128::from(ticks) << shift) / u128::from(nsec)) as u64
}

/// Port of `clocks_calc_mult_shift`: the best-accuracy `(mult, shift)` pair
/// with `cycles * mult >> shift` converting `from` Hz units to `to` units,
/// valid for at least `maxsec` seconds of input.
#[must_use]
pub fn clocks_calc_mult_shift(from: u32, to: u32, maxsec: u32) -> (u32, u32) {
    let mut sftacc = 32u32;
    let mut tmp = (u64::from(maxsec) * u64::from(from)) >> 32;
    while tmp != 0 {
        tmp >>= 1;
        sftacc -= 1;
    }
    let mut shift = 32;
    let mut mult = 0u64;
    while shift > 0 {
        mult = (u64::from(to) << shift) + u64::from(from) / 2;
        mult /= u64::from(from.max(1));
        if (mult >> sftacc) == 0 {
            break;
        }
        shift -= 1;
    }
    (mult as u32, shift)
}

/// Per-CPU TSC-to-nanoseconds scale (`struct cyc2ns_data`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cyc2Ns {
    pub mul: u32,
    pub shift: u32,
    pub offset: u64,
}

impl Cyc2Ns {
    /// Scale for a TSC of `khz` such that `ns(tsc_now) == ns_now` (continuity
    /// across a rescale, `__set_cyc2ns_scale`). `khz` must be non-zero.
    #[must_use]
    pub fn new(khz: u32, tsc_now: u64, ns_now: u64) -> Self {
        let (mut mul, mut shift) = clocks_calc_mult_shift(khz, NSEC_PER_MSEC as u32, 0);
        // Exported to perf as <= 31 (tsc.c:166-169).
        if shift == 32 {
            shift = 31;
            mul >>= 1;
        }
        Self {
            mul,
            shift,
            offset: ns_now.wrapping_sub(mul_u64_u32_shr(tsc_now, mul, shift)),
        }
    }

    #[must_use]
    pub fn ns(&self, tsc: u64) -> u64 {
        self.offset
            .wrapping_add(mul_u64_u32_shr(tsc, self.mul, self.shift))
    }
}

/// TSC frequency from CPUID leaf 0x15 (and 0x16 for the crystal fallback),
/// valid only for Intel (`native_calibrate_tsc` returns 0 elsewhere).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cpuid15 {
    pub tsc_khz: u64,
    pub crystal_khz: u64,
    /// `X86_FEATURE_TSC_KNOWN_FREQ`: the crystal frequency was reported.
    pub known_freq: bool,
}

/// `native_calibrate_tsc` for the given leaf registers. `base_mhz` is leaf 0x16
/// EAX when that leaf exists (`cpuid_level >= 0x16`), `goldmont_d` the Denverton
/// hard-coded 25 MHz crystal.
#[must_use]
pub fn tsc_khz_from_cpuid15(
    intel: bool,
    eax_denominator: u32,
    ebx_numerator: u32,
    ecx_hz: u32,
    base_mhz: Option<u32>,
    goldmont_d: bool,
) -> Option<Cpuid15> {
    if !intel || eax_denominator == 0 || ebx_numerator == 0 {
        return None;
    }
    let mut crystal_khz = u64::from(ecx_hz / 1000);
    if crystal_khz == 0 && goldmont_d {
        crystal_khz = 25_000;
    }
    let known_freq = crystal_khz != 0;
    if crystal_khz == 0
        && let Some(base) = base_mhz
    {
        crystal_khz =
            u64::from(base) * 1000 * u64::from(eax_denominator) / u64::from(ebx_numerator);
    }
    if crystal_khz == 0 {
        return None;
    }
    Some(Cpuid15 {
        tsc_khz: crystal_khz * u64::from(ebx_numerator) / u64::from(eax_denominator),
        crystal_khz,
        known_freq,
    })
}

/// `cpu_khz_from_cpuid` (Intel leaf 0x16 EAX base MHz).
#[must_use]
pub fn cpu_khz_from_cpuid16(intel: bool, base_mhz: u32) -> Option<u64> {
    (intel && base_mhz != 0).then(|| u64::from(base_mhz) * 1000)
}

/// Quick PIT calibration result: `delta` TSC cycles over `iterations` counter
/// MSB steps of 256 PIT ticks each (`quick_pit_calibrate` success path).
#[must_use]
pub fn pit_quick_khz(delta_tsc: u64, iterations: u64) -> Option<u64> {
    let divisor = u128::from(iterations) * 256 * 1000;
    (divisor != 0).then(|| ((u128::from(delta_tsc) * u128::from(PIT_TICK_RATE)) / divisor) as u64)
}

/// `calc_hpet_ref`: TSC kHz from a TSC delta over a 32-bit HPET counter delta
/// (`period_fs` is `HPET_PERIOD` in femtoseconds). Wraps like Linux.
#[must_use]
pub fn calc_hpet_ref(delta_tsc: u64, hpet1: u32, hpet2: u32, period_fs: u32) -> Option<u64> {
    let ticks = u64::from(hpet2.wrapping_sub(hpet1));
    // Linux: tmp = ticks * period_fs / 1e6 (ns); khz = delta * 1e6 / tmp.
    let ns = u128::from(ticks) * u128::from(period_fs) / 1_000_000;
    (ns != 0).then(|| ((u128::from(delta_tsc) * 1_000_000) / ns) as u64)
}

/// `calc_pmtimer_ref`: as above for the ACPI PM timer, `width_bits` 24 or 32.
#[must_use]
pub fn calc_pmtimer_ref(delta_tsc: u64, pm1: u32, pm2: u32, width_bits: u32) -> Option<u64> {
    if pm1 == 0 && pm2 == 0 {
        return None;
    }
    let mask: u64 = if width_bits >= 32 {
        u64::from(u32::MAX)
    } else {
        (1 << width_bits) - 1
    };
    let ticks = u64::from(pm2).wrapping_sub(u64::from(pm1)) & mask;
    let ns = u128::from(ticks) * 1_000_000_000 / u128::from(PMTMR_TICKS_PER_SEC);
    (ns != 0).then(|| ((u128::from(delta_tsc) * 1_000_000) / ns) as u64)
}

/// `tsc_refine_calibration_work`'s window: the refined value replaces the
/// early one only if within 1% of it.
#[must_use]
pub fn refine_is_acceptable(early_khz: u64, refined_khz: u64) -> bool {
    early_khz.abs_diff(refined_khz) <= early_khz / 100
}

/// Which source produced the TSC frequency, in Linux's order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TscSource {
    /// CPUID 0x15 crystal ratio (Intel).
    Cpuid15,
    /// CPUID 0x16 base frequency (Intel) used as the CPU, then TSC, frequency.
    Cpuid16,
    /// Quick PIT channel-2 calibration (500 ppm).
    PitQuick,
    /// Busy-wait against the HPET main counter (PIT unusable).
    Hpet,
    /// Busy-wait against the ACPI PM timer (PIT and HPET unusable).
    PmTimer,
}
impl TscSource {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Cpuid15 => "cpuid15",
            Self::Cpuid16 => "cpuid16",
            Self::PitQuick => "pit",
            Self::Hpet => "hpet",
            Self::PmTimer => "pmtimer",
        }
    }
}

/// `mktime64` (kernel/time/time.c:449) with the unsigned-int arithmetic of the
/// C original, so a garbage RTC yields the same garbage Linux would.
#[must_use]
pub fn mktime64(year0: u32, mon0: u32, day: u32, hour: u32, min: u32, sec: u32) -> i64 {
    let (mut mon, mut year) = (mon0, year0);
    mon = mon.wrapping_sub(2);
    if 0 >= mon as i32 {
        mon = mon.wrapping_add(12);
        year = year.wrapping_sub(1);
    }
    let days = (year / 4)
        .wrapping_sub(year / 100)
        .wrapping_add(year / 400)
        .wrapping_add(367u32.wrapping_mul(mon) / 12)
        .wrapping_add(day);
    let days = i64::from(days) + i64::from(year.wrapping_mul(365)) - 719_499;
    ((days * 24 + i64::from(hour)) * 60 + i64::from(min)) * 60 + i64::from(sec)
}

#[must_use]
pub fn bcd2bin(value: u8) -> u32 {
    u32::from(value & 0x0f) + u32::from(value >> 4) * 10
}

/// Raw CMOS registers as read by `mc146818_get_time_callback`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RtcRegisters {
    pub seconds: u8,
    pub minutes: u8,
    pub hours: u8,
    pub day: u8,
    pub month: u8,
    pub year: u8,
    /// FADT century register contents, 0 when the FADT has none.
    pub century: u8,
}

/// `mc146818_get_time` followed by `rtc_tm_to_time64`. x86 defines
/// `RTC_ALWAYS_BCD`, so registers are always BCD-decoded whatever the DM bit.
/// A 12-hour-mode RTC is not converted: Linux does not either.
#[must_use]
pub fn rtc_to_time64(regs: RtcRegisters) -> i64 {
    let mut year = bcd2bin(regs.year) as i32;
    let century = bcd2bin(regs.century) as i32;
    if century > 19 {
        year += (century - 19) * 100;
    }
    if year <= 69 {
        year += 100;
    }
    let month = bcd2bin(regs.month) as i32 - 1; // tm_mon
    mktime64(
        (year + 1900) as u32,
        (month + 1) as u32,
        bcd2bin(regs.day),
        bcd2bin(regs.hours),
        bcd2bin(regs.minutes),
        bcd2bin(regs.seconds),
    )
}

/// Scale a nanosecond delta to event-timer ticks (`clockevent_delta2ns`'s
/// inverse): `ns * mult >> 32`, saturating at `u64::MAX`.
#[must_use]
pub fn ns_to_ticks(ns: u64, mult: u64) -> u64 {
    u64::try_from((u128::from(ns) * u128::from(mult)) >> 32).unwrap_or(u64::MAX)
}

/// LAPIC clockevent multiplier: `div_sc(lapic_timer_period / APIC_DIVISOR,
/// TICK_NSEC, 32)` where `period` is bus clocks per tick (apic.c:739).
#[must_use]
pub fn lapic_mult(period: u64) -> u64 {
    div_sc(period / APIC_DIVISOR, TICK_NSEC, 32)
}

/// Bus clocks per `HZ` tick from a calibration run: the one-shot counter fell
/// by `timer_counts` (already divided by [`APIC_DIVISOR`]) while the TSC
/// advanced by `tsc_delta` at `tsc_khz` (`calibrate_APIC_clock`, apic.c:880-890).
#[must_use]
pub fn lapic_period_from_tsc(timer_counts: u64, tsc_delta: u64, tsc_khz: u64) -> Option<u64> {
    if tsc_delta == 0 || tsc_khz == 0 {
        return None;
    }
    // bus clocks per second = counts * 16 * tsc_hz / tsc_delta; per tick: / HZ.
    let per_second =
        u128::from(timer_counts) * u128::from(APIC_DIVISOR) * u128::from(tsc_khz) * 1000
            / u128::from(tsc_delta);
    u64::try_from(per_second / u128::from(HZ)).ok()
}

/// A time value in the Linux `timespec64` shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timespec {
    pub sec: i64,
    pub nsec: u32,
}
impl Timespec {
    #[must_use]
    pub fn from_ns(ns: i128) -> Self {
        let sec = ns.div_euclid(i128::from(NSEC_PER_SEC));
        let nsec = ns.rem_euclid(i128::from(NSEC_PER_SEC));
        Self {
            sec: sec as i64,
            nsec: nsec as u32,
        }
    }
}

/// Monotonic/boottime/realtime clock core over a TSC. The TSC never stops in
/// this kernel (no suspend), so `CLOCK_BOOTTIME` equals `CLOCK_MONOTONIC`, as in
/// Linux before the first suspend. `epoch_real_sec` is the CMOS time sampled
/// at the instant monotonic time was zero (`timekeeping_init`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clock {
    scale: Cyc2Ns,
    epoch_real_sec: i64,
}

impl Clock {
    /// Start the clock: monotonic time is 0 at `tsc_now`.
    #[must_use]
    pub fn new(tsc_khz: u32, tsc_now: u64, epoch_real_sec: i64) -> Self {
        Self {
            scale: Cyc2Ns::new(tsc_khz, tsc_now, 0),
            epoch_real_sec,
        }
    }
    /// Rebuild a clock from stored parts.
    #[must_use]
    pub fn from_parts(scale: Cyc2Ns, epoch_real_sec: i64) -> Self {
        Self {
            scale,
            epoch_real_sec,
        }
    }
    #[must_use]
    pub fn epoch_real_sec(&self) -> i64 {
        self.epoch_real_sec
    }
    /// Change the TSC frequency without a discontinuity at `tsc_now`.
    pub fn rescale(&mut self, tsc_khz: u32, tsc_now: u64) {
        self.scale = Cyc2Ns::new(tsc_khz, tsc_now, self.scale.ns(tsc_now));
    }
    #[must_use]
    pub fn monotonic_ns(&self, tsc: u64) -> u64 {
        self.scale.ns(tsc)
    }
    #[must_use]
    pub fn boottime_ns(&self, tsc: u64) -> u64 {
        self.scale.ns(tsc)
    }
    #[must_use]
    pub fn realtime(&self, tsc: u64) -> Timespec {
        Timespec::from_ns(
            i128::from(self.epoch_real_sec) * i128::from(NSEC_PER_SEC)
                + i128::from(self.scale.ns(tsc)),
        )
    }
    #[must_use]
    pub fn scale(&self) -> Cyc2Ns {
        self.scale
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mult_shift_matches_linux_choice_and_is_accurate() {
        // 1 GHz TSC -> 1 ns per cycle: mult/shift pair must be exactly 1.0.
        let (mult, shift) = clocks_calc_mult_shift(1_000_000, 1_000_000, 0);
        assert_eq!((u64::from(mult), shift), (1 << 31, 31));
        for khz in [
            800_000u32, 1_000_000, 2_445_398, 3_000_000, 4_500_000, 5_700_000, 24_000,
        ] {
            let c = Cyc2Ns::new(khz, 0, 0);
            assert!(c.shift <= 31);
            // One second of cycles is one second within 0.5 ppm.
            let ns = c.ns(u64::from(khz) * 1000);
            let error = ns.abs_diff(NSEC_PER_SEC);
            assert!(error < 500, "{khz}: {ns}");
            // An hour does not overflow.
            let hour = c.ns(u64::from(khz) * 1000 * 3600);
            assert!(hour.abs_diff(3600 * NSEC_PER_SEC) < 3600 * 500);
        }
        // Known-good vector: 3 GHz => mult/2^shift = 1/3 ns.
        let (mult, shift) = clocks_calc_mult_shift(3_000_000, 1_000_000, 0);
        assert_eq!((mult, shift), (1_431_655_765, 32));
    }

    #[test]
    fn rescale_is_continuous() {
        let mut c = Clock::new(3_000_000, 1_000, 1_700_000_000);
        let t = 9_000_000_000u64;
        let before = c.monotonic_ns(t);
        c.rescale(2_999_700, t);
        assert_eq!(c.monotonic_ns(t), before);
        // A slower TSC means more nanoseconds per cycle.
        assert!(c.monotonic_ns(t + 3_000_000_000) > before + NSEC_PER_SEC);
        assert_eq!(c.boottime_ns(t), c.monotonic_ns(t));
    }

    #[test]
    fn realtime_is_epoch_plus_monotonic() {
        let c = Clock::new(2_000_000, 500, 1_000);
        assert_eq!(
            c.realtime(500),
            Timespec {
                sec: 1_000,
                nsec: 0
            }
        );
        let later = c.realtime(500 + 3_000_000_000);
        assert_eq!(later.sec, 1_001);
        assert!((i64::from(later.nsec) - 500_000_000).abs() < 1_000);
        assert_eq!(
            Timespec::from_ns(-1),
            Timespec {
                sec: -1,
                nsec: 999_999_999
            }
        );
    }

    #[test]
    fn cpuid15_follows_linux() {
        // Skylake-style: crystal 0 -> derived from leaf 0x16 base 2600 MHz, ratio 188/2.
        let r = tsc_khz_from_cpuid15(true, 2, 188, 0, Some(2600), false).unwrap();
        assert_eq!(r.crystal_khz, 2600 * 1000 * 2 / 188);
        assert!(!r.known_freq);
        // Crystal reported: 24 MHz * 166 / 2.
        let r = tsc_khz_from_cpuid15(true, 2, 166, 24_000_000, None, false).unwrap();
        assert_eq!((r.tsc_khz, r.known_freq), (1_992_000, true));
        // Not Intel, zero ratio, or nothing to derive a crystal from.
        assert_eq!(
            tsc_khz_from_cpuid15(false, 2, 166, 24_000_000, None, false),
            None
        );
        assert_eq!(
            tsc_khz_from_cpuid15(true, 0, 166, 24_000_000, None, false),
            None
        );
        assert_eq!(
            tsc_khz_from_cpuid15(true, 2, 0, 24_000_000, None, false),
            None
        );
        assert_eq!(tsc_khz_from_cpuid15(true, 2, 166, 0, None, false), None);
        // Denverton hard-codes 25 MHz.
        assert_eq!(
            tsc_khz_from_cpuid15(true, 1, 88, 0, None, true)
                .unwrap()
                .tsc_khz,
            2_200_000
        );
        assert_eq!(cpu_khz_from_cpuid16(true, 3400), Some(3_400_000));
        assert_eq!(cpu_khz_from_cpuid16(true, 0), None);
        assert_eq!(cpu_khz_from_cpuid16(false, 3400), None);
    }

    #[test]
    fn reference_timer_math() {
        // 3 GHz TSC over 8,388,608 HPET ticks of 41.666666 ns (24 MHz) = 0.349525 s.
        let period_fs = 41_666_667;
        let hpet1 = 0xffff_0000u32;
        let hpet2 = hpet1.wrapping_add(8_388_608);
        let ns = 8_388_608u64 * u64::from(period_fs) / 1_000_000;
        let delta = 3_000_000u64 * ns / 1_000_000;
        let khz = calc_hpet_ref(delta, hpet1, hpet2, period_fs).unwrap();
        assert!(khz.abs_diff(3_000_000) < 3, "{khz}");
        assert_eq!(calc_hpet_ref(1, 5, 5, period_fs), None);
        // PM timer: 24-bit wrap, 3.579545 MHz, 1,789,772 ticks = 0.5 s.
        let pm1 = 0x00ff_ff00u32;
        let pm2 = (pm1 + 1_789_772) & 0xff_ffff;
        let khz = calc_pmtimer_ref(1_500_000_000, pm1, pm2, 24).unwrap();
        assert!(khz.abs_diff(3_000_000) < 5, "{khz}");
        assert_eq!(calc_pmtimer_ref(1, 0, 0, 24), None);
        // 32-bit width does not mask to 24 bits.
        assert!(calc_pmtimer_ref(1_500_000_000, 0, 0x0100_0000 + 1_789_772, 32).is_some());
        // PIT: 2^16 ticks of the counter MSB walk = 256 * i PIT ticks.
        let i = 20u64;
        let delta = 3_000_000_000u64 * i * 256 / PIT_TICK_RATE;
        let khz = pit_quick_khz(delta, i).unwrap();
        assert!(khz.abs_diff(3_000_000) < 3, "{khz}");
        assert_eq!(pit_quick_khz(1, 0), None);
    }

    #[test]
    fn refine_window_is_one_percent() {
        assert!(refine_is_acceptable(3_000_000, 3_029_999));
        assert!(refine_is_acceptable(3_000_000, 2_970_000));
        assert!(!refine_is_acceptable(3_000_000, 3_030_001));
        assert!(!refine_is_acceptable(3_000_000, 2_969_999));
    }

    #[test]
    fn mktime_and_rtc_decoding() {
        assert_eq!(mktime64(1970, 1, 1, 0, 0, 0), 0);
        assert_eq!(mktime64(2000, 3, 1, 0, 0, 0), 951_868_800);
        assert_eq!(mktime64(2024, 2, 29, 12, 34, 56), 1_709_210_096);
        assert_eq!(mktime64(2038, 1, 19, 3, 14, 8), 2_147_483_648);
        // Leap-second 60 and 24:00 are carried like Linux.
        assert_eq!(mktime64(1970, 1, 1, 0, 0, 60), 60);
        assert_eq!(mktime64(1970, 1, 1, 24, 0, 0), 86_400);
        let bcd = |regs: [u8; 7]| {
            rtc_to_time64(RtcRegisters {
                seconds: regs[0],
                minutes: regs[1],
                hours: regs[2],
                day: regs[3],
                month: regs[4],
                year: regs[5],
                century: regs[6],
            })
        };
        // 2024-02-29 12:34:56 with and without the FADT century register.
        assert_eq!(
            bcd([0x56, 0x34, 0x12, 0x29, 0x02, 0x24, 0x20]),
            1_709_210_096
        );
        assert_eq!(
            bcd([0x56, 0x34, 0x12, 0x29, 0x02, 0x24, 0x00]),
            1_709_210_096
        );
        // Years 70..99 are 19xx without a century byte, 20xx/21xx with one.
        assert_eq!(bcd([0, 0, 0, 1, 1, 0x70, 0]), 0);
        assert_eq!(
            bcd([0, 0, 0, 1, 1, 0x00, 0x21]),
            mktime64(2100, 1, 1, 0, 0, 0)
        );
        // Garbage must not panic.
        for v in [0u8, 0x0f, 0x99, 0xaa, 0xff] {
            let _ = bcd([v, v, v, v, v, v, v]);
        }
    }

    #[test]
    fn lapic_scaling() {
        // 100 MHz bus: 100_000 clocks per 1 ms tick; counter runs at /16.
        let period = lapic_period_from_tsc(6_250_000 / 10, 3_000_000_000 / 10, 3_000_000).unwrap();
        assert_eq!(period, 100_000);
        let mult = lapic_mult(period);
        // 1 ms is 6250 counter ticks; 2.5 ms is 15625.
        // Truncating mult/shift conversion, as in Linux: at most one tick low.
        assert!((6249..=6250).contains(&ns_to_ticks(TICK_NSEC, mult)));
        assert!((15_624..=15_625).contains(&ns_to_ticks(2_500_000, mult)));
        assert_eq!(ns_to_ticks(u64::MAX, u64::MAX), u64::MAX);
        assert_eq!(lapic_period_from_tsc(1, 0, 3_000_000), None);
    }
}
