// SPDX-License-Identifier: GPL-2.0-only
//! The kernel-run bare-metal test suite (decision A21), the `baremetal-suite`
//! profile: the user boots this kernel from a separate USB stick, it runs the
//! non-destructive boot proofs, prints a hardware inventory, runs every
//! supported oracle syscall-test group as a fresh `/init` on a fresh rootfs,
//! compares each group's output with the pinned Linux 6.18.57's, and ends on a
//! one-photograph summary screen. There is no keyboard, serial port or disk
//! driver: the screen is the only result channel, so the summary names a digest
//! of the whole captured log and the screen replays the log in pages first.
//!
//! # What the suite never does
//! No storage write (the kernel has no block or filesystem driver), no firmware
//! call (no EFI runtime service, no NVRAM), no network, no DMA, no PCI
//! configuration write beyond the 0xCF8 address register (`pci`), no reboot or
//! power change. The only I/O ports touched are the PCI configuration pair,
//! the ports the timer, PIC/APIC and RTC code already uses at every boot, and
//! (with `qemu-self-test` only, for the harness) COM1 and the debug-exit port.
//!
//! # Deviations from Linux, test profile only
//! * `/init` exiting, being killed, or ending in a kernel stop that the normal
//!   kernel reports as a panic ends only that group's run; Linux's panic text
//!   is still printed and captured for the record. Linux would stop the machine.
//! * Each group is a new process on a new rootfs in the same boot, where the
//!   reference output was recorded one boot per group. The monotonic clock is
//!   therefore older than in the reference runs; no group asserts more than a
//!   two-minute bound, which the suite's run order keeps.
//!
//! # Context and locking
//! Everything here runs on the BSP with interrupts off, outside any group's
//! syscall or fault locks. `RESULTS` and `ARCHIVES` are leaf locks taken
//! only for short copies. A group ends from `init_exited` (syscall or fault
//! path, after it dropped `PROCESS`/`TABLES`) or from `fatal` (a kernel stop:
//! the group is ended only if `userspace::locks_free`, else the suite aborts
//! with its results so far).
//!
//! shortcut: the captured log is one 256 KiB buffer; longer logs keep their
//! first 256 KiB and the summary says how many bytes were dropped. Upgrade with
//! a ring that keeps the tail as well once a storage driver can hold the log.

use crate::{
    boot::BootInfo,
    console, cpu,
    firmware::Acpi,
    log, pci,
    services::{self, IrqMutex},
    timer, userspace,
};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use kernel::suite::{
    self, Fnv64, GROUPS, GroupReport, ORACLE_EXPECTED, Text, UNSUPPORTED, civil_from_unix, hex16,
};
use raw_cpuid::{CpuId, ExtendedFeatures, ExtendedProcessorFeatureIdentifiers};

/// Identifies this build on the summary: set by `xtask baremetal-suite`
/// (`LINUX_RS_BUILD_ID`, the source commit and whether the tree was clean).
const BUILD_ID: &str = match option_env!("LINUX_RS_BUILD_ID") {
    Some(id) => id,
    None => "unversioned",
};
/// How long each replay page stays up when the command line has no
/// `suite_pause_ms=` (the harness passes a small one).
const DEFAULT_PAUSE_MS: usize = 6000;
const CAPTURE_BYTES: usize = 256 * 1024;
const MAX_PROOFS: usize = 40;
/// Inventory facts the summary repeats: cpu, memory, platform, time, display, pci, adapters.
const KEYS: usize = 7;
const NONE: usize = usize::MAX;
const MAX_GROUPS: usize = 8;
/// Extra `suite_groups=` words of the QEMU harness: `/init` modes that end a
/// run abnormally (a SIGSEGV; a syscall Linux has and this kernel does not),
/// proving that a bad group ends only itself. They have no expected output, so
/// they always count as failed.
#[cfg(feature = "qemu-self-test")]
const PROBES: [&str; 2] = ["fault", "io_uring"];
#[cfg(not(feature = "qemu-self-test"))]
const PROBES: [&str; 0] = [];
/// Longest log line kept whole by the replay and the stop-line search.
const LINE_BUFFER: usize = 512;
/// The line the user acts on.
const FINAL_LINE: &str = "linux-rs suite complete - photograph this screen, then hard-reset";

// ---------------------------------------------------------------------------
// The captured log

static CAPTURE: [AtomicU8; CAPTURE_BYTES] = [const { AtomicU8::new(0) }; CAPTURE_BYTES];
/// Bytes offered to [`capture_byte`]; the first `CAPTURE_BYTES` are stored.
static OFFERED: AtomicUsize = AtomicUsize::new(0);
static FROZEN: AtomicBool = AtomicBool::new(false);

/// Every byte written to the console (kernel log and init's output) passes
/// here. Lock-free and reentrant (an exception may print mid-line): a slot is
/// claimed with one `fetch_add`, so concurrent writers never share a slot.
pub fn capture_byte(byte: u8) {
    if FROZEN.load(Ordering::Relaxed) {
        return;
    }
    let index = OFFERED.fetch_add(1, Ordering::Relaxed);
    if let Some(slot) = CAPTURE.get(index) {
        slot.store(byte, Ordering::Relaxed);
    }
}

// The live screen while a group runs. A passing test line is captured but not
// drawn: a scroll redraws the whole framebuffer, and the groups print about
// 700 such lines, so drawing them would cost minutes on a large screen and
// bury everything else. Each one shows as a single `.` instead (a progress
// bar); any other line, and any failing test line, is drawn whole. The replay
// and the summary come from the capture, which has every line.

const HOLD: usize = 160;
const PASSING: &[u8] = b"init: test ";
static HOLD_BUF: [AtomicU8; HOLD] = [const { AtomicU8::new(0) }; HOLD];
/// Bytes of the current line held back (`< HOLD`), not yet drawn.
static HELD: AtomicUsize = AtomicUsize::new(0);
/// The current line was decided to be drawn as it comes.
static DIRECT: AtomicBool = AtomicBool::new(false);

fn flush_held(mut draw: impl FnMut(u8)) {
    let held = HELD.swap(0, Ordering::Relaxed);
    for slot in &HOLD_BUF[..held.min(HOLD)] {
        draw(slot.load(Ordering::Relaxed));
    }
}

/// Route one console byte to the screen: `draw` is called for each byte that
/// is shown now (none, one, or the held-back line plus this byte).
///
/// Lock-free like [`capture_byte`]; a reentrant writer can garble the live
/// screen but never index outside the hold buffer (every index is bounded).
pub fn screen_byte(byte: u8, mut draw: impl FnMut(u8)) {
    if CURRENT.load(Ordering::Relaxed) == NONE {
        draw(byte);
        return;
    }
    if DIRECT.load(Ordering::Relaxed) {
        draw(byte);
        if byte == b'\n' {
            DIRECT.store(false, Ordering::Relaxed);
        }
        return;
    }
    let held = HELD.load(Ordering::Relaxed).min(HOLD - 1);
    if byte == b'\n' {
        let line = |len: usize| (0..len).map(|i| HOLD_BUF[i].load(Ordering::Relaxed));
        let ends_ok = line(held)
            .rev()
            .skip_while(|&b| b == b'\r')
            .take(3)
            .eq(*b"ko ");
        if held >= PASSING.len() && line(PASSING.len()).eq(PASSING.iter().copied()) && ends_ok {
            HELD.store(0, Ordering::Relaxed);
            draw(b'.');
        } else {
            flush_held(&mut draw);
            draw(byte);
        }
        return;
    }
    HOLD_BUF[held].store(byte, Ordering::Relaxed);
    HELD.store(held + 1, Ordering::Relaxed);
    let diverged = held < PASSING.len() && byte != PASSING[held];
    if diverged || held + 1 >= HOLD - 1 {
        flush_held(&mut draw);
        DIRECT.store(true, Ordering::Relaxed);
    }
}

fn stored() -> usize {
    OFFERED.load(Ordering::Relaxed).min(CAPTURE_BYTES)
}

fn dropped() -> usize {
    OFFERED
        .load(Ordering::Relaxed)
        .saturating_sub(CAPTURE_BYTES)
}

fn byte_at(index: usize) -> u8 {
    CAPTURE[index].load(Ordering::Relaxed)
}

/// A heap copy of captured bytes `start..end` (`None` when the heap is full).
fn copy_range(start: usize, end: usize) -> Option<Vec<u8>> {
    let end = end.min(CAPTURE_BYTES);
    let start = start.min(end);
    let mut copy = Vec::new();
    copy.try_reserve_exact(end - start).ok()?;
    for index in start..end {
        copy.push_within_capacity(byte_at(index)).ok()?;
    }
    Some(copy)
}

/// Visit the lines of captured bytes `start..end` (without "\r\n"; a line
/// longer than [`LINE_BUFFER`] is cut and ends in `~`).
fn for_each_line(start: usize, end: usize, mut visit: impl FnMut(&[u8])) {
    let end = end.min(CAPTURE_BYTES);
    let mut line = [0u8; LINE_BUFFER];
    let mut length = 0;
    let mut full = false;
    for index in start..end {
        match byte_at(index) {
            b'\n' => {
                if full {
                    line[length - 1] = b'~';
                }
                let text = &line[..length];
                visit(text.strip_suffix(b"\r").unwrap_or(text));
                (length, full) = (0, false);
            }
            byte if length < line.len() => {
                line[length] = byte;
                length += 1;
            }
            _ => full = true,
        }
    }
    if length > 0 {
        if full {
            line[length - 1] = b'~';
        }
        visit(&line[..length]);
    }
}

/// The last captured line in `start..end` that begins with `prefix`.
fn last_line_with(start: usize, end: usize, prefix: &[u8]) -> Option<Text> {
    let mut last = None;
    for_each_line(start, end, |line| {
        if line.starts_with(prefix) {
            last = Some(Text::new(line));
        }
    });
    last
}

fn digest() -> u64 {
    let mut hash = Fnv64::new();
    for index in 0..stored() {
        hash.update(&[byte_at(index)]);
    }
    hash.finish()
}

// ---------------------------------------------------------------------------
// Results

#[derive(Clone, Copy)]
struct Proof {
    name: &'static str,
    ok: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Cause {
    /// `/init` called `exit_group` or died of a signal (Linux's `exit_code`).
    Exited(u32),
    /// A kernel stop (`FAIL ...`, panic, unimplemented syscall) ended the run.
    Stopped,
}

impl Cause {
    fn describe(self) -> Text {
        match self {
            Self::Exited(0) => Text::from_args(format_args!("init exit 0")),
            Self::Exited(code) if code.trailing_zeros() >= 8 => {
                Text::from_args(format_args!("init exit {}", code >> 8))
            }
            Self::Exited(code) => Text::from_args(format_args!("init signal {}", code & 0x7f)),
            Self::Stopped => Text::from_args(format_args!("kernel stop")),
        }
    }
}

#[derive(Clone, Copy)]
struct GroupRun {
    cause: Cause,
    /// `None` when the heap could not hold a copy of the output to compare.
    report: Option<GroupReport>,
    /// The kernel's last `FAIL` line of the run when it was stopped.
    stop: Option<Text>,
    millis: u64,
}

impl GroupRun {
    fn passed(&self) -> bool {
        self.cause == Cause::Exited(0) && self.report.is_some_and(|report| report.passed())
    }
}

#[derive(Clone, Copy)]
struct Results {
    proofs: [Proof; MAX_PROOFS],
    proof_count: usize,
    proofs_lost: usize,
    /// The groups to run, in order (`suite_groups=` or all of [`GROUPS`]).
    selected: [&'static str; MAX_GROUPS],
    selected_count: usize,
    groups: [Option<GroupRun>; MAX_GROUPS],
    keys: [Text; KEYS],
}

impl Results {
    const fn new() -> Self {
        Self {
            proofs: [Proof {
                name: "",
                ok: false,
            }; MAX_PROOFS],
            proof_count: 0,
            proofs_lost: 0,
            selected: [""; MAX_GROUPS],
            selected_count: 0,
            groups: [None; MAX_GROUPS],
            keys: [Text::EMPTY; KEYS],
        }
    }

    fn proofs(&self) -> &[Proof] {
        &self.proofs[..self.proof_count]
    }

    fn selected(&self) -> &[&'static str] {
        &self.selected[..self.selected_count]
    }

    /// The selected groups with their runs (`None`: not run).
    fn runs(&self) -> impl Iterator<Item = (&'static str, Option<GroupRun>)> + '_ {
        self.selected().iter().copied().zip(self.groups)
    }

    fn select(&mut self, name: &'static str) -> bool {
        let Some(slot) = self.selected.get_mut(self.selected_count) else {
            return false;
        };
        *slot = name;
        self.selected_count += 1;
        true
    }
}

static RESULTS: IrqMutex<Results> = IrqMutex::new(Results::new());
/// Heap copies of the boot modules (the loader's copies are unreadable once the
/// owned tables are active); each group unpacks them again.
static ARCHIVES: IrqMutex<Vec<Vec<u8>>> = IrqMutex::new(Vec::new());
static PAUSE_MS: AtomicUsize = AtomicUsize::new(DEFAULT_PAUSE_MS);

/// Record a boot proof's result (`PROOF <name> PASS|FAIL`) and return it.
pub fn record_proof(name: &'static str, ok: bool) -> bool {
    log!("PROOF {} {}\n", name, if ok { "PASS" } else { "FAIL" });
    let mut results = RESULTS.lock();
    if results.proof_count < MAX_PROOFS {
        let slot = results.proof_count;
        results.proofs[slot] = Proof { name, ok };
        results.proof_count += 1;
    } else {
        results.proofs_lost += 1;
    }
    ok
}

fn key(slot: usize, text: Text) {
    log!("INV {}\n", text);
    RESULTS.lock().keys[slot] = text;
}

// ---------------------------------------------------------------------------
// Boot-time entry points

/// Read the suite options of the kernel command line and say hello.
pub fn begin(boot: &BootInfo) {
    if let Some(ms) = boot
        .option_value(b"suite_pause_ms")
        .and_then(|value| core::str::from_utf8(value).ok())
        .and_then(|value| value.parse::<usize>().ok())
    {
        PAUSE_MS.store(ms, Ordering::Relaxed);
    }
    let mut results = RESULTS.lock();
    match boot.option_value(b"suite_groups") {
        None => {
            for name in GROUPS {
                results.select(name);
            }
        }
        Some(list) => {
            for word in list.split(|&b| b == b',') {
                match GROUPS.iter().chain(&PROBES).find(|g| g.as_bytes() == word) {
                    Some(name) if results.select(name) => {}
                    _ => log!("SUITE ignoring group {}\n", Text::new(word)),
                }
            }
        }
    }
    log!(
        "SUITE start build={} pause_ms={} groups={}\n",
        BUILD_ID,
        PAUSE_MS.load(Ordering::Relaxed),
        results.selected_count
    );
}

/// Copy the boot modules to the heap, before the loader mappings go away.
///
/// # Safety
/// The contract of `BootInfo::module_bytes`: the loader's module storage is
/// still mapped (the loader CR3 is active) and nothing writes it.
pub unsafe fn retain_archives(boot: &BootInfo) -> bool {
    let mut archives = ARCHIVES.lock();
    for index in 0..boot.module_count() {
        let Ok(span) = boot.module_span(index) else {
            return false;
        };
        // SAFETY: the caller's contract; the borrow ends in this iteration.
        let Ok(bytes) = (unsafe { boot.module_bytes(span) }) else {
            return false;
        };
        let mut copy = Vec::new();
        if copy.try_reserve_exact(bytes.len()).is_err() || archives.try_reserve(1).is_err() {
            return false;
        }
        for &byte in bytes {
            let _ = copy.push_within_capacity(byte);
        }
        let _ = archives.push_within_capacity(copy);
    }
    true
}

// ---------------------------------------------------------------------------
// Inventory

/// The names of CPU features this kernel (or its user programs) depends on or
/// reports, present and absent, from CPUID alone.
fn inventory_cpu() {
    let cpuid = CpuId::new();
    let vendor = cpuid.get_vendor_info();
    let brand = cpuid.get_processor_brand_string();
    let vendor = vendor.as_ref().map_or("?", |vendor| vendor.as_str());
    let brand = brand.as_ref().map_or("?", |brand| brand.as_str().trim());
    let Some(info) = cpuid.get_feature_info() else {
        key(0, Text::from_args(format_args!("cpu {vendor} {brand}")));
        return;
    };
    key(
        0,
        Text::from_args(format_args!(
            "cpu {brand}, family {:#x} model {:#x} stepping {}",
            info.family_id(),
            info.model_id(),
            info.stepping_id()
        )),
    );
    log!("INV cpu vendor={}\n", vendor);
    let extended = cpuid.get_extended_feature_info();
    let identifiers = cpuid.get_extended_processor_and_feature_identifiers();
    let power = cpuid.get_advanced_power_mgmt_info();
    let features = [
        ("tsc", info.has_tsc()),
        (
            "invariant-tsc",
            power.is_some_and(|p| p.has_invariant_tsc()),
        ),
        ("tsc-deadline", info.has_tsc_deadline()),
        ("apic", info.has_apic()),
        ("x2apic", info.has_x2apic()),
        ("pat", info.has_pat()),
        ("pge", info.has_pge()),
        ("pcid", info.has_pcid()),
        ("fxsr", info.has_fxsave_fxstor()),
        ("sse2", info.has_sse2()),
        ("xsave", info.has_xsave()),
        ("avx", info.has_avx()),
        ("rdrand", info.has_rdrand()),
        ("hypervisor", info.has_hypervisor()),
        (
            "nx",
            identifiers
                .as_ref()
                .is_some_and(ExtendedProcessorFeatureIdentifiers::has_execute_disable),
        ),
        (
            "1gib-pages",
            identifiers
                .as_ref()
                .is_some_and(ExtendedProcessorFeatureIdentifiers::has_1gib_pages),
        ),
        (
            "fsgsbase",
            extended
                .as_ref()
                .is_some_and(ExtendedFeatures::has_fsgsbase),
        ),
        (
            "smep",
            extended.as_ref().is_some_and(ExtendedFeatures::has_smep),
        ),
        (
            "smap",
            extended.as_ref().is_some_and(ExtendedFeatures::has_smap),
        ),
        (
            "umip",
            extended.as_ref().is_some_and(ExtendedFeatures::has_umip),
        ),
        (
            "rdseed",
            extended.as_ref().is_some_and(ExtendedFeatures::has_rdseed),
        ),
        (
            "avx2",
            extended.as_ref().is_some_and(ExtendedFeatures::has_avx2),
        ),
    ];
    for (heading, wanted) in [("present", true), ("absent", false)] {
        log!("INV cpu-features {}:", heading);
        for (name, present) in features {
            if present == wanted {
                log!(" {}", name);
            }
        }
        log!("\n");
    }
}

fn inventory_memory(boot: &BootInfo) {
    const NAMES: [&str; 9] = [
        "usable",
        "reserved",
        "acpi-reclaimable",
        "acpi-nvs",
        "bad",
        "bootloader",
        "kernel+modules",
        "framebuffer",
        "mapped-reserved",
    ];
    let mut totals = [0u64; NAMES.len()];
    let mut other = 0u64;
    for index in 0..boot.region_count() {
        let Ok(region) = boot.region(index) else {
            continue;
        };
        match usize::try_from(region.kind)
            .ok()
            .and_then(|kind| totals.get_mut(kind))
        {
            Some(total) => *total += region.length,
            None => other += region.length,
        }
    }
    log!("INV memory-map regions={}", boot.region_count());
    for (name, total) in NAMES.iter().zip(totals) {
        log!(" {}={}KiB", name, total >> 10);
    }
    log!(" other={}KiB\n", other >> 10);
    let ram = (totals[0] + totals[5]) >> 20;
    key(
        1,
        Text::from_args(format_args!(
            "memory {} MiB usable (+bootloader), {} regions",
            ram,
            boot.region_count()
        )),
    );
}

fn inventory_firmware(boot: &BootInfo, acpi: &Acpi) {
    log!(
        "INV acpi rsdp={:#x} tables={} signatures:",
        boot.rsdp,
        acpi.tables
    );
    for signature in acpi.signatures() {
        log!(" {}", core::str::from_utf8(signature).unwrap_or("????"));
    }
    log!("\n");
    let mut ioapics = 0;
    if let Some(madt) = &acpi.madt {
        for io in madt.ioapics() {
            ioapics += 1;
            log!(
                "INV ioapic id={} address={:#x} gsi_base={}\n",
                io.id,
                io.address,
                io.gsi_base
            );
        }
        for item in madt.overrides() {
            log!(
                "INV irq-override isa={} gsi={} flags={:#x}\n",
                item.source,
                item.gsi,
                item.flags
            );
        }
    }
    let cpus = acpi.madt.as_ref().map_or(0, |madt| madt.cpus_usable);
    let hpet = acpi.hpet.map_or(0, |hpet| hpet.address);
    let pm_timer = acpi.fadt.map_or(0, |fadt| fadt.pm_timer_port);
    key(
        2,
        Text::from_args(format_args!(
            "acpi {} tables, {} cpus, {} ioapics, hpet {:#x}, pm-timer {:#x}",
            acpi.tables, cpus, ioapics, hpet, pm_timer
        )),
    );
}

fn inventory_time() {
    let now = civil_from_unix(timer::ktime_get_real().sec);
    key(
        3,
        Text::from_args(format_args!(
            "rtc {:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC, tsc {} kHz, uptime {} s",
            now.year,
            now.month,
            now.day,
            now.hour,
            now.minute,
            now.second,
            timer::tsc_khz(),
            timer::ktime_get_boottime_ns() / 1_000_000_000
        )),
    );
}

fn inventory_display() {
    let mut count = 0;
    let mut first = Text::EMPTY;
    console::for_each_framebuffer(|width, height, bits, cols, rows| {
        log!(
            "INV framebuffer {} {}x{} {}bpp text-grid {}x{}\n",
            count,
            width,
            height,
            bits,
            cols,
            rows
        );
        if count == 0 {
            first = Text::from_args(format_args!("{width}x{height}x{bits}, text {cols}x{rows}"));
        }
        count += 1;
    });
    key(
        4,
        Text::from_args(format_args!(
            "display {count} framebuffer(s), first {first}"
        )),
    );
}

fn inventory_pci() {
    // SAFETY: the `pci` module contract: CPL0 on the BSP with interrupts off
    // (kernel_main, before any group), no other user of the ports (the kernel
    // has no PCI driver and no AP runs), read-only registers only.
    let mut adapters = [(0u16, 0u16); 4];
    let mut display_functions = 0;
    let scan = unsafe {
        pci::scan(|function| {
            // Base class 3: VGA, XGA and 3D display controllers.
            if function.base_class == 0x03 {
                if let Some(slot) = adapters.get_mut(display_functions) {
                    *slot = (function.vendor, function.device_id);
                }
                display_functions += 1;
            }
            log!(
                "INV pci {:02x}:{:02x}.{} {:04x}:{:04x} class {:02x}{:02x}{:02x} rev {:02x} hdr {:02x} {} {}\n",
                function.bus,
                function.device,
                function.func,
                function.vendor,
                function.device_id,
                function.base_class,
                function.sub_class,
                function.prog_if,
                function.revision,
                function.header_type,
                suite::pci_vendor(function.vendor),
                suite::pci_class(function.base_class, function.sub_class)
            );
        })
    };
    match scan {
        Some(scan) => key(
            5,
            Text::from_args(format_args!(
                "pci {} functions on {} buses (mechanism 1, ids only){}",
                scan.found,
                scan.buses,
                if scan.found > scan.listed {
                    ", list cut"
                } else {
                    ""
                }
            )),
        ),
        None => key(5, Text::from_args(format_args!("pci mechanism 1 absent"))),
    }
    // The display adapters by id: the machine has two GPUs.
    let mut text = Text::from_args(format_args!("display adapters ({display_functions}):"));
    for &(vendor, device) in adapters.iter().take(display_functions) {
        text = Text::from_args(format_args!("{text} {vendor:04x}:{device:04x}"));
    }
    key(6, text);
}

/// The hardware inventory (`INV ...` lines, captured like all output).
/// Context: BSP, IF clear, after the clock runs, before any group.
pub fn inventory(boot: &BootInfo, acpi: &Acpi) {
    inventory_cpu();
    inventory_memory(boot);
    inventory_firmware(boot, acpi);
    inventory_time();
    inventory_display();
    inventory_pci();
}

// ---------------------------------------------------------------------------
// Group loop

static NEXT: AtomicUsize = AtomicUsize::new(0);
static CURRENT: AtomicUsize = AtomicUsize::new(NONE);
static GROUP_START: AtomicUsize = AtomicUsize::new(0);
static GROUP_T0: AtomicU64 = AtomicU64::new(0);
static ENTERED: AtomicBool = AtomicBool::new(false);

fn selected(index: usize) -> Option<&'static str> {
    RESULTS.lock().selected().get(index).copied()
}

/// Run every group, then the late proofs and the summary. Never returns: each
/// group's end (`init_exited`/`fatal`) starts the next.
pub fn run() -> ! {
    start_next()
}

fn start_next() -> ! {
    let index = NEXT.fetch_add(1, Ordering::Relaxed);
    let Some(group) = selected(index) else {
        late_proofs();
        summary(None)
    };
    log!("SUITE group {} start\n", group);
    GROUP_START.store(stored(), Ordering::Relaxed);
    GROUP_T0.store(timer::ktime_get_ns(), Ordering::Relaxed);
    CURRENT.store(index, Ordering::Relaxed);
    let loaded = userspace::load_group(&ARCHIVES.lock(), group);
    userspace::run(loaded)
}

/// `/init` of the running group exited or was killed (`code` is Linux's
/// `exit_code`). Context: after the syscall/fault path dropped its locks.
pub fn init_exited(code: u32) -> ! {
    group_ended(Cause::Exited(code))
}

fn group_ended(cause: Cause) -> ! {
    let index = CURRENT.swap(NONE, Ordering::Relaxed);
    // A run cut off mid-line still shows what it had printed.
    flush_held(|byte| console::write_screen(&[byte]));
    DIRECT.store(false, Ordering::Relaxed);
    let Some(group) = selected(index) else {
        summary(Some(Text::from_args(format_args!(
            "a group ended while none was running"
        ))))
    };
    let (start, end) = (GROUP_START.load(Ordering::Relaxed), stored());
    let millis = (timer::ktime_get_ns() - GROUP_T0.load(Ordering::Relaxed)) / 1_000_000;
    let report =
        copy_range(start, end).map(|output| suite::compare_group(ORACLE_EXPECTED, group, &output));
    let stop = match cause {
        Cause::Stopped => last_line_with(start, end, b"FAIL"),
        Cause::Exited(_) => None,
    };
    let run = GroupRun {
        cause,
        report,
        stop,
        millis,
    };
    RESULTS.lock().groups[index] = Some(run);
    log!(
        "SUITE group {} result={} cause=\"{}\" matched={} expected={} observed={} mismatches={} millis={}\n",
        group,
        if run.passed() { "pass" } else { "fail" },
        cause.describe(),
        report.map_or(0, |r| r.matched),
        report.map_or(0, |r| r.expected),
        report.map_or(0, |r| r.observed),
        report.map_or(0, |r| r.mismatch_count),
        millis
    );
    userspace::teardown();
    start_next()
}

/// A kernel stop (`fail`): ends the running group when its locks are free (the
/// abandoned stack can no longer release them), else the suite.
pub fn fatal() -> ! {
    if CURRENT.load(Ordering::Relaxed) != NONE && userspace::locks_free() {
        group_ended(Cause::Stopped)
    }
    if ENTERED.swap(true, Ordering::Relaxed) {
        // A stop inside the summary itself: nothing more can be shown.
        cpu::halt()
    }
    summary(Some(last_line_with(0, stored(), b"FAIL").unwrap_or_else(
        || Text::from_args(format_args!("kernel stop")),
    )))
}

/// The proofs that would disturb the groups' timing or need no process:
/// the physical-memory exhaustion walk (every frame of RAM, minutes on a large
/// machine) and its buddy-order companion.
fn late_proofs() {
    crate::check_allocator_recovery(&mut services::FRAMES.lock());
}

// ---------------------------------------------------------------------------
// Summary

fn replay() {
    let pause = PAUSE_MS.load(Ordering::Relaxed);
    console::clear_screen();
    console::write_screen(
        b"-- linux-rs suite log replay, page 1 (pages advance by themselves) --\n",
    );
    console::set_pager(pause);
    for_each_line(0, stored(), |line| {
        // Passing test lines are the bulk of the log and carry no news; the
        // group reports and the summary count them. Failing ones stay.
        let compared = suite::PREFIXES
            .iter()
            .any(|prefix| line.starts_with(prefix));
        let failing = line.windows(4).any(|window| window == b"FAIL");
        // Per-group init boilerplate (four rows of auxv on a normal run); the
        // `SUITE group` records say how each run ended.
        const SAME: [&[u8]; 3] = [
            b"init: hello from userspace",
            b"init: ok",
            b"Kernel panic - not syncing: Attempted to kill init! exitcode=0x00000000",
        ];
        let boilerplate = SAME.contains(&line) || line.starts_with(b"init: argc=");
        if (!compared || failing) && !boilerplate {
            console::write_screen(line);
            console::write_screen(b"\n");
        }
    });
    console::page_hold();
    console::set_pager(0);
}

fn summary(abort: Option<Text>) -> ! {
    FROZEN.store(true, Ordering::Relaxed);
    let digest = digest();
    let (stored, dropped) = (stored(), dropped());
    replay();
    console::clear_screen();
    // One blank row keeps the first line off a monitor's overscan edge (screen
    // only: the serial transcript's digest range ends at the heading).
    console::write_screen(b"\n");
    let results = *RESULTS.lock();
    let groups_run = results.runs().filter(|(_, run)| run.is_some()).count();
    let groups_passed = results
        .groups
        .iter()
        .flatten()
        .filter(|g| g.passed())
        .count();
    let proofs_passed = results.proofs().iter().filter(|p| p.ok).count();
    let proofs = results.proofs().len();
    let ok = abort.is_none()
        && groups_run == results.selected_count
        && groups_passed == results.selected_count
        && proofs_passed == proofs
        && results.proofs_lost == 0
        && dropped == 0;

    log!(
        "linux-rs bare-metal suite   build {}   log digest {}\n",
        BUILD_ID,
        core::str::from_utf8(&hex16(digest)).unwrap_or("?")
    );
    for key in &results.keys {
        log!("  {}\n", key);
    }
    match abort {
        Some(reason) => log!(
            "RESULT: ABORTED after {} group(s): {}\n",
            groups_run,
            reason
        ),
        None if ok => log!(
            "RESULT: ALL PASS ({} groups, {} self-tests)\n",
            groups_passed,
            proofs
        ),
        None => log!(
            "RESULT: FAIL - {}/{} groups, {}/{} self-tests passed{}\n",
            groups_passed,
            results.selected_count,
            proofs_passed,
            proofs,
            if dropped > 0 { ", LOG TRUNCATED" } else { "" }
        ),
    }
    summary_groups(&results);
    summary_failures(&results);
    summary_proofs(&results);
    log!(
        "log: {} bytes captured, {} dropped, up {} s, digest {}\n",
        stored,
        dropped,
        timer::ktime_get_boottime_ns() / 1_000_000_000,
        core::str::from_utf8(&hex16(digest)).unwrap_or("?")
    );
    log!(
        "SUITE complete ok={} groups={}/{} proofs={}/{}\n",
        ok,
        groups_passed,
        results.selected_count,
        proofs_passed,
        proofs
    );
    log!("{}\n", FINAL_LINE);
    finish(ok)
}

/// One row per group, then the groups that are not run and why.
fn summary_groups(results: &Results) {
    log!("GROUPS (output vs pinned Linux 6.18.57, matched/expected lines)\n");
    for (name, run) in results.runs() {
        match run {
            Some(run) => {
                let (matched, expected) = run
                    .report
                    .map_or((0, 0), |report| (report.matched, report.expected));
                log!(
                    "  {:<7} {}  {}/{}  {}  {} ms\n",
                    name,
                    if run.passed() { "PASS" } else { "FAIL" },
                    matched,
                    expected,
                    run.cause.describe(),
                    run.millis
                );
            }
            None => log!("  {:<7} not run\n", name),
        }
    }
    for (name, why) in UNSUPPORTED {
        log!("  {:<7} skipped: {}\n", name, why);
    }
}

/// Why each failed group failed: the kernel's stop line, init's own failure
/// line and the first mismatching lines (wanted and got).
fn summary_failures(results: &Results) {
    for (name, run) in results.runs() {
        let Some(run) = run else { continue };
        if run.passed() {
            continue;
        }
        if let Some(stop) = run.stop {
            log!("  {} stopped: {}\n", name, stop);
        }
        let Some(report) = run.report else {
            log!("  {} output not compared (heap full)\n", name);
            continue;
        };
        if let Some(failure) = report.init_failure {
            log!("  {} init: {}\n", name, failure);
        }
        for mismatch in &report.mismatches[..report.mismatch_count.min(suite::MAX_MISMATCHES)] {
            log!(
                "  {} #{} want {}\n  {} #{} got  {}\n",
                name,
                mismatch.position,
                mismatch.expected,
                name,
                mismatch.position,
                mismatch.got
            );
        }
        if report.mismatch_count > suite::MAX_MISMATCHES {
            log!(
                "  {} ... {} more mismatches\n",
                name,
                report.mismatch_count - suite::MAX_MISMATCHES
            );
        }
    }
}

/// The self-test names, wrapped to the screen width; failures marked.
fn summary_proofs(results: &Results) {
    let passed = results.proofs().iter().filter(|p| p.ok).count();
    log!("SELF-TESTS {}/{} passed", passed, results.proofs().len());
    if results.proofs_lost > 0 {
        log!(" ({} more not listed)", results.proofs_lost);
    }
    log!("\n ");
    let (columns, _) = console::grid();
    let mut width = 1;
    for proof in results.proofs() {
        let item = proof.name.len() + 6;
        if width + item > columns.max(60) {
            log!("\n ");
            width = 1;
        }
        log!(" {}{}", if proof.ok { "" } else { "FAIL:" }, proof.name);
        width += item;
    }
    log!("\n");
}

fn finish(ok: bool) -> ! {
    #[cfg(feature = "qemu-self-test")]
    {
        if ok {
            log!("RESULT success\n");
        } else {
            log!("FAIL suite\n");
        }
        cpu::exit(ok)
    }
    #[cfg(not(feature = "qemu-self-test"))]
    {
        let _ = ok;
        cpu::halt()
    }
}
