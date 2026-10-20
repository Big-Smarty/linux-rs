// SPDX-License-Identifier: GPL-2.0-only
#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]
// Fallible allocation API (`Box::try_new`, `Vec::push_within_capacity`); the
// infallible one does not exist in target builds, see `kalloc`. Only the
// self-test uses them so far.
#![cfg_attr(
    feature = "qemu-self-test",
    feature(allocator_ext, vec_push_within_capacity)
)]

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
compile_error!(
    "the kernel requires --target x86_64-unknown-none; host tools/tests do not enable freestanding"
);

extern crate alloc;

// Links the scalar `memset`/`memcpy` providers the compiler emits calls to.
use kernel::{boot, firmware, image, memory};
use linux_rs_runtime as _;

mod apic;
mod console;
mod cpu;
mod kalloc;
mod mmio;
mod paging;
mod services;
mod timer;
mod userspace;

use boot::TestMode;
use core::{panic::PanicInfo, ptr};
use memory::{Allocator, Virtual};

fn inspect_boot_images(boot: &boot::BootInfo) {
    for index in 0..boot.module_count() {
        let span = unwrap(boot.module_span(index), "boot-module-span");
        let summary = {
            // SAFETY: trusted initialized immutable file storage, BSP only,
            // no DMA/AP/firmware writer or reclaim, loader CR3 still active.
            // All bytes/Record/Elf borrows end here before Tables::activate.
            let bytes = unwrap(unsafe { boot.module_bytes(span) }, "boot-module-bytes");
            image::inspect_archive(bytes)
        };
        // Linux (init/initramfs.c) reports a bad initramfs and still boots.
        let summary = match summary {
            Ok(summary) => summary,
            Err(error) => {
                log!(
                    "WARN Initramfs unpacking failed: module={} error={:?} skipped=true\n",
                    index,
                    error
                );
                continue;
            }
        };
        log!(
            "CHECK image inspected module={} physical={:#x} reserved={} bytes={} records={} files={} regular={} symlinks={} trailers={} skipped={} elf={} loads={} interpreters={} execution=false rootfs=false\n",
            index,
            span.physical(),
            span.reserved_length(),
            summary.input_bytes,
            summary.records,
            summary.files,
            summary.regular_files,
            summary.symlinks,
            summary.trailers,
            summary.skipped,
            summary.elf_files,
            summary.load_segments,
            summary.interpreters
        );
    }
}

fn check_module_epoch(boot: &boot::BootInfo, tables: &paging::Tables) {
    for index in 0..boot.module_count() {
        // The kind5 descriptor survives CR3; no payload borrow is recreated.
        let span = unwrap(boot.module_span(index), "retained-module-span");
        let mut offset = 0;
        while offset < span.reserved_length() {
            let address = unwrap(
                boot.direct_map
                    .checked_add(span.physical())
                    .and_then(|base| base.checked_add(offset))
                    .ok_or(boot::BootError::Overflow),
                "module-alias-address",
            );
            require(
                unwrap(tables.lookup(Virtual(address)), "module-alias-lookup").is_none(),
                "module-payload-not-aliased",
            );
            offset += memory::PAGE;
        }
    }
    log!(
        "CHECK module-epoch ok modules={} payload_alias=absent views=ended reservations=retained execution=false rootfs=false\n",
        boot.module_count()
    );
}

#[unsafe(link_section = ".rodata.probe")]
static mut READONLY_PROBE: u64 = 0x51a7_6e29_c0de_babe;

fn require(condition: bool, label: &str) {
    if !condition {
        log!("FAIL assertion={}\n", label);
        fail();
    }
}
fn unwrap<T, E: core::fmt::Debug>(result: Result<T, E>, label: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => {
            log!("FAIL {} error={:?}\n", label, error);
            fail();
        }
    }
}

#[unsafe(no_mangle)]
extern "C" fn kernel_main() -> ! {
    #[cfg(feature = "qemu-self-test")]
    cpu::serial_init();
    // SAFETY: _start has established our BSS stack, long mode and IF/DF=0; the
    // loader mappings are active. Nothing fallible precedes this, so every later
    // failure reaches the screen. The framebuffer extent is a kind7 loader
    // reservation (checked against the not-yet-validated map, see
    // take_framebuffers), mapped by the loader, never republished, and no Rust
    // references to it are created.
    let framebuffer = unsafe { console::init(&boot::BootInfo::take_framebuffers()) } > 0;
    log!("linux-rs bootstrap x86_64 limine-base=5 firmware=efi64\n");
    #[cfg(feature = "qemu-self-test")]
    require(console::self_test(), "console-scroll");
    #[cfg(feature = "qemu-self-test")]
    require(
        linux_rs_runtime::self_test(),
        "scalar-rust-memory-boundaries",
    );
    #[cfg(feature = "qemu-self-test")]
    log!(
        "CHECK memory-runtime ok memset_cases=272 memcpy_cases=4224 zero_length=true boundaries=true padding_fields=true same_allocation=true\n"
    );
    unwrap(cpu::validate(), "cpu");
    // SAFETY: BSP IF clear, no descriptor references/APs; image and all stacks
    // stay reserved for the complete lifetime of this execution.
    unsafe {
        cpu::install_descriptors();
    }
    // SAFETY: _start has established our BSS stack, long mode and IF/DF=0. This
    // is the one BSP handoff; loader memory is never reclaimed in this cell.
    let (boot, acpi) = loader_handoff(framebuffer);
    // The handoff is immutable from here on; `'static` lets the allocator
    // borrow it and keeps it reachable after this frame is abandoned.
    let boot = services::BOOT.init(boot);
    inspect_boot_images(boot);
    // SAFETY: one constructor call consumes usable RAM ownership from the
    // trusted handoff, no DMA/AP/firmware mutation or competing allocator.
    let mut allocator = unwrap(unsafe { Allocator::new(boot) }, "allocator");
    check_frame_ownership(&mut allocator);
    let mut tables = unwrap(paging::Tables::build(boot, &mut allocator), "tables-build");
    #[cfg(feature = "qemu-self-test")]
    {
        unwrap(
            paging::Tables::failure_tests(boot, &mut allocator, tables.pages),
            "table-allocation-rollback",
        );
        log!(
            "CHECK table-oom ok failure_points={} accounting=restored\n",
            tables.pages
        );
    }
    require(
        unwrap(tables.check_permissions(boot), "permissions"),
        "table-permissions",
    );
    // Kernel tables only; init's mappings below are added before CR3 loads,
    // which `paging`'s update rules allow but no longer require.
    let table_pages = tables.pages;
    let user = userspace::load(boot, &mut allocator, &mut tables);
    // Interrupt-controller and time device pages (LAPIC, IOAPICs, HPET) are
    // mapped uncached into the same unpublished tree; the APIC mode decision
    // reads only CPUID/IA32_APIC_BASE.
    let options = timer::Options::from_boot(boot);
    let prepared = apic::prepare(
        acpi.madt.as_ref(),
        options.nolapic,
        options.nox2apic,
        boot.test,
    );
    let device_pages = timer::map_mmio(
        boot,
        &mut allocator,
        &mut tables,
        &prepared,
        &acpi,
        options.noapic,
    );
    // SAFETY: the fully constructed tree covers current image/stack, descriptor,
    // loader/firmware/metadata and framebuffer resources at unchanged addresses;
    // guard/image-alias holes are intentional; no SMP/PCID/global translations.
    unsafe {
        tables.activate();
    }
    require(tables.is_active(), "cr3-owned-root");
    check_module_epoch(boot, &tables);
    require(
        unwrap(tables.lookup(Virtual(cpu::guards()[0])), "guard-lookup").is_none(),
        "stack-guard-unmapped",
    );
    log!(
        "CHECK paging ok tables={} wx=separated guards=5 image_alias=absent\n",
        table_pages
    );
    check_exceptions(boot, &mut allocator);
    #[cfg(feature = "qemu-self-test")]
    check_allocator_recovery(&mut allocator);
    #[cfg(feature = "qemu-self-test")]
    check_user_mm(&mut tables, &mut allocator);
    clock_and_irq_checks(boot, &prepared, &acpi, &device_pages, options);
    log!(
        "CHECKPOINT bootstrap-complete free_pages={} owned_tables={}\n",
        allocator.available(),
        tables.pages
    );
    publish_services(allocator, tables);
    // Diverges: init runs and its death ends the boot, or Linux's failure text.
    userspace::run(user)
}

/// The boot-phase locals end here: the frame allocator and the published tables
/// move into their statics, since `kernel_main`'s frame becomes init's kernel
/// stack and the syscall/fault paths allocate and edit tables from there.
fn publish_services(allocator: Allocator<'static>, tables: paging::Tables) {
    services::FRAMES.install(allocator);
    services::TABLES.install(tables);
    // The heap is usable from here on (it grows from `FRAMES`).
    #[cfg(feature = "qemu-self-test")]
    {
        unwrap(kalloc::self_test(), "heap");
        log!(
            "CHECK heap ok vec=1000 box=4096 align=4096 growth=buddy-frames oom=failed-cleanly recovered=true over_cap=rejected accounting=restored\n"
        );
    }
}

/// Interrupt controllers, clock and tick bring-up plus the proofs that depend
/// on a delivered tick. A failed bring-up is fatal in the QEMU suite; the
/// physical diagnostic profile reports it and continues without the
/// interrupt-dependent checks.
fn clock_and_irq_checks(
    boot: &boot::BootInfo,
    prepared: &apic::Prepared,
    acpi: &firmware::Acpi,
    device_pages: &timer::Mmio,
    options: timer::Options,
) {
    // SAFETY: BSP, IF clear, CR3 published with the device pages mapped, IDT
    // installed above; the only call, before any AP or DMA.
    let clock = unsafe { timer::init(prepared, acpi, device_pages, options) };
    let tick_ok = match clock {
        Ok(report) => {
            log!(
                "CHECK interrupt-controllers ok mode={} event={} ioapic_timer={}\n",
                match report.apic_mode {
                    kernel::intc::ApicMode::Disabled => "legacy-pic",
                    kernel::intc::ApicMode::Xapic => "xapic",
                    kernel::intc::ApicMode::X2apic => "x2apic",
                },
                report.event,
                report
                    .ioapic_timer
                    .map_or("n/a", |ok| if ok { "true" } else { "false" })
            );
            true
        }
        Err(error) => {
            // A physical diagnostic boot reports and continues so one boot
            // shows everything else; the QEMU suite treats it as a failure.
            log!(
                "{} timer-init error={:?}\n",
                if cfg!(feature = "qemu-self-test") {
                    "FAIL"
                } else {
                    "WARN"
                },
                error
            );
            if cfg!(feature = "qemu-self-test") {
                fail();
            }
            timer::mask_timer();
            false
        }
    };
    if tick_ok {
        unwrap(
            cpu::irq_guard_test(
                cfg!(feature = "qemu-self-test") && boot.test == TestMode::IrqRestoreEarly,
            ),
            "irq-guard",
        );
        log!(
            "CHECK irq-guard ok nested=2 out_of_order=true saved_on=true saved_off=true exclusive=true blocked_periods=2 blocked_delta=0 resumed=true\n"
        );
        require(cpu::irq_register_test(), "irq-all-gpr-preservation");
        let tick_start = timer::ticks();
        let wall_start = timer::ktime_get_ns();
        require(timer::wait_ticks(16, 500), "timer-delivery");
        let tick_ns = timer::ktime_get_ns() - wall_start;
        // The mutation case deliberately leaves the tick unmasked: the same
        // assertion must fail after real tick progression, not return an
        // injected failure.
        if boot.test != TestMode::UnmaskedTimer {
            timer::mask_timer();
        }
        let tick_end = timer::ticks();
        let delta = unwrap(timer::observe_periods(2), "timer-period-observation");
        log!("TIMER mask observation periods=2 irq_delta={}\n", delta);
        require(delta == 0, "timer-mask");
        require(tick_end >= tick_start + 16, "timer-delivery");
        // 16 ticks counted from an arbitrary phase span between 15 and 16
        // periods of HZ=1000; the bounds absorb host scheduling noise only.
        require(
            (14_000_000..=60_000_000).contains(&tick_ns),
            "timer-period-vs-tsc",
        );
        log!(
            "CHECK timer ok delivered={} masked_count={} gprs=15 periods=2 hz=1000 tick16_ns={} tsc_khz={}\n",
            tick_end - tick_start,
            timer::ticks(),
            tick_ns,
            timer::tsc_khz()
        );
        let proof = unwrap(
            timer::timekeeping_selftest().ok_or("timekeeping"),
            "timekeeping",
        );
        log!(
            "CHECK timekeeping ok slept_ns={} realtime_skew_ns={} boottime_lag_ns={} monotonic_steps={}\n",
            proof.waited_ns,
            proof.real_minus_mono_ns,
            proof.boot_minus_mono_ns,
            proof.monotonic_steps
        );
    } else {
        log!("WARN timer tick not delivered: interrupt-dependent checks skipped\n");
    }
}

fn loader_handoff(framebuffer: bool) -> (boot::BootInfo, firmware::Acpi) {
    // SAFETY: kernel_main reaches this exactly once from the CPL0 bootstrap
    // entry with our owned stack and IF/DF clear; the trusted loader's response
    // allocations remain live, reserved, and immutable for this execution.
    let boot = match unsafe { boot::BootInfo::take() } {
        Ok(info) => info,
        Err(error) => {
            log!("FAIL boot error={:?}\n", error);
            fail();
        }
    };
    log!(
        "CHECK entry ok framebuffer={} map_entries={}\n",
        framebuffer,
        boot.region_count()
    );
    // SAFETY: this cell trusts its recorded EFI/Limine/firmware handoff to supply
    // initialized immutable RSDP/XSDT/SDT storage after ExitBootServices. It calls
    // no firmware runtime service, starts no AP or DMA, and keeps all table RAM
    // reserved. No firmware/SMM/AP/DMA/software writer may mutate these tables
    // during discovery. Mutable FACS/NVS objects are not traversed. This explicit
    // external trust assumption does not claim protection from malicious firmware.
    let acpi = unwrap(unsafe { firmware::discover(&boot) }, "acpi");
    #[cfg(feature = "qemu-self-test")]
    require(
        firmware::regression_checks() && boot::regression_checks(),
        "production-parser-regressions",
    );
    log!(
        "CHECK handoff ok acpi_tables={} legacy_pic={} warnings={}\n",
        acpi.tables,
        acpi.legacy_pic,
        acpi.warnings().len() + acpi.warnings_dropped
    );
    for warning in acpi.warnings() {
        log!(
            "WARN acpi table {} {:?}\n",
            core::str::from_utf8(&warning.signature).unwrap_or("????"),
            warning.problem
        );
    }
    match &acpi.madt {
        Some(madt) => log!(
            "CHECK madt ok lapic={:#x} cpus={} lapics={} x2apics={} max_apic_id={} ioapics={} overrides={} nmi_sources={} lapic_nmis={} dropped={} pcat_compat={} irq0_gsi={}\n",
            madt.lapic_address,
            madt.cpus_usable,
            madt.lapic_entries,
            madt.x2apic_entries,
            madt.max_apic_id,
            madt.ioapics().len(),
            madt.overrides().len(),
            madt.nmi_sources().len(),
            madt.lapic_nmis().len(),
            madt.dropped,
            madt.pcat_compat,
            madt.isa_route(0).map_or(-1, |route| i64::from(route.gsi))
        ),
        None => log!("WARN madt absent: local APIC and IOAPIC topology unknown\n"),
    }
    log!(
        "CHECK time-tables hpet={:#x} pm_timer={:#x} century={:#x}\n",
        acpi.hpet.map_or(0, |h| h.address),
        acpi.fadt.map_or(0, |f| f.pm_timer_port),
        acpi.fadt.map_or(0, |f| f.century)
    );
    if boot.test == TestMode::BadMap {
        let invalid = boot::Region {
            base: u64::MAX - 4095,
            length: 8192,
            kind: 0,
        };
        require(
            matches!(
                boot::checked_region(invalid, 0),
                Err(boot::BootError::Overflow)
            ),
            "bad-map-overflow-rejected",
        );
        log!("EXPECTED failure bad-map rejected overflow\n");
        fail();
    }
    (boot, acpi)
}

fn check_frame_ownership(allocator: &mut Allocator<'_>) {
    let before = allocator.allocated();
    let mut first = unwrap(allocator.allocate(), "frame-first");
    let mut second = unwrap(allocator.allocate(), "frame-second");
    require(first.physical() != second.physical(), "frame-unique");
    require(first.bytes().iter().all(|&b| b == 0), "frame-zero");
    first.bytes().fill(0xa5);
    second.bytes().fill(0x5a);
    require(
        first.bytes().iter().all(|&b| b == 0xa5),
        "frame-content-isolation",
    );
    unwrap(allocator.release(first), "release-first");
    let mut first = unwrap(allocator.allocate(), "frame-reuse");
    require(
        first.physical() != second.physical() && first.bytes().iter().all(|&b| b == 0),
        "frame-reuse-zero",
    );
    unwrap(allocator.release(first), "release-reused");
    unwrap(allocator.release(second), "release-second");
    require(allocator.allocated() == before, "frame-accounting");
    require(
        matches!(
            allocator.allocate_aligned(8191),
            Err(memory::Error::Alignment)
        ),
        "frame-invalid-alignment",
    );
    log!(
        "CHECK memory ok usable_pages={} metadata_pages={} free_pages={}\n",
        allocator.total(),
        allocator.metadata_pages(),
        allocator.available()
    );
}

fn check_exceptions(boot: &boot::BootInfo, allocator: &mut Allocator<'_>) {
    require(cpu::breakpoint_test(), "breakpoint-return");
    // SAFETY: controlled fault probes with exact page/error/RIP matching. The
    // readonly probe has a mutable Rust type and no live reference, so an
    // accidentally writable mapping is a detected failure, not a const alias.
    let readonly = ptr::addr_of_mut!(READONLY_PROBE) as u64;
    let sentinel = unsafe { ptr::read_volatile(ptr::addr_of!(READONLY_PROBE)) };
    // SAFETY: IF0, owned IDT/CR3, and the unmapped BSP guard were checked above.
    require(
        unsafe { cpu::page_fault_register_test() },
        "page-fault-all-gpr-preservation",
    );
    log!("CHECK page-fault-gprs ok gprs=15\n");
    require(
        unsafe { cpu::fault_test(cpu::guards()[0], 0) },
        "guard-page-fault",
    );
    require(
        unsafe { cpu::fault_test(readonly, 1) },
        "readonly-page-fault",
    );
    require(
        unsafe { ptr::read_volatile(ptr::addr_of!(READONLY_PROBE)) } == sentinel,
        "readonly-value-preserved",
    );
    let mut nx = unwrap(allocator.allocate(), "nx-frame");
    nx.bytes()[0] = 0xc3; // RET if executable: a missing NX check must fail test.
    let nx_address = boot.direct_map + nx.physical().0;
    require(
        unsafe { cpu::fault_test(nx_address, 2) },
        "nx-execution-fault",
    );
    unwrap(allocator.release(nx), "nx-release");
    log!("CHECK exception ok breakpoint=returned gprs=15 guard=0 readonly=3 nx=17\n");
    if boot.test == TestMode::UnexpectedFault {
        cpu::unexpected_fault();
    }
    if boot.test == TestMode::UnexpectedPageFault {
        cpu::unexpected_page_fault();
    }
    if boot.test == TestMode::UnexpectedBreakpoint {
        cpu::unexpected_breakpoint();
    }
    if boot.test == TestMode::UnexpectedInterrupt {
        cpu::unexpected_interrupt();
    }
    assert!(boot.test != TestMode::Panic, "controlled panic case");
}

#[cfg(feature = "qemu-self-test")]
fn check_user_mm(tables: &mut paging::Tables, allocator: &mut Allocator<'_>) {
    unwrap(tables.user_mm_tests(allocator), "user-mm");
    log!(
        "CHECK user-mm ok pages=3 rollback_points=3 tlb=invlpg protect=ro unmap=3 conflict=rolled-back accounting=restored\n"
    );
}

fn fail() -> ! {
    #[cfg(feature = "qemu-self-test")]
    cpu::exit(false);
    #[cfg(not(feature = "qemu-self-test"))]
    cpu::halt()
}
#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    log!("FAIL panic {}\n", info);
    fail()
}

#[cfg(feature = "qemu-self-test")]
fn check_allocator_recovery(allocator: &mut Allocator<'_>) {
    let max_order = unwrap(allocator.test_orders(), "buddy-orders");
    let exhausted = unwrap(allocator.test_exhaustion(), "exhaustion");
    log!(
        "CHECK exhaustion ok frames={} recovered={}\n",
        exhausted,
        allocator.available()
    );
    log!(
        "CHECK buddy-orders ok max_order={} contiguous=true zeroed=true split=true coalesced=true fragmented=true aligned=131072 rollback=true\n",
        max_order
    );
}
