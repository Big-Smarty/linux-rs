// SPDX-License-Identifier: GPL-2.0-only
#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
compile_error!(
    "the kernel requires --target x86_64-unknown-none; host tools/tests do not enable freestanding"
);

// Links the scalar `memset`/`memcpy` providers the compiler emits calls to.
use kernel::{boot, firmware, image, memory};
use linux_rs_runtime as _;

mod console;
mod cpu;
mod paging;

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
    // take_framebuffer), mapped by the loader, never republished, and no Rust
    // references to it are created.
    let framebuffer = unsafe { console::init(boot::BootInfo::take_framebuffer()) };
    log!("linux-rs bootstrap x86_64 limine-base=5 firmware=efi64\n");
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
    inspect_boot_images(&boot);
    // SAFETY: one constructor call consumes usable RAM ownership from the
    // trusted handoff, no DMA/AP/firmware mutation or competing allocator.
    let mut allocator = unwrap(unsafe { Allocator::new(&boot) }, "allocator");
    check_frame_ownership(&mut allocator);
    let tables = unwrap(paging::Tables::build(&boot, &mut allocator), "tables-build");
    #[cfg(feature = "qemu-self-test")]
    {
        unwrap(
            paging::Tables::failure_tests(&boot, &mut allocator, tables.pages),
            "table-allocation-rollback",
        );
        log!(
            "CHECK table-oom ok failure_points={} accounting=restored\n",
            tables.pages
        );
    }
    require(
        unwrap(tables.check_permissions(&boot), "permissions"),
        "table-permissions",
    );
    // SAFETY: the fully constructed tree covers current image/stack, descriptor,
    // loader/firmware/metadata and framebuffer resources at unchanged addresses;
    // guard/image-alias holes are intentional; no SMP/PCID/global translations.
    unsafe {
        tables.activate();
    }
    require(tables.is_active(), "cr3-owned-root");
    check_module_epoch(&boot, &tables);
    require(
        unwrap(tables.lookup(Virtual(cpu::guards()[0])), "guard-lookup").is_none(),
        "stack-guard-unmapped",
    );
    log!(
        "CHECK paging ok tables={} wx=separated guards=4 image_alias=absent\n",
        tables.pages
    );
    check_exceptions(&boot, &mut allocator);
    #[cfg(feature = "qemu-self-test")]
    check_allocator_recovery(&mut allocator);
    unwrap(cpu::start_timer(acpi.legacy_pic), "timer-init");
    unwrap(
        cpu::irq_guard_test(
            cfg!(feature = "qemu-self-test") && boot.test == TestMode::IrqRestoreEarly,
        ),
        "irq-guard",
    );
    log!(
        "CHECK irq-guard ok nested=2 out_of_order=true saved_on=true saved_off=true exclusive=true blocked_wraps=2 blocked_delta=0 resumed=true\n"
    );
    require(cpu::irq_register_test(), "irq-all-gpr-preservation");
    let tick_start = cpu::ticks();
    while cpu::ticks() - tick_start < 16 {
        cpu::wait_tick();
    }
    // The mutation case deliberately leaves IRQ0 unmasked: the same assertion
    // must fail after real PIT progression, not return an injected failure.
    if boot.test != TestMode::UnmaskedTimer {
        cpu::mask_timer();
    }
    let tick_end = cpu::ticks();
    let observation = unwrap(cpu::observe_timer_periods(), "timer-period-observation");
    log!(
        "TIMER mask observation pit_wraps={} irq_delta={}\n",
        observation.wraps,
        observation.irq_delta
    );
    require(observation.irq_delta == 0, "timer-mask");
    require(tick_end >= tick_start + 16, "timer-delivery");
    log!(
        "CHECK timer ok delivered={} masked_count={} gprs=15 pit_wraps={}\n",
        tick_end - tick_start,
        cpu::ticks(),
        observation.wraps
    );
    log!(
        "CHECKPOINT bootstrap-complete free_pages={} owned_tables={}\n",
        allocator.available(),
        tables.pages
    );
    #[cfg(feature = "qemu-self-test")]
    {
        log!("RESULT success\n");
        cpu::exit(true);
    }
    #[cfg(not(feature = "qemu-self-test"))]
    cpu::halt()
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
        "CHECK handoff ok acpi_tables={} legacy_pic={}\n",
        acpi.tables,
        acpi.legacy_pic
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
