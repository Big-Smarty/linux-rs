// SPDX-License-Identifier: GPL-2.0-only
//! Isolated freestanding kernel builds and bounded QEMU evidence capture.

use crate::fixture;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const TARGET: &str = "x86_64-unknown-none";
// Reviewed host-build source replacement; kernel builds accept the checked-in file only if identical.
const PROJECT_CARGO_CONFIG: &str = "[source.crates-io]\nreplace-with = \"vendored-sources\"\n\n[source.vendored-sources]\ndirectory = \"vendor\"\n";
// The only vendored build scripts: (package directory, script path). Review them again on any bump.
// proc-macro2/quote/serde_derive/syn come only through serde_core's never-active `cfg(any())`
// edge, so they are locked and vendored but not built; their scripts are listed conservatively.
const VENDOR_BUILD_SCRIPTS: [(&str, &str); 9] = [
    ("const_fn-0.4.12", "build.rs"),
    ("rustversion-1.0.23", "build/build.rs"),
    ("proc-macro2-1.0.107", "build.rs"),
    ("quote-1.0.47", "build.rs"),
    ("serde-1.0.229", "build.rs"),
    ("serde_core-1.0.229", "build.rs"),
    ("serde_json-1.0.154", "build.rs"),
    ("zmij-1.0.23", "build.rs"),
    // user/init only: prints rerun-if-changed and a thumb-mode cfg for ARM targets (read in full); no process, network or file access.
    ("syscalls-0.8.1", "build.rs"),
];
// The only proc-macro packages (host-executed at build time, or locked but unbuilt).
const VENDOR_PROC_MACROS: [&str; 3] = [
    "const_fn-0.4.12",
    "rustversion-1.0.23",
    "serde_derive-1.0.229",
];
/// Rust-for-Linux's switch: removes every `alloc` API that can abort on
/// allocation failure, so kernel allocation can only be fallible. It must be in
/// the rustflags of the `-Zbuild-std` build of `alloc` (hence of every crate),
/// and in the target Clippy command (`docs/kernel-tooling.md`).
const NO_GLOBAL_OOM_HANDLING: &str = "--cfg=no_global_oom_handling";

/// What the isolated Cargo build compiles: the kernel (two feature profiles) or the user `/init`.
#[derive(Clone, Copy)]
enum Target {
    Kernel { qemu_self_test: bool },
    Init,
}

impl Target {
    fn is_init(self) -> bool {
        matches!(self, Self::Init)
    }

    fn package(self) -> &'static str {
        match self {
            Self::Kernel { .. } => "kernel",
            Self::Init => "linux-rs-init",
        }
    }

    fn binary(self) -> &'static str {
        match self {
            Self::Kernel { .. } => "linux-rs-kernel",
            Self::Init => "init",
        }
    }

    // Manifest key prefix (`kernel_elf_snapshot`, ...) and linker-map name.
    fn prefix(self) -> &'static str {
        match self {
            Self::Kernel { .. } => "kernel",
            Self::Init => "init",
        }
    }

    /// The `-Zbuild-std` crate list. Only the kernel has `alloc`, and its `alloc`
    /// is built with [`NO_GLOBAL_OOM_HANDLING`]: infallible allocation APIs do
    /// not exist in the kernel (`Box::new`, `Vec::push`, ... fail to compile).
    fn build_std(self) -> &'static str {
        match self {
            Self::Kernel { .. } => "-Zbuild-std=core,alloc,compiler_builtins",
            Self::Init => "-Zbuild-std=core,compiler_builtins",
        }
    }

    fn features(self) -> &'static str {
        match self {
            Self::Kernel {
                qemu_self_test: true,
            } => "qemu-self-test",
            _ => "freestanding",
        }
    }
}
const REQUIRED_RUSTC_COMMIT: &str = "5c543b0b8c73c7b72bc8284ced4fb22ead15734d";
const REQUIRED_CARGO_COMMIT: &str = "3d7cf6e937d6127d0f49881bf689c560b36d35c4";
const METADATA_TIMEOUT: Duration = Duration::from_secs(30);
const CAPTURE_LIMIT: usize = 16 * 1024 * 1024;
const KILL: &str = "/usr/bin/kill";
const SETPRIV: &str = "/usr/bin/setpriv";
pub(crate) const SERIAL_LOG_LIMIT: u64 = 4 * 1024 * 1024;
const BUILD_TIMEOUT: Duration = Duration::from_secs(900);
const FAT_IMAGE_BYTES: u64 = 64 * 1024 * 1024;
const OVMF_CODE: &str = "/usr/share/edk2/x64/OVMF_CODE.4m.fd";
const OVMF_VARS: &str = "/usr/share/edk2/x64/OVMF_VARS.4m.fd";
const LIMINE_EFI: &str = "/usr/share/limine/BOOTX64.EFI";
const LIMINE_DOCS: [(&str, &str); 2] = [
    ("/usr/share/doc/limine/COPYING", "limine-COPYING"),
    ("/usr/share/doc/limine/3RDPARTY.md", "limine-3RDPARTY.md"),
];
const OVMF_LICENSES: [(&str, &str); 2] = [
    (
        "/usr/share/licenses/edk2-ovmf/License.txt",
        "ovmf-License.txt",
    ),
    (
        "/usr/share/licenses/edk2-ovmf/OvmfPkg.License.txt",
        "ovmf-OvmfPkg.License.txt",
    ),
];

/// A boot module of one QEMU case. All are generated by the harness, never read from outside the run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Module {
    /// The generated initramfs carrying the built `/init`.
    Archive,
    /// Deterministic garbage with the gzip magic; the kernel must skip it, as Linux does.
    Corrupt,
    /// A genuinely zero-byte module.
    Empty,
    /// A valid archive with no `/init`.
    NoInit,
}

impl Module {
    fn file(self) -> &'static str {
        match self {
            Self::Archive => "initramfs.cpio",
            Self::Corrupt => "initramfs-corrupt.cpio",
            Self::Empty => "initramfs-empty.cpio",
            Self::NoInit => "initramfs-noinit.cpio",
        }
    }
}

const ARCHIVE_ONLY: &[Module] = &[Module::Archive];
const NO_INIT_ONLY: &[Module] = &[Module::NoInit];
const EMPTY_MODULE_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const EMPTY_MODULE_COUNTS: &str = "reserved=4096 bytes=0 records=0 files=0 regular=0 symlinks=0 trailers=0 skipped=0 elf=0 loads=0 interpreters=0 execution=false rootfs=false";
// Debug text of `image::Error::Archive` for a leading gzip magic (`CompressionPending`), per module.
const CORRUPT_MODULE_WARNING: &str =
    "error=Archive { offset: 0, error: CompressionPending(Gzip) } skipped=true";

fn module_epoch_record(modules: usize) -> String {
    format!(
        "CHECK module-epoch ok modules={modules} payload_alias=absent views=ended reservations=retained execution=false rootfs=false"
    )
}

/// What the guest's `/init` must have done, checked by [`validate_userspace`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum User {
    /// Never reached, or not asserted for this case.
    None,
    /// Runs to `init: ok` and `exit_group(0)`; the kernel then reports its death panic.
    Ok {
        /// `argc` as the init prints it (`/init` plus the words after `--`).
        argc: usize,
        /// The mode line the init prints before `init: ok`.
        mode_line: Option<&'static str>,
        /// Whether the whole summary line is compared (needs the `qemu64` constants).
        exact_summary: bool,
        /// CR4.SMEP / CR4.SMAP the kernel must report.
        protection: (bool, bool),
    },
    /// Reads address 0 (`-- fault`): SIGSEGV kills init, exit code 0xb.
    Segfault,
    /// Calls `io_uring_setup`, which Linux implements and this kernel does not: it stops.
    Unimplemented,
    /// Runs one oracle syscall-test group (`-- <group>`, `user/init/src/tests`) to `init: ok`;
    /// every `init: test|tests|info` line equals the pinned Linux's ([`validate_oracle`]).
    Oracle(&'static str),
    /// An oracle group whose later checks need a syscall that is not wired yet: the run must print
    /// the group's expected lines up to (not including) the first check whose line contains
    /// `until`, and then stop loudly on the `mmap` stop (`FAIL syscall unimplemented nr=9`).
    /// Replace by [`User::Oracle`] when the missing syscall lands.
    OracleUntil {
        group: &'static str,
        until: &'static str,
    },
    /// No `/init` in any archive: Linux's `prepare_namespace` failure text.
    NoRoot,
}

#[derive(Clone, Copy)]
struct DebugCase {
    name: &'static str,
    cmdline: Option<&'static str>,
    cpu: &'static str,
    expected_exit: i32,
    required: &'static [&'static str],
    forbid_success: bool,
    modules: &'static [Module],
    user: User,
    /// Display devices the guest must see: 1 (std VGA) or 2 (plus `ramfb`).
    framebuffers: usize,
    plat: Platform,
}

/// The QEMU machine a case boots and the interrupt-controller / time path the
/// kernel must report for it (`CHECK interrupt-controllers`, `CHECK tsc`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Platform {
    /// `-machine` type and options (accelerator is added from `kvm`).
    machine: &'static str,
    /// Run under KVM instead of TCG (needs a usable `/dev/kvm`).
    kvm: bool,
    /// Local APIC mode: `xapic`, `x2apic` or `legacy-pic`.
    mode: &'static str,
    /// Tick clockevent: `lapic-oneshot`, `lapic-deadline` or `pit-periodic`.
    event: &'static str,
    /// Why that mode was chosen (`CHECK apic reason=`): `default`, `hypervisor`,
    /// `no-interrupt-remapping` or `nolapic`. Pins the decision, not just its result.
    reason: &'static str,
    /// Whether PIT IRQ0 must be proven through the IOAPIC: `true`, `false` or `n/a`.
    ioapic_timer: &'static str,
    /// Whether the machine has an HPET (table, reference clock in `CHECK tsc`).
    hpet: bool,
    /// Accepted TSC calibration sources (`CHECK tsc source=`).
    tsc_sources: &'static [&'static str],
}

/// Default q35 under TCG: xAPIC, IOAPIC, HPET and PIT; the CPU model has no
/// TSC-deadline timer, so the one-shot LAPIC timer ticks.
const Q35_TCG: Platform = Platform {
    machine: "q35",
    kvm: false,
    mode: "xapic",
    reason: "default",
    event: "lapic-oneshot",
    ioapic_timer: "true",
    hpet: true,
    tsc_sources: &["pit", "hpet"],
};

const INIT_OK: User = User::Ok {
    argc: 1,
    mode_line: None,
    exact_summary: true,
    protection: (false, false),
};

const BUDDY_ORDER_RECORD: &str = "CHECK buddy-orders ok max_order=10 contiguous=true zeroed=true split=true coalesced=true fragmented=true aligned=131072 rollback=true";
const USER_MM_RECORD: &str = "CHECK user-mm ok pages=3 rollback_points=3 tlb=invlpg protect=ro unmap=3 conflict=rolled-back accounting=restored";
const HEAP_RECORD: &str = "CHECK heap ok vec=1000 box=4096 align=4096 growth=buddy-frames oom=failed-cleanly recovered=true over_cap=rejected accounting=restored";
const IRQ_GUARD_RECORD: &str = "CHECK irq-guard ok nested=2 out_of_order=true saved_on=true saved_off=true exclusive=true blocked_periods=2 blocked_delta=0 resumed=true";
/// Printed by `userspace::start` before ring 3 (self-test builds): the memory syscalls and the
/// one user-copy mechanism on the real tables, faulting pages in with Linux's short-copy results.
/// What init's `demand` mode prints after taking its own ring-3 page faults.
const DEMAND_MODE_LINE: &str = "init: demand ok";
const MM_USERCOPY_RECORD: &str = "CHECK mm-usercopy ok fault_in=read,write short_write=4 hole=8 readonly=refused zero_page=shared range=refused protnone=inverted,restored fixed=replaced stack=grown unmap=restored";
const PF_GPR_RECORD: &str = "CHECK page-fault-gprs ok gprs=15";
const MEMORY_RUNTIME_RECORD: &str = "CHECK memory-runtime ok memset_cases=272 memcpy_cases=4224 zero_length=true boundaries=true padding_fields=true same_allocation=true";

// Records every positive case must print. Extend here; per-module image records are checked in
// `validate_image_serial` because they depend on the case's module layout.
const SUCCESS_MARKERS: &[&str] = &[
    MEMORY_RUNTIME_RECORD,
    "CHECK entry ok",
    "CHECK handoff ok",
    "CHECK module-epoch ok",
    "CHECK memory ok",
    "CHECK paging ok",
    "CHECK table-oom ok",
    "CHECK exception ok",
    PF_GPR_RECORD,
    "CHECK exhaustion ok",
    BUDDY_ORDER_RECORD,
    USER_MM_RECORD,
    HEAP_RECORD,
    IRQ_GUARD_RECORD,
    "CHECK madt ok",
    "CHECK time-tables",
    "CHECK apic ok",
    "CHECK tsc ok",
    "CHECK clockevent ok",
    "CHECK interrupt-controllers ok",
    "CHECK timer ok",
    "CHECK timekeeping ok",
    "TIMER mask observation periods=2 irq_delta=0",
    "CHECKPOINT bootstrap-complete",
    "RESULT success",
];

/// One oracle syscall-test group run on this kernel: `-- <group>` on the command line, the normal
/// success markers, and every `init: test|tests|info` line equal to `xtask/oracle/expected.tsv`
/// ([`validate_oracle`]). Add one `oracle_case!(<group>)` line to [`DEBUG_CASES`] when the group's
/// syscalls land; nothing else needs editing.
macro_rules! oracle_case {
    ($group:ident) => {
        DebugCase {
            name: concat!("oracle-", stringify!($group)),
            cmdline: Some(concat!("-- ", stringify!($group))),
            cpu: "qemu64",
            expected_exit: 33,
            required: SUCCESS_MARKERS,
            forbid_success: false,
            modules: ARCHIVE_ONLY,
            user: User::Oracle(stringify!($group)),
            framebuffers: 1,
            plat: Q35_TCG,
        }
    };
}

const DEBUG_CASES: &[DebugCase] = &[
    DebugCase {
        name: "success",
        cmdline: None,
        cpu: "qemu64",
        expected_exit: 33,
        required: SUCCESS_MARKERS,
        forbid_success: false,
        modules: ARCHIVE_ONLY,
        user: INIT_OK,
        framebuffers: 2,
        plat: Q35_TCG,
    },
    DebugCase {
        name: "panic",
        cmdline: Some("test=panic"),
        cpu: "qemu64",
        expected_exit: 35,
        required: &["FAIL panic", "controlled panic case"],
        forbid_success: true,
        modules: ARCHIVE_ONLY,
        user: User::None,
        framebuffers: 1,
        plat: Q35_TCG,
    },
    DebugCase {
        name: "unexpected-fault",
        cmdline: Some("test=unexpected-fault"),
        cpu: "qemu64",
        expected_exit: 35,
        required: &["FAIL trap vector=6"],
        forbid_success: true,
        modules: ARCHIVE_ONLY,
        user: User::None,
        framebuffers: 1,
        plat: Q35_TCG,
    },
    DebugCase {
        name: "bad-map",
        cmdline: Some("test=bad-map"),
        cpu: "qemu64",
        expected_exit: 35,
        required: &["EXPECTED failure bad-map rejected overflow"],
        forbid_success: true,
        modules: ARCHIVE_ONLY,
        user: User::None,
        framebuffers: 1,
        plat: Q35_TCG,
    },
    DebugCase {
        name: "cpu-without-pat",
        cmdline: None,
        cpu: "qemu64,-pat",
        expected_exit: 35,
        required: &["FAIL cpu error=Pat"],
        forbid_success: true,
        modules: ARCHIVE_ONLY,
        user: User::None,
        framebuffers: 1,
        plat: Q35_TCG,
    },
    DebugCase {
        name: "unexpected-breakpoint",
        cmdline: Some("test=unexpected-breakpoint"),
        cpu: "qemu64",
        expected_exit: 35,
        required: &["FAIL trap vector=3"],
        forbid_success: true,
        modules: ARCHIVE_ONLY,
        user: User::None,
        framebuffers: 1,
        plat: Q35_TCG,
    },
    DebugCase {
        name: "unexpected-interrupt",
        cmdline: Some("test=unexpected-interrupt"),
        cpu: "qemu64",
        expected_exit: 35,
        required: &["FAIL trap vector=unknown-external"],
        forbid_success: true,
        modules: ARCHIVE_ONLY,
        user: User::None,
        framebuffers: 1,
        plat: Q35_TCG,
    },
    DebugCase {
        name: "unmasked-timer",
        cmdline: Some("test=unmasked-timer"),
        cpu: "qemu64",
        expected_exit: 35,
        required: &["FAIL assertion=timer-mask"],
        forbid_success: true,
        modules: ARCHIVE_ONLY,
        user: User::None,
        framebuffers: 1,
        plat: Q35_TCG,
    },
    DebugCase {
        name: "irq-restore-early",
        cmdline: Some("test=irq-restore-early"),
        cpu: "qemu64",
        expected_exit: 35,
        required: &["FAIL irq-guard error=InterruptGuard"],
        forbid_success: true,
        modules: ARCHIVE_ONLY,
        user: User::None,
        framebuffers: 1,
        plat: Q35_TCG,
    },
    DebugCase {
        name: "unexpected-page-fault",
        cmdline: Some("test=unexpected-page-fault"),
        cpu: "qemu64",
        expected_exit: 35,
        required: &["FAIL trap vector=14 error=0x0"],
        forbid_success: true,
        modules: ARCHIVE_ONLY,
        user: User::None,
        framebuffers: 1,
        plat: Q35_TCG,
    },
    DebugCase {
        name: "empty-module",
        cmdline: None,
        cpu: "qemu64",
        expected_exit: 33,
        required: SUCCESS_MARKERS,
        forbid_success: false,
        modules: &[Module::Archive, Module::Empty],
        user: INIT_OK,
        framebuffers: 1,
        plat: Q35_TCG,
    },
    DebugCase {
        name: "bad-module",
        cmdline: None,
        cpu: "qemu64",
        expected_exit: 33,
        required: SUCCESS_MARKERS,
        forbid_success: false,
        modules: &[Module::Corrupt, Module::Archive],
        user: INIT_OK,
        framebuffers: 1,
        plat: Q35_TCG,
    },
    DebugCase {
        name: "init-segfault",
        cmdline: Some("-- fault"),
        cpu: "qemu64",
        expected_exit: 35,
        required: &[
            "init: faulting on purpose",
            "Kernel panic - not syncing: Attempted to kill init! exitcode=0x0000000b",
            "FAIL init exitcode=0x0000000b",
        ],
        forbid_success: true,
        modules: ARCHIVE_ONLY,
        user: User::Segfault,
        framebuffers: 1,
        plat: Q35_TCG,
    },
    DebugCase {
        name: "no-init",
        cmdline: None,
        cpu: "qemu64",
        expected_exit: 35,
        required: &[
            "Kernel panic - not syncing: VFS: Unable to mount root fs on unknown-block(0,0)",
            "FAIL no-root",
        ],
        forbid_success: true,
        modules: NO_INIT_ONLY,
        user: User::NoRoot,
        framebuffers: 1,
        plat: Q35_TCG,
    },
    DebugCase {
        name: "unimplemented-syscall",
        cmdline: Some("-- io_uring"),
        cpu: "qemu64",
        expected_exit: 35,
        required: &[
            "init: calling io_uring_setup",
            "FAIL syscall unimplemented nr=425",
        ],
        forbid_success: true,
        modules: ARCHIVE_ONLY,
        user: User::Unimplemented,
        framebuffers: 1,
        plat: Q35_TCG,
    },
    DebugCase {
        name: "sse",
        cmdline: Some("-- sse"),
        cpu: "qemu64",
        expected_exit: 33,
        required: SUCCESS_MARKERS,
        forbid_success: false,
        modules: ARCHIVE_ONLY,
        user: User::Ok {
            argc: 2,
            mode_line: Some("init: sse ok"),
            exact_summary: true,
            protection: (false, false),
        },
        framebuffers: 1,
        plat: Q35_TCG,
    },
    // Ring-3 demand paging: init faults pages in itself (anonymous zero/private pages and stack
    // growth), so `CHECK user-faults` must count at least one handled fault.
    DebugCase {
        name: "demand",
        cmdline: Some("-- demand"),
        cpu: "qemu64",
        expected_exit: 33,
        required: SUCCESS_MARKERS,
        forbid_success: false,
        modules: ARCHIVE_ONLY,
        user: User::Ok {
            argc: 2,
            mode_line: Some(DEMAND_MODE_LINE),
            exact_summary: true,
            protection: (false, false),
        },
        framebuffers: 1,
        plat: Q35_TCG,
    },
    DebugCase {
        name: "rseq",
        cmdline: Some("-- rseq"),
        cpu: "qemu64",
        expected_exit: 33,
        required: SUCCESS_MARKERS,
        forbid_success: false,
        modules: ARCHIVE_ONLY,
        user: User::Ok {
            argc: 2,
            mode_line: Some("init: rseq enosys"),
            exact_summary: true,
            protection: (false, false),
        },
        framebuffers: 1,
        plat: Q35_TCG,
    },
    DebugCase {
        name: "cpu-max",
        cmdline: Some("-- sse"),
        cpu: "max",
        expected_exit: 33,
        required: SUCCESS_MARKERS,
        forbid_success: false,
        modules: ARCHIVE_ONLY,
        user: User::Ok {
            argc: 2,
            mode_line: Some("init: sse ok"),
            exact_summary: false,
            protection: (true, true),
        },
        framebuffers: 1,
        plat: Q35_TCG,
    },
    // Interrupt-controller / time variants (docs/kernel-tooling.md "Platform cases").
    DebugCase {
        name: "hpet-off",
        cmdline: None,
        cpu: "qemu64",
        expected_exit: 33,
        required: SUCCESS_MARKERS,
        forbid_success: false,
        modules: ARCHIVE_ONLY,
        user: INIT_OK,
        framebuffers: 1,
        plat: Platform {
            machine: "q35,hpet=off",
            hpet: false,
            tsc_sources: &["pit"],
            ..Q35_TCG
        },
    },
    DebugCase {
        name: "pit-off",
        cmdline: None,
        cpu: "qemu64",
        expected_exit: 33,
        required: SUCCESS_MARKERS,
        forbid_success: false,
        modules: ARCHIVE_ONLY,
        user: INIT_OK,
        framebuffers: 1,
        plat: Platform {
            machine: "q35,pit=off",
            ioapic_timer: "false",
            tsc_sources: &["hpet"],
            ..Q35_TCG
        },
    },
    DebugCase {
        name: "nolapic",
        cmdline: Some("nolapic"),
        cpu: "qemu64",
        expected_exit: 33,
        required: SUCCESS_MARKERS,
        forbid_success: false,
        modules: ARCHIVE_ONLY,
        user: INIT_OK,
        framebuffers: 1,
        plat: Platform {
            mode: "legacy-pic",
            reason: "nolapic",
            tsc_sources: &["pit"],
            event: "pit-periodic",
            ioapic_timer: "n/a",
            ..Q35_TCG
        },
    },
    DebugCase {
        name: "noapic",
        cmdline: Some("noapic"),
        cpu: "qemu64",
        expected_exit: 33,
        required: SUCCESS_MARKERS,
        forbid_success: false,
        modules: ARCHIVE_ONLY,
        user: INIT_OK,
        framebuffers: 1,
        plat: Platform {
            ioapic_timer: "n/a",
            ..Q35_TCG
        },
    },
    DebugCase {
        name: "x2apic-forced",
        cmdline: Some("test=force-x2apic"),
        cpu: "qemu64,+x2apic",
        expected_exit: 33,
        required: SUCCESS_MARKERS,
        forbid_success: false,
        modules: ARCHIVE_ONLY,
        user: INIT_OK,
        framebuffers: 1,
        plat: Platform {
            mode: "x2apic",
            reason: "hypervisor",
            ..Q35_TCG
        },
    },
    DebugCase {
        name: "x2apic-firmware",
        cmdline: Some("test=firmware-x2apic"),
        cpu: "qemu64,+x2apic",
        expected_exit: 33,
        required: SUCCESS_MARKERS,
        forbid_success: false,
        modules: ARCHIVE_ONLY,
        user: INIT_OK,
        framebuffers: 1,
        plat: Platform {
            reason: "no-interrupt-remapping",
            ..Q35_TCG
        },
    },
    DebugCase {
        name: "kvm",
        cmdline: None,
        cpu: "host",
        expected_exit: 33,
        required: SUCCESS_MARKERS,
        forbid_success: false,
        modules: ARCHIVE_ONLY,
        user: User::Ok {
            argc: 1,
            mode_line: None,
            exact_summary: false,
            protection: (true, true),
        },
        framebuffers: 1,
        plat: Platform {
            kvm: true,
            mode: "x2apic",
            reason: "hypervisor",
            event: "lapic-deadline",
            tsc_sources: &["pit", "hpet"],
            ..Q35_TCG
        },
    },
    oracle_case!(ids),
    oracle_case!(time),
    // The fs group runs through everything the VFS lane wires and stops at its first `mmap`
    // check (the memory-mapping lane); replace by `oracle_case!(fs)` when `mmap` lands.
    DebugCase {
        name: "oracle-fs-until-mmap",
        cmdline: Some("-- fs"),
        cpu: "qemu64",
        expected_exit: 35,
        required: &["FAIL syscall unimplemented nr=9"],
        forbid_success: true,
        modules: ARCHIVE_ONLY,
        user: User::OracleUntil {
            group: "fs",
            until: "fs.mmap-",
        },
        framebuffers: 1,
        plat: Q35_TCG,
    },
];

/// Expected stdout lines of the oracle syscall suite (`user/init` modes `mm ids time signal fs
/// proc`) as observed on the pinned Linux 6.18.57 (`target/linux-reference/init-reference-006`).
/// Tab-separated `group kind name line`, `#` comments and a header row; see the file header.
/// [`oracle_rows`] reads it; the `kernel-test` cases made by `oracle_case!` compare a run of the
/// mode on this kernel against it.
const ORACLE_EXPECTED: &str = include_str!("../oracle/expected.tsv");

/// One case catalog for execution and downstream evidence packaging.
pub(crate) fn debug_case_catalog() -> impl ExactSizeIterator<Item = (&'static str, i32)> {
    DEBUG_CASES
        .iter()
        .map(|case| (case.name, case.expected_exit))
}

pub(crate) struct Output {
    pub(crate) root: PathBuf,
    pub(crate) path: PathBuf,
    pub(crate) relative: PathBuf,
}

struct Build {
    elf: PathBuf,
    elf_relative: PathBuf,
    map_relative: PathBuf,
    elf_hash: String,
    executable_segments: Vec<(u64, u64)>,
    qemu_self_test: bool,
}

struct Tool {
    path: PathBuf,
    version: String,
}

struct QemuTools {
    qemu: Tool,
    limine: Tool,
    mkfs_fat: PathBuf,
    mdir: Tool,
    mmd: Tool,
    mcopy: Tool,
    sha256sum: Tool,
    fixtures: Fixtures,
}

/// (module file name, SHA-256 of its copy extracted from the FAT image), in boot order.
type ModuleHashes = Vec<(&'static str, String)>;

struct BootImage {
    disk: PathBuf,
    vars_copy: PathBuf,
    vars_sha256_initial: String,
    disk_sha256_initial: String,
    kernel_image_sha256: String,
    limine_image_sha256: String,
    module_image_sha256: ModuleHashes,
}

pub(crate) struct ProcessResult {
    pub(crate) exit_code: Option<i32>,
    pub(crate) timed_out: bool,
}

struct CaseResult {
    name: &'static str,
    cpu: &'static str,
    passed: bool,
    /// The case could not be run on this host (e.g. no usable `/dev/kvm`): neither
    /// a pass nor a failure, reported separately and never counted as matched.
    unavailable: bool,
    expected_exit: i32,
    observed_exit: Option<i32>,
    timed_out: bool,
    diagnostic: String,
    output: PathBuf,
}

struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| invalid("process was already reaped"))?;
        if let Some(status) = child.try_wait()? {
            // A successful parent must not leave compiler/helper descendants behind.
            let group = child.id();
            self.child = None;
            kill_process_group(group)?;
            Ok(Some(status))
        } else {
            Ok(None)
        }
    }

    fn stop_and_reap(&mut self) -> io::Result<Option<ExitStatus>> {
        let Some(mut child) = self.child.take() else {
            return Ok(None);
        };
        let group_result = kill_process_group(child.id());
        // Also kill/reap the direct child if the external group-kill utility failed.
        let direct_result = child.kill();
        let status = child.wait()?;
        group_result?;
        if let Err(error) = direct_result
            && error.kind() != io::ErrorKind::InvalidInput
        {
            return Err(error);
        }
        Ok(Some(status))
    }
}

fn kill_process_group(group: u32) -> io::Result<()> {
    // This fixed, non-shell utility is the only signal boundary; every
    // ordinary child is placed in its own group.
    let mut signal = Command::new(KILL)
        .args(["--signal", "KILL", "--", &format!("-{group}")])
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()?;
    let start = Instant::now();
    loop {
        let status = match signal.try_wait() {
            Ok(status) => status,
            Err(error) => {
                let _ = signal.kill();
                let _ = signal.wait();
                return Err(error);
            }
        };
        if let Some(status) = status {
            // Exit 1 also means the process group has already disappeared.
            return if matches!(status.code(), Some(0 | 1)) {
                Ok(())
            } else {
                Err(invalid(format!("process-group kill exited with {status}")))
            };
        }
        if start.elapsed() >= Duration::from_secs(2) {
            let kill = signal.kill();
            let reap = signal.wait();
            kill?;
            reap?;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "process-group kill timed out",
            ));
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn isolate_command(command: &mut Command) {
    let explicit = command
        .get_envs()
        .map(|(key, value)| (key.to_os_string(), value.map(OsStr::to_os_string)))
        .collect::<Vec<_>>();
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .process_group(0);
    for (key, value) in explicit {
        if let Some(value) = value {
            command.env(key, value);
        } else {
            command.env_remove(key);
        }
    }
}

/// Wrap a long-lived child so it gets SIGKILL when xtask's spawning thread dies
/// (Ctrl-C, SIGTERM, an aborting panic), instead of being orphaned. `setpriv`
/// sets `PR_SET_PDEATHSIG` and execs in place, keeping pid and process group.
/// The signal follows the spawning thread: every caller spawns on the thread that
/// waits for the child. shortcut: no `getppid` recheck, so a parent dying between
/// fork and the `prctl` still orphans the child; closing that needs `unsafe`/a crate.
fn supervised(program: &Path) -> Command {
    let mut command = Command::new(SETPRIV);
    command.args(["--pdeathsig", "KILL", "--"]).arg(program);
    command
}

fn record_setpriv(
    root: &Path,
    sha256sum: &Path,
    values: &mut BTreeMap<String, String>,
) -> io::Result<()> {
    // Canonical, like `process_group_kill_path`: package compares it with the hashed runtime input.
    manifest_value(
        values,
        "setpriv_path",
        display_path(&fs::canonicalize(SETPRIV)?)?,
    );
    manifest_value(
        values,
        "setpriv_version",
        single_line(&tool_output(Path::new(SETPRIV), &["--version"], root)?),
    );
    manifest_value(
        values,
        "sha256_setpriv",
        file_hash(root, sha256sum, Path::new(SETPRIV))?,
    );
    Ok(())
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.stop_and_reap();
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn contextual(path: &Path, error: &io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{}: {error}", path.display()))
}

fn create_new(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| contextual(path, &error))
}

fn ensure_real_directory(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            Err(invalid(format!(
                "{} must be a real directory, not a symlink or special file",
                path.display()
            )))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(|create_error| contextual(path, &create_error))
        }
        Err(error) => Err(contextual(path, &error)),
    }
}

fn clean_absolute_path(path: &Path) -> io::Result<PathBuf> {
    if path
        .components()
        .any(|component| component == std::path::Component::ParentDir)
    {
        return Err(invalid(format!(
            "parent traversal is not permitted: {}",
            path.display()
        )));
    }
    std::path::absolute(path)
}

fn require_real_ancestors(path: &Path) -> io::Result<()> {
    let mut ancestor = PathBuf::new();
    for component in path.components() {
        ancestor.push(component);
        let metadata = fs::symlink_metadata(&ancestor)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(invalid(format!(
                "directory ancestor is a symlink or special file: {}",
                ancestor.display()
            )));
        }
    }
    Ok(())
}

pub(crate) fn prepare_output(root: &Path, requested: &Path) -> io::Result<Output> {
    let root = clean_absolute_path(root)?;
    require_real_ancestors(&root)?;
    if requested
        .components()
        .any(|component| component == std::path::Component::ParentDir)
    {
        return Err(invalid("--output must not contain parent traversal"));
    }
    let target = root.join("target");
    ensure_real_directory(&target)?;
    let base = target.join("kernel-tooling");
    ensure_real_directory(&base)?;
    let requested = clean_absolute_path(&root.join(requested))?;
    if requested.parent() != Some(base.as_path()) {
        return Err(invalid(format!(
            "--output must be a direct child of {}/target/kernel-tooling",
            root.display()
        )));
    }
    let name = requested
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| invalid("--output must have a UTF-8 directory name"))?;
    if name.is_empty()
        || name.len() > 20
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(invalid(
            "--output directory name must contain 1-20 ASCII letters, digits, '-' or '_'",
        ));
    }
    match fs::symlink_metadata(&requested) {
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "refusing to reuse existing output directory {}",
                    requested.display()
                ),
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(contextual(&requested, &error)),
    }
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&requested)
        .map_err(|error| contextual(&requested, &error))?;
    let path = fs::canonicalize(&requested).map_err(|error| contextual(&requested, &error))?;
    let relative = path
        .strip_prefix(&root)
        .map_err(|error| invalid(format!("output escaped project root: {error}")))?
        .to_path_buf();
    Ok(Output {
        root,
        path,
        relative,
    })
}

fn relative_path(root: &Path, path: &Path) -> io::Result<PathBuf> {
    path.strip_prefix(root)
        .map(Path::to_path_buf)
        .map_err(|error| {
            invalid(format!(
                "{} is outside project root: {error}",
                path.display()
            ))
        })
}

fn display_path(path: &Path) -> io::Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid("path contains non-UTF-8 bytes"))
}

fn create_directory(path: &Path) -> io::Result<()> {
    fs::create_dir(path).map_err(|error| contextual(path, &error))
}

pub(crate) fn resolve_program(program: &Path) -> io::Result<PathBuf> {
    let candidates = if program.components().count() > 1 || program.is_absolute() {
        vec![program.to_path_buf()]
    } else {
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            // Empty and relative entries mean the current directory, which can hold planted tools.
            .filter(|directory| directory.is_absolute())
            .map(|directory| directory.join(program))
            .collect()
    };
    for candidate in candidates {
        if fs::metadata(&candidate)
            .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        {
            // Preserve argv[0] for multicall tools such as mtools. Rustup
            // proxies are resolved separately to the actual compiler binaries.
            return std::path::absolute(candidate);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("required executable {} was not found", program.display()),
    ))
}

fn drain_capture(stream: &mut UnixStream, bytes: &mut Vec<u8>) -> io::Result<bool> {
    let mut buffer = [0_u8; 8192];
    // Return regularly even if a child continuously fills the socket.
    for _ in 0..32 {
        match stream.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(count) => {
                if bytes.len() + count > CAPTURE_LIMIT {
                    return Err(invalid(
                        "external command exceeded the metadata capture limit",
                    ));
                }
                bytes.extend_from_slice(&buffer[..count]);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

fn capture_command(command: &mut Command, timeout: Duration) -> io::Result<Vec<u8>> {
    let (mut stdout, stdout_child) = UnixStream::pair()?;
    let (mut stderr, stderr_child) = UnixStream::pair()?;
    stdout.set_nonblocking(true)?;
    stderr.set_nonblocking(true)?;
    command
        .stdout(Stdio::from(OwnedFd::from(stdout_child)))
        .stderr(Stdio::from(OwnedFd::from(stderr_child)));
    let mut child = create_process(command)?;
    // Command retains its stdio handles after spawn; release its socket ends.
    command.stdout(Stdio::null()).stderr(Stdio::null());
    let mut out = Vec::new();
    let mut err = Vec::new();
    let start = Instant::now();
    let mut status = None;
    loop {
        let out_done = drain_capture(&mut stdout, &mut out)?;
        let err_done = drain_capture(&mut stderr, &mut err)?;
        if status.is_none() {
            status = child.try_wait()?;
        }
        if let Some(status) = status
            && out_done
            && err_done
        {
            return if status.success() {
                Ok(out)
            } else {
                Err(invalid(format!(
                    "{} exited with {status}: {}",
                    command.get_program().to_string_lossy(),
                    String::from_utf8_lossy(&err).trim()
                )))
            };
        }
        if start.elapsed() >= timeout {
            child.stop_and_reap()?;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "{} exceeded {} ms; stderr: {}",
                    command.get_program().to_string_lossy(),
                    timeout.as_millis(),
                    String::from_utf8_lossy(&err).trim()
                ),
            ));
        }
        thread::sleep(Duration::from_millis(5));
    }
}

pub(crate) fn tool_output(path: &Path, args: &[&str], root: &Path) -> io::Result<String> {
    let mut command = Command::new(path);
    command.args(args).current_dir(root);
    let bytes = capture_command(&mut command, METADATA_TIMEOUT)?;
    let text = String::from_utf8(bytes)
        .map_err(|error| invalid(format!("{} output was not UTF-8: {error}", path.display())))?;
    Ok(text.trim().to_owned())
}

fn tool(root: &Path, name: &str, args: &[&str]) -> io::Result<Tool> {
    let path = resolve_program(Path::new(name))?;
    let version = tool_output(&path, args, root)?;
    Ok(Tool { path, version })
}

fn validate_input(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| contextual(path, &error))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(invalid(format!(
            "{} must be a regular file, not a symlink or special file",
            path.display()
        )));
    }
    Ok(())
}

pub(crate) fn run_with_logs(
    command: &mut Command,
    stdout_path: &Path,
    stderr_path: &Path,
    timeout: Duration,
) -> io::Result<ProcessResult> {
    let stdout = create_new(stdout_path)?;
    let stderr = create_new(stderr_path)?;
    command
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    let child = create_process(command)?;
    wait_for_exit(child, timeout)
}

fn wait_for_exit(mut child: ChildGuard, timeout: Duration) -> io::Result<ProcessResult> {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(ProcessResult {
                exit_code: status.code(),
                timed_out: false,
            });
        }
        if start.elapsed() >= timeout {
            let status = child
                .stop_and_reap()?
                .ok_or_else(|| invalid("timed-out process disappeared before reaping"))?;
            return Ok(ProcessResult {
                exit_code: status.code(),
                timed_out: true,
            });
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn command_args<I, S>(args: I) -> io::Result<Vec<String>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    args.into_iter()
        .map(|arg| {
            arg.as_ref()
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| invalid("command argument contains non-UTF-8 bytes"))
        })
        .collect()
}

fn create_log_dir(output: &Path) -> io::Result<PathBuf> {
    let path = output.join("tool-versions");
    ensure_real_directory(&path)?;
    Ok(path)
}

fn capture_tool_version(
    root: &Path,
    output: &Path,
    name: &'static str,
    args: &[&str],
) -> io::Result<Tool> {
    let tool = tool(root, name, args)?;
    let version_dir = create_log_dir(output)?;
    let version_path = version_dir.join(format!("{name}-version.txt"));
    write_new(&version_path, tool.version.as_bytes())?;
    Ok(tool)
}

fn write_new(path: &Path, content: &[u8]) -> io::Result<()> {
    let mut file = create_new(path)?;
    file.write_all(content)
        .map_err(|error| contextual(path, &error))
}

pub(crate) fn file_hash(root: &Path, sha256sum: &Path, path: &Path) -> io::Result<String> {
    let mut command = Command::new(sha256sum);
    command.arg("--").arg(path).current_dir(root);
    let bytes = capture_command(&mut command, METADATA_TIMEOUT)?;
    let line = String::from_utf8(bytes)
        .map_err(|error| invalid(format!("sha256sum output was not UTF-8: {error}")))?;
    let digest = line.split_ascii_whitespace().next().ok_or_else(|| {
        invalid(format!(
            "sha256sum returned no digest for {}",
            path.display()
        ))
    })?;
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid(format!(
            "sha256sum returned invalid digest {digest:?}"
        )));
    }
    Ok(digest.to_owned())
}

fn write_manifest(path: &Path, values: BTreeMap<String, String>) -> io::Result<()> {
    // Validate every row before creating the file, so a bad value leaves no partial manifest.
    let mut text = String::from("key\tvalue\n");
    for (key, value) in values {
        if key.contains(['\t', '\n', '\r']) || value.contains(['\t', '\n', '\r']) {
            return Err(invalid(format!(
                "manifest field contains a tab or newline: {key:?}"
            )));
        }
        writeln!(text, "{key}\t{value}").map_err(|error| invalid(error.to_string()))?;
    }
    write_new(path, text.as_bytes())
}

fn manifest_value(values: &mut BTreeMap<String, String>, key: &str, value: impl Into<String>) {
    values.insert(key.to_owned(), value.into());
}

fn single_line(value: &str) -> String {
    value
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("; ")
        // Tabs and other controls would make write_manifest/parse_manifest reject the row.
        .replace(char::is_control, " ")
}

fn git_value(root: &Path, args: &[&str]) -> String {
    let Ok(git) = resolve_program(Path::new("git")) else {
        return "unavailable".to_owned();
    };
    let mut command = Command::new(git);
    command
        .args(args)
        .current_dir(root)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_OPTIONAL_LOCKS", "0");
    capture_command(&mut command, METADATA_TIMEOUT).map_or_else(
        |_| "unavailable".to_owned(),
        |bytes| String::from_utf8_lossy(&bytes).trim().to_owned(),
    )
}

fn collect_source_tree(directory: &Path, files: &mut Vec<PathBuf>) -> io::Result<()> {
    let metadata = fs::symlink_metadata(directory)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid(format!(
            "source directory is not a real directory: {}",
            directory.display()
        )));
    }
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let kind = entry.file_type()?;
        if kind.is_dir() {
            collect_source_tree(&path, files)?;
        } else if kind.is_file() {
            files.push(path);
        } else {
            return Err(invalid(format!(
                "source symlink or special file is forbidden: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

/// Every workspace member whose source is bound to a build and shipped as corresponding source.
pub(crate) const SOURCE_MEMBERS: [&str; 5] = ["kernel", "rt", "user/init", "xtask", "baremetal"];

fn source_files(root: &Path) -> io::Result<Vec<PathBuf>> {
    let mut files = vec![
        root.join("Cargo.toml"),
        root.join("Cargo.lock"),
        root.join("LICENSE"),
    ];
    for directory in SOURCE_MEMBERS {
        collect_source_tree(&root.join(directory), &mut files)?;
    }
    // Optional: absent in a tree with no registry dependencies.
    for optional in [".cargo/config.toml", "vendor"] {
        let path = root.join(optional);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_dir() => collect_source_tree(&path, &mut files)?,
            Ok(_) => files.push(path),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(contextual(&path, &error)),
        }
    }
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        let name = path.file_name().and_then(OsStr::to_str).unwrap_or("");
        if name.starts_with("rust-toolchain") {
            files.push(path);
        }
    }
    files.sort();
    files.dedup();
    Ok(files)
}

pub(crate) fn hash_files(
    root: &Path,
    sha256sum: &Path,
    files: &[PathBuf],
) -> io::Result<BTreeMap<PathBuf, String>> {
    let mut hashes = BTreeMap::new();
    // Batch source hashing: a separate process per Rust library file is wasteful.
    for batch in files.chunks(128) {
        for path in batch {
            validate_input(path)?;
        }
        let mut command = Command::new(sha256sum);
        command
            .args(["--binary", "--zero", "--"])
            .args(batch)
            .current_dir(root);
        let bytes = capture_command(&mut command, METADATA_TIMEOUT)?;
        let mut records = bytes.split(|byte| *byte == 0);
        for path in batch {
            let record = records
                .next()
                .ok_or_else(|| invalid("missing SHA-256 record"))?;
            if record.len() < 66
                || &record[64..66] != b" *"
                || record[66..] != *path.as_os_str().as_encoded_bytes()
                || !record[..64].iter().all(u8::is_ascii_hexdigit)
            {
                return Err(invalid(
                    "SHA-256 record does not bind the requested source path",
                ));
            }
            let digest =
                std::str::from_utf8(&record[..64]).map_err(|error| invalid(error.to_string()))?;
            hashes.insert(path.clone(), digest.to_owned());
        }
        if records.next() != Some(&[][..]) || records.next().is_some() {
            return Err(invalid("unexpected trailing SHA-256 output"));
        }
    }
    Ok(hashes)
}

fn write_input_manifest(path: &Path, hashes: &BTreeMap<PathBuf, String>) -> io::Result<()> {
    let mut values = BTreeMap::new();
    manifest_value(&mut values, "schema", "1");
    manifest_value(&mut values, "source_count", hashes.len().to_string());
    for (index, (source, digest)) in hashes.iter().enumerate() {
        let prefix = format!("source_{index:05}");
        manifest_value(
            &mut values,
            &format!("{prefix}_path"),
            display_path(source)?,
        );
        manifest_value(&mut values, &format!("{prefix}_sha256"), digest);
    }
    write_manifest(path, values)
}

fn require_unchanged(
    before: &BTreeMap<PathBuf, String>,
    after: &BTreeMap<PathBuf, String>,
) -> io::Result<()> {
    if before != after {
        let changed = before
            .keys()
            .chain(after.keys())
            .find(|path| before.get(*path) != after.get(*path))
            .ok_or_else(|| invalid("input set changed"))?;
        return Err(invalid(format!(
            "build input set or bytes changed: {}; before/after evidence retained",
            changed.display()
        )));
    }
    Ok(())
}

fn reject_build_overrides(root: &Path) -> io::Result<()> {
    reject_ambient_env(std::env::vars_os())?;
    reject_inherited_cargo_config(root)
}

fn reject_ambient_env(vars: impl IntoIterator<Item = (OsString, OsString)>) -> io::Result<()> {
    for (key, value) in vars {
        let name = key.to_string_lossy();
        let override_key = matches!(
            name.as_ref(),
            "RUSTC"
                | "RUSTC_WRAPPER"
                | "RUSTC_WORKSPACE_WRAPPER"
                | "RUSTFLAGS"
                | "CARGO_ENCODED_RUSTFLAGS"
                | "RUSTC_BOOTSTRAP"
                | "RUST_TARGET_PATH"
                | "LD_PRELOAD"
        ) || [
            "CARGO_BUILD_",
            "CARGO_TARGET_",
            "CARGO_PROFILE_",
            "CARGO_SOURCE_",
            "CARGO_UNSTABLE_",
        ]
        .iter()
        .any(|prefix| name.starts_with(prefix));
        if override_key && !value.is_empty() {
            return Err(invalid(format!(
                "kernel builds reject ambient override {name}"
            )));
        }
    }
    Ok(())
}

// Cargo merges every `.cargo/config*` from the working directory upwards. The only
// one accepted is the reviewed host source replacement, byte-identical, at the
// root or in an enclosing checkout (e.g. a worktree nested under the main checkout's
// `target/`). That is safe: its relative `directory = "vendor"` resolves against
// the file's own directory, the deeper (root) config takes precedence for the same
// keys, and build-std builds override `crates-io` with the per-run `--config`
// file anyway. Anything else, including a legacy `.cargo/config`, is rejected.
fn reject_inherited_cargo_config(root: &Path) -> io::Result<()> {
    // A root with its own vendor/ but no reviewed config would resolve an enclosing checkout's.
    if root.join("vendor").exists() && !root.join(".cargo/config.toml").is_file() {
        return Err(invalid(
            "a root with vendor/ must carry the reviewed .cargo/config.toml itself",
        ));
    }
    for directory in root.ancestors() {
        for name in [".cargo/config", ".cargo/config.toml"] {
            let config = directory.join(name);
            match fs::symlink_metadata(&config) {
                Ok(metadata) if metadata.is_file() && name == ".cargo/config.toml" => {
                    let text = fs::read(&config).map_err(|error| contextual(&config, &error))?;
                    if text != PROJECT_CARGO_CONFIG.as_bytes() {
                        return Err(invalid(format!(
                            "{} differs from the reviewed source replacement",
                            config.display()
                        )));
                    }
                }
                Ok(_) => {
                    return Err(invalid(format!(
                        "kernel builds reject inherited Cargo configuration: {}",
                        config.display()
                    )));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(contextual(&config, &error)),
            }
        }
    }
    Ok(())
}

fn compiler_support_files(sysroot: &Path) -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    // rustc loads these compiler libraries from its own sysroot.
    for entry in fs::read_dir(sysroot.join("lib"))? {
        let path = entry?.path();
        let name = path.file_name().and_then(OsStr::to_str).unwrap_or("");
        if name.starts_with("librustc_driver") || name.starts_with("libLLVM") {
            files.push(fs::canonicalize(path)?);
        }
    }
    files.sort();
    files.dedup();
    Ok(files)
}

fn runtime_source_files(sysroot: &Path) -> io::Result<Vec<PathBuf>> {
    let mut files = compiler_support_files(sysroot)?;
    collect_source_tree(&sysroot.join("lib/rustlib/src/rust/library"), &mut files)?;
    collect_source_tree(&sysroot.join("share/doc/rust/licenses"), &mut files)?;
    files.push(sysroot.join("share/doc/rust/COPYRIGHT-library.html"));
    files.sort();
    Ok(files)
}

#[derive(Debug)]
pub(crate) struct LockedRegistryPackage {
    name: String,
    version: String,
    checksum: String,
}

fn lock_field(line: &str, name: &str) -> Option<String> {
    let prefix = format!("{name} = \"");
    line.trim()
        .strip_prefix(&prefix)?
        .strip_suffix('"')
        .map(str::to_owned)
}

fn parse_std_registry_packages(lock: &Path) -> io::Result<Vec<LockedRegistryPackage>> {
    let text = fs::read_to_string(lock).map_err(|error| contextual(lock, &error))?;
    let mut packages = Vec::new();
    let mut fields = BTreeMap::new();
    let mut in_package = false;
    for line in text.lines() {
        if line.trim() == "[[package]]" {
            if in_package {
                finish_lock_package(&fields, &mut packages)?;
                fields.clear();
            }
            in_package = true;
            continue;
        }
        if in_package {
            for field in ["name", "version", "source", "checksum"] {
                if let Some(value) = lock_field(line, field)
                    && fields.insert(field, value).is_some()
                {
                    return Err(invalid(format!("duplicate {field} in std Cargo.lock")));
                }
            }
        }
    }
    if in_package {
        finish_lock_package(&fields, &mut packages)?;
    }
    packages.sort_by(|left, right| (&left.name, &left.version).cmp(&(&right.name, &right.version)));
    if packages
        .windows(2)
        .any(|pair| pair[0].name == pair[1].name && pair[0].version == pair[1].version)
    {
        return Err(invalid("duplicate registry package in std Cargo.lock"));
    }
    Ok(packages)
}

fn finish_lock_package(
    fields: &BTreeMap<&str, String>,
    packages: &mut Vec<LockedRegistryPackage>,
) -> io::Result<()> {
    let Some(source) = fields.get("source") else {
        return Ok(());
    };
    if source != "registry+https://github.com/rust-lang/crates.io-index" {
        return Err(invalid(format!(
            "unsupported std dependency source {source}; no network fallback"
        )));
    }
    let field = |name| {
        fields
            .get(name)
            .cloned()
            .ok_or_else(|| invalid(format!("std registry package has no {name}")))
    };
    let name = field("name")?;
    let version = field("version")?;
    let checksum = field("checksum")?;
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'+'))
        || name.is_empty()
        || version.is_empty()
        || checksum.len() != 64
        || !checksum.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(invalid(
            "invalid std registry package name, version or checksum",
        ));
    }
    packages.push(LockedRegistryPackage {
        name,
        version,
        checksum,
    });
    Ok(())
}

struct VendoredStdInputs {
    library: PathBuf,
    lock_file: PathBuf,
    source_config: PathBuf,
    local_config: PathBuf,
    manifest: PathBuf,
}

// The installed vendor checksum format contains only string/object values.
// Reject unsupported syntax instead of inventing an unauthenticated fallback.
struct ChecksumJson<'a> {
    rest: &'a str,
}

impl ChecksumJson<'_> {
    fn consume(&mut self, token: char) -> io::Result<()> {
        self.rest = self.rest.trim_start();
        self.rest = self
            .rest
            .strip_prefix(token)
            .ok_or_else(|| invalid(format!("expected {token:?} in vendor checksum JSON")))?;
        Ok(())
    }

    fn string(&mut self) -> io::Result<String> {
        self.consume('"')?;
        let mut value = String::new();
        loop {
            let character = self
                .rest
                .chars()
                .next()
                .ok_or_else(|| invalid("unterminated vendor checksum JSON string"))?;
            self.rest = &self.rest[character.len_utf8()..];
            match character {
                '"' => return Ok(value),
                '\\' => {
                    let escaped = self
                        .rest
                        .chars()
                        .next()
                        .ok_or_else(|| invalid("truncated JSON escape"))?;
                    self.rest = &self.rest[escaped.len_utf8()..];
                    value.push(match escaped {
                        '"' | '\\' | '/' => escaped,
                        'n' => '\n',
                        'r' => '\r',
                        't' => '\t',
                        'b' => '\u{8}',
                        'f' => '\u{c}',
                        'u' => {
                            let digits = self
                                .rest
                                .get(..4)
                                .ok_or_else(|| invalid("truncated unicode escape"))?;
                            let code = u32::from_str_radix(digits, 16)
                                .map_err(|error| invalid(error.to_string()))?;
                            self.rest = &self.rest[4..];
                            char::from_u32(code)
                                .ok_or_else(|| invalid("unsupported unicode surrogate"))?
                        }
                        _ => return Err(invalid("unsupported vendor JSON escape")),
                    });
                }
                character if character.is_control() => {
                    return Err(invalid("control byte in checksum JSON"));
                }
                _ => value.push(character),
            }
        }
    }

    fn fields(&mut self) -> io::Result<BTreeMap<String, String>> {
        self.consume('{')?;
        let mut values = BTreeMap::new();
        if !self.rest.trim_start().starts_with('}') {
            loop {
                let key = self.string()?;
                self.consume(':')?;
                if values.insert(key, self.string()?).is_some() {
                    return Err(invalid("duplicate vendor checksum field"));
                }
                if self.rest.trim_start().starts_with('}') {
                    break;
                }
                self.consume(',')?;
            }
        }
        self.consume('}')?;
        Ok(values)
    }
}

fn vendor_checksums(text: &str) -> io::Result<(String, BTreeMap<String, String>)> {
    let mut json = ChecksumJson { rest: text };
    json.consume('{')?;
    let mut package = None;
    let mut files = None;
    let mut comment_seen = false;
    loop {
        let key = json.string()?;
        json.consume(':')?;
        match key.as_str() {
            "package" if package.is_none() => package = Some(json.string()?),
            "files" if files.is_none() => files = Some(json.fields()?),
            "$comment" if !comment_seen => {
                let _ = json.string()?;
                comment_seen = true;
            }
            _ => return Err(invalid("unknown or duplicate vendor checksum key")),
        }
        if json.rest.trim_start().starts_with('}') {
            break;
        }
        json.consume(',')?;
    }
    json.consume('}')?;
    if !json.rest.trim().is_empty() {
        return Err(invalid("trailing vendor checksum JSON"));
    }
    Ok((
        package.ok_or_else(|| invalid("missing vendor package checksum"))?,
        files.ok_or_else(|| invalid("missing vendor file checksums"))?,
    ))
}

fn verify_vendor_checksums(
    directory: &Path,
    package: &LockedRegistryPackage,
    hashes: &BTreeMap<PathBuf, String>,
) -> io::Result<()> {
    let checksum_path = directory.join(".cargo-checksum.json");
    let (checksum, files) = vendor_checksums(&fs::read_to_string(&checksum_path)?)?;
    if checksum != package.checksum || files.is_empty() {
        return Err(invalid(format!(
            "vendor integrity metadata does not match locked {}",
            package.name
        )));
    }
    // Cargo itself only checks the listed files; an unlisted extra file would be unhashed source.
    let actual = hashes
        .keys()
        .filter(|path| path.starts_with(directory) && *path != &checksum_path)
        .count();
    if actual != files.len() {
        return Err(invalid(format!(
            "vendor package {} has {actual} files but its checksum manifest lists {}",
            package.name,
            files.len()
        )));
    }
    for (relative, expected) in files {
        let relative = Path::new(&relative);
        if relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
            || hashes.get(&directory.join(relative)) != Some(&expected)
        {
            return Err(invalid(format!(
                "vendor file checksum mismatch: {}",
                directory.join(relative).display()
            )));
        }
    }
    Ok(())
}

fn toml_string(value: &str) -> String {
    let mut quoted = String::from("\"");
    for character in value.chars() {
        match character {
            '\\' | '"' => {
                quoted.push('\\');
                quoted.push(character);
            }
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\t' => quoted.push_str("\\t"),
            _ => quoted.push(character),
        }
    }
    quoted.push('"');
    quoted
}

/// Verifies the root `vendor/` directory against the root `Cargo.lock`: the exact locked
/// registry package set, checksum manifests, no unlisted file and only reviewed build scripts.
/// Returns `(package, directory)` pairs. A lock with no registry packages needs no `vendor/`.
pub(crate) fn verify_project_vendor(
    root: &Path,
    sha256sum: &Path,
) -> io::Result<Vec<(LockedRegistryPackage, PathBuf)>> {
    let packages = parse_std_registry_packages(&root.join("Cargo.lock"))?;
    let vendor = root.join("vendor");
    let mut files = Vec::new();
    match fs::symlink_metadata(&vendor) {
        Ok(_) => collect_source_tree(&vendor, &mut files)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound && packages.is_empty() => {
            return Ok(Vec::new());
        }
        Err(error) => return Err(contextual(&vendor, &error)),
    }
    let hashes = hash_files(root, sha256sum, &files)?;
    let expected = packages
        .iter()
        .map(|package| format!("{}-{}", package.name, package.version))
        .collect::<BTreeSet<_>>();
    let mut found = BTreeSet::new();
    for entry in fs::read_dir(&vendor)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            return Err(invalid(format!(
                "vendor/ may contain only package directories: {}",
                entry.path().display()
            )));
        }
        found.insert(entry.file_name().to_string_lossy().into_owned());
    }
    if found != expected {
        return Err(invalid(format!(
            "vendor/ does not match Cargo.lock; unexpected {:?}, missing {:?}",
            found.difference(&expected).collect::<Vec<_>>(),
            expected.difference(&found).collect::<Vec<_>>()
        )));
    }
    for file in &files {
        let relative = file
            .strip_prefix(&vendor)
            .map_err(|error| invalid(error.to_string()))?;
        let is_script = relative.file_name().is_some_and(|name| name == "build.rs");
        let allowed = VENDOR_BUILD_SCRIPTS
            .iter()
            .any(|(package, script)| relative == Path::new(package).join(script));
        if is_script && !allowed {
            return Err(invalid(format!(
                "unreviewed vendored build script: vendor/{}",
                relative.display()
            )));
        }
    }
    let verified = packages
        .into_iter()
        .map(|package| {
            let directory = vendor.join(format!("{}-{}", package.name, package.version));
            verify_vendor_checksums(&directory, &package, &hashes)?;
            Ok((package, directory))
        })
        .collect::<io::Result<Vec<_>>>()?;
    verify_build_scripts(root, &expected)?;
    Ok(verified)
}

fn cargo_program() -> io::Result<PathBuf> {
    match std::env::var_os("CARGO").map(PathBuf::from) {
        Some(path) if path.is_absolute() => Ok(path),
        _ => resolve_program(Path::new("cargo")),
    }
}

/// Asks Cargo itself which targets are build scripts (`custom-build`) or proc-macros, whatever
/// the manifest spelling, and requires each to be a reviewed entry. `--all-features` makes
/// optional dependencies (the kernel's are behind `freestanding`) visible, and every locked
/// registry package must appear in the output or the check fails closed. The reviewed
/// `.cargo/config.toml` is forced with `--config`; ambient overrides are rejected as for builds.
fn verify_build_scripts(root: &Path, locked: &BTreeSet<String>) -> io::Result<()> {
    reject_build_overrides(root)?;
    let mut command = Command::new(cargo_program()?);
    command
        .args([
            "metadata",
            "--offline",
            "--locked",
            "--all-features",
            "--format-version",
            "1",
            "--config",
            ".cargo/config.toml",
        ])
        .current_dir(root);
    let output = capture_command(&mut command, METADATA_TIMEOUT)?;
    let metadata = serde_json::from_slice(&output)
        .map_err(|error| invalid(format!("cargo metadata output is not JSON: {error}")))?;
    check_vendored_targets(&metadata, &root.join("vendor"), locked)
}

fn check_vendored_targets(
    metadata: &serde_json::Value,
    vendor: &Path,
    locked: &BTreeSet<String>,
) -> io::Result<()> {
    let missing = || invalid("cargo metadata lacks an expected field");
    let mut seen = BTreeSet::new();
    for package in metadata["packages"].as_array().ok_or_else(missing)? {
        let name = package["name"].as_str().ok_or_else(missing)?;
        let version = package["version"].as_str().ok_or_else(missing)?;
        let id = format!("{name}-{version}");
        if package["source"].is_string() {
            seen.insert(id.clone());
        }
        for target in package["targets"].as_array().ok_or_else(missing)? {
            let kinds = target["kind"].as_array().ok_or_else(missing)?;
            let has = |kind: &str| kinds.iter().any(|value| value == kind);
            if has("proc-macro") && !VENDOR_PROC_MACROS.contains(&id.as_str()) {
                return Err(invalid(format!("unreviewed proc-macro: {id}")));
            }
            if has("custom-build") {
                let source = Path::new(target["src_path"].as_str().ok_or_else(missing)?);
                // Exact file identity, not a path-suffix match.
                let reviewed = VENDOR_BUILD_SCRIPTS
                    .iter()
                    .filter(|(package, _)| *package == id)
                    .any(|(package, script)| {
                        matches!(
                            (
                                fs::canonicalize(source),
                                fs::canonicalize(vendor.join(package).join(script))
                            ),
                            (Ok(actual), Ok(expected)) if actual == expected
                        )
                    });
                if !reviewed {
                    return Err(invalid(format!(
                        "unreviewed build script: {id} {}",
                        source.display()
                    )));
                }
            }
        }
    }
    if let Some(absent) = locked.difference(&seen).next() {
        return Err(invalid(format!(
            "cargo metadata omitted locked package {absent}; the build-script gate would be inert"
        )));
    }
    Ok(())
}

fn record_locked(
    inputs: &mut BTreeMap<String, String>,
    prefix: &str,
    package: &LockedRegistryPackage,
) {
    manifest_value(inputs, &format!("{prefix}_name"), &package.name);
    manifest_value(inputs, &format!("{prefix}_version"), &package.version);
    manifest_value(
        inputs,
        &format!("{prefix}_lock_checksum"),
        &package.checksum,
    );
}

fn link_vendored(merged: &Path, package: &Path) -> io::Result<()> {
    let name = package
        .file_name()
        .ok_or_else(|| invalid("vendored package has no directory name"))?;
    // create_new semantics: a std/project name-version collision fails instead of shadowing.
    std::os::unix::fs::symlink(package, merged.join(name))
        .map_err(|error| contextual(&merged.join(name), &error))
}

fn check_rust_src_vendor(vendor_dir: &Path, source_config: &Path) -> io::Result<()> {
    let vendor_metadata =
        fs::symlink_metadata(vendor_dir).map_err(|error| contextual(vendor_dir, &error))?;
    if vendor_metadata.file_type().is_symlink() || !vendor_metadata.is_dir() {
        return Err(invalid(
            "rust-src vendored dependency directory must be a real directory",
        ));
    }
    let source_config_text =
        fs::read_to_string(source_config).map_err(|error| contextual(source_config, &error))?;
    let expected_config = "[source.crates-io]\nreplace-with = \"vendored-sources\"\n\n[source.vendored-sources]\ndirectory = \"vendor\"";
    if source_config_text.trim() != expected_config {
        return Err(invalid(
            "unexpected installed rust-src source replacement configuration",
        ));
    }
    Ok(())
}

fn link_project_packages(
    inputs: &mut BTreeMap<String, String>,
    merged: &Path,
    project: &[(LockedRegistryPackage, PathBuf)],
    packages: &[LockedRegistryPackage],
) -> io::Result<()> {
    manifest_value(inputs, "project_package_count", project.len().to_string());
    for (index, (package, directory)) in project.iter().enumerate() {
        // The same name-version in both sets (e.g. memchr, used by std and serde_json) must be
        // the same .crate by checksum; the already-linked rust-src copy then serves both.
        match packages
            .iter()
            .find(|std| std.name == package.name && std.version == package.version)
        {
            Some(std) if std.checksum == package.checksum => {}
            Some(_) => {
                return Err(invalid(format!(
                    "{}-{} is locked with different checksums by rust-src and the project",
                    package.name, package.version
                )));
            }
            None => link_vendored(merged, directory)?,
        }
        record_locked(inputs, &format!("project_package_{index:04}"), package);
    }
    Ok(())
}

fn prepare_vendored_std(
    root: &Path,
    cargo_home: &Path,
    sysroot: &Path,
    sha256sum: &Path,
    hashes: &BTreeMap<PathBuf, String>,
) -> io::Result<VendoredStdInputs> {
    let library = sysroot.join("lib/rustlib/src/rust/library");
    let lock_file = library.join("Cargo.lock");
    let source_config = library.join(".cargo/config.toml");
    let vendor_dir = library.join("vendor");
    validate_input(&lock_file)?;
    validate_input(&source_config)?;
    check_rust_src_vendor(&vendor_dir, &source_config)?;
    let packages = parse_std_registry_packages(&lock_file)?;
    let project = verify_project_vendor(root, sha256sum)?;
    let mut inputs = BTreeMap::new();
    manifest_value(&mut inputs, "schema", "2");
    manifest_value(
        &mut inputs,
        "source",
        "installed rust-src library/vendor plus project vendor/, merged by symlink; no global Cargo cache or config copied",
    );
    manifest_value(
        &mut inputs,
        "trust",
        "installed qualified toolchain and committed vendor/; checksum consistency is not independent cryptographic authentication",
    );
    manifest_value(
        &mut inputs,
        "std_lockfile_sha256",
        file_hash(root, sha256sum, &lock_file)?,
    );
    manifest_value(
        &mut inputs,
        "std_source_config_sha256",
        file_hash(root, sha256sum, &source_config)?,
    );
    manifest_value(
        &mut inputs,
        "registry_package_count",
        packages.len().to_string(),
    );
    // Cargo allows one directory behind a replaced source and build-std needs both sets.
    let merged = cargo_home.join("vendor");
    DirBuilder::new()
        .mode(0o700)
        .create(&merged)
        .map_err(|error| contextual(&merged, &error))?;
    for (index, package) in packages.iter().enumerate() {
        let directory = vendor_dir.join(format!("{}-{}", package.name, package.version));
        let metadata =
            fs::symlink_metadata(&directory).map_err(|error| contextual(&directory, &error))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(invalid(format!(
                "locked rust-src vendor package is missing or not a real directory: {}/{}-{}",
                vendor_dir.display(),
                package.name,
                package.version
            )));
        }
        let checksum_manifest = directory.join(".cargo-checksum.json");
        validate_input(&checksum_manifest)?;
        verify_vendor_checksums(&directory, package, hashes)?;
        link_vendored(&merged, &directory)?;
        let prefix = format!("package_{index:04}");
        record_locked(&mut inputs, &prefix, package);
        manifest_value(
            &mut inputs,
            &format!("{prefix}_cargo_checksum_manifest_sha256"),
            file_hash(root, sha256sum, &checksum_manifest)?,
        );
    }
    link_project_packages(&mut inputs, &merged, &project, &packages)?;
    let manifest = cargo_home.join("vendored-std-inputs.tsv");
    write_manifest(&manifest, inputs)?;
    let local_config = cargo_home.join("config.toml");
    let config_text = format!(
        "[source.crates-io]\nreplace-with = \"kernel-vendored\"\n\n[source.kernel-vendored]\ndirectory = {}\n",
        toml_string(&display_path(&merged)?)
    );
    write_new(&local_config, config_text.as_bytes())?;
    Ok(VendoredStdInputs {
        library,
        lock_file,
        source_config,
        local_config,
        manifest,
    })
}

struct Toolchain {
    cargo: Tool,
    rustc: Tool,
    sysroot: PathBuf,
    lld: Tool,
    checked_hashes: BTreeMap<PathBuf, String>,
}

fn toolchain(root: &Path, output: &Path, sha256sum: &Path) -> io::Result<Toolchain> {
    reject_build_overrides(root)?;
    let rustup = resolve_program(Path::new("rustup"))?;
    let rustup_home = std::env::var_os("RUSTUP_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".rustup")))
        .ok_or_else(|| invalid("RUSTUP_HOME or HOME is needed to locate the installed nightly"))?;
    let selected = |name: &str| -> io::Result<PathBuf> {
        let mut command = Command::new(&rustup);
        command
            .args(["which", "--toolchain", "nightly", name])
            .current_dir(root)
            .env("RUSTUP_HOME", &rustup_home)
            .env("RUSTUP_AUTO_INSTALL", "0");
        let bytes = capture_command(&mut command, METADATA_TIMEOUT)?;
        let text = std::str::from_utf8(&bytes).map_err(|error| invalid(error.to_string()))?;
        let path = fs::canonicalize(text.trim())?;
        validate_input(&path)?;
        Ok(path)
    };
    let cargo_path = selected("cargo")?;
    let rustc_path = selected("rustc")?;
    let sysroot = rustc_path
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| invalid("rustc does not have a toolchain/bin path"))?
        .to_path_buf();
    if rustc_path != sysroot.join("bin/rustc") || cargo_path != sysroot.join("bin/cargo") {
        return Err(invalid(
            "selected Cargo and rustc must be actual binaries from the same sysroot",
        ));
    }
    let rust_lld = sysroot.join("lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld");
    let mut checked_paths = compiler_support_files(&sysroot)?;
    checked_paths.extend([cargo_path.clone(), rustc_path.clone(), rust_lld.clone()]);
    // Hash before querying versions, not just after qualification: the checked
    // binaries and their compiler libraries must also be the executed inputs.
    let checked_hashes = hash_files(root, sha256sum, &checked_paths)?;
    let qualify = |name: &str, path: PathBuf, args: &[&str], commit: &str| -> io::Result<Tool> {
        let version = tool_output(&path, args, root)?;
        if !version
            .lines()
            .any(|line| line.strip_prefix("commit-hash: ") == Some(commit))
        {
            return Err(invalid(format!(
                "{name} requires qualified commit {commit}; found {}",
                single_line(&version)
            )));
        }
        write_new(
            &create_log_dir(output)?.join(format!("{name}-version.txt")),
            version.as_bytes(),
        )?;
        Ok(Tool { path, version })
    };
    let cargo = qualify("cargo", cargo_path, &["-Vv"], REQUIRED_CARGO_COMMIT)?;
    let rustc = qualify("rustc", rustc_path, &["-vV"], REQUIRED_RUSTC_COMMIT)?;
    if fs::canonicalize(tool_output(&rustc.path, &["--print", "sysroot"], root)?)? != sysroot {
        return Err(invalid(
            "rustc reported a sysroot other than its qualified binary directory",
        ));
    }
    let lld = Tool {
        version: tool_output(&rust_lld, &["-flavor", "gnu", "--version"], root)?,
        path: rust_lld,
    };
    write_new(
        &create_log_dir(output)?.join("rust-lld-version.txt"),
        lld.version.as_bytes(),
    )?;
    Ok(Toolchain {
        cargo,
        rustc,
        sysroot,
        lld,
        checked_hashes,
    })
}

fn check_elf(root: &Path, output: &Path, elf: &Path, readelf: &Tool) -> io::Result<String> {
    let output_text = tool_output(&readelf.path, &["-h", &display_path(elf)?], root)?;
    write_new(&output.join("readelf-header.txt"), output_text.as_bytes())?;
    let type_ok = output_text
        .lines()
        .any(|line| line.contains("Type:") && line.contains("EXEC"));
    let machine_ok = output_text
        .lines()
        .any(|line| line.contains("Machine:") && line.contains("X86-64"));
    if !type_ok || !machine_ok {
        return Err(invalid(format!(
            "kernel ELF must be x86-64 ET_EXEC (Type EXEC={type_ok}, Machine x86-64={machine_ok}); see {}",
            output.join("readelf-header.txt").display()
        )));
    }
    Ok(output_text)
}
fn parse_executable_segments(text: &str) -> io::Result<Vec<(u64, u64)>> {
    let mut segments = Vec::new();
    for line in text.lines() {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.first() != Some(&"LOAD") {
            continue;
        }
        if fields.len() < 7 {
            return Err(invalid(format!("malformed PT_LOAD program header: {line}")));
        }
        let virtual_address = parse_hex_word(fields[2])
            .ok_or_else(|| invalid(format!("invalid PT_LOAD virtual address: {line}")))?;
        let memory_size = parse_hex_word(fields[5])
            .ok_or_else(|| invalid(format!("invalid PT_LOAD memory size: {line}")))?;
        let executable = fields[6..]
            .iter()
            .take_while(|field| !field.starts_with("0x"))
            .any(|field| field.contains('E'));
        if executable && memory_size > 0 {
            let end = virtual_address
                .checked_add(memory_size)
                .ok_or_else(|| invalid("PT_LOAD executable segment address overflow"))?;
            segments.push((virtual_address, end));
        }
    }
    if segments.is_empty() {
        return Err(invalid("ELF has no executable PT_LOAD segment"));
    }
    Ok(segments)
}

fn parse_hex_word(value: &str) -> Option<u64> {
    u64::from_str_radix(value.strip_prefix("0x").unwrap_or(value), 16).ok()
}

fn elf_executable_segments(
    root: &Path,
    output: &Path,
    elf: &Path,
    readelf: &Tool,
) -> io::Result<Vec<(u64, u64)>> {
    let text = tool_output(&readelf.path, &["-lW", &display_path(elf)?], root)?;
    write_new(&output.join("program-headers.txt"), text.as_bytes())?;
    parse_executable_segments(&text)
}
/// The init must be a static executable that needs nothing from a loader or linker. The `elf`
/// crate's facts are cross-checked against readelf's symbol table, an independent oracle.
fn verify_init(
    root: &Path,
    output: &Path,
    elf: &Path,
    readelf: &Tool,
    facts: &fixture::ElfFacts,
    manifest: &mut BTreeMap<String, String>,
) -> io::Result<()> {
    let symbols = tool_output(&readelf.path, &["-sW", &display_path(elf)?], root)?;
    write_new(&output.join("init-symbols.txt"), symbols.as_bytes())?;
    // `Num: Value Size Type Bind Vis Ndx Name`; the null symbol has no name field.
    let oracle_undefined = symbols
        .lines()
        .filter(|line| {
            let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
            fields.len() >= 8 && fields[6] == "UND"
        })
        .count() as u64;
    if facts.interpreters != 0
        || facts.dynamics != 0
        || facts.undefined_symbols != 0
        || oracle_undefined != 0
    {
        return Err(invalid(format!(
            "init is not a static, self-contained executable: PT_INTERP={} PT_DYNAMIC={} undefined symbols={} (readelf {oracle_undefined})",
            facts.interpreters, facts.dynamics, facts.undefined_symbols
        )));
    }
    manifest_value(manifest, "init_load_segments", facts.loads.to_string());
    manifest_value(
        manifest,
        "init_interpreters",
        facts.interpreters.to_string(),
    );
    manifest_value(manifest, "init_undefined_symbols", "0");
    Ok(())
}

/// Header facts of a built snapshot. The `elf` crate decides; readelf's captured text is an
/// independent oracle that must agree. Returns the executable `PT_LOAD` ranges.
fn snapshot_elf(
    root: &Path,
    output: &Path,
    elf: &Path,
    readelf: &Tool,
    target: Target,
    manifest: &mut BTreeMap<String, String>,
) -> io::Result<Vec<(u64, u64)>> {
    let facts = fixture::elf_facts(&fs::read(elf).map_err(|error| contextual(elf, &error))?)?;
    let _ = check_elf(root, output, elf, readelf)?;
    if facts.executable_segments.is_empty()
        || facts.executable_segments != elf_executable_segments(root, output, elf, readelf)?
    {
        return Err(invalid(
            "ELF executable PT_LOAD segments differ between the elf crate and readelf",
        ));
    }
    if target.is_init() {
        verify_init(root, output, elf, readelf, &facts, manifest)?;
    }
    Ok(facts.executable_segments)
}

fn write_target_spec(root: &Path, output: &Path, rustc: &Path) -> io::Result<PathBuf> {
    let text = tool_output(
        rustc,
        &[
            "-Zunstable-options",
            "--print",
            "target-spec-json",
            "--target",
            TARGET,
        ],
        root,
    )?;
    let path = output.join("target-spec.json");
    write_new(&path, text.as_bytes())?;
    Ok(path)
}

fn collect_runtime_archives(
    directory: &Path,
    artifacts: &mut Vec<PathBuf>,
    found: &mut RuntimeArchives,
) -> io::Result<()> {
    let mut entries = fs::read_dir(directory)
        .map_err(|error| contextual(directory, &error))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| contextual(&path, &error))?;
        if metadata.file_type().is_symlink() {
            return Err(invalid(format!(
                "runtime artifact symlink is not permitted: {}",
                path.display()
            )));
        }
        if metadata.is_dir() {
            collect_runtime_archives(&path, artifacts, found)?;
            continue;
        }
        if !metadata.is_file() {
            return Err(invalid(format!(
                "unsupported compiler output entry: {}",
                path.display()
            )));
        }
        if path.extension() != Some(OsStr::new("rlib")) {
            continue;
        }
        let name = path
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| invalid("non-UTF-8 compiler runtime artifact name"))?;
        if name.starts_with("libcore-") {
            found.core = true;
            artifacts.push(path);
        } else if name.starts_with("libcompiler_builtins-") {
            found.builtins = true;
            artifacts.push(path);
        } else if name.starts_with("liballoc-") {
            found.alloc = true;
            artifacts.push(path);
        }
    }
    Ok(())
}

/// Which rebuilt standard-library archives the target output contains.
#[derive(Default)]
struct RuntimeArchives {
    core: bool,
    builtins: bool,
    alloc: bool,
}

/// The rebuilt `core`/`compiler_builtins` (and, for the kernel, `alloc`)
/// archives of a fresh target directory; each required one must be present.
fn compiler_runtime_artifacts(target_dir: &Path, need_alloc: bool) -> io::Result<Vec<PathBuf>> {
    let output = target_dir.join(TARGET).join("release");
    let mut artifacts = Vec::new();
    let mut found = RuntimeArchives::default();
    collect_runtime_archives(&output, &mut artifacts, &mut found)?;
    artifacts.sort();
    if !found.core || !found.builtins || found.alloc != need_alloc {
        return Err(invalid(format!(
            "Cargo target output has core ({}), compiler_builtins ({}), alloc ({}; required: {need_alloc}) archives under {}",
            found.core,
            found.builtins,
            found.alloc,
            output.display()
        )));
    }
    Ok(artifacts)
}

struct PreparedBuild {
    command: Command,
    manifest: BTreeMap<String, String>,
    sources: BTreeMap<PathBuf, String>,
    runtime: BTreeMap<PathBuf, String>,
    fixed_inputs: Vec<PathBuf>,
    sysroot: PathBuf,
    sha256sum: PathBuf,
    readelf: Tool,
}

fn build_command(
    root: &Path,
    output: &Path,
    cargo: &Tool,
    rustc: &Tool,
    lld: &Tool,
    target: Target,
) -> io::Result<Command> {
    let mut command = supervised(&cargo.path);
    command
        .args([
            target.build_std(),
            "-Zbuild-std-features=compiler-builtins-mem",
            "rustc",
            "--offline",
            "--locked",
            "--config",
        ])
        // Highest precedence: the checked-in host source replacement must not shadow the merged one.
        .arg(output.join("cargo-home/config.toml"))
        .arg("--target-dir")
        .arg(output.join("cargo-target"))
        .args([
            "-p",
            target.package(),
            "--bin",
            target.binary(),
            "--target",
            TARGET,
            "--release",
            "--no-default-features",
            "--features",
            target.features(),
        ])
        .current_dir(root)
        .env("CARGO_HOME", output.join("cargo-home"))
        .env("RUSTC", &rustc.path)
        .env("RUSTC_WRAPPER", "")
        .env("RUSTC_WORKSPACE_WRAPPER", "")
        .env("RUSTFLAGS", "")
        // Applies to every crate of the target build (std, deps, project), so no checkout, run
        // or toolchain path is embedded in panic locations or debug info. The later, more
        // specific output prefix wins over the checkout prefix it lives under.
        .env(
            "CARGO_ENCODED_RUSTFLAGS",
            remap_flags(root, output, rustc, target)?,
        )
        .env("CARGO_TARGET_X86_64_UNKNOWN_NONE_LINKER", &lld.path)
        .args(["--", "-Crelocation-model=static", "-Clinker-flavor=gnu-lld"])
        .args(["-Clink-arg=--no-pie", "-Clink-arg=--no-undefined"])
        .arg(format!("-Clinker={}", display_path(&lld.path)?))
        .arg(format!(
            "-Clink-arg=-Map={}",
            display_path(&output.join(format!("{}.map", target.prefix())))?
        ));
    match target {
        Target::Kernel { .. } => command.arg("-Clink-arg=-Tkernel/linker.ld"),
        // The init only needs line tables off: the kernel never debugs it.
        Target::Init => command.arg("-Cstrip=debuginfo"),
    };
    Ok(command)
}

/// `CARGO_ENCODED_RUSTFLAGS` (unit-separator joined) mapping the checkout, run
/// directory and toolchain sysroot to fixed names, plus [`NO_GLOBAL_OOM_HANDLING`]
/// for the kernel (whose `alloc` is fallible-only).
fn remap_flags(root: &Path, output: &Path, rustc: &Tool, target: Target) -> io::Result<String> {
    let sysroot = rustc
        .path
        .ancestors()
        .nth(2)
        .ok_or_else(|| invalid("rustc has no sysroot"))?;
    let cfgs = (!target.is_init()).then(|| Ok(NO_GLOBAL_OOM_HANDLING.to_owned()));
    Ok([(root, "/src"), (output, "/out"), (sysroot, "/toolchain")]
        .into_iter()
        .map(|(path, to)| {
            let text = display_path(path)?;
            // `\x1f` separates the encoded flags (a path containing it would inject a flag);
            // other control bytes have no place in a recorded build path either.
            if text.chars().any(char::is_control) {
                return Err(invalid(format!("path has a control character: {text:?}")));
            }
            Ok(format!("--remap-path-prefix={text}={to}"))
        })
        .chain(cfgs)
        .collect::<io::Result<Vec<_>>>()?
        .join("\x1f"))
}

fn build_profile_manifest(target: Target) -> BTreeMap<String, String> {
    let mut manifest = BTreeMap::new();
    for (key, value) in [
        ("schema", "1"),
        ("target", TARGET),
        ("binary", target.binary()),
        ("package", target.package()),
        ("build_profile", target.features()),
        (
            "feature_set",
            if target.features() == "qemu-self-test" {
                "qemu-self-test (includes freestanding)"
            } else {
                "freestanding"
            },
        ),
        ("qualified_rustc_commit", REQUIRED_RUSTC_COMMIT),
        ("qualified_cargo_commit", REQUIRED_CARGO_COMMIT),
        ("cargo_working_directory", "."),
        (
            "host_msrv_scope",
            "workspace Rust version applies to host tools only",
        ),
        (
            "cargo_cache_policy",
            "installed rust-src vendor; offline, private CARGO_HOME, no global cache/config",
        ),
        (
            "source_binding",
            "before/after path sets and SHA-256 bytes must match",
        ),
        (
            "runtime_trust",
            "installed qualified toolchain; checksums are consistency, not independent authentication",
        ),
        ("runtime_closure_claim", "not-audited-by-xtask"),
    ] {
        manifest_value(&mut manifest, key, value);
    }
    manifest
}

fn record_build_tool(
    root: &Path,
    sha256sum: &Path,
    manifest: &mut BTreeMap<String, String>,
    name: &str,
    tool: &Tool,
) -> io::Result<()> {
    let identity = fs::canonicalize(&tool.path)?;
    manifest_value(manifest, &format!("{name}_path"), display_path(&identity)?);
    // Keep argv[0] spelling for multicall tools while sharing the canonical
    // identity with the runtime inventory and package consumer.
    manifest_value(
        manifest,
        &format!("{name}_invocation_path"),
        display_path(&tool.path)?,
    );
    manifest_value(
        manifest,
        &format!("{name}_version"),
        single_line(&tool.version),
    );
    manifest_value(
        manifest,
        &format!("sha256_{name}"),
        file_hash(root, sha256sum, &identity)?,
    );
    Ok(())
}

fn record_build_runtime(
    root: &Path,
    sha256sum: &Path,
    manifest: &mut BTreeMap<String, String>,
    vendor: &VendoredStdInputs,
    target_spec: &Path,
    harness: &Path,
) -> io::Result<()> {
    manifest_value(manifest, "harness_executable_path", display_path(harness)?);
    manifest_value(
        manifest,
        "sha256_harness_executable",
        file_hash(root, sha256sum, harness)?,
    );
    manifest_value(
        manifest,
        "process_group_kill_path",
        display_path(&fs::canonicalize(KILL)?)?,
    );
    manifest_value(
        manifest,
        "sha256_process_group_kill",
        file_hash(root, sha256sum, Path::new(KILL))?,
    );
    manifest_value(
        manifest,
        "rust_src_library_path",
        display_path(&vendor.library)?,
    );
    manifest_value(
        manifest,
        "rust_src_lockfile",
        display_path(&vendor.lock_file)?,
    );
    manifest_value(
        manifest,
        "rust_src_lockfile_sha256",
        file_hash(root, sha256sum, &vendor.lock_file)?,
    );
    manifest_value(
        manifest,
        "rust_src_vendor_config_sha256",
        file_hash(root, sha256sum, &vendor.source_config)?,
    );
    for (key, path) in [
        ("local_cargo_config", &vendor.local_config),
        ("vendored_std_inputs", &vendor.manifest),
    ] {
        manifest_value(manifest, key, display_path(&relative_path(root, path)?)?);
        manifest_value(
            manifest,
            &format!("{key}_sha256"),
            file_hash(root, sha256sum, path)?,
        );
    }
    manifest_value(
        manifest,
        "target_spec_path",
        display_path(&relative_path(root, target_spec)?)?,
    );
    manifest_value(
        manifest,
        "target_spec_sha256",
        file_hash(root, sha256sum, target_spec)?,
    );
    Ok(())
}

fn record_build_sources(
    root: &Path,
    manifest: &mut BTreeMap<String, String>,
    sources: &BTreeMap<PathBuf, String>,
) -> io::Result<()> {
    manifest_value(
        manifest,
        "source_commit",
        git_value(root, &["rev-parse", "HEAD"]),
    );
    manifest_value(
        manifest,
        "git_worktree_status",
        single_line(&git_value(
            root,
            &["status", "--porcelain", "--untracked-files=all"],
        )),
    );
    for (index, (source, digest)) in sources.iter().enumerate() {
        let key = format!("source_{index:04}");
        manifest_value(
            manifest,
            &format!("{key}_path"),
            display_path(&relative_path(root, source)?)?,
        );
        manifest_value(manifest, &format!("{key}_sha256"), digest);
    }
    Ok(())
}

fn prepare_build(root: &Path, output: &Path, target: Target) -> io::Result<PreparedBuild> {
    create_directory(&output.join("cargo-target"))?;
    let sha = capture_tool_version(root, output, "sha256sum", &["--version"])?;
    let Toolchain {
        cargo,
        rustc,
        sysroot,
        lld,
        checked_hashes,
    } = toolchain(root, output, &sha.path)?;
    let readelf = capture_tool_version(root, output, "readelf", &["--version"])?;
    let target_spec = write_target_spec(root, output, &rustc.path)?;
    let cargo_home = output.join("cargo-home");
    create_directory(&cargo_home)?;
    let sources = hash_files(root, &sha.path, &source_files(root)?)?;
    write_input_manifest(&output.join("source-inputs-before.tsv"), &sources)?;
    let mut runtime = hash_files(root, &sha.path, &runtime_source_files(&sysroot)?)?;
    let vendor = prepare_vendored_std(root, &cargo_home, &sysroot, &sha.path, &runtime)?;
    let mut fixed_inputs = vec![
        vendor.local_config.clone(),
        vendor.manifest.clone(),
        target_spec.clone(),
    ];
    for tool in [&cargo, &rustc, &lld, &readelf, &sha] {
        fixed_inputs.push(fs::canonicalize(&tool.path)?);
    }
    fixed_inputs.push(fs::canonicalize(KILL)?);
    fixed_inputs.push(fs::canonicalize(SETPRIV)?);
    let harness = fs::canonicalize(std::env::current_exe()?)?;
    fixed_inputs.push(harness.clone());
    runtime.extend(hash_files(root, &sha.path, &fixed_inputs)?);
    if checked_hashes
        .iter()
        .any(|(path, digest)| runtime.get(path) != Some(digest))
    {
        return Err(invalid(
            "qualified compiler binaries or libraries changed before build",
        ));
    }
    write_input_manifest(&output.join("runtime-inputs-before.tsv"), &runtime)?;
    let command = build_command(root, output, &cargo, &rustc, &lld, target)?;
    let mut manifest = build_profile_manifest(target);
    for (name, tool) in [
        ("cargo", &cargo),
        ("rustc", &rustc),
        ("rust_lld", &lld),
        ("readelf", &readelf),
        ("sha256sum", &sha),
    ] {
        record_build_tool(root, &sha.path, &mut manifest, name, tool)?;
    }
    record_setpriv(root, &sha.path, &mut manifest)?;
    record_build_runtime(
        root,
        &sha.path,
        &mut manifest,
        &vendor,
        &target_spec,
        &harness,
    )?;
    manifest_value(
        &mut manifest,
        "cargo_home",
        display_path(&relative_path(root, &cargo_home)?)?,
    );
    manifest_value(
        &mut manifest,
        "cargo_arguments",
        command_args(command.get_args())?.join(" | "),
    );
    manifest_value(
        &mut manifest,
        "cargo_encoded_rustflags",
        remap_flags(root, output, &rustc, target)?.replace('\x1f', " | "),
    );
    record_build_sources(root, &mut manifest, &sources)?;
    Ok(PreparedBuild {
        command,
        manifest,
        sources,
        runtime,
        fixed_inputs,
        sysroot,
        sha256sum: sha.path,
        readelf,
    })
}

fn bind_inputs_after(root: &Path, output: &Path, prepared: &mut PreparedBuild) -> io::Result<()> {
    let sources = hash_files(root, &prepared.sha256sum, &source_files(root)?)?;
    write_input_manifest(&output.join("source-inputs-after.tsv"), &sources)?;
    let mut files = runtime_source_files(&prepared.sysroot)?;
    files.extend(prepared.fixed_inputs.iter().cloned());
    let runtime = hash_files(root, &prepared.sha256sum, &files)?;
    write_input_manifest(&output.join("runtime-inputs-after.tsv"), &runtime)?;
    require_unchanged(&prepared.sources, &sources)?;
    require_unchanged(&prepared.runtime, &runtime)?;
    reject_build_overrides(root)?;
    for (key, filename) in [
        ("source_inputs_before", "source-inputs-before.tsv"),
        ("source_inputs_after", "source-inputs-after.tsv"),
        ("runtime_inputs_before", "runtime-inputs-before.tsv"),
        ("runtime_inputs_after", "runtime-inputs-after.tsv"),
    ] {
        let path = output.join(filename);
        manifest_value(
            &mut prepared.manifest,
            key,
            display_path(&relative_path(root, &path)?)?,
        );
        manifest_value(
            &mut prepared.manifest,
            &format!("sha256_{key}"),
            file_hash(root, &prepared.sha256sum, &path)?,
        );
    }
    Ok(())
}

fn record_segments(manifest: &mut BTreeMap<String, String>, segments: &[(u64, u64)]) {
    manifest_value(
        manifest,
        "executable_segment_count",
        segments.len().to_string(),
    );
    for (index, (start, end)) in segments.iter().enumerate() {
        manifest_value(
            manifest,
            &format!("executable_segment_{index:02}_start"),
            format!("0x{start:016x}"),
        );
        manifest_value(
            manifest,
            &format!("executable_segment_{index:02}_end"),
            format!("0x{end:016x}"),
        );
    }
}

fn finish_build(
    root: &Path,
    output: &Path,
    target: Target,
    prepared: PreparedBuild,
) -> io::Result<Build> {
    let PreparedBuild {
        mut manifest,
        sha256sum,
        readelf,
        ..
    } = prepared;
    let target_dir = output.join("cargo-target");
    let cargo_elf = target_dir
        .join(TARGET)
        .join("release")
        .join(target.binary());
    validate_input(&cargo_elf)?;
    if fs::metadata(&cargo_elf)?.len() == 0 {
        return Err(invalid("Cargo produced an empty ELF"));
    }
    let elf = output.join(format!("{}.elf", target.binary()));
    copy_file(&cargo_elf, &elf)?;
    let elf_relative = relative_path(root, &elf)?;
    let executable_segments = snapshot_elf(root, output, &elf, &readelf, target, &mut manifest)?;
    let map = output.join(format!("{}.map", target.prefix()));
    validate_input(&map)?;
    let map_relative = relative_path(root, &map)?;
    let elf_hash = file_hash(root, &sha256sum, &elf)?;
    let cargo_hash = file_hash(root, &sha256sum, &cargo_elf)?;
    if cargo_hash != elf_hash {
        return Err(invalid(
            "Cargo ELF changed while taking the immutable snapshot",
        ));
    }
    let runtimes = compiler_runtime_artifacts(&target_dir, !target.is_init())?;
    manifest_value(
        &mut manifest,
        "runtime_archive_count",
        runtimes.len().to_string(),
    );
    for (index, archive) in runtimes.iter().enumerate() {
        let key = format!("runtime_{index:02}");
        manifest_value(
            &mut manifest,
            &format!("{key}_path"),
            display_path(&relative_path(root, archive)?)?,
        );
        manifest_value(
            &mut manifest,
            &format!("{key}_sha256"),
            file_hash(root, &sha256sum, archive)?,
        );
    }
    record_segments(&mut manifest, &executable_segments);
    manifest_value(&mut manifest, "cargo_exit_code", "0");
    manifest_value(
        &mut manifest,
        "cargo_target_dir",
        display_path(&relative_path(root, &target_dir)?)?,
    );
    manifest_value(
        &mut manifest,
        "cargo_artifact_elf",
        display_path(&relative_path(root, &cargo_elf)?)?,
    );
    manifest_value(
        &mut manifest,
        &format!("{}_elf_snapshot", target.prefix()),
        display_path(&elf_relative)?,
    );
    manifest_value(&mut manifest, "map_path", display_path(&map_relative)?);
    manifest_value(
        &mut manifest,
        &format!("sha256_{}_elf_snapshot", target.prefix()),
        elf_hash.clone(),
    );
    manifest_value(&mut manifest, "sha256_cargo_artifact_elf", cargo_hash);
    manifest_value(
        &mut manifest,
        "sha256_link_map",
        file_hash(root, &sha256sum, &map)?,
    );
    write_manifest(&output.join("build-manifest.tsv"), manifest)?;
    Ok(Build {
        elf,
        elf_relative,
        map_relative,
        elf_hash,
        executable_segments,
        qemu_self_test: matches!(
            target,
            Target::Kernel {
                qemu_self_test: true
            }
        ),
    })
}

fn build_target(root: &Path, output: &Path, target: Target) -> io::Result<Build> {
    let mut prepared = prepare_build(root, output, target)?;
    let result = run_with_logs(
        &mut prepared.command,
        &output.join("cargo.stdout.log"),
        &output.join("cargo.stderr.log"),
        BUILD_TIMEOUT,
    )?;
    bind_inputs_after(root, output, &mut prepared)?;
    require_exit(
        prepared.command.get_program().as_ref(),
        &result,
        0,
        BUILD_TIMEOUT,
    )?;
    finish_build(root, output, target, prepared)
}

pub fn build(root: &Path, requested: &Path) -> io::Result<()> {
    let output = prepare_output(root, requested)?;
    let build = match build_target(
        &output.root,
        &output.path,
        Target::Kernel {
            qemu_self_test: false,
        },
    ) {
        Ok(build) => build,
        Err(error) => {
            let mut failure = BTreeMap::new();
            manifest_value(&mut failure, "command", "kernel-build");
            manifest_value(&mut failure, "status", "failed");
            manifest_value(&mut failure, "error", single_line(&error.to_string()));
            let _ = write_manifest(&output.path.join("failure.tsv"), failure);
            return Err(error);
        }
    };
    println!(
        "kernel-build: freestanding ELF {}",
        display_path(&build.elf_relative)?
    );
    println!("Link map: {}", display_path(&build.map_relative)?);
    println!(
        "Manifest: {}/build-manifest.tsv",
        display_path(&output.relative)?
    );
    Ok(())
}

fn copy_file(source: &Path, destination: &Path) -> io::Result<()> {
    validate_input(source)?;
    let mut source_file = File::open(source).map_err(|error| contextual(source, &error))?;
    let mut destination_file = create_new(destination)?;
    io::copy(&mut source_file, &mut destination_file)
        .map(|_| ())
        .map_err(|error| contextual(destination, &error))
}

fn copy_notices(root: &Path, output: &Path, sha256sum: &Path) -> io::Result<()> {
    let licenses = output.join("licenses");
    create_directory(&licenses)?;
    let mut manifest = BTreeMap::new();
    for (index, (source, name)) in LIMINE_DOCS.into_iter().chain(OVMF_LICENSES).enumerate() {
        let source = Path::new(source);
        let destination = licenses.join(name);
        copy_file(source, &destination)?;
        let copied_relative = relative_path(output, &destination)?;
        let prefix = format!("notice_{index:02}");
        manifest_value(
            &mut manifest,
            &format!("{prefix}_source"),
            display_path(source)?,
        );
        manifest_value(
            &mut manifest,
            &format!("{prefix}_copied"),
            display_path(&copied_relative)?,
        );
        manifest_value(
            &mut manifest,
            &format!("{prefix}_sha256"),
            file_hash(root, sha256sum, &destination)?,
        );
    }
    write_manifest(&licenses.join("manifest.tsv"), manifest)
}

fn qemu_config(case: DebugCase) -> String {
    let mut config = String::from(
        "timeout: 0\n\n/Linux Rust QEMU bootstrap test\n    protocol: limine\n    path: boot():/linux-rs-kernel\n    resolution: 1024x768x32\n",
    );
    for name in case.modules.iter().map(|module| module.file()) {
        config.push_str("    module_path: boot():/");
        config.push_str(name);
        config.push('\n');
        config.push_str("    module_string: ");
        config.push_str(name);
        config.push('\n');
    }
    if let Some(cmdline) = case.cmdline {
        config.push_str("    cmdline: ");
        config.push_str(cmdline);
        config.push('\n');
    }
    config
}

/// The run's generated module bytes, written once under `fixtures/` and bound by SHA-256.
struct Fixtures {
    dir: PathBuf,
    archive_sha256: String,
    corrupt_sha256: String,
    noinit_sha256: String,
    /// What the kernel must report for the generated archive and the built `/init`, by construction.
    expected: fixture::Expected,
}

impl Fixtures {
    fn generate(output: &Path, sha256sum: &Path, init_elf: &Path) -> io::Result<Self> {
        let init = fs::read(init_elf).map_err(|error| contextual(init_elf, &error))?;
        let facts = fixture::elf_facts(&init)?;
        let archive = fixture::initramfs(&init)?;
        let dir = output.join("fixtures");
        create_directory(&dir)?;
        let write = |module: Module, bytes: &[u8]| -> io::Result<String> {
            let path = dir.join(module.file());
            write_new(&path, bytes)?;
            file_hash(output, sha256sum, &path)
        };
        Ok(Self {
            archive_sha256: write(Module::Archive, &archive)?,
            corrupt_sha256: write(Module::Corrupt, fixture::CORRUPT_MODULE)?,
            noinit_sha256: write(Module::NoInit, &fixture::initramfs_without_init()?)?,
            expected: fixture::Expected {
                archive_counts: fixture::archive_counts(archive.len(), &facts),
                init: facts,
            },
            dir,
        })
    }

    fn sha256(&self, module: Module) -> &str {
        match module {
            Module::Archive => &self.archive_sha256,
            Module::Corrupt => &self.corrupt_sha256,
            Module::NoInit => &self.noinit_sha256,
            Module::Empty => EMPTY_MODULE_SHA256,
        }
    }
}

fn stage_image_modules(
    root: &Path,
    case_dir: &Path,
    tools: &QemuTools,
    modules: &[Module],
) -> io::Result<Vec<PathBuf>> {
    let sha = &tools.sha256sum.path;
    let mut bindings = String::from("source\tsnapshot\tsha256\tbytes\n");
    let mut snapshots = Vec::with_capacity(modules.len());
    for &module in modules {
        let snapshot = case_dir.join(module.file());
        let expected = tools.fixtures.sha256(module);
        let source = if module == Module::Empty {
            write_new(&snapshot, b"")?;
            "Rust-generated-empty-fixture".to_owned()
        } else {
            let source = tools.fixtures.dir.join(module.file());
            copy_file(&source, &snapshot)?;
            if file_hash(root, sha, &source)? != expected {
                return Err(invalid(format!(
                    "generated module changed: {}",
                    module.file()
                )));
            }
            display_path(&source)?
        };
        if file_hash(root, sha, &snapshot)? != expected {
            return Err(invalid(format!(
                "module snapshot changed: {}",
                module.file()
            )));
        }
        writeln!(
            bindings,
            "{source}\t{}\t{expected}\t{}",
            snapshot.display(),
            fs::metadata(&snapshot)?.len()
        )
        .map_err(io::Error::other)?;
        snapshots.push(snapshot);
    }
    write_new(&case_dir.join("module-inputs.tsv"), bindings.as_bytes())?;
    Ok(snapshots)
}

fn make_fat_image(
    root: &Path,
    case_dir: &Path,
    build: &Build,
    case: DebugCase,
    tools: &QemuTools,
) -> io::Result<BootImage> {
    let image = case_dir.join("disk.img");
    let image_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&image)
        .map_err(|error| contextual(&image, &error))?;
    image_file
        .set_len(FAT_IMAGE_BYTES)
        .map_err(|error| contextual(&image, &error))?;
    drop(image_file);
    let format_result = run_simple(
        root,
        &tools.mkfs_fat,
        &["-F", "32", "-n", "LINUXRS", &display_path(&image)?],
        case_dir,
        "mkfs.stdout.log",
        "mkfs.stderr.log",
        Duration::from_secs(30),
    )?;
    require_exit(&tools.mkfs_fat, &format_result, 0, Duration::from_secs(30))?;
    let bootloader = Path::new(LIMINE_EFI);
    let vars_template = Path::new(OVMF_VARS);
    let ovmf_code = Path::new(OVMF_CODE);
    validate_input(bootloader)?;
    validate_input(vars_template)?;
    validate_input(ovmf_code)?;
    let vars_copy = case_dir.join("OVMF_VARS.4m.fd");
    copy_file(vars_template, &vars_copy)?;
    let vars_sha256_initial = file_hash(root, &tools.sha256sum.path, &vars_copy)?;
    let config = case_dir.join("limine.conf");
    write_new(&config, qemu_config(case).as_bytes())?;
    let image_relative = display_path(&relative_path(root, &image)?)?;
    for (index, directory) in ["::/EFI", "::/EFI/BOOT"].into_iter().enumerate() {
        let result = run_simple(
            root,
            &tools.mmd.path,
            &["-i", &image_relative, directory],
            case_dir,
            &format!("mmd-{index}.stdout.log"),
            &format!("mmd-{index}.stderr.log"),
            Duration::from_secs(30),
        )?;
        require_exit(&tools.mmd.path, &result, 0, Duration::from_secs(30))?;
    }
    let elf_hash = file_hash(root, &tools.sha256sum.path, &build.elf)?;
    if elf_hash != build.elf_hash {
        return Err(invalid("kernel ELF snapshot changed before image staging"));
    }
    let elf_relative = display_path(&relative_path(root, &build.elf)?)?;
    let config_relative = display_path(&relative_path(root, &config)?)?;
    let snapshots = stage_image_modules(root, case_dir, tools, case.modules)?;
    let mut copy_specs = vec![
        (
            display_path(bootloader)?,
            "::/EFI/BOOT/BOOTX64.EFI".to_owned(),
        ),
        (elf_relative, "::/linux-rs-kernel".to_owned()),
        (config_relative, "::/limine.conf".to_owned()),
    ];
    for (module, snapshot) in case.modules.iter().zip(&snapshots) {
        copy_specs.push((
            display_path(&relative_path(root, snapshot)?)?,
            format!("::/{}", module.file()),
        ));
    }
    copy_fat_payloads(root, case_dir, &image_relative, copy_specs, tools)?;
    let (kernel_image_sha256, limine_image_sha256, module_image_sha256) =
        verify_image_payloads(root, case_dir, &image_relative, build, tools, case.modules)?;
    let disk_sha256_initial = file_hash(root, &tools.sha256sum.path, &image)?;
    Ok(BootImage {
        disk: image,
        vars_copy,
        vars_sha256_initial,
        disk_sha256_initial,
        kernel_image_sha256,
        limine_image_sha256,
        module_image_sha256,
    })
}

fn copy_fat_payloads(
    root: &Path,
    case_dir: &Path,
    image_relative: &str,
    files: impl IntoIterator<Item = (String, String)>,
    tools: &QemuTools,
) -> io::Result<()> {
    for (index, (source, destination)) in files.into_iter().enumerate() {
        let result = run_simple(
            root,
            &tools.mcopy.path,
            &["-i", image_relative, &source, &destination],
            case_dir,
            &format!("mcopy-{index}.stdout.log"),
            &format!("mcopy-{index}.stderr.log"),
            Duration::from_secs(30),
        )?;
        require_exit(&tools.mcopy.path, &result, 0, Duration::from_secs(30))?;
    }
    for (index, directory) in ["::/", "::/EFI/BOOT"].into_iter().enumerate() {
        let result = run_simple(
            root,
            &tools.mdir.path,
            &["-i", image_relative, directory],
            case_dir,
            &format!("mdir-{index}.stdout.log"),
            &format!("mdir-{index}.stderr.log"),
            Duration::from_secs(30),
        )?;
        require_exit(&tools.mdir.path, &result, 0, Duration::from_secs(30))?;
    }
    Ok(())
}

fn verify_image_payloads(
    root: &Path,
    case_dir: &Path,
    image_relative: &str,
    build: &Build,
    tools: &QemuTools,
    modules: &[Module],
) -> io::Result<(String, String, ModuleHashes)> {
    let kernel_copy = case_dir.join("image-verified-kernel.elf");
    let kernel_copy_relative = display_path(&relative_path(root, &kernel_copy)?)?;
    let result = run_simple(
        root,
        &tools.mcopy.path,
        &[
            "-i",
            image_relative,
            "::/linux-rs-kernel",
            &kernel_copy_relative,
        ],
        case_dir,
        "mcopy-verify-kernel.stdout.log",
        "mcopy-verify-kernel.stderr.log",
        Duration::from_secs(30),
    )?;
    require_exit(&tools.mcopy.path, &result, 0, Duration::from_secs(30))?;
    let kernel_image_sha256 = file_hash(root, &tools.sha256sum.path, &kernel_copy)?;
    if kernel_image_sha256 != build.elf_hash {
        return Err(invalid(
            "FAT image kernel ELF does not match the immutable build snapshot",
        ));
    }
    let limine_copy = case_dir.join("image-verified-BOOTX64.EFI");
    let limine_copy_relative = display_path(&relative_path(root, &limine_copy)?)?;
    let result = run_simple(
        root,
        &tools.mcopy.path,
        &[
            "-i",
            image_relative,
            "::/EFI/BOOT/BOOTX64.EFI",
            &limine_copy_relative,
        ],
        case_dir,
        "mcopy-verify-limine.stdout.log",
        "mcopy-verify-limine.stderr.log",
        Duration::from_secs(30),
    )?;
    require_exit(&tools.mcopy.path, &result, 0, Duration::from_secs(30))?;
    let limine_image_sha256 = file_hash(root, &tools.sha256sum.path, &limine_copy)?;
    let limine_sha256 = file_hash(root, &tools.sha256sum.path, Path::new(LIMINE_EFI))?;
    if limine_image_sha256 != limine_sha256 {
        return Err(invalid(
            "FAT image Limine EFI binary does not match the installed source file",
        ));
    }
    let mut module_image_sha256 = Vec::with_capacity(modules.len());
    for (index, module) in modules.iter().enumerate() {
        let (name, expected) = (module.file(), tools.fixtures.sha256(*module));
        let copy = case_dir.join(format!("image-verified-{name}"));
        let copy_relative = display_path(&relative_path(root, &copy)?)?;
        let result = run_simple(
            root,
            &tools.mcopy.path,
            &["-i", image_relative, &format!("::/{name}"), &copy_relative],
            case_dir,
            &format!("mcopy-verify-module-{index}.stdout.log"),
            &format!("mcopy-verify-module-{index}.stderr.log"),
            Duration::from_secs(30),
        )?;
        require_exit(&tools.mcopy.path, &result, 0, Duration::from_secs(30))?;
        let actual = file_hash(root, &tools.sha256sum.path, &copy)?;
        if actual != expected {
            return Err(invalid(format!(
                "FAT module does not match the generated input: {name}"
            )));
        }
        module_image_sha256.push((name, actual));
    }
    Ok((
        kernel_image_sha256,
        limine_image_sha256,
        module_image_sha256,
    ))
}

fn run_simple(
    root: &Path,
    tool: &Path,
    args: &[&str],
    log_dir: &Path,
    stdout_name: &str,
    stderr_name: &str,
    timeout: Duration,
) -> io::Result<ProcessResult> {
    let mut command = Command::new(tool);
    command.args(args).current_dir(root);
    run_with_logs(
        &mut command,
        &log_dir.join(stdout_name),
        &log_dir.join(stderr_name),
        timeout,
    )
}

fn require_exit(
    tool: &Path,
    result: &ProcessResult,
    expected: i32,
    timeout: Duration,
) -> io::Result<()> {
    if result.timed_out {
        return Err(invalid(format!(
            "{} exceeded {} seconds",
            tool.display(),
            timeout.as_secs()
        )));
    }
    if result.exit_code != Some(expected) {
        return Err(invalid(format!(
            "{} exited with {:?}; expected {expected}",
            tool.display(),
            result.exit_code
        )));
    }
    Ok(())
}

/// Guest-controlled, so bounded; invalid UTF-8 is an error, not an empty log.
fn read_serial_log(path: &Path) -> io::Result<String> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|error| contextual(path, &error))?
        .take(SERIAL_LOG_LIMIT + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > SERIAL_LOG_LIMIT {
        return Err(invalid(format!(
            "{} exceeds {SERIAL_LOG_LIMIT} bytes",
            path.display()
        )));
    }
    String::from_utf8(bytes).map_err(|error| invalid(format!("{}: {error}", path.display())))
}

fn debug_qemu_args(
    root: &Path,
    case_dir: &Path,
    image: &Path,
    vars_copy: &Path,
    case: DebugCase,
) -> io::Result<Vec<OsString>> {
    let relative = |path: &Path| display_path(&relative_path(root, path)?);
    let mut args = vec![
        OsString::from("-machine"),
        OsString::from(format!(
            "{},accel={}",
            case.plat.machine,
            if case.plat.kvm { "kvm" } else { "tcg" }
        )),
        OsString::from("-cpu"),
        OsString::from(case.cpu),
        OsString::from("-m"),
        OsString::from("512M"),
        OsString::from("-smp"),
        OsString::from("1"),
        OsString::from("-display"),
        OsString::from("none"),
        OsString::from("-monitor"),
        OsString::from("none"),
        OsString::from("-serial"),
        OsString::from(format!("file:{}", relative(&case_dir.join("serial.log"))?)),
        OsString::from("-no-reboot"),
        OsString::from("-nic"),
        OsString::from("none"),
        OsString::from("-drive"),
        OsString::from(format!(
            "if=pflash,unit=0,format=raw,readonly=on,file={OVMF_CODE}"
        )),
        OsString::from("-drive"),
        OsString::from(format!(
            "if=pflash,unit=1,format=raw,file={}",
            relative(vars_copy)?
        )),
        OsString::from("-drive"),
        OsString::from(format!(
            "if=none,id=boot,format=raw,readonly=on,file={}",
            relative(image)?
        )),
        OsString::from("-device"),
        OsString::from("virtio-blk-pci,drive=boot"),
        OsString::from("-boot"),
        OsString::from("order=c"),
        OsString::from("-device"),
        OsString::from("isa-debug-exit,iobase=0xf4,iosize=0x04"),
    ];
    if case.framebuffers == 2 {
        // A second display: OVMF publishes a second GOP handle, so Limine
        // reports two framebuffers and the console must draw on both.
        args.extend([OsString::from("-device"), OsString::from("ramfb")]);
    }
    Ok(args)
}

/// Whether this host can run a KVM case: `/dev/kvm` opens read/write.
fn kvm_usable() -> bool {
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_ok()
}

/// Run one case. Two exceptions to "one launch per case", both recorded:
/// - a KVM case on a host without usable KVM is `unavailable`, not run;
/// - a case whose only mismatch is the TSC calibration *source* (the quick PIT
///   calibration is timing sensitive and falls back to the HPET/PM timer under
///   heavy host load, which is correct kernel behaviour) is run once more in
///   `<name>-retry`; both attempts' logs stay, the second result decides, and
///   the diagnostic names the first failure.
fn run_debug_case(
    root: &Path,
    output: &Path,
    build: &Build,
    case: DebugCase,
    tools: &QemuTools,
    timeout: Duration,
) -> io::Result<CaseResult> {
    if case.plat.kvm && !kvm_usable() {
        let case_dir = output.join("cases").join(case.name);
        ensure_real_directory(&output.join("cases"))?;
        create_directory(&case_dir)?;
        let mut result = BTreeMap::new();
        manifest_value(&mut result, "schema", "1");
        manifest_value(&mut result, "case", case.name);
        manifest_value(&mut result, "status", "unavailable");
        manifest_value(
            &mut result,
            "assertions",
            "/dev/kvm is not usable read/write; case not run",
        );
        write_manifest(&case_dir.join("result.tsv"), result)?;
        return Ok(CaseResult {
            name: case.name,
            cpu: case.cpu,
            passed: false,
            unavailable: true,
            expected_exit: case.expected_exit,
            observed_exit: None,
            timed_out: false,
            diagnostic: "unavailable: /dev/kvm is not usable read/write".to_owned(),
            output: case_dir,
        });
    }
    let first = run_debug_case_in(root, output, build, case, tools, timeout, case.name)?;
    if first.passed || !first.diagnostic.starts_with("TSC calibration source") {
        return Ok(first);
    }
    let retry_name = format!("{}-retry", case.name);
    let mut second = run_debug_case_in(root, output, build, case, tools, timeout, &retry_name)?;
    second.diagnostic = format!(
        "retried once after `{}` (first attempt kept in cases/{}): {}",
        first.diagnostic, case.name, second.diagnostic
    );
    Ok(second)
}

fn run_debug_case_in(
    root: &Path,
    output: &Path,
    build: &Build,
    case: DebugCase,
    tools: &QemuTools,
    timeout: Duration,
    dir: &str,
) -> io::Result<CaseResult> {
    let case_dir = output.join("cases").join(dir);
    ensure_real_directory(&output.join("cases"))?;
    create_directory(&case_dir)?;
    let boot_image = make_fat_image(root, &case_dir, build, case, tools)?;
    let elf_before = file_hash(root, &tools.sha256sum.path, &build.elf)?;
    if elf_before != build.elf_hash {
        return Err(invalid("kernel ELF snapshot changed before QEMU launch"));
    }
    let args = debug_qemu_args(
        root,
        &case_dir,
        &boot_image.disk,
        &boot_image.vars_copy,
        case,
    )?;
    let args_text = command_args(&args)?;
    let stdout = case_dir.join("qemu.stdout.log");
    let stderr = case_dir.join("qemu.stderr.log");
    let mut command = supervised(&tools.qemu.path);
    command.args(&args).current_dir(root).stdin(Stdio::null());
    let process = run_with_logs(&mut command, &stdout, &stderr, timeout)?;
    let (markers_match, mut diagnostic) = match read_serial_log(&case_dir.join("serial.log")) {
        Ok(serial) => validate_debug_case(case, &process, &serial, &tools.fixtures.expected),
        Err(error) => (false, format!("unusable serial log: {error}")),
    };
    let disk_final = file_hash(root, &tools.sha256sum.path, &boot_image.disk)?;
    let disk_unchanged = disk_final == boot_image.disk_sha256_initial;
    if !disk_unchanged {
        diagnostic.push_str("; boot disk image changed during QEMU run");
    }
    let elf_after = file_hash(root, &tools.sha256sum.path, &build.elf)?;
    let snapshot_unchanged = elf_after == build.elf_hash;
    if !snapshot_unchanged {
        diagnostic.push_str("; kernel ELF snapshot changed during QEMU run");
    }
    let passed = markers_match && snapshot_unchanged && disk_unchanged;
    let vars_final = file_hash(root, &tools.sha256sum.path, &boot_image.vars_copy)?;
    let mut result = BTreeMap::new();
    manifest_value(&mut result, "schema", "1");
    manifest_value(&mut result, "case", case.name);
    manifest_value(&mut result, "cmdline", case.cmdline.unwrap_or(""));
    manifest_value(&mut result, "cpu", case.cpu);
    manifest_value(&mut result, "machine", case.plat.machine);
    manifest_value(
        &mut result,
        "accel",
        if case.plat.kvm { "kvm" } else { "tcg" },
    );
    manifest_value(&mut result, "expected_exit", case.expected_exit.to_string());
    manifest_value(
        &mut result,
        "observed_exit",
        process
            .exit_code
            .map_or_else(|| "none".to_owned(), |code| code.to_string()),
    );
    manifest_value(&mut result, "timed_out", process.timed_out.to_string());
    manifest_value(&mut result, "assertions", diagnostic.clone());
    manifest_value(
        &mut result,
        "status",
        if passed { "matched" } else { "failed" },
    );
    record_debug_tools(root, tools, &args_text, &mut result)?;
    manifest_value(&mut result, "sha256_kernel_elf", build.elf_hash.clone());
    manifest_value(&mut result, "sha256_kernel_elf_after_run", elf_after);
    record_image_result(
        root,
        &tools.sha256sum.path,
        &mut result,
        boot_image,
        vars_final,
        disk_final,
    )?;
    write_manifest(&case_dir.join("result.tsv"), result)?;
    Ok(CaseResult {
        name: case.name,
        cpu: case.cpu,
        passed,
        unavailable: false,
        expected_exit: case.expected_exit,
        observed_exit: process.exit_code,
        timed_out: process.timed_out,
        diagnostic,
        output: case_dir,
    })
}

fn record_debug_tools(
    root: &Path,
    tools: &QemuTools,
    args: &[String],
    result: &mut BTreeMap<String, String>,
) -> io::Result<()> {
    record_setpriv(root, &tools.sha256sum.path, result)?;
    manifest_value(result, "qemu_path", display_path(&tools.qemu.path)?);
    manifest_value(result, "qemu_version", single_line(&tools.qemu.version));
    manifest_value(result, "qemu_arguments", args.join(" | "));
    manifest_value(
        result,
        "sha256_qemu",
        file_hash(root, &tools.sha256sum.path, &tools.qemu.path)?,
    );
    manifest_value(result, "limine_version", single_line(&tools.limine.version));
    manifest_value(result, "limine_path", display_path(&tools.limine.path)?);
    manifest_value(
        result,
        "sha256_limine_cli",
        file_hash(root, &tools.sha256sum.path, &tools.limine.path)?,
    );
    manifest_value(
        result,
        "sha256_limine_efi",
        file_hash(root, &tools.sha256sum.path, Path::new(LIMINE_EFI))?,
    );
    manifest_value(result, "mkfs_fat_path", display_path(&tools.mkfs_fat)?);
    manifest_value(
        result,
        "mkfs_fat_version_source",
        "mkfs.stderr.log from the actual format command",
    );
    manifest_value(
        result,
        "sha256_mkfs_fat",
        file_hash(root, &tools.sha256sum.path, &tools.mkfs_fat)?,
    );
    manifest_value(result, "mmd_version", single_line(&tools.mmd.version));
    manifest_value(result, "mcopy_version", single_line(&tools.mcopy.version));
    manifest_value(
        result,
        "sha256_mmd",
        file_hash(root, &tools.sha256sum.path, &tools.mmd.path)?,
    );
    manifest_value(
        result,
        "sha256_mcopy",
        file_hash(root, &tools.sha256sum.path, &tools.mcopy.path)?,
    );
    Ok(())
}

fn record_image_result(
    root: &Path,
    sha256sum: &Path,
    result: &mut BTreeMap<String, String>,
    image: BootImage,
    vars_final: String,
    disk_final: String,
) -> io::Result<()> {
    manifest_value(
        result,
        "sha256_disk_image_initial",
        image.disk_sha256_initial,
    );
    manifest_value(result, "sha256_disk_image_after_run", disk_final);
    manifest_value(result, "sha256_image_kernel_elf", image.kernel_image_sha256);
    manifest_value(result, "sha256_image_limine_efi", image.limine_image_sha256);
    for (index, (name, hash)) in image.module_image_sha256.into_iter().enumerate() {
        manifest_value(result, &format!("sha256_image_module_{index}"), hash);
        manifest_value(
            result,
            &format!("source_module_{index}"),
            "Rust-generated-fixture",
        );
        manifest_value(result, &format!("file_module_{index}"), name);
    }
    manifest_value(
        result,
        "sha256_ovmf_code",
        file_hash(root, sha256sum, Path::new(OVMF_CODE))?,
    );
    manifest_value(
        result,
        "sha256_ovmf_vars_initial",
        image.vars_sha256_initial,
    );
    manifest_value(result, "sha256_ovmf_vars_after_run", vars_final);
    Ok(())
}

/// Firmware shares the UART before kernel entry. Accept only complete leading
/// ECMA-48 CSI sequences, never erase controls inside text or search for a
/// diagnostic substring. Keep the raw capture unchanged for independent review.
fn serial_record(mut line: &str) -> Result<&str, &'static str> {
    line = line.trim_end_matches('\r');
    while let Some(sequence) = line.strip_prefix("\x1b[") {
        let remaining = sequence
            .trim_start_matches(|ch| ('\u{30}'..='\u{3f}').contains(&ch))
            .trim_start_matches(|ch| ('\u{20}'..='\u{2f}').contains(&ch));
        if !remaining
            .as_bytes()
            .first()
            .is_some_and(|byte| (0x40..=0x7e).contains(byte))
        {
            return Err("malformed or truncated leading serial CSI sequence");
        }
        // The final byte is ASCII, so this is a UTF-8 boundary.
        line = &remaining[1..];
    }
    if line
        .bytes()
        .any(|byte| byte.is_ascii_control() && byte != b'\t')
    {
        return Err("unsupported serial control inside a text record");
    }
    Ok(line)
}

fn record_matches(line: &str, required: &str) -> bool {
    line.strip_prefix(required)
        .is_some_and(|suffix| suffix.is_empty() || suffix.starts_with(char::is_whitespace))
}

fn unique_exact_record(lines: &[&str], prefix: &str, expected: &str) -> bool {
    let mut records = lines.iter().filter(|line| record_matches(line, prefix));
    records.next() == Some(&expected) && records.next().is_none()
}

/// The console self-test record: exactly one, as expected for the display count,
/// and before the bootstrap checkpoint when that is reached.
fn validate_console_record(lines: &[&str], framebuffers: usize) -> Result<(), String> {
    let console = format!(
        "CHECK console ok framebuffers={framebuffers} scrolled=true tail=true stale=false readback=true wrap=true"
    );
    // Exactly one console record (a second one could come from a later stage or
    // userspace), and it precedes the bootstrap checkpoint when that is reached.
    let console_lines = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.starts_with("CHECK console"))
        .collect::<Vec<_>>();
    match console_lines.as_slice() {
        [(position, line)] if **line == console.as_str() => {
            if lines
                .iter()
                .position(|line| line.starts_with("CHECKPOINT"))
                .is_some_and(|checkpoint| checkpoint < *position)
            {
                return Err("console record must precede CHECKPOINT".to_owned());
            }
        }
        [] => return Err(format!("missing console record: {console}")),
        [(_, line)] => {
            return Err(format!(
                "console record {line:?} differs from expected {console:?}"
            ));
        }
        more => {
            return Err(format!(
                "expected exactly one console record, found {}",
                more.len()
            ));
        }
    }
    Ok(())
}

/// The value of `key=` among the whitespace-separated fields of `line`.
fn record_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split_ascii_whitespace()
        .find_map(|field| field.strip_prefix(key)?.strip_prefix('='))
}

fn unique_record<'a>(lines: &[&'a str], prefix: &str) -> Result<&'a str, String> {
    let mut found = lines.iter().filter(|line| record_matches(line, prefix));
    match (found.next(), found.next()) {
        (Some(line), None) => Ok(line),
        _ => Err(format!("{prefix} must appear exactly once")),
    }
}

/// The interrupt-controller and time path a positive case must report: the
/// expected mode/clockevent, the TSC calibration source, HPET presence and a
/// sane measured tick/sleep. QEMU variants differ; a wrong path never passes.
fn validate_platform(lines: &[&str], plat: Platform) -> Result<(), String> {
    let expected = format!(
        "CHECK interrupt-controllers ok mode={} event={} ioapic_timer={}",
        plat.mode, plat.event, plat.ioapic_timer
    );
    if !unique_exact_record(lines, "CHECK interrupt-controllers", &expected) {
        return Err(format!("platform must report exactly `{expected}`"));
    }
    let number =
        |line: &str, key: &str| record_field(line, key).and_then(|v| v.parse::<u64>().ok());
    let tsc = unique_record(lines, "CHECK tsc ok")?;
    let source = record_field(tsc, "source").unwrap_or("");
    if !plat.tsc_sources.contains(&source) {
        return Err(format!(
            "TSC calibration source `{source}` is not one of {:?}",
            plat.tsc_sources
        ));
    }
    if number(tsc, "khz").is_none_or(|khz| khz < 100_000)
        || (number(tsc, "hpet_hz").unwrap_or(0) != 0) != plat.hpet
        || record_field(tsc, "rtc") != Some("true")
    {
        return Err(
            "CHECK tsc must report khz>=100000, rtc=true and hpet_hz matching the machine"
                .to_owned(),
        );
    }
    // A PIT-calibrated TSC must say how many quick-PIT attempts it took (1..=3).
    if source == "pit" && !number(tsc, "pit_tries").is_some_and(|n| (1..=3).contains(&n)) {
        return Err("source=pit requires pit_tries in 1..=3".to_owned());
    }
    let tables = unique_record(lines, "CHECK time-tables")?;
    if (record_field(tables, "hpet").is_some_and(|v| v != "0x0")) != plat.hpet {
        return Err("CHECK time-tables hpet does not match the machine".to_owned());
    }
    let madt = unique_record(lines, "CHECK madt ok")?;
    if number(madt, "cpus") != Some(1) || number(madt, "ioapics") != Some(1) {
        return Err("CHECK madt must describe one CPU and one IOAPIC".to_owned());
    }
    let apic = unique_record(lines, "CHECK apic ok")?;
    if record_field(apic, "mode") != Some(plat.mode)
        || record_field(apic, "reason") != Some(plat.reason)
    {
        return Err(format!(
            "CHECK apic must report mode={} reason={}",
            plat.mode, plat.reason
        ));
    }
    let timer = unique_record(lines, "CHECK timer ok")?;
    // 16 ticks counted from an arbitrary phase span 15..16 periods of 1 ms;
    // generous host-noise bounds, the kernel enforces the same window.
    if !number(timer, "tick16_ns").is_some_and(|ns| (14_000_000..=60_000_000).contains(&ns)) {
        return Err("CHECK timer must measure 16 ticks within 14..60 ms on the TSC".to_owned());
    }
    let keeping = unique_record(lines, "CHECK timekeeping ok")?;
    if !number(keeping, "slept_ns").is_some_and(|ns| (20_000_000..=500_000_000).contains(&ns)) {
        return Err("CHECK timekeeping must sleep at least 20 ms".to_owned());
    }
    Ok(())
}

fn validate_debug_case(
    case: DebugCase,
    process: &ProcessResult,
    serial: &str,
    expected: &fixture::Expected,
) -> (bool, String) {
    if process.timed_out {
        return (false, "QEMU timed out; timeout is never a pass".to_owned());
    }
    if process.exit_code != Some(case.expected_exit) {
        return (
            false,
            format!(
                "QEMU exit {:?}, expected {}",
                process.exit_code, case.expected_exit
            ),
        );
    }
    let lines = match serial
        .lines()
        .map(serial_record)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(lines) => lines,
        Err(error) => return (false, error.to_owned()),
    };
    let missing = case
        .required
        .iter()
        .filter(|required| !lines.iter().any(|line| record_matches(line, required)))
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return (
            false,
            format!("missing serial assertions: {}", missing.join(", ")),
        );
    }
    if let Err(diagnostic) = validate_console_record(&lines, case.framebuffers) {
        return (false, diagnostic);
    }
    if !case.forbid_success
        && let Err(diagnostic) =
            validate_success_serial(&lines, case.modules, &expected.archive_counts)
    {
        return (false, diagnostic);
    }
    if !case.forbid_success
        && let Err(diagnostic) = validate_platform(&lines, case.plat)
    {
        return (false, diagnostic);
    }
    if let Err(diagnostic) = validate_userspace(&lines, case.user, &expected.init) {
        return (false, diagnostic);
    }
    if case.name == "unmasked-timer" {
        let observed_irq = lines.iter().any(|line| {
            let Some(rest) = line.strip_prefix("TIMER mask observation periods=2 irq_delta=")
            else {
                return false;
            };
            rest.split_ascii_whitespace()
                .next()
                .and_then(|value| value.parse::<u64>().ok())
                .is_some_and(|delta| delta > 0)
        });
        if !observed_irq {
            return (
                false,
                "unmasked timer must report periods=2 and nonzero irq_delta".to_owned(),
            );
        }
    }
    if case.name == "irq-restore-early"
        && (!observed_irq_restore(&lines, false)
            || lines
                .iter()
                .any(|line| record_matches(line, "CHECK irq-guard")))
    {
        return (
            false,
            "early IRQ restore must observe two tick periods, delivered IRQs and failed lock acquisition"
                .to_owned(),
        );
    }
    if case.name == "unexpected-page-fault"
        && (!unique_exact_record(
            &lines,
            "TRAP call-abi",
            "TRAP call-abi vector=14 rsp_mod16=8",
        ) || lines
            .iter()
            .any(|line| record_matches(line, "FAIL trap-call-abi")))
    {
        return (
            false,
            "fatal page fault must observe the actual ordinary-call entry alignment".to_owned(),
        );
    }
    if case.forbid_success && lines.iter().any(|line| line.starts_with("RESULT success")) {
        return (false, "negative case emitted RESULT success".to_owned());
    }
    (
        true,
        "expected QEMU exit and serial assertions matched".to_owned(),
    )
}

/// Linux 6.18.57 with no `/init` and no root device (observed on the pinned reference kernel).
fn validate_no_root(lines: &[&str]) -> Result<(), String> {
    let mut previous = None;
    for (record, what) in [
        (
            "check access for rdinit=/init failed: -2, ignoring",
            "rdinit warning",
        ),
        ("/dev/root: Can't open blockdev", "blockdev line"),
        (
            "VFS: Cannot open root device \"\" or unknown-block(0,0): error -6",
            "root device line",
        ),
        (
            "Please append a correct \"root=\" boot option; here are the available partitions:",
            "partition prompt",
        ),
        (
            "Kernel panic - not syncing: VFS: Unable to mount root fs on unknown-block(0,0)",
            "VFS panic",
        ),
        ("FAIL no-root", "failure marker"),
    ] {
        let mut found = lines
            .iter()
            .enumerate()
            .filter(|(_, line)| **line == record);
        let (position, _) = found.next().ok_or_else(|| format!("missing {what}"))?;
        if found.next().is_some() || previous.is_some_and(|earlier| position <= earlier) {
            return Err(format!("{what} duplicated or out of order"));
        }
        previous = Some(position);
    }
    if lines
        .iter()
        .any(|line| line.starts_with("Run /init") || line.starts_with("CHECK userspace exec"))
    {
        return Err("a boot without /init must not run one".to_owned());
    }
    Ok(())
}

/// Serial records located by predicate, each exactly once.
struct Finder<'a> {
    lines: &'a [&'a str],
}

impl Finder<'_> {
    fn at(&self, wanted: &dyn Fn(&str) -> bool, what: &str) -> Result<usize, String> {
        let mut found = self
            .lines
            .iter()
            .enumerate()
            .filter(|(_, line)| wanted(line));
        let (position, _) = found.next().ok_or_else(|| format!("missing {what}"))?;
        if found.next().is_some() {
            return Err(format!("{what} appears more than once"));
        }
        Ok(position)
    }

    fn exact(&self, text: &str, what: &str) -> Result<usize, String> {
        self.at(&|line| line == text, what)
    }
}

/// The records one run of the generated `/init` must produce, in order and exactly once.
fn validate_userspace(lines: &[&str], user: User, init: &fixture::ElfFacts) -> Result<(), String> {
    let find = Finder { lines };
    let (argc, mode_line, exact_summary, (execute_protection, access_protection)) = match user {
        User::None => return Ok(()),
        User::NoRoot => return validate_no_root(lines),
        User::Ok {
            argc,
            mode_line,
            exact_summary,
            protection,
        } => (argc, mode_line, exact_summary, protection),
        User::Segfault | User::Unimplemented | User::Oracle(_) | User::OracleUntil { .. } => {
            (2, None, true, (false, false))
        }
    };
    let audit = find.at(
        &|line| line.starts_with("CHECK userspace-audit ok user_pages="),
        "isolation audit",
    )?;
    if !lines[audit].ends_with("kernel_user_bits=0 above_task_size=0") {
        return Err("isolation audit reported a user bit in the kernel half".to_owned());
    }
    let exec_prefix = format!(
        "CHECK userspace exec path=/init entry={:#x} loads={} sp=0x7fffffff",
        init.entry, init.loads
    );
    let exec_suffix = format!(" smep={execute_protection} smap={access_protection}");
    let summary = fixture::init_summary(init, argc);
    let summary_prefix = format!(
        "init: argc={argc} argv0=/init pid=1 rsp_mod16=0 auxv=AT_MINSIGSTKSZ:0x5a0,AT_HWCAP:"
    );
    let mut positions = vec![
        audit,
        find.exact("Run /init as init process", "Run /init line")?,
        find.at(
            &|line| line.starts_with(&exec_prefix) && line.ends_with(&exec_suffix),
            "userspace exec record",
        )?,
        find.exact(MM_USERCOPY_RECORD, "mm-usercopy record")?,
        find.exact("init: hello from userspace", "init's first line")?,
        find.at(
            &|line| {
                if exact_summary {
                    line == summary
                } else {
                    line.starts_with(&summary_prefix)
                }
            },
            "init summary line",
        )?,
    ];
    if let Some(mode_line) = mode_line {
        positions.push(find.exact(mode_line, "init mode line")?);
    }
    let oracle = match user {
        User::Oracle(group) => Some((group, None)),
        User::OracleUntil { group, until } => Some((group, Some(until))),
        _ => None,
    };
    if let Some((group, until)) = oracle {
        let (first, last) = validate_oracle(lines, group, until)?;
        positions.push(first);
        // A one-line group has first == last; strict ordering must not reject it.
        if last != first {
            positions.push(last);
        }
    }
    positions.extend(user_tail(
        &find,
        user,
        init,
        mode_line == Some(DEMAND_MODE_LINE),
    )?);
    if positions.windows(2).all(|pair| pair[0] < pair[1]) {
        Ok(())
    } else {
        Err("userspace records are out of order".to_owned())
    }
}

/// Rows of [`ORACLE_EXPECTED`] for `group` in file order: `(kind, exact stdout line)` where kind is
/// `check`, `info` or `summary`. The header row and `#` comments are skipped.
fn oracle_rows(group: &str) -> impl Iterator<Item = (&'static str, &'static str)> + '_ {
    ORACLE_EXPECTED
        .lines()
        .filter(|line| !line.starts_with('#'))
        .skip(1)
        .filter_map(move |row| {
            let mut fields = row.split('\t');
            let (row_group, kind, _name, line) = (
                fields.next()?,
                fields.next()?,
                fields.next()?,
                fields.next()?,
            );
            (row_group == group).then_some((kind, line))
        })
}

/// The line prefixes of an oracle test group's output; everything else the guest prints (kernel
/// `printk`s, `init:` banner lines) is not part of the comparison.
const ORACLE_PREFIXES: [&str; 3] = ["init: test ", "init: tests ", "init: info "];

/// `init: info <group>.<name>`: the part of an info line that must match.
fn oracle_key(line: &str) -> Vec<&str> {
    line.splitn(4, ' ').take(3).collect()
}

/// The oracle group's output on this kernel must equal the pinned Linux's: the lines starting with
/// [`ORACLE_PREFIXES`], in order, none missing and none extra. `check` and `summary` rows compare
/// exactly (a `FAIL` line, a different count or a reordering is a mismatch); an `info` row is a
/// recorded observation, so only its `init: info <group>.<name>` key must match. Returns the
/// serial indices of the first and last such line, so the caller can order them between init's
/// summary line and `init: ok`.
///
/// With `until`, only the rows before the first check whose line contains it are expected (and
/// the group's summary row is not): the group runs as far as the syscalls that exist.
fn validate_oracle(
    lines: &[&str],
    group: &str,
    until: Option<&str>,
) -> Result<(usize, usize), String> {
    let mut expected = oracle_rows(group).collect::<Vec<_>>();
    if let Some(marker) = until {
        let cut = expected
            .iter()
            .position(|(_, line)| line.contains(marker))
            .ok_or_else(|| format!("oracle {group} has no check containing {marker:?}"))?;
        expected.truncate(cut);
    }
    if expected.is_empty() {
        return Err(format!("no expected oracle lines for group {group}"));
    }
    let observed = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| {
            ORACLE_PREFIXES
                .iter()
                .any(|prefix| line.starts_with(prefix))
        })
        .map(|(index, line)| (index, *line))
        .collect::<Vec<_>>();
    for (position, ((kind, want), (_, got))) in expected.iter().zip(&observed).enumerate() {
        let same = if *kind == "info" {
            oracle_key(want) == oracle_key(got)
        } else {
            want == got
        };
        if !same {
            return Err(format!(
                "oracle {group} line {position}: expected {want:?}, got {got:?}"
            ));
        }
    }
    if observed.len() != expected.len() {
        return Err(format!(
            "oracle {group}: expected {} lines, got {}",
            expected.len(),
            observed.len()
        ));
    }
    Ok((observed[0].0, observed[observed.len() - 1].0))
}

/// `init[1]: segfault at 0 ip <ip> sp <sp> error 4 in init[<off>,<start>+<len>] likely on CPU 0
/// (core 0, socket 0)` with the bracket bound to the ELF: `ip` lies in the page-rounded extent of
/// an executable `PT_LOAD`'s file-backed extent (page-rounded `p_vaddr..p_vaddr + p_filesz`, as
/// `print_vma_addr` reports; the bss tail is anonymous), and `start`/`len` are exactly that extent.
fn segfault_line_matches(line: &str, init: &fixture::ElfFacts) -> bool {
    let Some(rest) = line.strip_prefix("init[1]: segfault at 0 ip ") else {
        return false;
    };
    let Some((ip, rest)) = rest.split_once(" sp ") else {
        return false;
    };
    let Some((_, rest)) = rest.split_once(" error 4 in init[") else {
        return false;
    };
    let Some((bracket, tail)) = rest.split_once(']') else {
        return false;
    };
    let parse = |text: &str| u64::from_str_radix(text, 16).ok();
    let (Some(ip), Some((_, extent))) = (parse(ip), bracket.split_once(',')) else {
        return false;
    };
    let Some((start, length)) = extent
        .split_once('+')
        .and_then(|(start, length)| Some((parse(start)?, parse(length)?)))
    else {
        return false;
    };
    tail == " likely on CPU 0 (core 0, socket 0)"
        && init.executable_file_extents.iter().any(|&(vaddr, end)| {
            let first = vaddr & !4095;
            start == first
                && length == end.next_multiple_of(4096) - first
                && (start..start + length).contains(&ip)
        })
}

/// `CHECK user-faults ok handled=N`: the ring-3 page faults the address-space model resolved and
/// returned from. `demand` (init's `-- demand` mode: anonymous zero/private pages and stack growth
/// taken by init itself) requires N >= 1; the other modes never fault (the loader populated their
/// pages) but must still report the counter.
fn user_faults_handled(line: &str, demand: bool) -> bool {
    line.strip_prefix("CHECK user-faults ok handled=")
        .and_then(|count| count.parse::<u64>().ok())
        .is_some_and(|count| count >= u64::from(demand))
}

/// The records after the summary line, by what init did.
fn user_tail(
    find: &Finder<'_>,
    user: User,
    init: &fixture::ElfFacts,
    demand: bool,
) -> Result<Vec<usize>, String> {
    const DEATH: &str = "Kernel panic - not syncing: Attempted to kill init! exitcode=";
    Ok(match user {
        User::Ok { .. } | User::Oracle(_) => vec![
            find.exact("init: ok", "init: ok")?,
            find.at(
                &|line| user_faults_handled(line, demand),
                "handled ring-3 page faults record",
            )?,
            find.exact(&format!("{DEATH}0x00000000"), "init death panic")?,
            find.exact("RESULT success", "RESULT success")?,
        ],
        User::Segfault => vec![
            find.exact("init: faulting on purpose", "fault announcement")?,
            find.at(
                &|line| segfault_line_matches(line, init),
                "Linux segfault line",
            )?,
            find.exact(&format!("{DEATH}0x0000000b"), "init death panic")?,
            find.exact("FAIL init exitcode=0x0000000b", "failure marker")?,
        ],
        User::OracleUntil { .. } => vec![find.exact(
            "FAIL syscall unimplemented nr=9",
            "unimplemented-syscall stop",
        )?],
        User::Unimplemented => vec![
            find.exact(
                "init: calling io_uring_setup",
                "io_uring_setup announcement",
            )?,
            find.exact(
                "FAIL syscall unimplemented nr=425",
                "unimplemented-syscall stop",
            )?,
        ],
        User::None | User::NoRoot => Vec::new(),
    })
}

fn observed_irq_restore(lines: &[&str], acquired: bool) -> bool {
    let mut records = lines
        .iter()
        .filter(|line| record_matches(line, "IRQ restore observation"));
    let Some(line) = records.next() else {
        return false;
    };
    if records.next().is_some() {
        return false;
    }
    let Some(record) = line.strip_prefix("IRQ restore observation ") else {
        return false;
    };
    let Some(rest) = record.strip_prefix("periods=2 irq_delta=") else {
        return false;
    };
    let Some((delta, field)) = rest.split_once(' ') else {
        return false;
    };
    delta.parse::<u64>().is_ok_and(|value| value > 0)
        && field
            == if acquired {
                "lock_acquired=true"
            } else {
                "lock_acquired=false"
            }
}

/// Linux reports a bad initramfs and still boots: exactly this warning, never an inspection record.
fn corrupt_module_skipped(lines: &[&str], index: usize) -> bool {
    let warning =
        format!("WARN Initramfs unpacking failed: module={index} {CORRUPT_MODULE_WARNING}");
    let inspected = format!("CHECK image inspected module={index} ");
    unique_exact_record(lines, "WARN Initramfs unpacking failed:", &warning)
        && !lines.iter().any(|line| line.starts_with(&inspected))
}

fn validate_image_serial(
    lines: &[&str],
    modules: &[Module],
    archive_counts: &str,
) -> Result<(), String> {
    let epoch_record = module_epoch_record(modules.len());
    let inspected = modules.iter().filter(|m| **m != Module::Corrupt).count();
    if lines
        .iter()
        .filter(|line| line.starts_with("CHECK image inspected "))
        .count()
        != inspected
    {
        return Err(
            "image inspection must report each decodable module exactly once and no other"
                .to_owned(),
        );
    }
    if !unique_exact_record(lines, "CHECK module-epoch", &epoch_record) {
        return Err("missing exact ended-borrows/retained-reservations epoch proof".to_owned());
    }
    let epoch = lines
        .iter()
        .position(|line| *line == epoch_record)
        .ok_or_else(|| "missing module epoch".to_owned())?;
    let paging = lines
        .iter()
        .position(|line| line.starts_with("CHECK paging ok"))
        .ok_or_else(|| "missing owned paging proof".to_owned())?;
    if epoch >= paging {
        return Err("module epoch proof must precede the owned paging result".to_owned());
    }
    let mut spans = Vec::new();
    let mut previous = None;
    for (index, module) in modules.iter().enumerate() {
        if *module == Module::Corrupt {
            if !corrupt_module_skipped(lines, index) {
                return Err(format!(
                    "corrupt module {index} must be skipped with the exact warning"
                ));
            }
            continue;
        }
        let expected = if *module == Module::Empty {
            EMPTY_MODULE_COUNTS
        } else {
            archive_counts
        };
        let prefix = format!("CHECK image inspected module={index} physical=");
        let mut records = lines
            .iter()
            .enumerate()
            .filter(|(_, line)| line.starts_with(&prefix));
        let (position, line) = records
            .next()
            .ok_or_else(|| format!("missing module {index}"))?;
        if records.next().is_some()
            || position >= epoch
            || previous.is_some_and(|earlier| position <= earlier)
        {
            return Err("module records duplicate, reordered, or outside pre-CR3 epoch".to_owned());
        }
        previous = Some(position);
        let (physical, counts) = line
            .strip_prefix(&prefix)
            .and_then(|rest| rest.split_once(' '))
            .ok_or_else(|| "malformed module physical/count record".to_owned())?;
        if counts != expected {
            return Err(format!(
                "module {index} did not decode the bound immutable input"
            ));
        }
        let digits = physical
            .strip_prefix("0x")
            .ok_or_else(|| "missing physical hex prefix".to_owned())?;
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("invalid module physical address".to_owned());
        }
        let physical = u64::from_str_radix(digits, 16)
            .map_err(|_| "invalid module physical range".to_owned())?;
        let reserved = counts
            .strip_prefix("reserved=")
            .and_then(|rest| rest.split_once(' '))
            .and_then(|(value, _)| value.parse::<u64>().ok())
            .ok_or_else(|| "invalid module reserved length".to_owned())?;
        if physical == 0 || physical & 4095 != 0 {
            return Err("module physical address must be nonzero and page aligned".to_owned());
        }
        let end = physical
            .checked_add(reserved)
            .ok_or_else(|| "module reservation overflow".to_owned())?;
        spans.push((physical, end));
    }
    for (index, span) in spans.iter().enumerate() {
        if spans[..index]
            .iter()
            .any(|previous| previous.1 > span.0 && span.1 > previous.0)
        {
            return Err("module reservations overlap".to_owned());
        }
    }
    Ok(())
}

fn validate_success_serial(
    lines: &[&str],
    modules: &[Module],
    archive_counts: &str,
) -> Result<(), String> {
    if lines.iter().any(|line| line.starts_with("FAIL ")) {
        return Err("positive case emitted a failure diagnostic".to_owned());
    }
    if !unique_exact_record(lines, "CHECK memory-runtime", MEMORY_RUNTIME_RECORD) {
        return Err("positive case must report the exact scalar memory-provider proof".to_owned());
    }
    validate_image_serial(lines, modules, archive_counts)?;
    if !lines.contains(&"TIMER mask observation periods=2 irq_delta=0") {
        return Err(
            "positive case must observe exactly two tick periods and zero IRQ delta".to_owned(),
        );
    }
    if !unique_exact_record(lines, "CHECK page-fault-gprs", PF_GPR_RECORD) {
        return Err("positive case must report the exact returning-PF GPR proof".to_owned());
    }
    if !unique_exact_record(lines, "CHECK buddy-orders", BUDDY_ORDER_RECORD) {
        return Err("positive case must report the exact multi-order allocator proof".to_owned());
    }
    if !unique_exact_record(lines, "CHECK user-mm", USER_MM_RECORD) {
        return Err("positive case must report the exact post-activation user-mm proof".to_owned());
    }
    if !unique_exact_record(lines, "CHECK heap", HEAP_RECORD) {
        return Err("positive case must report the exact fallible-heap proof".to_owned());
    }
    if !unique_exact_record(lines, "CHECK irq-guard", IRQ_GUARD_RECORD)
        || !observed_irq_restore(lines, true)
    {
        return Err(
            "positive case must report the exact IRQ guard and real restore proof".to_owned(),
        );
    }
    let table_rollback = lines.iter().any(|line| {
        let Some(rest) = line.strip_prefix("CHECK table-oom ok failure_points=") else {
            return false;
        };
        let Some(points) = rest
            .split_ascii_whitespace()
            .next()
            .and_then(|value| value.parse::<usize>().ok())
        else {
            return false;
        };
        points > 0
            && rest
                .split_ascii_whitespace()
                .any(|field| field == "accounting=restored")
    });
    if !table_rollback {
        return Err(
            "table-allocation rollback must report failure_points>0 and accounting=restored"
                .to_owned(),
        );
    }
    for (prefix, required_field) in [
        ("CHECK exception ok", "gprs=15"),
        ("CHECK timer ok", "gprs=15"),
        ("CHECK timer ok", "periods=2"),
    ] {
        if !lines.iter().any(|line| {
            line.starts_with(prefix)
                && line
                    .split_ascii_whitespace()
                    .any(|field| field == required_field)
        }) {
            return Err(format!("{prefix} must assert {required_field}"));
        }
    }
    Ok(())
}

/// Captures the QEMU/image tool identities and generates the run's boot-module fixtures
/// (they need the recorded `sha256sum`), so everything a case stages exists after this call.
fn prepare_qemu_inputs(root: &Path, output: &Path, init_elf: &Path) -> io::Result<QemuTools> {
    let qemu = capture_tool_version(root, output, "qemu-system-x86_64", &["--version"])?;
    let limine = capture_tool_version(root, output, "limine", &["--version"])?;
    if limine.version.lines().next() != Some("Limine 12.9.3") {
        return Err(invalid(format!(
            "Limine 12.9.3 is required for the pinned base-revision contract; found {}",
            single_line(&limine.version)
        )));
    }
    let mkfs_fat = resolve_program(Path::new("mkfs.fat"))?;
    let mdir = capture_tool_version(root, output, "mdir", &["--version"])?;
    let mmd = capture_tool_version(root, output, "mmd", &["--version"])?;
    let mcopy = capture_tool_version(root, output, "mcopy", &["--version"])?;
    let sha256sum = capture_tool_version(root, output, "sha256sum", &["--version"])?;
    let fixtures = Fixtures::generate(output, &sha256sum.path, init_elf)?;
    Ok(QemuTools {
        qemu,
        limine,
        mkfs_fat,
        mdir,
        mmd,
        mcopy,
        sha256sum,
        fixtures,
    })
}

fn record_case(
    values: &mut BTreeMap<String, String>,
    output: &Output,
    case: &CaseResult,
) -> io::Result<()> {
    let prefix = format!("case_{}", case.name);
    manifest_value(
        values,
        &format!("{prefix}_status"),
        if case.passed {
            "matched"
        } else if case.unavailable {
            "unavailable"
        } else {
            "failed"
        },
    );
    manifest_value(values, &format!("{prefix}_cpu"), case.cpu);
    manifest_value(
        values,
        &format!("{prefix}_expected_exit"),
        case.expected_exit.to_string(),
    );
    manifest_value(
        values,
        &format!("{prefix}_observed_exit"),
        case.observed_exit
            .map_or_else(|| "none".to_owned(), |code| code.to_string()),
    );
    manifest_value(
        values,
        &format!("{prefix}_timed_out"),
        case.timed_out.to_string(),
    );
    manifest_value(
        values,
        &format!("{prefix}_diagnostic"),
        case.diagnostic.clone(),
    );
    manifest_value(
        values,
        &format!("{prefix}_artifacts"),
        display_path(&relative_path(&output.root, &case.output)?)?,
    );
    Ok(())
}

fn record_fixtures(
    values: &mut BTreeMap<String, String>,
    init_build: &Build,
    fixtures: &Fixtures,
) -> io::Result<()> {
    manifest_value(values, "init_elf", display_path(&init_build.elf_relative)?);
    manifest_value(values, "sha256_init_elf", init_build.elf_hash.clone());
    manifest_value(
        values,
        "sha256_fixture_initramfs",
        fixtures.archive_sha256.clone(),
    );
    manifest_value(
        values,
        "sha256_fixture_corrupt_module",
        fixtures.corrupt_sha256.clone(),
    );
    manifest_value(
        values,
        "expected_image_record",
        fixtures.expected.archive_counts.clone(),
    );
    manifest_value(
        values,
        "sha256_fixture_noinit_archive",
        fixtures.noinit_sha256.clone(),
    );
    manifest_value(
        values,
        "expected_init_summary",
        fixture::init_summary(&fixtures.expected.init, 1),
    );
    Ok(())
}

/// Everything one `kernel-test` run observed, for the top-level manifest.
struct TestRun {
    self_build: Build,
    default_build: Build,
    init_build: Build,
    fixtures: Fixtures,
    cases: Vec<CaseResult>,
    screenshot: PathBuf,
    screenshot_format: String,
    cpu_state: String,
}

fn write_top_manifest(output: &Output, run: &TestRun) -> io::Result<()> {
    let TestRun {
        self_build,
        default_build,
        init_build,
        fixtures,
        cases,
        screenshot,
        screenshot_format,
        cpu_state,
    } = run;
    let mut values = BTreeMap::new();
    manifest_value(&mut values, "schema", "1");
    manifest_value(&mut values, "command", "kernel-test");
    manifest_value(
        &mut values,
        "qemu_self_test_feature",
        self_build.qemu_self_test.to_string(),
    );
    manifest_value(&mut values, "default_feature_set", "freestanding");
    manifest_value(&mut values, "automated_case_count", cases.len().to_string());
    manifest_value(
        &mut values,
        "automated_cases_matched",
        cases.iter().filter(|case| case.passed).count().to_string(),
    );
    manifest_value(
        &mut values,
        "automated_cases_failed",
        cases
            .iter()
            .filter(|case| !case.passed && !case.unavailable)
            .count()
            .to_string(),
    );
    manifest_value(
        &mut values,
        "automated_cases_unavailable",
        cases
            .iter()
            .filter(|case| case.unavailable)
            .count()
            .to_string(),
    );
    for case in cases {
        record_case(&mut values, output, case)?;
    }
    manifest_value(
        &mut values,
        "default_boot_state",
        "halted_without_debug_exit; qmp-screen-capture-requires-human-review",
    );
    manifest_value(
        &mut values,
        "default_boot_qmp_cpu_state",
        cpu_state.to_owned(),
    );
    manifest_value(
        &mut values,
        "default_boot_screenshot",
        display_path(&relative_path(&output.root, screenshot)?)?,
    );
    manifest_value(
        &mut values,
        "default_boot_screenshot_format",
        screenshot_format,
    );
    manifest_value(&mut values, "default_boot_visual_review", "pending");
    manifest_value(
        &mut values,
        "default_boot_exit_policy",
        "QEMU timeout/exit is not a pass; capture is retained for manual review",
    );
    manifest_value(
        &mut values,
        "self_test_elf",
        display_path(&self_build.elf_relative)?,
    );
    manifest_value(
        &mut values,
        "default_elf",
        display_path(&default_build.elf_relative)?,
    );
    record_fixtures(&mut values, init_build, fixtures)?;
    manifest_value(
        &mut values,
        "result_scope",
        "QEMU-only bootstrap assertions; no physical parity/performance claim",
    );
    write_manifest(&output.path.join("manifest.tsv"), values)
}

pub fn test(root: &Path, requested: &Path, timeout: Duration) -> io::Result<()> {
    let output = prepare_output(root, requested)?;
    let result = run_kernel_test(&output, timeout);
    match result {
        Ok(run) => {
            write_top_manifest(&output, &run)?;
            let (cases, screenshot) = (&run.cases, &run.screenshot);
            let failures = cases
                .iter()
                .filter(|case| !case.passed && !case.unavailable)
                .collect::<Vec<_>>();
            let unavailable = cases
                .iter()
                .filter(|case| case.unavailable)
                .collect::<Vec<_>>();
            println!(
                "kernel-test: {}/{} debug-exit cases matched; default framebuffer capture requires human review",
                cases.iter().filter(|case| case.passed).count(),
                cases.len()
            );
            for case in &unavailable {
                println!(
                    "UNAVAILABLE (not run, not a pass): {}: {}",
                    case.name, case.diagnostic
                );
            }
            println!(
                "Framebuffer capture: {}",
                display_path(&relative_path(&output.root, screenshot)?)?
            );
            println!("Manifest: {}/manifest.tsv", display_path(&output.relative)?);
            if failures.is_empty() {
                Ok(())
            } else {
                Err(invalid(format!(
                    "{} QEMU debug-exit case(s) failed; inspect {}/manifest.tsv",
                    failures.len(),
                    display_path(&output.relative)?
                )))
            }
        }
        Err(error) => {
            let mut values = BTreeMap::new();
            manifest_value(&mut values, "schema", "1");
            manifest_value(&mut values, "command", "kernel-test");
            manifest_value(&mut values, "status", "failed");
            manifest_value(&mut values, "error", single_line(&error.to_string()));
            let _ = write_manifest(&output.path.join("manifest.tsv"), values);
            Err(error)
        }
    }
}

fn run_kernel_test(output: &Output, timeout: Duration) -> io::Result<TestRun> {
    let qemu_dir = output.path.join("qemu-self-test-build");
    create_directory(&qemu_dir)?;
    let self_build = build_target(
        &output.root,
        &qemu_dir,
        Target::Kernel {
            qemu_self_test: true,
        },
    )?;
    let default_dir = output.path.join("freestanding-build");
    create_directory(&default_dir)?;
    let default_build = build_target(
        &output.root,
        &default_dir,
        Target::Kernel {
            qemu_self_test: false,
        },
    )?;
    let init_dir = output.path.join("init-build");
    create_directory(&init_dir)?;
    let init_build = build_target(&output.root, &init_dir, Target::Init)?;
    for dir in [&default_dir, &init_dir] {
        if fs::read(qemu_dir.join("source-inputs-before.tsv"))?
            != fs::read(dir.join("source-inputs-before.tsv"))?
        {
            return Err(invalid(
                "source inputs changed between the self-test, default and init builds",
            ));
        }
    }
    let tools = prepare_qemu_inputs(&output.root, &output.path, &init_build.elf)?;
    copy_notices(&output.root, &output.path, &tools.sha256sum.path)?;
    let mut cases = Vec::with_capacity(DEBUG_CASES.len());
    for case in DEBUG_CASES.iter().copied() {
        cases.push(run_debug_case(
            &output.root,
            &output.path,
            &self_build,
            case,
            &tools,
            timeout,
        )?);
    }
    let (screenshot, screenshot_format, cpu_state) =
        capture_default_framebuffer(&output.root, &output.path, &default_build, &tools, timeout)?;
    Ok(TestRun {
        self_build,
        default_build,
        init_build,
        fixtures: tools.fixtures,
        cases,
        screenshot,
        screenshot_format,
        cpu_state,
    })
}

fn create_process(command: &mut Command) -> io::Result<ChildGuard> {
    isolate_command(command);
    command.spawn().map(ChildGuard::new).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "failed to spawn {}: {error}",
                command.get_program().to_string_lossy()
            ),
        )
    })
}

fn wait_qmp_socket(
    path: &Path,
    child: &mut ChildGuard,
    timeout: Duration,
) -> io::Result<UnixStream> {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Err(invalid(format!(
                "QEMU exited with {:?} before its QMP socket became ready",
                status.code()
            )));
        }
        match UnixStream::connect(path) {
            Ok(stream) => return Ok(stream),
            Err(error)
                if error.kind() == io::ErrorKind::ConnectionRefused
                    || error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(contextual(path, &error)),
        }
        if start.elapsed() >= timeout {
            return Err(invalid("QMP socket did not become ready before timeout"));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

struct Qmp {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
    log: File,
    deadline: Instant,
}

impl Qmp {
    fn new(stream: UnixStream, log_path: &Path, deadline: Instant) -> io::Result<Self> {
        let reader_stream = stream
            .try_clone()
            .map_err(|error| contextual(log_path, &error))?;
        Ok(Self {
            reader: BufReader::new(reader_stream),
            writer: stream,
            log: create_new(log_path)?,
            deadline,
        })
    }

    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "default guest QMP deadline expired",
                )
            })
    }

    fn read_message(&mut self) -> io::Result<String> {
        let mut bytes = Vec::new();
        loop {
            let timeout = self.remaining()?.min(Duration::from_secs(2));
            self.reader.get_ref().set_read_timeout(Some(timeout))?;
            let available = self.reader.fill_buf()?;
            if available.is_empty() {
                return Err(invalid("QMP closed before a complete message"));
            }
            let count = available
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(available.len(), |index| index + 1);
            if bytes.len() + count > 1024 * 1024 {
                return Err(invalid("QMP message exceeded 1 MiB"));
            }
            let complete = available[count - 1] == b'\n';
            bytes.extend_from_slice(&available[..count]);
            self.reader.consume(count);
            if complete {
                self.log.write_all(&bytes)?;
                return String::from_utf8(bytes).map_err(|error| invalid(error.to_string()));
            }
        }
    }

    fn write_request(&mut self, request: &Value) -> io::Result<()> {
        let line = format!("{request}\n");
        self.writer
            .set_write_timeout(Some(self.remaining()?.min(Duration::from_secs(2))))?;
        self.log.write_all(b"> ")?;
        self.log.write_all(line.as_bytes())?;
        self.writer.write_all(line.as_bytes())?;
        self.writer.flush()
    }

    fn greeting(&mut self) -> io::Result<String> {
        let line = self.read_message()?;
        let greeting = serde_json::from_str::<Value>(&line).ok();
        if !greeting.is_some_and(|message| message.get("QMP").is_some_and(Value::is_object)) {
            return Err(invalid("QEMU did not send a valid QMP greeting"));
        }
        Ok(line)
    }

    fn execute(&mut self, command: &str) -> io::Result<Reply> {
        self.write_request(&json!({ "execute": command }))?;
        self.response()
    }

    fn human_monitor(&mut self, command_line: &str) -> io::Result<Reply> {
        self.write_request(&json!({
            "execute": "human-monitor-command",
            "arguments": { "command-line": command_line },
        }))?;
        self.response()
    }

    fn screendump(&mut self, filename: &str, format: &str) -> io::Result<Reply> {
        self.write_request(&json!({
            "execute": "screendump",
            "arguments": { "filename": filename, "format": format },
        }))?;
        self.response()
    }

    fn quit(&mut self) -> io::Result<()> {
        self.write_request(&json!({ "execute": "quit" }))?;
        self.log.flush()
    }

    /// The next command reply; asynchronous events and other unsolicited messages are skipped.
    fn response(&mut self) -> io::Result<Reply> {
        loop {
            let raw = self.read_message()?;
            let mut message = serde_json::from_str::<Value>(&raw)
                .map_err(|error| invalid(format!("QMP sent invalid JSON: {error}")))?;
            if let Some(error) = message.get("error") {
                return Err(invalid(format!("QMP command failed: {error}")));
            }
            if let Some(ret) = message.get_mut("return") {
                return Ok(Reply {
                    ret: ret.take(),
                    raw,
                });
            }
        }
    }
}

/// A QMP `return`: the parsed payload and the exact line kept as evidence.
struct Reply {
    raw: String,
    ret: Value,
}

fn parse_hmp_register_state(response: &str) -> Option<(u64, u8, u64)> {
    let registers = ["RFL=", "EFL="].into_iter().find_map(|marker| {
        let value = response.split_once(marker)?.1;
        let digits = value.bytes().take_while(u8::is_ascii_hexdigit).count();
        (digits > 0)
            .then(|| u64::from_str_radix(&value[..digits], 16).ok())
            .flatten()
    })?;
    let hlt_value = response.split_once("HLT=")?.1;
    let hlt_digits = hlt_value.bytes().take_while(u8::is_ascii_digit).count();
    let hlt = (hlt_digits > 0)
        .then(|| hlt_value[..hlt_digits].parse::<u8>().ok())
        .flatten()?;
    let rip_value = response
        .split_once("RIP=")
        .or_else(|| response.split_once("EIP="))?
        .1;
    let rip_digits = rip_value.bytes().take_while(u8::is_ascii_hexdigit).count();
    let rip = (rip_digits > 0)
        .then(|| u64::from_str_radix(&rip_value[..rip_digits], 16).ok())
        .flatten()?;
    Some((registers, hlt, rip))
}

fn terminal_kernel_halt(response: &str, executable_segments: &[(u64, u64)]) -> Option<(u64, u64)> {
    let (flags, hlt, rip) = parse_hmp_register_state(response)?;
    let kernel_rip = executable_segments
        .iter()
        .any(|(start, end)| *start <= rip && rip < *end);
    (hlt == 1 && flags & (1 << 9) == 0 && kernel_rip).then_some((flags, rip))
}

#[cfg(test)]
mod monitor_tests {
    use super::*;

    #[test]
    fn terminal_halt_requires_kernel_rip_hlt_and_interrupts_disabled() {
        let segments = [(0xffff_ffff_8000_0000, 0xffff_ffff_8000_1000)];
        let kernel_state = "RIP=ffffffff80000020 EFL=00000002 HLT=1";
        assert_eq!(
            terminal_kernel_halt(kernel_state, &segments),
            Some((2, 0xffff_ffff_8000_0020))
        );
        assert_eq!(
            terminal_kernel_halt("RIP=ffffffff80000020 EFL=00000202 HLT=1", &segments),
            None
        );
        assert_eq!(
            terminal_kernel_halt("RIP=ffffffff80000020 EFL=00000002 HLT=0", &segments),
            None
        );
        assert_eq!(
            terminal_kernel_halt("RIP=000000000000fff0 EFL=00000002 HLT=1", &segments),
            None
        );
        assert_eq!(terminal_kernel_halt("No CPU available", &segments), None);
    }
}

fn valid_image(path: &Path) -> io::Result<Option<&'static str>> {
    let mut file = File::open(path).map_err(|error| contextual(path, &error))?;
    let mut header = [0_u8; 8];
    let read = file
        .read(&mut header)
        .map_err(|error| contextual(path, &error))?;
    if read >= 8 && header == [137, 80, 78, 71, 13, 10, 26, 10] {
        return Ok(Some("png"));
    }
    if read >= 2 && &header[..2] == b"P6" {
        return Ok(Some("ppm"));
    }
    Ok(None)
}

/// Private directory holding only the QMP socket. `sun_path` is ~108 bytes, so the
/// socket cannot live in a deep run directory; the path is recorded in the case's
/// `qemu_arguments`. Removed on drop.
struct QmpDir(PathBuf);

impl QmpDir {
    fn create(output: &Path) -> io::Result<Self> {
        let base = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        let name = output
            .file_name()
            .ok_or_else(|| invalid("output directory has no name"))?;
        let path = base.join(format!(
            "linux-rs-qmp-{}-{}",
            std::process::id(),
            name.to_string_lossy()
        ));
        let socket = display_path(&path.join("qmp.sock"))?;
        // QEMU option syntax splits on commas; `sun_path` holds 107 bytes plus NUL.
        if socket.contains(',') || socket.len() >= 100 {
            return Err(invalid(format!("unusable QMP socket path {socket}")));
        }
        DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|error| contextual(&path, &error))?;
        Ok(Self(path))
    }

    fn socket(&self) -> PathBuf {
        self.0.join("qmp.sock")
    }
}

impl Drop for QmpDir {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.socket());
        let _ = fs::remove_dir(&self.0);
    }
}

fn default_qemu_args(root: &Path, socket: &Path, image: &BootImage) -> io::Result<Vec<OsString>> {
    let socket_text = display_path(socket)?;
    let image_relative = display_path(&relative_path(root, &image.disk)?)?;
    let vars_relative = display_path(&relative_path(root, &image.vars_copy)?)?;
    let args = vec![
        OsString::from("-machine"),
        OsString::from("q35,accel=tcg"),
        OsString::from("-cpu"),
        OsString::from("qemu64"),
        OsString::from("-m"),
        OsString::from("512M"),
        OsString::from("-smp"),
        OsString::from("1"),
        OsString::from("-display"),
        OsString::from("none"),
        OsString::from("-monitor"),
        OsString::from("none"),
        OsString::from("-serial"),
        OsString::from("none"),
        OsString::from("-no-reboot"),
        OsString::from("-nic"),
        OsString::from("none"),
        OsString::from("-drive"),
        OsString::from(format!(
            "if=pflash,unit=0,format=raw,readonly=on,file={OVMF_CODE}"
        )),
        OsString::from("-drive"),
        OsString::from(format!("if=pflash,unit=1,format=raw,file={vars_relative}")),
        OsString::from("-drive"),
        OsString::from(format!(
            "if=none,id=boot,format=raw,readonly=on,file={image_relative}"
        )),
        OsString::from("-device"),
        OsString::from("virtio-blk-pci,drive=boot"),
        OsString::from("-boot"),
        OsString::from("order=c"),
        OsString::from("-qmp"),
        OsString::from(format!("unix:{socket_text},server=on,wait=off")),
    ];
    Ok(args)
}

fn observe_default_halt(
    qmp: &mut Qmp,
    child: &mut ChildGuard,
    build: &Build,
    case_dir: &Path,
    start: Instant,
    timeout: Duration,
) -> io::Result<(String, String)> {
    let _greeting = qmp.greeting()?;
    let _capabilities = qmp.execute("qmp_capabilities")?;
    let cpu_list = qmp.execute("query-cpus-fast")?;
    let has_cpu = cpu_list.ret.as_array().is_some_and(|cpus| {
        cpus.iter()
            .any(|cpu| cpu.get("cpu-index").is_some_and(Value::is_u64))
    });
    if !has_cpu {
        return Err(invalid(
            "QMP reported no x86_64 CPU for default framebuffer capture",
        ));
    }
    write_new(&case_dir.join("qmp-cpus.jsonl"), cpu_list.raw.as_bytes())?;
    let (register_response, flags, rip) = loop {
        let response = qmp.human_monitor("info registers")?;
        let registers = response.ret.as_str().unwrap_or_default();
        if let Some((flags, rip)) = terminal_kernel_halt(registers, &build.executable_segments) {
            break (response, flags, rip);
        }
        if let Some(status) = child.try_wait()? {
            return Err(invalid(format!(
                "default kernel QEMU exited with {:?} before terminal kernel HLT state; no screenshot pass",
                status.code()
            )));
        }
        if start.elapsed() >= timeout {
            return Err(invalid(format!(
                "default kernel did not reach HLT=1, IF=0 with RIP in an executable kernel segment within {} seconds; timeout is not a pass",
                timeout.as_secs()
            )));
        }
        thread::sleep(Duration::from_millis(50));
    };
    let status_response = qmp.execute("query-status")?;
    write_new(
        &case_dir.join("qmp-registers.jsonl"),
        register_response.raw.as_bytes(),
    )?;
    write_new(
        &case_dir.join("qmp-status.jsonl"),
        status_response.raw.as_bytes(),
    )?;
    let cpu_state = format!("HLT=1 IF=0 EFLAGS=0x{flags:x} RIP=0x{rip:016x} in executable PT_LOAD");
    Ok((cpu_state, status_response.raw))
}

fn capture_screen(
    root: &Path,
    case_dir: &Path,
    qmp: &mut Qmp,
) -> io::Result<(PathBuf, &'static str)> {
    let png = case_dir.join("framebuffer.png");
    let png_relative = display_path(&relative_path(root, &png)?)?;
    let png_command = qmp.screendump(&png_relative, "png");
    let png_ok = png_command.is_ok() && valid_image(&png).ok().flatten() == Some("png");
    if png_ok {
        Ok((png, "png"))
    } else {
        let ppm = case_dir.join("framebuffer.ppm");
        let ppm_relative = display_path(&relative_path(root, &ppm)?)?;
        qmp.screendump(&ppm_relative, "ppm")?;
        if valid_image(&ppm)? != Some("ppm") {
            return Err(invalid(
                "QMP screendump did not produce a valid PNG or PPM image",
            ));
        }
        Ok((ppm, "ppm"))
    }
}

struct DefaultCapture {
    screenshot: PathBuf,
    screenshot_format: &'static str,
    screenshot_hash: String,
    cpu_state: String,
    status_response: String,
    cleanup_result: String,
}

fn write_default_result(
    root: &Path,
    case_dir: &Path,
    build: &Build,
    tools: &QemuTools,
    boot_image: BootImage,
    args: &[String],
    capture: DefaultCapture,
) -> io::Result<(PathBuf, String, String)> {
    let DefaultCapture {
        screenshot,
        screenshot_format,
        screenshot_hash,
        cpu_state,
        status_response,
        cleanup_result,
    } = capture;
    let mut manifest = BTreeMap::new();
    manifest_value(&mut manifest, "schema", "1");
    manifest_value(
        &mut manifest,
        "kind",
        "default-freestanding-framebuffer-capture",
    );
    manifest_value(
        &mut manifest,
        "kernel_feature_set",
        "freestanding; no qemu-self-test",
    );
    manifest_value(
        &mut manifest,
        "kernel_elf",
        display_path(&build.elf_relative)?,
    );
    manifest_value(
        &mut manifest,
        "state",
        "HMP reports HLT=1, IF=0 and RIP inside executable PT_LOAD; visual review pending",
    );
    manifest_value(&mut manifest, "qmp_cpu_state", cpu_state.clone());
    manifest_value(&mut manifest, "qmp_status", single_line(&status_response));
    manifest_value(
        &mut manifest,
        "screenshot",
        display_path(&relative_path(root, &screenshot)?)?,
    );
    manifest_value(&mut manifest, "screenshot_format", screenshot_format);
    manifest_value(&mut manifest, "screenshot_sha256", screenshot_hash);
    manifest_value(
        &mut manifest,
        "visual_assertion",
        "not automated; director must inspect framebuffer capture",
    );
    manifest_value(
        &mut manifest,
        "qemu_exit_policy",
        "default kernel intentionally halts; no debug-exit code required",
    );
    manifest_value(&mut manifest, "qemu_cleanup", cleanup_result);
    manifest_value(
        &mut manifest,
        "qemu_version",
        single_line(&tools.qemu.version),
    );
    record_setpriv(root, &tools.sha256sum.path, &mut manifest)?;
    manifest_value(&mut manifest, "qemu_path", display_path(&tools.qemu.path)?);
    manifest_value(&mut manifest, "qemu_arguments", args.join(" | "));
    manifest_value(
        &mut manifest,
        "sha256_qemu",
        file_hash(root, &tools.sha256sum.path, &tools.qemu.path)?,
    );
    manifest_value(&mut manifest, "sha256_kernel_elf", build.elf_hash.clone());
    manifest_value(
        &mut manifest,
        "sha256_kernel_elf_after_run",
        file_hash(root, &tools.sha256sum.path, &build.elf)?,
    );
    let vars_final = file_hash(root, &tools.sha256sum.path, &boot_image.vars_copy)?;
    let disk_final = file_hash(root, &tools.sha256sum.path, &boot_image.disk)?;
    let disk_unchanged = disk_final == boot_image.disk_sha256_initial;
    record_image_result(
        root,
        &tools.sha256sum.path,
        &mut manifest,
        boot_image,
        vars_final,
        disk_final,
    )?;
    manifest_value(
        &mut manifest,
        "sha256_limine_efi",
        file_hash(root, &tools.sha256sum.path, Path::new(LIMINE_EFI))?,
    );
    write_manifest(&case_dir.join("result.tsv"), manifest)?;
    if !disk_unchanged {
        return Err(invalid("default-boot disk image changed during QEMU run"));
    }
    Ok((screenshot, screenshot_format.to_owned(), cpu_state))
}

fn capture_default_framebuffer(
    root: &Path,
    output: &Path,
    build: &Build,
    tools: &QemuTools,
    timeout: Duration,
) -> io::Result<(PathBuf, String, String)> {
    let case_dir = output.join("default-boot");
    create_directory(&case_dir)?;
    let boot_image = make_fat_image(
        root,
        &case_dir,
        build,
        DebugCase {
            name: "default",
            cmdline: None,
            cpu: "qemu64",
            expected_exit: 0,
            required: &[],
            forbid_success: false,
            modules: ARCHIVE_ONLY,
            user: User::None,
            framebuffers: 1,
            plat: Q35_TCG,
        },
        tools,
    )?;
    let elf_before = file_hash(root, &tools.sha256sum.path, &build.elf)?;
    if elf_before != build.elf_hash {
        return Err(invalid(
            "default kernel ELF snapshot changed before QEMU launch",
        ));
    }
    let qmp_dir = QmpDir::create(output)?;
    let socket = qmp_dir.socket();
    let args = default_qemu_args(root, &socket, &boot_image)?;
    let qemu_stdout = case_dir.join("qemu.stdout.log");
    let qemu_stderr = case_dir.join("qemu.stderr.log");
    let mut command = supervised(&tools.qemu.path);
    command.args(&args).current_dir(root).stdin(Stdio::null());
    command.stdout(Stdio::from(create_new(&qemu_stdout)?));
    command.stderr(Stdio::from(create_new(&qemu_stderr)?));
    let start = Instant::now();
    let mut child = create_process(&mut command)?;
    let stream = wait_qmp_socket(&socket, &mut child, timeout)?;
    let qmp_log = case_dir.join("qmp.log");
    let mut qmp = Qmp::new(stream, &qmp_log, start + timeout)?;
    let (cpu_state, status_response) =
        observe_default_halt(&mut qmp, &mut child, build, &case_dir, start, timeout)?;
    let (screenshot, screenshot_format) = capture_screen(root, &case_dir, &mut qmp)?;
    let screenshot_hash = file_hash(root, &tools.sha256sum.path, &screenshot)?;
    qmp.quit()?;
    let cleanup = wait_for_exit(child, Duration::from_secs(3))?;
    let cleanup_result = if cleanup.timed_out {
        "killed-and-reaped-after-screenshot".to_owned()
    } else {
        format!("qmp-quit-exit-{:?}", cleanup.exit_code)
    };
    let args_text = command_args(&args)?;
    let capture = DefaultCapture {
        screenshot,
        screenshot_format,
        screenshot_hash,
        cpu_state,
        status_response,
        cleanup_result,
    };
    let result = write_default_result(
        root, &case_dir, build, tools, boot_image, &args_text, capture,
    )?;
    require_exit(&tools.qemu.path, &cleanup, 0, Duration::from_secs(3))?;
    if file_hash(root, &tools.sha256sum.path, &build.elf)? != build.elf_hash {
        return Err(invalid(
            "default kernel ELF snapshot changed during QEMU capture",
        ));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_SCRATCH: AtomicU64 = AtomicU64::new(0);

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> io::Result<Self> {
            let id = NEXT_SCRATCH.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("linux-rs-xtask-{}-{id}", std::process::id()));
            fs::DirBuilder::new().mode(0o700).create(&path)?;
            Ok(Self(path))
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn process_fixture() -> io::Result<()> {
        let Some(mode) = std::env::var_os("LINUX_RS_PROCESS_FIXTURE") else {
            return Ok(());
        };
        if mode == "leaf" {
            thread::sleep(Duration::from_secs(60));
        } else if mode == "flood" {
            let block = [b'x'; 8192];
            let stdout = io::stdout();
            let mut stdout = stdout.lock();
            for _ in 0..=(CAPTURE_LIMIT / block.len()) {
                stdout.write_all(&block)?;
            }
        } else {
            let mut descendant = Command::new(std::env::current_exe()?)
                .args(["--exact", "kernel::tests::process_fixture", "--nocapture"])
                .env("LINUX_RS_PROCESS_FIXTURE", "leaf")
                .spawn()?;
            let path = std::env::var_os("LINUX_RS_PROCESS_IDS")
                .ok_or_else(|| invalid("test fixture has no PID output path"))?;
            let write = fs::write(path, format!("{} {}", std::process::id(), descendant.id()));
            if write.is_err() {
                descendant.kill()?;
            }
            descendant.wait()?;
            write?;
        }
        Ok(())
    }

    #[test]
    fn metadata_timeout_kills_descendants_and_reaps_direct_child() -> io::Result<()> {
        let scratch = Scratch::new()?;
        let ids = scratch.0.join("pids");
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args(["--exact", "kernel::tests::process_fixture", "--nocapture"])
            .env("LINUX_RS_PROCESS_FIXTURE", "parent")
            .env("LINUX_RS_PROCESS_IDS", &ids);
        let start = Instant::now();
        let error = capture_command(&mut command, Duration::from_secs(1)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(5));
        let text = fs::read_to_string(ids)?;
        let pids = text.split_ascii_whitespace().collect::<Vec<_>>();
        assert_eq!(pids.len(), 2);
        assert!(
            !Path::new("/proc").join(pids[0]).exists(),
            "direct child was not reaped"
        );
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let process_state = fs::read_to_string(format!("/proc/{}/stat", pids[1]));
            let live = process_state.is_ok_and(|text| {
                text.rsplit_once(") ")
                    .is_some_and(|(_, state)| !state.starts_with(['Z', 'X']))
            });
            if !live {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "descendant survived group timeout"
            );
            thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }

    #[test]
    fn child_dies_when_spawning_thread_exits() -> io::Result<()> {
        let exe = fs::canonicalize(std::env::current_exe()?)?;
        let pid = thread::spawn(move || -> io::Result<u32> {
            let mut command = supervised(&exe);
            command
                .args(["--exact", "kernel::tests::process_fixture"])
                .env("LINUX_RS_PROCESS_FIXTURE", "leaf")
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let child = create_process(&mut command)?;
            let pid = child.child.as_ref().map_or(0, Child::id);
            // setpriv must have exec'd (and so set the signal) before this thread exits.
            let start = Instant::now();
            while fs::read_link(format!("/proc/{pid}/exe"))? != exe {
                assert!(
                    start.elapsed() < Duration::from_secs(5),
                    "setpriv never exec'd"
                );
                thread::sleep(Duration::from_millis(5));
            }
            // Skip the guard's cleanup: only the death signal may end the child.
            std::mem::forget(child);
            Ok(pid)
        })
        .join()
        .map_err(|_| invalid("spawn thread panicked"))??;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let live = fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|text| {
                text.rsplit_once(") ")
                    .is_some_and(|(_, state)| !state.starts_with(['Z', 'X']))
            });
            if !live {
                return Ok(());
            }
            assert!(
                Instant::now() < deadline,
                "child outlived its spawning thread"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn remap_flags_reject_separator_and_control_bytes_in_paths() {
        let rustc = |path: &str| Tool {
            path: PathBuf::from(path),
            version: String::new(),
        };
        let kernel = Target::Kernel {
            qemu_self_test: false,
        };
        let flags = remap_flags(
            Path::new("/work/root"),
            Path::new("/work/root/out"),
            &rustc("/tc/bin/rustc"),
            kernel,
        )
        .unwrap();
        // Three path remaps, then the fallible-allocation-only switch.
        assert_eq!(flags.split('\x1f').count(), 4);
        assert!(flags.starts_with("--remap-path-prefix=/work/root=/src\x1f"));
        assert!(flags.ends_with("\x1f--cfg=no_global_oom_handling"));
        // The init has no `alloc` and keeps its flags (and bytes) unchanged.
        let init = remap_flags(
            Path::new("/work/root"),
            Path::new("/work/root/out"),
            &rustc("/tc/bin/rustc"),
            Target::Init,
        )
        .unwrap();
        assert_eq!(init.split('\x1f').count(), 3);
        assert!(!init.contains("oom"));
        assert_eq!(
            kernel.build_std(),
            "-Zbuild-std=core,alloc,compiler_builtins"
        );
        assert_eq!(
            Target::Init.build_std(),
            "-Zbuild-std=core,compiler_builtins"
        );
        for bad in ["/w/a\x1fb", "/w/a\nb", "/w/a\x7fb"] {
            let (root, output) = (Path::new(bad), Path::new("/w/out"));
            assert!(remap_flags(root, output, &rustc("/tc/bin/rustc"), kernel).is_err());
            assert!(
                remap_flags(
                    Path::new("/w"),
                    output,
                    &rustc(&format!("{bad}/bin/rustc")),
                    kernel
                )
                .is_err()
            );
        }
    }

    #[test]
    fn qmp_messages_are_classified_by_structure_and_requests_are_escaped() -> io::Result<()> {
        let scratch = Scratch::new()?;
        let (client, mut server) = UnixStream::pair()?;
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut qmp = Qmp::new(client, &scratch.0.join("qmp.log"), deadline)?;
        // An event whose text mentions "return" and "error" is not a reply (substring matching took it).
        server.write_all(b"{\"QMP\":{\"version\":{}}}\n")?;
        qmp.greeting()?;
        server.write_all(
            b"{\"event\":\"STOP\",\"data\":{\"note\":\"return error\"}}\n{\"return\":{\"x\":1}}\n",
        )?;
        assert_eq!(qmp.response()?.ret["x"], 1);
        server.write_all(b"{\"error\":{\"class\":\"GenericError\",\"desc\":\"no\"}}\n")?;
        assert!(qmp.response().is_err());
        server.write_all(b"not json\n")?;
        assert!(qmp.response().is_err());
        server.write_all(b"{\"return\":{}}\n")?;
        qmp.human_monitor("quote\" backslash\\ newline\n")?;
        let mut line = String::new();
        BufReader::new(&server).read_line(&mut line)?;
        let request = serde_json::from_str::<Value>(&line).map_err(io::Error::other)?;
        assert_eq!(
            request["arguments"]["command-line"],
            "quote\" backslash\\ newline\n"
        );
        server.write_all(b"{\"id\":1}\n")?;
        assert!(qmp.greeting().is_err());
        Ok(())
    }

    #[test]
    fn serial_log_is_bounded_and_utf8() -> io::Result<()> {
        let scratch = Scratch::new()?;
        let path = scratch.0.join("serial.log");
        fs::write(&path, "ok\n")?;
        assert_eq!(read_serial_log(&path)?, "ok\n");
        fs::write(&path, [0xff])?;
        assert!(read_serial_log(&path).is_err());
        fs::write(
            &path,
            vec![b'x'; usize::try_from(SERIAL_LOG_LIMIT).unwrap() + 1],
        )?;
        assert!(read_serial_log(&path).is_err());
        Ok(())
    }

    #[test]
    fn invalid_manifest_leaves_no_partial_file() -> io::Result<()> {
        let scratch = Scratch::new()?;
        let path = scratch.0.join("result.tsv");
        let mut values = BTreeMap::new();
        manifest_value(&mut values, "key", "bad\tvalue");
        assert!(write_manifest(&path, values).is_err());
        assert!(!path.exists());
        // Failure manifests build their error text with single_line, so they stay writable.
        let mut failure = BTreeMap::new();
        manifest_value(&mut failure, "error", single_line("a\tb\x1b[0m\nc"));
        write_manifest(&path, failure)?;
        assert!(fs::read_to_string(&path)?.ends_with("error\ta b [0m; c\n"));
        Ok(())
    }

    #[test]
    fn metadata_capture_rejects_oversized_output() -> io::Result<()> {
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args(["--exact", "kernel::tests::process_fixture", "--nocapture"])
            .env("LINUX_RS_PROCESS_FIXTURE", "flood");
        let error = capture_command(&mut command, Duration::from_secs(5)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("capture limit"));
        Ok(())
    }

    #[test]
    fn output_policy_rejects_symlink_ancestors_traversal_and_reuse() -> io::Result<()> {
        let scratch = Scratch::new()?;
        let root = scratch.0.join("project");
        fs::create_dir(&root)?;
        let run = prepare_output(&root, Path::new("target/kernel-tooling/fresh"))?;
        assert_eq!(fs::metadata(&run.path)?.permissions().mode() & 0o077, 0);
        assert!(prepare_output(&root, Path::new("target/kernel-tooling/fresh")).is_err());
        assert!(prepare_output(&root, Path::new("target/kernel-tooling/../escape")).is_err());
        let alias = scratch.0.join("alias");
        std::os::unix::fs::symlink(&root, &alias)?;
        assert!(
            prepare_output(&alias.join("."), Path::new("target/kernel-tooling/other")).is_err()
        );
        Ok(())
    }

    #[test]
    fn build_tool_identity_matches_inventory_through_symlink() -> io::Result<()> {
        let scratch = Scratch::new()?;
        let binary = fs::canonicalize(std::env::current_exe()?)?;
        let alias = scratch.0.join("tool-alias");
        std::os::unix::fs::symlink(&binary, &alias)?;
        let sha = resolve_program(Path::new("sha256sum"))?;
        let tool = Tool {
            path: alias.clone(),
            version: "Rust test executable".to_owned(),
        };
        let mut manifest = BTreeMap::new();
        record_build_tool(&scratch.0, &sha, &mut manifest, "readelf", &tool)?;
        let inventory = hash_files(&scratch.0, &sha, std::slice::from_ref(&binary))?;
        let identity = Path::new(&manifest["readelf_path"]);
        assert_eq!(identity, binary);
        assert_eq!(manifest["sha256_readelf"], inventory[identity]);
        assert_eq!(manifest["readelf_invocation_path"], display_path(&alias)?);
        Ok(())
    }

    #[test]
    fn source_binding_detects_bytes_additions_and_removals() -> io::Result<()> {
        let scratch = Scratch::new()?;
        for directory in SOURCE_MEMBERS {
            fs::create_dir_all(scratch.0.join(directory))?;
        }
        for file in [
            "Cargo.toml",
            "Cargo.lock",
            "LICENSE",
            "kernel/main.rs",
            "xtask/package.rs",
            "rt/lib.rs",
            "user/init/main.rs",
        ] {
            fs::write(scratch.0.join(file), b"initial\n")?;
        }
        let sha = resolve_program(Path::new("sha256sum"))?;
        let snapshot = || hash_files(&scratch.0, &sha, &source_files(&scratch.0)?);
        let before = snapshot()?;
        require_unchanged(&before, &snapshot()?)?;
        fs::write(scratch.0.join("xtask/package.rs"), b"modified\n")?;
        assert!(require_unchanged(&before, &snapshot()?).is_err());
        fs::write(scratch.0.join("xtask/package.rs"), b"initial\n")?;
        fs::write(scratch.0.join("xtask/new-module.rs"), b"new\n")?;
        assert!(require_unchanged(&before, &snapshot()?).is_err());
        fs::remove_file(scratch.0.join("xtask/new-module.rs"))?;
        fs::remove_file(scratch.0.join("kernel/main.rs"))?;
        assert!(require_unchanged(&before, &snapshot()?).is_err());
        fs::write(scratch.0.join("kernel/main.rs"), b"initial\n")?;
        require_unchanged(&before, &snapshot()?)?;
        // The kernel links rt, and user/init is a workspace member: edits must be seen.
        for file in ["rt/lib.rs", "user/init/main.rs"] {
            fs::write(scratch.0.join(file), b"modified\n")?;
            assert!(require_unchanged(&before, &snapshot()?).is_err(), "{file}");
            fs::write(scratch.0.join(file), b"initial\n")?;
        }
        Ok(())
    }

    #[test]
    fn source_members_cover_every_workspace_member() -> io::Result<()> {
        let manifest =
            fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../Cargo.toml"))?;
        let members = manifest
            .lines()
            .find_map(|line| line.strip_prefix("members = ["))
            .and_then(|rest| rest.strip_suffix(']'))
            .ok_or_else(|| invalid("workspace members line not found"))?;
        let mut declared = members
            .split(',')
            .map(|member| member.trim().trim_matches('"'))
            .collect::<Vec<_>>();
        declared.sort_unstable();
        let mut bound = SOURCE_MEMBERS.to_vec();
        bound.sort_unstable();
        assert_eq!(declared, bound);
        Ok(())
    }

    #[test]
    fn enclosing_checkout_config_is_accepted_only_when_identical() -> io::Result<()> {
        let scratch = Scratch::new()?;
        let outer = &scratch.0;
        let root = outer.join("target/worktrees/inner");
        fs::create_dir_all(root.join(".cargo"))?;
        fs::create_dir_all(outer.join(".cargo"))?;
        fs::write(root.join(".cargo/config.toml"), PROJECT_CARGO_CONFIG)?;
        fs::write(outer.join(".cargo/config.toml"), PROJECT_CARGO_CONFIG)?;
        reject_inherited_cargo_config(&root)?;
        fs::write(
            outer.join(".cargo/config.toml"),
            "[build]\nrustflags = []\n",
        )?;
        assert!(reject_inherited_cargo_config(&root).is_err());
        fs::remove_file(outer.join(".cargo/config.toml"))?;
        fs::write(outer.join(".cargo/config"), PROJECT_CARGO_CONFIG)?;
        assert!(reject_inherited_cargo_config(&root).is_err());
        Ok(())
    }

    #[test]
    fn checked_in_cargo_config_is_the_reviewed_constant() -> io::Result<()> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../.cargo/config.toml");
        assert_eq!(fs::read_to_string(path)?, PROJECT_CARGO_CONFIG);
        Ok(())
    }

    // `(name, version, full manifest, extra files)` for one vendored package.
    type FixturePackage<'a> = (&'a str, &'a str, String, &'a [&'a str]);

    fn manifest(name: &str, version: &str, tail: &str) -> String {
        format!("[package]\nname = \"{name}\"\nversion = \"{version}\"\nedition = \"2021\"\n{tail}")
    }

    // A project whose dependencies are all OPTIONAL (behind a feature, like the kernel's), each
    // vendored with a consistent `.cargo-checksum.json` (a coordinated edit).
    fn vendor_fixture(scratch: &Scratch, packages: &[FixturePackage<'_>]) -> io::Result<PathBuf> {
        let root = scratch.0.clone();
        let sha = resolve_program(Path::new("sha256sum"))?;
        fs::create_dir_all(root.join(".cargo"))?;
        fs::write(root.join(".cargo/config.toml"), PROJECT_CARGO_CONFIG)?;
        let checksum = "ab".repeat(32);
        let (mut dependencies, mut names, mut lock) = (String::new(), Vec::new(), String::new());
        for (name, version, manifest, extra) in packages {
            let package = root.join(format!("vendor/{name}-{version}"));
            fs::create_dir_all(package.join("src"))?;
            fs::write(package.join("src/lib.rs"), b"pub fn f() {}\n")?;
            fs::write(package.join("Cargo.toml"), manifest)?;
            let mut files = vec!["Cargo.toml", "src/lib.rs"];
            for file in *extra {
                fs::write(package.join(file), b"fn main() {}\n")?;
                files.push(file);
            }
            let paths = files
                .iter()
                .map(|file| package.join(file))
                .collect::<Vec<_>>();
            let hashes = hash_files(&root, &sha, &paths)?;
            let listed = files
                .iter()
                .zip(&paths)
                .map(|(file, path)| format!("\"{file}\":\"{}\"", hashes[path]))
                .collect::<Vec<_>>()
                .join(",");
            fs::write(
                package.join(".cargo-checksum.json"),
                format!("{{\"files\":{{{listed}}},\"package\":\"{checksum}\"}}"),
            )?;
            writeln!(
                dependencies,
                "{name} = {{ version = \"={version}\", optional = true }}"
            )
            .unwrap();
            names.push(format!("\"dep:{name}\""));
            writeln!(
                lock,
                "\n[[package]]\nname = \"{name}\"\nversion = \"{version}\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{checksum}\""
            )
            .unwrap();
        }
        fs::write(
            root.join("Cargo.toml"),
            format!(
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[lib]\npath = \"lib.rs\"\n\n[features]\nextra = [{}]\n\n[dependencies]\n{dependencies}",
                names.join(",")
            ),
        )?;
        fs::write(root.join("lib.rs"), b"")?;
        let deps = packages
            .iter()
            .map(|(name, ..)| format!("\"{name}\""))
            .collect::<Vec<_>>()
            .join(", ");
        fs::write(
            root.join("Cargo.lock"),
            format!(
                "version = 4\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [{deps}]\n{lock}"
            ),
        )?;
        Ok(root)
    }

    fn demo(tail: &str, extra: &'static [&'static str]) -> FixturePackage<'static> {
        ("demo", "1.0.0", manifest("demo", "1.0.0", tail), extra)
    }

    // A reviewed package carrying its reviewed script, as `cargo vendor` lays it out.
    fn const_fn(tail: &str, extra: &'static [&'static str]) -> FixturePackage<'static> {
        (
            "const_fn",
            "0.4.12",
            manifest("const_fn", "0.4.12", tail),
            extra,
        )
    }

    #[test]
    fn project_vendor_must_match_the_lock_exactly() -> io::Result<()> {
        let scratch = Scratch::new()?;
        let root = vendor_fixture(
            &scratch,
            &[
                demo("build = false\n", &[]),
                const_fn("build = \"build.rs\"\n", &["build.rs"]),
            ],
        )?;
        let sha = resolve_program(Path::new("sha256sum"))?;
        assert_eq!(verify_project_vendor(&root, &sha)?.len(), 2);

        let package = root.join("vendor/demo-1.0.0");
        let broken =
            |name: &str, change: &dyn Fn() -> io::Result<()>, undo: &dyn Fn() -> io::Result<()>| {
                change()?;
                let failed = verify_project_vendor(&root, &sha).is_err();
                undo()?;
                assert!(failed, "{name} must be rejected");
                io::Result::Ok(())
            };
        let lib = package.join("src/lib.rs");
        broken(
            "modified byte",
            &|| fs::write(&lib, b"pub fn g() {}\n"),
            &|| fs::write(&lib, b"pub fn f() {}\n"),
        )?;
        let extra = package.join("src/extra.rs");
        broken("unlisted file", &|| fs::write(&extra, b""), &|| {
            fs::remove_file(&extra)
        })?;
        let script = package.join("build.rs");
        broken("build.rs file", &|| fs::write(&script, b""), &|| {
            fs::remove_file(&script)
        })?;
        let stray = root.join("vendor/other-2.0.0");
        broken("unlocked package", &|| fs::create_dir(&stray), &|| {
            fs::remove_dir(&stray)
        })?;
        Ok(())
    }

    #[test]
    fn cargo_decides_which_optional_vendored_targets_are_unreviewed() -> io::Result<()> {
        let sha = resolve_program(Path::new("sha256sum"))?;
        let evil: &'static [&'static str] = &["evil.rs"];
        let dotted = "package.name = \"demo\"\npackage.version = \"1.0.0\"\npackage.edition = \"2021\"\npackage.build = \"evil.rs\"\n";
        // Every case is a coordinated edit of a manifest and its checksum JSON. Each must fail
        // even though the dependency is optional (visible only with --all-features).
        let cases: Vec<(&str, Vec<FixturePackage<'_>>, &str)> = vec![
            (
                "no spaces",
                vec![demo("build=\"evil.rs\"\n", evil)],
                "unreviewed build script",
            ),
            (
                "single quoted",
                vec![demo("build = 'evil.rs'\n", evil)],
                "unreviewed build script",
            ),
            (
                "source file",
                vec![demo("build = \"src/lib.rs\"\n", &[])],
                "unreviewed build script",
            ),
            (
                "dotted key",
                vec![("demo", "1.0.0", dotted.to_owned(), evil)],
                "unreviewed build script",
            ),
            (
                "borrowed reviewed script",
                vec![
                    demo("build = \"../const_fn-0.4.12/build.rs\"\n", &[]),
                    const_fn("build = \"build.rs\"\n", &["build.rs"]),
                ],
                "",
            ),
            (
                "renamed reviewed script",
                vec![const_fn("build = \"evil.rs\"\n", evil)],
                "unreviewed build script",
            ),
            (
                "proc-macro flip",
                vec![demo("build = false\n\n[lib]\nproc-macro = true\n", &[])],
                "unreviewed proc-macro",
            ),
        ];
        for (name, packages, message) in cases {
            let scratch = Scratch::new()?;
            let root = vendor_fixture(&scratch, &packages)?;
            let error = verify_project_vendor(&root, &sha).expect_err(name);
            assert!(error.to_string().contains(message), "{name}: {error}");
        }
        Ok(())
    }

    #[test]
    fn a_locked_package_missing_from_metadata_fails_closed() {
        let metadata = serde_json::json!({"packages": [{
            "name": "a", "version": "1.0.0", "source": "registry+x",
            "targets": [{"kind": ["lib"], "src_path": "/x/lib.rs"}]
        }]});
        let locked = |names: &[&str]| names.iter().map(|name| (*name).to_owned()).collect();
        assert!(check_vendored_targets(&metadata, Path::new("/v"), &locked(&["a-1.0.0"])).is_ok());
        let error =
            check_vendored_targets(&metadata, Path::new("/v"), &locked(&["a-1.0.0", "b-2.0.0"]));
        assert!(
            error
                .unwrap_err()
                .to_string()
                .contains("omitted locked package b-2.0.0")
        );
        assert!(
            check_vendored_targets(&serde_json::json!({}), Path::new("/v"), &locked(&[])).is_err()
        );
    }

    #[test]
    fn ambient_overrides_are_rejected_for_the_vendor_check_too() {
        let var = |key: &str, value: &str| (OsString::from(key), OsString::from(value));
        for key in [
            "RUSTC",
            "RUSTC_WRAPPER",
            "CARGO_BUILD_RUSTC",
            "CARGO_SOURCE_X",
        ] {
            assert!(reject_ambient_env([var(key, "x")]).is_err(), "{key}");
        }
        assert!(reject_ambient_env([var("RUSTC_WRAPPER", ""), var("CARGO_HOME", "/h")]).is_ok());
    }

    #[test]
    fn a_root_with_vendor_needs_its_own_reviewed_config() -> io::Result<()> {
        let scratch = Scratch::new()?;
        let outer = &scratch.0;
        fs::create_dir_all(outer.join(".cargo"))?;
        fs::write(outer.join(".cargo/config.toml"), PROJECT_CARGO_CONFIG)?;
        let root = outer.join("target/worktrees/inner");
        fs::create_dir_all(root.join("vendor"))?;
        assert!(reject_inherited_cargo_config(&root).is_err());
        fs::create_dir_all(root.join(".cargo"))?;
        fs::write(root.join(".cargo/config.toml"), PROJECT_CARGO_CONFIG)?;
        reject_inherited_cargo_config(&root)
    }

    #[test]
    fn runtime_archives_include_cargo_build_output_layout() -> io::Result<()> {
        let scratch = Scratch::new()?;
        let release = scratch.0.join(TARGET).join("release");
        let core = release.join("build/core/qualified-hash/out");
        let builtins = release.join("deps");
        fs::create_dir_all(&core)?;
        fs::create_dir_all(&builtins)?;
        fs::write(core.join("libcore-qualified.rlib"), b"archive fixture")?;
        fs::write(
            builtins.join("libcompiler_builtins-qualified.rlib"),
            b"archive fixture",
        )?;
        assert_eq!(compiler_runtime_artifacts(&scratch.0, false)?.len(), 2);
        // The kernel's build-std includes `alloc`; its absence is a failure,
        // and an unexpected one in the init build is too.
        assert!(compiler_runtime_artifacts(&scratch.0, true).is_err());
        fs::write(builtins.join("liballoc-qualified.rlib"), b"archive fixture")?;
        assert_eq!(compiler_runtime_artifacts(&scratch.0, true)?.len(), 3);
        assert!(compiler_runtime_artifacts(&scratch.0, false).is_err());
        std::os::unix::fs::symlink(&core, release.join("symlink"))?;
        assert!(compiler_runtime_artifacts(&scratch.0, true).is_err());
        Ok(())
    }

    #[test]
    fn vendor_metadata_rejects_duplicate_and_incomplete_objects() {
        let (package, files) = vendor_checksums(
            r#"{"$comment":"not authentication","files":{"src/lib.rs":"abc"},"package":"def"}"#,
        )
        .unwrap();
        assert_eq!(package, "def");
        assert_eq!(files.get("src/lib.rs").map(String::as_str), Some("abc"));
        for invalid in [
            r#"{"files":{},"package":"a","package":"b"}"#,
            r#"{"files":{"a":"b","a":"c"},"package":"d"}"#,
            r#"{"package":"a"}"#,
            r#"{"files":{},"package":null}"#,
            r#"{"files":{},"package":"a"} trailing"#,
        ] {
            assert!(vendor_checksums(invalid).is_err());
        }
    }

    #[test]
    fn executable_segments_reject_overflow_and_nonexecutables() {
        let headers = "LOAD 0x0000 0xffffffff80000000 0x0 0x1000 0x1000 R E 0x1000\nLOAD 0x1000 0xffffffff80001000 0x0 0x1000 0x2000 RW 0x1000";
        assert_eq!(
            parse_executable_segments(headers).unwrap(),
            vec![(0xffff_ffff_8000_0000, 0xffff_ffff_8000_1000)]
        );
        assert!(
            parse_executable_segments("LOAD 0x0 0xfffffffffffffff0 0x0 0x20 0x20 R E 0x1000")
                .is_err()
        );
        assert!(parse_executable_segments("LOAD 0x0 0x1000 0x0 0x10 0x10 RW 0x1000").is_err());
    }

    // What the kernel prints for a generated archive; `physical=` varies per module.
    const COUNTS: &str = "reserved=8192 bytes=4500 records=4 files=3 regular=1 symlinks=1 trailers=1 skipped=0 elf=1 loads=2 interpreters=0 execution=false rootfs=false";

    fn expected() -> fixture::Expected {
        fixture::Expected {
            archive_counts: COUNTS.to_owned(),
            init: fixture::ElfFacts {
                executable_segments: vec![(0x20_47b0, 0x20_c000)],
                executable_file_extents: vec![(0x20_47b0, 0x20_c000)],
                loads: 2,
                interpreters: 0,
                dynamics: 0,
                undefined_symbols: 0,
                entry: 0x20_4800,
                phnum: 6,
                phdr: 0x20_0040,
            },
        }
    }

    fn console_record(framebuffers: usize) -> String {
        format!(
            "CHECK console ok framebuffers={framebuffers} scrolled=true tail=true stale=false readback=true wrap=true"
        )
    }

    // Synthetic serials are written without the console record; add the one the
    // case expects unless the test supplied its own.
    fn validate(case: DebugCase, process: &ProcessResult, serial: &str) -> (bool, String) {
        let serial = if serial.contains("CHECK console") {
            serial.to_owned()
        } else {
            format!("{}\n{serial}", console_record(case.framebuffers))
        };
        validate_debug_case(case, process, &serial, &expected())
    }

    #[test]
    fn console_record_must_match_the_case_display_count() {
        let process = ProcessResult {
            timed_out: false,
            exit_code: Some(33),
        };
        let serial = success_serial();
        let success = case("success");
        assert_eq!(success.framebuffers, 2);
        assert!(validate(success, &process, &serial).0);
        // One framebuffer reported where two were attached, a failed check and a
        // missing record are all rejected.
        for bad in [
            console_record(1),
            console_record(2).replace("scrolled=true", "scrolled=false"),
            console_record(2).replace("readback=true", "readback=false"),
        ] {
            assert!(!validate(success, &process, &format!("{bad}\n{serial}")).0);
        }
        let (ok, why) = validate_debug_case(success, &process, &serial, &expected());
        assert!(!ok && why.contains("missing console record"), "{why}");
        // Exactly one record, before CHECKPOINT.
        let good = console_record(2);
        let twice = format!("{good}\n{good}\n{serial}");
        let (ok, why) = validate_debug_case(success, &process, &twice, &expected());
        assert!(!ok && why.contains("exactly one"), "{why}");
        let late = format!("{serial}\n{good}");
        let (ok, why) = validate_debug_case(success, &process, &late, &expected());
        assert!(!ok && why.contains("precede CHECKPOINT"), "{why}");
    }

    fn case(name: &str) -> DebugCase {
        *DEBUG_CASES.iter().find(|case| case.name == name).unwrap()
    }

    fn images(modules: &[Module]) -> String {
        modules
            .iter()
            .enumerate()
            .map(|(index, module)| {
                let physical = 0x2000_0000 + 0x1000_0000 * index;
                match module {
                    Module::Archive => format!("CHECK image inspected module={index} physical={physical:#x} {COUNTS}"),
                    Module::Empty => format!("CHECK image inspected module={index} physical={physical:#x} {EMPTY_MODULE_COUNTS}"),
                    Module::Corrupt => format!("WARN Initramfs unpacking failed: module={index} {CORRUPT_MODULE_WARNING}"),
                    Module::NoInit => unreachable!("only negative cases boot without /init"),
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn image_serial_requires_exact_counts_order_and_physical_ownership() {
        let serial = success_serial();
        let check = |text: &str, modules: &[Module]| {
            validate_image_serial(&text.lines().collect::<Vec<_>>(), modules, COUNTS)
        };
        assert!(check(&serial, &[Module::Archive]).is_ok());
        for (before, after) in [
            ("elf=1 ", "elf=0 "),
            ("loads=2", "loads=0"),
            ("execution=false", "execution=true"),
            ("physical=0x20000000", "physical=0x0"),
            ("physical=0x20000000", "physical=0x20000001"),
            ("payload_alias=absent", "payload_alias=present"),
            ("module=0 physical=", "module=1 physical="),
        ] {
            assert!(
                check(&serial.replace(before, after), &[Module::Archive]).is_err(),
                "{before}"
            );
        }
        let epoch = module_epoch_record(1);
        let late = format!("{}\n{epoch}", serial.replace(&epoch, ""));
        assert!(check(&late, &[Module::Archive]).is_err());
        // Two modules whose reservations (8192 bytes) overlap are rejected.
        let two = serial.replace(&epoch, &module_epoch_record(2)).replace(
            "CHECK memory ok",
            &format!(
                "{}\nCHECK memory ok",
                images(&[Module::Archive, Module::Empty])
                    .lines()
                    .nth(1)
                    .unwrap()
                    .replace("0x30000000", "0x20001000")
            ),
        );
        assert!(check(&two, &[Module::Archive, Module::Empty]).is_err());
    }

    #[test]
    fn empty_module_case_requires_zero_bytes_but_a_retained_page() {
        let modules = [Module::Archive, Module::Empty];
        let serial = success_serial_for(&modules);
        let process = ProcessResult {
            exit_code: Some(33),
            timed_out: false,
        };
        assert_eq!(case("empty-module").modules, modules);
        assert!(validate(case("empty-module"), &process, &serial).0);
        assert!(!validate(case("success"), &process, &serial).0);
        let bad = serial.replace("reserved=4096 bytes=0", "reserved=0 bytes=0");
        assert!(!validate(case("empty-module"), &process, &bad).0);
        let config = qemu_config(case("empty-module"));
        assert_eq!(config.matches("module_path:").count(), 2);
        assert!(config.contains("module_path: boot():/initramfs-empty.cpio"));
    }

    #[test]
    fn bad_module_case_requires_the_exact_skip_warning_and_no_inspection() {
        let modules = [Module::Corrupt, Module::Archive];
        let serial = success_serial_for(&modules);
        let process = ProcessResult {
            exit_code: Some(33),
            timed_out: false,
        };
        assert_eq!(case("bad-module").modules, modules);
        assert!(validate(case("bad-module"), &process, &serial).0);
        assert!(!validate(case("success"), &process, &serial).0);
        let warning = images(&modules[..1]);
        for bad in [
            serial.replace(&warning, ""),
            serial.replace("CompressionPending(Gzip)", "Magic"),
            serial.replace(&warning, &format!("{warning}\n{warning}")),
            serial.replace(
                &warning,
                &format!("{warning}\nCHECK image inspected module=0 physical=0x10000000 {COUNTS}"),
            ),
            serial.replace("module=1 physical", "module=0 physical"),
        ] {
            assert!(!validate(case("bad-module"), &process, &bad).0);
        }
        let config = qemu_config(case("bad-module"));
        assert!(
            config.find("initramfs-corrupt.cpio").unwrap()
                < config.find("module_string: initramfs.cpio").unwrap()
        );
    }

    fn exit(code: i32) -> ProcessResult {
        ProcessResult {
            exit_code: Some(code),
            timed_out: false,
        }
    }

    #[test]
    fn userspace_records_are_required_exactly_once_and_in_order() {
        let serial = success_serial();
        let ok = exit(33);
        assert!(validate(case("success"), &ok, &serial).0);
        let summary = fixture::init_summary(&expected().init, 1);
        for (what, bad) in [
            ("missing summary", serial.replace(&summary, "")),
            (
                "wrong AT_ENTRY",
                serial.replace("AT_ENTRY:0x204800", "AT_ENTRY:0x204801"),
            ),
            (
                "RSEQ auxv present",
                serial.replace("AT_PLATFORM:*", "AT_PLATFORM:*,AT_RSEQ_ALIGN:0x20"),
            ),
            ("wrong hwcap", serial.replace("0x78bfbfd", "0x178bfbff")),
            (
                "stack below the user range",
                serial.replace("sp=0x7fffffffee40 smep", "sp=0x1000 smep"),
            ),
            (
                "protection mismatch",
                serial.replace("smep=false smap=false", "smep=true smap=true"),
            ),
            (
                "no death panic",
                serial.replace(
                    "Kernel panic - not syncing: Attempted to kill init! exitcode=0x00000000",
                    "",
                ),
            ),
            (
                "wrong exit code",
                serial.replace("exitcode=0x00000000", "exitcode=0x00000100"),
            ),
            (
                "audit found user bits",
                serial.replace("kernel_user_bits=0", "kernel_user_bits=3"),
            ),
            ("no hello", serial.replace("init: hello from userspace", "")),
            ("no mm-usercopy", serial.replace(MM_USERCOPY_RECORD, "")),
            (
                "changed mm-usercopy",
                serial.replace("short_write=4", "short_write=0"),
            ),
            (
                "duplicate mm-usercopy",
                serial.replace(
                    MM_USERCOPY_RECORD,
                    &format!("{MM_USERCOPY_RECORD}\n{MM_USERCOPY_RECORD}"),
                ),
            ),
            (
                "Run line after the exec record",
                serial.replace("Run /init as init process\n", "").replace(
                    "init: hello from userspace",
                    "Run /init as init process\ninit: hello from userspace",
                ),
            ),
            (
                "no handled ring-3 fault record",
                serial.replace("CHECK user-faults ok handled=7\n", ""),
            ),
            (
                "unparsable handled ring-3 fault count",
                serial.replace("handled=7", "handled=many"),
            ),
            (
                "duplicate init: ok",
                serial.replace("init: ok", "init: ok\ninit: ok"),
            ),
        ] {
            assert!(!validate(case("success"), &ok, &bad).0, "{what}");
        }
    }

    #[test]
    fn userspace_modes_require_their_own_records() {
        let base = success_serial();
        // sse and rseq: argc=2 summary plus the mode line before `init: ok`.
        for (name, line) in [
            ("sse", "init: sse ok"),
            ("rseq", "init: rseq enosys"),
            ("demand", DEMAND_MODE_LINE),
        ] {
            let serial = base
                .replace("argc=1", "argc=2")
                .replace("\ninit: ok", &format!("\n{line}\ninit: ok"));
            assert!(validate(case(name), &exit(33), &serial).0, "{name}");
            assert!(
                !validate(case(name), &exit(33), &serial.replace(line, "")).0,
                "{name}"
            );
            assert!(
                !validate(case("success"), &exit(33), &serial).0,
                "argc=1 expected"
            );
        }
        // Only `demand` takes ring-3 faults: it needs a non-zero count, the others accept zero.
        let demand = base
            .replace("argc=1", "argc=2")
            .replace("\ninit: ok", &format!("\n{DEMAND_MODE_LINE}\ninit: ok"));
        let none = demand.replace("handled=7", "handled=0");
        assert!(!validate(case("demand"), &exit(33), &none).0);
        let quiet = base.replace("handled=7", "handled=0");
        assert!(validate(case("success"), &exit(33), &quiet).0);
        // cpu-max: protection must be reported on, the summary only by prefix.
        let max = base
            .replace("argc=1", "argc=2")
            .replace("AT_HWCAP:0x78bfbfd", "AT_HWCAP:0xfcbfbfd")
            .replace("smep=false smap=false", "smep=true smap=true")
            .replace("\ninit: ok", "\ninit: sse ok\ninit: ok");
        assert!(validate(case("cpu-max"), &exit(33), &max).0);
        assert!(
            !validate(
                case("cpu-max"),
                &exit(33),
                &max.replace("smap=true", "smap=false")
            )
            .0
        );
    }

    #[test]
    fn failing_init_cases_require_linux_text_and_no_success() {
        let prefix = success_serial()
            .split("\nRESULT success")
            .next()
            .unwrap()
            .replace("argc=1", "argc=2")
            .replace(
                "\ninit: ok\nCHECK user-faults ok handled=7\nKernel panic - not syncing: Attempted to kill init! exitcode=0x00000000",
                "",
            );
        let segfault = format!(
            "{prefix}\ninit: faulting on purpose\ninit[1]: segfault at 0 ip 0000000000205a27 sp 00007fffffffedd0 error 4 in init[4a27,204000+8000] likely on CPU 0 (core 0, socket 0)\nKernel panic - not syncing: Attempted to kill init! exitcode=0x0000000b\nFAIL init exitcode=0x0000000b"
        );
        // The segfault case boots with `-- fault`: argc=2 and no RESULT success.
        let serial = segfault.replace("\nRESULT success", "");
        assert!(validate(case("init-segfault"), &exit(35), &serial).0);
        assert!(
            !validate(
                case("init-segfault"),
                &exit(35),
                &serial.replace("error 4", "error 6")
            )
            .0
        );
        // The VMA bracket is bound to the ELF's executable segment.
        for wrong in [
            "init[4a27,204000+7000]",
            "init[4a27,203000+9000]",
            "init[4a27,204000+8000",
        ] {
            let bad = serial.replace("init[4a27,204000+8000]", wrong);
            assert!(
                !validate(case("init-segfault"), &exit(35), &bad).0,
                "{wrong}"
            );
        }
        let outside = serial.replace("ip 0000000000205a27", "ip 0000000000300000");
        assert!(!validate(case("init-segfault"), &exit(35), &outside).0);
        assert!(
            !validate(
                case("init-segfault"),
                &exit(35),
                &format!("{serial}\nRESULT success")
            )
            .0
        );
        assert!(
            !validate(
                case("init-segfault"),
                &exit(35),
                &serial.replace("exitcode=0x0000000b", "exitcode=0x00000004")
            )
            .0
        );

        let unimplemented =
            format!("{prefix}\ninit: calling io_uring_setup\nFAIL syscall unimplemented nr=425");
        assert!(validate(case("unimplemented-syscall"), &exit(35), &unimplemented).0);
        assert!(
            !validate(
                case("unimplemented-syscall"),
                &exit(35),
                &unimplemented.replace("nr=425", "nr=0")
            )
            .0
        );

        let no_root = "check access for rdinit=/init failed: -2, ignoring\n/dev/root: Can't open blockdev\nVFS: Cannot open root device \"\" or unknown-block(0,0): error -6\nPlease append a correct \"root=\" boot option; here are the available partitions:\nKernel panic - not syncing: VFS: Unable to mount root fs on unknown-block(0,0)\nFAIL no-root";
        assert!(validate(case("no-init"), &exit(35), no_root).0);
        assert!(
            !validate(
                case("no-init"),
                &exit(35),
                &no_root.replace("error -6", "error -2")
            )
            .0
        );
        assert!(
            !validate(
                case("no-init"),
                &exit(35),
                &format!("Run /init as init process\n{no_root}")
            )
            .0
        );
        assert!(
            !validate(
                case("no-init"),
                &exit(35),
                &no_root.replace("FAIL no-root", "No working init found")
            )
            .0
        );
        assert!(!validate(case("no-init"), &exit(33), no_root).0);
    }

    #[test]
    fn memory_provider_proof_rejects_incomplete_or_contradictory_records() {
        let serial = success_serial();
        let process = ProcessResult {
            exit_code: Some(33),
            timed_out: false,
        };
        for invalid in [
            String::new(),
            MEMORY_RUNTIME_RECORD.replace("memset_cases=272", "memset_cases=271"),
            MEMORY_RUNTIME_RECORD.replace("memcpy_cases=4224", "memcpy_cases=4223"),
            MEMORY_RUNTIME_RECORD.replace("zero_length=true", "zero_length=false"),
            MEMORY_RUNTIME_RECORD.replace("boundaries=true", "boundaries=false"),
            MEMORY_RUNTIME_RECORD.replace("padding_fields=true", "padding_fields=false"),
            MEMORY_RUNTIME_RECORD.replace("same_allocation=true", "same_allocation=false"),
            format!("{MEMORY_RUNTIME_RECORD} extra=true"),
            format!("{MEMORY_RUNTIME_RECORD}\n{MEMORY_RUNTIME_RECORD}"),
        ] {
            assert!(
                !validate(
                    DEBUG_CASES[0],
                    &process,
                    &serial.replace(MEMORY_RUNTIME_RECORD, &invalid),
                )
                .0,
                "{invalid}"
            );
        }
    }

    fn success_serial() -> String {
        success_serial_for(&[Module::Archive])
    }

    fn success_serial_for(modules: &[Module]) -> String {
        [
            MEMORY_RUNTIME_RECORD,
            "CHECK entry ok",
            "CHECK handoff ok acpi_tables=1 legacy_pic=1",
            "CHECK madt ok lapic=0xfee00000 cpus=1 ioapics=1",
            "CHECK time-tables hpet=0xfed00000 pm_timer=0x608",
            &images(modules),
            "CHECK memory ok",
            &module_epoch_record(modules.len()),
            "CHECK paging ok",
            "CHECK table-oom ok failure_points=1 accounting=restored",
            "CHECK exception ok gprs=15",
            PF_GPR_RECORD,
            "CHECK exhaustion ok",
            BUDDY_ORDER_RECORD,
            USER_MM_RECORD,
            HEAP_RECORD,
            "CHECK apic ok mode=xapic reason=default",
            "CHECK tsc ok khz=3000000 source=pit pit_tries=1 hpet_hz=100000000 rtc=true",
            "CHECK clockevent ok event=lapic-oneshot",
            "CHECK interrupt-controllers ok mode=xapic event=lapic-oneshot ioapic_timer=true",
            IRQ_GUARD_RECORD,
            "IRQ restore observation periods=2 irq_delta=2 lock_acquired=true",
            "CHECK timer ok periods=2 gprs=15 tick16_ns=15900000",
            "CHECK timekeeping ok slept_ns=20100000",
            "TIMER mask observation periods=2 irq_delta=0",
            "CHECKPOINT bootstrap-complete",
            "CHECK userspace-audit ok user_pages=49 user_tables=6 kernel_entries=6420 kernel_user_bits=0 above_task_size=0",
            "CHECK userspace-image ok entry=0x204800 sp=0x7fffffffee40 loads=2 brk=0x20d000 argc=1",
            "Run /init as init process",
            "CHECK userspace exec path=/init entry=0x204800 loads=2 sp=0x7fffffffee40 smep=false smap=false",
            MM_USERCOPY_RECORD,
            "init: hello from userspace",
            &fixture::init_summary(&expected().init, 1),
            "init: ok",
            "CHECK user-faults ok handled=7",
            "Kernel panic - not syncing: Attempted to kill init! exitcode=0x00000000",
            "RESULT success",
        ]
        .join("\n")
    }

    #[test]
    fn platform_records_must_match_the_case_machine() {
        let success = ProcessResult {
            exit_code: Some(33),
            timed_out: false,
        };
        let serial = success_serial();
        assert!(validate(DEBUG_CASES[0], &success, &serial).0);
        // A kernel that took a different path than the case declares must fail.
        for (from, to) in [
            (
                "mode=xapic event=lapic-oneshot",
                "mode=x2apic event=lapic-oneshot",
            ),
            (
                "event=lapic-oneshot ioapic_timer=true",
                "event=lapic-deadline ioapic_timer=true",
            ),
            ("ioapic_timer=true", "ioapic_timer=false"),
            ("source=pit", "source=pmtimer"),
            ("pit_tries=1", "pit_tries=0"),
            ("pit_tries=1", "pit_tries=4"),
            ("reason=default", "reason=hypervisor"),
            ("hpet_hz=100000000", "hpet_hz=0"),
            ("rtc=true", "rtc=false"),
            ("khz=3000000", "khz=1000"),
            ("hpet=0xfed00000", "hpet=0x0"),
            ("cpus=1 ioapics=1", "cpus=2 ioapics=1"),
            ("tick16_ns=15900000", "tick16_ns=2000"),
            ("tick16_ns=15900000", "tick16_ns=900000000"),
            ("slept_ns=20100000", "slept_ns=1000"),
            ("CHECK timekeeping ok slept_ns=20100000", ""),
            ("CHECK clockevent ok event=lapic-oneshot", ""),
            (
                "CHECK apic ok mode=xapic reason=default",
                "CHECK apic ok mode=x2apic reason=default",
            ),
        ] {
            assert!(
                !validate(DEBUG_CASES[0], &success, &serial.replace(from, to)).0,
                "{from} -> {to}"
            );
        }
    }

    #[test]
    fn each_platform_case_accepts_exactly_its_own_path() {
        let success = ProcessResult {
            exit_code: Some(33),
            timed_out: false,
        };
        let serial = success_serial();
        let case = |name| {
            DEBUG_CASES
                .iter()
                .copied()
                .find(|c| c.name == name)
                .unwrap()
        };
        let legacy = serial
            .replace(
                "mode=xapic event=lapic-oneshot ioapic_timer=true",
                "mode=legacy-pic event=pit-periodic ioapic_timer=n/a",
            )
            .replace(
                "CHECK apic ok mode=xapic reason=default",
                "CHECK apic ok mode=legacy-pic reason=nolapic",
            );
        assert!(validate(case("nolapic"), &success, &legacy).0);
        // nolapic and hpet-off require the quick-PIT source (one harness retry).
        assert!(
            !validate(
                case("nolapic"),
                &success,
                &legacy.replace("source=pit", "source=hpet")
            )
            .0
        );
        assert!(!validate(case("nolapic"), &success, &serial).0);
        let no_hpet = serial
            .replace("hpet_hz=100000000", "hpet_hz=0")
            .replace("hpet=0xfed00000", "hpet=0x0");
        assert!(validate(case("hpet-off"), &success, &no_hpet).0);
        assert!(
            !validate(
                case("hpet-off"),
                &success,
                &no_hpet.replace("source=pit", "source=pmtimer")
            )
            .0
        );
        assert!(!validate(case("hpet-off"), &success, &serial).0);
        let no_pit = serial
            .replace("ioapic_timer=true", "ioapic_timer=false")
            .replace("source=pit", "source=hpet");
        assert!(validate(case("pit-off"), &success, &no_pit).0);
        assert!(!validate(case("pit-off"), &success, &serial).0);
        // KVM accepts either PIT or HPET calibration but needs x2APIC + deadline.
        let kvm = serial
            .replace(
                "mode=xapic event=lapic-oneshot",
                "mode=x2apic event=lapic-deadline",
            )
            .replace(
                "CHECK apic ok mode=xapic reason=default",
                "CHECK apic ok mode=x2apic reason=hypervisor",
            )
            .replace("smep=false smap=false", "smep=true smap=true");
        assert!(validate(case("kvm"), &success, &kvm).0);
        assert!(
            validate(
                case("kvm"),
                &success,
                &kvm.replace("source=pit", "source=hpet")
            )
            .0
        );
        assert!(!validate(case("kvm"), &success, &serial).0);
        // x2apic-firmware must show the decision (mode xapic *because* the firmware
        // x2APIC was switched back), not just the same mode as the base case.
        let firmware = serial.replace("reason=default", "reason=no-interrupt-remapping");
        assert!(validate(case("x2apic-firmware"), &success, &firmware).0);
        assert!(!validate(case("x2apic-firmware"), &success, &serial).0);
        // x2apic-forced needs the x2APIC backend and the hypervisor rule.
        let forced = serial.replace(
            "mode=xapic event=lapic-oneshot",
            "mode=x2apic event=lapic-oneshot",
        );
        assert!(!validate(case("x2apic-forced"), &success, &forced).0);
        assert!(
            validate(
                case("x2apic-forced"),
                &success,
                &forced.replace(
                    "CHECK apic ok mode=xapic reason=default",
                    "CHECK apic ok mode=x2apic reason=hypervisor"
                )
            )
            .0
        );
    }

    #[test]
    fn debug_exit_cases_require_expected_codes_and_diagnostics() {
        let success = ProcessResult {
            exit_code: Some(33),
            timed_out: false,
        };
        let serial = success_serial();
        assert!(validate(DEBUG_CASES[0], &success, &serial).0);
        let wrong_exit = ProcessResult {
            exit_code: Some(0),
            timed_out: false,
        };
        assert!(!validate(DEBUG_CASES[0], &wrong_exit, &serial).0);
        assert!(
            !validate(
                DEBUG_CASES[0],
                &success,
                &serial.replace("failure_points=1", "failure_points=0")
            )
            .0
        );
        assert!(
            !validate(
                DEBUG_CASES[0],
                &success,
                &serial.replace("gprs=15", "gprs=14")
            )
            .0
        );
        let negative = ProcessResult {
            exit_code: Some(35),
            timed_out: false,
        };
        assert!(
            validate(
                DEBUG_CASES[1],
                &negative,
                "FAIL panic\ncontrolled panic case\n"
            )
            .0
        );
        assert!(!validate(DEBUG_CASES[1], &negative, "FAIL panic\n").0);
        assert!(
            !validate(
                DEBUG_CASES[1],
                &negative,
                "FAIL panic\ncontrolled panic case\nRESULT success\n"
            )
            .0
        );
        assert!(validate(DEBUG_CASES[2], &negative, "FAIL trap vector=6\n").0);
        assert!(
            validate(
                DEBUG_CASES[3],
                &negative,
                "EXPECTED failure bad-map rejected overflow\n"
            )
            .0
        );
        assert!(validate(DEBUG_CASES[4], &negative, "FAIL cpu error=Pat\n").0);
        assert!(validate(DEBUG_CASES[5], &negative, "FAIL trap vector=3\n").0);
        assert!(
            validate(
                DEBUG_CASES[6],
                &negative,
                "FAIL trap vector=unknown-external\n"
            )
            .0
        );
        assert!(
            validate(
                DEBUG_CASES[7],
                &negative,
                "TIMER mask observation periods=2 irq_delta=1\nFAIL assertion=timer-mask\n"
            )
            .0
        );
        assert!(
            !validate(
                DEBUG_CASES[7],
                &negative,
                "TIMER mask observation periods=2 irq_delta=0\nFAIL assertion=timer-mask\n"
            )
            .0
        );
    }

    #[test]
    fn buddy_proof_rejects_missing_changed_and_duplicate_records() {
        let success = ProcessResult {
            exit_code: Some(33),
            timed_out: false,
        };
        let serial = success_serial();
        for invalid in [
            String::new(),
            BUDDY_ORDER_RECORD.replace("max_order=10", "max_order=9"),
            BUDDY_ORDER_RECORD.replace("contiguous=true", "contiguous=false"),
            BUDDY_ORDER_RECORD.replace("zeroed=true", "zeroed=false"),
            BUDDY_ORDER_RECORD.replace("coalesced=true", "coalesced=false"),
            BUDDY_ORDER_RECORD.replace("split=true", "split=false"),
            BUDDY_ORDER_RECORD.replace("fragmented=true", "fragmented=false"),
            BUDDY_ORDER_RECORD.replace("aligned=131072", "aligned=65536"),
            BUDDY_ORDER_RECORD.replace("rollback=true", "rollback=false"),
            format!("{BUDDY_ORDER_RECORD} extra=true"),
            format!("{BUDDY_ORDER_RECORD}\n{BUDDY_ORDER_RECORD}"),
            "CHECK buddy-orders".to_owned(),
        ] {
            assert!(
                !validate(
                    DEBUG_CASES[0],
                    &success,
                    &serial.replace(BUDDY_ORDER_RECORD, &invalid),
                )
                .0,
                "accepted invalid multi-order proof: {invalid}"
            );
        }
    }

    #[test]
    fn heap_proof_rejects_missing_changed_and_duplicate_records() {
        let success = ProcessResult {
            exit_code: Some(33),
            timed_out: false,
        };
        let serial = success_serial();
        for invalid in [
            String::new(),
            HEAP_RECORD.replace("oom=failed-cleanly", "oom=none"),
            HEAP_RECORD.replace("recovered=true", "recovered=false"),
            HEAP_RECORD.replace("over_cap=rejected", "over_cap=accepted"),
            HEAP_RECORD.replace("growth=buddy-frames", "growth=none"),
            format!("{HEAP_RECORD} extra=true"),
            format!("{HEAP_RECORD}\n{HEAP_RECORD}"),
            "CHECK heap".to_owned(),
        ] {
            assert!(
                !validate(
                    DEBUG_CASES[0],
                    &success,
                    &serial.replace(HEAP_RECORD, &invalid),
                )
                .0,
                "accepted invalid heap proof: {invalid}"
            );
        }
    }

    #[test]
    fn user_mm_proof_rejects_missing_changed_and_duplicate_records() {
        let success = ProcessResult {
            exit_code: Some(33),
            timed_out: false,
        };
        let serial = success_serial();
        for invalid in [
            String::new(),
            USER_MM_RECORD.replace("tlb=invlpg", "tlb=none"),
            USER_MM_RECORD.replace("rollback_points=3", "rollback_points=2"),
            USER_MM_RECORD.replace("accounting=restored", "accounting=leaked"),
            format!("{USER_MM_RECORD} extra=true"),
            format!("{USER_MM_RECORD}\n{USER_MM_RECORD}"),
            "CHECK user-mm".to_owned(),
        ] {
            assert!(
                !validate(
                    DEBUG_CASES[0],
                    &success,
                    &serial.replace(USER_MM_RECORD, &invalid),
                )
                .0,
                "accepted invalid user-mm proof: {invalid}"
            );
        }
    }

    #[test]
    fn irq_guard_proof_rejects_missing_changed_or_duplicate_records() {
        let success = ProcessResult {
            exit_code: Some(33),
            timed_out: false,
        };
        let serial = success_serial();
        for (valid, invalid) in [
            (IRQ_GUARD_RECORD, ""),
            ("out_of_order=true", "out_of_order=false"),
            ("saved_off=true", "saved_off=false"),
            ("blocked_delta=0", "blocked_delta=1"),
            ("nested=2", "nested=20"),
            ("resumed=true", "resumed=true saved_on=false"),
            ("periods=2 irq_delta=2", "periods=2 irq_delta=0"),
            ("periods=2 irq_delta=2", "periods=1 irq_delta=2"),
            ("lock_acquired=true", "lock_acquired=false"),
            (
                "lock_acquired=true",
                "lock_acquired=true lock_acquired=false",
            ),
            (
                "lock_acquired=true",
                "lock_acquired=true\nIRQ restore observation periods=2 irq_delta=2 lock_acquired=false",
            ),
        ] {
            assert!(
                !validate(DEBUG_CASES[0], &success, &serial.replace(valid, invalid)).0,
                "accepted missing/incorrect IRQ ownership proof: {invalid}"
            );
        }
        for extra in [
            IRQ_GUARD_RECORD.to_owned(),
            IRQ_GUARD_RECORD.replace("saved_off=true", "saved_off=false"),
            format!("{IRQ_GUARD_RECORD} "),
            "CHECK irq-guard".to_owned(),
            BUDDY_ORDER_RECORD.replace("max_order=10", "max_order=9"),
            "IRQ restore observation".to_owned(),
        ] {
            assert!(
                !validate(DEBUG_CASES[0], &success, &format!("{serial}\n{extra}\n")).0,
                "accepted duplicated/contradictory proof record: {extra}"
            );
        }
    }

    #[test]
    fn early_irq_restore_requires_real_delivery_and_failed_acquisition() {
        let negative = ProcessResult {
            exit_code: Some(35),
            timed_out: false,
        };
        let early_restore = "IRQ restore observation periods=2 irq_delta=2 lock_acquired=false\nFAIL irq-guard error=InterruptGuard\n";
        assert!(validate(DEBUG_CASES[8], &negative, early_restore).0);
        for invalid in [
            "FAIL irq-guard error=InterruptGuard\n".to_owned(),
            early_restore.replace("irq_delta=2", "irq_delta=0"),
            early_restore.replace("periods=2", "periods=1"),
            early_restore.replace("lock_acquired=false", "lock_acquired=true"),
            early_restore.replace(
                "lock_acquired=false",
                "lock_acquired=false lock_acquired=true",
            ),
            format!("{early_restore}{IRQ_GUARD_RECORD}\n"),
            format!("{early_restore}{IRQ_GUARD_RECORD} \n"),
            format!("{early_restore}CHECK irq-guard\n"),
            format!("{early_restore}CHECK irq-guard skipped\n"),
            format!("{early_restore}RESULT success\n"),
            format!("{early_restore}{early_restore}"),
        ] {
            assert!(
                !validate(DEBUG_CASES[8], &negative, &invalid).0,
                "accepted absent/contradictory early-restore observation: {invalid}"
            );
        }
    }

    #[test]
    fn returning_page_fault_requires_complete_register_proof() {
        let process = ProcessResult {
            exit_code: Some(33),
            timed_out: false,
        };
        let valid = success_serial();
        assert!(validate(DEBUG_CASES[0], &process, &valid).0);
        for invalid in [
            valid.replace(PF_GPR_RECORD, ""),
            valid.replace(PF_GPR_RECORD, "CHECK page-fault-gprs ok gprs=14"),
            format!("{valid}\n{PF_GPR_RECORD}\n"),
            format!("{valid}\nCHECK page-fault-gprs ok gprs=0\n"),
            valid.replace(PF_GPR_RECORD, "CHECK page-fault-gprs ok gprs=15 gprs=0"),
        ] {
            assert!(!validate(DEBUG_CASES[0], &process, &invalid).0, "{invalid}");
        }
    }

    #[test]
    fn fatal_page_fault_requires_actual_aligned_call_observation() {
        let case = DEBUG_CASES
            .iter()
            .find(|case| case.name == "unexpected-page-fault")
            .copied()
            .unwrap();
        let process = ProcessResult {
            exit_code: Some(35),
            timed_out: false,
        };
        let valid = "TRAP call-abi vector=14 rsp_mod16=8\nFAIL trap vector=14 error=0x0 rip=0x1 cr2=0x2 rsp=0x3\n";
        assert!(validate(case, &process, valid).0);
        for invalid in [
            valid.replace("rsp_mod16=8", "rsp_mod16=0"),
            valid.replace("vector=14", "vector=13"),
            valid.replace("error=0x0", "error=0x3"),
            valid.replace("TRAP call-abi vector=14 rsp_mod16=8\n", ""),
            format!("{valid}TRAP call-abi vector=14 rsp_mod16=0\n"),
            format!("{valid}TRAP call-abi vector=14 rsp_mod16=8 extra=true\n"),
            format!("{valid}RESULT success\n"),
            format!("{valid}FAIL trap-call-abi\n"),
            format!("{valid}FAIL trap-call-abi extra=true\n"),
            "TRAP call-abi vector=14 rsp_mod16=0\nFAIL trap-call-abi\n".to_owned(),
        ] {
            assert!(!validate(case, &process, &invalid).0, "{invalid}");
        }
    }

    #[test]
    fn serial_firmware_framing_preserves_diagnostic_boundaries() {
        let negative = ProcessResult {
            exit_code: Some(35),
            timed_out: false,
        };
        // integrated-001: OVMF emitted two cursor-home sequences immediately
        // before the early CPU rejection, without another newline.
        let record = "BdsDxe: loading Boot0002\r\nBdsDxe: starting Boot0002\r\n\
            \x1b[001;001H\x1b[001;001HFAIL cpu error=Pat\n";
        assert!(validate(DEBUG_CASES[4], &negative, record).0);
        for invalid in [
            "\x1b[001;001Hloader: FAIL cpu error=Pat\n",
            "\x1b[001;001HFAIL cpu error=Pattern\n",
            "\x1b[001;001HFAIL cpu error=\x1b[0mPat\n",
            "\x1b[001;001HFAIL cpu error=Pat\rhidden\n",
            "\x1b[001;001HFAIL cpu error=Pat\n\x1b[001;",
            "\x1b]title\x07FAIL cpu error=Pat\n",
        ] {
            assert!(
                !validate(DEBUG_CASES[4], &negative, invalid).0,
                "accepted invalid framing: {invalid:?}"
            );
        }
        assert!(
            !validate(
                DEBUG_CASES[4],
                &negative,
                &format!("{record}\x1b[0mRESULT success\n")
            )
            .0
        );
        let positive = ProcessResult {
            exit_code: Some(33),
            timed_out: false,
        };
        assert!(
            !validate(
                DEBUG_CASES[0],
                &positive,
                &format!("{}\n\x1b[0mFAIL assertion=unexpected\n", success_serial())
            )
            .0
        );
    }

    #[test]
    fn timeout_is_never_a_debug_case_pass() {
        let timed_out = ProcessResult {
            exit_code: Some(9),
            timed_out: true,
        };
        assert!(!validate(DEBUG_CASES[0], &timed_out, &success_serial()).0);
    }

    fn oracle_lines(group: &str) -> Vec<String> {
        oracle_rows(group)
            .map(|(_, line)| line.to_owned())
            .collect()
    }

    /// The success serial of a `-- <group>` run: argc 2 and the group's lines before `init: ok`.
    fn oracle_serial(lines: &[String]) -> String {
        let one = fixture::init_summary(&expected().init, 1);
        let two = fixture::init_summary(&expected().init, 2);
        success_serial().replace(&one, &two).replace(
            "\ninit: ok\n",
            &format!("\n{}\ninit: ok\n", lines.join("\n")),
        )
    }

    #[test]
    fn oracle_case_requires_every_expected_line_exactly_in_order() {
        let process = ProcessResult {
            exit_code: Some(33),
            timed_out: false,
        };
        let case = case("oracle-ids");
        assert_eq!(case.cmdline, Some("-- ids"));
        assert_eq!(case.user, User::Oracle("ids"));
        let lines = oracle_lines("ids");
        assert_eq!(lines.len(), 158, "157 checks and the summary");
        assert_eq!(lines.last().unwrap(), "init: tests ids passed=157 failed=0");
        let (accepted, why) = validate(case, &process, &oracle_serial(&lines));
        assert!(accepted, "{why}");

        let mutate = |edit: &dyn Fn(&mut Vec<String>)| {
            let mut changed = lines.clone();
            edit(&mut changed);
            validate(case, &process, &oracle_serial(&changed))
        };
        for (what, (accepted, why)) in [
            ("missing line", mutate(&|l| drop(l.remove(10)))),
            ("missing summary", mutate(&|l| drop(l.pop()))),
            (
                "extra line",
                mutate(&|l| l.insert(5, "init: test ids.extra ok".to_owned())),
            ),
            ("duplicate", mutate(&|l| l.insert(5, l[5].clone()))),
            (
                "failing check",
                mutate(&|l| l[7] = format!("{} FAIL got=1 want=2", l[7].trim_end_matches(" ok"))),
            ),
            (
                "wrong count",
                mutate(&|l| {
                    *l.last_mut().unwrap() = "init: tests ids passed=156 failed=1".to_owned();
                }),
            ),
            ("reordered", mutate(&|l| l.swap(3, 4))),
            (
                "another group",
                mutate(&|l| l[0] = oracle_lines("time")[0].clone()),
            ),
        ] {
            assert!(!accepted, "{what} accepted: {why}");
            assert!(why.contains("oracle ids"), "{what}: {why}");
        }
        // Kernel noise and the banner are not part of the comparison ...
        let mut noisy = lines.clone();
        noisy.insert(2, "[    0.1] some printk".to_owned());
        noisy.insert(9, "init: banner line".to_owned());
        assert!(validate(case, &process, &oracle_serial(&noisy)).0);
        // ... but the lines must sit between init's summary line and `init: ok`.
        let serial = oracle_serial(&lines);
        let first = format!("\n{}", lines[0]);
        let early = serial.replacen(&first, "", 1).replacen(
            "init: hello from userspace",
            &format!("{}\ninit: hello from userspace", lines[0]),
            1,
        );
        assert!(!validate(case, &process, &early).0);
        // A run that did not reach `init: ok` is still a failure.
        let truncated = oracle_serial(&lines).replace("\ninit: ok\n", "\n");
        assert!(!validate(case, &process, &truncated).0);
    }

    #[test]
    fn partial_oracle_case_runs_to_the_first_unwired_check_and_stops_loudly() {
        let process = ProcessResult {
            exit_code: Some(35),
            timed_out: false,
        };
        let case = case("oracle-fs-until-mmap");
        assert_eq!(case.cmdline, Some("-- fs"));
        let all = oracle_lines("fs");
        let cut = all
            .iter()
            .position(|line| line.contains("fs.mmap-"))
            .unwrap();
        assert_eq!(cut, 245, "245 lines precede the first mapping check");
        let serial = |lines: &[String]| {
            oracle_serial(lines)
                .replace("\ninit: ok\n", "\n")
                .split("\nRESULT success")
                .next()
                .unwrap()
                .replace(
                    "Kernel panic - not syncing: Attempted to kill init! exitcode=0x00000000",
                    "FAIL syscall unimplemented nr=9",
                )
        };
        let good = serial(&all[..cut]);
        let (accepted, why) = validate(case, &process, &good);
        assert!(accepted, "{why}");
        // One line more (the mapping check ran), one fewer, or no loud stop all fail.
        assert!(!validate(case, &process, &serial(&all[..=cut])).0);
        assert!(!validate(case, &process, &serial(&all[..cut - 1])).0);
        assert!(!validate(case, &process, &good.replace("nr=9", "nr=0")).0);
        assert!(!validate(case, &process, &format!("{good}\nRESULT success")).0);
        let mut wrong = all[..cut].to_vec();
        wrong[3] = format!("{} FAIL", wrong[3].trim_end_matches(" ok"));
        assert!(!validate(case, &process, &serial(&wrong)).0);
    }

    #[test]
    fn oracle_info_rows_match_by_name_only() {
        let fs = oracle_rows("fs").collect::<Vec<_>>();
        let info = fs
            .iter()
            .position(|(kind, _)| *kind == "info")
            .expect("fs has info rows");
        let mut observed = fs
            .iter()
            .map(|(_, line)| (*line).to_owned())
            .collect::<Vec<_>>();
        let strings = observed.iter().map(String::as_str).collect::<Vec<_>>();
        assert_eq!(
            validate_oracle(&strings, "fs", None).map(|(first, _)| first),
            Ok(0)
        );
        // Another cookie value is an observation, another name is not.
        let original = observed[info].clone();
        let name_end = original.match_indices(' ').nth(2).unwrap().0;
        observed[info] = format!("{} different observation", &original[..name_end]);
        let strings = observed.iter().map(String::as_str).collect::<Vec<_>>();
        assert!(validate_oracle(&strings, "fs", None).is_ok());
        observed[info] = original.replacen("init: info fs.", "init: info fs.x", 1);
        let strings = observed.iter().map(String::as_str).collect::<Vec<_>>();
        assert!(validate_oracle(&strings, "fs", None).is_err());
        assert!(validate_oracle(&[], "nonexistent", None).is_err());
    }

    #[test]
    fn oracle_expected_lines_are_consistent() {
        let mut rows = ORACLE_EXPECTED
            .lines()
            .filter(|line| !line.starts_with('#'));
        assert_eq!(rows.next(), Some("group\tkind\tname\tline"));
        let mut checks: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        let mut summaries = BTreeMap::new();
        for row in rows {
            let [group, kind, name, line]: [&str; 4] =
                row.split('\t').collect::<Vec<_>>().try_into().unwrap();
            match kind {
                "check" => {
                    assert_eq!(line, format!("init: test {group}.{name} ok"));
                    checks.entry(group).or_default().push(name);
                }
                "info" => assert!(line.starts_with(&format!("init: info {group}.{name} "))),
                "summary" => {
                    assert_eq!(name, "-");
                    summaries.insert(group, line);
                }
                other => panic!("unknown kind {other}"),
            }
        }
        let groups = ["mm", "ids", "time", "signal", "fs", "proc"];
        assert_eq!(
            checks.keys().copied().collect::<Vec<_>>().len(),
            groups.len()
        );
        for group in groups {
            let names = &checks[group];
            let mut unique = names.clone();
            unique.sort_unstable();
            unique.dedup();
            assert_eq!(unique.len(), names.len(), "{group}: duplicate check names");
            assert_eq!(
                summaries[group],
                format!("init: tests {group} passed={} failed=0", names.len())
            );
        }
    }
}
