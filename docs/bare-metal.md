# Physical-machine development and qualification

## Scope, authorization, and evidence status

**A real x86_64 Rust bootstrap has bounded QEMU evidence; no physical candidate execution is claimed.** [Implementation](implementation.md) records cell9's eight QEMU cases, five production-parser host tests, strict owned Clippy and both-profile artifact inspection. M1 is underway, not complete. The current workstation is the only available physical target; no additional machines, serial/BMC, spare devices or power equipment are assumed. The user alone controls any later installation/selection/boot and supplies physical results. Workstation availability is not permission to modify its disks, firmware, bootloader, settings or running kernel.

QEMU is the first debugging target, **not** the only development target. Physical boot, recovery, platform discovery and timing are co-designed from **M1**. A storage-free M1 diagnostic trial may precede rootfs/initramfs/storage/userspace, using the real diagnostic image on separate user-owned recoverable media with independently usable known-good recovery. It still requires applicable QEMU gates, reviewed handoff/safety limits and the user's test window. Full Linux-replacement packaging retains all later storage/root/userspace prerequisites. Physical evidence remains blocked until the user's report; VM success cannot close it.

The first userspace is Arch/CachyOS; the compatibility/performance reference stays **upstream Linux 6.18.57**, not downstream CachyOS kernel patches. A future installable package must coexist with the working kernel and be explicitly selectable through Limine/systemd-boot. See [packaging](packaging.md), [operator suite](bare-metal-suite.md), [definition of done](definition-of-done.md), [verification](verification.md), [performance](performance.md), [architectures](subsystems/architectures.md), [drivers](subsystems/drivers.md), [firmware](subsystems/firmware.md), and [roadmap](roadmap.md).

The accepted design is a modular monolithic Rust kernel covering the fixed upstream 6.18.57 feature baseline plus explicit reviewed security deltas; later feature-baseline changes require a separate decision. Every in-baseline module's functionality requires a Rust replacement, but arbitrary proprietary/third-party out-of-tree modules are not implicitly in scope. Physical qualification must record approved security deltas rather than quietly changing its reference. Unavoidable function-local `asm!`/`naked_asm!` needs documented hardware/register/memory contracts and disassembly review; standalone assembly and `global_asm!` are prohibited implementation escape routes.

The bounded Rust smoke runner is not hardware certification. Running it under an existing Linux kernel validates that runner/environment only; its `--environment bare-metal` label and host metadata do not attest physical execution. Read-only prerequisite observations recorded x86_64, running `7.2.10-1-cachyos`, Btrfs root, UEFI visibility, active Limine 12.9.3, Secure Boot disabled and only `tty0`/no serial observed. These are not a complete lab inventory or a recovery drill. No candidate physical boot, performance comparison or qualified device is claimed, and no package installation, host bootloader/firmware/device/mount/reboot/elevation action occurred.

The diagnostic profile's bounded framebuffer path also has a separate manual QEMU run with serial disabled and no `isa-debug-exit`, retaining `target/kernel-first-boot/cell9/diagnostic-framebuffer.png` and associated records through [implementation](implementation.md). It demonstrates a reporting path under that emulator configuration, not that this workstation's framebuffer, boot selection or recovery has been exercised. Emulator QMP shutdown is cleanup, not a physical recovery drill.

## Five design answers

1. **Which existing Rust crates can be reused?** The bounded host/guest smoke runner uses `std` without third-party dependencies; future Rust orchestration can start the same way. For candidate boot/platform mechanisms, `uefi`, `acpi`, and `x86_64` are evaluation candidates under the [dependency catalog](dependencies.md), not admitted implementations or substitutes for Linux firmware quirks, SMP, DMA or mitigation behavior. Exact features, allocation/context assumptions, unsafe/assembly paths, licenses and target support require review. External QEMU, serial terminals, reference Linux diagnostics, standard bootloaders, vendor firmware/microcode and authorized lab tools are separately permitted provenance-controlled dependencies, not Rust kernel code.
2. **What should be bundled or shared?** Share machine manifests, boot/package IDs, user report format, recovery interlocks, serial timestamps, artifact hashes and platform qualification records across subsystem owners. Keep power control independent of the candidate and keep each device's reset/DMA contracts explicit.
3. **What can be simplified safely?** Start with one user's workstation, one reviewed boot path, and no destructive testing. Use read-only/temporary-sandbox smoke before optional lab stress. Serial and independent remote power are the recommended recoverable lab design, not invented capabilities of this workstation. Missing recovery/observability blocks tests that depend on it; a documented user-operated local-console/manual-power path may support a limited recoverable boot test, not unattended qualification.
4. **How is security preserved?** Keep candidate access away from management/reset controls and protected media; isolate management/test networks, verify TLS and use limited credentials where remote management exists. Preserve Secure Boot, IOMMU and mitigations, record firmware trust and approved security deltas, and protect/redact console/report secrets as specified below. Destructive tests require separate explicit authorization and sacrificial fixtures; neither convenience nor a benchmark permits weaker protection.
5. **What can be improved?** Make recovery repeatable, minimize time-to-first-observable-marker, test real noncoherent DMA/NUMA/power transitions and bounded error recovery early, and apply locality/batching/zero-copy optimization only after semantics/security and the [performance floor](performance.md) hold. No optimization or convenience justifies risking the user's primary system.

**Additional direct-port obligation:** reproduce baseline architecture initialization, firmware/ACPI/DT interpretation, interrupt/timer/SMP behavior, DMA and IOMMU ownership, power/hotplug/error handling, and device protocols in Rust. Virtual devices are not substitutes for the physical implementations. Project-owned smoke and future orchestration executables remain Rust-only.

## Ordered co-development milestones

| Milestone | Physical development and dependency gate | Required evidence; current blocker |
| --- | --- | --- |
| M0 evidence/setup | Record authorized workstation capabilities, backup/recovery plan, known-good boot selection, permitted temporary storage and report privacy policy; keep diagnostic versus replacement-package boundaries explicit | Partial read-only observations above exist. Detailed inventory, backup verification and independent recovery readiness still need evidence |
| M1 toolchain/boot | Retain actual QEMU trusted entry, checked firmware, memory/paging, exception/timer and bounded diagnostic evidence; complete applicable bootstrap cases and reviewed safe handoff before user boot | Real cell9 artifacts exist, but no physical boot/report/recovery pass. User must capture selected image/hash and expected entry/diagnostic markers, then demonstrate known-good recovery. Negative cases have their own expected failure/recovery outcomes; an unexplained failure is not bring-up completion |
| M2 MM/SMP/scheduler | Add physical memory-map validation, page-table faults, all discovered CPUs, interrupt/timer calibration, cache topology, CPU idle and watchdog behavior; no reliance on emulator scheduling/order | CPU/memory enumeration and timer/wakeup correctness under SMP stress; actual topology-specific evidence, no assumptions that a single socket is NUMA |
| M3 process/userspace | Boot exact reviewed Arch/CachyOS root environment when ELF/syscall/IPC dependencies are ready; run bounded Rust functional suite and record actual release | Suite report plus external boot evidence, process/signal/IPC differential tests; host-Linux suite success is not a candidate pass |
| M4 storage | Begin with a RAM-backed or dedicated disposable filesystem after the relevant drivers exist; add real controller/media only after DMA/IOMMU and error-path gates | Persistence/checksums/flush/recovery evidence for each real device and filesystem. No raw-device writes or power-loss testing on the workstation by default |
| M5 first workload | Real network device and balanced server/container workload with compatible userspace; isolate experimental traffic and temporary volumes | Packet/data correctness, isolation, physical [non-inferiority campaign](performance.md) and user report; loopback/virtual NIC evidence alone insufficient |
| M6 broad facilities | Power states/resume, hotplug, firmware/security mitigation, tracing, virtualization and other facilities as dependency implementations mature | Per-feature recovery and timing/security results; destructive or disruptive cases blocked absent separately authorized safe facilities |
| M7 architecture/device closure | Expand only when authorized physical resources or independently reviewable partner evidence exist; instantiate every baseline architecture/board/device configuration requirement | Named blocked cells remain visible. One workstation cannot close all Linux hardware scope |
| M8 release/maintenance | Independently reproduce required physical, semantic, security and performance results; rerun affected cells after firmware/toolchain/driver changes | Exact supported cells and evidence signed by owners; no blanket Linux parity while required cells remain blocked |

Initial physical bring-up must not wait for M8, but neither a fake package nor an unreviewed artifact is a safe handoff. Each user trial requires the complete applicable QEMU cases and recovery readiness. A storage-free milestone diagnostic experiment is explicitly narrower than Linux-replacement packaging and full kernel completion; it does not require inventing a temporary rootfs or toy filesystem.

## Available target versus proposed lab tiers

Tier identifiers organize requirements, not purchasing commitments or claims of possession. No procurement, new-host access, or automatic host mutation is authorized.

| Tier | Target and purpose | Recovery/observability requirement | Availability and qualification |
| --- | --- | --- | --- |
| W0: current workstation | Sole available physical target; partial read-only x86_64/UEFI/Limine/Btrfs observations above, with remaining CPU/board/device/topology details still to record | Preserve installed known-good kernel/default/entries; separate user-owned diagnostic media and independent rescue path; actual display/keyboard/manual power, serial/remote facilities only if observed and approved | Availability is not physical attestation. Recovery readiness and candidate execution unproved; all physical candidate evidence awaits the user's report |
| L1: recoverable M1 x86_64 bench | Proposed sacrificial Intel **or** AMD x86_64 machine with real serial and independent reset/power; first ideal unattended bring-up fixture | Board UART or BMC serial-over-LAN, correctly wired independent capture host, verified manual/remote reset and boot fallback, known-good rescue medium | Not acquired/authorized. Recommendation must not become a fictional mandatory acquisition before limited user-controlled W0 boot testing |
| L2: early vendor/platform diversity | Proposed Intel and AMD x86_64 plus arm64 UEFI/ACPI server and/or DT board while M2–M5 mechanisms develop | Independent recoverability per machine, relevant debug UART, safe removable storage and isolated test NIC | Not available; cross-vendor/ARM qualification blocked, not covered by W0/QEMU |
| L3: server/topology/error lab | Proposed multi-socket/NUMA machines, IOMMU groups/SR-IOV, ECC/RAS, multiple real NIC/storage vendors and topology, measured power | BMC/serial plus independent power, sacrificial media, isolated switch/load generator, calibrated meter and approved injection controls | Not available; NUMA, error, energy and topology cells blocked unless real capabilities are later recorded |
| L4: breadth/specialized/legacy | Proposed all remaining architecture/board, desktop/audio/GPU, embedded/RT, legacy bus and specialized accelerator cells | Vendor-appropriate console/JTAG/debugger only where allowed, recovery firmware/media, physical operator and electrical-safety policy | Not available; remain part of final scope, never certified from emulation alone |

For serial, confirm connector pinout, voltage (TTL UART is not RS-232), grounding and baud/parity/flow control against the actual board manual before connection. Never wire an unknown header from an internet guess. Linux requires console support available early rather than relying on a module loaded after failure; its multiple-console selection rules can affect `/dev/console`: [baseline serial-console documentation](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/admin-guide/serial-console.rst). A proposed kernel must implement the relevant console behavior, not merely print to QEMU's port.

A BMC/Redfish endpoint may support inventory, reset and virtual media, but exact actions/capabilities are vendor-specific and must be verified without assuming that a standards label guarantees them. See [DMTF Redfish](https://www.dmtf.org/standards/redfish). Keep management traffic on a separate trusted network, authenticate with verified TLS and limited credentials, and keep power/reset controls unavailable to the candidate guest/kernel. Neither BMC nor a network console is guaranteed to survive every platform hang; require an independent fallback for unattended destructive tests. None is assumed on W0.

## Baseline architecture coverage matrix

The [pinned upstream architecture inventory](https://api.github.com/repos/gregkh/linux/contents/arch?ref=v6.18.57) contains the families below. This is a **proposed qualification backlog**, not an assertion of Rust target availability or supported boards. Exact baseline subarchitectures, ABIs, endianness, word/page sizes, MMU/no-MMU modes, CPU revisions and board/device variants must be expanded with the [architecture plan](subsystems/architectures.md) and [coverage inventory](coverage.md). A single exemplar cannot prove a whole architecture. Compiler/backend gaps and inaccessible hardware are explicit blockers, never reasons to remove a family.

| Baseline `arch/` family | Required proposed physical execution class and distinguishing evidence |
| --- | --- |
| `x86` | Current workstation first, observed x86_64 only if confirmed; later Intel/AMD physical variants, 32-bit/compat cases, BIOS/UEFI where baseline relevant, APIC/interrupt and mitigation variants |
| `arm64` | Real ARM platform, ACPI/UEFI and DT variants, page sizes, GIC/timer/PSCI, coherent and relevant noncoherent I/O, SMP and IOMMU |
| `arm` | Real 32-bit ARM board variants, MMU/no-MMU where supported, endian/ABI/cache maintenance and interrupt/timer/power protocols |
| `riscv` | Physical RISC-V board variants, SBI/firmware, supported word sizes/extensions, interrupt-controller and noncoherent DMA/cache conditions |
| `powerpc` | Physical supported Power/PowerPC classes, endian/word-size/page variants, interrupt/DMA/NUMA behavior; partition-mediated evidence explicitly labelled |
| `s390` | Authorized IBM Z physical-system access and, as appropriate, LPAR execution; record firmware/hypervisor/partition mediation. LPAR is not VM-free whole-machine proof and does not certify untested partition/I/O modes |
| `loongarch` | Physical supported LoongArch machine/board, interrupt controller, firmware, CPU and I/O coherency behavior |
| `mips` | Physical supported MIPS variants, word sizes/endian/MMU/cache/board differences; one little-endian board does not cover big-endian or all ISAs |
| `sparc` | Physical supported SPARC classes, word-size/MMU/firmware/interrupt and device differences |
| `alpha` | Physical supported Alpha system, platform firmware, weak ordering, DMA and machine-check behavior |
| `parisc` | Physical supported PA-RISC system, firmware, word-size/interrupt/DMA/cache differences |
| `m68k` | Physical supported m68k board/system variants, MMU/no-MMU where applicable, CPU/cache/interrupt and legacy-device conditions |
| `sh` | Physical supported SuperH board/CPU variants, MMU/cache/endian and interrupt/DMA contracts |
| `arc` | Physical ARC board or actual FPGA implementation of the baseline configuration; cache/MMU/interrupt variants and real peripherals |
| `csky` | Physical supported C-SKY board/configuration, MMU/cache/interrupt/firmware/device behavior |
| `hexagon` | Authorized hardware exposing the baseline-supported Hexagon execution arrangement and devices; record host/firmware/DSP mediation, ownership and debug restrictions, not a generic DSP simulation |
| `microblaze` | Actual FPGA/board with pinned bitstream and soft-core configuration, bus/peripheral/cache/MMU details; a software simulator is not physical evidence |
| `nios2` | Actual baseline-compatible Nios II FPGA/board configuration and pinned bitstream, MMU/cache/device details; availability and toolchain gaps remain blockers |
| `openrisc` | Physical supported OpenRISC implementation or actual FPGA, pinned configuration/bitstream and interrupts/MMU/cache/peripherals |
| `xtensa` | Physical supported Xtensa core/board configuration, generated ISA/core options, MMU/no-MMU and cache/DMA behavior |
| `um` | User-mode Linux architecture is hosted, not a physical ISA/board to bare-boot. Qualify its hosted execution on a recorded qualified physical host and keep host-kernel mediation explicit; do not invent a bare-metal UML boot requirement |

All non-W0 cells are currently unavailable/unqualified. Where an architecture has no working Rust compiler/backend/toolchain or feasible board access, identify that exact missing prerequisite in the qualification record and continue reachable planning; simulator success cannot erase it. A third-party lab report requires reproducible inputs, machine/firmware disclosure consistent with privacy, authenticated artifacts and review; a vendor datasheet or assurance is not an execution record.

## Cross-cutting physical device and fault matrix

The matrix must be instantiated per actual platform and device ID/revision; a column labelled present is not a completed test. Public reports can redact unique serial numbers while retaining model/revision/topology needed for reproducibility.

| Area | Required development/qualification cases | Safety boundary and evidence |
| --- | --- | --- |
| Firmware/boot/trust | Actual firmware memory map, ACPI/DT, boot handoff, runtime-service boundaries, microcode load order, Secure Boot/measurement where supported, warm/cold paths | Pin version/hash/vendor provenance/license and update state; never automatically flash, alter Secure Boot keys or disable protection. Firmware is trusted external code, not Rust kernel implementation |
| CPUs/memory/NUMA | SMP startup/teardown, SMT/topology, memory holes/reservation, ECC and machine checks where supported, local/remote placement, CPU/memory hotplug | Never online/offline workstation resources automatically. Unsupported hardware remains blocked; protect reserved/firmware memory and preserve clock/ordering contracts |
| Interrupts/timers | Legacy and MSI/MSI-X where relevant, affinity/queue mapping, interrupt storms/loss, monotonic clocks, drift, suspend clock handling, watchdog recovery | Bounded fault cases and independent capture/recovery; do not mask required interrupts/mitigations to improve benchmarks |
| DMA/IOMMU/PCIe | Real NIC/storage DMA, address masks, bounce buffering, map/unmap and lifetime, coherent/noncoherent cache sync, IOMMU faults/isolation and revocation, PCI reset/hotplug | No arbitrary DMA or unsafe passthrough on W0. Tests needing malicious devices or fault endpoints require an isolated sacrificial rig. Never assume CPU physical address equals DMA address |
| Real networking | At least eventual independent NIC/controller vendor families, link-rate/queue/offload variants, cable/link loss, congestion and bidirectional traffic; Wi-Fi/other baseline devices as scope expands | Isolated test VLAN/link, no production traffic/credentials; local loopback and QEMU virtio do not qualify physical NICs |
| Real storage/filesystems | NVMe, SATA/AHCI, USB/removable and other baseline media/controllers; flush/FUA/write-cache, controller reset, surprise removal/error recovery, zoned/RAID/multipath where supported | Default W0 suite uses only new private temporary files. Real durability/power-cut tests require dedicated sacrificial device and separately approved isolation; never user's system/root/backup disk |
| Power/thermal | Idle/boost/power caps, runtime PM, suspend/resume/hibernate, repeated transitions, thermal limits/throttling, wake sources and clock continuity | Do not alter thermal protections/voltages. Suspend/hibernate can hang or affect disk state; user-authorized staged tests only after recovery readiness |
| Hotplug/error recovery | Supported CPU/memory/PCI/USB/storage/network hotplug; allocation/timeout/usercopy/futex/I/O fault paths; RAS/AER/ECC injection where safe and supported | Bounded injected faults first in QEMU/isolated fixtures; hardware-supported injection not assumed. No destructive/unbounded faults on primary workstation |
| Broader devices | GPU/display modes and reset, audio continuity, HID/input, embedded/industrial peripherals and legacy buses, accelerators | Electrical/process safety and user-data isolation per actual device. Server-first does not waive desktop, embedded, RT or legacy scope |

Linux explicitly distinguishes CPU virtual, physical and bus/DMA addresses, mapping lifetimes and cache-line hazards: [DMA API guide](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/core-api/dma-api-howto.rst). x86 coherent-emulator success does not establish correctness on a noncoherent board. Linux documents targeted allocation, usercopy, futex, storage and NVMe failure injection: [fault injection](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/fault-injection/fault-injection.rst). These are candidate requirements, not interfaces already implemented here. Its staged PM tests isolate freezer/devices/platform/CPU/core phases and warn of hangs: [suspend/hibernate debugging](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/power/basic-pm-debugging.rst). Never copy invasive upstream commands onto the user's host as an automatic smoke step.

## Safe workstation execution path

### Reference-host smoke before candidate userspace exists

The actual Rust smoke suite can be built/run by the main integration owner or user on the existing Linux environment using the documented CLI. This is a **runner/reference smoke**, not a new-kernel boot or performance proof. Determine the exact running `uname -r` first and supply that literal release; do not assume the installed kernel is upstream 6.18.57. The output directory must be new, writable and on an explicitly selected temporary filesystem. Review [suite limits](bare-metal-suite.md) before execution.

```text
cargo run -p baremetal -- run --output <new-directory> --label <label> --expect-release <exact-osrelease> --environment reference
```

The angle-bracket values are operator-supplied parameters, not literal shell-ready values or generated evidence. Historical actual host runs are in [suite evidence](bare-metal-suite.md#observed-host-runner-verification); this documentation migration runs no command. The suite neither installs a kernel nor modifies boot entries. Reference Linux 6.18.57 needs its own correctly labelled run when that exact reference is booted; an installed CachyOS run retains its actual release and cannot masquerade as the pinned reference.

### Before the user's first candidate boot

1. Use a real reviewed artifact and the corresponding declared-scope evidence. For a storage-free M1 trial, identify the `freestanding` diagnostic ELF and exact image/compiler/source/configuration hashes; it has no Linux release/rootfs/initramfs/userspace to invent. Use separate user-owned recoverable media and independent known-good recovery. A Linux-replacement package instead needs real storage/filesystem/root/initramfs/init/userspace and their hashes plus all [packaging](packaging.md) gates. No placeholder package is acceptable.
2. Finish the complete **applicable milestone QEMU suite**, including boot failure, exception, memory/interrupt/timer and shutdown/recovery cases supported by that milestone; include all functional/security prerequisites needed for the proposed user workload. Preserve logs and limitations. QEMU passing is a prerequisite, never physical proof.
3. Confirm recoverable selection for the artifact's **actual** boot format. The current diagnostic uses native Limine ELF; it is not a systemd-boot EFI/PE image or a Linux boot-protocol implementation. Preserve the known-good kernel/initramfs/entry and default; the user alone selects separate diagnostic media or later installs a qualified replacement package. Do not automatically edit firmware order, bootloader config, package state, filesystems or host devices. See [package design](packaging.md) and [maintained tooling](kernel-tooling.md), whose execution status is separate from manual cell9 evidence.
4. Have the user verify a separate backup of important data and bootable offline rescue media, ability to unlock encrypted storage if applicable, and working known-good boot recovery. Do not test corruption by touching that backup. If the recovery path or keys are missing, stop before candidate boot.
5. Record actual console and recovery paths. With no serial/BMC, the user uses a local console and photographs/logs only nonsecret markers; explain that early hangs may leave incomplete evidence. If a hang cannot be safely recovered without threatening data, the test is blocked. Independent serial/remote reset is recommended for a later sacrificial bench, not assumed or automatically configured.
6. Restrict the first artifact to the reviewed experiment. The M1 diagnostic has no storage drivers, mounts, rootfs or userdata access; do not add them just to make the trial resemble a replacement kernel. Later storage/userspace experiments require disposable media/root environments and must prevent experimental drivers from accessing user data. Read-only promises alone cannot bound faulty DMA/firmware; a device-access risk review remains necessary before booting a primary workstation.
7. User chooses a controlled test window and explicitly selects the candidate. At M1 collect boot markers and recovery observations only; the host/guest Rust userspace suite cannot execute before required ELF/syscalls/userspace dependencies exist. At later milestones run the suite as an unprivileged process in a new sandbox, with the exact expected candidate release.
8. Return report artifacts and recovery observations; select known-good kernel on the next user-controlled boot. Do not turn a missing report into success or ask the agent to reboot to obtain it.

### Candidate suite invocation when userspace exists

```text
cargo run -p baremetal -- run --output <new-directory> --label <label> --expect-release <exact-osrelease> --environment bare-metal
```

For QEMU use the same interface with `--environment qemu` inside its guest. Where development tools are not installed in the guest, build the suite ahead of time for the real userspace target and transfer the reviewed binary using the packaging/suite instructions; building on the host does not execute it on the target. A missing compiler/loader/library is a recorded deployment blocker, not a substituted host run.

The bounded suite covers memory/threads, private-sandbox filesystem sync/rename/links, loopback TCP/UDP/Unix sockets with timeouts, process exec/wait/exit, and proc/sysfs visibility with explicit unavailable/permission outcomes. It does **not** establish destructive recovery, real NIC throughput, raw block durability, IOMMU isolation, firmware correctness, NUMA, power states, kernel security, full ABI compatibility or the statistical performance floor. Every broader gate remains in [verification](verification.md) and [performance](performance.md); suite success does not waive it. Any unavailable/skip outcome leaves its capability unqualified even when other cases succeed.

## Destructive-test isolation and privacy

Destructive tests are disabled by default and outside the current smoke suite. Before any later power-cut, hot-unplug, raw fio, RAS injection, firmware or recovery campaign, require a separate explicit authorization and fixture record naming its owner, exact serial-to-slot mapping held privately, device allowlist, physical isolation, backup/restore process, stop condition and emergency recovery. Prefer physically disconnecting protected media and separating power domains; device path names such as `/dev/sda` are not stable authorization. Never reset or remove a controller shared with root/backup storage. Avoid USB hubs, switches and PDUs whose reset/power operation affects unrelated equipment. A lab-network reset must not sever the sole management/recovery route.

Use dedicated sacrificial media, with no personal/production data and no credentials. Isolate load generators, DHCP/PXE and fault traffic from home/corporate/production networks. Do not expose BMC, serial servers or test services to the public internet. Securely handle initramfs/root images, console dumps, panic memory and journals: they may contain keys, user paths, machine identity or packet content. Collect minimum relevant metadata; omit hardware serial IDs from public suite reports, keep credentials/recovery keys outside artifacts, and review/redact uploads without altering original evidence. Record hashes of originals privately and provenance of redacted derivatives.

Vendor firmware/microcode and bootloaders are external trust dependencies. Record vendor/source, version/hash or signed identifier, distribution license, verification method, update history and configuration. Do not describe firmware as Rust-only, assume closed firmware is verified safe, or silently turn off Secure Boot/IOMMU/mitigations. Configuration changes need user authorization, matching reference/candidate rebaseline and independent recovery instructions. Firmware unavailable, unverifiable or unredistributable can be an explicit qualification/distribution blocker.

## Qualification and user-report templates

These schemas are blank by design; they do not represent observed hardware or test outcomes. Preserve immutable raw logs and hashes separately from a concise public report.

```text
platform_id / operator / authorized_test_window:
availability: proposed | available | unavailable
qualification: not_started | blocked | failed | inconclusive | qualified
architecture / ABI / word_endian_page_variants / board_model_revision:
CPU_model_stepping / cores_SMT_sockets / NUMA_topology / RAM_geometry:
PCI_device_models_revisions / real_NIC_link_peer / storage_controller_media:
firmware_microcode_versions_hashes / ACPI_DT_hash / trust_license_records:
IOMMU_DMA_mode / mitigations / power_idle_boost_policy / bootloader_version:
known_good_kernel_entry / candidate_package_hash / image_initramfs_hashes:
expected_release / observed_release / userspace_image_hash:
console_type / capture_method / independent_power_or_manual_recovery:
backup_rescue_readiness / destructive_test_authorization_or_none:
QEMU_prerequisite_campaign / physical_test_scope / suite_binary_hash:
case_ids_outcomes / unavailable_skipped_cases / performance_campaign_ids:
raw_log_artifact_hashes / user_observations / recovery_result:
blocked_hardware_interfaces / unresolved_failures / next_required_gate:
platform_subsystem_security_reviewers / evidence_review_date:
```

User return report should include the selected boot entry and observed release, whether the console/clock/CPU/storage/network behavior matched expected scope, any exact panic/error/timeout, the suite output directory artifacts when runnable, and whether/how known-good recovery succeeded. Do not request secrets or upload complete system dumps by default. If an early hang prevents collecting a field, mark it unavailable and preserve the user's observation as ground truth. A user-reported boot failure is a failure record, not something to dismiss by repeating a host smoke test.

## Explicit definitions of done and remaining blockers

### Workstation bring-up cell

A particular M1 physical bring-up cell is done only when: a real reviewed image/package exists; the relevant complete QEMU suite passes with artifacts; the user has verified backup/known-good/offline recovery readiness; actual boot path and console are recorded; user-operated physical boot produces all expected successful milestone markers and observations; independent clocks/CPU/memory/interrupt observations required for that milestone are captured; and the user demonstrates return to known-good operation. An unexpected boot failure remains `failed` or `blocked` until its cause is repaired and the affected bring-up gates are successfully rerun; investigation and recovery alone are not success. Deliberately injected failure/recovery tests have separately defined expected outcomes and may pass only those cases, never substitute for successful bring-up. Missing serial can limit the claim but cannot justify inventing an early log. A boot marker alone proves neither userspace compatibility nor kernel completion.

### Physical functional-suite cell

A particular suite cell is done only when: its exact binary/configuration/environment/release are recorded; it executes on the intended machine/kernel, not a substituted host; all required bounded cases meet their defined expected outcomes with individual passing records and raw artifacts; errors, timeouts, permissions and unavailable cases remain visible; and reviewers limit the claim to those functional operations. An unexpected failure or a required skipped/unavailable case prevents cell closure; a narrower completed case may be reported without closing that cell. A deliberately tested error path passes only when its separately specified expected error and recovery behavior are observed. Skipped hardware/performance/security capabilities are not passed by this cell. Reference-run success validates runner operation on that reference only.

### Device/platform qualification

A device/platform cell is done only when: its specific architecture/configuration/firmware/trust manifest and approved safe fixture exist; direct Rust functionality covers the baseline behavior including faults and teardown; differential, stress, concurrency, recovery and security gates actually execute and pass their defined expected outcomes; real device paths rather than emulator-only replacements are exercised; workload/timing/resource/energy cells satisfy the [zero-margin performance floor](performance.md); and independent evidence/recovery review signs the precise claim. Unexpected failures and required skipped/unavailable gates prevent closure, even if investigation or recovery succeeds. Changing firmware, mitigation, compiler, topology or driver invalidates affected prior scope until reviewed/rerun. One qualified board cannot close all ISA, vendor or device cells.

### Whole-kernel physical closure

Whole-kernel closure still requires every required baseline architecture/device/feature cell to pass and the [standing definition of done](definition-of-done.md) to hold: **“Do not stop until everything is ported.”** A real limited bootstrap and bounded QEMU cases do not satisfy that rule. Failed, blocked, inconclusive, skipped or unavailable obligations cannot be relabelled complete; no aggregate, smoke exit, inventory count or single workstation replaces closure. Current blockers are the remaining full Linux implementation and replacement-package prerequisites, unexecuted physical boot/recovery and absent user report, incomplete detailed workstation/recovery evidence, no paired upstream-6.18.57 performance campaign, and unavailable additional platforms/sacrificial fixtures/sensors. No physical result is inferred from [cell9 evidence](implementation.md), and no final scope is removed.
