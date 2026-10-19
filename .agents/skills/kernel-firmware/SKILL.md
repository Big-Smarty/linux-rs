---
name: kernel-firmware
description: "Design and review Rust-only kernel firmware boundaries: ACPI tables and AML, UEFI boot/runtime services, FDT, SMBIOS, device firmware, microcode, licensing and untrusted input. Use for firmware parsing, platform enumeration, power management, or hardware bring-up."
---

# Kernel firmware

## Contract and inputs

Read the [firmware plan](../../../docs/subsystems/firmware.md), [architecture plan](../../../docs/subsystems/architectures.md), [driver plan](../../../docs/subsystems/drivers.md), [licensing contract](../../../docs/licensing.md), [dependency policy](../../../docs/dependencies.md), [bare-metal contract](../../../docs/bare-metal.md), and [verification contract](../../../docs/verification.md).

Required inputs are the pinned Linux 6.18.57 source mapping, platform/firmware revision, applicable specification editions, boot protocol and memory map, CPU/device identifiers, table/blob digests and provenance, expected Linux-visible enumeration/power behavior, and both QEMU and physical lab configurations. Record whether a table was supplied by firmware, loader, initrd override, or a test generator. Redact serial numbers and other sensitive platform identifiers from public artifacts.

The kernel and its project-owned executable tools are Rust-only. External firmware and microcode are permitted but remain external, non-Rust trust dependencies. ACPICA's C implementation may be an external comparison oracle, never a linked kernel implementation or disguised build dependency. A Rust crate named `acpi`, `aml`, `uefi`, or `fdt` is a candidate for review, not proof of complete compatibility or permission to link native code. Follow the dependency policy for the full feature/transitive graph and license obligations.

The [current bootstrap](../../../docs/implementation.md) has actual Limine base5/UEFI OVMF handoff, checked immutable RSDP/XSDT/SDT/MADT discovery, production-parser host tests and cell9 QEMU evidence. `ws-drivers-acpi` is `in_progress` with exact Rust-path/cell routing, not a completed ACPI port or physical-firmware qualification. External Limine 12.9.3 and OVMF retain separate provenance/notices; `kernel/src/boot.rs` preserves the protocol's 0BSD notices under `GPL-2.0-only AND 0BSD`. AML, EFI runtime services, native EFI/Linux boot paths, FDT/SMBIOS, device firmware/microcode application and broader power/platform behavior remain open.

## Ordered workflow

### 1. Establish ownership and trust before parsing

Build a per-platform firmware ledger: source, revision/specification version, digest, signature verification actually performed, redistribution terms, retained notices, update authority, rollback constraints, trust level, runtime privilege, memory reservation, and consumers. Keep host firmware, boot firmware, OS parser/interpreter, device firmware, CPU microcode, and secure-monitor/management firmware distinct.

An upstream GPL kernel license does not grant redistribution rights to arbitrary blobs. Preserve upstream per-file exceptions and firmware license texts. Do not embed a downloaded blob or copy a vendor SDK merely because Linux can request it. Unavailable or incompatible license terms block packaging that artifact; record the affected hardware cell rather than inventing a replacement.

Output: provenance/license/trust records and a platform inventory linked to the compatibility matrix.

### 2. Implement a shared hostile-input boundary, not a shared fictional format

Before creating a typed reference, validate mapped physical range, address width, overflow-free length/offset arithmetic, minimum header size, revision, alignment, checksum where specified, maximum accepted resource use, and lifetime. Do not read past a mapping to discover a length. Checksums detect some corruption, not malicious authenticity. The existing bootstrap's unsafe table borrow additionally requires initialized, immutable RSDP/SDT storage with no firmware/SMM/AP/DMA/software writers or reclamation for the borrow; reserved memory alone does not prove this. FACS, arbitrary NVS and runtime data are not admitted by that contract. Copy validated metadata when necessary to avoid mutation races; do not claim unavoidable-copy avoidance outranks memory safety.

Keep format-specific endian decoding and nested-record traversal explicit. Handle unknown revisions and optional records according to the pinned baseline/specification; reject invalid references without guessing addresses or exposing arbitrary memory. Preserve reserved/runtime regions and distinguish firmware-owned MMIO from allocatable RAM. A table's claim that a region exists is not authorization to access it.

Build parser corpora from legally collected real-machine tables and generated valid/malformed cases. Bound recursion, collection growth, string scans, traversal cycles, and total work. Fuzz parsing without live device effects first. Resource limits must have defined diagnostic/recovery behavior and compatibility review; silently truncating a valid table is not support.

Output: safe byte-parser contracts, lifetime/mapping rules, hostile-input corpus, and explicit error outcomes.

### 3. Port ACPI discovery and AML as separate mechanisms

Discover RSDP through the platform's supported paths; validate legacy and extended checksums/lengths before traversing RSDT/XSDT. Validate each SDT independently, use signatures and lengths rather than assuming table ordering, and follow FADT/DSDT/SSDT links with cycle/overlap protection. Describe MADT interrupt topology, SRAT/SLIT NUMA locality, MCFG PCI access, IOMMU tables, timers, and power tables through their actual revisioned formats.

Then plan the AML interpreter: package lengths and names, a shared namespace across definition blocks, integer width/revision semantics, references/conversions, control flow, method calls, synchronization levels/mutexes/global lock, serialized methods, notifications, dynamic table loading/unloading, fields, and operation regions. Static ACPI table parsing is not AML support. Do not substitute a few common `_STA`/`_CRS` methods for the full baseline scope.

Treat AML as executable untrusted firmware policy. Mediate SystemMemory/SystemIO/PCI/embedded-controller and other operation-region handlers through validated mappings, access-width rules, ownership and device lifecycle. Define sleeping context, reentrancy, lock ordering, event delivery, method cancellation/watchdog behavior, and error propagation. A generic interpreter timeout cannot silently alter valid Linux-observable behavior; characterize the limit and affected platforms.

Derive `_OSI` responses, `_OSC` ownership negotiation, device IDs/resources/dependencies, power resources and `_PSx`, `_PRW`, GPE/SCI events, thermal policy, battery/lid behavior, hotplug and sleep/wake from the pinned Linux implementation. No unsupported method may be reported as successful merely to get booting.

Output: separate table-parser and AML conformance matrices, namespace/operation-region contracts, hardware-quirk records with exact provenance, and differential tests against the baseline and external interpreter tooling.

### 4. Make UEFI service lifetime transitions explicit

Separate the loader's EFI ABI/image handling from kernel internal calling conventions. The existing Limine base5 path receives an already-exited boot-services handoff and makes no EFI service calls; that is not a native EFI stub implementation. For native EFI paths, validate system/configuration tables, signatures and revisions, descriptor size/version, physical ranges and memory attributes. Plan `GetMemoryMap` buffer resizing with checked allocation; capture the current map key immediately before `ExitBootServices`. If firmware rejects a stale key, follow the specification's permitted recovery path; avoid unrelated service calls or allocation that invalidates the map between acquisition and exit.

After successful exit, boot-service pointers and memory are not generally callable as services. Preserve runtime regions and define runtime-service mapping/address conversion, CPU/interrupt context, serialization, and fault containment. Specify variable enumeration/read/write permissions, quotas, authentication rules, capsule policy, time, reset, Secure Boot and measured-boot interactions. Secure Boot state is not proof that firmware is trustworthy or that a new kernel is compatible.

Output: boot-service-to-runtime ownership state machine, callable-service/context matrix, memory-attribute plan, and failure/recovery cases. Legacy BIOS and non-UEFI architectures remain separate tracked paths, not silently excluded.

### 5. Port FDT and SMBIOS without native-layout shortcuts

For FDT, decode the big-endian header, compatible versions, bounded totalsize, structure/string/reservation block offsets, alignments, tokens, NUL termination, nesting, and phandles. Preserve reserved memory and the DTB until consumers finish. Interpret address/size cells, `ranges`, `dma-ranges`, interrupt parents/maps, CPU enable methods, `chosen`, NUMA/topology and bindings in their node context; CPU native endian does not determine DTB byte order. Track overlays and dynamic changes with ownership/lifetime rules. Do not confuse FDT with every Open Firmware interface.

For SMBIOS, distinguish 32-bit and 64-bit entry points and the different table-length/max-size rules. Verify entry-point anchors/checksums, bounded structure length, string index traversal and double-NUL termination, end marker, handles and version-dependent fields. Retain unknown types safely. Treat descriptive inventory as untrusted metadata, not authority for usable RAM or CPU security features. Do not assume tables update after hotplug.

Output: format-specific validation cases and mappings to Linux-visible sysfs/platform inventory, with privacy handling and no fabricated device identity.

### 6. Separate device firmware loading from CPU microcode application

For device firmware, port lookup/request semantics, synchronous versus asynchronous context, cancellation, ownership/release, fallback policy, cache/resume behavior and device removal races. Validate blob compatibility before device transfer. Keep the device quiesced during update and define partial-load failure, reset and DMA cleanup. Signatures or checksums are meaningful only when their trust roots and verification procedure are recorded.

For CPU microcode, derive vendor/family/model/stepping matching, revision rules, image format validation and CPU-wide coordination. Establish early-load ordering relative to feature discovery, mitigation selection and secondary CPU startup; reapply/verify as required during resume and hotplug. Late updates require a distinct hazardous-operation review: shared SMT state, feature changes and non-maskable events make a simple register write or stop-the-world loop insufficient.

Never describe microcode or resident platform firmware as Rust. Do not promise that kernel rollback also rolls back a vendor's irreversible or anti-rollback-protected update. Use sacrificial recoverable lab systems and authorized vendor procedures, not ad hoc firmware flashing.

Output: loader state machines, provenance-linked payload inventory, failure/rollback boundaries, and vendor-specific microcode ordering/safety proof obligations.

### 7. Co-develop emulation and physical qualification from M1

At M1, plan QEMU UEFI/ACPI or FDT fixtures alongside a real system's serial/remote console, controlled power recovery and baseline Linux boot. Compare validated memory maps, tables, interrupt/timer setup and reset behavior without assuming identical table bytes between machines. Capture actual platform/firmware revisions and digests.

As facilities become available, cover real multi-vendor systems, NUMA, IOMMU/DMA isolation, interrupt routing, storage/network firmware, CPU hotplug, error injection, suspend/resume, thermal/power behavior, and security mitigations. Test missing/corrupt tables and blobs in emulation or offline parsers; never mutate production firmware to generate malformed inputs. Use isolated networks and sacrificial disks.

Require runnable Rust-owned firmware qualification cases with documented build inputs, exact invocation/boot procedure, machine selection, safety allowlist, expected observations, timeout/failure handling, log capture and recovery instructions. External reference tools may be non-Rust. A written test list without executable artifacts is not completed testing. Extend the actual [bootstrap parser/handoff cases](../../../docs/implementation.md) rather than describing them as unimplemented; AML, microcode, suspend and physical-platform cases remain outstanding. The delivered [bounded smoke runner](../../../docs/bare-metal-suite.md) is separate host/userspace tooling, not a substitute for those specialized cases.

## Definition of done and stop conditions

A firmware compatibility cell is done only when its parser/interpreter/loader and lifecycle behavior are implemented in Rust, provenance/licensing is resolved, all named semantic and hostile-input tests run, applicable QEMU and physical tests pass with retained evidence, and failures/recovery produce the documented outcomes. Parsing one vendor's tables or running an AML toy method is not full firmware parity. Performance/power observations use the [performance protocol](../../../docs/performance.md).

Apply the exhaustive [definition of done](../../../docs/definition-of-done.md). Only the current workstation is available for physical work now; the user installs/selects/boots a future candidate using the [packaging and recovery design](../../../docs/packaging.md). Do not initiate host boot changes, reboot, firmware updates or destructive experiments. Additional vendors, architectures, remote-console equipment and isolated recovery devices remain explicit lab blockers rather than silently waived requirements.

Stop promotion for unexplained firmware side effects, unbounded AML/parser work, unvalidated physical pointers, missing licenses, unsafe service lifetime, unsupported required AML behavior, absent console recovery, or missing physical evidence. Mark the exact platform/capability blocked or unqualified; do not remove it from the whole-baseline scope. Return records, state machines, executable-test requirements, actual observations, and unresolved blockers without invented boot or benchmark results.

## Primary authorities and source-access limitations

- [Pinned Linux ACPI namespace model](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/firmware-guide/acpi/namespace.rst) explains definition blocks and namespace/device exposure. It is not a complete normative AML grammar.
- [ACPI 6.5 software programming model](https://uefi.org/specs/ACPI/6.5/05_ACPI_Software_Programming_Model.html) and [AML specification](https://uefi.org/specs/ACPI/6.5/20_AML_Specification.html) are normative references to retrieve and pin for implementation. Full direct retrieval returned HTTP 403 during planning research; do not claim full clause-by-clause conformance review.
- [UEFI 2.10 boot services](https://uefi.org/specs/UEFI/2.10/07_Services_Boot_Services.html) defines the memory-map/exit contract; relevant excerpts were available through search, while direct retrieval returned HTTP 403. [Pinned Linux EFI stub behavior](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/admin-guide/efi-stub.rst) supplies baseline image and boot-argument behavior, not every UEFI runtime obligation.
- [Device Tree flattened format](https://devicetree-specification.readthedocs.io/en/stable/flattened-format.html) defines block layout, endian rules, versioning and reservations. Pin the specification edition and relevant bindings before implementation.
- [DMTF SMBIOS 3.9.0, DSP0134](https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.9.0.pdf) sections 5–6 define entry points, bounded structures and strings; do not assume every older machine implements this edition.
- [Pinned Linux firmware request API](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/driver-api/firmware/request_firmware.rst) and [microcode loader](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/arch/x86/microcode.rst) distinguish loading lifecycles and late-update hazards.
- [Pinned Linux licensing rules](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/process/license-rules.rst) require preserving per-file licenses and applicable exceptions; they do not license external vendor blobs.
