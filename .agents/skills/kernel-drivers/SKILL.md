---
name: kernel-drivers
description: "Design, port, and review Rust Linux-compatible drivers and shared device infrastructure. Use for device IDs, probe/remove, MMIO, DMA, IOMMU, interrupt handling, unplug, reset, power management, firmware loading, or physical-device qualification."
---

# Kernel driver engineering

## Scope and current contract

Use for bus/device enumeration and binding, register access, DMA/IOMMU, interrupt delivery, device lifecycle, firmware loading, power management, and driver-family ports. Pair storage and network drivers with [kernel-storage](../kernel-storage/SKILL.md) or [kernel-networking](../kernel-networking/SKILL.md), page ownership with [kernel-memory](../kernel-memory/SKILL.md), and architecture/firmware boundaries with [kernel-architecture](../kernel-architecture/SKILL.md), [kernel-firmware](../kernel-firmware/SKILL.md), and [kernel-unsafe](../kernel-unsafe/SKILL.md).

First read [repository instructions](../../../AGENTS.md), [approved decisions](../../../docs/decisions.md), [driver plan](../../../docs/subsystems/drivers.md), [architecture plan](../../../docs/subsystems/architectures.md), [firmware plan](../../../docs/subsystems/firmware.md), [compatibility](../../../docs/compatibility.md), and [reference metadata](../../../planning/reference.tsv). Consult [coverage](../../../docs/coverage.md), [dependencies](../../../docs/dependencies.md), [licensing](../../../docs/licensing.md), [verification](../../../docs/verification.md), [performance](../../../docs/performance.md), and [bare-metal requirements](../../../docs/bare-metal.md) before proposing acceptance.

Initial behavioral baseline: Linux 6.18.57. Implement kernel code in Rust, without legacy C modules or a C-backed driver runtime. External firmware/microcode is allowed only with explicit provenance, licensing, version, and trust records; it is not Rust implementation. Use kernel `no_std` and context-aware fallible allocation, not a blanket heap ban. QEMU is the first debug target, not the hardware-support contract. All driver families and remaining architectures remain in final scope; a VirtIO proof does not close physical-device coverage. The [current bootstrap](../../../docs/implementation.md) has checked ACPI discovery, a legacy PIC/PIT cell and bounded framebuffer diagnostics, with `ws-drivers-acpi` routed `in_progress`. It does not implement the complete driver model, DMA/IOMMU, storage/NIC drivers or physical-device qualification; other driver workstreams remain `not_started`.

Accepted architecture: modular monolithic Rust kernel. Feature scope is fixed to upstream Linux 6.18.57 with explicitly reviewed security deltas; record each delta's behavior, rationale, tests, and compatibility/performance impact. Later feature-baseline changes require a separate decision. Every in-baseline module's functionality needs a Rust replacement; arbitrary proprietary/out-of-tree modules are not implicitly included. Function-local `asm!` and `naked_asm!` are allowed only where unavoidable, with operation/register/memory/clobber/privilege proofs, reviewers, and disassembly checks; no `global_asm!` or standalone assembly escape.

## Establish primary evidence

Identify the exact upstream driver family, bus, device/subsystem IDs and revisions, quirks, Kconfig combinations, UAPI, dependencies, and relevant workstream IDs. Read pinned code plus hardware specifications/errata for that exact revision. Separate vendor promises, Linux implementation facts, and proposed Rust policy. Preserve direct-port notices and per-file license exceptions.

Pinned primary starting points:

- [DMA mapping guide](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/core-api/dma-api-howto.rst): CPU virtual, CPU physical, and device/bus addresses differ; coherent memory still requires ordering; streaming mappings have ownership and synchronization obligations.
- [Device I/O guide](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/driver-api/device-io.rst): accessor width/endianness, mapping modes, ordering, and posted-write completion. Rust volatile access alone is not a portable substitute.
- [Driver binding](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/driver-api/driver-model/binding.rst): matching is bus-specific. Check lifecycle details against pinned implementation rather than treating historical overview prose as complete current semantics.
- [Managed resources](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/driver-api/driver-model/devres.rst): partial-probe rollback and resource release; resource ownership does not remove caller synchronization and error checks.
- [Runtime PM](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/power/runtime_pm.rst): callback contexts, usage/child counts, exclusion, error handling, and active/suspended postconditions.
- [Firmware requests](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/driver-api/firmware/request_firmware.rst): synchronous/asynchronous lifetime and context requirements, plus resume availability.

## Ordered decision workflow

Answer all six decisions for each bus or driver subfamily, not once for the entire hardware tree.

1. **Port behavior and hardware coverage.** Enumerate matching rules, IDs/revisions, quirks, negotiation, device-node/sysfs/ioctl/netlink behavior, error reporting, reset, suspend, and removal. Linux internal driver ABI is not a stable external module contract. Port functionality into Rust replacements, not a loader for old C modules. Preserve required user-visible behavior while allowing safer internal representations.
2. **Evaluate reusable components.** Inspect exact crate version, license, transitive implementation, supported transports, allocation behavior, concurrency, DMA address model, memory barriers, and teardown. [virtio-drivers](https://docs.rs/virtio-drivers/latest/virtio_drivers/) is a candidate for VirtIO mechanisms, not automatic Linux driver or physical-hardware parity: its documented HAL and page-size/address assumptions need explicit adaptation and tests. Audit any MMIO/register or device-tree/ACPI helper for the same constraints. Do not run blind installers or adopt embedded runtimes that assume exclusive single-core ownership.
3. **Consolidate the right layer.** Reuse device identity/reference lifetime, bus-resource ownership, DMA mappings, interrupt registration, work cancellation, firmware loading, power dependencies, and error-recovery machinery. Share per-family queue/transport mechanisms only where actual hardware semantics agree. Keep reset sequences, endian rules, quirks, and ordering requirements explicit rather than burying them in one universal register abstraction.
4. **Simplify without erasing support.** Use narrow typed resources, explicit acquisition rollback, validated capability sets, and one lifecycle state machine per real device relationship. Early polling or one queue can be a declared bring-up mode, not a replacement for final interrupts, multiqueue, PM, or hot-unplug behavior. Never guess that a matching vendor ID means every revision works, delete legacy-family coverage, or silently force IOMMU passthrough.
5. **Review security and invariants.** Complete the state/ownership review below, treating both device-provided bytes and user requests as untrusted. Safety comments must explain the actual hardware and concurrency proof, not merely say the pointer is nonnull.
6. **Improve after correctness.** Measure doorbells, interrupts, DMA map/unmap, bounce copies, allocation, cache traffic, queue affinity, and lock contention. Consider batching, pooling, interrupt moderation, queue-local state, and reduced barriers only when hardware and architecture proofs allow them. Preserve bounded latency, power, security isolation, and error recovery; a faster QEMU path alone is not an improvement claim.

## Domain implementation workflow

### Enumeration, IDs, and probe

- Record the bus-specific match tuple: for example vendor/device/subsystem/class/revision or ACPI/device-tree identifiers, compatible-string order, and required properties. Include negative matches and conflicting drivers. Keep a per-ID/revision evidence matrix; an upstream directory inventory is not that matrix.
- Validate resource lengths, BAR/window arithmetic, alignment, register access width, capability-list termination, and firmware tables before use. Claim resources before publishing interfaces. Negotiate features as an intersection of verified device and driver capabilities, with explicit handling of unknown or mandatory bits.
- Model discovery, probing, deferred dependency resolution, active, quiescing, suspended, resetting, failed, and detached states where applicable. Specify every transition's lock/context, publication point, permitted callbacks, acquired resources, and rollback. Probe failure at each stage must leave no runnable callback or DMA referencing released memory.

### MMIO, DMA, and IOMMU

- Give CPU virtual, CPU physical, MMIO resource, port-I/O, and device DMA addresses distinct types/contracts. Do not derive DMA addresses by casting a virtual pointer. Describe device address masks, coherent versus streaming constraints, scatter/gather segment limits, bounce buffers, alignment, cacheline isolation, and map failures.
- Specify DMA state transitions: CPU initializes buffer, mapping/sync transfers ownership, descriptor publication precedes doorbell, device owns access, completion is ordered/validated, CPU regains ownership, then unmap/reuse. Pin user pages through the memory subsystem; keep mapping direction and all partial-map cleanup explicit. A coherent allocation does not eliminate ordering between descriptor fields and ownership bits.
- State the IOMMU domain/permission policy, isolation group limitations, mapping lifetime, fault handling, and invalidation completion before reuse. Where supported, review device translation caches/ATS, PASID, shared virtual addressing, and revocation with the relevant architecture and device specifications. Missing translation support is a blocker, not permission to pretend physical and bus addresses are equal.
- For every MMIO operation record mapping memory type, bounds, width, alignment, byte order, read/write side effects, read-modify-write legality, barrier domain, and posted-write flush/readback rule. A compiler fence, CPU fence, DMA barrier, and bus readback solve different problems. Do not expose device-owned registers or buffers as unconstrained ordinary mutable references.

### Interrupts, teardown, and power

- Define hard-IRQ, threaded/deferred, and poll contexts, interrupt sharing, mask/ack/rearm order, edge/level behavior, MSI/MSI-X vector allocation, affinity, and interrupt storms. No sleeping or reclaim-capable allocation in forbidden contexts. Synchronize completion with queue state and avoid a lost interrupt between draining and rearming.
- On normal remove, stop new external submissions/publication, serialize against PM/reset, disable or quiesce device work as hardware permits, synchronize interrupt handlers, drain/cancel deferred callbacks, retire DMA and translations, and release resources only after all possible users are excluded. Specify the exact device-specific order; this list is not a universal hardware sequence.
- Surprise unplug differs: MMIO reads may fault or return unusable values and the device may not honor shutdown. Ensure outstanding requests fail/wake with the correct errors, descriptors remain valid until safe retirement, and stale completions cannot target a newly probed device. Rust `Drop` and reference counting do not themselves stop hardware. Blocking/fallible teardown needs an explicit authorized context, not arbitrary destructor execution under a spinlock.
- Review reset, runtime suspend/resume, system suspend/hibernate, shutdown, wake sources, parent/child power dependencies, usage counters, and concurrent open/I/O/remove. A successful suspend transition must meet its no-device-traffic contract; a failed transition must not falsely publish a working device. Resume must reestablish mappings, queues, interrupt state, features, and required firmware before admitting I/O.
- For firmware record origin, digest, license/redistribution terms, version/revision binding, verification policy, parser bounds, upload/reset sequence, asynchronous cancellation, missing-image failure, and availability after resume/reboot. Never fabricate firmware, fetch arbitrary code into privileged execution, or label a blob Rust-only.

## Mandatory invariant review

Provide a resource/lifecycle table covering each MMIO mapping, IRQ, DMA buffer, IOMMU mapping, pin, callback, work item, firmware buffer, and published handle. For each: creator, owner, borrowing rules, context, ordering, failure cleanup, retirement proof, and tests.

Review at least these counterexamples:

- Device DMA continues after the last software reference is dropped.
- Unplug/reset occurs between reading a capability and using a register or between queue submission and interrupt completion.
- A completion, timeout, and cancellation race to finish the same request or reuse its queue tag.
- A failed DMA mapping is treated as an address, or memory is reused before IOMMU/device-cache invalidation completes.
- A firmware callback or deferred worker runs after remove; an IRQ handler observes half-published probe state.
- PM powers down a parent with an active child, or resumes external access before state restoration.
- Device lengths, addresses, identifiers, and descriptors overflow arithmetic, escape DMA permissions, or disclose stale kernel memory.

## Definition of done and required evidence

A driver change is done only when every applicable row has evidence; mark unavailable requirements blocked rather than waived. The [observed bootstrap cell](../../../docs/implementation.md) is limited ACPI/interrupt/diagnostic evidence, not execution or completion of every driver obligation below.

| Obligation | Required observable evidence |
| --- | --- |
| Behavioral coverage | Exact IDs/revisions/features and UAPI/errors mapped to pinned source, tested positive and negative matches, and all callers migrated without C runtime shims. |
| Resource correctness | Failure injection after every probe acquisition; concurrent submit/completion/cancel/remove/reset/PM tests; no leaked pins, mappings, IRQs, handles, or double completions after quiescence. |
| Device isolation | DMA-mask and map failures, IOMMU faults/revocation, hostile descriptors, invalid registers/capabilities, and interrupt storms exercise verified error paths. |
| Emulation and physical execution | QEMU debug evidence plus named physical machines from initial M1 bring-up onward; real DMA/IOMMU, interrupt, storage/network traffic, reset, unplug, PM, firmware, and vendor/revision coverage appropriate to the driver. |
| Runnable hardware suite | Exact existing Rust-owned runner invocation, suite/case IDs, boot artifact digest, target machine identity, transport/console setup, expected oracle, timeout, safe recovery, exit status, and raw logs. A prose test list or nonexistent command does not satisfy execution. |
| Performance | Matched pinned-Linux per-device/workload throughput, latency/tails, CPU, memory, initialization/startup, and power; repetitions, confidence intervals, firmware/queue/topology/mitigation controls, with no hidden individual regressions. |

Use the [verification plan](../../../docs/verification.md) to select model/unit, differential, regression, adversarial, stress, and recovery cases. Include interrupt/poll budget edges and device fault injection, not only successful data transfer. Pure register fakes cannot prove bus ordering or DMA coherency. Record multiple platform/CPU vendors and expand physical-device families alongside QEMU; VM success cannot substitute for physical qualification.

Apply the standing [definition of done](../../../docs/definition-of-done.md). The project's actual [bounded smoke suite](../../../docs/bare-metal-suite.md) is available through this repository-root interface:

```text
cargo run -p baremetal -- run --output <new-directory> --label <label> --expect-release <exact-osrelease> --environment <reference|qemu|bare-metal>
```

Choose one environment value and an exact expected running release, and use a new output directory. This is non-destructive functional smoke, not a DMA/IOMMU/MMIO/IRQ/PM/firmware or full-driver qualification suite. Its environment label is an operator assertion, not proof of physical hardware; reference-host success validates the runner only. Record individual pass/fail/skip/unavailable outcomes. Broader driver qualification needs its own genuinely runnable cases and evidence; never invent commands for unimplemented runners.

Only the current workstation is available initially; additional CPU/platform vendors and physical-device revisions are named blockers, not assumed resources. Suite metadata must not collect unique hardware serial IDs. The user personally installs/selects/boots candidates; never perform host install, boot/reboot, firmware, raw-device, privilege-elevation, or system-setting changes by default. [Packaging and recovery](../../../docs/packaging.md) separates the existing storage-free diagnostic ELF from Linux-replacement packaging, which still needs real storage/durable filesystem/root/initramfs/init/userspace and broader gates. Preserve the working kernel and recovery path; the native Limine diagnostic is not direct systemd-boot EFI/PE/Linux-image compatibility and has no physical pass. Initial Arch/CachyOS userspace and balanced server profiling do not imply downstream CachyOS kernel patches.

Run destructive resets, firmware experiments, and storage tests only on isolated lab devices with remote-console recovery, known-good boot fallback, and sacrificial media. Keep networking in an isolated lab. Run checks only when explicitly assigned to execute them; planning and delegated edit tasks must hand off gates to the integration owner. At-least-Linux performance is a release requirement, not currently demonstrated; inconclusive results are not passes and disabling mitigations is not an optimization.

## Stop conditions and handoff

Stop activating unsafe hardware paths when the register specification, DMA lifetime, IOMMU isolation, interrupt ordering, firmware provenance, or quiescence proof is missing. Stop a physical test before it can damage non-lab media, escape the lab network, or lose recovery access. Do not replace a missing device with a fabricated match or conceal an unavailable test platform.

Hand off the six decisions, upstream provenance, ID/revision matrix, capability and resource tables, lifecycle/ordering proofs, complete caller migration, tests actually executed versus planned, reproducible performance records, physical-suite artifacts, missing hardware/specifications, and exact qualification boundaries. Update owned plans/changelog as required; no scripts or installers are bundled with this skill.
