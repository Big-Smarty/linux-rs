# Documentation index

This is an index. **Start with the two pages that say what is true now:** the [current status](implementation.md#current-status) (what exists, what was tested at which commit, what is open) and [next steps](next-steps.md) (the working queue: each open item with its status, dependencies and acceptance test). Everything else is either a contract (what the finished kernel must do), a subsystem plan, or chronological history that names the commit or artifact it describes.

The repository is a Rust `no_std` x86_64 kernel for Linux 6.18.57 behaviour that runs processes, threads and unmodified Linux programs on one CPU in QEMU, with Rust host tooling for the build, the QEMU suite and a structural audit. M1 is underway, not complete; no physical boot, full Linux compatibility or performance qualification is claimed, and the complete Linux 6.18.57 scope remains mandatory. Read the [project entry point](../README.md) first. A link to a plan is not evidence of implemented support. Historical records (the `cell9` and `integrated-*` runs, the withdrawn `diagnostic-001`/`002` packages) are kept in [implementation](implementation.md) and [diagnostic handoff](diagnostic-handoff.md); only corrected `diagnostic-003` is conditionally cleared, and only for the user's unchanged separate-media/recovery procedure.

## Program and engineering contracts

| Document | Purpose |
| --- | --- |
| [Next steps](next-steps.md) | The working queue from the external audit: status at `main`, evidence, remaining work and acceptance test per item |
| [Implementation and evidence](implementation.md) | The authoritative current-status section, the maintained routing table, then lane-by-lane records and exact source/toolchain provenance as chronological history |
| [Kernel tooling](kernel-tooling.md) | The Rust-owned `kernel-build`, `kernel-test`, `kernel-package` and `baremetal-suite` interfaces, prerequisites and known gaps, fresh-output rules, case catalog |
| [Diagnostic handoff](diagnostic-handoff.md) | The separate storage-free diagnostic package lineage: which archive is conditionally cleared (`diagnostic-003` only), its inspection records and the user-operated safety limits |
| [Architecture](architecture.md) | What is implemented at `main` (process state, services, scheduler, VFS, memory ownership, locking exceptions), then the accepted modular monolithic direction and the remaining full-scope design |
| [Definition of done](definition-of-done.md) | Exhaustive per-unit, subsystem, milestone and full-kernel closure requirements; standing completion rule |
| [Packaging](packaging.md) | Separate storage-free diagnostic handoff versus Linux-replacement prerequisites, actual boot formats and user-controlled recovery |
| [Roadmap](roadmap.md) | The complete program and inventory (not the day-to-day queue): idiomatic Rust architecture and abstractions, crate strategy, M0–M8 work packages with exit gates, coverage map and risks |
| [Decisions](decisions.md) | Original and later approved requirements, distinct engineering choices, unresolved blockers and change discipline |
| [Compatibility](compatibility.md) | A short current support matrix, then the exact Linux behavioral boundary, userspace ABI and configuration semantics that are required |
| [Coverage](coverage.md) | Pinned upstream inventory, longest-prefix routing, scope gaps, and limits of structural coverage |
| [Dependencies](dependencies.md) | Candidate/rejected crates, bundling, runtime suitability, supply-chain and licensing admission |
| [Toolchain](toolchain.md) | How the host and kernel compilers are selected today, and the target compiler/linker/configuration strategy and reproducibility prerequisites |
| [Licensing](licensing.md) | Direct-port notices, SPDX expressions, syscall exceptions, and firmware provenance |
| [Verification](verification.md) | What each command establishes (host tests, candidate-kernel execution, reference-Linux observation, historical evidence); the differential, regression, adversarial, stress and recovery program |
| [Performance](performance.md) | At-least-Linux release requirement, fair measurements, noise control, confidence, and optimization policy |
| [Bare metal](bare-metal.md) | Physical lab, serial/recovery, multi-vendor platforms, DMA/NUMA, destructive-test isolation, and platform gates |
| [Maintenance](maintenance.md) | Security response, upstream version drift, release policy, and sustained qualification |
| [Research](research.md) | Primary-source evidence, source pinning, assumptions, and research method |
| [Project audit](project-audit.md) | Rust host CLI `check`/`status`, structural planning checks, current counts, negative fixtures, and precisely bounded audit claims |
| [Bare-metal suite](bare-metal-suite.md) | The user-run kernel suite (prepared, never run on hardware; groups in the [current status](implementation.md#current-status)) and the bounded nondestructive Rust smoke runner for an existing Linux: commands, outcomes, privacy and qualification limits |
| [Skills guide](skills.md) | Index and operating instructions for all sixteen local kernel skills |

## Subsystem implementation plans

Each plan must connect concrete implementation order to Linux-facing traps, usable or unsuitable dependencies, shared mechanisms, safe simplifications, security invariants, improvement opportunities, and observable evidence. Use the source inventory to find the owning workstream; do not assume this short index exhausts upstream scope.

| Plan | Responsibility |
| --- | --- |
| [Core](subsystems/core.md) | Boot/core runtime, locking, timing, workqueues, common mechanisms and build-support closure |
| [Memory](subsystems/memory.md) | Physical/virtual memory, allocators, reclaim, OOM, NUMA, DMA-facing memory and accounting |
| [Process](subsystems/process.md) | Scheduler/tasks, ELF, syscalls, signals, credentials and process lifecycle |
| [Storage](subsystems/storage.md) | Block/character storage infrastructure, queues, caching, ordering, error recovery and durability |
| [Filesystems](subsystems/filesystems.md) | VFS, pseudo/network/disk filesystems, namespace semantics and filesystem-family closure |
| [Networking](subsystems/networking.md) | Socket/network core, packet path, protocol families, routing, filtering and network controls |
| [IPC](subsystems/ipc.md) | Pipes, Unix sockets and process communication/synchronization interfaces |
| [Drivers](subsystems/drivers.md) | Device/bus/resource model and every baseline driver family, including desktop, accelerators and legacy devices |
| [Architectures](subsystems/architectures.md) | x86_64 first and all baseline architecture/ABI/backend closure |
| [Firmware](subsystems/firmware.md) | UEFI/ACPI/device-tree interfaces, firmware loading, microcode, trust and power/platform lifecycle |
| [Security](subsystems/security.md) | Credentials, capabilities, isolation, LSM, integrity, cryptography, mitigations and adversarial boundaries |
| [Observability](subsystems/observability.md) | Logs, tracing, perf, debugging, crash capture, instrumentation and introspection ABIs |
| [Virtualization](subsystems/virtualization.md) | Guest and host virtualization, KVM-facing compatibility and architecture extensions |
| [Extensions](subsystems/extensions.md) | Rust module lifecycle, eBPF and other extension mechanisms without legacy C module loading |

Performance and physical-hardware gates in these plans compose with [performance](performance.md) and [bare metal](bare-metal.md); subsystem-local VM success never waives physical qualification.

## Machine-readable scope

- [Reference metadata](../planning/reference.tsv): selected release, tag, commit/tree identities, retrieval and signature caveats.
- [Workstreams](../planning/workstreams.tsv): exactly five columns (`id`, `upstream_prefix`, `plan`, `priority`, `status`); status is only `not_started` or `in_progress`. The canonical [routed implementation status](implementation.md#routed-implementation-status) names every current `in_progress` owner and its revision-specific Rust-path/evidence binding; all other rows remain `not_started`.
- [Upstream paths](../planning/upstream-paths.tsv): complete pinned Git-tree entries and longest-path-component-prefix workstream assignments.

These files contain metadata, not imported Linux source or completed per-ABI/device evidence. The audit's `status` reports planning counts, not a compatibility percentage.

## Repository workflow and all local skills

[AGENTS.md](../AGENTS.md) and [CONTRIBUTING.md](../CONTRIBUTING.md) govern work; [CHANGELOG.md](../CHANGELOG.md) records implementation, documentation and tooling changes, and [LICENSE](../LICENSE) supplies the project license. The root [Cargo workspace](../Cargo.toml) includes the bootstrap documented in [implementation](implementation.md), the [host audit/build/test/package tooling](../xtask/Cargo.toml) and [Rust command dispatcher](../xtask/src/main.rs), and the [smoke package](../baremetal/Cargo.toml) and [Rust smoke implementation](../baremetal/src/main.rs). Host tooling is not kernel runtime implementation; reference-host smoke tests the runner, not the new kernel. [Kernel tooling](kernel-tooling.md) and [diagnostic handoff](diagnostic-handoff.md) separate command examples from retained execution and package-inspection records.

The [skills guide](skills.md) is the canonical index for these **sixteen** project-local skills:

1. `kernel-porting`
2. `kernel-abi`
3. `kernel-unsafe`
4. `kernel-concurrency`
5. `kernel-memory`
6. `kernel-drivers`
7. `kernel-storage`
8. `kernel-networking`
9. `kernel-verification`
10. `kernel-security`
11. `kernel-dependencies`
12. `kernel-documentation`
13. `kernel-architecture`
14. `kernel-firmware`
15. `kernel-performance`
16. `kernel-release`

Skills are operating guidance, not implementation, normative upstream behavior, or an excuse to relax project constraints. In particular, generic embedded advice must not replace the kernel's fallible, context-aware heap allocation design.

## Reading paths

- **First implementer:** architecture → decisions → roadmap → toolchain → compatibility → core/memory/process → verification/performance/bare-metal.
- **Subsystem owner:** coverage/workstreams → relevant plan → dependencies/licensing → shared core contracts → verification/performance → maintenance.
- **Reviewer/release owner:** decisions → reference metadata/research → compatibility/coverage → security → verification/performance/bare-metal → project audit/maintenance.

No schedule is implied by this reading order. Exact release selection and the distinction between userspace and internal ABI follow the primary sources cited in the [entry point](../README.md) and [architecture](architecture.md).
