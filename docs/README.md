# Documentation index

The repository contains a real Rust `no_std` x86_64 bootstrap with maintained QEMU evidence and an actual unsigned diagnostic ALPM package, alongside the original planning inventory and host tools. [Implementation and evidence](implementation.md) distinguishes historical manual `cell9` and initial planning results from `target/kernel-tooling/integrated-002`, `integrated-003` and final current-source-bound `integrated-004`, each of which returned 0 with eight matched cases. The real failed `integrated-001` 7/8 CSI-framing verdict remains retained. Independent director default-PNG reviews and separate bounded artifact/provider inspections are identified there, not inferred from capture-time pending fields.

[Diagnostic handoff](diagnostic-handoff.md) records the actual unsigned `target/kernel-tooling/diagnostic-001` package, read-only archive inspection, fresh project-owned extraction, metadata/checksum/source-binding evidence and exact artifact identities. Director independently opened and accepted the actual archive's format/source boundary, and the documented build succeeded from a new writable packaged-source copy. Neither is installation, a signature, approved SBOM, independent reproducibility or physical qualification. Host Rust1.88 strict Clippy/46 tests and separate final nightly strict-Clippy/51-test/format/check/status gates passed; [implementation](implementation.md) retains their distinct scope and raw evidence.

M1 is underway, not complete; no physical boot, full Linux compatibility or performance qualification is claimed. The complete Linux 6.18.57 scope remains mandatory. Read the [project entry point](../README.md) first. A link to a plan is not evidence of implemented support.

## Program and engineering contracts

| Document | Purpose |
| --- | --- |
| [Implementation and evidence](implementation.md) | Actual bootstrap mechanisms, exact source/toolchain provenance, historical manual versus current maintained runs, distinct host gates and bounded artifact/provider reviews |
| [Kernel tooling](kernel-tooling.md) | Exercised Rust-owned `kernel-build`, `kernel-test` and `kernel-package` interfaces, prerequisites, fresh-output rules and bounded evidence contracts |
| [Diagnostic handoff](diagnostic-handoff.md) | Actual unsigned package, ALPM/source/checksum inspection, independent archive format/source review, delivered-source consumer build and user-operated safety limits |
| [Architecture](architecture.md) | Accepted modular monolithic direction, bounded bootstrap, ownership/unsafe contexts and remaining full-scope design |
| [Definition of done](definition-of-done.md) | Exhaustive per-unit, subsystem, milestone and full-kernel closure requirements; standing completion rule |
| [Packaging](packaging.md) | Separate storage-free diagnostic handoff versus Linux-replacement prerequisites, actual boot formats and user-controlled recovery |
| [Roadmap](roadmap.md) | Dependency-ordered M0–M8 work packages and correctness, performance, and physical-hardware exit gates |
| [Decisions](decisions.md) | Original and later approved requirements, distinct engineering choices, unresolved blockers and change discipline |
| [Compatibility](compatibility.md) | Exact Linux behavioral boundary, userspace ABI and configuration semantics |
| [Coverage](coverage.md) | Pinned upstream inventory, longest-prefix routing, scope gaps, and limits of structural coverage |
| [Dependencies](dependencies.md) | Candidate/rejected crates, bundling, runtime suitability, supply-chain and licensing admission |
| [Toolchain](toolchain.md) | Host and target compiler/linker/configuration strategy and reproducibility prerequisites |
| [Licensing](licensing.md) | Direct-port notices, SPDX expressions, syscall exceptions, and firmware provenance |
| [Verification](verification.md) | Differential, regression, adversarial, stress, recovery and actual smoke evidence |
| [Performance](performance.md) | At-least-Linux release requirement, fair measurements, noise control, confidence, and optimization policy |
| [Bare metal](bare-metal.md) | Physical lab, serial/recovery, multi-vendor platforms, DMA/NUMA, destructive-test isolation, and platform gates |
| [Maintenance](maintenance.md) | Security response, upstream version drift, release policy, and sustained qualification |
| [Research](research.md) | Primary-source evidence, source pinning, assumptions, and research method |
| [Project audit](project-audit.md) | Rust host CLI, structural planning checks, negative fixtures, and precisely bounded audit claims |
| [Bare-metal suite](bare-metal-suite.md) | Actual bounded nondestructive Rust smoke runner, command, outcomes, privacy and qualification limitations |
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
