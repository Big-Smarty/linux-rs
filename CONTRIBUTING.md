# Contributing

## What exists, and what does not

**Task boundary.** Scope is set by the user's decisions A18–A21 in the [decision register](docs/decisions.md), not by this page. What is implemented, tested and open at the checked-out commit is the [current status](docs/implementation.md#current-status), and the ordered work queue with an acceptance test per item is [next steps](docs/next-steps.md); work follows those two pages and the [roadmap](docs/roadmap.md) work packages through the branch-and-PR flow below. It does not waive any whole-kernel requirement. See [AGENTS.md](AGENTS.md).

This is an implementation program for a Rust-only port of the complete Linux **6.18.57 LTS** behavioral baseline. It contains architectural/subsystem plans, a pinned structural inventory, local agent skills, the Rust `xtask` host auditor/build/QEMU/package interfaces, a Rust `baremetal` bounded non-destructive functional smoke suite for existing Linux, and a real GPL-2.0-only `no_std` x86_64 bootstrap kernel. [Implementation](docs/implementation.md) distinguishes actual maintained Limine/OVMF QEMU execution from historical manual evidence; [diagnostic handoff](docs/diagnostic-handoff.md) owns the separate package lineage. The current implementation request supersedes the original planning-only boundary; it does not close M1 or the full Linux scope.

The canonical [routing table](docs/implementation.md#routed-implementation-status) identifies the current `in_progress` workstreams; all other rows remain `not_started`. These states mean routed implementation is underway, not complete translation of a prefix or a Linux-compatibility percentage. Real storage and durable filesystems, networking, SMP/NUMA/RT, full mitigation/platform closure, physical boot/recovery and performance qualification remain open, and the Linux userspace and syscall surface that exists is bounded (see the [support matrix](docs/compatibility.md#current-support-matrix)). M0 is still conditional on its remaining [roadmap](docs/roadmap.md) evidence/decision/review/hardware gates.

**Physical authority:** diagnostic-001/002 remain permanently withdrawn. Director accepted only the exact corrected diagnostic-003 lineage for the unchanged conditional separate-media/recovery procedure; see [current handoff identities and requirements](docs/diagnostic-handoff.md). Fresh008 fatal/returning-PF evidence, independent bounded repair review and actual package/source-consumer records do not qualify later/rebuilt artifacts or establish physical success.

Start with [AGENTS.md](AGENTS.md), [architecture](docs/architecture.md), [decisions](docs/decisions.md), [coverage](docs/coverage.md), and [skills](docs/skills.md). [Toolchain](docs/toolchain.md), [implementation](docs/implementation.md), and [kernel tooling](docs/kernel-tooling.md) distinguish declared host requirements from the exact exercised kernel compiler. A Cargo manifest's minimum Rust version is a declaration, not proof it was tested. Do not install packages, change global skill/toolchain configuration or download large source/lab artifacts without an explicit task that requires it; commit only on a feature branch under the flow below.

The accepted architecture is a **modular monolithic Rust kernel**, not an open architecture choice. Both function-local `asm!` and `naked_asm!` are allowed only where unavoidable under [the assembly proof contract](AGENTS.md); standalone assembly and `global_asm!` escape hatches are forbidden. Feature scope stays fixed at upstream Linux 6.18.57 with explicit reviewed security deltas, whose provenance, rationale, compatibility effects and regression/security/performance evidence must be recorded. Later feature-baseline changes require a separate decision. Every in-baseline module's functionality must be ported; arbitrary proprietary/third-party out-of-tree module functionality requires separately enumerated approval and is not implied by “complete Linux scope.”

## Branches, pull requests and evidence

1. Work on a feature branch (a git worktree under `target/worktrees/` keeps the checkout clean, but `git worktree remove` deletes its ignored `target/`: first move its `target/kernel-tooling/` runs and gate logs to `target/evidence-archive/<worktree>/` in the main checkout and cite that path; see [known evidence losses](docs/implementation.md#known-evidence-losses)), commit focused changes, and open a pull request; do not push to `main` directly ([A20](docs/decisions.md)).
2. Pick one reproducible failure or missing capability from [next steps](docs/next-steps.md) (or record a new one in that format): one bounded change, one acceptance test. Do not combine a refactor with a semantic change.
3. A change to behaviour carries an executable test that goes through the real syscall or runtime path: a host unit test for pure logic, a `user/init` oracle row recorded on the pinned Linux first, or a `kernel-test` case. Directly editing a test model's fields does not test a setter-to-consumer connection. Record the command, configuration, artifacts and results (failures and `unavailable` cases included) in the pull request and, for a lane, in a new section of [implementation](docs/implementation.md); do not repeat the project history.
4. Obtain independent review covering the scope [AGENTS.md](AGENTS.md#evidence-review-performance-and-physical-hardware) requires, fix findings, then run the [gate sequence](docs/kernel-tooling.md#gate-sequence) (not yet one committed command, [next steps, item 6](docs/next-steps.md#item-6-reproducible-verification-off-the-original-workstation)). Merge only when every gate passes ([A20](docs/decisions.md)). A worker told to skip gates leaves them to the integration owner.
5. Update the pages that state status in the same change: the [current status](docs/implementation.md#current-status), [next steps](docs/next-steps.md), the [support matrix](docs/compatibility.md#current-support-matrix) where support changed, and a [CHANGELOG](CHANGELOG.md) line.

## Real host structural-audit commands

From the repository root, with the host toolchain prerequisites satisfied:

```text
cargo +1.88.0 run --offline --locked -p xtask -- check
cargo +1.88.0 run --offline --locked -p xtask -- status
```

These are **host structural-audit commands**, not kernel build or boot commands. `check` validates the local planning structure: inventory/reference schemas and consistency, ownership routing and plan existence, supported local Markdown links, skill metadata, and prohibited executable source extensions. It does not fetch upstream, verify signatures, inspect external dependencies or final machine code, prove unsafe soundness, run Linux tests, or establish semantic/performance parity. `status` reports structural workstream/inventory counts and recorded `not_started` / `in_progress` states, **not a percentage of Linux working** or completion of a routed prefix. See [the auditor specification and limitations](docs/project-audit.md) for the exact parser, link subset, diagnostics, and root handling.

For an integration owner validating an isolated negative-case fixture, the CLI also supports:

```text
cargo run -p xtask -- check --root /absolute/path/to/disposable-fixture
cargo run -p xtask -- status --root /absolute/path/to/disposable-fixture
```

Never corrupt the working inventory to manufacture a failing test. A negative fixture is a disposable copy with a deliberate, named defect. Preserve command, exit status, diagnostic, fixture mutation, tool version, and artifact location. Do not label an expected rejection as an unqualified test-suite pass. `--root` is not permission to follow external symlinks or modify unrelated trees.

Historical host integration results remain in [the audit evidence](docs/project-audit.md#observed-initial-host-integration-evidence) and [changelog](CHANGELOG.md); they are not a claim that subsequent edits or newly integrated commands have already passed. For delegated tasks explicitly excluding gates, skip all builds/tests/linters/formatters and hand off to the integration owner. Report “not run” rather than guessing. Any other checks must be scoped to code that actually exists and recorded as such.

## Runnable reference and bare-metal smoke suite

The repository-owned Rust `baremetal` executable is real functional test tooling, not a kernel implementation or complete qualification suite. Its interface is:

```text
cargo run -p baremetal -- run --output <new-directory> --label <label> --expect-release <exact-osrelease> --environment <reference|qemu|bare-metal>
```

Replace each placeholder with the intended value; `--environment` takes exactly one of the three labels, not the angle-bracket expression. Choose a **new** output directory, preferably under ignored `lab/artifacts/` or outside the checkout; existing output directories are refused, not overwritten. Supply the exact running kernel release you intend to test, not the project's future baseline by assumption. The explicit environment label is an operator assertion, **not proof** of physical hardware or of the kernel's origin.

Read [the suite's cases, results, and limitations](docs/bare-metal-suite.md) before execution. It performs bounded memory/thread, sandboxed filesystem/sync/rename/link, TCP/UDP/Unix loopback, process exec/wait/exit, and proc/sysfs visibility smoke checks, reporting per-case failures/skips/unavailable states and environment metadata without hardware serial IDs. It does not mount filesystems, write raw devices, change system settings, elevate privileges, reboot, update firmware, or invoke destructive external tests. Permission limits are reported rather than bypassed. Preserve output reports, exact command/configuration, and failures; a host reference run validates only the runner on the host kernel, not a new kernel.

The user personally installs/selects/boots physical candidates on the currently available workstation. Agents MUST NOT perform host package installation, bootloader/boot-entry changes, reboot, firmware changes, mounts, raw-device/destructive-disk actions or elevation. Initial userspace is Arch/CachyOS userspace, not downstream CachyOS kernel patches; the performance policy is balanced server. The eventual Linux-replacement kernel must install as a separate Arch-like package with selectable Limine/systemd-boot entries and preserve the working kernel/recovery path.

The real bootstrap ELF permits preparation of a **storage-free M1 diagnostic trial**, not a Linux-replacement installation. Such a trial may precede rootfs/initramfs/userspace only on separate user-owned recoverable media with independent known-good recovery, scoped QEMU evidence and a reviewed user-operated procedure. Use `freestanding` without `qemu-self-test`; the physical profile does not assume COM1 or QEMU's debug-exit device. Native Limine ELF is not Linux boot-protocol/PVH/native EFI/PE or systemd-boot compatibility. No physical boot/recovery pass follows from artifact existence or read-only workstation observations. See [packaging](docs/packaging.md), [definitions of done](docs/definition-of-done.md), and [physical-hardware safety](docs/bare-metal.md). A Linux-replacement package still requires the real storage, durable filesystem, root/initramfs/init/userspace and broad qualification prerequisites. Additional vendor/platform/NUMA/IOMMU/device coverage remains blocked until genuine targets/evidence exist.

## Current kernel commands and evidence boundaries

The maintained Rust-owned interfaces are documented in [kernel tooling](docs/kernel-tooling.md). These are generic examples using unused output names, not transcripts of the observed immutable runs; complete the fresh-run checks and default-screenshot review in [diagnostic handoff](docs/diagnostic-handoff.md) before packaging:

```text
cargo +1.88.0 run --offline --locked -p xtask -- kernel-build --output target/kernel-tooling/build-001
cargo +1.88.0 run --offline --locked -p xtask -- kernel-test --output target/kernel-tooling/test-001 --timeout-seconds 60
cargo +1.88.0 run --offline --locked -p xtask -- kernel-package --build-output target/kernel-tooling/test-001/freestanding-build --output target/kernel-tooling/package-001
```

Choose fresh direct-child output paths under `target/kernel-tooling/`; existing paths are refused. Follow installed-tool/compiler, isolated-output, firmware, timeout and artifact contracts. Require the **complete current case catalog**, fresh default visual acceptance and required independent/codegen review before packaging, not a stale fixed case count. Keep all executable/member sources and compiler inputs frozen through packaging/source-consumer proof. The package consumes the selected real default build without rebuilding/installing it; follow [diagnostic handoff](docs/diagnostic-handoff.md).

History: [implementation](docs/implementation.md) and [diagnostic handoff](docs/diagnostic-handoff.md); later review records never rewrite capture-time pending fields. Withdrawn 001/002 can never be booted, and no installation, signing/SBOM/legal, independent or bit-for-bit reproduction, physical success or replacement-kernel claim follows from any of it. No full-kernel benchmark or qualification command or result exists. Private SMP/platform work and object/rootfs research are not landed features.

### Compiler requirements and actual owned checks

Host MSRV **1.88** is a tested engineering floor, not user-selected. Select only `-p xtask -p baremetal`; `kernel`, `rt` and `user/init` declare 1.101. The current gate counts are in the [current status](docs/implementation.md#current-status). Target-specific Clippy for the four kernel profiles of the [gate sequence](docs/kernel-tooling.md#gate-sequence) must pass `--config <run>/freestanding-build/cargo-home/config.toml`, the per-run merged vendor source that `kernel-test` writes, because `-Zbuild-std` needs rust-src's vendor directory too. Final structural audits are separate. Exact compiler selection: [toolchain](docs/toolchain.md#compiler-selection-as-it-is-today).

The kernel manifest declares **1.101**, distinct from its exact exercised runtime compiler: `rustc 1.101.0-nightly`, commit `5c543b0b8c73c7b72bc8284ced4fb22ead15734d`, LLVM **23.1.1**, with matching `rust-src`, `rust-lld`, and rebuilt `core`/`compiler_builtins` for `x86_64-unknown-none`. The installed `nightly` alias is mutable; artifact manifests must bind the actual commit and inputs. Do not substitute host/stable `core`, install a target globally, or treat a package MSRV as proof of interrupt-ABI qualification. Qualified-nightly host workspace checks can include the kernel parser library; the freestanding binary is feature-gated and requires its separate target/build-std commands.

The historical `cell9` kernel host checks used the qualified compiler:

```text
cargo fmt -p kernel
cargo clippy -p kernel --lib --tests --locked -- -D warnings
cargo test -p kernel --lib --locked
```

[The historical owned strict-lint record](docs/implementation.md#final-owned-strict-lint-gate) preserves successful execution of those commands, five production-parser tests, and release-target Clippy for both `qemu-self-test` and `freestanding`. For freestanding Clippy, `-Zbuild-std` flags go **after** the external `clippy` subcommand; use the exact documented commands rather than moving them ahead of it. The inherited `core` soft-float future-incompatibility warning remains visible and unsuppressed. These are integration/repository verification results, not new detailed user approvals or proof of physical/full-Linux qualification.

Dependencies live in checked-in `vendor/` (offline, `--locked`); add or update one only through the [vendor workflow](docs/kernel-tooling.md#vendored-dependencies-and-the-fresh-clone-build) after [dependency admission](docs/dependencies.md), and run `xtask check` (it verifies every vendored package's checksum and the `cargo metadata` graph).

Initial Limine/OVMF and M1 sequencing are engineering choices under the general implementation request. Each new executable interface still MUST document and retain its exact command, toolchain/configuration, immutable artifacts, success/failure criteria, timeouts, recovery and safety limits. QEMU bring-up and physical-machine preparation are co-developed from M1; the missing physical execution cannot be fabricated or closed with a VM pass. See [toolchain](docs/toolchain.md), [verification](docs/verification.md), [bare metal](docs/bare-metal.md), and [performance](docs/performance.md).

## Select the exact owning plan

Use [workstreams](planning/workstreams.tsv) and [upstream paths](planning/upstream-paths.tsv), with longest **path-component-aware** prefix ownership. `net` is not a prefix match for an unrelated `network` path. [Coverage](docs/coverage.md) describes structural scope and limitations. Read the pinned upstream source for the concrete mechanism and configuration, not only a directory name or this table.

| Change area | Required plan entry points |
| --- | --- |
| Interrupts, clocks, locking, RCU, SMP, scheduler | [Core](docs/subsystems/core.md), [process](docs/subsystems/process.md) |
| Allocation, VM, page tables, reclaim, NUMA | [Memory](docs/subsystems/memory.md), [architectures](docs/subsystems/architectures.md) |
| Tasks, ELF, signals, syscalls, namespaces, cgroups | [Process](docs/subsystems/process.md), [compatibility](docs/compatibility.md) |
| Block I/O, device mapper, persistence, VFS and filesystems | [Storage](docs/subsystems/storage.md), [filesystems](docs/subsystems/filesystems.md) |
| Protocols, sockets, netlink, packet paths | [Networking](docs/subsystems/networking.md), [IPC](docs/subsystems/ipc.md) |
| IPC, futexes, pipes, shared memory | [IPC](docs/subsystems/ipc.md), [process](docs/subsystems/process.md) |
| Devices, buses, DMA, power management, hotplug | [Drivers](docs/subsystems/drivers.md), [firmware](docs/subsystems/firmware.md) |
| CPU families, boot/entry, ABI, MMU, atomics | [Architectures](docs/subsystems/architectures.md), [core](docs/subsystems/core.md) |
| Firmware, microcode, ACPI, device tree, boot trust | [Firmware](docs/subsystems/firmware.md), [licensing](docs/licensing.md) |
| Credentials, isolation, crypto, LSM, attack surfaces | [Security](docs/subsystems/security.md), [verification](docs/verification.md) |
| Tracing, perf, debugging, accounting interfaces | [Observability](docs/subsystems/observability.md), [performance](docs/performance.md) |
| Hypervisors and virtualization interfaces | [Virtualization](docs/subsystems/virtualization.md), [architectures](docs/subsystems/architectures.md) |
| Modules, BPF, programmable extensions | [Extensions](docs/subsystems/extensions.md), [security](docs/subsystems/security.md) |
| Crates, licensing, compiler/build tooling | [Dependencies](docs/dependencies.md), [licensing](docs/licensing.md), [toolchain](docs/toolchain.md) |
| Inventory, plans, documentation and local skills | [Coverage](docs/coverage.md), [research](docs/research.md), [project audit](docs/project-audit.md), [skills](docs/skills.md) |

Every change also considers [verification](docs/verification.md), [performance](docs/performance.md), and [bare metal](docs/bare-metal.md). Cross-subsystem ownership is explicit; do not silently duplicate another owner's shared mechanism.

## Five design questions for every task

Answer these for each concrete workstream/subfamily that the task changes. A global paragraph saying “port it safely” is not a design. Record exact source/configuration assumptions, dependencies, trade-offs, and unresolved blockers in the owning plan or review description.

1. **Can I use a preexisting crate?** Evaluate concrete candidates and alternatives, including no dependency. Record licensing/provenance, selected/transitive features and sources, `no_std`, allocation/failure/panic behavior, unsafe/architecture assumptions, maintenance/security, generated/native code, and integration cost. Reject C-backed kernel bridges and native-code transitive shortcuts. An evaluation is not permission to add the crate.
2. **Can I bundle functionality together?** Name the common primitives, owning API, lifetime/locking/allocation contracts, callers to migrate, and any Linux-visible distinctions that must remain. Share implementation where semantics permit; do not merge independent policy or ABI behavior merely because names look similar.
3. **Can I simplify things?** Identify implementation-only simplifications and how equivalence will be established. Sequencing, internal types, and deduplicated machinery may change; omitted protocols/devices/architectures, broad no-op/`ENOSYS` fallbacks, weakened security, and erased edge cases are not simplifications. If none is justified, say so.
4. **Is this secure?** Identify assets, trust boundaries, attacker-controlled inputs, permissions, resource-exhaustion paths, memory/unsafe and concurrency invariants, userspace/DMA ownership, rollback/teardown, and exploit mitigations. State concrete review, negative/adversarial/fault-injection tests, remaining risks, and blockers; neither Rust nor a passing happy-path test proves security.
5. **How can I improve this?** Name measurable opportunities, trade-offs, unavoidable work, correctness argument, differential tests, per-workload metrics, physical hardware/QEMU coverage, and rejection criteria while preserving compatibility, correctness, security, and baseline-or-better performance. A faster average cannot hide a regressing required workload or tail. Unmeasured opportunities remain proposals.

**Additionally mandatory:** give an ordered implementation/port plan with dependencies. Name the pinned Linux mechanisms, ABI/semantic traps, configurations/architectures, prerequisites, steps, observable definitions of done, and required evidence. Explain error paths, privilege boundaries, concurrency, resource exhaustion, and recovery rather than listing only happy-path entry points. The ordered plan does not replace any of the five answers.

## Definitions of done: no implied qualification

Every task MUST provide an explicit, exhaustive definition of done for its named scope, derived from the exact pinned source/configuration/architecture inventory and Linux-visible behaviors. The list must name edge/error/security/recovery paths as well as success, the required executable checks and their observables, review owners, hardware/configuration matrix, and the evidence location. Link each acceptance item to implementation and actual test/review evidence before closing it. A generic “all tests pass,” directory count, or completed document is not exhaustive behavioral coverage.

| Deliverable being claimed | Required completion evidence |
| --- | --- |
| Planning/setup contribution | Complete assigned plans and five-question answers, ordered dependencies and concrete definitions of done; primary provenance; consistent inventory routing/status; portable skill/link updates; actual host audit/smoke results recorded by the integration owner. Any unresolved provenance or decision gate remains explicit. This establishes only planning/tooling properties. |
| Implemented mechanism | Complete in-scope Linux semantics and architecture/configuration cases; callers migrated; reviewed Rust-only dependencies/generated linkage; unsafe/allocation/locking/security proofs; executable positive, boundary, negative, adversarial, failure, concurrency, and recovery tests; retained reference differential results and regressions; no stubs, fake fallbacks, or missing required evidence. |
| Initial platform/boot bring-up | Real build/boot artifacts and reproducible commands; expected console milestones, assertions, failure/timeout criteria, recovery; actual QEMU execution **and** a safe physical-target execution path from initial bring-up. Missing bare-metal equipment/evidence blocks the corresponding qualification; it cannot be marked complete using QEMU alone. |
| Runnable bare-metal test suite | The current [Rust smoke suite](docs/bare-metal-suite.md) supplies actual bounded non-destructive cases and commands for an existing running Linux environment; report actual runner execution separately from candidate-kernel evidence. Full kernel qualification additionally requires exhaustive cases for the hardware/feature matrix in the owning plan and [bare-metal contract](docs/bare-metal.md), hardware/firmware/configuration records, safe destructive-test opt-in for any future destructive cases, serial/remote-console capture, timeouts/recovery, per-case pass/fail/skip/blocker with reasons, and genuine candidate physical execution evidence. The structural auditor, bounded smoke alone, or VM-only run cannot establish full qualification. |
| Performance-qualified target/workload | Correctness/security gates passed; matched pinned-Linux comparison; throughput/latency/tails/CPU/memory/startup/power as applicable; repeated measurements, confidence intervals and controlled noise; each required workload/hardware item meets at-least-baseline criteria without hidden regressions or mitigation changes. Inconclusive or unmeasured items are not passes. |
| Full parity/release | Every pinned workstream and required behavioral/device/architecture/configuration item closed by traceable implementation, review, regression/differential/adversarial/stress/recovery evidence; executable physical/QEMU suites and performance qualification; complete source/license/supply-chain evidence, documented artifacts/reproduction/support/maintenance. No required uncovered item, hardware blocker, or arbitrary scope exclusion may be relabeled done. See [roadmap](docs/roadmap.md), [verification](docs/verification.md), and [maintenance](docs/maintenance.md). |

An acceptance record distinguishes **implemented**, **tested**, **qualified**, **blocked**, and **not started** claims in prose/evidence. The structural `planning/workstreams.tsv` retains exactly the five columns `id`, `upstream_prefix`, `plan`, `priority`, `status`, and accepts only `not_started` / `in_progress`. The promoted IDs are mapped to actual Rust paths and revision-specific evidence in [implementation](docs/implementation.md); none means a complete upstream prefix is translated. Do not add a `done` state, qualification columns or invented percentages. Any later machine-readable implementation/evidence schema needs an explicit coordinated migration and auditor update, not reinterpretation of this routing inventory.

The cross-project [definition-of-done contract](docs/definition-of-done.md) specifies exhaustive closure requirements, while [packaging](docs/packaging.md) distinguishes storage-free M1 diagnostics from a Linux-replacement package and its user-operated installation/recovery. The standing full-completion rule remains mandatory; the real initial bootstrap and host/Linux smoke tools do not satisfy it.

## Change lifecycle and review evidence

1. **Research and scope.** Read the relevant local skills and exact plans. Use [reference metadata](planning/reference.tsv) to identify the baseline. Cite primary source commit/path and relevant lines/symbols; distinguish observed upstream facts from proposed Rust design and unresolved blockers. Preserve the original GitHub-only retrieval history separately from the later independent kernel.org/GitHub object match and local good tag signature. The verified primary fingerprint `647F28654894E3BD457199BE38DBBDC86092693E` was pinned through kernel.org HTTPS signature-page and WKD/TLS publication; GPG reported `TRUST_UNDEFINED` / `[unknown]`, not Web-of-Trust or ultimate trust. [Implementation source evidence](docs/implementation.md#pinned-source-and-specification-map) identifies raw output at `target/implementation-prereqs/upstream-verification.txt`. Follow [research](docs/research.md) and [maintenance](docs/maintenance.md) for baseline updates; never update only a version string.
2. **Provenance and legal review.** This is a GPL-2.0-only direct source port, not clean-room work. Preserve original attribution, notices, SPDX expressions, UAPI exceptions, and per-file obligations. Record transformations and new authorship. See [licensing](docs/licensing.md) and [upstream license rules](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/process/license-rules.rst). An inventory blob hash is a structural source identifier, not proof of redistributed source compliance or local signature validation.
3. **Design first.** Answer the five questions; define shared interfaces and lock-order edges with affected owners. Record accepted/rejected crate decisions in [dependencies](docs/dependencies.md). Kernel allocation is fallible/context-aware, unsafe is justified locally, and Rust-only restrictions cover executable tools as well as runtime code. Review generated/link-time inputs. Preserve exact compatibility; do not import upstream C as a temporary bridge.
4. **Implement a bounded complete change.** Migrate affected callers, tests, docs, skills, inventory routing, and provenance together. Do not delete obscure upstream entries to make scope look finished. Distinguish planning updates from implementation evidence. Follow the [roadmap](docs/roadmap.md) prerequisite gates; work may overlap only after real dependencies permit it.
5. **Review before acceptance.** Obtain independent relevant subsystem review and security/unsafe/architecture review where affected. The review records must address userspace validation and TOCTOU, DMA ownership, allocation failure/reclaim, atomic ordering, per-CPU migration, SMP/hotplug, RCU grace periods, callback/destructor contexts, lock-order cycles, permissions/accounting, denial of service, and cleanup. Check semantic error precedence and partial operations, not just Rust type correctness. Describe performance costs as well as gains, following [upstream change-description guidance](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/process/submitting-patches.rst).
6. **Run applicable gates and report truthfully.** The integration owner executes applicable checks once combined changes land; a delegated no-gates assignment must not start competing builds/tests/linters/formatters. Record current kernel parser/QEMU results separately from host structural-audit/smoke results, and extend semantic differential/regression/adversarial/stress/recovery tests as mechanisms become reachable under [verification](docs/verification.md). Co-develop [physical hardware](docs/bare-metal.md) with QEMU from initial bring-up. Qualification requires [performance](docs/performance.md) at least the real pinned Linux baseline with comparable security/configuration and statistical evidence; no arbitrary allowed regression, aggregate-only hiding, or security-disabled wins. Missing equipment is a named blocker, not a VM-equivalent pass.
7. **Hand off complete evidence.** Include changed paths, purpose/user-visible effects, source links, five-question answers, actual commands/configurations/artifact hashes, exit statuses and results, reviews, assumptions, failures/skips, unavailable hardware, and remaining qualification blockers. Update [CHANGELOG](CHANGELOG.md) for permanent changes. Never claim “audit passed,” “booted,” “Linux compatible,” or “faster than Linux” without actual corresponding evidence. A planning-only change cannot establish kernel support.

## Lab safety and artifact handling

Keep large downloaded reference trees, raw images, captures, benchmark output, serial logs, and crash dumps outside tracked source under designated ignored locations or an explicitly recorded external path. Existing bootstrap evidence is under `target/kernel-first-boot/`, prerequisite provenance under `target/implementation-prereqs/`, and maintained harness outputs under `target/kernel-tooling/`; `lab/artifacts/` and `lab/external/` remain designated lab locations. Retain reviewable manifests, configuration, source provenance, checksums, concise results, and reproducer instructions in versioned records; ignored artifacts are local evidence, not a checked-in distribution. Never use ignored paths for code or to evade scans, overwrite historical evidence, or stage a mutable shared ELF as an immutable run input. Sanitize secrets and personal data before sharing evidence.

Physical testing uses isolated lab networks and sacrificial disks with a proved recovery path. Never target the running contributor host's storage or a production network. If the necessary physical target or safe recovery is unavailable, record the exact blocker and finish only safe reachable work. Do not substitute an invented QEMU result or postpone all hardware work to final release.
