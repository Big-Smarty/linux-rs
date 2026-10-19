---
name: kernel-release
description: "Prepare evidence-qualified Rust-only kernel releases: exhaustive compatibility closure, provenance, reproducibility, SBOM and security deltas, Linux-baseline performance, physical lab gates, Arch-style selectable boot packaging, and rollback. Use for milestone promotion or release readiness."
---

# Kernel release

## Release boundary

A plan, inventory, successful build, first boot or functional smoke run is not a completed Linux-compatible kernel. The earlier planning-only boundary is historical: the [implementation record](../../../docs/implementation.md) distinguishes frozen cell9 evidence, the actual maintained integration/diagnostic-package checkpoint and subsequent source revisions. Its canonical routing table names every `in_progress` owner under the unchanged [five-column/two-status schema](../kernel-documentation/SKILL.md); none is a completed upstream prefix. The unsigned diagnostic archive and retained local evidence are not a qualified Linux-replacement package. No physical candidate boot/recovery, performance pass, full M1 or full-kernel completion is supplied.

The standing completion rule is exhaustive: the future kernel is not done until every promised Linux 6.18.57 compatibility cell is implemented and evidence-qualified. Priority orders work; it does not remove architectures, legacy protocols, drivers, filesystems, desktop/audio/graphics, embedded/RT or obscure facilities from scope. A limited milestone artifact must state its exact limitations and must not be advertised as full parity.

The approved design is modular monolithic Rust, with fixed 6.18.57 feature scope plus explicit reviewed security deltas. Every in-baseline module's functionality must have a Rust replacement. Arbitrary proprietary or third-party out-of-tree module functionality is not implicitly promised; additions require separately enumerated and approved scope. A later feature-baseline change requires a separate decision.

Read the [definition of done](../../../docs/definition-of-done.md), [compatibility contract](../../../docs/compatibility.md), [coverage ledger](../../../docs/coverage.md), [verification protocol](../../../docs/verification.md), [roadmap](../../../docs/roadmap.md), [performance protocol](../../../docs/performance.md), [bare-metal contract](../../../docs/bare-metal.md), [smoke suite contract](../../../docs/bare-metal-suite.md), [packaging design](../../../docs/packaging.md), [licensing policy](../../../docs/licensing.md), and [maintenance plan](../../../docs/maintenance.md).

## Required inputs

- Immutable candidate source revision, exact upstream tag/commit/tree and verification status, dependency lock/source set, target/configuration manifests, and proposed release claims.
- Exhaustive compatibility/workstream ledger with behavioral cells and per-file provenance; a Git-path inventory alone is only structural coverage.
- Test-suite revisions, commands, artifacts, raw logs/results, environment manifests and links to failures, skips and unavailable hardware.
- Reproducible-build instructions, unsigned/signed artifact identities, SBOM, license/notices set, security delta, packaging/install design and recovery/rollback procedures.
- Named reviewers and release approvers; no automated tool or unchecked attestation substitutes for the technical evidence it summarizes.

## Ordered workflow

### 1. Freeze identity, scope and promises

Resolve the exact Linux baseline through [reference metadata](../../../planning/reference.tsv); retain signed-tag object, peeled commit/tree, retrieval source and actual signature verification. A hosting service's `verified` field is not independent local verification. The later [local source evidence](../../../docs/implementation.md) records matching kernel.org/GitHub objects and GPG “Good signature”, with signer fingerprint pinned through kernel.org HTTPS/WKD; GPG still reports `TRUST_UNDEFINED` / `[unknown]`, not Web-of-Trust or ultimate trust. Preserve the original GitHub-only retrieval history. Record any missing authentication as a blocker to the corresponding provenance claim, not as an invented successful verification.

Freeze candidate revision, configurations, target/backend/toolchain versions, dependency features and source digests. Define a release ID, qualification window, supported userspace/platform configurations, selected workloads and approved claims. Initial userspace is Arch/CachyOS userspace; downstream CachyOS kernel patch behavior is not silently included. Use the approved balanced server profile while preserving all final-scope workloads.

Output: a release manifest and claim-to-cell mapping. A changing candidate invalidates affected evidence unless a reviewed dependency analysis establishes exactly why it remains applicable.

### 2. Close every promised compatibility cell explicitly

Reconcile the structural inventory against semantic inventories: architectures/endian/word-size/MMU/noMMU/ABI variants; boot/entry/SMP/power; memory/process/scheduling/IPC; syscall/ioctl/netlink/sysfs/procfs and other Linux-visible interfaces; filesystem formats/durability; block/storage stacks; network protocols; drivers and devices; namespaces/cgroups/security; observability; virtualization/extensions; error paths and recovery. Preserve per-device and per-format distinctions rather than one row saying “drivers complete”.

For each cell require the upstream authority, implemented Rust paths, supported configuration, invariant/safety review, executable tests, baseline differential oracle, real outcomes, evidence digests and a responsible reviewer. Include successful behavior, negative/error/permission semantics, concurrency, resource exhaustion, cancellation, teardown, stress and recovery. Explain test coverage limitations. A suite passing one architecture or one data layout does not qualify another.

Classify test/qualification outcomes as passed, failed, inconclusive, skipped/unavailable or not implemented in their owning evidence records. These are not workstream status values: the five-column TSV permits only `not_started` and `in_progress`. Full-parity promotion requires every promised cell to be implemented and passed. Missing hardware, unsupported compiler backends, ENOSYS walls, C fallbacks and untested edge paths are blockers, not acceptable closure shortcuts. Do not mark upstream documentation/build/metadata workstreams implemented merely because executable subsystems exist.

Output: a complete closure report with zero hidden exclusions and explicit reasons for every nonpassing cell. Milestone promotion and full-kernel completion are different decisions.

### 3. Bind runnable tests and actual smoke evidence to the candidate

Require exact suite revisions, build/run commands, images, input seeds, userspace versions, timeout rules, expected outcomes and actual exit status. Retain raw differential, regression, adversarial, stress, durability/crash-recovery, security, performance and hardware results, not only a green dashboard. State which controls/oracles were used and which uncertainties remain.

The delivered bounded functional runner is invoked as:

```text
cargo run -p baremetal -- run --output <new-directory> --label <label> --expect-release <exact-osrelease> --environment <reference|qemu|bare-metal>
```

Choose one environment value and substitute the exact expected running release; placeholders are not a literal runnable command. The output directory must be new. Follow the [suite instructions](../../../docs/bare-metal-suite.md) for actual case behavior and artifact names. The environment label is the operator's assertion, not proof of physical execution. A reference-host run validates the runner only, not the planned kernel. When eventually run on a candidate, its bounded memory/threads, sandbox files/sync/rename/links, loopback sockets, process lifecycle and proc/sysfs observations remain smoke coverage, not full parity, power, DMA, hardware fault or performance certification.

Do not fill absent candidate results with reference-kernel output. Do not infer driver durability or physical-device coverage from sandbox files and loopback traffic. Broader qualification suites remain explicit implementation obligations until they actually exist and execute.

Output: evidence index bound to candidate/configuration/platform identity, with a separate smoke record and a test-gap report.

### 4. Enforce QEMU and physical gates from M1, not only M8

M1 promotion needs actually executed QEMU plus real x86_64 boot/entry/console/exception/timer/recovery cases and the rest of its contract, not only planned tests. The [cell9 observations](../../../docs/implementation.md) cover a narrow QEMU bootstrap cell; they do not close M1 or the physical path. M2 adds SMP, memory/TLB/cache/ordering and lifecycle cases; later milestones add the corresponding real storage, networking, firmware/power, security and userspace cases as dependencies land. QEMU is the first debug target, not authority for physical timing, DMA coherency, interrupt behavior, vendor firmware or power.

Only the current workstation is available now. The user personally installs/selects/boots a future candidate and reports evidence. Never run host install, boot-entry changes, reboot, firmware updates, raw-device writes or destructive tests on the user's behalf. The bounded runner must not mount, elevate, change system settings or control firmware. Preserve the existing working kernel and recovery media before candidate operations.

Keep additional vendor/architecture systems, NUMA, IOMMU/DMA, real disks/NICs, hotplug, suspend, thermal/power, error injection and remote-console/controlled-power recovery requirements in the physical qualification matrix. Unavailable lab capabilities are named blockers, never replaced by VM passes. Destructive recovery/error experiments require separately authorized isolated equipment, sacrificial media and a reviewed procedure; the workstation smoke path does not authorize them.

Output: milestone-by-platform gate table, operator instructions, retained real results and a physical acquisition/access blocker list.

### 5. Require Linux-baseline performance and security together

Apply the [performance protocol](../../../docs/performance.md): identical effective hardware/configuration/security and matched meaningful compiler settings, preregistered workload/metric matrix, independent repetitions, noise controls and familywise 99% one-sided zero-regression confidence bounds. Every selected metric for every promised workload/platform must independently pass; aggregate/geometric-mean gains do not mask regressions. Inconclusive or unmeasured is not passed. Physical throughput/latency/tails/CPU/memory/startup/power evidence cannot be replaced by QEMU timing or the functional smoke runner.

Create a security delta against both the pinned baseline and the prior candidate/release: upstream fixes and unresolved vulnerabilities, mitigations and configuration, authorization/isolation, crypto/trust roots, unsafe/assembly changes, dependency advisories, debug/profiling exposure, firmware/microcode revisions, and known limitations. Distinguish fixed issues, not-applicable with evidence, and unresolved issues. Do not claim a direct port automatically inherits every upstream fix or deliberately retain a known vulnerability to preserve a benchmark.

Output: per-cell performance decision and reviewed security delta. Correctness/security failures block release regardless of benchmark wins.

### 6. Verify provenance, Rust-only boundaries, licenses and SBOM

For each ported source file retain upstream path/commit/object, license expression/notices/exceptions and downstream transformation/review history. Preserve direct-port obligations; do not relabel it clean-room or erase original attribution. Check redistributed dependency and firmware terms individually, including binary payloads and generated artifacts.

Create a versioned machine-readable SBOM using an agreed standard such as SPDX or CycloneDX. Include project packages, exact transitive dependency versions/features/digests, runtime/compiler helpers, linked objects, generated/vendored code, bundled firmware/microcode, license expressions and relationships. Distinguish shipped runtime contents, build tools, external test oracles, and platform-resident firmware outside the package. Record external trust dependencies even when not redistributed. An SBOM is inventory, not a security certificate.

Audit actual build inputs and link artifacts for C/native dependencies, build-script downloads, unexpected helpers and legacy C modules. Rust extensions on source filenames alone do not prove machine-code provenance. Only unavoidable function-local `asm!` and `naked_asm!` are allowed, each with operation-specific necessity/safety/disassembly proof; no `global_asm!`, standalone assembly or C shim. External compilers/linkers, reference Linux, existing userspace, external suites and authorized firmware remain explicitly external, not falsely counted as Rust implementations.

Output: provenance/notices bundle, SBOM, source/linked-artifact review and unresolved licensing/trust findings.

### 7. Establish reproducibility without weakening security

Define the exact artifact set whose bytes must reproduce: kernel/image formats, debug symbols, initramfs and packaged metadata as applicable. Pin all inputs and build-environment attributes; control timestamps, paths, locales, archive order/ownership, user/host identity, dependency resolution and generated randomness according to the toolchain/security design. Do not remove hardening or publish private signing keys to obtain equal hashes.

Build in independent clean environments and compare the specified unsigned artifacts byte-for-byte/digests. Retain commands, environment descriptions, logs, artifacts and mismatch analysis. If signatures or authorized external inputs are nondeterministic, define and attest the unsigned-to-signed transformation and verification separately; do not call differing final artifacts bit-reproducible. Reproducibility is distinct from correspondence to reviewed source, signature trust and correctness.

Use provenance attestations with subject digests, resolved input digests, build instructions/parameters and builder identity. SLSA is a possible model, not a claimed certification level; only claim levels whose actual requirements are met. Independent verification includes trust policy and signatures, not just a JSON field saying “verified”.

Output: reproduction report and artifact/provenance manifests, with any mismatches or unverifiable trust steps blocking the affected claims.

### 8. Qualify packaging, boot selection and rollback before distribution

Distinguish an isolated **storage-free M1 diagnostic** from a **Linux-replacement package** under the [packaging design](../../../docs/packaging.md). The existing `freestanding` ELF may support a user-operated trial on separate recoverable media with independent known-good recovery before rootfs/initramfs/userspace exists; it is not physically qualified or M1-complete. It uses native Limine and a validated 32bpp framebuffer, not QEMU-only COM1/debug-exit devices, and cannot be directly loaded as a systemd-boot EFI/PE/Linux image. A Linux-replacement package still requires real storage and durable filesystem support, root/initramfs, init/userspace, configuration and module/replacement layout, broader qualification and actual supported loader formats. Use a separate package/version/artifact namespace and preserve the working kernel and default/recovery path. Never replace missing prerequisites with a fake kernel package, empty payload or placeholder PKGBUILD.

Project-owned executable packaging logic must be Rust; external pacman/mkinitcpio/boot tooling may be used through the approved interface. Declarative package/configuration data does not permit a shell implementation hidden in hooks. Define integrity verification, Secure Boot signing if applicable, initramfs firmware/license inclusion and release-specific ABI/module policy. No legacy C modules may be loaded as a compatibility escape.

Test installation, boot selection, failed/partial installation, interrupted update, missing initramfs, signature rejection, uninstall and return to the known-good kernel in disposable/recoverable environments before offering user-operated procedures. Rollback must state on-disk format compatibility, persistent state, key/variable changes, anti-rollback rules and irreversible firmware boundaries. Never promise that replacing a kernel reverses a filesystem format upgrade or a microcode/firmware update.

Output: real package artifact identities when available, installation/boot-selection evidence, reviewed non-destructive operator instructions and demonstrated recovery/rollback evidence. Packaging design alone is not package qualification.

### 9. Publish the evidence-bound decision and maintain it

Have independent owners review unresolved cells, security/performance/provenance/reproduction/lab/package results and claim wording. Publish exact qualified versions/configurations, evidence locations/digests, exclusions for any explicitly limited milestone, known issues and actionable recovery instructions. Full-parity wording requires no missing promised cells; a time deadline or majority pass cannot override the standing rule.

For ongoing maintenance, track upstream security/stable changes and new dependency/firmware risks, update provenance and SBOM, and invalidate/rerun evidence for affected cells. Baseline upgrades require an explicit decision and renewed qualification; do not silently compare against a moving Linux version. Define withdrawal/revocation, incident handling and rollback communication before release.

Output: signed/reviewed release decision tied to immutable artifacts and an evidence-preservation/maintenance owner.

## Exhaustive definition-of-done rule

Use [the authoritative definition of done](../../../docs/definition-of-done.md) as the checklist, not a substitute invented here. A full kernel release requires all promised cells implemented in Rust, source/licensing/runtime provenance resolved, all relevant semantic/security/stress/recovery gates genuinely executed and passed, complete architecture/device/firmware/physical qualification, per-cell nonregressing Linux-baseline performance, reproducible identified artifacts, SBOM/security delta, validated selectable packaging and recovery/rollback, and approved evidence-bound claims. Every criterion must have an artifact and reviewer; missing or inconclusive evidence is unfinished work.

Report the exact observed bootstrap scope and only checks the integration owner actually executes; retained earlier evidence must be identified as such. Initial-cell sequencing is an engineering decision, and strict Clippy is integration verification/repository policy rather than a new detailed user approval. Host MSRV 1.88 is a separate engineering metadata baseline, not the kernel's exact nightly 1.101 compiler/build-std identity or proof of host 1.88 execution. Do not mark M0 unconditional solely because files exist or M1–M8 complete because a runner or one QEMU bootstrap cell works.

## Stop conditions

Stop promotion for any promised cell missing, fabricated/stale evidence, security regression, unmatched baseline, statistical non-pass, licensing gap, unknown linked implementation provenance, irreproducible required artifact, unverified signature claim, unsafe packaging/recovery, or absent required physical evidence. Finish reachable review work and name exact blockers; never silently narrow full-kernel scope.

## Primary sources

- [Pinned Linux licensing rules](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/process/license-rules.rst) distinguish whole-kernel licensing, per-file licenses and syscall exceptions.
- [Pinned Linux reproducible builds](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/kbuild/reproducible-builds.rst) identifies timestamps, paths, signing and randomized inputs; its destructive cleanup examples are not instructions to run on this workspace.
- [Reproducible Builds definition](https://reproducible-builds.org/docs/definition/) requires bit-identical specified artifacts from the same declared inputs/environment/instructions.
- [SLSA v1.1 provenance model](https://slsa.dev/spec/v1.1/provenance) identifies subjects, build definition, resolved dependencies and builder/run details. This is a versioned design reference, not a claim that the project has achieved a SLSA level or that provenance proves behavioral compatibility.
