# linux-rs

A whole-kernel, direct-source Linux-to-Rust porting program targeting the behavior of **Linux 6.18.57 LTS**. The intended result is a Rust-implemented kernel that runs existing Linux userspace on every architecture and facility in the pinned baseline, with performance at least as good as the reference Linux kernel on the qualified workload/hardware matrix.

**Current status: v0.1.0, a bounded Rust bootstrap plus first-userspace checkpoint, not a completed Linux kernel.** After the earlier publication checkpoint the user asked to continue with a first-userspace slice and a complete roadmap ([A18–A20](docs/decisions.md)); both are delivered and recorded in the [v0.1.0 checkpoint](docs/implementation.md#v010-continuation-checkpoint) (the [publication checkpoint](docs/implementation.md#publication-checkpoint) remains as history). The GPL-2.0-only `no_std` x86_64 kernel uses Limine base revision5 and QEMU q35/TCG/OVMF; the implementation record distinguishes this checkpoint from the full port. [Diagnostic handoff](docs/diagnostic-handoff.md) governs the separate immutable003 package only.

Fourteen of the 2,623 structural workstreams are `in_progress`: `ws-arch-x86-entry`, `ws-arch-x86-kernel`, `ws-arch-x86-mm`, `ws-drivers-acpi`, `ws-drivers-tty`, `ws-fs`, `ws-init`, `ws-kernel`, `ws-kernel-exit-c`, `ws-kernel-locking`, `ws-lib`, `ws-mm`, `ws-mm-mmap-c`, and `ws-mm-page-alloc-c`; 2,609 remain `not_started`. These labels route actual bootstrap, indexed-buddy, borrowed-image inspection and first-userspace slice work (one static `/init` in ring 3 under a declared configuration), **not** complete upstream prefixes, a Linux-compatibility percentage, or milestone completion. The [ledger](planning/workstreams.tsv) retains its five-column schema and the [routing table](docs/implementation.md#routed-implementation-status) binds each active row to source and limits.

M0 still has unresolved decision/review/hardware obligations, and M1 is not complete. No physical candidate boot/recovery, general Linux userspace/syscall/rootfs (only the single-`/init` slice exists), scheduler, durable filesystem, networking, SMP/NUMA, real-time, full mitigation, full-baseline compatibility, or performance qualification is claimed. All remain mandatory; neither host-tool results nor the initial QEMU cell closes them.

## Start here

1. Read the [architecture](docs/architecture.md), [approved decisions and unresolved questions](docs/decisions.md), and [dependency-ordered M0–M8 roadmap](docs/roadmap.md).
2. Establish the [compatibility contract](docs/compatibility.md), [complete structural coverage inventory](docs/coverage.md), and [reference provenance](planning/reference.tsv).
3. Follow the [toolchain contract](docs/toolchain.md), [current implementation commands/evidence](docs/implementation.md), [maintained kernel tooling](docs/kernel-tooling.md), [dependency policy](docs/dependencies.md), and [licensing/provenance rules](docs/licensing.md) before importing or implementing source.
4. Prepare [correctness verification](docs/verification.md), [performance comparisons](docs/performance.md), and the [physical-hardware lab](docs/bare-metal.md) together. QEMU is the first debugger target, not a substitute for real machines.
5. Use the [skills guide](docs/skills.md), [contribution workflow](CONTRIBUTING.md), and [agent rules](AGENTS.md). The [documentation index](docs/README.md) links every program document and subsystem plan.

## Seven approved decisions

1. **Baseline:** exact initial behavioral reference Linux **6.18.57 LTS**, not whichever kernel happens to be installed.
2. **Platforms:** x86_64 QEMU first, then real hardware and **all remaining baseline architectures**. Ordering is not a final scope exclusion. Real-hardware work begins alongside initial bring-up.
3. **Source and license:** GPL-2.0-only **direct source port**, not a clean-room reimplementation; preserve provenance, notices, and per-file license exceptions.
4. **Implementation language:** the kernel and project-owned executable tools are **Rust only**. External compilers/linkers, rustc/LLVM, QEMU, reference Linux, external tests, and existing userspace may be non-Rust.
5. **Firmware:** external firmware and microcode are permitted with explicit provenance, licensing, and trust records; they are not represented as Rust code.
6. **Modules:** no loading legacy C kernel modules, no C kernel shim, and no incremental C-backed kernel runtime. Port the functionality to Rust replacements.
7. **Workload order:** server/container workloads first. Desktop/graphics/audio, embedded/real-time, legacy protocols, and all baseline-supported filesystems and drivers remain in the final scope.

The additional release requirements are correctness, comprehensive testing of executable artifacts, **at-least-reference-Linux performance**, and physical-hardware co-development from bring-up. Those are requirements, not demonstrated achievements. The initial Limine/OVMF cell and its M1 sequencing are engineering implementation choices under the general implementation request, not additional detailed user approvals. Strict Clippy is integration/repository verification, not a new user approval. Approved decisions and unresolved broader choices remain distinguished in the [decision register](docs/decisions.md).

## Implementation boundaries

The user-approved architecture is a **modular monolithic Rust kernel**: preserve Linux-facing behavior while giving Rust ownership and reviewed unsafe boundaries to memory, synchronization, devices, and ABI entry points. Internal novelty is not a goal. Detailed mechanisms remain subject to review. The kernel is `no_std`; host tools may use `std`. Allocation is fallible and execution-context-aware, not forbidden globally.

Function-local `asm!` and `naked_asm!` are user-approved **only where unavoidable with proofs**, with operation, alternatives, register/memory/clobber/privilege contracts, reviewers, and disassembly evidence documented. `global_asm!`, standalone `.S`/`.s` or assembly implementation files, and C/C++/Zig implementation are prohibited. `repr(C)` and `extern` ABI declarations are not C implementation. Macro permission is not permission to hide an assembly subsystem in Rust strings.

The accepted finite feature/behavior inventory is **upstream Linux 6.18.57**, with explicitly reviewed security deltas and affected-cell requalification; later feature-baseline changes require a separate decision. Security review workflow, release cadence/resources and version naming remain unresolved, not implied approvals. Every baseline module's functionality needs a Rust replacement, with no legacy C execution; arbitrary third-party/proprietary out-of-tree modules are not automatically in scope.

Subsequent approved choices are Arch/CachyOS **userspace** without downstream kernel patches, a balanced server performance profile, the current workstation as the only presently available physical machine, and user-operated future installation/boot/testing. The eventual Linux-replacement kernel must be a separate Arch-like package selectable through Limine/systemd-boot while preserving the working kernel. Never automatically install, reboot, edit host boot configuration, mount or raw-write devices, elevate privileges, or change firmware. See [packaging](docs/packaging.md), [exhaustive definitions of done](docs/definition-of-done.md), and the [bare-metal smoke suite](docs/bare-metal-suite.md).

A storage-free M1 diagnostic trial on separate user-owned recoverable media, with independent known-good recovery, may precede rootfs/initramfs/userspace implementation. It is **not** a Linux-replacement package or a physical pass. The existing native Limine ELF is not a Linux boot-protocol image, PVH implementation, native EFI/PE image, or systemd-boot-compatible payload. The diagnostic uses `freestanding` without `qemu-self-test`; QEMU-only COM1/debug-exit assumptions must not reach a physical artifact. Read-only workstation observations are not recovery proof or physical attestation, and no physical trial is authorized by their existence.

A Linux syscall-number table alone is not compatibility. Signals, cancellation/restarts, memory ordering, filesystem durability, ioctls, netlink, procfs/sysfs, namespaces/cgroups, device behavior, architecture-specific layouts, and failure paths are part of the observable contract. Neither unsupported stubs nor a wall of `ENOSYS` responses count as completed work.

## What is available now

- **Physical handoff is lineage-specific:** diagnostic-001/002 are permanently withdrawn. Only the exact corrected diagnostic-003 archive/original ELF is conditionally cleared for the user's separate-media/recovery procedure; [current identities and photo/hash/recovery requirements](docs/diagnostic-handoff.md) apply. No physical evidence exists, and no later source or rebuilt smoke artifact is cleared.
- **v0.1.0 additions** ([checkpoint record](docs/implementation.md#v010-continuation-checkpoint)): the [first-userspace slice](docs/implementation.md#first-userspace-slice-kernel-side) (static `/init` loaded and run in ring 3 on a Linux `pt_regs` `SYSCALL` entry, exact `create_elf_tables` stack/auxv, `write`/`getpid`/`exit`/`exit_group`, Linux-exact init-death/segfault/no-root texts, SMEP/SMAP/UMIP, user FPU via FXSR) valid only under its declared configuration (no vDSO, `CONFIG_RSEQ=n`, no compat syscalls, `noxsave`, `norandmaps`); audited vendored crates (`x86_64`, `raw-cpuid`, `font8x8`, host `serde_json`/`cpio`/`elf`) with checksum/`cargo metadata` verification and offline builds; an 18-case `kernel-test` suite that generates its initramfs fixtures and builds `/init` in Rust; path-remapped builds whose kernel, `/init` and initramfs hashes were byte-identical between the canonical checkout and a fresh clone on one workstation; and the complete idiomatic-Rust [roadmap](docs/roadmap.md) (119 WPs). None of this is physical evidence or full compatibility.
- The earlier [publication-checkpoint kernel](docs/implementation.md#publication-checkpoint): trusted entry/firmware, indexed whole-block buddy ownership, owned four-level mappings, exact008 repaired exception entry, saved-IF/PIC/PIT checks, actual CPIO/ELF boot-module inspection with borrow/no-alias epochs, and scalar Rust memory providers. These are bounded consumed mechanisms, not full Linux subsystem ports, rootfs, SMP or userspace.
- [Maintained QEMU evidence](docs/implementation.md#maintained-integration-and-retained-harness-failure) retains the actual failed0017/8 run and successful002–005 eight-case cells. The [IRQ-save revision](docs/implementation.md#raw-irq-save-exclusion-revision) has its own0069/9 evidence. Independent error-code ABI review then led to a genuine failed0079/10 reproduction and corrected00810/10, including terminal call alignment and returning-PF15-GPR proof; see [repair and limits](docs/implementation.md#error-code-entry-defect-reproduction-and-repair). No old artifact is silently rebound or physically cleared.
- At the earlier publication checkpoint, memory/image integration and the necessary scalar `memcpy` closure had fresh11-case evidence;009's actual11/11 remains separately provider-unqualified, and010/011 are superseded source-bound checks. [The final publication record](docs/implementation.md#publication-checkpoint) gives exact latest hashes/reviews and final gates. No earlier package or physical clearance transfers to changed source.
- Actual corrected **unsigned diagnostic-003**, with genuine ALPM metadata, read-only inspection, complete source/evidence binding and successful build from a fresh source copy. Director opened the actual archive/metadata and accepted inspection/consumer records; [handoff](docs/diagnostic-handoff.md) preserves exact scope. Withdrawn001/002 remain immutable. This is not installation, signing/SBOM/legal, independent or bit-for-bit reproduction, physical qualification or a Linux replacement.
- [Historical frozen manual `cell9` evidence](docs/implementation.md#observed-execution-and-retained-failures): eight bounded QEMU cases (one positive exit 33, seven expected rejection exits 35), five production-parser host tests, both-profile artifact inspection, and [strict owned Clippy](docs/implementation.md#final-owned-strict-lint-gate). Exact ELF hashes, logs and earlier failures are retained separately from maintained runs; ignored local artifacts are not a checked-in distribution.
- The [design](docs/architecture.md), [roadmap](docs/roadmap.md), and [decision register](docs/decisions.md).
- Detailed [subsystem implementation plans](docs/README.md), including dependencies, compatibility traps, security invariants, candidate dependencies, safe simplifications, and observable gates.
- A pinned upstream tree assignment in [reference metadata](planning/reference.tsv), [workstreams](planning/workstreams.tsv), and [upstream paths](planning/upstream-paths.tsv). This maps structural scope, not implemented behavior.
- Sixteen original project-local skills, indexed through the [skills guide](docs/skills.md).
- A Rust host audit (vendored `serde_json` for the vendor gate; 22 vendored packages verified by `check`) described in [project audit](docs/project-audit.md). Its `check`/`status` commands check structural consistency, not kernel execution. The Rust-owned `kernel-build`/`kernel-test`/`kernel-package` interfaces are documented separately in [kernel tooling](docs/kernel-tooling.md), with their actual maintained-run and package evidence distinguished above.
- A dependency-free Rust [bare-metal smoke runner](docs/bare-metal-suite.md), usable on reference Linux now and on future candidate kernels. It is bounded and nondestructive; it does not certify full compatibility, physical provenance, or performance.

From the repository root, after the host toolchain prerequisites are satisfied:

```text
cargo run -p xtask -- check
cargo run -p xtask -- status
```

These two entry points are structural audits, not kernel build or boot commands. Consult [the audit contract](docs/project-audit.md) for supported Markdown validation, fixture-root support, and limitations. Documented bootstrap build/test/package examples follow; complete the fresh-run checks and default-screenshot review in [diagnostic handoff](docs/diagnostic-handoff.md) before packaging:

```text
cargo +1.88.0 run --offline --locked -p xtask -- kernel-build --output target/kernel-tooling/build-001
cargo +1.88.0 run --offline --locked -p xtask -- kernel-test --output target/kernel-tooling/test-001 --timeout-seconds 30
cargo +1.88.0 run --offline --locked -p xtask -- kernel-package --build-output target/kernel-tooling/test-001/freestanding-build --output target/kernel-tooling/package-001
```

These are command examples using unused names, not observed transcripts. Choose fresh direct children of `target/kernel-tooling/`; existing paths are refused. Satisfy the exact installed compiler/tool prerequisites (`kernel-test` also needs QEMU, OVMF, Limine and the FAT tools, but no external fixture: it builds `/init` and [generates its initramfs inputs](docs/kernel-tooling.md#generated-initramfs-fixtures)). A fresh clone with those prerequisites ran the host checks, `kernel-build` and the full `kernel-test` suite on the maintainer workstation (same host, user and toolchain installation; not independently reproduced elsewhere). `kernel-package` consumes a real default build without rebuilding/installing it and does not grant physical clearance. Historical cell9/package003 evidence remains bound to its original bytes.

### Host compiler versus kernel runtime compiler

Host tools declare Rust **1.88**, a tested engineering floor rather than a user choice. At v0.1.0 host 1.88 passed strict Clippy and the `xtask`/`baremetal` tests (70 + 10), and the exact-nightly workspace passed strict Clippy and **kernel 121, xtask 70, baremetal 10 unit tests plus two doc tests**, with both target-specific Clippy profiles and the 18-case suite also passing; [the v0.1.0 record](docs/implementation.md#v010-continuation-checkpoint) gives each command. Earlier counts (55/113) are [publication-checkpoint](docs/implementation.md#publication-checkpoint) history. Kernel manifest **1.101** is distinct from required `rustc1.101.0-nightly` commit`5c543b0b8c73c7b72bc8284ced4fb22ead15734d`/LLVM23.1.1, matching rust-src and rebuilt core/compiler_builtins for `x86_64-unknown-none`. Pinning alone does not certify lowering; entry/provider reviews remain explicit. No global installation or host change is implied.

### Existing-Linux functional smoke

The runnable functional smoke interface is:

```text
cargo run -p baremetal -- run --output <new-directory> --label <label> --expect-release <exact-osrelease> --environment <reference|qemu|bare-metal>
```

Use a genuinely new output directory and the exact running OS release. Environment is an operator assertion, not physical-machine detection. The suite exercises bounded memory/threads, sandboxed file operations, loopback sockets, process lifecycle, and proc/sysfs visibility with explicit outcomes. It never installs or boots the candidate, mounts or raw-writes devices, elevates privileges, changes settings, or updates firmware. Running it on the existing host validates the runner/reference behavior only.

## Completion means evidence, not a percentage

M8 requires justified semantic compatibility, security and recovery evidence, complete architecture/device/facility closure against the pinned inventory, and per-cell performance qualification on the agreed matrix. Individual workloads cannot be silently removed because they regress. An untested device or platform remains unqualified; a geometric mean cannot hide a regression. No fixed delivery date or staffing sufficiency is asserted.

## Primary baseline evidence

- [kernel.org releases metadata](https://www.kernel.org/releases.json): baseline selection metadata, observed 2026-10-19.
- [v6.18.57 annotated tag](https://api.github.com/repos/gregkh/linux/git/tags/c05de972ca192e22ce318dd70ce8e990b9466f6d): tag object `c05de972ca192e22ce318dd70ce8e990b9466f6d` resolves to commit `2ff600d29ee478d0a8d46ef8a58afb5e038fe692`, tree `911d5155c230d7d778ac38585e01e8ab46d75a90`. The original inventory retrieval used GitHub-reported verification; that historical observation alone was not independent local verification.
- [Current local source authentication](docs/implementation.md#pinned-source-and-specification-map): independent kernel.org/GitHub fetches matched those objects, and isolated `git verify-tag` reported a good signature for primary fingerprint `647F28654894E3BD457199BE38DBBDC86092693E`, pinned against kernel.org HTTPS signature-page and WKD/TLS publication. GPG reported `TRUST_UNDEFINED` / `[unknown]`: no Web-of-Trust or ultimate-trust claim. Raw evidence is retained locally at `target/implementation-prereqs/upstream-verification.txt`; this later check does not rewrite the original retrieval history.
- [Pinned Linux licensing rules](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/process/license-rules.rst): overall GPLv2, per-file licensing, and UAPI syscall exceptions.
- [Pinned Linux ABI guidance](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/ABI/README) and [internal driver interface guidance](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/process/stable-api-nonsense.rst): userspace stability is distinct from internal interfaces.

See [research and evidence conventions](docs/research.md), [maintenance](docs/maintenance.md), and the [change record](CHANGELOG.md) for provenance, drift, and future updates. The project license is in [LICENSE](LICENSE); individual source-derived notices and exceptions must also be retained.
