# linux-rs

A whole-kernel, direct-source Linux-to-Rust porting program targeting the behavior of **Linux 6.18.57 LTS**. The intended result is a Rust-implemented kernel that runs existing Linux userspace on every architecture and facility in the pinned baseline, with performance at least as good as the reference Linux kernel on the qualified workload/hardware matrix.

**Current status: a bounded single-CPU Rust kernel, not a completed Linux kernel.** The GPL-2.0-only `no_std` x86_64 kernel boots under Limine and OVMF in QEMU, runs processes, threads and unmodified Linux programs, and is checked against recordings of the pinned Linux 6.18.57. It was last tagged `v0.2.0`. The single authoritative description of what exists, what was tested at which commit and what is open is the [current status](docs/implementation.md#current-status); the working queue with an acceptance test per item is [next steps](docs/next-steps.md). Nothing here is physical-hardware, performance, M1 or full-compatibility qualification, and none of it lowers the complete 6.18.57 scope.

## What runs today

- **Platform:** x86_64 only, one CPU, QEMU q35 (TCG, KVM for some cases) with OVMF and Limine 12.9.3. No SMP, no durable storage, no networking (the declared configuration has `CONFIG_NET` off, as the pinned reference build does), no mitigations such as KPTI, no performance measurement.
- **Processes:** `fork`, `clone`/`clone3`, `vfork`, threads, `execve` (static, dynamic ELF with `PT_INTERP`, `#!`), `wait4`/`waitid`, signals with exact frames, job control, futexes, on a FIFO scheduler with per-task kernel stacks. `fork` copies the address space eagerly (no copy-on-write).
- **Filesystems and I/O:** a tmpfs rootfs unpacked from the initramfs, `mount` for `tmpfs` and `proc`, a `procfs`, pipes and `poll`, a console tty with serial and PS/2 input.
- **What the runtime userspace is:** the boot `/init` is the harness-built test program `user/init` (`xtask` builds it; it is not a general init). Real programs run only inside its oracle test groups, from extra initramfs modules: the host's static BusyBox and 61 host glibc programs (bash, coreutils, python3.14 and others), each pinned by sha256 and never committed. There is no interactive shell yet.
- **Evidence:** oracle groups whose serial output equals the pinned Linux's for the compared lines, plus kernel library and host-tool tests; counts and the commit they were run at are in the [current status](docs/implementation.md#current-status). QEMU only: **no physical-hardware result exists**, and the user-run bare-metal suite is prepared but has never been run. See [what each command establishes](docs/verification.md#what-each-command-establishes).
- **What stops the kernel:** a syscall Linux implements and this kernel does not, and several other conditions, stop the **whole kernel** loudly instead of one task ([item 13](docs/next-steps.md#item-13-whole-kernel-stops)). The [support matrix](docs/compatibility.md#current-support-matrix) lists supported, partial and unsupported areas.

## Build and test

Prerequisites are in [kernel tooling](docs/kernel-tooling.md#prerequisites-and-known-gaps). The compiler rules are in [toolchain](docs/toolchain.md#compiler-selection-as-it-is-today): the host tools use 1.88 and the kernel uses an exact nightly commit that `xtask` selects and checks. From the repository root:

```text
# structural audit and host unit tests (what each proves: docs/verification.md)
cargo +1.88.0 run --offline --locked -p xtask -- check
cargo +1.88.0 run --offline --locked -p xtask -- status
cargo +1.88.0 test --offline --locked -p xtask -p baremetal
cargo +nightly test --offline --locked -p kernel --lib

# build the kernel, run the QEMU suite (fresh output names under target/kernel-tooling/ only)
cargo +1.88.0 run --offline --locked -p xtask -- kernel-build --output target/kernel-tooling/build-001
cargo +1.88.0 run --offline --locked -p xtask -- kernel-test --output target/kernel-tooling/test-001 --timeout-seconds 60
```

These are command examples with unused names, not transcripts. `check` and every kernel build currently need a rustup compiler reachable through `/usr/bin`; a case reported `unavailable` (no KVM, no AVX-512, missing pinned host programs) is neither passed nor failed, so compare the matched count with the catalog before calling a run a pass. There is no CI and no committed single "all gates" command yet ([item 6](docs/next-steps.md#item-6-reproducible-verification-off-the-original-workstation)). `kernel-package` and `baremetal-suite` (the user-run USB tree) are described in [kernel tooling](docs/kernel-tooling.md#commands). Existing-Linux functional smoke:

```text
cargo run -p baremetal -- run --output <new-directory> --label <label> --expect-release <exact-osrelease> --environment <reference|qemu|bare-metal>
```

Use a genuinely new output directory and the exact running OS release; the environment label is an operator assertion, not physical-machine detection. The runner is bounded and non-destructive (no mounts, raw writes, elevation, reboot or firmware changes), and a reference-host run validates the runner only ([suite contract](docs/bare-metal-suite.md)).

## Start here

1. Read the [current status](docs/implementation.md#current-status), [next steps](docs/next-steps.md), [architecture](docs/architecture.md) and [approved decisions and unresolved questions](docs/decisions.md); the [roadmap](docs/roadmap.md) is the complete M0–M8 program and inventory.
2. Establish the [compatibility contract](docs/compatibility.md) (requirement and a short present-support matrix), [complete structural coverage inventory](docs/coverage.md), and [reference provenance](planning/reference.tsv).
3. Follow the [toolchain contract](docs/toolchain.md), [maintained kernel tooling](docs/kernel-tooling.md), [dependency policy](docs/dependencies.md), and [licensing/provenance rules](docs/licensing.md) before importing or implementing source.
4. Prepare [correctness verification](docs/verification.md), [performance comparisons](docs/performance.md), and the [physical-hardware lab](docs/bare-metal.md) together. QEMU is the first debugger target, not a substitute for real machines.
5. Use the [skills guide](docs/skills.md), [contribution workflow](CONTRIBUTING.md), and [agent rules](AGENTS.md). The [documentation index](docs/README.md) links every program document and subsystem plan.

Each structural workstream is `in_progress` or `not_started` (the counts are in the [current status](docs/implementation.md#current-status)); the [routing table](docs/implementation.md#routed-implementation-status) names every active row and its Rust paths. These labels route actual slices of work, **not** complete upstream prefixes, a compatibility percentage or milestone completion. The [ledger](planning/workstreams.tsv) keeps its five-column schema. M0 still has unresolved decision/review/hardware obligations, and M1 is not complete.

**Physical authority:** diagnostic-001/002 are permanently withdrawn. Only the exact corrected diagnostic-003 archive and original ELF named in the [diagnostic handoff](docs/diagnostic-handoff.md) is conditionally cleared for the user's unchanged separate-media/recovery procedure and its photo/hash requirements; no later source or rebuilt artifact is cleared, and no physical evidence exists.

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

## History and evidence

History: [implementation](docs/implementation.md) and [diagnostic handoff](docs/diagnostic-handoff.md). Records that cite files only in the maintainer's ignored `target/` tree (the gate script, the pinned reference build and recordings, archived logs) cannot be reproduced from a clone; only `xtask/oracle/expected.tsv` is committed.

## Completion means evidence, not a percentage

M8 requires justified semantic compatibility, security and recovery evidence, complete architecture/device/facility closure against the pinned inventory, and per-cell performance qualification on the agreed matrix. Individual workloads cannot be silently removed because they regress. An untested device or platform remains unqualified; a geometric mean cannot hide a regression. No fixed delivery date or staffing sufficiency is asserted.

## Primary baseline evidence

- [kernel.org releases metadata](https://www.kernel.org/releases.json): baseline selection metadata, observed 2026-10-19.
- [v6.18.57 annotated tag](https://api.github.com/repos/gregkh/linux/git/tags/c05de972ca192e22ce318dd70ce8e990b9466f6d): tag object `c05de972ca192e22ce318dd70ce8e990b9466f6d` resolves to commit `2ff600d29ee478d0a8d46ef8a58afb5e038fe692`, tree `911d5155c230d7d778ac38585e01e8ab46d75a90`. The original inventory retrieval used GitHub-reported verification; that historical observation alone was not independent local verification.
- [Current local source authentication](docs/implementation.md#pinned-source-and-specification-map): independent kernel.org/GitHub fetches matched those objects, and isolated `git verify-tag` reported a good signature for primary fingerprint `647F28654894E3BD457199BE38DBBDC86092693E`, pinned against kernel.org HTTPS signature-page and WKD/TLS publication. GPG reported `TRUST_UNDEFINED` / `[unknown]`: no Web-of-Trust or ultimate-trust claim. Raw evidence is retained locally at `target/implementation-prereqs/upstream-verification.txt`; this later check does not rewrite the original retrieval history.
- [Pinned Linux licensing rules](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/process/license-rules.rst): overall GPLv2, per-file licensing, and UAPI syscall exceptions.
- [Pinned Linux ABI guidance](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/ABI/README) and [internal driver interface guidance](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/process/stable-api-nonsense.rst): userspace stability is distinct from internal interfaces.

See [research and evidence conventions](docs/research.md), [maintenance](docs/maintenance.md), and the [change record](CHANGELOG.md) for provenance, drift, and future updates. The project license is in [LICENSE](LICENSE); individual source-derived notices and exceptions must also be retained.
