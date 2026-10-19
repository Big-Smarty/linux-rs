---
name: kernel-porting
description: Plan and execute provenance-preserving direct ports from pinned Linux source to a Rust-only kernel. Use for upstream inventory, licensing, behavioral decomposition, dependency cutovers, differential tests, and port completion evidence.
---

# Kernel source porting

## Scope and authority

Use this skill for a source-backed port, not a clean-room reimplementation or a C-backed Rust wrapper. Read [project instructions](../../../AGENTS.md), [architecture](../../../docs/architecture.md), [compatibility contract](../../../docs/compatibility.md), [coverage](../../../docs/coverage.md), and the owning subsystem plan before selecting code. The initial baseline is Linux 6.18.57; [reference metadata](../../../planning/reference.tsv) identifies its exact objects. The earlier planning-only boundary is superseded by the real Rust bootstrap and consumed foundation mechanisms in [implementation](../../../docs/implementation.md). Its canonical workstream-to-Rust-path-to-revision routing names every `in_progress` owner, not completed translations of Linux source files or prefixes; all other workstreams stay `not_started` under the unchanged [five-column schema](../kernel-documentation/SKILL.md).

Project-owned executable implementation must be Rust, kernel code `no_std`, with context-aware fallible allocation. Existing external reference Linux, userspace programs, and test suites may be non-Rust. Never introduce a C shim, retained C implementation, legacy C module loader, standalone assembly, or an ENOSYS facade and call it a port. Preserve unsupported work explicitly rather than silently reducing the all-Linux scope.

The standing [definition of done](../../../docs/definition-of-done.md) requires complete behavioral porting and evidence qualification before calling the kernel done; the existing bootstrap is neither full Linux nor M1 completion. Initial userspace is Arch/CachyOS userspace without importing downstream CachyOS kernel patches, with a balanced server performance profile. Only the current workstation is presently available: other required hardware remains an explicit qualification blocker.

Use the actual bounded [bare-metal smoke suite](../../../docs/bare-metal-suite.md) when authorized:

```text
cargo run -p baremetal -- run --output <new-directory> --label <label> --expect-release <exact-osrelease> --environment <reference|qemu|bare-metal>
```

Use a new output directory; preserve the report's failures, skips, unavailable cases and environment metadata. The environment label is an operator assertion, not physical-machine attestation. A reference-host run validates the runner only; its bounded memory/thread, sandbox filesystem, loopback socket, process and visibility cases are neither full kernel qualification nor performance proof. Broader port-specific tests remain required. Do not report an invocation as executed unless it really ran.

Follow [packaging design](../../../docs/packaging.md) without conflating the existing diagnostic ELF with a Linux-replacement package. A storage-free M1 diagnostic trial may precede rootfs/initramfs/userspace on separate user-owned recoverable media with independent known-good recovery; it has not physically booted. A separate Arch-style Linux-replacement package still requires real storage, durable filesystem, root/initramfs and init/userspace prerequisites. Native Limine ELF does not implement systemd-boot EFI/PE/Linux-image compatibility. The user installs/selects/boots physical candidates while preserving the working kernel and recovery; never perform host bootloader installation, reboot, raw-device changes or firmware actions as part of source porting.

## Required inputs and evidence

Before editing implementation, obtain:

- Workstream ID from [workstreams](../../../planning/workstreams.tsv), exact upstream paths and blob IDs from [tree inventory](../../../planning/upstream-paths.tsv), target architecture/configuration, and milestone dependencies from [roadmap](../../../docs/roadmap.md).
- Exact pinned source, relevant UAPI, callers, error/unwind paths, configuration-generated variants, architecture overrides, and existing upstream tests. A directory listing is structural coverage, not a behavioral specification.
- Original SPDX expressions, copyright notices, license exceptions, dual-license selection if applicable, and firmware/data provenance. Use [licensing policy](../../../docs/licensing.md); a rewrite in Rust does not erase derivation.
- A reproducible reference environment: baseline commit, full configuration, compiler/linker, boot parameters, userspace/test revisions, hardware or emulator identity, and security mitigations.
- Acceptance cases, threat/invariant analysis, and a named owner for each missing shared primitive. Record unavailable source, reference execution, or physical equipment as blockers rather than invented evidence.

## Ordered procedure

1. **Resolve the source boundary.** Confirm tag, commit, tree, and blob relationships against the reference record. Preserve GitHub-only retrieval history separately from the later matching local fetch and GPG “Good signature” in [implementation evidence](../../../docs/implementation.md). Its fingerprint is pinned against kernel.org HTTPS/WKD; `TRUST_UNDEFINED` / `[unknown]` remains, with no Web-of-Trust or ultimate-trust claim. Do not substitute current mainline when a pinned file is inconvenient. Consult later fixes for security research, but record any deliberate departure from the baseline in [decisions](../../../docs/decisions.md).
2. **Create a behavior map before a translation map.** Enumerate entry points, observable outputs and side effects, permissions/namespaces, ownership, lock/context requirements, callbacks, timers, allocation/reclaim behavior, and teardown. Follow indirect dispatch, Kconfig/architecture alternatives, and disabled/error branches. For each behavior, name source locations, consumers, prerequisites, and an observable oracle.
3. **Separate interfaces from mechanisms.** Preserve user-visible ABI, persistent/wire formats, and lifecycle semantics. Linux internal function names and C data structures are not a stable third-party driver ABI. Rust internals may change, but every affected caller must migrate in the same coherent cutover. An old userspace ABI remains supported even when its internal adapter is redesigned.
4. **Inventory dependency closure.** Include MM, scheduler, IRQ/preemption, usercopy, credentials, clocks, firmware, buses, allocation, build metadata, and test infrastructure actually reached by the port. A workstream with no routed implementation stays `not_started`; genuine work underway is `in_progress`, even while dependencies or qualification remain open. Sequence dependency gates separately from those two statuses. A source file translated against fictitious APIs is not a completed unit.
5. **Select the smallest complete vertical behavior.** Choose a real end-to-end operation with success, denied access, interruption, resource exhaustion, concurrent teardown, and recovery paths. Priority may start with x86_64/server workloads; retain other architectures, device families, and obscure facilities in the coverage map. Do not equate one example device or syscall with an entire directory.
6. **Apply the five decisions below to that behavior.** Document reuse and rejection evidence, shared bundles, safe simplifications, security constraints, and measurable improvements separately. Do not insert a stock paragraph claiming all are addressed.
7. **Port semantics into Rust.** Establish explicit ownership/state transitions and narrow reviewed unsafe boundaries. Preserve integer width/sign/overflow rules, endian handling, partial work, timeout clock choice, wait/wakeup ordering, refcounts, and failure rollback. Use the ABI, unsafe, and concurrency skills for those boundaries. Do not translate C data races into Rust plain or volatile races.
8. **Integrate a clean internal cutover.** Migrate every caller, callback registration, teardown path, configuration variant, and test interface affected. Remove obsolete project implementation after cutover; do not remove upstream provenance or still-required public ABI adapters. No compatibility alias should conceal an incomplete internal migration.
9. **Collect differential evidence.** Run the same observable cases against pinned Linux and the Rust kernel only when both real environments exist and execution is authorized. Compare return values, output bytes, errno precedence, ordering, persistence, signals, timing semantics, and security outcomes. Preserve raw observations and minimize unexpected differences into regression cases. Nondeterministic results require allowed-outcome analysis, not byte-for-byte log equality.
10. **Qualify beyond the happy path.** Advance milestone gates only with the semantic, safety, bare-metal, and performance evidence below. Update per-file/behavior implementation and test records, owning plans, dependency decisions, and changelog. Structural inventory remains separate from implementation/test coverage.

## Five decisions for every port slice

| Decision | Required reasoning |
| --- | --- |
| Reuse crates? | Check [dependency policy](../../../docs/dependencies.md): exact candidate/version/source, GPL compatibility, transitive licenses, `no_std` features, allocator/failure/context behavior, architecture coverage, unsafe surface, build scripts/native linkage, advisories, maintenance, and measured cost. `core` is the default for primitives; a userspace Linux wrapper does not implement a kernel subsystem. Linux Rust wrappers that call C are references, not acceptable runtime dependencies. No crate is selected merely because it is popular. |
| Bundle mechanisms? | Identify existing shared usercopy, allocation, waitqueue, time, credentials, DMA, and tracing mechanisms. Reuse one contract and one owner across consumers; do not bundle unrelated policies into a global lock or create one scheduler per subsystem. State caller migration and failure semantics. |
| Simplify safely? | Change private representation or eliminate duplicate internal machinery only when all ABI/error/order/configuration cases remain covered. Prioritizing bring-up is scheduling, not deleting RT, compat, old formats, protocols, or hardware from final scope. Preserve intentional quirks with source-backed tests, not unexplained special cases. |
| Strengthen security? | Derive untrusted inputs, privilege checks, object lifetimes, integer/size bounds, secret/padding exposure, denial-of-service limits, speculative boundaries, and teardown races. A safer language does not implement Linux capabilities, namespaces, or policy automatically. |
| Improve? | First establish semantic equivalence; then measure allocation/copy/lock/cacheline costs and remove avoidable work without weakening checks. State workload, expected mechanism, counter-metric, and before/after evidence. A clever redesign without behavioral evidence is not an improvement claim. |

## Port-specific traps

- Do not mechanically map C `long`, unions, bitfields, flexible arrays, ERR_PTR encodings, or container arithmetic into Rust references/enums. Layout, provenance, initialization, and overflow obligations differ.
- Rust `Drop` helps ordinary ownership cleanup but does not discharge deferred IRQ/work/RCU/DMA references. Quiesce every asynchronous observer before freeing. Allocation and destructor behavior must be legal in the current context.
- Do not replace a user-visible partial read/write or recoverable error with panic, unwrap, all-or-nothing convenience APIs, or a different errno. Record reference behavior for competing invalid inputs.
- Preserve upstream licensing on UAPI-derived definitions, test fixtures, tables, protocol constants, and generated data as appropriate; source inventory must include headers and generators, not only `.c` files.
- Reference Linux tests may depend on privileged/destructive operations. Use disposable guests, sacrificial disks, isolated networks, and lab recovery; never run a broad kernel suite against the host by default.

## Evidence gates

Use [verification](../../../docs/verification.md), [performance](../../../docs/performance.md), and [bare-metal qualification](../../../docs/bare-metal.md).

- **M0:** source/license/configuration provenance, behavioral inventory, dependency ownership, and planned tests. Documentation existence alone is not an unconditional M0 pass.
- **M1 onward:** a real executable path, serial/remote-console logs, reproducible QEMU debug case, and a corresponding physical-machine bring-up case with known-good recovery. Bare metal is co-developed from initial bring-up, not deferred to M8.
- **Owning milestone M2–M7:** differential normal/adversarial/regression tests, OOM and fault injection, interruption, SMP stress, hotplug/unload/reset where relevant, and durable recovery for persistent state. Test the applicable architecture/configuration variants, not just the developer host.
- **Performance and M8:** compare each applicable workload/hardware cell with pinned real Linux under matched configuration, mitigations, compiler policy, topology, firmware, storage, and load. Record throughput, latency/tails, CPU, memory, startup, and power as applicable, repetitions, uncertainty, and noise controls. Do not hide regressions in an aggregate or invent an allowable slowdown; at-least-baseline performance is a release requirement. Unproven non-inferiority is not a pass.

Record command/environment, revision, raw artifacts, expected/observed outcome, and limitations for every exercised gate. Retain the exact cell9 QEMU, parser-test and lint evidence in [implementation](../../../docs/implementation.md), including prior failed runs, without reclassifying it as full source-port, physical or performance qualification. In planning-only or no-gates work, mark new intended tests unrun and distinguish citations of earlier execution from checks performed for the current assignment.

## Stop and escalation rules

Stop the affected implementation/gate and escalate with exact missing evidence when source provenance cannot be reconciled, license obligations conflict, a behavior depends on an unimplemented primitive, reference results disagree without explanation, unsafe/lifecycle invariants cannot be stated, hardware recovery is unsafe, or performance/hardware evidence is unavailable. Finish independent reachable planning work. Never compensate with fake support, silent source-version drift, security disablement, or a passing claim.

## Deliverable checklist

- [ ] Exact source and license/notice mapping; inventory IDs and complete behavior/caller/configuration boundary.
- [ ] Ordered dependency-backed implementation/cutover, five decisions, and unsafe/concurrency/security invariants.
- [ ] Native/compat/architecture and failure/teardown cases; affected callers/tests/docs updated together.
- [ ] Differential observations or explicit unrun cases; safe lab/recovery instructions; performance measurement cells.
- [ ] Raw evidence links, unresolved blockers, owning milestone/status, and no unsupported implementation/parity claim.

## Primary references

- [Pinned Linux licensing rules](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/process/license-rules.rst): whole-kernel licensing, per-file licenses, SPDX, UAPI exceptions.
- [Linux internal API policy](https://raw.githubusercontent.com/torvalds/linux/master/Documentation/process/stable-api-nonsense.rst): background policy, not a substitute for pinned implementation behavior.
- [Rust undefined behavior](https://doc.rust-lang.org/reference/behavior-considered-undefined.html): `unsafe` is not exemption from language rules.
- [Agent Skills specification](https://agentskills.io/specification): portable directory/frontmatter format; this file needs no helper scripts or agent-specific tooling.
