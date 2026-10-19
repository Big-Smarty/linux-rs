---
name: kernel-memory
description: "Plan, port, and review Linux-compatible Rust memory management: allocation contexts, reclaim, OOM, NUMA, page faults, user-page pins, page tables, cache maintenance, and SMP TLB invalidation. Use for allocator, virtual-memory, memory-pressure, migration, or DMA-pinning work."
---

# Kernel memory engineering

## Scope and authority

Use this skill for physical-page ownership, kernel allocation, address spaces, faults, reclaim/swap, memory control groups, NUMA, migration, huge pages, pinning, and translation retirement. Pair device DMA work with [kernel-drivers](../kernel-drivers/SKILL.md), file-backed mappings with [kernel-storage](../kernel-storage/SKILL.md), and synchronization or unsafe boundaries with [kernel-concurrency](../kernel-concurrency/SKILL.md) and [kernel-unsafe](../kernel-unsafe/SKILL.md).

Before changing anything, read the current [repository instructions](../../../AGENTS.md), [decisions](../../../docs/decisions.md), [memory plan](../../../docs/subsystems/memory.md), relevant [core plan](../../../docs/subsystems/core.md) and [process plan](../../../docs/subsystems/process.md), [compatibility contract](../../../docs/compatibility.md), and [coverage ledger](../../../docs/coverage.md). Read [verification](../../../docs/verification.md), [performance](../../../docs/performance.md), and [bare-metal requirements](../../../docs/bare-metal.md) before defining acceptance. Use the current [reference metadata](../../../planning/reference.tsv), not whichever Linux version is newest.

The approved initial baseline is Linux 6.18.57. Kernel implementation is Rust-only and `no_std`; fallible, context-aware heap allocation is permitted and necessary. Do not import a microcontroller's blanket no-heap policy, use a C kernel shim, or treat a userspace allocator as the complete kernel memory subsystem. Host-side Rust tools may use `std`. The [existing bootstrap](../../../docs/implementation.md) has an actual RAM-sized ownership bitmap, raw initialization before references, unique frame tokens and owned four-level mappings/CR3. Cell9 exercises actual exhaustion/restoration, all 20 table-allocation failure points, W^X/no writable text alias/four guards and exact page-fault errors 0/3/17. `ws-mm` and `ws-arch-x86-mm` are `in_progress` with exact Rust-path routing, not complete Linux allocation, reclaim, NUMA, usercopy, SMP or physical qualification.

Accepted architecture: modular monolithic Rust kernel. Feature scope is fixed to upstream Linux 6.18.57 with explicitly reviewed security deltas; record each delta's behavior, rationale, tests, and compatibility/performance impact. Later feature-baseline changes require a separate decision. Every in-baseline module's functionality needs a Rust replacement; arbitrary proprietary/out-of-tree modules are not implicitly included. Function-local `asm!` and `naked_asm!` are allowed only where unavoidable, with operation/register/memory/clobber/privilege proofs, reviewers, and disassembly checks; no `global_asm!` or standalone assembly escape.

## Ground the change in evidence

1. Identify the upstream paths, functions, callers, configurations, architecture, userspace observations, and workstream IDs affected. Inspect pinned implementation and selftests, not only API prose. Preserve per-file SPDX/provenance for direct ports under the [licensing rules](../../../docs/licensing.md).
2. Establish the allocation/fault/reclaim call graph, including indirect callbacks into writeback, shrinkers, drivers, and cgroups. Mark process, hard-IRQ, softirq, NMI, preemption-disabled, and lock-held contexts separately. Record which paths may sleep, fault, enter filesystem or block I/O, reclaim recursively, or consume reserves.
3. Record source facts, proposed Rust mechanisms, unresolved choices, and observed test results in separate fields. Do not convert structural inventory coverage into semantic coverage. If upstream documentation is skeletal, follow its implementation rather than inventing its missing specification.

Primary starting points, all pinned to the baseline:

- [Allocation guide](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/core-api/memory-allocation.rst): sleeping reclaim, nonblocking allocation, accounting, reserves, and physical versus virtual contiguity.
- [Pinning guide](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/core-api/pin_user_pages.rst): ordinary references versus pins, long-term restrictions, writeback interactions, and observable pin counters.
- [Cache and TLB contracts](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/core-api/cachetlb.rst): architectural postconditions and cache/page-table/TLB ordering; x86 cache behavior is not a universal architecture rule.
- [NUMA policy](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/admin-guide/mm/numa_memory_policy.rst): task, VMA, shared-policy, cpuset, and migration interactions. Historical descriptions must be checked against pinned code.
- [Reclaim implementation](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/mm/vmscan.c) and [OOM implementation](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/mm/oom_kill.c): actual policy, constrained domains, progress, eligibility, and locking. Their introductory documentation alone is not a sufficient behavioral specification.

## Ordered decision workflow

For every touched mechanism, answer these questions in this order; retain rejected alternatives and the evidence that rejected them.

1. **Port the contract.** Enumerate observable behavior first: allocation failure, fault result/signal, overcommit, residency, accounting, cgroup pressure and OOM, NUMA policy, `mmap`/`mprotect`/`munmap`, `madvise`, huge-page behavior, and relevant `/proc` or sysfs observations. Separate Linux internal representation from required behavior. A Rust refcount need not copy a C bit encoding, but it must preserve its lifetime and accounting semantics.
2. **Evaluate reuse.** Consult the [dependency ledger](../../../docs/dependencies.md). For each allocator, address-space container, bitset, or page-table candidate, inspect its exact version, license, transitive code, allocation-failure behavior, alignment, supported page sizes, SMP assumptions, and architecture support. A `no_std` badge does not prove fallibility, interrupt safety, NUMA, reclaim, or Linux policy compatibility. Reject or narrowly reuse components that assume one global heap, panicking growth, fixed physical address widths, or immediate freeing after unmap. Record an evidence-backed direct-port choice when no candidate fits.
3. **Consolidate mechanisms.** Define shared physical-frame ownership, allocation context, accounting, page/folio state, reference/pin accounting, wait/wakeup, and translation-retirement contracts before individual clients. Coordinate page cache, DMA, networking pools, and process mappings around these contracts. Do not create per-subsystem incompatible frame allocators or global locks merely to make types uniform.
4. **Simplify internally.** Prefer one reviewed implementation per invariant, explicit page-state transitions, checked range arithmetic, and narrow architecture hooks. An early single-node or single-page-size milestone may reduce debug combinations only if every excluded mode is still tracked, not advertised as supported, and does not erase final NUMA/architecture scope. Never simplify away observable OOM rules, fault races, accounting, cache maintenance, or memory barriers.
5. **Review security and invariants.** Complete the invariant review below before choosing unsafe representations or fast paths. Explain denied operations and error propagation rather than substituting panics, indefinite retries, or silent success.
6. **Improve after semantic proof.** Profile actual workload stalls, allocation/copy counts, lock contention, cache misses, fragmentation, and remote memory traffic. Consider per-CPU caches, batching, TLB range aggregation, locality-aware placement, and page-table walks only with preserved accounting, bounded memory retention, CPU-hotplug drain, and retirement proofs. No avoidable allocation or copying in a proposed hot path; no performance claim without measurements.

## Implementation sequence and review obligations

### Allocation and physical memory

- Start with firmware memory-map validation, reserved ranges, overflow-safe PFN/address conversion, direct-map limits, and an explicit boot-to-runtime allocator handoff. Every allocatable frame has exactly one owner/state; firmware, MMIO, kernel image, stacks, page tables, and crash/recovery regions are not free RAM.
- Establish page allocator zones/nodes, alignment/order constraints, fragmentation/compaction rules, slab/object lifetime, virtual allocations, and exhaustion behavior before higher-level clients depend on them. Physical contiguity, virtual contiguity, and DMA reachability are different properties.
- Specify an allocation-context matrix for each callsite: may sleep/reclaim, may invoke filesystem/I/O, charging domain, node/zone restrictions, movable/unmovable status, reserve access, and retry/failure policy. Propagate no-filesystem/no-I/O scopes through nested allocations; a renamed GFP flag without scope behavior is not equivalent.
- Fallible collection growth and partially initialized object rollback must leave ownership and charges consistent. Reserves are bounded and justified; ordinary user-triggered requests must not consume emergency reserves indiscriminately. Stack allocation is not a universal replacement: review worst-case kernel stack use and recursion.

### Address spaces, faults, pins, and TLBs

- Implement mapping metadata, page-table ownership, permissions, user-copy fault handling, anonymous/file-backed faults, COW, sharing, and reverse mappings with explicit lock ordering. Review faults racing truncate, unmap, fork, exit, migration, and permission changes; copying a pointer out of a locked map does not extend its lifetime.
- Distinguish owned frame references, shared references, short-term data pins, long-term pins, and device mappings. Specify partial pin success, cancellation, dirty-on-release behavior, COW resolution, pin limits, and accounting. Check long-term restrictions and MMU-notifier/device-invalidation interactions against the pinning source; do not promise that all file or DAX pages are pinnable.
- Write the architectural sequence for cache maintenance, PTE publication, memory barriers, TLB invalidation, remote acknowledgement, and eventual frame/page-table reclamation. Include PCID/ASID reuse, global mappings, speculative walkers, CPUs entering/leaving an address space, huge-page split/merge, and CPU hotplug. A local `invlpg`, a compiler fence, or Rust ownership alone does not discharge SMP retirement.
- Give each unsafe mapping/reference an aliasing, initialization, permission, address-range, and lifetime proof. Do not create ordinary mutable Rust references to concurrently changing page tables or device-owned memory merely because a raw address is available.

### Reclaim, OOM, and NUMA

- Add reclaimable-cache registration, background and direct reclaim, dirty writeback coordination, swap, compaction, and memory-pressure accounting with explicit progress measures. Do not free dirty, pinned, under-I/O, mapped, or otherwise referenced memory without completing the appropriate protocol. Define shrinker callbacks' allocation and lock restrictions.
- Review filesystem/reclaim inversion and reserve deadlocks. Define what happens when reclaim makes no progress, I/O fails, swap is exhausted, or a cgroup limit is reached. OOM handling must distinguish global, memcg, cpuset, and policy-constrained domains, victim eligibility/protection, process exit/reaping, and notification semantics; killing an arbitrary task or panicking on allocation failure is not a port.
- Model topology, memoryless CPUs/nodes, distances, cpuset restrictions, task/VMA/shared policies, interleave modes, fallback, migration, and memory hotplug. Test changing policy versus placement of existing pages; those are not interchangeable. Keep frame/pin/accounting state consistent while migration or node offlining fails halfway.

## Mandatory invariant review

Before approval, provide a transition table and counterexample for each applicable property:

- A frame cannot be both allocated and free; every successful allocation has one matching eventual release, and every partial failure unwinds the right subset exactly once.
- Page identity, refcounts, mapcounts, pins, dirty/writeback state, and charges cannot be forged, overflow silently, or become inconsistent through concurrent teardown.
- Untrusted memory requests remain charged and bounded; no cross-process data disclosure through reuse, uninitialized padding, speculative permissions, or stale mappings.
- No sleeping or reclaim recursion occurs in forbidden contexts; all nested lock/reclaim paths have a documented order and progress argument.
- Permissions and ownership survive COW/fork/truncate/unmap races; stale translations cannot access a reused frame or page-table page.
- Offlining, cancellation, OOM victim exit, and asynchronous completion do not bypass reference, pin, or grace-period obligations.

## Evidence, definition of done, and acceptance

Define checks with input/configuration, reference behavior, oracle, expected failure, artifacts, and responsible execution owner. Run only checks explicitly authorized by the current assignment; a planning task must not fabricate boot/test results.

1. **Pure/state-machine checks:** checked address arithmetic, allocator partition conservation, failure at every allocation stage, range split/merge, ref/pin accounting, OOM eligibility, and modeled translation-retirement interleavings. Host testing cannot establish actual TLB/cache correctness.
2. **Differential and adversarial checks:** baseline selftests and equivalent workloads for mapping/fault/COW, signals and errors, huge pages, swap/reclaim, cgroup limits/events, NUMA placement, page pins, permission races, and concurrent exit. Force low memory, fragmented orders, writeback failure, and allocation failure without suppressing discrepancies.
3. **QEMU plus physical machines from bring-up:** M1 memory-map and page-table smoke checks, then M2 SMP faults, shootdowns, pressure and allocator tests on both paths. Use serial/remote recovery; cover multiple CPU/platform vendors, actual NUMA, IOMMU-driven pins, suspend/resume, CPU/memory hotplug where supported, and relevant noncoherent/weakly ordered architectures as their ports advance. Missing hardware is a named blocker, not replaced by simulated NUMA.
4. **Performance qualification:** compare to pinned Linux on matched hardware, topology, mitigations, compiler/configuration, memory size, huge-page/swap settings, and firmware. Measure fault and allocation latency/tails, reclaim stalls, TLB shootdown cost, throughput, CPU, resident/metadata memory, startup, remote traffic, and power under both idle and pressure workloads. Include repetitions, confidence intervals, warm/cold states, and noise controls. At-least-Linux performance is a release requirement; inconclusive results and individual regressions are not passes and cannot be hidden in aggregate averages.

A memory change is done only when its full affected contract is mapped to source and callers, ownership/accounting/retirement invariants are reviewed, all applicable semantic/failure/race gates pass, and required performance plus physical evidence exists. Apply the standing [definition of done](../../../docs/definition-of-done.md); unavailable hardware or an inconclusive measurement is a blocker, not a waiver. Scope completion must include all required modes, not only the initial fast path.

| Completion dimension | Required artifact |
| --- | --- |
| Behavioral closure | Pinned syscall/fault/OOM/accounting/NUMA contract matrix, all affected callers migrated, and differential results including errors and partial failures. |
| Invariant closure | Allocation-context/lock tables, ownership/pin transitions, architectural cache/TLB sequence, reclamation acknowledgement proof, and adversarial/race results. |
| Execution closure | Runnable case IDs/invocations, build digest, machine model/configuration, expected oracle, timeout, exit status, and raw logs for QEMU and physical machines. Host models alone do not close hardware behavior. |
| Qualification closure | Reproducible per-workload Linux comparisons and the required physical-platform matrix, with every missing platform and unproven guarantee explicitly blocked. |

The actual [bounded smoke suite](../../../docs/bare-metal-suite.md) has this repository-root invocation:

```text
cargo run -p baremetal -- run --output <new-directory> --label <label> --expect-release <exact-osrelease> --environment <reference|qemu|bare-metal>
```

Choose one environment value, supply the exact running release, and use a new output directory. The suite exercises bounded memory/threads and other functional smoke; it does not exercise kernel OOM/reclaim/NUMA/TLB completeness or certify performance. Its environment label is an operator assertion, not proof of physical execution. Reference-host success validates the runner, not an implemented kernel. Preserve individual pass/fail/skip/unavailable results.

Only the current workstation is available initially; other vendors, NUMA, IOMMU and architecture platforms remain named qualification blockers. Never collect unique hardware serial IDs in suite metadata. The user operates candidate installation, boot selection, and recovery. Do not install, reboot, change firmware/system settings, elevate, or run destructive pressure tests on the host by default. Follow the [packaging/recovery contract](../../../docs/packaging.md): the existing storage-free diagnostic ELF may precede rootfs/initramfs/userspace on separate user-owned recoverable media with independent known-good recovery, but is not a Linux-replacement package or a physical pass. Replacement packaging still needs real storage/durable filesystem/root/initramfs/init/userspace and broader gates. Use Arch/CachyOS userspace and the approved balanced server profile without importing downstream CachyOS kernel patches.

## Limits, stop conditions, and handoff

Stop the unsafe or externally visible change if allocation context, pin lifetime, lock order, OOM domain, architectural ordering, or retirement acknowledgement is unresolved. Do not continue by leaking indefinitely, weakening permissions, disabling mitigations, or marking a required behavior unsupported forever. Isolate and record the blocker while completing independent planning work.

Hand off: affected workstream/upstream paths; the six decisions; mapping and ownership transitions; allocation-context and lock-order tables; API/caller migration; security analysis; tests actually executed versus planned; per-workload performance evidence; physical hardware coverage/blockers; and exact remaining qualification limits. Update existing plans, provenance, and changelog only within assignment ownership. No scripts, global installers, new runtime dependencies, or evidence claims are implied by loading this skill.
