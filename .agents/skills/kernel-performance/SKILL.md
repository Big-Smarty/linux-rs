---
name: kernel-performance
description: "Qualify and improve Rust-kernel performance against an identical pinned Linux baseline using per-workload hardware matrices, zero-margin statistical noninferiority, preserved security, profiling, physical power/timing metrics, and reproducible evidence. Use for optimization or performance claims."
---

# Kernel performance

## Non-negotiable meaning of success

The release requirement is performance at least as good as the real pinned Linux 6.18.57 baseline for every promised workload/hardware cell and selected metric, without weakened correctness, durability, isolation or security. This is a requirement, not an observed result. The [real bootstrap's QEMU cases](../../../docs/implementation.md) establish bounded functional assertions, not benchmarks: run durations and PIT IRQ counts/wraps are neither calibrated Linux timekeeping nor physical performance evidence. No physical candidate measurement or matched Linux performance qualification exists; the currently routed `in_progress` workstreams do not close M1–M8 or imply a completion percentage.

Read the [performance protocol](../../../docs/performance.md), [physical lab contract](../../../docs/bare-metal.md), [verification contract](../../../docs/verification.md), [compatibility contract](../../../docs/compatibility.md), [security plan](../../../docs/subsystems/security.md), [observability plan](../../../docs/subsystems/observability.md), and [toolchain contract](../../../docs/toolchain.md). The project protocol controls the experiment; this skill does not authorize looser regression margins or security tradeoffs.

Never report absolute superiority, equivalence, zero-cost abstractions, zero-copy wins, or “Linux speed” from code inspection. An aggregate score cannot hide any failing or untested cell. “No statistically significant regression” is not proof of noninferiority. An interval crossing the acceptance boundary is inconclusive, not a pass.

## Required inputs

- Candidate revision/configuration/image digest and exact Linux baseline commit/configuration/image digest, not the host's unrelated distro kernel.
- Preregistered workload versions, data/image digests, client/server topology, load generator, correctness oracle, selected metrics and direction, concurrency/load levels, warm/cold-state rules and hardware cells.
- Full hardware/firmware/microcode inventory, topology/NUMA placement, storage and network settings, security mitigation state and relevant CPU features.
- Compiler/backend/linker identity and build settings, instrumentation settings, runnable test-suite artifacts, raw-data schema, statistical method, uncertainty target and experiment stopping rule.
- A recoverable physical lab and an emulation setup available from M1. Unavailable hardware or counters are explicit blockers for the corresponding claim.

## Ordered workflow

### 1. Establish semantic eligibility before timing

Tie each workload to compatibility tests: correct outputs, syscall/error behavior, isolation, scheduling semantics, persistence guarantees, packet loss/error handling and recovery. A filesystem that acknowledges unwritten data, a server that drops hard requests, or a kernel that skips mitigations is not faster compatible behavior.

Run functional/differential/regression/adversarial tests before performance qualification when implementation exists. Retain error counts and incomplete requests as workload outcomes; never exclude them to improve a score. Microbenchmarks help local diagnosis but cannot replace end-to-end server/container, filesystem, networking, scheduling, desktop, embedded/RT or other promised workload coverage.

Output: an eligibility record for each workload/cell and blockers for unimplemented semantics. A planning-only assignment produces the record schema and executable requirements, not invented eligible results.

### 2. Build the workload-by-platform matrix before seeing results

Select cells by architecture, CPU/platform vendor and generation, endian/ABI mode where applicable, core/SMT count, single/multi-socket, NUMA locality, memory size/pressure, storage device/filesystem/durability mode, NIC/link/queue configuration, IOMMU/DMA mode, firmware/microcode, and mitigation profile. Cover idle, low load, saturation, burst and contention; include cold starts and steady state.

For every workload select applicable throughput, latency distribution/tails, CPU consumption, memory consumption, startup, and power/energy metrics. State why a metric is genuinely inapplicable rather than quietly dropping it. Include:

- Throughput at fixed offered load and the load at which latency/error constraints break; distinguish completed correct work from attempted operations.
- Latency p50/p95/p99/p99.9 or the preselected relevant tails, with adequate sample counts and clock accuracy. A sample maximum is not a proved worst-case real-time bound.
- Total system and per-completed-unit CPU, utilization, context switches and migrations where meaningful; matched PMU instructions/cycles/cache events for diagnosis, not universal architectural scores.
- Resident/committed/peak memory, kernel allocations and retained cache under defined accounting; steady-state leaks and fragmentation under stress.
- Boot-to-defined-ready checkpoint, process/container startup and resume timing; firmware/loader time measured separately where appropriate.
- Whole-system idle/load watts, energy per correct unit of work, wakeup/idle residency and thermal/frequency state on physical machines. Identify meter/counter coverage, calibration, sampling rate and uncertainty; CPU energy counters alone do not establish whole-machine power.

Output: immutable experiment IDs and a complete matrix whose unrun cells remain visible. Prioritizing server/containers does not remove final-scope workloads or architectures.

### 3. Make the Linux comparison genuinely matched

Alternate the candidate and baseline on the same physical system with the same userspace/data, CPU features/topology/affinity, memory/NUMA policy, microcode/firmware, devices, queues, offloads, storage layout, mount/durability options, network peers, power policy, boot arguments and security mitigations. Record effective settings, not only requested options. Do not compare candidate RAM storage with baseline physical storage or accelerated VM execution with emulated execution.

Pin optimization level, code-generation CPU/features, LTO, debug information, hardening and instrumentation policy; keep equivalent compiler settings identical wherever meaningful. Linux's C compiler and the Rust kernel's rustc cannot be literally the same language frontend: disclose both frontends/backends and unavoidable differences. Do not handicap Linux or call this an identical-compiler experiment. Unresolved material configuration/mitigation mismatches invalidate qualification until corrected or the comparison is appropriately separated and approved.

Measure debug/sanitizer/instrumented builds separately from release builds. Never turn off KASLR, speculative-execution mitigations, IOMMU protection, access checks, persistence barriers, auditing or other promised security to win. If the baseline contains a known vulnerability, keep the pinned compatibility/performance comparison visible and add a separately identified fixed-security comparison; do not quietly change the baseline or ship the vulnerability for speed.

Output: paired environment manifests and a reviewed configuration/security delta. A “default settings” label without effective-state evidence is insufficient.

### 4. Control noise and define independent repetitions

Use isolated lab networks and sacrificial storage. Control background tasks, thermal equilibration, cooling, power source/governor, turbo/SMT policy, IRQ placement, CPU affinity and NUMA allocation equally for both systems. Capture temperatures, frequencies, throttling, error counters and clock synchronization. Include production-representative scheduling variation rather than using isolation to erase a promised behavior.

Randomize or counterbalance boot/run order, block paired runs by machine and time, and repeat across independent boots/sessions. Document warmups, cache preparation, data reset and cleanup before starting. Define independent experimental units: millions of requests in one boot are not millions of independent kernel trials. Choose repetition counts from precision/power needs using pilot data kept distinct from qualification data. Preregister invalid-run criteria; retain invalid data with reasons. Never trim slow runs or extend sampling only until a pass appears.

Output: run-order/seed, session IDs, warm/cold-state procedure, raw observations, invalidation log, independent-unit definition and a fixed stopping rule.

### 5. Apply zero-margin, per-cell statistical acceptance

Use the project's familywise 99% one-sided confidence requirement across the preregistered selected workload/platform/metric family. For each metric define a signed benefit so positive means the candidate is better: candidate minus Linux for higher-is-better metrics; Linux minus candidate for lower-is-better metrics. A normalized or log-ratio formulation is acceptable when justified, with the no-regression boundary still exactly zero. No arbitrary positive regression allowance is permitted.

Choose paired inference when the design supports pairing, with assumptions checked. Preserve session/machine clustering and serial correlation; do not treat correlated request samples as independent replicates. Use a justified interval method for means, ratios, quantiles and energy uncertainty; a mean's t-interval is not a tail-latency confidence interval. Specify multiplicity control for the whole selected family and account for repeated interim looks, or forbid them. Record the method/version and analysis inputs so another reviewer can reproduce it.

A cell/metric passes only when its corrected one-sided lower confidence bound for signed benefit is at least zero and all semantic/error criteria pass. A negative bound, insufficient samples, missing hardware, unstable measurement or unresolved confounder is not a pass. An interval containing zero does not by itself prove equivalence. Publish estimates and intervals, including failures and inconclusive cells, rather than only significance labels.

A release passes performance only if every required cell and metric independently passes. Means/geometric means and dashboards are summaries, never substitutes. Replicate important wins on independent sessions/hardware; do not generalize a measured result to untested systems.

Output: per-cell estimates, corrected intervals, pass/fail/inconclusive decisions, complete raw data and analysis provenance. This demanding rule may leave exact-parity results inconclusive; do not relax it silently.

### 6. Profile first, then optimize the demonstrated bottleneck

Once semantic correctness is established, collect allocation/copy counts, lock contention and hold times, scheduler/IRQ time, cache/TLB misses, I/O queue behavior and end-to-end traces as relevant. Use external Linux `perf` for baseline measurements where available; do not claim its kernel APIs already exist in the candidate. Candidate instrumentation must be implemented and validated, or use supported external measurement and state the visibility limitation. Separate instrumented diagnosis from qualification and quantify observer overhead.

Write one falsifiable bottleneck hypothesis, the minimal Rust change, preserved invariants, expected affected cells and rollback criteria. Prefer algorithm/data layout, eliminating avoidable allocations/copies, batching and safe locality improvements before complex lock-free/SIMD techniques. Pooling, zero-copy, sharding and batching need explicit lifetime, cancellation, DMA, memory-budget, fairness and tail-latency review; avoiding one copy does not justify pinning unbounded memory. Unsafe or assembly optimization requires its own proof and measured need.

After each change rerun the applicable correctness/security and performance matrix when execution is authorized. Check that throughput gains did not regress tails, CPU, memory, startup, energy, fairness or other workloads. Revert changes that do not meet the actual contract; preserve negative results as evidence rather than layering speculative optimizations.

Output: profile-backed optimization record, invariant review, runnable regression cases, before/after evidence and a clear decision.

### 7. Integrate physical measurement from initial bring-up

At M1 design both QEMU and physical suite paths: reset/boot checkpoint timing, timer/interrupt sanity, serial capture, environment manifest collection and remote-power recovery. QEMU provides deterministic diagnostics, not proof of native interrupt timing, cache/NUMA behavior, DMA coherency, thermal/power characteristics or Linux-level physical performance. Add measurements as M2 scheduling/MM, M4 storage and M5 server/network functionality actually become executable.

Use a Rust-owned runnable suite: each case needs artifact hashes, exact build and invocation/boot instructions, baseline/candidate selectors, machine identity, safe device allowlists, load source, collection format, timeouts, success/failure oracle and recovery procedure. Build the collector and analysis tools in Rust if project-owned; external suites/load generators may be non-Rust. Archive commands and exit outcomes from genuine execution. The suite's specification is not an already runnable binary, and an executable that only prints planned results is not a test suite.

Before physical storage/network/power tests, verify out-of-band console and recovery on an isolated lab system; never benchmark destructively on the workstation's disks. Plan multiple CPU/platform vendors, NUMA, real IOMMU/DMA/storage/NICs, interrupts, suspend/hotplug and error/recovery cases. Record unacquired hardware and unimplemented counters as named blockers.

The delivered [bounded functional smoke runner](../../../docs/bare-metal-suite.md) is runnable tooling, not this broader benchmark/analysis suite and not physical-performance proof. Its environment label is an operator assertion; host-reference output does not qualify the candidate kernel. Only the current workstation is available now. The user operates future candidate installation/selection/boot under the [packaging design](../../../docs/packaging.md); do not change host boot state, reboot, update firmware or perform destructive tests. Missing lab systems/equipment remains a qualification blocker.

## Definition of done, stop conditions and handoff

An optimization is done only when its relevant semantics/security checks and preregistered performance cells have real, reproducible passing evidence and the code change remains maintainable. Full performance qualification additionally requires all promised cells, physical coverage and metrics; an early subset can be reported only with its exact scope and cannot be called Linux parity.

Apply the exhaustive [definition of done](../../../docs/definition-of-done.md). The initial Arch/CachyOS userspace and balanced server profile are approved priorities, not permission to include downstream CachyOS kernel patches silently or omit the other promised workloads. Every claimed result must identify that actual userspace/profile and the exact upstream Linux baseline.

Stop qualification on semantic failures, security differences, missing baseline artifacts, unequal material settings, invalid statistics, uncalibrated power claims, unavailable physical cells or absent raw data. Return the experiment manifest, runnable suite/analysis artifact identities, all results and uncertainty, qualified scope, failing/inconclusive cells and blockers. Never invent a benchmark, smoke execution or physical measurement. During planning-only work do not execute future kernel gates.

## Primary methodology sources and their limits

- [NIST confidence intervals for differences between means](https://www.itl.nist.gov/div898/handbook/prc/section3/prc312.htm) provides paired/unpaired interval formulas. Use the relevant assumptions; its informal interpretation of a zero-containing interval does not establish this project's noninferiority requirement, and mean formulas do not qualify quantiles.
- [Pinned Linux perf security guidance](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/admin-guide/perf-security.rst) explains sensitive PMU/sample data and access/resource controls. Profiling is not permission to bypass those controls or publish secrets.
- [Pinned Linux reproducible-build guidance](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/kbuild/reproducible-builds.rst) identifies volatile inputs relevant to artifact identity; reproducible binaries alone do not prove reproducible performance.
- The stricter zero-margin familywise 99% acceptance and complete physical matrix are project release policy in the [performance protocol](../../../docs/performance.md), not a claim that upstream Linux or a generic statistics reference guarantees these results.
