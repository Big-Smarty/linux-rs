---
name: kernel-storage
description: "Plan, port, and review Rust Linux-compatible VFS, block storage, and filesystems. Use for pathname/mount semantics, page cache, writeback, fsync durability, flush/FUA barriers, journals, recovery, hostile disk images, or physical-storage qualification."
---

# Kernel storage and filesystem engineering

## Scope and authority

Use for VFS and mount behavior, inode/dentry/open-file lifetimes, page cache and direct I/O, writeback, block queues and stacked devices, filesystem formats, durability, and recovery. Device transport belongs jointly to [kernel-drivers](../kernel-drivers/SKILL.md); reclaim, mappings, and page pins to [kernel-memory](../kernel-memory/SKILL.md); concurrency, UAPI, and hostile input to [kernel-concurrency](../kernel-concurrency/SKILL.md), [kernel-abi](../kernel-abi/SKILL.md), and [kernel-security](../kernel-security/SKILL.md).

First read [repository instructions](../../../AGENTS.md), [decisions](../../../docs/decisions.md), [storage plan](../../../docs/subsystems/storage.md), [filesystem plan](../../../docs/subsystems/filesystems.md), [memory plan](../../../docs/subsystems/memory.md), [compatibility](../../../docs/compatibility.md), and [reference metadata](../../../planning/reference.tsv). Read [coverage](../../../docs/coverage.md), [dependencies](../../../docs/dependencies.md), [licensing](../../../docs/licensing.md), [verification](../../../docs/verification.md), [performance](../../../docs/performance.md), and [bare-metal requirements](../../../docs/bare-metal.md) before selecting acceptance gates.

Initial baseline is Linux 6.18.57, implemented as Rust-only kernel code without a C storage runtime. External reference Linux, existing userspace filesystem utilities, and test suites may be non-Rust. Kernel `no_std` does not prohibit a heap: allocation must be fallible, charged where appropriate, and legal in its execution/reclaim context. Preserve all required filesystem and storage-family scope; an initial server root filesystem is an ordering choice, not a permanent omission. The [real bootstrap](../../../docs/implementation.md) has no VFS, block stack, filesystem, rootfs/initramfs or userspace; storage/filesystem workstreams remain `not_started`, distinct from the currently routed `in_progress` bootstrap/foundation rows. No toy filesystem or storage shim substitutes for those obligations.

Accepted architecture: modular monolithic Rust kernel. Feature scope is fixed to upstream Linux 6.18.57 with explicitly reviewed security deltas; record each delta's behavior, rationale, tests, and compatibility/performance impact. Later feature-baseline changes require a separate decision. Every in-baseline module's functionality needs a Rust replacement; arbitrary proprietary/out-of-tree modules are not implicitly included. Function-local `asm!` and `naked_asm!` are allowed only where unavoidable, with operation/register/memory/clobber/privilege proofs, reviewers, and disassembly checks; no `global_asm!` or standalone assembly escape.

## Gather sources before changing representation

Identify upstream filesystem/block paths, workstream IDs, format versions/features, mount options, queue capabilities, UAPI, and reference configuration. Read relevant pinned implementation, locking contracts, on-disk format specifications, and baseline tests. Preserve provenance and per-file notices for direct source ports. A filesystem name or directory count does not establish on-disk feature support.

Pinned primary starting points:

- [VFS overview](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/filesystems/vfs.rst): distinct dentry, inode, open-file, and superblock roles plus operation/context contracts. Follow referenced locking/mount documentation and actual methods for the touched behavior.
- [Volatile write-cache control](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/block/writeback_cache_control.rst): completion is not necessarily persistence; `REQ_PREFLUSH` orders previously completed writes onto nonvolatile media, while `REQ_FUA` makes the flagged write's completion durable. Stacked devices must preserve the contract.
- [Writeback error sequences](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/core-api/errseq.rst): errors observed by multiple subscribers require cursors, and shared cursor updates require synchronization; an atomic canonical error alone is insufficient.
- [Allocation contexts](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/core-api/memory-allocation.rst): reclaim recursion through filesystem/I/O and scoped restrictions.
- [Page pins](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/core-api/pin_user_pages.rst): direct I/O and long-term pins interact with writeback, migration, and file-backed pages.

Keep factual source observations separate from proposed Rust structures, design assumptions, and measured outcomes. A checksum verifies an integrity condition, not the trustworthiness of arbitrary filesystem metadata; a journal is not by itself a proof of every advertised durability guarantee.

## Ordered decision workflow

Answer the following for each VFS mechanism, block subfamily, and filesystem format/feature, including pseudo, network, stacked, and legacy filesystems.

1. **Port the behavior.** Enumerate required syscalls, errno/partial-I/O/signal behavior, mount flags/options, locking, user namespace and permission semantics, on-disk features, recovery outcomes, and compatibility surfaces such as ioctl/statfs/proc/sysfs. Separate internal data representation from required Linux behavior. Do not replace a missing operation with success, universal `ENOSYS`, a userspace filesystem shim, or a read-only claim for a required writable filesystem.
2. **Evaluate reuse.** Review the [dependency ledger](../../../docs/dependencies.md) and exact source/version/license of candidates for endian codecs, checksums, compression, indexing, transport, or filesystem parsing. Audit bounds, fallibility, allocation context, feature flags, crash consistency, concurrency, and transitive non-Rust code. A standalone FAT/ext reader, userspace filesystem library, or sector API is not a drop-in VFS/writeback/durability implementation. Reuse only the verified mechanism; record direct port or rejection with evidence when semantics do not fit.
3. **Consolidate shared mechanisms.** Use common pathname/permission handling, open-file lifetime, page cache, block requests, completion/cancellation, writeback-error tracking, extent/range arithmetic, and flush propagation where contracts align. Coordinate caches with memory reclaim and direct I/O. Share journal primitives or parsers only when the formats' ordering and trust boundaries genuinely match; do not merge unrelated recovery protocols behind a misleading generic transaction API.
4. **Simplify safely.** Prefer checked byte-oriented parsing, explicit state machines, one coherent cache owner, and narrow format-specific operations. A limited bring-up format or feature set is acceptable only as an explicitly unqualified milestone with every missing requirement retained in coverage. Do not discard barriers, mount options, xattrs, quotas, ACL/security labels, or error reporting because basic file copying works. A conservative write-through debug mode must not be mislabeled full performance or feature parity.
5. **Review security and invariants.** Complete the lifecycle, durability, and hostile-input reviews below. Identify permissions and LSM hooks before exposing objects; reject malformed inputs according to the contract without panics or unbounded privileged work.
6. **Improve after correctness.** Profile lookup/cache behavior, extent searches, allocation, dirty throttling, I/O batching, queue contention, copies, and flush frequency. Improve locality, indexed lookups, batching, coalescing, readahead, and queue affinity only while preserving wakeups, fairness, coherence, error observation, and crash invariants. Never gain a benchmark by acknowledging nondurable data as durable or weakening the reference's security/durability settings.

## Domain implementation sequence

### VFS, namespaces, and cached data

- Establish distinct lifetimes and identifiers for superblocks, mounts, dentries including negative entries, inodes, open file descriptions, and descriptor-table entries. `dup`/fork can share open-file offsets and status; an unlinked-but-open inode remains usable. Define mount and inode teardown relative to outstanding operations and deferred reclamation.
- Port pathname traversal and permissions with symlinks, `.`/`..`, mount crossings, chroot/root handles, directory descriptors, rename races, lookup flags, namespace ownership, and user-copy failures. Review `openat`/`openat2` constraints, atomic create/exclusive behavior, hard links, sticky/setgid directories, id mapping, capabilities, ACLs, labels, and authorization rechecks. Do not normalize arbitrary filename bytes as UTF-8 or accidentally change case sensitivity.
- Define locks and atomicity for lookup/create/unlink/link/rename, including cross-directory and mount constraints, rename flags, notifications, and interaction with concurrent open/stat/readdir. Specify directory iteration cookies and restart behavior rather than treating a directory as a stable vector.
- Implement shared page-cache identity and dirty/writeback state before exposing buffered I/O and file mappings. Order truncate/hole punch, fault/COW, writeback, direct I/O, invalidation, and pinned pages. A zero-copy path must retain pages and authorize access until every completion/cancellation is settled; zero-copy is not a substitute for coherence.
- Preserve partial read/write results, append placement, shared offsets, sparse holes, EOF, error precedence, nonblocking behavior, signals, `poll`/asynchronous completion, time updates, and per-filesystem semantics. Do not assume a helper's return type already encodes Linux short-I/O behavior.

### Block queues, writeback, and durability

- Begin with request range/sector arithmetic, logical versus physical block sizes, alignment, queue limits, scatter/gather, ownership, exactly-once completion, and failure/cancellation. Include requeue, timeout, unplug/reset, media errors, and queue drain. Extend to partitions, device mapping, RAID, integrity/encryption, zoned devices, discard, and other tracked subfamilies rather than declaring a single raw device complete.
- Define dirty-page/inode accounting, background writeback, dirty throttling, cgroup ownership, congestion/backpressure, reclaim interaction, and error propagation. Inject allocation/I/O failures throughout. No-filesystem/no-I/O allocation scopes must survive indirect helpers and callbacks; avoiding one explicit recursive call is insufficient.
- Write a durability dependency graph: data writes, metadata writes, log/checkpoint/commit records, preflush, FUA or required emulation, completion, and user acknowledgement. Distinguish CPU memory barriers, device ordering, and persistence barriers. Record each queue's truthful volatile-cache and FUA capabilities and carry semantics through every remapping/stacking layer.
- Define `fsync`, `fdatasync`, `msync`, synchronous writes, filesystem sync, close/error observation, freeze/unmount, and directory-entry persistence individually against the baseline. Do not infer namespace durability from an atomic rename or a successful ordinary write. Track writeback errors for independent open-file observers; synchronize shared cursors without swallowing a previous error.
- Test separate lost-write, torn-write, reordered-write, and reported-I/O-error models. Specify atomic-write guarantees only for actually supported alignment/size/hardware contracts. Never claim generic media makes arbitrary writes atomic or that a successful readback proves survival across power loss.

### Format parsing, journal/recovery, and hostile images

- Treat superblocks, geometry, feature bits, trees/extents, directories, bitmaps, reference counts, xattrs, compressed data, journals, and externally modified images as hostile. Decode endianness explicitly; check arithmetic before multiplying block counts or forming slices. Validate ranges, alignment, overlap, recursion/cycles, object identity, checksums, and resource consumption before allocating or following references.
- Define compatibility versus incompatible feature negotiation, read-only versus writable mount conditions, backup metadata selection, and error/remount policy per format. Do not guess the meaning of unknown feature bits or repair user media silently. Even read-only mount may invoke recovery; make writes and their authorization explicit.
- For each journal/COW/log-structured format, specify transaction membership, data/metadata ordering, commit visibility, checksummed records, replay bounds, allocation/free ordering, orphan handling, checkpoint/truncation, and idempotence. Recovery must reject impossible/corrupt states rather than manufacture successful completion. Test mount interrupted by failure and recovery interrupted again.
- Model ENOSPC, metadata-reserve exhaustion, quotas, memory exhaustion, bad sectors, removed media, checksum failures, and read-only transitions. Explain which acknowledged data must survive and which unacknowledged operations may appear after restart. Keep the on-disk oracle independent of the implementation that produced the image.

## Mandatory invariant review

Produce a lifecycle/lock table and crash-consistency table. Include these counterexamples:

- A dentry is evicted while a lookup uses it, an inode number is reused while an old handle survives, or a rename crosses a permission/namespace boundary during validation.
- Buffered and direct I/O disagree on the same bytes; truncate frees blocks while a fault, pin, or writeback still references them.
- A timeout and completion both free a request; a removed block device receives a late request or an obsolete completion tag.
- Filesystem reclaim waits on a lock held by the allocation that invoked reclaim; error handling allocates from the same exhausted path.
- Commit is acknowledged before required media persistence, a flush is dropped in a stacked device, or one observer clears another observer's writeback error.
- A hostile image causes out-of-bounds access, integer overflow, infinite traversal, decompression amplification, double allocation, cross-file disclosure, or unauthorized writes during recovery.

For each transition, identify the owner, locks/context, charge/reservation, success and partial-failure states, durability point where relevant, and safe retirement condition. Rust memory safety does not prove metadata consistency, authorization, or data durability.

## Definition of done and evidence gates

No kernel or storage results exist merely because this skill is present. For an implementation change, every applicable obligation must have observed evidence, not only a checklist.

| Obligation | Required evidence |
| --- | --- |
| Behavioral parity | Source/UAPI/format-feature mapping, exact reference configuration, and differential tests for values, errors, partial I/O, namespace/permission behavior, and concurrent object lifetime. |
| Parser and failure safety | Unit/property/fuzz cases for corrupted images and range arithmetic, bounded-resource checks, allocation/I/O failures, cancellation, races, and mount/replay failure with no corruption outside the authorized target. |
| Durability/recovery | Operation traces and independent post-crash oracle for each declared persistence boundary; crash/reorder/torn-write/lost-write tests through journaling, stacked queues, and recovery interrupted again. |
| External regression suites | Relevant baseline selftests, filesystem regression/stress suites, and format-specific utilities run against documented compatible cases; record unsupported test prerequisites as blockers, not passes. |
| QEMU and physical media | Both paths from initial storage bring-up, including real controller DMA/IOMMU, queue depth, volatile-cache/FUA behavior, flush errors, resets/removal, and suspend/resume. VM disks alone cannot qualify physical persistence. |
| Runnable bare-metal suite | Exact existing Rust-owned orchestration invocation, suite/case IDs, boot artifact digest, machine/controller/firmware identity, sacrificial-media identifiers, console/recovery setup, timeout, exit status, oracle, and raw logs. A prose scenario is not a runnable or executed suite. |
| At-least-Linux performance | Per-workload throughput, latency/tails, CPU, memory, startup/mount/recovery time, and power with repeated matched pinned-Linux runs and confidence intervals, not an aggregate score alone. |

Maintain physical coverage across CPU/platform and controller/media vendors as available, with named missing hardware blockers. Use only positively identified sacrificial disks or disposable images and prohibit production/host-root devices. Verify target identity out of band; exported suite metadata must not collect unique hardware serial IDs. Keep image mounting, fuzzing, power-cut, and corruption experiments isolated. Require remote-console access and a known-good boot path before destructive recovery testing. A simulated crash is valuable but does not replace safely controlled physical power-loss evidence when that guarantee is claimed.

Match Linux configuration, filesystem format/features/mount options, disk state, cache settings, firmware, topology, mitigations, compiler settings, and workload/data-set size. Include warm/cold cache, memory pressure, durable synchronous writes, large sequential I/O, small random I/O, metadata contention, and recovery. Capture variance/noise and individual regressions. Do not disable barriers, checksums, security, or error handling to win. Inconclusive/non-inferior-looking results are not demonstrated passes.

Apply the standing [definition of done](../../../docs/definition-of-done.md). The actual [bounded smoke suite](../../../docs/bare-metal-suite.md) uses this repository-root interface:

```text
cargo run -p baremetal -- run --output <new-directory> --label <label> --expect-release <exact-osrelease> --environment <reference|qemu|bare-metal>
```

Choose one environment value, an exact expected running release, and a new output directory. Its filesystem/sync/rename/link checks stay inside a self-created sandbox; they do not mount, raw-write devices, change settings, elevate, reboot, or perform physical power-loss/crash injection. They are functional smoke, not proof of durable-media or filesystem parity. The environment label is an operator assertion, not proof of physical execution. Reference-host success validates the runner only; preserve individual pass/fail/skip/unavailable results. Broader storage suites need separate runnable cases and evidence, not invented commands.

Only the current workstation is available initially; controller/media/platform diversity remains named qualification blockers. The user operates installation, boot selection, and recovery. Do not run host boot/install/reboot/firmware/destructive disk actions. Under [packaging](../../../docs/packaging.md), the existing storage-free M1 diagnostic may be tried before rootfs/initramfs/userspace only on separate user-owned recoverable media with independent known-good recovery; this is not a Linux-replacement package, physical qualification or durable-storage claim. A Linux-replacement package still requires real storage, durable filesystem, root/initramfs, init/userspace and broader gates, preserving the working kernel and supported boot/recovery path. Native Limine ELF is not direct systemd-boot EFI/PE/Linux compatibility. Initial Arch/CachyOS userspace and balanced server profiling do not mean downstream CachyOS kernel patches are in scope.

Execute gates only when the assignment authorizes execution; planning/edit workers hand the gate list to the integration owner and report no fabricated results. Update current [verification](../../../docs/verification.md), [performance](../../../docs/performance.md), and [bare-metal](../../../docs/bare-metal.md) evidence through their designated owners.

## Stop conditions and handoff

Stop mutation or qualification when persistence capabilities, on-disk format semantics, flush propagation, replay safety, cache/pin ownership, or target-media identity are unresolved. Stop a physical experiment if recovery or isolation is lost. Do not suppress a failing fsync, silently remount as a substitute for required writable behavior, or mark an untested filesystem compatible.

Hand off the six decisions, pinned provenance, feature/mount/UAPI matrix, lifecycle/lock and durability graphs, threat analysis, migrated callers, executed versus planned test results, crash traces and independent oracle, runnable-suite artifacts, performance comparisons, physical coverage, exact blockers, and remaining unqualified scope. Keep changes within assignment ownership and update existing plans/changelog as directed. This skill installs nothing and contains no scripts.
