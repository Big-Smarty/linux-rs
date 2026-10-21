# Pinned upstream coverage and inventory

## Scope and current state

This is the complete **structural inventory** of Linux **6.18.57**, retrieved on **2026-10-19**, not a compatibility or completion percentage. The bounded [publication checkpoint](implementation.md#publication-checkpoint) routes ten workstreams `in_progress`; 2,613 remain `not_started` (the first-userspace slice since raised this to fourteen and 2,609, and the signal model (`ws-kernel-signal-c`) adds one more, see [routing](implementation.md#routed-implementation-status)). Actual source and consumer evidence, not directory counts, determine the narrow claims. Latest authority is the post-publication continuation in [A18–A20](decisions.md); M0's unresolved gates and all M1–M8, physical and performance obligations remain open.

The three machine-readable inputs are:

- [Reference](../planning/reference.tsv): immutable upstream object identities, acquisition facts, and structural counts.
- [Workstreams](../planning/workstreams.tsv): path prefixes, accountable plan files, ordering priorities, and current routed implementation status.
- [Upstream paths](../planning/upstream-paths.tsv): every tree entry in the pinned snapshot, without source contents.

The [project audit](project-audit.md) checks their offline consistency. It does not fetch upstream, authenticate a signature, prove source-to-binary equivalence, or establish semantic coverage. The [compatibility](compatibility.md), [verification](verification.md), [performance](performance.md), and [bare-metal](bare-metal.md) plans define separate behavioral and qualification obligations.

The [exhaustive definition of done](definition-of-done.md) remains a standing rule: no whole-kernel completion claim until the entire pinned scope is implemented and evidence-qualified. The current delivery includes a real bounded bootstrap and the separate [functional smoke suite](bare-metal-suite.md), not Linux parity. Initial userspace remains **Arch/CachyOS with a balanced server profile**, not downstream CachyOS kernel patches. A storage-free M1 diagnostic trial is distinct from a future full replacement package: [packaging](packaging.md) retains real root/initramfs/storage/userspace and deployment gates, known-good boot and user-controlled recovery.

## Observed provenance

| Item | Observed value |
| --- | --- |
| Repository | `https://github.com/gregkh/linux` |
| Tag | `v6.18.57` |
| Annotated tag object | `c05de972ca192e22ce318dd70ce8e990b9466f6d` |
| Commit | `2ff600d29ee478d0a8d46ef8a58afb5e038fe692` |
| Root tree | `911d5155c230d7d778ac38585e01e8ab46d75a90` |
| Retrieval date | `2026-10-19` |
| Current signature status | `locally_verified_kernel_org_wkd_fingerprint_pinned_trust_undefined` |
| Original acquisition signature status | `github_verified_not_locally_verified` |
| GitHub tag verification | `verified=true`, reason `valid`, verification timestamp `2026-10-15T10:14:03Z` |

The original inventory used GitHub API observations, not an independent local signature check. The tag reference resolved to the annotated tag object, that object to the commit, and the commit to the root tree. Its primary records remain the [tag reference](https://api.github.com/repos/gregkh/linux/git/ref/tags/v6.18.57), [immutable annotated tag](https://api.github.com/repos/gregkh/linux/git/tags/c05de972ca192e22ce318dd70ce8e990b9466f6d), [immutable commit](https://api.github.com/repos/gregkh/linux/git/commits/2ff600d29ee478d0a8d46ef8a58afb5e038fe692), and [immutable root tree](https://api.github.com/repos/gregkh/linux/git/trees/911d5155c230d7d778ac38585e01e8ab46d75a90). Git object hashes establish identity/structural consistency, not publisher trust by themselves.

Subsequent independent local fetches from kernel.org and GitHub matched the exact tag object → commit → tree chain above. Isolated GPG `verify-tag` reported **Good signature** for primary fingerprint `647F28654894E3BD457199BE38DBBDC86092693E`, pinned by the [kernel.org HTTPS signature page](https://www.kernel.org/signature.html) and matching WKD/TLS key retrieval. GPG explicitly reported **`TRUST_UNDEFINED` / `[unknown]`**: this is fingerprint-pinned HTTPS/WKD authentication, not Web-of-Trust or ultimate trust. The raw local record is `target/implementation-prereqs/upstream-verification.txt`; [implementation](implementation.md) and [reference metadata](../planning/reference.tsv) preserve the current evidence and historical distinction. No global GPG trust-store change is implied.

## Complete counts

The root itself is not an `upstream-paths.tsv` entry. Directories are included as `tree` entries, not merely inferred from file paths. Git symlinks are blobs; their targets were not followed. Executable-mode source files remain upstream metadata, not imported executable tools.

| Measure | Observed count |
| --- | ---: |
| All inventory entries, excluding root | 97,294 |
| Blob entries | 91,246 |
| Tree entries, excluding root | 6,048 |
| Gitlink/commit entries | 0 |
| Root immediate entries | 41 |
| Root immediate directories | 24 |
| Root immediate blobs | 17 |
| Regular-mode blobs (`100644`) | 90,007 |
| Executable-mode blobs (`100755`) | 1,154 |
| Symlink-mode blobs (`120000`) | 85 |
| Workstreams, including root fallback | 2,623 |
| Workstreams receiving at least one entry | 2,622 |
| P0 / P1 / P2 / P3 workstreams | 620 / 544 / 1,419 / 40 |
| Tree objects reconstructed during acquisition, including root | 6,049 |

The fallback `.` intentionally receives no entries in this snapshot because each top-level path has an explicit workstream. Its presence makes the routing rule total; future unclassified entries must still be reviewed rather than treating fallback assignment as adequate detailed planning.

### Entries by top-level directory

Counts include the named directory entry and every descendant. The remaining 17 entries are the root's metadata/build/documentation blobs.

| Upstream directory | Entries |
| --- | ---: |
| `Documentation` | 11,554 |
| `LICENSES` | 28 |
| `arch` | 19,024 |
| `block` | 102 |
| `certs` | 13 |
| `crypto` | 197 |
| `drivers` | 38,967 |
| `fs` | 2,358 |
| `include` | 6,853 |
| `init` | 18 |
| `io_uring` | 79 |
| `ipc` | 14 |
| `kernel` | 716 |
| `lib` | 812 |
| `mm` | 203 |
| `net` | 2,076 |
| `rust` | 261 |
| `samples` | 334 |
| `scripts` | 633 |
| `security` | 321 |
| `sound` | 3,095 |
| `tools` | 9,581 |
| `usr` | 15 |
| `virt` | 23 |

## Acquisition and truncation handling

Only Git metadata was acquired for the inventory: paths, kinds, modes used during acquisition, object identities, and tag/commit/tree API records. No Linux source blobs, firmware bytes, build artifacts, or non-Rust acquisition scripts are checked into this project. The exported schema deliberately contains path/kind/object/workstream rather than source text, executable bits, or symlink targets.

GitHub documents that recursive tree responses can truncate and directs clients to retrieve smaller trees; its documented recursive limits are 100,000 entries and 7 MB. A count below a numerical limit is **not** proof of completeness. The controlling flag is `truncated`, followed here by reconstruction of the returned tree identities. See the primary [Git trees API documentation](https://docs.github.com/en/rest/git/trees#get-a-tree).

Observed acquisition:

1. Resolve tag reference → annotated tag object → commit → root tree. Require matching requested/returned object identities and expected object kinds at each step.
2. Fetch the root without `recursive`, obtaining 41 immediate entries and `truncated=false`.
3. Fetch the root with `?recursive=1`. This returned **72,518 entries and `truncated=true`**. This response was explicitly discarded as an inventory source; it was not declared complete or merged as though complete.
4. Split at the root's 24 direct subtree objects. Fetch each subtree by its SHA with `?recursive=1`. **All 24 responses reported `truncated=false`.** Retain each top-level tree entry from the complete nonrecursive root response, and prefix every returned child path with its owning top-level directory. No further split was necessary for this snapshot.
5. Had any subtree response been truncated, discard that partial slice, fetch its nonrecursive immediate entries, retain those entries once, and repeat recursively for each child tree until every retained slice is complete. A truncated nonrecursive response or failed/unresolved child is a blocker, not permission to set `inventory_complete=true`.
6. Check uniqueness and parent-tree closure while assembling entries. Reconstruct each Git tree payload from its immediate children using the acquisition-time modes, bytewise Git tree ordering, names, and raw child object IDs; hash `tree <payload-byte-length>\0<payload>` with SHA-1. All **6,049** tree identities, including the pinned root, matched during acquisition. This establishes that assembled directory metadata reproduces the fetched object identities; it does not validate blob contents, which were not downloaded. Git describes its [object model](https://git-scm.com/book/en/v2/Git-Internals-Git-Objects) and [object-ID encoding](https://git-scm.com/docs/gitformat-pack).
7. Generate workstreams, apply longest component-prefix ownership, and write deterministic UTF-8 TSV records with LF endings and final newlines. Only after all retained slices and object reconstruction succeed may the reference claim `inventory_complete=true`.

The original acquisition made **34 API responses**: three tag/commit resolution records, one nonrecursive root, five additional nonrecursive first-level discovery trees (`arch`, `drivers`, `fs`, `net`, `sound`), one discarded truncated recursive root, and 24 complete recursive subtree responses. Full HTTP response archives, acquisition-time modes and raw signature output are not embedded in the checked-in TSVs. The later local signature/source-object evidence is separate; it does not rewrite this acquisition history. Reproduction refetches immutable upstream objects; the offline audit cannot reconstruct the Git tree from the reduced TSV schema alone.

### Reproduction procedure

The following is an algorithm specification, not an installed non-Rust implementation. Any permanent project acquisition tool must be implemented in Rust, separate from the offline audit and subject to the [dependency/toolchain policy](toolchain.md).

- Request `GET https://api.github.com/repos/gregkh/linux/git/ref/tags/v6.18.57`, follow the tag object and commit API URLs, and compare all four recorded object identities. Use the immutable object IDs for all subsequent requests, not a moving branch or an unpinned raw URL.
- Request `GET https://api.github.com/repos/gregkh/linux/git/trees/911d5155c230d7d778ac38585e01e8ab46d75a90` without a `recursive` parameter. Omitting the parameter matters: GitHub treats even `recursive=false` as enabling recursion.
- Execute the complete-slice algorithm below; request metadata only. An HTTP error, rate limit, missing field, unexpected object kind, object-identity mismatch, duplicate path, or unresolved truncation is an acquisition failure. Honor rate-limit responses and resume by immutable object ID rather than changing the baseline.

```text
collect(prefix, tree_object):
    recursive = get_tree(tree_object, recursive_parameter_present)
    require recursive.sha == tree_object
    if recursive.truncated == false:
        return every recursive entry with prefix prepended
    direct = get_tree(tree_object, recursive_parameter_absent)
    require direct.sha == tree_object and direct.truncated == false
    result = every direct entry with prefix prepended
    for each direct entry whose kind is tree:
        append collect(prefix joined with entry.path, entry.object)
    return result

inventory = collect(empty_prefix, pinned_root_tree)
require unique paths and each non-root parent present as a tree
reconstruct every directory object from acquisition metadata
require reconstructed root == pinned_root_tree
route every entry by longest component-prefix workstream
sort reference by key, workstreams by id, upstream entries by path
write exact TSV headers and final LF; retain no source bytes
```

The actual acquisition additionally used the explicitly recorded root/top-level split described above. Independent reproduction may choose a different valid partition and therefore a different request count, but must obtain the same complete path/kind/object inventory and root identity. Mode spelling uses `40000` in the Git tree payload rather than the API's zero-padded `040000`; children are sorted as Git compares names, treating a directory name as followed by `/`. Blob/tree object kinds must match their modes. Do not follow symlink blobs or fetch blobs merely to enumerate metadata.

A second independent inventory route may use external Git's filtered, no-checkout metadata acquisition into an **external scratch directory**, followed by `git ls-tree -r -t --full-tree` at the pinned commit. The remote must actually support and honor blob filtering; a source-downloading fallback is not this metadata-only method. Do not introduce a Linux checkout, helper script or second baseline into the repository. This alternate complete-inventory reconstruction was not part of the original delivery; the later local kernel.org/GitHub object and signature checks establish the narrower provenance result above.

## Workstream rules and accountable plans

`planning/workstreams.tsv` has the exact header `id`, `upstream_prefix`, `plan`, `priority`, `status`, separated by tabs. Its IDs are stable readable lower-case path-derived identifiers. Every top-level path, all **21** immediate architecture directories, all **143** immediate driver directories, all **77** immediate filesystem directories, and all **71** immediate networking directories have explicit prefix records. The **25** immediate sound directories are also explicit. Further partitions include second-level architecture/driver/filesystem/network/sound areas; kernel mechanism directories and selected shared-directory files; memory, IPC, block and io_uring mechanisms; libraries; security modules; virtualization; Rust reference code; build/configuration machinery; documentation; UAPI headers; test and selftest families. Headers, license metadata, tests, documentation, configuration, and upstream non-Rust tools remain in scope even though they are not kernel runtime implementation.

The schema remains exactly **five columns** and accepts only `not_started` or `in_progress`. `cargo run -p xtask -- status` prints the current counts, and the [routing table](implementation.md#routed-implementation-status) names every `in_progress` row. The [row-to-source/evidence map](implementation.md#routed-implementation-status) records selected consumed mechanisms, not whole prefixes or a `done` state.

For an entry `p`, a prefix matches if it is `.`, equals `p`, or is followed in `p` by `/`. The longest matching prefix wins. This is component-aware: `net` cannot match `network`, and a prefix naming one file cannot match a longer filename. Exactly one workstream is recorded per entry. Cross-subsystem dependencies are described in the linked plans, not by duplicating source entries. Adding a more-specific workstream requires recalculating affected assignments.

Priority means ordering, **never final-scope exclusion**:

| Priority | Intended ordering |
| --- | --- |
| P0 | Provenance/toolchain, boot/platform primitives, shared mechanisms, architecture/UAPI foundations; gated by M0–M3 as applicable. |
| P1 | Storage, networking, process/container/server functionality and physical-machine prerequisites; M1–M5 dependency gates apply. |
| P2 | Broad facilities, remaining platform families, multimedia, virtualization and general closure; work may overlap earlier milestones when dependencies permit. |
| P3 | Explicit legacy/less-common closure families, still required by the pinned scope and M7–M8 qualification. |

A priority is not a milestone assignment, hardware readiness assertion, dependency edge, or permission to implement without its prerequisite gates. P0 includes reference/header material needed to establish contracts; it does not imply that every architecture or feature represented by such material boots first.

| Structural areas | Accountable plans |
| --- | --- |
| Boot/common kernel mechanisms, shared Rust reference primitives and libraries | [Core](subsystems/core.md) |
| Allocation, page management, DMA/mapping and reclamation | [Memory](subsystems/memory.md) |
| Processes, scheduling, cgroups, credentials-related process contracts and execution | [Process](subsystems/process.md), with security-specific entries assigned to [security](subsystems/security.md) |
| SysV/POSIX IPC and futex mechanisms | [IPC](subsystems/ipc.md) |
| Block/storage stacks and selected storage driver families | [Storage](subsystems/storage.md) |
| Every filesystem family, VFS-related source and io_uring | [Filesystems](subsystems/filesystems.md) |
| Every net family, packet/control mechanisms and selected network library/header areas | [Networking](subsystems/networking.md) |
| Every architecture and platform primitive family | [Architectures](subsystems/architectures.md) |
| General device families including sound and graphics | [Drivers](subsystems/drivers.md) |
| ACPI/DT/firmware and firmware lifecycle mechanisms | [Firmware](subsystems/firmware.md) |
| LSMs, crypto, keys, integrity and security-specific process code | [Security](subsystems/security.md) |
| Tracing, audit, counters, diagnostics and related tools | [Observability](subsystems/observability.md) |
| KVM/virtualization infrastructure | [Virtualization](subsystems/virtualization.md) |
| BPF, modules, livepatch and related programmable mechanisms | [Extensions](subsystems/extensions.md) |
| UAPI and architecture-dependent userspace headers | [Compatibility](compatibility.md) |
| Selftests, KUnit, fault injection, verification and reference testing tools | [Verification](verification.md) |
| Build/configuration, Rust integration and executable-tool replacements | [Toolchain](toolchain.md), [dependencies](dependencies.md) |
| Licensing, notices, maintainership and upstream process metadata | [Licensing](licensing.md), [maintenance](maintenance.md) |
| Physical platform tooling and qualification concerns | [Bare metal](bare-metal.md) |
| Remaining reference documentation | [Research](research.md) |

Directory ownership is not an ABI promise. Linux distinguishes its stable userspace interface from its deliberately non-stable internal driver interface; see the pinned [upstream explanation](https://raw.githubusercontent.com/gregkh/linux/2ff600d29ee478d0a8d46ef8a58afb5e038fe692/Documentation/process/stable-api-nonsense.rst). Rust internal APIs may be redesigned and bundled, but externally observable pinned behavior and hardware requirements cannot be removed by renaming a workstream.

## Dynamic closure registries required before completion claims

Static tree enumeration prevents forgotten source areas but cannot enumerate all runtime combinations or establish feature completion. The bounded bootstrap source/evidence map is in [implementation](implementation.md); the whole-scope registries below remain required implementation work, not artifacts claimed complete by this delivery.

| Registry | Required identity and relationships | Evidence before a completion claim |
| --- | --- | --- |
| Source/provenance and symbols | Upstream commit/path/blob, original license/exception/notices, declaration or symbol identity, architecture/config guards, call/data dependencies, downstream Rust path/revision and owner. Include assembly, generated inputs and inline code, not only exported C functions. | Reviewed port/transformation record, downstream implementation mapping, preserved provenance, invariant review and linked executed tests. Absence from a symbol extractor is not exclusion. |
| Syscalls and ABIs | Architecture/personality, number/name, entry convention, arguments, structure layouts/alignment, errors, restart/signal semantics, compat/time32/time64 variants; ioctl/netlink/socket/procfs/sysfs/debugfs/ELF/vDSO and filesystem/protocol contracts. | Differential reference results for normal/invalid/racing inputs, wire/layout fixtures, capability/namespace checks, executable userspace compatibility evidence, explicit unsupported/blocker records. |
| Kconfig/build | Symbol, type/default/dependencies/select/imply/choice, architecture applicability, feature interactions, generated outputs and corresponding Rust configuration. | Config closure, dependency checks and executed representative/pairwise/adversarial configurations. Merely retaining the Kconfig filename does not implement any configuration option. |
| Devices/platforms | Driver family plus PCI/USB/ACPI/DT/platform IDs, compatible revisions and quirks, firmware/microcode identity and licensing, buses, DMA/IOMMU/IRQ/power/error behavior, required resources. | Device-specific implementation, probe/remove/hotplug/reset/recovery tests, physical machine identity/firmware/topology, negative cases and reproducible logs. A family row is not every hardware implementation completed. |
| Filesystems/protocols | Format/protocol version, optional/legacy features, endianness, mount/session flags, upgrade/recovery behavior and peer interoperability. | Corpus/version matrix, crash/durability/corruption or packet/protocol fault testing, baseline compatibility and actual results. A directory can contain several independent formats or wire contracts. |
| Qualification | Workload + hardware/config/security/firmware/toolchain identity, reference and Rust revisions, environment/noise controls, repetitions/statistics, correctness gate and failure records. | At-least-baseline performance evidence per required metric and workload plus QEMU and real-hardware results. Untested hardware, inconclusive non-inferiority and averages hiding regressions are not passes. |

The registries must be derived repeatedly as code/configuration changes, permit many-to-many source-to-Rust mappings, preserve negative evidence and named unavailable-hardware blockers, and connect each completion claim to its exact executed artifacts. Shared implementation is encouraged when invariants permit; shared code does not erase separately observable ABIs, device quirks or test obligations. No fixed per-symbol/ABI/Kconfig/device count is asserted here because those registries have not been generated.

## Limits, release obligations and baseline updates

- Structural coverage is complete for this recorded Git tree, not for unversioned external firmware repositories, out-of-tree modules, later kernels, generated build products, or every possible reference configuration. Such dependencies require explicit provenance and compatibility records. Legacy C kernel modules cannot be loaded as an implementation shortcut.
- No physical candidate boot, full Linux correctness or kernel performance qualification is claimed. Bare metal remains an M1 co-development obligation, with a safe storage-free diagnostic trial distinguished from a Linux-replacement package. Only the workstation is available; user-controlled boot/recovery and missing multi-vendor/NUMA/other physical coverage remain explicit gates. Do not install, reboot, change firmware or perform destructive host testing.
- At-least-Linux performance is a release requirement, never inferred from Rust, path counts or algorithm choice. Preserve security settings and Linux-facing semantics while removing avoidable allocations, copies, work and contention only when correctness permits. Apply the full [performance protocol](performance.md) and [hardware qualification protocol](bare-metal.md).
- A workstream advances to `in_progress` only for genuine routed implementation with linked evidence, not because its document exists or all paths are assigned. That status does not satisfy completion: per-file/mechanism implementation and reviewed behavioral, adversarial, stress, recovery, hardware and performance evidence remain required under [verification](verification.md).
- A new upstream baseline is a deliberate update: resolve and authenticate its identities, rebuild the complete metadata inventory with truncation handling, diff added/removed/changed/renamed paths and object IDs, reassign every entry by component-prefix ownership, update affected license/ABI/Kconfig/device/evidence registries, and preserve prior release provenance. A path deletion or rename must not silently delete a compatibility obligation. All maintained branches must declare the baseline and security-backport delta they actually implement; see [maintenance](maintenance.md).

The project audit and bounded functional runner are appropriate setup tools; neither substitutes for exhaustive kernel delivery gates. Directory and status totals are planning counts, never a compatibility percentage.
