# Security, trust and cryptography

## Status, scope and release contract

**Planning status: `not_started`.** This is a proposed direct Rust port of Linux **6.18.57**, not an implemented security boundary, an audit result, a certification, or evidence of a secure kernel. M1–M3 must establish protection and credential invariants before first user code; M4–M5 integrate storage/network/container checks; M6 develops the broad facilities below; M7 closes every baseline configuration and architecture; M8 requires measured parity and security qualification. Security is not deferred to M6 simply because broad policy support lands there.

Accepted architecture is a **modular monolithic Rust kernel** with fixed 6.18.57 feature scope and explicit reviewed security deltas; changing the feature baseline requires a separate decision. Only function-local `asm!`/`naked_asm!` are permitted when unavoidable and supported by proof/review contracts; `global_asm!`, standalone assembly and C runtime escape paths are prohibited. Every in-baseline module function requires a Rust replacement; arbitrary third-party/proprietary out-of-tree modules are not implicitly in scope.

Related authorities: [process and namespaces](process.md), [memory protection](memory.md), [filesystems](filesystems.md), [networking](networking.md), [IPC](ipc.md), [modules and BPF](extensions.md), [observability](observability.md), [virtualization](virtualization.md), [firmware trust](firmware.md), [dependencies](../dependencies.md), [compatibility and delta ledger](../compatibility.md), [verification](../verification.md), [performance](../performance.md), and [physical lab](../bare-metal.md).

The [standing definition of done](../definition-of-done.md), [runnable bounded smoke suite](../bare-metal-suite.md) and [packaging](../packaging.md) distinguish historical planning, the bounded [bootstrap](../implementation.md) and whole-kernel completion. None establishes the security-facility implementations or qualification described here. Arch/CachyOS userspace and a balanced server profile are the first workload; downstream CachyOS kernel patches are not silently part of the baseline.

Upstream facts below are grounded in the pinned sources linked in each section. Proposed implementation choices are not upstream guarantees. Some upstream narrative documents explicitly describe old interfaces: the [LSM overview](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/security/lsm.rst) warns that its APIs are outdated. Extract the final hook, action, format and configuration matrices from the pinned implementation/UAPI and selftests, not just prose, and record conflicts before porting.

### Explicit definition of done

Each subfamily is done only when its complete pinned configuration/UAPI/operation matrix has implementation and differential-test evidence; legitimate existing policy/userspace works unchanged at the documented interface; denial, allocation failure, concurrent mutation and teardown are tested; authorization and audit match the reference except approved security deltas; every relevant architecture has qualified emulated **and physical** evidence; and every required workload meets at-least-reference performance with security settings held equal. An unimplemented feature, missing hardware, inconclusive result or a passing subset is not a pass. The security-facility workstreams described here remain `not_started`.

## Threat boundaries and non-negotiable invariants

| Boundary | Attacker-controlled inputs and required separation |
|---|---|
| Userspace → kernel | Syscall numbers, compat structures, nested pointers, credentials, namespaces, filesystem images and asynchronous buffers; copy/snapshot mutable metadata, validate lengths/overflow, use fault-safe user access, and never create Rust references to memory whose concurrent mutation invalidates them. |
| Tenant → tenant | UID/GID mappings, cgroups, IPC, ptrace, key possession, network labels and passed descriptors; namespace-root is not host-root and a retained descriptor carries its baseline authority. |
| Device/firmware → kernel | DMA, interrupts, ACPI/DT tables, microcode, TPM responses and malicious removable devices; require mapping ownership, IOMMU isolation where supported, bounded parsing and provenance. Rust ownership does not constrain external DMA. |
| Module/BPF/debugger → kernel | Privileged extension loading is a security policy decision, not a safety proof; BPF input is untrusted even if its author used Rust. Constrain executable mappings, verifier authority, credentials and disclosure. |
| Guest ↔ host | A guest controls exit state, virtual devices and shared buffers; confidential guests additionally treat host-controlled input as hostile. No memory-safety argument substitutes for hardware/firmware guarantees. |
| Microarchitecture ↔ protection domain | Speculation, caches, SMT, PMUs, predictor state, transient faults and timer precision can violate assumptions despite memory-safe source. Maintain architecture-specific mitigation and residual-risk records. |
| Supply chain → build/runtime | Pin source, features, compiler and notices; validate transitive native code, build scripts and inline assembly; signatures authenticate provenance, not correctness. |

Safe Rust can prevent some memory errors in sound abstractions. It does **not** eliminate authorization mistakes, races in protocol design, deadlocks, cryptographic misuse, DMA faults, side channels, speculation bugs or unsafe/compiler defects. Never market the port as audited merely because a crate, tool, memory-safe language or third-party report was used.

Every intentional security behavior change belongs in the central compatibility delta ledger: stable ID, pinned behavior/reproducer, vulnerability or threat rationale, exact changed success/error/audit semantics, affected userspace/configurations/architectures, upstream fix relationship, mitigation trade-offs, reviewer/approval, differential tests, release note and rollback/forward-fix policy. Do not reproduce an exploitable defect just to win parity; do not silently tighten behavior or call rejection of all input a fix. Preserve non-vulnerable use cases and report any remaining compatibility impact. Approved exclusion of legacy C modules is explicit; it does not excuse leaving their functionality unported.

## 1. Credentials, DAC, capabilities and namespace authority

**Authority:** [credentials](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/security/credentials.rst), including distinct subjective/objective identities, and [capability implementation](https://github.com/gregkh/linux/blob/v6.18.57/security/commoncap.c). Exact capability numbers and wire structures come from pinned `include/uapi/linux/capability.h`, not a new project enumeration.

1. After task lifetime, RCU/refcounts, UID/GID mappings and VFS permission scaffolding exist, inventory every credential read/change, DAC/ACL check and capability callsite, including in drivers and deferred workers.
2. Port immutable published credential snapshots, prepare/commit/abort transitions, temporary subjective overrides, FSUID/FSGID and supplementary groups; bind retained file/socket/request authority at the same points as Linux.
3. Implement `capget/capset`, all effective/permitted/inheritable/bounding/ambient sets, securebits, `no_new_privs`, set-ID exec, file capability xattr versions/root IDs, user-namespace scoping, idmapped mounts, dumpability and ptrace coupling. Preserve exact exec transformation order and errors.
4. Wire security hooks into every syscall and non-syscall entry: io_uring workers, kernel upcalls, SCM_RIGHTS/SCM_CREDENTIALS/SCM_SECURITY, ptrace, procfs and device ioctls. Authorization at submission and execution must follow the operation's pinned semantics rather than a blanket check once.

**Crates/shared foundations:** project-owned `no_std` credential/capability implementation; generic bitflags may assist representation after dependency review but cannot implement namespace policy. Reuse process namespaces, fallible allocation, UID/GID translation, VFS ACLs, audit subjects and reference-safe snapshots. Reject host `libc`, POSIX convenience crates or generic RBAC engines as kernel authorization authorities.

**Simplification limit/security:** typed IDs, immutable aggregates and centralized capability predicates simplify internals; do not merge all IDs into one integer, turn every capability into `CAP_SYS_ADMIN`, remove compat ABIs or treat namespace capability as globally effective. A failed exec/credential commit must not partly publish privilege. Checked arithmetic and object lifetimes are necessary but not sufficient.

**Optimization and done tests:** cache immutable group lookups and use read-mostly snapshots without per-check allocation; permission caches must include namespace, object/policy generation and relevant mount state. Differentially run LTP capability/credential tests, libcap tooling, set-ID/file-cap executables, namespace/container transitions and descriptor passing; race exec/setns/unshare/close and inject OOM at each transition. On Intel/AMD and subsequent physical architecture targets measure permission-check cycles, metadata ops/s, container start p50/p99, CPU and credential memory under identical policies. No unauthorized success and no unexplained changed denial are acceptable.

## 2. LSM framework and complete mediation

**Authority:** pinned [security framework](https://github.com/gregkh/linux/blob/v6.18.57/security/security.c), [LSM usage](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/admin-guide/LSM/index.rst) and the explicitly historical [LSM overview](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/security/lsm.rst). LSM names do not imply arbitrary runtime module loading.

1. Extract hook definitions, default returns, short-circuit/aggregation rules, blob layouts, registration ordering/exclusivity, numeric IDs, `lsm=`/`security=` options and LSM syscall/UAPI behavior from the pinned tree. Record per-hook ownership and all object creation/free/error paths.
2. Establish typed per-object security storage with initialization before exposure and cleanup after final use. Preserve configured hook order and baseline supported stacking combinations; do not invent universal stacking or infer current behavior from old prose.
3. Mediate VFS lookup/open/mmap/xattrs/rename/mount, exec/credentials, signals/ptrace, sockets/NetLabel, IPC, keyrings, module/BPF/perf, firmware, lockdown and asynchronous paths. Include anonymous inodes, overlayfs copy-up, network filesystems, transferred descriptors and user namespace crossings.
4. Export securityfs, `/sys/kernel/security/lsm`, proc attribute interfaces and LSM-specific namespaces with exact permissions and formats, then integrate each policy below with audit and configuration selection.

**Crates/bundling:** no general Rust LSM drop-in selected. Port semantics to project-owned policy adapters over shared security objects, RCU epochs, labelled network/IPC objects, binary parsers and policy-generation invalidation. Share a framework, not a single synthetic policy that loses SELinux/AppArmor distinctions.

**Simplification/security/optimization:** build-time generated typed hook dispatch is a candidate for avoiding dynamic allocation and indirect calls where it preserves ordering and configured behavior. Absence of a policy can have a fast path; absence must never become an implicit allow for an enabled but uninitialized policy. No global string formatting in allow paths; policy replacement is atomic and invalidates caches. Treat hook-coverage review as a necessary artifact, not proof that no bypass exists.

**Done tests:** produce a hook→object→entrypoint→test matrix, reference boot-option/stacking combinations and malformed proc/securityfs write tests; inject allocation failure at every blob init and policy replacement. Run enabled policy suites with syscall and io_uring variants, descriptor passing, namespaces and network labels. Measure enabled/disabled hook cycles, policy-load time/memory, allowed/denied path throughput, lock contention and audit overhead on real NUMA/SMT systems. A fast deny-all implementation fails compatibility.

### 2.1 SELinux

**Port steps:** decode pinned binary policy versions, symbol tables and class/permission mappings before decision logic; implement SID/context translation, access-vector cache (AVC), TE/RBAC/MLS decisions, constraints and transitions; then selinuxfs, status page, policy load/reload, booleans, permissive/enforcing modes, xattrs, mount labelling, exec and networking/IPC labels. Validate distro policies using existing `checkpolicy`, `load_policy`, `setfiles` and labelled workloads. [Pinned SELinux guidance](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/admin-guide/LSM/SELinux.rst) points to the upstream policy/userspace projects; policy compilation remains an external userspace workload, not a C kernel dependency.

**Crate/shared decision:** project-owned policy database/AVC; no crate is assumed to implement Linux policy semantics. Reuse bounded endian readers, interned contexts, VFS xattrs, securityfs/audit and generation-tagged caches. Do not link libselinux or libsepol into the kernel.

**Simplification and invariants:** interned typed SIDs can replace raw pointer conventions, but retain unknown-class/permission handling, MLS categories, policy-version negotiation, deny/audit masks, permissive-mode records and reload behavior. Never confuse an AVC cache hit with enduring authorization across policy/object relabel.

**Improve/test/done:** precompute validated permission tables, use read-mostly AVC shards, avoid label-string allocation on allowed hot paths. Require SELinux upstream tests plus real distro enforcing policy boots, relabel/overlayfs/container/network cases and reload under concurrent access; compare allow/deny and AVC records. Physical tests measure labelled open/exec/network throughput, p99 latency, AVC miss/reload costs and memory, not just microbenchmarks.

### 2.2 AppArmor

**Port steps:** implement profile binary protocol/versioning and feature discovery, DFA/path matching and permission transitions; add profile namespaces, hats, exec transitions, file/socket/mount/ptrace/signal mediation and pinned supported policy features; then replacement/removal, query interfaces, complain/enforce and audit. Authority: [pinned administration](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/admin-guide/LSM/apparmor.rst) and [pinned implementation](https://github.com/gregkh/linux/tree/v6.18.57/security/apparmor).

**Crate/shared decision:** port policy engine; a generic regex/glob crate is not an AppArmor DFA or path-resolution replacement. Reuse VFS path snapshots, mount namespaces, policy epochs, exec state and audit but keep AppArmor profile identity distinct from inode labels.

**Simplification and invariants:** validated compact DFA tables and typed profile transitions are allowed; replacing path mediation with inode-only rules, normalizing away deleted/disconnected path behavior, or reporting unsupported features as present is not. Publish replacements atomically, retain profiles for active references, and preserve user namespace/profile namespace distinctions.

**Improve/test/done:** cache only generation-safe path/profile decisions; benchmark policy parser memory and DFA traversal. Run AppArmor regression tests with distribution profiles, namespace stacking/replacement, hardlinks/rename/overlayfs, unlinked descriptors and container exec; fuzz binary policy and query parsing. Physical filesystem/container workloads must match enforcement/audit and report start-up tails, ops/s, CPU and memory.

### 2.3 Smack

**Port steps:** implement label internment and special-label semantics, rule evaluation and xattr transitions; export smackfs and per-task attributes; wire filesystem/mmap, UNIX IPC/SCM_SECURITY and NetLabel/CIPSO networking; then rule updates, bring-up/audit behavior and policy tooling. Authority: [pinned Smack model and interfaces](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/admin-guide/LSM/Smack.rst).

**Crate/shared decision:** project-owned label/rule adapter sharing generic internment, xattrs, networking label encoding and audit. No crate selected for the policy engine; a string-label library cannot stand in for special labels and network mapping.

**Simplification/invariants:** compact label IDs are internal only; preserve external strings, xattr names and access modes, label inheritance and NetLabel rules. Never silently strip CIPSO/CALIPSO metadata or merge subject/object labels at descriptor transfer.

**Improve/test/done:** generation-indexed rule lookup and shared immutable labels avoid repeated strings. Differentially exercise Smack utilities, special labels, rule updates, labelled IPC, network option rejection and relabelling under load. Real NICs on isolated labelled networks and xattr-capable disks must pass; measure packet rate/tails, labelled file ops, rule-load cost and memory.

### 2.4 TOMOYO

**Port steps:** port policy input grammar and securityfs interfaces, pathname encodings and domain naming; implement domain transitions/exception policy and operation ACLs; then learning, permissive, enforcing and supervisor behavior with userspace policy tools. Authority: [pinned TOMOYO guidance](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/admin-guide/LSM/tomoyo.rst) and [policy specification](https://tomoyo.sourceforge.net/2.6/policy-specification/index.html).

**Crate/shared decision:** bounded project parser/matcher and domain engine; share path snapshot and audit infrastructure but not AppArmor's policy format. Generic parser primitives are candidates only after allocation/complexity review; no TOMOYO-compatible crate is presumed available.

**Simplification/invariants:** immutable interned path/domain data can reduce copies; do not remove learning/supervisor modes or substitute inode labels for pathname policy. Bound parser work and account policy memory without changing accepted grammar; retained policy readers must survive updates.

**Improve/test/done:** compare complete accepted/rejected policy input and domain-transition traces, escaped paths, namespace/mount/rename races, policy deletion and supervisor disconnect/OOM. Run real TOMOYO tools; physical metadata/exec benchmarks report p99 decision latency, policy memory and learning throughput under equivalent security modes.

### 2.5 Landlock, Yama and remaining pinned LSMs

**Landlock steps:** implement pinned ABI version/flags and rights negotiation, ruleset descriptors and layered domains; attach restrictions to credentials and retained descriptors; integrate path/refer/truncate, network and scope rights supported by this baseline, logging, ptrace and namespace interactions. [Landlock's model](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/security/landlock.rst) requires monotonic restriction and retained file-descriptor rights. Read the pinned userspace API and selftests for the actual supported rights; do not hard-code an older filesystem-only subset.

**Landlock crate/shared/simplification:** project policy tree over VFS objects/credentials, not the userspace `landlock` convenience crate as enforcement. Reuse RCU/object refs and policy intersection. Compact persistent domains and an unsandboxed fast path may simplify internals; no rule may grant authority denied by DAC/another policy or lose restrictions when an FD crosses a UNIX socket. **Optimize/test/done:** path-tree sharing without policy bypass; run every pinned Landlock selftest, ABI negotiation and layered ruleset/OOM/SCM_RIGHTS races; measure unsandboxed overhead, sandboxed open/rename/connect latency and per-layer memory on physical storage/network.

**Yama steps:** implement `ptrace_scope` 0–3, `PR_SET_PTRACER`/ANY, ancestry, dumpability, namespaces and irrevocable mode 3, then all ptrace-like access callsites. [Yama authority](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/admin-guide/LSM/Yama.rst). **Crate/shared:** project adapter over task refs and generic ptrace checks; no new crate. **Limits/invariants:** cache task relationships only with valid lifetime/namespace authority; never weaken ordinary ptrace DAC checks or remove debugger compatibility to simplify ancestry. **Optimize/test/done:** benchmark attach/check costs and run debugger/crash-handler/Wine-style relationships across PID/user namespaces, exec, reparenting and mode changes on real SMP systems.

**Other LSM closure steps:** inventory every pinned `security/` selection, including LoadPin, SafeSetID, IPE, lockdown, capability and BPF-LSM; map each hook/interface/test before implementation. LoadPin must preserve filesystem trust/immutability and module/firmware loading policy; SafeSetID must preserve configured UID/GID transition policy; IPE must preserve integrity-property evaluation, signed policy and audit behavior. Sources: [LSM index](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/admin-guide/LSM/index.rst), [IPE design](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/security/ipe.rst). **Crate/shared:** project adapters over the common policy/signature/credential framework; no universal policy crate. **Limits/invariants:** support all baseline mechanisms rather than collapsing them into SELinux or declaring “Rust makes this unnecessary.” **Optimize/test/done:** cold-path validation, immutable policy replacement, per-mechanism upstream tests, real firmware/module filesystems and UID transitions; record policy-check cycles, load/reload time and memory independently for each. BPF-LSM enforcement and helper authority are jointly gated by [extensions](extensions.md).

## 3. Seccomp and asynchronous interface security

**Authority:** [pinned seccomp filter API](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/userspace-api/seccomp_filter.rst). Seccomp is syscall filtering, not a complete object-level sandbox; classic BPF seccomp is not arbitrary eBPF execution.

1. Implement strict mode, `prctl` and `seccomp` APIs, classic instruction validation and immutable filter chains after syscall/compat dispatch and signals exist.
2. Preserve action precedence and data, KILL_THREAD versus KILL_PROCESS, TRAP/SIGSYS details, ERRNO, LOG, TRACE and ALLOW, architecture tags/argument widths, TSYNC/thread synchronization, inheritance and `no_new_privs`/namespace capability checks.
3. Port user notification listeners, ID validity, reply/continue semantics, descriptor insertion, polling, cancellation and races with exit/exec/ptrace. Document that notification supervisors inspecting pointed-to user memory must handle TOCTOU; filter bytecode cannot dereference arbitrary user pointers.
4. Cross-check every [io_uring](filesystems.md) registration/restriction/personality and worker execution path with credentials, LSM and audit. Seccomp seeing an `io_uring_enter` syscall is not automatically filtering every SQE as a syscall; preserve the pinned security interface and approved fixes without inventing a stronger but incompatible model.

**Crate/shared:** project-owned classic BPF verifier/interpreter, sharing instruction decoding infrastructure with [extensions](extensions.md) only where semantics agree; no generic VM verifier is accepted as seccomp policy. Share credential snapshots, waitqueues, fd tables and syscall metadata.

**Simplification/security:** cache filter decisions only where the reference permits and arguments/architecture cannot invalidate them; listener IDs must prevent stale replies and FD injection must be atomic with security checks. Do not disable user notifications, compat syscalls or io_uring to obtain easy safety.

**Optimization and done:** constant-result fast paths and validated shared chains reduce allocation and dispatch overhead. Require pinned seccomp selftests, real container profiles, all action/TSYNC/notification races and io_uring negative-authority tests; compare errno, signals, audit and notifications. Physical tests measure syscall p50/p99/p999, filter-depth/verifier startup cost, container startup, notification throughput and CPU/memory with both fast and complex filters.

## 4. Key retention, trust anchors and secrets

**Authority:** [key retention service](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/security/keys/core.rst), [request-key](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/security/keys/request-key.rst), [trusted/encrypted keys](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/security/keys/trusted-encrypted.rst), and [asymmetric keys](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/crypto/asymmetric-keys.rst).

1. Port `add_key`, `request_key`, `keyctl`, serial allocation, permission/possession search, subscription/inheritance, quotas, expiry/negative/revoked/dead states, construction authorization and request-key upcalls.
2. Implement pinned key types (including user/logon/big-key, keyring, asymmetric and supported trusted/encrypted backends), cycle/depth limits, keyring restrictions, garbage collection and namespace behavior; enumerate rather than assume that a generic byte-string store suffices.
3. Integrate X.509/PKCS#7 parsing, system/secondary/platform/machine/blacklist trust relationships as present in the pinned configuration, revocation and module/kexec/IMA consumers. Hardware-backed TPM/TEE trust needs real drivers and provisioning evidence; firmware/microcode remain external trust components.

**Crate/shared:** kernel key lifecycle is project-owned. RustCrypto DER/X.509/signature primitive families are evaluation candidates, not preapproved/audited libraries; verify exact algorithm support, allocation/complexity limits, licenses and pure-Rust feature closure. Reuse crypto providers, timers, RCU and credential policy. Reject OpenSSL/native FFI and host OS key stores in kernel execution.

**Simplification/invariants:** typed lifecycle and owned secret buffers reduce accidental exposure; preserve serial errors, possession versus permission, upcall authority, key type-specific readable/non-readable payloads and expiry. Erasure must cover buffers/temporary copies where technically enforceable, with compiler/disassembly evidence; never promise eliminating all historical copies or microarchitectural leakage.

**Optimization/test/done:** index keyring searches and shard quota/GC work without bypassing restrictions; avoid cloning payloads. Run keyutils/LTP/pinned tests, simultaneous construction/revocation/expiry, malformed ASN.1 and adversarial key graphs, namespace/exec and GC pressure. TPM/TEE backend tests require actual hardware and measured provisioning/revocation behavior. Report lookup and construction tails, key counts/memory, GC pause and TPM command latency; unavailable backend hardware blocks that backend's qualification.

## 5. Integrity, IMA, EVM, secure loading and lockdown

**Authority:** [IMA templates](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/security/IMA-templates.rst), [integrity source](https://github.com/gregkh/linux/tree/v6.18.57/security/integrity), [lockdown implementation](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/security/lockdown/lockdown.c), [module signing](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/admin-guide/module-signing.rst) and [IPE](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/security/ipe.rst).

1. After trustworthy crypto, keyrings, VFS xattrs and TPM interfaces, implement integrity object caches and invalidation, measurement policy/parser/templates/log formats and PCR extension/order. Measurement, appraisal and audit are distinct operations; a digest does not itself enforce policy.
2. Port IMA appraisal/signature/hash behavior for exec, file access/mmap, kernel-read/load paths and other pinned hooks; policy update and boot parameters; EVM protected metadata HMAC/signature handling, portable signatures, initialization and repair modes. Integrate fs-verity/dm-verity and overlay/network filesystem behavior with [filesystems](filesystems.md) and [storage](storage.md).
3. Connect trust chains, signed Rust replacements, firmware loading and kexec to the same policy framework; preserve failure handling when TPM is absent/unavailable. Test persistent xattrs across crashes and avoid measuring stale data after concurrent writes/metadata changes.
4. Port lockdown levels, reason-specific checks and monotonic escalation via boot/securityfs. Audit all callsites: kernel memory access, ports/MSRs, hibernation, kexec, modules, BPF/perf/debug and hardware interfaces. Secure Boot provenance and lockdown are related policy mechanisms, not synonyms and not proof against compromised firmware.

**Crate/shared:** no generic IMA/EVM or lockdown crate selected; project policy/cache/format port over reviewed hash/signature providers. Share keyrings, xattrs, TPM transaction ordering, executable-page protection, audit and boot trust records. Never implement new crypto constructions to avoid a missing dependency.

**Simplification/invariants:** use one validated template registry and typed measurement/appraisal outcomes, but preserve old formats, policy modes, legacy accepted algorithms where required by baseline policy and all explicit exceptions. A cached appraisal is invalid after relevant data/xattr/policy/key changes. Lockdown escalation cannot be silently reversed by an unrelated subsystem. Debug convenience cannot bypass production trust.

**Optimization/test/done:** cache validated file digests by reliable version plus policy/key generation; batch only where PCR/log ordering is unchanged. Run IMA/EVM tests with reference policies and TPM PCR/log replay, modified data/xattrs, bad signatures/revoked keys, appraisal-fix modes, fs-verity/overlay cases, kexec and lockdown attempts. Physical TPMs, secure-boot-capable Intel/AMD and later target platforms, sacrificial disks and recovery console are mandatory. Measure boot/exec/open throughput and tails, digest bandwidth, policy/log memory, PCR command latency, reload cost and power; identical appraisal/lockdown/security settings are required for comparison.

## 6. Randomness and cryptographic services

### 6.1 Random subsystem

**Authority:** the pinned [random driver](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/drivers/char/random.c) separates initialization/readiness, fast key erasure CRNG, accumulation/extraction, collectors and userspace interfaces. Preserve that security analysis rather than inventing a new generator.

1. Port readiness states, collectors and entropy-credit policy, bootloader/CPU/hardware RNG trust options, reseeding and per-CPU generation; connect IRQ/time/power/resume and VM-generation events only with correct entropy assumptions.
2. Implement exact `getrandom` flags/errors/blocking/signal behavior, `/dev/random` and `/dev/urandom`, poll/ioctl/sysctl and pinned vDSO interface where configured. Internal cryptographic consumers must obey readiness requirements; do not seed from a fixed value to make first boot pass.
3. Qualify clone/snapshot/resume, CPU hotplug, broken hardware RNG, low-entropy boot and confidential-guest inputs; coordinate persisted seed handling with userspace rather than claiming the kernel alone guarantees unique boots.

**Crate/shared:** project port of the pinned construction using reviewed pure-Rust ChaCha/BLAKE2s primitives where suitable; `rand`/`getrandom` host crates are not kernel entropy sources. Share timers, per-CPU state, waitqueues and CPU/hwrng drivers. No homebrew entropy estimate or PRNG.

**Limits/security/optimization:** test hooks may inject deterministic material only in isolated test builds, never production. Statistical randomness tests cannot prove cryptographic security or adequate entropy. Use per-CPU batching/key erasure and avoid global locks/copies without weakening reseed/forward/backtracking properties.

**Done tests:** differential API tests before/after readiness, nonblocking/signal/partial reads, hardware RNG failure, suspend, CPU hotplug and VM clone/reseed; primitive known-answer tests plus independent cryptographic review. Physical cold boots without virtual entropy, real RNG sources and power cycles are required. Report time-to-ready, syscall/vDSO latency, bytes/s, per-CPU scaling, reseed contention, CPU/memory and energy at baseline-equivalent trust settings.

### 6.2 Crypto API, providers and side-channel review

**Authority:** [crypto architecture](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/crypto/architecture.rst) defines templates, algorithm naming/priorities and sync/async contracts; [AF_ALG](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/crypto/userspace-if.rst) exposes userspace consumers. [RustCrypto traits](https://github.com/RustCrypto/traits) describe primitives, not Linux compatibility or a blanket security audit.

1. Inventory every pinned algorithm/template/provider/UAPI and its consumers: symmetric/AEAD/hash/MAC/KDF/RNG, asymmetric signatures/key exchange, compression and hardware/offload interfaces. Deprecated algorithms are not silently removed; preserve required behavior subject to documented policy/security deltas.
2. Build Linux-compatible registration, names/priorities, transform/request lifetimes, scatter-gather/in-place rules, callback/backlog/cancellation, alignment/context constraints and `/proc/crypto`; integrate AF_ALG sockets/setsockopt/send/recv and provider selftests.
3. Select independently reviewed implementations per primitive/version/configuration. Candidate families include RustCrypto digest/cipher/aead/signature/DER crates and `zeroize`/constant-time comparison utilities after exact review. Reject C-backed OpenSSL/ring/native libraries or vendored assembly as runtime shortcuts under the Rust-only rule. Crate names alone are not approval, constant-time evidence or audit evidence.
4. Implement architecture intrinsics/hardware provider paths only after kernel SIMD/FPU context preservation, preemption/IRQ rules, feature detection and compiler code-generation review. Unavoidable inline assembly requires the project's per-operation contract; no `.S` imports. Maintain correct scalar paths and offload DMA ownership.

**Bundling/simplification:** one provider/request framework can serve TLS/IPsec/WireGuard, storage encryption, verity, integrity, modules and random. Shared primitives do not imply shared keys/nonces. Preserve all advertised algorithms and priority/exact-name selection; fail honestly on unavailable algorithms during staged development and retain them as incomplete, not final exclusions.

**Security/optimization:** no custom cryptographic algorithm or ad hoc nonce/padding scheme. Review nonce uniqueness, tag failure behavior, key lifetime, padding/oracle behavior, secret-dependent branches/memory, CPU dispatch, speculative access, accelerator/DMA boundaries and zeroization limits. Constant-time source is not a guarantee about compiled code or hardware. Optimize validated vectorization, scatter-gather and request pooling without exposing unauthenticated plaintext or reusing secrets unsafely.

**Done tests:** pinned crypto test vectors plus independent published known-answer/adversarial vectors, cross-provider/scalar equivalence, AF_ALG userspace, malformed ASN.1, short/in-place/overlapping buffers, callback races, CPU migration/hotplug and hardware reset/OOM. Physical CPUs with and without acceleration and real offload devices require throughput by message size, p50/p99/p999 request latency, cycles/byte, CPU/memory, startup and energy. Run timing/leakage analysis across chosen CPUs/compilers and document its coverage limits; a negative leakage test is not proof of no side channel. No FIPS or external-audit claim without evidence covering the exact artifact and configuration.

## 7. Audit, attack surface and microarchitectural mitigations

### 7.1 Linux audit

**Authority:** pinned [audit implementation](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/kernel/audit.c) explicitly includes filtering, netlink delivery, backlog waits, rate limiting and possible record loss; audit is not merely printk.

1. Port audit netlink control/messages/ACKs, rule parsing/listing, syscall/compat architecture selection, entry/exit/task/user/exclusion filters, loginuid/session/container-relevant identity and immutable configuration.
2. Integrate syscall contexts, inode/path/watch/tree rules, LSM subjects/objects, exec argument encoding, namespace IDs, async io_uring contexts and all pinned event producers. Preserve multi-record serial correlation, timestamp and escaped/binary data formats.
3. Implement daemon registration/reconnect, multicast, backlog/rate limits, lost counters, wait/failure policy and boot configuration. Lifecycle references and wakeups must survive daemon exit, net namespace changes and memory pressure.

**Crates/shared:** project audit protocol and rule engine over shared netlink, credential/path snapshots, queues and clocks. Do not substitute `tracing`/`log` or a structured logging crate for Linux audit. Share emergency storage only with explicit audit loss/failure semantics.

**Limits/security/optimization:** defer formatting and reuse retained path data without changing record lifetime; per-CPU staging is permitted only if ordering/correlation/backpressure stay correct. Do not silently drop records, disable audit under load, expose another tenant's subject or claim tamper-proof persistence from kernel netlink delivery.

**Done tests:** auditd/auditctl/ausearch plus upstream audit tests; byte/field differential rules/records, immutable mode, daemon restart, saturation, rate-limit/backlog waits/loss and configured panic behavior; adversarial exec strings and io_uring attribution. On physical NUMA storage/network loads measure audit-off/on throughput, p99 syscall delay, daemon drain bandwidth, lost records, memory and power at identical rules/failure policy.

### 7.2 Hardening, speculative execution and trust closure

**Authority:** [self-protection](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/security/self-protection.rst), architecture mitigation code and [confidential-computing threat model](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/security/snp-tdx-threat-model.rst). Architecture-specific mitigations belong jointly to [architectures](architectures.md), [memory](memory.md) and this security review.

1. Inventory baseline vulnerability flags, CPU/microcode detection, mitigation boot options/status files and per-context-switch/entry/exit barriers for each CPU family. Cover Spectre/Meltdown-class issues, stale buffers/register state, SMT cross-domain leakage, predictor controls, KPTI, return protections, speculation-safe indexing and future baseline-specific errata; names are not a substitute for the matrix.
2. Establish W^X/RO-after-init, userspace access separation, stack protection/overflow checks, randomized layouts, allocator hardening, bounds/overflow handling, executable/JIT policy and correct usercopy; expose compatible controls with equivalent default security.
3. Integrate PMU/debug/address disclosure restrictions, sensitive crash/log retention, DMA/IOMMU threat policy and confidential-guest shared-memory validation. Account for physical attacks and firmware trust that software cannot eliminate.

**Crate/shared:** project architecture/security mechanisms; CPU register crates can represent fields after review but cannot choose mitigations. Reuse MM/context switching, firmware/microcode records and centralized executable-memory patch transactions. Compiler CFI or sanitizers are candidates only after exact Rust kernel/toolchain support is demonstrated, not assumed.

**Limits/invariants/optimization:** no disabling compat ABIs, SMT mitigation, IOMMU, KASLR, seccomp or LSM to meet performance. Configuration-specialized fast paths and batching of safe mitigation operations need equivalence evidence. Keep the same threat assumptions and mitigation mode in reference/port comparisons; distinguish optional upstream modes from supported final configurations.

**Done tests:** architecture mitigation selftests and adversarial cross-process/cross-VM workloads, usercopy fault injection, W^X/patch races, DMA isolation, firmware update/resume/hotplug, PMU disclosure and cold-boot checks on multiple physical CPU vendors/steppings. Inspect actual machine code/barriers and microcode/status settings. Measure syscall/context-switch/VM-exit/network/storage/container throughput and latency plus CPU/memory/power per hardware; residual leakage and unavailable hardware are named qualification blockers, never hidden behind a Rust claim.

## Operator execution and coverage limits

The actual non-destructive Rust smoke harness can run after the user manually boots the reference or a future candidate:

```text
cargo run -p baremetal -- run --output <new-directory> --label <label> --expect-release <exact-osrelease> --environment <reference|qemu|bare-metal>
```

Select one environment and the exact running release. The environment label is an operator assertion, not proof of bare metal. [Suite documentation](../bare-metal-suite.md) defines its bounded memory/thread/filesystem/loopback/process/proc/sysfs checks; it does not prove LSM, crypto, seccomp, key, integrity, audit, DMA or side-channel correctness. It must not relabel the host filesystem, change security policy, load modules, provision TPM secrets, update firmware, run exploit tests or reboot. Preserve working Limine/systemd-boot entries under the [packaging plan](../packaging.md); the present bootstrap is not a security-qualified Linux-replacement artifact and cannot run this Linux userspace suite.

Future full security campaigns use independently acquired **pinned external** suites and real Rust project tests. A concrete external entrypoint after dependency/configuration preparation is `make -C <pinned-linux>/tools/testing/selftests TARGETS="seccomp landlock" run_tests`; policy-specific SELinux/AppArmor/Smack/TOMOYO, audit, keys, IMA/EVM and crypto campaigns require their own exact tool versions/configurations, real policies and named test manifests. External suite C/assembly/userspace is allowed as an oracle, not as the project kernel implementation. Save per-case executions/skips, allow/deny/audit traces, serial recovery and hardware manifests; a zero aggregate return with skipped security tests is not qualification.

Only the current workstation is presently available. Inventory its actual CPU/microcode/IOMMU/TPM/RNG/security-boot features before assigning tests; additional vendors/steppings, non-x86 architectures, offload engines and trusted-key backends remain named unavailable-hardware blockers until real evidence exists. Sacrificial storage/isolated networks and separately approved operator actions are required for adversarial, crash or provisioning tests. Never substitute a VM entropy source, virtual TPM or modeled speculation result for the corresponding physical requirement.

## Integration evidence and present blockers

Maintain per-subfamily operation/configuration matrices, source provenance/notices, unsafe contracts, threat-model reviews, parser fuzz corpora, differential traces, workload manifests and raw performance distributions. [Verification](../verification.md) owns artifact retention and [maintenance](../maintenance.md) owns upstream security intake; each security fix updates the delta ledger transparently. The bootstrap does not implement these security facilities: there is no selected audited crypto artifact, completed policy hook inventory or observed physical security qualification. Those remain explicit implementation/qualification prerequisites; source-signature validity and bootstrap memory checks do not discharge them.
