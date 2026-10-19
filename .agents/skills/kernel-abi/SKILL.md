---
name: kernel-abi
description: Preserve exact Linux syscall, ioctl, signal, ELF, procfs, sysfs, netlink, and compat ABIs in Rust. Use for byte layouts, architecture calling conventions, errno precedence, restart semantics, usercopy, and differential compatibility evidence.
---

# Exact Linux ABI implementation

## Contract and trigger

Apply this skill whenever a change crosses the userspace boundary, including returned text, filesystem metadata, socket ancillary data, signal frames, vDSO behavior, executable loading, tracing or device controls. Read [project rules](../../../AGENTS.md), [compatibility](../../../docs/compatibility.md), [process plan](../../../docs/subsystems/process.md) and [architecture plan](../../../docs/subsystems/architectures.md). The target is exact Linux6.18.57, not merely POSIX/source compatibility. The [real bootstrap](../../../docs/implementation.md) has loader/non-error compiler entries and a necessary local repair for independently confirmed broken error-code lowering, with genuine fatal-call and returning-PF15-GPR evidence. Do not generalize old BP/IRQ proof to a missing call path or confuse saved interruptedRSP with raw entryRSP. No Linux userspace/syscall/compat/usercopy qualification follows; routed `in_progress` is not completion.

Rust-only implementation permits `repr(C)` and appropriate `extern` ABI syntax; these are not C implementations. A Rust function using `extern "C"` does not thereby become a Linux syscall entry point. No C runtime shim or legacy C kernel module is allowed.

The [standing definition of done](../../../docs/definition-of-done.md) is stricter than a smoke pass: every applicable ABI/personality/configuration requires its own implemented behavior and qualified evidence. Initial workload integration uses Arch/CachyOS userspace, not downstream CachyOS kernel patches. Keep all other baseline interfaces in scope.

The actual [bounded smoke suite](../../../docs/bare-metal-suite.md) exercises selected memory/thread, sandbox-filesystem, loopback-socket, process and proc/sysfs behavior and validates the expected running release. Run it only with authorized operator-selected environment and a new report directory. A reference-host smoke proves runner execution only; it does not prove a future kernel's ABI or attest physical hardware. Add the exact native/compat, errno, signal/restart and adversarial cases required here rather than interpreting generic smoke as their substitute. Preserve failures/skips/unavailable cases; do not invent results.

Only the current workstation is available today, so unavailable target-ABI/hardware cells remain blockers. The user installs/selects/boots any real candidate under the [separate-package/recovery design](../../../docs/packaging.md); this skill authorizes no host installation, reboot, firmware or destructive disk action.

## Inputs required before coding

Obtain the pinned implementation and UAPI definitions for every touched interface, upstream blob IDs, owning [workstream](../../../planning/workstreams.tsv), supported architecture/personality/configuration combinations, and [decisions](../../../docs/decisions.md). Record the calling convention, register/stack use, scalar widths, endianness, alignment, structure offsets, flags/constants, size-negotiation rules, and exact observable behavior.

Capture baseline cases from a real pinned Linux environment when execution is authorized. Include raw syscall results as distinct from libc-translated `-1`/errno, output bytes and defined padding, state changes, signals, restart behavior, blocking/poll readiness, and permission/namespace effects. Record libc/tool revisions if used; a libc wrapper can hide the kernel's result. Get reference error precedence by constructing multiple-invalid-condition cases rather than guessing from manual-page summaries.

## Ordered procedure

1. **Build an ABI matrix.** List native, compat, historical, and architecture-specific personalities/configurations separately. For x86 include native x86_64, IA32, and x32 where the baseline configuration exposes them; x32 is not synonymous with IA32. Add all baseline architectures in the closure plan. A native-only first milestone does not remove compat or other architectures from scope.
2. **Trace the full entry-to-return path.** Locate syscall numbering/dispatch, argument extraction and sign/zero extension, access checks, implementation, post-processing, tracing/seccomp/audit, signal delivery, and return instruction. Separate internal errno/restart states from public results. Include register clobbers, stack alignment, user/kernel privilege transition, FPU/vector state, TLS, and fault return requirements for entry primitives.
3. **Write a layout ledger.** For each externally exchanged type record size, alignment, each field offset/width/signedness/byte order, reserved bits and bytes, flexible-array bounds, and union interpretation per ABI. `repr(C)` follows the target C layout; it does not make i386 and x86_64 layouts identical and does not recursively fix nested `repr(Rust)` types. An alignment attribute does not repair a bad access address.
4. **Separate raw wire values from validated domain types.** Decode integers and byte arrays before constructing Rust `bool`, enums, references, `NonZero`, or strings. Linux paths and names are generally byte sequences, not guaranteed UTF-8. Use checked lengths/offsets and explicit endian conversions where the interface specifies them. `repr(packed)` is not a generic solution: no reference may be formed to an unaligned field.
5. **Implement recoverable user access.** A user address is untrusted and may fault, change, unmap, or cross a protection boundary after validation. Use the architecture's fault-recoverable usercopy abstraction, checked ranges and address-space limits; never turn a user address into a normal Rust reference. Pin only when semantics demand a pin, and account for unmap/COW/reclaim and security policy. A range check alone does not prevent TOCTOU or faulting.
6. **Preserve copy and commit semantics.** Identify which data is sampled once, which may be reread by baseline design, how partial copies are reported, when externally visible state commits, and how output-copy failure affects already completed work. Avoid double-fetch vulnerabilities without silently promising atomic snapshots absent from the ABI. Preserve short I/O, EOF, nonblocking and interrupted behavior.
7. **Encode errors deliberately.** Derive numeric errno values from the selected architecture's pinned definitions; do not assume every architecture uses identical numbering. At raw x86_64 syscall return, distinguish negative error encoding from libc's translation, while keeping architecture-specific return conventions separate. Preserve `EINVAL`/`EFAULT`/`EBADF`/permission-check precedence and side effects from source plus differential evidence. Unknown ioctls ordinarily yield `ENOTTY`; preserve documented baseline exceptions rather than “correcting” an existing userspace contract during a port.
8. **Implement restart as a state machine.** For x86 signal delivery, the pinned code turns `ERESTARTNOHAND` and `ERESTART_RESTARTBLOCK` into `EINTR` when delivering a handler; `ERESTARTSYS` depends on `SA_RESTART`; `ERESTARTNOINTR` restarts. Without a delivered handler, restart-block and ordinary restart paths differ. Derive the complete behavior from the actual architecture implementation, including saved syscall number/PC, tracing, timeout remainder/restart-block payload, no-signal case, stop/continue, and `rt_sigreturn`. Never leak internal `ERESTART*` values to ordinary userspace or automatically retry every interrupted operation.
9. **Implement compat translation explicitly.** Distinguish pointer arguments from scalar ioctl arguments before conversion. Account for s390's 31-bit pointer rule, architecture-specific 64-bit alignment, signed extension, time32/time64, stat variants, signal sets/frames, ioctl sizes, and ancillary layouts. Separate native/compat decoders may feed one validated internal operation; do not reinterpret incompatible structs or assume a cast performs translation.
10. **Exercise and integrate.** Establish layout/constant assertions for actual target builds and independent fixtures from pinned definitions/reference outputs. Differentially execute public behavior, then migrate all syscall/device/compat consumers, documentation and tests together. New internal adapters must not leave obsolete internal paths; old public ABIs still require their own correct decoding/encoding.

## Subfamily checks

| Boundary | Specific traps and required evidence |
| --- | --- |
| Syscalls and ioctls | Number spaces, architecture return conventions, reserved flags, encoded ioctl size/direction, size-extension rules, usercopy faults, permission/error precedence, partial operations, restart. Include scalar versus pointer arguments and unknown commands. |
| Signals, ptrace and vDSO | Exact stack/frame alignment, red zone, alternate stack exhaustion, restorer/trampoline, FPU/XSAVE feature and size validation, untrusted sigreturn, register sanitization, tracer edits, clock fallback and mapping protections. “Signal handler ran” is not frame compatibility evidence. |
| ELF and process launch | Machine/class/endianness, interpreter, segment bounds/overlap, auxv, credentials, ASLR, stack/TLS, personality, malformed files and privilege transitions. Reuse parsing does not implement loader policy. |
| procfs/sysfs and metadata | File names, byte formatting, offsets/short reads, permissions, poll behavior, namespace views, lifetime under process/device removal. Treat documented ABI separately from debug-only diagnostics; do not assume all textual output is arbitrary. |
| Netlink/socket controls | Native/wire endian rules, attribute lengths/alignment, unknown attributes and policies, multipart sequence/dump interruption, credentials/namespaces, truncation and ancillary data. Parsing success alone does not prove protocol semantics. |

## Five design decisions

- **Reuse:** prefer `core` for layout/offset assertions and explicit checked decoding. [Zerocopy](https://docs.rs/zerocopy/latest/zerocopy/) is a candidate for verified byte conversion with appropriate traits and `no_std` configuration, not a usercopy engine, semantic validator, or permission model. Accept no dependency until exact version/features, transitive code/licenses, Rust-only build/runtime, unsafe, target coverage, failure paths, advisories, and [dependency policy](../../../docs/dependencies.md) are reviewed. Host `libc` definitions may help reference harnesses but do not define kernel behavior or justify runtime C linkage.
- **Bundle:** centralize raw syscall-result encoding, architecture usercopy, layout ledgers, checked length/attribute decoding, and native/compat translation conventions. Keep per-interface error order, flags, credentials, and transaction semantics explicit rather than forcing them through a lossy generic wrapper.
- **Simplify:** shared validated operations behind separate native/compat codecs can eliminate duplicate policy. Do not normalize historical layouts, replace time units, reject reserved bits differently, unify clock semantics, or remove old ABI entry points merely to simplify Rust types.
- **Secure:** initialize every output byte actually copied, including reserved/padding bytes under the ABI's rules. Rust field assignment or a typed move is not a proof that padding remains initialized; use explicit byte serialization or an appropriate proven conversion contract. Check all integer math, validate sigreturn/ELF inputs, preserve isolation and speculation mitigations, and avoid secret/address disclosure.
- **Improve:** after equivalent behavior, measure repeated usercopies, avoidable allocation, parsing and syscall-entry overhead. Coalesce copies only with a proof preserving sampling, fault, partial-result and ordering semantics. Zero-copy is not automatically safe or faster and may require pinning/resource limits.

## Qualification gates

Follow [verification](../../../docs/verification.md), [performance](../../../docs/performance.md), and [bare metal](../../../docs/bare-metal.md).

- **M1:** entry/exception-return and usercopy-fault primitives require actual QEMU and initial physical-machine recovery-backed execution, including privilege isolation and serial logs.
- **M3 and consuming M4–M7 gates:** assert sizes/alignments/offsets/constants for each target ABI; run differential native/compat cases with null/unaligned/cross-page/unmapped buffers, competing invalid inputs, size bounds, short operations, signals with and without `SA_RESTART`, malformed sigreturn, timeouts, SMP unmap races, and adversarial permissions/namespaces. Add subfamily cases above and external userspace compatibility suites in disposable environments.
- **M8/performance:** compare entry overhead, usercopy throughput, fault latency/tails, allocation/memory, CPU, startup and applicable workload power against pinned Linux on matched real hardware and configurations. Include mitigations, firmware, repetitions, confidence intervals and noise controls; no arbitrary regression allowance or aggregate hiding. QEMU timing does not qualify bare-metal performance. Hardware/ABI cells without evidence remain unqualified.

These are required qualification gates, not instructions to fabricate execution or run checks during a no-gates assignment. Report exact commands, raw artifacts, environment and observed outcome only for tests actually run. The [cell9 QEMU entry/fault/GPR evidence](../../../docs/implementation.md) is real, but no Linux userspace ABI execution, physical pass or performance qualification follows from it.

## Stop and escalation

Stop when reference source and measurements disagree without explanation, an ABI personality lacks a calling/layout definition, usercopy cannot recover faults, output initialization cannot be proved, signal/restart behavior is guessed, or physical-machine safety/evidence is absent. Escalate security-versus-baseline conflicts through [decisions](../../../docs/decisions.md), never silently preserve an exploitable defect or change ABI. Do not treat “compiles,” generated bindings, or one passing libc program as ABI parity.

## Deliverable checklist

- [ ] Pinned source/UAPI and architecture/personality matrix; exact layout/constant and error/restart ledgers.
- [ ] Checked codecs, recoverable usercopy, output initialization and commit/failure invariants.
- [ ] Crate/bundle/simplification/security/improvement decisions with evidence and migrated consumers.
- [ ] Native/compat/adversarial/differential cases, real-hardware gates, performance cells and raw results or explicit unrun blockers.
- [ ] Remaining unsupported interfaces/status recorded honestly; public compatibility not inferred from source inventory.

## Primary references

- [Pinned x86 syscall table](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/arch/x86/entry/syscalls/syscall_64.tbl): distinct common, 64 and x32 entries.
- [Pinned x86 signal implementation](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/arch/x86/kernel/signal.c): frame selection/alignment and restart transitions; do not generalize instruction rewinds to other architectures.
- [Pinned ioctl guidance](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/driver-api/ioctl.rst): compat pointer/scalar distinctions, alignment, return codes, padding leaks.
- [Rust type-layout guarantees](https://doc.rust-lang.org/reference/type-layout.html) and [undefined behavior](https://doc.rust-lang.org/reference/behavior-considered-undefined.html): representation is distinct from validity and calling ABI.
