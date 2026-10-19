---
name: kernel-architecture
description: "Plan and review Rust-only kernel architecture ports: compiler backends, endian and ABI rules, MMU/noMMU, boot and entry stacks, SMP, interrupts, unavoidable inline assembly, and paired QEMU/physical bring-up. Use for target enablement or architecture-sensitive changes."
---

# Kernel architecture

## Purpose and boundaries

Use this workflow for a new target, boot path, exception or syscall entry, context switch, atomic primitive, or architecture-specific optimization. A compiler target is not proof of a working kernel. x86_64 QEMU is the first debug target, not the final architecture scope or a substitute for hardware qualification.

The approved design is a modular monolithic Rust kernel directly porting the fixed Linux 6.18.57 feature scope under GPL-2.0-only with preserved per-file provenance and exceptions. Explicit reviewed security deltas are permitted; changing the feature baseline requires a separate decision. Every in-baseline module's functionality needs a Rust replacement; arbitrary third-party/proprietary out-of-tree module functionality requires separately enumerated and approved scope. Kernel code is `no_std`; host tools may use `std`. No C-backed kernel, legacy C modules, standalone assembly files, or alternative-language implementation is permitted. Fallible, context-aware allocation is allowed; MCU advice to prohibit all allocation does not apply.

Read the [architecture contract](../../../docs/architecture.md), [architecture workstream](../../../docs/subsystems/architectures.md), [toolchain contract](../../../docs/toolchain.md), [compatibility contract](../../../docs/compatibility.md), [roadmap](../../../docs/roadmap.md), [physical lab contract](../../../docs/bare-metal.md), and [verification contract](../../../docs/verification.md). The [current implementation](../../../docs/implementation.md) is a real x86_64, one-BSP, four-level-paging bootstrap through external Limine base5/UEFI OVMF on q35. Cell9 records actual owned mappings/CR3, guards/W^X, compiler interrupt entry, exact fault/GPR tests and PIT interrupts/masking. Its workstream-to-Rust-path routing is `in_progress`, not architecture parity or M1 completion; physical, Linux boot/PVH/native EFI, SMP and other baseline paths remain open.

## Required inputs

- Exact reference commit and upstream path/object mapping from [reference metadata](../../../planning/reference.tsv) and [coverage](../../../docs/coverage.md).
- Target architecture and subarchitecture, machine/board, supported CPU generations, boot protocol, firmware revisions, endian modes, pointer widths, page sizes, MMU/noMMU configurations, and userspace ABIs promised by the baseline.
- Pinned rustc/LLVM/linker versions, actual target specification, code-generation settings, required unstable features, and dependency/runtime source inventory.
- QEMU machine/CPU/accelerator configuration plus a named recoverable physical system. Record unavailable hardware as a blocker, not a successful emulated equivalent.

## Ordered workflow

### 1. Derive the architecture capability ledger

For each baseline architecture, enumerate the architecture directory, configuration variants, ABI entry points, atomics, cache/TLB operations, interrupt controllers, boot formats, firmware interfaces, and special runtime facilities. Track source coverage separately from behavioral coverage. Preserve every baseline architecture even when compiler or lab support is missing.

Create a row for each meaningful architecture × endian × word size × MMU mode × ABI × platform cell. Record compiler/backend status, required primitive, upstream authority, implementation owner, QEMU availability, physical availability, and unresolved proof obligation. A shared architecture name is not evidence that all variants work.

Output: a capability/dependency ledger in the existing architecture plan, with explicit backend and hardware blockers and links to the relevant compatibility cells.

### 2. Prove the compiler and image contract before entering Rust

Inspect the pinned target rather than assuming host-Linux defaults. Establish data layout, pointer/address spaces, atomic widths, alignment, CPU feature baseline, relocation/code model, TLS/per-CPU access, red zone, stack probes, panic/unwind strategy, vector/FPU use, and compiler-generated helper routines. Audit transitive runtime objects: `no_std` alone does not prove absence of non-Rust helpers or host assumptions.

Determine whether a maintained built-in freestanding target suffices. A custom target requires a pinned schema/compiler and independent validation; a missing LLVM backend is an implementation blocker requiring backend work, not permission to use a C shim. Do not select a userspace Linux target solely because its triple exists.

The existing bootstrap uses maintained `x86_64-unknown-none` with exact `rustc 1.101.0-nightly` commit `5c543b0b8c73c7b72bc8284ced4fb22ead15734d`, LLVM 23.1.1 and matching installed `rust-src` rebuilt as target `core`/`compiler_builtins`. Bind compiler/runtime identity to the actual ELF and disassembly; a mutable `nightly` alias, stable/nightly mixture or host Linux `core` is not equivalent. Host-tool MSRV 1.88 is a separate engineering metadata baseline, not a user-selected Rust version or a qualification result inferred from nightly kernel tests. Follow the exact [build and lint evidence](../../../docs/implementation.md) and maintained [kernel tooling](../../../docs/kernel-tooling.md).

Specify linker sections, entry symbol/address, load and virtual addresses, relocation processing, reserved memory, BSS initialization, image headers/checksums, and executable/writable permissions. Linker configuration is build data, not an excuse to place implementation assembly in a linker script.

Output: a reproducible target/image recipe and an artifact-inspection checklist. For x86_64, explicitly check the documented freestanding no-red-zone/System V function ABI; do not confuse it with the Linux syscall ABI or UEFI calling convention.

### 3. Design the minimal boot-to-Rust state transition

Write the boot state machine from firmware/loader entry through validated memory ownership, bootstrap stack, early fault reporting, CPU feature discovery, and the first ordinary Rust call. List register contents, privilege level, paging/cache state, interrupt masking, alignment, argument ownership, and valid mappings at each edge. Do not call ordinary Rust with an uninitialized or incorrectly aligned stack.

Keep loader memory, initrd, firmware tables, runtime regions, page tables, and per-CPU stacks reserved until their lifetime ends. Treat addresses and lengths as untrusted; checked arithmetic and validated ranges precede references. Establish a supported, recoverable early diagnostic console before enabling complex machinery. The existing diagnostic ELF uses validated 32bpp framebuffer output, not assumed physical COM1 hardware; identify its capture/recovery path separately from the serial/remote-console requirements of broader qualification.

Plan both QEMU and physical boot from M1. QEMU exercises deterministic fault cases; the physical path verifies actual firmware handoff, interrupt/timer initialization, reset/power behavior, and recovery. Start with owned removable media and isolated lab hardware, not the developer's host disk.

Output: ordered boot transitions, memory-map ownership diagram, exact console/recovery procedure, and expected observable checkpoints. Printed text alone does not prove safe entry or correct memory ownership.

### 4. Separate MMU and noMMU semantics explicitly

For MMU targets, define page-table layout/walker validation, permissions, executable mappings, ASIDs/PCIDs, cache attributes, page-size variants, user access checks, TLB invalidation, remote shootdown acknowledgments, and instruction-cache synchronization. Test stale translations, permission downgrade races, noncoherent devices, and aliasing-sensitive mappings.

For noMMU targets, derive the baseline's executable loader, relocation, memory sharing, `mmap`, process creation, protection limitations, and fault behavior. Do not manufacture MMU isolation or assume `fork` semantics from an MMU target. Share policy and checked address helpers only when the underlying architectural guarantees match.

Make endian conversion explicit at firmware/UAPI/device boundaries; do not use native-endian typed overlays for external byte streams. Distinguish CPU endian mode, device endian, and ABI structure layout.

Output: MMU/noMMU operation contracts and differential cases tied to the exact baseline configuration.

### 5. Specify entry, stacks, context switching, and interrupts

For boot, syscall, synchronous exception, ordinary IRQ, NMI-like event, debug trap, and machine-check paths, document saved registers, error-code format, stack switching, nesting, return validation, privilege transitions, and speculation mitigations. Account for task, per-CPU, emergency, interrupt, and double-fault stacks where applicable; establish overflow detection and bounded early stack use.

Mark transition regions that cannot allocate, fault, sleep, unwind or be instrumented. Preserve Linux ordering for context tracking/RCU, preemption, tracing/accounting, signals, seccomp/audit and rescheduling. Ordinary Rust ABIs are not interrupt-return protocols. Non-error `extern "x86-interrupt"` entries remain exact-compiler-bound; its confirmed error-code lowering defect requires the minimal local naked boundary recorded in [implementation](../../../docs/implementation.md#error-code-entry-defect-reproduction-and-repair). Review every named error vector, hardware frame/error offsets, ordinary callee alignment and preservation, CLD/no-unwind/IRET restore; exercise a genuinely failing-before fatal path and all15 GPRs across returningPF, not only BP/IRQ. Requalify changed source/compiler and never clear withdrawn old artifacts. Never trust user-controlled return addresses, flags, segments or extended state.

Bring up secondary CPUs only after per-CPU storage, interrupt vectors/controllers, topology, startup acknowledgments, and memory ordering are established. Define offline/hotplug teardown and failed-start handling. Include timer delivery, affinity, spurious/lost interrupts, IPI races, local interrupt masking, and NMI nesting. A local interrupt-disable operation is not an SMP lock.

Output: entry/exit and CPU lifecycle state machines, architecture-specific safety contracts, and fault/stress cases for [concurrency review](../kernel-concurrency/SKILL.md) and [unsafe review](../kernel-unsafe/SKILL.md).

### 6. Require an unavoidable-assembly proof for every operation

Prefer Rust or sound intrinsics. Only function-local `asm!` and unavoidable `naked_asm!` routines are permitted; `global_asm!` is forbidden. For each proposed operation, record:

1. Exact privileged/architectural operation and baseline source/specification authority.
2. Why ordinary Rust and available intrinsics cannot express it; reject convenience-only assembly.
3. Entry/exit privilege, interrupt and preemption state, CPU features, register inputs/outputs and all clobbers, flags, memory effects, ordering, stack alignment/use, control-flow and fault behavior.
4. Justification for every option such as `nomem`, `nostack`, `preserves_flags`, or `noreturn`; compiler barriers are not automatically hardware barriers.
5. Safe wrapper preconditions/postconditions, ownership/lifetime rules, and architecture plus unsafe reviewer identities.
6. Planned disassembly/relocation inspection under the pinned supported optimization settings, including checks for unexpected prologues, stack accesses, vector use, helper calls, instrumentation, and instruction encodings.
7. QEMU and physical tests that observe the operation and its failure modes.

No standalone `.S`, `.s`, or assembly implementation files and no `global_asm!` escape, even for boot entry. Do not copy upstream entry assembly wholesale. If the pinned compiler cannot express a required entry contract within the approved Rust/function-local `asm!`/`naked_asm!` boundary, stop that port and record the compiler capability blocker; do not silently weaken the contract.

Output: an assembly proof record attached to each unsafe architecture primitive, not merely a generic `SAFETY` comment.

### 7. Advance only on cell-specific evidence

At M1 require image inspection, reset-to-entry, validated stack/memory map, deliberately triggered exception, timer interrupt, and recovery on both QEMU and a physical x86_64 system. Preserve the actually executed cell9 subset in [implementation](../../../docs/implementation.md); do not relabel the still-open physical path as passed. As M2 facilities land, add AP startup/shutdown, cross-core atomic and ordering tests, TLB/cache coherence, CPU hotplug, interrupt storms, NUMA and IOMMU/DMA interactions. From M3 verify actual userspace syscall/ELF/signal/compat ABIs, not just kernel self-tests. Extend the same paired process through every architecture at M7.

Use baseline differential, adversarial, stress, and recovery tests. Retain logs, image/configuration digests, firmware/CPU revisions, disassembly, failures, and test-command identity. Link optimization proposals to the [performance contract](../../../docs/performance.md); emulated timing never qualifies physical performance.

Use the delivered [bounded functional smoke runner](../../../docs/bare-metal-suite.md) only for the observations it implements once userspace runs; it does not exercise early entry, interrupt nesting, physical DMA or complete architecture parity. Extend the existing freestanding bootstrap cases with exact build/boot instructions, timeouts, expected observations and recovery steps for remaining architecture requirements. Only the current workstation is physically available now. An isolated storage-free diagnostic trial can precede rootfs/initramfs/userspace on separate user-owned recoverable media with independent known-good recovery; it is not a Linux-replacement package or M1 closure. The user operates candidate install/boot under the [packaging design](../../../docs/packaging.md), preserving the working kernel. Do not change host boot state, reboot or run destructive hardware tests. Missing remote-console/recovery equipment or additional architectures/vendors remains a named qualification blocker.

An architecture cell is done only when its compiler/image/boot/entry/MMU-or-noMMU/SMP/interrupt/ABI obligations are implemented, unsafe and mandatory assembly proofs reviewed, and all applicable differential/adversarial/stress/recovery cases genuinely pass on both emulation and required physical platforms. Apply the exhaustive [definition of done](../../../docs/definition-of-done.md); enumerating architecture directories or successfully compiling a target is not closure.

## Stop conditions and handoff

Stop advancement for unexplained register/stack corruption, unsupported backend operations, missing assembly proof, absent recovery, missing physical evidence, or contradictory ABI behavior. Keep untested cells unqualified and proposed changes `not_started` until actual work changes their status. A first boot is not architecture parity.

Return the affected cells and upstream paths, target recipe, state machines, safety/assembly proof obligations, paired test plan, observed evidence only, and named blockers. Do not claim builds, boots, or performance results that were not executed. During planning-only assignments do not run the future gates.

## Primary sources and limitations

- [Rust target tiers](https://doc.rust-lang.org/rustc/platform-support.html) distinguish build/test guarantees; they do not certify Linux kernel behavior. Recheck against the pinned compiler, since online documentation moves.
- [Freestanding x86_64 target contract](https://doc.rust-lang.org/rustc/platform-support/x86_64-unknown-none.html) documents no `std`, no default allocator, soft-float defaults, code model, and function ABI.
- [Rust inline assembly reference](https://doc.rust-lang.org/reference/inline-assembly.html) governs compiler-facing assembly obligations; it does not prove privileged hardware semantics.
- [Pinned Linux x86 boot protocol](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/arch/x86/boot.rst) supplies versioned boot layout and handoff requirements, not a portable all-architecture boot protocol.
- [Pinned Linux entry/exit handling](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/core-api/entry.rst) explains transition ordering and non-instrumentable regions. Port its obligations, not its C implementation.
