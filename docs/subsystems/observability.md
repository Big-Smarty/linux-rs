# Observability, debugging, crash recovery and RAS

## Status and shared acceptance contract

**Every observability-facility workstream below remains `not_started`.** This document proposes a Rust-only Linux 6.18.57 facility port, not existing tracing support. The [core bootstrap](core.md) does not implement these Linux logging/tracing/crash interfaces. Early diagnostics and physical console/recovery preparation belong in M1 alongside QEMU; physical execution remains gated and unclaimed. SMP-safe infrastructure follows M2–M3; broad tools/facilities develop through M6; every baseline architecture/device/configuration closes in M7 and measured qualification is M8. “Advanced” does not mean optional final compatibility.

Accepted architecture is **modular monolithic Rust**, with fixed 6.18.57 feature scope and explicit reviewed security deltas. Only unavoidable function-local `asm!`/`naked_asm!` with proof/review contracts may implement low-level transitions; no `global_asm!`, standalone assembly or C runtime shim. All in-baseline module functionality needs Rust replacements; extra third-party/out-of-tree artifacts require separate scope approval.

Related plans: [core](core.md), [memory](memory.md), [process](process.md), [architecture backends](architectures.md), [drivers](drivers.md), [firmware](firmware.md), [security](security.md), [extension/BTF lifecycle](extensions.md), [virtualization](virtualization.md), [toolchain](../toolchain.md), [verification](../verification.md), [performance](../performance.md), [physical lab](../bare-metal.md), [runnable smoke suite](../bare-metal-suite.md), and [definition of done](../definition-of-done.md).

**Definition of done for each family:** enumerate pinned configuration/architecture/UAPI/features and external tool consumers; implement every supported behavior and negative/error path; preserve security/lockdown/namespace permissions and wire formats except approved ledger deltas; pass differential, adversarial, concurrency and recovery tests; supply both emulated and physical evidence for each required backend; demonstrate at-least-reference workload performance. Missing PMU, trace device, RAS injection facility or physical architecture is a named blocker, not a pass, an excuse to delete the feature, or an inferred capability from QEMU. The current workstation is the only currently available physical host; the rest of the matrix is an acquisition/qualification prerequisite.

The [pinned tracing index](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/trace/index.rst) includes ftrace, trace events, kprobes/fprobes/eprobes, hardware trace, runtime verification, OS-noise/timer-latency and userspace events. That is a closure list, not a promise that a single log buffer implements them all. Architecture-dependent support must match pinned configuration truth. The [ftrace design narrative](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/trace/ftrace-design.rst) explicitly warns that portions are out of date; resolve concrete behavior against pinned code and selftests.

## 1. Diagnostics, symbols, stack unwinding and interactive debug

### Ordered port

1. M1: initialize an allocation-independent serial/early console and bounded emergency log before normal allocation or interrupts. Add build identity, CPU/exception/register information and a panic ownership protocol; do not deadlock printing a fault that interrupted the console lock. Validate through the physical recovery console as soon as boot exists.
2. M2: implement SMP log record reservation/commit and readout, sequence numbers, timestamps, levels, rate limiting, console handover and panic flush. Port Linux-visible printk/kmsg/syslog semantics, `/dev/kmsg`, console configuration, dynamic debug and permissions; keep early/emergency data recoverable across normal-console failure.
3. Establish symbol/build-ID tables, per-architecture frame/unwind metadata, exception/IRQ/NMI stack transitions, module/JIT symbols and dependable stack-walk failure reporting. Support Rust optimized/inlined frames in offline DWARF consumers. A plausible backtrace is not a reliable stack proof.
4. Port supported kgdb/kdb/debug transport behavior and breakpoints with SMP stop/resume, register access, single-step and fault handling; integrate ptrace/proc access with [process](process.md). Compare GDB usage against the pinned remote protocol and actual architecture register set. DebugFS remains intentionally less stable upstream than userspace ABIs, but baseline tool-consumed interfaces still need an explicit compatibility record.

### Crates, bundling and simplification limits

Project-owned kernel logging/unwind and debug protocol layers share CPU stop/rendezvous, clocks, symbol lifetime and security hooks. `log` can be evaluated only as an internal static-message facade, not as a replacement for printk ABI; `tracing` subscriber runtimes are not a kernel scheduler/IRQ-safe tracing implementation. [gimli](https://github.com/gimli-rs/gimli) is an offline DWARF parsing candidate; [object](https://github.com/gimli-rs/object) is a candidate for trusted build artifacts, not an unrestricted untrusted loader: its maintainers explicitly say little effort is spent mitigating denial of service and parser results are not platform loader behavior. Feature/license/native-code closure remains subject to [dependency review](../dependencies.md).

Typed log records, static format metadata and one controlled symbol registry can simplify internals. Do not replace Linux interfaces with a project-only binary logger, delete interactive debugging to avoid unsafe code, or claim reliable unwinding solely because frame pointers are enabled. No separate assembly implementations: required trap entry/debug operations use reviewed Rust/inline assembly contracts and machine-code inspection.

### Security, optimization and observable done

Permissions must enforce `dmesg_restrict`, address-disclosure controls, capabilities, LSM and lockdown, including panic dumps and remote debug. Debugger sessions effectively control kernel execution; treat transport access as a privileged trust boundary. Avoid secret logging; secure retention and access to dumps are separate from producing them.

Optimize disabled debug sites to avoid formatting/allocation, use per-CPU/batched non-emergency console work without changing ordering/loss accounting, and bound panic-time work. Differentially test log read/poll/seek/wrap/loss, rate limits, console switching, NMI/IRQ recursion, OOM and concurrent panic; compare GDB register/step/breakpoint behavior on QEMU and real CPU vendors. Physical unplugged/slow serial, CPU hotplug, suspend/resume and panic-console recovery are mandatory. Measure disabled-site cycles, messages/s, drops, log memory, serial perturbation, panic-to-first-byte and unwind latency/completeness across normal/IRQ/NMI/module/JIT frames. Never improve a benchmark by suppressing required records or disabling security.

## 2. Tracepoints, tracefs, ftrace and event analysis

**Primary contracts:** [trace events](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/trace/events.rst), [ftrace](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/trace/ftrace.rst), [tracepoints](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/trace/tracepoints.rst), [ring-buffer design](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/trace/ring-buffer-design.rst) and [buffer mmap](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/trace/ring-buffer-map.rst).

### Ordered port

1. After per-CPU storage, clocks, RCU and nested interrupt handling, port trace record layouts and buffer reserve/commit/reader protocols. Preserve overwrite versus producer/consumer loss behavior, nesting, memory barriers, page ownership, timestamps and per-CPU statistics; generic “lock-free” is not an argument for the required NMI/preemption protocol.
2. Implement tracefs mounts, directory/file semantics, instances, CPU masks, buffer sizing, raw/text/snapshot/pipe/mmap reads, event IDs/formats/filter expressions and triggers. Preserve dynamic locations, field signedness/offsets, parsing errors, poll behavior and snapshot versus consuming-read distinctions used by trace-cmd/perf.
3. Port static tracepoints and disabled fast paths, event classes, scheduler/syscall/IRQ/memory/block/network/module/security/virtualization events and user_events registration/write/fault behavior. Each subsystem adds its pinned producers and format tests; do not advertise an event that never fires.
4. Implement compiler-assisted function tracing/function graph, dynamic patch sites and register-save/trampoline ABIs in Rust. Toolchain must demonstrate Rust instrumentation, stable patchable site shape, inlining/tail-call handling and unwind metadata; importing the upstream C `mcount`/assembly runtime is prohibited. Coordinate patch conflicts with kprobes/BPF/livepatch through a single transaction authority.
5. Add histogram/synthetic events, event probes/fprobes, function filters, latency tracers, boot-time tracing, osnoise/timerlat/hwlat and runtime verification monitors/generation as present in the pinned matrix. Project-owned monitor generators are Rust; external reference generators can be research oracles, not runtime dependencies.

### Crates and shared mechanisms

Project-owned event/tracefs implementation. Generic ringbuffer crates are rejected as drop-in replacements unless they prove the exact nested-writer/per-CPU/page-swap/mmap ordering contract. Share clocks, event descriptions, static keys, RCU unregister, executable patch service and symbol lifetimes across ftrace/perf/BPF. Share implementation components only when semantics match: [BPF ringbuf](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/bpf/ringbuf.rst) has a distinct MPSC reservation/ordering contract and is not interchangeable with perf/ftrace buffers.

**Safe simplifications:** generate event layout descriptions and Rust accessors from one reviewed declarative source; use compile-time specialization for disabled configurations. Preserve Linux event names/fields and observable functionality; a renamed Rust struct does not justify breaking userspace event parsing. Do not merge all trace instances or replace missing tracers with empty files.

### Invariants, optimization and tests

No observer may read uncommitted/uninitialized record data. Unregister waits for in-flight callbacks and mapped buffers retain lifetime. IRQ/NMI producers cannot sleep or allocate through normal reclaim. Tracefs permissions and event filtering must not leak another tenant's memory. Executable patching respects W^X with architecture rendezvous/cache synchronization; no persistent writable-executable alias.

Optimize disabled tracepoints to a measured minimal path, reserve records in-place, avoid hot-path string formatting and batch consumer wakeups only with equivalent visibility. Test all pinned ftrace selftests and event parsers, concurrent mmap/read/wrap/snapshot/resizing, recursion and NMI nesting, CPU hotplug, preemption/RT configurations, clock changes and malformed filter/trigger grammars. Verify actual scheduler/block/network workloads in trace-cmd/perf, not only synthetic producers. On physical SMP/NUMA systems measure disabled and enabled cycles/site, events/s and losses by source, p99/p999 workload interference, CPU/memory and power. Test latency tracers on real timing hardware and firmware-induced stalls; VM timings are not physical tail-latency evidence.

## 3. Kprobes, kretprobes, uprobes and dynamic event safety

**Primary contracts:** [kprobes](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/trace/kprobes.rst), [kprobe trace syntax](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/trace/kprobetrace.rst), [uprobes](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/trace/uprobetracer.rst), [fprobes](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/trace/fprobe.rst).

1. Build per-architecture instruction decoding/relocation/single-step and exception-table integration before arbitrary-address probes. Implement forbidden-address blacklists and interaction with alternative instructions, ftrace sites, jump labels, modules and Rust code generation.
2. Port registration, duplicate/aggregate probes, fault and pre/post handlers, optimized probes and return instances, including `maxactive`/miss accounting. Return interception must agree with stack-unwind, pointer authentication/shadow stacks and reliable-stack consumers.
3. Implement uprobes by inode/file offset and mapped executable lifetime, copy-on-write pages, execute-out-of-line slots, fork/exec/mmap/unmap and return handling; preserve fetch-argument syntax/types and tracefs/dynamic_events APIs. Never copy hard-coded instruction offsets from a different binary build.
4. Connect perf and BPF attach interfaces, kprobe/fprobe/eprobe event parsing and deferred unregister. Probing Rust implementation symbols requires concrete symbol/type mapping, not pretending every old C-internal symbol is a stable ABI. Record tool-consumed incompatibilities in the delta ledger and provide measured replacements, not silent disappearance.

**Crate/shared decision:** project architecture decoder/patch adapter initially follows pinned behavior; instruction-decoder crate candidates require coverage, license, `no_std`, no hidden allocation and fault/privilege review for the particular architecture, and none is approved by this plan. Share executable patch transactions, RCU, symbol/build-ID tables and trace records. No generic JIT library is assumed able to relocate arbitrary kernel instructions safely.

**Simplification/security:** batch registration and typed handler contexts can simplify control flow, not remove arbitrary-offset probes, compat userspace or return probes supported by baseline. Fault-safe bounded user fetches are mandatory; an uprobed process can race memory unmapping and modify arguments. Probe installation/unload races cannot redirect to freed memory. Preserve lockdown/capability/LSM checks.

**Optimize/test/done:** use proven ftrace-backed sites/optimized probes where supported without altering semantics. Differentially test probes across instruction classes, faults, nested IRQ/NMI, recursion, module unload, patched functions, exec/mmap races and malicious fetch expressions; compare hit/miss counts and registers. Physical architecture coverage includes debugger state, instruction-cache coherence and mitigations enabled. Measure cycles/hit, enabled/disabled workload overhead, registration/unregistration time, return-instance memory and tail latency under high event rates.

## 4. Perf events, PMUs and hardware trace

**Security authority:** [perf security](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/admin-guide/perf-security.rst) details disclosure risk and `CAP_PERFMON`/legacy capability controls. Resolve exact permission behavior against implementation; historical prose is not permission to bypass LSM/lockdown as root.

### Port and dependency sequence

1. After scheduler clocks, fd/mmap/poll, signals, credentials and resource accounting, port `perf_event_open` attribute-size negotiation, event IDs, ioctls/read formats and file lifecycle. Include software events, groups, inherit, task/CPU/cgroup attachment, pinned/exclusive events, enable/disable/reset, period/frequency and overflow/throttling.
2. Implement sampling/ring buffers, metadata/mmap pages, ordering and loss records, callchains, branch stacks, registers/stack samples, AUX buffers, signal/async notifications and time conversion. Include compat UAPI and CPU migration/hotplug/reconfiguration.
3. Port PMU scheduling, constraints/multiplexing, event accounting and architecture-specific driver backends: Intel/AMD core/uncore/IBS/PT where supported, Arm PMU/SPE/CoreSight, and remaining baseline architecture/device PMUs. Generate an exact PMU/event/counter/resource matrix from `arch/` and `drivers/perf` rather than a generic counter emulation.
4. Integrate Intel Trace Hub, STM/Sys-T, HiSilicon PTT, MMIO tracing and other pinned trace devices with [drivers](drivers.md); the [trace index](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/trace/index.rst) defines the relevant families. Add virtualization PMU save/restore and guest accounting with [virtualization](virtualization.md).
5. Validate existing perf tooling, data records, build IDs, debug/symbol resolution and event discovery/sysfs formats; project-owned build/conversion helpers must be Rust, existing external perf remains an allowed compatibility oracle.

**Crates/bundling:** project perf/PMU implementation. Userspace perf-event wrapper crates can be differential clients after review, not PMU drivers or kernel schedulers. Offline `gimli`/`object` candidates share trusted-artifact parsing; BPF event output shares lifecycle/metadata but not every buffer invariant.

**Limits/invariants:** optimize event scheduling tables and per-CPU records but preserve counter constraints, multiplexed running/enabled time, overflow semantics, resource limits, paranoia/permission knobs and sampling precision distinctions. Do not fake unsupported hardware events as zero counters or mislabel a sampled event as precise. No leakage of stale register/stack/PMU state across tenants or VM switches; no unbounded NMI stack/record work.

**Done tests and optimization:** run `perf test` and pinned perf-events selftests plus cgroup/group/inherit/hotplug/overflow races and malicious attributes/mmap offsets. Compare counter correctness on calibrated workloads, overflow/lost/throttle behavior and PMU security denials. Physical CPUs/devices and their firmware/steppings are mandatory; QEMU generic PMU does not qualify Intel PT/Arm SPE/uncore. Measure sample loss, interrupt cost, disabled/enabled application throughput/tails, cycles/event, counter scheduling fairness, CPU/memory, AUX drain bandwidth and power. Keep enabled mitigation/watchdog/PMU reservations the same as reference.

## 5. BTF, DWARF, build metadata and debug information

**Authority:** [pinned BTF](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/bpf/btf.rst) distinguishes the kernel API from ELF `.BTF`/`.BTF.ext` userspace contracts. [Extensions](extensions.md) owns validation, BPF type IDs, CO-RE and attach semantics; this section owns producing and consuming truthful observability metadata.

1. Inventory rustc/LLVM output and available BTF conversion support per architecture and optimization mode. Preserve build ID, symbols, file/line/inlining, unwind information and reproducible mappings; do not assume Rust DWARF lowers to usable Linux BTF automatically.
2. Implement required Rust-only project metadata generation/conversion if external tooling cannot represent the kernel's types. Build tooling may invoke allowed external rustc/LLVM utilities; do not embed a C conversion runtime. Produce truthful representation of Rust layouts and intentionally defined Linux-facing compatibility views.
3. Integrate vmlinux/module BTF, function/line info and runtime JIT symbols with perf, bpftool, tracing, crash tools and GDB. If a tool requires C-style internal field names/layouts, define and test the compatibility view or record a specific unresolved delta. BTF cannot claim nonexistent fields or expose private Rust memory through unchecked offsets.
4. Validate endianness, type graphs, qualifier/enum/bitfield/size rules and DWARF references, including malicious metadata submitted through APIs; separate bounded runtime validation from rich offline analysis.

**Crates/shared:** `gimli` and `object` are offline candidates, with bounds/DoS review for untrusted inputs; project-owned BTF validator/generator until a suitable candidate passes the exact Linux contract. Reuse one symbol/type identity registry and metadata hashes, not duplicate incompatible BTF type IDs in security/tracing/BPF.

**Simplification/security/optimization:** deduplicate and compress offline metadata without changing lookup/relocation semantics; keep only necessary bounded metadata resident. Do not publish misleading fake Linux C layouts to make CO-RE tests pass. Security controls cover addresses, kernel types and privileged debug data; stale module/JIT type IDs cannot refer to freed content.

**Done:** existing bpftool/libbpf/Aya relocation and introspection workflows, GDB Rust frames, perf callchains, module load/unload and crash-dump analysis work against actual artifacts on each architecture. Fuzz type/offset graphs and test stripped/separate-debug files and optimized code. Measure metadata size, kernel resident memory, type-load/query startup and relocation time. Compiler/BTF mapping not yet demonstrated is an explicit toolchain blocker, not presumed support.

## 6. Kexec, kdump, persistent failure evidence and recovery

**Authority:** [kdump](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/admin-guide/kdump/kdump.rst) describes a reserved dump-capture kernel, ELF headers and `/proc/vmcore`; the narrative's architecture list is not sufficient evidence of all pinned implementation capabilities.

1. Coordinate [memory](memory.md), architecture boot and drivers to implement crash-reserved memory, kexec image/file loading, relocation/control pages, CPU stop/state capture, device quiescence and boot handoff in Rust with audited inline assembly where unavoidable.
2. Preserve ELF notes/register layouts, `elfcorehdr`, VMCOREINFO consumer contracts, `/proc/vmcore`, crashkernel placement/options and userspace kexec/makedumpfile tooling behavior. The dump-capture kernel is a real independently bootable artifact, not a mock logger.
3. Port panic/notifier ordering, emergency restart and pstore/ramoops/firmware persistence with the [firmware](firmware.md) owner; recover crash logs even when normal storage locks are unavailable. Decode corrupt/incomplete dumps with explicit errors.
4. Enforce signed-loading/lockdown policies, dump permissions and confidential-memory exclusions; crash memory includes credentials/keys. Validate DMA isolation and crashkernel survival when the first kernel fails with active devices.

**Crates/shared:** project kexec/image/crash machinery with shared ELF readers and signature/key services. Offline dump tools can use reviewed `object`/`gimli`; parser convenience does not implement physical memory addressability or machine handoff. Existing external `kexec-tools`, makedumpfile and crash/GDB are compatibility clients, not project kernel C dependencies.

**Limits/security/optimization:** reserved pool and precomputed immutable ELF notes reduce panic-time allocation; preserve dump contents and reference userspace expectations. Do not call “panic prints registers” kdump parity, remove kexec because of lockdown, or make crash success depend on a scheduler still working. Avoid indiscriminate secret redaction that silently corrupts vmcore; implement configured supported restrictions and record deltas explicitly.

**Done tests:** normal kexec and induced panic produce analyzable dumps with all CPU notes, memory ranges, modules and symbols; test low memory, corrupted first-kernel state, nested failure, huge memory/NUMA, IOMMU-active storage/network and watchdog pretimeout. Emulation precedes **explicit operator-approved destructive fault injection on recovery-equipped physical test machines**, never the developer host automatically. Measure reservation memory, load time, panic-to-capture time, dump bytes/s, completeness and service restoration time; report each failed capture and unavailable device/hardware condition.

## 7. Livepatch and runtime text/state transitions

**Authority:** [pinned livepatch](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/livepatch/livepatch.rst) describes shared text-modification concerns, per-task consistency, stack checking and transitions; it explicitly distinguishes architectures without reliable-stack support.

1. Require reliable per-architecture stack validation, task/interrupt identity, module lifetime and the shared ftrace/text patch service. Inventory enabled functions and Rust codegen effects: inlining, generics, tail calls, name mangling, ABI and compiler changes.
2. Implement signed Rust livepatch replacement artifacts, relocation/symbol targeting, per-task transition state and syscall/idle switching, convergence/cancel/reversal, callbacks, shadow/state handling and sysfs/proc interfaces. Support cumulative/replacement and pinned supported force behavior with explicit risk; do not mark completion while tasks still execute old code.
3. Specify patch function ABI/semantic invariants and coordinated multi-function/data-state transitions. Existing legacy C livepatch modules cannot load; replacement functionality and operational userspace behavior remain required. Distinguish that approved artifact boundary from an unsupported promise of stable Rust internal ABI across compilers.
4. Exercise patch interactions with modules, ftrace/kprobes/BPF trampolines, hotplug, NMI and CPU stop. Patch unload waits for references, stacks and readers; signatures do not guarantee semantic compatibility.

**Crates/shared:** no livepatch crate selected. Project port over shared executable mapping, signature, RCU, task transition, unwind and module registries. Do not add a second independent patching engine or reuse a userspace hot-reload crate.

**Simplification/invariants:** typed state epochs and generated patch metadata may simplify transition accounting, not permit replacing arbitrary stateful functions without a consistency model. An architecture can be staged without livepatch but remains incomplete until its pinned support is met; no fake success on unsupported stacks. Force transitions need the exact baseline behavior and documented lifetime consequences, not a hidden safety ban.

**Optimization/test/done:** compile disabled patch sites minimally and amortize registration, never skip stack validation to improve convergence numbers. Run pinned livepatch selftests with actual Rust artifacts, blocked kthreads, active recursive calls, interrupts, reversal, failed init/signature, stacking and module unload. Physical SMP/hotplug and sustained network/storage workloads must remain correct during repeated transitions. Measure per-call disabled/enabled overhead, patch-load time, convergence p50/p99/worst case, stopped time, retained old-code memory and workload tails. A stuck transition is a reported failed/incomplete case, not silently averaged away.

## 8. RAS, hardware faults and watchdogs

### 8.1 RAS, EDAC, MCE/APEI/GHES and recovery

**Authority:** [RAS concepts and interfaces](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/admin-guide/RAS/main.rst) distinguish corrected, uncorrected, fatal and non-fatal errors; “continue after every error” is not reliability.

1. Port architecture machine-check/firmware-first error record intake, EDAC and device PCIe/CXL/memory error providers with [drivers](drivers.md) and [firmware](firmware.md). Validate CPER/firmware record sizes and lifetime; capture unrecoverable state without normal allocation assumptions.
2. Implement classification, counters, trace/sysfs/event delivery, corrected-error handling, page poisoning/offlining, SIGBUS/fatal process policy, memory/device recovery and escalation/reboot policy. Integrate memory hotplug, huge pages, DAX/persistent memory, DMA pins and VFIO assigned devices rather than assuming all poison is ordinary anonymous RAM.
3. Support the pinned injection/testing interfaces under their privilege/configuration gates, without enabling destructive injectors in ordinary smoke runs; preserve userspace rasdaemon/EDAC/MCE tooling formats and correlate hardware IDs.

**Crates/shared:** project RAS state machines and bounded record codecs; no generic error-reporting crate supplies hardware semantics. Share MM poison state, memory ownership, workqueues, emergency logging and firmware parsers. Typed error states simplify propagation, not recovery facts.

**Invariants/limits:** corrupted pages cannot reenter allocation or leak across tenants; a DMA mapping to poisoned/offlined memory must be synchronized safely. Never suppress correctable records to claim a lower error rate or keep executing after fatal corruption just to maintain uptime. Fault injection is not evidence of every real failure mode.

**Optimization/test/done:** batch safe deferred corrected-error accounting while retaining identity and ordering; fatal paths stay bounded. Differential record/threshold/policy tests, ECC/MCE/APEI and PCIe injection, poisoned memory in anon/file/huge/DAX/pinned/guest workloads, hotplug and repeated recovery. Physical ECC/firmware/error-injection hardware is required and currently unavailable beyond whatever the workstation actually exposes; inspect and record, never assume ECC/injection from CPU branding. Measure detection/report/recovery latency, lost reports, isolation correctness, memory retired, workload tails and service outage; VM injection alone is insufficient.

### 8.2 Lockup detectors, hung-task/RCU stalls and hardware watchdogs

**Authority:** [lockup watchdogs](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/admin-guide/lockup-watchdogs.rst) couple hrtimer/perf detection with CPU masks/NO_HZ behavior; [watchdog API](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/watchdog/watchdog-api.rst) describes keepalive, timeouts, nowayout, magic close and pretimeouts but warns of its historical coverage. Pinned implementation/driver capabilities arbitrate exact behavior.

1. Implement soft/hard lockup, hung-task and RCU-stall observation after clocks/SMP/scheduler/RCU exist, then panic/warn policy, threshold and CPU-mask/sysctl/boot behavior including isolated/NO_HZ CPUs and suspend/hotplug.
2. Port watchdog core and per-device drivers, `/dev/watchdogN`/legacy device, ioctls/capability reporting, exclusive ownership, timeout quantization, keepalive, magic close, nowayout, boot status and pretimeout governors.
3. Integrate firmware/BMC handoff and panic/kdump timing without racing two agents that alternately disarm/rearm the device. A live userspace daemon does not prove all kernel CPUs are progressing, and a software watchdog cannot reset a machine when its own execution source is stopped.

**Crates/shared:** project detector/driver implementations; share timers, perf counter reservations, CPU hotplug, emergency logging and recovery policy. Generic embedded watchdog HALs may help register adapters only after exact device/API review; they are not `/dev/watchdog` compatibility.

**Limits/security/optimization:** timer batching and per-CPU state reduce overhead only within documented detection bounds; retain nowayout and actual hardware-supported returned timeout, do not fake exact timeout settings. Serialize open/close and device removal; privileged writes must not accidentally disable protection. Avoid false positives on suspend, long firmware pauses or oversubscribed guests while preserving reference policy.

**Done tests:** watchdog device/timeout/keepalive/close/pretimeout tests and software lockup/stall injection with captured reason/CPU/stack, then reset/capture evidence. Genuine physical reset tests require console, saved working boot option and **explicit separate operator action**; never arm a nowayout watchdog in the ordinary non-destructive suite. Measure detection versus configured threshold, reset/panic-to-recovery time, false positives, counter/timer CPU and power overhead and workload p99/p999 effects. Record absent watchdog/NMI PMU/BMC as backend blockers.

## Operator execution and evidence separation

The bounded project suite is a real Rust userspace smoke harness, **not** an implementation of the probes, crash injectors or full suites above. From a manually booted reference/candidate and a fresh output path, use the documented contract:

```text
cargo run -p baremetal -- run --output <new-directory> --label <label> --expect-release <exact-osrelease> --environment <reference|qemu|bare-metal>
```

The operator chooses one environment value and provides the exact running release; labels are operator assertions, not remote proof of bare metal. It captures only the [suite's bounded coverage](../bare-metal-suite.md). It must not mount tracefs, arm watchdogs, load modules, patch code, reboot or inject faults merely to make this document's future gates look exercised. Manual boot/package selection preserves the existing Arch/CachyOS kernel and recovery entries according to [packaging](../packaging.md).

For full future qualification, acquire/build the **pinned external Linux selftests and matching tools outside project executable source**, record their versions/configuration and perform separate privileged lab campaigns. Concrete existing suite entrypoints include `perf test`, the pinned `tools/testing/selftests/ftrace/ftracetest`, the pinned livepatch selftest runner through `make -C <pinned-linux>/tools/testing/selftests TARGETS=livepatch run_tests`, and relevant perf-events/BPF/KVM tests selected in their owning plans. Build/run recipes must be qualified against the actual tool/kernel and saved with stdout/stderr, test names, skip reasons, event-format snapshots, serial logs and hardware manifest; “make returned zero” with skipped tests does not qualify a backend.

All throughput/latency/CPU/memory/startup/power comparisons follow [performance methodology](../performance.md): same hardware, firmware, topology, security/mitigations, event set, compiler optimization intent and workload; repetitions/confidence intervals and raw per-case distributions; no geometric-mean masking, no arbitrary allowed regression and no security-disabled fast result. No observability-facility, performance or physical qualification result is claimed by this plan.
