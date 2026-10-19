---
name: kernel-networking
description: "Plan, port, and review Linux-compatible Rust networking: socket ABI, protocol state, packet ownership, checksums/offloads, queues and backpressure, namespaces, netlink, routing, filtering, and NIC integration. Use for network stack changes and network correctness/performance qualification."
---

# Kernel networking engineering

## Scope and current authority

Use for the Linux socket contract, packet storage and metadata, protocol processing, network control plane, namespaces, routing, traffic control, filtering, and network-device integration. Pair NIC/DMA work with [kernel-drivers](../kernel-drivers/SKILL.md), page pools and zero-copy pins with [kernel-memory](../kernel-memory/SKILL.md), descriptor/Unix-socket behavior with [kernel-abi](../kernel-abi/SKILL.md), and concurrent lifetime or hostile packets with [kernel-concurrency](../kernel-concurrency/SKILL.md) and [kernel-security](../kernel-security/SKILL.md).

Read [repository instructions](../../../AGENTS.md), [approved decisions](../../../docs/decisions.md), [network plan](../../../docs/subsystems/networking.md), [IPC plan](../../../docs/subsystems/ipc.md), [driver plan](../../../docs/subsystems/drivers.md), [compatibility](../../../docs/compatibility.md), and [reference metadata](../../../planning/reference.tsv) before designing. Consult [coverage](../../../docs/coverage.md), [dependencies](../../../docs/dependencies.md), [licensing](../../../docs/licensing.md), [verification](../../../docs/verification.md), [performance](../../../docs/performance.md), [bare-metal requirements](../../../docs/bare-metal.md), and the [definition of done](../../../docs/definition-of-done.md).

The initial reference is Linux 6.18.57; implementation is Rust-only kernel `no_std` without C kernel modules or runtime shims. Use fallible, accounted allocation with context restrictions, not a blanket heap ban. Initial userspace is Arch/CachyOS userspace, not a promise to inherit downstream CachyOS kernel patches. Balanced server/container workloads guide priority and performance profiling, not final protocol scope. The [current bootstrap](../../../docs/implementation.md) has real QEMU execution but no socket ABI, protocol stack or NIC implementation; networking workstreams remain `not_started`, distinct from the currently routed `in_progress` bootstrap/foundation rows.

Accepted architecture: modular monolithic Rust kernel. Feature scope is fixed to upstream Linux 6.18.57 with explicitly reviewed security deltas; record each delta's behavior, rationale, tests, and compatibility/performance impact. Later feature-baseline changes require a separate decision. Every in-baseline module's functionality needs a Rust replacement; arbitrary proprietary/out-of-tree modules are not implicitly included. Function-local `asm!` and `naked_asm!` are allowed only where unavoidable, with operation/register/memory/clobber/privilege proofs, reviewers, and disassembly checks; no `global_asm!` or standalone assembly escape.

## Primary evidence and contract extraction

Map exact pinned upstream paths, configurations, syscalls/options, protocols, netlink families, feature bits, and workstream IDs. Read implementation and selftests for the changed behavior, including indirect callbacks and error paths. Preserve provenance and per-file notices for direct ports. Record observed facts, proposed mechanisms, assumptions, and test results separately.

Starting sources:

- [Packet metadata and cloning](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/networking/skbuff.rst) and [actual buffer/checksum contracts](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/include/linux/skbuff.h): metadata ownership, shared payload references, checksum state, offsets, and driver obligations. The RST references generated header documentation; read the header rather than treating those directives as the full contract.
- [NAPI](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/networking/napi.rst): scheduling/ownership, IRQ masking, zero budget, exact-budget completion, and disable semantics. Releasing poll ownership is not the same as proving every subsequent instruction has exited.
- [Segmentation offloads](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/networking/segmentation-offloads.rst): TSO/GSO/GRO, encapsulation, checksums, and required software fallback before hardware offload.
- [Netlink introduction](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/userspace-api/netlink/intro.rst): classic versus generic families, TLV framing/alignment, acknowledgements, multipart dumps, errors, and notifications.
- [Linux socket manual](https://man7.org/linux/man-pages/man7/socket.7.html): userspace interface and readiness/options. It is not version-pinned; reconcile every applicable detail against Linux 6.18.57 source and tests.
- [RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html): TCP wire/state-machine requirements, with separate companion documents for congestion control and other extensions. RFC conformance alone does not establish Linux socket or full Linux TCP policy compatibility.
- [smoltcp documentation](https://docs.rs/smoltcp/latest/smoltcp/): a candidate toolbox of protocol primitives whose documentation explicitly distinguishes its socket API from Berkeley sockets. Inspect and pin an exact version before any reuse.

## Ordered decision workflow

Produce these decisions for each protocol/control-plane/datapath subfamily, including obscure and legacy families retained in coverage.

1. **Port behavior first.** Identify socket family/type/protocol combinations, UAPI layouts and errors, options, readiness, packet/wire behavior, netlink schemas, network-namespace scope, filtering hooks, and driver capabilities. Identify baseline configuration and policy, not just the RFC's minimum. Do not equate a working HTTP request, ping, loopback, or TCP handshake with full networking compatibility.
2. **Evaluate reuse.** Review exact candidate source/version/license/features and transitive code in the [dependency ledger](../../../docs/dependencies.md). Evaluate protocol coverage, timers, congestion/recovery algorithms, cancellation, fallibility, SMP, namespace/accounting integration, offloads, and Linux observable semantics. `smoltcp` is not a Linux-stack drop-in: wire codecs or individual algorithms may be reusable only after feature-by-feature analysis. Userspace socket wrappers and async runtimes are not kernel socket implementations. Reject unsupported substitutions explicitly rather than hiding missing netlink, ancillary data, or protocols behind an adapter.
3. **Consolidate shared mechanisms.** Establish shared packet-buffer ownership, fragments, checked cursors, timers, reference retirement, route/neighbor references, namespace lifetime, queue accounting, socket wait/wakeup, and netlink validation. Integrate DMA/page pools with the common memory/driver contracts. Reuse framing or indexing where semantics align; do not force stream, datagram, Unix, packet, and netlink sockets into one fake identical state machine.
4. **Simplify internally.** Prefer explicit packet state and typed checksum/offset metadata, one validated TLV walker, narrow protocol operations, and per-queue ownership. Software checksums or one queue can be declared bring-up modes, not final scope reductions or performance proof. Do not remove extension headers, multicast, routing policies, namespace permissions, ancillary data, or legacy families just because a minimal stack is easier.
5. **Review security and invariants.** Perform the ownership, state-machine, namespace, and resource-bound reviews below. Treat wire packets, device descriptors, user buffers, sockopts, and netlink messages as untrusted. Safety and robustness require more than Rust bounds checking.
6. **Improve after semantic proof.** Profile packet/byte workload distribution, allocation, copying, cache misses, lock contention, IRQ rate, queue locality, timers, and drops. Consider page-pool recycling, batching, scatter/gather, multiqueue/RSS, affinity, GSO/GRO, and zero-copy with validated fallback. Preserve ordering, accounting, fairness, cancellation, latency/tails, power, and security. Avoid introducing copies or allocations merely to hide an ownership design problem.

## Domain implementation workflow

### Socket semantics and protocol state

- Establish socket object, open-file description, descriptor, namespace, credentials, and protocol-control-block lifetimes. Define state transitions for create/bind/listen/connect/accept/send/receive/shutdown/close and asynchronous error. Review shared descriptors, concurrent close/cancel, namespace exit, and timers retaining a socket. Unix ancillary descriptor cycles and credential transfer need explicit lifetime/security handling with IPC/VFS owners.
- Specify blocking/nonblocking behavior, partial stream I/O, datagram boundaries and truncation, zero-length operations, peer EOF versus reset, half-close, SIGPIPE suppression, signal interruption/restart, timeout versus error precedence, and asynchronous connect completion. Readiness is an observation of state, not a reservation of future progress; prove wait registration/recheck ordering and edge-trigger wakeups.
- Port `sendmsg`/`recvmsg`, iovecs, control-message alignment and length, `MSG_*` flags, `SCM_RIGHTS`/credentials, error queues, timestamping, socket options, `accept4`, `poll`/epoll, and asynchronous APIs as applicable. Validate user lengths, compat layouts, authorization, partial user-copy faults, and information disclosure through padding. Unsupported flags must match the pinned error behavior, not be silently ignored.
- Implement protocol families through explicit dependency gates: link/ARP/neighbor discovery, IPv4 and IPv6 routing/fragmentation/reassembly/ICMP, UDP, TCP, multicast, and server/container control paths first; retain SCTP, DCCP, MPTCP, packet/raw sockets, tunnels, XFRM/IPsec, wireless and other baseline families in tracked scope. DNS/DHCP are generally userspace services; do not invent a kernel DNS resolver to stand in for required socket behavior.
- For each protocol, extract state/event/timer tables, sequence-space arithmetic, checksum and length rules, MTU/PMTU, fragmentation limits, retransmission, congestion control, flow control, reset/error behavior, options/extensions, and namespace bindings from pinned code and relevant standards. A single RFC cannot stand in for Linux algorithms, interoperability quirks, or security fixes.

### Packet ownership, checksums, and offload

- Model packet metadata separately from payload storage, shared fragments, clones, headroom/tailroom, and mutable headers. Define who may mutate, when copy-on-write is needed, and which clones retain data. A cloned metadata object is not proof of unique payload access; never create mutable references into shared or device-owned bytes without an exclusion proof.
- Write receive and transmit transitions from descriptor/DMA ownership through poll/stack/queue/socket, retransmission, filtering/cloning, and final release. Account actual retained storage and fragments rather than only visible payload bytes. Cover partial mapping, DMA sync, enqueue failure, reroute, timeout, completion, cancellation, and unplug. Zero-copy send/receive retains user pins and completion obligations until the true final consumer is done.
- Represent checksum states with their actual meanings: unknown/not verified, verified by a capable device, a supplied complete checksum, and a requested partial offload are not interchangeable booleans. Validate checksum start/offset, inner/outer headers, coverage, pseudo-header adjustments, fragmentation, encapsulation, and CRC versus Internet checksums. Device-provided success metadata must be valid for the actual protocol/feature.
- Advertise offloads only after verified feature negotiation and a correct software fallback. Test unsupported combinations and route/device changes. Implement GSO segmentation and GRO coalescing with appropriate protocol constraints and header/sequence/checksum updates; do not collapse UDP datagram semantics or propagate stale offload metadata after rewriting headers. A packet capture before offload may show partial checksums or large segments and is not by itself a wire-correctness oracle.

### Polling, queues, backpressure, and control plane

- Specify execution contexts, poll budget, hard-IRQ/deferred transitions, mask/rearm order, and disable/drain semantics jointly with drivers. Handle zero-budget TX-only work, exactly exhausted RX budgets, and teardown after poll ownership release. Do not assume poll is always called only after this driver scheduled it.
- Bound socket send/receive queues, device rings, qdisc backlog, reassembly, neighbor resolution, route caches, timers, and control messages. Specify accounting domain, watermarks, admission/drop policy, stop/wake order, and readiness changes. Backpressure must reach producers without lost wakeups, unbounded queue growth, or starvation; transmitting forever in one poll is not throughput correctness.
- Define route/neighbor updates, address/link lifecycle, policy routing, forwarding, qdiscs, bridging/VLAN, filtering/conntrack/NAT, BPF/XDP hooks, tunnel/XFRM state, and notifications through their real workstreams. Hook placement and packet rewrite order affect checksums, policy, and visibility; moving them for convenience can change behavior.
- Bind sockets, addresses, routes, devices, filters, sysctls, statistics, and permissions to the correct network/user namespace. Check capabilities in the owning namespace, not just a global root boolean. Drain references/timers and prevent cross-namespace disclosure on namespace destruction or device migration.
- For netlink implement classic and generic framing, aligned TLVs, nested attributes, policy validation, unknown/duplicate attributes according to family rules, sequence/port IDs, ACK and extended errors, multipart dump completion/interruption, multicast notifications, and receive-buffer loss behavior. Dump iteration racing mutation must have a documented baseline-compatible contract. `ip`/`ss`/container tooling needs actual route/link/socket-control behavior, not a no-op configuration endpoint.

## Mandatory invariant review

Document ownership transitions, protocol state/event tables, timer cancellation, lock/context order, queue accounting, and namespace authorization. Review at least:

- A retransmission still references payload recycled by TX completion; a clone mutates another packet's shared header; a user pin is released before zero-copy completion.
- Close, timeout, device removal, and completion race to free or wake the same socket/request; a timer observes a reallocated flow identity.
- A malformed extension/header/TLV overflows arithmetic, loops indefinitely, escapes buffer bounds, or amplifies memory/CPU work.
- A packet accepted as checksum-verified had unsupported encapsulation or metadata changed after verification; an offload is requested on a device that cannot honor it.
- Queue stop/wake and socket readiness lose an event; a flood starves other namespaces/flows; a failed enqueue leaks its memory charge.
- Namespace teardown or route replacement frees a referenced object or applies another tenant's credentials, rules, statistics, or notifications.

Each unsafe boundary must explain alignment, initialization, aliasing, ownership duration, external mutation, and retirement. Refcounts, a mutex, or a safe packet parser alone do not establish protocol, scheduling, or isolation correctness.

## Definition of done and executable evidence

For an implementation change, every applicable requirement needs an independent oracle and observed artifacts. Report pass/fail/skip/unavailable separately; no packet/protocol/kernel passes are implied by planning documents.

| Obligation | Required evidence |
| --- | --- |
| Socket compatibility | Differential syscall/option/ancillary/error/readiness traces against the pinned baseline, including concurrent close/cancel, partial I/O, half-close/reset, timeout/signal, and descriptor sharing. |
| Protocol and hostile-input correctness | State/timer and arithmetic tests, packet replay/fuzzing, malformed/fragmented/reordered/duplicated/dropped traffic, PMTU and zero-window cases, and selected baseline protocol selftests with version/configuration recorded. |
| Ownership and pressure | Allocation/map failures, clone/COW, retransmission, zero-copy pin lifetime, bounded queues/reassembly, stop/wake races, flood fairness, and cancellation/unplug leak checks after quiescence. |
| Control-plane/isolation parity | Real userspace route/link/netlink and container workflows; dump/notification races and loss; capability, namespace teardown, policy-routing/filtering, and cross-namespace negative tests. |
| QEMU plus physical NICs | QEMU debugging plus physical-machine evidence from initial network bring-up, with real DMA/IOMMU, IRQ/RSS/multiqueue, offload on/off, MTU, link flap/reset/unplug, PM, and firmware cases appropriate to each NIC. |
| Performance | Matched pinned-Linux per-flow/workload packets/s, bits/s, connection rate, latency/tails, CPU, retained memory, service startup, and power with repetitions, confidence intervals, noise controls, and no hidden individual regression. |

The actual [bounded smoke suite](../../../docs/bare-metal-suite.md) is invoked from the repository root with:

```text
cargo run -p baremetal -- run --output <new-directory> --label <label> --expect-release <exact-osrelease> --environment <reference|qemu|bare-metal>
```

Choose one environment value, an exact expected running release, a meaningful label, and a new output directory. Execute only when assigned; never install/select/boot/reboot the host on the user's behalf. The suite provides bounded TCP/UDP/Unix loopback smoke alongside memory, filesystem, process, and proc/sysfs checks. Its environment label is an operator assertion, not proof of physical hardware; a reference-host run validates the runner, not a future kernel. It does not replace protocol, NIC, namespace, adversarial, stress, recovery, or performance qualification.

For every broader physical case record its genuinely runnable invocation, case ID, Rust-owned orchestration artifact, kernel digest, machine/NIC model and firmware/configuration without collecting unique hardware serial IDs, expected oracle, timeout, exit status, console/recovery procedure, and raw logs. Do not invent a command for a runner that does not yet exist. Only the current workstation is presently available; additional vendors, NUMA/IOMMU platforms, and NIC families remain named qualification blockers, not silently assumed hardware. Keep traffic/flood/fuzz tests on isolated lab networks; default smoke must not change network settings, request privilege, contact external hosts, mount media, or write raw devices.

Use matched baseline configuration, mitigations, firmware, compiler settings, topology, affinity, MTU, offloads, queue counts, qdiscs, link speed, and congestion algorithms. Compare both small/large messages, single/many flows, cold/warm setup, bidirectional traffic, loss and memory pressure, using balanced server workloads and real physical paths. Loopback bandwidth and one bulk-flow maximum do not establish Linux performance parity. At-least-Linux performance is a release requirement; inconclusive measurements and individual regressions are not passes. Never disable security or required features to obtain a favorable number.

## Limits, stop conditions, and handoff

Stop externally visible or unsafe changes when ownership, checksum/offload semantics, queue progress, timer retirement, protocol behavior, or namespace authorization is unresolved. Stop physical traffic generation if isolation or recovery is uncertain. Do not conceal missing protocol support behind a successful narrow demo, permanently reduce scope, or substitute generic async/web application advice for kernel execution rules.

Hand off the six decisions, source/provenance and workstream mapping, socket/protocol/feature matrix, packet and timer ownership, queue/lock/context tables, namespace threat analysis, caller migrations, tests actually executed versus planned, runnable smoke and broader-suite artifacts, per-workload performance evidence, physical coverage/blockers, and exact unqualified requirements. Update owned plans/changelog through the assignment's integration rules. No installers or scripts are bundled with this skill.
