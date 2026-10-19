# IPC, local sockets, and notification port program

## Status and authority boundaries

**All kernel implementation workstreams in this document are `not_started`.** Baseline: Linux **6.18.57**, commit `2ff600d29ee478d0a8d46ef8a58afb5e038fe692`. This delivery plans an actual Rust kernel implementation; it does not implement IPC, claim Linux parity, or substitute a userspace broker for kernel semantics. M3 establishes process-facing IPC and notifications, M4 completes VFS/mapping/splice integration, M5 integrates server/container/network workloads, M6–M7 close broader facilities/architectures, and M8 requires complete semantic/security/performance qualification. No obscure IPC mode or lifetime rule is removed to meet an earlier milestone.

Read with [architecture](../architecture.md), [compatibility](../compatibility.md), [verification](../verification.md), [definition of done](../definition-of-done.md), [performance](../performance.md), [bare-metal](../bare-metal.md), [runnable smoke suite](../bare-metal-suite.md), [packaging](../packaging.md), and [dependencies](../dependencies.md). Initial integration uses Arch/CachyOS userspace, **not** downstream CachyOS kernel patches. Measurements use the approved balanced-server profile and pinned upstream Linux reference.

Accepted architecture: **modular monolithic Rust**, fixed upstream 6.18.57 feature scope with explicit reviewed security deltas recorded in [decisions](../decisions.md). Later feature-baseline changes require a separate decision. All in-baseline module functionality must be ported; arbitrary third-party/proprietary out-of-tree modules are additional scope only when separately enumerated and approved. No C/assembly IPC shim is permitted. Unavoidable architecture primitives are supplied by their owner using only reviewed function-local `asm!`/`naked_asm!`, never `global_asm!` or standalone assembly. Differential/security/performance records identify approved security deltas and their expected effects; baseline compatibility is not an excuse to preserve an explicitly corrected vulnerability.

| Sole authority | IPC consumes and integrates |
| --- | --- |
| [Processes](process.md) | Task identity, credentials/capabilities/userns mappings, fd inheritance conventions, signals/pending queues, restart/timeout rules, fork/exec/exit hooks, namespace creation/setns, futex/robust-list/PI implementation and scheduler behavior. POSIX userspace semaphores using shared memory/futex are not a second SysV kernel-semaphore implementation. |
| [Core](core.md) | Waitqueues/wake queues, poll registration, RCU/SRCU, IRQ-safe locks, timekeeping/hrtimers/alarm timers, workqueues and notifier-chain mechanics. This document owns IPC readiness predicates, registration consumers and object lifetime, not a competing wakeup framework. |
| [Memory](memory.md) | Page references/mappings/faults, shmem/hugetlb integration, accounting, pinning and usercopy boundaries. IPC does not implement a parallel VM for shared memory. |
| [Storage](storage.md) and [filesystems](filesystems.md) | Open-file-description ownership, fdtable lookup/reservation/install/close, VFS inode/dentry/mount/open/permission operations, anonymous inode support, poll/epoll/io_uring/splice foundations, tmpfs and filesystem notifications. IPC supplies pipe/FIFO/mqueue/socket-specific operations. |
| [Networking](networking.md) | Socket syscall facade/sockfs, generic sendmsg/recvmsg/cmsg wire representation, skb-like packet storage, netlink and device/transport infrastructure. AF_UNIX semantics and SCM descriptor/credential lifetime are authoritative here; other protocol cmsgs remain owned by their protocols. |
| [Security](security.md) | LSM/audit hooks, credential snapshots, security labels, key notifications and capability policy. IPC must preserve check ordering, namespace ownership and observable denial behavior. |
| [Observability](observability.md) and [virtualization](virtualization.md) | Generic proc/sysfs/fdinfo and trace infrastructure; eventfd consumers such as virtualization/io_uring integrate the same object reference/notification contract, not a private counter clone. |

## Primary source ledger and precedence

Observed primary evidence:

- [I1: baseline IPC build inventory](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/ipc/Makefile) explicitly includes SysV msg/sem/shm, POSIX mqueues, compatibility, sysctls and namespace support. [Namespace implementation](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/ipc/namespace.c) shows initialization rollback, owning userns references, VFS/mqueue races and deferred destruction.
- [I2: pipe implementation](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/fs/pipe.c) documents page ownership/stealing, references for tee, capacity/quotas and read/wakeup behavior. Linux man-pages [pipe(7)](https://man7.org/linux/man-pages/man7/pipe.7.html) and [ipc_namespaces(7)](https://man7.org/linux/man-pages/man7/ipc_namespaces.7.html) supply ABI descriptions.
- [I3: baseline AF_UNIX implementation](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/net/unix/af_unix.c), [ancillary implementation](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/net/core/scm.c), and [socket/cmsg definitions](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/include/linux/socket.h). Linux man-pages [unix(7)](https://man7.org/linux/man-pages/man7/unix.7.html) describes pathname/abstract sockets and descriptor/credential passing.
- [I4: baseline mqueue implementation](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/ipc/mqueue.c) explicitly documents acquire/release publication of direct waiter handoff, priority trees and signal/netlink notification lifetime. Linux man-pages [mq_overview(7)](https://man7.org/linux/man-pages/man7/mq_overview.7.html) describes Linux fd/priority/persistence/namespace behavior.
- [I5: baseline eventfd implementation](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/fs/eventfd.c) and Linux man-pages [eventfd(2)](https://man7.org/linux/man-pages/man2/eventfd.2.html), [signalfd(2)](https://man7.org/linux/man-pages/man2/signalfd.2.html), and [timerfd_create(2)](https://man7.org/linux/man-pages/man2/timerfd_create.2.html).
- [I6: SysV shared-memory control](https://man7.org/linux/man-pages/man2/shmctl.2.html), [SysV semaphore operations](https://man7.org/linux/man-pages/man2/semop.2.html), and [SysV message operations](https://man7.org/linux/man-pages/man2/msgop.2.html), authored by the Linux man-pages project.
- [I7: baseline notifier contracts](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/include/linux/notifier.h) distinguish atomic/blocking/raw/SRCU chains. [General notification/watch queues](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/core-api/watch_queue.rst) document notification pipes, loss records and subscription ownership.

**Precedence caveat:** man-pages HTML is a mutable documentation project, not a pinned 6.18.57 implementation transcript. Where it is historical/incomplete, baseline UAPI/source/configuration and controlled differential evidence win. Two observed examples matter: `unix(7)` says AF_UNIX lacks OOB support, but I3 implements optional stream OOB under `CONFIG_AF_UNIX_OOB`; `eventfd(2)` describes short writes but I5 explicitly rejects **any write size other than eight bytes**. Preserve these baseline distinctions, never blindly implement the convenient prose.

All Rust object/type/layout/optimization choices below are **proposed design**, not observed code or measured gains. Candidate crates are not approved dependencies or claims of compatibility.

## 1. Shared lifecycle, wait/readiness, and ABI infrastructure

### Ordered port and invariants

1. Inventory every raw syscall and architecture/compat variant, operation/flag/control command, proc/sysctl/fdinfo view and configuration-dependent error. Include legacy multiplexed IPC/socket entry points where the baseline architecture exposes them; libc wrappers do not necessarily map one-to-one to syscall names.
2. Consume one VFS open-file-description/fdtable implementation. Define IPC objects independently from descriptor numbers, task IDs and namespace lookup keys. Separate a live object reference from public name/ID availability and from an in-flight operation reference.
3. Implement operation-specific read/write/queue predicates, under their real lock/publication protocol. Register a waiter before the final predicate check, publish data before wakeup, and recheck after waking. A readiness notification is advisory and may race another consumer; it is not a promise the subsequent syscall cannot block.
4. Integrate core wake queues/poll and process signal/restart/timeout cancellation. Define for each operation the commit point, visible partial result, usercopy-fault outcome, interrupted/error precedence, waiter unlink path and object-destruction interlock. Do not impose one generic “all errors roll everything back” rule on Linux APIs with committed partial state.
5. Integrate namespace/uid/memcg/rlimit accounting and security/audit. Reserve charges before allocation where required and release once on all failed/abandoned paths. Keep object data/padding initialized before copy-out.
6. Connect fork/clone/exec/exit, fd passing, procfs and cgroup changes; then stress destruction while poll/asynchronous users hold references. Use RAII only where destruction context is legal: final reference release in IRQ/atomic context may need deferred destruction, not a sleeping `Drop`.

### Reuse, consolidation, and safe simplification

Use shared uaccess/iov cursors, fd reservation guards, page owners, timer/waiter registrations, namespace ID allocators and accounting transactions. Typed namespace IDs, operation states and owned waiter registrations can remove C-style unchecked casts and cleanup labels without removing Linux's observable commit points. Rust `Arc`/`Weak` alone is not a solution to all IPC graphs: fd passing can create semantically required cycles. A universal async channel API is not a drop-in pipe, SysV queue, signal queue or semaphore.

Crate decisions: the kernel's own no_std synchronization/MM/fd primitives are primary. [heapless](https://raw.githubusercontent.com/rust-embedded/heapless/main/README.md) is a candidate only for demonstrably bounded scratch (for example a protocol-bounded ancillary descriptor list), not for lowering runtime-configurable queue capacities. Userspace `std::sync`, Tokio channels, IPC brokers and libc/nix syscall wrappers cannot implement the kernel services they call. They may be external test clients. Any wire-layout helper must pass the [dependency policy](../dependencies.md); generic serialization is not Linux ABI encoding.

### Threats, optimization, and gates

Main threats are lost wakeups, stale fd/ID reuse, namespace confusion, usercopy faults while holding atomic locks, counter overflow, refcount resurrection, callback recursion and cancellation/teardown UAF. Candidate optimizations: per-object rather than global locks, wake only necessary waiters, avoid allocations on uncontended small operations, batch deferred wakeups and use zero-copy only where the API permits ownership sharing. Preserve fairness/ordering/visibility and exact charge accounting.

Completion requires schedule-controlled race/model tests of publish–wait–wake–cancel–free, syscall byte/errno/partial-state differential tests, allocation/usercopy failure at each step, lock-order and leak/accounting checks, and fork/exec/exit/setns/credential-change stress. Exercise poll/select/epoll level/edge/oneshot/exclusive and async completion combinations where baseline supports them; do not give a non-pollable SysV object a fictional fd ABI. Physical SMP/NUMA and supported weak-memory architectures must test publication, not only x86 QEMU. Physical NIC requirements apply to consumers involving socket/splice/eventfd completions; pure SysV IPC has no NIC dependency, and no fake NIC gate substitutes for CPU/MM testing.

## 2. Anonymous pipes, FIFOs, packet mode, and splice ownership

### Ordered implementation

1. Port anonymous pipe creation (`pipe`/`pipe2`), dual endpoint fd installation and error cleanup using VFS references. Model reader/writer counts separately from total files and in-flight references; duplicate/forked/in-flight references affect EOF and SIGPIPE.
2. Port page-backed ring slots, read/write/vector operations, short I/O, wake rules, `PIPE_BUF` atomicity, nonblock and signal behavior, ioctl/fcntl/fdinfo and quota/capacity policy.
3. Integrate FIFO inode creation/open rendezvous, `O_NONBLOCK`, Linux read-write opens, permissions and unlink/reopen lifetime. Pathname persistence is not persistent queued data: FIFO data is an in-memory pipe service, not disk writes.
4. Port `O_DIRECT` pipe packet mode and supported runtime mode changes, preserving packet splitting and truncated-read discard rules; it is not disk direct-I/O. Add notification-pipe mode separately (section 9).
5. Connect splice/tee/vmsplice/sendfile/socket paths, page confirmation/release/get/steal operations, pipe resize and teardown. Migrate all users, including watch queues, to checked per-slot ownership flags before sharing pages.

### Linux traps and retained boundaries

I2 and `pipe(7)` establish byte-stream behavior, EOF only when all writers are gone, `SIGPIPE`/`EPIPE` when readers are gone, no seek, atomic writes through `PIPE_BUF` and different small/large blocking/nonblocking semantics. Preserve exact partial-write behavior on signals/faults and the distinction between free bytes and available ring slots; page fragmentation can make capacity smaller than a byte-count estimate. A zero-length read succeeds without waiting. FIFO writer open without readers, reader/writer rendezvous, pending signals and poll hangup across writer generations need reference-specific tests; do not equate one closed writer with permanent EOF for a named FIFO.

`F_GETPIPE_SZ/F_SETPIPE_SZ`, per-user soft/hard page limits, privilege rules, page-size-dependent defaults, rounding, busy-shrink rejection and accounting-before-allocation races are ABI. Pipe packet mode and watch-queue packet records are different modes. Shared file-cache pages must never inherit anonymous writable/mergeable flags: a page brought in through splice cannot become silently writable through a later pipe merge.

### Crates, bundling, simplification, and performance

No Rust queue/channel crate supplies Linux pipe VFS/splice semantics. Use shared VFS fd transactions, MM pages and wait infrastructure. One typed `PipeSlot` storage class can share anonymous/file/pinned/watch storage safely while making writable/mergeable/stealable permissions explicit. Separate FIFO open policy from the shared pipe data engine. This is a behavior-preserving simplification; replacing the page ring with a copied byte deque and dropping splice is not.

Reuse cached anonymous pages, move page references for splice, clone references for tee, batch wakeups, and avoid copying metadata per byte. **Zero-copy is conditional:** a page may be stolen only with exclusive ownership and compatible accounting/mapping state; vmsplice lifetime, COW, file invalidation, network TX completion and errors must remain valid. Never skip validation or make a file page writable to win a benchmark.

### Threats and completion gates

Threats: page-cache corruption through stale slot flags, pin/pipe quota exhaustion, ring-index wrap, stolen-page UAF, lock-order inversion in pipe-to-pipe splice, hidden writer references preventing EOF, and callbacks from notification producers after close. Differential tests must cover `PIPE_BUF-1`, `PIPE_BUF`, `PIPE_BUF+1`, capacity boundaries/resize, concurrent writers and readers, nonblock/zero lengths, EINTR/restart, packet mode, FIFO open/unlink/reopen, copy faults at page boundaries, fd exhaustion and all page ownership transitions. Run pipe/splice/vmsplice/tee upstream/LTP regression cases, jobserver/pipeline workloads, memory pressure and repeated close/ring reuse.

Physical tests: same/remote NUMA-node pipelines and CPU migration, supported page sizes/weak-memory platforms, file→pipe→physical TCP/TLS NIC transfers with SG on/off, truncation/invalidation concurrent with sends, NIC reset and teardown before completion. Pure FIFO conformance does not need a NIC, but claiming end-to-end zero-copy network transfer does. Measure small token round-trip tails, bulk throughput, CPU, resident/pinned memory, page churn, process startup/pipeline setup and power against matched Linux.

## 3. AF_UNIX endpoint semantics and ancillary transfer

### Endpoint port order

1. Consume networking's socket facade/packet ownership and VFS sockfs. Port unnamed `socketpair`, stream/datagram/seqpacket endpoints, bind/connect/listen/accept/shutdown and endpoint state/refcounts.
2. Implement pathname binding/lookup/permissions/inode identity and abstract/autobind names. Pathnames use filesystem/mount resolution; abstract names are length-delimited bytes and netns-scoped, not NUL-terminated paths or filesystem permission objects. Keep shared VFS references when names are unlinked or processes change mount/net namespace.
3. Implement reliable local datagram message boundaries and stream/seqpacket queues, backpressure, sender/peer address/error semantics, peek offsets, OOB support when configured, readiness/ioctl/diagnostics and splice/read actors.
4. Implement ancillary parsing, in-flight file/credential/security/PIDFD ownership and receive installation (below), then cyclic garbage collection (section 4), before declaring descriptor passing functional.
5. Connect LSM/cgroup/namespace rules and every close/exit/rebind/listener/embryonic-connection cancellation path; stress concurrent send/connect/accept/close/GC.

### Endpoint compatibility traps

Preserve pathname directory write/search and socket permission checks, umask, returned address lengths including unterminated/full-length paths, abstract embedded NUL bytes, autobind behavior, stale pathname sockets and exact bind/connect error ordering. `SO_PEERCRED` is a connection/listen/socketpair-time snapshot as baseline defines, not dynamically reading peer's current credentials. `SO_PASSCRED` per-message credentials are a different interface. Preserve per-type `SO_SNDBUF/SO_RCVBUF` effects, datagram queue limits, `MSG_PEEK/TRUNC/WAITALL`, zero-length datagrams versus stream EOF, stream cmsg barriers/coalescing, half-close, SIGPIPE and pending data/error readiness.

I3 implements configurable stream urgent/OOB behavior, including `MSG_OOB`, SIGURG, `EPOLLPRI` and `SIOCATMARK`. Test both enabled and disabled configurations and type-specific rejection; do not carry forward the obsolete universal “AF_UNIX has no OOB” statement from mutable man-pages. New baseline socket controls such as SCM-rights admission and PIDFD/security options require explicit UAPI/source inventory, not only the old common subset.

### Ancillary port order and commit semantics

1. Copy/validate native and compat `cmsghdr` chains with checked length/alignment/overflow and user iov/control bounds. Preserve level/type-specific validation, unknown cmsg behavior, duplicate controls, truncated headers/data and cmsg packing. Avoid reinterpret-casting unaligned user bytes as Rust references.
2. On send, resolve fd numbers to held **open file descriptions**, validate each allowed object/type, and charge in-flight references to the correct sender identity. I3's `scm.c` rejects io_uring files for SCM_RIGHTS at this baseline; do not “simplify” to universal fd passing. Enforce `SCM_MAX_FD`, rlimits/in-flight limits and LSM checks; clean up every acquired file/pid/user reference on parse failure.
3. Snapshot/validate `SCM_CREDENTIALS` with process-owned namespace mapping and capability checks (`pid`, real/effective/saved IDs as baseline allows), preserve `SO_PASSCRED` synthesis and peer snapshots, and hold PID identity rather than only reusable numeric PID. Integrate SCM_SECURITY/`SO_PASSSEC` through security-owned labels and SCM_PIDFD/`SO_PASSPIDFD`/peer-PIDFD behavior through process-owned pidfs/pidfd authority.
4. Attach owned ancillary state to queued message extents. Preserve which stream byte/message carries a control boundary, what `MSG_PEEK` duplicates/retains, datagram/seqpacket truncation behavior and ownership during discarded unread data.
5. On receive, reserve/install fds with the actual baseline per-descriptor commit behavior and `MSG_CMSG_CLOEXEC`. Receiver fd numbers can differ from sender values; offsets/open-file-status flags are shared via the open description, close-on-exec is descriptor-local. If control space/rlimits/faults limit installation, reproduce baseline installed prefix, `MSG_CTRUNC`, cleanup and error behavior. **Do not invent an atomic all-or-nothing multi-fd receive transaction:** I3's loop installs one fd at a time and can stop after a prefix.
6. Release unused/undeliverable ancillary references, credentials and security contexts exactly once. A release may make a previously rooted socket graph collectible; synchronize with GC and epoll/async references rather than relying on a destructor's lexical scope.

### Reuse, safe simplification, threats, and performance

No userspace Unix-socket/IPC crate implements these kernel semantics. Reuse a shared checked cmsg cursor, VFS fd reservation guard and networking packet owners; `heapless` is only a bounded scratch candidate where the protocol's real upper bound permits it. Typed `PassedFile`, `CredentialSnapshot`, `PidIdentity` and security-label references simplify bookkeeping without flattening controls into bytes or cloning file contents. Consolidate native/compat logic around common semantic operations while retaining separate exact packing/copyout behavior.

Threats include descriptor/credential smuggling, PID reuse, namespace mapping confusion, ancillary integer overflow, privilege changes during queued-message lifetime, hidden GC roots, in-flight file-limit bypass, LSM ordering errors and uninitialized padding leakage. Reduce payload copies using shared immutable packet extents, amortize ancillary list allocations within actual bounds and defer wakeups outside queue locks; do not use weak references for passed open descriptions that must remain alive.

### Completion gates

Raw syscall/reference cases for every socket type/name style/cmsg flag/length: multiple fd objects, repeated descriptors, shared offsets/status flags, descriptor-local CLOEXEC, `MSG_CMSG_CLOEXEC`, zero-data control messages as each type permits, stream control barriers, credentials before/after setuid/exec/setns, SCM_SECURITY/PIDFD, vanished/recycled PIDs, no cmsg buffer/short buffers, peeking, rlimit/fdtable exhaustion, io_uring rejection and copy faults during a partially installed fd list. Include listeners whose connecting peer exits before accept, close with unread rights, pathname unlink/recreate and abstract-netns separation. Compare messages, error precedence, installed descriptors, fdinfo/proc views, leaks and security decisions.

Physical gates: cross-core/NUMA local messaging and GC races on real SMP, supported weak-memory CPUs, physical file/NIC/eventfd objects passed then used after sender exit/namespace change, driver reset while receiver holds the passed description, and external Arch/CachyOS service workloads. Measure per-size/ancillary-count round-trip tails, throughput, CPU, memory/in-flight references, startup/socketpair and power; local sockets have no wire-offload requirement by themselves, but passed network endpoints must meet networking's physical gates.

## 4. UNIX descriptor graph garbage collection and lifetime closure

### Ordered implementation

1. Inventory all graph edges and roots: fdtable/open-description references, in-flight SCM_RIGHTS including UNIX sockets, queued messages, listeners/embryonic peers, epoll and asynchronous holds, kernel users and pending destructors. Ordinary strong references can intentionally form cycles through socket queues.
2. Port the pinned GC algorithm and in-flight accounting from the exact baseline, including locking/RCU and graph update timing. Separate candidate discovery from claiming an edge unreachable; hold references to every graph object examined.
3. Integrate send/peek/receive/discard/close/listener teardown and allocation failure with graph mutation. Define graph epoch/lock ordering and publication points with endpoint locks and fd installation; no concurrent mutation may manufacture a freeable live root.
4. Implement deferred destruction in a context allowed to drop files/credentials/pages and trigger nested releases; remove stale graph metadata and charges exactly once. Add instrumentation only through normal debug facilities, not permanent hot-path allocation/logging.

### Reuse, simplification, and optimization

Default is a direct Rust port, not a generic cycle-collecting crate. `Arc`/`Weak`, tracing-GC crates or “never pass sockets” would change semantics or fail kernel allocation/context requirements. Share VFS reference and RCU primitives; typed edge records and arena/index generations may simplify unsafe links only after preserving the algorithm's root/liveness proof. Do not infer collectibility merely because Rust strong counts are equal to the number of visible fdtable entries.

Candidate improvements are incremental graph accounting, avoiding full scans when no potentially cyclic UNIX rights exist, compact per-message edge arrays and minimizing lock hold times; each needs semantic/lifetime proof and matched stress measurement. Garbage collector throughput alone cannot hide extra memory retention or stalled send latency.

### Threats and gates

Threats: reference cycles leaking unbounded kernel memory, collecting a live socket while an SCM receive/peek installs a new root, listener/embryonic graph mistakes, double-release, recursive file release deadlock and stale edge pointers. Completion requires generated cyclic graphs (self-loops, two-node cycles, long strongly connected components, rooted/unrooted transitions, nested passed epoll/other allowed objects), concurrency with `MSG_PEEK`, receive installation faults, fork/exit and listener destruction. Verify surviving endpoints remain usable and unreachable charges return to baseline after allowed grace periods. Test allocation failure/pressure, repeated ID reuse and long-running churn on physical SMP/NUMA; passing a physical NIC fd into a collectible graph must neither leak the driver object forever nor tear it down while independently rooted. Measure maximum retained memory, GC work, send/receive tail stalls, CPU and recovery time.

## 5. System V IPC common IDs, permissions, and namespace lifecycle

### Ordered port

1. Port IPC namespace creation/reference/owning-userns and ID/key lookup machinery, ID generation/sequence rules, `IPC_PRIVATE`, create/exclusive flags, permission structures and LSM/audit hooks.
2. Port shared stat/set/info/stat-any/proc/sysctl/compat encoders with exact layouts and privilege/error order. Preserve internal index versus public generated ID distinctions and checkpoint/restore controls where configured.
3. Integrate object-specific destruction/waiter wakeups and deferred reclaim. Follow I1's partial namespace-initialization rollback, mqueue mount/refcount race and RCU-delayed destruction; do not free everything immediately when the last observed task leaves while mounts/fds/namespaces still hold valid references.
4. Implement shm, sem and msg families below and process clone/unshare/setns/exit hooks as one audited namespace integration.

**Reuse/consolidation:** use one typed namespace ID allocator, common checked permission/stat copying, security hooks and accounting. No general-purpose IPC/channel crate supplies key/ID/sysctl/Linux ABI. Internal generational handles simplify stale-ID checks without changing the visible generated-number/sequence behavior. Shared cleanup utilities cannot erase each family's distinct `IPC_RMID` semantics.

**Threat/performance:** ID reuse/sequence wrap, capability checks in the wrong userns, `/proc/sysvipc` leaks, namespace create/destroy exhaustion, error rollback and table-lock contention. Read-mostly lookups with RCU and per-object locks are candidates; map capacity cannot be a tiny compile-time embedded limit. Gate creation/lookup/remove races with stale IDs, all permission/userns/capability combinations, stat-any/info enumeration, namespace crossing, mount-held references, fault injection and sysctl limit changes. Physical SMP/NUMA churn and weak-memory publication are required; no NIC/offload operation is inherent in SysV common IDs.

## 6. System V shared memory

### Ordered port and behavior

1. Port `shmget` creation/lookup, sizing/page rounding, flags/limits/accounting and shmem or hugetlb backing via memory/filesystem owners. Include supported `SHM_HUGETLB` size/permission/noreserve options; do not treat all segments as eagerly allocated contiguous memory.
2. Port `shmat/shmdt`, requested addresses/`SHM_RND/REMAP/RDONLY/EXEC`, VM permissions, attach counts and metadata/times/PIDs. Integrate fork inheritance and exec/exit detach through process-owned VM lifecycle.
3. Port `shmctl` permission/stat/set/info/stat-any, `SHM_LOCK/UNLOCK` and memory-lock accounting, `IPC_RMID`, `SHM_DEST`, forced-RMID policy and namespace destruction.
4. Exercise fault, swap/reclaim, COW-related VM interactions, huge pages and final detach under concurrent removal and ID reuse.

I6 explicitly separates **marking for removal** from physical destruction after last detach. Linux permits attaching a marked segment in circumstances implemented by the baseline; preserve Linux behavior rather than applying a stricter portable interpretation. Namespace/name/ID disappearance, backing memory and existing mappings are separate lifetimes. `shm_nattch`, last-operation PID and stat-any/index results are observable; no inventing a convenience “close fd destroys shm” API.

### Reuse, simplification, threats, optimization, and done

No off-the-shelf shared-memory Rust userspace crate implements VM/syscall semantics. Consume shmem/hugetlb/VMA/page owners and common SysV permissions/ID machinery. One typed backing variant and attach guard may replace duplicated pointer handling without dropping hugepage, read-only/execute/remap or deferred-remove modes. POSIX shm and memfd are filesystem/memory interfaces, not aliases for SysV `shmget`; link their authority rather than force a new common public API.

Threats: arbitrary attach/remap overwrites, unauthorized executable/shared mappings, uninitialized page exposure, attach-count/accounting races, namespace teardown UAF and memory-lock/hugepage exhaustion. Proposed performance work is shared zero-copy mappings, lazy fault/reclaim and NUMA placement, not copying data at attach or disabling security. Page-fault/THP/hugepage policy must stay baseline-compatible.

Done requires raw-syscall/compat structure and errno tests, all attach flags/addresses, fork/exec/exit, RMID-before/after attach and final detach, lock/unlock limits, permission/userns changes, stat/info/proc views, swap/reclaim/hugetlb and allocation failure. Run PostgreSQL/other SysV-shm consumers as Arch/CachyOS userspace integration alongside adversarial map/rmid loops. Physical SMP/NUMA page migration, TLB shootdown and memory pressure/recovery are mandatory; NIC offload is not applicable unless a consumer registers these pages for DMA, in which case MM/driver pin rules and real device teardown tests also apply. Measure create/attach/startup, fault/steady-state bandwidth and latency, CPU, RSS/swap/locked pages and power against Linux.

## 7. System V semaphore sets

### Ordered port and retained semantics

1. Port `semget/semctl` set creation/lookup, all scalar/array/stat/info commands, permission/limit/stat metadata and common ID/namespace handling.
2. Port `semop` operation-vector validation and **array-order, all-or-nothing** update semantics, wait-for-zero, negative decrement, positive increment, `IPC_NOWAIT`, waiter counts and wake selection.
3. Port `semtimedop`, absolute internal deadline from relative ABI timeout, signal/timeout/remove races and exact non-restart behavior. I6 states interruption leaves the timeout structure unchanged and `semop` is not automatically restarted under `SA_RESTART`.
4. Port `SEM_UNDO` per-task/shared-undo lists, `CLONE_SYSVSEM`, fork/exec/exit integration and `SETVAL/SETALL` clearing adjustments. Follow Linux's clamp-to-zero exit behavior where full negative undo cannot be applied; exit must not wait forever for another task.
5. Integrate concurrent set removal/namespace teardown and failed undo-allocation rollback before exposing success.

### Reuse and simplification

Use common SysV IDs/permission metadata, process exit hooks, timer/waiter primitives and prevalidated operation scratch storage. No userspace semaphore/futex/channel crate replaces atomic **multi-semaphore** operations, zero-waits or SEM_UNDO. Consolidate vector validation with checked duplicate-index operations and typed adjustment records; never decompose one semop vector into separately committed per-element operations. A simpler common set lock is admissible only when observable ordering is retained and the performance gate passes, not as a permanent excuse for global contention.

### Threats, improvements, and gates

Threats: vector/adjustment overflow, duplicate operation mishandling, partial commit on memory failure, undo use-after-free after `IPC_RMID`, namespace/clone ownership confusion, wakeup starvation and attacker-created zero-wait contention. Candidate gains: prevalidate and reserve undo records before commit, avoid work for unaffected waiters, use per-set/per-semaphore synchronization where the baseline atomic-vector semantics can be preserved, batch task wakeups and compact sparse undo entries. Do not bypass Linux limits or replace SysV semaphores with process-private Rust mutexes.

Done gates cover mixed positive/negative/zero and repeated-index vectors, atomic rollback, wait counts/last PID/sem_otime, `IPC_NOWAIT`, timeout/granularity, signal/no-restart, set removal, `SETVAL/SETALL`, undo clone/fork/exec/exit and clamp-to-zero, compat time and allocation-failure cases. Differential LTP/raw-syscall tests plus process-death/namespace stress, model-checked commit/wake/exit interleavings and physical SMP/NUMA contention/weak-memory runs. Measure operations/second and per-vector latency tails, uncontended/contended CPU, undo memory, exit recovery and power; NIC/offload is not an intrinsic semaphore criterion.

## 8. System V message queues and POSIX mqueues

### System V msg

**Ordered port:** (1) `msgget/msgctl` keys/IDs, limits/metadata/permissions; (2) `msgsnd` payload/type copy/accounting/queue/wait and `msgrcv` selection/copy/remove; (3) Linux extensions `MSG_EXCEPT/MSG_COPY/MSG_NOERROR`, configured checkpoint/restore support and compat `long` type layout; (4) sender/receiver direct handoff and wake ordering; (5) IPC_RMID, namespace destruction, cancellation and failed copy paths.

**Semantics:** I6 permits zero-length messages but separately limits message count to prevent unlimited metadata allocation. `msgtyp=0`, positive/excluding, and negative lowest-type selection are not the same as FIFO or priority delivery. `E2BIG` without `MSG_NOERROR` leaves the message queued; truncation with that flag discards the tail. `MSG_COPY` uses ordinal nondestructive lookup, requires NOWAIT and conflicts with EXCEPT. Preserve `ENOMSG` versus `EAGAIN`, permissions, mtype width/sign, non-restarted EINTR, removal wakeup and per-operation commit/fault behavior; do not assume ordinary fd/poll operations exist.

**Reuse/simplify:** common SysV IDs, message payload owner/accounting and checked usercopy, plus mqueue's low-level message storage only where semantics match. No channel crate implements type selection/ID controls. Typed selectors and one validated internal message representation simplify encoding, but cannot merge this API with POSIX priority queues. Avoid alloc/copy when handing an already-owned message to a waiting receiver; never alias mutable user memory as queued payload because `msgsnd` copies it.

**Threat/performance/gates:** hostile type selection, zero-size floods, large type queues/linear scan CPU, usercopy-after-removal and direct-handoff publication races. Test every selection mode/truncation/extension combination, simultaneous waiters/signals/remove, metadata/byte limits, mtype compat/endian, usercopy faults and namespace isolation against Linux. Stress on physical SMP/NUMA and weak-memory platforms. Measure message-size/type-distribution throughput/tails, CPU/scans, kernel memory and wake/exit recovery; pure SysV queues have no physical NIC/offload requirement.

### POSIX mqueues

**Ordered port:** (1) IPC-namespace mqueuefs superblock/inodes, named create/open/unlink and VFS fd operations; (2) priority-indexed FIFO queues within equal priority, attrs/limits/accounting and send/receive; (3) timed send/receive with realtime absolute deadlines and native/time64/compat encodings; (4) poll readiness and direct waiter handoff using I4's release/acquire ordering; (5) `mq_notify` signal/none/thread notification, cancellation and owner exit/exec; (6) mount/namespace lifetime, stat/proc views, security/audit and full destruction.

**Retain:** Linux queue descriptors are file descriptors, opened close-on-exec by default; queue names/unlink and existing open descriptions have separate lifetimes. Forked descriptors share mq_flags. Highest numeric priority is first, equal-priority FIFO; baseline-supported priority range must not be reduced to POSIX's minimum. `mq_receive` buffer requirements differ from SysV truncation. Defaults/limits and `RLIMIT_MSGQUEUE` charge kernel overhead as baseline specifies, while exposed QSIZE is a separate observable metric.

`mq_notify` is one registration with one-shot notification, not a continuous stream of callbacks. Preserve empty→nonempty transition, pending receiver precedence, registration ownership/EBUSY, unregister, rearm and owner/exec effects. I4's `SIGEV_THREAD` kernel path uses a netlink notification cookie; libc/userland creates callback threads. Do not spawn a kernel thread per message or omit this path because it is not SIGEV_SIGNAL. This makes netlink/socket lifetime a genuine M3–M5 dependency; complete signal-only mqueues are not full mqueue completion.

**Reuse/consolidation/simplification:** share namespace/fs/fd references, message storage with SysV where compatible, checked attrs and common waiter/deadline primitives. No async channel/priority-queue crate supplies Linux persistence/notify/waiter semantics. A typed priority index plus FIFO buckets can simplify queue traversal with identical priority and error rules; a fixed-capacity heap must not cap runtime-configurable counts/priorities or change equal-priority order. Direct handoff is a measured optimization that needs I4's publication/lifetime proof, not unchecked references to a sleeping task's stack.

**Threat/performance/gates:** priority/size/rate exhaustion, registration credential/PID reuse, notification-cookie leaks, VFS namespace resurrection, timeout/close race and stale waiter message pointers. Cache queue nodes and share already-kernel-owned payloads; reduce wakeups/lock hold time without missing transitions or altering notifications. Differential full mq_* and raw-syscall/compat tests, names/unlink/recreate, attrs sharing, priority extremes/equal priorities, capacity/rlimit/sysctl changes, timed waits under realtime adjustment, all notification modes and process death. Physical SMP/NUMA, weak memory, scheduler contention and suspend/time-change tests; the netlink notify path must work on bare metal even though no NIC offload is involved. Measure throughput/tails, CPU, queue memory/charges, registration/startup and power. No priority average may hide starvation/tail regressions.

## 9. eventfd, signalfd, timerfd, and notification pipes

### eventfd

**Ordered port:** anonymous-inode/fd creation (`eventfd`/`eventfd2`) → locked counter/read/write/semaphore semantics → poll/wait and kernel signal/get/put APIs → io_uring/AIO/virtualization/network driver consumers → fdinfo, release and recursion-safe wakeup lifetime. I5 shows kernel signal may run in non-sleeping context and can saturate at `u64::MAX`; user writes cannot request that overflow. Ordinary maximum user counter is `u64::MAX-1`.

**Retain:** native-endian eight-byte successful reads (at least eight-byte read buffer), **exactly eight-byte writes** in baseline source, `EFD_SEMAPHORE` read-one decrement versus read-and-zero, nonblock and CLOEXEC distinction, overflow poll error, write readiness, read/reset/wakeup order, fork/SCM sharing and kernel context references after a userspace fd closes. The object is not an unbounded notification log; accumulated counts intentionally coalesce.

**Reuse/simplify/crates:** common anonymous inode, wait and VFS refs; no generic atomic/channel crate can supply fd lifetime/readiness. A counter under the wait lock or a proved equivalent atomic protocol is simpler than an invented scheduler/event subsystem; preserve I5's poll registration/acquire order and recursion guard. Inline the counter, avoid per-event allocations and batch compatible wakeups, without silently losing increments.

**Threat/gates:** lost increments/wakeup, overflow arithmetic, reentrant wake callback deadlock, signaling a freed context and usercopy failure after committed reset. Compare short/long read/write sizes, zero/max/overflow, semaphore mode, concurrent signal/read/write/poll, fd reuse/fork/SCM, fdinfo and final release, plus allocation/usercopy failures. Physical SMP/NUMA and kernel-consumer tests include physical NIC/device completion or virtqueue interrupt signaling where consumed: no DMA/event after teardown. Measure signal/read round-trip tails, wake CPU, memory, idle power and event storms against Linux.

### signalfd

**Ordered port:** consume process-owned pending signals/selection/namespace mapping → `signalfd/signalfd4` create/update masks/flags → read/whole `signalfd_siginfo` records and poll → clone/fork/exec/SCM/epoll lifetime → fdinfo and removal. This is an alternate consumer of existing signal state, **not** a second queue that receives copies of signals independently of handlers/sigwait.

**Retain:** masked SIGKILL/SIGSTOP are silently excluded, signals are consumed once, thread-directed versus shared process signals obey process authority, record fields/padding are initialized, synchronously generated fault signals retain baseline limitations, raw syscall sigset size differs from libc interface. The reading task determines which pending signals are visible even for an fd inherited or passed from another process. I5 documents inherited signalfd/epoll registration behavior after fork: child reads can work while an inherited epoll registration does not notify child signals; do not “fix” compatibility by silently making them global.

**Reuse/simplify/crates:** share process signal dequeue/locking and anonymous inode/waits; no userspace signal crate implements it. Typed mask and signal record conversion simplify ABI encoding; keep 128-byte layout and compat fields exact. Avoid allocating/copying a second queue; batch complete records per read while preserving selection/partial-result semantics.

**Threat/gates:** cross-thread/PID-namespace information leaks, stale mask/update race, duplicate consumption, padding leaks and signal/wait/close deadlock. Differential pending standard/RT signals, mask updates, read buffer boundaries, simultaneous handler/sigwait/signalfd readers, fork/SCM/exec, namespace ID mapping and epoll behavior. Physical SMP signal storms, CPU migration and process exit; no NIC/offload dependency is intrinsic. Measure dequeue/wake latency tails, CPU/record, memory and power without altering signal priority/coalescing.

### timerfd

**Ordered port:** core clock/hrtimer/alarm/time-namespace prerequisites → `timerfd_create/settime/gettime` and supported clock IDs → expiration/read/poll counts → clock-set cancellation, suspend/boottime/alarm semantics → checkpoint/restore tick ioctl where configured, compat/time64 and lifetime.

**Retain:** relative versus absolute arm, disarm and periodic overrun counts, read of accumulated native-endian u64, supported clock/capability checks, monotonic excluding versus boottime including suspend, alarm wake privilege, `TFD_TIMER_CANCEL_ON_SET`/`ECANCELED`, and I5's negative realtime-jump zero-byte-read corner case. `gettime` remaining value is relative even for absolute arming. Preserve settime/disarm/read/copyout commit ordering and timer replacement races; a generic userspace `Instant`/sleep loop is not the kernel clock model.

**Reuse/simplify/crates:** use core-owned timers/clock events and anonymous inode/wait refs, not a second timer wheel or async runtime. Typed clock/deadline/armed states simplify units and cancellation without dropping realtime/alarm/time64 behavior. Lazy overrun calculation and batching may reduce interrupts/locking if reference-compatible tick counts/readiness and latency remain intact; do not change default clock granularity or timer slack to win a benchmark.

**Threat/gates:** expiry counter/time arithmetic overflow, malicious rearm rates, callback after last reference, privileged wake bypass and discontinuity/suspend races. Differential clock/flag/errors and nanosecond/overflow boundaries, concurrent set/read/get/close, signals, fd passing, tick restore, fork/exec, clock changes and namespace offsets. Physical timer/interrupt accuracy, sleep/resume/wake, suspend-unavailable explicit blocks and multiple platforms/clock sources must complement QEMU. No NIC offload criterion for timerfd itself; network timers separately meet networking gates. Measure deadline error/tails, arm/read CPU, memory, wake frequency/startup and idle/load power against Linux with matching tick/clock/power settings.

### Watch queues / notification pipes

**Ordered port:** pipe ring and security key-notify producers → notification pipe allocation and sizing/filter ioctl → watch registration/source/queue references and record encoding → nonblocking posting, meta-loss/meta-removal and read behavior → close/source removal, RCU/deferred release and failed registration rollback.

I7 specifies producers never wait for consumers: no slot/preallocated message buffer leads to lost events and a loss notification, not blocking the kernel on a reader. Splice and related operations are disabled for these pipes because rollback would interleave with producer records. Preserve source/watch IDs, filters, record lengths, registration authorization and source-close/queue-close ordering. Do not turn them into ordinary byte pipes, promise lossless delivery, or silently drop the required loss record.

**Reuse/simplify:** use the shared pipe storage engine with explicit nonmergeable notification slot type and core RCU/security-owned key sources. No general event-bus crate supplies this ABI. Typed watch registration guards simplify teardown while retaining source-specific removal callbacks and LSM filtering per queue. Preallocate producer storage and avoid copies/allocations in atomic posting; do not remove memory bounds.

**Threat/gates:** key/security event leaks, filter length arithmetic, producer UAF after watch removal, full-ring bookkeeping, record boundary loss and posted-after-close races. Differential key notification/filter/loss/removal tests, queue full/resize, multiple producers/watchers, source death, usercopy faults and restricted splice errors. Physical SMP/weak-memory stress and security source churn; no inherent physical NIC/offload dependency. Measure notification latency/tails, producer CPU, memory bounds and lost-event reporting under matched load.

## 10. Kernel notifier integration, not a new public IPC ABI

**Ordered port:** consume core's distinct atomic/blocking/raw/SRCU notifier implementations → list all IPC/netdevice/key/timekeeping consumers and callback context restrictions → typed registration lifetime and callback payload validity → priority/stop/error/robust rollback behavior → synchronized unregister and destroy.

I7 requires atomic callbacks not to block; blocking/SRCU registrations use process context; raw chains put protection on the caller; unregister from within the same chain is prohibited for the specified chain types. Callback priority and stop-mask semantics matter. Robust notifications may unwind a completed prefix in reverse semantic operation; a generic broadcast channel that always invokes every subscriber is not equivalent. No stable internal C module ABI is promised, but user-visible effect order, teardown safety and driver integration must remain correct.

**Reuse/crates/consolidation:** core's one notifier implementation, RCU/SRCU and context tokens. Reject userspace observer/event-bus crates as replacements. Typed payload views scoped to callback lifetime and registration guards can replace raw `void*` casts; avoid heap-boxing every event/callback. One shared mechanism may serve all subsystems while preserving chain classes and specific ordering. Queueing all callbacks asynchronously would be a behavior change, not simplification.

**Threat/performance:** dangling callback target, reentrancy/self-unregister deadlock, sleeping in IRQ/atomic context, lock inversion, misordered veto/rollback and exposed stack references surviving notification. Favor cheap read-mostly traversal and registration-time allocation, but honor grace periods before freeing. Completion requires callback priority/stop/error/rollback cases, unregister racing every callsite, forbidden-context assertions, allocation failure and teardown stress. Physical device/netns/CPU hotplug/timekeeping and driver reset integrations must exercise actual callback contexts; physical NIC notifier order must agree with network device teardown and no callback may access unmapped DMA. Measure callback latency/CPU and long unregister tails under matched update/call rates.

## 11. Conformance and performance matrix

Every workstream needs a record for **all applicable cells**, not one global “IPC tests pass” flag:

| Dimension | Required cases/evidence |
| --- | --- |
| ABI and configuration | Native/compat32/time64, supported endian/page-size/architecture layouts; correct disabled/config-dependent errors; raw syscalls and Arch/CachyOS libc/userspace entry points; lengths, zero counts, boundary values, invalid flags, unknown commands and copy faults. |
| References | fd lookup/dup/close/fork/exec/SCM/async, namespace IDs versus references, last-reference and partially initialized destruction, fd/ID/PID recycling and cyclic graphs. |
| Contention and scheduling | One/many producers/consumers, priority/waiter order, blocked/nonblock, signal/restart, timeout/suspend/clock change, CPU migration/hotplug and publish–wait–wake adversarial schedules. |
| Limits/security | Userns/IPC/net/mount/PID namespaces as appropriate, capabilities/LSM/audit, credentials changing after creation/send, rlimits/sysctls/memcg, low memory/allocation faults, hugepages/swap/pins, no uninitialized padding. |
| Integration | Pipe/FIFO pipelines/jobserver, SCM service managers, database shared memory/semaphore/message consumers, mq notification libc handshake, eventfd device/async users, signalfd service loops and timerfd reactor loops. Correct cmsg/syscall ABI is not inferred from one application's happy path. |
| Physical and recovery | Current workstation initially under operator-controlled candidate boot and preserved recovery; then required SMP/NUMA/weak-memory/clock/suspend/device matrices. Real NIC/SG/offload/reset evidence only for pipe/socket/DMA completion consumers, not irrelevant requirements invented for pure SysV objects. Unavailable hardware remains blocked. |
| Performance | Matched pinned Linux and candidate, balanced-server settings/security/mitigations/firmware/compiler/topology, multiple repetitions/confidence intervals and noise controls. Per-case throughput, latency/tails, CPU, allocated/resident/locked memory, create/attach/startup/exit recovery and power. No mean-only summary or unproven non-inferiority passes; every declared case must meet at-least-baseline Linux. |

Reuse existing external Linux kselftests/LTP/regression workloads and preserve their assertions; external non-Rust suites are permitted. A Rust-native race/fault harness must cover gaps, including GC/SCM and precise copy-fault commit semantics. Track exact external test revisions, kernel/config/boot artifact identities, commands, cases, expected/actual status, seeds, platform settings and result artifacts. No skipped test or inaccessible physical mode is a pass. Future test programs/tools owned by this project are Rust; no project-owned shell/Python runner is introduced to dodge that rule.

## 12. Exhaustive definition of done

For **each** numbered section and subfamily, done means the conjunction of:

1. Every pinned path, syscall variant, ABI layout, flag, control operation, notification source and config-dependent behavior has a disposition and implementation/test owner. All callers, tests and user documentation are migrated; no dead compatibility shim or fake success remains.
2. Actual Rust kernel implementation exists, uses approved no_std/context-aware allocation and shared authorities, preserves source licensing/provenance, and contains no hidden C-backed IPC implementation or userspace broker. Rust dependency claims have been audited rather than inferred from crate names.
3. Operation state/commit/rollback rules reproduce baseline values, errno, partial results, copy-fault effects, permissions/check ordering, signal/restart/timeout behavior, message/control boundaries, proc/sysctl/fdinfo views and lifecycle. All intentional deviations need explicit compatibility approval, not narrowed tests.
4. Every creation/failure/lookup/dup/send/wait/poll/consume/cancel/fork/exec/exit/remove/last-reference path and race is exercised, including namespaces, cyclic graphs and deferred/atomic destruction. Charges, file/pid/label/page references and wait/notify registrations eventually release correctly; memory safety and ownership invariants have evidence beyond compilation.
5. Differential, regression, adversarial, stress, model/property and recovery tests cover the above matrix against pinned Linux and actual userspace. Failure cases test failed operations' remaining state, not just errno. Exact executed evidence is retained, and failures/skips/unavailable/inconclusive results are disclosed.
6. Physical co-development begins with user-operated boot on the current workstation alongside QEMU; required additional hardware and safe lab cases are named blockers until available. Relevant MM/interrupt/clock/NIC/DMA/offload/suspend interactions are tested on actual hardware. VM/host-runner evidence never certifies a different kernel or missing hardware.
7. Every declared workload/hardware cell meets at least pinned Linux performance under the matched statistical protocol, with semantic/security assertions enabled. Faster happy-path message throughput cannot excuse slower tails, larger retained memory, broken fairness or worse power elsewhere; inconclusive results do not qualify.
8. Reproducible test/recovery instructions, maintenance/CVE regression ownership and [project-wide standing definition of done](../definition-of-done.md) are satisfied. Only qualified configurations may be labeled supported; plan/setup completion is never called kernel completion.

## 13. Actual runnable smoke versus future full qualification

The project's dependency-free Rust [bare-metal smoke suite](../bare-metal-suite.md) is the actual runnable setup deliverable:

```text
cargo run -p baremetal -- run --output <new-directory> --label <label> --expect-release <exact-osrelease> --environment <reference|qemu|bare-metal>
```

Its bounded memory/thread, sandbox filesystem, TCP/UDP/UNIX loopback, process and proc/sysfs cases are useful initial smoke. New output directories prevent evidence overwrite; exact release validation prevents casually labeling a reference run as a candidate. The environment label is operator-provided, not independent proof of bare metal. It never mounts, changes system settings/network namespaces, elevates, reboots, installs kernels, raw-writes devices or updates firmware by default. On current reference Linux it validates the runner and that environment only.

**Not provided by basic loopback smoke:** SCM_RIGHTS/security/PIDFD/GC conformance, SysV/mqueue semantics, pipe splice/page ownership, full notifier/clock behavior, privileged namespace/LSM failures, physical NIC/offloads, kernel fault injection, full-architecture parity or at-least-Linux performance proof. All those remain explicit qualification obligations above, not inferred passes. Historical planning evidence: the original plan author ran no build/test/lint/formatter/kernel or physical gates; smoke/audit execution belonged to the integration owner. That history does not describe the later kernel implementation record.

Only the current workstation is available. The user will personally install/select/boot a future Linux-userspace-capable candidate via the applicable [packaging](../packaging.md) path, preserving the existing working kernel and recovery. The current [bootstrap](../implementation.md) does not implement IPC or the Linux userspace environment needed for this suite. No host install/boot/reboot action is authorized by these instructions. Additional platforms/NUMA devices/timing and isolated NIC peers remain named missing prerequisites, not assumed resources. IPC implementation workstreams remain `not_started`; reference smoke and early kernel self-tests do not change that status.
