# Bounded Linux host/guest functional smoke suite

`baremetal` is an actual dependency-free, safe-Rust userspace executable, not a kernel, boot image, hardware certification tool or replacement for Linux's suites. It runs on installed Linux or a Linux-compatible guest, and can run on a future user-booted candidate once its userspace ABI exists. A separate real Rust `no_std` bootstrap now exists with bounded [revision-specific evidence](implementation.md), but it cannot execute this userspace suite. The current [routed kernel workstreams](implementation.md#routed-implementation-status) are `in_progress`; neither those routes nor this tool establish M1/full-Linux or physical qualification.

The currently observed workstation release is `7.2.10-1-cachyos`. A run on that release checks this runner and that installed Linux environment; it does **not** establish compatibility with the pinned Linux `6.18.57` oracle and does not test a Rust kernel. `--environment` is an explicit operator assertion, never automatic VM/bare-metal detection or attestation. The current workstation is the only available physical machine; missing additional platforms remain blockers under the [physical-machine plan](bare-metal.md).

## Build and dry CLI behavior

Use the existing Rust installation; do not change the global toolchain. The host workspace MSRV is 1.88, separate from the kernel manifest's 1.101 and exact-nightly runtime pin. A host minimum-version gate selects `baremetal`/`xtask`, not the kernel; the nightly historical runs below do not prove 1.88 execution. From the repository root on Arch/CachyOS:

```console
cargo build --offline --release -p baremetal
./target/release/baremetal --help
./target/release/baremetal run --help
```

There are no third-party crate dependencies, native build scripts, downloaded test payloads, or `unsafe` blocks. The Rust standard library and Linux userspace runtime are still prerequisites. The default `x86_64-unknown-linux-gnu` build requires the matching ELF interpreter and compatible **glibc** shared libraries on the target (Arch's `glibc` package), along with the required syscall ABI. A copied executable does not supply libc, a root filesystem, firmware, or a bootable kernel. Architecture, dynamic-loader/libc versions, and supported ISA must match the destination. Offline compilation still requires an already-installed Rust toolchain and its target standard library; it does not install missing components.

Help exits zero without reading procfs, creating directories, opening sockets, or running cases. No arguments, unknown arguments, missing or duplicate options, invalid labels, invalid environments, non-UTF-8 values, and control characters in option text are rejected with a diagnostic and exit `2`. Option order is flexible, but all four options are required exactly once:

```text
baremetal run --output <new-directory> --label <label> --expect-release <exact-osrelease> --environment <reference|qemu|bare-metal>
```

Labels contain 1–80 ASCII letters/digits/dot/underscore/hyphen, beginning with a letter or digit. They are metadata only and never interpolated into report filenames. Output paths must be UTF-8, at most 4096 bytes, contain no control characters or `..` components, and end in a normal directory component. Labels and releases cannot inject TSV rows. Internal `--internal-case` and `--internal-exec` modes implement child isolation and exec/wait checks; they are not supported operator interfaces and are not qualification shortcuts.

## Run on the current installed Linux

Run as the normal workstation user, **without sudo/root**. The runner refuses effective UID 0, established from `/proc/self/status`. Choose a trusted, already-existing output parent outside the repository; do not put evidence in a shared attacker-writable directory. The example creates only that user-owned report parent, not a suite output directory:

```console
mkdir -p "$HOME/linux-rs-reports"
cargo run --offline --release -p baremetal -- run --output "$HOME/linux-rs-reports/reference-7.2.10-01" --label workstation-reference-01 --expect-release 7.2.10-1-cachyos --environment reference
```

Use the release you **intend** to test. If the running system changes, explicitly review its `/proc/sys/kernel/osrelease` and update your intended exact release rather than blindly substituting a command's output and defeating the wrong-kernel guard. The runner reads that procfs file and rejects a mismatch **before tests and before creating any output**. For the eventual pinned oracle, boot the independently established `6.18.57` reference kernel and pass its exact configured `osrelease`, including any deliberately configured local suffix. A label saying `reference` does not establish that provenance.

A second run with the same output path fails, even if the existing directory is empty. An existing regular file or symlink is also refused. Nothing is overwritten. Refusal examples (each command must be inspected as an expected nonzero result, not chained as a successful test):

```console
./target/release/baremetal run --output "$HOME/linux-rs-reports/wrong-release-must-not-exist" --label wrong-release --expect-release definitely-not-the-running-release --environment reference
./target/release/baremetal run --output "$HOME/linux-rs-reports/reference-7.2.10-01" --label reuse-refused --expect-release 7.2.10-1-cachyos --environment reference
./target/release/baremetal run --output "$HOME/linux-rs-reports/invalid-cli-must-not-exist" --label bad/label --expect-release 7.2.10-1-cachyos --environment reference
```

The first and third commands must leave their proposed outputs absent. The second assumes the preceding successful run created that exact output; it must retain every existing byte. A wrong-release refusal exits `1`; malformed CLI exits `2`. Filesystem/permission/resource errors also exit `1` and must not be reclassified as a test pass. Meaningful permanent unit tests cover CLI completeness/duplicates, control/path rejection, TSV escaping, dry help parsing, and invalid internal cases; they are not kernel behavior evidence.

## Copy and run in QEMU or on the future physical candidate

Build on the Arch host as above. Copy the executable, **not** an imagined kernel artifact, using an existing user-approved transfer path. For example, if an already-configured lab guest has SSH and compatible userspace:

```console
scp target/release/baremetal lab-user@lab-guest:baremetal
```

This external transfer command is not invoked by the suite. Do not enable networking or install packages solely by assumption. In the guest, first check the intended exact release manually, create a private report parent if needed, then run:

```console
mkdir -p "$HOME/linux-rs-reports"
./baremetal run --output "$HOME/linux-rs-reports/qemu-candidate-01" --label qemu-candidate-01 --expect-release EXACT-CANDIDATE-OSRELEASE --environment qemu
```

Replace `EXACT-CANDIDATE-OSRELEASE` with the approved candidate artifact's literal release, not the current workstation release. On the physical machine, the user separately installs/selects/boots an approved future artifact using the [Arch and boot-entry design](packaging.md), preserving the known-good kernel and recovery entry. The suite itself never performs those actions. Once the user has booted the intended candidate and its Arch-compatible userspace, copy the executable through an approved path and run locally:

```console
./baremetal run --output "$HOME/linux-rs-reports/physical-candidate-01" --label workstation-candidate-01 --expect-release EXACT-CANDIDATE-OSRELEASE --environment bare-metal
```

The physical-machine command is runnable only when the kernel, loader, libc, procfs, filesystem, socket, thread, and process prerequisites really exist. It is not evidence that they exist now. M1 boot markers/recovery are earlier requirements: this userspace suite does not postpone physical bring-up, and cannot replace early boot/interrupt/firmware evidence. Preserve candidate/reference artifact provenance separately without embedding private machine identifiers in public reports.

## Cases and distinct invariants

All files below are relative to a private per-case directory inside the newly created output's `sandbox/`. No fixture is read from or written to an arbitrary pre-existing directory. Reports and child logs are outside those case directories but still within the new output.

| Report case | Actual invariant | Important limit |
| --- | --- | --- |
| `memory-pages` | Fallible allocation of 4 MiB; initialize and verify every byte, mutate one byte per 4096-byte stride and recheck contents | Stride is a test pattern, not discovery of real page size, NUMA placement, MMU isolation, physical RAM health, or allocation-failure qualification |
| `thread-synchronization` | Four scoped/joined threads perform 8000 mutex-protected updates; exact count and arithmetic checksum | Does not prove all memory orderings, scheduler fairness, SMP stress, futex semantics, or absence of rare races |
| `file-roundtrip-seek-truncate` | 65536-byte roundtrip, cross-boundary seek/write, truncation length/prefix/EOF, zero-filled extension | Only the output filesystem and this small access pattern |
| `fsync-rename-visibility` | Sync staged file, replace a name with rename, sync parent directory; fresh open sees new bytes, old open descriptor retains old inode/content, source name disappears | **Not crash durability**: no power cut, remount, crash recovery, or persistence verification |
| `hardlink-symlink` | Same device/inode and link count, exact relative readlink target, lstat symlink type, surviving content/count after original name unlink | Sandbox files only; not cross-filesystem links or all permission/name-resolution edge cases |
| `directory-metadata` | Exact bounded directory enumeration, regular-file type/length, empty nested-directory metadata | Not arbitrary recursive traversal or a filesystem feature matrix |
| `process-exec-wait-exit` | Self-exec produces exact stdout, empty stderr, status 23, and is waited/reaped | Two-second child deadline; no shell or external executable; not ELF/ABI completeness |
| `tcp-loopback-eof` | Ephemeral IPv4 loopback connection, exact bidirectional bytes, half-close EOF in both directions | No external interface, IPv6, packet loss, throughput, congestion control, or NIC/driver qualification |
| `udp-datagrams` | Three exact connected-loopback datagrams, including zero-length, preserve boundaries; reverse acknowledgment | No external network, loss injection, arbitrary backlog, or routing checks |
| `unix-socket-transfer` | Unix stream socketpair transfers exact bidirectional bytes and half-close EOF | No filesystem socket pathname (avoids the Unix pathname length limit), descriptor passing, credentials, or namespace coverage |
| `proc-self-maps` | At most 8192 bytes, inspecting only newline-terminated records for valid address ranges and readable/executable mappings | Any incomplete final record is discarded, even if the byte limit splits a UTF-8 character. Only ASCII address fields are decoded; permissions are checked as bytes and ignored pathname bytes need not be UTF-8. Raw virtual addresses/paths are not retained. If the cap is reached before both mapping properties are established (for example, long executable paths consume the prefix), the case is `skip`/not covered, never `pass`. Missing mappings below the cap or malformed complete records still fail. |
| `proc-self-status` | Nonempty Name/State and positive numeric Threads | No raw identity/status dump; parent also needs status for the unprivileged preflight |
| `sysfs-cpu-online` | Read CPU online ranges and validate ordered, nonoverlapping range syntax | Observation only, not CPU-hotplug/topology qualification; missing/denied file is `skip` |
| `sysfs-node-online` | Read NUMA node online ranges and validate ordered, nonoverlapping range syntax | Observation only, not NUMA placement or memory policy; missing/denied file is `skip` |

Missing/permission-denied optional proc/sysfs observations become explicit `skip` with the unavailable path and reason; other observation errors or malformed data fail. If parent preflight cannot read release/status, the run fails before output instead. Filesystem, network, memory, process, and thread cases do not silently skip unsupported functionality. A filesystem that rejects directory `fsync`, hard links, or symlinks fails the relevant case; do not hide that failure by relabeling it unsupported. Select an appropriate ordinary writable local filesystem for a comparable reference/candidate run and document its type outside the suite.

The maps byte-cap skip denotes insufficient observation, not malformed Linux behavior or qualification. Every complete observed address/permission field is validated before coverage is classified, even when the prefix reaches the cap or already contains both mapping properties. Deterministic unit cases distinguish `pass`, `skip`, and errors for normal/non-UTF-8 paths, a truncated UTF-8 final record, long-path cap exhaustion, missing mappings below the cap, and malformed complete records at the cap. These tests do not establish kernel qualification or replace an actual runner report.

## Reports, bounds, privacy, and safe failure

`metadata.tsv` contains a `key<TAB>value` header and tool package/version, exact expected/actual release, label, asserted environment, architecture/OS, start Unix timestamp, configured timeouts, and `qualified=false`. It explicitly labels elapsed values as observations, **not performance qualification**. It does not read DMI/board/disk/network serials, MAC addresses, machine-id, hostname, boot command line, or device identifiers. Operator text and filesystem error messages can still disclose information; absence of deliberate serial collection is not automatic anonymization.

`report.tsv` has exactly:

```text
case<TAB>status<TAB>elapsed_ms<TAB>details
```

There is one row per attempted case, with lowercase `pass`, `fail`, or `skip`. Tabs, newlines, carriage returns, backslashes, and other control characters are escaped in fields; `elapsed_ms` includes process startup/polling and instrumentation overhead. It is not a benchmark. Each case has a `.stdout.txt` and `.stderr.txt` child log; per-case test fixtures and nested exec evidence remain under `sandbox/`. A completed run exits `1` if any case failed, otherwise `0`, including runs with skips. **Zero exit with skips is not full coverage, certification, or a release pass.** Independent cases continue after a case failure, timeout, spawn error, or bad child output. Failure to create/write/sync the report is a run-level failure; a partial report is never complete evidence.

The runner creates the output atomically as a new directory with mode `0700`; newly created evidence files use mode `0600` (the caller's umask may narrow access). Its parent must already exist. It resolves that parent before creation, and never follows a pre-existing output symlink. Fixed case names, not operator labels, select the sandbox paths. `create_new` protects file creation; no automatic recursive deletion is performed. Keep the parent trusted and stable: this dependency-free safe-std implementation is not a hardened `openat2` directory-capability sandbox against a concurrent attacker who can rename/replace ancestors or who runs as the same user. Do not run it against hostile filesystem trees.

The suite runs one case subprocess at a time, with a ten-second wall-clock deadline, kill, and wait/reap on expiry. The synchronization case has exactly four scoped workers, joined before successful return. Network transfers are tiny fixed payloads with two-second read/write timeouts; TCP connect and accept are deadline-bounded. The nested exec child has its own two-second deadline. There are no socket worker threads to leak. Stream reads have fixed lengths and EOF checks; UDP reads have fixed-size buffers; proc/sysfs/log reads are bounded at 8192 bytes, with a bounded-prefix exception for maps. The main allocation payload is 4 MiB; file fixtures are at most 65536 bytes each; all loops and fixture counts are fixed or bounded by those input caps. Per-case subprocess isolation also terminates its threads on timeout. The only descendant process is the immediate, fixed self-exec check, whose normal code path immediately prints one line and exits.

Timeouts assume the kernel schedules the supervisor and honors kill/wait and I/O. A hung kernel or uninterruptible filesystem operation can defeat userspace deadlines/reaping; this cannot be solved by safe standard-library code running on that same kernel. Supervisor interruption or power loss can also leave partial evidence, and forcibly terminating a parent can interrupt nested-child reaping. Do not treat a lack of report rows as `skip` or success. No real-time bound, hostile-kernel containment, signal-handler recovery, or process-tree supervisor is claimed.

There is no privilege elevation, raw device access, mount/unmount, firmware operation, package install, boot entry modification, reboot, system tuning, sysctl write, external network contact, or destructive privileged test. The only unlink removes a regular sandbox file created by that same case; the only rename replaces another same-case fixture created with `create_new`. Evidence is deliberately retained. After review, manually remove only the precise report directory you created, using your normal file manager or carefully reviewed cleanup command; never feed an unreviewed label/path into recursive deletion.

Before sharing any report:

1. Confirm the intended kernel was booted and expected/actual releases agree; record separately whether this is installed-host runner smoke, pinned-oracle smoke, QEMU candidate smoke, or candidate physical smoke.
2. Read every status, including skips, and verify all 14 case rows exist. An incomplete report, crash, timeout, or missing metadata is not a pass.
3. Inspect metadata, details, child logs, sandbox filenames, and the terminal transcript for usernames, private paths, operator-provided identifiers, addresses, and environment details before publication. Raw maps/status are not intentionally saved, but manually captured consoles may contain private data.
4. Keep immutable originals locally; publish reviewed/redacted copies with redaction noted rather than silently modifying the original evidence. Preserve tool source revision/build provenance separately; package version alone does not establish source identity.
5. Compare only runs with documented equivalent filesystem/userspace and candidate/reference configuration. Do not compare elapsed smoke values as a performance score.
6. On a case failure, stop any qualification claim, preserve the entire output, collect the user-approved nonprivate console/recovery evidence, and retry only into a **different** new output after understanding the failure. On a host/kernel hang use the prearranged external recovery plan; this runner must not install or trigger recovery actions.

## Observed host-runner verification

At the end of the original setup delivery, the runner was exercised on `7.2.10-1-cachyos` with `--environment reference`, using `rustc 1.101.0-nightly (5c543b0b8 2026-09-29)`. This historical record is neither the pinned `6.18.57` oracle nor a Rust candidate run, and does not qualify later changes. All runs recorded `qualified=false`.

| Executable-path scenario | Passed | Failed | Skipped |
| --- | ---: | ---: | ---: |
| Ordinary project path | 14 | 0 | 0 |
| Directory containing a non-UTF-8 byte | 14 | 0 | 0 |
| Valid 4,069-byte executable pathname | 13 | 0 | 1 |

Both pathname regressions were reproduced before repair. Arbitrary pathname bytes no longer invalidate unrelated maps fields. The long-path case exhausts the 8192-byte observation cap before a complete executable-mapping record is available; `proc-self-maps` now explicitly reports incomplete coverage, not a kernel failure or a passed case. Deterministic tests also require malformed complete records to fail even at the cap.

Twelve separate CLI/safety scenarios exercised help, invalid usage, exact-release mismatch before output creation, existing-output preservation, symlink-output refusal and missing-parent refusal. That setup revision passed formatting, warnings-denied offline Clippy and all 20 workspace unit tests; this is not the current final workspace count. Those runs exercised no privileged/root execution, hostile-kernel containment, candidate QEMU/physical boot, crash durability or performance qualification. Subsequent eight-case kernel QEMU and five kernel-parser test evidence is separate in [implementation](implementation.md), not an execution of this userspace runner.

Ordinary-path reports, metadata, child logs and sandbox are retained locally in `target/reference-smoke-final/`; temporary pathname/negative fixtures were removed. These generated files are ignored build/lab evidence, not portable checked-in certification. Re-run into a new directory when validating a different binary or kernel.

## What remains mandatory outside this smoke

Follow the [full definition of done](definition-of-done.md), [verification plan](verification.md), [bare-metal matrix](bare-metal.md), and [performance requirement](performance.md). This suite alone cannot establish Linux parity, safe DMA/IOMMU operation, real device interrupts, firmware/suspend/hotplug, full architecture support, security mitigation correctness, crash consistency, complete syscall compatibility, or performance at least Linux.

The broader program still requires pinned Linux kselftest/KUnit equivalents where applicable, LTP and syscall/ABI differential tests, stress and fault injection, xfstests and filesystem crash/recovery campaigns on sacrificial media, isolated external networking suites and real NIC tests, container/server workload compatibility, security/adversarial tests, hardware/firmware/NUMA/power/interrupt qualification, and controlled repeated performance/power comparisons. These external reference/testing tools may contain non-Rust code; project-owned executable implementations remain Rust. They are not invoked or installed here. Their absence is a recorded requirement/blocker, never converted into this smoke's `pass` rows. See [upstream kselftest documentation](https://docs.kernel.org/dev-tools/kselftest.html), [KUnit documentation](https://docs.kernel.org/dev-tools/kunit/), [LTP](https://github.com/linux-test-project/ltp), and [xfstests](https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/).
