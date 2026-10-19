# Rust-owned x86_64 kernel build and QEMU tooling

## Scope and honest status

`xtask` keeps the existing offline `check` and `status` planning-audit commands and adds real Rust-owned `kernel-build`, `kernel-test` and `kernel-package` commands. They cover the current x86_64/UEFI/Limine bootstrap cell and separate unsigned diagnostic distribution only. They do not implement or qualify the Linux 6.18.57 kernel, establish physical boot support, Linux parity, security, performance, or any other architecture. The broader fixed Linux baseline remains in scope.

The implemented first boot cell uses QEMU `q35` with OVMF, Limine 12.9.3, and Limine protocol base revision 5. This is an engineering sequencing choice, not a newly attributed detailed user approval. Tool/firmware provenance and the independent Linux tag verification remain in `target/implementation-prereqs/{tooling-manifest.txt,upstream-verification.txt}`; the latter records `TRUST_UNDEFINED`, not Web-of-Trust certification.

This page specifies the maintained interface and acceptance rules. Actual `integrated-002`, `integrated-003` and final metadata-bound `integrated-004` runs each returned0 with eight matched cases and independently reviewed default captures; `integrated-001` remains retained failed evidence. Host Rust1.88 strict Clippy/46 tests and separate final nightly strict-Clippy/51-test/format/check/status gates passed. The genuine unsigned `diagnostic-001` archive received actual read-only metadata/member/extraction/hash inspection and independent director format/source acceptance; its documented build also succeeded from a new writable packaged-project copy, without whole-ELF/map identity or independent reproducibility claims. [Implementation](implementation.md) identifies exact hashes, comparisons and review limits. Historical manual `cell9` results are not relabelled as maintained-harness results. Newly captured screenshots always begin with human review pending.

## Commands

Run from the repository root on the Linux x86_64 host. The shared build/test/package output policy accepts only a fresh direct child of `target/kernel-tooling/`; it refuses reuse, parent traversal, symlink directory ancestors and special files. The run directory is created with mode `0700` (subject to a more restrictive umask). Each build owns an isolated Cargo target directory and map, so it does not read or overwrite `target/x86_64-unknown-none/release`, the kernel developer's work directory, a host disk, or a shared `target/kernel.map`.

```console
cargo +1.88.0 run --offline --locked -p xtask -- check
cargo +1.88.0 run --offline --locked -p xtask -- status
cargo +1.88.0 run --offline --locked -p xtask -- kernel-build --output target/kernel-tooling/build-001
cargo +1.88.0 run --offline --locked -p xtask -- kernel-test --output target/kernel-tooling/test-001
cargo +1.88.0 run --offline --locked -p xtask -- kernel-test --output target/kernel-tooling/test-002 --timeout-seconds 30
cargo +1.88.0 run --offline --locked -p xtask -- kernel-package --build-output target/kernel-tooling/test-002/freestanding-build --output target/kernel-tooling/package-001
```

`--root PATH` may appear before or after a command and selects the project root; relative `--output` paths resolve under that root. Output names are 1–20 ASCII letters, digits, hyphens, or underscores. `--timeout-seconds` is valid only for `kernel-test`, from 1 through 300, and applies to each guest. Usage errors return 2; audit/build/test failures return 1; success returns 0. Existing `check`/`status` semantics and exit behavior remain unchanged.

### External module-fixture prerequisites

Current `kernel-test` consumes these **existing exact external reference inputs**; it does not generate/download substitutes. Both are ignored local `target/` artifacts and are **not in the Git publication**. A fresh clone cannot reproduce the full QEMU suite until the operator obtains the matching archives and places them at these paths. `kernel-build`, host tests and structural audits do not require them. The external toolchain/firmware/loader/image-tool prerequisites below still apply; no installation is automatic.

| Relative input | Exact bytes | SHA-256 |
| --- | ---: | --- |
| `target/linux-reference/artifacts/initramfs.cpio` |2203136| `3f8a6aa43d1b1050534c92ba7d12c936f53c64837e8fa54b4e0a0c9423c82391` |
| `target/linux-reference/uefi-kvm-arch-001/artifacts/initramfs-arch.cpio` |13751296| `b4b5584f72a9a3d79c8700231656897b63a7612fe18830648cd9bc45093bb008` |

These are retained Steam-runtime/TCG and installed-Arch/KVM **reference** closures, respectively, not candidate userspace execution or an offer to redistribute their licenses blindly. The runner binds source and FAT-extracted payload bytes. It creates the third genuinely empty file only for `empty-module`; its zero length does not become a borrowed4096-byte archive. The loader's backing page stays reserved. No portable fixture-generation framework or missing-input fallback is implied.

## Build profiles and compiler contract

Both profiles run Cargo from the project root with `--offline --locked`, fresh output-local `CARGO_HOME` and per-profile `--target-dir`. `rustup which --toolchain nightly`, with automatic installation disabled, resolves already-installed actual Cargo/rustc once; inherited host `CARGO` and proxy selection do not choose the runtime. Required Cargo commit `3d7cf6e937d6127d0f49881bf689c560b36d35c4` and rustc commit `5c543b0b8c73c7b72bc8284ced4fb22ead15734d` must share a sysroot. Absolute `RUSTC` and exact bundled `rust-lld` are bound through Cargo and explicit `-Clinker`. Host1.88 is separate. Pinning does not certify all compiler lowering: the [confirmed error-code ABI defect and local repair](implementation.md#error-code-entry-defect-reproduction-and-repair) require their own generated-code/consumer review.

Compiler executables and their installed `librustc_driver`/LLVM support libraries are hashed **before** the identity queries, checked against the pre-build inventory, and included in the post-build equality check. This closes ordinary alias/file drift; it is not a sandbox against a malicious tool or a same-user adversary changing bytes and restoring them between observations.

Every child starts with a cleared environment plus a minimal system `PATH`, `LC_ALL=C`, and explicitly constructed settings. The runner rejects nonempty `RUSTC`, compiler wrappers, Rust flags/bootstrap/target-path overrides, `LD_PRELOAD`, and Cargo build/target/profile/source/unstable overrides (including a redirected build directory). The build explicitly sets both wrapper variables, `RUSTFLAGS` and `CARGO_ENCODED_RUSTFLAGS` to empty; it does not rely on removal that could expose a Cargo-config fallback. Cargo's own inherited `LD_LIBRARY_PATH` is discarded rather than forwarded. Repository/ancestor `.cargo/config{,.toml}` files, including a home directory that is an ancestor, are refused; global Cargo configuration is not copied. There is no toolchain/target installation, network resolution, or global Cargo/Rustup mutation.

Shared target/compiler arguments are:

```text
-Zbuild-std=core,compiler_builtins
-Zbuild-std-features=compiler-builtins-mem
rustc --offline --locked --target-dir <private-output>/cargo-target
-p kernel --bin linux-rs-kernel --target x86_64-unknown-none --release --no-default-features
-Crelocation-model=static
-Clinker=<actual-qualified-sysroot>/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld
-Clinker-flavor=gnu-lld
-Clink-arg=--no-pie
-Clink-arg=-Tkernel/linker.ld
-Clink-arg=--no-undefined
-Clink-arg=-Map=<this-run>/kernel.map
```

`kernel-build` uses only `--features freestanding`. `kernel-test` independently builds `--features qemu-self-test` (which includes `freestanding`) and `--features freestanding`, under `qemu-self-test-build/` and `freestanding-build/`. The ELF snapshot, linker map, target specification and runtime archives are per-profile. The source inventories must also agree across the two builds. Runtime archives are discovered recursively in the **fresh** target's release tree, including current Cargo's `release/build/{core,compiler_builtins}/<hash>/out/` layout, not assumed to live in `deps`. Both runtime providers must be present; artifact symlinks/special files fail.

### Source and vendored standard-library binding

Before Cargo runs, the harness records every regular file in the current `kernel/`, `xtask/` (including every module and `package.rs`), `baremetal/` and `vendor/` trees, root `Cargo.toml`, `Cargo.lock`, `LICENSE`, `.cargo/config.toml`, and any root `rust-toolchain*` files. It separately records the complete selected installed `rust-src/library` tree, including `core`, compiler-builtins, workspace metadata, vendor files and checksum manifests; the Rust library copyright/license files; exact compiler/tool inputs; the running harness executable; and generated local Cargo configuration/target specification. Source symlinks and special files are refused.

Sorted path/SHA-256 inventories are saved as `source-inputs-{before,after}.tsv` and `runtime-inputs-{before,after}.tsv`. Hashing is batched and uses NUL-delimited filename records. After Cargo finishes, the source trees are re-enumerated and rehashed: additions, removals or byte changes fail the build, even if Cargo returned zero. Both successful and failed build directories are retained. These snapshots detect changes over the observed interval; they do not authenticate a pre-existing modified checkout or prove reproducibility.

The runner requires the matching installed Rust source distribution's own `library/vendor` and exact source-replacement configuration. It strictly parses the installed lock/checksum metadata, compares each locked vendor package checksum and each listed file digest with the pre-build inventory, and preserves those inputs. Only a generated **run-local** Cargo configuration points crates.io resolution at the [merged vendor directory](#vendored-dependencies-and-the-fresh-clone-build) (rust-src vendor plus the project `vendor/`). No global registry cache, reconstructed source-only cache, downloaded dependency, or fabricated `.cargo-checksum.json` is used. Cargo remains offline and enforces its normal source checks. The trust root is the installed qualified toolchain/rust-src distribution: checksum consistency is **not independent cryptographic authentication**.

The ELF must be x86-64 ET_EXEC with executable PT_LOAD ranges. Its immutable snapshot hash is checked when copied, before FAT staging, and after guests. The manifest explicitly says that xtask does **not** perform full symbol/disassembly/provider/unsafe/legal closure review. That review and reproducibility remain separate acceptance obligations.

### Vendored dependencies and the fresh-clone build

Registry crates live in `vendor/` (committed, produced by `cargo vendor --locked --versioned-dirs`, never hand-edited) and the checked-in `.cargo/config.toml` replaces `crates-io` with it, so every `--locked --offline` host command (`check`, tests, Clippy, `kernel-build`) resolves from a clone with only the pinned toolchains installed: no network and no `~/.cargo` registry cache. Verified with an empty `CARGO_HOME`.

`kernel-build`/`kernel-test` use `-Zbuild-std`, and Cargo allows only one directory behind a replaced source, so the harness builds a per-run merged source: `<output>/cargo-home/vendor/` holds one symlink per rust-src `library/vendor` package and per project `vendor/` package (a name-version collision fails), and `<output>/cargo-home/config.toml` points `crates-io` at it. The build command passes that file with `--config`, which has higher precedence than the checked-in host config, so the two never shadow each other. Before the build the harness verifies every project package against the root `Cargo.lock` (exact locked set, `.cargo-checksum.json` `package` equals the lock checksum, every listed file hash equals the file, **no unlisted file**, only the reviewed `build.rs` allowlist) and records them in `vendored-std-inputs.tsv`. `vendor/` and `.cargo/config.toml` are in the before/after source inventories, so a byte change during the build fails it. `reject_build_overrides` still refuses any `.cargo/config*` in an ancestor directory; at the root it accepts only `.cargo/config.toml` byte-identical to `PROJECT_CARGO_CONFIG` in `xtask/src/kernel.rs` (a unit test pins the checked-in file to that constant). The checksum chain is integrity consistency, not authentication of the crates.io bytes.

Update workflow: add or bump a crate with `cargo add` (exact `=x.y.z` pins in `kernel/Cargo.toml`), then `cargo vendor --locked --versioned-dirs vendor` (after removing the old `vendor/`), review the diff and the new crate per the [admission record](dependencies.md#admission-record-one-crate-one-exact-configuration), add any new `build.rs` to `VENDOR_BUILD_SCRIPTS` only after reviewing it, and run `check`. A branch that adds a crate while another does too must re-run `cargo vendor` after the merge. Target-specific `cargo clippy -Zbuild-std ...` is not covered by the checked-in host config (it needs the merged source): append `--config target/kernel-tooling/<a kernel-build run>/cargo-home/config.toml` to it, as exercised in [implementation](implementation.md#cpu-layer-on-audited-crates).

### Bounded processes

Metadata/version/hash/git/ELF/target queries use bounded socket capture: 30 seconds and at most 16 MiB per stdout/stderr stream. Cargo has a 900-second deadline; filesystem-image commands have 30-second deadlines. No shell implements the harness. Ordinary commands run in a new Unix process group (`CommandExt::process_group(0)`) and the long-lived children (cargo, QEMU) are launched as `/usr/bin/setpriv --pdeathsig KILL -- <program>` (util-linux; it sets `PR_SET_PDEATHSIG` and execs in place, so pid and process group are unchanged). Ctrl-C, SIGTERM or an aborting panic of xtask therefore kills them instead of orphaning them. The signal follows the spawning thread, and every spawn happens on the thread that waits for the child. `setpriv` is a fixed absolute path whose version and SHA-256 are recorded in the manifests (and in the build runtime inputs). Not covered: grandchildren such as `rustc` (once cargo is dead they finish their current compilation unit and stop; observed gone within seconds), a parent dying between fork and `prctl` (no `getppid` recheck without `unsafe`), short-lived metadata/image tools, and the `kill` utility. A crate such as `rustix` was rejected: it needs `unsafe` `pre_exec` and its dependencies would enter the shared lock file that the isolated offline kernel build must vendor. On timeout/error, and when a direct child exits with descendants still present, the runner uses the fixed `/usr/bin/kill --signal KILL -- -<group>` utility, itself bounded to two seconds, and reaps its direct child. The shared helpers are also used by packaging. This controls the audited tools' inherited process trees, not a hostile process deliberately escaping its group.

## FAT image and firmware boundary

The runner creates regular image/evidence files and a private QMP socket in a fresh `0700` directory `$XDG_RUNTIME_DIR/linux-rs-qmp-<pid>-<run-name>` (falling back to `/tmp`; removed after the capture) because `sun_path` is too short for deep checkouts; its path is in the recorded `qemu_arguments`. It sizes a disposable FAT32 image with Rust filesystem calls, then invokes `mkfs.fat`, `mmd`, and `mcopy` with explicit argument vectors; there is no shell, mount, loop-device, raw-device write, privilege escalation, or network device. The image contains the real ELF at `/linux-rs-kernel`, Limine at `/EFI/BOOT/BOOTX64.EFI`, and a generated `limine.conf` with `timeout: 0`, `protocol: limine`, `path: boot():/linux-rs-kernel`, and `resolution: 1024x768x32`. The runner extracts the staged ELF and EFI application again, compares their actual payload digests to their inputs, and records those image-payload hashes rather than merely hashing unrelated source files.

QEMU uses x86_64 `q35`, TCG, one CPU, 512 MiB, no NIC, and OVMF. `OVMF_CODE.4m.fd` is read-only and the boot disk is attached `readonly=on` as a `virtio-blk-pci` device (QEMU rejects read-only `ide-hd`/AHCI disks; Limine/OVMF only read it); a fresh `OVMF_VARS.4m.fd` copy is created for every guest and retained after execution. Limine's EFI payload is retained as an image-verified extraction; Limine/OVMF notices are also copied. Limine's `--version` first line must be exactly `Limine 12.9.3`. Manifests retain tool identities, QEMU arguments, image/firmware digests, variable-store before/after digests, boot-disk `sha256_disk_image_initial`/`_after_run` digests (a difference fails the run) and observed outcomes. The guest serial log is read with a 4 MiB cap; an oversized, missing or non-UTF-8 log fails the case with that reason.

## Automated self-test cases

The self-test profile uses QEMU's explicitly supplied `isa-debug-exit` device. No exit code alone is accepted: success requires exit 33 **and** all required serial records; failures require exit 35 **and** the case-specific diagnostic, and must not contain `RESULT success`.

Current source has **eleven cases**. The tenth genuine terminal-PF case retains failed0079/10/callee residue0 and corrected00810/10/residue8; positive cases require the unique returning-PF fifteen-GPR proof. The eleventh `empty-module` case is independently expected33, not treated as a negative merely because its name differs from `success`. Historical008/003 source does not contain the new buddy/image/runtime consumer wave; [publication evidence](implementation.md#publication-checkpoint) separates current inputs and retained failures.

Serial captures retain the exact UART bytes, including firmware output before kernel entry. Validation accepts complete **leading** ECMA-48 CSI control sequences before each LF/CRLF-delimited text record, then requires the same anchored diagnostic and token boundary. It never strips embedded controls, searches arbitrary substrings, or accepts an exit code without diagnostic evidence; malformed or unsupported control framing fails closed. Both positive-case `FAIL` rejection and negative-case `RESULT success` rejection use these same normalized records.

The first maintained run, `target/kernel-tooling/integrated-001/`, really executed eight cases and the default capture but returned1 with seven matches. The missing-PAT guest exited35 without timeout; its raw serial bytes contain two OVMF `ESC[001;001H` cursor-home sequences immediately before `FAIL cpu error=Pat`. The old validator required an unprefixed text line and falsely rejected that record. This is a framing defect, not missing kernel rejection or confirmed Limine text concatenation. Its manifest, raw log, configuration and failed result remain intact. A production-verdict regression covers that framing plus embedded controls, malformed escapes, textual prefixes, token lookalikes and masked success/failure diagnostics. Fresh `integrated-002`, `integrated-003` and final source-bound `integrated-004` subsequently matched all eight cases; the historical failed directory was never reused.

| Case | Kernel/QEMU input | Required result |
| --- | --- | --- |
| Success | `qemu64`, no test command line, both exact archive modules | Exit33; entry/handoff/memory/paging/exhaustion and nonzero table rollback; exact buddy-order/zero/split/coalescence/fragmentation/alignment proof;272memset and4224memcpy boundary checks, null-zero/padded-field/disjoint-range proofs; both archive/ELF summaries and post-CR3 no-alias epoch; exact arbitrary-order IRQ guard and actual restore observation; returning-PF/BP/IRQ15-GPR, masked wraps2/delta0, complete checkpoint and `RESULT success`, no `FAIL` |
| Controlled panic | `test=panic` | Exit 35; `FAIL panic` and `controlled panic case` |
| Unexpected fault | `test=unexpected-fault` | Exit 35; `FAIL trap vector=6` |
| Malformed map | `test=bad-map` | Exit 35; production validation diagnostic `EXPECTED failure bad-map rejected overflow` |
| Missing PAT | QEMU CPU `qemu64,-pat`, no test command line | Exit 35; `FAIL cpu error=Pat` |
| Unarmed breakpoint | `test=unexpected-breakpoint` | Exit 35; `FAIL trap vector=3` |
| Unknown external interrupt | `test=unexpected-interrupt` | Exit 35; `FAIL trap vector=unknown-external` |
| Genuine unmasked timer mutation | `test=unmasked-timer` leaves PIC IRQ0 unmasked | Exit 35; actual `pit_wraps=2`, nonzero observed IRQ delta, and `FAIL assertion=timer-mask`; no injected failure result or success marker |
| Genuine early IRQ restore mutation | `test=irq-restore-early` restores saved IF while retaining raw controller ownership | Exit35; exactly one restore observation with two real PIT wraps, nonzero IRQ delta and `lock_acquired=false`; `FAIL irq-guard error=InterruptGuard`, no positive guard proof or success result. The pending IRQ tries the actual lock; no injected acquisition failure or assumption that STI bypasses its interrupt shadow. |
| Unarmed hardware page fault | `test=unexpected-page-fault` reads the verified unmapped guard without a recovery permit | Exit35 **and** exactly one `TRAP call-abi vector=14 rsp_mod16=8` from the actual naked ordinary-callee entry witness, plus genuine `FAIL trap vector=14 error=0x0`. A bad residue, missing/duplicate/contradictory proof, `FAIL trap-call-abi` or success record is not a pass. The witness observes; it never realigns the caller. |
| Empty boot module | Both archives plus a real zero-byte third payload | Exit33 and **all** positive proofs, plus exact third-module bytes0/reserved4096/all archive/ELF counts0, and post-CR3 module epoch3. Neither missing evidence nor a synthetic serial line is accepted. |

Each of the eleven current cases has a separate FAT image, QEMU process, copied variable store, serial log, QEMU stdout/stderr and `result.tsv`. Timeouts always fail; the runner kills the guest process group and reaps QEMU. It deliberately omits `-no-shutdown`, which would hide the debug-exit result. Port `0xf4` and assumed COM1 output are confined to the explicit QEMU self-test feature/device profile.

## Default freestanding framebuffer capture

The default ELF boots with **no** `qemu-self-test`, debug-exit device, serial port or COM1 assumption. QMP `query-cpus-fast` supplies CPU identity, not halt evidence. The runner polls QMP's HMP `info registers` and requires `HLT=1`, EFLAGS.IF clear, and RIP inside an executable PT_LOAD of the exact built ELF. This excludes a firmware/menu halt and an STI/HLT timer loop, but can still represent a kernel failure halt: human framebuffer inspection remains essential. Socket readiness, bounded QMP messages and screenshot requests share the guest deadline; reads/writes are additionally bounded to two seconds and each response line to 1 MiB. The runner retains raw QMP/HMP state and requests PNG, falling back to PPM if unavailable while preserving the failed PNG attempt. It then requests QMP `quit`; exit zero within three seconds is required. Timeout, premature exit, failed cleanup or a changed ELF snapshot fails the command rather than producing a pass.

A valid image header and QMP state are checked, but **the screenshot contents are not OCR'd or otherwise programmatically certified**. The run report labels the capture `pending` human visual review, and `kernel-test` prints its exact path. A director must inspect `default-boot/framebuffer.png` (or `.ppm`) and confirm the complete checkpoint; an image file existing by itself is not a visual pass.

## Retained output

Each `kernel-build` retains `cargo.stdout.log`, `cargo.stderr.log`, the isolated target tree and runtime libraries, `readelf-header.txt`, `program-headers.txt`, `linux-rs-kernel.elf`, `kernel.map`, `target-spec.json`, tool versions, before/after source/runtime inventories and `build-manifest.tsv`. A failed top-level build writes `failure.tsv` when possible; a failed test writes a failure `manifest.tsv`. Partial files and logs are never overwritten by a subsequent run.

Each `kernel-test` also retains per-case images, configuration, image-verified ELF/EFI payloads, variable stores, serial/QEMU logs, notices and results. Default capture retains `qmp.log`, `qmp-cpus.jsonl`, `qmp-registers.jsonl`, `qmp-status.jsonl` and the framebuffer. The top-level manifest separates automated case matches from **pending** human visual review; case count is recorded, not inferred from an old run.

The separate experimental `kernel-package --build-output <existing-default-build-dir> --output target/kernel-tooling/<fresh-name>` interface consumes a real default-profile build without rebuilding a self-test profile into the package. Its scope, ALPM inspection and user-operated recovery restrictions are documented in [diagnostic handoff](diagnostic-handoff.md). It does not install anything or qualify a Linux-replacement package.

Execution and package evidence now share one case-name/expected-exit catalog. The package validator checks the current catalog count and every case receipt, then copies all case evidence. It no longer keeps a separate eight-case list, count or success-versus-failure exit assumption. The consumer regression uses actual fixture validation/copy/hash operations and a fresh staging destination for failed-receipt rejection, so duplicate-output errors cannot mask a missing status check. Immutable diagnostic-001 remains bound to its older source and eight-case004 evidence.

Focused host regressions cover process-group timeout/reaping with native Rust children, capture limits, fresh/private output and symlink/traversal rejection, source-byte/set changes, canonical tool identity versus invocation spelling, nested Cargo runtime layout/vendor checksums, serial verdicts, ELF/HMP parsing and actual recipe/BUILDINFO consumers. Historical004 passed host46/nightly51 tests; corrected-entry008 passed host52/nightly65 tests, two ownership compile-fail docs, strict Clippy for host/workspace/both freestanding profiles and formatting. Its genuine ten-case/default execution and independent director display/log review are separate from unit tests; emitted-code review, package/source consumer proof and physical clearance remain distinct. Retained0079/10 is the intended failing-before ABI observation, not an exit-only pass.

## Five design checks

1. **Crates:** no crate or new Cargo dependency is introduced; the host runner remains Rust `std` and invokes audited external tools.
2. **Bundle:** both build profiles share the same compiler/target/linker argument construction, per-run manifest, file hashing, process timeout/reaping, and FAT image staging; only the explicit feature set and QEMU evidence differ.
3. **Simplify:** one Limine/OVMF x86_64 QEMU cell is implemented first. It does not narrow the required Linux architecture, device, ABI, filesystem, protocol, or deployment scope.
4. **Security:** outputs are fresh regular files under `target/kernel-tooling`; external commands use argument vectors, no shell, network, mount, raw device, privilege or global configuration writes. QEMU networking is disabled. Debug-exit is confined to the explicit test-feature build; default capture uses no serial/debug-exit assumption. Tool and firmware inputs are hashed and notices retained.
5. **Improve:** immutable per-run ELF snapshots and separate profile caches prevent cross-build races; real allocation-failure, exception, interrupt and timer cases expose regressions. The framebuffer screenshot improves observability without claiming automated visual correctness or physical qualification.

Related contracts: [implementation evidence](implementation.md), [toolchain](toolchain.md), [verification](verification.md), [bare-metal execution](bare-metal.md), [packaging](packaging.md), and [licensing](licensing.md). QEMU results remain emulation evidence only; user-operated physical testing and full Linux parity gates are separate.