# Experimental bootstrap diagnostic: package and manual handoff

> **CURRENT AUTHORITY: ONLY the named diagnostic-003 lineage below is conditionally cleared for the user's separate-media diagnostic trial.** Archive SHA-256 `bda84047e66a4c3be71a4525b31389a95118a5df69cc23b322a4bbc3e291078f`, original packaged ELF SHA-256 `beca60940b86cbf1bb8e0496d5eeab02a29ca47ad7abdf46a9a942618091117d`. Director accepted its actual008 execution/display, independent bounded ABI repair review, actual archive/metadata and source-consumer records. **Diagnostic-001/002 remain permanently withdrawn; never boot or retroactively clear them.** This current guidance does not rewrite any archived HOLD or clear the rebuilt source-smoke ELF, later source revisions or other artifacts. Every manual recovery/media/platform condition below remains mandatory. No physical evidence exists yet: return the complete screen photograph, exact ELF digest and known-good recovery result.

> **Dated record, 2026-10-20 (A21): a second, separate lineage is prepared for the user's trial.** At the user's request ([A21](decisions.md): "a bare metal test suite I can just execute while using the new kernel") the repository can now produce a **kernel-run bare-metal suite tree** (`xtask baremetal-suite`; procedure, contents and limits in [bare-metal-suite](bare-metal-suite.md#kernel-run-suite-a21)). It is a distinct lineage from diagnostic-003: a different kernel feature set (`freestanding` + `baremetal-suite`), a different artifact (a directory tree for a separate FAT32 USB stick, not an ALPM package), later source (the first-userspace slice, VFS, memory mapping and time lanes run in it) and a different procedure. It is **prepared, not physically cleared**: it has no physical evidence and none is claimed; it becomes physical evidence only if and when the user boots it from separate recoverable media per that document and returns the photographs. Everything in this handoff about diagnostic-001/002 (withdrawn), diagnostic-003 (conditionally cleared, unchanged) and the user-only boot/recovery rules stays in force; agents still never write media, change boot entries or firmware, mount, elevate or reboot.

## What this deliverable is

`linux-rs-bootstrap-diagnostic` is a **separate, unsigned, experimental x86_64 ALPM package** containing the real default `freestanding` kernel ELF, its build/map/source provenance, corresponding source and notices. It is not `linux`, does not provide, replace or conflict with Linux packages, and cannot run the installed Linux system. The package producer is [Rust-owned `xtask/src/package.rs`](../xtask/src/package.rs). Its real `PKGBUILD` is restricted constant assignment data generated, parsed and consumed by Rust, never executed as shell; it is not a makepkg/AUR recipe. No project build script, shell installer, installation hook or placeholder kernel is involved.

This is a **storage-free M1 diagnostic trial**, not a completed M1 or a Linux-replacement package. The bootstrap exercises a narrow BSP-only entry/memory/mapping/exception/legacy-timer path and stops. It has no Linux root filesystem, storage/filesystem implementation, initramfs consumer, init, userspace/syscall compatibility, network stack or normal shutdown/reboot service. It cannot run the separate Linux userspace `baremetal` smoke runner. The full Linux 6.18.57 scope and all of its physical, security, performance and release obligations remain mandatory; see [implementation](implementation.md), [definition of done](definition-of-done.md) and [packaging](packaging.md).

**No agent installs a package, modifies the host boot menu/default, mounts media, writes a raw device, changes firmware/Secure Boot/keys, elevates privileges or reboots the machine.** The commands in the build/inspection section create or read repository-local regular files only. The later physical actions are exclusively the user's decision and manual operation, on separate user-owned recoverable media, with independent known-good recovery already available.

## Corrected replacement candidate: diagnostic-003

This candidate is built from immutable **integrated-008**, not the withdrawn004/006 ELFs. Actual008 matched all ten cases with expected33/35 and no timeout; retained007 genuinely failed its new fatal-PF/alignment test with measured ordinary-callee residue0. Corrected008 observes residue8 and the genuine fatalPF diagnostic, plus a separate all15-GPR returning-PF proof. Director actually opened008's legible1024x768/noFAIL default PNG and read its manifest/result/positive/fatal logs. Saved interruptedRSP is not raw handler-entryRSP.

| Exact new identity / gate | Observed record |
| --- | --- |
| Archive | `target/kernel-tooling/diagnostic-003/linux-rs-bootstrap-diagnostic-0.1.0.elfbeca60940b86cbf1bb8e0496d5eeab02a29ca47ad7abdf46a9a942618091117d-1-x86_64.pkg.tar.zst` |
| Archive SHA-256 | `bda84047e66a4c3be71a4525b31389a95118a5df69cc23b322a4bbc3e291078f` |
| Packaged/default ELF SHA-256 | `beca60940b86cbf1bb8e0496d5eeab02a29ca47ad7abdf46a9a942618091117d`; original/image-extracted/after-run/packaged bytes agree |
| Default PNG SHA-256 | `db44fe6b28591dd01e61feded2aa0c7898ce311599f7793d2454ea6f124afd2e`; finalfree116657/21tables, HLT1/IF0/RIP`ffffffff80005375`; QMPquit0 is cleanup only |
| ABI-001 independent disposition | `target/kernel-tooling/abi-fix-002/independent-review/review.json`, SHA`20ef8259abfa001a1de46fbca684342fe56b0066b570791441673ede667fb0f5`;107-file seal`2b7d4f34f8b9c22b447698d07631a6010a94e712e95745dfe66c48d381ea1bb6`. Addressed under BSP/CPL0/scalar/no-unwind assumptions, not full-kernel certification |
| Fresh artifact review | `integrated-008/artifact-review/`: actual both-profile nm/readelf/objdump, complete provider/scalar/port review by author; independent repair review separately examines all20 error entries and complete fatal/returning call paths, not a second complete port/provider audit |
| Actual archive consumers | Maintained package command0; read-only bsdtar/pacman/hash queries and project-owned extraction0;4761 safe regular/directory members,3788 inner checksums,4760 complete mtree records;23 project/3663 runtime sources and all50 files for ten cases byte-exact. `diagnostic-003/inspection/review.json` |
| Genuine ALPM metadata | Root PKGINFO/BUILDINFOv2/MTREE;12 scalar BUILDINFO fields and1449 observed installed identifiers; assembly cwd/project provenance remains distinct from earlier kernel compilation. Actual consumed constant-only PKGBUILD SHA`2cfb19d424b188813109cacbc607f0d63438fa7102aeb84d538bb7cacc002cfe` |
| Delivered-source consumer | Fresh writable23-file copy actually ran documented kernel-build0/9.47s. RebuiltELF`e4ddb9b1aa5454eaf9f7a11a812d5c3f5dea6733e70667de7e5f418667b7fc52`; all3 loaded segments/metadata identical, wholeELF/map differ. Measured nonloaded debug/symbol differences and stable source/runtime inputs: `source-build-003/review.json` |
| Director acceptance / limits | Director opened the actual archive and selected metadata, and read inspection/source-build records; separate `inspection/director-record-review.json` and `source-build-003/director-record-review.json`. Accepted this software replacement for the unchanged conditional trial, not an independent checksum rerun, installation, physical boot/recovery, legal/signing/SBOM, clean/bit-for-bit reproduction, Linux replacement or performance certification |

## Retained historical evidence: withdrawn001 and earlier cells

The retained **manual** `cell9` default-profile framebuffer was visually accepted by the integration director: 1024×768, legible entry/handoff/memory/paging/exception/timer/checkpoint lines, `PIT_WRAPS=2 IRQ_DELTA=0`, final `FREE_PAGES=18382 OWNED_TABLES=20`, and no `FAIL`. Exact identities:

- `target/kernel-first-boot/cell9/diagnostic-framebuffer.png`: SHA-256 `e93610dc7b45d533e30b96cf602f32456284e585d63c784c9f7872d89c5cc583`.
- `target/kernel-first-boot/cell9/diagnostic.elf`: SHA-256 `734f5c50ca0e49896de94a32520e8e04bc4cddcb97eff2b1b53b5a7a5bb319c6`.
- Review record: `target/kernel-first-boot/cell9/diagnostic-director-visual-review.json`.
- Retained manual HMP observation: `HLT=1`, IF clear, RIP `ffffffff8000404b`; QMP quit exited 0.

That observation establishes only the identified manual QEMU display cell. It predates the root workspace Rust-version metadata change from 1.85 to 1.88 and **is not fresh maintained-harness proof, a package inspection, a physical pass, a Linux performance result or complete M1 evidence**. The eight separate manual self-test cases and compiler/runtime audit remain identified historical evidence in [implementation](implementation.md).

| Historical001 deliverable gate, not current physical clearance | Result record |
| --- | --- |
| Fresh maintained eight-case QEMU run plus default framebuffer/terminal halt | The final metadata-bound `integrated-004` returned 0 with eight matches and no case timeout, using `/bin` invocation versus canonical `/usr/bin` tool identities. `integrated-002` and `integrated-003` are separately retained successful earlier runs. `integrated-001` returned 1 with seven matches because leading OVMF CSI controls hid the early PAT diagnostic from the old parser; its failed manifest/logs remain retained. |
| Human review of the fresh default screenshots and exact ELF hash | Director independently opened and accepted each of `integrated-002`, `integrated-003` and `integrated-004`'s `default-boot/framebuffer.png`, SHA-256 `6f49b78b5fdc5f829da6ac96fbb52d3d838b9a7f2960577dc31eecdcf1e51d5b`, bound to default ELF `cf5bac4bb29c4ec02fc6b0ae7bb7a71003206cc08132cc468b37cf01812cb8a6`. Legible1024x768 complete checkpoint, final `FREE_PAGES=116681 OWNED_TABLES=21`, `PIT_WRAPS=2 IRQ_DELTA=0`, no `FAIL`; separate per-run `director-visual-review.json` records retain observations. |
| Actual archive creation, mandatory ALPM metadata and read-only inspection | `target/kernel-tooling/diagnostic-001/` contains the genuine package, SHA-256 `cd37904857a0ea24f43f4cbc1646da73f3993388b4eb9c7714bca6d39a35a904`, made from integrated-004 with actual invocation cwd `/tmp`. Read-only bsdtar/pacman queries, safe project-only extraction, all3776 inner checksums and all4746 mtree records passed; `inspection/review.json` retains exact scope. Director separately opened the actual archive/metadata/recipe and reviewed source/hash/command evidence, closing the missing-BUILDINFO finding in `inspection/director-review.json`; not legal/release approval. |
| Delivered corresponding-source consumer build | The documented `kernel-build` actually succeeded from a new writable packaged-project copy using the existing matching compiler/rust-src, with original archive/extraction untouched. `target/kernel-tooling/source-build-001/review.json` retains source/runtime/target/ELF/map comparison; whole ELF/map bytes differ, while all loaded segment bytes/metadata match. This is same-host source usefulness evidence, not independent or bit-for-bit reproducibility. |
| User-operated physical trial and successful known-good recovery | Not run; no physical success is claimed. |
| Independent reproducibility, approved release SBOM/legal/security/performance review | Not established by this experimental archive. |

Package manifests deliberately record the creation-time evidence scope and pending independent inspection. Append an identified later inspection/review record rather than silently rewriting an already hashed package manifest. Checksums bind retained bytes; they do not provide a signing trust chain or prove that a manifest was authored honestly.

The fresh runs' self-test ELF is `9cd8eb284ec29068928ac258da991a84e2b88103c50fb4c7cefabee37811f44a`. Separate actual `nm -u`, `nm -C --defined-only`, `readelf -h -lW -r` and `objdump -d -C` outputs for **both** immutable profiles are under each run's `artifact-review/`, with the integration owner's findings in `review.json`. Both are ET_EXEC RX/R/RW with NX stack, no undefined symbols or relocations, scalar inspected instructions and project Rust `memset`; the default port-I/O sites exclude COM1/f4. The third run's maps differ only in the recorded run and Cargo binary-output directory paths; complete fresh instruction/symbol/layout outputs match the same ELF bytes. This is artifact-specific inspection, not an automatic harness assertion or blanket security/legal clearance. Capture-time manifests retain `pending` human review; separately identified later reviews do not rewrite those hashed records.

The delivered-source smoke's rebuilt ELF is `a7b4a61d8e11018e3d6efa16fdd4e3135aea6592ba6685dc5d2be34fbb4d1850`, not the packaged `cf5bac4b…cb8a6`. Only nonloaded `.debug_info`/`.debug_str` payloads differ; the actual source-root string and map output paths/`.debug_str` length changed. All21 project hashes, target-specification bytes, compiler/rust-src/vendor inputs and rebuilt runtime archives match. [The measured comparison](implementation.md#delivered-source-consumer-smoke) separates those observations from full-file reproducibility; the smoke did not boot or replace the packaged artifact.

## Build and produce the actual package

### Prerequisites

Use the exact already-installed qualified runtime toolchain: `rustc 1.101.0-nightly`, full commit `5c543b0b8c73c7b72bc8284ced4fb22ead15734d`, matching `rust-src`, its offline library/vendor inputs and matching linker. Host tools have the separate Rust 1.88 baseline. The harness resolves and checks actual compiler executables rather than treating a mutable `nightly` alias as identity. See [kernel tooling](kernel-tooling.md) for exact Cargo flags, audited external QEMU/Limine/OVMF/image-tool inputs, timeouts and provenance rules.

The package producer requires existing external `bsdtar`, `zstd`, `sha256sum` and `pacman`. It resolves their paths and records versions and binary hashes. Pacman is used only for read-only installed-package environment queries, never installation. The producer does not fetch, install or update tools. External execution uses explicit argument vectors and shared process-group cleanup: metadata queries have 30-second deadlines and a 16-MiB capture bound; archive/compression operations have retained stderr and a 300-second deadline. No shell, network, mount, raw-device path or privileged operation is used.

Freeze the workspace member sources and compiler input tree before the build; leave them quiescent until packaging finishes. Do not run concurrent edits, toolchain updates or another process against these output directories. Every source file copied into the package must match the selected build's source hash. A packaging-code change after a build also requires a new build, because the full `xtask` source is part of that build's recorded source inventory.

### Fresh proof and packaging commands

Run from the repository root, using unused output names. The following are real interfaces, not a claim that they have already succeeded:

```text
cargo +1.88.0 run -p xtask --locked --offline -- kernel-test --output target/kernel-tooling/diag-proof --timeout-seconds 60
```

Retain `target/kernel-tooling/diag-proof/manifest.tsv`, every case result/log, every build manifest, the default `result.tsv`/QMP state and framebuffer image. Require the complete source-bound case catalog to match and manually review the **fresh** default screenshot for the successful checkpoint and absence of `FAIL`. Immutable diagnostic-001 retains its original eight-case004 proof and its current HOLD. Record reviewer, ELF/image SHA-256 and observations separately. Automatic HLT/IF/RIP is not visual success: failure also intentionally halts. These software instructions never override the physical hold.

Only after that proof/review, create the package from that exact default build:

```text
cargo +1.88.0 run -p xtask --locked --offline -- kernel-package --build-output target/kernel-tooling/diag-proof/freestanding-build --output target/kernel-tooling/diag-pkg
```

The command never builds a kernel itself. It accepts either the explicit `kernel-test` **`freestanding-build`** directory above or a direct `kernel-build` directory:

```text
cargo +1.88.0 run -p xtask --locked --offline -- kernel-build --output target/kernel-tooling/diag-build
cargo +1.88.0 run -p xtask --locked --offline -- kernel-package --build-output target/kernel-tooling/diag-build --output target/kernel-tooling/diag-build-pkg
```

The second route produces a **build-only** package whose manifest explicitly states that no QEMU execution evidence was supplied. It does not authorize a physical trial; obtain fresh matched-suite and default-display evidence for the exact candidate lineage first. Do not rename a self-test build to bypass the feature-profile check. `qemu-self-test` implies `freestanding` but still includes QEMU-specific behavior and is always refused as the packaged kernel.

`--root PATH` is optional; relative input/output paths are resolved under it. Outputs must be **new direct children of `target/kernel-tooling/`**, with 1–20 ASCII letters/digits/`-`/`_` in the directory name. Existing directories, symlinked inputs/ancestors, special files, path traversal and stale/missing manifests fail closed. Partial failed output is retained for diagnosis and cannot be reused. The root, sources and outputs are trusted single-owner local directories; the tool is not a sandbox against a malicious same-UID process racing filesystem ancestors.

### Output and package layout

The filename is:

```text
linux-rs-bootstrap-diagnostic-0.1.0.elf<full-default-ELF-SHA256>-1-x86_64.pkg.tar.zst
```

`<full-default-ELF-SHA256>` describes the actual 64-character value printed by the command; it is not literal command input. The version identifies **ELF lineage**, not a Linux release or a claim of bit-identical package metadata. The separately printed archive SHA-256 identifies the exact package, including its creation-time metadata and documentation.

The output directory retains the real archive, `package-manifest.tsv`, outer `SHA256SUMS`, `staging/`, explicit NUL-delimited archive-member lists and archive/compression stderr logs. The final package name is published only after both archive and compression commands succeed; failed creation cannot leave a successful-looking `.pkg.tar.zst` filename.

Archive contents are explicit regular files/directories, owned by root in archive metadata without changing host ownership:

```text
.PKGINFO
.BUILDINFO
.MTREE
usr/lib/linux-rs-bootstrap-diagnostic/linux-rs-kernel.elf
usr/share/doc/linux-rs-bootstrap-diagnostic/
    diagnostic-handoff.md
    implementation.md
    kernel-tooling.md
    licensing.md
    NOTICE.txt
    REPRODUCING.txt
    SHA256SUMS
    limine-entry.example.conf
    provenance/package.tsv
    provenance/build/...
    provenance/qemu/...                 (only for the matched kernel-test input)
    notices/...
    corresponding-source/PKGBUILD
    corresponding-source/project/...
    corresponding-source/rust-library/...
```

`.PKGINFO`, `.BUILDINFO` and `.MTREE` are required root archive members, not prefixed `./` paths. `.BUILDINFO` is format 2 with each required scalar exactly once: the parsed recipe identity, the SHA-256 of the **actual consumed `corresponding-source/PKGBUILD` bytes**, actual xtask Cargo name/version, package-assembly time/directories and installed package name/version/architecture records queried from pacman. The installed inventory must agree before and after staging. No makepkg environment/options or unobserved packages are invented. This describes **package assembly**; the earlier kernel compilation retains separate exact compiler/runtime/source provenance, not a fabricated historical host inventory. `.MTREE` is a real generated gzip-compressed mtree with SHA-256 records. No `.INSTALL`, ALPM hook, systemd unit, initramfs preset, `/boot`, `/efi`, `/usr/lib/modules`, `/usr/lib/kernel/install.d`, `provides`, `conflict` or `replaces` is generated. There is no fake `.SIGNATURE`, detached signature or SBOM-approval marker. This package has no dependency that automatically installs Limine or firmware. A user-controlled package-manager transaction can execute **preexisting system-wide hooks**, so do not infer that “no shipped hooks” makes arbitrary host installation side-effect-free; inspection/extraction into an isolated user directory is the recommended route for this trial.

The only kernel executable payload is the default ELF. A matching self-test build manifest and case logs may be attached as provenance, but **no self-test ELF, disk image, OVMF variables, bootloader or firmware binary** is shipped. The configuration example is documentation, not an installed boot entry.

The restricted PKGBUILD grammar permits only the required whitelisted scalar and array assignments with constant single-quoted strings. Rust rejects duplicate/unknown/missing fields, functions, commands, expansions, escapes, source traversal, duplicate sources and missing/non-SHA-256 digests. Its four real sources are the default ELF, its build manifest and the complete source/runtime input inventories; the producer checks each digest and derives package identity/metadata from the parsed recipe. The recipe is neither an unrelated manifest renamed to satisfy BUILDINFO nor a claim that makepkg can execute it. Read-only `pacman -Qip` acceptance alone does **not** establish ALPM format compliance.

### Read-only inspection before any extraction or trial

Substitute `PACKAGE` below with the **exact generated archive pathname** printed by the command, and `ELF` with `target/kernel-tooling/diag-proof/freestanding-build/linux-rs-kernel.elf`. These capitals are explained substitutions, not actual filenames:

```text
sha256sum PACKAGE
bsdtar -tf PACKAGE
bsdtar -tvf PACKAGE
bsdtar -xOf PACKAGE .PKGINFO
bsdtar -xOf PACKAGE .BUILDINFO
bsdtar -xOf PACKAGE usr/share/doc/linux-rs-bootstrap-diagnostic/corresponding-source/PKGBUILD
bsdtar -xOf PACKAGE usr/share/doc/linux-rs-bootstrap-diagnostic/provenance/package.tsv
pacman -Qip PACKAGE
pacman -Qlp PACKAGE
sha256sum ELF
```

`pacman -Qip` and `-Qlp` inspect a package file; they are **not** `pacman -U` and do not install it. Match the archive checksum against the outer `package-manifest.tsv`/`SHA256SUMS`, and the ELF digest against the version, `.PKGINFO`, packaged build manifest and fresh default-run result. Independently check all required BUILDINFO v2 fields, the actual invocation `startdir` (which may differ from `--root`), installed inventory, and `pkgbuild_sha256sum` against the extracted recipe's exact bytes. Inspect the list for only the declared prefixes and regular-file/directory types: reject absolute names, `..`, links, devices, hooks, firmware/EFI payloads or boot/module paths. Inspect metadata for the experimental name, `x86_64`, no Linux replacement relations and unsigned status. A successful ALPM query validates readability, not full format compliance, bootability, signature trust or physical compatibility.

If the user chooses to extract after these checks, the destination must be a **new empty user-owned directory**, not `/`, `/boot`, an active ESP or a mounted system root. The user can run:

```text
bsdtar --no-same-owner --no-same-permissions -xf PACKAGE -C NEW_EMPTY_USER_DIRECTORY
```

`NEW_EMPTY_USER_DIRECTORY` is the user's precreated isolated destination. From its root, the user can run:

```text
sha256sum -c usr/share/doc/linux-rs-bootstrap-diagnostic/SHA256SUMS
sha256sum usr/lib/linux-rs-bootstrap-diagnostic/linux-rs-kernel.elf
```

The inner checksum list covers the staged payload, sources, notices, BUILDINFO and provenance before the list itself, PKGINFO and MTREE were generated; `.MTREE` supplies the package metadata/file inventory, and the outer archive hash binds the entire archive. None of these checks installs or starts the ELF. Retain real command outputs and exit codes; do not manufacture an inspection pass.

## Corresponding source, license and trust boundary

The package refuses to copy a current but different kernel under an older ELF's identity. It checks the real regular-file ELF, its x86_64 ELF64 `ET_EXEC` layout and executable entry, exact default feature profile, original map/specification hashes, compiler commit, before/after source/runtime manifests, and copied source hashes. The complete root Cargo workspace is present: actual root `Cargo.toml`/`Cargo.lock`, `LICENSE`, and actual `kernel`, `xtask` and `baremetal` member manifests/sources. It is not an unreproducible root manifest pointing at missing members.

The matching installed `rust-src` **library workspace**, its Cargo lock/configuration/vendor tree, `core`, compiler-builtins and all its actual workspace member sources are preserved, with build-time path/hash bindings. This broader external compiler-source bundle preserves its own original licenses, copyright comments, NOTICE files and checksum metadata. Inactive targets, external upstream scripts, build-only dependencies and C/assembly test/reference material in that bundle do not become project-owned executable logic or evidence that such code is linked into the kernel. No bundled compiler source is executed by packaging. Compiler/tool executables remain external: their exact paths/hashes are verified but they are not redistributed.

Retained obligations include:

- Full project GPL version 2 text; original source-reference and transformation records are preserved. No invented author or copyright holder is added.
- Limine protocol revision `3a0526b700e356f0eac1b71a77697b3fd1c707a3` selected ABI definitions, with original `Copyright (C) 2022-2026 Mintsuki and contributors.` and complete 0BSD permission/warranty notice. `kernel/src/boot.rs` remains `GPL-2.0-only AND 0BSD`; the extracted notice does not replace the original file.
- Rust `core`'s `MIT OR Apache-2.0` election of MIT, actual `COPYRIGHT-library.html`, and all installed license texts including MIT, Apache, LLVM exception and Unicode. The compiler's generic MIT template is retained verbatim alongside actual copyright records, not filled with invented authorship.
- Compiler-builtins 0.1.160's full `MIT AND Apache-2.0 WITH LLVM-exception AND (MIT OR Apache-2.0)` terms, with MIT elected for the alternative branch and all conjunctive terms/exception retained. Complete `compiler-builtins/LICENSE.txt`, `libm/LICENSE.txt` and per-file notices remain in the source bundle. The package does not falsely flatten these terms to MIT alone. The exact link map and [runtime audit](implementation.md#runtime-and-instruction-closure) distinguish the required scalar project Rust `memset` from unselected archive providers.

`REPRODUCING.txt` records the actual maintained build command and exact-source/toolchain prerequisites. Use a writable separate copy of the included project source and the exact already-available compiler with matching included library/vendor sources; do not overwrite a shared/global toolchain to reproduce. Original absolute paths/debug information and creation timestamps may affect bytes. No independent clean-environment or bit-for-bit reproduction has yet been established for this package.

The four packaged Markdown files retain repository-relative links to the broader plans; they are references, not a fabricated complete documentation checkout. Rust file locations are under `corresponding-source/project/`. That executable workspace is sufficient for the named `kernel-build` reproduction, but `xtask check`/`status` additionally need the full project's planning inventory and documentation. To regenerate a package from this source copy, also copy the four included Markdown files into its `docs/` directory before running the documented package command. None of these instructions asserts an audit, reproduction or repackaging pass.

There is no bundled external Limine/OVMF/firmware/microcode. Existing external Limine is a separately inventoried loader, not Rust kernel implementation; machine firmware remains another external trust dependency. Installation availability does not grant blanket redistribution rights. Review [licensing](licensing.md) before further distribution. The file inventory is not an approved standard-format release SBOM or legal/security clearance. Linux upstream tag verification remains the separately recorded fingerprint-pinned “Good signature” with GPG `TRUST_UNDEFINED` / `[unknown]`, not Web-of-Trust/ultimate trust, and does not authenticate this unsigned local package.

## User-only physical trial: prerequisites and stop conditions

**These conditions apply only to the explicitly cleared diagnostic-003 archive/original ELF above.** Historical001/002 instructions remain overridden by their permanent withdrawal; no archived HOLD is rewritten. The source-smoke rebuilt ELF and later revisions are not cleared by this handoff. Proceed only when **all** are true:

1. **Exact corrected candidate evidence:** the complete maintained catalog for that source matches, its default framebuffer and required source/codegen/package reviews are accepted, and packaged ELF digest equals the identified run. Diagnostic-003 is bound to corrected ten-case008 and the identities above; withdrawn001/002 can never satisfy this requirement. An unrelated old screenshot, build-only package or HLT register is insufficient.
2. **Independent known-good recovery:** the user has a working kernel/normal boot choice plus separately recoverable rescue media, knows how to select them manually, and has demonstrated that recovery path before this candidate. Keep working kernel/initramfs/boot configuration unchanged. Do not make the diagnostic the persistent default, remove recovery media or depend on candidate keyboard/network/reboot support.
3. **Separate user-owned media:** use an already prepared, independently bootable, recoverable removable/candidate medium with an existing known-good external Limine installation. Identify it by physical ownership/label, not a guessed `/dev/sdX` name. Never overwrite the live root disk or active ESP, create a raw image on a host block device, repartition, or reuse production data for this diagnostic. The package tool neither prepares nor mounts media. If safe separate media/recovery is unavailable, stop.
4. **Compatible platform reviewed:** this particular cell requires x86_64 UEFI64, native Limine protocol base 5 support, four-level paging, required NX/PAT capabilities, valid immutable ACPI RSDP/XSDT/SDT/MADT handoff, legacy PIC/PIT availability and an accepted framebuffer. It is BSP-only and deliberately rejects unsupported CPU/controller modes, including x2APIC. A working Linux boot does not prove these narrower assumptions. No arbitrary physical device/platform support is claimed.
5. **Visible console and bounded recovery:** the user can observe/photograph the display independently, reach the firmware's one-time boot selector and use the machine's known manual reset/power-off recovery. No physical serial port, COM1, QEMU debug-exit device, remote console, watchdog or automatic fallback is assumed. If the display or manual recovery is unavailable, stop before selecting the diagnostic.
6. **Firmware/security unchanged:** record firmware/loader version and existing Secure Boot policy without enrolling keys, flashing firmware, disabling security settings or editing boot variables for this experiment. This native Limine ELF is unsigned; a platform requiring a signing chain that does not already accept this experimental path is blocked, not a reason for the tool/agent to bypass policy.
7. **Data and device safety:** save work and shut down the known-good OS normally using the user's established procedure before manually selecting the medium. Do not attach experimental DMA/storage test workloads or add kernel test command-line mutations. “Storage-free” describes the kernel's lack of storage I/O; it is not isolation from privileged firmware, bootloader behavior, live-device DMA or power-loss effects. If data cannot be isolated adequately, stop.

These prerequisites allow only an initial storage-free diagnostic observation. They do not establish real-disk durability, device/DMA safety, multiprocessor behavior, mitigation equivalence, performance or full physical M1 coverage.

### Manual loader handoff, without host boot mutation

The user alone may copy the verified default ELF **as an ordinary file** onto their separate already-accessible candidate medium, for example at `/linux-rs-bootstrap-diagnostic/linux-rs-kernel.elf` on that medium. Recheck the copied file's SHA-256 against the package and fresh build. Do not copy the self-test ELF or any `disk.img` from the QEMU run.

Using the medium's existing external Limine, the user may add a clearly marked **nondefault manual selection on that separate medium**, preserving its known-good choice and the host's original configuration. The packaged example contains:

```text
/linux-rs EXPERIMENTAL storage-free diagnostic
    protocol: limine
    path: boot():/linux-rs-bootstrap-diagnostic/linux-rs-kernel.elf
    resolution: 1024x768x32
```

This is a Limine menu fragment, not a command and not a complete replacement configuration. `boot():` refers to the medium from which that Limine instance was booted; the user must confirm it resolves to the candidate medium, not the host ESP. Preserve the existing recovery/default/menu timeout policy. Do not add `test=...`, a root disk, modules or initramfs. Do not apply the QEMU harness's zero-timeout configuration to the host or recovery medium. Copying/selecting/rebooting is never performed by an agent.

The ELF is **native Limine protocol input**, not a UEFI PE/COFF application, Linux bzImage/boot protocol, PVH image, UKI or systemd-boot-compatible kernel. Renaming it `.efi` or adding it as a systemd-boot Linux/EFI entry cannot supply those missing interfaces. Firmware starts the existing external Limine EFI loader; Limine loads the ELF through the specified protocol. A future native EFI/Linux/systemd-boot path is separate required implementation work.

The user manually selects the separate medium through the established one-time boot mechanism, then the explicitly experimental entry. The working host boot choice remains unchanged. Before selection, start a camera/video and note a 30-second observation deadline.

## Expected framebuffer, failure and recovery protocol

The default profile does **not** use QEMU COM1 or port `0xf4`; it writes only through the accepted 32bpp RGB framebuffer and ultimately masks interrupts and halts. The console validates the handoff's address/range, geometry, pitch and channel layout. Requesting 1024×768×32 does not prove that firmware supplied an acceptable display. The diagnostic-003 lineage's renderer used uppercase glyphs, so source log names below appear uppercase on its screen (later lineages render exact ASCII via `font8x8`; they are not diagnostic-003 and carry no physical clearance).

Within **30 seconds after manually selecting the diagnostic**, expect all of these in order, with real machine-dependent counts:

```text
LINUX-RS BOOTSTRAP X86_64 LIMINE-BASE=5 FIRMWARE=EFI64
CHECK ENTRY OK FRAMEBUFFER=TRUE MAP_ENTRIES=...
CHECK HANDOFF OK ACPI_TABLES=... LEGACY_PIC=TRUE
CHECK MEMORY OK USABLE_PAGES=... METADATA_PAGES=... FREE_PAGES=...
CHECK PAGING OK TABLES=... WX=SEPARATED GUARDS=4 IMAGE_ALIAS=ABSENT
CHECK EXCEPTION OK BREAKPOINT=RETURNED GPRS=15 GUARD=0 READONLY=3 NX=17
TIMER MASK OBSERVATION PIT_WRAPS=2 IRQ_DELTA=0
CHECK TIMER OK DELIVERED=... MASKED_COUNT=... GPRS=15 PIT_WRAPS=2
CHECKPOINT BOOTSTRAP-COMPLETE FREE_PAGES=... OWNED_TABLES=...
```

The ellipses identify fields to record, not literal success text and not fixed capacities. Delivered timer interrupts must be at least 16. Free-page/table counts can differ by loader/firmware memory map; neither `18382` nor `20` is a physical acceptance constant. There must be **no `FAIL`**. `CHECK TABLE-OOM`, `CHECK EXHAUSTION` and `RESULT SUCCESS` are self-test-only records: they are not required or expected in the packaged default profile.

After the complete checkpoint, a static display/intentional halt is expected. It does not mean the machine powered off, handed control to Linux or can process keyboard commands. A photograph alone does not establish IF/HLT hardware state; record only what was observable. QEMU's prior HMP register observation is not a physical measurement.

Treat any `FAIL`, panic/trap diagnostic, partial checkpoint, garbled display, loader error, reboot/reset, blank screen, or missing complete checkpoint at the deadline as **failed or inconclusive**, never success. Very early CPU/boot rejection can occur before framebuffer setup, so blank output is an actionable inconclusive failure, not evidence that the candidate is idle. Waiting longer without a predefined new experiment does not turn a timeout into a pass.

On success **or** failure:

1. Photograph/video the entire screen before changing power/reset state; retain the last visible line and elapsed time. Do not try terminal commands or serial/debug-exit tricks.
2. Use only the user's previously established manual reset/power-off procedure. The candidate has no orderly OS shutdown service. This is why no productive workload or storage durability experiment is authorized here.
3. Remove/deselect the candidate medium as appropriate to the established recovery path. Manually select the unchanged known-good kernel or independent recovery medium. Do not repeatedly auto-boot the failing candidate.
4. Confirm the known-good system actually boots and ordinary recovery is available; record its exact observed release and any unexpected state. Failure to recover blocks all further trials and requires the user's independent recovery process, not ad hoc boot/firmware repair by an agent.
5. Keep the candidate, package and evidence immutable. Rebuild/package a new lineage for any source/configuration/compiler change rather than relabeling this result.

No destructive failure injection, firmware mutation, storage write/recovery test or physical negative `test=` mode is authorized by this protocol. Those need separate isolated equipment/procedures and future implementation.

## Evidence to return after the user-operated trial

Return a concise record with actual observations, not a blanket “works”:

- Exact package filename/archive SHA-256, packaged ELF SHA-256, build manifest and fresh QEMU run/screenshot/review identities. Include the copied medium-file digest and actual Limine fragment used.
- User assertion of physical execution, date/time and broad hardware/firmware facts needed to interpret the cell: CPU vendor/family/model/features, RAM, firmware/loader version, UEFI/Secure Boot state, framebuffer mode and known PIC/PIT availability. Omit hardware serial numbers, MAC addresses, UUIDs, unrelated personal data and keys.
- Unedited photograph/video of entry through terminal checkpoint or first/last failure; readable text transcription alongside, not replacing raw images. State whether all expected lines were legible and whether any `FAIL`, reset, blank display or timeout occurred. Record measured wall time and dynamic counts without substituting QEMU values.
- Outcome **observed checkpoint**, **failed**, or **inconclusive**, with the exact limiting evidence. A checkpoint can only qualify this narrow trial after review; it is not full M1 or Linux compatibility.
- Actual manual recovery action, exact known-good release observed after return, and whether the original boot/default/configuration remained unchanged. Successful candidate output without demonstrated return to known-good is incomplete recovery evidence.
- Any surprising device/storage/firmware behavior or unresolved prerequisite. Stop further trials if safety assumptions failed.

Do not return fabricated guest exit codes: a physical default diagnostic has no QEMU debug-exit result. Do not run Linux benchmarks or the userspace smoke suite “inside” this kernel; neither userspace nor those facilities exists yet.

## Gates still required for a Linux-replacement package

This separate storage-free diagnostic intentionally does not pretend to install a usable Linux system. A real replacement package still requires actual storage drivers, durable filesystems, root/initramfs handling, init and Linux userspace/ABI support; real configuration/module or Rust replacement layout; supported Linux/EFI/systemd-boot and other promised loaders; safe install/update/uninstall/failed-install recovery; complete source/runtime/license/SBOM/signature and reproducibility review; broader architecture/device/firmware/SMP/security/stress/crash-recovery physical qualification; and matched pinned-Linux per-cell performance evidence. See [release obligations](licensing.md#release-obligations-and-exhaustive-definition-of-done), [verification](verification.md), [bare-metal qualification](bare-metal.md) and [performance](performance.md). None is waived by a readable archive or one successful screen.

## Design decisions and format authorities

1. **Crates:** no new Cargo crate is introduced. Rust `std` owns paths/manifests/staging; already available `bsdtar` and `zstd` supply real audited external archive/compression formats, not a home-grown tar/zstd implementation.
2. **Shared mechanisms:** process deadlines/reaping, tool resolution/version output and SHA-256 reuse the maintained kernel host helpers. Build/source/runtime hashes are consumed rather than creating a second build/profile convention.
3. **Simplification:** one honest separately named storage-free payload is shipped outside boot/module-hook paths. No pretend rootfs, compatibility alias, installation shim, EFI rename or Linux package replacement is added.
4. **Security:** regular-file/ancestor/path checks, fresh private output, original source/hash binding, explicit archive members, no bootloader/firmware redistribution and no install/boot actions limit the intended operation. A trusted quiescent local workspace and external tools remain prerequisites; checksums are not cryptographic authentication.
5. **Improvement:** retain raw evidence and exact source/notices, compare fresh default framebuffer to its own ELF lineage, and require independent artifact inspection and user-operated recovery before making stronger claims. Package generation itself is not such a claim.

Primary format references: [ALPM package specification](https://alpm.archlinux.page/specifications/alpm-package.7.html), [PKGINFO v2](https://alpm.archlinux.page/specifications/PKGINFOv2.5.html), [BUILDINFO v2](https://alpm.archlinux.page/specifications/BUILDINFOv2.5.html), [ALPM MTREE](https://alpm.archlinux.page/specifications/ALPM-MTREE.5.html), [pacman manual](https://man.archlinux.org/man/pacman.8.en), [bsdtar manual](https://man.archlinux.org/man/bsdtar.1.en), and [zstd manual](https://man.archlinux.org/man/zstd.1.en). Repository-specific requirements and actual source/license facts are recorded in [kernel tooling](kernel-tooling.md), [implementation](implementation.md) and [licensing](licensing.md), not inferred from format compliance.
