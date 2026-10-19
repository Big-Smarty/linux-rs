# Licensing, provenance and distribution

## Approved license model and present state

This is a **direct Linux-to-Rust source-port program under GPL-2.0-only**, not a clean-room implementation. Translation into Rust does not erase original copyright, license obligations, file-specific exceptions or provenance. The reference is Linux **6.18.57**, resolved to commit `2ff600d29ee478d0a8d46ef8a58afb5e038fe692`; authoritative metadata and the exact tag/commit/tree chain are in [coverage](coverage.md) and [reference metadata](../planning/reference.tsv). The original GitHub-only signature observation is preserved separately from the subsequent local verification; neither is a blanket legal or security clearance.

[LICENSE](../LICENSE) contains the complete GNU GPL version 2 license text, including its official explanatory application appendix, obtained from the [Free Software Foundation's official text](https://www.gnu.org/licenses/old-licenses/gpl-2.0.txt). The appendix's example placeholders, Gnomovision and Yoyodyne are part of that authentic license text, not project copyright claims or permission to relicense this GPL-2.0-only project as “or later.” No invented project copyright holder has been added to LICENSE. Actual authorship/copyright notices must follow real contributions and provenance.

The current repository includes a real original Rust `no_std` bootstrap informed by pinned Linux/architecture references, plus planning records and host tools. [Implementation](implementation.md) records what was actually authored or adapted, built, booted and inspected; it does not claim complete Linux source files were translated. The kernel links code from the vendored third-party crates in the table below (CPU layer only); no other crates.io crate is linked. The current planning auditor and bounded smoke suite have no third-party Cargo dependencies, but compiler/standard-library/runtime and external loader/firmware inputs are not absent.

### Current bootstrap provenance and notice scope

| Input | Actual use and retained obligations |
| --- | --- |
| Original kernel Rust | GPL-2.0-only. Preserve source-reference and transformation records without inventing upstream authorship for original code or calling the whole direct-port program clean-room. |
| Limine protocol revision `3a0526b700e356f0eac1b71a77697b3fd1c707a3` | Selected ABI definitions and 0BSD notices are retained in `kernel/src/boot.rs`. Original validation code remains GPL-2.0-only; the combined file correctly declares `GPL-2.0-only AND 0BSD`. Protocol-object identity is not a signature-authentication claim. |
| Vendored crates in `vendor/` (`x86_64` 0.15.5, `raw-cpuid` 11.6.0, `bitflags` 2.13.2, `bit_field` 0.10.3, `volatile` 0.4.6, `const_fn` 0.4.12, `rustversion` 1.0.23) | Third-party source kept byte-identical with each crate's own `LICENSE-MIT`/`LICENSE-APACHE` (`raw-cpuid`: `LICENSE.md`; `x86_64`/`raw-cpuid`: `AUTHORS`) and SPDX/copyright headers; **not** relicensed as GPL-2.0-only source. MIT is elected for every dual-licensed crate (`raw-cpuid` is MIT only); no Apache-only crate is in the graph. In the linked ELF only `x86_64` and `raw-cpuid` appear as named symbols (e.g. `CpuId::new`, `Descriptor::tss_segment_raw`); `bitflags`/`bit_field` are compile-time macro/inline code merged into their callers, not separately loaded sections, but their notices are kept for a binary distribution conservatively. The MIT notices must accompany a binary; the package's corresponding-source bundle includes `vendor/` for that. `const_fn`/`rustversion` run only on the build host. Per-crate record: [dependencies](dependencies.md#admitted-exact-configurations). Not legal advice; counsel review is open. |
| Matching compiler `core` | The exact-nightly `rust-src` build uses the `MIT OR Apache-2.0` core license with the MIT option elected. Retain the toolchain's `share/doc/rust/COPYRIGHT-library.html` and `licenses/MIT.txt` notices for artifact-distribution review. |
| `compiler_builtins` 0.1.160 and emitted helpers | A matching-source compiler input, not a blanket crate admission. Preserve its full `MIT AND Apache-2.0 WITH LLVM-exception AND (MIT OR Apache-2.0)` expression and selected-provider notices. Feature `c` is not selected. Inspection found avoidable architecture-selected `memset` assembly; the final artifact instead uses the needed scalar project Rust `memset`, with no speculative helper stubs. Both-profile symbol/disassembly evidence is in [implementation](implementation.md). |
| External Limine 12.9.3 (`limine 12.9.3-2`) | Separate BSD-2-Clause bootloader, not Rust kernel implementation. Its package signature was validated; applicable notices include `/usr/share/doc/limine/{COPYING,3RDPARTY.md}`. ABI definitions and the complete external bootloader are distinct license inputs. |
| External OVMF (`edk2-ovmf 202608-1`) | Firmware, not linked Rust candidate code. Preserve applicable BSD-2-Clause-Patent/Apache-2.0/MIT package provenance and `/usr/share/licenses/edk2-ovmf/{License.txt,OvmfPkg.License.txt}` notices. Exact CODE/VARS and notice hashes are recorded in the implementation prerequisites. Installed-package integrity is not source-to-binary reproducibility or general redistribution approval. |

Independent local kernel.org/GitHub fetches matched the pinned tag object, commit and tree. Isolated GPG `verify-tag` reported **Good signature** for primary fingerprint `647F28654894E3BD457199BE38DBBDC86092693E`, authenticated by the [kernel.org HTTPS signature page](https://www.kernel.org/signature.html) plus matching WKD/TLS fingerprint retrieval. GPG explicitly reported **`TRUST_UNDEFINED` / `[unknown]`**: no Web-of-Trust certification, ultimate trust or global trust-store change is claimed. Raw evidence is retained at `target/implementation-prereqs/upstream-verification.txt`, with exact tool/artifact records linked from [implementation](implementation.md).

The policy below is engineering compliance guidance, **not legal advice**. Counsel must resolve uncertain license expressions, combination/distribution boundaries, patent questions, firmware redistribution and any incompatible notices before admission or release. A missing permission is a blocker, not permission to drop required functionality or silently replace its behavior.

## Why Linux's per-file rules matter

The pinned [Linux licensing rules](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/Documentation/process/license-rules.rst) state that the whole kernel is GPL version 2 only, while individual files may carry compatible licenses and exceptions. SPDX expressions communicate the exact terms; `OR` permits selection of an alternative, while `AND` accumulates obligations. Preserve original notices and legally meaningful combinations rather than rewriting everything to a single uniform header.

For new project-owned Rust source, use an accurate `// SPDX-License-Identifier: GPL-2.0-only` where this project's approved licensing applies. For translated files, retain the correct upstream license/exception and copyright notices, identify the upstream path/revision and record translation/modification history. Do not manufacture dates, names or per-file ownership claims. Pure factual planning inventories are not a substitute for a source provenance ledger. Tool package metadata must express the actual project license; a Cargo license string alone does not retain notices or grant rights.

When a file contains material from several upstream sources, document each and its license contribution. Preserve license texts and attribution required by permissive code too. Do not remove prior notices simply because the combined kernel is distributed under GPL-2.0-only, and do not silently broaden a source file's exception to unrelated code.

## Syscall boundary and UAPI exports

The pinned [Linux-syscall-note exception](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/LICENSES/exceptions/Linux-syscall-note) and [COPYING](https://raw.githubusercontent.com/gregkh/linux/v6.18.57/COPYING) distinguish normal userspace syscall use from a kernel-derived work. UAPI headers with the exception may be included by non-GPL userspace under their stated terms. This does **not** make kernel internals, copied implementation bodies, in-kernel drivers or arbitrary exported interfaces exempt.

Proposed UAPI generation process:

1. Identify exact pinned UAPI sources, architecture variants, original SPDX expressions, copyright and exception text. Keep exported interface definitions separate from internal implementations.
2. Translate/generate Rust ABI constants/layouts and any future userspace headers from a provenance-recorded source. Keep generated outputs' applicable notices; do not infer an exception just because a file is installed into a userspace SDK.
3. Validate every width/alignment/packing, compat/time32/time64 field and ioctl encoding against the baseline; record ABI evidence independently of license evidence.
4. For files legitimately carrying `GPL-2.0-only WITH Linux-syscall-note` or another exact upstream expression, preserve that expression and ship the corresponding exception text when distributing those files. Do not add `WITH Linux-syscall-note` globally to the kernel or grant an exception on someone else's behalf.
5. Review each generated/exported SDK package and its source/notices before distribution. Userspace binaries and external test programs retain their own licenses; using kernel syscalls does not require them to become project-owned Rust implementations.

No UAPI SDK or generated Linux baseline source export is shipped by the current bootstrap. Before first export, copy the exact applicable upstream exception/license notices into the distribution rather than paraphrasing legal text.

## Crate license decisions: alternatives are not conjunctions

[Dependency research](dependencies.md) is a candidate catalog, not an approved software bill of materials. Inspect the exact release archive and **all** target/build/proc-macro/transitive code, including files not covered by the root manifest expression.

| Expression or material | Proposed handling for a GPL-2.0-only kernel |
| --- | --- |
| `MIT OR Apache-2.0` | Evaluate and explicitly select the **MIT option** for the relevant package/files, retain MIT copyright/permission notices and record the election. Do not describe the dependency as relicensed solely GPL or claim every transitive package also offers MIT. |
| `BSD-2-Clause OR Apache-2.0 OR MIT`, `Zlib OR Apache-2.0 OR MIT` | Select a reviewed GPLv2-compatible alternative where genuinely available and satisfy its notices. Confirm each included file is covered by that alternative. |
| **Apache-2.0 only** | Not admitted into the GPL-2.0-only combined kernel under ordinary terms. The [FSF compatibility analysis](https://www.gnu.org/licenses/license-list.html#apache2) says Apache-2.0 is compatible with GPLv3 but **not GPLv2**, including additional patent-related requirements. GPL-2.0-only cannot simply upgrade to GPLv3 to cure this. Seek actual additional permission, different compatible code or a Rust implementation with appropriate provenance. |
| `MIT AND Apache-2.0`, `Apache-2.0 AND ISC`, or mixed-file terms | All relevant conjunctive terms apply; MIT in the expression is not an escape hatch. Escalate exact obligations; reject ordinary Apache-only/conjunctive-incompatible combinations unless a valid exception/permission is established. |
| MPL-2.0 (`fdt` candidate) | No blanket rejection or blanket approval: evaluate file-specific license, secondary-license provisions, Exhibit B/incompatible-with-secondary-licenses marking and notices, with counsel. Exact source/release disposition is required before combination. |
| `Apache-2.0 WITH LLVM-exception` and compiler runtime mixed terms | LLVM exception can change compatibility analysis, but its exact scope and the accompanying `AND` terms must be reviewed. [compiler_builtins currently declares](https://raw.githubusercontent.com/rust-lang/compiler-builtins/master/compiler-builtins/Cargo.toml) `MIT AND Apache-2.0 WITH LLVM-exception AND (MIT OR Apache-2.0)`. Do not flatten this to “MIT,” assume it is plain Apache-only or assume component exception covers arbitrary third-party runtime code. Review selected linked implementations and bundled notices. |
| GPL-2.0-or-later / other GPL-compatible input | Counsel-approved selection must be recorded alongside the whole-kernel GPL-2.0-only distribution; preserve original notices and available permissions. Do not change upstream grants or imply all GPL versions are interchangeable. |
| Unknown/custom license, “source available,” no license, incompatible extra restrictions | Block admission/distribution pending actual permission. Repository visibility and access to source are not a license. |
| Native bindings/runtime under a compatible license | License compatibility does not satisfy the Rust-only implementation boundary. ACPICA C runtime, libfdt, native OpenSSL/ring C/standalone assembly or `*-sys` code remain disallowed kernel implementations under the approved design. |

The FSF itself distinguishes general licensing guidance from personalized legal advice. Counsel's role is to review actual artifacts and circumstances, not issue an unqualified “all Rust crates are compatible” assurance. Similar crate names, repository badges, a crates.io license field, vendoring, statically linking a library or disabling its default features are not substitutes for this review.

Host build tools, compiler, linker, reference Linux, emulator and external test suites are normally separate artifacts with their own licenses and source-distribution requirements. Their separation is a reviewed fact of the distribution, not a general-purpose loophole for linking prohibited target code. A tool generating Rust source can also copy licensed tables or templates; review generated output ownership/notices. Rust-only executable ownership does not mean external toolchain binaries are implemented entirely in Rust.

## Source provenance record and import workflow

For **every** direct port or imported/adapted mechanism, record before integration:

- upstream repository, exact commit/tag/path and original blob checksum; acquisition source/date and independently checked signature status, without promoting GitHub metadata into a verified trust claim;
- original license expression, per-file notices and any SPDX exception, bundled license files, rights/permissions relied on and selected dual-license option;
- original-to-Rust mapping: one-to-one port, split/merged translation, generated material, or independently written implementation informed by source; changed algorithms/semantics and rationale, real author/reviewer and modification dates;
- source dependencies and copied snippets/tables, including test vectors, firmware interface definitions and generated constants; an unattributed snippet from an issue/forum is not automatically reusable;
- behavioral differential/tests and remaining divergence tracked separately from license clearance; legal admission cannot certify Linux correctness, memory safety or performance;
- retained source/preferred modification form and deterministic build/install inputs necessary to satisfy distribution obligations, with archival location and immutable artifact association.

Ordered workflow: obtain authenticated baseline evidence → inspect actual files/licenses → record mapping/permission and planned SPDX/notices → translate required behavior in Rust → review semantics and unsafe/assembly contracts → integrate all notices/SBOM/source offer/source distribution materials → qualify and sign release artifacts. Do not start by copying an entire tree and retroactively guessing file licenses. Do not relabel translated Linux algorithms as clean-room code.

Upstream-source descriptions/inventories do not authorize removing original attribution when implementation begins. SPDX scanning can identify candidates for review; it cannot establish authorship or resolve conflicting grants automatically. A generated source map must retain exact pinned Linux revision and later security/backport lineage so maintainers can reason about legal and behavioral changes together.

### Consumed bitmap translation record

The post-integrated-004 [native-word bitmap](../kernel/src/bitmap.rs) is a direct selected-algorithm translation from Linux6.18.57 commit `2ff600d29ee478d0a8d46ef8a58afb5e038fe692`, not a clean-room claim. Source was read from the authenticated unchanged external reference tree under `target/linux-reference/source/linux-6.18.57/`; [source authentication](implementation.md#pinned-source-and-specification-map) retains the exact signature/trust boundary. The implementation author is worker `kernel-implementation-astra`, model `openai-codex/gpt-6-astra:max`,2026-10-19; independent algorithm/notice review is scoped separately from legal clearance.

| Input / exact blob | Material and transformation |
| --- | --- |
| `lib/find_bit.c` / `d4b5a29e3e7283ae415671d22a0f71720929f20a` | Original `GPL-2.0-or-later`; selected `FIND_NEXT_BIT`/`_find_next_zero_bit` algorithm becomes safe native-word masking/scanning/size-sentinel logic. Original Red Hat/David Howells, IBM/Rusty Russell and Yury Norov notices remain, including attribution for other original functions rather than falsely assigning their authorship to new Rust integration. |
| `lib/test_bitmap.c` / `c83829ef557f58029f5693035076e97aa2314018` | Original `GPL-2.0-only`; translated500-bit clear-iteration fixture retains every-tenth-bit and100–149 clear positions and checks each start offset. No C test implementation is linked or executed in the candidate. |
| `include/linux/find.h` / `9d720ad92bc15d25ac2abd0f0353310dc73cc2c7`; `lib/bitmap.c` / `b97692854966e0073e32dfd4589b42ae3359c9cb` | GPL-2.0/GPL-2.0-only semantic references for sentinel and native-word/unused-tail behavior; not whole-file translations or admissions of their remaining APIs. |

The file declares `GPL-2.0-only AND GPL-2.0-or-later`: new borrowed-view/integration material is GPL-2.0-only while the upstream algorithm's original grant remains intact. No new rights holder, counsel approval, release election or broad distribution certification is invented. Whole-kernel release still requires the legal dispositions above. The [core contract](subsystems/core.md#2-common-primitives-and-waitwakeup-machinery--m1m3) records source behavior, Rust ownership changes, tests and remaining architecture/performance boundaries; actual future artifacts must bind this revision, not reuse diagnostic-001's older source manifest.

### Selected IRQ-state and locking contract translation

The subsequent [CPU-local IRQ wrapper](../kernel/src/cpu.rs) translates selected native saved-IF/restoration and unlock-before-restore behavior from the same Linux6.18.57 pin: `arch/x86/include/asm/irqflags.h`, blob `b30e5474c18e1be63b7c69354c26ae6a6cb02731`, and `include/linux/spinlock_api_smp.h`, blob `9ecb0ab504e32010387c6910f0ef22fd670e97a5`. Both original files declare `GPL-2.0`; no additional author notice is removed. Exact local file Git hashes were compared to those pinned objects. The combined CPU file retains GPL-2.0-only and names the inputs; the author/model/date remain the successor identified above.

The native [TTAS ownership bit](../kernel/src/sync.rs), packed nesting protocol and Rust tests are original GPL-2.0-only integration. They are not a translation or relicensing of the separately reviewed GPL-2.0-or-later `qspinlock.h`; its MCS, mixed-width and queued behavior remains unported. Lockdep, scheduler/preemption and RT semantics are separate unimplemented contracts, not properties supplied by this primitive. `drivers/clocksource/i8253.c` is a GPL-2.0 reference for shared latch/read port exclusion, not a claim to port its jiffies clocksource, errata or clock-event implementation. Independent source reviews and actual revision execution have separate scope; no legal certification is inferred.

### Selected buddy and boot-image translation records

The bounded publication wave uses the same authenticated Linux6.18.57 commit `2ff600d29ee478d0a8d46ef8a58afb5e038fe692`. Original SPDX/grants and author notices are retained in each translated Rust file; reference-only definitions are distinguished from implemented algorithms. This is direct-source work, not clean-room or full upstream-file completion.

| Input / exact pinned blob | Selected Rust material |
| --- | --- |
| `mm/page_alloc.c` / `ec5ca89cbc00061af2c33d693ebc97a1b557ece0` | [buddy.rs](../kernel/src/buddy.rs): selected `__rmqueue_smallest`, `expand` and `__free_one_page` splitting/coalescing. GPL-2.0-only; Torvalds, Tweedie, Wichert, Molnar, Sarcar, Bligh, Red Hat/Howells notices retained. No Linux zone/GFP/reclaim/per-CPU policy claim. |
| `mm/internal.h` / `ef42eee87c7bed06a7250469fb90ab86d773a18d` | Selected buddy-PFN/admissibility behavior; original GPL-2.0-or-later preserved with GPL-2.0-only new integration. |
| `include/linux/mmzone.h` / `7fb7331c57250782a464a9583c6ea4867f4ffdab` | GPL-2.0 default-order reference, not a zone-layout/API port. |
| `init/initramfs.c` / `6ddbfb17fb8f1b42f7a937defc9e017c75539ae5`; `init/initramfs_test.c` / `3f0241ca907597d8248a87e2c97d364097312558` | [cpio.rs](../kernel/src/image/cpio.rs), [tests](../kernel/src/image/tests.rs): selected raw newc/crc field/framing and test intent. No VFS unpack or equivalence claim for incomplete-stream side effects. |
| `lib/decompress.c` / `7785471586c627aa2e40121f5bad0399aeac5a54` | GPL-2.0 compression magic classification only; no decompressor. |
| `lib/kstrtox.c` / `97be2a39f537105af99f3c4a2044db76743e3f54`; `lib/vsprintf.c` / `a8f12833fbb32f525a3a62e9bb66282d3ff57f76` | Selected bounded hexadecimal conversion semantics. Original GPL-2.0/GPL-2.0-only and notices remain, not claims of porting other original authors' formatting code. |
| `fs/binfmt_elf.c` / `e4653bb99946b1d9be67ff625d4344ca41d6e7ca`; `fs/exec.c` / `4aa6905259591dddf578dcb153ef6571b28cebed` | [elf.rs](../kernel/src/image/elf.rs): selected header/load/interpreter and zero-filled short-header behavior. GPL-2.0-only, Youngdale and Torvalds notices retained. No task mappings or exec implementation. |
| `arch/x86/include/asm/elf.h` / `6c8fdc96be7e8bd33919d9b56ae8a8a68f4b0c3f`; `include/uapi/linux/elf.h` / `819ded2d39de2bfcfca3c25a52c8b8cd51a01c12` | Selected native preliminary checks and ELF definitions. The original Linux-syscall-note applies to its UAPI material only, not a new exception for the kernel implementation. |

The new free-word hierarchy/ownership integration and shared checked [byte decoder](../kernel/src/image/bytes.rs) are GPL-2.0-only. No crate/native dependency was added; no unaudited C parser/allocator or assembly memory provider is admitted as a shortcut. Independent component/source review and actual current consumers are bounded evidence in [implementation](implementation.md#publication-checkpoint), not legal, signing, full Linux behavior or performance certification. The published source/provenance record does not pretend ignored full upstream trees/toolchains/disks are in Git.

## External firmware, microcode and boot trust

Approved external firmware/microcode may be non-Rust and is **not claimed as Rust code**. This includes machine firmware, CPU microcode, device firmware and any externally built UEFI/QEMU firmware used for testing. Do not confuse permission to use external firmware with permission to embed a native ACPICA/libfdt/runtime library in the kernel.

For each used/distributed blob or firmware package, record: vendor/upstream origin, exact version/hash, signing/authentication status and trust root, license text/redistribution conditions, whether user-supplied or bundled, hardware/device mapping, loading stage and privilege, update/rollback/revocation policy, known security limitations and measurement impact. Do not infer redistribution permission from availability in an installed Linux firmware directory. Keep firmware hash/configuration identical in Linux versus Rust-kernel performance comparisons unless the difference is an explicitly controlled experiment.

On the currently available workstation, the user controls package installation, boot selection and physical recovery. No planning/audit command updates firmware, enrolls keys, changes Secure Boot state, writes raw disks, installs boot entries or reboots the host. [Packaging](packaging.md) must keep a known-good kernel selectable in Limine/systemd-boot. Test logs/metadata omit hardware serial identifiers and private signing material; release manifests must not contain signing keys or personal machine secrets.

Bundled firmware and boot artifacts need separately accurate notices and trust scope. A signed Rust kernel does not prove trusted firmware, device DMA safety or absence of SMM/management-engine code. Hardware without tested firmware/mitigation evidence stays unqualified under [bare-metal](bare-metal.md).

## Release obligations and exhaustive definition of done

The official GPL text is authoritative; this checklist is not a replacement for its terms or a legal determination that any particular combination is distributable. Before each real distribution:

1. Resolve all original/translated/third-party/generated/firmware licenses for the exact shipped artifacts and configs; retain copyright and modification notices, applicable full license texts and exceptions, dual-license elections and counsel dispositions. No ambiguous source is silently omitted from the legal record.
2. Produce a complete artifact-specific SBOM/provenance manifest and corresponding source in its preferred modification form, including relevant build and installation controls, dependency sources/patches and configuration. Review GPLv2 section 3 source-delivery/offer option and distribution mechanics with counsel; a link to an unrelated upstream branch is not an artifact-specific source archive.
3. Include license/warranty information and required attributions with source/binary/package/SDK distributions. Do not invent copyright holder names, a contributor's authority or an exception. Preserve upstream per-file exception scope.
4. Reconcile source manifests/checksums with link maps and runtime-closure evidence in [toolchain](toolchain.md); compiler-generated/bundled runtime objects and firmware are not ignored simply because they are outside Cargo's normal dependency list.
5. Review package split boundaries, userspace/UAPI treatment, external test tools, firmware and bootloader distribution licenses. Ship no fake kernel image/package now; later user-operated Arch-like installation must preserve rollback as [packaging](packaging.md) requires.
6. Retain provenance/security/update responsibility and a means to reproduce the exact source/binary association. A toolchain/crate/firmware update invalidates affected dispositions until reviewed. Follow [maintenance](maintenance.md).
7. Obtain acceptance of both legal/provenance evidence and independent full behavioral/security/hardware/performance qualification. License clearance alone never means “kernel done.” The strict standing [definition of done](definition-of-done.md), [verification](verification.md), [performance](performance.md) and [bare-metal suite limitations](bare-metal-suite.md) govern claims.

Remaining blockers include artifact-specific distribution/legal review, complete corresponding-source/SBOM/reproducibility records and the unimplemented full Linux scope. The bounded compiler/runtime/loader/firmware identities and local fingerprint-pinned signature verification above are actual evidence, not still-unselected inputs; they do not establish universal trust, broad legal clearance or physical qualification. Only current-workstation physical access is available. Other required hardware and all unexecuted physical/performance gates remain explicit blockers, not a reduced final scope.
