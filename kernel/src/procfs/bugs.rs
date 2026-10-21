// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: fs/proc/array.c (`task_seccomp`
// text mapping), arch/x86/kernel/cpu/bugs.c (`ssb_prctl_get`, `ib_prctl_get`).
// GPL-2.0.
#![forbid(unsafe_code)]
//! The speculation-control lines of `/proc/<pid>/status`.
//!
//! shortcut: the x86 CPU bug database (`cpu_set_bug_bits`, the vulnerability
//! white- and black-lists) is not ported, and this kernel enables no
//! speculation mitigation (`PR_SET_SPECULATION_CTRL` is not implemented). The
//! texts are those of a CPU the whitelist lists as not affected by Speculative
//! Store Bypass (`NO_SSB`) with `spectre_v2_user` mitigations off, which is
//! what the `qemu64` CPU of the reference run reports. Upgrade with the bug
//! database; until then the lines on real hardware may differ from Linux's.

/// `Speculation_Store_Bypass:`.
#[must_use]
pub const fn ssb_text() -> &'static str {
    "not vulnerable"
}

/// `SpeculationIndirectBranch:`.
#[must_use]
pub const fn ib_text() -> &'static str {
    "always enabled"
}
