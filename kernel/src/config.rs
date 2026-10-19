// SPDX-License-Identifier: GPL-2.0-only
// Citations are to the pinned Linux 6.18.57 tree, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692 (GPL-2.0 and GPL-2.0-only files).
#![forbid(unsafe_code)]
//! The one declared Linux configuration this kernel claims to behave like.
//!
//! "Equivalent to a Linux option" must be behaviour, not wording: every entry
//! names the pinned source that defines the behaviour and, where the option
//! turns a syscall off, the exact syscall numbers that then answer `-ENOSYS`
//! (`kernel/sys_ni.c` `COND_SYSCALL`). The reference oracle was booted with
//! `target/linux-reference/artifacts/reference.config`; the declared
//! configuration differs from it on purpose where noted, and an oracle line is
//! only comparable after removing what the difference adds (`AT_RSEQ_*`).

/// One declared option.
#[derive(Clone, Copy, Debug)]
pub struct Declared {
    /// Kconfig symbol or boot parameter.
    pub symbol: &'static str,
    pub value: &'static str,
    /// Pinned source lines that define the behaviour.
    pub source: &'static str,
    /// Syscalls answered with `-ENOSYS` because of this option.
    pub enosys: &'static [u32],
}

pub const DECLARED: [Declared; 9] = [
    Declared {
        symbol: "boot: norandmaps",
        value: "randomize_va_space=0: STACK_TOP fixed, no arch_align_stack/brk randomisation",
        source: "fs/binfmt_elf.c:1020-1022, arch/x86/kernel/process.c:1019-1024",
        enosys: &[],
    },
    Declared {
        symbol: "boot: vdso=0",
        value: "vdso64_enabled=0: no AT_SYSINFO_EHDR",
        source: "arch/x86/include/asm/elf.h:331-337",
        enosys: &[],
    },
    Declared {
        symbol: "boot: noxsave",
        value: "FXSAVE-only FPU state (x87 and SSE still run): AT_MINSIGSTKSZ 0x5a0",
        source: "arch/x86/kernel/fpu/signal.c:511-531, arch/x86/kernel/signal.c:214-226",
        enosys: &[],
    },
    Declared {
        symbol: "boot: nofsgsbase",
        value: "CR4.FSGSBASE clear: AT_HWCAP2 = 0",
        source: "arch/x86/kernel/cpu/common.c:2399-2402",
        enosys: &[],
    },
    Declared {
        symbol: "CONFIG_RSEQ",
        value: "n (reference config: y): no AT_RSEQ_*, rseq(2) is -ENOSYS",
        source: "init/Kconfig:1910, fs/binfmt_elf.c:287 and the #ifdef in create_elf_tables, kernel/sys_ni.c:392",
        enosys: &[334],
    },
    Declared {
        symbol: "CONFIG_X86_USER_SHADOW_STACK",
        value: "n (as the reference config): map_shadow_stack(2) is -ENOSYS",
        source: "arch/x86/Kconfig:1876, kernel/sys_ni.c:294",
        enosys: &[453],
    },
    Declared {
        symbol: "CONFIG_UPROBES",
        value: "n (reference config: y): uretprobe(2) and uprobe(2) are -ENOSYS",
        source: "kernel/sys_ni.c:394-395, arch/x86/kernel/uprobes.c:367,818",
        enosys: &[335, 336],
    },
    Declared {
        symbol: "CONFIG_X86_X32_ABI",
        value: "n (as the reference config): numbers with __X32_SYSCALL_BIT are -ENOSYS",
        source: "arch/x86/entry/syscall_64.c:69-82",
        enosys: &[],
    },
    Declared {
        symbol: "CONFIG_IA32_EMULATION=y with boot ia32_emulation=0",
        value: "y (sigframe_ia32 sizing: AT_MINSIGSTKSZ 0x5a0 equals the oracle) but ia32_enabled() is false: no int $0x80 gate (#GP), no SYSENTER/compat SYSCALL entry (CSTAR -> -ENOSYS stub, SYSENTER MSRs zero)",
        source: "arch/x86/kernel/signal.c:181-185, arch/x86/kernel/idt.c:124-126 and 233-239, arch/x86/kernel/cpu/common.c:2230-2252, arch/x86/include/asm/ia32.h:84",
        enosys: &[],
    },
];

/// `rseq` presence in the auxiliary vector follows `CONFIG_RSEQ`.
pub const RSEQ: bool = false;

/// Is `number` a syscall that a declared option turns into `-ENOSYS`?
#[must_use]
pub fn is_disabled_syscall(number: u32) -> bool {
    DECLARED.iter().any(|entry| entry.enosys.contains(&number))
}

#[cfg(test)]
mod tests {
    use super::{DECLARED, RSEQ, is_disabled_syscall};
    use syscalls::Sysno;

    #[test]
    fn disabled_syscalls_are_the_cond_syscalls_of_the_declared_options() {
        assert_eq!(Sysno::rseq as u32, 334);
        assert_eq!(Sysno::map_shadow_stack as u32, 453);
        assert_eq!(Sysno::uretprobe as u32, 335);
        assert_eq!(Sysno::uprobe as u32, 336);
        for number in [334, 453, 335, 336] {
            assert!(is_disabled_syscall(number));
        }
        for number in [0, 1, 39, 60, 231, 333, 337, 452, 454] {
            assert!(!is_disabled_syscall(number));
        }
        const { assert!(!RSEQ) };
        for entry in DECLARED {
            assert!(
                !entry.source.is_empty() && !entry.value.is_empty(),
                "{}",
                entry.symbol
            );
            assert!(
                entry
                    .enosys
                    .iter()
                    .all(|&n| Sysno::new(n as usize).is_some())
            );
        }
    }
}
