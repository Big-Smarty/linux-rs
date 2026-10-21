// SPDX-License-Identifier: GPL-2.0
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: arch/x86/kernel/cpu/proc.c
// (`show_cpuinfo`), arch/x86/kernel/cpu/common.c (`cpu_detect`,
// `get_model_name`, `cpu_detect_cache_sizes`, `get_cpu_cap`,
// `get_cpu_address_sizes`), arch/x86/kernel/cpu/powerflags.c, and the bug
// rules of arch/x86/kernel/cpu/{amd.c,common.c}.
// Transformation: the CPUID reads become a [`CpuFacts`] snapshot taken by the
// binary; the file text is produced from it by pure code.
#![forbid(unsafe_code)]
//! `/proc/cpuinfo` for one `x86_64` CPU.
//!
//! # Contract
//! * Context: task; pure formatting of a snapshot, allocation through [`Seq`].
//! * shortcut: the capability words are exactly those `get_cpu_cap` fills from
//!   CPUID. Linux's synthetic words (3, 7, 8: `rep_good`, `nopl`,
//!   `constant_tsc`, the scattered leaves, the virtualization words), the
//!   Transmeta/Centaur words, the dependency clearing of `cpuid-deps.c` and
//!   the kernel-configuration masks are not modelled, so `flags` is a subset
//!   of Linux's. The `bugs` line applies the AMD rules and the generic
//!   Spectre/NULL-segment rules; Intel's vulnerability white-list
//!   (`cpu_vuln_whitelist`, the `IA32_ARCH_CAPABILITIES` MSR) is not ported,
//!   so it can name more bugs than Linux does on Intel parts. `microcode` is
//!   omitted (the microcode revision MSR is not read), the Intel cache size
//!   comes from the legacy `0x8000000{5,6}` leaves rather than `cpuid(4)`,
//!   and the topology is one package, one core, one thread. Upgrade each with
//!   its source file.

use crate::{
    seq::{self, Seq},
    vfs::KResult,
};

use super::capflags::{BUG_FLAGS, CAP_FLAGS};

/// `NCAPINTS`.
const NCAPINTS: usize = 22;
/// The first bug bit: `NCAPINTS * 32`.
const BUG_BASE: u16 = 22 * 32;

/// Everything `/proc/cpuinfo` needs from the CPU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuFacts {
    pub cpuid_level: u32,
    pub extended_level: u32,
    pub vendor: [u8; 12],
    pub family: u32,
    pub model: u32,
    pub stepping: u32,
    /// The 48-byte brand string, unprocessed.
    pub model_id: [u8; 48],
    /// `x86_capability[]` for the words CPUID fills.
    pub caps: [u32; NCAPINTS],
    /// `x86_power` (`0x80000007` EDX).
    pub power: u32,
    pub cache_kb: u32,
    pub tlb_size: u32,
    pub clflush: u32,
    pub phys_bits: u32,
    pub virt_bits: u32,
    pub apicid: u32,
    /// The time-stamp-counter frequency in kHz; 0 when unknown.
    pub tsc_khz: u64,
}

impl CpuFacts {
    /// No CPU facts (before the first snapshot).
    pub const EMPTY: Self = Self {
        cpuid_level: 0,
        extended_level: 0,
        vendor: [0; 12],
        family: 0,
        model: 0,
        stepping: 0,
        model_id: [0; 48],
        caps: [0; NCAPINTS],
        power: 0,
        cache_kb: 0,
        tlb_size: 0,
        clflush: 0,
        phys_bits: 0,
        virt_bits: 0,
        apicid: 0,
        tsc_khz: 0,
    };

    /// Read the facts with `cpuid(leaf, subleaf) -> [eax, ebx, ecx, edx]`.
    #[allow(clippy::too_many_lines)] // one straight read of the leaves `get_cpu_cap` reads
    pub fn read(cpuid: impl Fn(u32, u32) -> [u32; 4]) -> Self {
        let mut f = Self::EMPTY;
        let [level, vendor_a, vendor_c, vendor_b] = cpuid(0, 0);
        f.cpuid_level = level;
        f.vendor[0..4].copy_from_slice(&vendor_a.to_le_bytes());
        f.vendor[4..8].copy_from_slice(&vendor_b.to_le_bytes());
        f.vendor[8..12].copy_from_slice(&vendor_c.to_le_bytes());
        // `cpu_detect`: family 4 without leaf 1.
        f.family = 4;
        let mut initial_apic = 0;
        if level >= 1 {
            let [tfms, misc, ecx, edx] = cpuid(1, 0);
            f.family = (tfms >> 8) & 0xf;
            if f.family == 0xf {
                f.family += (tfms >> 20) & 0xff;
            }
            f.model = (tfms >> 4) & 0xf;
            if f.family >= 6 {
                f.model += ((tfms >> 16) & 0xf) << 4;
            }
            f.stepping = tfms & 0xf;
            if edx & (1 << 19) != 0 {
                f.clflush = ((misc >> 8) & 0xff) * 8;
            }
            initial_apic = misc >> 24;
            f.caps[0] = edx;
            f.caps[4] = ecx;
        }
        if level >= 6 {
            f.caps[14] = cpuid(6, 0)[0];
        }
        if level >= 7 {
            let [max_sub, ebx, ecx, edx] = cpuid(7, 0);
            f.caps[9] = ebx;
            f.caps[16] = ecx;
            f.caps[18] = edx;
            if max_sub >= 1 {
                f.caps[12] = cpuid(7, 1)[0];
            }
        }
        if level >= 0xd {
            f.caps[10] = cpuid(0xd, 1)[0];
        }
        if level >= 0xb {
            let [_, _, _, x2apic] = cpuid(0xb, 0);
            f.apicid = x2apic;
        } else {
            f.apicid = initial_apic;
        }
        let ext = cpuid(0x8000_0000, 0)[0];
        f.extended_level = if ext & 0xffff_0000 == 0x8000_0000 {
            ext
        } else {
            0
        };
        let ext = f.extended_level;
        if ext >= 0x8000_0001 {
            let r = cpuid(0x8000_0001, 0);
            f.caps[6] = r[2];
            f.caps[1] = r[3];
        }
        if ext >= 0x8000_0007 {
            let r = cpuid(0x8000_0007, 0);
            f.caps[17] = r[1];
            f.power = r[3];
        }
        if ext >= 0x8000_0008 {
            f.caps[13] = cpuid(0x8000_0008, 0)[1];
        }
        if ext >= 0x8000_000a {
            f.caps[15] = cpuid(0x8000_000a, 0)[3];
        }
        if ext >= 0x8000_001f {
            f.caps[19] = cpuid(0x8000_001f, 0)[0];
        }
        if ext >= 0x8000_0021 {
            f.caps[20] = cpuid(0x8000_0021, 0)[0];
        }
        if ext >= 0x8000_0004 {
            for (i, leaf) in (0x8000_0002u32..=0x8000_0004).enumerate() {
                for (j, word) in cpuid(leaf, 0).iter().enumerate() {
                    let at = i * 16 + j * 4;
                    f.model_id[at..at + 4].copy_from_slice(&word.to_le_bytes());
                }
            }
        }
        // `cpu_detect_cache_sizes`
        if ext >= 0x8000_0005 {
            let r = cpuid(0x8000_0005, 0);
            f.cache_kb = (r[2] >> 24) + (r[3] >> 24);
        }
        if ext >= 0x8000_0006 {
            let r = cpuid(0x8000_0006, 0);
            f.tlb_size = ((r[1] >> 16) & 0xfff) + (r[1] & 0xfff);
            f.cache_kb = r[2] >> 16;
        }
        // `get_cpu_address_sizes`
        if ext < 0x8000_0008 {
            f.clflush = 64;
            f.phys_bits = 36;
            f.virt_bits = 48;
        } else {
            let eax = cpuid(0x8000_0008, 0)[0];
            f.virt_bits = (eax >> 8) & 0xff;
            f.phys_bits = eax & 0xff;
            if f.clflush == 0 {
                f.clflush = 32;
            }
        }
        f
    }

    fn has(&self, bit: usize) -> bool {
        self.caps[bit / 32] & (1 << (bit % 32)) != 0
    }

    fn is_amd(&self) -> bool {
        &self.vendor == b"AuthenticAMD" || &self.vendor == b"HygonGenuine"
    }

    /// The `X86_BUG_*` bits (counted from `NCAPINTS * 32`) this CPU has.
    fn bugs(&self) -> u64 {
        let bit = |n: u32| 1u64 << n;
        let mut bugs = 0;
        // NULL_SEL_CLR_BASE (`0x80000021` EAX bit 6) fixes the segment bug.
        if self.caps[20] & (1 << 6) == 0 {
            bugs |= bit(10); // null_seg
        }
        if self.is_amd() {
            bugs |= bit(8); // sysret_ss_attrs
            // XSAVEERPTR is `0x80000008` EBX bit 2 (word 13).
            if self.family >= 6 && self.caps[13] & (1 << 2) == 0 {
                bugs |= bit(6); // fxsave_leak
            }
            if self.family == 0xf {
                bugs |= bit(11); // swapgs_fence
                if self.model > 0x41 || (self.model == 0x41 && self.stepping >= 2) {
                    bugs |= bit(13); // amd_e400
                }
            }
        }
        bugs |= bit(15) | bit(16) | bit(32 + 5); // spectre_v1, spectre_v2, spectre_v2_user
        bugs
    }
}

/// `x86_power_flags[]`.
const POWER_FLAGS: [&str; 13] = [
    "ts",
    "fid",
    "vid",
    "ttp",
    "tm",
    "stc",
    "100mhzsteps",
    "hwpstate",
    "",
    "cpb",
    "eff_freq_ro",
    "proc_feedback",
    "acc_power",
];

/// `show_cpuinfo` for CPU 0.
///
/// # Errors
/// `ENOMEM`.
pub fn render(f: &CpuFacts, out: &mut Seq) -> KResult<()> {
    let text =
        |bytes: &[u8]| -> usize { bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len()) };
    out.puts("processor\t: 0\nvendor_id\t: ")?;
    let vendor = &f.vendor[..text(&f.vendor)];
    if vendor.is_empty() {
        out.puts("unknown")?;
    } else {
        out.put(vendor)?;
    }
    seq::print(
        out,
        format_args!(
            "\ncpu family\t: {}\nmodel\t\t: {}\nmodel name\t: ",
            f.family, f.model
        ),
    )?;
    // `get_model_name`: leading blanks and trailing blanks removed.
    let name = &f.model_id[..text(&f.model_id)];
    let start = name.iter().position(|&b| b != b' ').unwrap_or(name.len());
    let end = name
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(start, |i| i + 1);
    if start >= end {
        out.puts("unknown")?;
    } else {
        out.put(&name[start..end])?;
    }
    seq::print(out, format_args!("\nstepping\t: {}\n", f.stepping))?;
    if f.has(4) {
        if f.tsc_khz == 0 {
            out.puts("cpu MHz\t\t: Unknown\n")?;
        } else {
            seq::print(
                out,
                format_args!(
                    "cpu MHz\t\t: {}.{:03}\n",
                    f.tsc_khz / 1000,
                    f.tsc_khz % 1000
                ),
            )?;
        }
    }
    if f.cache_kb != 0 {
        seq::print(out, format_args!("cache size\t: {} KB\n", f.cache_kb))?;
    }
    seq::print(
        out,
        format_args!(
            "physical id\t: 0\nsiblings\t: 1\ncore id\t\t: 0\ncpu cores\t: 1\napicid\t\t: {a}\n\
             initial apicid\t: {a}\nfpu\t\t: yes\nfpu_exception\t: yes\ncpuid level\t: {}\nwp\t\t: yes\n",
            f.cpuid_level,
            a = f.apicid
        ),
    )?;
    out.puts("flags\t\t:")?;
    for &(bit, name) in CAP_FLAGS.iter().filter(|(bit, _)| *bit < BUG_BASE) {
        if f.has(usize::from(bit)) {
            out.putc(b' ')?;
            out.puts(name)?;
        }
    }
    out.puts("\nbugs\t\t:")?;
    let bugs = f.bugs();
    for &(bit, name) in BUG_FLAGS {
        if bugs & (1 << u32::from(bit)) != 0 {
            out.putc(b' ')?;
            out.puts(name)?;
        }
    }
    // `loops_per_jiffy` is the TSC frequency per jiffy (HZ = 1000 here).
    let lpj = f.tsc_khz;
    seq::print(
        out,
        format_args!("\nbogomips\t: {}.{:02}\n", lpj / 500, (lpj / 5) % 100),
    )?;
    if f.tlb_size > 0 {
        seq::print(out, format_args!("TLB size\t: {} 4K pages\n", f.tlb_size))?;
    }
    seq::print(
        out,
        format_args!(
            "clflush size\t: {}\ncache_alignment\t: {}\naddress sizes\t: {} bits physical, {} bits virtual\n",
            f.clflush, f.clflush, f.phys_bits, f.virt_bits
        ),
    )?;
    out.puts("power management:")?;
    for i in 0..32 {
        if f.power & (1 << i) != 0 {
            match POWER_FLAGS.get(i) {
                Some(name) => {
                    if !name.is_empty() {
                        out.putc(b' ')?;
                    }
                    out.puts(name)?;
                }
                None => seq::print(out, format_args!(" [{i}]"))?,
            }
        }
    }
    out.puts("\n\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn qemu64(leaf: u32, _sub: u32) -> [u32; 4] {
        match leaf {
            0 => [13, 0x6874_7541, 0x444d_4163, 0x6974_6e65],
            1 => [0x0006_0fb1, 0x0001_0800, 0x8000_2001, 0x078b_fbfd],
            0x8000_0000 => [0x8000_000a, 0, 0, 0],
            0x8000_0001 => [0x0006_0fb1, 0, 0x0000_0101, 0x2191_abfd],
            0x8000_0006 => [0, 0x0400_0000 | 0x0000_0400, 0x0200_0000, 0],
            0x8000_0008 => [0x0000_3028, 0, 0, 0],
            _ => [0; 4],
        }
    }

    #[test]
    fn decodes_family_model_stepping_and_vendor() {
        let f = CpuFacts::read(qemu64);
        assert_eq!((f.family, f.model, f.stepping), (15, 107, 1));
        assert_eq!(&f.vendor, b"AuthenticAMD");
        assert_eq!((f.phys_bits, f.virt_bits, f.clflush), (40, 48, 64));
        assert_eq!(f.cache_kb, 512);
    }

    #[test]
    fn flags_follow_the_word_order() {
        let mut f = CpuFacts::read(qemu64);
        f.tsc_khz = 5_399_968;
        let mut s = Seq::new();
        render(&f, &mut s).unwrap();
        let text = core::str::from_utf8(s.as_bytes()).unwrap();
        assert!(text.contains("flags\t\t: fpu de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 "));
        assert!(text.contains(" syscall nx lm "));
        assert!(text.contains("\nbugs\t\t: fxsave_leak sysret_ss_attrs null_seg swapgs_fence amd_e400 spectre_v1 spectre_v2 spectre_v2_user\nbogomips\t: 10799.93\n"));
        assert!(text.ends_with("power management:\n\n"));
    }
}
