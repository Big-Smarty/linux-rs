// SPDX-License-Identifier: GPL-2.0-only AND (GPL-2.0 WITH Linux-syscall-note)
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: fs/binfmt_elf.c
// (`create_elf_tables`, GPL-2.0-only), fs/exec.c (`kernel_execve`,
// `setup_arg_pages`; GPL-2.0-only), mm/vma_exec.c (`create_init_stack_vma`),
// arch/x86/include/asm/elf.h (`ARCH_DLINFO`, `ELF_HWCAP`, `ELF_PLATFORM`),
// arch/x86/kernel/process.c (`arch_align_stack`), arch/x86/kernel/signal.c
// (`init_sigframe_size`, GPL-2.0), arch/x86/include/asm/sigframe.h and
// uapi/asm/sigcontext.h (struct sizes), include/uapi/linux/auxvec.h
// (GPL-2.0 WITH Linux-syscall-note). Constants only from the uapi headers.
// Transformation: the kernel builds the final stack image directly into a
// caller-provided window instead of copying strings between mm structures.
#![forbid(unsafe_code)]
//! The initial user stack of `/init`, byte for byte as Linux builds it.
//!
//! Configuration reproduced: `x86_64`, `norandmaps` (no stack, brk or
//! `arch_align_stack` randomisation), `vdso=0` (no `AT_SYSINFO_EHDR`),
//! `CONFIG_RSEQ=n` (no `AT_RSEQ_*`; rseq(2) is not implemented), root
//! credentials, not secure-exec, no interpreter.
//!
//! Layout from the top: one empty pointer slot, the exec filename, `envp`
//! strings, `argv` strings, 16-byte alignment, the platform string, 16 random
//! bytes, the auxiliary vector, then `argc`, `argv[]`, NULL, `envp[]`, NULL,
//! rounded so `rsp` is 16-byte aligned at entry. `argv[0]` is the lowest string.

use super::args::Word;
use crate::{memory::PAGE, usercopy::TASK_SIZE_MAX};

/// `STACK_TOP = TASK_SIZE_LOW = DEFAULT_MAP_WINDOW` (no randomisation).
pub const STACK_TOP: u64 = TASK_SIZE_MAX;
/// Pages that hold the argument block (strings, vectors).
pub const ARG_PAGES: usize = 4;
/// `setup_arg_pages` expands the stack VMA by `stack_expand = 128 KiB`.
pub const EXPAND_PAGES: usize = 32;
/// shortcut: the stack never grows past this fixed extent (Linux grows it on
/// demand up to `RLIMIT_STACK`, 8 MiB). Upgrade with a user page-fault handler
/// that can allocate frames.
pub const STACK_PAGES: usize = ARG_PAGES + EXPAND_PAGES;
pub const STACK_START: u64 = STACK_TOP - (STACK_PAGES as u64) * PAGE;
/// The window [`build`] fills: the top `ARG_PAGES` pages.
pub const WINDOW_BYTES: usize = ARG_PAGES * crate::memory::PAGE_BYTES;

pub const PLATFORM: &[u8] = b"x86_64\0";
pub const ENVP: [Word<'static>; 2] = [Word::plain(b"HOME=/"), Word::plain(b"TERM=linux")];

// uapi/linux/auxvec.h and asm/auxvec.h
pub const AT_NULL: u64 = 0;
pub const AT_PHDR: u64 = 3;
pub const AT_PHENT: u64 = 4;
pub const AT_PHNUM: u64 = 5;
pub const AT_PAGESZ: u64 = 6;
pub const AT_BASE: u64 = 7;
pub const AT_FLAGS: u64 = 8;
pub const AT_ENTRY: u64 = 9;
pub const AT_UID: u64 = 11;
pub const AT_EUID: u64 = 12;
pub const AT_GID: u64 = 13;
pub const AT_EGID: u64 = 14;
pub const AT_PLATFORM: u64 = 15;
pub const AT_HWCAP: u64 = 16;
pub const AT_CLKTCK: u64 = 17;
pub const AT_SECURE: u64 = 23;
pub const AT_RANDOM: u64 = 25;
pub const AT_HWCAP2: u64 = 26;
pub const AT_EXECFN: u64 = 31;
pub const AT_MINSIGSTKSZ: u64 = 51;

/// `USER_HZ` / `CLOCKS_PER_SEC`.
pub const CLKTCK: u64 = 100;

/// Values that vary per boot or per image.
#[derive(Clone, Copy, Debug)]
pub struct Aux {
    /// `boot_cpu_data.x86_capability[CPUID_1_EDX]`.
    pub hwcap: u32,
    pub phdr: u64,
    pub phnum: u16,
    pub entry: u64,
    pub random: [u8; 16],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StackError {
    /// `-E2BIG`: the block does not fit the window.
    TooBig,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Built {
    /// Initial `rsp`.
    pub sp: u64,
    pub argc: u64,
    /// `AT_EXECFN` string address.
    pub execfn: u64,
    pub random: u64,
}

struct Window<'a> {
    bytes: &'a mut [u8],
    base: u64,
}

impl Window<'_> {
    fn put(&mut self, address: u64, data: &[u8]) -> Result<(), StackError> {
        let start = usize::try_from(address.checked_sub(self.base).ok_or(StackError::TooBig)?)
            .map_err(|_| StackError::TooBig)?;
        let end = start.checked_add(data.len()).ok_or(StackError::TooBig)?;
        self.bytes
            .get_mut(start..end)
            .ok_or(StackError::TooBig)?
            .copy_from_slice(data);
        Ok(())
    }
    fn word(&mut self, address: u64, value: u64) -> Result<(), StackError> {
        self.put(address, &value.to_le_bytes())
    }
    /// Copy NUL-terminated strings upward from `start`; returns the end.
    fn strings<'w>(
        &mut self,
        start: u64,
        words: impl Iterator<Item = Word<'w>>,
    ) -> Result<u64, StackError> {
        let mut at = start;
        for word in words {
            for byte in word.bytes() {
                self.put(at, &[byte])?;
                at += 1;
            }
            self.put(at, &[0])?;
            at += 1;
        }
        Ok(at)
    }
}

fn size<'w>(mut words: impl Iterator<Item = Word<'w>>) -> Result<u64, StackError> {
    words.try_fold(0u64, |total, word| {
        total
            .checked_add(word.len() as u64 + 1)
            .ok_or(StackError::TooBig)
    })
}

/// Build the stack block into `window`, which covers
/// `[STACK_TOP - window.len(), STACK_TOP)`. Zero-filled on entry; bytes below
/// the final `rsp` are left untouched.
///
/// # Errors
/// [`StackError::TooBig`] when the block would not fit the window (Linux
/// `-E2BIG` for argument sizes, `-EFAULT` if the stack could not grow).
pub fn build<'w>(
    window: &mut [u8],
    filename: &[u8],
    argv: impl Iterator<Item = Word<'w>> + Clone,
    envp: impl Iterator<Item = Word<'w>> + Clone,
    aux: &Aux,
) -> Result<Built, StackError> {
    let base = STACK_TOP
        .checked_sub(window.len() as u64)
        .ok_or(StackError::TooBig)?;
    let mut stack = Window {
        bytes: window,
        base,
    };
    let fits = |p: u64, length: u64| {
        p.checked_sub(length)
            .filter(|&p| p >= base)
            .ok_or(StackError::TooBig)
    };

    // __bprm_mm_init / create_init_stack_vma: bprm->p = vm_end - sizeof(void *)
    let mut p = STACK_TOP - 8;
    // copy_string_kernel(bprm->filename); bprm->exec = bprm->p
    p = fits(p, filename.len() as u64 + 1)?;
    stack.put(p, filename)?;
    let execfn = p;
    // copy_strings_kernel(envc, envp), then (argc, argv): argv[0] ends lowest.
    p = fits(p, size(envp.clone())?)?;
    stack.strings(p, envp.clone())?;
    let env_start = p;
    p = fits(p, size(argv.clone())?)?;
    stack.strings(p, argv.clone())?;
    let arg_start = p;

    // create_elf_tables
    p = fits(p & !0xf, 0)?; // arch_align_stack with norandmaps
    p = fits(p, PLATFORM.len() as u64)?;
    stack.put(p, PLATFORM)?;
    let platform = p;
    p = fits(p, 16)?;
    stack.put(p, &aux.random)?;
    let random = p;

    let auxv: [(u64, u64); 19] = [
        (AT_MINSIGSTKSZ, crate::xstate::max_frame_size()),
        (AT_HWCAP, u64::from(aux.hwcap)),
        (AT_PAGESZ, PAGE),
        (AT_CLKTCK, CLKTCK),
        (AT_PHDR, aux.phdr),
        (AT_PHENT, super::plan::PHENT),
        (AT_PHNUM, u64::from(aux.phnum)),
        (AT_BASE, 0),
        (AT_FLAGS, 0),
        (AT_ENTRY, aux.entry),
        (AT_UID, 0),
        (AT_EUID, 0),
        (AT_GID, 0),
        (AT_EGID, 0),
        (AT_SECURE, 0),
        (AT_RANDOM, random),
        (AT_HWCAP2, 0),
        (AT_EXECFN, execfn),
        (AT_PLATFORM, platform),
    ];
    // ei_index counts the AT_NULL pair too.
    let ei_words = 2 * (auxv.len() as u64 + 1);
    let arg_count = argv.clone().count() as u64;
    let env_count = envp.clone().count() as u64;
    let items = (arg_count + 1) + (env_count + 1) + 1;
    // STACK_ROUND(STACK_ADD(p, ei_index), items)
    let sp = fits(p, 8 * ei_words)?;
    let sp = fits(sp, 8 * items)? & !15;
    if sp < base {
        return Err(StackError::TooBig);
    }

    let mut at = sp;
    stack.word(at, arg_count)?;
    at += 8;
    let mut string = arg_start;
    for word in argv {
        stack.word(at, string)?;
        at += 8;
        string += word.len() as u64 + 1;
    }
    stack.word(at, 0)?;
    at += 8;
    let mut string = env_start;
    for word in envp {
        stack.word(at, string)?;
        at += 8;
        string += word.len() as u64 + 1;
    }
    stack.word(at, 0)?;
    at += 8;
    for (id, value) in auxv {
        stack.word(at, id)?;
        stack.word(at + 8, value)?;
        at += 16;
    }
    stack.word(at, AT_NULL)?;
    stack.word(at + 8, 0)?;
    Ok(Built {
        sp,
        argc: arg_count,
        execfn,
        random,
    })
}

/// `SplitMix64` (Vigna): expands a 64-bit seed into the 16 `AT_RANDOM` bytes.
/// shortcut: only used when RDRAND is absent; the seed (TSC and addresses) is
/// predictable, so `AT_RANDOM` is NOT cryptographically random on such a CPU.
/// Upgrade when the kernel has an entropy pool (`get_random_bytes`).
#[must_use]
pub fn weak_random(seed: u64) -> [u8; 16] {
    let mut state = seed;
    let mut out = [0; 16];
    for half in out.as_chunks_mut::<8>().0 {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        *half = (z ^ (z >> 31)).to_le_bytes();
    }
    out
}

#[cfg(test)]
mod tests;
