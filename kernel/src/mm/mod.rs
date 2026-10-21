// SPDX-License-Identifier: GPL-2.0-only
#![forbid(unsafe_code)]
//! Linux memory-mapping semantics as pure, host-tested library code.
//!
//! Reproduces, for one single-threaded process under the declared
//! configuration (x86-64, 4-level paging, `norandmaps`, no THP, no KSM, no
//! userfaultfd, no protection keys, `CONFIG_COMPAT_BRK=n`), the VMA set,
//! mmap placement, and the decisions of `mmap`, `munmap`, `mprotect`, `brk`,
//! `madvise` and the user page fault of Linux 6.18.57. Page-table effects go through
//! the [`UserPages`] trait; the kernel binary implements it on its tables.
//! See `docs/implementation.md#memory-mapping-model`.

mod env;
mod fault;
mod flags;
mod layout;
mod madvise;
mod ops;
mod pt;
mod remap;
mod space;

#[cfg(test)]
pub(crate) mod tests;

pub use env::{Env, FileInfo, Overcommit, RLIM_INFINITY, STK_LIM};
pub use fault::{
    FaultOutcome, PF_INSTR, PF_PK, PF_PROT, PF_RSVD, PF_SGX, PF_SHSTK, PF_USER, PF_WRITE, SegvCode,
    VSYSCALL_ADDR, pkru_denies_key0,
};
pub use flags::*;
pub use layout::{DEFAULT_MAP_WINDOW, mmap_address_hint_valid, pick_mmap_base, round_hint_to_min};
pub use madvise::{
    Madvise, Unsupported as MadviseUnsupported, madvise_behavior_valid, madvise_range,
};
pub use ops::{FileMapping, Mmap, Unsupported, mmap_off_to_pgoff};
pub use pt::{OutOfMemory, Pte, UserPages};
pub use remap::{MREMAP_DONTUNMAP, MREMAP_FIXED, MREMAP_MAYMOVE};
pub use space::{Mm, TASK_SIZE, Vma};
