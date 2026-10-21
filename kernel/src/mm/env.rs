// SPDX-License-Identifier: GPL-2.0-only
// Linux 6.18.57 (2ff600d29ee478d0a8d46ef8a58afb5e038fe692): mm/mmap.c
// (`sysctl_max_map_count` users, `mlock_future_ok`, `can_do_mlock` callers),
// mm/util.c `__vm_enough_memory` (OVERCOMMIT_ALWAYS / OVERCOMMIT_GUESS),
// include/linux/mm.h `stack_guard_gap`, include/asm-generic/resource.h
// (`INIT_RLIMITS`), security/min_addr.c, security/commoncap.c
// `cap_mmap_addr`. GPL-2.0.
#![forbid(unsafe_code)]
//! Everything outside the address space that the memory-mapping rules read:
//! rlimits, sysctls and the two capabilities involved. Passed by reference so
//! `setrlimit`/`sysctl` changes need no `Mm` mutation.

use super::flags::PAGE_SHIFT;

/// `RLIM_INFINITY`.
pub const RLIM_INFINITY: u64 = u64::MAX;
/// `_STK_LIM`: the default `RLIMIT_STACK` soft limit, 8 MiB.
pub const STK_LIM: u64 = 8 * 1024 * 1024;

/// `sysctl_overcommit_memory`. `OVERCOMMIT_NEVER` (2) needs the global
/// `vm_committed_as` counter and the commit limit, which belong to the
/// frame-accounting owner; it is not representable here rather than silently
/// treated as another mode.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Overcommit {
    /// Mode 1.
    Always,
    /// Mode 0: refuse only a request larger than RAM plus swap.
    Guess {
        total_ram_pages: u64,
        total_swap_pages: u64,
    },
}

#[derive(Clone, Copy, Debug)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "one flag per fact the rules read (capabilities, boot options, CPU features)"
)]
pub struct Env {
    /// `RLIMIT_STACK` soft limit.
    pub rlimit_stack: u64,
    /// `RLIMIT_DATA` soft and hard limits.
    pub rlimit_data: u64,
    pub rlimit_data_max: u64,
    /// `RLIMIT_AS` soft limit.
    pub rlimit_as: u64,
    /// `RLIMIT_MEMLOCK` soft limit in bytes.
    pub rlimit_memlock: u64,
    /// `sysctl vm.max_map_count`.
    pub max_map_count: u32,
    /// `stack_guard_gap` in bytes (`stack_guard_gap=` boot option, pages).
    pub stack_guard_gap: u64,
    /// `mmap_min_addr` (`CONFIG_DEFAULT_MMAP_MIN_ADDR=4096` in the reference).
    pub mmap_min_addr: u64,
    pub overcommit: Overcommit,
    /// `capable(CAP_IPC_LOCK)`.
    pub cap_ipc_lock: bool,
    /// `capable(CAP_SYS_RAWIO)`: lets a mapping below `dac_mmap_min_addr`.
    pub cap_sys_rawio: bool,
    /// `ignore_rlimit_data` boot parameter.
    pub ignore_rlimit_data: bool,
    /// `cpu_feature_enabled(X86_FEATURE_OSPKE)`: protection keys are on, so a `PROT_EXEC`-only
    /// mapping would get the execute-only key (`execute_only_pkey`), which this model does not
    /// carry (no `VM_PKEY_BIT*`, no key in the page tables, no `pkey_alloc` state): those
    /// requests end in [`super::Unsupported::ExecuteOnlyPkey`], a loud stop.
    pub ospke: bool,
}

impl Env {
    /// Root init on the reference configuration: default `INIT_RLIMITS`,
    /// `vm.max_map_count` 65530, `stack_guard_gap` 256 pages, all capabilities.
    #[must_use]
    pub const fn init(total_ram_pages: u64, total_swap_pages: u64) -> Self {
        Self {
            rlimit_stack: STK_LIM,
            rlimit_data: RLIM_INFINITY,
            rlimit_data_max: RLIM_INFINITY,
            rlimit_as: RLIM_INFINITY,
            // MLOCK_LIMIT = 8 MiB (include/linux/mm.h) for unprivileged; the
            // init task's limit is the INIT_RLIMITS value.
            rlimit_memlock: 8 * 1024 * 1024,
            max_map_count: 65530,
            stack_guard_gap: 256 << PAGE_SHIFT,
            mmap_min_addr: 4096,
            overcommit: Overcommit::Guess {
                total_ram_pages,
                total_swap_pages,
            },
            cap_ipc_lock: true,
            cap_sys_rawio: true,
            ignore_rlimit_data: false,
            ospke: false,
        }
    }

    /// `security_vm_enough_memory_mm` -> `cap_vm_enough_memory` ->
    /// `__vm_enough_memory`. `true` = enough (0 in Linux). Commit accounting
    /// (`vm_acct_memory`) is not tracked, see `Overcommit`.
    #[must_use]
    pub(super) fn enough_memory(&self, pages: u64) -> bool {
        match self.overcommit {
            Overcommit::Always => true,
            Overcommit::Guess {
                total_ram_pages,
                total_swap_pages,
            } => pages <= total_ram_pages.saturating_add(total_swap_pages),
        }
    }
}

/// The facts about an open file that `do_mmap` reads (mm/mmap.c 394-446).
/// The VFS owner fills it; nothing here dereferences the file.
#[allow(
    clippy::struct_excessive_bools,
    reason = "one flag per fact `do_mmap` reads from the file"
)]
#[derive(Clone, Copy, Debug)]
pub struct FileInfo {
    /// Identity of the open file description (`vma->vm_file`): two VMAs merge
    /// only if this is equal.
    pub id: u64,
    /// `file->f_mode & FMODE_READ` / `FMODE_WRITE`.
    pub readable: bool,
    pub writable: bool,
    /// `path_noexec(&file->f_path)`.
    pub noexec: bool,
    /// `IS_SWAPFILE`, `IS_APPEND(inode)`.
    pub swapfile: bool,
    pub append_only: bool,
    /// `can_mmap_file`: the file has `->mmap`/`->mmap_prepare`.
    pub can_mmap: bool,
    /// `file_mmap_size_max`: `MAX_LFS_FILESIZE` for regular, block and socket
    /// files, `u64::MAX` otherwise, 0 for `FOP_UNSIGNED_OFFSET`.
    pub mmap_size_max: u64,
    /// `FOP_MMAP_SYNC`.
    pub mmap_sync: bool,
    /// `is_file_hugepages`.
    pub hugepages: bool,
}
