// SPDX-License-Identifier: GPL-2.0-only
// Linux 6.18.57 (2ff600d29ee478d0a8d46ef8a58afb5e038fe692), GPL-2.0 with the
// Linux-syscall-note for the uapi values: include/linux/mm.h (`VM_*`, 266-540),
// include/linux/mman.h (`calc_vm_prot_bits`, `calc_vm_flag_bits`),
// include/uapi/asm-generic/mman-common.h, include/uapi/linux/mman.h,
// arch/x86/include/uapi/asm/mman.h, mm/vma.h (`is_*_mapping`).
// Transformation: the VMA flag word is a typed newtype holding only the bits
// that exist in the declared configuration; bits of disabled options
// (`VM_SOFTDIRTY`, `VM_SHADOW_STACK`, `VM_GROWSUP`, protection keys,
// `VM_HUGEPAGE`/`VM_NOHUGEPAGE`) are absent instead of defined as zero.
#![forbid(unsafe_code)]
//! VMA flags, the `mmap`/`mprotect` ABI constants and the pure flag algebra.

use core::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, Not};

pub use crate::memory::PAGE as PAGE_SIZE;

/// `PAGE_SHIFT`.
pub const PAGE_SHIFT: u32 = 12;
/// `PAGE_ALIGN(x)`; `None` where Linux's unsigned arithmetic wraps to 0.
#[must_use]
pub const fn page_align(x: u64) -> Option<u64> {
    match x.checked_add(PAGE_SIZE - 1) {
        Some(v) => Some(v & !(PAGE_SIZE - 1)),
        None => None,
    }
}
/// `PAGE_MASK` applied: round down.
#[must_use]
pub const fn page_floor(x: u64) -> u64 {
    x & !(PAGE_SIZE - 1)
}
#[must_use]
pub const fn offset_in_page(x: u64) -> u64 {
    x & (PAGE_SIZE - 1)
}

/// `vm_flags_t` restricted to the bits of the declared configuration.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct VmFlags(pub u64);

impl VmFlags {
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(0x1);
    pub const WRITE: Self = Self(0x2);
    pub const EXEC: Self = Self(0x4);
    pub const SHARED: Self = Self(0x8);
    pub const MAYREAD: Self = Self(0x10);
    pub const MAYWRITE: Self = Self(0x20);
    pub const MAYEXEC: Self = Self(0x40);
    pub const MAYSHARE: Self = Self(0x80);
    pub const GROWSDOWN: Self = Self(0x100);
    pub const PFNMAP: Self = Self(0x400);
    pub const LOCKED: Self = Self(0x2000);
    pub const IO: Self = Self(0x4000);
    pub const DONTEXPAND: Self = Self(0x4_0000);
    pub const LOCKONFAULT: Self = Self(0x8_0000);
    pub const ACCOUNT: Self = Self(0x10_0000);
    pub const NORESERVE: Self = Self(0x20_0000);
    pub const HUGETLB: Self = Self(0x40_0000);
    pub const SYNC: Self = Self(0x80_0000);
    pub const WIPEONFORK: Self = Self(0x200_0000);
    pub const DONTDUMP: Self = Self(0x400_0000);
    pub const MIXEDMAP: Self = Self(0x1000_0000);
    /// `VM_DROPPABLE` is bit 40 under `CONFIG_64BIT`.
    pub const DROPPABLE: Self = Self(1 << 40);

    /// `VM_ACCESS_FLAGS`.
    pub const ACCESS: Self = Self(0x7);
    /// `VM_SPECIAL`: non-mergeable, non-mlockable.
    pub const SPECIAL: Self = Self(0x4000 | 0x4_0000 | 0x400 | 0x1000_0000);
    /// `VM_STACK` (`CONFIG_STACK_GROWSUP` is n).
    pub const STACK: Self = Self::GROWSDOWN;
    /// `VM_DATA_FLAGS_TSK_EXEC` for a task without `READ_IMPLIES_EXEC`
    /// (64-bit tasks: `elf_read_implies_exec` is 32-bit only).
    pub const DATA_DEFAULT: Self = Self(0x1 | 0x2 | 0x10 | 0x20 | 0x40);
    /// `VM_STACK_FLAGS`.
    pub const STACK_FLAGS: Self = Self(Self::STACK.0 | Self::DATA_DEFAULT.0 | Self::ACCOUNT.0);
    /// `VM_IGNORE_MERGE` (`VM_STICKY`): `VM_SOFTDIRTY` is 0 without
    /// `CONFIG_MEM_SOFT_DIRTY` and `VM_MAYBE_GUARD` is never set (no
    /// `MADV_GUARD_INSTALL` yet), so nothing is ignored.
    pub const IGNORE_MERGE: Self = Self(0);

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}
impl BitOr for VmFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}
impl BitAnd for VmFlags {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}
impl Not for VmFlags {
    type Output = Self;
    fn not(self) -> Self {
        Self(!self.0)
    }
}
impl BitOrAssign for VmFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}
impl BitAndAssign for VmFlags {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

/// mm/vma.h `is_exec_mapping`.
#[must_use]
pub const fn is_exec_mapping(f: VmFlags) -> bool {
    f.0 & (VmFlags::EXEC.0 | VmFlags::WRITE.0 | VmFlags::STACK.0) == VmFlags::EXEC.0
}
/// mm/vma.h `is_stack_mapping` (no `VM_SHADOW_STACK` in this configuration).
#[must_use]
pub const fn is_stack_mapping(f: VmFlags) -> bool {
    f.contains(VmFlags::STACK)
}
/// mm/vma.h `is_data_mapping`.
#[must_use]
pub const fn is_data_mapping(f: VmFlags) -> bool {
    f.0 & (VmFlags::WRITE.0 | VmFlags::SHARED.0 | VmFlags::STACK.0) == VmFlags::WRITE.0
}

pub const PROT_NONE: u64 = 0x0;
pub const PROT_READ: u64 = 0x1;
pub const PROT_WRITE: u64 = 0x2;
pub const PROT_EXEC: u64 = 0x4;
pub const PROT_SEM: u64 = 0x8;
pub const PROT_GROWSDOWN: u64 = 0x0100_0000;
pub const PROT_GROWSUP: u64 = 0x0200_0000;

pub const MAP_SHARED: u64 = 0x01;
pub const MAP_PRIVATE: u64 = 0x02;
pub const MAP_SHARED_VALIDATE: u64 = 0x03;
pub const MAP_DROPPABLE: u64 = 0x08;
pub const MAP_TYPE: u64 = 0x0f;
pub const MAP_FIXED: u64 = 0x10;
pub const MAP_ANONYMOUS: u64 = 0x20;
pub const MAP_32BIT: u64 = 0x40;
pub const MAP_ABOVE4G: u64 = 0x80;
pub const MAP_GROWSDOWN: u64 = 0x0100;
pub const MAP_DENYWRITE: u64 = 0x0800;
pub const MAP_EXECUTABLE: u64 = 0x1000;
pub const MAP_LOCKED: u64 = 0x2000;
pub const MAP_NORESERVE: u64 = 0x4000;
pub const MAP_POPULATE: u64 = 0x8000;
pub const MAP_NONBLOCK: u64 = 0x1_0000;
pub const MAP_STACK: u64 = 0x2_0000;
pub const MAP_HUGETLB: u64 = 0x4_0000;
pub const MAP_SYNC: u64 = 0x8_0000;
pub const MAP_FIXED_NOREPLACE: u64 = 0x10_0000;
pub const MAP_UNINITIALIZED: u64 = 0x400_0000;
/// `MAP_HUGE_SHIFT` encodings (`hugetlb_encode.h`).
pub const MAP_HUGE_2MB: u64 = 21 << 26;
pub const MAP_HUGE_1GB: u64 = 30 << 26;
/// include/linux/mman.h `LEGACY_MAP_MASK`.
pub const LEGACY_MAP_MASK: u64 = MAP_SHARED
    | MAP_PRIVATE
    | MAP_FIXED
    | MAP_ANONYMOUS
    | MAP_DENYWRITE
    | MAP_EXECUTABLE
    | MAP_GROWSDOWN
    | MAP_LOCKED
    | MAP_NORESERVE
    | MAP_POPULATE
    | MAP_NONBLOCK
    | MAP_STACK
    | MAP_HUGETLB
    | MAP_UNINITIALIZED
    | MAP_32BIT
    | MAP_ABOVE4G
    | MAP_HUGE_2MB
    | MAP_HUGE_1GB;

/// `calc_vm_prot_bits` (no protection keys: `arch_calc_vm_prot_bits` adds
/// only `VM_PKEY_BIT*`, and `execute_only_pkey` is -1 without OSPKE).
#[must_use]
pub const fn calc_vm_prot_bits(prot: u64) -> VmFlags {
    VmFlags(
        ((prot & PROT_READ) * (VmFlags::READ.0 / PROT_READ))
            | ((prot & PROT_WRITE) * (VmFlags::WRITE.0 / PROT_WRITE))
            | ((prot & PROT_EXEC) * (VmFlags::EXEC.0 / PROT_EXEC)),
    )
}

/// `calc_vm_flag_bits` for `CONFIG_TRANSPARENT_HUGEPAGE=n` (`MAP_STACK` adds
/// nothing).
#[must_use]
pub const fn calc_vm_flag_bits(flags: u64) -> VmFlags {
    let mut f = 0;
    if flags & MAP_GROWSDOWN != 0 {
        f |= VmFlags::GROWSDOWN.0;
    }
    if flags & MAP_LOCKED != 0 {
        f |= VmFlags::LOCKED.0;
    }
    if flags & MAP_SYNC != 0 {
        f |= VmFlags::SYNC.0;
    }
    VmFlags(f)
}

/// What the page tables must enforce for a VMA (`vm_get_page_prot`, reduced to
/// the three facts the x86 `protection_map` encodes for a user page).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PageProt {
    /// Any of read/write/exec: otherwise the PTE is `PAGE_NONE` (present bit
    /// clear with `_PAGE_PROTNONE`, so the frame is retained).
    pub accessible: bool,
    /// `VM_WRITE`. For a private mapping the hardware write bit stays clear
    /// until the page is exclusively owned (copy-on-write, zero page), which
    /// the write-fault path establishes; for a `VM_SHARED` mapping it is set.
    pub write: bool,
    /// `VM_EXEC` (clear = `_PAGE_NX`).
    pub exec: bool,
}

#[must_use]
pub const fn page_prot(f: VmFlags) -> PageProt {
    PageProt {
        accessible: f.intersects(VmFlags::ACCESS),
        write: f.contains(VmFlags::WRITE),
        exec: f.contains(VmFlags::EXEC),
    }
}
