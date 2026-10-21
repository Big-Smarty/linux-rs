// SPDX-License-Identifier: GPL-2.0-only
// Linux 6.18.57 (2ff600d29ee478d0a8d46ef8a58afb5e038fe692): arch/x86/mm/mmap.c
// (`mmap_base`, `mmap_legacy_base`, `arch_pick_mmap_layout`,
// `mmap_address_hint_valid`), arch/x86/kernel/sys_x86_64.c
// (`arch_get_unmapped_area{,_topdown}`, `find_start_end`), mm/mmap.c
// (`__get_unmapped_area`, `round_hint_to_min`), mm/vma.c (`unmapped_area`,
// `unmapped_area_topdown`), security/commoncap.c `cap_mmap_addr`. GPL-2.0 and
// GPL-2.0-or-later (arch/x86/mm/mmap.c).
// Transformation: the maple-tree gap search (`mas_empty_area{,_rev}`) is a
// scan of the sorted VMA vector; `norandmaps` removes every random term; the
// 32-bit/x32 and AMD F15h `va_align` paths do not exist in this configuration.
#![forbid(unsafe_code)]
//! Where `mmap` puts things: the layout bases and `get_unmapped_area`.
//!
//! Declared configuration: x86-64, 4-level paging, `norandmaps`
//! (`randomize_va_space = 0`: `arch_rnd` is 0, `stack_maxrandom_size` is 0),
//! `sysctl_legacy_va_layout = 0`, no `ADDR_COMPAT_LAYOUT`, no
//! `CONFIG_TRANSPARENT_HUGEPAGE` (no `thp_get_unmapped_area`), no
//! `VM_SHADOW_STACK` (`start_gap` is always 0), `va_align.flags = -1`
//! (`align_mask` is 0 for every non-hugetlb mapping).

use syscalls::Errno;

use super::{
    env::Env,
    flags::{
        MAP_32BIT, MAP_ABOVE4G, MAP_FIXED, PAGE_SIZE, VmFlags, offset_in_page, page_align,
        page_floor,
    },
    space::{Mm, TASK_SIZE},
};

/// `DEFAULT_MAP_WINDOW`.
pub const DEFAULT_MAP_WINDOW: u64 = (1 << 47) - PAGE_SIZE;
const SIZE_128M: u64 = 128 * 1024 * 1024;
const SZ_4G: u64 = 1 << 32;

/// `(mmap_base, mmap_legacy_base)` of `arch_pick_mmap_layout` with
/// `rnd = 0` and `task_size = DEFAULT_MAP_WINDOW`. `mmap_is_legacy()` is
/// false (`sysctl_legacy_va_layout = 0`, no `ADDR_COMPAT_LAYOUT`), so
/// `MMF_TOPDOWN` is set by [`Mm::new`].
#[must_use]
pub fn pick_mmap_base(env: &Env) -> (u64, u64) {
    let task_size = DEFAULT_MAP_WINDOW;
    // mmap_legacy_base: __TASK_UNMAPPED_BASE = PAGE_ALIGN(task_size / 3).
    let legacy_base = page_align(task_size / 3).unwrap_or(0);
    // mmap_base: stack rlimit plus the guard gap, clamped to [128 MiB, 5/6 of
    // the task size], below the stack.
    let mut gap = env.rlimit_stack;
    let pad = env.stack_guard_gap; // + stack_maxrandom_size (0 without PF_RANDOMIZE)
    // Values close to RLIM_INFINITY can overflow.
    if gap.checked_add(pad).is_some_and(|g| g > gap) {
        gap += pad;
    }
    let gap = gap.clamp(SIZE_128M, (task_size / 6) * 5);
    (page_align(task_size - gap).unwrap_or(0), legacy_base)
}

/// `struct vm_unmapped_area_info` (without `start_gap`, always 0 here).
#[derive(Clone, Copy, Debug, Default)]
struct Info {
    topdown: bool,
    length: u64,
    low_limit: u64,
    high_limit: u64,
    align_mask: u64,
    align_offset: u64,
}

impl Mm {
    /// Lowest `s >= low` with `[s, s + len)` free and `s + len <= high`
    /// (`mas_empty_area`).
    fn lowest_gap(&self, low: u64, high: u64, len: u64) -> Option<u64> {
        let mut cand = low;
        for v in self.vmas.iter() {
            if v.end <= cand {
                continue;
            }
            if cand.checked_add(len).is_some_and(|e| e <= v.start) {
                break;
            }
            cand = v.end;
        }
        (cand.checked_add(len)? <= high).then_some(cand)
    }

    /// End `e <= high` of the highest free `[e - len, e)` with `e - len >= low`
    /// (`mas_empty_area_rev`).
    fn highest_gap(&self, low: u64, high: u64, len: u64) -> Option<u64> {
        let mut end = high;
        for v in self.vmas.iter().rev() {
            if v.start >= end {
                continue;
            }
            if end.checked_sub(len).is_none_or(|s| v.end <= s) {
                break;
            }
            end = v.start;
        }
        (end.checked_sub(len)? >= low).then_some(end)
    }

    /// `vm_unmapped_area`: `unmapped_area` / `unmapped_area_topdown`.
    fn vm_unmapped_area(&self, env: &Env, info: &Info) -> Result<u64, Errno> {
        // Worst-case alignment overhead (start_gap is 0).
        let length = info
            .length
            .checked_add(info.align_mask)
            .ok_or(Errno::ENOMEM)?;
        let mut low = info.low_limit.max(env.mmap_min_addr);
        let mut high = info.high_limit;
        loop {
            if info.topdown {
                let end = self.highest_gap(low, high, length).ok_or(Errno::ENOMEM)?;
                let mut gap = end - info.length;
                gap -= gap.wrapping_sub(info.align_offset) & info.align_mask;
                let at = self.lower(end - length); // VMAs wholly below the range
                let next = self.vmas.get(at);
                if let Some(t) = next.filter(|t| t.flags.contains(VmFlags::GROWSDOWN)) {
                    if Self::vm_start_gap(env, t) < end {
                        high = Self::vm_start_gap(env, t);
                        continue;
                    }
                } else if let Some(p) = at.checked_sub(1).map(|i| &self.vmas[i])
                    && Self::vm_end_gap(p) > gap
                {
                    high = p.start;
                    continue;
                }
                return Ok(gap);
            }
            let found = self.lowest_gap(low, high, length).ok_or(Errno::ENOMEM)?;
            let mut gap = found;
            gap += info.align_offset.wrapping_sub(gap) & info.align_mask;
            let at = self.lower(found);
            let next = self.vmas.get(at);
            if let Some(t) = next.filter(|t| t.flags.contains(VmFlags::GROWSDOWN)) {
                if Self::vm_start_gap(env, t) < gap + length - 1 {
                    low = t.end;
                    continue;
                }
            } else if let Some(p) = at.checked_sub(1).map(|i| &self.vmas[i])
                && Self::vm_end_gap(p) > gap
            {
                low = Self::vm_end_gap(p);
                continue;
            }
            return Ok(gap);
        }
    }

    /// `arch_get_unmapped_area` (x86, bottom-up).
    fn arch_get_unmapped_area(
        &self,
        env: &Env,
        addr: u64,
        len: u64,
        pgoff: u64,
        flags: u64,
    ) -> Result<u64, Errno> {
        if flags & MAP_FIXED != 0 {
            return Ok(addr);
        }
        // find_start_end
        let (begin, end) = if flags & MAP_32BIT != 0 {
            (0x4000_0000, 0x8000_0000)
        } else {
            (
                self.mmap_legacy_base,
                if addr > DEFAULT_MAP_WINDOW {
                    TASK_SIZE
                } else {
                    DEFAULT_MAP_WINDOW
                },
            )
        };
        if len > end {
            return Err(Errno::ENOMEM);
        }
        let mut addr = addr;
        if addr != 0 {
            addr = page_align(addr).unwrap_or(0);
            let ok = end - len >= addr
                && self
                    .find_vma(addr)
                    .is_none_or(|v| addr + len <= Self::vm_start_gap(env, v));
            if ok {
                return Ok(addr);
            }
        }
        let info = Info {
            topdown: false,
            length: len,
            low_limit: begin,
            high_limit: end,
            align_mask: 0,
            align_offset: pgoff << super::flags::PAGE_SHIFT,
        };
        self.vm_unmapped_area(env, &info)
    }

    /// `arch_get_unmapped_area_topdown` (x86).
    fn arch_get_unmapped_area_topdown(
        &self,
        env: &Env,
        addr0: u64,
        len: u64,
        pgoff: u64,
        flags: u64,
    ) -> Result<u64, Errno> {
        if len > TASK_SIZE {
            return Err(Errno::ENOMEM);
        }
        // No address checking. See comment at mmap_address_hint_valid().
        if flags & MAP_FIXED != 0 {
            return Ok(addr0);
        }
        if flags & MAP_32BIT == 0 {
            if addr0 != 0 {
                let addr = page_floor(addr0);
                if mmap_address_hint_valid(addr, len)
                    && self
                        .find_vma(addr)
                        .is_none_or(|v| addr + len <= Self::vm_start_gap(env, v))
                {
                    return Ok(addr);
                }
            }
            let info = Info {
                topdown: true,
                length: len,
                low_limit: if flags & MAP_ABOVE4G != 0 {
                    SZ_4G
                } else {
                    PAGE_SIZE
                },
                // A hint above DEFAULT_MAP_WINDOW adds TASK_SIZE_MAX -
                // DEFAULT_MAP_WINDOW, which is 0 under 4-level paging.
                high_limit: self.mmap_base,
                align_mask: 0,
                align_offset: pgoff << super::flags::PAGE_SHIFT,
            };
            if let Ok(a) = self.vm_unmapped_area(env, &info) {
                debug_assert_eq!(offset_in_page(a), 0);
                return Ok(a);
            }
        }
        // A failed mmap() very likely causes application failure, so fall
        // back to the bottom-up function (also the MAP_32BIT path).
        self.arch_get_unmapped_area(env, addr0, len, pgoff, flags)
    }

    /// `__get_unmapped_area` for an anonymous or file mapping whose file has no
    /// `get_unmapped_area` operation (every regular filesystem here).
    ///
    /// # Errors
    /// `ENOMEM` (no room, or `len`/`addr` beyond `TASK_SIZE`), `EINVAL` (a
    /// `MAP_FIXED` address that is not page aligned), `EPERM` (below
    /// `mmap_min_addr` without `CAP_SYS_RAWIO`).
    pub fn get_unmapped_area(
        &self,
        env: &Env,
        addr: u64,
        len: u64,
        pgoff: u64,
        flags: u64,
    ) -> Result<u64, Errno> {
        // arch_mmap_check is empty on x86-64.
        if len > TASK_SIZE {
            return Err(Errno::ENOMEM);
        }
        // A MAP_SHARED anonymous mapping goes through shmem_get_unmapped_area,
        // which with THP off calls the same function.
        let addr = if self.topdown {
            self.arch_get_unmapped_area_topdown(env, addr, len, pgoff, flags)?
        } else {
            self.arch_get_unmapped_area(env, addr, len, pgoff, flags)?
        };
        // `IS_ERR_VALUE(addr)`: an address in [-4095, -1] is returned as an
        // errno before any other check (only `MAP_FIXED` can reach this, as the
        // arch function hands the caller's address back unexamined).
        if addr >= u64::MAX - 4094 {
            return Err(Errno::new(i32::try_from(addr.wrapping_neg()).unwrap_or(0)));
        }
        if addr > TASK_SIZE - len {
            return Err(Errno::ENOMEM);
        }
        if offset_in_page(addr) != 0 {
            return Err(Errno::EINVAL);
        }
        // security_mmap_addr -> cap_mmap_addr (dac_mmap_min_addr == mmap_min_addr)
        if addr < env.mmap_min_addr && !env.cap_sys_rawio {
            return Err(Errno::EPERM);
        }
        Ok(addr)
    }
}

/// `mmap_address_hint_valid` (4-level: both ends on the same side of
/// `DEFAULT_MAP_WINDOW`).
#[must_use]
pub fn mmap_address_hint_valid(addr: u64, len: u64) -> bool {
    if TASK_SIZE - len < addr {
        return false;
    }
    (addr > DEFAULT_MAP_WINDOW) == (addr.wrapping_add(len) > DEFAULT_MAP_WINDOW)
}

/// `round_hint_to_min` (mm/mmap.c:219).
#[must_use]
pub fn round_hint_to_min(env: &Env, hint: u64) -> u64 {
    let hint = page_floor(hint);
    if hint != 0 && hint < env.mmap_min_addr {
        return page_align(env.mmap_min_addr).unwrap_or(0);
    }
    hint
}
