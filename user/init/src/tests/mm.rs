// SPDX-License-Identifier: GPL-2.0-only
//! `mm` group: `brk`, anonymous private `mmap`, `munmap`, `mprotect`, zero fill and read-back.
//! Linux sources (6.18.57): `mm/mmap.c` (`brk`, `__get_unmapped_area`, `do_mmap`, `munmap`),
//! `mm/mprotect.c`, `arch/x86/kernel/sys_x86_64.c` (`arch_get_unmapped_area*`). Exact addresses
//! hold under `norandmaps` with no vDSO (`vdso=0`): `mmap_base = TASK_SIZE - 128 MiB - stack gap`.

use syscalls::{Errno, Sysno};

use super::{PAGE, Probe, R, T, TASK_SIZE, all_bytes, mapped, mmap, peek, poke, sys};

const PROT_NONE: usize = 0;
const PROT_R: usize = 1;
const PROT_RW: usize = 3;
const PROT_RWX: usize = 7;
const MAP_PRIVATE: usize = 0x02;
const MAP_FIXED: usize = 0x10;
const MAP_ANON: usize = 0x20;
const MAP_32BIT: usize = 0x40;
const MAP_GROWSDOWN: usize = 0x100;
const MAP_NORESERVE: usize = 0x4000;
const MAP_POPULATE: usize = 0x8000;
const MAP_STACK: usize = 0x20000;
const MAP_FIXED_NOREPLACE: usize = 0x10_0000;
const ANON: usize = MAP_PRIVATE | MAP_ANON;
const NOFD: usize = usize::MAX;

/// Top of the mmap area with no randomization and no vDSO: `PAGE_ALIGN(TASK_SIZE - gap)` with
/// `gap` = 128 MiB (`MIN_GAP`), which exceeds the 8 MiB stack limit plus guard gap.
const MMAP_TOP: usize = TASK_SIZE - 0x800_0000;

unsafe extern "C" {
    /// Linker-defined end of `.bss` (`lld` defines it when referenced).
    static _end: u8;
}

fn brk(a: usize) -> usize {
    sys(Sysno::brk, &[a]).unwrap_or(usize::MAX)
}

fn map(a: usize, len: usize, prot: usize, flags: usize) -> R {
    mmap(a, len, prot, flags, NOFD, 0)
}

pub fn run() -> bool {
    let mut t = T::new("mm");
    let probe = Probe::new();
    brk_checks(&mut t);
    mmap_checks(&mut t, &probe);
    munmap_checks(&mut t, &probe);
    mprotect_checks(&mut t, &probe);
    t.finish()
}

fn brk_checks(t: &mut T) {
    // `brk` starts at the page-aligned end of the last PT_LOAD (`load_elf_binary`).
    let start = (ptr_end() + PAGE - 1) & !(PAGE - 1);
    t.eq("brk-query", brk(0), start);
    t.eq("brk-grow", brk(start + 3 * PAGE), start + 3 * PAGE);
    t.eq("brk-grown-mapped", mapped(start, 3 * PAGE), Ok(0));
    t.eq(
        "brk-grown-guard",
        mapped(start + 3 * PAGE, PAGE),
        Err(Errno::ENOMEM),
    );
    t.holds(
        "brk-zero-filled",
        all_bytes(start, 3 * PAGE, 0),
        "nonzero",
        "3 zero pages",
    );
    poke(start, 0x11);
    poke(start + PAGE + 5, 0x22);
    poke(start + 3 * PAGE - 1, 0x33);
    t.eq(
        "brk-readback",
        (
            peek(start),
            peek(start + PAGE + 5),
            peek(start + 3 * PAGE - 1),
        ),
        (0x11, 0x22, 0x33),
    );
    // An unaligned request is recorded exactly while the mapping rounds up.
    t.eq(
        "brk-unaligned",
        brk(start + 3 * PAGE + 5),
        start + 3 * PAGE + 5,
    );
    t.eq("brk-unaligned-mapped", mapped(start, 4 * PAGE), Ok(0));
    t.eq(
        "brk-unaligned-end",
        mapped(start + 4 * PAGE, PAGE),
        Err(Errno::ENOMEM),
    );
    t.eq("brk-shrink", brk(start + PAGE), start + PAGE);
    t.eq(
        "brk-shrunk-unmapped",
        mapped(start + PAGE, PAGE),
        Err(Errno::ENOMEM),
    );
    t.eq(
        "brk-shrunk-kept",
        (mapped(start, PAGE), peek(start)),
        (Ok(0), 0x11),
    );
    // Below the start of the heap (and below `end_data`): the break is unchanged.
    t.eq("brk-below-start", brk(0x10000), start + PAGE);
    t.eq("brk-regrow", brk(start + 3 * PAGE), start + 3 * PAGE);
    t.holds(
        "brk-regrow-zero",
        all_bytes(start + PAGE, 2 * PAGE, 0) && peek(start) == 0x11,
        "stale data",
        "discarded pages are zero, kept page intact",
    );
    // A mapping in the way: `newbrk + PAGE_SIZE` must not reach the next vma.
    let wall = start + 0x10_000;
    t.eq(
        "brk-wall-map",
        map(wall, PAGE, PROT_RW, ANON | MAP_FIXED),
        Ok(wall),
    );
    t.eq("brk-up-to-wall-guard", brk(wall - PAGE), wall - PAGE);
    t.eq("brk-into-wall", brk(wall), wall - PAGE);
    t.eq("brk-unaligned-into-wall", brk(wall - PAGE + 1), wall - PAGE);
    t.eq("brk-wall-unmap", sys(Sysno::munmap, &[wall, PAGE]), Ok(0));
    t.eq("brk-huge", brk(TASK_SIZE - PAGE), wall - PAGE);
    t.eq("brk-reset", brk(start), start);
    t.eq(
        "brk-reset-unmapped",
        mapped(start, PAGE),
        Err(Errno::ENOMEM),
    );
}

fn ptr_end() -> usize {
    core::ptr::addr_of!(_end).addr()
}

fn mmap_checks(t: &mut T, probe: &Probe) {
    // Top-down placement from `mmap_base`, adjacent to the previous mapping.
    let a = MMAP_TOP - 2 * PAGE;
    t.eq("mmap-first", map(0, 2 * PAGE, PROT_RW, ANON), Ok(a));
    t.eq(
        "mmap-second-adjacent",
        map(0, PAGE, PROT_RW, ANON),
        Ok(a - PAGE),
    );
    t.holds(
        "mmap-zero-filled",
        all_bytes(a, 2 * PAGE, 0),
        "nonzero",
        "2 zero pages",
    );
    for i in 0..2 * PAGE {
        poke(a + i, (i % 251) as u8 + 1);
    }
    t.holds(
        "mmap-readback",
        (0..2 * PAGE).all(|i| peek(a + i) == (i % 251) as u8 + 1),
        "mismatch",
        "pattern",
    );
    t.holds(
        "mmap-kernel-access",
        probe.readable(a, 2 * PAGE) && probe.writable(a, 2 * PAGE),
        "EFAULT",
        "usable by read/write",
    );

    // Hints are honoured when free, page-aligned up, and ignored below mmap_min_addr.
    let hint = 0x1000_0000;
    t.eq("mmap-hint", map(hint, PAGE, PROT_RW, ANON), Ok(hint));
    t.eq(
        "mmap-hint-occupied",
        map(hint, PAGE, PROT_RW, ANON),
        Ok(a - 2 * PAGE),
    );
    // x86 rounds a non-fixed hint *down* (`addr &= PAGE_MASK`).
    t.eq(
        "mmap-hint-unaligned",
        map(hint + 0x1000_0123, PAGE, PROT_RW, ANON),
        Ok(hint + 0x1000_0000),
    );
    // arch_get_unmapped_area* never consults mmap_min_addr; `security_mmap_addr` lets root pass.
    t.eq(
        "mmap-hint-low",
        map(0x1000, PAGE, PROT_RW, ANON),
        Ok(0x1000),
    );
    t.eq(
        "mmap-hint-low-unmap",
        sys(Sysno::munmap, &[0x1000, PAGE]),
        Ok(0),
    );
    t.eq(
        "mmap-hint-straddle",
        map(hint - PAGE / 2, 2 * PAGE, PROT_RW, ANON),
        Ok(a - 4 * PAGE),
    );
    t.eq(
        "mmap-32bit",
        map(0, PAGE, PROT_RW, ANON | MAP_32BIT),
        Ok(0x4000_0000),
    );

    // MAP_FIXED replaces whatever is there and zero-fills it.
    let fixed = 0x3000_0000;
    t.eq(
        "mmap-fixed",
        map(fixed, 3 * PAGE, PROT_RW, ANON | MAP_FIXED),
        Ok(fixed),
    );
    poke(fixed, 1);
    poke(fixed + PAGE, 2);
    poke(fixed + 2 * PAGE, 3);
    t.eq(
        "mmap-fixed-replace",
        map(fixed + PAGE, PAGE, PROT_RW, ANON | MAP_FIXED),
        Ok(fixed + PAGE),
    );
    t.eq(
        "mmap-fixed-replace-data",
        (peek(fixed), peek(fixed + PAGE), peek(fixed + 2 * PAGE)),
        (1, 0, 3),
    );
    t.eq(
        "mmap-fixed-low",
        map(0x1000, PAGE, PROT_RW, ANON | MAP_FIXED),
        Ok(0x1000),
    );
    t.eq(
        "mmap-fixed-low-unmap",
        sys(Sysno::munmap, &[0x1000, PAGE]),
        Ok(0),
    );
    t.eq(
        "mmap-fixed-unaligned",
        map(fixed + 1, PAGE, PROT_RW, ANON | MAP_FIXED),
        Err(Errno::EINVAL),
    );
    t.eq(
        "mmap-fixed-past-task-size",
        map(TASK_SIZE, PAGE, PROT_RW, ANON | MAP_FIXED),
        Err(Errno::ENOMEM),
    );
    t.eq(
        "mmap-fixed-straddles-task-size",
        map(TASK_SIZE - PAGE, 2 * PAGE, PROT_RW, ANON | MAP_FIXED),
        Err(Errno::ENOMEM),
    );

    // MAP_FIXED_NOREPLACE: free range maps, any overlap is EEXIST and leaves the data alone.
    let nr = 0x5000_0000;
    let noreplace = ANON | MAP_FIXED_NOREPLACE;
    t.eq(
        "noreplace-free",
        map(nr, 2 * PAGE, PROT_RW, noreplace),
        Ok(nr),
    );
    poke(nr, 9);
    t.eq(
        "noreplace-exact",
        map(nr, 2 * PAGE, PROT_RW, noreplace),
        Err(Errno::EEXIST),
    );
    t.eq(
        "noreplace-tail",
        map(nr + PAGE, 2 * PAGE, PROT_RW, noreplace),
        Err(Errno::EEXIST),
    );
    t.eq(
        "noreplace-head",
        map(nr - PAGE, 2 * PAGE, PROT_RW, noreplace),
        Err(Errno::EEXIST),
    );
    t.eq(
        "noreplace-adjacent",
        map(nr + 2 * PAGE, PAGE, PROT_RW, noreplace),
        Ok(nr + 2 * PAGE),
    );
    t.eq("noreplace-data-kept", peek(nr), 9);
    t.eq(
        "noreplace-unaligned",
        map(nr + 3 * PAGE + 1, PAGE, PROT_RW, noreplace),
        Err(Errno::EINVAL),
    );

    // PROT_NONE and protections.
    let none = map(0, 2 * PAGE, PROT_NONE, ANON);
    t.eq("prot-none-addr", none, Ok(a - 6 * PAGE));
    let none = none.unwrap_or(0);
    t.holds(
        "prot-none-inaccessible",
        !probe.readable(none, PAGE)
            && !probe.writable(none, PAGE)
            && mapped(none, 2 * PAGE) == Ok(0),
        "accessible",
        "mapped but unreadable and unwritable",
    );
    let ro = map(0, PAGE, PROT_R, ANON).unwrap_or(0);
    t.holds(
        "prot-read-only",
        probe.readable(ro, PAGE) && !probe.writable(ro, PAGE) && peek(ro) == 0,
        "writable",
        "readable, not writable",
    );
    t.eq("prot-exec-rwx", map(0, PAGE, PROT_RWX, ANON).is_ok(), true);
    // mmap, unlike mprotect, silently ignores unknown protection bits (`calc_vm_prot_bits`).
    t.eq("prot-unknown-bit", map(0, PAGE, 0x40, ANON).is_ok(), true);

    // Flags that are accepted and change nothing observable for anonymous private memory.
    for (name, flag) in [
        ("flag-noreserve", MAP_NORESERVE),
        ("flag-populate", MAP_POPULATE),
        ("flag-stack", MAP_STACK),
        ("flag-growsdown", MAP_GROWSDOWN),
    ] {
        let r = map(0, PAGE, PROT_RW, ANON | flag);
        t.holds(
            name,
            r.is_ok_and(|p| all_bytes(p, PAGE, 0)),
            r,
            "zeroed page",
        );
    }

    // Argument errors, in the order mm/mmap.c checks them.
    t.eq(
        "mmap-len-zero",
        map(0, 0, PROT_RW, ANON),
        Err(Errno::EINVAL),
    );
    t.eq(
        "mmap-no-sharing",
        map(0, PAGE, PROT_RW, MAP_ANON),
        Err(Errno::EINVAL),
    );
    t.eq(
        "mmap-unaligned-offset",
        mmap(0, PAGE, PROT_RW, ANON, NOFD, 1),
        Err(Errno::EINVAL),
    );
    t.eq(
        "mmap-aligned-offset-anon",
        mmap(0, PAGE, PROT_RW, ANON, NOFD, PAGE).is_ok(),
        true,
    );
    t.eq(
        "mmap-len-max",
        map(0, usize::MAX, PROT_RW, ANON),
        Err(Errno::ENOMEM),
    );
    t.eq(
        "mmap-len-wraps-page-align",
        map(0, usize::MAX - 100, PROT_RW, ANON),
        Err(Errno::ENOMEM),
    );
    t.eq(
        "mmap-len-over-task-size",
        map(0, TASK_SIZE + PAGE, PROT_RW, ANON),
        Err(Errno::ENOMEM),
    );
    t.eq(
        "mmap-len-no-room",
        map(0, TASK_SIZE - PAGE, PROT_RW, ANON),
        Err(Errno::ENOMEM),
    );
    t.eq(
        "mmap-file-bad-fd",
        mmap(0, PAGE, PROT_RW, MAP_PRIVATE, NOFD, 0),
        Err(Errno::EBADF),
    );
    t.eq(
        "mmap-file-closed-fd",
        mmap(0, PAGE, PROT_RW, MAP_PRIVATE, 1000, 0),
        Err(Errno::EBADF),
    );
}

fn munmap_checks(t: &mut T, probe: &Probe) {
    let x = 0x4000_0000;
    let unmap = |a: usize, len: usize| sys(Sysno::munmap, &[a, len]);
    t.eq(
        "munmap-setup",
        map(x, 5 * PAGE, PROT_RW, ANON | MAP_FIXED),
        Ok(x),
    );
    for i in 0..5 {
        poke(x + i * PAGE, 0x40 + i as u8);
    }
    t.eq("munmap-head", unmap(x, PAGE), Ok(0));
    t.eq("munmap-head-gone", mapped(x, PAGE), Err(Errno::ENOMEM));
    t.eq("munmap-head-rest", mapped(x + PAGE, 4 * PAGE), Ok(0));
    t.eq("munmap-tail", unmap(x + 4 * PAGE, PAGE), Ok(0));
    t.eq(
        "munmap-tail-gone",
        mapped(x + 4 * PAGE, PAGE),
        Err(Errno::ENOMEM),
    );
    t.eq("munmap-split", unmap(x + 2 * PAGE, PAGE), Ok(0));
    t.eq(
        "munmap-split-pieces",
        (
            mapped(x + PAGE, PAGE),
            mapped(x + 2 * PAGE, PAGE),
            mapped(x + 3 * PAGE, PAGE),
            mapped(x + PAGE, 3 * PAGE),
        ),
        (Ok(0), Err(Errno::ENOMEM), Ok(0), Err(Errno::ENOMEM)),
    );
    t.eq(
        "munmap-split-data",
        (peek(x + PAGE), peek(x + 3 * PAGE)),
        (0x41, 0x43),
    );
    t.holds(
        "munmap-split-kernel-view",
        probe.readable(x + PAGE, PAGE) && !probe.readable(x + 2 * PAGE, PAGE),
        "mismatch",
        "left readable, hole unreadable",
    );
    t.eq("munmap-hole-spanning", unmap(x, 5 * PAGE), Ok(0));
    t.eq("munmap-all-gone", mapped(x, 5 * PAGE), Err(Errno::ENOMEM));
    t.eq("munmap-unmapped-ok", unmap(x, PAGE), Ok(0));
    t.eq("munmap-unaligned", unmap(x + 1, PAGE), Err(Errno::EINVAL));
    t.eq("munmap-len-zero", unmap(x, 0), Err(Errno::EINVAL));
    t.eq("munmap-len-max", unmap(x, usize::MAX), Err(Errno::EINVAL));
    t.eq(
        "munmap-past-task-size",
        unmap(TASK_SIZE, PAGE),
        Err(Errno::EINVAL),
    );
    t.eq(
        "munmap-straddles-task-size",
        unmap(TASK_SIZE - PAGE, 2 * PAGE),
        Err(Errno::EINVAL),
    );
    t.eq(
        "munmap-unaligned-len-rounds-up",
        map(x, 2 * PAGE, PROT_RW, ANON | MAP_FIXED),
        Ok(x),
    );
    t.eq("munmap-len-rounds", unmap(x, 1), Ok(0));
    t.eq(
        "munmap-len-rounded-state",
        (mapped(x, PAGE), mapped(x + PAGE, PAGE)),
        (Err(Errno::ENOMEM), Ok(0)),
    );
    t.eq("munmap-cleanup", unmap(x + PAGE, PAGE), Ok(0));
    // Memory comes back zeroed after unmap + remap.
    t.eq(
        "munmap-remap",
        map(x, PAGE, PROT_RW, ANON | MAP_FIXED),
        Ok(x),
    );
    t.eq("munmap-remap-zero", all_bytes(x, PAGE, 0), true);
    t.eq("munmap-remap-cleanup", unmap(x, PAGE), Ok(0));
}

fn mprotect_checks(t: &mut T, probe: &Probe) {
    let x = 0x6000_0000;
    let prot = |a: usize, len: usize, p: usize| sys(Sysno::mprotect, &[a, len, p]);
    t.eq(
        "mprotect-setup",
        map(x, 3 * PAGE, PROT_RW, ANON | MAP_FIXED),
        Ok(x),
    );
    for i in 0..3 {
        poke(x + i * PAGE, 0x70 + i as u8);
    }
    t.eq(
        "mprotect-middle-none",
        prot(x + PAGE, PAGE, PROT_NONE),
        Ok(0),
    );
    t.eq(
        "mprotect-split-access",
        (
            probe.writable(x, PAGE),
            probe.readable(x + PAGE, PAGE),
            probe.writable(x + PAGE, PAGE),
            probe.writable(x + 2 * PAGE, PAGE),
            mapped(x, 3 * PAGE),
        ),
        (true, false, false, true, Ok(0)),
    );
    t.eq("mprotect-first-read-only", prot(x, PAGE, PROT_R), Ok(0));
    t.eq(
        "mprotect-read-only-access",
        (probe.readable(x, PAGE), probe.writable(x, PAGE)),
        (true, false),
    );
    t.eq("mprotect-restore", prot(x, 3 * PAGE, PROT_RW), Ok(0));
    t.eq(
        "mprotect-data-preserved",
        (peek(x), peek(x + PAGE), peek(x + 2 * PAGE)),
        (0x70, 0x71, 0x72),
    );
    t.eq(
        "mprotect-whole-range-span",
        prot(x + PAGE, 2 * PAGE, PROT_R),
        Ok(0),
    );
    t.eq("mprotect-reset", prot(x, 3 * PAGE, PROT_RW), Ok(0));
    t.eq(
        "mprotect-unaligned",
        prot(x + 1, PAGE, PROT_R),
        Err(Errno::EINVAL),
    );
    t.eq("mprotect-bad-prot", prot(x, PAGE, 0x40), Err(Errno::EINVAL));
    t.eq(
        "mprotect-grows-both",
        prot(x, PAGE, 0x0300_0000 | PROT_R),
        Err(Errno::EINVAL),
    );
    t.eq("mprotect-len-zero", prot(x, 0, PROT_R), Ok(0));
    t.eq("mprotect-len-zero-bad-prot", prot(x, 0, 0x40), Ok(0));
    t.eq(
        "mprotect-len-wraps",
        prot(x, usize::MAX, PROT_R),
        Err(Errno::ENOMEM),
    );
    t.eq(
        "mprotect-len-wraps-bad-prot",
        prot(x, usize::MAX, 0x40),
        Err(Errno::ENOMEM),
    );
    t.eq(
        "mprotect-unmapped",
        prot(x - PAGE, PAGE, PROT_R),
        Err(Errno::ENOMEM),
    );
    t.eq(
        "mprotect-starts-in-hole",
        prot(x - PAGE, 2 * PAGE, PROT_R),
        Err(Errno::ENOMEM),
    );
    t.eq("mprotect-hole-no-effect", probe.writable(x, PAGE), true);
    // A hole after the first vma: the leading part is already changed when ENOMEM is reported.
    t.eq(
        "mprotect-hole-after",
        prot(x, 4 * PAGE, PROT_R),
        Err(Errno::ENOMEM),
    );
    t.eq(
        "mprotect-hole-after-partial",
        (probe.writable(x, 3 * PAGE), probe.readable(x, 3 * PAGE)),
        (false, true),
    );
    t.eq(
        "mprotect-cleanup",
        sys(Sysno::munmap, &[x, 3 * PAGE]),
        Ok(0),
    );
    // Merging neighbours with equal protection keeps both usable and splittable.
    t.eq(
        "mprotect-adjacent-a",
        map(x, PAGE, PROT_RW, ANON | MAP_FIXED),
        Ok(x),
    );
    t.eq(
        "mprotect-adjacent-b",
        map(x + PAGE, PAGE, PROT_RW, ANON | MAP_FIXED),
        Ok(x + PAGE),
    );
    t.eq("mprotect-across-two-vmas", prot(x, 2 * PAGE, PROT_R), Ok(0));
    t.eq(
        "mprotect-across-two-vmas-state",
        (probe.writable(x, 2 * PAGE), probe.readable(x, 2 * PAGE)),
        (false, true),
    );
    t.eq(
        "mprotect-adjacent-cleanup",
        sys(Sysno::munmap, &[x, 2 * PAGE]),
        Ok(0),
    );
}
