// SPDX-License-Identifier: GPL-2.0-only
//! Host tests of the memory-mapping model. Expected values come from three
//! sources, named per test: `oracle` = a line recorded on the pinned Linux
//! 6.18.57 (`target/linux-reference/init-reference-005/oracle-mm-tcg.log`,
//! check name quoted), `src` = derived by hand from the cited pinned source
//! (no oracle covers it), `model` = a property of this model itself.
//! Blind spot: `Vec::try_reserve` failure is not injectable on the host.
#![allow(
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::many_single_char_names,
    clippy::similar_names,
    clippy::cast_possible_truncation,
    reason = "test names quote Linux identifiers; one test per Linux sequence"
)]
extern crate std;

use alloc::collections::BTreeMap;
use std::{format, vec::Vec};
use syscalls::Errno;

use super::*;

const P: u64 = PAGE_SIZE;
const ANON: u64 = MAP_PRIVATE | MAP_ANONYMOUS;
const RW: u64 = PROT_READ | PROT_WRITE;
/// Oracle: `PAGE_ALIGN(TASK_SIZE - 128 MiB)` with `norandmaps`, `vdso=0`.
const MMAP_TOP: u64 = TASK_SIZE - 0x800_0000;
const STACK_PAGES: u64 = 36;
const STACK_START: u64 = TASK_SIZE - STACK_PAGES * P;

#[derive(Clone, Copy, PartialEq, Debug)]
struct Hw {
    kind: Pte,
    prot: PageProt,
}

/// Page tables as a map; `fail_maps` injects `OutOfMemory` after that many
/// successful `map_*` calls.
#[derive(Default)]
struct Fake {
    pages: BTreeMap<u64, Hw>,
    fail_maps: Option<u32>,
}

impl Fake {
    fn budget(&mut self) -> Result<(), OutOfMemory> {
        match &mut self.fail_maps {
            Some(0) => Err(OutOfMemory),
            Some(n) => {
                *n -= 1;
                Ok(())
            }
            None => Ok(()),
        }
    }
}

impl UserPages for Fake {
    fn lookup(&self, page: u64) -> Pte {
        self.pages.get(&page).map_or(Pte::Absent, |h| h.kind)
    }
    fn map_zero_page(&mut self, page: u64, prot: PageProt) -> Result<(), OutOfMemory> {
        self.budget()?;
        self.pages.insert(
            page,
            Hw {
                kind: Pte::ZeroPage,
                prot,
            },
        );
        Ok(())
    }
    fn map_anon_page(&mut self, page: u64, prot: PageProt) -> Result<(), OutOfMemory> {
        self.budget()?;
        self.pages.insert(
            page,
            Hw {
                kind: Pte::Anon {
                    writable: prot.write,
                },
                prot,
            },
        );
        Ok(())
    }
    fn make_writable(&mut self, page: u64) {
        if let Some(Hw {
            kind: Pte::Anon { writable },
            ..
        }) = self.pages.get_mut(&page)
        {
            *writable = true;
        }
    }
    fn unmap(&mut self, start: u64, pages: u64) -> u64 {
        let mut freed = 0;
        for i in 0..pages {
            if let Some(h) = self.pages.remove(&(start + i * P)) {
                freed += u64::from(matches!(h.kind, Pte::Anon { .. }));
            }
        }
        freed
    }
    fn protect(&mut self, start: u64, pages: u64, prot: PageProt) {
        for i in 0..pages {
            if let Some(h) = self.pages.get_mut(&(start + i * P)) {
                h.prot = prot;
                if let Pte::Anon { writable } = &mut h.kind {
                    *writable &= prot.write;
                }
            }
        }
    }
}

struct W {
    env: Env,
    mm: Mm,
    pt: Fake,
}

impl W {
    /// An exec'd-looking process: only the initial stack VMA
    /// (`setup_arg_pages`: `VM_STACK_FLAGS`, 36 pages, `pgoff = start >> 12`).
    fn new() -> Self {
        let env = Env::init(1 << 17, 0); // 512 MiB, no swap
        let mut mm = Mm::new(&env);
        let stack = Vma {
            start: STACK_START,
            end: TASK_SIZE,
            flags: VmFlags::STACK_FLAGS,
            pgoff: 0,
            file: None,
            anon: None,
        };
        mm.insert_vm_struct(&env, stack).unwrap();
        mm.total_vm = STACK_PAGES;
        mm.stack_vm = STACK_PAGES;
        Self {
            env,
            mm,
            pt: Fake::default(),
        }
    }
    fn map(&mut self, addr: u64, len: u64, prot: u64, flags: u64) -> Result<u64, Errno> {
        match self
            .mm
            .mmap(&self.env, &mut self.pt, addr, len, prot, flags, 0, None)?
        {
            Mmap::Mapped(a) => Ok(a),
            other => panic!("{other:?}"),
        }
    }
    fn munmap(&mut self, a: u64, l: u64) -> Result<(), Errno> {
        self.mm.munmap(&self.env, &mut self.pt, a, l)
    }
    fn mprotect(&mut self, a: u64, l: u64, p: u64) -> Result<(), Errno> {
        self.mm.mprotect(&self.env, &mut self.pt, a, l, p)
    }
    fn brk(&mut self, a: u64) -> u64 {
        self.mm.brk(&self.env, &mut self.pt, a)
    }
    fn fault(&mut self, a: u64, ec: u64) -> FaultOutcome {
        self.mm
            .handle_user_fault(&self.env, &mut self.pt, a, ec | PF_USER)
    }
    /// Is every page of the range inside some VMA (the oracle's `mapped()`).
    fn covered(&self, a: u64, len: u64) -> bool {
        let mut at = a;
        while at < a + len {
            match self.mm.find_vma(at) {
                Some(v) if v.start <= at => at = v.end,
                _ => return false,
            }
        }
        true
    }
    /// One user access as the CPU would take it: faults until it succeeds or
    /// a signal is decided. `kind`: 0 read, 1 write, 2 fetch.
    fn access(&mut self, addr: u64, kind: u8) -> FaultOutcome {
        for _ in 0..4 {
            let page = addr & !(P - 1);
            let hw = self.pt.pages.get(&page).copied();
            let ec = match (hw, kind) {
                (Some(h), 0) if h.prot.accessible => return FaultOutcome::Handled,
                (Some(h), 1) if h.prot.accessible && h.kind == (Pte::Anon { writable: true }) => {
                    return FaultOutcome::Handled;
                }
                (Some(h), 2) if h.prot.accessible && h.prot.exec => return FaultOutcome::Handled,
                (Some(h), k) if h.prot.accessible => {
                    PF_PROT
                        | if k == 1 {
                            PF_WRITE
                        } else if k == 2 {
                            PF_INSTR
                        } else {
                            0
                        }
                }
                (_, k) => {
                    if k == 1 {
                        PF_WRITE
                    } else if k == 2 {
                        PF_INSTR
                    } else {
                        0
                    }
                }
            };
            match self.fault(addr, ec) {
                FaultOutcome::Handled => {}
                other => return other,
            }
        }
        panic!("fault loop at {addr:#x}");
    }
    fn readable(&mut self, a: u64) -> bool {
        self.access(a, 0) == FaultOutcome::Handled
    }
    fn writable(&mut self, a: u64) -> bool {
        self.access(a, 1) == FaultOutcome::Handled
    }
    fn maps(&self) -> Vec<(u64, u64, u64)> {
        self.mm
            .vmas()
            .iter()
            .map(|v| (v.start, v.end, v.flags.0 & VmFlags::ACCESS.0))
            .collect()
    }
    fn check_invariants(&self) {
        let v = self.mm.vmas();
        for w in v.windows(2) {
            assert!(w[0].end <= w[1].start, "overlap {w:?}");
        }
        for a in v {
            assert!(a.start < a.end && a.start % P == 0 && a.end % P == 0 && a.end <= TASK_SIZE);
        }
        let total: u64 = v.iter().map(Vma::pages).sum();
        assert_eq!(self.mm.total_vm, total, "total_vm");
        assert_eq!(self.mm.map_count(), v.len() as u64);
    }
}

// ---- layout -------------------------------------------------------------

/// src: arch/x86/mm/mmap.c `mmap_base` (gap = 8 MiB + 256 pages is below the
/// 128 MiB floor) and `__TASK_UNMAPPED_BASE` = PAGE_ALIGN(TASK_SIZE/3).
#[test]
fn layout_default_matches_oracle_top() {
    let w = W::new();
    assert_eq!(w.mm.mmap_base, MMAP_TOP);
    assert_eq!(w.mm.mmap_base, 0x7fff_f7ff_f000);
    assert_eq!(w.mm.mmap_legacy_base, 0x2aaa_aaaa_b000);
    assert!(w.mm.topdown);
}

/// src: `mmap_base` clamp: gap = rlim + guard gap; `gap + pad > gap` guards
/// the overflow at RLIM_INFINITY; the cap is (TASK_SIZE / 6) * 5.
#[test]
fn layout_stack_rlimit_gap_and_clamp() {
    let mut env = Env::init(1 << 17, 0);
    env.rlimit_stack = 1 << 30;
    assert_eq!(pick_mmap_base(&env).0, TASK_SIZE - (1 << 30) - 0x10_0000);
    env.rlimit_stack = RLIM_INFINITY;
    assert_eq!(pick_mmap_base(&env).0, 0x1555_5555_6000);
    env.rlimit_stack = 0;
    assert_eq!(pick_mmap_base(&env).0, MMAP_TOP);
    env.rlimit_stack = 120 * 1024 * 1024; // + 1 MiB guard = 121 MiB < 128 MiB
    assert_eq!(pick_mmap_base(&env).0, MMAP_TOP);
    env.rlimit_stack = 200 * 1024 * 1024;
    assert_eq!(pick_mmap_base(&env).0, TASK_SIZE - 201 * 1024 * 1024);
}

// ---- mmap ---------------------------------------------------------------

/// oracle: mmap-first, mmap-second-adjacent, mmap-hint, mmap-hint-occupied,
/// mmap-hint-unaligned, mmap-hint-low, mmap-hint-straddle, mmap-32bit.
#[test]
fn mmap_placement_matches_oracle() {
    let mut w = W::new();
    let a = MMAP_TOP - 2 * P;
    assert_eq!(w.map(0, 2 * P, RW, ANON), Ok(a));
    assert_eq!(w.map(0, P, RW, ANON), Ok(a - P));
    let hint = 0x1000_0000;
    assert_eq!(w.map(hint, P, RW, ANON), Ok(hint));
    assert_eq!(w.map(hint, P, RW, ANON), Ok(a - 2 * P));
    // x86 rounds a non-fixed hint *down*.
    assert_eq!(
        w.map(hint + 0x1000_0123, P, RW, ANON),
        Ok(hint + 0x1000_0000)
    );
    // Neither arch_get_unmapped_area nor the root capability checks mmap_min_addr.
    assert_eq!(w.map(0x1000, P, RW, ANON), Ok(0x1000));
    assert_eq!(w.munmap(0x1000, P), Ok(()));
    assert_eq!(w.map(hint - P / 2, 2 * P, RW, ANON), Ok(a - 4 * P));
    assert_eq!(w.map(0, P, RW, ANON | MAP_32BIT), Ok(0x4000_0000));
    w.check_invariants();
}

/// oracle: mmap-fixed, mmap-fixed-replace(-data), mmap-fixed-low,
/// mmap-fixed-unaligned, mmap-fixed-past-task-size, -straddles-task-size.
#[test]
fn mmap_fixed_matches_oracle() {
    let mut w = W::new();
    let f = 0x3000_0000;
    assert_eq!(w.map(f, 3 * P, RW, ANON | MAP_FIXED), Ok(f));
    for i in 0..3 {
        assert!(w.writable(f + i * P));
    }
    assert_eq!(w.pt.pages.len(), 3);
    assert_eq!(w.map(f + P, P, RW, ANON | MAP_FIXED), Ok(f + P));
    // The replaced page is gone from the tables (zero-filled on next touch).
    assert_eq!(w.pt.lookup(f + P), Pte::Absent);
    assert_ne!(w.pt.lookup(f), Pte::Absent);
    assert_eq!(w.map(f + 1, P, RW, ANON | MAP_FIXED), Err(Errno::EINVAL));
    assert_eq!(
        w.map(TASK_SIZE, P, RW, ANON | MAP_FIXED),
        Err(Errno::ENOMEM)
    );
    assert_eq!(
        w.map(TASK_SIZE - P, 2 * P, RW, ANON | MAP_FIXED),
        Err(Errno::ENOMEM)
    );
    w.check_invariants();
}

/// oracle: noreplace-free/exact/tail/head/adjacent/unaligned.
#[test]
fn mmap_fixed_noreplace_matches_oracle() {
    let mut w = W::new();
    let nr = 0x5000_0000;
    let f = ANON | MAP_FIXED_NOREPLACE;
    assert_eq!(w.map(nr, 2 * P, RW, f), Ok(nr));
    assert_eq!(w.map(nr, 2 * P, RW, f), Err(Errno::EEXIST));
    assert_eq!(w.map(nr + P, 2 * P, RW, f), Err(Errno::EEXIST));
    assert_eq!(w.map(nr - P, 2 * P, RW, f), Err(Errno::EEXIST));
    assert_eq!(w.map(nr + 2 * P, P, RW, f), Ok(nr + 2 * P));
    assert_eq!(w.map(nr + 3 * P + 1, P, RW, f), Err(Errno::EINVAL));
}

/// oracle: mmap-len-zero, mmap-no-sharing, mmap-len-max, mmap-len-wraps-page-align,
/// mmap-len-over-task-size, mmap-len-no-room, mmap-unaligned-offset (x86 wrapper).
#[test]
fn mmap_argument_errors_match_oracle() {
    let mut w = W::new();
    assert_eq!(w.map(0, 0, RW, ANON), Err(Errno::EINVAL));
    assert_eq!(w.map(0, P, RW, MAP_ANONYMOUS), Err(Errno::EINVAL));
    assert_eq!(mmap_off_to_pgoff(1), Err(Errno::EINVAL));
    assert_eq!(mmap_off_to_pgoff(P), Ok(1));
    assert_eq!(w.map(0, u64::MAX, RW, ANON), Err(Errno::ENOMEM));
    assert_eq!(w.map(0, u64::MAX - 100, RW, ANON), Err(Errno::ENOMEM));
    assert_eq!(w.map(0, TASK_SIZE + P, RW, ANON), Err(Errno::ENOMEM));
    assert_eq!(w.map(0, TASK_SIZE - P, RW, ANON), Err(Errno::ENOMEM));
    // MAP_SHARED_VALIDATE (3) without a file is not a type (do_mmap anon switch).
    assert_eq!(
        w.map(0, P, RW, MAP_ANONYMOUS | MAP_SHARED_VALIDATE),
        Err(Errno::EINVAL)
    );
    w.check_invariants();
}

/// oracle: prot-unknown-bit, flag-noreserve, flag-populate, flag-stack,
/// flag-growsdown, prot-none-addr, prot-exec-rwx.
#[test]
fn mmap_flags_and_prot_matches_oracle() {
    let mut w = W::new();
    let mut a = MMAP_TOP;
    for (prot, flags) in [
        (PROT_NONE, ANON),
        (RW, ANON),
        (0x40, ANON), // unknown prot bits are ignored by mmap, rejected by mprotect
        (RW, ANON | MAP_NORESERVE),
        (RW, ANON | MAP_POPULATE),
        (RW, ANON | MAP_STACK),
        (RW, ANON | MAP_GROWSDOWN),
    ] {
        a -= P;
        assert_eq!(w.map(0, P, prot, flags), Ok(a), "{prot:#x} {flags:#x}");
    }
    // MAP_POPULATE faulted the page in writable (populate_vma_page_range FOLL_WRITE).
    assert_eq!(w.pt.lookup(MMAP_TOP - 5 * P), Pte::Anon { writable: true });
    // MAP_GROWSDOWN makes a growsdown VMA (calc_vm_flag_bits).
    assert!(w.mm.find_vma(a).unwrap().flags.contains(VmFlags::GROWSDOWN));
    // PROT_NONE is mapped but inaccessible.
    assert!(w.covered(MMAP_TOP - P, P));
    assert!(!w.readable(MMAP_TOP - P));
    assert_eq!(
        w.access(MMAP_TOP - P, 0),
        FaultOutcome::Segv {
            code: SegvCode::AccErr,
            address: MMAP_TOP - P
        }
    );
}

/// src: mm/mmap.c do_mmap anon switch; MAP_DROPPABLE is bit 3 of MAP_TYPE.
#[test]
fn mmap_droppable_and_unsupported() {
    let mut w = W::new();
    let a = w.map(0, P, RW, MAP_ANONYMOUS | MAP_DROPPABLE).unwrap();
    let v = *w.mm.find_vma(a).unwrap();
    assert!(v.flags.contains(
        VmFlags::DROPPABLE | VmFlags::NORESERVE | VmFlags::WIPEONFORK | VmFlags::DONTDUMP
    ));
    assert_eq!(v.pgoff, a >> 12);
    assert_eq!(
        w.map(0, P, RW, MAP_ANONYMOUS | MAP_DROPPABLE | MAP_LOCKED),
        Err(Errno::EINVAL)
    );
    assert_eq!(
        w.map(0, P, RW, MAP_ANONYMOUS | MAP_DROPPABLE | MAP_GROWSDOWN),
        Err(Errno::EINVAL)
    );
    // 0x0a = MAP_DROPPABLE | MAP_PRIVATE is not a type.
    assert_eq!(
        w.map(0, P, RW, MAP_ANONYMOUS | MAP_DROPPABLE | MAP_PRIVATE),
        Err(Errno::EINVAL)
    );
    // Shared anonymous memory and hugetlb stop before any change.
    let before = w.maps();
    let shared = w.mm.mmap(
        &w.env,
        &mut w.pt,
        0,
        P,
        RW,
        MAP_ANONYMOUS | MAP_SHARED,
        0,
        None,
    );
    assert!(matches!(
        shared,
        Ok(Mmap::Unsupported(Unsupported::SharedAnonymous))
    ));
    let huge =
        w.mm.mmap(&w.env, &mut w.pt, 0, P, RW, ANON | MAP_HUGETLB, 0, None);
    assert!(matches!(huge, Ok(Mmap::Unsupported(Unsupported::Hugetlb))));
    assert_eq!(w.maps(), before);
    // MAP_SHARED | MAP_GROWSDOWN is refused before shmem is needed.
    assert_eq!(
        w.map(0, P, RW, MAP_ANONYMOUS | MAP_SHARED | MAP_GROWSDOWN),
        Err(Errno::EINVAL)
    );
}

/// src: mm/mmap.c do_mmap file branch order.
#[test]
fn mmap_file_branch_checks_and_typed_outcome() {
    let mut w = W::new();
    let f = FileInfo {
        id: 7,
        readable: true,
        writable: false,
        noexec: false,
        swapfile: false,
        append_only: false,
        can_mmap: true,
        mmap_size_max: u64::MAX >> 1,
        mmap_sync: false,
        hugepages: false,
    };
    let call = |w: &mut W, f: &FileInfo, prot, flags, pgoff| {
        w.mm.mmap(&w.env, &mut w.pt, 0, P, prot, flags, pgoff, Some(f))
    };
    // MAP_PRIVATE writable of a read-only file is fine (copy-on-write).
    let r = call(&mut w, &f, RW, MAP_PRIVATE, 3).unwrap();
    let Mmap::NeedsFile(m) = r else {
        panic!("{r:?}")
    };
    assert_eq!((m.addr, m.len, m.pgoff, m.file.id), (MMAP_TOP - P, P, 3, 7));
    assert!(
        m.vm_flags
            .contains(VmFlags::READ | VmFlags::WRITE | VmFlags::MAYWRITE)
    );
    assert!(!m.vm_flags.contains(VmFlags::SHARED));
    assert_eq!(
        w.mm.vmas().len(),
        1,
        "nothing is mapped until the VFS commits"
    );
    // MAP_SHARED + PROT_WRITE on a file not opened for writing.
    assert_eq!(
        call(&mut w, &f, RW, MAP_SHARED, 0).err(),
        Some(Errno::EACCES)
    );
    // A shared read-only mapping drops MAYWRITE/SHARED.
    let Ok(Mmap::NeedsFile(m)) = call(&mut w, &f, PROT_READ, MAP_SHARED, 0) else {
        panic!()
    };
    assert!(
        m.vm_flags.contains(VmFlags::MAYSHARE)
            && !m.vm_flags.contains(VmFlags::MAYWRITE | VmFlags::SHARED)
    );
    // MAP_SHARED_VALIDATE rejects flags outside the legacy mask.
    assert_eq!(
        call(
            &mut w,
            &f,
            PROT_READ,
            MAP_SHARED_VALIDATE | MAP_FIXED_NOREPLACE,
            0
        )
        .err(),
        Some(Errno::EOPNOTSUPP)
    );
    assert_eq!(call(&mut w, &f, PROT_READ, 0, 0).err(), Some(Errno::EINVAL));
    let unreadable = FileInfo {
        readable: false,
        ..f
    };
    assert_eq!(
        call(&mut w, &unreadable, PROT_READ, MAP_PRIVATE, 0).err(),
        Some(Errno::EACCES)
    );
    let noexec = FileInfo { noexec: true, ..f };
    assert_eq!(
        call(&mut w, &noexec, PROT_READ | PROT_EXEC, MAP_PRIVATE, 0).err(),
        Some(Errno::EPERM)
    );
    let Ok(Mmap::NeedsFile(m)) = call(&mut w, &noexec, PROT_READ, MAP_PRIVATE, 0) else {
        panic!()
    };
    assert!(!m.vm_flags.contains(VmFlags::MAYEXEC));
    let nommap = FileInfo {
        can_mmap: false,
        ..f
    };
    assert_eq!(
        call(&mut w, &nommap, PROT_READ, MAP_PRIVATE, 0).err(),
        Some(Errno::ENODEV)
    );
    assert_eq!(
        call(&mut w, &f, PROT_READ, MAP_PRIVATE | MAP_GROWSDOWN, 0).err(),
        Some(Errno::EINVAL)
    );
    assert_eq!(
        call(&mut w, &f, PROT_READ, MAP_PRIVATE, u64::MAX).err(),
        Some(Errno::EOVERFLOW)
    );
    // MAP_HUGETLB on a non-hugetlb file is EINVAL (ksys_mmap_pgoff).
    assert_eq!(
        call(&mut w, &f, PROT_READ, MAP_PRIVATE | MAP_HUGETLB, 0).err(),
        Some(Errno::EINVAL)
    );
    // The VFS owner commits through mmap_region; the VMA then carries the file.
    let Ok(Mmap::NeedsFile(m)) = call(&mut w, &f, PROT_READ, MAP_PRIVATE, 5) else {
        panic!()
    };
    w.mm.mmap_region(
        &w.env,
        &mut w.pt,
        Some(m.file.id),
        m.addr,
        m.len,
        m.vm_flags,
        m.pgoff,
    )
    .unwrap();
    assert_eq!(w.mm.find_vma(m.addr).unwrap().file, Some(7));
    assert!(matches!(
        w.fault(m.addr, 0),
        FaultOutcome::NeedsFile { write: false, .. }
    ));
}

/// src: mm/mmap.c do_mmap: MAP_FIXED_NOREPLACE -> EEXIST is after
/// get_unmapped_area; limits: sysctl_max_map_count (`>`), RLIMIT_AS, overcommit.
#[test]
fn mmap_limits() {
    let mut w = W::new();
    // do_mmap refuses when map_count > max_map_count (strictly greater).
    w.env.max_map_count = 3;
    assert_eq!(w.map(0, P, PROT_NONE, ANON), Ok(MMAP_TOP - P));
    assert_eq!(w.map(0, P, RW, ANON), Ok(MMAP_TOP - 2 * P)); // map_count 2 -> 3
    assert_eq!(w.map(0, P, PROT_READ, ANON), Ok(MMAP_TOP - 3 * P)); // 3 is not > 3 -> 4
    assert_eq!(w.map(0, P, PROT_EXEC, ANON), Err(Errno::ENOMEM));
    w.env.max_map_count = 65530;
    // RLIMIT_AS: total_vm + pages > limit.
    let total = w.mm.total_vm;
    w.env.rlimit_as = (total + 2) * P;
    assert_eq!(w.map(0, 3 * P, RW, ANON), Err(Errno::ENOMEM));
    assert!(w.map(0, 2 * P, RW, ANON).is_ok());
    w.env.rlimit_as = RLIM_INFINITY;
    // Overcommit heuristic: a request larger than RAM + swap is refused (private writable only).
    assert_eq!(w.map(0, (1 << 17) * P + P, RW, ANON), Err(Errno::ENOMEM));
    assert!(w.map(0, (1 << 17) * P + P, PROT_READ, ANON).is_ok());
    // RLIMIT_DATA applies to private writable mappings.
    w.env.rlimit_data = w.mm.data_vm * P;
    assert_eq!(w.map(0, P, RW, ANON), Err(Errno::ENOMEM));
    assert!(w.map(0, P, PROT_READ, ANON).is_ok());
    w.env.rlimit_data = RLIM_INFINITY;
    // MAP_LOCKED needs CAP_IPC_LOCK or room under RLIMIT_MEMLOCK.
    w.env.cap_ipc_lock = false;
    w.env.rlimit_memlock = 0;
    assert_eq!(w.map(0, P, RW, ANON | MAP_LOCKED), Err(Errno::EPERM));
    w.env.rlimit_memlock = 2 * P;
    assert_eq!(w.map(0, 3 * P, RW, ANON | MAP_LOCKED), Err(Errno::EAGAIN));
    assert!(w.map(0, 2 * P, RW, ANON | MAP_LOCKED).is_ok());
    assert_eq!(w.mm.locked_vm, 2);
    w.check_invariants();
}

/// src: mm/vma.c vma_merge_new_range; observable as map_count (vm.max_map_count,
/// /proc/self/maps lines).
#[test]
fn mmap_adjacent_anonymous_vmas_merge() {
    let mut w = W::new();
    let base = w.mm.map_count();
    let a = w.map(0, P, RW, ANON).unwrap();
    assert_eq!(w.mm.map_count(), base + 1);
    // Directly below: merges to the right (pgoff continues), still one VMA.
    assert_eq!(w.map(0, P, RW, ANON), Ok(a - P));
    assert_eq!(w.mm.map_count(), base + 1);
    assert_eq!(w.mm.find_vma(a).unwrap().start, a - P);
    // Different protection never merges.
    assert_eq!(w.map(0, P, PROT_READ, ANON), Ok(a - 2 * P));
    assert_eq!(w.mm.map_count(), base + 2);
    // MAP_FIXED between two compatible VMAs joins all three.
    let f = 0x2000_0000;
    w.map(f, P, RW, ANON | MAP_FIXED).unwrap();
    w.map(f + 2 * P, P, RW, ANON | MAP_FIXED).unwrap();
    assert_eq!(w.mm.map_count(), base + 4);
    w.map(f + P, P, RW, ANON | MAP_FIXED).unwrap();
    assert_eq!(w.mm.map_count(), base + 3);
    assert_eq!(w.mm.find_vma(f).unwrap().end, f + 3 * P);
    // VM_ACCOUNT and VM_NORESERVE are part of the flags: MAP_NORESERVE does not merge.
    w.map(f + 3 * P, P, RW, ANON | MAP_FIXED | MAP_NORESERVE)
        .unwrap();
    assert_eq!(w.mm.map_count(), base + 4);
    w.check_invariants();
}

/// src: mm/vma.c is_mergeable_anon_vma / mm/vma.c find_mergeable_anon_vma +
/// anon_vma_prepare (rmap.c): two separately written VMAs have distinct
/// anon_vmas and cannot merge, a fresh neighbour reuses one.
#[test]
fn anon_vma_identity_controls_merging() {
    let mut w = W::new();
    let f = 0x2000_0000;
    w.map(f, P, RW, ANON | MAP_FIXED).unwrap();
    w.map(f + 2 * P, P, RW, ANON | MAP_FIXED).unwrap();
    // Touch both: each gets its own anon_vma (they are not adjacent).
    assert!(w.writable(f) && w.writable(f + 2 * P));
    let (a1, a2) = (
        w.mm.find_vma(f).unwrap().anon,
        w.mm.find_vma(f + 2 * P).unwrap().anon,
    );
    assert!(a1.is_some() && a2.is_some() && a1 != a2);
    // The middle page: can merge left (no anon yet) but left+right are incompatible,
    // so only the left neighbour absorbs it.
    w.map(f + P, P, RW, ANON | MAP_FIXED).unwrap();
    assert_eq!(
        w.maps()
            .iter()
            .filter(|m| m.0 >= f && m.0 < f + 4 * P)
            .count(),
        2
    );
    assert_eq!(w.mm.find_vma(f).unwrap().end, f + 2 * P);
    // A write fault in the absorbed page keeps the left anon_vma; the right one stays distinct.
    assert!(w.writable(f + P));
    assert_eq!(w.mm.find_vma(f).unwrap().anon, a1);
    // Faulting a new adjacent VMA reuses the neighbour's anon_vma (find_mergeable_anon_vma).
    w.map(f + 3 * P, P, RW | PROT_EXEC, ANON | MAP_FIXED)
        .unwrap();
    assert!(w.writable(f + 3 * P));
    assert_eq!(
        w.mm.find_vma(f + 3 * P).unwrap().anon,
        a2,
        "reused from prev (compatible modulo access flags)"
    );
}

// ---- munmap -------------------------------------------------------------

/// oracle: munmap-* checks.
#[test]
fn munmap_matches_oracle() {
    let mut w = W::new();
    let x = 0x4000_0000;
    assert_eq!(w.map(x, 5 * P, RW, ANON | MAP_FIXED), Ok(x));
    for i in 0..5 {
        assert!(w.writable(x + i * P));
    }
    assert_eq!(w.munmap(x, P), Ok(()));
    assert!(!w.covered(x, P) && w.covered(x + P, 4 * P));
    assert_eq!(w.munmap(x + 4 * P, P), Ok(()));
    assert_eq!(w.munmap(x + 2 * P, P), Ok(()));
    assert!(w.covered(x + P, P) && !w.covered(x + 2 * P, P) && w.covered(x + 3 * P, P));
    assert!(!w.covered(x + P, 3 * P));
    // tables follow the VMAs
    assert_eq!(w.pt.lookup(x + 2 * P), Pte::Absent);
    assert_ne!(w.pt.lookup(x + P), Pte::Absent);
    assert_eq!(w.munmap(x, 5 * P), Ok(()));
    assert!(!w.covered(x, 5 * P) && w.pt.pages.is_empty());
    assert_eq!(w.munmap(x, P), Ok(())); // unmapped range is not an error
    assert_eq!(w.munmap(x + 1, P), Err(Errno::EINVAL));
    assert_eq!(w.munmap(x, 0), Err(Errno::EINVAL));
    assert_eq!(w.munmap(x, u64::MAX), Err(Errno::EINVAL));
    assert_eq!(w.munmap(TASK_SIZE, P), Err(Errno::EINVAL));
    assert_eq!(w.munmap(TASK_SIZE - P, 2 * P), Err(Errno::EINVAL));
    // length rounds up
    assert_eq!(w.map(x, 2 * P, RW, ANON | MAP_FIXED), Ok(x));
    assert_eq!(w.munmap(x, 1), Ok(()));
    assert!(!w.covered(x, P) && w.covered(x + P, P));
    w.check_invariants();
}

/// src: mm/vma.c vms_gather_munmap_vmas: a hole punch needs one more VMA than
/// max_map_count allows -> ENOMEM before any split; a one-sided cut does not.
#[test]
fn munmap_hole_punch_respects_max_map_count() {
    let mut w = W::new();
    let x = 0x4000_0000;
    w.map(x, 3 * P, RW, ANON | MAP_FIXED).unwrap();
    w.env.max_map_count = w.mm.map_count() as u32;
    let before = w.maps();
    assert_eq!(w.munmap(x + P, P), Err(Errno::ENOMEM));
    assert_eq!(w.maps(), before, "nothing split");
    assert_eq!(w.munmap(x, P), Ok(())); // cutting an end needs no extra VMA
    w.check_invariants();
}

/// src: mm/vma.c `__mmap_setup`: the edge splits happen before the limit
/// checks and are not undone when `may_expand_vm` refuses (`vms_abort_munmap_vmas`
/// only reattaches).
#[test]
fn mmap_region_failure_leaves_edge_splits() {
    let mut w = W::new();
    let x = 0x4000_0000;
    w.map(x, 4 * P, RW, ANON | MAP_FIXED).unwrap();
    w.map(x + 6 * P, 2 * P, RW, ANON | MAP_FIXED).unwrap();
    let count = w.mm.map_count();
    w.env.rlimit_as = w.mm.total_vm * P;
    // [x+3P, x+7P) replaces 2 mapped pages with 4: +2 pages over the limit.
    assert_eq!(
        w.map(x + 3 * P, 4 * P, RW, ANON | MAP_FIXED),
        Err(Errno::ENOMEM)
    );
    assert_eq!(
        w.mm.map_count(),
        count + 2,
        "start split of the first, end split of the last"
    );
    assert!(w.covered(x, 4 * P) && w.covered(x + 6 * P, 2 * P) && !w.covered(x + 4 * P, 2 * P));
    w.env.rlimit_as = RLIM_INFINITY;
    w.check_invariants();
}

// ---- mprotect -----------------------------------------------------------

/// oracle: mprotect-* checks.
#[test]
fn mprotect_matches_oracle() {
    let mut w = W::new();
    let x = 0x6000_0000;
    assert_eq!(w.map(x, 3 * P, RW, ANON | MAP_FIXED), Ok(x));
    assert_eq!(w.mprotect(x + P, P, PROT_NONE), Ok(()));
    assert!(w.writable(x));
    assert!(!w.readable(x + P) && !w.writable(x + P));
    assert!(w.writable(x + 2 * P));
    assert!(w.covered(x, 3 * P));
    assert_eq!(w.mm.map_count(), 1 + 3);
    assert_eq!(w.mprotect(x, P, PROT_READ), Ok(()));
    assert!(w.readable(x) && !w.writable(x));
    assert_eq!(w.mprotect(x, 3 * P, RW), Ok(()));
    // The first and last pages were written (distinct anon_vmas), the middle one
    // never: the middle merges into its left neighbour only (is_mergeable_anon_vma).
    assert_eq!(w.mm.map_count(), 1 + 2);
    assert_eq!(w.mm.find_vma(x).unwrap().end, x + 2 * P);
    assert_eq!(w.mprotect(x + P, 2 * P, PROT_READ), Ok(()));
    assert_eq!(w.mprotect(x, 3 * P, RW), Ok(()));
    assert_eq!(w.mprotect(x + 1, P, PROT_READ), Err(Errno::EINVAL));
    assert_eq!(w.mprotect(x, P, 0x40), Err(Errno::EINVAL));
    assert_eq!(
        w.mprotect(x, P, 0x0300_0000 | PROT_READ),
        Err(Errno::EINVAL)
    );
    assert_eq!(w.mprotect(x, 0, PROT_READ), Ok(()));
    assert_eq!(w.mprotect(x, 0, 0x40), Ok(()));
    assert_eq!(w.mprotect(x, u64::MAX, PROT_READ), Err(Errno::ENOMEM));
    assert_eq!(w.mprotect(x, u64::MAX, 0x40), Err(Errno::ENOMEM));
    assert_eq!(w.mprotect(x - P, P, PROT_READ), Err(Errno::ENOMEM));
    assert_eq!(w.mprotect(x - P, 2 * P, PROT_READ), Err(Errno::ENOMEM));
    assert!(w.writable(x), "start in a hole changes nothing");
    // A hole after the first VMA: the leading part is already changed.
    assert_eq!(w.mprotect(x, 4 * P, PROT_READ), Err(Errno::ENOMEM));
    assert!(!w.writable(x) && w.readable(x) && !w.writable(x + 2 * P));
    assert_eq!(w.munmap(x, 3 * P), Ok(()));
    w.check_invariants();
}

/// oracle: mprotect-adjacent-a/b, mprotect-across-two-vmas (the two mappings
/// were already one VMA through the mmap merge).
#[test]
fn mprotect_across_merged_vmas() {
    let mut w = W::new();
    let x = 0x6000_0000;
    w.map(x, P, RW, ANON | MAP_FIXED).unwrap();
    w.map(x + P, P, RW, ANON | MAP_FIXED).unwrap();
    assert_eq!(w.mm.map_count(), 2);
    assert_eq!(w.mprotect(x, 2 * P, PROT_READ), Ok(()));
    assert!(w.readable(x) && !w.writable(x) && !w.writable(x + P));
    assert_eq!(w.mm.map_count(), 2);
}

/// src: mm/mprotect.c do_mprotect_pkey: `(newflags & ~(newflags >> 4)) &
/// VM_ACCESS_FLAGS` is EACCES (only possible with a file's VM_MAY* limits);
/// PROT_GROWSDOWN needs VM_GROWSDOWN; PROT_GROWSUP never matches on x86.
#[test]
fn mprotect_growsdown_rules() {
    let mut w = W::new();
    let x = 0x6000_0000;
    w.map(x, 2 * P, RW, ANON | MAP_FIXED).unwrap();
    assert_eq!(
        w.mprotect(x, P, PROT_GROWSDOWN | PROT_READ),
        Err(Errno::EINVAL)
    );
    assert_eq!(
        w.mprotect(x, P, PROT_GROWSUP | PROT_READ),
        Err(Errno::EINVAL)
    );
    // On the stack, PROT_GROWSDOWN extends the change down to vm_start.
    assert_eq!(
        w.mprotect(STACK_START + 4 * P, P, PROT_GROWSDOWN | PROT_READ),
        Ok(())
    );
    let s = w.mm.find_vma(TASK_SIZE - P).unwrap();
    assert_eq!((s.start, s.end), (STACK_START + 5 * P, TASK_SIZE));
    // vm_start >= end with GROWSDOWN is ENOMEM.
    assert_eq!(
        w.mprotect(x - P, P, PROT_GROWSDOWN | PROT_READ),
        Err(Errno::ENOMEM)
    );
}

/// src: mprotect_fixup: split needs map_count < max (split_vma), merge does not.
#[test]
fn mprotect_split_respects_max_map_count() {
    let mut w = W::new();
    let x = 0x6000_0000;
    w.map(x, 3 * P, RW, ANON | MAP_FIXED).unwrap();
    w.env.max_map_count = w.mm.map_count() as u32;
    let before = w.maps();
    assert_eq!(w.mprotect(x + P, P, PROT_READ), Err(Errno::ENOMEM));
    assert_eq!(w.maps(), before);
    assert_eq!(w.mprotect(x, 3 * P, PROT_READ), Ok(())); // whole VMA: no split
}

/// src: mprotect_fixup accounting: making a private mapping writable charges
/// and sets VM_ACCOUNT; making it read-only again before any write fault drops it.
#[test]
fn mprotect_updates_account_and_stats() {
    let mut w = W::new();
    let x = 0x6000_0000;
    w.map(x, 2 * P, PROT_READ, ANON | MAP_FIXED).unwrap();
    assert_eq!(w.mm.data_vm, 0);
    assert_eq!(w.mprotect(x, 2 * P, RW), Ok(()));
    assert!(w.mm.find_vma(x).unwrap().flags.contains(VmFlags::ACCOUNT));
    assert_eq!(w.mm.data_vm, 2);
    assert_eq!(w.mprotect(x, 2 * P, PROT_READ), Ok(()));
    assert!(
        !w.mm.find_vma(x).unwrap().flags.contains(VmFlags::ACCOUNT),
        "no anon_vma yet"
    );
    assert_eq!(w.mm.data_vm, 0);
    // After a write fault the anon_vma exists and ACCOUNT stays.
    assert_eq!(w.mprotect(x, 2 * P, RW), Ok(()));
    assert!(w.writable(x));
    assert_eq!(w.mprotect(x, 2 * P, PROT_READ), Ok(()));
    assert!(w.mm.find_vma(x).unwrap().flags.contains(VmFlags::ACCOUNT));
    // RLIMIT_DATA: refused when the area turns into data.
    w.env.rlimit_data = 0;
    w.env.rlimit_data_max = 0;
    assert_eq!(w.mprotect(x, 2 * P, RW), Err(Errno::ENOMEM));
}

// ---- brk ----------------------------------------------------------------

/// A static executable's layout: text (file), data (file), bss (`vm_brk_flags`)
/// and the break starting at the page-aligned end of bss.
fn exec_world() -> (W, u64) {
    let mut w = W::new();
    let env = w.env;
    let ins = |w: &mut W, s: u64, e: u64, fl: VmFlags, pgoff| {
        let v = Vma {
            start: s,
            end: e,
            flags: fl,
            pgoff,
            file: Some(1),
            anon: None,
        };
        w.mm.insert_vm_struct(&env, v).unwrap();
        w.mm.total_vm += (e - s) / P;
    };
    let base = VmFlags::MAYREAD | VmFlags::MAYWRITE | VmFlags::MAYEXEC;
    ins(
        &mut w,
        0x40_0000,
        0x40_2000,
        VmFlags::READ | VmFlags::EXEC | base,
        0,
    );
    ins(
        &mut w,
        0x40_2000,
        0x40_3000,
        VmFlags::READ | VmFlags::WRITE | base,
        2,
    );
    w.mm.vm_brk_flags(&env, &mut w.pt, 0x40_3000, 0x2000, VmFlags::NONE)
        .unwrap();
    let start = 0x40_5000;
    w.mm.start_brk = start;
    w.mm.brk = start;
    w.mm.start_data = 0x40_2000;
    w.mm.end_data = 0x40_3000;
    (w, start)
}

/// oracle: brk-query .. brk-reset; the sequence of `brk_checks`.
#[test]
fn brk_matches_oracle() {
    let (mut w, start) = exec_world();
    assert_eq!(w.brk(0), start, "brk(0) is below start_brk: unchanged");
    assert_eq!(w.brk(start + 3 * P), start + 3 * P);
    assert!(w.covered(start, 3 * P) && !w.covered(start + 3 * P, P));
    assert!(w.writable(start) && w.writable(start + 3 * P - 1));
    assert_eq!(w.brk(start + 3 * P + 5), start + 3 * P + 5);
    assert!(w.covered(start, 4 * P) && !w.covered(start + 4 * P, P));
    assert_eq!(w.brk(start + P), start + P);
    assert!(!w.covered(start + P, P) && w.covered(start, P));
    assert_eq!(w.pt.lookup(start + 2 * P), Pte::Absent);
    assert_ne!(w.pt.lookup(start), Pte::Absent);
    assert_eq!(w.brk(0x10000), start + P);
    assert_eq!(w.brk(start + 3 * P), start + 3 * P);
    // A mapping in the way: newbrk + PAGE_SIZE must not reach the next vma.
    let wall = start + 0x10_000;
    assert_eq!(w.map(wall, P, RW, ANON | MAP_FIXED), Ok(wall));
    assert_eq!(w.brk(wall - P), wall - P);
    assert_eq!(w.brk(wall), wall - P);
    assert_eq!(w.brk(wall - P + 1), wall - P);
    assert_eq!(w.munmap(wall, P), Ok(()));
    // The stack's guard gap stops the break far below TASK_SIZE.
    assert_eq!(w.brk(TASK_SIZE - P), wall - P);
    assert_eq!(w.brk(start), start);
    assert!(!w.covered(start, P));
    w.check_invariants();
}

/// src: mm/mmap.c brk -> vma_prev_limit(start_brk): the heap never merges
/// into the bss VMA that ends exactly at start_brk, but later growth extends
/// the heap VMA itself (`do_brk_flags` with `just_expand`).
#[test]
fn brk_heap_is_separate_from_bss_and_extends_in_place() {
    let (mut w, start) = exec_world();
    let n = w.mm.map_count();
    assert_eq!(w.brk(start + P), start + P);
    assert_eq!(w.mm.map_count(), n + 1);
    assert_eq!(w.brk(start + 5 * P), start + 5 * P);
    assert_eq!(w.mm.map_count(), n + 1);
    let h = w.mm.find_vma(start).unwrap();
    assert_eq!((h.start, h.end), (start, start + 5 * P));
    assert_eq!(h.flags, VmFlags::DATA_DEFAULT | VmFlags::ACCOUNT);
    assert_eq!(h.pgoff, start >> 12);
    // data_vm and total_vm moved with it.
    assert_eq!(
        w.mm.data_vm,
        2 + 5,
        "bss + heap (the file data page is not accounted by this fixture)"
    );
}

/// src: include/linux/mm.h check_data_rlimit: (brk - start_brk) + (end_data -
/// start_data) > rlim is refused, byte-exact (may_expand_vm is page-granular).
#[test]
fn brk_rlimit_data() {
    let (mut w, start) = exec_world();
    w.mm.end_data = w.mm.start_data + 10 * P; // a large data segment
    w.env.rlimit_data = 12 * P;
    assert_eq!(w.brk(start + 2 * P), start + 2 * P); // 2P + 10P == 12P
    assert_eq!(w.brk(start + 2 * P + 1), start + 2 * P); // over by one byte
    // may_expand_vm's page-granular RLIMIT_DATA check also applies (bss is 2 pages).
    w.env.rlimit_data = 4 * P;
    w.mm.end_data = w.mm.start_data;
    assert_eq!(w.brk(start + 3 * P), start + 2 * P, "2 + 3 data pages > 4");
    assert_eq!(
        w.brk(start + 2 * P - 1),
        start + 2 * P - 1,
        "shrinking is always allowed"
    );
}

/// src: sys_brk shrink: `!brkvma || brkvma->vm_start >= oldbrk` -> unchanged.
#[test]
fn brk_shrink_over_foreign_mapping_is_refused() {
    let (mut w, start) = exec_world();
    assert_eq!(w.brk(start + 4 * P), start + 4 * P);
    // Replace the middle of the heap with a differently-protected mapping.
    w.map(start + P, P, PROT_READ, ANON | MAP_FIXED).unwrap();
    // Shrinking through it still works (munmap semantics of do_vmi_align_munmap).
    assert_eq!(w.brk(start), start);
    assert!(!w.covered(start, 4 * P));
    // brk below nothing mapped: shrink with no VMA in range is refused.
    assert_eq!(w.brk(start + 3 * P), start + 3 * P);
    assert_eq!(w.munmap(start, 3 * P), Ok(()));
    assert_eq!(
        w.brk(start + P),
        start + 3 * P,
        "no brk vma to shrink: unchanged"
    );
}

// ---- page fault ---------------------------------------------------------

/// src: do_anonymous_page: a read maps the zero page read-only; a write maps
/// a private frame; a later write to the zero page copies (wp_page_copy).
#[test]
fn fault_demand_zero_read_then_write() {
    let mut w = W::new();
    let a = w.map(0, 2 * P, RW, ANON).unwrap();
    assert_eq!(w.fault(a + 5, 0), FaultOutcome::Handled);
    assert_eq!(w.pt.lookup(a), Pte::ZeroPage);
    assert_eq!(
        w.mm.find_vma(a).unwrap().anon,
        None,
        "a read fault does not prepare an anon_vma"
    );
    assert_eq!(w.fault(a + 5, PF_PROT | PF_WRITE), FaultOutcome::Handled);
    assert_eq!(w.pt.lookup(a), Pte::Anon { writable: true });
    assert!(w.mm.find_vma(a).unwrap().anon.is_some());
    assert_eq!(w.fault(a + P, PF_WRITE), FaultOutcome::Handled);
    assert_eq!(w.pt.lookup(a + P), Pte::Anon { writable: true });
    // After mprotect(READ) -> mprotect(RW) the page is read-only until the write fault makes it writable.
    w.mprotect(a, 2 * P, PROT_READ).unwrap();
    w.mprotect(a, 2 * P, RW).unwrap();
    assert_eq!(w.pt.lookup(a), Pte::Anon { writable: false });
    assert_eq!(w.fault(a, PF_PROT | PF_WRITE), FaultOutcome::Handled);
    assert_eq!(w.pt.lookup(a), Pte::Anon { writable: true });
}

/// src: arch/x86/mm/fault.c access_error + bad_area*, lock_mm_and_find_vma.
#[test]
fn fault_signals() {
    let mut w = W::new();
    let ro = w.map(0, P, PROT_READ, ANON).unwrap();
    let none = w.map(0, P, PROT_NONE, ANON).unwrap();
    let x = w.map(0, P, PROT_READ | PROT_EXEC, ANON).unwrap();
    let acc = |address| FaultOutcome::Segv {
        code: SegvCode::AccErr,
        address,
    };
    let map = |address| FaultOutcome::Segv {
        code: SegvCode::MapErr,
        address,
    };
    assert_eq!(w.fault(ro + 8, PF_WRITE), acc(ro + 8));
    assert_eq!(w.fault(ro, PF_PROT | PF_WRITE), acc(ro));
    assert_eq!(w.fault(none + 1, 0), acc(none + 1));
    assert_eq!(w.fault(none, PF_WRITE), acc(none));
    // Read of a present page with a protection violation is always an access error.
    assert_eq!(w.fault(ro, PF_PROT), acc(ro));
    // A fetch from a non-exec page: not-present is "a read" and succeeds (the page is
    // mapped, NX); the retried fetch then faults with PF_PROT and is refused.
    assert_eq!(w.access(ro, 2), acc(ro));
    assert_ne!(w.pt.lookup(ro), Pte::Absent);
    assert_eq!(w.access(x, 2), FaultOutcome::Handled);
    // Unmapped, below mmap area, and kernel addresses.
    assert_eq!(w.fault(0x1000, 0), map(0x1000));
    assert_eq!(w.fault(0, PF_WRITE), map(0));
    assert_eq!(w.fault(TASK_SIZE, 0), map(TASK_SIZE));
    assert_eq!(
        w.fault(0xffff_ffff_ff60_0000, PF_INSTR),
        map(0xffff_ffff_ff60_0000)
    );
    assert_eq!(
        w.fault(0xffff_8000_0000_0000, PF_WRITE),
        map(0xffff_8000_0000_0000)
    );
    // Unresolvable hardware causes.
    assert_eq!(w.fault(ro, PF_PK), acc(ro));
    assert_eq!(w.fault(ro, PF_SHSTK), acc(ro));
    assert_eq!(w.fault(ro, PF_RSVD | PF_PROT), FaultOutcome::PgtableBad);
    // Kernel-address check comes first, then reserved bits.
    assert_eq!(w.fault(TASK_SIZE, PF_RSVD), map(TASK_SIZE));
}

/// src: do_anonymous_page: VM_SHARED without vm_ops -> SIGBUS; OOM -> VM_FAULT_OOM,
/// tables unchanged.
#[test]
fn fault_oom_and_bus() {
    let mut w = W::new();
    let a = w.map(0, P, RW, ANON).unwrap();
    w.pt.fail_maps = Some(0);
    assert_eq!(w.fault(a, PF_WRITE), FaultOutcome::Oom);
    assert_eq!(w.fault(a, 0), FaultOutcome::Oom);
    assert!(w.pt.pages.is_empty());
    w.pt.fail_maps = None;
    assert_eq!(w.fault(a, PF_WRITE), FaultOutcome::Handled);
    // A VM_SHARED VMA with no object cannot be built by the system calls; build one directly.
    let v = Vma {
        start: 0x7000_0000,
        end: 0x7000_1000,
        flags: VmFlags::READ | VmFlags::SHARED | VmFlags::MAYREAD,
        pgoff: 0,
        file: None,
        anon: None,
    };
    w.mm.insert_vm_struct(&w.env, v).unwrap();
    assert_eq!(
        w.fault(0x7000_0000, 0),
        FaultOutcome::Bus {
            address: 0x7000_0000
        }
    );
}

/// src: expand_downwards/acct_stack_growth/lock_mm_and_find_vma.
#[test]
fn fault_stack_growth() {
    let mut w = W::new();
    let below = STACK_START - P;
    // One page below the stack: expands, no new VMA, pgoff follows start.
    assert_eq!(w.fault(below + 8, PF_WRITE), FaultOutcome::Handled);
    let s = *w.mm.find_vma(below).unwrap();
    assert_eq!((s.start, s.end, s.pgoff), (below, TASK_SIZE, below >> 12));
    assert_eq!(w.mm.map_count(), 1);
    assert_eq!(w.mm.stack_vm, STACK_PAGES + 1);
    assert_eq!(w.mm.total_vm, STACK_PAGES + 1);
    // Far below: grows in one step to the faulting page.
    let far = STACK_START - 100 * P;
    assert_eq!(w.fault(far, PF_WRITE), FaultOutcome::Handled);
    assert_eq!(w.mm.find_vma(far).unwrap().start, far);
    // RLIMIT_STACK (8 MiB): size = end - address > limit is ENOMEM -> SEGV_MAPERR.
    let limit_start = TASK_SIZE - 8 * 1024 * 1024;
    assert_eq!(w.fault(limit_start, PF_WRITE), FaultOutcome::Handled);
    let too_far = limit_start - P;
    assert_eq!(
        w.fault(too_far, PF_WRITE),
        FaultOutcome::Segv {
            code: SegvCode::MapErr,
            address: too_far
        }
    );
    assert_eq!(
        w.mm.find_vma(limit_start).unwrap().start,
        limit_start,
        "failed growth changes nothing"
    );
    // A bigger limit allows it.
    w.env.rlimit_stack = 16 * 1024 * 1024;
    assert_eq!(w.fault(too_far, PF_WRITE), FaultOutcome::Handled);
    w.check_invariants();
}

/// src: expand_downwards: an accessible neighbour closer than stack_guard_gap
/// (unsigned `address - prev->vm_end`) blocks growth; a PROT_NONE one does not.
#[test]
fn fault_stack_guard_gap() {
    let mut w = W::new();
    let gap = w.env.stack_guard_gap; // 256 pages
    let n = STACK_START - 300 * P;
    // An accessible mapping 300 pages below the stack.
    w.map(n, P, RW, ANON | MAP_FIXED).unwrap();
    let ok = n + P + gap; // exactly stack_guard_gap above its end
    assert_eq!(w.fault(ok, PF_WRITE), FaultOutcome::Handled);
    let bad = ok - P;
    assert_eq!(
        w.fault(bad, PF_WRITE),
        FaultOutcome::Segv {
            code: SegvCode::MapErr,
            address: bad
        }
    );
    // The same with PROT_NONE neighbour (vma_is_accessible false): growth goes through.
    w.mprotect(n, P, PROT_NONE).unwrap();
    assert_eq!(w.fault(bad, PF_WRITE), FaultOutcome::Handled);
    // mmap placement keeps the same distance: topdown stops at vm_start_gap of the stack.
    let a = w.map(0, P, RW, ANON).unwrap();
    assert_eq!(a, MMAP_TOP - P);
    w.check_invariants();
}

/// src: mm/vma.c unmapped_area_topdown: a VM_GROWSDOWN VMA right above a gap
/// forces the range to end below `vm_start_gap` (stack_guard_gap before it).
#[test]
fn topdown_search_respects_stack_guard_gap() {
    let mut w = W::new();
    // Move the mmap base up to the stack to see the guard.
    w.mm.mmap_base = STACK_START;
    let a = w.map(0, P, RW, ANON).unwrap();
    assert_eq!(a, STACK_START - w.env.stack_guard_gap - P);
    // With the guard gap configured to one page.
    w.env.stack_guard_gap = P;
    let b = w.map(0, P, RW, ANON).unwrap();
    // unmapped_area_topdown retries below vm_start_gap(stack) = S - 1 page.
    assert_eq!(b, STACK_START - 2 * P);
}

/// src: arch_get_unmapped_area_topdown falls back to the bottom-up search when
/// top-down has no room; legacy base is TASK_UNMAPPED_BASE.
#[test]
fn unmapped_area_fallback_and_limits() {
    let mut w = W::new();
    // Fill everything between PAGE_SIZE and mmap_base except 2 pages above mmap_base...
    w.mm.mmap_base = 0x20_0000;
    let a = w.map(0, 0x10_0000, RW, ANON).unwrap();
    assert_eq!(a, 0x10_0000);
    // Only 0x1000..0x100000 remains below the base; ask for more: the bottom-up
    // fallback starts at mmap_legacy_base.
    let b = w.map(0, 0x20_0000, RW, ANON).unwrap();
    assert_eq!(b, w.mm.mmap_legacy_base);
    // A hint above TASK_SIZE - len is not honoured.
    let c = w.map(TASK_SIZE - P, 2 * P, RW, ANON).unwrap();
    assert!(c < w.mm.mmap_base);
    // MAP_ABOVE4G: search floor is 4 GiB.
    let d = w.map(0, P, RW, ANON | MAP_ABOVE4G).unwrap();
    assert!(d >= 1 << 32);
}

/// src: mm/vma.c unmapped_area (bottom-up) with align_mask: the aligned gap
/// is searched with worst-case length.
#[test]
fn bottom_up_search_matches_lowest_gap() {
    let mut w = W::new();
    w.mm.topdown = false;
    let base = w.mm.mmap_legacy_base;
    assert_eq!(w.map(0, 2 * P, RW, ANON), Ok(base));
    assert_eq!(w.map(0, P, RW, ANON), Ok(base + 2 * P));
    w.munmap(base, P).unwrap();
    assert_eq!(
        w.map(0, 2 * P, RW, ANON),
        Ok(base + 3 * P),
        "hole of one page is too small"
    );
    assert_eq!(w.map(0, P, RW, ANON), Ok(base));
    // mmap_min_addr only matters to the search floor: low_limit is raised to it.
    assert_eq!(w.map(0, P, RW, ANON | MAP_32BIT), Ok(0x4000_0000));
}

/// src: security_mmap_addr/cap_mmap_addr: below mmap_min_addr without
/// CAP_SYS_RAWIO is EPERM for MAP_FIXED; round_hint_to_min for hints.
#[test]
fn mmap_min_addr_rules() {
    let mut w = W::new();
    w.env.mmap_min_addr = 0x10000;
    w.env.cap_sys_rawio = false;
    assert_eq!(w.map(0x1000, P, RW, ANON | MAP_FIXED), Err(Errno::EPERM));
    assert_eq!(w.map(0x10000, P, RW, ANON | MAP_FIXED), Ok(0x10000));
    // A low hint is raised to mmap_min_addr (round_hint_to_min), rounded page.
    assert_eq!(round_hint_to_min(&w.env, 0x2345), 0x10000);
    assert_eq!(round_hint_to_min(&w.env, 0), 0);
    // The bumped hint 0x10000 is occupied: fall back to the top-down search.
    assert_eq!(w.map(0x2000, P, RW, ANON), Ok(MMAP_TOP - P));
}

// ---- brk / vm_brk_flags -------------------------------------------------

/// src: vm_brk_flags: only VM_EXEC may be passed; length overflow ENOMEM; it
/// replaces what is there.
#[test]
fn vm_brk_flags_rules() {
    let mut w = W::new();
    let env = w.env;
    let x = 0x40_0000;
    assert_eq!(
        w.mm.vm_brk_flags(&env, &mut w.pt, x, 0, VmFlags::NONE),
        Ok(())
    );
    assert_eq!(
        w.mm.vm_brk_flags(&env, &mut w.pt, x, P, VmFlags::WRITE),
        Err(Errno::EINVAL)
    );
    assert_eq!(
        w.mm.vm_brk_flags(&env, &mut w.pt, x, u64::MAX - 5, VmFlags::NONE),
        Err(Errno::ENOMEM)
    );
    assert_eq!(
        w.mm.vm_brk_flags(&env, &mut w.pt, x, 3 * P, VmFlags::EXEC),
        Ok(())
    );
    let v = *w.mm.find_vma(x).unwrap();
    assert!(v.flags.contains(VmFlags::EXEC | VmFlags::WRITE));
    w.map(x + P, P, PROT_READ, ANON | MAP_FIXED).unwrap();
    assert_eq!(
        w.mm.vm_brk_flags(&env, &mut w.pt, x, 3 * P, VmFlags::NONE),
        Ok(())
    );
    assert_eq!(w.mm.find_vma(x).unwrap().end, x + 3 * P);
    w.check_invariants();
}

/// model: every operation keeps the VMA invariants and the statistics; the
/// tables never map outside a VMA or with more rights than it grants.
#[test]
fn random_sequences_keep_invariants() {
    let mut seed = 0x1234_5678_9abc_def0_u64;
    let mut rnd = move |n: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % n
    };
    for round in 0..40 {
        let mut w = W::new();
        let base = 0x1000_0000;
        for step in 0..120 {
            let a = base + rnd(24) * P;
            let l = (rnd(6) + 1) * P;
            let prot = [PROT_NONE, PROT_READ, RW, PROT_READ | PROT_EXEC][rnd(4) as usize];
            match rnd(6) {
                0 | 1 => {
                    let _ = w.map(a, l, prot, ANON | MAP_FIXED);
                }
                2 => {
                    let _ = w.munmap(a, l);
                }
                3 => {
                    let _ = w.mprotect(a, l, prot);
                }
                4 => {
                    let _ = w.access(a, rnd(2) as u8);
                }
                _ => {
                    let _ = w.map(0, l, prot, ANON);
                }
            }
            w.check_invariants();
            for (&page, hw) in &w.pt.pages {
                let v = w.mm.find_vma(page).filter(|v| v.start <= page);
                let v = v.unwrap_or_else(|| {
                    panic!("round {round} step {step}: pte outside vma {page:#x}")
                });
                if let Pte::Anon { writable: true } = hw.kind {
                    assert!(
                        v.flags.contains(VmFlags::WRITE),
                        "writable pte without VM_WRITE {page:#x}"
                    );
                }
            }
        }
        let _ = format!("{:?}", w.mm);
    }
}
