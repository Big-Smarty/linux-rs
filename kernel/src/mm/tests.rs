// SPDX-License-Identifier: GPL-2.0-only
//! Host tests of the memory-mapping model. Expected values come from three
//! sources, named per test: `oracle` = the value transcribed from the oracle
//! test `user/init/src/tests/mm.rs` (check name quoted), whose 121 `mm` checks
//! all passed on the pinned Linux 6.18.57 (`xtask/oracle/expected.tsv`; the
//! local capture is `target/linux-reference/init-reference-006`, whose logs
//! hold only `ok` lines: the values are in the test source), `src` = derived
//! by hand from the cited pinned source (no oracle covers it), `model` = a
//! property of this model itself.
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
pub(crate) struct Hw {
    pub(crate) kind: Pte,
    pub(crate) prot: PageProt,
}

/// Page tables as a map; `fail_maps` injects `OutOfMemory` after that many
/// successful `map_*` calls.
#[derive(Default)]
pub(crate) struct Fake {
    pub(crate) pages: BTreeMap<u64, Hw>,
    /// Resident pages that are still the file's page-cache page (`resident_file_pages`).
    pub(crate) files: alloc::collections::BTreeSet<u64>,
    pub(crate) fail_maps: Option<u32>,
    /// `move_pages` fails (a destination table could not be allocated).
    pub(crate) fail_moves: bool,
}

impl Fake {
    /// The pages of the range (the populated ones only: ranges can span 2^35 pages); markers go
    /// too when `markers`.
    fn remove_range(&mut self, start: u64, pages: u64, markers: bool) -> u64 {
        let end = start.saturating_add(pages.saturating_mul(P));
        let keys: Vec<u64> = self.pages.range(start..end).map(|(k, _)| *k).collect();
        let mut freed = 0;
        for k in keys {
            if !markers && self.pages[&k].kind == Pte::Guard {
                continue;
            }
            if let Some(h) = self.pages.remove(&k) {
                freed += u64::from(matches!(h.kind, Pte::Anon { .. }));
            }
            self.files.remove(&k);
        }
        freed
    }
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
        self.remove_range(start, pages, true)
    }
    fn zap(&mut self, start: u64, pages: u64) -> u64 {
        self.remove_range(start, pages, false)
    }
    fn install_guards(&mut self, start: u64, pages: u64) -> Result<(), OutOfMemory> {
        for i in 0..pages {
            self.budget()?;
            let page = start + i * P;
            if self.pages.get(&page).map(|h| h.kind) != Some(Pte::Guard) {
                self.pages.insert(
                    page,
                    Hw {
                        kind: Pte::Guard,
                        prot: PageProt {
                            accessible: false,
                            write: false,
                            exec: false,
                        },
                    },
                );
            }
        }
        Ok(())
    }
    fn remove_guards(&mut self, start: u64, pages: u64) {
        let end = start.saturating_add(pages.saturating_mul(P));
        self.pages
            .retain(|k, h| !(*k >= start && *k < end && h.kind == Pte::Guard));
    }
    fn resident_file_pages(&self, start: u64, pages: u64) -> u64 {
        let end = start.saturating_add(pages.saturating_mul(P));
        self.files
            .range(start..end)
            .filter(|k| self.pages.contains_key(k))
            .count() as u64
    }
    fn move_pages(
        &mut self,
        old_start: u64,
        new_start: u64,
        pages: u64,
    ) -> Result<(), OutOfMemory> {
        if self.fail_moves {
            return Err(OutOfMemory);
        }
        let end = old_start.saturating_add(pages.saturating_mul(P));
        let keys: Vec<u64> = self.pages.range(old_start..end).map(|(k, _)| *k).collect();
        for k in keys {
            if let Some(h) = self.pages.remove(&k) {
                assert!(
                    self.pages.insert(new_start + (k - old_start), h).is_none(),
                    "move_pages onto a mapped page"
                );
            }
        }
        Ok(())
    }
    fn protect(&mut self, start: u64, pages: u64, prot: PageProt) {
        let end = start.saturating_add(pages.saturating_mul(P));
        for (_, h) in self.pages.range_mut(start..end) {
            h.prot = prot;
            if let Pte::Anon { writable } = &mut h.kind {
                *writable &= prot.write;
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
        assert_eq!((mm.total_vm, mm.stack_vm), (STACK_PAGES, STACK_PAGES));
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
        self.mm
            .mprotect(&self.env, &mut self.pt, a, l, p)
            .map(|stop| assert_eq!(stop, None))
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
    assert_eq!(pick_mmap_base(&env).0, 0x7fff_bfef_f000);
    env.rlimit_stack = RLIM_INFINITY;
    assert_eq!(pick_mmap_base(&env).0, 0x1555_5555_6000);
    env.rlimit_stack = 0;
    assert_eq!(pick_mmap_base(&env).0, MMAP_TOP);
    env.rlimit_stack = 120 * 1024 * 1024; // + 1 MiB guard = 121 MiB < 128 MiB
    assert_eq!(pick_mmap_base(&env).0, MMAP_TOP);
    env.rlimit_stack = 200 * 1024 * 1024;
    assert_eq!(pick_mmap_base(&env).0, 0x7fff_f36f_f000);
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
        mmap_error: None,
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
    // model: a page the loader already installed as a private frame needs no
    // file; once the VMA is writable the write fault only raises the write bit.
    w.pt.map_anon_page(m.addr, page_prot(m.vm_flags)).unwrap();
    assert_eq!(w.fault(m.addr, 0), FaultOutcome::Handled);
    let Ok(Mmap::NeedsFile(m)) = call(&mut w, &f, PROT_READ | PROT_WRITE, MAP_PRIVATE, 9) else {
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
    w.pt.map_anon_page(
        m.addr,
        PageProt {
            accessible: true,
            write: true,
            exec: false,
        },
    )
    .unwrap();
    w.pt.pages.get_mut(&m.addr).unwrap().kind = Pte::Anon { writable: false };
    assert_eq!(w.fault(m.addr, PF_WRITE | PF_PROT), FaultOutcome::Handled);
    assert_eq!(w.pt.lookup(m.addr), Pte::Anon { writable: true });
}

/// src: mm/vma.c `__mmap_setup` (limits, then the PTEs of what the range replaces are cleared),
/// `__mmap_new_file_vma` (`->mmap` fails) and `vms_abort_munmap_vmas` (the PTEs are gone, so the
/// replaced VMAs cannot come back: "leaving a gap"). oracle: `procfs.mmap-fixed-eio-leaves-gap`.
#[test]
fn a_failing_file_mmap_leaves_a_gap_after_the_limits() {
    let mut w = W::new();
    let at = 0x2000_0000;
    w.map(at, 2 * P, RW, ANON | MAP_FIXED).unwrap();
    w.pt.map_anon_page(at, page_prot(VmFlags::READ | VmFlags::WRITE))
        .unwrap();
    let file = FileInfo {
        id: 7,
        readable: true,
        writable: false,
        noexec: false,
        swapfile: false,
        append_only: false,
        can_mmap: true,
        mmap_error: Some(Errno::EIO),
        mmap_size_max: u64::MAX >> 1,
        mmap_sync: false,
        hugepages: false,
    };
    let prepare = |w: &mut W| {
        let r = w.mm.mmap(
            &w.env,
            &mut w.pt,
            at,
            P,
            PROT_READ,
            MAP_PRIVATE | MAP_FIXED,
            0,
            Some(&file),
        );
        let Ok(Mmap::NeedsFile(m)) = r else {
            panic!("{r:?}")
        };
        m
    };
    let m = prepare(&mut w);
    // The address-space limit comes before ->mmap.
    let total = w.mm.total_vm;
    w.env.rlimit_as = 0;
    let r = w.mm.mmap_region_with(
        &w.env,
        &mut w.pt,
        Some(7),
        m.addr,
        m.len,
        m.vm_flags,
        m.pgoff,
        m.file.mmap_error,
    );
    assert_eq!(r, Err(Errno::ENOMEM));
    assert_eq!(w.mm.total_vm, total);
    let covers = |w: &W, page: u64| w.mm.vmas().iter().any(|v| v.start <= page && page < v.end);
    assert!(covers(&w, at));
    w.env.rlimit_as = RLIM_INFINITY;
    let r = w.mm.mmap_region_with(
        &w.env,
        &mut w.pt,
        Some(7),
        m.addr,
        m.len,
        m.vm_flags,
        m.pgoff,
        m.file.mmap_error,
    );
    assert_eq!(r, Err(Errno::EIO));
    assert!(!covers(&w, at), "the replaced page is gone");
    assert!(covers(&w, at + P), "its neighbour stays");
    assert_eq!(w.mm.total_vm, total - 1);
    assert_eq!(w.pt.lookup(at), Pte::Absent);
    assert!(w.mm.vmas().iter().all(|vma| vma.file != Some(7)));
    w.check_invariants();
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
    assert_eq!(w.mm.data_vm, 1 + 2 + 5, "data page + bss + heap");
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
    // The vsyscall page (CONFIG_LEGACY_VSYSCALL_XONLY=y): a user fetch is
    // emulated by Linux, here a loud distinct outcome; a write or a data read
    // is refused by emulate_vsyscall itself and ends as SEGV_MAPERR.
    assert_eq!(
        w.fault(0xffff_ffff_ff60_0400, PF_INSTR),
        FaultOutcome::Vsyscall {
            address: 0xffff_ffff_ff60_0400,
            error_code: PF_INSTR | PF_USER
        }
    );
    assert_eq!(
        w.fault(0xffff_ffff_ff60_0000, PF_WRITE | PF_INSTR),
        map(0xffff_ffff_ff60_0000)
    );
    assert_eq!(
        w.fault(0xffff_ffff_ff60_0000, 0),
        map(0xffff_ffff_ff60_0000)
    );
    assert_eq!(
        w.fault(0xffff_ffff_ff60_1000, PF_INSTR),
        map(0xffff_ffff_ff60_1000)
    );
    assert_eq!(
        w.fault(0xffff_ffff_ff60_0000, PF_RSVD | PF_INSTR),
        FaultOutcome::PgtableBad
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

/// src: mm/mmap.c `__get_unmapped_area`: `if (IS_ERR_VALUE(addr)) return addr;`
/// precedes the `TASK_SIZE`/alignment checks, so a `MAP_FIXED` address in
/// [-4095, -1] is the errno `-addr` (the arch function returns it untouched).
#[test]
fn mmap_fixed_error_range_address_is_an_errno() {
    let mut w = W::new();
    let f = ANON | MAP_FIXED;
    assert_eq!(w.map(u64::MAX, P, RW, f), Err(Errno::EPERM)); // -1
    assert_eq!(w.map(u64::MAX - 11, P, RW, f), Err(Errno::ENOMEM)); // -12
    assert_eq!(w.map(u64::MAX - 21, P, RW, f), Err(Errno::EINVAL)); // -22
    assert_eq!(w.map(u64::MAX - 4094, P, RW, f), Err(Errno::new(4095)));
    // One below the range is an ordinary out-of-range address.
    assert_eq!(w.map(u64::MAX - 4095, P, RW, f), Err(Errno::ENOMEM));
    w.check_invariants();
}

/// model: a loader-built VMA is accounted by `insert_vm_struct`, so unmapping
/// it cannot underflow the counters.
#[test]
fn inserted_vma_is_accounted_and_unmaps_cleanly() {
    let mut w = W::new();
    assert_eq!((w.mm.total_vm, w.mm.stack_vm), (STACK_PAGES, STACK_PAGES));
    assert_eq!(w.munmap(STACK_START, STACK_PAGES * P), Ok(()));
    assert_eq!((w.mm.total_vm, w.mm.stack_vm), (0, 0));
    assert_eq!(w.mm.map_count(), 0);
}

/// src: kernel/fork.c `dup_mmap` and mm/rmap.c `anon_vma_fork`: counters and
/// layout copied, `locked_vm` 0 and `VM_LOCKED` cleared, a VMA with an
/// `anon_vma` gets a new one of its own, a `VM_ACCOUNT` VMA is charged again;
/// the parent is untouched.
#[test]
fn dup_copies_the_layout_and_counters_for_a_forked_child() {
    let mut w = W::new();
    let a = w.map(0, 3 * P, RW, ANON).unwrap();
    assert!(w.writable(a)); // gives the VMA an anon_vma
    w.mm.locked_vm = 2;
    w.mm.def_flags = VmFlags::LOCKED; // as mlockall(MCL_FUTURE) would leave it
    w.mm.vmas[0].flags = VmFlags(w.mm.vmas[0].flags.0 | VmFlags::LOCKED.0);
    let parent_before = w.mm.vmas().to_vec();
    let (total, stack) = (w.mm.total_vm, w.mm.stack_vm);
    let child = w.mm.dup(&w.env).unwrap();
    assert_eq!(w.mm.vmas(), parent_before.as_slice(), "parent untouched");
    assert_eq!(child.vmas().len(), parent_before.len());
    assert_eq!(
        (child.total_vm, child.stack_vm, child.locked_vm),
        (total, stack, 0)
    );
    // mm_init keeps only `def_flags & VM_INIT_DEF_MASK` (VM_NOHUGEPAGE: none here).
    assert_eq!(child.def_flags, VmFlags::NONE);
    assert_eq!(w.mm.def_flags, VmFlags::LOCKED);
    assert_eq!(
        (child.mmap_base, child.start_brk, child.brk, child.topdown),
        (w.mm.mmap_base, w.mm.start_brk, w.mm.brk, w.mm.topdown)
    );
    for (p, c) in parent_before.iter().zip(child.vmas()) {
        assert_eq!(
            (p.start, p.end, p.pgoff, p.file),
            (c.start, c.end, c.pgoff, c.file)
        );
        assert!(!c.flags.intersects(VmFlags::LOCKED));
        assert_eq!(p.anon.is_some(), c.anon.is_some());
    }
    // The mapped VMA's anon_vma is a fresh one, not the parent's.
    let pa = w.mm.find_vma(a).unwrap().anon;
    let ca = child.find_vma(a).unwrap().anon;
    assert!(pa.is_some() && ca.is_some() && pa != ca);
    // A charge the policy refuses (more pages than RAM) fails the whole dup.
    let tiny = Env::init(16, 0);
    assert_eq!(w.mm.dup(&tiny).err(), Some(Errno::ENOMEM));
}

/// src: mm/mmap.c `do_mmap` and arch/x86/mm/pkeys.c `execute_only_pkey`/
/// `__arch_override_mprotect_pkey`: with protection keys on, a `PROT_EXEC`-only request takes the
/// execute-only key, which this model does not carry, so it stops (nothing changed) at the point
/// where Linux would pick the key; everything before that point keeps its errno, every other
/// protection and a CPU without keys are unchanged.
#[test]
fn execute_only_requests_stop_when_protection_keys_are_on() {
    let mut w = W::new();
    let x = w.map(0, 2 * P, RW, ANON).unwrap();
    let maps = w.mm.map_count();
    // Without keys: an ordinary execute-only mapping and mprotect.
    assert!(w.map(0, P, PROT_EXEC, ANON).is_ok());
    assert_eq!(w.mprotect(x, P, PROT_EXEC), Ok(()));
    assert_eq!(w.mprotect(x, P, RW), Ok(()));
    let maps = maps + 1;
    w.env.ospke = true;
    let r = w.mm.mmap(&w.env, &mut w.pt, 0, P, PROT_EXEC, ANON, 0, None);
    assert!(
        matches!(r, Ok(Mmap::Unsupported(Unsupported::ExecuteOnlyPkey))),
        "{r:?}"
    );
    assert_eq!(w.mm.map_count(), maps, "nothing was mapped");
    // The checks before the key lookup answer as before.
    assert_eq!(
        w.mm.mmap(&w.env, &mut w.pt, 0, 0, PROT_EXEC, ANON, 0, None)
            .err(),
        Some(Errno::EINVAL)
    );
    // Other protections are not affected.
    assert!(w.map(0, P, PROT_READ | PROT_EXEC, ANON).is_ok());
    assert!(w.map(0, P, RW, ANON).is_ok());
    // mprotect: the stop comes after the argument and hole checks, per VMA.
    let before = w.mm.find_vma(x).copied();
    assert_eq!(
        w.mm.mprotect(&w.env, &mut w.pt, x, P, PROT_EXEC),
        Ok(Some(Unsupported::ExecuteOnlyPkey))
    );
    assert_eq!(w.mm.find_vma(x).copied(), before, "the VMA is unchanged");
    assert_eq!(
        w.mm.mprotect(&w.env, &mut w.pt, x + 1, P, PROT_EXEC),
        Err(Errno::EINVAL)
    );
    assert_eq!(
        w.mm.mprotect(&w.env, &mut w.pt, x - 8 * P, P, PROT_EXEC),
        Err(Errno::ENOMEM)
    );
    assert_eq!(w.mm.mprotect(&w.env, &mut w.pt, x, 0, PROT_EXEC), Ok(None));
    assert_eq!(w.mm.mprotect(&w.env, &mut w.pt, x, P, PROT_READ), Ok(None));
}

/// src: arch/x86/mm/fault.c `bad_area_access_from_pkeys` for a VMA with key 0: the hardware's PK
/// bit, or an access the PKRU denies (AD denies reads and writes, WD writes), never a fetch.
#[test]
fn pkru_denies_key0_follows_arch_vma_access_permitted() {
    assert!(pkru_denies_key0(PF_PK | PF_PROT, 0));
    assert!(pkru_denies_key0(PF_PK | PF_WRITE, 0));
    assert!(!pkru_denies_key0(PF_PROT, 0));
    assert!(
        !pkru_denies_key0(PF_PROT | PF_WRITE, 0x5555_5554),
        "keys 1-15 only"
    );
    assert!(pkru_denies_key0(PF_PROT, 1), "AD denies a read");
    assert!(pkru_denies_key0(PF_PROT | PF_WRITE, 1), "AD denies a write");
    assert!(!pkru_denies_key0(PF_PROT, 2), "WD allows a read");
    assert!(pkru_denies_key0(PF_PROT | PF_WRITE, 2), "WD denies a write");
    assert!(
        !pkru_denies_key0(PF_PROT | PF_INSTR, 3),
        "pkeys never affect fetches"
    );
    assert!(
        pkru_denies_key0(PF_PK | PF_INSTR, 3),
        "unless the hardware said so"
    );
}

/// src: arch/x86/mm/fault.c `access_error` (:1049-1085): `arch_vma_access_permitted` is asked
/// before `handle_mm_fault`, so an access the PKRU denies is refused (`Segv(AccErr)`, which the
/// binary turns into `SEGV_PKUERR`) before any page is populated; an access it allows, and every
/// access on a CPU without keys, is handled as before.
#[test]
fn pkru_denial_refuses_before_a_page_is_populated() {
    let mut w = W::new();
    let a = w.map(0, 3 * P, RW, ANON).unwrap();
    let refused = FaultOutcome::Segv {
        code: SegvCode::AccErr,
        address: a,
    };
    w.env.ospke = true;
    // AD: a not-present read and write are refused and nothing is mapped.
    w.env.pkru = 1;
    assert_eq!(w.fault(a, 0), refused);
    assert_eq!(w.fault(a, PF_WRITE), refused);
    assert!(w.pt.pages.is_empty(), "the denied access populated a page");
    // WD: the read populates the zero page, the write is refused and does not COW it.
    w.env.pkru = 2;
    assert_eq!(w.fault(a, 0), FaultOutcome::Handled);
    assert_eq!(w.pt.lookup(a), Pte::ZeroPage);
    assert_eq!(w.fault(a, PF_WRITE | PF_PROT), refused);
    assert_eq!(
        w.pt.lookup(a),
        Pte::ZeroPage,
        "the denied write copied the page"
    );
    // A write to a page never touched is refused with nothing mapped.
    let b = a + P;
    assert_eq!(
        w.fault(b, PF_WRITE),
        FaultOutcome::Segv {
            code: SegvCode::AccErr,
            address: b
        }
    );
    assert_eq!(w.pt.lookup(b), Pte::Absent);
    // A fetch is never affected by the PKRU.
    w.env.pkru = 3;
    let x = w.map(0, P, PROT_READ | PROT_EXEC, ANON).unwrap();
    assert_eq!(w.fault(x, PF_INSTR), FaultOutcome::Handled);
    // Keys off: the PKRU value is not looked at.
    w.env.ospke = false;
    assert_eq!(w.fault(b, PF_WRITE), FaultOutcome::Handled);
}

#[test]
fn the_vma_stamp_moves_with_every_change_and_names_the_address_space() {
    let mut w = W::new();
    let first = w.mm.vma_stamp();
    // Reading never moves it.
    let _ = (w.mm.vmas().len(), w.mm.find_vma(0x1000), w.mm.map_count());
    assert_eq!(w.mm.vma_stamp(), first);
    let addr = w
        .map(
            0,
            2 * P,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
        )
        .unwrap();
    let mapped = w.mm.vma_stamp();
    assert_ne!(mapped, first, "mmap");
    assert_eq!(mapped.0, first.0, "same address space");
    let _ = (w.mm.vmas().len(), w.mm.find_vma(addr));
    assert_eq!(w.mm.vma_stamp(), mapped);
    w.munmap(addr, P).unwrap();
    assert_ne!(w.mm.vma_stamp(), mapped, "munmap");
    // A fork's copy and a new address space are not the same space.
    assert_ne!(w.mm.dup(&w.env).unwrap().vma_stamp().0, w.mm.vma_stamp().0);
    assert_ne!(Mm::new(&w.env).vma_stamp().0, w.mm.vma_stamp().0);
}

// ---- mremap ----------------------------------------------------------------

impl W {
    fn mremap(&mut self, a: u64, old: u64, new: u64, flags: u64, to: u64) -> Result<u64, Errno> {
        self.mm
            .mremap(&self.env, &mut self.pt, a, old, new, flags, to)
    }
    fn resident(&self, a: u64, pages: u64) -> Vec<bool> {
        (0..pages)
            .map(|i| self.pt.pages.contains_key(&(a + i * P)))
            .collect()
    }
}

/// src: mm/mremap.c `check_mremap_params`, `check_prep_vma` and `do_mremap`, in order.
#[test]
fn mremap_argument_errors_follow_check_order() {
    let mut w = W::new();
    let a = w.map(0, 4 * P, RW, ANON).unwrap();
    let eq = |r: Result<u64, Errno>, e: Errno, what: &str| assert_eq!(r, Err(e), "{what}");
    eq(w.mremap(a, P, P, 0x8, 0), Errno::EINVAL, "unknown flag");
    eq(
        w.mremap(a, P, P, MREMAP_FIXED, a - 8 * P),
        Errno::EINVAL,
        "FIXED without MAYMOVE",
    );
    eq(
        w.mremap(a, P, P, MREMAP_DONTUNMAP, 0),
        Errno::EINVAL,
        "DONTUNMAP without MAYMOVE",
    );
    eq(
        w.mremap(a, P, 2 * P, MREMAP_MAYMOVE | MREMAP_DONTUNMAP, a - 16 * P),
        Errno::EINVAL,
        "DONTUNMAP resizes",
    );
    eq(
        w.mremap(a + 1, P, P, 0, 0),
        Errno::EINVAL,
        "unaligned address",
    );
    eq(w.mremap(a, P, 0, 0, 0), Errno::EINVAL, "zero new length");
    eq(
        w.mremap(a, P, TASK_SIZE + P, MREMAP_MAYMOVE, 0),
        Errno::EINVAL,
        "new length too big",
    );
    eq(
        w.mremap(a, P, P, MREMAP_MAYMOVE | MREMAP_FIXED, a - 16 * P + 1),
        Errno::EINVAL,
        "unaligned new address",
    );
    eq(
        w.mremap(a, 2 * P, 2 * P, MREMAP_MAYMOVE | MREMAP_FIXED, a + P),
        Errno::EINVAL,
        "target overlaps source",
    );
    eq(
        w.mremap(a, 0, P, 0, 0),
        Errno::EINVAL,
        "duplicating a private mapping",
    );
    eq(
        w.mremap(a - 64 * P, P, P, 0, 0),
        Errno::EFAULT,
        "nothing mapped there",
    );
    // Equal lengths are the address itself, whatever the length (no VMA check is made).
    assert_eq!(w.mremap(a + P, P, P, 0, 0), Ok(a + P));
    assert_eq!(w.mremap(a, 5 * P, 5 * P, 0, 0), Ok(a));
    // Growing needs the range to lie within the VMA.
    eq(
        w.mremap(a, 5 * P, 6 * P, MREMAP_MAYMOVE, 0),
        Errno::EFAULT,
        "beyond the VMA",
    );
    // The overflowing offset: a length that wraps PAGE_ALIGN to zero is a zero length.
    eq(
        w.mremap(a, P, u64::MAX, 0, 0),
        Errno::EINVAL,
        "length wraps to zero",
    );
    w.check_invariants();
}

/// src: mm/mremap.c `vrm_overlaps` and `remap_move` add the caller's `addr` and `old_len` in
/// unsigned long, which wraps; a wrapped range holds no VMA, so Linux answers EFAULT (or the
/// earlier EINVAL). It must never be an arithmetic panic (an unprivileged `mremap` argument).
#[test]
fn mremap_wrapping_ranges_never_panic() {
    let mut w = W::new();
    let _ = w.map(0, 4 * P, RW, ANON).unwrap();
    let top = 0u64.wrapping_sub(P);
    for flags in 0..8u64 {
        for old in [P, 2 * P, 0u64.wrapping_sub(3 * P), 0u64.wrapping_sub(P)] {
            for new in [P, 2 * P, old] {
                for addr in [top, top - P, 0x7fff_ffff_f000, 0x10000] {
                    for to in [0x10000, 0x40000, TASK_SIZE - P] {
                        let _ = w.mremap(addr, old, new, flags, to);
                    }
                }
            }
        }
    }
    let fixed = MREMAP_MAYMOVE | MREMAP_FIXED;
    let huge = 0u64.wrapping_sub(P);
    for (old, new, what) in [
        (2 * P, P, "wrapped end, no VMA at the start"),
        (huge, P, "huge old length"),
        (P, P, "equal-length batched move of an unmapped top page"),
    ] {
        assert_eq!(
            w.mremap(top, old, new, fixed, 0x10000),
            Err(Errno::EFAULT),
            "{what}"
        );
    }
    w.check_invariants();
}

/// src: mm/mremap.c `shrink_vma`, `expand_vma`, `expand_vma_in_place`, `vma_expandable`.
#[test]
fn mremap_shrinks_and_expands_in_place() {
    let mut w = W::new();
    let a = w.map(0, 4 * P, RW, ANON).unwrap();
    for i in 0..4 {
        assert!(w.writable(a + i * P));
    }
    let before = w.mm.total_vm;
    // Shrink: the tail goes, its pages with it.
    assert_eq!(w.mremap(a, 4 * P, 2 * P, 0, 0), Ok(a));
    assert_eq!(w.resident(a, 4), [true, true, false, false]);
    assert_eq!(w.mm.total_vm, before - 2);
    assert_eq!(w.mm.find_vma(a).unwrap().end, a + 2 * P);
    // A shrink of a middle part keeps both ends (`MAYMOVE` is not needed).
    assert_eq!(w.mremap(a + P, 2 * P, P, 0, 0), Ok(a + P));
    assert_eq!(w.mm.find_vma(a).unwrap().end, a + 2 * P);
    // Grow in place: nothing is above the top-most mapping (the stack gap is free).
    let top = w.mm.find_vma(a).unwrap().end;
    assert_eq!(top, MMAP_TOP - 2 * P);
    assert_eq!(w.mremap(a, 2 * P, 6 * P, 0, 0), Ok(a));
    let v = *w.mm.find_vma(a).unwrap();
    assert_eq!((v.start, v.end), (a, a + 6 * P));
    assert_eq!(w.mm.total_vm, before - 2 + 4);
    // Only a range that ends at the VMA's end can grow in place; otherwise it moves or fails.
    assert_eq!(w.mremap(a, 2 * P, 3 * P, 0, 0), Err(Errno::ENOMEM));
    w.check_invariants();
}

/// src: mm/mremap.c `expand_vma` -> `vrm_set_new_addr` -> `move_vma`: a blocked growth moves
/// the mapping to the top-down area and takes its pages along.
#[test]
fn mremap_moves_a_blocked_mapping_with_its_pages() {
    let mut w = W::new();
    let upper = w.map(0, 2 * P, RW, ANON).unwrap();
    let lower = w.map(0, 2 * P, PROT_READ, ANON).unwrap();
    assert_eq!(lower + 2 * P, upper);
    assert!(w.readable(lower));
    let faulted_before = w.resident(lower, 2);
    let total = w.mm.total_vm;
    // Blocked by `upper`, and no MAYMOVE.
    assert_eq!(w.mremap(lower, 2 * P, 4 * P, 0, 0), Err(Errno::ENOMEM));
    let moved = w.mremap(lower, 2 * P, 4 * P, MREMAP_MAYMOVE, 0).unwrap();
    assert!(moved < lower);
    assert!(
        w.mm.find_vma(lower)
            .is_none_or(|v| v.start >= lower + 2 * P)
    );
    let v = *w.mm.find_vma(moved).unwrap();
    assert_eq!((v.start, v.end), (moved, moved + 4 * P));
    assert_eq!(
        w.resident(moved, 4),
        [faulted_before[0], faulted_before[1], false, false]
    );
    assert_eq!(w.resident(lower, 2), [false, false]);
    assert_eq!(w.mm.total_vm, total + 2);
    // A never-faulted anonymous VMA takes pgoff = start >> 12 again.
    let fresh = w.map(0, P, RW, ANON | MAP_NORESERVE).unwrap();
    let moved = w.mremap(fresh, P, 2 * P, MREMAP_MAYMOVE, 0).unwrap();
    assert_eq!(w.mm.find_vma(moved).unwrap().pgoff, moved >> 12);
    w.check_invariants();
}

/// src: mm/mremap.c `mremap_to`, `vrm_overlaps`.
#[test]
fn mremap_fixed_replaces_the_target() {
    let mut w = W::new();
    let a = w.map(0x2000_0000, 3 * P, RW, ANON | MAP_FIXED).unwrap();
    let b = w
        .map(0x3000_0000, 3 * P, PROT_READ, ANON | MAP_FIXED)
        .unwrap();
    assert!(w.writable(a));
    assert!(w.readable(b + P));
    let flags = MREMAP_MAYMOVE | MREMAP_FIXED;
    // a -> over b: b is unmapped first; the pages of a arrive, b's go.
    assert_eq!(w.mremap(a, 3 * P, 3 * P, flags, b), Ok(b));
    assert!(w.mm.find_vma(a).is_none_or(|v| v.start >= a + 3 * P));
    let v = *w.mm.find_vma(b).unwrap();
    assert_eq!(
        (v.start, v.end, v.flags.contains(VmFlags::WRITE)),
        (b, b + 3 * P, true)
    );
    assert_eq!(w.resident(b, 3), [true, false, false]);
    // Growing while moving to a fixed address.
    let c = w.map(0x4000_0000, P, RW, ANON | MAP_FIXED).unwrap();
    assert_eq!(w.mremap(c, P, 3 * P, flags, 0x5000_0000), Ok(0x5000_0000));
    assert_eq!(w.mm.find_vma(0x5000_0000).unwrap().end, 0x5000_0000 + 3 * P);
    // Shrinking while moving: the tail is unmapped, the rest moves.
    assert_eq!(
        w.mremap(0x5000_0000, 3 * P, P, flags, 0x6000_0000),
        Ok(0x6000_0000)
    );
    assert_eq!(w.mm.find_vma(0x6000_0000).unwrap().end, 0x6000_0000 + P);
    assert!(
        w.mm.find_vma(0x5000_0000)
            .is_none_or(|v| v.start >= 0x6000_0000)
    );
    w.check_invariants();
}

/// src: mm/mremap.c `move_vma` with `MREMAP_DONTUNMAP`, `dontunmap_complete`.
#[test]
fn mremap_dontunmap_leaves_an_empty_mapping_behind() {
    let mut w = W::new();
    let a = w.map(0x2000_0000, 2 * P, RW, ANON | MAP_FIXED).unwrap();
    assert!(w.writable(a));
    let total = w.mm.total_vm;
    let to = w
        .mremap(a, 2 * P, 2 * P, MREMAP_MAYMOVE | MREMAP_DONTUNMAP, 0)
        .unwrap();
    assert_ne!(to, a);
    assert_eq!(w.mm.total_vm, total + 2, "both mappings count");
    let old = *w.mm.find_vma(a).unwrap();
    assert_eq!((old.start, old.end, old.anon), (a, a + 2 * P, None));
    assert_eq!(old.pgoff, a >> 12, "unfaulted again");
    assert_eq!(w.resident(a, 2), [false, false]);
    assert_eq!(w.resident(to, 2), [true, false]);
    w.check_invariants();
}

/// src: mm/mremap.c `remap_move`: every VMA of the range moves, the gap between them is kept.
#[test]
fn mremap_fixed_moves_several_vmas_keeping_the_gaps() {
    let mut w = W::new();
    let base = 0x2000_0000;
    w.map(base, P, RW, ANON | MAP_FIXED).unwrap();
    w.map(base + P, P, PROT_READ, ANON | MAP_FIXED).unwrap();
    w.map(base + 3 * P, P, RW, ANON | MAP_FIXED).unwrap();
    assert!(w.writable(base));
    let to = 0x3000_0000;
    let flags = MREMAP_MAYMOVE | MREMAP_FIXED;
    assert_eq!(w.mremap(base, 4 * P, 4 * P, flags, to), Ok(to));
    let vmas: Vec<(u64, u64, u64)> =
        w.mm.vmas()
            .iter()
            .filter(|v| v.start >= to && v.end <= to + 4 * P)
            .map(|v| (v.start - to, v.end - to, v.flags.0 & VmFlags::ACCESS.0))
            .collect();
    assert_eq!(vmas, [(0, P, 3), (P, 2 * P, 1), (3 * P, 4 * P, 3)]);
    assert!(w.mm.find_vma(base).is_none_or(|v| v.start >= base + 4 * P));
    assert_eq!(w.resident(to, 1), [true]);
    // A gap at the very start is EFAULT, nothing mapped at all too.
    assert_eq!(
        w.mremap(to - P, 2 * P, 2 * P, flags, 0x4000_0000),
        Err(Errno::EFAULT)
    );
    assert_eq!(
        w.mremap(0x7000_0000, P, P, flags, 0x4000_0000),
        Err(Errno::EFAULT)
    );
    w.check_invariants();
}

/// src: mm/mremap.c `copy_vma_and_data`: a page-table move that fails leaves the old mapping
/// whole and unmaps the copy.
#[test]
fn mremap_failing_page_table_move_keeps_the_old_mapping() {
    let mut w = W::new();
    let upper = w.map(0, 2 * P, RW, ANON).unwrap();
    let lower = w.map(0, 2 * P, PROT_READ, ANON).unwrap();
    assert!(w.readable(lower));
    let (maps, total) = (w.maps(), w.mm.total_vm);
    w.pt.fail_moves = true;
    assert_eq!(
        w.mremap(lower, 2 * P, 4 * P, MREMAP_MAYMOVE, 0),
        Err(Errno::ENOMEM)
    );
    assert_eq!((w.maps(), w.mm.total_vm), (maps, total));
    assert!(w.pt.pages.contains_key(&lower));
    let _ = upper;
    w.check_invariants();
}

// ---- madvise ------------------------------------------------------------

impl W {
    /// `do_madvise` for everything but `MADV_POPULATE_*`.
    fn madvise(&mut self, a: u64, len: u64, advice: i32) -> Result<(), Madvise> {
        match madvise_range(a, len, advice).map_err(Madvise::Errno)? {
            None => Ok(()),
            Some(end) => self.mm.madvise(&self.env, &mut self.pt, a, end, advice),
        }
    }
    /// A private file mapping of file 7 (a tmpfs file here, `VM_MAYWRITE` set) at `addr`.
    fn file_map(&mut self, addr: u64, pages: u64, flags: VmFlags) {
        self.mm
            .mmap_region(&self.env, &mut self.pt, Some(7), addr, pages * P, flags, 0)
            .unwrap();
    }
    fn lines(&self) -> Vec<(u64, u64)> {
        self.mm.vmas().iter().map(|v| (v.start, v.end)).collect()
    }
}

const E_INVAL: Madvise = Madvise::Errno(Errno::EINVAL);
const E_NOMEM: Madvise = Madvise::Errno(Errno::ENOMEM);

/// src: mm/madvise.c `madvise_behavior_valid` (+ oracle `madvise.accepts-*`/`invalid-advice-*`):
/// exactly these values, none of the KSM, THP and memory-failure ones.
#[test]
fn madvise_behavior_valid_is_the_declared_configurations_set() {
    let valid = [
        0, 1, 2, 3, 4, 8, 9, 10, 11, 16, 17, 18, 19, 20, 21, 22, 23, 24, 102, 103,
    ];
    for advice in -3..130 {
        assert_eq!(
            madvise_behavior_valid(advice),
            valid.contains(&advice),
            "{advice}"
        );
    }
    assert!(!madvise_behavior_valid(i32::MIN) && !madvise_behavior_valid(-1));
}

/// src: mm/madvise.c `is_valid_madvise`, `madvise_should_skip`, `madvise_do_behavior`
/// (oracle `madvise.unaligned-start-*`, `len-*`).
#[test]
fn madvise_range_checks_in_linux_order() {
    let a = 0x7000_0000_0000;
    assert_eq!(madvise_range(a, 3 * P, 4), Ok(Some(a + 3 * P)));
    assert_eq!(madvise_range(a, 1, 4), Ok(Some(a + P)));
    assert_eq!(madvise_range(a, 0, 4), Ok(None));
    // The advice is judged first, then the alignment, then the length.
    assert_eq!(madvise_range(a + 1, 0, 12), Err(Errno::EINVAL));
    assert_eq!(madvise_range(a + 1, 0, 4), Err(Errno::EINVAL));
    assert_eq!(madvise_range(a, 0, 12), Err(Errno::EINVAL));
    // PAGE_ALIGN wrapping to zero, and the end wrapping.
    assert_eq!(madvise_range(a, u64::MAX, 4), Err(Errno::EINVAL));
    assert_eq!(madvise_range(a, u64::MAX - 4094, 4), Err(Errno::EINVAL));
    assert_eq!(madvise_range(a, u64::MAX - 4095, 4), Err(Errno::EINVAL));
    assert_eq!(
        madvise_range(0, u64::MAX - 4095, 0),
        Ok(Some(u64::MAX - 4095))
    );
    assert_eq!(madvise_range(u64::MAX - 4095, P, 0), Err(Errno::EINVAL));
}

/// src: mm/madvise.c `madvise_walk_vmas` (oracle `madvise.hole-*`, `error-*`): every VMA of the
/// range is processed, a hole is `ENOMEM` once the rest was done, the first error ends the walk.
#[test]
fn madvise_walk_processes_the_mapped_parts_and_reports_holes() {
    let mut w = W::new();
    let a = w.map(0, 5 * P, RW, ANON).unwrap();
    for i in 0..5 {
        assert!(w.writable(a + i * P));
    }
    w.munmap(a + 2 * P, P).unwrap();
    assert_eq!(w.madvise(a, 5 * P, MADV_DONTNEED), Err(E_NOMEM));
    let kinds = |w: &W| {
        (0..5)
            .map(|i| w.pt.pages.contains_key(&(a + i * P)))
            .collect::<Vec<_>>()
    };
    assert_eq!(kinds(&w), [false; 5], "both sides were zapped");
    // A hole first, last, and nothing but a hole.
    assert!(w.writable(a) && w.writable(a + P));
    assert_eq!(w.madvise(a - P, 3 * P, MADV_DONTNEED), Err(E_NOMEM));
    assert!(!w.pt.pages.contains_key(&a));
    assert!(w.writable(a));
    assert_eq!(w.madvise(a, 3 * P, MADV_DONTNEED), Err(E_NOMEM));
    assert!(!w.pt.pages.contains_key(&a));
    assert_eq!(w.madvise(a + 2 * P, P, MADV_DONTNEED), Err(E_NOMEM));
    assert_eq!(w.madvise(a + 5 * P, P, MADV_DONTNEED), Err(E_NOMEM));
    assert_eq!(w.madvise(0x1000, P, MADV_NORMAL), Err(E_NOMEM));
    // An error ends the walk: [X][locked Y][Z].
    let x = w.map(0x5000_0000_0000, P, RW, ANON).unwrap();
    w.map(x + P, P, RW, ANON | MAP_LOCKED).unwrap();
    w.map(x + 2 * P, P, RW, ANON).unwrap();
    for i in [0, 1, 2] {
        assert!(w.writable(x + i * P));
    }
    assert_eq!(w.madvise(x, 3 * P, MADV_DONTNEED), Err(E_INVAL));
    let present = |w: &W, i: u64| w.pt.pages.contains_key(&(x + i * P));
    assert_eq!(
        (present(&w, 0), present(&w, 1), present(&w, 2)),
        (false, true, true)
    );
    // The same with a hole in front: the error wins over the remembered ENOMEM.
    assert_eq!(w.madvise(x - P, 4 * P, MADV_DONTNEED), Err(E_INVAL));
    assert_eq!(w.madvise(x, 3 * P, MADV_DONTNEED_LOCKED), Ok(()));
    assert_eq!(w.madvise(x, 3 * P, MADV_FREE), Err(E_INVAL));
    w.check_invariants();
}

/// src: mm/madvise.c `madvise_dontneed_free`, `madvise_free_single_vma`, `madvise_cold`,
/// `madvise_pageout` and `can_madv_lru_vma` (oracle `madvise.locked-*`, `free-*`).
#[test]
fn madvise_refuses_what_linux_refuses_per_vma() {
    let mut w = W::new();
    let a = w.map(0, P, RW, ANON).unwrap();
    let l = w.map(0, P, RW, ANON | MAP_LOCKED).unwrap();
    let f = 0x5000_0000_0000;
    w.file_map(f, 2, VmFlags::DATA_DEFAULT);
    for (advice, plain, locked, file) in [
        (MADV_DONTNEED, Ok(()), Err(E_INVAL), Ok(())),
        (MADV_DONTNEED_LOCKED, Ok(()), Ok(()), Ok(())),
        (MADV_FREE, Ok(()), Err(E_INVAL), Err(E_INVAL)),
        (MADV_COLD, Ok(()), Err(E_INVAL), Ok(())),
        (MADV_PAGEOUT, Ok(()), Err(E_INVAL), Ok(())),
        (MADV_WILLNEED, Ok(()), Ok(()), Ok(())),
        (MADV_RANDOM, Ok(()), Ok(()), Ok(())),
        (MADV_WIPEONFORK, Ok(()), Ok(()), Err(E_INVAL)),
        (MADV_KEEPONFORK, Ok(()), Ok(()), Ok(())),
        (MADV_DONTDUMP, Ok(()), Ok(()), Ok(())),
        (
            MADV_REMOVE,
            Err(E_INVAL),
            Err(E_INVAL),
            Err(Madvise::Errno(Errno::EACCES)),
        ),
        (MADV_GUARD_INSTALL, Ok(()), Err(E_INVAL), Ok(())),
        (MADV_GUARD_REMOVE, Ok(()), Ok(()), Ok(())),
    ] {
        assert_eq!(w.madvise(a, P, advice), plain, "plain {advice}");
        assert_eq!(w.madvise(l, P, advice), locked, "locked {advice}");
        assert_eq!(w.madvise(f, 2 * P, advice), file, "file {advice}");
    }
    // A shared writable file mapping cannot exist yet, and a MADV_REMOVE of one stops.
    let s = 0x5100_0000_0000;
    w.file_map(
        s,
        1,
        VmFlags::DATA_DEFAULT | VmFlags::SHARED | VmFlags::MAYSHARE,
    );
    assert_eq!(
        w.madvise(s, P, MADV_REMOVE),
        Err(Madvise::Unsupported(MadviseUnsupported::RemoveSharedFile))
    );
    // A read-only shared mapping (VM_SHARED and VM_MAYWRITE cleared by do_mmap): EACCES.
    let r = 0x5200_0000_0000;
    w.file_map(
        r,
        1,
        VmFlags(VmFlags::READ.0 | VmFlags::MAYREAD.0 | VmFlags::MAYEXEC.0 | VmFlags::MAYSHARE.0),
    );
    assert_eq!(
        w.madvise(r, P, MADV_REMOVE),
        Err(Madvise::Errno(Errno::EACCES))
    );
    assert_eq!(w.madvise(r, P, MADV_WIPEONFORK), Err(E_INVAL));
    w.check_invariants();
}

/// src: mm/madvise.c `madvise_pageout`/`madvise_cold_or_pageout_pte_range`: without swap an
/// anonymous page stays, a clean page-cache page is unmapped (the resident counters show it),
/// which needs the rmap to be exact: stop.
#[test]
fn pageout_of_resident_file_pages_stops_instead_of_guessing() {
    let mut w = W::new();
    let f = 0x5000_0000_0000;
    w.file_map(f, 3, VmFlags::DATA_DEFAULT);
    assert_eq!(
        w.madvise(f, 3 * P, MADV_PAGEOUT),
        Ok(()),
        "nothing resident"
    );
    w.pt.pages.insert(
        f + P,
        Hw {
            kind: Pte::Anon { writable: false },
            prot: page_prot(VmFlags::DATA_DEFAULT),
        },
    );
    w.pt.files.insert(f + P);
    assert_eq!(
        w.madvise(f, 3 * P, MADV_PAGEOUT),
        Err(Madvise::Unsupported(MadviseUnsupported::PageoutFilePages))
    );
    assert_eq!(
        w.madvise(f + 2 * P, P, MADV_PAGEOUT),
        Ok(()),
        "another page"
    );
    assert_eq!(
        w.madvise(f, 3 * P, MADV_COLD),
        Ok(()),
        "COLD only moves LRU lists"
    );
    assert!(w.pt.pages.contains_key(&(f + P)));
    // An anonymous page is never touched.
    let a = w.map(0, P, RW, ANON).unwrap();
    assert!(w.writable(a));
    assert_eq!(w.madvise(a, P, MADV_PAGEOUT), Ok(()));
    assert!(w.pt.pages.contains_key(&a));
}

/// src: mm/madvise.c `madvise_update_vma` -> mm/vma.c `vma_modify_flags` (oracle
/// `madvise.random-splits` ... `mixed-clear-merges-both-sides`): the advice that only sets flags
/// splits and merges VMAs like `mprotect`, and a request that changes nothing does nothing.
#[test]
fn flag_advice_splits_and_merges_vmas() {
    let mut w = W::new();
    let a = w.map(0, 6 * P, RW, ANON).unwrap();
    let whole = std::vec![(a, a + 6 * P)];
    assert_eq!(w.lines().iter().filter(|l| l.0 == a).count(), 1);
    w.madvise(a + 2 * P, P, MADV_RANDOM).unwrap();
    let split = |w: &W| {
        w.lines()
            .into_iter()
            .filter(|l| l.0 >= a && l.0 < a + 6 * P)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        split(&w),
        [
            (a, a + 2 * P),
            (a + 2 * P, a + 3 * P),
            (a + 3 * P, a + 6 * P)
        ]
    );
    assert!(
        w.mm.find_vma(a + 2 * P)
            .unwrap()
            .flags
            .contains(VmFlags::RAND_READ)
    );
    // SEQUENTIAL replaces RANDOM on the same page; NORMAL merges the three back.
    w.madvise(a + 2 * P, P, MADV_SEQUENTIAL).unwrap();
    let v = *w.mm.find_vma(a + 2 * P).unwrap();
    assert!(v.flags.contains(VmFlags::SEQ_READ) && !v.flags.contains(VmFlags::RAND_READ));
    w.madvise(a + 2 * P, P, MADV_NORMAL).unwrap();
    assert_eq!(split(&w), whole);
    // Setting what is set changes nothing (not even the version).
    w.madvise(a, 6 * P, MADV_DONTFORK).unwrap();
    let stamp = w.mm.vma_stamp();
    w.madvise(a, 6 * P, MADV_DONTFORK).unwrap();
    assert_eq!(w.mm.vma_stamp(), stamp);
    // Different flags on neighbouring pages stay apart; clearing the odd one out merges all.
    w.madvise(a + P, P, MADV_DONTDUMP).unwrap();
    assert_eq!(split(&w).len(), 3);
    w.madvise(a, 6 * P, MADV_DODUMP).unwrap();
    assert_eq!(split(&w), whole);
    w.madvise(a, 6 * P, MADV_DOFORK).unwrap();
    assert_eq!(
        w.mm.find_vma(a).unwrap().flags,
        VmFlags::DATA_DEFAULT | VmFlags::ACCOUNT
    );
    // The flags of the walk that merges with the next VMA: nothing is applied twice.
    w.madvise(a, 3 * P, MADV_WIPEONFORK).unwrap();
    w.madvise(a + 3 * P, 3 * P, MADV_WIPEONFORK).unwrap();
    assert_eq!(split(&w), whole);
    assert_eq!(w.madvise(a, 6 * P, MADV_KEEPONFORK), Ok(()));
    assert_eq!(split(&w), whole);
    w.check_invariants();
}

/// src: mm/madvise.c `madvise_vma_behavior` (`DOFORK`/`KEEPONFORK`/`DODUMP` refusals) and
/// `madvise_update_vma`; mm/mmap.c `do_mmap` (`MAP_DROPPABLE` sets `VM_WIPEONFORK|VM_DONTDUMP`).
#[test]
fn flag_advice_refusals() {
    let mut w = W::new();
    let d = w.map(0, 2 * P, RW, MAP_DROPPABLE | MAP_ANONYMOUS).unwrap();
    assert!(w.mm.find_vma(d).unwrap().flags.contains(VmFlags::DROPPABLE));
    assert_eq!(w.madvise(d, 2 * P, MADV_KEEPONFORK), Err(E_INVAL));
    assert_eq!(w.madvise(d, 2 * P, MADV_DODUMP), Err(E_INVAL));
    assert_eq!(w.madvise(d, 2 * P, MADV_DONTDUMP), Ok(()));
    assert_eq!(w.madvise(d, 2 * P, MADV_WIPEONFORK), Ok(()));
    // DOFORK of an I/O VMA, DODUMP of a special one.
    w.mm.vmas[0].flags |= VmFlags::IO;
    let io = w.mm.vmas[0].start;
    assert_eq!(w.madvise(io, P, MADV_DOFORK), Err(E_INVAL));
    assert_eq!(w.madvise(io, P, MADV_DODUMP), Err(E_INVAL));
    assert_eq!(w.madvise(io, P, MADV_DONTFORK), Ok(()));
}

/// src: mm/madvise.c `madvise_vma_behavior`: `-ENOMEM` from `madvise_update_vma` (a split over
/// `max_map_count`) is reported as `-EAGAIN`; the other advice keeps `ENOMEM` (oracle: none, the
/// limit is 65530 there).
#[test]
fn a_split_over_max_map_count_is_eagain() {
    let mut w = W::new();
    let a = w.map(0, 4 * P, RW, ANON).unwrap();
    w.env.max_map_count = w.mm.map_count() as u32;
    assert_eq!(
        w.madvise(a + P, P, MADV_RANDOM),
        Err(Madvise::Errno(Errno::EAGAIN))
    );
    assert_eq!(
        w.lines().iter().filter(|l| l.0 == a).count(),
        1,
        "nothing changed"
    );
    // Not a flag change: no split is needed, so no limit applies.
    assert_eq!(w.madvise(a + P, P, MADV_DONTNEED), Ok(()));
    assert_eq!(
        w.madvise(a, 4 * P, MADV_RANDOM),
        Ok(()),
        "whole VMA: no split"
    );
}

/// src: mm/madvise.c `guard_install_set_pte`, `guard_remove_pte_entry`, mm/memory.c
/// `zap_nonpresent_ptes` and `handle_pte_marker` (oracle `madvise.install`, `remove`,
/// `dontneed-over-guard`, `guard-prot-none`, `after-munmap-no-guard`).
#[test]
fn guard_markers_install_remove_survive_zaps_and_end_in_sigsegv() {
    let mut w = W::new();
    let a = w.map(0, 8 * P, RW, ANON).unwrap();
    for i in 0..6 {
        assert!(w.writable(a + i * P));
    }
    assert_eq!(w.madvise(a + P, 4 * P, MADV_GUARD_INSTALL), Ok(()));
    let kind = |w: &W, i: u64| w.pt.lookup(a + i * P);
    assert_eq!(kind(&w, 0), Pte::Anon { writable: true });
    for i in 1..5 {
        assert_eq!(kind(&w, i), Pte::Guard, "page {i}");
    }
    assert_eq!(kind(&w, 5), Pte::Anon { writable: true });
    assert_eq!(kind(&w, 6), Pte::Absent);
    assert!(
        w.mm.find_vma(a)
            .unwrap()
            .flags
            .contains(VmFlags::MAYBE_GUARD)
    );
    // The access: SEGV_MAPERR at the exact address, for a read and a write, a kernel access too.
    assert_eq!(
        w.fault(a + P + 9, PF_WRITE),
        FaultOutcome::Segv {
            code: SegvCode::MapErr,
            address: a + P + 9
        }
    );
    assert_eq!(
        w.fault(a + 2 * P, 0),
        FaultOutcome::Segv {
            code: SegvCode::MapErr,
            address: a + 2 * P
        }
    );
    assert_eq!(
        w.mm.handle_user_fault(&w.env, &mut w.pt, a + 3 * P, 0),
        FaultOutcome::Segv {
            code: SegvCode::MapErr,
            address: a + 3 * P
        }
    );
    // Zapping, freeing and the other hints leave the markers.
    for advice in [
        MADV_DONTNEED,
        MADV_FREE,
        MADV_COLD,
        MADV_PAGEOUT,
        MADV_WILLNEED,
        MADV_RANDOM,
    ] {
        assert_eq!(w.madvise(a, 8 * P, advice), Ok(()), "{advice}");
        assert_eq!(kind(&w, 2), Pte::Guard, "after {advice}");
    }
    assert_eq!(kind(&w, 0), Pte::Absent, "DONTNEED took the data");
    // Installing again, over markers and a populated page, is fine; the data goes.
    assert!(w.writable(a));
    assert_eq!(w.madvise(a, 3 * P, MADV_GUARD_INSTALL), Ok(()));
    assert_eq!(
        (kind(&w, 0), kind(&w, 1), kind(&w, 2)),
        (Pte::Guard, Pte::Guard, Pte::Guard)
    );
    // Removing: only markers go, nothing else changes.
    assert_eq!(w.madvise(a + 2 * P, 4 * P, MADV_GUARD_REMOVE), Ok(()));
    assert_eq!(
        (kind(&w, 1), kind(&w, 2), kind(&w, 3), kind(&w, 4)),
        (Pte::Guard, Pte::Absent, Pte::Absent, Pte::Absent)
    );
    assert_eq!(kind(&w, 5), Pte::Absent, "DONTNEED took this one too");
    assert!(w.writable(a + 2 * P));
    // PROT_NONE: the access error comes first.
    w.mprotect(a, 8 * P, PROT_NONE).unwrap();
    assert_eq!(
        w.fault(a + P, 0),
        FaultOutcome::Segv {
            code: SegvCode::AccErr,
            address: a + P
        }
    );
    w.mprotect(a, 8 * P, RW).unwrap();
    assert_eq!(kind(&w, 1), Pte::Guard, "mprotect keeps the marker");
    // munmap drops it, and a new mapping there has none.
    w.munmap(a, 8 * P).unwrap();
    assert_eq!(w.pt.lookup(a + P), Pte::Absent);
    let b = w.map(a, 2 * P, RW, ANON | MAP_FIXED).unwrap();
    assert!(w.writable(b + P));
    w.check_invariants();
}

/// src: mm/madvise.c `madvise_guard_install` (`is_valid_guard_vma`, `VM_MAYBE_GUARD`,
/// `anon_vma_prepare`) and `madvise_guard_remove` (`allow_locked`), and out of memory in the page
/// table walk (oracle `madvise.install-locked`, `remove-locked`, `install-over-hole`).
#[test]
fn guard_install_checks_the_vma_and_reports_out_of_memory() {
    let mut w = W::new();
    let l = w.map(0, 2 * P, RW, ANON | MAP_LOCKED).unwrap();
    assert_eq!(w.madvise(l, 2 * P, MADV_GUARD_INSTALL), Err(E_INVAL));
    assert!(
        !w.mm
            .find_vma(l)
            .unwrap()
            .flags
            .contains(VmFlags::MAYBE_GUARD),
        "refused before the flag"
    );
    assert_eq!(w.madvise(l, 2 * P, MADV_GUARD_REMOVE), Ok(()));
    // An anonymous VMA gets its anon_vma; a hole is ENOMEM after the mapped part was done.
    let a = w.map(0, 4 * P, RW, ANON).unwrap();
    w.munmap(a + 2 * P, P).unwrap();
    assert_eq!(w.mm.find_vma(a).unwrap().anon, None);
    assert_eq!(w.madvise(a, 4 * P, MADV_GUARD_INSTALL), Err(E_NOMEM));
    assert!(w.mm.find_vma(a).unwrap().anon.is_some());
    // Both VMAs of the range were done: [a, a+2P) and [a+3P, a+4P).
    let kinds: Vec<Pte> = (0..4).map(|i| w.pt.lookup(a + i * P)).collect();
    assert_eq!(kinds, [Pte::Guard, Pte::Guard, Pte::Absent, Pte::Guard]);
}

/// src: mm/vma.c `vma_merge_new_range`/`vma_expand`/`vma_merge_existing_range` and
/// include/linux/mm.h `VM_STICKY` (oracle `madvise.guard-vma-merges-with-a-new-neighbour`): a VMA
/// that may hold guards still merges, and the merged VMA keeps the flag.
#[test]
fn vm_maybe_guard_is_sticky_and_never_blocks_a_merge() {
    let mut w = W::new();
    let a = w
        .map(0x5000_0000_0000, 2 * P, RW, ANON | MAP_FIXED)
        .unwrap();
    assert_eq!(w.madvise(a, P, MADV_GUARD_INSTALL), Ok(()));
    let b = w.map(a + 2 * P, 2 * P, RW, ANON | MAP_FIXED).unwrap();
    assert_eq!(w.lines().iter().filter(|l| l.0 == a).count(), 1, "merged");
    assert_eq!(w.mm.find_vma(b).unwrap().start, a);
    assert!(
        w.mm.find_vma(b)
            .unwrap()
            .flags
            .contains(VmFlags::MAYBE_GUARD)
    );
    // Merging in front takes the flag too.
    let c = w.map(a - 2 * P, 2 * P, RW, ANON | MAP_FIXED).unwrap();
    assert_eq!(w.mm.find_vma(c).unwrap().start, c);
    assert_eq!(w.mm.find_vma(c).unwrap().end, a + 4 * P);
    assert!(
        w.mm.find_vma(c)
            .unwrap()
            .flags
            .contains(VmFlags::MAYBE_GUARD)
    );
    // A split keeps it on both halves.
    w.mprotect(a, P, PROT_READ).unwrap();
    for v in
        w.mm.vmas()
            .iter()
            .filter(|v| v.start >= c && v.end <= a + 4 * P)
    {
        assert!(v.flags.contains(VmFlags::MAYBE_GUARD), "{v:?}");
    }
    w.check_invariants();
}

/// src: kernel/fork.c `dup_mmap` (`VM_DONTCOPY`, `VM_WIPEONFORK`) and mm/mmap.c
/// `vm_stat_account` (oracle `madvise.dontfork-*`, `wipeonfork-*`).
#[test]
fn dup_leaves_out_dontfork_and_wipes_wipeonfork() {
    let mut w = W::new();
    let a = w
        .map(0x5000_0000_0000, 6 * P, RW, ANON | MAP_FIXED)
        .unwrap();
    for i in 0..6 {
        assert!(w.writable(a + i * P));
    }
    w.madvise(a + P, 2 * P, MADV_DONTFORK).unwrap();
    w.madvise(a + 4 * P, P, MADV_WIPEONFORK).unwrap();
    let (total, data) = (w.mm.total_vm, w.mm.data_vm);
    let child = w.mm.dup(&w.env).unwrap();
    assert_eq!(
        (w.mm.total_vm, w.mm.data_vm),
        (total, data),
        "parent untouched"
    );
    assert_eq!((child.total_vm, child.data_vm), (total - 2, data - 2));
    assert!(
        child.find_vma(a + P).is_none_or(|v| v.start > a + P),
        "no DONTFORK range"
    );
    assert_eq!(child.find_vma(a).unwrap().end, a + P);
    let wiped = child.find_vma(a + 4 * P).unwrap();
    assert!(wiped.flags.contains(VmFlags::WIPEONFORK) && wiped.anon.is_none());
    assert!(child.find_vma(a).unwrap().anon.is_some());
    assert!(!Mm::copies_pages(wiped.flags));
    assert!(!Mm::copies_pages(VmFlags::DONTCOPY));
    assert!(Mm::copies_pages(
        VmFlags::DATA_DEFAULT | VmFlags::MAYBE_GUARD
    ));
    // The charge of a copied VM_ACCOUNT range is the copied ones only.
    let tiny = Env::init(5, 0);
    assert_eq!(w.mm.dup(&tiny).err(), Some(Errno::ENOMEM));
    let drop_all = {
        let mut m = Mm::new(&w.env);
        m.insert_vm_struct(
            &w.env,
            Vma {
                start: a,
                end: a + 64 * P,
                flags: VmFlags::DATA_DEFAULT | VmFlags::ACCOUNT | VmFlags::DONTCOPY,
                pgoff: 0,
                file: None,
                anon: None,
            },
        )
        .unwrap();
        m
    };
    assert!(
        drop_all.dup(&Env::init(1, 0)).is_ok(),
        "a left-out VMA is not charged"
    );
}

/// src: mm/gup.c `faultin_page_range` + `check_vma_flags` + `__get_user_pages` with
/// `FOLL_MADV_POPULATE` and `vm_fault_to_errno` (oracle `madvise.populate-*`).
#[test]
fn populate_span_follows_gups_checks() {
    let mut w = W::new();
    let a = w.map(0, 2 * P, RW, ANON).unwrap();
    let ro = w.map(0, P, PROT_READ, ANON).unwrap();
    let none = w.map(0, P, PROT_NONE, ANON).unwrap();
    let wo = w.map(0, P, PROT_WRITE, ANON).unwrap();
    let env = w.env;
    let span = |w: &W, at, end, write| w.mm.populate_span(&env, at, end, write);
    assert_eq!(
        span(&w, a, a + 10 * P, false),
        Ok(a + 2 * P),
        "one VMA at a time"
    );
    assert_eq!(span(&w, a + P, a + 2 * P, true), Ok(a + 2 * P));
    assert_eq!(span(&w, ro, ro + P, false), Ok(ro + P));
    assert_eq!(span(&w, ro, ro + P, true), Err(Errno::EINVAL));
    assert_eq!(span(&w, none, none + P, false), Err(Errno::EINVAL));
    assert_eq!(span(&w, none, none + P, true), Err(Errno::EINVAL));
    assert_eq!(span(&w, wo, wo + P, false), Err(Errno::EINVAL));
    assert_eq!(span(&w, wo, wo + P, true), Ok(wo + P));
    assert_eq!(
        span(&w, 0x1000, 0x2000, false),
        Err(Errno::ENOMEM),
        "no VMA: no skipping"
    );
    assert_eq!(span(&w, a + 2 * P, a + 4 * P, false), Err(Errno::ENOMEM));
    // Protection keys: the task's PKRU denies key 0.
    let denied = Env {
        ospke: true,
        pkru: 1,
        ..env
    };
    assert_eq!(
        w.mm.populate_span(&denied, a, a + P, false),
        Err(Errno::EINVAL)
    );
    let write_disabled = Env {
        ospke: true,
        pkru: 2,
        ..env
    };
    assert_eq!(
        w.mm.populate_span(&write_disabled, a, a + P, false),
        Ok(a + P)
    );
    assert_eq!(
        w.mm.populate_span(&write_disabled, a, a + P, true),
        Err(Errno::EINVAL)
    );
    // The error of a page that could not be faulted in.
    assert_eq!(w.mm.populate_error(&w.pt, a), Errno::ENOMEM);
    w.madvise(a, P, MADV_GUARD_INSTALL).unwrap();
    assert_eq!(w.mm.populate_error(&w.pt, a), Errno::EFAULT);
    let f = 0x5000_0000_0000;
    w.file_map(f, 1, VmFlags::DATA_DEFAULT);
    assert_eq!(w.mm.populate_error(&w.pt, f), Errno::EFAULT, "SIGBUS");
}

/// model: `UserPages::unmap` drops guard markers and `zap` keeps them, the exact difference
/// between `munmap` and `MADV_DONTNEED` (mm/memory.c `zap_drop_markers`).
#[test]
fn zap_keeps_markers_and_unmap_drops_them() {
    let mut pt = Fake::default();
    pt.install_guards(0x1000, 3).unwrap();
    pt.map_anon_page(
        0x4000,
        PageProt {
            accessible: true,
            write: true,
            exec: false,
        },
    )
    .unwrap();
    assert_eq!(pt.zap(0x1000, 3), 0);
    assert_eq!(pt.lookup(0x2000), Pte::Guard);
    assert_eq!(pt.zap(0x4000, 1), 1);
    pt.remove_guards(0x2000, 1);
    assert_eq!(
        (pt.lookup(0x1000), pt.lookup(0x2000), pt.lookup(0x3000)),
        (Pte::Guard, Pte::Absent, Pte::Guard)
    );
    assert_eq!(pt.unmap(0x1000, 3), 0);
    assert_eq!(pt.lookup(0x1000), Pte::Absent);
    // Table exhaustion: the pages before the failing one are guards.
    pt.fail_maps = Some(2);
    assert_eq!(pt.install_guards(0x10_000, 4), Err(OutOfMemory));
    assert_eq!(
        (
            pt.lookup(0x10_000),
            pt.lookup(0x11_000),
            pt.lookup(0x12_000)
        ),
        (Pte::Guard, Pte::Guard, Pte::Absent)
    );
}
