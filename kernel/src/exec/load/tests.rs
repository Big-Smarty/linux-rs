#![allow(
    clippy::unreadable_literal,
    clippy::cast_possible_truncation,
    clippy::similar_names,
    clippy::large_types_passed_by_value,
    clippy::cast_possible_wrap
)]
//! Loader tests: the mapping rules are the model's; these check that the
//! `elf_load` sequence reaches them in Linux's order and that the errno the
//! old plan-level duplicates produced is now produced by the model.
extern crate std;
use super::{Pager, exec_file, insert_stack, map_segments};
use crate::{
    exec::{
        plan::{LoadError, LoadPlan, MAX_LOADS, Unsupported, tests::*},
        stack::STACK_START,
    },
    memory::PAGE_BYTES,
    mm::{
        Env, Mm, OutOfMemory, PageProt, Pte, UserPages as _, VmFlags,
        tests::{Fake, Hw},
    },
    usercopy::TASK_SIZE_MAX,
};
use std::vec::Vec;
use syscalls::Errno;

impl Pager for Fake {
    fn install(
        &mut self,
        page: u64,
        prot: PageProt,
        _bytes: &[u8; PAGE_BYTES],
    ) -> Result<(), OutOfMemory> {
        let kind = Pte::Anon {
            writable: prot.write,
        };
        assert!(self.pages.insert(page, Hw { kind, prot }).is_none());
        Ok(())
    }
}

pub(crate) fn env() -> Env {
    Env::init(1 << 17, 0)
}

fn build(file: &[u8]) -> Result<(Mm, Fake), LoadError> {
    let plan = LoadPlan::new(file)?;
    let env = env();
    let mut mm = Mm::new(&env);
    let mut pt = Fake::default();
    insert_stack(&mut mm, &env, plan.exec_stack)?;
    map_segments(&plan, file, &exec_file(1), &mut mm, &env, &mut pt)?;
    Ok((mm, pt))
}

fn load_phs(phs: &[Ph], len: usize) -> Result<(Mm, Fake), LoadError> {
    build(&elf(EXEC, 0x1000, phs, len))
}

fn errno(result: Result<(Mm, Fake), LoadError>) -> Errno {
    match result {
        Err(LoadError::Errno(errno)) => errno,
        Err(other) => panic!("expected an errno, got {other:?}"),
        Ok(_) => panic!("expected an errno, got success"),
    }
}

fn unsupported(result: Result<(Mm, Fake), LoadError>) -> Unsupported {
    match result {
        Err(LoadError::Unsupported(kind)) => kind,
        Err(other) => panic!("expected unsupported, got {other:?}"),
        Ok(_) => panic!("expected unsupported, got success"),
    }
}

/// The oracle `init`, mapped; the `Mm` the report and fault tests start from.
pub(crate) fn loaded_oracle() -> Mm {
    build(&oracle()).unwrap().0
}

#[test]
fn oracle_binary_builds_the_vmas_and_fields_linux_has() {
    let (mm, pt) = build(&oracle()).unwrap();
    let v: Vec<_> = mm
        .vmas()
        .iter()
        .map(|v| (v.start, v.end, v.pgoff, v.file, v.flags))
        .collect();
    // r--, r-x, rw-, rw- (not merged: the file offsets are not contiguous).
    assert_eq!(v.len(), 5);
    assert_eq!(v[0].0..v[0].1, 0x200000..0x204000);
    assert_eq!((v[0].2, v[0].3), (0, Some(1)));
    assert_eq!((v[1].0, v[1].1, v[1].2), (0x204000, 0x20b000, 3));
    assert!(v[1].4.contains(VmFlags::EXEC) && !v[1].4.contains(VmFlags::WRITE));
    assert_eq!((v[2].0, v[2].1, v[2].2), (0x20b000, 0x20c000, 9));
    assert!(v[2].4.contains(VmFlags::WRITE));
    assert_eq!((v[3].0, v[3].1, v[3].2), (0x20c000, 0x20d000, 9));
    // print_vma_addr in the oracle: init[45b4,204000+7000] for ip 0x2055b4.
    assert_eq!(mm.find_vma(0x2055b4).unwrap().file, Some(1));
    assert!(mm.find_vma(0x20d000).is_some_and(|v| v.start > 0x20d000));
    // The stack is the last VMA.
    let stack = mm.vmas().last().unwrap();
    assert_eq!((stack.start, stack.end), (STACK_START, TASK_SIZE_MAX));
    assert!(stack.flags.contains(VmFlags::GROWSDOWN));
    assert_eq!((mm.start_brk, mm.brk), (0x20d000, 0x20d000));
    assert_eq!((mm.start_data, mm.end_data), (0x20cde0, 0x20cfc0));
    // 4 + 7 + 1 + 1 file pages are installed, 4 KiB each, none for the bss.
    assert_eq!(pt.pages.len(), 13);
    assert_eq!(pt.lookup(0x20b000), Pte::Anon { writable: true });
    assert_eq!(pt.lookup(0x204000), Pte::Anon { writable: false });
}

#[test]
fn bss_is_a_demand_zero_anonymous_vma() {
    let (mm, pt) = load_phs(&[load(R | W, 0, 0x600123, 0, 0x2000)], 0x1000).unwrap();
    let bss = mm.find_vma(0x600000).unwrap();
    assert_eq!((bss.start, bss.end, bss.file), (0x600000, 0x603000, None));
    assert_eq!(mm.start_brk, 0x603000);
    assert!(pt.pages.is_empty());
    // A segment with both parts: the file page, then an anonymous VMA.
    let (mm, pt) = load_phs(&[load(R | W, 0, 0x400000, 0x10, 0x2000)], 0x1000).unwrap();
    assert_eq!(mm.find_vma(0x400000).unwrap().file, Some(1));
    assert_eq!(mm.find_vma(0x401000).unwrap().file, None);
    assert_eq!(pt.pages.len(), 1);
}

#[test]
fn entry_and_segment_bounds_follow_task_size() {
    let l = load(R | X, 0, 0x400000, 0x100, 0x100);
    assert_eq!(
        errno(build(&elf(EXEC, TASK_SIZE_MAX, &[l], 0x1000))),
        Errno::EINVAL
    );
    assert!(build(&elf(EXEC, TASK_SIZE_MAX - 1, &[l], 0x1000)).is_ok());
    // vaddr + memsz beyond TASK_SIZE_MAX: the brk layer says ENOMEM first.
    assert_eq!(
        errno(load_phs(
            &[load(R, 0, 0x400000, 0x10, TASK_SIZE_MAX)],
            0x1000
        )),
        Errno::ENOMEM
    );
    // ... but a first segment whose file page lands on the stack is -EEXIST.
    assert_eq!(
        errno(load_phs(
            &[load(R, 0, TASK_SIZE_MAX - 0x1000, 0x10, 0x2000)],
            0x1000
        )),
        Errno::EEXIST
    );
    assert_eq!(
        errno(load_phs(&[load(R, 0, TASK_SIZE_MAX, 0x10, 0x10)], 0x1000)),
        Errno::ENOMEM
    );
    assert_eq!(
        errno(load_phs(
            &[load(R, 0, 0x400000, 0, u64::MAX - 0x1000)],
            0x1000
        )),
        Errno::ENOMEM
    );
    // memsz = u64::MAX: the C arithmetic wraps to an empty brk range, and the
    // post-mapping `memsz > TASK_SIZE` check answers -EINVAL.
    assert_eq!(
        errno(load_phs(&[load(R, 0, 0x400000, 0, u64::MAX)], 0x1000)),
        Errno::EINVAL
    );
    assert_eq!(
        errno(load_phs(
            &[load(R, 0, 0x400000, 0, TASK_SIZE_MAX + 1)],
            0x1000
        )),
        Errno::ENOMEM
    );
    // An anonymous-only segment ending exactly at TASK_SIZE_MAX is MAP_FIXED
    // over the argument stack: Linux runs on with it clobbered, this loader
    // stops loudly.
    assert_eq!(
        unsupported(load_phs(
            &[load(R | W, 0, TASK_SIZE_MAX - 0x2000, 0, 0x2000)],
            0x1000
        )),
        Unsupported::Overlap
    );
    // filesz > memsz is -EINVAL after mapping.
    assert_eq!(
        errno(load_phs(&[load(R, 0, 0x400000, 0x20, 0x10)], 0x1000)),
        Errno::EINVAL
    );
    // Mapped but beyond: p_vaddr at/after TASK_SIZE_MAX with size zero.
    assert_eq!(
        errno(load_phs(&[load(R, 0, u64::MAX, 0, 0)], 0x1000)),
        Errno::EINVAL
    );
}

#[test]
fn offset_alignment_and_wraparound_follow_vm_mmap() {
    // vaddr page offset 0x10 but file offset 0: off = -0x10, not page aligned.
    assert_eq!(
        errno(load_phs(&[load(R, 0, 0x400010, 0x10, 0x10)], 0x1000)),
        Errno::EINVAL
    );
    // Congruent offsets work.
    assert!(load_phs(&[load(R, 0x10, 0x400010, 0x10, 0x10)], 0x1000).is_ok());
    // offset + size wraps around 2^64: vm_mmap says -EINVAL.
    assert_eq!(
        errno(load_phs(
            &[load(R, u64::MAX - 0xfff, 0x400000, 0x2000, 0x2000)],
            0x1000
        )),
        Errno::EINVAL
    );
    // Above ramfs MAX_LFS_FILESIZE: file_mmap_ok in do_mmap.
    assert_eq!(
        errno(load_phs(&[load(R, 1 << 63, 0x400000, 0x10, 0x10)], 0x1000)),
        Errno::EOVERFLOW
    );
    // filesz so large that page_align wraps to zero: nothing is mapped and the
    // post-mapping check rejects it.
    assert_eq!(
        errno(load_phs(
            &[load(R, 0, 0x400000, u64::MAX - 100, u64::MAX)],
            0x1000
        )),
        Errno::EINVAL
    );
}

#[test]
fn segments_past_eof_and_replacement_follow_the_model() {
    // The last page of the mapping starts past EOF: Linux would raise SIGBUS.
    assert_eq!(
        unsupported(load_phs(&[load(R, 0, 0x400000, 0x3000, 0x3000)], 0x1000)),
        Unsupported::BeyondEof
    );
    assert!(load_phs(&[load(R, 0, 0x400000, 0x3000, 0x3000)], 0x2001).is_ok());
    // First segment on the stack is MAP_FIXED_NOREPLACE: -EEXIST.
    assert_eq!(
        errno(load_phs(&[load(R, 0, STACK_START, 0x10, 0x10)], 0x1000)),
        Errno::EEXIST
    );
    // A later segment is MAP_FIXED: it replaces the earlier pages, which the
    // model unmaps (here: the second page of `a` becomes `b`'s).
    let a = load(R, 0, 0x400000, 0x1800, 0x1800);
    let b = load(R | W, 0x1000, 0x401000, 0x10, 0x10);
    let (mm, pt) = load_phs(&[a, b], 0x2000).unwrap();
    assert_eq!(mm.find_vma(0x400000).unwrap().end, 0x401000);
    let second = mm.find_vma(0x401000).unwrap();
    assert!(second.flags.contains(VmFlags::WRITE));
    assert_eq!(pt.lookup(0x401000), Pte::Anon { writable: true });
    assert_eq!(pt.pages.len(), 2);
    // ... and onto the stack the loader stops loudly.
    let on_stack = load(R | W, 0, STACK_START, 0, 0x1000);
    assert_eq!(
        unsupported(load_phs(&[a, on_stack], 0x2000)),
        Unsupported::Overlap
    );
    // Touching but disjoint is fine.
    assert!(load_phs(&[a, load(R | W, 0x1000, 0x402000, 0x10, 0x10)], 0x2000).is_ok());
}

#[test]
fn prot_none_segment_keeps_its_page_behind_a_none_pte() {
    let (mm, pt) = load_phs(&[load(0, 0x1000, 0x500000, 0x10, 0x10)], 0x2000).unwrap();
    assert!(mm.find_vma(0x500000).is_some_and(|v| !v.is_accessible()));
    assert_eq!(pt.pages[&0x500000].prot.accessible, false);
}

#[test]
fn stack_gets_exec_only_with_pt_gnu_stack_x() {
    let stack = |flags| Ph {
        kind: GNU_STACK,
        flags,
        offset: 0,
        vaddr: 0,
        filesz: 0,
        memsz: 0,
    };
    let l = load(R, 0, 0x400000, 0x100, 0x100);
    for (flags, exec) in [(R | W, false), (R | W | X, true)] {
        let (mm, _) = build(&elf(EXEC, 0x1000, &[l, stack(flags)], 0x1000)).unwrap();
        let s = mm.find_vma(STACK_START).unwrap();
        assert_eq!(s.flags.contains(VmFlags::EXEC), exec);
        assert!(
            s.flags
                .contains(VmFlags::GROWSDOWN | VmFlags::READ | VmFlags::WRITE)
        );
    }
}

#[test]
fn segment_limit_and_hostile_headers_never_panic() {
    let loads: Vec<Ph> = (0..=MAX_LOADS as u64)
        .map(|i| load(R, 0, 0x400000 + i * 0x2000, 0x10, 0x10))
        .collect();
    assert!(load_phs(&loads[..MAX_LOADS], 0x1000).is_ok());
    assert_eq!(
        unsupported(load_phs(&loads, 0x1000)),
        Unsupported::TooManyLoads
    );
    let good = oracle();
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    for _ in 0..5_000 {
        let mut bytes = good.clone();
        for _ in 0..4 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let at = (state % (64 + 56 * 7)) as usize;
            bytes[at] = (state >> 32) as u8;
        }
        let _ = build(&bytes);
    }
}
