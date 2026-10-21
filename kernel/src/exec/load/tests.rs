#![allow(
    clippy::doc_markdown,
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
use super::{Interp, Layout, Pager, exec_file, insert_stack, map_image, map_segments};
use crate::{
    exec::{
        plan::{
            ELF_ET_DYN_BASE, InterpPlan, LoadError, LoadPlan, MAX_LOADS, Unsupported, tests::*,
        },
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
        _file: bool,
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
    build_in(file, env())
}

fn build_in(file: &[u8], env: Env) -> Result<(Mm, Fake), LoadError> {
    let plan = LoadPlan::new(file)?;
    let mut mm = Mm::new(&env);
    let mut pt = Fake::default();
    insert_stack(&mut mm, &env, plan.exec_stack, STACK_START)?;
    map_segments(&plan, file, &exec_file(1), &mut mm, &env, &mut pt)?;
    Ok((mm, pt))
}

fn load_phs(phs: &[Ph], len: usize) -> Result<(Mm, Fake), LoadError> {
    build(&elf(EXEC, 0x1000, phs, len))
}

fn errno(result: Result<(Mm, Fake), LoadError>) -> Errno {
    match result.map(|_| ()) {
        Err(LoadError::Errno(errno)) => errno,
        Err(other) => panic!("expected an errno, got {other:?}"),
        Ok(()) => panic!("expected an errno, got success"),
    }
}

fn unsupported(result: Result<(Mm, Fake), LoadError>) -> Unsupported {
    match result.map(|_| ()) {
        Err(LoadError::Unsupported(kind)) => kind,
        Err(other) => panic!("expected unsupported, got {other:?}"),
        Ok(()) => panic!("expected unsupported, got success"),
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
    assert!(!pt.pages[&0x500000].prot.accessible);
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

/// src: mm/mmap.c `do_mmap` (`prot == PROT_EXEC` takes `execute_only_pkey()`), via `elf_map`: with
/// protection keys on, a `PF_X`-only segment is a loud stop, not a readable mapping and not an
/// errno; any other protection, and a CPU without keys, load as before.
#[test]
fn execute_only_segment_stops_when_protection_keys_are_on() {
    let image = elf(EXEC, 0x1000, &[load(X, 0, 0x400000, 0x10, 0x10)], 0x1000);
    assert!(build(&image).is_ok(), "no keys: a readable mapping");
    let keys = Env {
        ospke: true,
        ..env()
    };
    assert_eq!(
        unsupported(build_in(&image, keys)),
        Unsupported::ExecuteOnlyPkey
    );
    for flags in [R | X, R, R | W, W | X] {
        let image = elf(
            EXEC,
            0x1000,
            &[load(flags, 0, 0x400000, 0x10, 0x10)],
            0x1000,
        );
        assert!(build_in(&image, keys).is_ok(), "{flags}");
    }
    // A bss-only segment is an anonymous mapping (`vm_brk_flags`), not execute-only.
    let bss = elf(EXEC, 0x1000, &[load(X, 0, 0x400000, 0, 0x2000)], 0x1000);
    assert!(build_in(&bss, keys).is_ok());
}

// ---- ET_DYN images and interpreters (load_elf_binary / load_elf_interp) -------------------

const MMAP_TOP: u64 = TASK_SIZE_MAX - 0x800_0000;

/// Map `main` (file id 1) with `interp` (file id 2) into a fresh address space.
fn dyn_build(main: &[u8], interp: Option<&[u8]>) -> Result<(Mm, Fake, Layout), LoadError> {
    let env = env();
    let plan = LoadPlan::new(main)?;
    let iplan = interp.map(InterpPlan::new).transpose()?;
    let mut mm = Mm::new(&env);
    let mut pt = Fake::default();
    insert_stack(&mut mm, &env, plan.exec_stack, STACK_START)?;
    let layout = {
        let interp = iplan.as_ref().zip(interp).map(|(plan, bytes)| Interp {
            plan,
            bytes,
            info: exec_file(2),
        });
        map_image(
            &plan,
            main,
            &exec_file(1),
            interp.as_ref(),
            &mut mm,
            &env,
            &mut pt,
        )?
    };
    Ok((mm, pt, layout))
}

fn pie_phs() -> [Ph; 2] {
    [
        load(R | X, 0, 0, 0x400, 0x400),
        load(R | W, 0x1010, 0x2010, 0x20, 0x3000),
    ]
}

fn image(kind: u16, entry: u64, phs: &[Ph]) -> Vec<u8> {
    elf(kind, entry, phs, 0x1040)
}

/// src: fs/binfmt_elf.c `load_elf_interp` only range checks the biased `load_addr + vaddr`, so an
/// `ET_DYN` interpreter whose `PT_LOAD` lies near 2^64 reaches the file-page installation with an
/// unbiased start that must wrap (a hostile interpreter must not panic the kernel).
#[test]
fn an_interpreter_segment_near_the_top_of_the_address_space_does_not_overflow() {
    let main = image(DYN, 0x200, &pie_phs());
    let high = 0u64.wrapping_sub(0x1_0000);
    let interp = elf(
        DYN,
        0x300,
        &[load(R | X, 0, high, 0x11000, 0x11000)],
        0x12000,
    );
    let (_, _, layout) = dyn_build(&main, Some(&interp)).unwrap();
    // Mapped top-down (0x11000 bytes), then `load_addr = map_addr - vaddr` with vaddr = -0x10000.
    assert_eq!(layout.interp_base, MMAP_TOP - 0x11000 + 0x1_0000);
}

/// src: fs/binfmt_elf.c `load_elf_binary` (ET_DYN with PT_INTERP: `load_bias = ELF_ET_DYN_BASE`,
/// `MAP_FIXED_NOREPLACE`, `total_size` mapping trimmed to the first segment) and
/// `load_elf_interp` (the interpreter lands top-down, below the stack gap).
#[test]
fn pie_with_an_interpreter_loads_at_the_dyn_base_and_the_interpreter_top_down() {
    let main = image(DYN, 0x200, &pie_phs());
    let interp = image(DYN, 0x300, &pie_phs());
    let (mm, pt, layout) = dyn_build(&main, Some(&interp)).unwrap();
    // ELF_ET_DYN_BASE page aligned (`load_bias - vaddr`, ELF_PAGESTART).
    let bias = ELF_ET_DYN_BASE & !0xfff;
    assert_eq!(layout.load_bias, bias);
    assert_eq!(layout.e_entry, bias + 0x200);
    assert_eq!(layout.phdr, bias + 0x40);
    // The interpreter is placed by the first mmap: top-down below mmap_base; nothing else is.
    assert_eq!(
        layout.interp_base,
        MMAP_TOP - 0x6000,
        "total_size 0x5010 is six pages, mapped whole first and trimmed after"
    );
    assert_eq!(layout.entry, layout.interp_base + 0x300);
    let v: Vec<_> = mm
        .vmas()
        .iter()
        .map(|v| (v.start, v.end, v.file, v.flags.contains(VmFlags::WRITE)))
        .collect();
    // main text (file 1), data (file 1) + bss, interpreter text/data/bss (file 2), stack.
    assert_eq!(v[0], (bias, bias + 0x1000, Some(1), false));
    assert_eq!(v[1], (bias + 0x2000, bias + 0x3000, Some(1), true));
    assert_eq!(v[2], (bias + 0x3000, bias + 0x6000, None, true));
    assert_eq!(v[3].2, Some(2));
    assert_eq!(v.last().unwrap().1, TASK_SIZE_MAX);
    // brk follows the bss of the program; the file pages (not the bss) are installed.
    assert_eq!((mm.start_brk, mm.brk), (bias + 0x6000, bias + 0x6000));
    assert_eq!(pt.pages.len(), 2 + 2);
    assert_eq!(mm.start_code, bias);
    assert_eq!(mm.end_code, bias + 0x400);
    assert_eq!((mm.start_data, mm.end_data), (bias + 0x2010, bias + 0x2030));
}

/// src: fs/binfmt_elf.c `load_elf_binary`: ET_DYN without PT_INTERP is placed by the first
/// `mmap` (a loader or static PIE), and its brk moves to `ELF_ET_DYN_BASE`.
#[test]
fn dyn_without_an_interpreter_is_placed_top_down_and_moves_the_brk() {
    let main = image(DYN, 0x200, &pie_phs());
    let (mm, _, layout) = dyn_build(&main, None).unwrap();
    assert_eq!(layout.interp_base, 0, "AT_BASE is 0 without an interpreter");
    // total_size 0x5010 (6 pages with the alignment) ends at the top of the mmap area.
    assert_eq!(layout.load_bias, MMAP_TOP - 0x6000);
    assert_eq!(layout.entry, layout.load_bias + 0x200);
    assert_eq!(layout.e_entry, layout.entry);
    assert_eq!(mm.start_brk, (ELF_ET_DYN_BASE + 0xfff) & !0xfff);
    // The hole after the text is not mapped (the whole-image mapping was trimmed).
    let b = layout.load_bias;
    assert!(
        mm.find_vma(b + 0x1000)
            .is_none_or(|v| v.start >= b + 0x2000)
    );
}

/// src: `maximum_alignment`, the trial `elf_load` at address 0 and `MAP_FIXED_NOREPLACE`.
#[test]
fn a_large_p_align_places_the_image_on_that_boundary() {
    let mut file = image(DYN, 0x200, &pie_phs());
    for index in 0..2 {
        let at = 64 + 56 * index + 48;
        file[at..at + 8].copy_from_slice(&0x20_0000u64.to_le_bytes());
    }
    // Without an interpreter: found by a trial mapping, then aligned down.
    let (_, _, layout) = dyn_build(&file, None).unwrap();
    assert_eq!(layout.load_bias % 0x20_0000, 0);
    assert!(layout.load_bias < MMAP_TOP);
    // With one: ELF_ET_DYN_BASE rounded down to the alignment.
    let interp = image(DYN, 0x300, &pie_phs());
    let (_, _, layout) = dyn_build(&file, Some(&interp)).unwrap();
    assert_eq!(layout.load_bias, ELF_ET_DYN_BASE & !0x1f_ffff);
}

/// src: `load_elf_interp`: an `ET_EXEC` interpreter is mapped `MAP_FIXED` at its own addresses;
/// `AT_BASE` is zero then (`load_addr` is only set for `ET_DYN`).
#[test]
fn an_et_exec_interpreter_is_fixed_and_has_no_base() {
    let main = image(DYN, 0x200, &pie_phs());
    let interp = image(
        EXEC,
        0x7000_0200,
        &[
            load(R | X, 0, 0x7000_0000, 0x400, 0x400),
            load(R | W, 0x1010, 0x7000_2010, 0x20, 0x1000),
        ],
    );
    let (mm, _, layout) = dyn_build(&main, Some(&interp)).unwrap();
    assert_eq!(layout.interp_base, 0);
    assert_eq!(layout.entry, 0x7000_0200);
    assert_eq!(mm.find_vma(0x7000_0000).unwrap().file, Some(2));
}

/// src: `load_elf_interp` errors; each is fatal after `begin_new_exec`, the values are the C's.
#[test]
fn interpreter_errors_after_the_point_of_no_return_are_the_c_values() {
    let main = image(DYN, 0x200, &pie_phs());
    let err = |interp: Vec<u8>| match dyn_build(&main, Some(&interp)) {
        Err(LoadError::Errno(e)) => e,
        other => panic!("{:?}", other.map(|_| ())),
    };
    // Neither ET_EXEC nor ET_DYN: `error = ~0UL`, which load_elf_binary turns into -EPERM.
    let mut rel = image(DYN, 0, &pie_phs());
    rel[16] = 1;
    assert_eq!(err(rel), Errno::EPERM);
    // Nothing to map: total_mapping_size is 0.
    let note = Ph {
        kind: GNU_STACK,
        flags: R | W,
        offset: 0,
        vaddr: 0,
        filesz: 0,
        memsz: 0,
    };
    assert_eq!(err(image(DYN, 0, &[note])), Errno::EINVAL);
    // A segment that runs past TASK_SIZE: -ENOMEM from the last check (or the mapping itself).
    let huge = image(DYN, 0, &[load(R | X, 0, 0, 0x400, 0x7fff_ffff_f000)]);
    assert_eq!(err(huge), Errno::ENOMEM);
    // p_filesz larger than p_memsz.
    let filesz = image(DYN, 0, &[load(R | X, 0, 0, 0x800, 0x400)]);
    assert_eq!(err(filesz), Errno::ENOMEM);
}

/// src: `load_elf_binary`: the first PT_LOAD of an ET_DYN with total size 0 is -EINVAL; a program
/// without any PT_LOAD still reaches the interpreter.
#[test]
fn dyn_edge_cases_follow_the_loop() {
    let empty = Ph {
        filesz: 0,
        memsz: 0,
        ..load(R, 0, 0, 0, 0)
    };
    assert_eq!(
        errno(dyn_build(&image(DYN, 0, &[empty]), None).map(|(mm, pt, _)| (mm, pt))),
        Errno::EINVAL
    );
    let note = Ph {
        kind: GNU_STACK,
        flags: R | W,
        offset: 0,
        vaddr: 0,
        filesz: 0,
        memsz: 0,
    };
    let interp = image(DYN, 0x300, &pie_phs());
    let (_, _, layout) = dyn_build(&image(DYN, 0x200, &[note]), Some(&interp)).unwrap();
    assert_eq!(layout.load_bias, 0, "no load: the bias stays 0");
    assert_eq!(layout.phdr, 0);
}
