#![allow(
    clippy::unreadable_literal,
    clippy::cast_possible_truncation,
    clippy::similar_names,
    clippy::large_types_passed_by_value,
    clippy::format_push_string,
    clippy::cast_possible_wrap
)]
extern crate std;
use super::{LoadError, LoadPlan, MAX_LOADS, Unsupported};
use crate::{exec::stack::STACK_START, usercopy::TASK_SIZE_MAX};
use std::vec::Vec;
use syscalls::Errno;

pub(crate) const X: u32 = 1;
pub(crate) const W: u32 = 2;
pub(crate) const R: u32 = 4;
pub(crate) const LOAD: u32 = 1;
pub(crate) const INTERP: u32 = 3;
pub(crate) const GNU_STACK: u32 = 0x6474_e551;
pub(crate) const EXEC: u16 = 2;
pub(crate) const DYN: u16 = 3;

#[derive(Clone, Copy)]
pub(crate) struct Ph {
    pub kind: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
}

pub(crate) const fn load(flags: u32, offset: u64, vaddr: u64, filesz: u64, memsz: u64) -> Ph {
    Ph {
        kind: LOAD,
        flags,
        offset,
        vaddr,
        filesz,
        memsz,
    }
}

/// A minimal ELF64 image: header, `phs` at offset 64, padded to `len`.
pub(crate) fn elf(file_type: u16, entry: u64, phs: &[Ph], len: usize) -> Vec<u8> {
    let mut bytes = std::vec![0u8; len.max(64 + 56 * phs.len())];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[16..18].copy_from_slice(&file_type.to_le_bytes());
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&entry.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&(phs.len() as u16).to_le_bytes());
    for (index, ph) in phs.iter().enumerate() {
        let at = 64 + 56 * index;
        bytes[at..at + 4].copy_from_slice(&ph.kind.to_le_bytes());
        bytes[at + 4..at + 8].copy_from_slice(&ph.flags.to_le_bytes());
        bytes[at + 8..at + 16].copy_from_slice(&ph.offset.to_le_bytes());
        bytes[at + 16..at + 24].copy_from_slice(&ph.vaddr.to_le_bytes());
        bytes[at + 24..at + 32].copy_from_slice(&ph.vaddr.to_le_bytes());
        bytes[at + 32..at + 40].copy_from_slice(&ph.filesz.to_le_bytes());
        bytes[at + 40..at + 48].copy_from_slice(&ph.memsz.to_le_bytes());
        bytes[at + 48..at + 56].copy_from_slice(&0x1000u64.to_le_bytes());
    }
    bytes
}

/// The oracle `init` of target/linux-reference/init-reference-001 (readelf.txt).
pub(crate) fn oracle() -> Vec<u8> {
    elf(
        EXEC,
        0x2047d0,
        &[
            Ph {
                kind: 6,
                flags: R,
                offset: 0x40,
                vaddr: 0x200040,
                filesz: 0x188,
                memsz: 0x188,
            },
            load(R, 0, 0x200000, 0x37c8, 0x37c8),
            load(R | X, 0x37d0, 0x2047d0, 0x6094, 0x6094),
            load(R | W, 0x9868, 0x20b868, 0x578, 0x798),
            load(R | W, 0x9de0, 0x20cde0, 0x1e0, 0x1e0),
            Ph {
                kind: 0x6474_e552,
                flags: R,
                offset: 0x9868,
                vaddr: 0x20b868,
                filesz: 0x578,
                memsz: 0x798,
            },
            Ph {
                kind: GNU_STACK,
                flags: R | W,
                offset: 0,
                vaddr: 0,
                filesz: 0,
                memsz: 0,
            },
        ],
        53912,
    )
}

fn plan(phs: &[Ph], len: usize) -> Result<LoadPlan, LoadError> {
    LoadPlan::new(&elf(EXEC, 0x1000, phs, len))
}
fn errno(result: Result<LoadPlan, LoadError>) -> Errno {
    match result {
        Err(LoadError::Errno(errno)) => errno,
        other => panic!("expected an errno, got {other:?}"),
    }
}
fn unsupported(result: Result<LoadPlan, LoadError>) -> Unsupported {
    match result {
        Err(LoadError::Unsupported(kind)) => kind,
        other => panic!("expected unsupported, got {other:?}"),
    }
}

#[test]
fn oracle_binary_plans_like_linux() {
    let file = oracle();
    let plan = LoadPlan::new(&file).unwrap();
    assert_eq!(plan.entry, 0x2047d0);
    assert_eq!(plan.phdr, 0x200040); // AT_PHDR in the oracle's auxv
    assert_eq!(plan.phnum, 7); // AT_PHNUM
    assert!(!plan.exec_stack);
    assert_eq!(plan.brk, 0x20d000);
    let segments = plan.segments();
    assert_eq!(segments.len(), 4);
    assert_eq!(
        (
            segments[0].start,
            segments[0].file_pages,
            segments[0].anon_pages
        ),
        (0x200000, 4, 0)
    );
    assert_eq!(
        (
            segments[1].start,
            segments[1].file_pages,
            segments[1].file_offset
        ),
        (0x204000, 7, 0x3000)
    );
    assert_eq!(
        (
            segments[2].start,
            segments[2].file_pages,
            segments[2].anon_pages
        ),
        (0x20b000, 1, 0)
    );
    assert_eq!(
        (
            segments[3].start,
            segments[3].file_pages,
            segments[3].file_offset
        ),
        (0x20c000, 1, 0x9000)
    );
    // print_vma_addr in the oracle: init[45b4,204000+7000] for ip 0x2055b4.
    let vma = plan.vmas.find(0x2055b4).unwrap();
    assert_eq!(
        (vma.start, vma.end - vma.start, vma.pgoff),
        (0x204000, 0x7000, 3)
    );
    assert!(plan.vmas.find(0x20d000).is_none());
    assert!(plan.vmas.find(0x1fffff).is_none());
}

#[test]
fn page_contents_come_from_the_file_with_padzero_only_when_writable() {
    let mut file = oracle();
    file.iter_mut().skip(128 + 56 * 7).for_each(|b| *b = 0xaa);
    let plan = LoadPlan::new(&file).unwrap();
    let mut page = [0u8; 4096];
    // Writable segment with bss: bytes from p_vaddr+p_filesz (0x20bde0) are zeroed,
    // the file bytes before it survive.
    plan.segments()[2].fill_page(&file, 0, &mut page);
    assert_eq!(page[0x868], 0xaa);
    assert_eq!(page[0xddf], 0xaa);
    assert!(page[0xde0..].iter().all(|&b| b == 0));
    // Same bytes in a read-only segment are NOT cleared (clear_user fails and
    // is ignored): page 0 of the first segment holds file bytes up to its end.
    let ro = elf(EXEC, 0x1000, &[load(R, 0, 0x400000, 0x10, 0x2000)], 0x1000);
    let ro_plan = LoadPlan::new(&ro).unwrap();
    let mut ro_file = ro.clone();
    ro_file.fill(0xbb);
    ro_plan.segments()[0].fill_page(&ro_file, 0, &mut page);
    assert!(
        page.iter().all(|&b| b == 0xbb),
        "no padzero on a read-only mapping"
    );
    // The anonymous bss part is zero, readable and writable even though the
    // segment itself is read-only, and executable only when the segment is.
    let seg = ro_plan.segments()[0];
    assert_eq!((seg.file_pages, seg.anon_pages), (1, 1));
    let p = seg.page_prot(1);
    assert!(p.read && p.write && !p.exec);
    ro_plan.segments()[0].fill_page(&ro_file, 1, &mut page);
    assert!(page.iter().all(|&b| b == 0));
}

#[test]
fn short_last_file_page_is_zero_extended() {
    // 0x1800-byte file: the second page holds 0x800 file bytes, then zeros.
    let mut file = elf(
        EXEC,
        0x1000,
        &[load(R, 0, 0x400000, 0x1800, 0x1800)],
        0x1800,
    );
    let plan = LoadPlan::new(&file).unwrap();
    file.fill(0xcc);
    let mut page = [1u8; 4096];
    plan.segments()[0].fill_page(&file, 1, &mut page);
    assert!(page[..0x800].iter().all(|&b| b == 0xcc));
    assert!(page[0x800..].iter().all(|&b| b == 0));
}

#[test]
fn header_rejections_are_enoexec_in_linux_order() {
    let good = oracle();
    let mut bad = good.clone();
    bad[0] = 0;
    assert_eq!(errno(LoadPlan::new(&bad)), Errno::ENOEXEC);
    assert_eq!(errno(LoadPlan::new(&[])), Errno::ENOEXEC);
    assert_eq!(errno(LoadPlan::new(&good[..63])), Errno::ENOEXEC);
    for (offset, value) in [
        (16usize, 1u8),
        (16, 4),
        (16, 0),
        (18, 3),
        (18, 0),
        (54, 32),
        (54, 0),
        (56, 0),
    ] {
        let mut bad = good.clone();
        bad[offset] = value;
        assert_eq!(
            errno(LoadPlan::new(&bad)),
            Errno::ENOEXEC,
            "{offset}={value}"
        );
    }
    // e_phnum * 56 > 65536, and the table must lie inside the file.
    let mut bad = good.clone();
    bad[56..58].copy_from_slice(&1171u16.to_le_bytes());
    assert_eq!(errno(LoadPlan::new(&bad)), Errno::ENOEXEC);
    bad[56..58].copy_from_slice(&u16::MAX.to_le_bytes());
    assert_eq!(errno(LoadPlan::new(&bad)), Errno::ENOEXEC);
    let truncated = &good[..64 + 56 * 3];
    assert_eq!(errno(LoadPlan::new(truncated)), Errno::ENOEXEC);
    let mut bad = good.clone();
    bad[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(errno(LoadPlan::new(&bad)), Errno::ENOEXEC);
}

#[test]
fn dynamic_and_pie_are_explicitly_unsupported_not_errors() {
    let interp = Ph {
        kind: INTERP,
        flags: R,
        offset: 0x1000,
        vaddr: 0,
        filesz: 5,
        memsz: 5,
    };
    let mut file = elf(
        EXEC,
        0x1000,
        &[interp, load(R, 0, 0x400000, 0x100, 0x100)],
        0x2000,
    );
    file[0x1000..0x1005].copy_from_slice(b"/ld\0\0");
    assert_eq!(unsupported(LoadPlan::new(&file)), Unsupported::Interpreter);
    file[0x1004] = b'x'; // unterminated
    file[0x1003] = b'x';
    assert_eq!(errno(LoadPlan::new(&file)), Errno::ENOEXEC);
    let tiny = Ph {
        filesz: 1,
        ..interp
    };
    assert_eq!(
        errno(LoadPlan::new(&elf(EXEC, 0x1000, &[tiny], 0x2000))),
        Errno::ENOEXEC
    );
    let huge = Ph {
        filesz: 4097,
        ..interp
    };
    assert_eq!(
        errno(LoadPlan::new(&elf(EXEC, 0x1000, &[huge], 0x2000))),
        Errno::ENOEXEC
    );
    let beyond = Ph {
        offset: 0x10_0000,
        ..interp
    };
    assert_eq!(
        errno(LoadPlan::new(&elf(EXEC, 0x1000, &[beyond], 0x2000))),
        Errno::EIO
    );
    let pie = elf(DYN, 0x1000, &[load(R, 0, 0, 0x100, 0x100)], 0x1000);
    assert_eq!(unsupported(LoadPlan::new(&pie)), Unsupported::SharedObject);
}

#[test]
fn gnu_stack_last_one_wins() {
    let stack = |flags| Ph {
        kind: GNU_STACK,
        flags,
        offset: 0,
        vaddr: 0,
        filesz: 0,
        memsz: 0,
    };
    let l = load(R, 0, 0x400000, 0x100, 0x100);
    assert!(!plan(&[l], 0x1000).unwrap().exec_stack);
    assert!(plan(&[l, stack(R | W | X)], 0x1000).unwrap().exec_stack);
    assert!(!plan(&[l, stack(R | W)], 0x1000).unwrap().exec_stack);
    assert!(
        !plan(&[l, stack(R | W | X), stack(R | W)], 0x1000)
            .unwrap()
            .exec_stack
    );
}

#[test]
fn rwx_segments_are_allowed_and_prot_none_is_accounted_but_inaccessible() {
    let p = plan(
        &[
            load(R | W | X, 0, 0x400000, 0x100, 0x100),
            load(0, 0x1000, 0x500000, 0x10, 0x10),
        ],
        0x2000,
    )
    .unwrap();
    let rwx = p.segments()[0].prot;
    assert!(rwx.read && rwx.write && rwx.exec);
    assert!(!p.segments()[1].prot.accessible());
    // x86 has no write-only or execute-only user pages: they read too.
    assert!(
        plan(&[load(W, 0, 0x400000, 0x10, 0x10)], 0x1000)
            .unwrap()
            .segments()[0]
            .prot
            .accessible()
    );
}

#[test]
fn entry_and_segment_bounds_follow_task_size() {
    let l = load(R | X, 0, 0x400000, 0x100, 0x100);
    assert_eq!(
        errno(LoadPlan::new(&elf(EXEC, TASK_SIZE_MAX, &[l], 0x1000))),
        Errno::EINVAL
    );
    assert!(LoadPlan::new(&elf(EXEC, TASK_SIZE_MAX - 1, &[l], 0x1000)).is_ok());
    assert!(LoadPlan::new(&elf(EXEC, 0, &[], 0x1000)).is_err()); // no program headers
    // vaddr + memsz beyond TASK_SIZE_MAX: the mmap/brk layer says ENOMEM first.
    assert_eq!(
        errno(plan(&[load(R, 0, 0x400000, 0x10, TASK_SIZE_MAX)], 0x1000)),
        Errno::ENOMEM
    );
    // ... but a first segment whose file page lands on the stack is -EEXIST.
    assert_eq!(
        errno(plan(
            &[load(R, 0, TASK_SIZE_MAX - 0x1000, 0x10, 0x2000)],
            0x1000
        )),
        Errno::EEXIST
    );
    assert_eq!(
        errno(plan(&[load(R, 0, TASK_SIZE_MAX, 0x10, 0x10)], 0x1000)),
        Errno::ENOMEM
    );
    assert_eq!(
        errno(plan(&[load(R, 0, 0x400000, 0, u64::MAX - 0x1000)], 0x1000)),
        Errno::ENOMEM
    );
    // memsz = u64::MAX: the C arithmetic wraps to an empty brk range, and the
    // post-mapping `memsz > TASK_SIZE` check answers -EINVAL.
    assert_eq!(
        errno(plan(&[load(R, 0, 0x400000, 0, u64::MAX)], 0x1000)),
        Errno::EINVAL
    );
    assert_eq!(
        errno(plan(&[load(R, 0, 0x400000, 0, TASK_SIZE_MAX + 1)], 0x1000)),
        Errno::ENOMEM
    );
    // Anonymous-only segment ending exactly at TASK_SIZE_MAX is mappable but
    // overlaps the fixed stack: explicit, not silent.
    assert_eq!(
        unsupported(plan(
            &[load(R | W, 0, TASK_SIZE_MAX - 0x2000, 0, 0x2000)],
            0x1000
        )),
        Unsupported::Overlap
    );
    // filesz > memsz is -EINVAL after mapping.
    assert_eq!(
        errno(plan(&[load(R, 0, 0x400000, 0x20, 0x10)], 0x1000)),
        Errno::EINVAL
    );
    // Mapped but beyond: p_vaddr at/after TASK_SIZE_MAX with size zero.
    assert_eq!(
        errno(plan(&[load(R, 0, u64::MAX, 0, 0)], 0x1000)),
        Errno::EINVAL
    );
}

#[test]
fn offset_alignment_and_wraparound_follow_vm_mmap() {
    // vaddr page offset 0x10 but file offset 0: off = -0x10, not page aligned.
    assert_eq!(
        errno(plan(&[load(R, 0, 0x400010, 0x10, 0x10)], 0x1000)),
        Errno::EINVAL
    );
    // Congruent offsets work.
    assert!(plan(&[load(R, 0x10, 0x400010, 0x10, 0x10)], 0x1000).is_ok());
    // offset + size wraps around 2^64: vm_mmap says -EINVAL.
    assert_eq!(
        errno(plan(
            &[load(R, u64::MAX - 0xfff, 0x400000, 0x2000, 0x2000)],
            0x1000
        )),
        Errno::EINVAL
    );
    // Above ramfs MAX_LFS_FILESIZE.
    assert_eq!(
        errno(plan(&[load(R, 1 << 63, 0x400000, 0x10, 0x10)], 0x1000)),
        Errno::EOVERFLOW
    );
    // filesz so large that page_align wraps to zero: nothing is mapped and the
    // post-mapping check rejects it.
    assert_eq!(
        errno(plan(
            &[load(R, 0, 0x400000, u64::MAX - 100, u64::MAX)],
            0x1000
        )),
        Errno::EINVAL
    );
}

#[test]
fn mapping_beyond_end_of_file_and_overlaps_are_explicit() {
    // The last page of the mapping starts past EOF: Linux would raise SIGBUS.
    assert_eq!(
        unsupported(plan(&[load(R, 0, 0x400000, 0x3000, 0x3000)], 0x1000)),
        Unsupported::BeyondEof
    );
    assert!(plan(&[load(R, 0, 0x400000, 0x3000, 0x3000)], 0x2001).is_ok());
    // First segment on the stack is MAP_FIXED_NOREPLACE: -EEXIST.
    assert_eq!(
        errno(plan(&[load(R, 0, STACK_START, 0x10, 0x10)], 0x1000)),
        Errno::EEXIST
    );
    // Later overlap (MAP_FIXED would replace) is unsupported.
    let a = load(R, 0, 0x400000, 0x1800, 0x1800);
    let b = load(R | W, 0x1000, 0x401000, 0x10, 0x10);
    assert_eq!(unsupported(plan(&[a, b], 0x2000)), Unsupported::Overlap);
    let on_stack = load(R | W, 0, STACK_START, 0, 0x1000);
    assert_eq!(
        unsupported(plan(&[a, on_stack], 0x2000)),
        Unsupported::Overlap
    );
    // Touching but disjoint is fine.
    assert!(plan(&[a, load(R | W, 0x1000, 0x402000, 0x10, 0x10)], 0x2000).is_ok());
}

#[test]
fn segment_count_is_bounded() {
    let loads: Vec<Ph> = (0..=MAX_LOADS as u64)
        .map(|i| load(R, 0, 0x400000 + i * 0x2000, 0x10, 0x10))
        .collect();
    assert!(plan(&loads[..MAX_LOADS], 0x1000).is_ok());
    assert_eq!(unsupported(plan(&loads, 0x1000)), Unsupported::TooManyLoads);
}

#[test]
fn program_header_address_is_zero_when_unmapped() {
    // The table (offset 64) is not inside any PT_LOAD file range.
    let p = plan(&[load(R, 0x1000, 0x401000, 0x100, 0x100)], 0x2000).unwrap();
    assert_eq!(p.phdr, 0);
    let p = plan(&[load(R, 0, 0x400000, 0x200, 0x200)], 0x1000).unwrap();
    assert_eq!(p.phdr, 0x400040);
}

#[test]
fn bss_only_segment_and_brk() {
    let p = plan(&[load(R | W, 0, 0x600123, 0, 0x2000)], 0x1000).unwrap();
    let s = p.segments()[0];
    assert_eq!((s.start, s.file_pages, s.anon_pages), (0x600000, 0, 3));
    assert_eq!(p.brk, 0x603000);
    assert!(p.vmas.find(0x600000).is_none()); // anonymous: no file name
    let empty = plan(&[load(R, 0, 0x600000, 0, 0)], 0x1000).unwrap();
    assert_eq!(empty.segments()[0].pages(), 0);
}

#[test]
fn hostile_random_headers_never_panic() {
    // xorshift-driven corruption of the oracle's header and program table.
    let good = oracle();
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    for _ in 0..20_000 {
        let mut bytes = good.clone();
        for _ in 0..4 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let at = (state % (64 + 56 * 7)) as usize;
            bytes[at] = (state >> 32) as u8;
        }
        let _ = LoadPlan::new(&bytes);
    }
}
