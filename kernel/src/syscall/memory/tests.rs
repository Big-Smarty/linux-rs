#![allow(clippy::too_many_lines, clippy::doc_markdown)]
//! Argument decoding and outcome mapping of the memory syscalls. The mapping
//! rules themselves are tested in `mm::tests` against the oracle values.
use crate::{
    mm::{MAP_ANONYMOUS, MAP_HUGETLB, MAP_PRIVATE, MAP_SHARED, PROT_READ, PROT_WRITE},
    syscall::{Outcome, dispatch, error, testing::task},
    usercopy::TASK_SIZE_MAX,
};
use syscalls::{Errno, Sysno};

const P: u64 = 4096;
const TOP: u64 = TASK_SIZE_MAX - 0x800_0000;
const ANON: u64 = MAP_PRIVATE | MAP_ANONYMOUS;
const RW: u64 = PROT_READ | PROT_WRITE;

fn neg(errno: Errno) -> Outcome {
    Outcome::Return(error(errno))
}

#[test]
fn mmap_munmap_mprotect_and_brk_return_linux_values() {
    let mut t = task();
    let mut call = |sysno: Sysno, args: [u64; 6]| dispatch(&mut t, sysno as u64, args);
    // First anonymous mapping sits right under mmap_base (norandmaps).
    assert_eq!(
        call(Sysno::mmap, [0, P, RW, ANON, u64::MAX, 0]),
        Outcome::Return((TOP - P).cast_signed())
    );
    assert_eq!(
        call(Sysno::mprotect, [TOP - P, P, PROT_READ, 0, 0, 0]),
        Outcome::Return(0)
    );
    assert_eq!(
        call(Sysno::mprotect, [TOP - P + 1, P, 0, 0, 0, 0]),
        neg(Errno::EINVAL)
    );
    assert_eq!(
        call(Sysno::munmap, [TOP - P, P, 0, 0, 0, 0]),
        Outcome::Return(0)
    );
    assert_eq!(
        call(Sysno::munmap, [TOP - P, P, 0, 0, 0, 0]),
        Outcome::Return(0)
    ); // hole: fine
    assert_eq!(call(Sysno::munmap, [1, P, 0, 0, 0, 0]), neg(Errno::EINVAL));
    assert_eq!(
        call(Sysno::munmap, [TOP, 0, 0, 0, 0, 0]),
        neg(Errno::EINVAL)
    );
    // brk(0) before any program break is set returns the current (zero) break.
    assert_eq!(call(Sysno::brk, [0; 6]), Outcome::Return(0));
}

#[test]
fn mmap_decodes_offset_descriptor_and_unsupported_requests() {
    let mut t = task();
    let mut call = |args: [u64; 6]| dispatch(&mut t, Sysno::mmap as u64, args);
    // x86-64 sys_mmap: the byte offset must be page aligned, checked first.
    assert_eq!(call([0, P, RW, ANON, 0, 1]), neg(Errno::EINVAL));
    assert_eq!(call([0, 0, RW, 0, 99, 1]), neg(Errno::EINVAL));
    // A file mapping resolves the descriptor: 3 is closed, 0 is the console
    // (no ->mmap: ENODEV after do_mmap's argument checks, so len 0 is EINVAL).
    assert_eq!(call([0, P, RW, MAP_PRIVATE, 3, 0]), neg(Errno::EBADF));
    assert_eq!(
        call([0, P, RW, MAP_PRIVATE, 0x1_0000_0000, 0]),
        Outcome::Return(error(Errno::ENODEV))
    );
    assert_eq!(call([0, P, RW, MAP_PRIVATE, 0, 0]), neg(Errno::ENODEV));
    assert_eq!(call([0, 0, RW, MAP_PRIVATE, 0, 0]), neg(Errno::EINVAL));
    assert_eq!(call([0, P, RW, 0, 2, 0]), neg(Errno::EINVAL)); // no MAP_PRIVATE|MAP_SHARED
    // The anonymous requests Linux serves with shmem or hugetlbfs stop loudly.
    assert_eq!(
        call([0, P, RW, MAP_SHARED | MAP_ANONYMOUS, 0, 0]),
        Outcome::Unimplemented(9)
    );
    assert_eq!(
        call([0, P, RW, ANON | MAP_HUGETLB, 0, 0]),
        Outcome::Unimplemented(9)
    );
}

#[test]
fn madvise_checks_then_walks_then_stops_for_unimplemented_advice() {
    let mut t = task();
    let base = match dispatch(&mut t, Sysno::mmap as u64, [0, 3 * P, RW, ANON, 0, 0]) {
        Outcome::Return(a) => a.cast_unsigned(),
        other => panic!("{other:?}"),
    };
    let mut madvise = |start: u64, len: u64, advice: u64| {
        dispatch(&mut t, Sysno::madvise as u64, [start, len, advice, 0, 0, 0])
    };
    // MADV_NORMAL over a mapped range is 0; any hole is ENOMEM (after the walk).
    assert_eq!(madvise(base, 3 * P, 0), Outcome::Return(0));
    assert_eq!(madvise(base + 1, 1, 0), neg(Errno::EINVAL));
    assert_eq!(madvise(base, 4 * P, 0), neg(Errno::ENOMEM));
    assert_eq!(madvise(base - P, 2 * P, 0), neg(Errno::ENOMEM));
    assert_eq!(madvise(base + 3 * P, P, 0), neg(Errno::ENOMEM));
    // Zero length is success before any behaviour runs, a wrapping one EINVAL.
    assert_eq!(madvise(base, 0, 0), Outcome::Return(0));
    assert_eq!(madvise(base, 0, 4), Outcome::Return(0));
    assert_eq!(madvise(base, u64::MAX, 0), neg(Errno::EINVAL));
    assert_eq!(madvise(u64::MAX - 4095, 2 * P, 0), neg(Errno::EINVAL));
    // Behaviours the declared configuration does not have are EINVAL even for
    // an empty range; `int behavior` is truncated to 32 bits.
    for advice in [
        5,
        12,
        13,
        14,
        15,
        25,
        100,
        101,
        104,
        0xffff_ffff,
        0x1_0000_0000 | 7,
    ] {
        assert_eq!(madvise(base, 0, advice), neg(Errno::EINVAL), "{advice}");
    }
    assert_eq!(madvise(base, P, 0x1_0000_0000), Outcome::Return(0));
    // Valid behaviours this kernel does not implement stop loudly.
    for advice in [
        1, 2, 3, 4, 8, 9, 10, 11, 16, 17, 18, 19, 20, 21, 22, 23, 24, 102, 103,
    ] {
        assert_eq!(
            madvise(base, P, advice),
            Outcome::Unimplemented(28),
            "{advice}"
        );
    }
}
