#![allow(
    clippy::unreadable_literal,
    clippy::cast_possible_truncation,
    clippy::similar_names,
    clippy::large_types_passed_by_value,
    clippy::format_push_string,
    clippy::cast_possible_wrap
)]
extern crate std;
use super::{
    ARG_PAGES, AT_BASE, AT_CLKTCK, AT_EGID, AT_ENTRY, AT_EUID, AT_EXECFN, AT_FLAGS, AT_GID,
    AT_HWCAP, AT_HWCAP2, AT_MINSIGSTKSZ, AT_NULL, AT_PAGESZ, AT_PHDR, AT_PHENT, AT_PHNUM,
    AT_PLATFORM, AT_RANDOM, AT_SECURE, AT_UID, Aux, ENVP, MIN_SIGSTACK_SIZE, STACK_PAGES,
    STACK_START, STACK_TOP, StackError, WINDOW_BYTES, Word, build, weak_random,
};
use std::{string::String, vec::Vec};

const AUX: Aux = Aux {
    hwcap: 0x078b_fbfd,
    phdr: 0x20_0040,
    phnum: 7,
    entry: 0x20_47d0,
    random: *b"0123456789abcdef",
};

fn make(
    argv: &[&[u8]],
    envp: &[Word<'_>],
    filename: &[u8],
    len: usize,
) -> Result<(Vec<u8>, super::Built), StackError> {
    let mut window = std::vec![0u8; len];
    let words = argv.iter().map(|text| Word::plain(text));
    let built = build(&mut window, filename, words, envp.iter().copied(), &AUX)?;
    Ok((window, built))
}

/// Decode the block at `sp` the way a C runtime would.
struct Decoded {
    argc: u64,
    argv: Vec<String>,
    envp: Vec<String>,
    auxv: Vec<(u64, u64)>,
}

fn decode(window: &[u8], sp: u64) -> Decoded {
    let base = STACK_TOP - window.len() as u64;
    let word = |address: u64| {
        let at = (address - base) as usize;
        u64::from_le_bytes(window[at..at + 8].try_into().unwrap())
    };
    let string = |address: u64| {
        let at = (address - base) as usize;
        let end = window[at..].iter().position(|&b| b == 0).unwrap();
        String::from_utf8(window[at..at + end].to_vec()).unwrap()
    };
    let argc = word(sp);
    let mut at = sp + 8;
    let mut argv = Vec::new();
    for _ in 0..argc {
        argv.push(string(word(at)));
        at += 8;
    }
    assert_eq!(word(at), 0);
    at += 8;
    let mut envp = Vec::new();
    while word(at) != 0 {
        envp.push(string(word(at)));
        at += 8;
    }
    at += 8;
    let mut auxv = Vec::new();
    loop {
        let pair = (word(at), word(at + 8));
        at += 16;
        auxv.push(pair);
        if pair.0 == AT_NULL {
            break;
        }
    }
    Decoded {
        argc,
        argv,
        envp,
        auxv,
    }
}

#[test]
fn known_layout_is_byte_exact() {
    let (window, built) = make(&[b"/init"], &ENVP, b"/init", WINDOW_BYTES).unwrap();
    // Hand-computed from create_elf_tables: top-8, then "/init\0" (6), env
    // (7 + 11), argv "/init\0" (6), align 16, platform (7), random (16), 40 aux
    // words, 6 vector words, round down to 16.
    assert_eq!(built.execfn, 0x7fff_ffff_eff2);
    assert_eq!(built.random, 0x7fff_ffff_efb9);
    assert_eq!(built.sp, 0x7fff_ffff_ee40);
    assert_eq!(built.sp % 16, 0);
    let top = &window[WINDOW_BYTES - 8..];
    assert_eq!(top, [0; 8], "empty pointer slot above the filename");
    let at = |address: u64, len: usize| {
        let start = (address - (STACK_TOP - WINDOW_BYTES as u64)) as usize;
        &window[start..start + len]
    };
    assert_eq!(at(0x7fff_ffff_eff2, 6), b"/init\0");
    assert_eq!(at(0x7fff_ffff_efe0, 18), b"HOME=/\0TERM=linux\0");
    assert_eq!(at(0x7fff_ffff_efda, 6), b"/init\0");
    assert_eq!(at(0x7fff_ffff_efc9, 7), b"x86_64\0");
    assert_eq!(at(0x7fff_ffff_efb9, 16), b"0123456789abcdef");
    let decoded = decode(&window, built.sp);
    assert_eq!(decoded.argc, 1);
    assert_eq!(decoded.argv, ["/init"]);
    assert_eq!(decoded.envp, ["HOME=/", "TERM=linux"]);
    // Pointers: argv[0] at the lowest string, envp strings follow in order.
    let word = |address: u64| u64::from_le_bytes(at(address, 8).try_into().unwrap());
    assert_eq!(word(built.sp + 8), 0x7fff_ffff_efda);
    assert_eq!(word(built.sp + 24), 0x7fff_ffff_efe0);
    assert_eq!(word(built.sp + 32), 0x7fff_ffff_efe7);
}

#[test]
fn auxv_order_and_values_match_the_pinned_oracle_without_vdso_or_rseq() {
    let (window, built) = make(&[b"/init"], &ENVP, b"/init", WINDOW_BYTES).unwrap();
    let auxv = decode(&window, built.sp).auxv;
    let expected = [
        (AT_MINSIGSTKSZ, 0x5a0),
        (AT_HWCAP, 0x78b_fbfd),
        (AT_PAGESZ, 0x1000),
        (AT_CLKTCK, 0x64),
        (AT_PHDR, 0x20_0040),
        (AT_PHENT, 0x38),
        (AT_PHNUM, 7),
        (AT_BASE, 0),
        (AT_FLAGS, 0),
        (AT_ENTRY, 0x20_47d0),
        (AT_UID, 0),
        (AT_EUID, 0),
        (AT_GID, 0),
        (AT_EGID, 0),
        (AT_SECURE, 0),
        (AT_RANDOM, built.random),
        (AT_HWCAP2, 0),
        (AT_EXECFN, built.execfn),
        (AT_PLATFORM, 0x7fff_ffff_efc9),
        (AT_NULL, 0),
    ];
    assert_eq!(auxv, expected);
    // No AT_SYSINFO_EHDR (33), AT_RSEQ_FEATURE_SIZE (27) or AT_RSEQ_ALIGN (28).
    assert!(auxv.iter().all(|&(id, _)| ![33, 27, 28].contains(&id)));
}

#[test]
fn min_sigstack_size_is_the_fxsave_only_get_sigframe_size() {
    // 732 (sigframe_ia32) + 15 + 512 + 112 + 63 = 1434 -> round_up(16).
    assert_eq!(MIN_SIGSTACK_SIZE, 0x5a0);
    assert_eq!(MIN_SIGSTACK_SIZE % 16, 0);
}

#[test]
fn strings_vectors_and_alignment_hold_for_every_length() {
    // Exhaust lengths around the 16-byte alignment: every combination of
    // filename, argv and env lengths mod 16 (and more argv words).
    for filename_len in 1..20 {
        for arg_len in 0..20 {
            for env_len in 0..20 {
                let filename = std::vec![b'f'; filename_len];
                let arg0 = std::vec![b'a'; arg_len];
                let arg1 = std::vec![b'b'; arg_len + 1];
                let env = std::vec![b'e'; env_len];
                let envp = [
                    Word::plain(&env),
                    Word {
                        param: b"K",
                        value: Some(&env),
                    },
                ];
                let argv: [&[u8]; 3] = [&filename, &arg0, &arg1];
                let (window, built) = make(&argv, &envp, &filename, WINDOW_BYTES).unwrap();
                assert_eq!(built.sp % 16, 0);
                let decoded = decode(&window, built.sp);
                assert_eq!(decoded.argc, 3);
                assert_eq!(decoded.argv[0].as_bytes(), &filename[..]);
                assert_eq!(decoded.argv[1].as_bytes(), &arg0[..]);
                assert_eq!(decoded.argv[2].as_bytes(), &arg1[..]);
                assert_eq!(decoded.envp[0].as_bytes(), &env[..]);
                assert_eq!(decoded.envp[1].as_bytes(), [b"K=", &env[..]].concat());
                assert_eq!(decoded.auxv.len(), 20);
                let platform = decoded.auxv[18].1;
                assert!(built.sp < built.random && built.random < platform);
            }
        }
    }
}

#[test]
fn argv_zero_is_the_lowest_string_and_env_follows_argv() {
    let (window, built) = make(&[b"/init", b"fault", b"x"], &ENVP, b"/init", WINDOW_BYTES).unwrap();
    let base = STACK_TOP - WINDOW_BYTES as u64;
    let pointers: Vec<u64> = (0..3)
        .map(|i| {
            let at = (built.sp + 8 + 8 * i - base) as usize;
            u64::from_le_bytes(window[at..at + 8].try_into().unwrap())
        })
        .collect();
    assert!(pointers[0] < pointers[1] && pointers[1] < pointers[2]);
    assert_eq!(pointers[1] - pointers[0], 6);
    assert_eq!(pointers[2] - pointers[1], 6);
}

#[test]
fn oversized_blocks_fail_with_too_big_not_a_panic() {
    let huge = std::vec![b'x'; WINDOW_BYTES];
    assert_eq!(
        make(&[&huge], &ENVP, b"/init", WINDOW_BYTES).unwrap_err(),
        StackError::TooBig
    );
    let nearly = std::vec![b'x'; WINDOW_BYTES - 128];
    assert_eq!(
        make(&[&nearly], &ENVP, b"/init", WINDOW_BYTES).unwrap_err(),
        StackError::TooBig
    );
    assert_eq!(
        make(&[b"/init"], &ENVP, &huge, WINDOW_BYTES).unwrap_err(),
        StackError::TooBig
    );
    // A window that cannot even hold the fixed parts.
    for len in [0, 8, 64, 300] {
        assert_eq!(
            make(&[b"/init"], &ENVP, b"/init", len).unwrap_err(),
            StackError::TooBig
        );
    }
    // 32 init words plus the filename fit the argument pages comfortably.
    let words: Vec<&[u8]> = std::vec![&b"0123456789"[..]; 33];
    assert!(make(&words, &ENVP, b"/init", WINDOW_BYTES).is_ok());
}

#[test]
fn stack_extent_matches_linux_arg_pages_plus_expand() {
    assert_eq!(STACK_TOP, 0x7fff_ffff_f000);
    assert_eq!(STACK_PAGES, ARG_PAGES + 32);
    assert_eq!(STACK_START, STACK_TOP - 36 * 4096);
}

#[test]
fn weak_random_is_splitmix64() {
    // First SplitMix64 output for seed 0 (Vigna's reference).
    assert_eq!(
        &weak_random(0)[..8],
        &0xe220_a839_7b1d_cdafu64.to_le_bytes()
    );
    assert_ne!(weak_random(1), weak_random(2));
}
