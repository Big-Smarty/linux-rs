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
    BadFrame, ExecFailed, InitDeath, NO_INIT, SIGBUS, SIGFPE, SIGILL, SIGSEGV, SIGTRAP, Segfault,
    TrapLine, signal_exit_code, user_exception,
};
use crate::exec::load::tests::loaded_oracle;
use crate::exec::report::FileRegion;
use std::string::ToString;

#[test]
fn init_death_and_no_init_text_are_linux_exact() {
    assert_eq!(
        InitDeath(0).to_string(),
        "Kernel panic - not syncing: Attempted to kill init! exitcode=0x00000000"
    );
    assert_eq!(
        InitDeath(0x0100).to_string(),
        "Kernel panic - not syncing: Attempted to kill init! exitcode=0x00000100"
    );
    assert_eq!(
        InitDeath(signal_exit_code(SIGSEGV)).to_string(),
        "Kernel panic - not syncing: Attempted to kill init! exitcode=0x0000000b"
    );
    assert_eq!(
        NO_INIT,
        "Kernel panic - not syncing: No working init found.  Try passing init= option to kernel. See Linux Documentation/admin-guide/init.rst for guidance."
    );
    assert_eq!(
        ExecFailed(-8).to_string(),
        "Failed to execute /init (error -8)"
    );
}

#[test]
fn segfault_line_matches_the_oracle_byte_for_byte() {
    let mm = loaded_oracle();
    let line = Segfault {
        address: 0,
        ip: 0x20_55b4,
        sp: 0x7ffd_2010_a150,
        error: 4,
        region: FileRegion::of(&mm, 0x20_55b4),
    };
    // From target/linux-reference/init-reference-001/oracle-fault.log.
    assert_eq!(
        line.to_string(),
        "init[1]: segfault at 0 ip 00000000002055b4 sp 00007ffd2010a150 error 4 in init[45b4,204000+7000] likely on CPU 0 (core 0, socket 0)"
    );
}

#[test]
fn segfault_outside_a_file_mapping_has_no_vma_part_and_kernel_addresses_look_like_prot() {
    let mm = loaded_oracle();
    let line = Segfault {
        address: 0xffff_8000_0000_1000,
        ip: 0x7fff_ffff_e000,
        sp: 0x7fff_ffff_ee40,
        error: 6,
        region: FileRegion::of(&mm, 0x7fff_ffff_e000),
    };
    assert_eq!(
        line.to_string(),
        "init[1]: segfault at ffff800000001000 ip 00007fffffffe000 sp 00007fffffffee40 error 7 likely on CPU 0 (core 0, socket 0)"
    );
    // The bss/heap side of the last data page, and the byte past a region.
    let inside = Segfault {
        address: 0,
        ip: 0x20_cfff,
        sp: 0,
        error: 0,
        region: FileRegion::of(&mm, 0x20_cfff),
    };
    assert!(inside.to_string().contains(" in init[9fff,20c000+1000]"));
    let past = Segfault {
        address: 0,
        ip: 0x20_d000,
        sp: 0,
        error: 0,
        region: FileRegion::of(&mm, 0x20_d000),
    };
    assert!(!past.to_string().contains(" in "));
}

#[test]
fn user_exceptions_map_to_linux_signals_and_messages() {
    let cases = [
        (0u8, SIGFPE, Some(("trap ", "divide error"))),
        (1, SIGTRAP, None),
        (3, SIGTRAP, Some(("trap ", "int3"))),
        (4, SIGSEGV, Some(("trap ", "overflow"))),
        (5, SIGSEGV, Some(("trap ", "bounds"))),
        (6, SIGILL, Some(("trap ", "invalid opcode"))),
        (10, SIGSEGV, Some(("trap ", "invalid TSS"))),
        (11, SIGBUS, Some(("trap ", "segment not present"))),
        (12, SIGBUS, Some(("trap ", "stack segment"))),
        (13, SIGSEGV, Some(("", "general protection fault"))),
        (16, SIGFPE, None),
        (17, SIGBUS, Some(("trap ", "alignment check"))),
        (19, SIGFPE, None),
    ];
    for (vector, signal, message) in cases {
        let user = user_exception(vector).unwrap();
        assert_eq!(
            (user.signal, user.message),
            (signal, message),
            "vector {vector}"
        );
    }
    // Not a plain user signal here: NMI, #NM, #DF, #PF (own path), #MC, ...
    for vector in [2u8, 7, 8, 9, 14, 15, 18, 20, 21, 32, 255] {
        assert!(user_exception(vector).is_none(), "vector {vector}");
    }
    assert_eq!([SIGILL, SIGTRAP, SIGBUS, SIGFPE, SIGSEGV], [4, 5, 7, 8, 11]);
}

#[test]
fn trap_line_formats_like_show_signal() {
    let mm = loaded_oracle();
    let line = TrapLine {
        kind: "",
        desc: "general protection fault",
        ip: 0x20_55b4,
        sp: 0x7ffd_2010_a150,
        error: 0,
        region: FileRegion::of(&mm, 0x20_55b4),
    };
    assert_eq!(
        line.to_string(),
        "traps: init[1] general protection fault ip:2055b4 sp:7ffd2010a150 error:0 in init[45b4,204000+7000]"
    );
    let divide = TrapLine {
        kind: "trap ",
        desc: "divide error",
        ip: 1,
        sp: 2,
        error: 0,
        region: FileRegion::of(&mm, 1),
    };
    assert_eq!(
        divide.to_string(),
        "traps: init[1] trap divide error ip:1 sp:2 error:0"
    );
}

#[test]
fn bad_frame_line_matches_the_pinned_kernel() {
    let plan = LoadPlan::new(&oracle()).unwrap();
    // `signal_fault` on the pinned 6.18.57 (target/sigfix-linux/linux-smoke-tcg.log: the
    // `signals` smoke's rt_sigreturn with `rsp` at 0x1000), minus the `[ time]` prefix.
    let line = BadFrame {
        ip: 0x20_55b4,
        sp: 0x1000,
        orig_ax: 0xf,
        vmas: &plan.vmas,
    };
    assert_eq!(
        line.to_string(),
        "init[1] bad frame in rt_sigreturn frame:(____ptrval____) ip:2055b4 sp:1000 orax:f in init[45b4,204000+7000]"
    );
}
