// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: kernel/exit.c (`sys_exit`,
// `sys_exit_group`), kernel/sys.c (`sys_getpid`). GPL-2.0-only.
//! Process identity and exit syscalls: `getpid`, `exit`, `exit_group`.

use super::{Context, Outcome};
use syscalls::Sysno;

pub(super) fn dispatch<C: Context>(ctx: &mut C, sysno: Sysno, args: [u64; 6]) -> Option<Outcome> {
    match sysno {
        Sysno::getpid => Some(Outcome::Return(i64::from(ctx.tgid()))),
        Sysno::exit | Sysno::exit_group => Some(Outcome::Exit(exit_code(args[0]))),
        _ => None,
    }
}

/// `do_exit((error_code & 0xff) << 8)` / `do_group_exit` of the same value.
#[must_use]
pub fn exit_code(status: u64) -> u32 {
    #[allow(clippy::cast_possible_truncation)]
    let status = status as u8;
    u32::from(status) << 8
}

#[cfg(test)]
mod tests {
    use crate::syscall::{Outcome, dispatch, testing::task};
    use syscalls::Sysno;

    #[test]
    fn getpid_exit_and_exit_group_encode_like_linux() {
        let mut task = task();
        assert_eq!(
            dispatch(&mut task, Sysno::getpid as u64, [9; 6]),
            Outcome::Return(1)
        );
        for number in [Sysno::exit as u64, Sysno::exit_group as u64] {
            let mut exit = |status| dispatch(&mut task, number, [status, 0, 0, 0, 0, 0]);
            assert_eq!(exit(0), Outcome::Exit(0));
            assert_eq!(exit(1), Outcome::Exit(0x100));
            assert_eq!(exit(0xff), Outcome::Exit(0xff00));
            assert_eq!(exit(0x1ff), Outcome::Exit(0xff00));
            assert_eq!(exit(0x1234_5601), Outcome::Exit(0x100));
            assert_eq!(exit(u64::MAX), Outcome::Exit(0xff00));
        }
    }

    #[test]
    fn getpid_reports_the_context_identity() {
        let mut task = task();
        task.tgid = 4242;
        assert_eq!(
            dispatch(&mut task, Sysno::getpid as u64, [0; 6]),
            Outcome::Return(4242)
        );
    }
}
