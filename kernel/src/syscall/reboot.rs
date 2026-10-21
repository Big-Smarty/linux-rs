// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: kernel/reboot.c
// (`SYSCALL_DEFINE4(reboot)`), include/uapi/linux/reboot.h,
// arch/x86/entry/syscalls/syscall_64.tbl. GPL-2.0-only.
// Transformation: the checks before the machine is touched; the machine
// transitions themselves are not ported.
#![forbid(unsafe_code)]
//! `reboot`.
//!
//! Context: task context, never sleeps. The capability check, the magic numbers and the command
//! decoding are Linux's, in its order. `LINUX_REBOOT_CMD_CAD_ON/OFF` are accepted and
//! remembered nowhere: Ctrl-Alt-Del is not a key this kernel's keyboard driver acts on, so the
//! `C_A_D` flag has no reader. The commands that end or restart the machine (`RESTART`,
//! `RESTART2`, `HALT`, `POWER_OFF`) stop loudly
//! ([`Outcome::Unimplemented`]): there is no shutdown path (`kernel_restart`, ACPI power-off, the
//! `reboot=` methods) to run, and a call that returns success without stopping the machine is
//! what `init` would believe. `RESTART2` still copies its command string first, so a bad pointer
//! is `EFAULT` as in Linux. `SW_SUSPEND` is `EINVAL` (its `case` is under `CONFIG_HIBERNATION`,
//! `# CONFIG_HIBERNATION is not set` in the reference configuration, so it falls to `default`)
//! and `KEXEC` is `EINVAL` (`kernel_kexec`: `!kexec_image`; no `kexec_load`/`kexec_file_load`
//! exists here, so no image can be loaded).

use syscalls::{Errno, Sysno};

use super::{Context, Outcome, Stop, Sys, outcome};
use crate::usercopy::strncpy_from_user;

const MAGIC1: i32 = 0xfee1_deadu32.cast_signed();
const MAGIC2: [i32; 4] = [672_274_793, 85_072_278, 369_367_448, 537_993_216];

const CMD_RESTART: u32 = 0x0123_4567;
const CMD_HALT: u32 = 0xcdef_0123;
const CMD_CAD_ON: u32 = 0x89ab_cdef;
const CMD_CAD_OFF: u32 = 0x0000_0000;
const CMD_POWER_OFF: u32 = 0x4321_fedc;
const CMD_RESTART2: u32 = 0xa1b2_c3d4;

pub(super) fn dispatch<C: Context>(ctx: &mut C, sysno: Sysno, a: [u64; 6]) -> Option<Outcome> {
    let result = match sysno {
        #[allow(clippy::cast_possible_truncation)]
        Sysno::reboot => reboot(ctx, a[0] as i32, a[1] as i32, a[2] as u32, a[3]),
        _ => return None,
    };
    Some(outcome(sysno as u32, result))
}

fn reboot<C: Context>(ctx: &mut C, magic1: i32, magic2: i32, cmd: u32, arg: u64) -> Sys {
    // ns_capable(pid_ns->user_ns, CAP_SYS_BOOT)
    if !ctx.cred().sys_boot {
        return Err(Errno::EPERM.into());
    }
    if magic1 != MAGIC1 || !MAGIC2.contains(&magic2) {
        return Err(Errno::EINVAL.into());
    }
    // reboot_pid_ns: nothing for the initial PID namespace.
    match cmd {
        CMD_CAD_ON | CMD_CAD_OFF => Ok(0),
        CMD_RESTART2 => {
            let mut buffer = [0u8; 256];
            if strncpy_from_user(ctx, &mut buffer[..255], arg).is_none() {
                return Err(Errno::EFAULT.into());
            }
            Err(Stop::Unimplemented)
        }
        CMD_RESTART | CMD_HALT | CMD_POWER_OFF => Err(Stop::Unimplemented),
        // CMD_KEXEC (kernel_kexec() without an image), CMD_SW_SUSPEND (no CONFIG_HIBERNATION
        // case) and every unknown command: `default: ret = -EINVAL`.
        _ => Err(Errno::EINVAL.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syscall::{
        dispatch, error,
        testing::{Task, task},
    };

    const CMD_SW_SUSPEND: u32 = 0xd000_fce2;
    const CMD_KEXEC: u32 = 0x4558_4543;

    fn call(t: &mut Task, args: [u64; 4]) -> Outcome {
        dispatch(
            t,
            Sysno::reboot as u64,
            [args[0], args[1], args[2], args[3], 0, 0],
        )
    }

    const M1: u64 = 0xfee1_dead;
    const M2: u64 = 672_274_793;

    #[test]
    fn capability_then_magic_then_command() {
        let mut t = task();
        t.pages.map(0x1000, true);
        let neg = |errno: Errno| Outcome::Return(error(errno));
        // Magic numbers: the first, and any of the four second ones.
        assert_eq!(call(&mut t, [0, M2, 0, 0]), neg(Errno::EINVAL));
        assert_eq!(call(&mut t, [M1, 1, 0, 0]), neg(Errno::EINVAL));
        for second in [672_274_793u64, 85_072_278, 369_367_448, 537_993_216] {
            assert_eq!(
                call(&mut t, [M1, second, u64::from(CMD_CAD_ON), 0]),
                Outcome::Return(0)
            );
        }
        // The magic numbers are `int`s: the upper halves are ignored.
        assert_eq!(
            call(
                &mut t,
                [M1 | 1 << 40, M2 | 1 << 33, u64::from(CMD_CAD_OFF), 0]
            ),
            Outcome::Return(0)
        );
        // An unknown command, KEXEC and SW_SUSPEND are EINVAL; the machine commands stop loudly.
        assert_eq!(call(&mut t, [M1, M2, 5, 0]), neg(Errno::EINVAL));
        for cmd in [CMD_KEXEC, CMD_SW_SUSPEND] {
            assert_eq!(
                call(&mut t, [M1, M2, u64::from(cmd), 0]),
                neg(Errno::EINVAL)
            );
        }
        for cmd in [CMD_RESTART, CMD_HALT, CMD_POWER_OFF] {
            assert_eq!(
                call(&mut t, [M1, M2, u64::from(cmd), 0]),
                Outcome::Unimplemented(169)
            );
        }
        // RESTART2 reads its string first.
        assert_eq!(
            call(&mut t, [M1, M2, u64::from(CMD_RESTART2), 0x9000_0000]),
            neg(Errno::EFAULT)
        );
        assert_eq!(
            call(&mut t, [M1, M2, u64::from(CMD_RESTART2), 0x1000]),
            Outcome::Unimplemented(169)
        );
        // Without CAP_SYS_BOOT: EPERM before anything else is looked at.
        t.attrs.cred.euid = 1000;
        assert_eq!(call(&mut t, [0, 0, 0, 0]), neg(Errno::EPERM));
        assert_eq!(
            call(&mut t, [M1, M2, u64::from(CMD_HALT), 0]),
            neg(Errno::EPERM)
        );
    }
}
