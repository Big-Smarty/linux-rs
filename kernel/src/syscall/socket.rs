// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: net/socket.c (GPL-2.0:
// `__sys_getsockname`, `__sys_getpeername`, `sock_from_file`),
// arch/x86/entry/syscalls/syscall_64.tbl.
#![forbid(unsafe_code)]
//! The socket calls that only name a descriptor and ask it what it is.
//!
//! This kernel has no sockets (`socket(2)` is a loud stop), so no open description is one:
//! `sock_from_file` is `NULL` and the answer is `ENOTSOCK`, after `EBADF` for a closed (or
//! `O_PATH`) descriptor. Programs probe their standard input this way (`bash` calls
//! `getpeername(0)` at start-up to see whether it was started by `rshd`).
//!
//! * shortcut: a description of a kind the VFS cannot classify ([`FileKind::Unsupported`]) may
//!   be a socket in Linux: the call stops loudly instead of answering `ENOTSOCK`.

use syscalls::{Errno, Sysno};

// The descriptor is an `int`: its low 32 bits are what the kernel looks up.
#[allow(clippy::cast_possible_truncation)]
const fn int(raw: u64) -> u64 {
    raw as u32 as u64
}

use super::{Context, Outcome, Stop, Sys, fd::fdget, outcome};
use crate::vfs::file::FileKind;

pub(super) fn dispatch<C: Context>(ctx: &mut C, sysno: Sysno, a: [u64; 6]) -> Option<Outcome> {
    let result = match sysno {
        // `int fd`, a `struct sockaddr *` and an `int *`: only the descriptor is looked at.
        Sysno::getsockname | Sysno::getpeername => not_a_socket(ctx, a[0]),
        _ => return None,
    };
    Some(outcome(sysno as u32, result))
}

/// `CLASS(fd, f)(fd)` then `sock_from_file`.
fn not_a_socket<C: Context>(ctx: &mut C, fd: u64) -> Sys {
    let view = fdget(ctx, int(fd), false)?;
    if matches!(view.kind, FileKind::Unsupported) {
        return Err(Stop::Unimplemented);
    }
    Err(Errno::ENOTSOCK.into())
}
