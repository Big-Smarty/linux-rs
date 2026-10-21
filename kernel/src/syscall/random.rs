// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: drivers/char/random.c
// (`SYSCALL_DEFINE3(getrandom)`, `get_random_bytes_user`), include/uapi/linux/
// random.h (`GRND_*`), lib/iov_iter.c (`import_ubuf`), arch/x86/entry/syscalls/
// syscall_64.tbl. GPL-2.0-only.
// Transformation: the entropy source is the CPU's hardware generator
// (`Context::hw_random`: `RDSEED`/`RDRAND`), handed to user space in 64-byte
// blocks without the ChaCha20 stage `get_random_bytes_user` puts between them.
#![forbid(unsafe_code)]
// x86_64 only: `usize` is 64 bits; the casts below are the C types of the ABI.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
//! `getrandom`.
//!
//! Context: task context, never sleeps. `crng_ready()` is true whenever the CPU
//! has a hardware generator (a Linux that boots on such a CPU credits `RDSEED`
//! output to the pool at `random_init` and has a ready CRNG from the start);
//! `GRND_NONBLOCK` therefore never answers `EAGAIN` and nothing blocks.
//!
//! shortcut: there is no CRNG, no entropy pool and no `/dev/random`; the bytes
//! are the hardware generator's own. A CPU without one (no `RDRAND`) cannot be
//! answered correctly: a call that would need entropy stops loudly
//! ([`Outcome::Unimplemented`]) instead of returning predictable bytes. Upgrade
//! with a `ChaCha20` CRNG seeded from the generator and a timer/interrupt pool.

use syscalls::{Errno, Sysno};

use super::{Context, MAX_RW_COUNT, Outcome, Stop, Sys, outcome};
use crate::usercopy::{access_ok, copy_to_user};

const GRND_NONBLOCK: u32 = 1;
const GRND_RANDOM: u32 = 2;
const GRND_INSECURE: u32 = 4;
/// `CHACHA_BLOCK_SIZE` and `CHACHA_KEY_SIZE`.
const BLOCK: usize = 64;
const KEY: usize = 32;
const PAGE: u64 = 4096;

pub(super) fn dispatch<C: Context>(ctx: &mut C, sysno: Sysno, a: [u64; 6]) -> Option<Outcome> {
    let result = match sysno {
        #[allow(clippy::cast_possible_truncation)]
        Sysno::getrandom => getrandom(ctx, a[0], a[1], a[2] as u32),
        _ => return None,
    };
    Some(outcome(sysno as u32, result))
}

/// 64 bytes from the hardware generator.
fn block<C: Context>(ctx: &mut C) -> Option<[u8; BLOCK]> {
    let mut out = [0u8; BLOCK];
    for word in out.as_chunks_mut::<8>().0 {
        word.copy_from_slice(&ctx.hw_random()?.to_le_bytes());
    }
    Some(out)
}

fn getrandom<C: Context>(ctx: &mut C, ubuf: u64, len: u64, flags: u32) -> Sys {
    if flags & !(GRND_NONBLOCK | GRND_RANDOM | GRND_INSECURE) != 0 {
        return Err(Errno::EINVAL.into());
    }
    // Insecure and blocking randomness at the same time make no sense.
    if flags & (GRND_INSECURE | GRND_RANDOM) == (GRND_INSECURE | GRND_RANDOM) {
        return Err(Errno::EINVAL.into());
    }
    // import_ubuf(ITER_DEST) (lib/iov_iter.c:1433-1437): the clamp to MAX_RW_COUNT, then access_ok.
    let len = len.min(u64::from(MAX_RW_COUNT));
    if !access_ok(ubuf, len) {
        return Err(Errno::EFAULT.into());
    }
    if len == 0 {
        return Ok(0);
    }
    // crng_make_state: the first block also seeds the stream; a request of at
    // most a key's worth is answered from it directly.
    let first = block(ctx).ok_or(Stop::Unimplemented)?;
    if len as usize <= KEY {
        let n = len as usize;
        let missing = copy_to_user(ctx, ubuf, &first[..n]);
        return if missing == n {
            Err(Errno::EFAULT.into())
        } else {
            Ok((n - missing) as i64)
        };
    }
    let mut done = 0u64;
    let mut next = Some(first);
    loop {
        let bytes = match next.take() {
            Some(bytes) => bytes,
            None => block(ctx).ok_or(Stop::Unimplemented)?,
        };
        let n = (len - done).min(BLOCK as u64) as usize;
        let missing = copy_to_user(ctx, ubuf + done, &bytes[..n]);
        done += (n - missing) as u64;
        if done == len || missing != 0 {
            break;
        }
        if done.is_multiple_of(PAGE) && ctx.state().signal_pending() {
            break;
        }
    }
    if done == 0 {
        Err(Errno::EFAULT.into())
    } else {
        Ok(done as i64)
    }
}
