// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: kernel/futex/syscalls.c
// (`SYSCALL_DEFINE6(futex)` 168-227, `do_futex` 126-166, `futex_init_timeout`,
// `futex_parse_waitv`, `futex2_setup_timeout`, `futex_waitv`, `futex_wake`, `futex_wait`,
// `futex_requeue` syscalls, `set_robust_list`, `get_robust_list`), kernel/futex/core.c
// (`get_futex_key`, `exit_robust_list`, `handle_futex_death`, `futex_cleanup`),
// kernel/futex/waitwake.c (`futex_wake`, `futex_wake_op`, `__futex_wait`, `futex_wait`,
// `futex_wait_restart`, `futex_wait_multiple`), kernel/futex/requeue.c (`futex_requeue`),
// kernel/futex/pi.c (`futex_lock_pi`, `futex_unlock_pi`, `futex_lock_pi_atomic`,
// `lock_pi_update_atomic` for the uncontended cases), kernel/fork.c (`mm_release`'s
// `clear_child_tid` wake). GPL-2.0-or-later / GPL-2.0-only.
// Transformation: see `crate::futex`. The user word is read, compared and written through
// `usercopy` (the one user-copy layer); under the `PROCESS` lock no task runs in between, so the
// pairs "read then write" are the atomic operations `futex_cmpxchg_value_locked` and
// `arch_futex_atomic_op_inuser` perform. `get_futex_key` pins nothing: the key of a non-private
// futex is decided from the VMA (a writable mapping is faulted in for write, which copies a
// private file page, and keys by address space; a read-only file mapping keys by the file;
// anything else cannot be keyed and is `EFAULT`, as `get_user_pages_fast` + the anonymous /
// zero-page checks make it). The priority-inheritance operations check their arguments in
// Linux's order, take and release an unowned lock, and stop the kernel loudly where a
// `pi_state` or an `rt_mutex` would be needed.
#![forbid(unsafe_code)]
//! `futex(2)`, `futex_waitv(2)`, `futex_wake(2)`, `futex_wait(2)`, `futex_requeue(2)`,
//! `get_robust_list(2)` and the exit-time cleanup of robust lists and `clear_child_tid`.

use super::{AddressSpace, Context, Outcome, Stop, Sys, outcome};
use crate::{
    futex::{
        BITSET_MATCH_ANY, FUTEX_CLOCK_REALTIME, FUTEX_CMD_MASK, FUTEX_CMP_REQUEUE,
        FUTEX_CMP_REQUEUE_PI, FUTEX_LOCK_PI, FUTEX_LOCK_PI2, FUTEX_OWNER_DIED, FUTEX_PRIVATE_FLAG,
        FUTEX_REQUEUE, FUTEX_TID_MASK, FUTEX_TRYLOCK_PI, FUTEX_UNLOCK_PI, FUTEX_WAIT,
        FUTEX_WAIT_BITSET, FUTEX_WAIT_REQUEUE_PI, FUTEX_WAITERS, FUTEX_WAKE, FUTEX_WAKE_BITSET,
        FUTEX_WAKE_OP, Flags, Key, ROBUST_LIST_HEAD_SIZE, ROBUST_LIST_LIMIT, Ticket, WAITV_MAX,
        WakeOp,
    },
    memory::PAGE,
    mm::VmFlags,
    sched::{CLASS_FUTEX, WaitKey},
    signal::{
        deliver::{ERESTART_RESTARTBLOCK, ERESTARTSYS},
        wait::signal_pending_synced,
    },
    usercopy::{TASK_SIZE_MAX, copy_from_user, put_user},
};
use syscalls::{Errno, Sysno};

use super::time::{FutexRestart, RestartBlock, RestartFn};

/// `enum futex_access`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Access {
    Read,
    Write,
}

/// `FUTEX2_*` flag bits.
const FUTEX2_SIZE_U32: u32 = 0x02;
const FUTEX2_SIZE_MASK: u32 = 0x03;
const FUTEX2_NUMA: u32 = 0x04;
const FUTEX2_MPOL: u32 = 0x08;
const FUTEX2_PRIVATE: u32 = FUTEX_PRIVATE_FLAG;
const FUTEX2_VALID_MASK: u32 = FUTEX2_SIZE_MASK | FUTEX2_NUMA | FUTEX2_MPOL | FUTEX2_PRIVATE;
const KTIME_MAX: i64 = i64::MAX;

/// `-errno` as the syscall's value.
fn err(errno: Errno) -> i64 {
    -i64::from(errno.into_raw())
}

/// An absolute time on one of the two clocks the futex timeouts use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Abs {
    pub ns: i64,
    pub realtime: bool,
}

impl Abs {
    /// The `CLOCK_MONOTONIC` instant a wait with this deadline ends at.
    fn monotonic<C: Context>(self, ctx: &C) -> u64 {
        let ns = if self.realtime {
            i128::from(self.ns) - i128::from(ctx.clock_state().real_offset_ns)
        } else {
            i128::from(self.ns)
        };
        u64::try_from(ns.max(0)).unwrap_or(u64::MAX)
    }
}

fn read_u32<C: Context>(ctx: &mut C, uaddr: u64) -> Option<u32> {
    let mut bytes = [0u8; 4];
    (copy_from_user(ctx, &mut bytes, uaddr) == 0).then(|| u32::from_le_bytes(bytes))
}

fn write_u32<C: Context>(ctx: &mut C, uaddr: u64, value: u32) -> bool {
    put_user(ctx, uaddr, &value.to_le_bytes())
}

/// `get_futex_key(uaddr, flags, &key, rw)`.
///
/// # Errors
/// `EINVAL` (not 4-byte aligned), `EFAULT`.
fn get_futex_key<C: Context>(
    ctx: &mut C,
    uaddr: u64,
    flags: Flags,
    rw: Access,
) -> Result<Key, Errno> {
    let size = 4u64;
    if uaddr % size != 0 {
        return Err(Errno::EINVAL);
    }
    // access_ok(uaddr, size): the pinned Linux accepts an address up to and including
    // TASK_SIZE_MAX (observed: init-reference-024, `FUTEX_WAKE_PRIVATE` there returns 0).
    if uaddr > TASK_SIZE_MAX {
        return Err(Errno::EFAULT);
    }
    let page = uaddr & !(PAGE - 1);
    #[allow(clippy::cast_possible_truncation)]
    let offset = (uaddr - page) as u32;
    let identity = ctx.futex().mm;
    if !flags.shared() {
        return Ok(Key::Private {
            mm: identity,
            page,
            offset,
        });
    }
    let vma = {
        let AddressSpace { mm, .. } = ctx.address_space();
        mm.find_vma(page).copied().filter(|vma| vma.start <= page)
    };
    let Some(vma) = vma else {
        return Err(Errno::EFAULT);
    };
    if vma.flags.contains(VmFlags::WRITE) {
        // get_user_pages_fast(FOLL_WRITE): the page is present and private to the address
        // space (a private file page was copied), so the key is the address space's.
        if crate::usercopy::UserPages::page(ctx, page, true).is_none() {
            return Err(Errno::EFAULT);
        }
        return Ok(Key::MmShared {
            mm: identity,
            page,
            offset,
        });
    }
    // The retry for FUTEX_READ with plain read access: a file page is the file's; an anonymous
    // or zero page "never changes and thus doesn't make sense for futex operations".
    if rw == Access::Write || !vma.flags.contains(VmFlags::READ) {
        return Err(Errno::EFAULT);
    }
    let Some(file) = vma.file else {
        return Err(Errno::EFAULT);
    };
    if crate::usercopy::UserPages::page(ctx, page, false).is_none() {
        return Err(Errno::EFAULT);
    }
    Ok(Key::File {
        file,
        index: vma.pgoff + ((page - vma.start) >> 12),
        offset,
    })
}

// ---- wake and wake_op -----------------------------------------------------------------------

fn wake_owners<C: Context>(
    ctx: &mut C,
    f: impl FnOnce(&mut crate::futex::Futexes, &mut dyn FnMut(u32)) -> i32,
) -> i32 {
    let parts = ctx.futex();
    let waker = parts.waker;
    f(parts.queue, &mut |owner| waker.wake(owner))
}

/// `futex_wake(uaddr, flags, nr_wake, bitset)`.
fn futex_wake<C: Context>(ctx: &mut C, uaddr: u64, flags: Flags, nr_wake: i32, bitset: u32) -> i64 {
    if bitset == 0 {
        return err(Errno::EINVAL);
    }
    let key = match get_futex_key(ctx, uaddr, flags, Access::Read) {
        Ok(key) => key,
        Err(errno) => return err(errno),
    };
    if flags.0 & Flags::STRICT != 0 && nr_wake == 0 {
        return 0;
    }
    i64::from(wake_owners(ctx, |queue, wake| {
        queue.wake(&key, nr_wake, bitset, wake)
    }))
}

/// `futex_wake_op(uaddr1, flags, uaddr2, nr_wake, nr_wake2, op)`.
fn futex_wake_op<C: Context>(
    ctx: &mut C,
    uaddr1: u64,
    flags: Flags,
    uaddr2: u64,
    nr_wake: i32,
    nr_wake2: i32,
    op: u32,
) -> i64 {
    let key1 = match get_futex_key(ctx, uaddr1, flags, Access::Read) {
        Ok(key) => key,
        Err(errno) => return err(errno),
    };
    let key2 = match get_futex_key(ctx, uaddr2, flags, Access::Write) {
        Ok(key) => key,
        Err(errno) => return err(errno),
    };
    // futex_atomic_op_inuser: the operation on the word, then the comparison on the old value.
    let decoded = WakeOp::decode(op);
    let Some(old) = read_u32(ctx, uaddr2) else {
        return err(Errno::EFAULT);
    };
    let new = match decoded.apply(old) {
        Ok(new) => new,
        Err(errno) => return err(errno),
    };
    if !write_u32(ctx, uaddr2, new) {
        return err(Errno::EFAULT);
    }
    let second = match decoded.compare(old) {
        Ok(second) => second,
        Err(errno) => return err(errno),
    };
    i64::from(wake_owners(ctx, |queue, wake| {
        queue.wake_op(&key1, nr_wake, &key2, nr_wake2, second, wake)
    }))
}

// ---- requeue --------------------------------------------------------------------------------

/// `futex_requeue(uaddr1, flags1, uaddr2, flags2, nr_wake, nr_requeue, cmpval, requeue_pi)`.
#[allow(clippy::too_many_arguments)]
fn futex_requeue<C: Context>(
    ctx: &mut C,
    uaddr1: u64,
    flags1: Flags,
    uaddr2: u64,
    flags2: Flags,
    nr_wake: i32,
    nr_requeue: i32,
    cmpval: Option<u32>,
    requeue_pi: bool,
) -> Sys {
    if nr_wake < 0 || nr_requeue < 0 {
        return Err(Errno::EINVAL.into());
    }
    if requeue_pi {
        // "Requeue PI only works on two distinct uaddrs", and a single waiter may be woken.
        if uaddr1 == uaddr2 || nr_wake != 1 {
            return Err(Errno::EINVAL.into());
        }
    }
    let key1 = get_futex_key(ctx, uaddr1, flags1, Access::Read)?;
    let key2 = get_futex_key(
        ctx,
        uaddr2,
        flags2,
        if requeue_pi {
            Access::Write
        } else {
            Access::Read
        },
    )?;
    if requeue_pi && key1 == key2 {
        return Err(Errno::EINVAL.into());
    }
    if let Some(expected) = cmpval {
        let Some(current) = read_u32(ctx, uaddr1) else {
            return Err(Errno::EFAULT.into());
        };
        if current != expected {
            return Err(Errno::EAGAIN.into());
        }
    }
    if requeue_pi {
        // Nothing to do without a waiter on the source; with one, the lock transfer to a
        // `pi_state` is the part this kernel does not have.
        if ctx.futex().queue.waiting_on(&key1) > 0 {
            return Err(Stop::Unimplemented);
        }
        return Ok(0);
    }
    Ok(i64::from(wake_owners(ctx, |queue, wake| {
        queue.requeue(&key1, &key2, nr_wake, nr_requeue, wake)
    })))
}

// ---- wait -----------------------------------------------------------------------------------

fn futex_key<C: Context>(ctx: &mut C) -> WaitKey {
    WaitKey::new(CLASS_FUTEX, ctx.futex().owner)
}

/// How a sleep on the futex queue ended.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Slept {
    Woken,
    TimedOut,
    Signal,
}

/// `futex_do_wait`: sleep until the waiter is taken out of the queue, the deadline passes or a
/// signal is pending.
fn sleep_on_queue<C: Context>(ctx: &mut C, deadline: Option<Abs>) -> Slept {
    let key = futex_key(ctx);
    loop {
        let signalled = signal_pending_synced(ctx);
        let owner = ctx.futex().owner;
        if ctx.futex().queue.is_woken(owner) {
            return Slept::Woken;
        }
        if signalled {
            return Slept::Signal;
        }
        let until = deadline.map(|d| d.monotonic(ctx));
        if until.is_some_and(|at| ctx.now_ns() >= at) {
            return Slept::TimedOut;
        }
        ctx.wait(key, until);
    }
}

/// `__futex_wait(uaddr, flags, val, to, bitset)`: `0`, `-EAGAIN`, `-ETIMEDOUT`, `-ERESTARTSYS`
/// or the key's / the word's error.
fn futex_wait_once<C: Context>(
    ctx: &mut C,
    uaddr: u64,
    flags: Flags,
    val: u32,
    deadline: Option<Abs>,
    bitset: u32,
) -> i64 {
    if bitset == 0 {
        return err(Errno::EINVAL);
    }
    loop {
        // futex_wait_setup: the key, the word, and only then the queue.
        let key = match get_futex_key(ctx, uaddr, flags, Access::Read) {
            Ok(key) => key,
            Err(errno) => return err(errno),
        };
        let Some(current) = read_u32(ctx, uaddr) else {
            return err(Errno::EFAULT);
        };
        if current != val {
            return err(Errno::EAGAIN);
        }
        let parts = ctx.futex();
        let owner = parts.owner;
        let ticket: Ticket = parts.queue.queue(key, bitset, owner, 0);
        let slept = sleep_on_queue(ctx, deadline);
        // "If we were woken (and unqueued), we succeeded, whatever."
        let still_queued = ctx.futex().queue.unqueue(ticket);
        if !still_queued || slept == Slept::Woken {
            let _ = ctx.futex().queue.take_woken(owner);
            return 0;
        }
        if slept == Slept::TimedOut {
            return err(Errno::ETIMEDOUT);
        }
        // "We expect signal_pending(current), but we might be the victim of a spurious wakeup
        // as well."
        if !signal_pending_synced(ctx) {
            continue;
        }
        return -ERESTARTSYS;
    }
}

/// `futex_wait(uaddr, flags, val, abs_time, bitset)`: with a timeout, a signal ends the wait
/// as `-ERESTART_RESTARTBLOCK` and `restart_syscall` runs it again.
fn futex_wait<C: Context>(
    ctx: &mut C,
    uaddr: u64,
    flags: Flags,
    val: u32,
    deadline: Option<Abs>,
    bitset: u32,
) -> i64 {
    let ret = futex_wait_once(ctx, uaddr, flags, val, deadline, bitset);
    let Some(abs) = deadline else {
        return ret;
    };
    if ret != -ERESTARTSYS {
        return ret;
    }
    ctx.set_restart_block(RestartBlock {
        func: RestartFn::Futex,
        clockid: 0,
        expires_ns: abs.ns,
        rmtp: 0,
        futex: FutexRestart {
            uaddr,
            val,
            flags: flags.with(Flags::HAS_TIMEOUT).0 | if abs.realtime { Flags::CLOCKRT } else { 0 },
            bitset,
        },
    });
    -ERESTART_RESTARTBLOCK
}

/// `futex_wait_restart`: the call again from the restart block, which becomes
/// `do_no_restart_syscall` first.
pub(super) fn restart<C: Context>(ctx: &mut C, block: RestartBlock) -> i64 {
    let flags = Flags(block.futex.flags);
    let deadline = (flags.0 & Flags::HAS_TIMEOUT != 0).then_some(Abs {
        ns: block.expires_ns,
        realtime: flags.clock_realtime(),
    });
    ctx.set_restart_block(RestartBlock::NONE);
    futex_wait(
        ctx,
        block.futex.uaddr,
        flags,
        block.futex.val,
        deadline,
        block.futex.bitset,
    )
}

// ---- priority inheritance: the uncontended cases --------------------------------------------

/// `futex_lock_pi(uaddr, flags, time, trylock)` when no `pi_state` is needed: the word is free
/// (taken), or already ours (`EDEADLK`), or its owner does not exist (`ESRCH`, after the waiters
/// bit is set). A lock another live task holds needs an `rt_mutex`: a loud stop.
fn futex_lock_pi<C: Context>(ctx: &mut C, uaddr: u64, flags: Flags) -> Sys {
    get_futex_key(ctx, uaddr, flags, Access::Write)?;
    let vpid = ctx.futex().tid;
    loop {
        // futex_lock_pi_atomic
        let Some(uval) = read_u32(ctx, uaddr) else {
            return Err(Errno::EFAULT.into());
        };
        if uval & FUTEX_TID_MASK == vpid {
            return Err(Errno::EDEADLK.into());
        }
        if uval & FUTEX_TID_MASK == 0 {
            // We take over the futex, preserving the owner-died bit.
            let new = (uval & FUTEX_OWNER_DIED) | vpid;
            if !write_u32(ctx, uaddr, new) {
                return Err(Errno::EFAULT.into());
            }
            return Ok(0);
        }
        // First waiter: the waiters bit is set before attaching to the owner.
        let waiting = uval | FUTEX_WAITERS;
        if waiting != uval && !write_u32(ctx, uaddr, waiting) {
            return Err(Errno::EFAULT.into());
        }
        let owner = i32::try_from(uval & FUTEX_TID_MASK).unwrap_or(0);
        let exists = ctx.tasks().list.find_task_by_vpid(owner).is_some();
        if !exists {
            return Err(Errno::ESRCH.into());
        }
        return Err(Stop::Unimplemented);
    }
}

/// `futex_unlock_pi(uaddr, flags)` when no task waits in the kernel (there is no way to wait
/// there yet): the word is cleared if it is still what we read.
fn futex_unlock_pi<C: Context>(ctx: &mut C, uaddr: u64, flags: Flags) -> Sys {
    let vpid = ctx.futex().tid;
    let Some(uval) = read_u32(ctx, uaddr) else {
        return Err(Errno::EFAULT.into());
    };
    // "We release only a lock we actually own."
    if uval & FUTEX_TID_MASK != vpid {
        return Err(Errno::EPERM.into());
    }
    get_futex_key(ctx, uaddr, flags, Access::Write)?;
    Ok(if write_u32(ctx, uaddr, 0) {
        0
    } else {
        return Err(Errno::EFAULT.into());
    })
}

// ---- futex2 and waitv -----------------------------------------------------------------------

/// `futex2_to_flags` + `futex_flags_valid` + the NUMA / mempolicy bits this kernel lacks.
fn futex2_flags(flags2: u32) -> Result<Flags, Stop> {
    if flags2 & !FUTEX2_VALID_MASK != 0 {
        return Err(Errno::EINVAL.into());
    }
    let mut flags = flags2 & FUTEX2_SIZE_MASK;
    if flags2 & FUTEX2_PRIVATE == 0 {
        flags |= Flags::SHARED;
    }
    // Only 32-bit futexes are implemented.
    if flags & Flags::SIZE_MASK != FUTEX2_SIZE_U32 {
        return Err(Errno::EINVAL.into());
    }
    // `FUTEX2_NUMA` (the node word beside the futex) and `FUTEX2_MPOL` (the memory policy
    // of the VMA) change what `get_futex_key` reads and writes; there are no nodes or
    // policies here.
    if flags2 & (FUTEX2_NUMA | FUTEX2_MPOL) != 0 {
        return Err(Stop::Unimplemented);
    }
    Ok(Flags(flags))
}

/// `futex_validate_input(flags, val)` for 32-bit futexes.
fn validate_input(val: u64) -> bool {
    val >> 32 == 0
}

/// `futex2_setup_timeout` up to the absolute deadline.
fn futex2_deadline<C: Context>(
    ctx: &mut C,
    timeout: u64,
    clockid: i32,
) -> Result<Option<Abs>, Errno> {
    if timeout == 0 {
        return Ok(None);
    }
    let realtime = clockid == 0;
    if clockid != 0 && clockid != 1 {
        return Err(Errno::EINVAL);
    }
    let ts = read_timespec(ctx, timeout)?;
    let ns = init_timeout(ts)?;
    Ok(Some(Abs { ns, realtime }))
}

/// `get_timespec64`.
fn read_timespec<C: Context>(ctx: &mut C, at: u64) -> Result<(i64, i64), Errno> {
    let mut bytes = [0u8; 16];
    if copy_from_user(ctx, &mut bytes, at) != 0 {
        return Err(Errno::EFAULT);
    }
    let mut word = [0u8; 8];
    word.copy_from_slice(&bytes[..8]);
    let sec = i64::from_le_bytes(word);
    word.copy_from_slice(&bytes[8..]);
    Ok((sec, i64::from_le_bytes(word)))
}

/// `timespec64_valid` + `timespec64_to_ktime` (saturating at `KTIME_MAX`).
fn init_timeout((sec, nsec): (i64, i64)) -> Result<i64, Errno> {
    if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
        return Err(Errno::EINVAL);
    }
    Ok(sec
        .checked_mul(1_000_000_000)
        .and_then(|ns| ns.checked_add(nsec))
        .unwrap_or(KTIME_MAX))
}

/// One element of `struct futex_waitv`.
#[derive(Clone, Copy)]
struct WaitvEntry {
    val: u32,
    uaddr: u64,
    flags: Flags,
}

/// `futex_parse_waitv` for entry `index` of the array at `base`.
fn parse_waitv_entry<C: Context>(ctx: &mut C, base: u64, index: u64) -> Result<WaitvEntry, Stop> {
    let mut bytes = [0u8; 24];
    if copy_from_user(ctx, &mut bytes, base.wrapping_add(index * 24)) != 0 {
        return Err(Errno::EFAULT.into());
    }
    let word = |at: usize| {
        let mut w = [0u8; 8];
        w.copy_from_slice(&bytes[at..at + 8]);
        u64::from_le_bytes(w)
    };
    let (val, uaddr) = (word(0), word(8));
    let flags2 = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
    let reserved = u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
    if flags2 & !FUTEX2_VALID_MASK != 0 || reserved != 0 {
        return Err(Errno::EINVAL.into());
    }
    let flags = futex2_flags(flags2)?;
    if !validate_input(val) {
        return Err(Errno::EINVAL.into());
    }
    #[allow(clippy::cast_possible_truncation)]
    Ok(WaitvEntry {
        val: val as u32,
        uaddr,
        flags,
    })
}

/// `futex_waitv(waiters, nr_futexes, flags, timeout, clockid)`.
fn futex_waitv<C: Context>(
    ctx: &mut C,
    waiters: u64,
    nr: u32,
    flags: u32,
    timeout: u64,
    clockid: i32,
) -> Sys {
    if flags != 0 {
        return Err(Errno::EINVAL.into());
    }
    if nr == 0 || nr as usize > WAITV_MAX || waiters == 0 {
        return Err(Errno::EINVAL.into());
    }
    let deadline = futex2_deadline(ctx, timeout, clockid)?;
    // kcalloc of the vector, then the parse of each entry.
    let mut entries = alloc::vec::Vec::new();
    entries
        .try_reserve_exact(nr as usize)
        .map_err(|_| Errno::ENOMEM)?;
    ctx.futex().queue.reserve(nr as usize)?;
    for index in 0..u64::from(nr) {
        let entry = parse_waitv_entry(ctx, waiters, index)?;
        let _ = entries.push_within_capacity(entry);
    }
    // futex_wait_multiple: the keys of every entry first, then each word is read and queued.
    let mut keys = alloc::vec::Vec::new();
    keys.try_reserve_exact(entries.len())
        .map_err(|_| Errno::ENOMEM)?;
    for entry in &entries {
        let key = get_futex_key(ctx, entry.uaddr, entry.flags, Access::Read)?;
        let _ = keys.push_within_capacity(key);
    }
    let owner = ctx.futex().owner;
    for (index, entry) in entries.iter().enumerate() {
        let Some(current) = read_u32(ctx, entry.uaddr) else {
            ctx.futex().queue.unqueue_owner(owner);
            return Err(Errno::EFAULT.into());
        };
        if current != entry.val {
            // "Even if something went wrong, if we find out that a futex was woken, we don't
            // return error and return this index to userspace."
            let woken = ctx.futex().queue.unqueue_owner(owner);
            return match woken {
                Some(at) => Ok(i64::from(at)),
                None => Err(Errno::EAGAIN.into()),
            };
        }
        #[allow(clippy::cast_possible_truncation)]
        ctx.futex()
            .queue
            .queue(keys[index], BITSET_MATCH_ANY, owner, index as u32);
    }
    let slept = sleep_on_queue(ctx, deadline);
    let woken = ctx.futex().queue.unqueue_owner(owner);
    if let Some(at) = woken {
        return Ok(i64::from(at));
    }
    match slept {
        Slept::TimedOut => Err(Errno::ETIMEDOUT.into()),
        // Plain -ERESTARTSYS: the absolute deadline makes a restart exact.
        _ => Ok(-ERESTARTSYS),
    }
}

// ---- robust lists ---------------------------------------------------------------------------

/// `get_robust_list(pid, head_ptr, len_ptr)`.
fn get_robust_list<C: Context>(ctx: &mut C, pid: i32, head_ptr: u64, len_ptr: u64) -> i64 {
    let (head, ok) = {
        let t = ctx.tasks();
        let target = if pid == 0 {
            Some(t.current)
        } else {
            t.list.find_task_by_vpid(pid)
        };
        let Some(target) = target else {
            return err(Errno::ESRCH);
        };
        // ptrace_may_access(p, PTRACE_MODE_READ_REALCREDS)
        (
            t.list.task(target).map_or(0, |task| task.robust_list),
            t.list.ptrace_may_access(t.current, target),
        )
    };
    if !ok {
        return err(Errno::EPERM);
    }
    if !put_user(ctx, len_ptr, &ROBUST_LIST_HEAD_SIZE.to_le_bytes()) {
        return err(Errno::EFAULT);
    }
    if !put_user(ctx, head_ptr, &head.to_le_bytes()) {
        return err(Errno::EFAULT);
    }
    0
}

/// `handle_futex_death(uaddr, curr, pi, pending_op)`: `Err(())` is the walk's "stop" (-1).
fn handle_futex_death<C: Context>(
    ctx: &mut C,
    uaddr: u64,
    pi: bool,
    pending_op: bool,
) -> Result<(), ()> {
    // Futex address must be 32bit aligned.
    if uaddr % 4 != 0 {
        return Err(());
    }
    let vpid = ctx.futex().tid;
    let Some(uval) = read_u32(ctx, uaddr) else {
        return Err(());
    };
    let owner = uval & FUTEX_TID_MASK;
    let shared = Flags(Flags::SIZE_32 | Flags::SHARED);
    if owner != vpid {
        // The unlock-path races: wake the next waiter the dead thread would have woken.
        if pending_op && !pi && (owner == 0 || uval & FUTEX_WAITERS == 0) {
            let _ = futex_wake(ctx, uaddr, shared, 1, BITSET_MATCH_ANY);
        }
        return Ok(());
    }
    // Mark the lock dead, keeping the waiters bit (the read and the write are one atomic
    // `cmpxchg` for the other tasks: no task runs between them).
    let mval = (uval & FUTEX_WAITERS) | FUTEX_OWNER_DIED;
    if !write_u32(ctx, uaddr, mval) {
        return Err(());
    }
    // Wake robust non-PI futexes here.
    if !pi && uval & FUTEX_WAITERS != 0 {
        let _ = futex_wake(ctx, uaddr, shared, 1, BITSET_MATCH_ANY);
    }
    Ok(())
}

/// `fetch_robust_entry`: the pointer at `at` with its low bit (the PI marker) split off.
fn fetch_robust_entry<C: Context>(ctx: &mut C, at: u64) -> Option<(u64, bool)> {
    let mut bytes = [0u8; 8];
    (copy_from_user(ctx, &mut bytes, at) == 0).then(|| {
        let word = u64::from_le_bytes(bytes);
        (word & !1, word & 1 != 0)
    })
}

/// `exit_robust_list(curr)`: walk the list `set_robust_list` registered (very carefully, it is
/// a user-space list) and mark every lock the exiting thread holds dead, waking a waiter.
/// Silent on any sign of a damaged list.
fn exit_robust_list<C: Context>(ctx: &mut C, head: u64) {
    let Some((mut entry, mut pi)) = fetch_robust_entry(ctx, head) else {
        return;
    };
    let mut offset = [0u8; 8];
    if copy_from_user(ctx, &mut offset, head.wrapping_add(8)) != 0 {
        return;
    }
    let futex_offset = u64::from_le_bytes(offset);
    let Some((pending, pending_pi)) = fetch_robust_entry(ctx, head.wrapping_add(16)) else {
        return;
    };
    let mut limit = ROBUST_LIST_LIMIT;
    while entry != head {
        // Fetch the next entry before calling handle_futex_death.
        let next = fetch_robust_entry(ctx, entry);
        // "A pending lock might already be on the list, so don't process it twice."
        if entry != pending
            && handle_futex_death(ctx, entry.wrapping_add(futex_offset), pi, false).is_err()
        {
            return;
        }
        let Some((next_entry, next_pi)) = next else {
            return;
        };
        entry = next_entry;
        pi = next_pi;
        // Avoid excessively long or circular lists.
        limit -= 1;
        if limit == 0 {
            break;
        }
    }
    if pending != 0 {
        let _ = handle_futex_death(ctx, pending.wrapping_add(futex_offset), pending_pi, true);
    }
}

/// `futex_cleanup` + `mm_release`: what a thread leaving its address space (`exit_mm`, or
/// `exec_mmap`) does in it. The robust list is walked and forgotten; `clear_child_tid` is
/// zeroed and its waiters woken when other tasks share the address space.
pub fn mm_release<C: Context>(ctx: &mut C) {
    let list = {
        let t = ctx.tasks();
        let current = t.current;
        t.list
            .task_mut(current)
            .map_or(0, |task| core::mem::take(&mut task.robust_list))
    };
    if list != 0 {
        exit_robust_list(ctx, list);
    }
    let clear = core::mem::take(&mut ctx.attrs().clear_child_tid);
    if clear != 0 && ctx.futex().mm_users > 1 {
        // We don't check the error code - if userspace has not set up a proper pointer then
        // tough luck. The wake is a plain (non-private) FUTEX_WAKE of one waiter.
        let _ = write_u32(ctx, clear, 0);
        let _ = futex_wake(ctx, clear, Flags::from_op(FUTEX_WAKE), 1, BITSET_MATCH_ANY);
    }
}

// ---- the system calls -----------------------------------------------------------------------

/// `futex_cmd_has_timeout`.
fn cmd_has_timeout(cmd: u32) -> bool {
    matches!(
        cmd,
        FUTEX_WAIT | FUTEX_LOCK_PI | FUTEX_LOCK_PI2 | FUTEX_WAIT_BITSET | FUTEX_WAIT_REQUEUE_PI
    )
}

/// `do_futex(uaddr, op, val, timeout, uaddr2, val2, val3)`.
#[allow(clippy::too_many_arguments)]
fn do_futex<C: Context>(
    ctx: &mut C,
    uaddr: u64,
    op: u32,
    val: u32,
    timeout: Option<Abs>,
    uaddr2: u64,
    val2: u32,
    val3: u32,
) -> Sys {
    let mut flags = Flags::from_op(op);
    let cmd = op & FUTEX_CMD_MASK;
    if flags.clock_realtime()
        && cmd != FUTEX_WAIT_BITSET
        && cmd != FUTEX_WAIT_REQUEUE_PI
        && cmd != FUTEX_LOCK_PI2
    {
        return Err(Errno::ENOSYS.into());
    }
    #[allow(clippy::cast_possible_wrap)]
    let (nr_wake, nr_requeue) = (val as i32, val2 as i32);
    match cmd {
        FUTEX_WAIT => Ok(futex_wait(
            ctx,
            uaddr,
            flags,
            val,
            timeout,
            BITSET_MATCH_ANY,
        )),
        FUTEX_WAIT_BITSET => Ok(futex_wait(ctx, uaddr, flags, val, timeout, val3)),
        FUTEX_WAKE => Ok(futex_wake(ctx, uaddr, flags, nr_wake, BITSET_MATCH_ANY)),
        FUTEX_WAKE_BITSET => Ok(futex_wake(ctx, uaddr, flags, nr_wake, val3)),
        FUTEX_REQUEUE => futex_requeue(
            ctx, uaddr, flags, uaddr2, flags, nr_wake, nr_requeue, None, false,
        ),
        FUTEX_CMP_REQUEUE => futex_requeue(
            ctx,
            uaddr,
            flags,
            uaddr2,
            flags,
            nr_wake,
            nr_requeue,
            Some(val3),
            false,
        ),
        FUTEX_WAKE_OP => Ok(futex_wake_op(
            ctx, uaddr, flags, uaddr2, nr_wake, nr_requeue, val3,
        )),
        FUTEX_LOCK_PI | FUTEX_LOCK_PI2 => {
            if cmd == FUTEX_LOCK_PI {
                flags = flags.with(Flags::CLOCKRT);
            }
            futex_lock_pi(ctx, uaddr, flags)
        }
        FUTEX_UNLOCK_PI => futex_unlock_pi(ctx, uaddr, flags),
        FUTEX_TRYLOCK_PI => futex_lock_pi(ctx, uaddr, flags),
        FUTEX_WAIT_REQUEUE_PI => {
            if uaddr == uaddr2 || val3 == 0 {
                // `futex_wait_requeue_pi`: "if (uaddr == uaddr2) return -EINVAL; if (!bitset)
                // return -EINVAL" (do_futex passes FUTEX_BITSET_MATCH_ANY, never zero).
                return Err(Errno::EINVAL.into());
            }
            // The wait itself queues a `rt_waiter` for the lock hand-over.
            Err(Stop::Unimplemented)
        }
        FUTEX_CMP_REQUEUE_PI => futex_requeue(
            ctx,
            uaddr,
            flags,
            uaddr2,
            flags,
            nr_wake,
            nr_requeue,
            Some(val3),
            true,
        ),
        _ => Err(Errno::ENOSYS.into()),
    }
}

/// `SYSCALL_DEFINE6(futex)`.
fn sys_futex<C: Context>(ctx: &mut C, a: [u64; 6]) -> Sys {
    #[allow(clippy::cast_possible_truncation)]
    let (op, val, val3) = (a[1] as u32, a[2] as u32, a[5] as u32);
    let (uaddr, utime, uaddr2) = (a[0], a[3], a[4]);
    let cmd = op & FUTEX_CMD_MASK;
    let mut timeout = None;
    if utime != 0 && cmd_has_timeout(cmd) {
        let ts = read_timespec(ctx, utime)?;
        let t = init_timeout(ts)?;
        // futex_init_timeout: FUTEX_WAIT is relative to now (monotonic); the other commands
        // are absolute, on the realtime clock for FUTEX_LOCK_PI and with the flag.
        timeout = Some(if cmd == FUTEX_WAIT {
            let now = i64::try_from(ctx.now_ns()).unwrap_or(KTIME_MAX);
            Abs {
                ns: now.checked_add(t).unwrap_or(KTIME_MAX),
                realtime: false,
            }
        } else {
            Abs {
                ns: t,
                realtime: cmd == FUTEX_LOCK_PI || op & FUTEX_CLOCK_REALTIME != 0,
            }
        });
    }
    #[allow(clippy::cast_possible_truncation)]
    do_futex(ctx, uaddr, op, val, timeout, uaddr2, utime as u32, val3)
}

pub(super) fn dispatch<C: Context>(ctx: &mut C, sysno: Sysno, a: [u64; 6]) -> Option<Outcome> {
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let int = |arg: u64| arg as u32 as i32;
    let number = sysno as u32;
    Some(match sysno {
        Sysno::futex => outcome(number, sys_futex(ctx, a)),
        Sysno::futex_waitv => outcome(
            number,
            futex_waitv(
                ctx,
                a[0],
                int(a[1]).cast_unsigned(),
                int(a[2]).cast_unsigned(),
                a[3],
                int(a[4]),
            ),
        ),
        Sysno::futex_wake => outcome(number, sys_futex_wake(ctx, a)),
        Sysno::futex_wait => outcome(number, sys_futex_wait(ctx, a)),
        Sysno::futex_requeue => outcome(number, sys_futex_requeue(ctx, a)),
        Sysno::get_robust_list => Outcome::Return(get_robust_list(ctx, int(a[0]), a[1], a[2])),
        _ => return None,
    })
}

/// `SYSCALL_DEFINE4(futex_wake)`.
fn sys_futex_wake<C: Context>(ctx: &mut C, a: [u64; 6]) -> Sys {
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let (nr, flags2) = (a[2] as u32 as i32, a[3] as u32);
    let flags = futex2_flags(flags2)?;
    if !validate_input(a[1]) {
        return Err(Errno::EINVAL.into());
    }
    #[allow(clippy::cast_possible_truncation)]
    Ok(futex_wake(
        ctx,
        a[0],
        flags.with(Flags::STRICT),
        nr,
        a[1] as u32,
    ))
}

/// `SYSCALL_DEFINE6(futex_wait)`.
fn sys_futex_wait<C: Context>(ctx: &mut C, a: [u64; 6]) -> Sys {
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let (flags2, clockid) = (a[3] as u32, a[5] as u32 as i32);
    let flags = futex2_flags(flags2)?;
    if !validate_input(a[1]) || !validate_input(a[2]) {
        return Err(Errno::EINVAL.into());
    }
    let deadline = futex2_deadline(ctx, a[4], clockid)?;
    #[allow(clippy::cast_possible_truncation)]
    Ok(futex_wait_once(
        ctx,
        a[0],
        flags,
        a[1] as u32,
        deadline,
        a[2] as u32,
    ))
}

/// `SYSCALL_DEFINE4(futex_requeue)`.
fn sys_futex_requeue<C: Context>(ctx: &mut C, a: [u64; 6]) -> Sys {
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let (flags, nr_wake, nr_requeue) = (a[1] as u32, a[2] as u32 as i32, a[3] as u32 as i32);
    if flags != 0 || a[0] == 0 {
        return Err(Errno::EINVAL.into());
    }
    let first = parse_waitv_entry(ctx, a[0], 0)?;
    let second = parse_waitv_entry(ctx, a[0], 1)?;
    // "For now mandate both flags are identical."
    if first.flags != second.flags {
        return Err(Errno::EINVAL.into());
    }
    futex_requeue(
        ctx,
        first.uaddr,
        first.flags,
        second.uaddr,
        second.flags,
        nr_wake,
        nr_requeue,
        Some(first.val),
        false,
    )
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::too_many_lines,
        clippy::items_after_statements,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    extern crate std;
    use super::*;
    use crate::signal::SIGUSR1;
    use crate::syscall::{
        Outcome, dispatch, error,
        testing::{Task, task},
    };
    use crate::usercopy::{copy_from_user, copy_to_user};

    const W: u64 = 0x1000;
    const BAD: u64 = 0xdead_0000_0000;
    const PRIVATE: u64 = 128;

    fn t() -> Task {
        let mut t = task();
        t.pages.map(0x1000, true);
        t.pages.map(0x2000, true);
        t
    }

    fn call(t: &mut Task, sysno: Sysno, args: &[u64]) -> i64 {
        let mut full = [0; 6];
        full[..args.len()].copy_from_slice(args);
        match dispatch(t, sysno as u64, full) {
            Outcome::Return(value) => value,
            other => panic!("{other:?}"),
        }
    }

    fn futex(t: &mut Task, args: &[u64]) -> i64 {
        call(t, Sysno::futex, args)
    }

    fn neg(errno: Errno) -> i64 {
        error(errno)
    }

    fn put(t: &mut Task, at: u64, value: u32) {
        assert_eq!(copy_to_user(t, at, &value.to_le_bytes()), 0);
    }

    fn get(t: &mut Task, at: u64) -> u32 {
        let mut b = [0u8; 4];
        assert_eq!(copy_from_user(t, &mut b, at), 0);
        u32::from_le_bytes(b)
    }

    fn key(at: u64) -> Key {
        Key::Private {
            mm: 1,
            page: at & !0xfff,
            offset: (at & 0xfff) as u32,
        }
    }

    /// Owners `1..` wait on `at` (private), in order.
    fn waiters(t: &mut Task, at: u64, owners: &[u32]) {
        for &owner in owners {
            t.futexes.queue(key(at), BITSET_MATCH_ANY, owner, 0);
        }
    }

    #[test]
    fn argument_errors_in_linuxs_order() {
        let mut t = t();
        put(&mut t, W, 1);
        let wait = FUTEX_WAIT as u64 | PRIVATE;
        assert_eq!(futex(&mut t, &[W, wait, 0]), neg(Errno::EAGAIN));
        assert_eq!(futex(&mut t, &[W + 1, wait, 1]), neg(Errno::EINVAL));
        assert_eq!(futex(&mut t, &[0, wait, 1]), neg(Errno::EFAULT));
        assert_eq!(futex(&mut t, &[BAD, wait, 1]), neg(Errno::EFAULT));
        // The timeout comes first, and is checked for validity before anything else.
        put(&mut t, 0x2000, 0);
        assert_eq!(futex(&mut t, &[W + 1, wait, 1, BAD]), neg(Errno::EFAULT));
        assert_eq!(copy_to_user(&mut t, 0x2000, &(-1i64).to_le_bytes()), 0);
        assert_eq!(futex(&mut t, &[W, wait, 1, 0x2000]), neg(Errno::EINVAL));
        assert_eq!(copy_to_user(&mut t, 0x2000, &1i64.to_le_bytes()), 0);
        assert_eq!(
            copy_to_user(&mut t, 0x2008, &1_000_000_000i64.to_le_bytes()),
            0
        );
        assert_eq!(futex(&mut t, &[W + 1, wait, 1, 0x2000]), neg(Errno::EINVAL));
        // Commands: unknown, the removed FUTEX_FD, the clock flag where it does not belong.
        assert_eq!(futex(&mut t, &[W, 14, 1]), neg(Errno::ENOSYS));
        assert_eq!(futex(&mut t, &[W, 2, 1]), neg(Errno::ENOSYS));
        assert_eq!(futex(&mut t, &[W, 256, 1]), neg(Errno::ENOSYS));
        assert_eq!(futex(&mut t, &[W, 256 | 1, 1]), neg(Errno::ENOSYS));
        assert_eq!(
            futex(&mut t, &[W, 256 | 9 | PRIVATE, 1, 0, 0, 0]),
            neg(Errno::EINVAL),
            "WAIT_BITSET with bitset 0"
        );
        assert_eq!(futex(&mut t, &[W, 10, 1, 0, 0, 0]), neg(Errno::EINVAL));
        assert_eq!(futex(&mut t, &[W, 1 | PRIVATE, 1]), 0, "nobody to wake");
        // The last user address is a valid private key; the one above is not.
        assert_eq!(
            futex(&mut t, &[TASK_SIZE_MAX, 1 | PRIVATE, 1]),
            0,
            "access_ok accepts it"
        );
        assert_eq!(
            futex(&mut t, &[TASK_SIZE_MAX + 4, 1 | PRIVATE, 1]),
            neg(Errno::EFAULT)
        );
    }

    #[test]
    fn wake_wakes_in_queue_order_and_reports_the_count() {
        let mut t = t();
        waiters(&mut t, W, &[3, 4, 5]);
        waiters(&mut t, W + 4, &[6]);
        assert_eq!(futex(&mut t, &[W, 1 | PRIVATE, 2]), 2);
        assert_eq!(t.futex_wakes.0, [3, 4]);
        assert_eq!(futex(&mut t, &[W, 1 | PRIVATE, 100]), 1);
        assert_eq!(t.futex_wakes.0, [3, 4, 5]);
        // A zero count still wakes the first waiter there is.
        assert_eq!(futex(&mut t, &[W + 4, 1 | PRIVATE, 0]), 1);
        assert_eq!(t.futex_wakes.0.last(), Some(&6));
        // Bitsets: no common bit, a common bit.
        t.futexes.queue(key(W), 0b110, 7, 0);
        assert_eq!(futex(&mut t, &[W, 10 | PRIVATE, 5, 0, 0, 0b001]), 0);
        assert_eq!(futex(&mut t, &[W, 10 | PRIVATE, 5, 0, 0, 0b100]), 1);
    }

    #[test]
    fn requeue_and_cmp_requeue_count_woken_plus_moved() {
        let mut t = t();
        put(&mut t, W, 5);
        waiters(&mut t, W, &[1, 2, 3, 4]);
        let cmp = 4 | PRIVATE;
        assert_eq!(
            futex(&mut t, &[W, cmp, 1, 2, W + 8, 6]),
            neg(Errno::EAGAIN),
            "the compare value is checked"
        );
        assert_eq!(futex(&mut t, &[W, cmp, 1, 2, W + 8, 5]), 3);
        assert_eq!(t.futex_wakes.0, [1]);
        assert_eq!(t.futexes.waiting_on(&key(W)), 1);
        assert_eq!(t.futexes.waiting_on(&key(W + 8)), 2);
        assert_eq!(futex(&mut t, &[W + 8, 1 | PRIVATE, 10]), 2);
        assert_eq!(t.futex_wakes.0, [1, 2, 3]);
        // Negative counts; unaligned or unreadable second address.
        assert_eq!(
            futex(&mut t, &[W, 3 | PRIVATE, u64::MAX >> 32, 1, W + 8]),
            neg(Errno::EINVAL)
        );
        assert_eq!(
            futex(&mut t, &[W, 3 | PRIVATE, 1, 1, W + 9]),
            neg(Errno::EINVAL)
        );
        assert_eq!(
            futex(&mut t, &[W, 3 | PRIVATE, 1, 1, BAD]),
            neg(Errno::EFAULT)
        );
    }

    #[test]
    fn wake_op_stores_before_it_compares() {
        let mut t = t();
        put(&mut t, W + 4, 5);
        waiters(&mut t, W, &[1, 2]);
        waiters(&mut t, W + 4, &[3, 4]);
        let op = |op: u32, oparg: u32, cmp: u32, cmparg: u32| {
            u64::from(
                (op & 0xf) << 28 | (cmp & 0xf) << 24 | (oparg & 0xfff) << 12 | (cmparg & 0xfff),
            )
        };
        // *b += 1, the old value is 5: wake one on a and one on b.
        assert_eq!(
            futex(&mut t, &[W, 5 | PRIVATE, 1, 1, W + 4, op(1, 1, 0, 5)]),
            2
        );
        assert_eq!(get(&mut t, W + 4), 6);
        assert_eq!(t.futex_wakes.0, [1, 3]);
        // Not equal: only a.
        assert_eq!(
            futex(&mut t, &[W, 5 | PRIVATE, 1, 1, W + 4, op(0, 9, 1, 6)]),
            1
        );
        assert_eq!(get(&mut t, W + 4), 9);
        // A comparison that does not exist: the operation was done, the call fails.
        assert_eq!(
            futex(&mut t, &[W, 5 | PRIVATE, 0, 0, W + 4, op(0, 3, 6, 0)]),
            neg(Errno::ENOSYS)
        );
        assert_eq!(get(&mut t, W + 4), 3);
        // An operation that does not exist: nothing was stored.
        assert_eq!(
            futex(&mut t, &[W, 5 | PRIVATE, 0, 0, W + 4, op(7, 1, 0, 0)]),
            neg(Errno::ENOSYS)
        );
        assert_eq!(get(&mut t, W + 4), 3);
    }

    #[test]
    fn a_timed_wait_ends_with_etimedout_and_a_signal_installs_the_restart_block() {
        let mut t = t();
        put(&mut t, W, 0);
        put(&mut t, 0x2000, 0);
        assert_eq!(
            copy_to_user(&mut t, 0x2008, &20_000_000i64.to_le_bytes()),
            0
        );
        let start = t.now;
        // Nothing wakes it: the fake clock jumps to the deadline.
        assert_eq!(
            futex(&mut t, &[W, FUTEX_WAIT as u64 | PRIVATE, 0, 0x2000]),
            neg(Errno::ETIMEDOUT)
        );
        assert!(t.now >= start + 20_000_000);
        assert_eq!(t.futexes.len(), 0, "unqueued");
        // A signal arrives first: the call is restarted from the block.
        t.script_signal(t.now + 5_000_000, SIGUSR1);
        t.state.hand.actions[usize::from(SIGUSR1) - 1].handler = 0x4000;
        let deadline = t.now + 20_000_000;
        assert_eq!(
            futex(&mut t, &[W, FUTEX_WAIT as u64 | PRIVATE, 0, 0x2000]),
            -ERESTART_RESTARTBLOCK
        );
        let block = t.clocks.restarts.last().copied().unwrap();
        assert_eq!(block.func, RestartFn::Futex);
        assert_eq!((block.futex.uaddr, block.futex.val), (W, 0));
        assert_eq!(block.expires_ns, i64::try_from(deadline).unwrap());
        // restart_syscall resumes with the same absolute deadline (after the signal is gone).
        let _ = t.state.dequeue_signal();
        assert_eq!(
            call(&mut t, Sysno::restart_syscall, &[]),
            neg(Errno::ETIMEDOUT)
        );
        assert!(t.now >= deadline);
        assert_eq!(t.clocks.restarts.last().copied(), Some(RestartBlock::NONE));
    }

    #[test]
    fn the_robust_list_of_an_exiting_thread_is_walked() {
        let mut t = t();
        // head at 0x2000: next = L0 (0x2100), offset 8, pending = L2 (0x2300).
        let head = 0x2000u64;
        let (l0, l1, l2) = (0x2100u64, 0x2200u64, 0x2300u64);
        for (at, word) in [
            (head, l0),
            (head + 8, 8),
            (head + 16, l2),
            (l0, l1),
            (l1, head),
            (l2, head),
        ] {
            assert_eq!(copy_to_user(&mut t, at, &word.to_le_bytes()), 0);
        }
        let tid = t.tgid;
        put(&mut t, l0 + 8, tid | FUTEX_WAITERS);
        put(&mut t, l1 + 8, tid + 1);
        put(&mut t, l2 + 8, tid);
        waiters(&mut t, l0 + 8, &[9]);
        // Shared-key waiter wanted: the walk wakes with a non-private key, so a private
        // waiter is not woken; a shared one needs a VMA, which the fake lacks, so the wake
        // finds nobody and the lock words tell the story.
        t.tasks.task_mut(t.current).unwrap().robust_list = head;
        mm_release(&mut t);
        assert_eq!(get(&mut t, l0 + 8), FUTEX_OWNER_DIED | FUTEX_WAITERS);
        assert_eq!(
            get(&mut t, l1 + 8),
            tid + 1,
            "another owner's lock is left alone"
        );
        assert_eq!(get(&mut t, l2 + 8), FUTEX_OWNER_DIED, "the pending entry");
        assert_eq!(t.tasks.task(t.current).unwrap().robust_list, 0);
        // set_robust_list / get_robust_list.
        assert_eq!(call(&mut t, Sysno::set_robust_list, &[head, 24]), 0);
        assert_eq!(
            call(&mut t, Sysno::get_robust_list, &[0, 0x1800, 0x1808]),
            0
        );
        let mut out = [0u8; 16];
        assert_eq!(copy_from_user(&mut t, &mut out, 0x1800), 0);
        assert_eq!(u64::from_le_bytes(out[..8].try_into().unwrap()), head);
        assert_eq!(u64::from_le_bytes(out[8..].try_into().unwrap()), 24);
        assert_eq!(
            call(&mut t, Sysno::get_robust_list, &[99, 0x1800, 0x1808]),
            neg(Errno::ESRCH)
        );
        assert_eq!(
            call(&mut t, Sysno::get_robust_list, &[0, 0x1800, BAD]),
            neg(Errno::EFAULT)
        );
    }

    #[test]
    fn clear_child_tid_is_zeroed_and_woken_only_when_the_mm_is_shared() {
        let mut t = t();
        put(&mut t, W, 77);
        t.attrs.clear_child_tid = W;
        mm_release(&mut t);
        assert_eq!(
            get(&mut t, W),
            77,
            "a private mm: unobservable, not written"
        );
        assert_eq!(t.attrs.clear_child_tid, 0);
        t.attrs.clear_child_tid = W;
        t.mm_users = 2;
        mm_release(&mut t);
        assert_eq!(get(&mut t, W), 0);
    }

    #[test]
    fn pi_operations_take_a_free_lock_and_stop_for_a_held_one() {
        let mut t = t();
        let tid = t.tgid;
        let lock = (6 | PRIVATE, 8 | PRIVATE, 7 | PRIVATE);
        assert_eq!(futex(&mut t, &[W, lock.2]), neg(Errno::EPERM));
        assert_eq!(futex(&mut t, &[W, lock.1]), 0);
        assert_eq!(get(&mut t, W), tid);
        assert_eq!(futex(&mut t, &[W, lock.1]), neg(Errno::EDEADLK));
        assert_eq!(futex(&mut t, &[W, lock.0]), neg(Errno::EDEADLK));
        assert_eq!(futex(&mut t, &[W, lock.2]), 0);
        assert_eq!(get(&mut t, W), 0);
        // A lock a task that does not exist holds: the waiters bit is set, ESRCH.
        put(&mut t, W, 4000);
        assert_eq!(futex(&mut t, &[W, lock.0]), neg(Errno::ESRCH));
        assert_eq!(get(&mut t, W), 4000 | FUTEX_WAITERS);
        // One that exists would need an rt_mutex: a loud stop.
        put(&mut t, W, 1 | FUTEX_OWNER_DIED);
        let held = t.tgid + 0; // the caller's own pid is not "another task"
        let _ = held;
        let child = t
            .tasks
            .fork(
                t.current,
                crate::task::tasklist::ForkParams {
                    rlimit_sigpending: 10,
                    rlimit_nproc: 100,
                    exit_signal: 17,
                    clear_sighand: false,
                },
            )
            .unwrap();
        let other = u32::try_from(t.tasks.task_pid_vnr(child)).unwrap();
        put(&mut t, W, other);
        assert_eq!(
            dispatch(&mut t, Sysno::futex as u64, [W, lock.0, 0, 0, 0, 0]),
            Outcome::Unimplemented(Sysno::futex as u32)
        );
        // The requeue operations check first; with no waiter they are a no-op.
        assert_eq!(
            futex(&mut t, &[W, 11 | PRIVATE, 0, 0, W]),
            neg(Errno::EINVAL)
        );
        assert_eq!(
            futex(&mut t, &[W, 12 | PRIVATE, 1, 1, W, 0]),
            neg(Errno::EINVAL)
        );
        assert_eq!(
            futex(&mut t, &[W, 12 | PRIVATE, 2, 1, W + 4, 0]),
            neg(Errno::EINVAL),
            "one waiter to wake"
        );
        put(&mut t, W, 3);
        assert_eq!(
            futex(&mut t, &[W, 12 | PRIVATE, 1, 1, W + 4, 4]),
            neg(Errno::EAGAIN)
        );
        assert_eq!(futex(&mut t, &[W, 12 | PRIVATE, 1, 1, W + 4, 3]), 0);
    }

    #[test]
    fn futex2_argument_checks() {
        let mut t = t();
        put(&mut t, W, 3);
        let entry = |t: &mut Task, at: u64, val: u64, uaddr: u64, flags: u32, reserved: u32| {
            assert_eq!(copy_to_user(t, at, &val.to_le_bytes()), 0);
            assert_eq!(copy_to_user(t, at + 8, &uaddr.to_le_bytes()), 0);
            assert_eq!(copy_to_user(t, at + 16, &flags.to_le_bytes()), 0);
            assert_eq!(copy_to_user(t, at + 20, &reserved.to_le_bytes()), 0);
        };
        let private32 = 2 | 128;
        entry(&mut t, 0x2000, 3, W, private32, 0);
        let waitv = |t: &mut Task, n: u64, flags: u64, timeout: u64, clock: u64| {
            call(t, Sysno::futex_waitv, &[0x2000, n, flags, timeout, clock])
        };
        assert_eq!(waitv(&mut t, 1, 1, 0, 0), neg(Errno::EINVAL));
        assert_eq!(waitv(&mut t, 0, 0, 0, 0), neg(Errno::EINVAL));
        assert_eq!(waitv(&mut t, 129, 0, 0, 0), neg(Errno::EINVAL));
        assert_eq!(
            call(&mut t, Sysno::futex_waitv, &[0, 1, 0, 0, 0]),
            neg(Errno::EINVAL)
        );
        assert_eq!(
            call(&mut t, Sysno::futex_waitv, &[BAD, 1, 0, 0, 0]),
            neg(Errno::EFAULT)
        );
        entry(&mut t, 0x2000, 3, W, 3, 0);
        assert_eq!(waitv(&mut t, 1, 0, 0, 0), neg(Errno::EINVAL), "size 8");
        entry(&mut t, 0x2000, 3, W, private32, 1);
        assert_eq!(waitv(&mut t, 1, 0, 0, 0), neg(Errno::EINVAL), "reserved");
        entry(&mut t, 0x2000, 1 << 32, W, private32, 0);
        assert_eq!(
            waitv(&mut t, 1, 0, 0, 0),
            neg(Errno::EINVAL),
            "value wider than the futex"
        );
        entry(&mut t, 0x2000, 4, W, private32, 0);
        assert_eq!(waitv(&mut t, 1, 0, 0, 0), neg(Errno::EAGAIN));
        assert_eq!(waitv(&mut t, 1, 0, 0x2800, 5), neg(Errno::EINVAL), "clock");
        assert_eq!(waitv(&mut t, 1, 0, BAD, 1), neg(Errno::EFAULT));
        // futex_wake / futex_wait.
        assert_eq!(
            call(&mut t, Sysno::futex_wake, &[W, 1, 1, private32 as u64]),
            0
        );
        assert_eq!(
            call(&mut t, Sysno::futex_wake, &[W, 0, 1, private32 as u64]),
            neg(Errno::EINVAL)
        );
        assert_eq!(
            call(&mut t, Sysno::futex_wake, &[W, 1, 1, 0]),
            neg(Errno::EINVAL)
        );
        assert_eq!(
            call(&mut t, Sysno::futex_wake, &[W, 1, 0, private32 as u64]),
            0,
            "STRICT: zero is zero"
        );
        assert_eq!(
            call(
                &mut t,
                Sysno::futex_wait,
                &[W, 4, 1, private32 as u64, 0, 0]
            ),
            neg(Errno::EAGAIN)
        );
    }
}
