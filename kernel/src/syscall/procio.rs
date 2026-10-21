// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: fs/seq_file.c (GPL-2.0:
// `seq_read_iter`, `traverse`, `seq_lseek`, `single_open`), fs/proc/base.c
// (`proc_pid_cmdline_read`, `get_mm_cmdline`, `get_mm_proctitle`,
// `environ_read`, `proc_pid_readlink`), fs/proc/generic.c (`proc_reg_read`),
// fs/read_write.c (`generic_file_llseek`, `default_llseek`). All GPL-2.0.
// Transformation: the state of a `seq_file` is `File::seq` ([`crate::seq::SeqFile`]);
// the text is produced whole by `procfs::show` with its record ends marked, and
// handed out as `seq_read_iter` would fill its buffer.
#![forbid(unsafe_code)]
//! Reading and seeking the files of `/proc`.
//!
//! Context: task context. A `seq_file` text is generated when the file is read
//! from the start or at a position other than the one the last read ended at
//! (the first read, or after `lseek`), and then served record by record as
//! `seq_read_iter` fills its buffer (see [`crate::seq::SeqFile`]). The files
//! with their own `read` (`cmdline`, `environ`) are generated on every call.

use alloc::{sync::Arc, vec::Vec};
use syscalls::Errno;

use super::{
    Context, Stop, Sys,
    fd::{Dest, View},
};
use crate::{
    procfs::{
        self, Kind, ProcNode,
        show::{self, ShowScope},
    },
    seq::{Seq, Snapshot},
    usercopy::copy_from_user,
    vfs::{FMODE_LSEEK, MAX_NON_LFS},
};

/// The node a procfs file refers to.
fn node_of(view: &View) -> Result<ProcNode, Errno> {
    view.inode.and_then(ProcNode::of).ok_or(Errno::EINVAL)
}

/// Whether the entry's `read` is its own (not `seq_read`).
fn own_read(kind: Kind) -> bool {
    matches!(kind, Kind::Cmdline | Kind::Environ)
}

/// `proc_reg_read` / `seq_read_iter` of a procfs file.
pub(super) fn read<C: Context>(
    ctx: &mut C,
    view: &View,
    dest: &mut Dest,
    pos: Option<&mut i64>,
) -> Sys {
    let node = node_of(view)?;
    let Some(pos) = pos else {
        return Err(Errno::EINVAL.into());
    };
    if own_read(node.kind) {
        return read_own(ctx, node, dest, pos);
    }
    // seq_read_iter: nothing is shown for an empty buffer.
    let count = usize::try_from(dest.remaining()).unwrap_or(usize::MAX);
    if count == 0 {
        return Ok(0);
    }
    let at = *pos;
    let mut state = ctx
        .files()
        .vfs
        .files
        .get_mut(view.id)
        .seq
        .take()
        .unwrap_or_default();
    if state.wants_snapshot(at) {
        // `->start` from the beginning, or `traverse` after a position change.
        match generate(ctx, node) {
            Ok(snap) => state.load(snap),
            Err(stop) => {
                state.reset(); // "with prejudice"
                ctx.files().vfs.files.get_mut(view.id).seq = Some(state);
                return Err(stop);
            }
        }
    }
    // `m_start` of `maps` asks for the task again at every refill.
    let gone = node.kind == Kind::Maps && ctx.tasks().list.find_task_by_vpid(node.tgid).is_none();
    let result = state.read(at, count, gone.then_some(Errno::ESRCH), &mut |bytes| {
        dest.copy_out(ctx, bytes)
    });
    ctx.files().vfs.files.get_mut(view.id).seq = Some(state);
    let copied = result?;
    *pos = at + i64::try_from(copied).unwrap_or(0);
    Ok(i64::try_from(copied).unwrap_or(0))
}

/// The files with their own `read` (`proc_pid_cmdline_read`, `environ_read`):
/// generated at every call and sliced at the position.
fn read_own<C: Context>(ctx: &mut C, node: ProcNode, dest: &mut Dest, pos: &mut i64) -> Sys {
    let at = *pos;
    let data = own_text(ctx, node)?;
    let start = usize::try_from(at).unwrap_or(usize::MAX).min(data.len());
    let asked = dest.remaining();
    let copied = dest.copy_out(ctx, &data[start..]);
    if copied == 0 && start < data.len() && asked > 0 {
        // The user buffer was unwritable from the start.
        return Err(Errno::EFAULT.into());
    }
    if copied > 0 {
        *pos = at + i64::try_from(copied).unwrap_or(0);
    }
    Ok(i64::try_from(copied).unwrap_or(0))
}

/// Show a node afresh: its text and the ends of its records.
fn generate<C: Context>(ctx: &mut C, node: ProcNode) -> Result<Snapshot, Stop> {
    let produced = ctx.with_show(ShowScope::of(node), |s| {
        let mut seq = Seq::new();
        show::read(s, node, &mut seq).and_then(|()| seq.into_snapshot())
    })?;
    Ok(produced?)
}

/// `(arg_start, arg_end, env_start, env_end, copy)` of a published task.
type ExecArgs = (u64, u64, u64, u64, Option<Arc<Vec<u8>>>);

/// The text of `cmdline` and `environ`: the caller's own is read from its
/// memory (`access_remote_vm` on `current`), another task's is the copy taken
/// at its `execve`.
fn own_text<C: Context>(ctx: &mut C, node: ProcNode) -> Result<Vec<u8>, Stop> {
    let me = i32::try_from(ctx.tgid()).unwrap_or(0);
    // The task must exist (get_proc_task) and have an address space.
    let view_args = ctx.with_show(
        ShowScope::Pid(node.tgid),
        |s| -> Result<Option<ExecArgs>, Errno> {
            s.tasks.find_task_by_vpid(node.tgid).ok_or(Errno::ESRCH)?;
            let view = s.vfs.fs.ns.proc.view(node.tgid).ok_or(Errno::ESRCH)?;
            let Some(mm) = s.vfs.fs.ns.proc.mm_of(node.tgid) else {
                return Ok(None);
            };
            Ok(Some((
                mm.arg_start,
                mm.arg_end,
                mm.env_start,
                mm.env_end,
                view.args.clone(),
            )))
        },
    )??;
    let Some((arg_start, arg_end, env_start, env_end, args)) = view_args else {
        return Ok(Vec::new());
    };
    if node.tgid != me {
        // Another task: the copy taken at exec (`args` = arg_start..env_end).
        let args = args.as_deref().map_or(&[][..], Vec::as_slice);
        return Ok(slice_args(
            node.kind, args, arg_start, arg_end, env_start, env_end,
        ));
    }
    let (arg_start, arg_end, env_start, env_end) = ctx
        .mm_args()
        .unwrap_or((arg_start, arg_end, env_start, env_end));
    let range = match node.kind {
        Kind::Cmdline => cmdline_range(ctx, arg_start, arg_end, env_start, env_end),
        _ => (env_start, env_end.max(env_start)),
    };
    if range.0 >= range.1 || env_end == 0 {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let len = usize::try_from(range.1 - range.0).unwrap_or(0);
    out.try_reserve_exact(len).map_err(|_| Errno::ENOMEM)?;
    out.resize_with_fallible(len)?;
    let missing = copy_from_user(ctx, &mut out, range.0);
    out.truncate(len - missing);
    if node.kind == Kind::Cmdline && out.last().is_some_and(|&b| b != 0) {
        // get_mm_proctitle: the title ends at its first NUL.
        if let Some(at) = out.iter().position(|&b| b == 0) {
            out.truncate(at + 1);
        }
    }
    Ok(out)
}

/// The byte range `cmdline` shows (`get_mm_cmdline`): the arguments, or
/// through the first NUL of the area when `setproctitle` overwrote the end.
fn cmdline_range<C: Context>(
    ctx: &mut C,
    arg_start: u64,
    arg_end: u64,
    env_start: u64,
    env_end: u64,
) -> (u64, u64) {
    if arg_start >= arg_end {
        return (0, 0);
    }
    let (env_start, env_end) = if env_start != arg_end || env_end < env_start {
        (arg_end, arg_end)
    } else {
        (env_start, env_end)
    };
    let _ = env_start;
    let mut last = [0u8; 1];
    let overwritten = copy_from_user(ctx, &mut last, arg_end - 1) == 0 && last[0] != 0;
    if overwritten {
        (arg_start, env_end.min(arg_start + 4096))
    } else {
        (arg_start, arg_end)
    }
}

/// Slice a task's exec-time copy.
fn slice_args(
    kind: Kind,
    args: &[u8],
    arg_start: u64,
    arg_end: u64,
    env_start: u64,
    env_end: u64,
) -> Vec<u8> {
    let (from, to) = match kind {
        Kind::Cmdline => (arg_start, arg_end),
        _ => (env_start, env_end),
    };
    let lo = usize::try_from(from.saturating_sub(arg_start)).unwrap_or(usize::MAX);
    let hi = usize::try_from(to.saturating_sub(arg_start)).unwrap_or(usize::MAX);
    let mut out = Vec::new();
    if out
        .try_reserve_exact(hi.saturating_sub(lo).min(args.len()))
        .is_err()
    {
        return out;
    }
    for &byte in args.get(lo..hi.min(args.len())).unwrap_or_default() {
        let _ = out.push_within_capacity(byte);
    }
    out
}

/// `generic_file_llseek` of a procfs file or directory: `generic_file_llseek_size` with the
/// superblock's `s_maxbytes` (`MAX_NON_LFS`: procfs never sets one) and the end of file `i_size`
/// (0). `pos` is the file position; the result is the new one.
///
/// # Errors
/// `ENXIO` for `SEEK_DATA` and `SEEK_HOLE` (`must_set_pos`: at or beyond the end of file),
/// `EINVAL` for a negative or too large position.
pub(super) fn generic_llseek(pos: i64, offset: i64, whence: u32) -> Result<i64, Errno> {
    let target = match whence {
        0 | 2 => offset,
        1 if offset == 0 => return Ok(pos),
        1 => pos.wrapping_add(offset),
        _ => return Err(Errno::ENXIO),
    };
    if (0..=MAX_NON_LFS).contains(&target) {
        Ok(target)
    } else {
        Err(Errno::EINVAL)
    }
}

/// `default_llseek` of a sysctl file (`proc_sys_file_operations`): no maximum, an end of file of 0
/// compared as signed numbers.
fn default_llseek(pos: i64, offset: i64, whence: u32) -> Result<i64, Errno> {
    let target = match whence {
        0 | 2 => offset,
        1 if offset == 0 => return Ok(pos),
        1 => pos.wrapping_add(offset),
        // SEEK_DATA and SEEK_HOLE at or beyond the end of file; below it (any negative offset)
        // the data stays where the offset is, and the hole is at the end of file.
        _ if offset >= 0 => return Err(Errno::ENXIO),
        3 => offset,
        _ => 0,
    };
    if target >= 0 {
        Ok(target)
    } else {
        Err(Errno::EINVAL)
    }
}

/// `seq_lseek` / `generic_file_llseek` / `default_llseek` of a procfs file.
pub(super) fn lseek<C: Context>(ctx: &mut C, view: &View, whence: u32, offset: i64) -> Sys {
    let node = node_of(view)?;
    if view.mode & FMODE_LSEEK == 0 {
        return Err(Errno::ESPIPE.into());
    }
    if own_read(node.kind) || node.kind == Kind::SysFile {
        let new = if node.kind == Kind::SysFile {
            default_llseek(view.pos, offset, whence)?
        } else {
            generic_llseek(view.pos, offset, whence)?
        };
        if whence != 1 || offset != 0 {
            // The next read shows the text afresh.
            ctx.files().vfs.files.get_mut(view.id).seq = None;
        }
        return Ok(new);
    }
    // seq_lseek: SET and CUR only, any non-negative position.
    let new = match whence {
        0 => offset,
        1 => offset.wrapping_add(view.pos),
        _ => return Err(Errno::EINVAL.into()),
    };
    if new < 0 {
        return Err(Errno::EINVAL.into());
    }
    let file = ctx.files().vfs.files.get_mut(view.id);
    // seq_lseek: a new position other than the read position runs `traverse`.
    let mut state = file.seq.take().unwrap_or_default();
    let moved = if state.seek_wants_snapshot(new) {
        generate(ctx, node).map(|snap| state.load(snap))
    } else {
        Ok(())
    };
    let sought = moved.and_then(|()| state.seek(new).map_err(Stop::from));
    let file = ctx.files().vfs.files.get_mut(view.id);
    if sought.is_err() {
        state.reset();
        file.pos = 0; // "with extreme prejudice"
    }
    file.seq = Some(state);
    sought.map(|()| new)
}

/// `readlink(2)` on a procfs link: the text `do_proc_readlink` or the
/// `get_link` of the entry gives.
pub(super) fn readlink<C: Context>(ctx: &mut C, node: ProcNode) -> Result<Vec<u8>, Stop> {
    Ok(ctx.with_show(ShowScope::Pid(node.tgid), |s| {
        procfs::show::readlink(s, node)
    })??)
}

trait ResizeFallible {
    fn resize_with_fallible(&mut self, len: usize) -> Result<(), Errno>;
}

impl ResizeFallible for Vec<u8> {
    fn resize_with_fallible(&mut self, len: usize) -> Result<(), Errno> {
        while self.len() < len {
            self.push_within_capacity(0).map_err(|_| Errno::ENOMEM)?;
        }
        Ok(())
    }
}

/// `comm_write` (`fs/proc/base.c`): at most `TASK_COMM_LEN - 1` bytes, up to the first NUL, become
/// the name of the writer's own thread group; another group's `comm` is `EINVAL` and a vanished
/// task `ESRCH`. The file position is ignored and a newline is kept.
///
/// Context: task, `vfs` lock held by the dispatcher.
///
/// # Errors
/// `EFAULT`, `ESRCH`, `EINVAL`.
pub fn comm_write<C: Context>(ctx: &mut C, view: &View, buf: u64, count: u64) -> Sys {
    let node = node_of(view)?;
    let take = usize::try_from(count)
        .unwrap_or(usize::MAX)
        .min(crate::task::COMM_LEN - 1);
    let mut name = [0u8; crate::task::COMM_LEN];
    if copy_from_user(ctx, &mut name[..take], buf) != 0 {
        return Err(Errno::EFAULT.into());
    }
    ctx.tasks()
        .list
        .find_task_by_vpid(node.tgid)
        .ok_or(Errno::ESRCH)?;
    if i32::try_from(ctx.tgid()).ok() != Some(node.tgid) {
        return Err(Errno::EINVAL.into());
    }
    // `set_task_comm`: `strscpy_pad` keeps the bytes up to the first NUL.
    let length = name
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(name.len());
    name[length..].fill(0);
    ctx.attrs().comm = name;
    Ok(i64::try_from(count).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    // oracle: `procfs.llseek-{cmdline,dir,...}-*` (generic_file_llseek) and
    // `procfs.llseek-sysctl-*` (default_llseek), recorded on the pinned Linux.
    #[test]
    fn generic_llseek_is_limited_to_non_lfs_with_an_empty_file() {
        let max = MAX_NON_LFS;
        assert_eq!(generic_llseek(5, max, 0), Ok(max));
        assert_eq!(generic_llseek(5, max + 1, 0), Err(Errno::EINVAL));
        assert_eq!(generic_llseek(max, 0, 1), Ok(max), "SEEK_CUR 0 asks only");
        assert_eq!(generic_llseek(max, 1, 1), Err(Errno::EINVAL));
        assert_eq!(generic_llseek(max, -max + 15, 1), Ok(15));
        assert_eq!(generic_llseek(5, 7, 2), Ok(7));
        assert_eq!(generic_llseek(5, -1, 2), Err(Errno::EINVAL));
        assert_eq!(generic_llseek(5, -1, 0), Err(Errno::EINVAL));
        for offset in [0, 100, -1, i64::MAX] {
            assert_eq!(generic_llseek(5, offset, 3), Err(Errno::ENXIO));
            assert_eq!(generic_llseek(5, offset, 4), Err(Errno::ENXIO));
        }
    }

    #[test]
    fn default_llseek_has_no_maximum_and_compares_as_signed() {
        assert_eq!(default_llseek(0, 1 << 40, 0), Ok(1 << 40));
        assert_eq!(default_llseek(1 << 40, 0, 1), Ok(1 << 40));
        assert_eq!(default_llseek(1 << 40, 5, 1), Ok((1 << 40) + 5));
        assert_eq!(default_llseek(0, -1, 0), Err(Errno::EINVAL));
        assert_eq!(default_llseek(0, 7, 2), Ok(7));
        assert_eq!(default_llseek(0, -1, 2), Err(Errno::EINVAL));
        assert_eq!(default_llseek(0, 0, 3), Err(Errno::ENXIO));
        assert_eq!(default_llseek(0, 1 << 40, 3), Err(Errno::ENXIO));
        assert_eq!(default_llseek(0, -1, 3), Err(Errno::EINVAL));
        assert_eq!(default_llseek(0, 0, 4), Err(Errno::ENXIO));
        // A negative offset is below the end of file: the hole is at the end of file (0).
        assert_eq!(default_llseek(9, -5, 4), Ok(0));
    }
}
