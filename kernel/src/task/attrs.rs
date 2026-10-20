// SPDX-License-Identifier: GPL-2.0-only
// Selected state and initial values from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: init/init_task.c (`init_task`:
// `comm`, `timer_slack_ns`, `INIT_SIGNALS` rlimits), include/asm-generic/resource.h
// (`INIT_RLIMITS`), include/uapi/linux/resource.h (`_STK_LIM`, `MLOCK_LIMIT`,
// `RLIM_NLIMITS`), include/uapi/linux/fs.h (`INR_OPEN_CUR/MAX`),
// include/uapi/linux/mqueue.h (`MQ_BYTES_MAX`), fs/file.c (`sysctl_nr_open`),
// kernel/fork.c (`set_max_threads`, `fork_init`), fs/fs_struct.c
// (`init_fs.umask`), kernel/user.c (`root_user`), kernel/groups.c
// (`init_groups`). All GPL-2.0-only.
// Transformation: the `task_struct`/`signal_struct`/`cred`/`fs_struct` fields
// the identity group reads are plain typed state of the one task; there is no
// reference counting, locking or sharing because nothing shares them yet.
#![forbid(unsafe_code)]
//! Per-task attributes of the identity and process-attribute syscalls
//! (`syscall::ids`): credentials, resource limits, the filesystem context,
//! personality and the user pointers `set_tid_address`/`set_robust_list` store.
//! The process tree (parent, process group, session) is not here: it is the
//! [`super::tasklist::Tasklist`]'s.
//!
//! Context: task context of the one user task; the owner (`userspace::Process`)
//! is only reachable under the `PROCESS` lock, so no field needs a lock of its
//! own. When more than one task exists these move into the `task_struct`
//! analogue, `cred` (shared, copy-on-write), `signal_struct` (`rlim`) and
//! `fs_struct` (shared with `CLONE_FS`) exactly where Linux keeps them.

/// `RLIM_NLIMITS`.
pub const RLIM_NLIMITS: usize = 16;
/// `RLIM_INFINITY` (`~0UL` on 64-bit).
pub const RLIM_INFINITY: u64 = u64::MAX;
/// `RLIMIT_CPU`.
pub const RLIMIT_CPU: usize = 0;
/// `RLIMIT_FSIZE`.
pub const RLIMIT_FSIZE: usize = 1;
/// `RLIMIT_STACK`.
pub const RLIMIT_STACK: usize = 3;
/// `RLIMIT_NPROC`.
pub const RLIMIT_NPROC: usize = 6;
/// `RLIMIT_NOFILE`.
pub const RLIMIT_NOFILE: usize = 7;
/// `RLIMIT_SIGPENDING`.
pub const RLIMIT_SIGPENDING: usize = 11;
/// `sysctl_nr_open` (fs/file.c:96), the ceiling `RLIMIT_NOFILE`'s hard limit may reach.
pub const NR_OPEN: u64 = 1024 * 1024;

/// `struct rlimit` / `struct rlimit64` (identical on x86-64): `{ rlim_cur, rlim_max }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rlimit {
    pub cur: u64,
    pub max: u64,
}

const fn limit(cur: u64, max: u64) -> Rlimit {
    Rlimit { cur, max }
}

/// `signal_struct::rlim`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rlimits([Rlimit; RLIM_NLIMITS]);

/// `MIN_THREADS` and `MAX_THREADS` (= `FUTEX_TID_MASK`) of kernel/fork.c:130-135.
const MIN_THREADS: u64 = 20;
const MAX_THREADS: u64 = 0x3fff_ffff;
/// `THREAD_SIZE` with 4 KiB pages and no KASAN (`THREAD_SIZE_ORDER = 2`).
const THREAD_SIZE: u64 = 4096 << 2;

/// `fork_init`'s `max_threads` (via `set_max_threads(MAX_THREADS)`) for
/// `free_pages` free 4 KiB pages: the thread structures may use 1/8 of memory.
#[must_use]
pub fn max_threads(free_pages: u64) -> u64 {
    // Linux selects MAX_THREADS when `fls64(nr_pages) + fls64(PAGE_SIZE) > 64`
    // (nr_pages >= 2^51). `checked_mul` overflows only from 2^52, but between
    // the two the quotient (nr_pages / 32) is far above MAX_THREADS and the
    // clamp gives the same result.
    let threads = free_pages
        .checked_mul(4096)
        .map_or(MAX_THREADS, |bytes| bytes / (THREAD_SIZE * 8));
    threads.clamp(MIN_THREADS, MAX_THREADS)
}

impl Rlimits {
    /// `INIT_RLIMITS` (include/asm-generic/resource.h:12-29) with the
    /// memory-derived `RLIMIT_NPROC` and `RLIMIT_SIGPENDING` of `fork_init`
    /// (kernel/fork.c:828-831): `max_threads / 2`, soft and hard.
    #[must_use]
    pub fn init(max_threads: u64) -> Self {
        const INF: u64 = RLIM_INFINITY;
        let threads = max_threads / 2;
        Self([
            limit(INF, INF),                         // CPU
            limit(INF, INF),                         // FSIZE
            limit(INF, INF),                         // DATA
            limit(8 * 1024 * 1024, INF),             // STACK (_STK_LIM)
            limit(0, INF),                           // CORE
            limit(INF, INF),                         // RSS
            limit(threads, threads),                 // NPROC
            limit(1024, 4096),                       // NOFILE (INR_OPEN_CUR, INR_OPEN_MAX)
            limit(8 * 1024 * 1024, 8 * 1024 * 1024), // MEMLOCK (MLOCK_LIMIT)
            limit(INF, INF),                         // AS
            limit(INF, INF),                         // LOCKS
            limit(threads, threads),                 // SIGPENDING
            limit(819_200, 819_200),                 // MSGQUEUE (MQ_BYTES_MAX)
            limit(0, 0),                             // NICE
            limit(0, 0),                             // RTPRIO
            limit(INF, INF),                         // RTTIME
        ])
    }

    /// `task_rlimit(current, resource)`.
    ///
    /// # Panics
    /// When `resource >= RLIM_NLIMITS` (callers pass a constant).
    #[must_use]
    pub fn get(&self, resource: usize) -> Rlimit {
        self.0[resource]
    }

    /// `do_prlimit` (kernel/sys.c:1500-1556) minus the `RLIMIT_CPU` timer
    /// (the caller refuses that case): validate, return the old value, store
    /// the new one. `resource` is the raw `unsigned int`.
    ///
    /// Init holds every capability and no syscall can drop one yet, so the
    /// `CAP_SYS_RESOURCE` check on raising a hard limit always passes and the
    /// LSM hook (`security_task_setrlimit`) has no module to consult.
    ///
    /// # Errors
    /// `Invalid` for a resource `>= RLIM_NLIMITS` or `cur > max`; `Permission`
    /// for an `RLIMIT_NOFILE` hard limit above `sysctl_nr_open`.
    pub fn prlimit(&mut self, resource: u32, new: Option<Rlimit>) -> Result<Rlimit, LimitError> {
        // shortcut: Linux clamps this user index with `array_index_nospec`
        // (kernel/sys.c do_prlimit, Spectre v1); there is no nospec primitive
        // in the tree yet (a branchless mask the optimiser cannot undo needs a
        // reviewed asm site), so only the architectural bounds check exists.
        // Upgrade with one shared `array_index_nospec` for every user-indexed table.
        let index = usize::try_from(resource)
            .ok()
            .filter(|&index| index < RLIM_NLIMITS)
            .ok_or(LimitError::Invalid)?;
        if let Some(new) = new {
            if new.cur > new.max {
                return Err(LimitError::Invalid);
            }
            if index == RLIMIT_NOFILE && new.max > NR_OPEN {
                return Err(LimitError::Permission);
            }
        }
        let old = self.0[index];
        if let Some(new) = new {
            self.0[index] = new;
        }
        Ok(old)
    }
}

/// Why `do_prlimit` refused: `-EINVAL` or `-EPERM`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimitError {
    Invalid,
    Permission,
}

/// The credentials `getuid`..`getgroups` report (`struct cred`). Init is root
/// of the initial user namespace (kernel/user.c `root_user`, `init_cred`), so
/// `from_kuid_munged` is the identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cred {
    pub uid: u32,
    pub euid: u32,
    pub suid: u32,
    pub gid: u32,
    pub egid: u32,
    pub sgid: u32,
    /// `group_info->gid[]`; `init_groups` has none.
    pub groups: &'static [u32],
}

impl Cred {
    #[must_use]
    pub const fn root() -> Self {
        Self {
            uid: 0,
            euid: 0,
            suid: 0,
            gid: 0,
            egid: 0,
            sgid: 0,
            groups: &[],
        }
    }
}

/// `current->fs`: the root, the working directory and the file-creation mask.
/// The VFS spine owns the type ([`crate::vfs::FsStruct`]); `umask(2)` edits
/// `umask`, `chdir`/`fchdir`/`getcwd` use the directory handles.
pub use crate::vfs::FsStruct;

/// `TASK_COMM_LEN`.
pub const COMM_LEN: usize = 16;

/// Everything the identity group keeps per task.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attributes {
    pub cred: Cred,
    pub rlimits: Rlimits,
    pub fs: FsStruct,
    /// `task_struct::comm`, NUL-padded. A task started by `execve("/init")`
    /// is named after the file: `init`.
    pub comm: [u8; COMM_LEN],
    /// `task_struct::personality` (`PER_LINUX = 0`).
    pub personality: u32,
    /// `task_struct::clear_child_tid` (`set_tid_address`). Nothing clears it
    /// yet: that is `mm_release` at exit, which a single immortal init lacks.
    pub clear_child_tid: u64,
    /// `task_struct::robust_list` (`set_robust_list`), walked at exit only.
    pub robust_list: u64,
}

impl Attributes {
    /// The init task's attributes; `max_threads` is [`max_threads`] of the
    /// free pages when `fork_init` runs.
    #[must_use]
    pub fn init(max_threads: u64) -> Self {
        let mut comm = [0; COMM_LEN];
        comm[..4].copy_from_slice(b"init");
        Self {
            cred: Cred::root(),
            rlimits: Rlimits::init(max_threads),
            fs: FsStruct::INIT,
            comm,
            personality: 0,
            clear_child_tid: 0,
            robust_list: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Attributes, LimitError, MAX_THREADS, MIN_THREADS, RLIM_INFINITY, Rlimit, max_threads,
    };

    #[test]
    fn max_threads_follows_set_max_threads() {
        // One thread structure (16 KiB) per eight stacks' worth of memory.
        assert_eq!(max_threads(0), MIN_THREADS);
        assert_eq!(max_threads(31), MIN_THREADS);
        assert_eq!(max_threads(128 * 1024), 128 * 1024 * 4096 / (16384 * 8));
        // 512 MiB of 4 KiB pages: 4096 threads, RLIMIT_NPROC/SIGPENDING 2048.
        assert_eq!(max_threads(131_072), 4096);
        let limits = Attributes::init(max_threads(131_072)).rlimits;
        assert_eq!(limits.0[6], limits.0[11]);
        assert_eq!(
            limits.0[6],
            Rlimit {
                cur: 2048,
                max: 2048
            }
        );
        // 64 GiB: still below MAX_THREADS (0x3fffffff).
        assert_eq!(max_threads(16 * 1024 * 1024), 524_288);
        assert_eq!(max_threads(1 << 52), MAX_THREADS);
        assert_eq!(max_threads(u64::MAX), MAX_THREADS);
    }

    #[test]
    fn init_rlimits_are_init_rlimits() {
        let mut attrs = Attributes::init(20_000);
        let want = |cur, max| Ok(Rlimit { cur, max });
        let table = [
            (3, want(8 << 20, RLIM_INFINITY)),
            (4, want(0, RLIM_INFINITY)),
            (6, want(10_000, 10_000)),
            (7, want(1024, 4096)),
            (8, want(8 << 20, 8 << 20)),
            (11, want(10_000, 10_000)),
            (12, want(819_200, 819_200)),
            (13, want(0, 0)),
            (15, want(RLIM_INFINITY, RLIM_INFINITY)),
        ];
        for (resource, expected) in table {
            assert_eq!(
                attrs.rlimits.prlimit(resource, None),
                expected,
                "{resource}"
            );
        }
    }

    #[test]
    fn prlimit_validates_before_storing_and_returns_the_old_value() {
        let mut limits = Attributes::init(100).rlimits;
        let set = |limits: &mut super::Rlimits, resource, cur, max| {
            limits.prlimit(resource, Some(Rlimit { cur, max }))
        };
        assert_eq!(set(&mut limits, 16, 0, 0), Err(LimitError::Invalid));
        assert_eq!(set(&mut limits, u32::MAX, 0, 0), Err(LimitError::Invalid));
        assert_eq!(set(&mut limits, 4, 10, 5), Err(LimitError::Invalid));
        // nr_open: the cap applies to the hard limit of RLIMIT_NOFILE only.
        assert_eq!(
            set(&mut limits, 7, 1, (1 << 20) + 1),
            Err(LimitError::Permission)
        );
        assert_eq!(
            set(&mut limits, 7, 1, 1 << 20),
            Ok(Rlimit {
                cur: 1024,
                max: 4096
            })
        );
        assert_eq!(
            set(&mut limits, 8, 1, 1 << 40),
            Ok(Rlimit {
                cur: 8 << 20,
                max: 8 << 20
            })
        );
        // A refused change stored nothing; invalid is checked before permission.
        assert_eq!(
            limits.prlimit(7, None),
            Ok(Rlimit {
                cur: 1,
                max: 1 << 20
            })
        );
        assert_eq!(set(&mut limits, 7, 3, 2), Err(LimitError::Invalid));
    }
}
