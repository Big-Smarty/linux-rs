// SPDX-License-Identifier: GPL-2.0-only
//! `procfs` group, part two: what `truncate`, `lseek`, `mmap` and `statfs` make of a procfs file.
//! Linux 6.18.57: `fs/attr.c` (`setattr_prepare`, `inode_newsize_ok`, `setattr_copy`,
//! `notify_change`), `fs/open.c` (`vfs_truncate`, `do_ftruncate`, `handle_truncate`),
//! `fs/proc/base.c` (`proc_nochmod_setattr`), `fs/proc/generic.c` (`proc_notify_change`),
//! `fs/proc/proc_sysctl.c` (`proc_sys_setattr`), `fs/read_write.c` (`generic_file_llseek_size`,
//! `default_llseek`), `fs/seq_file.c` (`seq_lseek`), `fs/proc/inode.c` (`proc_reg_mmap`),
//! `mm/mmap.c` (`file_mmap_ok`, `do_mmap`), `mm/vma.c` (`__mmap_region`), `fs/statfs.c`
//! (`calculate_f_flags`, `vfs_statfs`), `mm/shmem.c` (`shmem_statfs`), `fs/proc/root.c`.
//!
//! Every expectation was recorded on the pinned Linux first; the notes name the rule that
//! produces it.

use syscalls::{Errno, Sysno};

use core::fmt::Write as _;

use super::{
    Buf, MNT_DETACH, MS_NOATIME, MS_NODEV, MS_NODIRATIME, MS_NOEXEC, MS_NOSUID, MS_RDONLY,
    MS_REMOUNT, MS_STRICTATIME, O_DIRECTORY, O_PATH, O_RDONLY, O_RDWR, O_WRONLY, Page, R, SEEK_CUR,
    SEEK_END, SEEK_SET, T, Txt, addr, addr_mut, c, close, fstat, lseek, mount, open, put_file,
    slurp, stat, umount,
};

const O_TRUNC: usize = 0o1000;
const RLIMIT_FSIZE: usize = 1;
const SIGXFSZ: usize = 25;
const BIT_XFSZ: u64 = 1 << (SIGXFSZ - 1);
const SEEK_DATA: usize = 3;
const SEEK_HOLE: usize = 4;
const PROT_READ: usize = 1;
const PROT_WRITE: usize = 2;
const MAP_SHARED: usize = 1;
const MAP_PRIVATE: usize = 2;
const MAP_FIXED: usize = 0x10;
const MAP_ANON: usize = 0x20;
const MAP_FIXED_NOREPLACE: usize = 0x10_0000;

fn truncate(path: &str, len: usize) -> R {
    sys_(Sysno::truncate, &[addr(&c(path)), len])
}

fn ftruncate(fd: usize, len: usize) -> R {
    sys_(Sysno::ftruncate, &[fd, len])
}

fn sys_(nr: Sysno, args: &[usize]) -> R {
    super::sys(nr, args)
}

/// `clock_gettime(CLOCK_REALTIME)` in nanoseconds.
fn now_ns() -> i64 {
    let mut ts = [0i64; 2];
    let _ = sys_(Sysno::clock_gettime, &[0, addr_mut(&mut ts)]);
    ts[0] * 1_000_000_000 + ts[1]
}

fn ns(pair: [i64; 2]) -> i64 {
    pair[0] * 1_000_000_000 + pair[1]
}

/// The signals pending for the caller.
fn pending() -> u64 {
    let mut set = 0u64;
    let _ = sys_(Sysno::rt_sigpending, &[addr_mut(&mut set), 8]);
    set
}

/// Throws a pending `SIGXFSZ` away: an ignored signal is discarded from the pending set, and the
/// default action comes back afterwards.
fn forget_xfsz() {
    for handler in [1u64, 0] {
        let act = [handler, 0, 0, 0];
        let _ = sys_(Sysno::rt_sigaction, &[SIGXFSZ, addr(&act), 0, 8]);
    }
}

fn set_fsize(limit: u64) {
    let mut old = [0u64; 2];
    let _ = sys_(Sysno::prlimit64, &[0, RLIMIT_FSIZE, 0, addr_mut(&mut old)]);
    let new = [limit, old[1]];
    let _ = sys_(Sysno::prlimit64, &[0, RLIMIT_FSIZE, addr(&new), 0]);
}

/// `truncate(2)`, `ftruncate(2)` and `open(O_TRUNC)` of procfs files.
///
/// `proc_nochmod_setattr`, `proc_notify_change` and `proc_sys_setattr` all run `setattr_prepare`
/// (`inode_newsize_ok`: `RLIMIT_FSIZE` with `SIGXFSZ`, then the superblock's `s_maxbytes`, which
/// procfs leaves at `MAX_NON_LFS`) and `setattr_copy` (the times the caller asked for) and never
/// change the size, which stays what the entry reports.
pub(super) fn setattr(t: &mut T) {
    use super::super::proc::nap;
    let block = BIT_XFSZ;
    let _ = sys_(Sysno::rt_sigprocmask, &[0, addr(&block), 0, 8]);
    forget_xfsz();
    let comm = "/proc/self/comm";

    // truncate(2): ATTR_SIZE alone.
    t.eq("trunc-zero", truncate(comm, 0), Ok(0));
    t.eq("trunc-small", truncate(comm, 100), Ok(0));
    t.eq("trunc-non-lfs-max", truncate(comm, 0x7fff_ffff), Ok(0));
    t.eq(
        "trunc-above-non-lfs",
        truncate(comm, 0x8000_0000),
        Err(Errno::EFBIG),
    );
    t.eq("trunc-huge", truncate(comm, 1 << 40), Err(Errno::EFBIG));
    t.eq(
        "trunc-i64-max",
        truncate(comm, i64::MAX as usize),
        Err(Errno::EFBIG),
    );
    t.eq(
        "trunc-negative",
        truncate(comm, usize::MAX),
        Err(Errno::EINVAL),
    );
    // s_maxbytes ends in -EFBIG without a signal.
    t.eq("trunc-maxbytes-no-signal", pending() & BIT_XFSZ, 0);
    t.eq("trunc-size-unchanged", stat(comm).1.size, 0);
    t.eq(
        "trunc-sysctl",
        truncate("/proc/sys/kernel/hostname", 1 << 31),
        Err(Errno::EFBIG),
    );
    t.eq(
        "trunc-pid-file",
        truncate("/proc/self/status", 1 << 31),
        Err(Errno::EFBIG),
    );
    t.eq(
        "trunc-global-file",
        truncate("/proc/version", 1 << 31),
        Err(Errno::EFBIG),
    );
    t.eq(
        "trunc-global-file-zero",
        truncate("/proc/version", 0),
        Ok(0),
    );
    t.eq(
        "trunc-dir",
        truncate("/proc/self/fd", 0),
        Err(Errno::EISDIR),
    );
    t.eq(
        "trunc-noent",
        truncate("/proc/nonexistent", 0),
        Err(Errno::ENOENT),
    );

    // RLIMIT_FSIZE is checked first, and raises SIGXFSZ.
    set_fsize(1000);
    t.eq("trunc-limit-within", truncate(comm, 1000), Ok(0));
    t.eq("trunc-limit-within-no-signal", pending() & BIT_XFSZ, 0);
    t.eq(
        "trunc-limit-exceeded",
        truncate(comm, 1001),
        Err(Errno::EFBIG),
    );
    t.eq("trunc-limit-signal", pending() & BIT_XFSZ != 0, true);
    forget_xfsz();
    t.eq(
        "trunc-limit-before-maxbytes",
        truncate(comm, 1 << 31),
        Err(Errno::EFBIG),
    );
    t.eq(
        "trunc-limit-before-maxbytes-signal",
        pending() & BIT_XFSZ != 0,
        true,
    );
    forget_xfsz();
    t.eq(
        "trunc-limit-negative",
        truncate(comm, usize::MAX),
        Err(Errno::EINVAL),
    );
    t.eq("trunc-limit-negative-no-signal", pending() & BIT_XFSZ, 0);
    // A length at or below the entry's size is no growth: the limit does not apply.
    let size = usize::try_from(stat("/proc/cmdline").1.size).unwrap_or(0);
    set_fsize(0);
    t.eq(
        "trunc-limit0-same-size",
        truncate("/proc/cmdline", size),
        Ok(0),
    );
    t.eq("trunc-limit0-same-size-no-signal", pending() & BIT_XFSZ, 0);
    t.eq(
        "trunc-limit0-shrink",
        truncate("/proc/cmdline", size / 2),
        Ok(0),
    );
    t.eq(
        "trunc-limit0-grow",
        truncate("/proc/cmdline", size + 1),
        Err(Errno::EFBIG),
    );
    t.eq("trunc-limit0-grow-signal", pending() & BIT_XFSZ != 0, true);
    forget_xfsz();
    set_fsize(u64::MAX);

    // ftruncate(2): the same checks, and ATTR_MTIME | ATTR_CTIME.
    let fd = open(comm, O_RDWR).unwrap_or(99);
    t.eq("ftrunc-zero", ftruncate(fd, 0), Ok(0));
    t.eq("ftrunc-non-lfs-max", ftruncate(fd, 0x7fff_ffff), Ok(0));
    t.eq(
        "ftrunc-above-non-lfs",
        ftruncate(fd, 0x8000_0000),
        Err(Errno::EFBIG),
    );
    t.eq(
        "ftrunc-negative",
        ftruncate(fd, usize::MAX),
        Err(Errno::EINVAL),
    );
    t.eq("ftrunc-maxbytes-no-signal", pending() & BIT_XFSZ, 0);
    set_fsize(1000);
    t.eq("ftrunc-limit-within", ftruncate(fd, 1000), Ok(0));
    t.eq(
        "ftrunc-limit-exceeded",
        ftruncate(fd, 1001),
        Err(Errno::EFBIG),
    );
    t.eq("ftrunc-limit-signal", pending() & BIT_XFSZ != 0, true);
    forget_xfsz();
    set_fsize(u64::MAX);
    let ro = open(comm, O_RDONLY).unwrap_or(99);
    t.eq("ftrunc-read-only", ftruncate(ro, 0), Err(Errno::EINVAL));
    let dir = open("/proc/self/fd", O_RDONLY | O_DIRECTORY).unwrap_or(99);
    t.eq("ftrunc-dir", ftruncate(dir, 0), Err(Errno::EINVAL));
    let path = open(comm, O_PATH).unwrap_or(99);
    t.eq("ftrunc-opath", ftruncate(path, 0), Err(Errno::EBADF));
    let _ = (close(ro), close(dir), close(path));

    // The times: both are the moment of the call, and they stay.
    let before = now_ns();
    t.eq("ftrunc-time-call", ftruncate(fd, 0), Ok(0));
    let after = now_ns();
    let (_, st) = fstat(fd);
    let (m, ct) = (ns(st.mtime), ns(st.ctime));
    t.eq("ftrunc-mtime-is-ctime", m, ct);
    t.holds(
        "ftrunc-mtime-is-now",
        (before - 20_000_000..=after + 1_000_000).contains(&m),
        (before, m, after),
        "the moment of the call",
    );
    nap(100);
    let (_, st2) = fstat(fd);
    t.eq("ftrunc-times-stay", (ns(st2.mtime), ns(st2.ctime)), (m, ct));
    // truncate(2) asks for no time (ATTR_MTIME/ATTR_CTIME are absent): setattr_copy leaves them.
    t.eq("trunc-leaves-times-call", truncate(comm, 0), Ok(0));
    let (_, st3) = fstat(fd);
    t.eq(
        "trunc-leaves-times",
        (ns(st3.mtime), ns(st3.ctime)),
        (m, ct),
    );
    // A failed ftruncate changes nothing either.
    nap(30);
    t.eq(
        "ftrunc-fail-call",
        ftruncate(fd, 1 << 31),
        Err(Errno::EFBIG),
    );
    let (_, st4) = fstat(fd);
    t.eq(
        "ftrunc-fail-leaves-times",
        (ns(st4.mtime), ns(st4.ctime)),
        (m, ct),
    );
    // The same node reached by another path shows the same time.
    let (_, via_path) = stat(comm);
    t.eq(
        "ftrunc-times-by-path",
        (ns(via_path.mtime), ns(via_path.ctime)),
        (m, ct),
    );
    // A later ftruncate moves them on.
    let later = now_ns();
    t.eq("ftrunc-again-call", ftruncate(fd, 0), Ok(0));
    let (_, st5) = fstat(fd);
    t.holds(
        "ftrunc-again-moves-times",
        ns(st5.mtime) > m && ns(st5.mtime) >= later - 20_000_000 && ns(st5.mtime) == ns(st5.ctime),
        (m, later, ns(st5.mtime)),
        "later than before",
    );
    let _ = close(fd);

    // open(O_TRUNC): handle_truncate, ATTR_MTIME | ATTR_CTIME | ATTR_OPEN.
    let before = now_ns();
    let host = open("/proc/sys/kernel/hostname", O_WRONLY | O_TRUNC);
    let after = now_ns();
    t.eq("otrunc-sysctl", host.map(|_| ()), Ok(()));
    let host = host.unwrap_or(99);
    let (_, st) = fstat(host);
    let (m, ct) = (ns(st.mtime), ns(st.ctime));
    t.eq("otrunc-mtime-is-ctime", m, ct);
    t.holds(
        "otrunc-mtime-is-now",
        (before - 20_000_000..=after + 1_000_000).contains(&m),
        (before, m, after),
        "the moment of the call",
    );
    nap(50);
    let (_, st2) = fstat(host);
    t.eq("otrunc-times-stay", (ns(st2.mtime), ns(st2.ctime)), (m, ct));
    let _ = close(host);
    let mut name = [0u8; 128];
    let n = slurp("/proc/sys/kernel/hostname", &mut name).unwrap_or(0);
    t.holds(
        "otrunc-keeps-value",
        n > 1 && name[n - 1] == b'\n',
        Txt(&name[..n]),
        "the host name, untouched",
    );
    // A read-only open with O_TRUNC needs write permission, which root has.
    let before = now_ns();
    let ver = open("/proc/version", O_RDONLY | O_TRUNC);
    t.eq("otrunc-read-only-open", ver.map(|_| ()), Ok(()));
    let ver = ver.unwrap_or(99);
    let (_, st) = fstat(ver);
    t.holds(
        "otrunc-read-only-times",
        ns(st.mtime) >= before - 20_000_000 && ns(st.mtime) == ns(st.ctime),
        (before, ns(st.mtime)),
        "set by the open",
    );
    let _ = close(ver);
    // A pid file and a descriptor's fdinfo.
    t.eq(
        "otrunc-pid-file",
        open(comm, O_WRONLY | O_TRUNC).map(close),
        Ok(Ok(0)),
    );
    t.eq(
        "otrunc-fdinfo",
        open("/proc/self/fdinfo/0", O_RDONLY | O_TRUNC).map(close),
        Ok(Ok(0)),
    );
    // A directory is not truncated.
    t.eq(
        "otrunc-dir",
        open("/proc/self/fd", O_RDONLY | O_TRUNC | O_DIRECTORY),
        Err(Errno::EISDIR),
    );
    t.eq(
        "otrunc-dir-write",
        open("/proc/self/fd", O_WRONLY | O_TRUNC),
        Err(Errno::EISDIR),
    );

    // A read-only mount: mnt_want_write comes before the truncation.
    let mounted = mount(Some("proc"), "/mnt/a", Some("proc"), MS_RDONLY, None);
    t.eq("trunc-ro-mount", mounted, Ok(0));
    t.eq(
        "trunc-ro",
        truncate("/mnt/a/self/comm", 0),
        Err(Errno::EROFS),
    );
    t.eq(
        "trunc-ro-above-non-lfs",
        truncate("/mnt/a/self/comm", 1 << 31),
        Err(Errno::EROFS),
    );
    t.eq(
        "trunc-ro-otrunc",
        open("/mnt/a/self/comm", O_WRONLY | O_TRUNC),
        Err(Errno::EROFS),
    );
    t.eq(
        "trunc-ro-otrunc-read-only",
        open("/mnt/a/version", O_RDONLY | O_TRUNC),
        Err(Errno::EROFS),
    );
    let _ = umount("/mnt/a", 0);

    let _ = sys_(Sysno::rt_sigprocmask, &[1, addr(&block), 0, 8]);
}

/// `lseek(2)` on procfs files. The entries with their own `read` (`cmdline`, `environ`) and the
/// directories use `generic_file_llseek` with the superblock's `s_maxbytes` (`MAX_NON_LFS`) and
/// an end of file of 0; sysctl files use `default_llseek` (no limit); the `seq_file` entries use
/// `seq_lseek` (`SEEK_SET` and `SEEK_CUR` only).
pub(super) fn llseek(t: &mut T) {
    const MAX_NON_LFS: isize = 0x7fff_ffff;
    // generic_file_llseek.
    for (label, path, flags) in [
        ("cmdline", "/proc/self/cmdline", O_RDONLY),
        ("environ", "/proc/self/environ", O_RDONLY),
        ("dir", "/proc/self/fd", O_RDONLY | O_DIRECTORY),
        ("root", "/proc", O_RDONLY | O_DIRECTORY),
        ("sysdir", "/proc/sys/kernel", O_RDONLY | O_DIRECTORY),
    ] {
        let fd = open(path, flags).unwrap_or(99);
        let n = |what: &str| text!(40, "llseek-{label}-{what}");
        t.eq(
            n("max").str(),
            lseek(fd, MAX_NON_LFS, SEEK_SET),
            Ok(0x7fff_ffff),
        );
        t.eq(
            n("above-max").str(),
            lseek(fd, MAX_NON_LFS + 1, SEEK_SET),
            Err(Errno::EINVAL),
        );
        t.eq(n("pos-kept").str(), lseek(fd, 0, SEEK_CUR), Ok(0x7fff_ffff));
        t.eq(
            n("cur-above-max").str(),
            lseek(fd, 1, SEEK_CUR),
            Err(Errno::EINVAL),
        );
        t.eq(
            n("cur-back").str(),
            lseek(fd, -0x7fff_fff0, SEEK_CUR),
            Ok(15),
        );
        t.eq(
            n("negative").str(),
            lseek(fd, -1, SEEK_SET),
            Err(Errno::EINVAL),
        );
        t.eq(n("pos-after-error").str(), lseek(fd, 0, SEEK_CUR), Ok(15));
        t.eq(n("end").str(), lseek(fd, 7, SEEK_END), Ok(7));
        t.eq(
            n("end-negative").str(),
            lseek(fd, -1, SEEK_END),
            Err(Errno::EINVAL),
        );
        t.eq(
            n("end-max").str(),
            lseek(fd, MAX_NON_LFS, SEEK_END),
            Ok(0x7fff_ffff),
        );
        t.eq(
            n("end-above-max").str(),
            lseek(fd, MAX_NON_LFS + 1, SEEK_END),
            Err(Errno::EINVAL),
        );
        t.eq(n("set-zero").str(), lseek(fd, 0, SEEK_SET), Ok(0));
        // The entry is empty as far as seeking goes: no data, no hole.
        for (what, whence) in [("data", SEEK_DATA), ("hole", SEEK_HOLE)] {
            t.eq(n(what).str(), lseek(fd, 0, whence), Err(Errno::ENXIO));
            t.eq(
                text!(48, "llseek-{label}-{what}-far").str(),
                lseek(fd, 100, whence),
                Err(Errno::ENXIO),
            );
            t.eq(
                text!(48, "llseek-{label}-{what}-negative").str(),
                lseek(fd, -1, whence),
                Err(Errno::ENXIO),
            );
        }
        t.eq(n("pos-after-enxio").str(), lseek(fd, 0, SEEK_CUR), Ok(0));
        t.eq(n("whence-5").str(), lseek(fd, 0, 5), Err(Errno::EINVAL));
        let _ = close(fd);
    }

    // default_llseek: no maximum, signed comparisons against an end of file of 0.
    let fd = open("/proc/sys/kernel/hostname", O_RDONLY).unwrap_or(99);
    t.eq(
        "llseek-sysctl-big",
        lseek(fd, 1 << 40, SEEK_SET),
        Ok(1 << 40),
    );
    t.eq("llseek-sysctl-big-pos", lseek(fd, 0, SEEK_CUR), Ok(1 << 40));
    t.eq(
        "llseek-sysctl-cur",
        lseek(fd, 5, SEEK_CUR),
        Ok((1 << 40) + 5),
    );
    t.eq(
        "llseek-sysctl-negative",
        lseek(fd, -1, SEEK_SET),
        Err(Errno::EINVAL),
    );
    t.eq("llseek-sysctl-end", lseek(fd, 7, SEEK_END), Ok(7));
    t.eq(
        "llseek-sysctl-end-negative",
        lseek(fd, -1, SEEK_END),
        Err(Errno::EINVAL),
    );
    t.eq(
        "llseek-sysctl-data",
        lseek(fd, 0, SEEK_DATA),
        Err(Errno::ENXIO),
    );
    t.eq(
        "llseek-sysctl-data-far",
        lseek(fd, 1 << 40, SEEK_DATA),
        Err(Errno::ENXIO),
    );
    t.eq(
        "llseek-sysctl-data-negative",
        lseek(fd, -1, SEEK_DATA),
        Err(Errno::EINVAL),
    );
    t.eq(
        "llseek-sysctl-hole",
        lseek(fd, 0, SEEK_HOLE),
        Err(Errno::ENXIO),
    );
    t.eq(
        "llseek-sysctl-pos-after-enxio",
        lseek(fd, 0, SEEK_CUR),
        Ok(7),
    );
    // A negative offset is below the end of file, so the hole is at the end of file: 0.
    t.eq(
        "llseek-sysctl-hole-negative",
        lseek(fd, -5, SEEK_HOLE),
        Ok(0),
    );
    t.eq(
        "llseek-sysctl-whence-5",
        lseek(fd, 0, 5),
        Err(Errno::EINVAL),
    );
    let _ = close(fd);

    // seq_lseek: neither the end nor data and holes.
    let fd = open("/proc/self/limits", O_RDONLY).unwrap_or(99);
    t.eq("llseek-seq-big", lseek(fd, 1 << 20, SEEK_SET), Ok(1 << 20));
    t.eq("llseek-seq-end", lseek(fd, 0, SEEK_END), Err(Errno::EINVAL));
    t.eq(
        "llseek-seq-data",
        lseek(fd, 0, SEEK_DATA),
        Err(Errno::EINVAL),
    );
    t.eq(
        "llseek-seq-hole",
        lseek(fd, 0, SEEK_HOLE),
        Err(Errno::EINVAL),
    );
    t.eq(
        "llseek-seq-data-far",
        lseek(fd, 1 << 20, SEEK_DATA),
        Err(Errno::EINVAL),
    );
    t.eq("llseek-seq-whence-5", lseek(fd, 0, 5), Err(Errno::EINVAL));
    let _ = close(fd);
}

/// `mmap(2)` of procfs files. The entries of the global table run on `proc_reg_file_ops` /
/// `proc_iter_file_ops`, whose `->mmap` (`proc_reg_mmap`) is `-EIO` for an entry without
/// `proc_mmap` (all of them here); the process files, the sysctls and the directories have no
/// `->mmap` (`-ENODEV`). A procfs regular file is `S_ISREG`: `file_mmap_ok` allows offsets up to
/// `MAX_LFS_FILESIZE`, directories `ULONG_MAX`.
pub(super) fn mmap_files(t: &mut T) {
    let map = |fd: usize, prot: usize, flags: usize, off: usize| {
        super::super::mmap(0, 4096, prot, flags, fd, off)
    };
    let cases: [(&str, &str, usize, Errno); 11] = [
        ("version", "/proc/version", O_RDONLY, Errno::EIO),
        ("cpuinfo", "/proc/cpuinfo", O_RDONLY, Errno::EIO),
        ("meminfo", "/proc/meminfo", O_RDONLY, Errno::EIO),
        ("uptime", "/proc/uptime", O_RDONLY, Errno::EIO),
        ("maps", "/proc/self/maps", O_RDONLY, Errno::ENODEV),
        ("status", "/proc/self/status", O_RDONLY, Errno::ENODEV),
        ("cmdline", "/proc/self/cmdline", O_RDONLY, Errno::ENODEV),
        ("comm", "/proc/self/comm", O_RDWR, Errno::ENODEV),
        ("fdinfo", "/proc/self/fdinfo/0", O_RDONLY, Errno::ENODEV),
        (
            "sysctl",
            "/proc/sys/kernel/hostname",
            O_RDONLY,
            Errno::ENODEV,
        ),
        (
            "dir",
            "/proc/self/fd",
            O_RDONLY | O_DIRECTORY,
            Errno::ENODEV,
        ),
    ];
    let far = 0x7fff_ffff_ffff_f000usize;
    let last = 0x7fff_ffff_ffff_e000usize;
    for (label, path, flags, want) in cases {
        let fd = open(path, flags).unwrap_or(99);
        let n = |what: &str| text!(40, "mmap-{label}-{what}");
        t.eq(
            n("private").str(),
            map(fd, PROT_READ, MAP_PRIVATE, 0),
            Err(want),
        );
        t.eq(
            n("shared").str(),
            map(fd, PROT_READ, MAP_SHARED, 0),
            Err(want),
        );
        // proc_fill_super sets SB_I_NOEXEC: path_noexec is true before ->mmap is looked at.
        t.eq(
            n("exec").str(),
            map(fd, PROT_READ | 4, MAP_PRIVATE, 0),
            Err(Errno::EPERM),
        );
        // The offset: the last one `file_mmap_ok` allows, and the first it refuses.
        t.eq(
            n("last-offset").str(),
            map(fd, PROT_READ, MAP_PRIVATE, last),
            Err(want),
        );
        let beyond = if label == "dir" {
            Errno::ENODEV
        } else {
            Errno::EOVERFLOW
        };
        t.eq(
            n("beyond-offset").str(),
            map(fd, PROT_READ, MAP_PRIVATE, far),
            Err(beyond),
        );
        // Checks that come before ->mmap: a shared writable mapping of a read-only description,
        // and an unaligned offset.
        if flags & O_RDWR == 0 {
            t.eq(
                n("shared-write").str(),
                map(fd, PROT_READ | PROT_WRITE, MAP_SHARED, 0),
                Err(Errno::EACCES),
            );
        }
        t.eq(
            n("unaligned").str(),
            map(fd, PROT_READ, MAP_PRIVATE, 1),
            Err(Errno::EINVAL),
        );
        t.eq(
            n("zero-length").str(),
            super::super::mmap(0, 0, PROT_READ, MAP_PRIVATE, fd, 0),
            Err(Errno::EINVAL),
        );
        let _ = close(fd);
    }
    t.eq(
        "mmap-badfd",
        map(99, PROT_READ, MAP_PRIVATE, 0),
        Err(Errno::EBADF),
    );
    let path = open("/proc/version", O_PATH).unwrap_or(99);
    t.eq(
        "mmap-opath",
        map(path, PROT_READ, MAP_PRIVATE, 0),
        Err(Errno::EBADF),
    );
    let _ = close(path);

    // ->mmap fails after the mapping was prepared and the old one was cleared; the limits and
    // MAP_FIXED_NOREPLACE come first.
    let at = 0x5100_0000_0000usize;
    let fd = open("/proc/version", O_RDONLY).unwrap_or(99);
    t.eq(
        "mmap-page",
        super::super::mmap(
            at,
            4096,
            3,
            MAP_PRIVATE | MAP_ANON | MAP_FIXED_NOREPLACE,
            usize::MAX,
            0,
        ),
        Ok(at),
    );
    super::super::poke(at, 0x5a);
    let in_maps = || -> bool {
        let mut maps: Page = [0; 16384];
        let text = super::pid_text(super::getpid(), "maps", &mut maps).unwrap_or_default();
        super::lines(text).any(|l| l.starts_with(b"510000000000-510000001000 rw-p"))
    };
    t.eq("mmap-page-listed", in_maps(), true);
    t.eq(
        "mmap-fixed-eio",
        super::super::mmap(at, 4096, PROT_READ, MAP_PRIVATE | MAP_FIXED, fd, 0),
        Err(Errno::EIO),
    );
    // __mmap_setup cleared the old PTEs before ->mmap failed, so vms_abort_munmap_vmas leaves
    // the gap: the replaced range is unmapped although the call failed.
    t.eq("mmap-fixed-eio-leaves-gap", in_maps(), false);
    t.eq(
        "mmap-page-again",
        super::super::mmap(
            at,
            4096,
            3,
            MAP_PRIVATE | MAP_ANON | MAP_FIXED_NOREPLACE,
            usize::MAX,
            0,
        ),
        Ok(at),
    );
    t.eq(
        "mmap-noreplace-first",
        super::super::mmap(
            at,
            4096,
            PROT_READ,
            MAP_PRIVATE | MAP_FIXED_NOREPLACE,
            fd,
            0,
        ),
        Err(Errno::EEXIST),
    );
    t.eq("mmap-noreplace-first-intact", in_maps(), true);
    let _ = sys_(Sysno::munmap, &[at, 4096]);
    t.eq(
        "mmap-fixed-eio-empty",
        super::super::mmap(at, 4096, PROT_READ, MAP_PRIVATE | MAP_FIXED, fd, 0),
        Err(Errno::EIO),
    );
    let mut page: Page = [0; 16384];
    let statm = super::pid_text(super::getpid(), "statm", &mut page).unwrap_or_default();
    let pages = super::num(super::field(statm, b' ', 0)).unwrap_or(0);
    t.eq(
        "mmap-eio-leaves-no-mapping",
        super::pid_text(super::getpid(), "statm", &mut page)
            .map(|s| super::num(super::field(s, b' ', 0)).unwrap_or(0)),
        Ok(pages),
    );
    let _ = close(fd);
}

/// The ten numbers of a `statfs` that do not vary: type, block size, blocks, free blocks, blocks
/// available, files, free files, name length, fragment size and flags (`f_fsid` is random and
/// the spare words are zero).
fn sf_words(words: [u64; 15]) -> [u64; 10] {
    [
        words[0], words[1], words[2], words[3], words[4], words[5], words[6], words[8], words[9],
        words[10],
    ]
}

fn statfs_of(path: &str) -> Result<[u64; 10], Errno> {
    let mut words = [0u64; 15];
    sys_(Sysno::statfs, &[addr(&c(path)), addr_mut(&mut words)])?;
    Ok(sf_words(words))
}

fn fstatfs_of(fd: usize) -> Result<[u64; 10], Errno> {
    let mut words = [0u64; 15];
    sys_(Sysno::fstatfs, &[fd, addr_mut(&mut words)])?;
    Ok(sf_words(words))
}

/// `statfs(2)` and `fstatfs(2)`: the counts of the superblock and the flags of the mount
/// (`calculate_f_flags`).
pub(super) fn statfs_flags(t: &mut T) {
    const TMPFS: u64 = 0x0102_1994;
    const PROC: u64 = 0x9fa0;
    const VALID: u64 = 0x20;
    const RDONLY: u64 = 1;
    const NOSUID: u64 = 2;
    const NODEV: u64 = 4;
    const NOEXEC: u64 = 8;
    const NOATIME: u64 = 0x400;
    const NODIRATIME: u64 = 0x800;
    const RELATIME: u64 = 0x1000;
    let limited = |blocks: u64, bfree: u64, files: u64, ffree: u64, flags: u64| -> [u64; 10] {
        [
            TMPFS,
            4096,
            blocks,
            bfree,
            bfree,
            files,
            ffree,
            255,
            4096,
            VALID | flags,
        ]
    };
    let data = Some("size=1m,nr_inodes=64");
    let cases: [(&str, usize, u64); 9] = [
        ("default", 0, RELATIME),
        ("ro", MS_RDONLY, RELATIME | RDONLY),
        ("nosuid", MS_NOSUID, RELATIME | NOSUID),
        ("nodev", MS_NODEV, RELATIME | NODEV),
        ("noexec", MS_NOEXEC, RELATIME | NOEXEC),
        ("noatime", MS_NOATIME, NOATIME),
        ("nodiratime", MS_NODIRATIME, RELATIME | NODIRATIME),
        ("strictatime", MS_STRICTATIME, 0),
        (
            "all",
            MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOATIME | MS_NODIRATIME,
            RDONLY | NOSUID | NODEV | NOEXEC | NOATIME | NODIRATIME,
        ),
    ];
    for (label, flags, want) in cases {
        let n = |what: &str| text!(40, "statfs-{label}-{what}");
        t.eq(
            n("mount").str(),
            mount(Some("x"), "/mnt/a", Some("tmpfs"), flags, data),
            Ok(0),
        );
        let fd = open("/mnt/a", O_RDONLY | O_DIRECTORY).unwrap_or(99);
        let words = limited(256, 256, 64, 63, want);
        t.eq(n("path").str(), statfs_of("/mnt/a"), Ok(words));
        t.eq(n("fd").str(), fstatfs_of(fd), Ok(words));
        if label == "all" {
            // An open description keeps the flags of the mount it was opened through after the
            // mount is detached; the path now names what lies below.
            t.eq(n("detach").str(), umount("/mnt/a", MNT_DETACH), Ok(0));
            t.eq(n("detached-fd").str(), fstatfs_of(fd), Ok(words));
            t.eq(
                n("below").str(),
                statfs_of("/mnt/a").map(|w| w[0]),
                Ok(TMPFS),
            );
            let _ = close(fd);
        } else {
            let _ = close(fd);
            t.eq(n("umount").str(), umount("/mnt/a", 0), Ok(0));
        }
    }

    // Counts follow the use: three pages and a file.
    t.eq(
        "statfs-use-mount",
        mount(Some("x"), "/mnt/a", Some("tmpfs"), 0, data),
        Ok(0),
    );
    t.eq(
        "statfs-use-fill",
        put_file("/mnt/a/f", 3 * 4096),
        Ok(3 * 4096),
    );
    t.eq(
        "statfs-use",
        statfs_of("/mnt/a"),
        Ok(limited(256, 253, 64, 62, RELATIME)),
    );
    let file = open("/mnt/a/f", O_RDONLY).unwrap_or(99);
    t.eq(
        "statfs-use-fd",
        fstatfs_of(file),
        Ok(limited(256, 253, 64, 62, RELATIME)),
    );
    // A remount changes the flags of the mount and of the superblock together, and back.
    t.eq(
        "statfs-remount-ro",
        mount(None, "/mnt/a", Some("tmpfs"), MS_REMOUNT | MS_RDONLY, None),
        Ok(0),
    );
    t.eq(
        "statfs-remount-ro-path",
        statfs_of("/mnt/a"),
        Ok(limited(256, 253, 64, 62, RELATIME | RDONLY)),
    );
    t.eq(
        "statfs-remount-ro-fd",
        fstatfs_of(file),
        Ok(limited(256, 253, 64, 62, RELATIME | RDONLY)),
    );
    t.eq(
        "statfs-remount-rw",
        mount(None, "/mnt/a", Some("tmpfs"), MS_REMOUNT, None),
        Ok(0),
    );
    t.eq(
        "statfs-remount-rw-path",
        statfs_of("/mnt/a"),
        Ok(limited(256, 253, 64, 62, RELATIME)),
    );
    t.eq(
        "statfs-remount-limits",
        mount(
            None,
            "/mnt/a",
            Some("tmpfs"),
            MS_REMOUNT,
            Some("size=2m,nr_inodes=100"),
        ),
        Ok(0),
    );
    t.eq(
        "statfs-remount-limits-path",
        statfs_of("/mnt/a"),
        Ok(limited(512, 509, 100, 98, RELATIME)),
    );
    // An unlinked file that is still open keeps its pages and its inode.
    t.eq(
        "statfs-unlink",
        sys_(Sysno::unlink, &[addr(&c("/mnt/a/f"))]),
        Ok(0),
    );
    t.eq(
        "statfs-unlinked",
        statfs_of("/mnt/a"),
        Ok(limited(512, 509, 100, 98, RELATIME)),
    );
    t.eq(
        "statfs-unlinked-fd",
        fstatfs_of(file),
        Ok(limited(512, 509, 100, 98, RELATIME)),
    );
    let _ = close(file);
    t.eq(
        "statfs-closed",
        statfs_of("/mnt/a"),
        Ok(limited(512, 512, 100, 99, RELATIME)),
    );
    // An unlimited tmpfs reports zero counts for what is not limited.
    t.eq("statfs-unlimited-umount", umount("/mnt/a", 0), Ok(0));
    t.eq(
        "statfs-unlimited-mount",
        mount(Some("x"), "/mnt/a", Some("tmpfs"), 0, Some("nr_inodes=0")),
        Ok(0),
    );
    let w = statfs_of("/mnt/a").unwrap_or_default();
    t.holds(
        "statfs-unlimited",
        w[0] == TMPFS
            && w[1] == 4096
            && w[2] > 0
            && w[2] == w[3]
            && w[3] == w[4]
            && w[5] == 0
            && w[6] == 0
            && w[7] == 255
            && w[8] == 4096
            && w[9] == VALID | RELATIME,
        w,
        "blocks from the default size, no inode limit",
    );
    let _ = umount("/mnt/a", 0);

    // procfs: simple_statfs.
    let mounted = mount(
        Some("proc"),
        "/mnt/b",
        Some("proc"),
        MS_NOSUID | MS_NODEV | MS_NOEXEC,
        None,
    );
    t.eq("statfs-proc-mount", mounted, Ok(0));
    let proc_words =
        |flags: u64| -> [u64; 10] { [PROC, 4096, 0, 0, 0, 0, 0, 255, 4096, VALID | flags] };
    let nsne = RELATIME | NOSUID | NODEV | NOEXEC;
    t.eq("statfs-proc-dir", statfs_of("/mnt/b"), Ok(proc_words(nsne)));
    t.eq(
        "statfs-proc-file",
        statfs_of("/mnt/b/version"),
        Ok(proc_words(nsne)),
    );
    t.eq(
        "statfs-proc-pid-file",
        statfs_of("/mnt/b/self/status"),
        Ok(proc_words(nsne)),
    );
    t.eq(
        "statfs-proc-sysctl",
        statfs_of("/mnt/b/sys/kernel/hostname"),
        Ok(proc_words(nsne)),
    );
    let fd = open("/mnt/b/version", O_RDONLY).unwrap_or(99);
    t.eq("statfs-proc-fd", fstatfs_of(fd), Ok(proc_words(nsne)));
    let _ = close(fd);
    let opath = open("/mnt/b/self", O_PATH | O_DIRECTORY).unwrap_or(99);
    t.eq("statfs-proc-opath", fstatfs_of(opath), Ok(proc_words(nsne)));
    let _ = close(opath);
    t.eq(
        "statfs-proc-remount-ro",
        mount(
            None,
            "/mnt/b",
            Some("proc"),
            MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC,
            None,
        ),
        Ok(0),
    );
    t.eq(
        "statfs-proc-ro",
        statfs_of("/mnt/b/version"),
        Ok(proc_words(nsne | RDONLY)),
    );
    let held = open("/mnt/b/version", O_RDONLY).unwrap_or(99);
    t.eq("statfs-proc-detach", umount("/mnt/b", MNT_DETACH), Ok(0));
    t.eq(
        "statfs-proc-detached-fd",
        fstatfs_of(held),
        Ok(proc_words(nsne | RDONLY)),
    );
    let _ = close(held);
    t.eq(
        "statfs-missing",
        statfs_of("/mnt/b/none"),
        Err(Errno::ENOENT),
    );
}
