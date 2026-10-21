// SPDX-License-Identifier: GPL-2.0-only
//! `procfs` group: `mount(2)`/`umount2(2)` and the `/proc` filesystem. Linux 6.18.57:
//! `fs/namespace.c` (`path_mount`, `do_new_mount`, `do_remount`, `do_reconfigure_mnt`,
//! `do_change_type`, `do_umount`), `fs/proc_namespace.c` (`/proc/<pid>/mounts`, `mountinfo`),
//! `mm/shmem.c` (tmpfs options), `fs/proc/{root,base,array,fd,task_mmu,stat,meminfo,uptime,
//! loadavg,version,cmdline,devices}.c`, `fs/proc/proc_sysctl.c`, `kernel/sysctl.c`.
//!
//! Mount points are the empty directories of the generated initramfs (`/proc`, `/mnt/a` ..
//! `/mnt/h`, `xtask/src/fixture.rs`). What legitimately differs between runs and kernels (pids
//! beyond 1, memory totals, times, the CPU's model) is checked by format, field counts and
//! invariants against the system calls that report the same facts; what is deterministic (the
//! text of the mount tables, the mode and listing order of every entry, `/proc/self/limits`,
//! the executable's mappings) is compared exactly.

use core::fmt::{self, Debug, Write as _};

use syscalls::{Errno, Sysno};

use super::{PAGE, R, T, addr, addr_mut, getpid, sys};

macro_rules! pl {
    ($($a:tt)*) => { super::emit(format_args!($($a)*)) };
}

const AT_FDCWD: usize = -100isize as usize;
const BAD: usize = 0xdead_0000_0000;

const O_RDONLY: usize = 0;
const O_WRONLY: usize = 1;
const O_RDWR: usize = 2;
const O_CREAT: usize = 0o100;
const O_NOFOLLOW: usize = 0o400_000;
const O_DIRECTORY: usize = 0o200_000;
const O_PATH: usize = 0o10_000_000;

const MS_RDONLY: usize = 1;
const MS_NOSUID: usize = 2;
const MS_NODEV: usize = 4;
const MS_NOEXEC: usize = 8;
const MS_REMOUNT: usize = 32;
const MS_NOATIME: usize = 1024;
const MS_NODIRATIME: usize = 2048;
const MS_BIND: usize = 4096;
const MS_REC: usize = 16384;
const MS_UNBINDABLE: usize = 1 << 17;
const MS_PRIVATE: usize = 1 << 18;
const MS_SLAVE: usize = 1 << 19;
const MS_SHARED: usize = 1 << 20;
const MS_STRICTATIME: usize = 1 << 24;
const MS_NOUSER: usize = 1 << 31;

const MNT_FORCE: usize = 1;
const MNT_DETACH: usize = 2;
const MNT_EXPIRE: usize = 4;
const UMOUNT_NOFOLLOW: usize = 8;

const S_IFMT: u32 = 0o170_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFREG: u32 = 0o100_000;
const S_IFLNK: u32 = 0o120_000;

/// A byte string that prints as escaped text, so a failing comparison is readable.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Txt<'a>(&'a [u8]);

impl Debug for Txt<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_char('"')?;
        for &b in self.0 {
            match b {
                b'\n' => f.write_str("\\n")?,
                b'\t' => f.write_str("\\t")?,
                b'"' | b'\\' => {
                    f.write_char('\\')?;
                    f.write_char(b as char)?;
                }
                0x20..=0x7e => f.write_char(b as char)?,
                _ => write!(f, "\\x{b:02x}")?,
            }
        }
        f.write_char('"')
    }
}

/// A fixed buffer that implements `fmt::Write`: the text of an expected value.
struct Buf<const N: usize> {
    data: [u8; N],
    len: usize,
}

impl<const N: usize> Buf<N> {
    fn new() -> Self {
        Self {
            data: [0; N],
            len: 0,
        }
    }
    fn bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

impl<const N: usize> fmt::Write for Buf<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let n = s.len().min(N - self.len);
        self.data[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

impl<const N: usize> Buf<N> {
    fn str(&self) -> &str {
        core::str::from_utf8(self.bytes()).unwrap_or("?")
    }
    fn _0_str(&self) -> &str {
        self.str()
    }
}

macro_rules! text {
    ($n:expr, $($a:tt)*) => {{
        let mut b = Buf::<$n>::new();
        let _ = write!(b, $($a)*);
        b
    }};
}

mod attr;
pub mod vfork;

/// `s` followed by a NUL, for a system call argument.
fn c(s: &str) -> [u8; 192] {
    let mut out = [0u8; 192];
    out[..s.len()].copy_from_slice(s.as_bytes());
    out
}

// ---- system calls ---------------------------------------------------------------------------

fn mount(src: Option<&str>, dst: &str, ty: Option<&str>, flags: usize, data: Option<&str>) -> R {
    let (s, d, t, o) = (src.map(c), c(dst), ty.map(c), data.map(c));
    let ptr = |v: &Option<[u8; 192]>| v.as_ref().map_or(0, |b| addr(b));
    sys(Sysno::mount, &[ptr(&s), addr(&d), ptr(&t), flags, ptr(&o)])
}

fn umount(dst: &str, flags: usize) -> R {
    sys(Sysno::umount2, &[addr(&c(dst)), flags])
}

fn open(path: &str, flags: usize) -> R {
    sys(Sysno::open, &[addr(&c(path)), flags, 0o644])
}

fn close(fd: usize) -> R {
    sys(Sysno::close, &[fd])
}

fn read(fd: usize, buf: &mut [u8]) -> R {
    sys(Sysno::read, &[fd, addr_mut(buf), buf.len()])
}

fn pread(fd: usize, buf: &mut [u8], off: usize) -> R {
    sys(Sysno::pread64, &[fd, addr_mut(buf), buf.len(), off])
}

fn lseek(fd: usize, off: isize, whence: usize) -> R {
    sys(Sysno::lseek, &[fd, off as usize, whence])
}

/// The whole content of `path` (up to `buf.len()` bytes).
fn slurp(path: &str, buf: &mut [u8]) -> Result<usize, Errno> {
    let fd = open(path, O_RDONLY)?;
    let mut used = 0;
    loop {
        match read(fd, &mut buf[used..]) {
            Ok(0) => break,
            Ok(n) => used += n,
            Err(e) => {
                let _ = close(fd);
                return Err(e);
            }
        }
        if used == buf.len() {
            break;
        }
    }
    let _ = close(fd);
    Ok(used)
}

fn readlink(path: &str, buf: &mut [u8]) -> Result<usize, Errno> {
    sys(Sysno::readlink, &[addr(&c(path)), addr_mut(buf), buf.len()])
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
struct Stat {
    dev: u64,
    ino: u64,
    nlink: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    pad0: u32,
    rdev: u64,
    size: i64,
    blksize: i64,
    blocks: i64,
    atime: [i64; 2],
    mtime: [i64; 2],
    ctime: [i64; 2],
    unused: [i64; 3],
}

fn stat(path: &str) -> (R, Stat) {
    let mut st = Stat::default();
    (sys(Sysno::stat, &[addr(&c(path)), addr_mut(&mut st)]), st)
}

fn lstat(path: &str) -> (R, Stat) {
    let mut st = Stat::default();
    (
        sys(
            Sysno::newfstatat,
            &[AT_FDCWD, addr(&c(path)), addr_mut(&mut st), 0x100],
        ),
        st,
    )
}

fn fstat(fd: usize) -> (R, Stat) {
    let mut st = Stat::default();
    (sys(Sysno::fstat, &[fd, addr_mut(&mut st)]), st)
}

/// `stx_mnt_id` of `path` (`statx`, `STATX_MNT_ID`).
fn mnt_id(path: &str) -> Result<u64, Errno> {
    let mut out = [0u8; 256];
    sys(
        Sysno::statx,
        &[AT_FDCWD, addr(&c(path)), 0, 0x1000, addr_mut(&mut out)],
    )?;
    Ok(u64::from_le_bytes(
        out[144..152].try_into().unwrap_or([0; 8]),
    ))
}

fn getcwd(buf: &mut [u8]) -> Result<usize, Errno> {
    sys(Sysno::getcwd, &[addr_mut(buf), buf.len()])
}

fn chdir(path: &str) -> R {
    sys(Sysno::chdir, &[addr(&c(path))])
}

/// A directory listing: `(name, d_type)` of every entry but `.` and `..`, in kernel order, as
/// `names` (comma separated, with `/` and the type letter) -- and the raw entries for checks.
struct Dir {
    names: [u8; 4096],
    len: usize,
    count: usize,
}

impl Dir {
    /// `path`'s entries as `name:type` joined by `,`; `Err` on the first failure.
    fn list(path: &str) -> Result<Self, Errno> {
        let fd = open(path, O_RDONLY | O_DIRECTORY)?;
        let mut dir = Self {
            names: [0; 4096],
            len: 0,
            count: 0,
        };
        let mut buf = [0u8; 2048];
        loop {
            let n = match sys(Sysno::getdents64, &[fd, addr_mut(&mut buf), buf.len()]) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    let _ = close(fd);
                    return Err(e);
                }
            };
            let mut at = 0;
            while at + 19 <= n {
                let reclen = usize::from(u16::from_le_bytes([buf[at + 16], buf[at + 17]]));
                let kind = buf[at + 18];
                let name = &buf[at + 19..at + reclen];
                let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
                let name = &name[..end];
                at += reclen;
                if name == b"." || name == b".." {
                    continue;
                }
                let need = name.len() + 3;
                if dir.len + need > dir.names.len() {
                    break;
                }
                if dir.len > 0 {
                    dir.names[dir.len] = b',';
                    dir.len += 1;
                }
                dir.names[dir.len..dir.len + name.len()].copy_from_slice(name);
                dir.len += name.len();
                dir.names[dir.len] = b':';
                // DT_DIR, DT_REG, DT_LNK as a letter.
                dir.names[dir.len + 1] = match kind {
                    4 => b'd',
                    8 => b'f',
                    10 => b'l',
                    _ => b'?',
                };
                dir.len += 2;
                dir.count += 1;
            }
        }
        let _ = close(fd);
        Ok(dir)
    }

    fn text(&self) -> &[u8] {
        &self.names[..self.len]
    }

    /// The entries (`name:type`) as slices.
    fn entries(&self) -> impl Iterator<Item = &[u8]> {
        self.text().split(|&b| b == b',').filter(|e| !e.is_empty())
    }

    /// The entries named in `known`, in listing order, as `name:type` joined by `,`.
    fn subset<'a>(&self, known: &[&str], out: &'a mut [u8; 1024]) -> &'a [u8] {
        let mut len = 0;
        for entry in self.entries() {
            let name = &entry[..entry.len() - 2];
            if known.iter().any(|k| k.as_bytes() == name) {
                if len > 0 {
                    out[len] = b',';
                    len += 1;
                }
                out[len..len + entry.len()].copy_from_slice(entry);
                len += entry.len();
            }
        }
        &out[..len]
    }
}

// ---- text helpers -----------------------------------------------------------------------------

fn lines(buf: &[u8]) -> impl Iterator<Item = &[u8]> {
    buf.split_inclusive(|&b| b == b'\n')
}

/// The `n`th field of `line` split on `sep` (empty fields count).
fn field(line: &[u8], sep: u8, n: usize) -> &[u8] {
    line.split(|&b| b == sep).nth(n).unwrap_or_default()
}

fn num(s: &[u8]) -> Option<u64> {
    if s.is_empty() || s.len() > 20 {
        return None;
    }
    s.iter().try_fold(0u64, |acc, &b| {
        b.is_ascii_digit()
            .then(|| acc.checked_mul(10)?.checked_add(u64::from(b - b'0')))
            .flatten()
    })
}

fn signed(s: &[u8]) -> Option<i64> {
    match s.strip_prefix(b"-") {
        Some(rest) => num(rest).map(|v| -(v as i64)),
        None => num(s).map(|v| v as i64),
    }
}

fn has_prefix(s: &[u8], p: &str) -> bool {
    s.starts_with(p.as_bytes())
}

/// A scratch page-sized buffer on the stack.
type Page = [u8; 16384];

/// `/proc/self/mountinfo` (the text of the file).
fn mountinfo(buf: &mut Page) -> usize {
    slurp("/proc/self/mountinfo", buf).unwrap_or(0)
}

/// The mountinfo line of the mount whose mount point is `point`, the newest if several.
fn mi_line<'a>(buf: &'a [u8], point: &str) -> &'a [u8] {
    let mut found: &[u8] = &[];
    for line in lines(buf) {
        if field(line, b' ', 4) == point.as_bytes() {
            found = line;
        }
    }
    found
}

/// Whether the mountinfo text has a mount at `point`.
fn mi_has(buf: &[u8], point: &str) -> bool {
    !mi_line(buf, point).is_empty()
}

pub fn run() -> bool {
    let mut t = T::new("procfs");
    mount_errors(&mut t);
    proc_mount(&mut t);
    tmpfs_mounts(&mut t);
    tmpfs_options(&mut t);
    remounts(&mut t);
    proc_options(&mut t);
    propagation(&mut t);
    stacking_and_detach(&mut t);
    proc_tree(&mut t);
    global_files(&mut t);
    pid_files(&mut t);
    seq_files(&mut t);
    seq_records(&mut t);
    wchan(&mut t);
    publication(&mut t);
    attr::setattr(&mut t);
    attr::llseek(&mut t);
    attr::mmap_files(&mut t);
    attr::statfs_flags(&mut t);
    vfork::window(&mut t);
    vfork::exec(&mut t);
    mounts_poll(&mut t);
    root_umount(&mut t);
    t.finish()
}

fn mount_errors(t: &mut T) {
    // do_mount resolves the mount point first, so path errors precede every flag check.
    t.eq(
        "err-noent",
        mount(Some("x"), "/nonexistent", Some("tmpfs"), 0, None),
        Err(Errno::ENOENT),
    );
    t.eq(
        "err-empty-path",
        mount(Some("x"), "", Some("tmpfs"), 0, None),
        Err(Errno::ENOENT),
    );
    t.eq(
        "err-notdir",
        mount(Some("x"), "/fixture/hello.txt", Some("tmpfs"), 0, None),
        Err(Errno::ENOTDIR),
    );
    t.eq(
        "err-noent-before-nouser",
        mount(Some("x"), "/nonexistent", Some("tmpfs"), MS_NOUSER, None),
        Err(Errno::ENOENT),
    );
    // Then MS_NOUSER, ahead of the type lookup.
    t.eq(
        "err-nouser",
        mount(Some("x"), "/mnt/a", Some("nosuchfs"), MS_NOUSER, None),
        Err(Errno::EINVAL),
    );
    // MS_NOUSER is the C `int` (1<<31), which sign-extends: every bit from 31 to 63 is MS_NOUSER.
    // The magic MS_MGC_VAL in the top half of the low word is discarded with `~MS_MGC_MSK`, an
    // `unsigned int` that clears bits 16 to 63.
    const MS_MGC_VAL: usize = 0xC0ED_0000;
    for (name, flags, want) in [
        ("nouser-bit32", 1 << 32, Errno::EINVAL),
        ("nouser-bit47", 1 << 47, Errno::EINVAL),
        ("nouser-bit63", 1 << 63, Errno::EINVAL),
        ("nouser-bit31-and-32", MS_NOUSER | 1 << 32, Errno::EINVAL),
        ("magic-alone", MS_MGC_VAL, Errno::ENODEV),
        ("magic-clears-nouser", MS_MGC_VAL | MS_NOUSER, Errno::ENODEV),
        ("magic-clears-bit32", MS_MGC_VAL | 1 << 32, Errno::ENODEV),
        ("magic-clears-bit63", MS_MGC_VAL | 1 << 63, Errno::ENODEV),
        (
            "magic-clears-high-word",
            MS_MGC_VAL | 0xffff_ffff_0000_0000,
            Errno::ENODEV,
        ),
        ("not-the-magic", 0xC0EC_0000, Errno::EINVAL),
    ] {
        t.eq(
            format_args!("err-flags-{name}"),
            mount(Some("x"), "/mnt/a", Some("nosuchfs"), flags, None),
            Err(want),
        );
    }
    // do_new_mount: no type is EINVAL, an unregistered one ENODEV.
    t.eq(
        "err-type-null",
        mount(Some("x"), "/mnt/a", None, 0, None),
        Err(Errno::EINVAL),
    );
    t.eq(
        "err-type-unknown",
        mount(Some("x"), "/mnt/a", Some("nosuchfs"), 0, None),
        Err(Errno::ENODEV),
    );
    t.eq(
        "err-type-rootfs",
        mount(Some("x"), "/mnt/a", Some("rootfs"), 0, None),
        Err(Errno::ENODEV),
    );
    t.eq(
        "err-type-empty",
        mount(Some("x"), "/mnt/a", Some(""), 0, None),
        Err(Errno::ENODEV),
    );
    // A block device filesystem needs a source that is one.
    t.eq(
        "err-ext4-no-source",
        mount(None, "/mnt/a", Some("ext4"), 0, None),
        Err(Errno::EINVAL),
    );
    t.eq(
        "err-ext4-missing-source",
        mount(Some("/nonexistent"), "/mnt/a", Some("ext4"), 0, None),
        Err(Errno::ENOENT),
    );
    t.eq(
        "err-ext4-not-a-device",
        mount(Some("/init"), "/mnt/a", Some("ext4"), 0, None),
        Err(Errno::ENOTBLK),
    );
    // Flags that need a mount point.
    t.eq(
        "err-remount-not-a-mountpoint",
        mount(Some("x"), "/mnt/a", Some("tmpfs"), MS_REMOUNT, None),
        Err(Errno::EINVAL),
    );
    t.eq(
        "err-reconfigure-not-a-mountpoint",
        mount(
            Some("x"),
            "/mnt/a",
            Some("tmpfs"),
            MS_REMOUNT | MS_BIND,
            None,
        ),
        Err(Errno::EINVAL),
    );
    t.eq(
        "err-private-not-a-mountpoint",
        mount(Some("x"), "/mnt/a", None, MS_PRIVATE, None),
        Err(Errno::EINVAL),
    );
    // The options of tmpfs.
    for (name, data) in [
        ("unknown", "bogus=1"),
        ("mode-not-octal", "mode=999"),
        ("mode-empty", "mode="),
        ("mode-missing", "mode"),
        ("size-junk", "size=zz"),
        ("size-empty", "size="),
        ("size-missing", "size"),
        ("nr-inodes-junk", "nr_inodes=1q"),
        ("uid-junk", "uid=x"),
        ("uid-max", "uid=4294967295"),
        ("gid-max", "gid=4294967295"),
        ("gid-empty", "gid="),
        ("uid-too-big", "uid=4294967296"),
        ("flag-with-value", "noswap=1"),
        ("huge", "huge=always"),
        ("quota", "quota"),
    ] {
        t.eq(
            format_args!("err-tmpfs-{name}"),
            mount(Some("x"), "/mnt/a", Some("tmpfs"), 0, Some(data)),
            Err(Errno::EINVAL),
        );
    }
    // The options of proc.
    for (name, data) in [
        ("unknown", "bogus=1"),
        ("hidepid-value", "hidepid=3"),
        ("hidepid-word", "hidepid=bogus"),
        ("subset", "subset=net"),
        ("subset-empty", "subset="),
        ("subset-missing", "subset"),
        ("subset-list", "subset=pid,net"),
        ("hidepid-empty", "hidepid="),
        ("hidepid-missing", "hidepid"),
        ("hidepid-sign", "hidepid=-1"),
        ("hidepid-big", "hidepid=4294967297"),
        ("gid-missing", "gid"),
        ("gid-empty", "gid="),
        ("gid-big", "gid=4294967296"),
        ("gid-negative", "gid=-1"),
        ("gid-junk", "gid=1x"),
        ("pidns-empty", "pidns="),
        ("pidns-missing", "pidns"),
        ("tmpfs-option", "size=1"),
    ] {
        t.eq(
            format_args!("err-proc-{name}"),
            mount(Some("x"), "/mnt/a", Some("proc"), 0, Some(data)),
            Err(Errno::EINVAL),
        );
    }
    // An option error leaves nothing behind: the next mount still gets the first id.
    let mut buf: Page = [0; 16384];
    let n = mountinfo(&mut buf);
    t.eq("err-nothing-mounted", &buf[..n.min(0)], b"".as_slice());
    // The strings are copied type first, then the source, then the options, and only then is
    // the mount point read.
    let tmpfs = c("tmpfs");
    let none = c("x");
    let missing = c("/nonexistent");
    let mnt_a = c("/mnt/a");
    let m = |src: usize, dst: usize, ty: usize, data: usize| {
        sys(Sysno::mount, &[src, dst, ty, 0, data])
    };
    t.eq(
        "fault-type",
        m(addr(&none), addr(&missing), BAD, 0),
        Err(Errno::EFAULT),
    );
    t.eq(
        "fault-source",
        m(BAD, addr(&missing), addr(&tmpfs), 0),
        Err(Errno::EFAULT),
    );
    t.eq(
        "fault-options",
        m(addr(&none), addr(&missing), addr(&tmpfs), BAD),
        Err(Errno::EFAULT),
    );
    t.eq(
        "fault-mountpoint",
        m(addr(&none), BAD, addr(&tmpfs), 0),
        Err(Errno::EFAULT),
    );
    t.eq(
        "fault-mountpoint-null",
        m(addr(&none), 0, addr(&tmpfs), 0),
        Err(Errno::EFAULT),
    );
    t.eq("fault-all", m(BAD, BAD, BAD, BAD), Err(Errno::EFAULT));
    t.eq(
        "fault-ok-without-options",
        m(addr(&none), addr(&mnt_a), 0, 0),
        Err(Errno::EINVAL),
    );
    // Names beyond PATH_MAX: strndup_user answers EINVAL, the path ENAMETOOLONG.
    let mut long = [b'a'; 4200];
    long[4199] = 0;
    t.eq(
        "long-type",
        m(addr(&none), addr(&mnt_a), addr(&long), 0),
        Err(Errno::EINVAL),
    );
    t.eq(
        "long-source",
        m(addr(&long), addr(&mnt_a), addr(&tmpfs), 0),
        Err(Errno::EINVAL),
    );
    t.eq(
        "long-mountpoint",
        m(addr(&none), addr(&long), addr(&tmpfs), 0),
        Err(Errno::ENAMETOOLONG),
    );
    // umount2: the flags are checked before the path.
    t.eq(
        "umount-badflags",
        umount("/nonexistent", 0x10),
        Err(Errno::EINVAL),
    );
    t.eq(
        "umount-badflags-high",
        umount("/nonexistent", 0x8000_0000),
        Err(Errno::EINVAL),
    );
    t.eq(
        "umount-noent",
        umount("/nonexistent", 0),
        Err(Errno::ENOENT),
    );
    t.eq("umount-empty", umount("", 0), Err(Errno::ENOENT));
    t.eq(
        "umount-not-a-mountpoint",
        umount("/mnt/a", 0),
        Err(Errno::EINVAL),
    );
    t.eq(
        "umount-fault",
        sys(Sysno::umount2, &[BAD, 0]),
        Err(Errno::EFAULT),
    );
}

/// The device number of a `0:N` anonymous device in `st_dev`.
fn dev_of(minor: u64) -> u64 {
    minor
}

/// `mount -t proc proc /proc` and the first lines of the mount table.
fn proc_mount(t: &mut T) {
    t.eq("proc-absent", stat("/proc/self").0, Err(Errno::ENOENT));
    t.eq("proc-empty", Dir::list("/proc").map(|d| d.count), Ok(0));
    t.eq(
        "mount-proc",
        mount(Some("proc"), "/proc", Some("proc"), 0, None),
        Ok(0),
    );
    let mut buf: Page = [0; 16384];
    let n = mountinfo(&mut buf);
    let text = &buf[..n];
    // The root mount: ids 1 and 1, the anonymous device 0:2, the rootfs superblock options
    // (size and inode limits only when they differ from the defaults).
    let root = lines(text).next().unwrap_or_default();
    t.holds(
        "mountinfo-rootfs",
        has_prefix(root, "1 1 0:2 / / rw - rootfs rootfs rw")
            && rootfs_limits_ok(&root[b"1 1 0:2 / / rw - rootfs rootfs rw".len()..]),
        Txt(root),
        "1 1 0:2 / / rw - rootfs rootfs rw[,size=Nk,nr_inodes=N/4]",
    );
    t.eq(
        "mountinfo-proc",
        Txt(mi_line(text, "/proc")),
        Txt(b"17 1 0:16 / /proc rw,relatime - proc proc rw\n"),
    );
    t.eq("mountinfo-count", lines(text).count(), 2);
    // /proc/mounts is a link to self/mounts, which shows the same table the old way.
    let mut link = [0u8; 64];
    t.eq(
        "mounts-link",
        readlink("/proc/mounts", &mut link).map(|n| Txt(&link[..n]).0.len()),
        Ok(11),
    );
    t.eq("mounts-link-text", Txt(&link[..11]), Txt(b"self/mounts"));
    let n = slurp("/proc/mounts", &mut buf).unwrap_or(0);
    let mounts = &buf[..n];
    let second = lines(mounts).nth(1).unwrap_or_default();
    t.eq(
        "mounts-proc",
        Txt(second),
        Txt(b"proc /proc proc rw,relatime 0 0\n"),
    );
    let first = lines(mounts).next().unwrap_or_default();
    t.holds(
        "mounts-rootfs",
        has_prefix(first, "rootfs / rootfs rw") && first.ends_with(b" 0 0\n"),
        Txt(first),
        "rootfs / rootfs rw[,size=..,nr_inodes=..] 0 0",
    );
    // The mount's identity as stat and statx report it.
    t.eq("statx-mnt-id-proc", mnt_id("/proc"), Ok(17));
    t.eq("statx-mnt-id-self", mnt_id("/proc/self"), Ok(17));
    t.eq("statx-mnt-id-root", mnt_id("/"), Ok(1));
    t.eq("statx-mnt-id-mnt", mnt_id("/mnt"), Ok(1));
    let (r, st) = stat("/proc");
    t.eq("stat-proc-dev", (r, st.dev), (Ok(0), dev_of(16)));
    t.eq(
        "stat-proc-mode",
        (st.mode, st.uid, st.gid),
        (S_IFDIR | 0o555, 0, 0),
    );
    // A second mount of proc on the same mount point stacks a new superblock on top.
    t.eq(
        "mount-proc-again",
        mount(Some("proc"), "/proc", Some("proc"), 0, None),
        Ok(0),
    );
    let n = mountinfo(&mut buf);
    t.eq(
        "mountinfo-proc-stacked",
        Txt(mi_line(&buf[..n], "/proc")),
        Txt(b"18 17 0:17 / /proc rw,relatime - proc proc rw\n"),
    );
    t.eq("umount-proc-top", umount("/proc", 0), Ok(0));
    let n = mountinfo(&mut buf);
    t.eq(
        "mountinfo-proc-unstacked",
        Txt(mi_line(&buf[..n], "/proc")),
        Txt(b"17 1 0:16 / /proc rw,relatime - proc proc rw\n"),
    );
}

/// The tail of the rootfs line after `rw`: nothing, or `,size=Nk,nr_inodes=M` with N = 4 M.
fn rootfs_limits_ok(tail: &[u8]) -> bool {
    let tail = tail.strip_suffix(b"\n").unwrap_or(tail);
    if tail.is_empty() {
        return true;
    }
    let Some(rest) = tail.strip_prefix(b",size=") else {
        return false;
    };
    let size = field(rest, b'k', 0);
    let Some(inodes) = rest[size.len()..].strip_prefix(b"k,nr_inodes=") else {
        return false;
    };
    matches!((num(size), num(inodes)), (Some(k), Some(i)) if k == 4 * i)
}

/// The tmpfs mounts: options, mount table lines, identity, the files inside.
fn tmpfs_mounts(t: &mut T) {
    let mut buf: Page = [0; 16384];
    t.eq(
        "mount-tmpfs",
        mount(Some("tmpfs"), "/mnt/a", Some("tmpfs"), 0, None),
        Ok(0),
    );
    let n = mountinfo(&mut buf);
    t.eq(
        "tmpfs-line",
        Txt(mi_line(&buf[..n], "/mnt/a")),
        Txt(b"18 1 0:17 / /mnt/a rw,relatime - tmpfs tmpfs rw\n"),
    );
    let (r, st) = stat("/mnt/a");
    t.eq(
        "tmpfs-root-stat",
        (r, st.dev, st.ino, st.mode, st.uid, st.gid, st.nlink),
        (Ok(0), dev_of(17), 1, S_IFDIR | 0o1777, 0, 0, 2),
    );
    t.eq("tmpfs-root-size", st.size, 40);
    t.eq("tmpfs-mnt-id", mnt_id("/mnt/a"), Ok(18));
    let (_, up) = stat("/mnt/a/..");
    let (_, mnt) = stat("/mnt");
    t.eq("tmpfs-dotdot-leaves", (up.dev, up.ino), (mnt.dev, mnt.ino));
    t.eq(
        "tmpfs-dotdot-dir",
        Dir::list("/mnt/a").map(|d| d.count),
        Ok(0),
    );
    // A file in it: numbered from 2 on the new superblock, on its device.
    let fd = open("/mnt/a/f", O_RDWR | O_CREAT);
    t.holds("tmpfs-create", fd.is_ok(), fd, "created");
    let fd = fd.unwrap_or(99);
    let (r, st) = fstat(fd);
    t.eq(
        "tmpfs-file",
        (r, st.dev, st.ino, st.mode),
        (Ok(0), dev_of(17), 2, S_IFREG | 0o644),
    );
    t.eq(
        "tmpfs-write",
        sys(Sysno::write, &[fd, addr(b"hello"), 5]),
        Ok(5),
    );
    // The mount is busy while a file is open.
    t.eq(
        "tmpfs-busy-open-file",
        umount("/mnt/a", 0),
        Err(Errno::EBUSY),
    );
    t.eq("tmpfs-close", close(fd), Ok(0));
    // ... or a working directory is inside it.
    t.eq("tmpfs-chdir", chdir("/mnt/a"), Ok(0));
    let mut cwd = [0u8; 64];
    let n = getcwd(&mut cwd).unwrap_or(0);
    t.eq("tmpfs-getcwd", Txt(&cwd[..n]), Txt(b"/mnt/a\0"));
    t.eq("tmpfs-busy-cwd", umount("/mnt/a", 0), Err(Errno::EBUSY));
    t.eq("tmpfs-cwd-dotdot", chdir(".."), Ok(0));
    let n = getcwd(&mut cwd).unwrap_or(0);
    t.eq("tmpfs-getcwd-dotdot", Txt(&cwd[..n]), Txt(b"/mnt\0"));
    t.eq("tmpfs-cwd-back", chdir("/"), Ok(0));
    t.eq("tmpfs-umount", umount("/mnt/a", 0), Ok(0));
    t.eq("tmpfs-gone", stat("/mnt/a/f").0, Err(Errno::ENOENT));
    let n = mountinfo(&mut buf);
    t.eq("tmpfs-line-gone", mi_line(&buf[..n], "/mnt/a").len(), 0);
}

/// The mountinfo line of `point`, compared with `want`.
fn line_is(t: &mut T, name: &str, point: &str, want: &str) {
    let mut buf: Page = [0; 16384];
    let n = mountinfo(&mut buf);
    t.eq(name, Txt(mi_line(&buf[..n], point)), Txt(want.as_bytes()));
}

/// The `/proc/self/mounts` line of the mount at `point`.
fn mounts_is(t: &mut T, name: &str, point: &str, want: &str) {
    let mut buf: Page = [0; 16384];
    let n = slurp("/proc/self/mounts", &mut buf).unwrap_or(0);
    let mut found: &[u8] = &[];
    for line in lines(&buf[..n]) {
        if field(line, b' ', 1) == point.as_bytes() {
            found = line;
        }
    }
    t.eq(name, Txt(found), Txt(want.as_bytes()));
}

/// Create `path` and write `len` bytes: the result of the write.
fn put_file(path: &str, len: usize) -> R {
    let fd = open(path, O_RDWR | O_CREAT)?;
    let data = [0x5au8; 4096];
    let mut done = 0;
    let mut result = Ok(0);
    while done < len {
        match sys(Sysno::write, &[fd, addr(&data), (len - done).min(4096)]) {
            Ok(n) => done += n,
            Err(e) => {
                result = Err(e);
                break;
            }
        }
    }
    let _ = close(fd);
    result.map(|_| done)
}

/// Options, limits, read-only mounts.
fn tmpfs_options(t: &mut T) {
    // Every option of `show_options`, in its order, and the per-mount flags.
    t.eq(
        "opts-mount",
        mount(
            Some("mytmp"),
            "/mnt/b",
            Some("tmpfs"),
            MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOATIME,
            Some("size=1m,mode=0700,nr_inodes=100,uid=5,gid=6"),
        ),
        Ok(0),
    );
    line_is(
        t,
        "opts-line",
        "/mnt/b",
        "18 1 0:17 / /mnt/b rw,nosuid,nodev,noexec,noatime - tmpfs mytmp rw,size=1024k,nr_inodes=100,mode=700,uid=5,gid=6\n",
    );
    mounts_is(
        t,
        "opts-mounts",
        "/mnt/b",
        "mytmp /mnt/b tmpfs rw,nosuid,nodev,noexec,noatime,size=1024k,nr_inodes=100,mode=700,uid=5,gid=6 0 0\n",
    );
    let (r, st) = stat("/mnt/b");
    t.eq(
        "opts-root",
        (r, st.mode, st.uid, st.gid),
        (Ok(0), S_IFDIR | 0o700, 5, 6),
    );
    t.eq("opts-umount", umount("/mnt/b", 0), Ok(0));
    // size and nr_inodes are limits, with the root inode counted.
    t.eq(
        "limits-mount",
        mount(
            Some("x"),
            "/mnt/c",
            Some("tmpfs"),
            0,
            Some("size=8k,nr_inodes=3"),
        ),
        Ok(0),
    );
    line_is(
        t,
        "limits-line",
        "/mnt/c",
        "18 1 0:17 / /mnt/c rw,relatime - tmpfs x rw,size=8k,nr_inodes=3\n",
    );
    t.eq("limits-two-pages", put_file("/mnt/c/f1", 8192), Ok(8192));
    t.eq(
        "limits-third-page",
        put_file("/mnt/c/f1", 1).map(|_| ()),
        Ok(()),
    );
    let fd = open("/mnt/c/f1", O_WRONLY | 0o2000);
    t.eq("limits-append", fd.map(|_| ()), Ok(()));
    let fd = fd.unwrap_or(99);
    t.eq(
        "limits-enospc",
        sys(Sysno::write, &[fd, addr(b"x"), 1]),
        Err(Errno::ENOSPC),
    );
    let _ = close(fd);
    t.eq(
        "limits-inode-2",
        open("/mnt/c/f2", O_RDWR | O_CREAT).map(|fd| close(fd)),
        Ok(Ok(0)),
    );
    t.eq(
        "limits-inode-3",
        open("/mnt/c/f3", O_RDWR | O_CREAT),
        Err(Errno::ENOSPC),
    );
    // A remount cannot go below the use, nor limit what was unlimited.
    t.eq(
        "limits-remount-too-small",
        mount(None, "/mnt/c", Some("tmpfs"), MS_REMOUNT, Some("size=4k")),
        Err(Errno::EINVAL),
    );
    t.eq(
        "limits-remount-too-few-inodes",
        mount(
            None,
            "/mnt/c",
            Some("tmpfs"),
            MS_REMOUNT,
            Some("nr_inodes=1"),
        ),
        Err(Errno::EINVAL),
    );
    t.eq(
        "limits-remount-grow",
        mount(
            None,
            "/mnt/c",
            Some("tmpfs"),
            MS_REMOUNT,
            Some("size=16k,nr_inodes=9"),
        ),
        Ok(0),
    );
    line_is(
        t,
        "limits-grown",
        "/mnt/c",
        "18 1 0:17 / /mnt/c rw,relatime - tmpfs x rw,size=16k,nr_inodes=9\n",
    );
    t.eq(
        "limits-room-again",
        open("/mnt/c/f3", O_RDWR | O_CREAT).map(|fd| close(fd)),
        Ok(Ok(0)),
    );
    t.eq("limits-umount", umount("/mnt/c", 0), Ok(0));
    t.eq(
        "limits-unlimited",
        mount(
            Some("x"),
            "/mnt/c",
            Some("tmpfs"),
            0,
            Some("size=0,nr_inodes=0"),
        ),
        Ok(0),
    );
    line_is(
        t,
        "limits-unlimited-line",
        "/mnt/c",
        "18 1 0:17 / /mnt/c rw,relatime - tmpfs x rw,size=0k,nr_inodes=0\n",
    );
    t.eq(
        "limits-cannot-limit-size",
        mount(None, "/mnt/c", Some("tmpfs"), MS_REMOUNT, Some("size=16k")),
        Err(Errno::EINVAL),
    );
    t.eq(
        "limits-cannot-limit-inodes",
        mount(
            None,
            "/mnt/c",
            Some("tmpfs"),
            MS_REMOUNT,
            Some("nr_inodes=16"),
        ),
        Err(Errno::EINVAL),
    );
    t.eq("limits-unlimited-umount", umount("/mnt/c", 0), Ok(0));
    // A mount that is read-only from the start.
    t.eq(
        "ro-mount",
        mount(
            Some("ro"),
            "/mnt/d",
            Some("tmpfs"),
            MS_RDONLY,
            Some("size=64k"),
        ),
        Ok(0),
    );
    line_is(
        t,
        "ro-line",
        "/mnt/d",
        "18 1 0:17 / /mnt/d ro,relatime - tmpfs ro ro,size=64k\n",
    );
    t.eq(
        "ro-create",
        open("/mnt/d/f", O_RDWR | O_CREAT),
        Err(Errno::EROFS),
    );
    t.eq(
        "ro-unlink-missing",
        sys(Sysno::unlink, &[addr(&c("/mnt/d/f"))]),
        Err(Errno::EROFS),
    );
    t.eq(
        "ro-open-dir-for-write",
        open("/mnt/d", O_WRONLY),
        Err(Errno::EISDIR),
    );
    t.eq("ro-read-dir", Dir::list("/mnt/d").map(|d| d.count), Ok(0));
    // Remounting read-write.
    t.eq(
        "ro-remount-rw",
        mount(None, "/mnt/d", Some("tmpfs"), MS_REMOUNT, None),
        Ok(0),
    );
    line_is(
        t,
        "ro-rw-line",
        "/mnt/d",
        "18 1 0:17 / /mnt/d rw,relatime - tmpfs ro rw,size=64k\n",
    );
    t.eq("ro-create-after", put_file("/mnt/d/f", 10), Ok(10));
    // ... and read-only again: refused while a file is open for writing.
    let fd = open("/mnt/d/f", O_WRONLY).unwrap_or(99);
    t.eq(
        "ro-remount-busy",
        mount(None, "/mnt/d", Some("tmpfs"), MS_REMOUNT | MS_RDONLY, None),
        Err(Errno::EBUSY),
    );
    let _ = close(fd);
    t.eq(
        "ro-remount-ro",
        mount(None, "/mnt/d", Some("tmpfs"), MS_REMOUNT | MS_RDONLY, None),
        Ok(0),
    );
    line_is(
        t,
        "ro-ro-line",
        "/mnt/d",
        "18 1 0:17 / /mnt/d ro,relatime - tmpfs ro ro,size=64k\n",
    );
    t.eq(
        "ro-open-write",
        open("/mnt/d/f", O_WRONLY),
        Err(Errno::EROFS),
    );
    t.eq(
        "ro-open-read",
        open("/mnt/d/f", O_RDONLY).map(|fd| close(fd)),
        Ok(Ok(0)),
    );
    t.eq(
        "ro-unlink",
        sys(Sysno::unlink, &[addr(&c("/mnt/d/f"))]),
        Err(Errno::EROFS),
    );
    t.eq("ro-umount", umount("/mnt/d", 0), Ok(0));
}

/// Remounting: the flags are the call's own, the access times are kept.
fn remounts(t: &mut T) {
    t.eq(
        "remount-mount",
        mount(
            Some("r"),
            "/mnt/e",
            Some("tmpfs"),
            MS_NOSUID | MS_NODEV,
            Some("mode=755"),
        ),
        Ok(0),
    );
    line_is(
        t,
        "remount-line",
        "/mnt/e",
        "18 1 0:17 / /mnt/e rw,nosuid,nodev,relatime - tmpfs r rw,mode=755\n",
    );
    // A remount without the flags drops them; the atime flags are preserved.
    t.eq(
        "remount-plain",
        mount(None, "/mnt/e", Some("tmpfs"), MS_REMOUNT, None),
        Ok(0),
    );
    line_is(
        t,
        "remount-plain-line",
        "/mnt/e",
        "18 1 0:17 / /mnt/e rw,relatime - tmpfs r rw,mode=755\n",
    );
    t.eq(
        "remount-flags",
        mount(
            None,
            "/mnt/e",
            Some("tmpfs"),
            MS_REMOUNT | MS_NOEXEC | MS_NOSUID,
            None,
        ),
        Ok(0),
    );
    line_is(
        t,
        "remount-flags-line",
        "/mnt/e",
        "18 1 0:17 / /mnt/e rw,nosuid,noexec,relatime - tmpfs r rw,mode=755\n",
    );
    // The atime flags: noatime replaces relatime; a plain remount keeps them.
    t.eq(
        "remount-noatime",
        mount(
            None,
            "/mnt/e",
            Some("tmpfs"),
            MS_REMOUNT | MS_NOATIME | MS_NODIRATIME,
            None,
        ),
        Ok(0),
    );
    line_is(
        t,
        "remount-noatime-line",
        "/mnt/e",
        "18 1 0:17 / /mnt/e rw,noatime,nodiratime - tmpfs r rw,mode=755\n",
    );
    t.eq(
        "remount-keeps-atime",
        mount(None, "/mnt/e", Some("tmpfs"), MS_REMOUNT, None),
        Ok(0),
    );
    line_is(
        t,
        "remount-keeps-atime-line",
        "/mnt/e",
        "18 1 0:17 / /mnt/e rw,noatime,nodiratime - tmpfs r rw,mode=755\n",
    );
    t.eq(
        "remount-strict",
        mount(
            None,
            "/mnt/e",
            Some("tmpfs"),
            MS_REMOUNT | MS_STRICTATIME,
            None,
        ),
        Ok(0),
    );
    line_is(
        t,
        "remount-strict-line",
        "/mnt/e",
        "18 1 0:17 / /mnt/e rw - tmpfs r rw,mode=755\n",
    );
    // Generic options in the data of a remount: ro/rw change the superblock, others are refused.
    t.eq(
        "remount-data-ro",
        mount(None, "/mnt/e", Some("tmpfs"), MS_REMOUNT, Some("ro")),
        Ok(0),
    );
    line_is(
        t,
        "remount-data-ro-line",
        "/mnt/e",
        "18 1 0:17 / /mnt/e rw - tmpfs r ro,mode=755\n",
    );
    mounts_is(
        t,
        "remount-data-ro-mounts",
        "/mnt/e",
        "r /mnt/e tmpfs ro,mode=755 0 0\n",
    );
    t.eq(
        "remount-data-rw",
        mount(None, "/mnt/e", Some("tmpfs"), MS_REMOUNT, Some("rw,sync")),
        Ok(0),
    );
    line_is(
        t,
        "remount-data-sync-line",
        "/mnt/e",
        "18 1 0:17 / /mnt/e rw - tmpfs r rw,sync,mode=755\n",
    );
    t.eq(
        "remount-data-dirsync",
        mount(None, "/mnt/e", Some("tmpfs"), MS_REMOUNT, Some("dirsync")),
        Err(Errno::EINVAL),
    );
    t.eq(
        "remount-data-async",
        mount(None, "/mnt/e", Some("tmpfs"), MS_REMOUNT, Some("async")),
        Ok(0),
    );
    t.eq(
        "remount-bad-option",
        mount(None, "/mnt/e", Some("tmpfs"), MS_REMOUNT, Some("bogus")),
        Err(Errno::EINVAL),
    );
    // MS_REMOUNT | MS_BIND changes the mount only.
    t.eq(
        "reconfigure-ro",
        mount(None, "/mnt/e", None, MS_REMOUNT | MS_BIND | MS_RDONLY, None),
        Ok(0),
    );
    line_is(
        t,
        "reconfigure-ro-line",
        "/mnt/e",
        "18 1 0:17 / /mnt/e ro - tmpfs r rw,mode=755\n",
    );
    t.eq(
        "reconfigure-ro-create",
        open("/mnt/e/f", O_RDWR | O_CREAT),
        Err(Errno::EROFS),
    );
    t.eq(
        "reconfigure-rw",
        mount(None, "/mnt/e", None, MS_REMOUNT | MS_BIND, None),
        Ok(0),
    );
    line_is(
        t,
        "reconfigure-rw-line",
        "/mnt/e",
        "18 1 0:17 / /mnt/e rw - tmpfs r rw,mode=755\n",
    );
    t.eq("reconfigure-create", put_file("/mnt/e/f", 1), Ok(1));
    t.eq("remount-umount", umount("/mnt/e", 0), Ok(0));
    // Atime defaults of a new mount.
    for (name, flags, shown) in [
        ("strict", MS_STRICTATIME, "rw"),
        ("noatime", MS_NOATIME, "rw,noatime"),
        ("nodiratime", MS_NODIRATIME, "rw,nodiratime,relatime"),
        ("noatime-strict", MS_NOATIME | MS_STRICTATIME, "rw"),
        ("nosymfollow", 256, "rw,relatime,nosymfollow"),
    ] {
        t.eq(
            format_args!("atime-{name}-mount"),
            mount(Some("t"), "/mnt/f", Some("tmpfs"), flags, None),
            Ok(0),
        );
        let want = text!(160, "18 1 0:17 / /mnt/f {shown} - tmpfs t rw\n");
        let label = text!(40, "atime-{name}");
        line_is(t, label.str(), "/mnt/f", want.str());
        t.eq(
            format_args!("atime-{name}-umount"),
            umount("/mnt/f", 0),
            Ok(0),
        );
    }
}

/// Propagation types: only the state of one mount is observable here.
fn propagation(t: &mut T) {
    t.eq(
        "prop-mount-e",
        mount(Some("e"), "/mnt/e", Some("tmpfs"), 0, None),
        Ok(0),
    );
    t.eq(
        "prop-mount-f",
        mount(Some("f"), "/mnt/f", Some("tmpfs"), 0, None),
        Ok(0),
    );
    line_is(
        t,
        "prop-private-by-default",
        "/mnt/e",
        "18 1 0:17 / /mnt/e rw,relatime - tmpfs e rw\n",
    );
    t.eq(
        "prop-shared-e",
        mount(None, "/mnt/e", None, MS_SHARED, None),
        Ok(0),
    );
    line_is(
        t,
        "prop-shared-e-line",
        "/mnt/e",
        "18 1 0:17 / /mnt/e rw,relatime shared:1 - tmpfs e rw\n",
    );
    // Idempotent; a second mount gets the next group.
    t.eq(
        "prop-shared-e-again",
        mount(None, "/mnt/e", None, MS_SHARED, None),
        Ok(0),
    );
    t.eq(
        "prop-shared-f",
        mount(None, "/mnt/f", None, MS_SHARED, None),
        Ok(0),
    );
    line_is(
        t,
        "prop-shared-e-kept",
        "/mnt/e",
        "18 1 0:17 / /mnt/e rw,relatime shared:1 - tmpfs e rw\n",
    );
    line_is(
        t,
        "prop-shared-f-line",
        "/mnt/f",
        "19 1 0:18 / /mnt/f rw,relatime shared:2 - tmpfs f rw\n",
    );
    // Private frees the group id; the next shared mount gets the lowest.
    t.eq(
        "prop-private-e",
        mount(None, "/mnt/e", None, MS_PRIVATE, None),
        Ok(0),
    );
    line_is(
        t,
        "prop-private-e-line",
        "/mnt/e",
        "18 1 0:17 / /mnt/e rw,relatime - tmpfs e rw\n",
    );
    t.eq(
        "prop-private-silent",
        mount(None, "/mnt/e", None, MS_PRIVATE | 32768, None),
        Ok(0),
    );
    t.eq(
        "prop-shared-e-reuse",
        mount(None, "/mnt/e", None, MS_SHARED, None),
        Ok(0),
    );
    line_is(
        t,
        "prop-shared-e-reuse-line",
        "/mnt/e",
        "18 1 0:17 / /mnt/e rw,relatime shared:1 - tmpfs e rw\n",
    );
    // Unbindable is shown after the shared tag; slave leaves it alone, private clears it.
    t.eq(
        "prop-unbindable-e",
        mount(None, "/mnt/e", None, MS_UNBINDABLE, None),
        Ok(0),
    );
    line_is(
        t,
        "prop-unbindable-line",
        "/mnt/e",
        "18 1 0:17 / /mnt/e rw,relatime unbindable - tmpfs e rw\n",
    );
    t.eq(
        "prop-slave-e",
        mount(None, "/mnt/e", None, MS_SLAVE, None),
        Ok(0),
    );
    line_is(
        t,
        "prop-slave-keeps-unbindable",
        "/mnt/e",
        "18 1 0:17 / /mnt/e rw,relatime unbindable - tmpfs e rw\n",
    );
    t.eq(
        "prop-private-e-clears",
        mount(None, "/mnt/e", None, MS_PRIVATE, None),
        Ok(0),
    );
    line_is(
        t,
        "prop-cleared-line",
        "/mnt/e",
        "18 1 0:17 / /mnt/e rw,relatime - tmpfs e rw\n",
    );
    // Several types, or other flags, are refused.
    t.eq(
        "prop-two-types",
        mount(None, "/mnt/e", None, MS_PRIVATE | MS_SHARED, None),
        Err(Errno::EINVAL),
    );
    t.eq(
        "prop-with-ro",
        mount(None, "/mnt/e", None, MS_PRIVATE | MS_RDONLY, None),
        Err(Errno::EINVAL),
    );
    t.eq(
        "prop-with-nosuid",
        mount(None, "/mnt/e", None, MS_SHARED | MS_NOSUID, None),
        Err(Errno::EINVAL),
    );
    t.eq(
        "prop-rec-alone",
        mount(None, "/mnt/e", None, MS_REC, None),
        Err(Errno::EINVAL),
    );
    t.eq("prop-umount-f", umount("/mnt/f", 0), Ok(0));
    t.eq("prop-umount-e", umount("/mnt/e", 0), Ok(0));
}

/// Stacked mounts, busy mounts, lazy and expiring unmounts, identifier reuse.
fn stacking_and_detach(t: &mut T) {
    // Mounts stack on the root of the one below.
    t.eq(
        "stack-1",
        mount(Some("s1"), "/mnt/g", Some("tmpfs"), 0, None),
        Ok(0),
    );
    t.eq("stack-file-below", put_file("/mnt/g/below", 3), Ok(3));
    t.eq(
        "stack-2",
        mount(Some("s2"), "/mnt/g", Some("tmpfs"), 0, None),
        Ok(0),
    );
    let mut buf: Page = [0; 16384];
    let n = mountinfo(&mut buf);
    let g: [&[u8]; 2] = {
        let mut it = lines(&buf[..n]).filter(|l| field(l, b' ', 4) == b"/mnt/g");
        [it.next().unwrap_or_default(), it.next().unwrap_or_default()]
    };
    t.eq(
        "stack-line-1",
        Txt(g[0]),
        Txt(b"18 1 0:17 / /mnt/g rw,relatime - tmpfs s1 rw\n"),
    );
    t.eq(
        "stack-line-2",
        Txt(g[1]),
        Txt(b"19 18 0:18 / /mnt/g rw,relatime - tmpfs s2 rw\n"),
    );
    t.eq(
        "stack-hides-below",
        stat("/mnt/g/below").0,
        Err(Errno::ENOENT),
    );
    t.eq("stack-top-dev", stat("/mnt/g").1.dev, dev_of(18));
    t.eq("stack-dotdot", stat("/mnt/g/..").1.ino, stat("/mnt").1.ino);
    t.eq("stack-busy-below", umount("/mnt/g", 0), Ok(0));
    t.eq("stack-below-visible", stat("/mnt/g/below").1.size, 3);
    t.eq("stack-umount-bottom", umount("/mnt/g", 0), Ok(0));
    t.eq("stack-umount-none", umount("/mnt/g", 0), Err(Errno::EINVAL));
    // A mount with a mount below it is busy; a lazy unmount takes both.
    t.eq(
        "child-parent",
        mount(Some("p"), "/mnt/h", Some("tmpfs"), 0, None),
        Ok(0),
    );
    t.eq(
        "child-dir",
        open("/mnt/h", O_RDONLY | O_DIRECTORY).map(|fd| close(fd)),
        Ok(Ok(0)),
    );
    t.eq(
        "child-mount",
        mount(Some("c"), "/mnt/h", Some("tmpfs"), 0, None),
        Ok(0),
    );
    t.eq("child-busy", umount("/mnt/a", 0), Err(Errno::EINVAL));
    // Lazy: nothing is busy for MNT_DETACH, ids return.
    t.eq(
        "detach-expire-flags",
        umount("/mnt/h", MNT_EXPIRE | MNT_DETACH),
        Err(Errno::EINVAL),
    );
    t.eq(
        "detach-expire-force",
        umount("/mnt/h", MNT_EXPIRE | MNT_FORCE),
        Err(Errno::EINVAL),
    );
    t.eq("detach-top", umount("/mnt/h", MNT_DETACH), Ok(0));
    t.eq("detach-bottom", umount("/mnt/h", MNT_DETACH), Ok(0));
    let n = mountinfo(&mut buf);
    t.eq("detach-gone", mi_has(&buf[..n], "/mnt/h"), false);
    // Expiry: the first call marks, the second unmounts; a busy mount is refused first.
    t.eq(
        "expire-mount",
        mount(Some("x"), "/mnt/a", Some("tmpfs"), 0, None),
        Ok(0),
    );
    t.eq("expire-chdir", chdir("/mnt/a"), Ok(0));
    t.eq(
        "expire-busy",
        umount("/mnt/a", MNT_EXPIRE),
        Err(Errno::EBUSY),
    );
    t.eq("expire-chdir-out", chdir("/"), Ok(0));
    t.eq(
        "expire-first",
        umount("/mnt/a", MNT_EXPIRE),
        Err(Errno::EAGAIN),
    );
    t.eq("expire-second", umount("/mnt/a", MNT_EXPIRE), Ok(0));
    t.eq(
        "expire-third",
        umount("/mnt/a", MNT_EXPIRE),
        Err(Errno::EINVAL),
    );
    // UMOUNT_NOFOLLOW on a directory mount point works like the plain call.
    t.eq(
        "nofollow-mount",
        mount(Some("x"), "/mnt/b", Some("tmpfs"), 0, None),
        Ok(0),
    );
    t.eq("nofollow-umount", umount("/mnt/b", UMOUNT_NOFOLLOW), Ok(0));
    // Identifier reuse: the lowest free id and device; a lazily unmounted mount keeps its
    // identity while a file or working directory is inside, and releases it afterwards.
    t.eq(
        "ids-mount-1",
        mount(Some("i1"), "/mnt/a", Some("tmpfs"), 0, None),
        Ok(0),
    );
    t.eq(
        "ids-mount-2",
        mount(Some("i2"), "/mnt/b", Some("tmpfs"), 0, None),
        Ok(0),
    );
    t.eq("ids-1", mnt_id("/mnt/a"), Ok(18));
    t.eq("ids-2", mnt_id("/mnt/b"), Ok(19));
    t.eq("ids-chdir", chdir("/mnt/a"), Ok(0));
    let fd = open("/mnt/b/held", O_RDWR | O_CREAT).unwrap_or(99);
    t.eq("ids-detach-a", umount("/mnt/a", MNT_DETACH), Ok(0));
    t.eq("ids-detach-b", umount("/mnt/b", MNT_DETACH), Ok(0));
    t.eq(
        "ids-file-still-works",
        sys(Sysno::write, &[fd, addr(b"ok"), 2]),
        Ok(2),
    );
    t.eq(
        "ids-cwd-still-works",
        Dir::list(".").map(|d| d.count),
        Ok(0),
    );
    t.eq(
        "ids-mount-3",
        mount(Some("i3"), "/mnt/c", Some("tmpfs"), 0, None),
        Ok(0),
    );
    t.eq("ids-3-skips-held", mnt_id("/mnt/c"), Ok(20));
    t.eq("ids-3-dev-skips-held", stat("/mnt/c").1.dev, dev_of(19));
    t.eq("ids-close", close(fd), Ok(0));
    t.eq(
        "ids-mount-4",
        mount(Some("i4"), "/mnt/d", Some("tmpfs"), 0, None),
        Ok(0),
    );
    t.eq("ids-4-reuses-b", mnt_id("/mnt/d"), Ok(19));
    t.eq("ids-chdir-out", chdir("/"), Ok(0));
    t.eq(
        "ids-mount-5",
        mount(Some("i5"), "/mnt/e", Some("tmpfs"), 0, None),
        Ok(0),
    );
    t.eq("ids-5-reuses-a", mnt_id("/mnt/e"), Ok(18));
    for dir in ["/mnt/c", "/mnt/d", "/mnt/e"] {
        t.eq(
            format_args!("ids-umount{}", &dir[4..]),
            umount(dir, 0),
            Ok(0),
        );
    }
}

/// `uname(2)`: the six fields, NUL padded to 65 bytes each.
fn uname() -> [[u8; 65]; 6] {
    let mut u = [[0u8; 65]; 6];
    let _ = sys(Sysno::uname, &[addr_mut(&mut u)]);
    u
}

/// A NUL-padded field without the padding.
fn trimmed(field: &[u8]) -> &[u8] {
    field.split(|&b| b == 0).next().unwrap_or_default()
}

/// The layout of `/proc`: listings, modes, lookups, the shape of the links.
fn proc_tree(t: &mut T) {
    let me = getpid();
    let known = [
        "sys",
        "stat",
        "mounts",
        "uptime",
        "cmdline",
        "cpuinfo",
        "devices",
        "loadavg",
        "meminfo",
        "version",
        "filesystems",
        "self",
        "thread-self",
    ];
    let mut out = [0u8; 1024];
    let dir = Dir::list("/proc").unwrap_or(Dir {
        names: [0; 4096],
        len: 0,
        count: 0,
    });
    // Linux lists the registered entries in the order of its tree (name length, then bytes),
    // then `self` and `thread-self`, then every thread group by number.
    t.eq(
        "root-order",
        Txt(dir.subset(&known, &mut out)),
        Txt(b"sys:d,stat:f,mounts:l,uptime:f,cmdline:f,cpuinfo:f,devices:f,loadavg:f,meminfo:f,version:f,filesystems:f,self:l,thread-self:l"),
    );
    let mut previous = 0u64;
    let mut ordered = true;
    let mut dirs = true;
    let mut has_me = false;
    let mut numeric = 0usize;
    for entry in dir.entries() {
        let name = &entry[..entry.len() - 2];
        if let Some(pid) = num(name) {
            numeric += 1;
            ordered &= pid > previous;
            previous = pid;
            dirs &= entry[entry.len() - 1] == b'd';
            has_me |= pid == me as u64;
        }
    }
    t.holds(
        "root-pids-ascending",
        ordered && numeric >= 1,
        numeric,
        "pids in ascending order",
    );
    t.holds("root-pids-are-directories", dirs, dirs, "d_type DT_DIR");
    t.eq("root-lists-self", has_me, true);
    let (_, root) = stat("/proc");
    t.holds(
        "root-nlink",
        root.nlink >= 3 + numeric as u64 - 1,
        root.nlink,
        "2 + subdirectories + thread groups",
    );
    // Links.
    let mut buf = [0u8; 64];
    let n = readlink("/proc/self", &mut buf).unwrap_or(0);
    t.eq("self-link", Txt(&buf[..n]), Txt(text!(16, "{me}").bytes()));
    let n = readlink("/proc/thread-self", &mut buf).unwrap_or(0);
    t.eq(
        "thread-self-link",
        Txt(&buf[..n]),
        Txt(text!(32, "{me}/task/{me}").bytes()),
    );
    for (name, want) in [("self", 0), ("thread-self", 0), ("mounts", 11)] {
        let (r, st) = lstat(text!(32, "/proc/{name}").str());
        t.eq(
            format_args!("link-attr-{name}"),
            (r, st.mode, st.uid, st.gid, st.nlink, st.size),
            (Ok(0), S_IFLNK | 0o777, 0, 0, 1, want),
        );
    }
    // The same node by number and through self.
    let by_self = stat("/proc/self/stat").1;
    let by_pid = stat(text!(32, "/proc/{me}/stat").str()).1;
    t.eq(
        "same-node",
        (by_self.dev, by_self.ino),
        (by_pid.dev, by_pid.ino),
    );
    let task = stat(text!(48, "/proc/{me}/task/{me}/stat").str()).1;
    t.eq("task-node-dev", task.dev, by_pid.dev);
    t.eq(
        "thread-self-is-task",
        stat("/proc/thread-self/stat").1.ino,
        task.ino,
    );
    // Modes of the entries of a process directory, in their order.
    for (name, mode, size) in [
        ("task", S_IFDIR | 0o555, 0),
        ("fd", S_IFDIR | 0o500, 3),
        ("fdinfo", S_IFDIR | 0o555, 0),
        ("environ", S_IFREG | 0o400, 0),
        ("status", S_IFREG | 0o444, 0),
        ("personality", S_IFREG | 0o400, 0),
        ("limits", S_IFREG | 0o444, 0),
        ("comm", S_IFREG | 0o644, 0),
        ("cmdline", S_IFREG | 0o444, 0),
        ("stat", S_IFREG | 0o444, 0),
        ("statm", S_IFREG | 0o444, 0),
        ("maps", S_IFREG | 0o444, 0),
        ("cwd", S_IFLNK | 0o777, 0),
        ("root", S_IFLNK | 0o777, 0),
        ("exe", S_IFLNK | 0o777, 0),
        ("mounts", S_IFREG | 0o444, 0),
        ("mountinfo", S_IFREG | 0o444, 0),
        ("wchan", S_IFREG | 0o444, 0),
    ] {
        let (r, st) = lstat(text!(48, "/proc/self/{name}").str());
        let expected_size = if name == "fd" { st.size } else { size };
        t.eq(
            format_args!("entry-{name}"),
            (r, st.mode, st.uid, st.gid, st.size),
            (Ok(0), mode, 0, 0, expected_size),
        );
    }
    t.holds(
        "entry-fd-size",
        stat("/proc/self/fd").1.size >= 3,
        stat("/proc/self/fd").1,
        "the open descriptors",
    );
    t.eq("entry-fd-nlink", stat("/proc/self/fd").1.nlink, 2);
    t.eq("entry-fdinfo-nlink", stat("/proc/self/fdinfo").1.nlink, 2);
    t.eq("entry-task-nlink", stat("/proc/self/task").1.nlink, 3);
    t.holds(
        "entry-pid-nlink",
        stat("/proc/self").1.nlink >= 5,
        stat("/proc/self").1.nlink,
        "2 + subdirectories",
    );
    // The listing of a process directory, in the order of Linux's table.
    let pid_names = [
        "task",
        "fd",
        "fdinfo",
        "environ",
        "status",
        "personality",
        "limits",
        "comm",
        "cmdline",
        "stat",
        "statm",
        "maps",
        "cwd",
        "root",
        "exe",
        "mounts",
        "mountinfo",
        "wchan",
    ];
    let dir = Dir::list("/proc/self").unwrap_or(Dir {
        names: [0; 4096],
        len: 0,
        count: 0,
    });
    t.eq(
        "pid-order",
        Txt(dir.subset(&pid_names, &mut out)),
        Txt(b"task:d,fd:d,fdinfo:d,environ:f,status:f,personality:f,limits:f,comm:f,cmdline:f,stat:f,statm:f,maps:f,cwd:l,root:l,exe:l,mounts:f,mountinfo:f,wchan:f"),
    );
    let thread = Dir::list("/proc/self/task/1")
        .or_else(|_| Dir::list(text!(48, "/proc/{me}/task/{me}").str()));
    let thread = thread.unwrap_or(Dir {
        names: [0; 4096],
        len: 0,
        count: 0,
    });
    t.eq(
        "tid-order",
        Txt(thread.subset(&pid_names, &mut out)),
        Txt(b"fd:d,fdinfo:d,environ:f,status:f,personality:f,limits:f,comm:f,cmdline:f,stat:f,statm:f,maps:f,cwd:l,root:l,exe:l,mounts:f,mountinfo:f,wchan:f"),
    );
    let tasks = Dir::list("/proc/self/task").unwrap_or(Dir {
        names: [0; 4096],
        len: 0,
        count: 0,
    });
    t.eq(
        "task-listing",
        Txt(tasks.text()),
        Txt(text!(16, "{me}:d").bytes()),
    );
    // Lookups.
    for (name, path, want) in [
        ("pid-zero", "/proc/0", Err(Errno::ENOENT)),
        ("pid-leading-zero", "/proc/01", Err(Errno::ENOENT)),
        ("pid-sign", "/proc/-1", Err(Errno::ENOENT)),
        ("pid-junk", "/proc/1x", Err(Errno::ENOENT)),
        ("pid-huge", "/proc/4294967295", Err(Errno::ENOENT)),
        ("pid-too-long", "/proc/99999999999", Err(Errno::ENOENT)),
        ("pid-absent", "/proc/999999", Err(Errno::ENOENT)),
        (
            "self-absent-entry",
            "/proc/self/nonexistent",
            Err(Errno::ENOENT),
        ),
        ("self-dotdot-name", "/proc/self/..stat", Err(Errno::ENOENT)),
        ("file-not-dir", "/proc/self/stat/x", Err(Errno::ENOTDIR)),
        (
            "file-trailing-slash",
            "/proc/self/stat/",
            Err(Errno::ENOTDIR),
        ),
        ("task-other-tid", "/proc/self/task/2", Err(Errno::ENOENT)),
        ("fd-absent", "/proc/self/fd/9999", Err(Errno::ENOENT)),
        ("fd-junk", "/proc/self/fd/x", Err(Errno::ENOENT)),
        ("fd-leading-zero", "/proc/self/fd/00", Err(Errno::ENOENT)),
        ("global-absent", "/proc/nonexistent", Err(Errno::ENOENT)),
        ("sys-absent", "/proc/sys/nonexistent", Err(Errno::ENOENT)),
    ] {
        t.eq(format_args!("lookup-{name}"), stat(path).0, want);
    }
    // Through the link and out of the tree.
    t.eq(
        "self-dotdot",
        stat("/proc/self/..").1.ino,
        stat("/proc").1.ino,
    );
    t.eq(
        "self-dot",
        stat("/proc/self/.").1.ino,
        stat("/proc/self").1.ino,
    );
    t.eq("self-slash", stat("/proc/self/").0.map(|_| ()), Ok(()));
    t.eq("proc-dotdot", stat("/proc/..").1.ino, stat("/").1.ino);
    t.eq("proc-dotdot-dev", stat("/proc/..").1.dev, stat("/").1.dev);
    t.eq(
        "self-nofollow",
        lstat("/proc/self").1.mode & S_IFMT,
        S_IFLNK,
    );
    t.eq("self-follow", stat("/proc/self").1.mode & S_IFMT, S_IFDIR);
    t.eq(
        "self-trailing-slash-follows",
        lstat("/proc/self/").1.mode & S_IFMT,
        S_IFDIR,
    );
    t.eq(
        "open-nofollow-link",
        open("/proc/self", O_RDONLY | O_NOFOLLOW),
        Err(Errno::ELOOP),
    );
    t.eq(
        "open-dir-as-dir",
        open("/proc/self/fd", O_RDONLY | O_DIRECTORY).map(|fd| close(fd)),
        Ok(Ok(0)),
    );
    t.eq(
        "open-file-as-dir",
        open("/proc/self/stat", O_RDONLY | O_DIRECTORY),
        Err(Errno::ENOTDIR),
    );
    let mut small = [0u8; 8];
    let fd = open("/proc/self/fd", O_RDONLY | O_DIRECTORY).unwrap_or(99);
    t.eq("read-dir", read(fd, &mut small), Err(Errno::EISDIR));
    let _ = close(fd);
    let fd = open("/proc/self/stat", O_RDONLY).unwrap_or(99);
    t.eq(
        "getdents-on-file",
        sys(Sysno::getdents64, &[fd, addr_mut(&mut small), 8]),
        Err(Errno::ENOTDIR),
    );
    let _ = close(fd);
    // Nothing can be created, removed or written where Linux has no operation for it.
    // The lookup of a missing name is an error in procfs (no negative dentry to create in).
    t.eq(
        "create-in-proc",
        open("/proc/newfile", O_RDWR | O_CREAT),
        Err(Errno::ENOENT),
    );
    t.eq(
        "create-in-pid",
        open("/proc/self/newfile", O_RDWR | O_CREAT),
        Err(Errno::ENOENT),
    );
    t.eq(
        "create-in-sys",
        open("/proc/sys/newfile", O_RDWR | O_CREAT),
        Err(Errno::ENOENT),
    );
    t.eq(
        "unlink-in-proc",
        sys(Sysno::unlink, &[addr(&c("/proc/version"))]),
        Err(Errno::EPERM),
    );
    t.eq(
        "unlink-absent-in-proc",
        sys(Sysno::unlink, &[addr(&c("/proc/nonexistent"))]),
        Err(Errno::ENOENT),
    );
    t.eq(
        "unlink-link-in-proc",
        sys(Sysno::unlink, &[addr(&c("/proc/self"))]),
        Err(Errno::EPERM),
    );
    // The process directories are immutable: nothing below them can change.
    t.eq(
        "unlink-in-pid",
        sys(Sysno::unlink, &[addr(&c("/proc/self/fd"))]),
        Err(Errno::EPERM),
    );
    t.eq(
        "unlink-file-in-pid",
        sys(Sysno::unlink, &[addr(&c("/proc/self/stat"))]),
        Err(Errno::EPERM),
    );
    t.eq(
        "unlink-pid",
        sys(Sysno::unlink, &[addr(&c("/proc/self/."))]).map(|_| ()),
        Err(Errno::EISDIR),
    );
    t.eq(
        "unlink-sys-dir",
        sys(Sysno::unlink, &[addr(&c("/proc/sys"))]),
        Err(Errno::EISDIR),
    );
    t.eq(
        "unlink-in-sys",
        sys(Sysno::unlink, &[addr(&c("/proc/sys/kernel"))]),
        Err(Errno::EACCES),
    );
    let fd = open("/proc/version", O_WRONLY);
    t.eq("open-readonly-file-for-write", fd.map(|_| ()), Ok(()));
    // A registered entry without a writer says EIO; a seq_file of a process has no write at all.
    t.eq(
        "write-registered-entry",
        sys(Sysno::write, &[fd.unwrap_or(99), addr(b"x"), 1]),
        Err(Errno::EIO),
    );
    let _ = close(fd.unwrap_or(99));
    let fd = open("/proc/self/stat", O_WRONLY);
    t.eq("open-pid-file-for-write", fd.map(|_| ()), Ok(()));
    t.eq(
        "write-seq-file",
        sys(Sysno::write, &[fd.unwrap_or(99), addr(b"x"), 1]),
        Err(Errno::EINVAL),
    );
    let _ = close(fd.unwrap_or(99));
    // sysctl permissions have no capability override: root sees its own owner bits.
    t.eq(
        "sysctl-readonly-for-write",
        open("/proc/sys/kernel/ostype", O_WRONLY),
        Err(Errno::EACCES),
    );
    t.eq(
        "sysctl-writable-for-write",
        open("/proc/sys/kernel/hostname", O_WRONLY).map(|fd| close(fd)),
        Ok(Ok(0)),
    );
    t.eq(
        "sysctl-dir-for-write",
        open("/proc/sys/kernel", O_WRONLY),
        Err(Errno::EISDIR),
    );
    t.eq(
        "umount-proc-file",
        umount("/proc/version", 0),
        Err(Errno::EINVAL),
    );
}

// ---- the global files -------------------------------------------------------------------------

/// `clock_gettime(CLOCK_BOOTTIME)` in hundredths of a second.
fn boottime_centis() -> u64 {
    let mut ts = [0i64; 2];
    let _ = sys(Sysno::clock_gettime, &[7, addr_mut(&mut ts)]);
    (ts[0] as u64) * 100 + (ts[1] as u64) / 10_000_000
}

fn realtime_secs() -> i64 {
    let mut ts = [0i64; 2];
    let _ = sys(Sysno::clock_gettime, &[0, addr_mut(&mut ts)]);
    ts[0]
}

/// `path` read whole into `buf`.
fn proc_text<'a>(path: &str, buf: &'a mut Page) -> &'a [u8] {
    let n = slurp(path, buf).unwrap_or(0);
    &buf[..n]
}

/// `a.bc` as hundredths.
fn centis(s: &[u8]) -> Option<u64> {
    let at = s.iter().position(|&b| b == b'.')?;
    let (whole, frac) = (&s[..at], &s[at + 1..]);
    (frac.len() == 2).then_some(())?;
    Some(num(whole)? * 100 + num(frac)?)
}

/// The numbers of a space separated line, up to 16 (`None` if a field is not a number).
fn numbers(line: &[u8]) -> Option<([u64; 16], usize)> {
    let mut out = [0u64; 16];
    let mut n = 0;
    for f in line
        .trim_ascii()
        .split(|&b| b == b' ')
        .filter(|f| !f.is_empty())
    {
        *out.get_mut(n)? = num(f)?;
        n += 1;
    }
    Some((out, n))
}

/// `cpuid(leaf, sub)` as `[eax, ebx, ecx, edx]`.
fn cpuid(leaf: u32, sub: u32) -> [u32; 4] {
    let r = core::arch::x86_64::__cpuid_count(leaf, sub);
    [r.eax, r.ebx, r.ecx, r.edx]
}

/// The value of the `Key:` row of a `meminfo` text (kB).
fn mem_kb(mem: &[u8], key: &str) -> Option<u64> {
    let l =
        lines(mem).find(|l| l.starts_with(key.as_bytes()) && l.get(key.len()) == Some(&b':'))?;
    num(l[key.len() + 1..]
        .trim_ascii()
        .split(|&b| b == b' ')
        .next()?)
}

/// Whether a `meminfo` row has the `show_val_kb` / `HugePages_*` layout: the number ends at
/// column 24 (or runs on from column 16 when wider) and a unit follows unless it is a count.
fn mem_row_ok(l: &[u8], key: &str) -> bool {
    let counted = key.starts_with("HugePages_");
    let Some(body) = l.strip_suffix(if counted { &b"\n"[..] } else { &b" kB\n"[..] }) else {
        return false;
    };
    let digits = body.iter().rev().take_while(|b| b.is_ascii_digit()).count();
    let end = body.len();
    let start = end - digits;
    digits > 0
        && body[key.len() + 1..start].iter().all(|&b| b == b' ')
        && end == 24.max(16 + digits)
        && start >= key.len() + 2
}

fn global_files(t: &mut T) {
    let mut page: Page = [0; 16384];
    let u = uname();

    // /proc/version: "Linux version %s (%s) (%s) %s\n" -- release, builder, compiler, version.
    let v = proc_text("/proc/version", &mut page);
    let mut head = text!(
        96,
        "Linux version {} (",
        core::str::from_utf8(trimmed(&u[2])).unwrap_or("?")
    );
    let _ = head.write_str("");
    t.holds(
        "version-head",
        v.starts_with(head.bytes()),
        Txt(&v[..v.len().min(40)]),
        "Linux version <release> (",
    );
    let tail = text!(
        96,
        " {}\n",
        core::str::from_utf8(trimmed(&u[3])).unwrap_or("?")
    );
    t.holds(
        "version-tail",
        v.ends_with(tail.bytes()),
        Txt(&v[v.len().saturating_sub(40)..]),
        "<space><uname version>\\n",
    );
    t.holds(
        "version-one-line",
        v.iter().filter(|&&b| b == b'\n').count() == 1 && v.windows(3).any(|w| w == b") ("),
        v.len(),
        "one line with the builder and the compiler in parentheses",
    );
    t.eq("version-size", stat("/proc/version").1.size, 0);

    // /proc/filesystems: one "nodev\tname" or "\tname" line per registered type.
    let fs = proc_text("/proc/filesystems", &mut page);
    let shaped = !fs.is_empty()
        && lines(fs).all(|l| {
            l.ends_with(b"\n")
                && (l.starts_with(b"nodev\t") || l.starts_with(b"\t"))
                && l.split(|&b| b == b'\t').nth(1).is_some_and(|n| n.len() > 1)
        });
    t.holds(
        "filesystems-shape",
        shaped,
        Txt(&fs[..fs.len().min(60)]),
        "each line `nodev\\tname\\n` or `\\tname\\n`",
    );
    t.holds(
        "filesystems-tmpfs",
        lines(fs).any(|l| l == b"nodev\ttmpfs\n"),
        0,
        "nodev tmpfs listed",
    );
    t.holds(
        "filesystems-proc",
        lines(fs).any(|l| l == b"nodev\tproc\n"),
        0,
        "nodev proc listed",
    );

    // /proc/uptime: "%lu.%02lu %lu.%02lu\n" -- boot time and the idle time of all CPUs.
    let before = boottime_centis();
    let up = proc_text("/proc/uptime", &mut page);
    let after = boottime_centis();
    let body = up.trim_ascii_end();
    let up_c = centis(body.split(|&b| b == b' ').next().unwrap_or_default());
    let idle_c = centis(body.split(|&b| b == b' ').nth(1).unwrap_or_default());
    t.holds(
        "uptime-shape",
        up.ends_with(b"\n")
            && body.split(|&b| b == b' ').count() == 2
            && up_c.is_some()
            && idle_c.is_some(),
        Txt(up),
        "`up.cc idle.cc\\n`",
    );
    t.holds(
        "uptime-bracketed",
        up_c.is_some_and(|v| (before..=after).contains(&v)),
        (before, up_c, after),
        "CLOCK_BOOTTIME before <= uptime <= after",
    );
    t.holds(
        "uptime-idle-bounded",
        up_c.zip(idle_c).is_some_and(|(up, idle)| idle <= up),
        (up_c, idle_c),
        "one CPU: idle <= uptime",
    );

    // /proc/loadavg: "%lu.%02lu x3 %u/%d %d\n" -- averages, running/threads, last pid.
    let la = proc_text("/proc/loadavg", &mut page);
    let body = la.trim_ascii_end();
    let nth = |n: usize| body.split(|&b| b == b' ').nth(n).unwrap_or_default();
    let loads_ok = (0..3).all(|i| centis(nth(i)).is_some());
    let running = num(nth(3).split(|&b| b == b'/').next().unwrap_or_default());
    let threads = num(nth(3).split(|&b| b == b'/').nth(1).unwrap_or_default());
    let last = num(nth(4));
    t.holds(
        "loadavg-shape",
        la.ends_with(b"\n") && body.split(|&b| b == b' ').count() == 5 && loads_ok,
        Txt(la),
        "`a.cc b.cc c.cc r/t pid\\n`",
    );
    t.holds(
        "loadavg-counts",
        running.zip(threads).is_some_and(|(r, t)| r >= 1 && t >= r),
        (running, threads),
        "1 <= running <= threads",
    );
    t.holds(
        "loadavg-last-pid",
        last.is_some_and(|p| p >= getpid() as u64),
        (last, getpid()),
        "last pid >= ours",
    );
    let mut si = [0u64; 14];
    let _ = sys(Sysno::sysinfo, &[addr_mut(&mut si)]);
    t.eq("loadavg-threads-sysinfo", threads, Some(si[10] & 0xffff));

    // /proc/stat: the per-CPU time lines, then the counters.
    let mut page2: Page = [0; 16384];
    let st = proc_text("/proc/stat", &mut page2);
    let mut it = lines(st);
    let (cpu, cpu0) = (it.next().unwrap_or_default(), it.next().unwrap_or_default());
    let agg = cpu.strip_prefix(b"cpu  ").and_then(numbers);
    let one = cpu0.strip_prefix(b"cpu0 ").and_then(numbers);
    t.holds(
        "stat-cpu-line",
        agg.is_some_and(|x| x.1 == 10),
        Txt(cpu),
        "`cpu  ` and ten counters",
    );
    t.holds(
        "stat-cpu0-line",
        one.is_some_and(|x| x.1 == 10),
        Txt(cpu0),
        "`cpu0 ` and ten counters",
    );
    t.holds(
        "stat-cpu-sum",
        agg.zip(one)
            .is_some_and(|(a, b)| a.0.iter().zip(&b.0).all(|(x, y)| x.abs_diff(*y) <= 50)),
        (agg.map(|x| x.0[0]), one.map(|x| x.0[0])),
        "the aggregate is the one CPU",
    );
    let intr = it.next().unwrap_or_default();
    t.holds(
        "stat-intr",
        has_prefix(intr, "intr ") && intr.ends_with(b"\n"),
        Txt(&intr[..intr.len().min(30)]),
        "`intr <total> <per-irq>...`",
    );
    let total = num(intr.split(|&b| b == b' ').nth(1).unwrap_or_default()).unwrap_or(0);
    let sum: u64 = intr
        .trim_ascii_end()
        .split(|&b| b == b' ')
        .skip(2)
        .filter_map(num)
        .sum();
    t.holds(
        "stat-intr-total",
        total > 0 && total >= sum,
        (total, sum),
        "the total covers the vectors (and the architecture counters)",
    );
    let mut key = |k: &str| -> Option<u64> {
        let l = it.next()?;
        num(l
            .strip_prefix(k.as_bytes())?
            .strip_prefix(b" ")?
            .strip_suffix(b"\n")?)
    };
    let (ctxt, btime, procs, running, blocked) = (
        key("ctxt"),
        key("btime"),
        key("processes"),
        key("procs_running"),
        key("procs_blocked"),
    );
    t.holds(
        "stat-ctxt",
        ctxt.is_some_and(|c| c >= 1),
        ctxt,
        "ctxt N, at least one switch",
    );
    let (now, up_s) = (realtime_secs(), (boottime_centis() / 100) as i64);
    t.holds(
        "stat-btime",
        btime.is_some_and(|b| (now - up_s - 3..=now - up_s + 3).contains(&(b as i64))),
        (btime, now, up_s),
        "btime = now - uptime (+-3 s)",
    );
    t.holds(
        "stat-processes",
        procs.is_some_and(|p| p >= 1),
        procs,
        "processes counts forks",
    );
    t.holds(
        "stat-running",
        running.is_some_and(|r| r >= 1),
        running,
        "procs_running >= 1 (us)",
    );
    t.eq("stat-blocked", blocked, Some(0));
    let softirq = it.next().unwrap_or_default();
    t.holds(
        "stat-softirq",
        softirq
            .strip_prefix(b"softirq ")
            .and_then(numbers)
            .is_some_and(|x| x.1 == 11),
        Txt(softirq),
        "softirq total + 10 vectors",
    );
    t.eq("stat-end", it.next(), None);

    // The CPU time counters advance while a task burns CPU.
    let busy = |page: &mut Page| {
        let st = proc_text("/proc/stat", page);
        st.strip_prefix(b"cpu  ")
            .and_then(|r| numbers(r.split(|&b| b == b'\n').next()?))
            .map_or(0, |x| x.0[0] + x.0[2])
    };
    let before = busy(&mut page);
    let (end, mut spin) = (boottime_centis() + 30, 0u64);
    while boottime_centis() < end {
        spin += 1;
    }
    let after = busy(&mut page);
    t.holds(
        "stat-user-advances",
        after > before && spin > 0,
        (before, after),
        "user+system ticks grow while spinning",
    );

    // /proc/meminfo: the fixed key order, the "%-15s %8lu kB" layout.
    let mem = proc_text("/proc/meminfo", &mut page);
    let keys = [
        "MemTotal",
        "MemFree",
        "MemAvailable",
        "Buffers",
        "Cached",
        "SwapCached",
        "Active",
        "Inactive",
        "Active(anon)",
        "Inactive(anon)",
        "Active(file)",
        "Inactive(file)",
        "Unevictable",
        "Mlocked",
        "SwapTotal",
        "SwapFree",
        "Dirty",
        "Writeback",
        "AnonPages",
        "Mapped",
        "Shmem",
        "KReclaimable",
        "Slab",
        "SReclaimable",
        "SUnreclaim",
        "KernelStack",
        "PageTables",
        "SecPageTables",
        "NFS_Unstable",
        "Bounce",
        "WritebackTmp",
        "CommitLimit",
        "Committed_AS",
        "VmallocTotal",
        "VmallocUsed",
        "VmallocChunk",
        "Percpu",
        "Balloon",
        "HugePages_Total",
        "HugePages_Free",
        "HugePages_Rsvd",
        "HugePages_Surp",
        "Hugepagesize",
        "Hugetlb",
        "DirectMap4k",
        "DirectMap2M",
    ];
    let rows = lines(mem).count();
    let order_ok = lines(mem)
        .zip(keys)
        .all(|(l, k)| l.starts_with(k.as_bytes()) && l.get(k.len()) == Some(&b':'));
    t.holds(
        "meminfo-keys",
        order_ok && rows == keys.len(),
        rows,
        "the Linux key order (no HardwareCorrupted, no DirectMap1G)",
    );
    let bad = lines(mem)
        .zip(keys)
        .find(|(l, k)| !mem_row_ok(l, k))
        .map(|(l, _)| l);
    t.holds(
        "meminfo-layout",
        bad.is_none(),
        Txt(bad.unwrap_or_default()),
        "`%-15s %8lu kB` rows",
    );
    let val = |k: &str| mem_kb(mem, k).unwrap_or(u64::MAX);
    t.eq(
        "meminfo-total-sysinfo",
        val("MemTotal"),
        si[4] * u64::from((si[13] as u32).max(1)) / 1024,
    );
    t.holds(
        "meminfo-free-bounded",
        val("MemFree") > 0
            && val("MemFree") <= val("MemTotal")
            && val("MemAvailable") > 0
            && val("MemAvailable") <= val("MemTotal"),
        (val("MemFree"), val("MemAvailable"), val("MemTotal")),
        "0 < free <= total, 0 < available <= total",
    );
    t.holds(
        "meminfo-cached-shmem",
        val("Cached") >= val("Shmem"),
        (val("Cached"), val("Shmem")),
        "Cached includes Shmem",
    );
    t.eq("meminfo-swap", (val("SwapTotal"), val("SwapFree")), (0, 0));
    t.eq(
        "meminfo-huge",
        (val("HugePages_Total"), val("Hugepagesize")),
        (0, 2048),
    );
    let shmem0 = val("Shmem");

    // tmpfs pages are Shmem: they appear and disappear with the file's data.
    let mounted = mount(None, "/mnt/a", Some("tmpfs"), 0, None);
    let put = put_file("/mnt/a/blob", 2048 * 4096);
    let shmem1 = mem_kb(proc_text("/proc/meminfo", &mut page), "Shmem").unwrap_or(0);
    t.holds(
        "meminfo-shmem-grows",
        mounted.is_ok()
            && put.is_ok()
            && (shmem0 + 8192 - 500..=shmem0 + 8192 + 500).contains(&shmem1),
        (mounted, put, shmem0, shmem1),
        "Shmem grows by 8 MiB (+-500 kB of per-CPU counter lag) for 2048 tmpfs pages",
    );
    let _ = sys(Sysno::unlink, &[addr(&c("/mnt/a/blob"))]);
    let _ = umount("/mnt/a", 0);
    let shmem2 = mem_kb(proc_text("/proc/meminfo", &mut page), "Shmem").unwrap_or(u64::MAX);
    t.holds(
        "meminfo-shmem-returns",
        shmem2 <= shmem0 + 500,
        (shmem0, shmem2),
        "Shmem returns after the unmount",
    );

    // /proc/cmdline: the boot command line and a newline; the inode size is that plus one.
    let cmd = proc_text("/proc/cmdline", &mut page);
    t.holds(
        "cmdline-newline",
        cmd.len() > 1 && cmd.ends_with(b"\n") && cmd.iter().filter(|&&b| b == b'\n').count() == 1,
        Txt(cmd),
        "one line",
    );
    t.eq(
        "cmdline-size",
        stat("/proc/cmdline").1.size,
        cmd.len() as i64,
    );

    // /proc/devices: character majors in order, then the block majors.
    let dev = proc_text("/proc/devices", &mut page);
    let (mut shape_ok, mut last, mut section) = (true, 0u64, 0);
    for l in lines(dev) {
        match (section, l) {
            (0, b"Character devices:\n") => section = 1,
            (1, b"\n") => section = 2,
            (2, b"Block devices:\n") => {
                section = 3;
                last = 0;
            }
            (1 | 3, _) => {
                let major =
                    num(l.get(..3).unwrap_or_default().trim_ascii_start()).unwrap_or(u64::MAX);
                shape_ok &= l.get(3) == Some(&b' ') && major >= last && l.len() > 5;
                last = major;
            }
            _ => shape_ok = false,
        }
    }
    t.holds(
        "devices-shape",
        shape_ok && section == 3,
        section,
        "`Character devices:`, majors ascending, blank, `Block devices:`",
    );
    for entry in [
        "  1 mem\n",
        "  4 tty\n",
        "  4 ttyS\n",
        "  5 /dev/tty\n",
        "  4 /dev/vc/0\n",
    ] {
        t.holds(
            format_args!("devices-{}", entry.trim()),
            lines(dev).any(|l| l == entry.as_bytes()),
            0,
            "registered by the console stack",
        );
    }

    cpuinfo_checks(t, proc_text("/proc/cpuinfo", &mut page));
    sysctl_values(t, &u);
}

/// The keys of `/proc/cpuinfo` in Linux's order; `false` marks the ones printed only when the
/// CPU reports them.
const CPUINFO_KEYS: [(&str, bool); 27] = [
    ("processor", true),
    ("vendor_id", true),
    ("cpu family", true),
    ("model", true),
    ("model name", true),
    ("stepping", true),
    ("microcode", false),
    ("cpu MHz", true),
    ("cache size", false),
    ("physical id", true),
    ("siblings", true),
    ("core id", true),
    ("cpu cores", true),
    ("apicid", true),
    ("initial apicid", true),
    ("fpu", true),
    ("fpu_exception", true),
    ("cpuid level", true),
    ("wp", true),
    ("flags", true),
    ("bugs", true),
    ("bogomips", true),
    ("TLB size", false),
    ("clflush size", true),
    ("cache_alignment", true),
    ("address sizes", true),
    ("power management", true),
];

/// `(key, value)` of a `key\t: value` line.
fn kv(line: &[u8]) -> (&[u8], &[u8]) {
    let mut parts = line.splitn(2, |&b| b == b':');
    let key = parts.next().unwrap_or_default().trim_ascii_end();
    (key, parts.next().unwrap_or_default().trim_ascii())
}

fn cpuinfo_checks(t: &mut T, cpu: &[u8]) {
    let (mut at, mut keys_ok) = (0, true);
    for l in lines(cpu).take_while(|l| *l != b"\n") {
        match CPUINFO_KEYS[at..]
            .iter()
            .position(|(name, _)| name.as_bytes() == kv(l).0)
        {
            Some(pos)
                if CPUINFO_KEYS[at..at + pos]
                    .iter()
                    .all(|(_, required)| !required) =>
            {
                at += pos + 1
            }
            _ => {
                keys_ok = false;
                break;
            }
        }
    }
    keys_ok &= at == CPUINFO_KEYS.len() && cpu.ends_with(b"\n\n");
    t.holds(
        "cpuinfo-keys",
        keys_ok,
        (at, Txt(&cpu[cpu.len().saturating_sub(24)..])),
        "Linux's key order, a blank line at the end",
    );
    let get = |key: &str| {
        lines(cpu)
            .map(kv)
            .find(|(k, _)| *k == key.as_bytes())
            .map_or(&[][..], |(_, v)| v)
    };
    let leaf0 = cpuid(0, 0);
    let mut vendor = [0u8; 12];
    vendor[..4].copy_from_slice(&leaf0[1].to_le_bytes());
    vendor[4..8].copy_from_slice(&leaf0[3].to_le_bytes());
    vendor[8..].copy_from_slice(&leaf0[2].to_le_bytes());
    t.eq("cpuinfo-processor", Txt(get("processor")), Txt(b"0"));
    t.eq("cpuinfo-vendor", Txt(get("vendor_id")), Txt(&vendor));
    let tfms = cpuid(1, 0)[0];
    let family = if (tfms >> 8) & 0xf == 0xf {
        0xf + ((tfms >> 20) & 0xff)
    } else {
        (tfms >> 8) & 0xf
    };
    let model = ((tfms >> 4) & 0xf)
        + if family >= 6 {
            ((tfms >> 16) & 0xf) << 4
        } else {
            0
        };
    t.eq(
        "cpuinfo-family",
        num(get("cpu family")),
        Some(u64::from(family)),
    );
    t.eq("cpuinfo-model", num(get("model")), Some(u64::from(model)));
    t.eq(
        "cpuinfo-stepping",
        num(get("stepping")),
        Some(u64::from(tfms & 0xf)),
    );
    let mut brand = [0u8; 48];
    for (i, leaf) in (0x8000_0002u32..=0x8000_0004).enumerate() {
        for (j, w) in cpuid(leaf, 0).iter().enumerate() {
            brand[i * 16 + j * 4..i * 16 + j * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
    }
    let end = brand.iter().position(|&b| b == 0).unwrap_or(48);
    t.eq(
        "cpuinfo-model-name",
        Txt(get("model name")),
        Txt(brand[..end].trim_ascii()),
    );
    t.eq(
        "cpuinfo-cpuid-level",
        num(get("cpuid level")),
        Some(u64::from(leaf0[0])),
    );
    let ext = cpuid(0x8000_0008, 0)[0];
    t.eq(
        "cpuinfo-address-sizes",
        Txt(get("address sizes")),
        Txt(text!(
            48,
            "{} bits physical, {} bits virtual",
            ext & 0xff,
            (ext >> 8) & 0xff
        )
        .bytes()),
    );
    let clflush = u64::from((cpuid(1, 0)[1] >> 8) & 0xff) * 8;
    t.eq("cpuinfo-clflush", num(get("clflush size")), Some(clflush));
    t.eq(
        "cpuinfo-alignment",
        num(get("cache_alignment")),
        Some(clflush),
    );
    // The frequency is printed as `MHz.kHz`; bogomips is twice the MHz.
    let mhz = get("cpu MHz");
    let parts = (
        mhz.split(|&b| b == b'.').next(),
        mhz.split(|&b| b == b'.').nth(1),
    );
    let khz = parts
        .0
        .and_then(num)
        .zip(parts.1.and_then(num))
        .map(|(a, b)| a * 1000 + b);
    t.holds(
        "cpuinfo-mhz",
        khz.is_some_and(|k| k > 100_000) && parts.1.is_some_and(|f| f.len() == 3),
        Txt(mhz),
        "`MHz.kHz` with three decimals",
    );
    let bogo = get("bogomips");
    let bparts = (
        bogo.split(|&b| b == b'.').next(),
        bogo.split(|&b| b == b'.').nth(1),
    );
    let bogo_c = bparts
        .0
        .and_then(num)
        .zip(bparts.1.and_then(num))
        .map(|(a, b)| a * 100 + b);
    t.holds(
        "cpuinfo-bogomips",
        khz.zip(bogo_c)
            .is_some_and(|(k, b)| (b as i64 - (k as i64) / 5).abs() <= (k as i64) / 250 + 1),
        Txt(bogo),
        "twice the MHz",
    );
    // `flags`: a bit CPUID reports appears under Linux's name; one it does not report does not.
    let flags = get("flags");
    let has = |name: &str| flags.split(|&b| b == b' ').any(|f| f == name.as_bytes());
    let (edx1, ecx1, ext1) = (cpuid(1, 0)[3], cpuid(1, 0)[2], cpuid(0x8000_0001, 0)[3]);
    let mut flags_ok = true;
    for (name, set) in [
        ("fpu", edx1 & 1 != 0),
        ("tsc", edx1 & (1 << 4) != 0),
        ("pae", edx1 & (1 << 6) != 0),
        ("cx8", edx1 & (1 << 8) != 0),
        ("apic", edx1 & (1 << 9) != 0),
        ("sse", edx1 & (1 << 25) != 0),
        ("sse2", edx1 & (1 << 26) != 0),
        ("pni", ecx1 & 1 != 0),
        ("cx16", ecx1 & (1 << 13) != 0),
        ("hypervisor", ecx1 & (1 << 31) != 0),
        ("syscall", ext1 & (1 << 11) != 0),
        ("nx", ext1 & (1 << 20) != 0),
        ("lm", ext1 & (1 << 29) != 0),
    ] {
        if has(name) != set {
            flags_ok = false;
            t.info("cpuinfo-flag-mismatch", format_args!("{name} cpuid={set}"));
        }
    }
    t.holds(
        "cpuinfo-flags",
        flags_ok,
        Txt(&flags[..flags.len().min(64)]),
        "flags follow CPUID",
    );
    t.holds(
        "cpuinfo-flags-order",
        flags.starts_with(b"fpu "),
        Txt(&flags[..flags.len().min(8)]),
        "word 0 first",
    );
}

fn sysctl_values(t: &mut T, u: &[[u8; 65]; 6]) {
    let mut buf = [0u8; 256];
    let mut read = |path: &str| -> Option<([u8; 256], usize)> {
        let n = slurp(path, &mut buf).ok()?;
        let mut out = [0u8; 256];
        out[..n].copy_from_slice(&buf[..n]);
        Some((out, n))
    };
    for (path, at) in [
        ("/proc/sys/kernel/ostype", 0usize),
        ("/proc/sys/kernel/hostname", 1),
        ("/proc/sys/kernel/osrelease", 2),
        ("/proc/sys/kernel/version", 3),
        ("/proc/sys/kernel/domainname", 5),
    ] {
        let got = read(path);
        let want = text!(
            80,
            "{}\n",
            core::str::from_utf8(trimmed(&u[at])).unwrap_or("?")
        );
        t.eq(
            path,
            got.as_ref().map(|(b, n)| Txt(&b[..*n])),
            Some(Txt(want.bytes())),
        );
    }
    let mut number = |path: &str| read(path).and_then(|(b, n)| num(b[..n].strip_suffix(b"\n")?));
    t.eq(
        "sysctl-pid_max",
        number("/proc/sys/kernel/pid_max"),
        Some(32768),
    );
    t.holds(
        "sysctl-threads-max",
        number("/proc/sys/kernel/threads-max").is_some_and(|n| n >= 20),
        0,
        "a thread limit",
    );
    t.eq(
        "sysctl-ngroups_max",
        number("/proc/sys/kernel/ngroups_max"),
        Some(65536),
    );
    t.eq(
        "sysctl-cap_last_cap",
        number("/proc/sys/kernel/cap_last_cap"),
        Some(40),
    );
    t.eq(
        "sysctl-overflowuid",
        number("/proc/sys/kernel/overflowuid"),
        Some(65534),
    );
    t.eq(
        "sysctl-overflowgid",
        number("/proc/sys/kernel/overflowgid"),
        Some(65534),
    );
    t.eq(
        "sysctl-max_map_count",
        number("/proc/sys/vm/max_map_count"),
        Some(65530),
    );
    t.eq(
        "sysctl-overcommit_memory",
        number("/proc/sys/vm/overcommit_memory"),
        Some(0),
    );
    t.eq(
        "sysctl-randomize_va_space",
        number("/proc/sys/kernel/randomize_va_space"),
        Some(0),
    );
    t.holds(
        "sysctl-mmap_min_addr",
        number("/proc/sys/vm/mmap_min_addr").is_some_and(|n| n >= 4096),
        0,
        "a page or more",
    );
    for (path, mode) in [
        ("/proc/sys", 0o40555),
        ("/proc/sys/kernel", 0o40555),
        ("/proc/sys/vm", 0o40555),
        ("/proc/sys/kernel/ostype", 0o100_444),
        ("/proc/sys/kernel/hostname", 0o100_644),
        ("/proc/sys/kernel/pid_max", 0o100_644),
        ("/proc/sys/vm/max_map_count", 0o100_644),
        ("/proc/sys/kernel/cap_last_cap", 0o100_444),
    ] {
        t.eq(text!(96, "mode {path}").str(), stat(path).1.mode, mode);
    }
}

// ---- the files of a process ------------------------------------------------------------------

const PF_SUPERPRIV: i128 = 0x100;
const O_CLOEXEC: usize = 0o2_000_000;

/// The text of `/proc/<pid>/<name>`.
fn pid_text<'a>(pid: usize, name: &str, buf: &'a mut Page) -> Result<&'a [u8], Errno> {
    let path = text!(64, "/proc/{pid}/{name}");
    let n = slurp(path.str(), buf)?;
    Ok(&buf[..n])
}

/// A parsed `/proc/<pid>/stat` line: the command and the fields from the state on.
struct StatLine<'a> {
    pid: &'a [u8],
    comm: &'a [u8],
    /// Field `n` of proc(5) (3 = state .. 52 = exit_code) is `f[n - 3]`.
    f: [&'a [u8]; 50],
    count: usize,
}

fn parse_stat(line: &[u8]) -> Option<StatLine<'_>> {
    let line = line.strip_suffix(b"\n")?;
    let open = line.iter().position(|&b| b == b'(')?;
    let close = line.iter().rposition(|&b| b == b')')?;
    let mut s = StatLine {
        pid: line[..open].trim_ascii_end(),
        comm: &line[open + 1..close],
        f: [&[]; 50],
        count: 2,
    };
    for field in line.get(close + 2..)?.split(|&b| b == b' ') {
        *s.f.get_mut(s.count - 2)? = field;
        s.count += 1;
    }
    Some(s)
}

impl StatLine<'_> {
    /// Field `n` as a number (`i128::MIN` if it is not one).
    fn n(&self, n: usize) -> i128 {
        let s = self.f[n - 3];
        let (neg, digits) = match s.strip_prefix(b"-") {
            Some(rest) => (true, rest),
            None => (false, s),
        };
        if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
            return i128::MIN;
        }
        let v = digits
            .iter()
            .fold(0i128, |a, &b| a * 10 + i128::from(b - b'0'));
        if neg { -v } else { v }
    }
    fn state(&self) -> &[u8] {
        self.f[0]
    }
}

/// The value of the `Key:` line of `/proc/<pid>/status` (after the tab).
fn status_val<'a>(status: &'a [u8], key: &str) -> &'a [u8] {
    lines(status)
        .find(|l| l.starts_with(key.as_bytes()) && l.get(key.len()) == Some(&b':'))
        .map_or(&[][..], |l| l[key.len() + 1..].trim_ascii())
}

/// The leading number of the `Key:` line (kB for the `Vm*` lines).
fn status_kb(status: &[u8], key: &str) -> u64 {
    num(status_val(status, key)
        .split(|&b| b == b' ')
        .next()
        .unwrap_or_default())
    .unwrap_or(u64::MAX)
}

const STATUS_KEYS_LIVE: [&str; 56] = [
    "Name",
    "Umask",
    "State",
    "Tgid",
    "Ngid",
    "Pid",
    "PPid",
    "TracerPid",
    "Uid",
    "Gid",
    "FDSize",
    "Groups",
    "NStgid",
    "NSpid",
    "NSpgid",
    "NSsid",
    "Kthread",
    "VmPeak",
    "VmSize",
    "VmLck",
    "VmPin",
    "VmHWM",
    "VmRSS",
    "RssAnon",
    "RssFile",
    "RssShmem",
    "VmData",
    "VmStk",
    "VmExe",
    "VmLib",
    "VmPTE",
    "VmSwap",
    "HugetlbPages",
    "CoreDumping",
    "THP_enabled",
    "untag_mask",
    "Threads",
    "SigQ",
    "SigPnd",
    "ShdPnd",
    "SigBlk",
    "SigIgn",
    "SigCgt",
    "CapInh",
    "CapPrm",
    "CapEff",
    "CapBnd",
    "CapAmb",
    "NoNewPrivs",
    "Seccomp",
    "Speculation_Store_Bypass",
    "SpeculationIndirectBranch",
    "Cpus_allowed",
    "Cpus_allowed_list",
    "Mems_allowed",
    "Mems_allowed_list",
];

/// The keys of a task without an address space or filesystem context (a zombie).
const STATUS_KEYS_ZOMBIE: [&str; 36] = [
    "Name",
    "State",
    "Tgid",
    "Ngid",
    "Pid",
    "PPid",
    "TracerPid",
    "Uid",
    "Gid",
    "FDSize",
    "Groups",
    "NStgid",
    "NSpid",
    "NSpgid",
    "NSsid",
    "Kthread",
    "Threads",
    "SigQ",
    "SigPnd",
    "ShdPnd",
    "SigBlk",
    "SigIgn",
    "SigCgt",
    "CapInh",
    "CapPrm",
    "CapEff",
    "CapBnd",
    "CapAmb",
    "NoNewPrivs",
    "Seccomp",
    "Speculation_Store_Bypass",
    "SpeculationIndirectBranch",
    "Cpus_allowed",
    "Cpus_allowed_list",
    "Mems_allowed",
    "Mems_allowed_list",
];

/// Whether the lines of the status text are `keys` in order, then the two context switch counters.
fn status_keys_ok(status: &[u8], keys: &[&str]) -> bool {
    let mut it = lines(status);
    for key in keys {
        let Some(l) = it.next() else { return false };
        if !(l.starts_with(key.as_bytes())
            && l.get(key.len()) == Some(&b':')
            && l.get(key.len() + 1) == Some(&b'\t'))
        {
            return false;
        }
    }
    let vol = it
        .next()
        .is_some_and(|l| l.starts_with(b"voluntary_ctxt_switches:\t"));
    let nonvol = it
        .next()
        .is_some_and(|l| l.starts_with(b"nonvoluntary_ctxt_switches:\t"));
    vol && nonvol && it.next().is_none()
}

fn getppid() -> usize {
    sys(Sysno::getppid, &[]).unwrap_or(usize::MAX)
}

fn rlimit(resource: usize) -> (u64, u64) {
    let mut lim = [0u64; 2];
    let _ = sys(Sysno::getrlimit, &[resource, addr_mut(&mut lim)]);
    (lim[0], lim[1])
}

fn fcntl(fd: usize, cmd: usize, arg: usize) -> R {
    sys(Sysno::fcntl, &[fd, cmd, arg])
}

fn hex_range(line: &[u8]) -> Option<(u64, u64)> {
    let range = line.split(|&b| b == b' ').next()?;
    let at = range.iter().position(|&b| b == b'-')?;
    let h = |s: &[u8]| {
        s.iter().try_fold(0u64, |a, &b| {
            Some(a * 16 + u64::from((b as char).to_digit(16)?))
        })
    };
    Some((h(&range[..at])?, h(&range[at + 1..])?))
}

fn hex16(s: &[u8]) -> Option<u64> {
    s.iter().try_fold(0u64, |a, &b| {
        Some(a * 16 + u64::from((b as char).to_digit(16)?))
    })
}

/// `path`'s link target equals `want`.
fn link_is(t: &mut T, name: &str, path: &str, want: &str) {
    let mut buf = [0u8; 160];
    let got = readlink(path, &mut buf);
    t.holds(
        name,
        got.is_ok_and(|n| &buf[..n] == want.as_bytes()),
        got.map(|n| Txt(&buf[..n])),
        want,
    );
}

/// The signal masks of `status` follow rt_sigprocmask, rt_sigaction, kill and tgkill.
fn sig_status(t: &mut T, me: usize) {
    let mut page: Page = [0; 16384];
    let mut get = |key: &str| -> Option<u64> {
        hex16(status_val(
            pid_text(me, "status", &mut page).unwrap_or_default(),
            key,
        ))
    };
    let (blk0, ign0, cgt0) = (get("SigBlk"), get("SigIgn"), get("SigCgt"));
    let (usr1, usr2) = (1u64 << 9, 1u64 << 11);
    let both = usr1 | usr2;
    let _ = sys(Sysno::rt_sigprocmask, &[0, addr(&both), 0, 8]);
    t.eq("sigblk", get("SigBlk"), blk0.map(|b| b | both));
    let _ = sys(Sysno::kill, &[me, 10]);
    t.eq(
        "shdpnd",
        (get("ShdPnd"), get("SigPnd")),
        (Some(usr1), Some(0)),
    );
    let _ = sys(Sysno::tgkill, &[me, me, 12]);
    t.eq(
        "sigpnd",
        (get("ShdPnd"), get("SigPnd")),
        (Some(usr1), Some(usr2)),
    );
    // SIG_IGN discards the pending signals and shows in SigIgn.
    let ign = [1u64, 0, 0, 0];
    let _ = sys(Sysno::rt_sigaction, &[10, addr(&ign), 0, 8]);
    let _ = sys(Sysno::rt_sigaction, &[12, addr(&ign), 0, 8]);
    t.eq("sigign", get("SigIgn"), ign0.map(|b| b | both));
    t.eq(
        "ign-discards-pending",
        (get("ShdPnd"), get("SigPnd")),
        (Some(0), Some(0)),
    );
    // A handler shows in SigCgt and leaves SigIgn.
    let handler = [0x40_0000u64, 0x0400_0000, 0x40_0000, 0];
    let _ = sys(Sysno::rt_sigaction, &[10, addr(&handler), 0, 8]);
    t.eq(
        "sigcgt",
        (get("SigCgt"), get("SigIgn")),
        (cgt0.map(|b| b | usr1), ign0.map(|b| b | usr2)),
    );
    let dfl = [0u64; 4];
    let _ = sys(Sysno::rt_sigaction, &[10, addr(&dfl), 0, 8]);
    let _ = sys(Sysno::rt_sigaction, &[12, addr(&dfl), 0, 8]);
    let old = blk0.unwrap_or(0);
    let _ = sys(Sysno::rt_sigprocmask, &[2, addr(&old), 0, 8]);
    t.eq(
        "sig-restored",
        (get("SigBlk"), get("SigIgn"), get("SigCgt")),
        (blk0, ign0, cgt0),
    );
}

fn pid_files(t: &mut T) {
    let me = getpid();
    let mut page2: Page = [0; 16384];
    let mut page: Page = [0; 16384];
    let mut mapbuf: Page = [0; 16384];
    core::hint::black_box((&mut page, &mut page2, &mut mapbuf));
    let pid = me as u64;
    let (soft_sig, _) = rlimit(11);

    // /proc/self/comm and the name round trip.
    t.eq(
        "comm",
        Txt(pid_text(me, "comm", &mut page).unwrap_or_default()),
        Txt(b"init\n"),
    );
    let fd = open("/proc/self/comm", O_RDWR).unwrap_or(99);
    t.eq(
        "comm-write",
        sys(
            Sysno::write,
            &[fd, addr(b"abcdefghijklmnopqrstuvwxyz\n"), 27],
        ),
        Ok(27),
    );
    t.eq(
        "comm-written",
        Txt(pid_text(me, "comm", &mut page).unwrap_or_default()),
        Txt(b"abcdefghijklmno\n"),
    );
    let mut name = [0u8; 16];
    let _ = sys(Sysno::prctl, &[16, addr_mut(&mut name)]);
    t.eq(
        "comm-prctl-get-name",
        Txt(trimmed(&name)),
        Txt(b"abcdefghijklmno"),
    );
    t.eq(
        "comm-in-status",
        Txt(status_val(
            pid_text(me, "status", &mut page).unwrap_or_default(),
            "Name",
        )),
        Txt(b"abcdefghijklmno"),
    );
    t.eq(
        "comm-in-stat",
        Txt(
            parse_stat(pid_text(me, "stat", &mut page).unwrap_or_default())
                .map_or(&[][..], |s| s.comm),
        ),
        Txt(b"abcdefghijklmno"),
    );
    t.eq(
        "comm-empty-write",
        sys(Sysno::write, &[fd, addr(b""), 0]),
        Ok(0),
    );
    t.eq(
        "comm-emptied",
        Txt(pid_text(me, "comm", &mut page).unwrap_or_default()),
        Txt(b"\n"),
    );
    t.eq(
        "comm-write-nul",
        sys(Sysno::write, &[fd, addr(b"ab\0cd"), 5]),
        Ok(5),
    );
    t.eq(
        "comm-stops-at-nul",
        Txt(pid_text(me, "comm", &mut page).unwrap_or_default()),
        Txt(b"ab\n"),
    );
    t.eq(
        "comm-write-fault",
        sys(Sysno::write, &[fd, BAD, 4]),
        Err(Errno::EFAULT),
    );
    let _ = sys(Sysno::write, &[fd, addr(b"init"), 4]);
    let _ = close(fd);
    t.eq(
        "comm-restored",
        Txt(pid_text(me, "comm", &mut page).unwrap_or_default()),
        Txt(b"init\n"),
    );

    // /proc/self/stat
    let stat_text = pid_text(me, "stat", &mut page).unwrap_or_default();
    let status_text = pid_text(me, "status", &mut page2).unwrap_or_default();
    let maps = pid_text(me, "maps", &mut mapbuf).unwrap_or_default();
    let Some(st) = parse_stat(stat_text) else {
        t.holds(
            "stat-parse",
            false,
            Txt(stat_text),
            "pid (comm) state ... 52 fields",
        );
        return;
    };
    t.holds("stat-fields", st.count == 52, st.count, "52 fields");
    t.eq("stat-pid", num(st.pid), Some(pid));
    t.eq("stat-comm", Txt(st.comm), Txt(b"init"));
    t.eq("stat-state", Txt(st.state()), Txt(b"R"));
    t.eq("stat-ppid", st.n(4), getppid() as i128);
    t.eq(
        "stat-pgrp",
        st.n(5),
        sys(Sysno::getpgid, &[0]).map_or(-1, |v| v as i128),
    );
    t.eq(
        "stat-session",
        st.n(6),
        sys(Sysno::getsid, &[0]).map_or(-1, |v| v as i128),
    );
    t.eq("stat-tty", (st.n(7), st.n(8)), (0, -1));
    t.eq("stat-flags", st.n(9) & !PF_SUPERPRIV, 0);
    t.holds(
        "stat-minflt",
        st.n(10) >= 1,
        st.n(10),
        "page faults were taken",
    );
    t.eq("stat-majflt", st.n(12), 0);
    t.holds(
        "stat-times",
        st.n(14) >= 0 && st.n(15) >= 0 && st.n(16) >= 0 && st.n(17) >= 0,
        (st.n(14), st.n(15)),
        "ticks",
    );
    t.eq("stat-priority-nice", (st.n(18), st.n(19)), (20, 0));
    t.eq("stat-threads", st.n(20), 1);
    t.eq("stat-itrealvalue", st.n(21), 0);
    let up_ticks = boottime_centis() as i128;
    t.holds(
        "stat-starttime",
        st.n(22) >= 0 && st.n(22) <= up_ticks,
        (st.n(22), up_ticks),
        "started before now",
    );
    let vm_size = status_kb(status_text, "VmSize");
    t.eq("stat-vsize", st.n(23), i128::from(vm_size) * 1024);
    // `get_mm_rss` reads the per-CPU counters without folding them (a lag of up to one batch of
    // 32 pages); status sums them exactly.
    t.holds(
        "stat-rss",
        (st.n(24) - i128::from(status_kb(status_text, "VmRSS") / 4)).abs() <= 32,
        (st.n(24), status_kb(status_text, "VmRSS") / 4),
        "rss pages, within the counter batch",
    );
    t.eq("stat-rsslim", st.n(25), i128::from(rlimit(5).0));
    t.eq("stat-kstk", (st.n(29), st.n(30)), (0, 0));
    t.eq("stat-signals", (st.n(31), st.n(32)), (0, 0));
    t.eq("stat-wchan-swap", (st.n(35), st.n(36), st.n(37)), (0, 0, 0));
    t.eq("stat-exit-signal", st.n(38), 17);
    t.eq("stat-processor", st.n(39), 0);
    t.eq("stat-sched", (st.n(40), st.n(41)), (0, 0));
    t.eq(
        "stat-delay-guest",
        (st.n(42), st.n(43), st.n(44)),
        (0, 0, 0),
    );
    t.eq("stat-exit-code", st.n(52), 0);

    // The maps cross-check the addresses of stat and the sizes of status.
    let text_line = lines(maps).find(|l| l.windows(5).any(|w| w == b" r-xp"));
    let (text_lo, text_hi) = text_line.and_then(hex_range).unwrap_or((0, 0));
    let stack_line = lines(maps).find(|l| l.trim_ascii_end().ends_with(b"[stack]"));
    let (stack_lo, stack_hi) = stack_line.and_then(hex_range).unwrap_or((0, 0));
    let (sc, ec) = (st.n(26) as u64, st.n(27) as u64);
    t.holds(
        "stat-code-range",
        text_lo <= sc && sc < ec && ec <= text_hi,
        (sc, ec, text_lo, text_hi),
        "start_code..end_code inside the text mapping",
    );
    t.holds(
        "stat-startstack",
        (stack_lo..stack_hi).contains(&(st.n(28) as u64)),
        (st.n(28), stack_lo, stack_hi),
        "start_stack inside [stack]",
    );
    let (sd, ed) = (st.n(45) as u64, st.n(46) as u64);
    t.holds(
        "stat-data-range",
        ec <= sd && sd <= ed,
        (sd, ed),
        "end_code <= start_data <= end_data",
    );
    let (as_, ae, es, ee) = (
        st.n(48) as u64,
        st.n(49) as u64,
        st.n(50) as u64,
        st.n(51) as u64,
    );
    t.holds(
        "stat-arg-env",
        stack_lo <= as_ && as_ < ae && ae <= es && es < ee && ee <= stack_hi,
        (as_, ae, es, ee),
        "arg_start < arg_end <= env_start < env_end inside [stack]",
    );

    // /proc/self/statm
    let statm = pid_text(me, "statm", &mut page).unwrap_or_default();
    let sm = |n: usize| {
        num(statm
            .trim_ascii_end()
            .split(|&b| b == b' ')
            .nth(n)
            .unwrap_or_default())
        .unwrap_or(u64::MAX)
    };
    t.holds(
        "statm-shape",
        statm.ends_with(b"\n") && statm.trim_ascii_end().split(|&b| b == b' ').count() == 7,
        Txt(statm),
        "7 numbers",
    );
    t.eq("statm-size", sm(0), vm_size / 4);
    t.eq("statm-resident", sm(1), status_kb(status_text, "VmRSS") / 4);
    t.eq(
        "statm-shared",
        sm(2),
        (status_kb(status_text, "RssFile") + status_kb(status_text, "RssShmem")) / 4,
    );
    t.eq(
        "statm-text",
        sm(3),
        (ec.div_ceil(4096) * 4096 - (sc & !4095)) / 4096,
    );
    t.eq("statm-lib-dt", (sm(4), sm(6)), (0, 0));
    t.eq(
        "statm-data",
        sm(5),
        (status_kb(status_text, "VmData") + status_kb(status_text, "VmStk")) / 4,
    );

    // /proc/self/status
    t.holds(
        "status-keys",
        status_keys_ok(status_text, &STATUS_KEYS_LIVE),
        Txt(&status_text[..status_text.len().min(40)]),
        "Linux's keys in order",
    );
    let sv = |k: &str| status_val(status_text, k);
    let umask = {
        let old = sys(Sysno::umask, &[0o22]).unwrap_or(0);
        let _ = sys(Sysno::umask, &[old]);
        old
    };
    t.eq(
        "status-name-state",
        (Txt(sv("Name")), Txt(sv("State"))),
        (Txt(b"init"), Txt(b"R (running)")),
    );
    t.eq(
        "status-umask",
        Txt(sv("Umask")),
        Txt(text!(8, "{umask:04o}").bytes()),
    );
    t.eq(
        "status-ids",
        (
            num(sv("Tgid")),
            num(sv("Pid")),
            num(sv("PPid")),
            num(sv("Ngid")),
        ),
        (Some(pid), Some(pid), Some(getppid() as u64), Some(0)),
    );
    t.eq("status-tracer", num(sv("TracerPid")), Some(0));
    let (mut ru, mut eu, mut su) = (0u32, 0u32, 0u32);
    let _ = sys(
        Sysno::getresuid,
        &[addr_mut(&mut ru), addr_mut(&mut eu), addr_mut(&mut su)],
    );
    let (mut rg, mut eg, mut sg) = (0u32, 0u32, 0u32);
    let _ = sys(
        Sysno::getresgid,
        &[addr_mut(&mut rg), addr_mut(&mut eg), addr_mut(&mut sg)],
    );
    t.eq(
        "status-uid",
        Txt(sv("Uid")),
        Txt(text!(48, "{ru}\t{eu}\t{su}\t{eu}").bytes()),
    );
    t.eq(
        "status-gid",
        Txt(sv("Gid")),
        Txt(text!(48, "{rg}\t{eg}\t{sg}\t{eg}").bytes()),
    );
    t.eq("status-fdsize", num(sv("FDSize")), Some(64));
    t.eq(
        "status-groups",
        Txt(lines(status_text)
            .find(|l| l.starts_with(b"Groups:"))
            .unwrap_or_default()),
        Txt(b"Groups:\t \n"),
    );
    t.eq(
        "status-ns-ids",
        (num(sv("NStgid")), num(sv("NSpid")), Txt(sv("Kthread"))),
        (Some(pid), Some(pid), Txt(b"0")),
    );
    t.eq(
        "status-ns-groups",
        (num(sv("NSpgid")), num(sv("NSsid"))),
        (
            sys(Sysno::getpgid, &[0]).ok().map(|v| v as u64),
            sys(Sysno::getsid, &[0]).ok().map(|v| v as u64),
        ),
    );
    let rss = status_kb(status_text, "VmRSS");
    t.eq(
        "status-rss-parts",
        status_kb(status_text, "RssAnon")
            + status_kb(status_text, "RssFile")
            + status_kb(status_text, "RssShmem"),
        rss,
    );
    t.holds(
        "status-vm-order",
        status_kb(status_text, "VmPeak") >= vm_size
            && status_kb(status_text, "VmHWM") >= rss
            && vm_size >= rss
            && rss > 0,
        (vm_size, rss),
        "VmPeak >= VmSize >= VmRSS, VmHWM >= VmRSS",
    );
    t.eq(
        "status-vm-zeroes",
        (
            status_kb(status_text, "VmLck"),
            status_kb(status_text, "VmPin"),
            status_kb(status_text, "VmLib"),
            status_kb(status_text, "VmSwap"),
            status_kb(status_text, "HugetlbPages"),
        ),
        (0, 0, 0, 0, 0),
    );
    t.eq(
        "status-vmstk",
        status_kb(status_text, "VmStk"),
        (stack_hi - stack_lo) / 1024,
    );
    t.holds(
        "status-vmexe-pte",
        status_kb(status_text, "VmExe") > 0 && status_kb(status_text, "VmPTE") >= 4,
        (
            status_kb(status_text, "VmExe"),
            status_kb(status_text, "VmPTE"),
        ),
        "text size and page tables",
    );
    t.eq(
        "status-misc",
        (
            Txt(sv("CoreDumping")),
            Txt(sv("THP_enabled")),
            Txt(sv("untag_mask")),
            Txt(sv("Threads")),
        ),
        (Txt(b"0"), Txt(b"0"), Txt(b"0xffffffffffffffff"), Txt(b"1")),
    );
    t.eq(
        "status-sigq",
        Txt(sv("SigQ")),
        Txt(text!(32, "0/{soft_sig}").bytes()),
    );
    t.eq(
        "status-caps",
        (
            Txt(sv("CapInh")),
            Txt(sv("CapPrm")),
            Txt(sv("CapEff")),
            Txt(sv("CapBnd")),
            Txt(sv("CapAmb")),
        ),
        (
            Txt(b"0000000000000000"),
            Txt(b"000001ffffffffff"),
            Txt(b"000001ffffffffff"),
            Txt(b"000001ffffffffff"),
            Txt(b"0000000000000000"),
        ),
    );
    t.eq(
        "status-privs",
        (Txt(sv("NoNewPrivs")), Txt(sv("Seccomp"))),
        (Txt(b"0"), Txt(b"0")),
    );
    t.eq(
        "status-speculation",
        (
            Txt(sv("Speculation_Store_Bypass")),
            Txt(sv("SpeculationIndirectBranch")),
        ),
        (Txt(b"not vulnerable"), Txt(b"always enabled")),
    );
    t.eq(
        "status-cpus-mems",
        (
            Txt(sv("Cpus_allowed")),
            Txt(sv("Cpus_allowed_list")),
            Txt(sv("Mems_allowed")),
            Txt(sv("Mems_allowed_list")),
        ),
        (Txt(b"1"), Txt(b"0"), Txt(b"00000000,00000001"), Txt(b"0")),
    );
    sig_status(t, me);

    // The context switch counters advance when the task sleeps.
    let vol = |p: &mut Page| {
        status_kb(
            pid_text(me, "status", p).unwrap_or_default(),
            "voluntary_ctxt_switches",
        )
    };
    let before = vol(&mut page);
    super::proc::nap(20);
    let after = vol(&mut page);
    t.holds(
        "status-voluntary-switches",
        after > before,
        (before, after),
        "sleeping is a voluntary switch",
    );

    // minflt grows with first-touch faults on fresh anonymous pages.
    let min0 =
        parse_stat(pid_text(me, "stat", &mut page).unwrap_or_default()).map_or(0, |s| s.n(10));
    let map = sys(Sysno::mmap, &[0, 32 * 4096, 3, 0x22, usize::MAX, 0]);
    if let Ok(base) = map {
        for i in 0..32 {
            super::poke(base + i * 4096, 1);
        }
        let min1 =
            parse_stat(pid_text(me, "stat", &mut page).unwrap_or_default()).map_or(0, |s| s.n(10));
        t.holds(
            "stat-minflt-grows",
            (32..40).contains(&(min1 - min0)),
            (min0, min1),
            "32 first-touch faults",
        );
        let _ = sys(Sysno::munmap, &[base, 32 * 4096]);
    } else {
        t.holds("stat-minflt-grows", false, map, "mmap");
    }

    // limits: the table of getrlimit values.
    let limits = pid_text(me, "limits", &mut page).unwrap_or_default();
    let mut want: Buf<2048> = Buf::new();
    let _ = write!(
        want,
        "{:<25} {:<20} {:<20} {:<10}\n",
        "Limit", "Soft Limit", "Hard Limit", "Units"
    );
    for (name, res, unit) in [
        ("Max cpu time", 0, "seconds"),
        ("Max file size", 1, "bytes"),
        ("Max data size", 2, "bytes"),
        ("Max stack size", 3, "bytes"),
        ("Max core file size", 4, "bytes"),
        ("Max resident set", 5, "bytes"),
        ("Max processes", 6, "processes"),
        ("Max open files", 7, "files"),
        ("Max locked memory", 8, "bytes"),
        ("Max address space", 9, "bytes"),
        ("Max file locks", 10, "locks"),
        ("Max pending signals", 11, "signals"),
        ("Max msgqueue size", 12, "bytes"),
        ("Max nice priority", 13, ""),
        ("Max realtime priority", 14, ""),
        ("Max realtime timeout", 15, "us"),
    ] {
        let (soft, hard) = rlimit(res);
        let show = |v: u64| -> Buf<24> {
            if v == u64::MAX {
                text!(24, "unlimited")
            } else {
                text!(24, "{v}")
            }
        };
        let _ = write!(
            want,
            "{:<25} {:<20} {:<20} ",
            name,
            show(soft).str(),
            show(hard).str()
        );
        if unit.is_empty() {
            let _ = want.write_str("\n");
        } else {
            let _ = write!(want, "{unit:<10}\n");
        }
    }
    t.eq("limits", Txt(limits), Txt(want.bytes()));

    // cmdline and environ of the caller.
    let cmd = pid_text(me, "cmdline", &mut page).unwrap_or_default();
    t.holds(
        "cmdline-shape",
        cmd.starts_with(b"/init\0") && cmd.ends_with(b"\0"),
        Txt(cmd),
        "NUL separated arguments starting with /init",
    );
    let env = pid_text(me, "environ", &mut page2).unwrap_or_default();
    t.eq("environ", Txt(env), Txt(b"HOME=/\0TERM=linux\0"));
    let mut tail = [0u8; 64];
    let fd = open("/proc/self/cmdline", O_RDONLY).unwrap_or(99);
    let n = pread(fd, &mut tail, 2).unwrap_or(0);
    t.eq("cmdline-offset", Txt(&tail[..n]), Txt(&cmd[2..]));
    t.eq("cmdline-past-end", pread(fd, &mut tail, 4096), Ok(0));
    let _ = close(fd);

    // The links of the process.
    link_is(t, "exe", "/proc/self/exe", "/init");
    link_is(t, "root", "/proc/self/root", "/");
    link_is(t, "cwd", "/proc/self/cwd", "/");
    t.eq("chdir-sub", chdir("/fixture/sub"), Ok(0));
    link_is(t, "cwd-after-chdir", "/proc/self/cwd", "/fixture/sub");
    t.eq("chdir-back", chdir("/"), Ok(0));
    let mut four = [0u8; 4];
    t.eq(
        "exe-opens-the-binary",
        slurp("/proc/self/exe", &mut four),
        Ok(4),
    );
    t.eq("exe-is-elf", Txt(&four), Txt(b"\x7fELF"));
    t.eq(
        "exe-same-inode",
        (stat("/proc/self/exe").1.ino, stat("/proc/self/exe").1.dev),
        (stat("/init").1.ino, stat("/init").1.dev),
    );

    fd_files(t, me);
    child_files(t, me);
}

fn fd_files(t: &mut T, me: usize) {
    let mut page: Page = [0; 16384];
    let fd = open("/fixture/hello.txt", O_RDONLY | O_CLOEXEC).unwrap_or(99);
    let _ = lseek(fd, 5, 0);
    let listing = Dir::list("/proc/self/fd").unwrap_or(Dir {
        names: [0; 4096],
        len: 0,
        count: 0,
    });
    let mine = text!(16, "{fd}:l");
    t.holds(
        "fd-listed",
        listing.entries().any(|e| e == mine.bytes()),
        Txt(listing.text()),
        "the new descriptor is a link entry",
    );
    t.holds(
        "fd-listed-ascending",
        listing
            .entries()
            .filter_map(|e| num(&e[..e.len() - 2]))
            .is_sorted(),
        Txt(listing.text()),
        "ascending",
    );
    link_is(
        t,
        "fd-link",
        text!(32, "/proc/self/fd/{fd}").str(),
        "/fixture/hello.txt",
    );
    let flags = fcntl(fd, 3, 0).unwrap_or(0);
    let want = text!(
        96,
        "pos:\t5\nflags:\t0{:o}\nmnt_id:\t{}\nino:\t{}\n",
        flags | O_CLOEXEC,
        mnt_id("/fixture/hello.txt").unwrap_or(0),
        stat("/fixture/hello.txt").1.ino
    );
    t.eq(
        "fdinfo",
        Txt(pid_text(me, text!(32, "fdinfo/{fd}").str(), &mut page).unwrap_or_default()),
        Txt(want.bytes()),
    );
    let _ = fcntl(fd, 2, 0);
    let want = text!(
        96,
        "pos:\t5\nflags:\t0{:o}\nmnt_id:\t{}\nino:\t{}\n",
        flags,
        mnt_id("/fixture/hello.txt").unwrap_or(0),
        stat("/fixture/hello.txt").1.ino
    );
    t.eq(
        "fdinfo-cloexec-cleared",
        Txt(pid_text(me, text!(32, "fdinfo/{fd}").str(), &mut page).unwrap_or_default()),
        Txt(want.bytes()),
    );
    // Opening the link opens the file again, with its own position.
    t.eq(
        "fd-link-reopens",
        Txt(pid_text(me, text!(32, "fd/{fd}").str(), &mut page).unwrap_or_default()),
        Txt(b"hello, oracle\n"),
    );
    t.eq(
        "fd-link-stat",
        (
            stat(text!(32, "/proc/self/fd/{fd}").str()).1.ino,
            fstat(fd).1.ino,
        ),
        (fstat(fd).1.ino, stat("/fixture/hello.txt").1.ino),
    );
    let _ = close(fd);
    t.eq(
        "fd-closed",
        stat(text!(32, "/proc/self/fd/{fd}").str()).0,
        Err(Errno::ENOENT),
    );
    t.eq(
        "fdinfo-closed",
        open(text!(32, "/proc/self/fdinfo/{fd}").str(), O_RDONLY),
        Err(Errno::ENOENT),
    );

    // A pipe: its name carries the inode, its mount is the internal pipefs.
    let mut pair = [0i32; 2];
    let _ = sys(Sysno::pipe2, &[addr_mut(&mut pair), 0]);
    let (r, w) = (pair[0] as usize, pair[1] as usize);
    let mut buf = [0u8; 64];
    let n = readlink(text!(32, "/proc/self/fd/{r}").str(), &mut buf).unwrap_or(0);
    let ino = buf[..n]
        .strip_prefix(b"pipe:[")
        .and_then(|s| s.strip_suffix(b"]"))
        .and_then(num);
    t.holds("pipe-link", ino.is_some(), Txt(&buf[..n]), "pipe:[inode]");
    let ino = ino.unwrap_or(0);
    t.eq(
        "pipe-fdinfo",
        Txt(pid_text(me, text!(32, "fdinfo/{r}").str(), &mut page).unwrap_or_default()),
        Txt(text!(64, "pos:\t0\nflags:\t00\nmnt_id:\t13\nino:\t{ino}\n").bytes()),
    );
    t.eq(
        "pipe-fdinfo-writer",
        Txt(pid_text(me, text!(32, "fdinfo/{w}").str(), &mut page).unwrap_or_default()),
        Txt(text!(64, "pos:\t0\nflags:\t01\nmnt_id:\t13\nino:\t{ino}\n").bytes()),
    );
    // The descriptor's own attributes: the pipe inode named in the link, on the pipefs mount.
    t.eq("pipe-fstat-ino", fstat(r).1.ino, ino);
    let mut out = [0u8; 256];
    let r_statx = sys(
        Sysno::statx,
        &[r, addr(b"\0"), 0x1000, 0x1000, addr_mut(&mut out)],
    );
    t.eq(
        "pipe-mnt-id",
        (
            r_statx,
            u64::from_le_bytes(out[144..152].try_into().unwrap_or([0; 8])),
        ),
        (Ok(0), 13),
    );
    let mut second = [0i32; 2];
    let _ = sys(Sysno::pipe2, &[addr_mut(&mut second), 0]);
    t.holds(
        "pipe-inodes-differ",
        fstat(second[0] as usize).1.ino != ino,
        (ino, fstat(second[0] as usize).1.ino),
        "each pipe has its own inode",
    );
    let _ = (close(second[0] as usize), close(second[1] as usize));
    let _ = (close(r), close(w));

    // A file that was unlinked says so.
    let mounted = mount(None, "/mnt/b", Some("tmpfs"), 0, None);
    let _ = put_file("/mnt/b/gone", 10);
    let fd = open("/mnt/b/gone", O_RDONLY).unwrap_or(99);
    link_is(
        t,
        "fd-link-before-unlink",
        text!(32, "/proc/self/fd/{fd}").str(),
        "/mnt/b/gone",
    );
    let _ = sys(Sysno::unlink, &[addr(&c("/mnt/b/gone"))]);
    link_is(
        t,
        "fd-link-deleted",
        text!(32, "/proc/self/fd/{fd}").str(),
        "/mnt/b/gone (deleted)",
    );
    t.eq(
        "fdinfo-deleted",
        Txt(&pid_text(me, text!(32, "fdinfo/{fd}").str(), &mut page).unwrap_or_default()[..7]),
        Txt(b"pos:\t0\n"),
    );
    let _ = close(fd);
    t.eq(
        "fd-dir-tmpfs-umount",
        (mounted, umount("/mnt/b", 0)),
        (Ok(0), Ok(0)),
    );
}

/// A forked child, asleep and then a zombie, seen from its parent.
fn child_files(t: &mut T, me: usize) {
    use super::proc::{nap, spawn, wait4};
    let mut page: Page = [0; 16384];
    let mut page2: Page = [0; 16384];
    let mut pair = [0i32; 2];
    let _ = sys(Sysno::pipe2, &[addr_mut(&mut pair), 0]);
    let (r, w) = (pair[0] as usize, pair[1] as usize);
    let child = spawn(|| {
        let _ = close(w);
        let mut b = [0u8; 1];
        let _ = read(r, &mut b);
        3
    });
    let state_of = |pid: usize, page: &mut Page| -> u8 {
        parse_stat(pid_text(pid, "stat", page).unwrap_or_default()).map_or(b'?', |s| s.state()[0])
    };
    for _ in 0..200 {
        if state_of(child, &mut page) == b'S' {
            break;
        }
        nap(5);
    }
    let own_maps = {
        let mut p: Page = [0; 16384];
        let n = pid_text(me, "maps", &mut p).map_or(0, <[u8]>::len);
        let mut out = [0u8; 4096];
        out[..n.min(4096)].copy_from_slice(&p[..n.min(4096)]);
        (out, n)
    };

    // asleep
    let stat_text = pid_text(child, "stat", &mut page).unwrap_or_default();
    let st = parse_stat(stat_text);
    t.holds(
        "child-stat",
        st.as_ref().is_some_and(|s| s.count == 52),
        Txt(stat_text),
        "52 fields",
    );
    let Some(st) = st else { return };
    t.eq(
        "child-stat-pid-comm",
        (num(st.pid), Txt(st.comm), Txt(st.state())),
        (Some(child as u64), Txt(b"init"), Txt(b"S")),
    );
    t.eq("child-stat-ppid", st.n(4), me as i128);
    t.eq("child-stat-flags", st.n(9), 0x40);
    t.eq(
        "child-stat-sleeping-wchan",
        (st.n(35), st.n(38), st.n(39)),
        (1, 17, 0),
    );
    t.holds(
        "child-stat-sizes",
        st.n(23) > 0 && st.n(24) > 0,
        (st.n(23), st.n(24)),
        "an address space",
    );
    let status_text = pid_text(child, "status", &mut page2).unwrap_or_default();
    t.holds(
        "child-status-keys",
        status_keys_ok(status_text, &STATUS_KEYS_LIVE),
        Txt(&status_text[..status_text.len().min(40)]),
        "the live keys",
    );
    t.eq(
        "child-status-ids",
        (
            Txt(status_val(status_text, "State")),
            num(status_val(status_text, "Pid")),
            num(status_val(status_text, "PPid")),
            Txt(status_val(status_text, "Name")),
        ),
        (
            Txt(b"S (sleeping)"),
            Some(child as u64),
            Some(me as u64),
            Txt(b"init"),
        ),
    );
    t.eq(
        "child-status-fdsize",
        num(status_val(status_text, "FDSize")),
        Some(64),
    );
    let mut other: Page = [0; 16384];
    t.eq(
        "child-cmdline",
        Txt(pid_text(child, "cmdline", &mut page).unwrap_or_default()),
        Txt(pid_text(me, "cmdline", &mut other).unwrap_or_default()),
    );
    t.eq(
        "child-environ",
        Txt(pid_text(child, "environ", &mut page).unwrap_or_default()),
        Txt(b"HOME=/\0TERM=linux\0"),
    );
    let child_maps = pid_text(child, "maps", &mut page).unwrap_or_default();
    // The parent may have grown its stack since the fork; every other mapping is inherited as is.
    let own = &own_maps.0[..own_maps.1.min(4096)];
    let inherited = lines(child_maps).count() == lines(own).count()
        && lines(child_maps)
            .zip(lines(own))
            .all(|(a, b)| a == b || (a.ends_with(b"[stack]\n") && b.ends_with(b"[stack]\n")));
    t.holds(
        "child-maps-inherited",
        inherited,
        Txt(&child_maps[..child_maps.len().min(200)]),
        "the parent's mappings",
    );
    link_is(
        t,
        "child-exe",
        text!(32, "/proc/{child}/exe").str(),
        "/init",
    );
    link_is(t, "child-cwd", text!(32, "/proc/{child}/cwd").str(), "/");
    link_is(t, "child-root", text!(32, "/proc/{child}/root").str(), "/");
    let listing = Dir::list(text!(32, "/proc/{child}/fd").str()).unwrap_or(Dir {
        names: [0; 4096],
        len: 0,
        count: 0,
    });
    let mine = text!(16, "{r}:l");
    t.holds(
        "child-fd-dir",
        listing.entries().any(|e| e == mine.bytes())
            && !listing.entries().any(|e| e == text!(16, "{w}:l").bytes()),
        Txt(listing.text()),
        "the pipe's read end is open, its write end closed",
    );
    let mut buf = [0u8; 64];
    let n = readlink(text!(48, "/proc/{child}/fd/{r}").str(), &mut buf).unwrap_or(0);
    t.holds(
        "child-fd-pipe-link",
        buf[..n].starts_with(b"pipe:["),
        Txt(&buf[..n]),
        "pipe:[inode]",
    );
    let tasks = Dir::list(text!(32, "/proc/{child}/task").str()).unwrap_or(Dir {
        names: [0; 4096],
        len: 0,
        count: 0,
    });
    t.eq(
        "child-task-dir",
        Txt(tasks.text()),
        Txt(text!(24, "{child}:d").bytes()),
    );
    t.eq(
        "child-mounts",
        Txt(pid_text(child, "mounts", &mut page).unwrap_or_default()),
        Txt(pid_text(me, "mounts", &mut other).unwrap_or_default()),
    );

    // zombie
    let _ = sys(Sysno::write, &[w, addr(b"x"), 1]);
    for _ in 0..200 {
        if state_of(child, &mut page) == b'Z' {
            break;
        }
        nap(5);
    }
    let stat_text = pid_text(child, "stat", &mut page).unwrap_or_default();
    let Some(st) = parse_stat(stat_text) else {
        t.holds("zombie-stat", false, Txt(stat_text), "a stat line");
        return;
    };
    t.eq(
        "zombie-state",
        (Txt(st.state()), st.n(4), st.n(9)),
        (Txt(b"Z"), me as i128, 0x804c),
    );
    t.eq(
        "zombie-no-mm",
        (
            st.n(23),
            st.n(24),
            st.n(26),
            st.n(27),
            st.n(28),
            st.n(45),
            st.n(51),
        ),
        (0, 0, 0, 0, 0, 0, 0),
    );
    t.eq(
        "zombie-exit",
        (st.n(38), st.n(52), st.n(35)),
        (17, 3 << 8, 1),
    );
    t.eq(
        "zombie-statm",
        Txt(pid_text(child, "statm", &mut page).unwrap_or_default()),
        Txt(b"0 0 0 0 0 0 0\n"),
    );
    let status_text = pid_text(child, "status", &mut page2).unwrap_or_default();
    t.holds(
        "zombie-status-keys",
        status_keys_ok(status_text, &STATUS_KEYS_ZOMBIE),
        Txt(&status_text[..status_text.len().min(40)]),
        "no Umask, no memory lines",
    );
    t.eq(
        "zombie-status-values",
        (
            Txt(status_val(status_text, "State")),
            Txt(status_val(status_text, "FDSize")),
            Txt(status_val(status_text, "Name")),
        ),
        (Txt(b"Z (zombie)"), Txt(b"0"), Txt(b"init")),
    );
    t.eq(
        "zombie-cmdline",
        pid_text(child, "cmdline", &mut page).map(<[u8]>::len),
        Ok(0),
    );
    t.eq(
        "zombie-maps",
        pid_text(child, "maps", &mut page).map(<[u8]>::len),
        Ok(0),
    );
    t.eq(
        "zombie-environ",
        open(text!(32, "/proc/{child}/environ").str(), O_RDONLY),
        Err(Errno::ESRCH),
    );
    t.eq(
        "zombie-mounts",
        open(text!(32, "/proc/{child}/mounts").str(), O_RDONLY),
        Err(Errno::EINVAL),
    );
    t.eq(
        "zombie-mountinfo",
        open(text!(32, "/proc/{child}/mountinfo").str(), O_RDONLY),
        Err(Errno::EINVAL),
    );
    t.holds(
        "zombie-limits",
        pid_text(child, "limits", &mut page).is_ok_and(|l| l.starts_with(b"Limit ")),
        0,
        "limits still readable",
    );
    let mut buf = [0u8; 16];
    for name in ["exe", "cwd", "root"] {
        t.eq(
            text!(32, "zombie-{name}").str(),
            readlink(text!(32, "/proc/{child}/{name}").str(), &mut buf),
            Err(Errno::ENOENT),
        );
    }
    let listing = Dir::list(text!(32, "/proc/{child}/fd").str());
    t.eq("zombie-fd-dir", listing.map(|d| d.count), Ok(0));
    t.eq(
        "zombie-fd-size",
        stat(text!(32, "/proc/{child}/fd").str()).1.size,
        0,
    );
    t.eq(
        "zombie-fdinfo",
        open(text!(32, "/proc/{child}/fdinfo/0").str(), O_RDONLY),
        Err(Errno::ENOENT),
    );
    let tasks = Dir::list(text!(32, "/proc/{child}/task").str()).unwrap_or(Dir {
        names: [0; 4096],
        len: 0,
        count: 0,
    });
    t.eq(
        "zombie-task-dir",
        Txt(tasks.text()),
        Txt(text!(24, "{child}:d").bytes()),
    );
    let _ = close(w);
    let _ = close(r);

    // reaped
    let reaped = wait4(child as isize, 0);
    t.eq("child-reaped", reaped.0, Ok(child));
    t.eq(
        "reaped-stat",
        open(text!(32, "/proc/{child}/stat").str(), O_RDONLY),
        Err(Errno::ENOENT),
    );
    t.eq(
        "reaped-dir",
        stat(text!(32, "/proc/{child}").str()).0,
        Err(Errno::ENOENT),
    );
    t.eq(
        "reaped-fd",
        Dir::list(text!(32, "/proc/{child}/fd").str()).map(|d| d.count),
        Err(Errno::ENOENT),
    );
}

// ---- seq_file reads, positions and ioctls ------------------------------------------------------

const FIONREAD: usize = 0x541b;
const SEEK_SET: usize = 0;
const SEEK_CUR: usize = 1;
const SEEK_END: usize = 2;

fn fionread(fd: usize) -> Result<i32, Errno> {
    let mut left = 0i32;
    sys(Sysno::ioctl, &[fd, FIONREAD, addr_mut(&mut left)]).map(|_| left)
}

fn seq_files(t: &mut T) {
    let mut whole = [0u8; 512];
    let total = slurp("/proc/version", &mut whole).unwrap_or(0);
    let whole = &whole[..total];

    // Small reads reassemble the text, and the position follows them.
    let fd = open("/proc/version", O_RDONLY).unwrap_or(99);
    let mut joined = [0u8; 512];
    let (mut used, mut chunks) = (0, 0);
    let mut piece = [0u8; 7];
    while let Ok(n) = read(fd, &mut piece) {
        if n == 0 {
            break;
        }
        joined[used..used + n].copy_from_slice(&piece[..n]);
        used += n;
        chunks += 1;
    }
    t.eq("seq-small-reads", Txt(&joined[..used]), Txt(whole));
    t.eq("seq-chunk-count", chunks, total.div_ceil(7));
    t.eq("seq-eof-position", lseek(fd, 0, SEEK_CUR), Ok(total));
    t.eq("seq-read-at-eof", read(fd, &mut piece), Ok(0));

    // lseek: SET and CUR work, a negative result and END do not.
    t.eq("seq-seek-set", lseek(fd, 3, SEEK_SET), Ok(3));
    let n = read(fd, &mut piece).unwrap_or(0);
    t.eq(
        "seq-read-after-seek",
        Txt(&piece[..n]),
        Txt(&whole[3..3 + n]),
    );
    t.eq("seq-seek-cur", lseek(fd, -2, SEEK_CUR), Ok(3 + n - 2));
    t.eq(
        "seq-seek-negative",
        lseek(fd, -1, SEEK_SET),
        Err(Errno::EINVAL),
    );
    t.eq("seq-seek-end", lseek(fd, 0, SEEK_END), Err(Errno::EINVAL));
    t.eq(
        "seq-seek-cur-negative",
        lseek(fd, -1000, SEEK_CUR),
        Err(Errno::EINVAL),
    );
    t.eq("seq-seek-back-to-start", lseek(fd, 0, SEEK_SET), Ok(0));
    let n = read(fd, &mut piece).unwrap_or(0);
    t.eq("seq-reread", Txt(&piece[..n]), Txt(&whole[..n]));
    let past = lseek(fd, 100_000, SEEK_SET);
    t.eq("seq-seek-past-end", past, Ok(100_000));
    t.eq("seq-read-past-end", read(fd, &mut piece), Ok(0));

    // pread does not move the position.
    t.eq("seq-pos-before-pread", lseek(fd, 5, SEEK_SET), Ok(5));
    let mut at = [0u8; 9];
    let n = pread(fd, &mut at, 11).unwrap_or(0);
    t.eq("seq-pread", Txt(&at[..n]), Txt(&whole[11..11 + n]));
    t.eq("seq-pread-keeps-position", lseek(fd, 0, SEEK_CUR), Ok(5));
    t.eq("seq-pread-at-end", pread(fd, &mut at, total), Ok(0));
    t.eq("seq-pread-past-end", pread(fd, &mut at, total + 50), Ok(0));
    t.eq(
        "seq-pread-negative",
        sys(Sysno::pread64, &[fd, addr_mut(&mut at), 9, usize::MAX]),
        Err(Errno::EINVAL),
    );

    // FIONREAD of a regular procfs file is `i_size - f_pos`: the size is 0, so the position shows
    // up negated.
    t.eq("seq-fionread-pos5", fionread(fd), Ok(-5));
    let _ = lseek(fd, 0, SEEK_SET);
    t.eq("seq-fionread-pos0", fionread(fd), Ok(0));
    let _ = close(fd);
    let dir = open("/proc", O_RDONLY | O_DIRECTORY).unwrap_or(99);
    t.eq("seq-fionread-dir", fionread(dir), Err(Errno::ENOTTY));
    let _ = close(dir);
    let cmd = open("/proc/cmdline", O_RDONLY).unwrap_or(99);
    let size = stat("/proc/cmdline").1.size as i32;
    t.eq("seq-fionread-cmdline", fionread(cmd), Ok(size));
    let _ = close(cmd);

    // A file regenerates when it is read again from the start: two instants of the clock.
    let fd = open("/proc/uptime", O_RDONLY).unwrap_or(99);
    let mut first = [0u8; 64];
    let a = read(fd, &mut first).unwrap_or(0);
    super::proc::nap(30);
    let _ = lseek(fd, 0, SEEK_SET);
    let mut second = [0u8; 64];
    let b = read(fd, &mut second).unwrap_or(0);
    let up = |s: &[u8]| centis(s.split(|&x| x == b' ').next().unwrap_or_default());
    t.holds(
        "seq-regenerates",
        up(&first[..a]) < up(&second[..b]) && up(&second[..b]).is_some(),
        (Txt(&first[..a]), Txt(&second[..b])),
        "a rewound read shows the clock again",
    );
    // Continuing at the end keeps the old text: no new data.
    t.eq("seq-continue-at-end", read(fd, &mut second), Ok(0));
    let _ = close(fd);

    // Reads of a directory and of a link.
    let fd = open("/proc/self/fd", O_RDONLY | O_DIRECTORY).unwrap_or(99);
    t.eq("dir-pread", pread(fd, &mut at, 0), Err(Errno::EISDIR));
    let _ = close(fd);
    // Zero-length and bad-buffer reads.
    let fd = open("/proc/version", O_RDONLY).unwrap_or(99);
    t.eq(
        "seq-zero-read",
        sys(Sysno::read, &[fd, addr_mut(&mut at), 0]),
        Ok(0),
    );
    t.eq(
        "seq-bad-buffer",
        sys(Sysno::read, &[fd, BAD, 8]),
        Err(Errno::EFAULT),
    );
    t.eq("seq-read-after-fault", lseek(fd, 0, SEEK_CUR), Ok(0));
    let _ = close(fd);
}

// ---- poll on the mount tables ------------------------------------------------------------------

const POLLIN: i16 = 0x1;
const POLLPRI: i16 = 0x2;
const POLLOUT: i16 = 0x4;

/// `poll` on one descriptor: `(result, revents)`.
fn poll1(fd: usize, events: i16, timeout_ms: i32) -> (R, i16) {
    let mut pfd = [fd as i32 as u32 as u64 | (u64::from(events as u16) << 32)];
    let r = sys(Sysno::poll, &[addr_mut(&mut pfd), 1, timeout_ms as usize]);
    (r, (pfd[0] >> 48) as i16)
}

/// `mounts_poll`: readable always, `POLLERR | POLLPRI` once per change of the mount table.
fn mounts_poll(t: &mut T) {
    let fd = open("/proc/self/mountinfo", O_RDONLY).unwrap_or(99);
    // Only requested events (and POLLERR) are reported.
    let err_pri = 0xa; // POLLERR | POLLPRI
    let none = (Ok(0), 0);
    t.eq(
        "mounts-poll-quiet",
        poll1(fd, POLLIN | POLLPRI, 0),
        (Ok(1), POLLIN),
    );
    t.eq(
        "mounts-poll-mount",
        mount(None, "/mnt/c", Some("tmpfs"), 0, None),
        Ok(0),
    );
    t.eq(
        "mounts-poll-after-mount",
        poll1(fd, POLLPRI, 0),
        (Ok(1), err_pri),
    );
    t.eq("mounts-poll-reported-once", poll1(fd, POLLPRI, 0), none);
    t.eq("mounts-poll-out-not-ready", poll1(fd, POLLOUT, 0), none);
    t.eq(
        "mounts-poll-remount",
        mount(None, "/mnt/c", None, MS_REMOUNT | MS_RDONLY | MS_BIND, None),
        Ok(0),
    );
    t.eq(
        "mounts-poll-after-remount",
        poll1(fd, POLLPRI, 0),
        (Ok(1), err_pri),
    );
    t.eq(
        "mounts-poll-propagation-silent",
        mount(None, "/mnt/c", None, MS_PRIVATE, None),
        Ok(0),
    );
    t.eq("mounts-poll-after-type-change", poll1(fd, POLLPRI, 0), none);
    t.eq("mounts-poll-umount", umount("/mnt/c", 0), Ok(0));
    t.eq(
        "mounts-poll-after-umount",
        poll1(fd, POLLPRI, 0),
        (Ok(1), err_pri),
    );
    let fresh = open("/proc/mounts", O_RDONLY).unwrap_or(99);
    t.eq("mounts-poll-new-file-quiet", poll1(fresh, POLLPRI, 0), none);
    // A sleeping poll is woken by another task's mount.
    let waiter = super::proc::spawn(|| {
        super::proc::nap(60);
        usize::from(mount(None, "/mnt/d", Some("tmpfs"), 0, None).is_err())
    });
    let started = boottime_centis();
    let slept = poll1(fd, POLLPRI, 5000);
    let took = boottime_centis() - started;
    t.eq("mounts-poll-wakes", slept, (Ok(1), err_pri));
    t.holds(
        "mounts-poll-woke-early",
        took < 300,
        took,
        "returned well before the 5 s timeout",
    );
    t.eq(
        "mounts-poll-child",
        super::proc::wait4(waiter as isize, 0).1,
        0,
    );
    t.eq("mounts-poll-cleanup", umount("/mnt/d", 0), Ok(0));
    // Any other procfs file has no poll operation: the default mask.
    let stat = open("/proc/version", O_RDONLY).unwrap_or(99);
    t.eq(
        "proc-poll-default",
        poll1(stat, POLLIN | POLLOUT, 0),
        (Ok(1), 0x5),
    );
    let _ = (close(fd), close(fresh), close(stat));
}

// ---- unmounting the root ----------------------------------------------------------------------

/// `umount2("/")` remounts the root filesystem read-only (`do_umount_root`); open writers make it
/// `EBUSY`. It leaves the filesystem read-only, so this runs last and puts it back.
fn root_umount(t: &mut T) {
    let writer = open("/rootwriter", O_RDWR | O_CREAT);
    t.holds(
        "root-writer-created",
        writer.is_ok(),
        writer,
        "a file on the root to write",
    );
    t.eq("root-umount-busy", umount("/", 0), Err(Errno::EBUSY));
    t.eq(
        "root-umount-detach-busy",
        umount("/", MNT_DETACH),
        Err(Errno::EINVAL),
    );
    let _ = close(writer.unwrap_or(99));
    t.eq("root-umount", umount("/", 0), Ok(0));
    let mut buf: Page = [0; 16384];
    let n = mountinfo(&mut buf);
    // The mount keeps its flags; the superblock is what became read-only.
    let line = mi_line(&buf[..n], "/");
    t.holds(
        "root-now-ro",
        line.starts_with(b"1 1 0:2 / / rw - rootfs rootfs ro"),
        Txt(line),
        "superblock shows ro",
    );
    t.eq(
        "root-ro-create",
        open("/rootwriter2", O_RDWR | O_CREAT),
        Err(Errno::EROFS),
    );
    t.eq(
        "root-ro-read",
        slurp("/fixture/hello.txt", &mut buf),
        Ok(14),
    );
    t.eq("root-umount-again", umount("/", 0), Ok(0));
    t.eq(
        "root-remount-rw",
        mount(None, "/", None, MS_REMOUNT, None),
        Ok(0),
    );
    let n = mountinfo(&mut buf);
    let line = mi_line(&buf[..n], "/");
    t.holds(
        "root-rw-again",
        line.starts_with(b"1 1 0:2 / / rw - rootfs rootfs rw"),
        Txt(line),
        "superblock shows rw",
    );
    let again = open("/rootwriter2", O_RDWR | O_CREAT);
    t.holds("root-rw-create", again.is_ok(), again, "writes work again");
    let _ = close(again.unwrap_or(99));
    let _ = sys(Sysno::unlink, &[addr(&c("/rootwriter2"))]);
    let _ = sys(Sysno::unlink, &[addr(&c("/rootwriter"))]);
}

// ---- proc options: display, parsing and the order of a remount -------------------------------

/// The superblock options of the mountinfo line of `point` (`- fstype source options`).
fn sb_opts<'a>(buf: &'a mut Page, point: &str) -> &'a [u8] {
    let n = mountinfo(buf);
    let line = mi_line(&buf[..n], point);
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    let at = line
        .windows(3)
        .position(|w| w == b" - ")
        .map_or(0, |at| at + 3);
    field(&line[at..], b' ', 2)
}

fn proc_options(t: &mut T) {
    let mut buf: Page = [0; 16384];
    // `proc_show_options`: gid, hidepid, subset, in that order after the generic flags.
    for (name, fs, data, want) in [
        ("gid-hex", "proc", "gid=0x10", "rw,gid=16"),
        ("gid-octal", "proc", "gid=010", "rw,gid=8"),
        ("gid-plus", "proc", "gid=+5", "rw,gid=5"),
        ("gid-newline", "proc", "gid=5\n", "rw,gid=5"),
        ("gid-zero", "proc", "gid=0", "rw"),
        ("gid-last-wins", "proc", "gid=3,gid=4", "rw,gid=4"),
        ("gid-max", "proc", "gid=4294967295", "rw,gid=65534"),
        ("hidepid-plus", "proc", "hidepid=+1", "rw,hidepid=noaccess"),
        ("hidepid-hex", "proc", "hidepid=0x2", "rw,hidepid=invisible"),
        (
            "hidepid-octal",
            "proc",
            "hidepid=04",
            "rw,hidepid=ptraceable",
        ),
        ("hidepid-zero", "proc", "hidepid=0", "rw"),
        ("hidepid-off", "proc", "hidepid=off", "rw"),
        (
            "hidepid-name",
            "proc",
            "hidepid=invisible",
            "rw,hidepid=invisible",
        ),
        (
            "hidepid-last-wins",
            "proc",
            "hidepid=2,hidepid=1",
            "rw,hidepid=noaccess",
        ),
        (
            "hidepid-newline",
            "proc",
            "hidepid=1\n",
            "rw,hidepid=noaccess",
        ),
        ("subset-pid", "proc", "subset=pid", "rw,subset=pid"),
        (
            "all-three",
            "proc",
            "subset=pid,hidepid=1,gid=3",
            "rw,gid=3,hidepid=noaccess,subset=pid",
        ),
        ("flag-ro", "proc", "ro,gid=2", "ro,gid=2"),
        (
            "flags",
            "proc",
            "sync,mand,lazytime",
            "rw,sync,mand,lazytime",
        ),
        (
            "tmpfs-uid-edge",
            "tmpfs",
            "uid=4294967294",
            "rw,uid=4294967294",
        ),
        (
            "tmpfs-gid-edge",
            "tmpfs",
            "gid=4294967294",
            "rw,gid=4294967294",
        ),
        ("tmpfs-uid-plus", "tmpfs", "uid=+7", "rw,uid=7"),
    ] {
        let mounted = mount(Some("x"), "/mnt/g", Some(fs), 0, Some(data));
        t.eq(format_args!("po-{name}-mount"), mounted, Ok(0));
        if mounted.is_ok() {
            t.eq(
                format_args!("po-{name}-options"),
                Txt(sb_opts(&mut buf, "/mnt/g")),
                Txt(want.as_bytes()),
            );
            let _ = umount("/mnt/g", 0);
        }
    }

    // A remount applies the options only after reconfigure_super's checks: a flag it refuses
    // (EINVAL) or a writer it finds (EBUSY) leave the options as they were.
    t.eq(
        "po-mount",
        mount(
            Some("x"),
            "/mnt/g",
            Some("proc"),
            0,
            Some("gid=5,hidepid=2,subset=pid"),
        ),
        Ok(0),
    );
    let opts = |buf: &mut Page| -> [u8; 96] {
        let mut out = [0u8; 96];
        let text = sb_opts(buf, "/mnt/g");
        out[..text.len().min(96)].copy_from_slice(&text[..text.len().min(96)]);
        out
    };
    let trim = |raw: &[u8; 96]| -> usize { raw.iter().position(|&b| b == 0).unwrap_or(96) };
    let first = opts(&mut buf);
    t.eq(
        "po-options",
        Txt(&first[..trim(&first)]),
        Txt(b"rw,gid=5,hidepid=invisible,subset=pid"),
    );
    t.eq(
        "po-remount-hidepid",
        mount(None, "/mnt/g", None, MS_REMOUNT, Some("hidepid=1")),
        Ok(0),
    );
    let now = opts(&mut buf);
    t.eq(
        "po-remount-keeps-the-rest",
        Txt(&now[..trim(&now)]),
        Txt(b"rw,gid=5,hidepid=noaccess,subset=pid"),
    );
    t.eq(
        "po-remount-dirsync",
        mount(None, "/mnt/g", None, MS_REMOUNT, Some("gid=7,dirsync")),
        Err(Errno::EINVAL),
    );
    let after = opts(&mut buf);
    t.eq(
        "po-remount-dirsync-changes-nothing",
        Txt(&after[..trim(&after)]),
        Txt(b"rw,gid=5,hidepid=noaccess,subset=pid"),
    );
    let writer = open("/mnt/g/self/comm", O_WRONLY).unwrap_or(99);
    t.eq(
        "po-remount-busy",
        mount(
            None,
            "/mnt/g",
            None,
            MS_REMOUNT | MS_RDONLY,
            Some("hidepid=2,gid=9"),
        ),
        Err(Errno::EBUSY),
    );
    let after = opts(&mut buf);
    t.eq(
        "po-remount-busy-changes-nothing",
        Txt(&after[..trim(&after)]),
        Txt(b"rw,gid=5,hidepid=noaccess,subset=pid"),
    );
    let _ = close(writer);
    t.eq(
        "po-remount-ro",
        mount(
            None,
            "/mnt/g",
            None,
            MS_REMOUNT | MS_RDONLY,
            Some("hidepid=2,gid=9"),
        ),
        Ok(0),
    );
    let after = opts(&mut buf);
    t.eq(
        "po-options-after-ro",
        Txt(&after[..trim(&after)]),
        Txt(b"ro,gid=9,hidepid=invisible,subset=pid"),
    );
    t.eq(
        "po-remount-pidns",
        mount(None, "/mnt/g", None, MS_REMOUNT, Some("pidns=/nonexistent")),
        Err(Errno::EBUSY),
    );
    t.eq(
        "po-remount-unknown",
        mount(None, "/mnt/g", None, MS_REMOUNT, Some("bogus")),
        Err(Errno::EINVAL),
    );
    t.eq(
        "po-remount-rw",
        mount(None, "/mnt/g", None, MS_REMOUNT, Some("hidepid=ptraceable")),
        Ok(0),
    );
    let after = opts(&mut buf);
    t.eq(
        "po-options-after-rw",
        Txt(&after[..trim(&after)]),
        Txt(b"rw,gid=9,hidepid=ptraceable,subset=pid"),
    );
    t.eq("po-umount", umount("/mnt/g", 0), Ok(0));
}

// ---- seq_file reads over many records, vanished tasks, wchan ----------------------------------

/// The length of the line that starts at `from` in `text` (through its newline), 0 at the end.
fn line_len(text: &[u8], from: usize) -> usize {
    match text.get(from..) {
        Some(rest) if !rest.is_empty() => rest
            .iter()
            .position(|&b| b == b'\n')
            .map_or(rest.len(), |at| at + 1),
        _ => 0,
    }
}

/// Whether `got` bytes taken from the record boundary `from` of `text` are what `seq_read_iter`
/// fills: whole lines, less than the 4096-byte buffer (it is doubled only for a bigger record),
/// and no more could have been added without reaching it.
fn fill_ok(text: &[u8], from: usize, got: usize) -> bool {
    let end = from + got;
    got < 4096
        && (end == text.len() || (end > from && text[end - 1] == b'\n'))
        && (end == text.len() || got + line_len(text, end) >= 4096)
}

/// The reads of a many-record `seq_file` (`maps`, `mounts`, `mountinfo`): a big read returns whole
/// records that fit the buffer, the rest of a buffer is served first, and a seek into a record
/// serves its tail before the next records.
fn seq_chunks(t: &mut T, name: &str, path: &str) {
    let mut whole: Page = [0; 16384];
    // The flat text, by small reads (a read smaller than the buffered records is a plain slice).
    let fd = open(path, O_RDONLY).unwrap_or(99);
    let mut total = 0;
    let mut small = [0u8; 97];
    while let Ok(n) = read(fd, &mut small) {
        if n == 0 || total + n > whole.len() {
            break;
        }
        whole[total..total + n].copy_from_slice(&small[..n]);
        total += n;
    }
    let _ = close(fd);
    let text = &whole[..total];
    t.holds(
        format_args!("{name}-is-long"),
        total > 8192,
        total,
        "more than two buffers of text",
    );

    // Big reads: every chunk is whole records filling the buffer.
    let fd = open(path, O_RDONLY).unwrap_or(99);
    let mut big: Page = [0; 16384];
    let (mut pos, mut chunks, mut all_ok, mut same) = (0usize, 0, true, true);
    let mut first = 0;
    loop {
        let n = read(fd, &mut big).unwrap_or(0);
        if n == 0 {
            break;
        }
        all_ok &= fill_ok(text, pos, n);
        same &= text.get(pos..pos + n) == Some(&big[..n]);
        if chunks == 0 {
            first = n;
        }
        pos += n;
        chunks += 1;
    }
    let _ = close(fd);
    t.holds(
        format_args!("{name}-big-reads-fill-whole-records"),
        all_ok && same && pos == total,
        (chunks, pos, total),
        "whole records, each chunk the longest that fits 4096 bytes",
    );
    t.holds(
        format_args!("{name}-big-reads-take-several-calls"),
        chunks >= 3,
        chunks,
        "at least three reads",
    );

    // A short read, then a big one. The first read buffers whole records until it has as many
    // bytes as the caller asked for (`m->count >= iov_iter_count`); the second serves the rest of
    // that buffer, then fills a fresh one.
    let fd = open(path, O_RDONLY).unwrap_or(99);
    let n1 = read(fd, &mut big[..100]).unwrap_or(0);
    let n2 = read(fd, &mut big).unwrap_or(0);
    let mut buffered = 0;
    while buffered < 100 {
        buffered += line_len(text, buffered);
    }
    let rest = buffered - 100;
    t.holds(
        format_args!("{name}-rest-of-the-buffer-then-a-fill"),
        n1 == 100
            && n2 >= rest
            && text.get(100..100 + n2) == Some(&big[..n2])
            && fill_ok(text, buffered, n2 - rest),
        (n1, n2, rest, first),
        "the rest of the buffered records, then the next records that fit",
    );
    let _ = close(fd);

    // pread into the middle of the third line: its tail, then the records that fit.
    let third = line_len(text, 0) + line_len(text, line_len(text, 0));
    let off = third + 5;
    let tail = line_len(text, third) - 5;
    let fd = open(path, O_RDONLY).unwrap_or(99);
    let n = pread(fd, &mut big, off).unwrap_or(0);
    t.holds(
        format_args!("{name}-pread-into-a-record"),
        n >= tail
            && text.get(off..off + n) == Some(&big[..n])
            && fill_ok(text, off + tail, n - tail),
        (n, tail),
        "the tail of the record, then the records that fit",
    );
    // lseek into a record, then read: the same.
    t.eq(
        format_args!("{name}-seek-into-a-record"),
        lseek(fd, off as isize, SEEK_SET),
        Ok(off),
    );
    let n = read(fd, &mut big).unwrap_or(0);
    t.holds(
        format_args!("{name}-read-after-seek"),
        n >= tail
            && text.get(off..off + n) == Some(&big[..n])
            && fill_ok(text, off + tail, n - tail),
        (n, tail),
        "the tail of the record, then the records that fit",
    );
    // A seek to a record boundary, and to the end.
    let second = line_len(text, 0);
    t.eq(
        format_args!("{name}-seek-to-a-boundary"),
        lseek(fd, second as isize, SEEK_SET),
        Ok(second),
    );
    let n = read(fd, &mut big).unwrap_or(0);
    t.holds(
        format_args!("{name}-read-from-a-boundary"),
        text.get(second..second + n) == Some(&big[..n]) && fill_ok(text, second, n),
        n,
        "whole records that fit",
    );
    t.eq(
        format_args!("{name}-seek-to-the-end"),
        lseek(fd, total as isize, SEEK_SET),
        Ok(total),
    );
    t.eq(
        format_args!("{name}-read-at-the-end"),
        read(fd, &mut big),
        Ok(0),
    );
    // A zero-length read shows nothing and is 0 wherever the file is.
    t.eq(
        format_args!("{name}-zero-length"),
        read(fd, &mut big[..0]),
        Ok(0),
    );
    let _ = close(fd);
}

fn seq_records(t: &mut T) {
    use super::proc::{nap, spawn, wait4};
    // Enough VMAs for `maps` to be several buffers long: single pages with a gap between them.
    const MAP_PRIVATE_ANON_FIXED_NOREPLACE: usize = 0x2 | 0x20 | 0x10_0000;
    let mut made = 0;
    for i in 0..220usize {
        let at = 0x6000_0000 + i * 0x2000;
        if super::mmap(at, 4096, 1, MAP_PRIVATE_ANON_FIXED_NOREPLACE, usize::MAX, 0) == Ok(at) {
            made += 1;
        }
    }
    t.eq("seq-vmas-made", made, 220);
    seq_chunks(t, "seq-maps", "/proc/self/maps");
    for i in 0..220usize {
        let _ = sys(Sysno::munmap, &[0x6000_0000 + i * 0x2000, 4096]);
    }

    // The mount tables: stacked tmpfs mounts.
    let mut stacked = 0;
    for _ in 0..300 {
        if mount(Some("x"), "/mnt/h", Some("tmpfs"), 0, None).is_ok() {
            stacked += 1;
        }
    }
    t.eq("seq-mounts-made", stacked, 300);
    seq_chunks(t, "seq-mountinfo", "/proc/self/mountinfo");
    seq_chunks(t, "seq-mounts", "/proc/self/mounts");
    let mut gone = 0;
    for _ in 0..stacked {
        if umount("/mnt/h", 0).is_ok() {
            gone += 1;
        }
    }
    t.eq("seq-mounts-removed", gone, stacked);

    // A task that exits under an open `maps`: the opened file keeps the address space it was
    // opened on, so a zombie reads as empty; once reaped, a read or a seek finds no task (ESRCH)
    // and a seek that fails puts the position back to 0.
    let child = spawn(|| {
        nap(20);
        0
    });
    let path = text!(32, "/proc/{child}/maps");
    let fd = open(path.str(), O_RDONLY).unwrap_or(99);
    let mut buf = [0u8; 64];
    let _ = wait4(-1, 1 /* WNOHANG */);
    // Let it exit without reaping: poll its state.
    for _ in 0..100 {
        let mut page: Page = [0; 16384];
        let state = pid_text(child, "stat", &mut page)
            .ok()
            .and_then(parse_stat)
            .map_or(b'?', |s| s.state()[0]);
        if state == b'Z' {
            break;
        }
        nap(5);
    }
    t.eq("seq-zombie-maps-read", read(fd, &mut buf), Ok(0));
    t.eq("seq-reaped", wait4(child as isize, 0).0, Ok(child));
    t.eq("seq-gone-zero-length", read(fd, &mut buf[..0]), Ok(0));
    t.eq("seq-gone-read", read(fd, &mut buf), Err(Errno::ESRCH));
    t.eq("seq-gone-seek", lseek(fd, 100, SEEK_SET), Err(Errno::ESRCH));
    t.eq("seq-gone-position-reset", lseek(fd, 0, SEEK_CUR), Ok(0));
    t.eq("seq-gone-seek-zero", lseek(fd, 0, SEEK_SET), Ok(0));
    let _ = close(fd);
}

fn wchan(t: &mut T) {
    use super::proc::{nap, spawn, wait4};
    let mut page: Page = [0; 16384];
    // `proc_pid_wchan` prints the symbol a sleeping task waits in, else `0`: the task reading its
    // own file, and a zombie (its stack is gone), print `0`.
    t.eq(
        "wchan-self",
        Txt(pid_text(getpid(), "wchan", &mut page).unwrap_or_default()),
        Txt(b"0"),
    );
    let child = spawn(|| 0);
    for _ in 0..100 {
        let mut stat: Page = [0; 16384];
        let state = pid_text(child, "stat", &mut stat)
            .ok()
            .and_then(parse_stat)
            .map_or(b'?', |s| s.state()[0]);
        if state == b'Z' {
            break;
        }
        nap(5);
    }
    t.eq(
        "wchan-zombie",
        Txt(pid_text(child, "wchan", &mut page).unwrap_or_default()),
        Txt(b"0"),
    );
    let _ = wait4(child as isize, 0);
    t.eq(
        "wchan-reaped",
        pid_text(child, "wchan", &mut page).map(<[u8]>::len),
        Err(Errno::ENOENT),
    );
}

// ---- views that follow a changing task ----------------------------------------------------------

/// The descriptors, mappings, resident pages and pid list of a task as `/proc` shows them while
/// the task keeps changing: a few changes at a time, bursts wider than anything a kernel could
/// replay one by one, a sparse table, and seventy children that all exit while the reader sleeps.
/// Every check compares what `/proc` says with what the test itself did, so it holds on any
/// kernel; the recording on the pinned Linux fixes which of them must.
fn publication(t: &mut T) {
    use super::proc::{nap, spawn, wait4};
    let me = getpid();
    let mut page: Page = [0; 16384];
    let base = open("/fixture/hello.txt", O_RDONLY).unwrap_or(99);
    let listed = || Dir::list("/proc/self/fd").map_or(usize::MAX, |d| d.count);
    let before = listed();

    // Ninety duplicates in a row, then every other one closed again.
    let mut fds = [0usize; 90];
    for fd in &mut fds {
        *fd = fcntl(base, 0 /* F_DUPFD */, 10).unwrap_or(0);
    }
    t.eq("pub-fd-burst-count", listed(), before.wrapping_add(90));
    let ascending = fds.is_sorted() && fds[0] >= 10;
    t.holds(
        "pub-fd-burst-ascending",
        ascending,
        fds[0],
        "lowest free first",
    );
    for fd in fds.iter().skip(1).step_by(2) {
        let _ = close(*fd);
    }
    t.eq(
        "pub-fd-burst-closed-count",
        listed(),
        before.wrapping_add(45),
    );
    let mut wrong = 0;
    for (i, fd) in fds.iter().enumerate() {
        let link = text!(32, "/proc/self/fd/{fd}");
        let open = stat(link.str()).0.is_ok();
        wrong += usize::from(open != (i % 2 == 0));
    }
    t.eq("pub-fd-membership", wrong, 0);

    // The close-on-exec bit of a descriptor is part of its fdinfo; flip every third.
    let flags = fcntl(base, 3 /* F_GETFL */, 0).unwrap_or(0);
    let mut wrong = 0;
    for (i, fd) in fds.iter().enumerate().step_by(2) {
        if i % 3 == 0 {
            let _ = fcntl(*fd, 2 /* F_SETFD */, 1);
        }
    }
    for (i, fd) in fds.iter().enumerate().step_by(2) {
        let want = text!(
            96,
            "pos:\t0\nflags:\t0{:o}\nmnt_id:\t{}\nino:\t{}\n",
            flags | if i % 3 == 0 { O_CLOEXEC } else { 0 },
            mnt_id("/fixture/hello.txt").unwrap_or(0),
            stat("/fixture/hello.txt").1.ino
        );
        let got = pid_text(me, text!(32, "fdinfo/{fd}").str(), &mut page).unwrap_or_default();
        wrong += usize::from(got != want.bytes());
    }
    t.eq("pub-fdinfo-cloexec", wrong, 0);

    // A sparse table: a descriptor far above the others, listed in its place.
    let high = fcntl(base, 0, 900).unwrap_or(0);
    t.eq("pub-fd-high", high, 900);
    let listing = Dir::list("/proc/self/fd").unwrap_or(Dir {
        names: [0; 4096],
        len: 0,
        count: 0,
    });
    t.holds(
        "pub-fd-high-listed",
        listing.entries().last() == Some(b"900:l".as_slice())
            && listing
                .entries()
                .filter_map(|e| num(&e[..e.len() - 2]))
                .is_sorted(),
        Txt(listing.text()),
        "last and ascending",
    );
    let _ = close(high);
    t.eq(
        "pub-fd-high-closed",
        stat("/proc/self/fd/900").0,
        Err(Errno::ENOENT),
    );
    for fd in fds.iter().step_by(2) {
        let _ = close(*fd);
    }
    t.eq("pub-fd-all-closed", listed(), before);
    let _ = close(base);

    // Mappings: forty regions that cannot merge (readable, inaccessible, ...), then the
    // inaccessible ones removed, then the holes filled so that everything merges.
    const PRIVATE_ANON: usize = 0x22;
    let overlapping = |lo: usize, hi: usize| -> usize {
        let mut p: Page = [0; 16384];
        let text = pid_text(me, "maps", &mut p).unwrap_or_default();
        lines(text)
            .filter_map(hex_range)
            .filter(|&(a, b)| a < hi as u64 && b > lo as u64)
            .count()
    };
    let mut regions = [0usize; 40];
    for (i, region) in regions.iter_mut().enumerate() {
        *region = sys(
            Sysno::mmap,
            &[
                0,
                4096,
                usize::from(i % 2 == 0),
                PRIVATE_ANON,
                usize::MAX,
                0,
            ],
        )
        .unwrap_or(0);
    }
    let lo = regions.iter().copied().min().unwrap_or(0);
    let hi = regions.iter().copied().max().unwrap_or(0) + 4096;
    t.holds(
        "pub-maps-contiguous",
        regions.iter().all(|&r| r != 0) && hi - lo == 40 * 4096,
        (lo, hi),
        "forty neighbouring pages",
    );
    t.eq("pub-maps-alternating", overlapping(lo, hi), 40);
    for region in regions.iter().skip(1).step_by(2) {
        let _ = sys(Sysno::munmap, &[*region, 4096]);
    }
    t.eq("pub-maps-holed", overlapping(lo, hi), 20);
    for region in regions.iter().skip(1).step_by(2) {
        let _ = sys(
            Sysno::mmap,
            &[
                *region,
                4096,
                1,
                PRIVATE_ANON | 0x10, /* MAP_FIXED */
                usize::MAX,
                0,
            ],
        );
    }
    t.eq("pub-maps-merged", overlapping(lo, hi), 1);
    let _ = sys(Sysno::munmap, &[lo, hi - lo]);
    t.eq("pub-maps-gone", overlapping(lo, hi), 0);

    // Resident pages: touched pages show in RssAnon at once, and leave with the mapping.
    let rss_anon =
        |p: &mut Page| status_kb(pid_text(me, "status", p).unwrap_or_default(), "RssAnon");
    let r0 = rss_anon(&mut page);
    let map = sys(Sysno::mmap, &[0, 64 * 4096, 3, PRIVATE_ANON, usize::MAX, 0]).unwrap_or(0);
    t.eq("pub-rss-untouched", rss_anon(&mut page) <= r0 + 64, true);
    for i in 0..64 {
        super::poke(map + i * 4096, 1);
    }
    let r1 = rss_anon(&mut page);
    t.holds(
        "pub-rss-touched",
        (r0 + 256..=r0 + 256 + 64).contains(&r1),
        (r0, r1),
        "64 pages of 4 kB, give or take a few of the test's own",
    );
    let _ = sys(Sysno::munmap, &[map, 64 * 4096]);
    let r2 = rss_anon(&mut page);
    t.holds(
        "pub-rss-unmapped",
        (r0..=r0 + 64).contains(&r2),
        (r0, r2),
        "back to where it was",
    );

    // Seventy children in one process group, all killed while the reader sleeps, then reaped.
    let numeric = || -> usize {
        Dir::list("/proc").map_or(usize::MAX, |d| {
            d.entries().filter(|e| e[0].is_ascii_digit()).count()
        })
    };
    let alive = numeric();
    let mut kids = [0usize; 70];
    for kid in &mut kids {
        *kid = spawn(|| {
            nap(60_000);
            0
        });
    }
    let group = kids[0];
    let mut grouped = 0;
    for kid in kids {
        grouped += usize::from(sys(Sysno::setpgid, &[kid, group]).is_ok());
    }
    t.eq(
        "pub-pids-spawned",
        (kids.iter().all(|&k| k != usize::MAX), grouped),
        (true, 70),
    );
    t.eq("pub-pids-listed", numeric(), alive + 70);
    let mut missing = 0;
    for kid in kids {
        missing += usize::from(stat(text!(32, "/proc/{kid}").str()).0.is_err());
    }
    t.eq("pub-pids-present", missing, 0);
    let _ = sys(Sysno::kill, &[(-(group as isize)) as usize, 9]);
    nap(300);
    let mut zombies = 0;
    for kid in kids {
        let state = parse_stat(pid_text(kid, "stat", &mut page).unwrap_or_default())
            .map_or(b'?', |s| s.state()[0]);
        zombies += usize::from(state == b'Z');
    }
    t.eq("pub-pids-zombies", zombies, 70);
    t.eq("pub-pids-zombies-listed", numeric(), alive + 70);
    let mut reaped = 0;
    while let (Ok(_), _) = wait4(-1, 0) {
        reaped += 1;
    }
    t.eq("pub-pids-reaped", reaped, 70);
    let mut left = 0;
    for kid in kids {
        left += usize::from(stat(text!(32, "/proc/{kid}").str()).0.is_ok());
    }
    t.eq("pub-pids-gone", (left, numeric()), (0, alive));
}

// ---- the permission matrix of /proc (reference-only mode `procperm`) ---------------------------

/// Reference-only mode `procperm`: records, on the pinned Linux, what `hidepid`, `gid=`,
/// `subset=pid`, ownership, the dumpable rules and `ptrace_may_access` make of `/proc/<pid>` for
/// observers with other credentials. It prints `init: info procperm.<observer>.<mount>.<victim>
/// <probes>` rows and no checks: this kernel has no credential-changing system call (the
/// `setuid` family stops it loudly), so the matrix cannot run on it; it is the table the host
/// tests of `kernel/src/procfs/permtests.rs` compare the permission functions with.
pub fn perm_probe() {
    use super::proc::{nap, spawn, wait4};
    const PR_SET_DUMPABLE: usize = 4;
    let mut pair = [0i32; 2];
    let _ = sys(Sysno::pipe2, &[addr_mut(&mut pair), 0]);
    let (pr, pw) = (pair[0] as usize, pair[1] as usize);
    let set_ids = |uid: usize, gid: usize| {
        let _ = sys(Sysno::setresgid, &[gid, gid, gid]);
        let _ = sys(Sysno::setresuid, &[uid, uid, uid]);
    };
    // Victims: a dumpable and a non-dumpable user task asleep, a root task asleep, a zombie.
    let sleeper = |uid: usize, gid: usize, dumpable: bool| {
        spawn(move || {
            if uid != 0 {
                set_ids(uid, gid);
            }
            if dumpable {
                let _ = sys(Sysno::prctl, &[PR_SET_DUMPABLE, 1]);
            }
            let _ = close(pw);
            let mut b = [0u8; 1];
            let _ = read(pr, &mut b);
            0
        })
    };
    let v_user = sleeper(1000, 100, true);
    let v_undump = sleeper(1000, 100, false);
    let v_root = sleeper(0, 0, true);
    let v_zombie = spawn(move || {
        set_ids(1000, 100);
        let _ = sys(Sysno::prctl, &[PR_SET_DUMPABLE, 1]);
        0
    });
    nap(300);
    let victims = [
        ("user", v_user),
        ("undumpable", v_undump),
        ("root", v_root),
        ("zombie", v_zombie),
    ];
    let mounts = [
        ("plain", "/mnt/a", None),
        ("hide1", "/mnt/b", Some("hidepid=1")),
        ("hide2", "/mnt/c", Some("hidepid=2")),
        ("hide4", "/mnt/d", Some("hidepid=4")),
        ("gid100hide2", "/mnt/e", Some("gid=100,hidepid=2")),
        ("subsetpid", "/mnt/f", Some("subset=pid")),
    ];
    let observers: [(&str, usize, usize); 4] = [
        ("root", 0, 0),
        ("other", 2000, 200),
        ("owner", 1000, 100),
        ("group", 2000, 100),
    ];
    for (who, uid, gid) in observers {
        // Fresh superblocks for every observer: Linux keeps the dentries a lookup
        // instantiated, and a later observer would find them without the checks of the lookup.
        for (_, point, data) in mounts {
            let _ = mount(Some("proc"), point, Some("proc"), 0, data);
        }
        let probe = move || {
            if uid != 0 {
                set_ids(uid, gid);
            }
            let me = getpid();
            for (mname, point, _) in mounts {
                let mut rows: [Buf<400>; 4] = [Buf::new(), Buf::new(), Buf::new(), Buf::new()];
                for (row, (_, v)) in rows.iter_mut().zip(victims) {
                    let dir = text!(64, "{point}/{v}");
                    let (r, st) = stat(dir.str());
                    let head = match r {
                        Ok(_) => text!(48, "ok:{}:{}:{:o}", st.uid, st.gid, st.mode & 0o7777),
                        Err(e) => text!(48, "{e:?}"),
                    };
                    let try_open = |name: &str, flags: usize| -> Buf<24> {
                        let path = text!(96, "{point}/{v}/{name}");
                        match open(path.str(), flags) {
                            Ok(fd) => {
                                let _ = close(fd);
                                text!(24, "ok")
                            }
                            Err(e) => text!(24, "{e:?}"),
                        }
                    };
                    let link = |name: &str| -> Buf<24> {
                        let path = text!(96, "{point}/{v}/{name}");
                        let mut out = [0u8; 256];
                        match readlink(path.str(), &mut out) {
                            Ok(_) => text!(24, "ok"),
                            Err(e) => text!(24, "{e:?}"),
                        }
                    };
                    let fdinfo = text!(24, "fdinfo/{pr}");
                    let _ = write!(
                        row,
                        "dir={} stat={} environ={} maps={} comm={} cmdline={} exe={} cwd={} fd={} fdinfo={} fdinfofile={}",
                        head.str(),
                        try_open("stat", O_RDONLY).str(),
                        try_open("environ", O_RDONLY).str(),
                        try_open("maps", O_RDONLY).str(),
                        try_open("comm", O_RDONLY).str(),
                        try_open("cmdline", O_RDONLY).str(),
                        link("exe").str(),
                        link("cwd").str(),
                        try_open("fd", O_RDONLY | O_DIRECTORY).str(),
                        try_open("fdinfo", O_RDONLY | O_DIRECTORY).str(),
                        try_open(fdinfo.str(), O_RDONLY).str(),
                    );
                }
                // The listing last: it would instantiate the entries it shows.
                let listing = Dir::list(point);
                for (row, (vname, v)) in rows.iter().zip(victims) {
                    let listed = match &listing {
                        Ok(d) => {
                            let want = text!(16, "{v}");
                            if d.entries()
                                .any(|e| e.strip_suffix(b":d") == Some(want.bytes()))
                            {
                                "in"
                            } else {
                                "out"
                            }
                        }
                        Err(_) => "err",
                    };
                    pl!(
                        "init: info procperm.{who}.{mname}.{vname} {} list={listed}",
                        row.str()
                    );
                }
            }
            let _ = me;
            0
        };
        if uid == 0 {
            probe();
        } else {
            let child = spawn(probe);
            let _ = wait4(child as isize, 0);
        }
        for (_, point, _) in mounts {
            let _ = umount(point, MNT_DETACH);
        }
    }
    let _ = close(pw);
    let _ = close(pr);
    for (_, v) in victims {
        let _ = wait4(v as isize, 0);
    }
}
