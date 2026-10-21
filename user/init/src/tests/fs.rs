// SPDX-License-Identifier: GPL-2.0-only
//! `fs` group: the initramfs (`/init`, `/linuxrc`, the `fixture` tree of `xtask/src/fixture.rs`),
//! descriptors, `/dev/console` on fds 0-2 and the devtmpfs nodes the boot provides. Linux
//! 6.18.57: `fs/open.c`, `fs/read_write.c`, `fs/stat.c`, `fs/readdir.c`, `fs/fcntl.c`, `fs/file.c`,
//! `fs/namei.c`, `mm/shmem.c` (the rootfs is tmpfs), `drivers/base/devtmpfs.c`,
//! `drivers/tty/tty_io.c`, `drivers/char/mem.c`.

use syscalls::{Errno, Sysno};

use super::{PAGE, R, T, addr, addr_mut, mmap, peek, sys};

const BAD: usize = 0xdead_0000_0000;
const AT_FDCWD: usize = -100isize as usize;
const AT_SYMLINK_NOFOLLOW: usize = 0x100;
const AT_EMPTY_PATH: usize = 0x1000;

const O_RDONLY: usize = 0;
const O_WRONLY: usize = 1;
const O_RDWR: usize = 2;
const O_CREAT: usize = 0o100;
const O_EXCL: usize = 0o200;
const O_NONBLOCK: usize = 0o4000;
const O_APPEND: usize = 0o2000;
const O_DIRECTORY: usize = 0o200_000;
const O_NOFOLLOW: usize = 0o400_000;
const O_CLOEXEC: usize = 0o2_000_000;
const O_LARGEFILE: usize = 0o100_000;

const S_IFMT: u32 = 0o170_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFCHR: u32 = 0o020_000;
const S_IFREG: u32 = 0o100_000;
const S_IFLNK: u32 = 0o120_000;

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct Stat {
    pub dev: u64,
    pub ino: u64,
    pub nlink: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pad0: u32,
    pub rdev: u64,
    pub size: i64,
    pub blksize: i64,
    pub blocks: i64,
    pub atime: [i64; 2],
    pub mtime: [i64; 2],
    pub ctime: [i64; 2],
    unused: [i64; 3],
}

fn open(path: &[u8], flags: usize, mode: usize) -> R {
    sys(Sysno::open, &[addr(path), flags, mode])
}

fn openat(dirfd: usize, path: &[u8], flags: usize) -> R {
    sys(Sysno::openat, &[dirfd, addr(path), flags, 0])
}

fn close(fd: usize) -> R {
    sys(Sysno::close, &[fd])
}

fn stat_path(path: &[u8]) -> (R, Stat) {
    let mut st = Stat::default();
    (sys(Sysno::stat, &[addr(path), addr_mut(&mut st)]), st)
}

fn fstat(fd: usize) -> (R, Stat) {
    let mut st = Stat::default();
    (sys(Sysno::fstat, &[fd, addr_mut(&mut st)]), st)
}

fn fstatat(dirfd: usize, path: &[u8], flags: usize) -> (R, Stat) {
    let mut st = Stat::default();
    (
        sys(
            Sysno::newfstatat,
            &[dirfd, addr(path), addr_mut(&mut st), flags],
        ),
        st,
    )
}

fn read(fd: usize, buf: &mut [u8]) -> R {
    sys(Sysno::read, &[fd, addr_mut(buf), buf.len()])
}

fn lseek(fd: usize, off: isize, whence: usize) -> R {
    sys(Sysno::lseek, &[fd, off as usize, whence])
}

fn fcntl(fd: usize, cmd: usize, arg: usize) -> R {
    sys(Sysno::fcntl, &[fd, cmd, arg])
}

fn major(rdev: u64) -> u64 {
    ((rdev >> 8) & 0xfff) | ((rdev >> 32) & !0xfff)
}

fn minor(rdev: u64) -> u64 {
    (rdev & 0xff) | ((rdev >> 12) & !0xff)
}

/// One `linux_dirent64`: inode, offset, type, name (borrowed from the buffer).
struct Dirent<'a> {
    ino: u64,
    off: i64,
    kind: u8,
    name: &'a [u8],
}

/// The entries of a getdents64 buffer of `len` valid bytes, or `None` if the framing is invalid.
fn dirents(buf: &[u8], len: usize) -> Option<([Option<Dirent<'_>>; 24], usize)> {
    let mut out: [Option<Dirent<'_>>; 24] = [const { None }; 24];
    let (mut at, mut n) = (0, 0);
    while at < len {
        let head = buf.get(at..at + 19)?;
        let reclen = usize::from(u16::from_le_bytes([head[16], head[17]]));
        let rec = buf.get(at..at + reclen)?;
        let name = rec.get(19..)?;
        let end = name.iter().position(|&b| b == 0)?;
        if reclen % 8 != 0 || n == out.len() {
            return None;
        }
        out[n] = Some(Dirent {
            ino: u64::from_le_bytes(head[0..8].try_into().ok()?),
            off: i64::from_le_bytes(head[8..16].try_into().ok()?),
            kind: head[18],
            name: &name[..end],
        });
        n += 1;
        at += reclen;
    }
    Some((out, n))
}

/// Names of `path`'s entries in kernel order, joined by `,` into `names`; returns the byte count.
fn list(path: &[u8], names: &mut [u8; 512]) -> Result<usize, Errno> {
    let fd = open(path, O_RDONLY | O_DIRECTORY, 0)?;
    let mut buf = [0u8; 2048];
    let mut used = 0;
    loop {
        let n = sys(Sysno::getdents64, &[fd, addr_mut(&mut buf), buf.len()])?;
        if n == 0 {
            break;
        }
        let Some((entries, count)) = dirents(&buf, n) else {
            let _ = close(fd);
            return Err(Errno::EIO);
        };
        for e in entries.into_iter().take(count).flatten() {
            if e.name == b"." || e.name == b".." {
                continue;
            }
            if used + e.name.len() + 1 > names.len() {
                break;
            }
            if used > 0 {
                names[used] = b',';
                used += 1;
            }
            names[used..used + e.name.len()].copy_from_slice(e.name);
            used += e.name.len();
        }
    }
    let _ = close(fd);
    Ok(used)
}

/// The `fs` group.
pub fn run() -> bool {
    let mut t = T::new("fs");
    console(&mut t);
    initramfs_files(&mut t);
    stat_family(&mut t);
    directories(&mut t);
    open_errors(&mut t);
    descriptors(&mut t);
    links(&mut t);
    creating(&mut t);
    mapping(&mut t);
    devices(&mut t);
    t.finish()
}

fn console(t: &mut T) {
    // The kernel opens /dev/console three times before running init (`console_on_rootfs`).
    let (r0, s0) = fstat(0);
    let (r1, s1) = fstat(1);
    let (r2, s2) = fstat(2);
    t.eq("console-fstat", (r0, r1, r2), (Ok(0), Ok(0), Ok(0)));
    // `default_rootfs` (init/noinitramfs.c) mknods /dev/console 0600; no devtmpfs is mounted.
    t.eq(
        "console-is-char-device-5-1",
        (s0.mode, major(s0.rdev), minor(s0.rdev)),
        (S_IFCHR | 0o600, 5, 1),
    );
    t.eq(
        "console-fds-share-one-device",
        (
            s0.rdev,
            s1.rdev,
            s2.rdev,
            s0.ino == s1.ino,
            s1.ino == s2.ino,
        ),
        (s0.rdev, s0.rdev, s0.rdev, true, true),
    );
    t.eq("console-owner", (s0.uid, s0.gid, s0.nlink), (0, 0, 1));
    for fd in 0..3 {
        // Opened by the kernel itself, so without the O_LARGEFILE a user `open` adds on x86-64.
        t.eq(
            format_args!("console-fd{fd}-flags"),
            fcntl(fd, 3, 0),
            Ok(O_RDWR),
        );
        t.eq(
            format_args!("console-fd{fd}-cloexec"),
            fcntl(fd, 1, 0),
            Ok(0),
        );
        t.eq(
            format_args!("console-fd{fd}-is-tty"),
            sys(Sysno::ioctl, &[fd, 0x5401, addr_mut(&mut [0u8; 64])]),
            Ok(0),
        );
    }
    let (rc, sc) = stat_path(b"/dev/console\0");
    t.eq(
        "console-node",
        (rc, sc.rdev, sc.mode),
        (Ok(0), s0.rdev, s0.mode),
    );
    t.holds(
        "console-shares-inode-with-dev-console",
        sc.ino == s0.ino && sc.dev == s0.dev,
        (sc.ino, s0.ino),
        "the same inode",
    );
    t.eq("console-no-seek", lseek(1, 0, 0), Err(Errno::ESPIPE));
    t.eq(
        "console-pread",
        sys(Sysno::pread64, &[1, addr_mut(&mut [0u8; 4]), 4, 0]),
        Err(Errno::ESPIPE),
    );
    t.eq(
        "console-write-zero",
        sys(Sysno::write, &[1, addr(b"x"), 0]),
        Ok(0),
    );
    t.eq(
        "console-tcgets-fault",
        sys(Sysno::ioctl, &[1, 0x5401, BAD]),
        Err(Errno::EFAULT),
    );
    // `tty_std_termios` with the ttyS0 console's `c_cflag` (`uart_set_options`: B9600 | CS8 |
    // CREAD | HUPCL | CLOCAL): c_iflag ICRNL|IXON, c_oflag OPOST|ONLCR, c_lflag ISIG|ICANON|ECHO|
    // ECHOE|ECHOK|ECHOCTL|ECHOKE|IEXTEN, c_line N_TTY, then INIT_C_CC.
    let mut want = [0u8; 36];
    for (i, word) in [0o2400u32, 0o5, 0o6275, 0o105_073].into_iter().enumerate() {
        want[4 * i..4 * i + 4].copy_from_slice(&word.to_le_bytes());
    }
    want[17..34].copy_from_slice(&[3, 28, 127, 21, 4, 0, 1, 0, 17, 19, 26, 0, 18, 15, 23, 22, 0]);
    let mut termios = [0u8; 36];
    t.eq(
        "console-tcgets-termios",
        (
            sys(Sysno::ioctl, &[1, 0x5401, addr_mut(&mut termios)]),
            termios,
        ),
        (Ok(0), want),
    );
    t.eq(
        "console-ioctl-unknown",
        sys(Sysno::ioctl, &[1, 0xdead, 0]),
        Err(Errno::ENOTTY),
    );
    t.eq(
        "console-tiocgwinsz",
        sys(Sysno::ioctl, &[1, 0x5413, addr_mut(&mut [0u8; 8])]),
        Ok(0),
    );
    t.eq(
        "console-tiocgpgrp",
        sys(Sysno::ioctl, &[1, 0x540f, addr_mut(&mut [0u8; 4])]),
        Err(Errno::ENOTTY),
    );
}

fn initramfs_files(t: &mut T) {
    let mut buf = [0u8; 64];
    let fd = open(b"/init\0", O_RDONLY, 0);
    t.eq("open-init-lowest-fd", fd, Ok(3));
    let fd = fd.unwrap_or(99);
    t.eq(
        "read-init-magic",
        (read(fd, &mut buf[..4]), &buf[..4]),
        (Ok(4), b"\x7fELF".as_slice()),
    );
    t.eq("offset-after-read", lseek(fd, 0, 1), Ok(4));
    t.eq(
        "pread-keeps-offset",
        (
            sys(Sysno::pread64, &[fd, addr_mut(&mut buf), 3, 1]),
            &buf[..3],
            lseek(fd, 0, 1),
        ),
        (Ok(3), b"ELF".as_slice(), Ok(4)),
    );
    let size = fstat(fd).1.size;
    t.eq("lseek-end", lseek(fd, 0, 2), Ok(size as usize));
    t.eq("lseek-end-minus", lseek(fd, -4, 2), Ok(size as usize - 4));
    t.eq("read-at-end-part", read(fd, &mut buf), Ok(4));
    t.eq("read-at-eof", read(fd, &mut buf), Ok(0));
    t.eq("lseek-past-end", lseek(fd, 1 << 20, 0), Ok(1 << 20));
    t.eq("read-past-end", read(fd, &mut buf), Ok(0));
    t.eq("lseek-negative", lseek(fd, -1, 0), Err(Errno::EINVAL));
    t.eq(
        "lseek-negative-from-cur",
        lseek(fd, -(1 << 21), 1),
        Err(Errno::EINVAL),
    );
    t.eq("lseek-bad-whence", lseek(fd, 0, 7), Err(Errno::EINVAL));
    t.eq("lseek-set-zero", lseek(fd, 0, 0), Ok(0));
    t.eq(
        "pread-negative-offset",
        sys(Sysno::pread64, &[fd, addr_mut(&mut buf), 4, usize::MAX]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "pread-past-end",
        sys(Sysno::pread64, &[fd, addr_mut(&mut buf), 4, 1 << 40]),
        Ok(0),
    );
    t.eq(
        "read-fault",
        sys(Sysno::read, &[fd, BAD, 4]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "read-null",
        sys(Sysno::read, &[fd, 0, 4]),
        Err(Errno::EFAULT),
    );
    // The address is checked even for a zero length when it lies beyond the user address space ...
    t.eq(
        "read-zero-length-kernel-address",
        sys(Sysno::read, &[fd, BAD, 0]),
        Err(Errno::EFAULT),
    );
    // ... but an unmapped user address is never touched for zero bytes.
    t.eq(
        "read-zero-length-unmapped-user-address",
        sys(Sysno::read, &[fd, 0x7000_0000_0000, 0]),
        Ok(0),
    );
    t.eq(
        "write-to-read-only-fd",
        sys(Sysno::write, &[fd, addr(b"x"), 1]),
        Err(Errno::EBADF),
    );
    t.eq("close-init", close(fd), Ok(0));
    t.eq("close-again", close(fd), Err(Errno::EBADF));

    // The fixture text file.
    let fd = open(b"/fixture/hello.txt\0", O_RDONLY, 0).unwrap_or(99);
    t.eq("hello-fd-reuses-lowest", fd, 3);
    t.eq(
        "hello-read",
        (read(fd, &mut buf), &buf[..14]),
        (Ok(14), b"hello, oracle\n".as_slice()),
    );
    t.eq("hello-eof", read(fd, &mut buf), Ok(0));
    t.eq(
        "hello-pread-middle",
        (
            sys(Sysno::pread64, &[fd, addr_mut(&mut buf), 6, 7]),
            &buf[..6],
        ),
        (Ok(6), b"oracle".as_slice()),
    );
    t.eq(
        "hello-pread-short",
        (
            sys(Sysno::pread64, &[fd, addr_mut(&mut buf), 100, 12]),
            &buf[..2],
        ),
        (Ok(2), b"e\n".as_slice()),
    );
    let mut a = [0u8; 5];
    let mut b = [0u8; 20];
    let iov = [[addr_mut(&mut a), 5], [addr_mut(&mut b), 20]];
    t.eq(
        "hello-preadv",
        (sys(Sysno::preadv, &[fd, addr(&iov), 2, 7]), &a[..], &b[..7]),
        (Ok(7), b"oracl".as_slice(), b"e\n\0\0\0\0\0".as_slice()),
    );
    let _ = lseek(fd, 0, 0);
    let mut a = [0u8; 7];
    let mut b = [0u8; 20];
    let iov = [[addr_mut(&mut a), 7], [addr_mut(&mut b), 20]];
    t.eq(
        "hello-readv",
        (sys(Sysno::readv, &[fd, addr(&iov), 2]), &a[..], &b[..7]),
        (Ok(14), b"hello, ".as_slice(), b"oracle\n".as_slice()),
    );
    t.eq(
        "readv-bad-count",
        sys(Sysno::readv, &[fd, addr(&iov), 2000]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "readv-fault",
        sys(Sysno::readv, &[fd, BAD, 2]),
        Err(Errno::EFAULT),
    );
    t.eq("readv-zero", sys(Sysno::readv, &[fd, addr(&iov), 0]), Ok(0));
    t.eq("hello-close", close(fd), Ok(0));
    let fd = open(b"/fixture/empty\0", O_RDONLY, 0).unwrap_or(99);
    t.eq("empty-read", read(fd, &mut buf), Ok(0));
    t.eq("empty-size", fstat(fd).1.size, 0);
    let _ = close(fd);
    // /linuxrc is a symlink to /init.
    let fd = open(b"/linuxrc\0", O_RDONLY, 0).unwrap_or(99);
    t.eq(
        "linuxrc-follows-to-init",
        (read(fd, &mut buf[..4]), &buf[..4]),
        (Ok(4), b"\x7fELF".as_slice()),
    );
    t.eq(
        "linuxrc-same-inode-as-init",
        fstat(fd).1.ino,
        stat_path(b"/init\0").1.ino,
    );
    let _ = close(fd);
    let fd = open(b"/fixture/noexec\0", O_RDONLY, 0).unwrap_or(99);
    t.eq(
        "noexec-content",
        (read(fd, &mut buf), &buf[..18]),
        (Ok(18), b"not an executable\n".as_slice()),
    );
    let _ = close(fd);
}

fn stat_family(t: &mut T) {
    let (r, hello) = stat_path(b"/fixture/hello.txt\0");
    t.eq("stat-hello", r, Ok(0));
    t.eq(
        "stat-hello-mode-size",
        (hello.mode, hello.size, hello.nlink, hello.uid, hello.gid),
        (S_IFREG | 0o644, 14, 1, 0, 0),
    );
    t.eq("stat-hello-blksize", hello.blksize, 4096);
    t.eq("stat-hello-blocks", hello.blocks, 8);
    // The archive header's mtime (0) is applied; atime and ctime are the unpack time.
    t.eq("stat-hello-mtime-from-archive", hello.mtime, [0, 0]);
    t.eq("stat-hello-rdev", hello.rdev, 0);
    let (_, init) = stat_path(b"/init\0");
    t.eq(
        "stat-init-mode",
        (init.mode, init.nlink, init.uid, init.gid),
        (S_IFREG | 0o755, 1, 0, 0),
    );
    t.holds(
        "stat-init-size",
        init.size > 4096 && init.blocks >= init.size / 512,
        (init.size, init.blocks),
        "size > 4096, blocks cover it",
    );
    t.eq(
        "stat-same-device",
        (init.dev == hello.dev, init.ino != hello.ino),
        (true, true),
    );
    let (_, root) = stat_path(b"/\0");
    t.eq(
        "stat-root",
        (root.mode, root.nlink, root.uid, root.gid),
        // /dev, /root, /fixture, /proc and /mnt
        (S_IFDIR | 0o1777, 7, 0, 0),
    );
    t.eq("stat-root-same-dev", root.dev, init.dev);
    let (_, fixture) = stat_path(b"/fixture\0");
    t.eq(
        "stat-fixture-dir",
        (fixture.mode, fixture.nlink, fixture.size),
        (S_IFDIR | 0o755, 3, 40 + 5 * 20),
    );
    let (_, sub) = stat_path(b"/fixture/sub\0");
    t.eq(
        "stat-sub-dir",
        (sub.mode, sub.nlink, sub.size),
        (S_IFDIR | 0o755, 2, 40 + 20),
    );
    let (_, empty) = stat_path(b"/fixture/empty\0");
    t.eq(
        "stat-empty",
        (empty.size, empty.blocks, empty.mode),
        (0, 0, S_IFREG | 0o644),
    );
    let (_, noexec) = stat_path(b"/fixture/noexec\0");
    t.eq(
        "stat-noexec",
        (noexec.mode, noexec.size),
        (S_IFREG | 0o755, 18),
    );
    // lstat / AT_SYMLINK_NOFOLLOW see the link itself.
    let mut st = Stat::default();
    t.eq(
        "lstat-link",
        (
            sys(Sysno::lstat, &[addr(b"/fixture/link\0"), addr_mut(&mut st)]),
            st.mode,
            st.size,
            st.nlink,
        ),
        (Ok(0), S_IFLNK | 0o777, 9, 1),
    );
    t.eq(
        "stat-link-follows",
        (
            stat_path(b"/fixture/link\0").1.mode,
            stat_path(b"/fixture/link\0").1.size,
        ),
        (S_IFREG | 0o644, 14),
    );
    let (r, nf) = fstatat(AT_FDCWD, b"/linuxrc\0", AT_SYMLINK_NOFOLLOW);
    t.eq(
        "fstatat-nofollow",
        (r, nf.mode, nf.size),
        (Ok(0), S_IFLNK | 0o777, 5),
    );
    let (r, fl) = fstatat(AT_FDCWD, b"/linuxrc\0", 0);
    t.eq(
        "fstatat-follow",
        (r, fl.mode, fl.ino),
        (Ok(0), S_IFREG | 0o755, init.ino),
    );
    // Relative paths and directory descriptors.
    let (r, rel) = fstatat(AT_FDCWD, b"fixture/hello.txt\0", 0);
    t.eq("fstatat-relative-to-cwd", (r, rel.ino), (Ok(0), hello.ino));
    let dfd = open(b"/fixture\0", O_RDONLY | O_DIRECTORY, 0).unwrap_or(99);
    let (r, rel) = fstatat(dfd, b"hello.txt\0", 0);
    t.eq(
        "fstatat-relative-to-dirfd",
        (r, rel.ino),
        (Ok(0), hello.ino),
    );
    let (r, rel) = fstatat(dfd, b"/fixture/hello.txt\0", 0);
    t.eq(
        "fstatat-absolute-ignores-dirfd",
        (r, rel.ino),
        (Ok(0), hello.ino),
    );
    let (r, me) = fstatat(dfd, b"\0", AT_EMPTY_PATH);
    t.eq(
        "fstatat-empty-path-dirfd",
        (r, me.mode),
        (Ok(0), S_IFDIR | 0o755),
    );
    let (r, me) = fstatat(AT_FDCWD, b"\0", AT_EMPTY_PATH);
    t.eq(
        "fstatat-empty-path-cwd",
        (r, me.mode, me.ino),
        (Ok(0), S_IFDIR | 0o1777, root.ino),
    );
    t.eq(
        "fstatat-empty-path-without-flag",
        fstatat(dfd, b"\0", 0).0,
        Err(Errno::ENOENT),
    );
    t.eq(
        "fstatat-bad-flags",
        fstatat(dfd, b"hello.txt\0", 0x8000_0000).0,
        Err(Errno::EINVAL),
    );
    t.eq(
        "fstatat-bad-dirfd",
        fstatat(999, b"hello.txt\0", 0).0,
        Err(Errno::EBADF),
    );
    t.eq(
        "fstatat-bad-dirfd-absolute-ok",
        fstatat(999, b"/init\0", 0).0,
        Ok(0),
    );
    let file = open(b"/init\0", O_RDONLY, 0).unwrap_or(99);
    t.eq(
        "fstatat-dirfd-is-file",
        fstatat(file, b"x\0", 0).0,
        Err(Errno::ENOTDIR),
    );
    t.eq(
        "fstatat-fault",
        sys(Sysno::newfstatat, &[AT_FDCWD, BAD, addr_mut(&mut st), 0]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "fstatat-fault-buffer",
        sys(Sysno::newfstatat, &[AT_FDCWD, addr(b"/init\0"), BAD, 0]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "fstat-same-as-stat",
        (fstat(file).1.ino, fstat(file).1.size),
        (init.ino, init.size),
    );
    t.eq("fstat-bad-fd", fstat(999).0, Err(Errno::EBADF));
    t.eq(
        "fstat-fault",
        sys(Sysno::fstat, &[file, BAD]),
        Err(Errno::EFAULT),
    );
    let _ = close(file);
    let _ = close(dfd);
    t.eq(
        "stat-missing",
        stat_path(b"/nonexistent\0").0,
        Err(Errno::ENOENT),
    );
    t.eq(
        "stat-through-file",
        stat_path(b"/init/x\0").0,
        Err(Errno::ENOTDIR),
    );
    t.eq("stat-empty-path", stat_path(b"\0").0, Err(Errno::ENOENT));
    // statx.
    let mut stx = [0u8; 256];
    let r = sys(
        Sysno::statx,
        &[
            AT_FDCWD,
            addr(b"/fixture/hello.txt\0"),
            0,
            0x7ff,
            addr_mut(&mut stx),
        ],
    );
    let u32at = |o: usize| u32::from_le_bytes([stx[o], stx[o + 1], stx[o + 2], stx[o + 3]]);
    let u64at = |o: usize| u64::from_le_bytes(stx[o..o + 8].try_into().unwrap_or([0; 8]));
    t.eq("statx", r, Ok(0));
    t.eq("statx-mask-basic", u32at(0) & 0x7ff, 0x7ff);
    t.eq(
        "statx-fields",
        (
            u32at(16),
            u32at(20),
            u32at(24),
            u32at(28) & 0xffff,
            u64at(40),
            u32at(4),
        ),
        (1, 0, 0, S_IFREG | 0o644, 14, 4096),
    );
    t.eq("statx-ino-matches-stat", u64at(32), hello.ino);
    t.eq(
        "statx-bad-flags",
        sys(
            Sysno::statx,
            &[
                AT_FDCWD,
                addr(b"/init\0"),
                0x8000_0000,
                0x7ff,
                addr_mut(&mut stx),
            ],
        ),
        Err(Errno::EINVAL),
    );
    t.eq(
        "statx-reserved-mask-bit",
        sys(
            Sysno::statx,
            &[
                AT_FDCWD,
                addr(b"/init\0"),
                0,
                0x8000_0000,
                addr_mut(&mut stx),
            ],
        ),
        Err(Errno::EINVAL),
    );
    t.eq(
        "statx-missing",
        sys(
            Sysno::statx,
            &[
                AT_FDCWD,
                addr(b"/nonexistent\0"),
                0,
                0x7ff,
                addr_mut(&mut stx),
            ],
        ),
        Err(Errno::ENOENT),
    );
    t.eq(
        "statx-fault",
        sys(Sysno::statx, &[AT_FDCWD, addr(b"/init\0"), 0, 0x7ff, BAD]),
        Err(Errno::EFAULT),
    );
    // access(2) as root: read/write always, execute only with an x bit somewhere.
    let access = |p: &[u8], mode: usize| sys(Sysno::access, &[addr(p), mode]);
    t.eq("access-exists", access(b"/fixture/hello.txt\0", 0), Ok(0));
    t.eq(
        "access-read-write",
        access(b"/fixture/hello.txt\0", 6),
        Ok(0),
    );
    t.eq(
        "access-exec-no-x-bit",
        access(b"/fixture/hello.txt\0", 1),
        Err(Errno::EACCES),
    );
    t.eq(
        "access-exec-with-x-bit",
        access(b"/fixture/noexec\0", 1),
        Ok(0),
    );
    t.eq("access-dir-exec", access(b"/fixture\0", 1), Ok(0));
    t.eq(
        "access-missing",
        access(b"/nonexistent\0", 0),
        Err(Errno::ENOENT),
    );
    t.eq("access-bad-mode", access(b"/init\0", 8), Err(Errno::EINVAL));
    t.eq(
        "faccessat-relative",
        sys(Sysno::faccessat, &[AT_FDCWD, addr(b"fixture\0"), 0]),
        Ok(0),
    );
    t.eq(
        "faccessat2-bad-flags",
        sys(
            Sysno::faccessat2,
            &[AT_FDCWD, addr(b"fixture\0"), 0, 0x8000_0000],
        ),
        Err(Errno::EINVAL),
    );
}

fn directories(t: &mut T) {
    let mut names = [0u8; 512];
    // tmpfs lists the newest entry first (`offset_readdir`): `default_rootfs` made dev and root,
    // then the archive added init, linuxrc and fixture.
    let n = list(b"/\0", &mut names).unwrap_or(0);
    t.eq(
        "getdents-root-order",
        &names[..n],
        b"mnt,proc,fixture,linuxrc,init,root,dev".as_slice(),
    );
    let n = list(b"/fixture\0", &mut names).unwrap_or(0);
    t.eq(
        "getdents-fixture-order",
        &names[..n],
        b"link,sub,noexec,empty,hello.txt".as_slice(),
    );
    let n = list(b"/fixture/sub\0", &mut names).unwrap_or(0);
    t.eq("getdents-sub", &names[..n], b"nested.txt".as_slice());
    let fd = open(b"/fixture\0", O_RDONLY | O_DIRECTORY, 0).unwrap_or(99);
    let mut buf = [0u8; 1024];
    let r = sys(Sysno::getdents64, &[fd, addr_mut(&mut buf), buf.len()]);
    let len = r.unwrap_or(0);
    t.holds(
        "getdents-first-call",
        len > 0 && len % 8 == 0,
        r,
        "one call returns every entry, 8-byte aligned records",
    );
    let parsed = dirents(&buf, len);
    let (entries, count) = parsed.unwrap_or(([const { None }; 24], 0));
    let entry = |i: usize| entries[i].as_ref();
    t.eq("getdents-count", count, 7);
    t.eq(
        "getdents-dot-first",
        (entry(0).map(|e| e.name), entry(0).map(|e| e.kind)),
        (Some(b".".as_slice()), Some(4)),
    );
    t.eq(
        "getdents-dotdot-second",
        (entry(1).map(|e| e.name), entry(1).map(|e| e.kind)),
        (Some(b"..".as_slice()), Some(4)),
    );
    let kinds: [Option<u8>; 5] = [2, 3, 4, 5, 6].map(|i| entry(i).map(|e| e.kind));
    t.eq(
        "getdents-d_type",
        kinds,
        [Some(10), Some(4), Some(8), Some(8), Some(8)],
    );
    let hello_ino = stat_path(b"/fixture/hello.txt\0").1.ino;
    t.holds(
        "getdents-inodes-match-stat",
        entry(6).is_some_and(|e| e.name == b"hello.txt" && e.ino == hello_ino),
        entry(6).map(|e| e.ino),
        "d_ino == st_ino",
    );
    t.eq(
        "getdents-dotdot-ino-is-root",
        entry(1).map(|e| e.ino),
        Some(stat_path(b"/\0").1.ino),
    );
    let offs: [Option<i64>; 7] = [0, 1, 2, 3, 4, 5, 6].map(|i| entry(i).map(|e| e.off));
    // tmpfs `d_off` is the offset of the *next* entry (`offset_readdir`), ending in DIR_OFFSET_EOD
    // (`S32_MAX`); recorded as information, not matched by the future harness case.
    t.info("getdents-d_off", format_args!("{offs:?}"));
    t.eq(
        "getdents-d_off-cookie-seek",
        {
            // Seeking to a d_off continues after that entry.
            let after = entry(4).map_or(0, |e| e.off);
            let _ = lseek(fd, after as isize, 0);
            let n = sys(Sysno::getdents64, &[fd, addr_mut(&mut buf), buf.len()]).unwrap_or(0);
            dirents(&buf, n).map(|(e, c)| (c, e[0].as_ref().map(|x| x.name.len())))
        },
        Some((2, Some(5))),
    );
    t.eq(
        "getdents-eof",
        sys(Sysno::getdents64, &[fd, addr_mut(&mut buf), buf.len()]),
        Ok(0),
    );
    t.eq("getdents-rewind", lseek(fd, 0, 0), Ok(0));
    t.eq(
        "getdents-small-buffer",
        sys(Sysno::getdents64, &[fd, addr_mut(&mut buf), 10]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "getdents-record-sized-buffer",
        sys(Sysno::getdents64, &[fd, addr_mut(&mut buf), 24]),
        Ok(24),
    );
    t.eq(
        "getdents-fault",
        sys(Sysno::getdents64, &[fd, BAD, 1024]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "getdents-read-on-dir",
        read(fd, &mut buf),
        Err(Errno::EISDIR),
    );
    t.eq(
        "getdents-lseek-end-on-dir",
        lseek(fd, 0, 2),
        Err(Errno::EINVAL),
    );
    let _ = close(fd);
    let file = open(b"/init\0", O_RDONLY, 0).unwrap_or(99);
    t.eq(
        "getdents-on-file",
        sys(Sysno::getdents64, &[file, addr_mut(&mut buf), 1024]),
        Err(Errno::ENOTDIR),
    );
    let _ = close(file);
    t.eq(
        "getdents-bad-fd",
        sys(Sysno::getdents64, &[999, addr_mut(&mut buf), 1024]),
        Err(Errno::EBADF),
    );
}

fn open_errors(t: &mut T) {
    t.eq(
        "open-missing",
        open(b"/nonexistent\0", O_RDONLY, 0),
        Err(Errno::ENOENT),
    );
    t.eq(
        "open-missing-in-dir",
        open(b"/fixture/nonexistent\0", O_RDONLY, 0),
        Err(Errno::ENOENT),
    );
    t.eq(
        "open-missing-dir-component",
        open(b"/nonexistent/x\0", O_RDONLY, 0),
        Err(Errno::ENOENT),
    );
    t.eq(
        "open-empty-path",
        open(b"\0", O_RDONLY, 0),
        Err(Errno::ENOENT),
    );
    t.eq(
        "open-through-file",
        open(b"/init/x\0", O_RDONLY, 0),
        Err(Errno::ENOTDIR),
    );
    t.eq(
        "open-trailing-slash-on-file",
        open(b"/init/\0", O_RDONLY, 0),
        Err(Errno::ENOTDIR),
    );
    t.eq(
        "open-directory-flag-on-file",
        open(b"/init\0", O_RDONLY | O_DIRECTORY, 0),
        Err(Errno::ENOTDIR),
    );
    t.eq(
        "open-dir-for-write",
        open(b"/fixture\0", O_WRONLY, 0),
        Err(Errno::EISDIR),
    );
    t.eq(
        "open-dir-rdwr",
        open(b"/fixture\0", O_RDWR, 0),
        Err(Errno::EISDIR),
    );
    t.eq(
        "open-dir-creat",
        open(b"/fixture\0", O_CREAT | O_WRONLY, 0o644),
        Err(Errno::EISDIR),
    );
    t.eq(
        "open-excl-existing",
        open(b"/init\0", O_CREAT | O_EXCL | O_WRONLY, 0o644),
        Err(Errno::EEXIST),
    );
    t.eq(
        "open-fault",
        sys(Sysno::open, &[BAD, O_RDONLY, 0]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "open-null",
        sys(Sysno::open, &[0, O_RDONLY, 0]),
        Err(Errno::EFAULT),
    );
    let long = [b'a'; 300];
    let mut path = [0u8; 302];
    path[0] = b'/';
    path[1..301].copy_from_slice(&long);
    t.eq(
        "open-name-too-long",
        open(&path, O_RDONLY, 0),
        Err(Errno::ENAMETOOLONG),
    );
    let mut huge = [b'a'; 4200];
    huge[0] = b'/';
    for i in (64..4200).step_by(64) {
        huge[i] = b'/';
    }
    huge[4199] = 0;
    t.eq(
        "open-path-too-long",
        open(&huge, O_RDONLY, 0),
        Err(Errno::ENAMETOOLONG),
    );
    t.eq(
        "open-nofollow-symlink",
        open(b"/linuxrc\0", O_RDONLY | O_NOFOLLOW, 0),
        Err(Errno::ELOOP),
    );
    let dfd = open(b"/fixture\0", O_RDONLY | O_DIRECTORY, 0).unwrap_or(99);
    t.eq(
        "openat-relative",
        openat(dfd, b"hello.txt\0", O_RDONLY).map(|fd| close(fd).is_ok()),
        Ok(true),
    );
    t.eq(
        "openat-absolute-ignores-dirfd",
        openat(999, b"/init\0", O_RDONLY).map(|fd| close(fd).is_ok()),
        Ok(true),
    );
    t.eq(
        "openat-bad-dirfd",
        openat(999, b"hello.txt\0", O_RDONLY),
        Err(Errno::EBADF),
    );
    t.eq(
        "openat-dotdot",
        openat(dfd, b"../init\0", O_RDONLY).map(|fd| close(fd).is_ok()),
        Ok(true),
    );
    t.eq(
        "openat-dotdot-at-root",
        openat(dfd, b"../../../fixture/empty\0", O_RDONLY).map(|fd| close(fd).is_ok()),
        Ok(true),
    );
    let file = open(b"/init\0", O_RDONLY, 0).unwrap_or(99);
    t.eq(
        "openat-dirfd-is-file",
        openat(file, b"x\0", O_RDONLY),
        Err(Errno::ENOTDIR),
    );
    t.eq(
        "openat-dirfd-is-file-empty-relative",
        openat(file, b"\0", O_RDONLY),
        Err(Errno::ENOENT),
    );
    let _ = close(file);
    t.eq(
        "openat-dir-fd-read",
        {
            let fd = openat(dfd, b"sub\0", O_RDONLY | O_DIRECTORY).unwrap_or(99);
            let r = list(b"/fixture/sub\0", &mut [0u8; 512]);
            let _ = close(fd);
            r.is_ok()
        },
        true,
    );
    let _ = close(dfd);
    // Descriptor numbers: lowest free, and ENFILE-style limits via RLIMIT_NOFILE.
    let a = open(b"/init\0", O_RDONLY, 0).unwrap_or(99);
    let b = open(b"/init\0", O_RDONLY, 0).unwrap_or(99);
    t.eq("open-allocates-lowest", (a, b), (3, 4));
    let _ = close(a);
    t.eq(
        "open-reuses-closed-slot",
        open(b"/init\0", O_RDONLY, 0),
        Ok(3),
    );
    let _ = close(3);
    let _ = close(b);
    let lim = [8u64, 4096];
    let mut old = [0u64; 2];
    let _ = sys(Sysno::prlimit64, &[0, 7, addr(&lim), addr_mut(&mut old)]);
    let fds = [
        open(b"/init\0", O_RDONLY, 0),
        open(b"/init\0", O_RDONLY, 0),
        open(b"/init\0", O_RDONLY, 0),
        open(b"/init\0", O_RDONLY, 0),
        open(b"/init\0", O_RDONLY, 0),
    ];
    t.eq(
        "open-emfile",
        (fds.map(|r| r.is_ok()), open(b"/init\0", O_RDONLY, 0)),
        ([true; 5], Err(Errno::EMFILE)),
    );
    for fd in fds.into_iter().flatten() {
        let _ = close(fd);
    }
    let _ = sys(Sysno::prlimit64, &[0, 7, addr(&old), 0]);
    t.eq("close-bad-fd", close(999), Err(Errno::EBADF));
    t.eq("close-minus-one", close(usize::MAX), Err(Errno::EBADF));
    t.eq("read-bad-fd", read(999, &mut [0u8; 4]), Err(Errno::EBADF));
    t.eq(
        "write-bad-fd",
        sys(Sysno::write, &[999, addr(b"x"), 1]),
        Err(Errno::EBADF),
    );
    t.eq("lseek-bad-fd", lseek(999, 0, 0), Err(Errno::EBADF));
}

fn descriptors(t: &mut T) {
    let fd = open(b"/fixture/hello.txt\0", O_RDONLY, 0).unwrap_or(99);
    let mut buf = [0u8; 8];
    t.eq("dup-lowest", sys(Sysno::dup, &[fd]), Ok(fd + 1));
    t.eq(
        "dup-shares-offset",
        (read(fd, &mut buf[..3]), lseek(fd + 1, 0, 1)),
        (Ok(3), Ok(3)),
    );
    t.eq("dup-clears-cloexec", fcntl(fd + 1, 1, 0), Ok(0));
    t.eq("dup2-to-new", sys(Sysno::dup2, &[fd, 10]), Ok(10));
    t.eq("dup2-same-fd", sys(Sysno::dup2, &[fd, fd]), Ok(fd));
    t.eq(
        "dup2-same-fd-bad",
        sys(Sysno::dup2, &[999, 999]),
        Err(Errno::EBADF),
    );
    t.eq(
        "dup2-replaces",
        (sys(Sysno::dup2, &[fd, fd + 1]), close(fd + 1)),
        (Ok(fd + 1), Ok(0)),
    );
    t.eq(
        "dup2-bad-old",
        sys(Sysno::dup2, &[999, 5]),
        Err(Errno::EBADF),
    );
    t.eq(
        "dup2-new-above-limit",
        sys(Sysno::dup2, &[fd, 1 << 24]),
        Err(Errno::EBADF),
    );
    t.eq(
        "dup2-new-negative",
        sys(Sysno::dup2, &[fd, usize::MAX]),
        Err(Errno::EBADF),
    );
    t.eq("dup-bad-fd", sys(Sysno::dup, &[999]), Err(Errno::EBADF));
    t.eq(
        "dup3-cloexec",
        (sys(Sysno::dup3, &[fd, 11, O_CLOEXEC]), fcntl(11, 1, 0)),
        (Ok(11), Ok(1)),
    );
    t.eq(
        "dup3-no-cloexec",
        (sys(Sysno::dup3, &[fd, 12, 0]), fcntl(12, 1, 0)),
        (Ok(12), Ok(0)),
    );
    t.eq(
        "dup3-same-fd",
        sys(Sysno::dup3, &[fd, fd, 0]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "dup3-bad-flags",
        sys(Sysno::dup3, &[fd, 13, O_NONBLOCK]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "dup3-bad-old",
        sys(Sysno::dup3, &[999, 13, 0]),
        Err(Errno::EBADF),
    );
    t.eq(
        "dup3-new-above-limit",
        sys(Sysno::dup3, &[fd, 1 << 24, 0]),
        Err(Errno::EBADF),
    );
    // fcntl.
    t.eq("fcntl-getfd", fcntl(fd, 1, 0), Ok(0));
    t.eq(
        "fcntl-setfd-cloexec",
        (fcntl(fd, 2, 1), fcntl(fd, 1, 0)),
        (Ok(0), Ok(1)),
    );
    t.eq(
        "fcntl-setfd-clear",
        (fcntl(fd, 2, 0), fcntl(fd, 1, 0)),
        (Ok(0), Ok(0)),
    );
    t.eq(
        "fcntl-setfd-ignores-other-bits",
        (fcntl(fd, 2, 0xfe), fcntl(fd, 1, 0)),
        (Ok(0), Ok(0)),
    );
    t.eq("fcntl-getfl", fcntl(fd, 3, 0), Ok(O_RDONLY | O_LARGEFILE));
    t.eq(
        "fcntl-setfl-nonblock",
        (fcntl(fd, 4, O_NONBLOCK), fcntl(fd, 3, 0)),
        (Ok(0), Ok(O_RDONLY | O_LARGEFILE | O_NONBLOCK)),
    );
    t.eq(
        "fcntl-setfl-append",
        (fcntl(fd, 4, O_APPEND), fcntl(fd, 3, 0)),
        (Ok(0), Ok(O_RDONLY | O_LARGEFILE | O_APPEND)),
    );
    t.eq(
        "fcntl-setfl-ignores-access-mode",
        (fcntl(fd, 4, O_RDWR), fcntl(fd, 3, 0)),
        (Ok(0), Ok(O_RDONLY | O_LARGEFILE)),
    );
    t.eq(
        "fcntl-getfl-shared-by-dup",
        (fcntl(fd, 4, O_NONBLOCK), fcntl(10, 3, 0)),
        (Ok(0), Ok(O_RDONLY | O_LARGEFILE | O_NONBLOCK)),
    );
    t.eq("fcntl-dupfd", fcntl(fd, 0, 20), Ok(20));
    t.eq("fcntl-dupfd-skips-used", fcntl(fd, 0, 20), Ok(21));
    t.eq(
        "fcntl-dupfd-cloexec",
        (fcntl(fd, 1030, 30), fcntl(30, 1, 0)),
        (Ok(30), Ok(1)),
    );
    t.eq(
        "fcntl-dupfd-above-limit",
        fcntl(fd, 0, 1 << 24),
        Err(Errno::EINVAL),
    );
    t.eq("fcntl-bad-cmd", fcntl(fd, 9999, 0), Err(Errno::EINVAL));
    t.eq("fcntl-bad-fd", fcntl(999, 1, 0), Err(Errno::EBADF));
    t.eq(
        "fcntl-bad-fd-bad-cmd",
        fcntl(999, 9999, 0),
        Err(Errno::EBADF),
    );
    for d in [10, 11, 12, 20, 21, 30, fd + 1, fd] {
        let _ = close(d);
    }
    // O_CLOEXEC at open.
    let c = open(b"/init\0", O_RDONLY | O_CLOEXEC, 0).unwrap_or(99);
    t.eq("open-cloexec", fcntl(c, 1, 0), Ok(1));
    let _ = close(c);
    // Pipes are covered by `proc`; here only that fd flags work on them.
    let mut p = [0u32; 2];
    t.eq(
        "pipe2-cloexec",
        (
            sys(Sysno::pipe2, &[addr_mut(&mut p), O_CLOEXEC]),
            fcntl(p[0] as usize, 1, 0),
            fcntl(p[1] as usize, 1, 0),
        ),
        (Ok(0), Ok(1), Ok(1)),
    );
    let _ = close(p[0] as usize);
    let _ = close(p[1] as usize);
    // chdir / fchdir / getcwd.
    let cwd = || {
        let mut b = [0u8; 64];
        let r = sys(Sysno::getcwd, &[addr_mut(&mut b), 64]);
        (r, b)
    };
    t.eq("chdir", sys(Sysno::chdir, &[addr(b"/fixture\0")]), Ok(0));
    let (r, b) = cwd();
    t.eq(
        "getcwd-after-chdir",
        (r, &b[..9]),
        (Ok(9), b"/fixture\0".as_slice()),
    );
    t.eq(
        "open-relative-after-chdir",
        open(b"hello.txt\0", O_RDONLY, 0).map(|fd| close(fd).is_ok()),
        Ok(true),
    );
    t.eq(
        "chdir-dotdot",
        (sys(Sysno::chdir, &[addr(b"sub/..\0")]), cwd().0),
        (Ok(0), Ok(9)),
    );
    t.eq(
        "chdir-to-file",
        sys(Sysno::chdir, &[addr(b"hello.txt\0")]),
        Err(Errno::ENOTDIR),
    );
    t.eq(
        "chdir-missing",
        sys(Sysno::chdir, &[addr(b"nonexistent\0")]),
        Err(Errno::ENOENT),
    );
    let dfd = open(b"/fixture/sub\0", O_RDONLY | O_DIRECTORY, 0).unwrap_or(99);
    t.eq(
        "fchdir",
        (
            sys(Sysno::fchdir, &[dfd]),
            cwd().1[..13] == *b"/fixture/sub\0",
        ),
        (Ok(0), true),
    );
    let file = open(b"/init\0", O_RDONLY, 0).unwrap_or(99);
    t.eq(
        "fchdir-file",
        sys(Sysno::fchdir, &[file]),
        Err(Errno::ENOTDIR),
    );
    t.eq(
        "fchdir-bad-fd",
        sys(Sysno::fchdir, &[999]),
        Err(Errno::EBADF),
    );
    let _ = close(file);
    let _ = close(dfd);
    t.eq(
        "chdir-root",
        (sys(Sysno::chdir, &[addr(b"/\0")]), cwd().0),
        (Ok(0), Ok(2)),
    );
    t.eq("chdir-fault", sys(Sysno::chdir, &[BAD]), Err(Errno::EFAULT));
}

fn links(t: &mut T) {
    let mut buf = [0u8; 32];
    let rl = |p: &[u8], b: &mut [u8]| sys(Sysno::readlink, &[addr(p), addr_mut(b), b.len()]);
    t.eq(
        "readlink",
        (rl(b"/fixture/link\0", &mut buf), &buf[..9]),
        (Ok(9), b"hello.txt".as_slice()),
    );
    t.eq(
        "readlink-absolute-target",
        (rl(b"/linuxrc\0", &mut buf), &buf[..5]),
        (Ok(5), b"/init".as_slice()),
    );
    t.eq(
        "readlink-truncates",
        (rl(b"/fixture/link\0", &mut buf[..4]), &buf[..4]),
        (Ok(4), b"hell".as_slice()),
    );
    t.eq(
        "readlink-not-a-link",
        rl(b"/init\0", &mut buf),
        Err(Errno::EINVAL),
    );
    t.eq(
        "readlink-missing",
        rl(b"/nonexistent\0", &mut buf),
        Err(Errno::ENOENT),
    );
    t.eq(
        "readlink-zero-size",
        sys(
            Sysno::readlink,
            &[addr(b"/fixture/link\0"), addr_mut(&mut buf), 0],
        ),
        Err(Errno::EINVAL),
    );
    t.eq(
        "readlink-fault",
        sys(Sysno::readlink, &[addr(b"/fixture/link\0"), BAD, 8]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "readlinkat",
        sys(
            Sysno::readlinkat,
            &[AT_FDCWD, addr(b"fixture/link\0"), addr_mut(&mut buf), 32],
        ),
        Ok(9),
    );
    let fd = open(b"/fixture/link\0", O_RDONLY, 0).unwrap_or(99);
    let mut text = [0u8; 16];
    t.eq(
        "open-follows-symlink",
        (read(fd, &mut text), &text[..14]),
        (Ok(14), b"hello, oracle\n".as_slice()),
    );
    let _ = close(fd);
    t.eq(
        "open-symlink-nofollow",
        open(b"/fixture/link\0", O_RDONLY | O_NOFOLLOW, 0),
        Err(Errno::ELOOP),
    );
    t.eq(
        "open-trailing-slash-on-symlink-to-file",
        open(b"/fixture/link/\0", O_RDONLY, 0),
        Err(Errno::ENOTDIR),
    );
}

fn creating(t: &mut T) {
    let name = b"/oracle-created\0";
    let fd = open(name, O_CREAT | O_EXCL | O_RDWR, 0o666).unwrap_or(99);
    t.eq("create", fd, 3);
    let mut buf = [0u8; 16];
    t.eq(
        "create-write",
        sys(Sysno::write, &[fd, addr(b"payload"), 7]),
        Ok(7),
    );
    let st = fstat(fd).1;
    t.eq(
        "create-stat",
        (st.mode, st.size, st.nlink, st.uid, st.gid),
        (S_IFREG | 0o644, 7, 1, 0, 0),
    );
    t.eq(
        "create-read-back",
        (
            sys(Sysno::pread64, &[fd, addr_mut(&mut buf), 16, 0]),
            &buf[..7],
        ),
        (Ok(7), b"payload".as_slice()),
    );
    t.eq("create-append-position", lseek(fd, 0, 1), Ok(7));
    t.eq(
        "create-pwrite-extends",
        (
            sys(Sysno::pwrite64, &[fd, addr(b"XY"), 2, 10]),
            fstat(fd).1.size,
        ),
        (Ok(2), 12),
    );
    t.eq(
        "create-hole-reads-zero",
        (
            sys(Sysno::pread64, &[fd, addr_mut(&mut buf), 12, 0]),
            &buf[5..12],
        ),
        (Ok(12), b"ad\0\0\0XY".as_slice()),
    );
    t.eq(
        "create-ftruncate",
        (sys(Sysno::ftruncate, &[fd, 3]), fstat(fd).1.size),
        (Ok(0), 3),
    );
    t.eq(
        "create-excl-twice",
        open(name, O_CREAT | O_EXCL | O_RDWR, 0o666),
        Err(Errno::EEXIST),
    );
    t.eq(
        "create-open-existing-creat",
        open(name, O_CREAT | O_RDONLY, 0o600).map(|f| close(f).is_ok()),
        Ok(true),
    );
    t.eq(
        "create-mode-not-changed-by-reopen",
        stat_path(name).1.mode,
        S_IFREG | 0o644,
    );
    t.eq(
        "create-in-root-listing",
        {
            let mut names = [0u8; 512];
            let n = list(b"/\0", &mut names).unwrap_or(0);
            names[..n].starts_with(b"oracle-created,")
        },
        true,
    );
    t.eq(
        "create-O_TRUNC",
        {
            let f = open(name, O_WRONLY | 0o1000, 0).unwrap_or(99);
            let size = fstat(f).1.size;
            let _ = close(f);
            size
        },
        0,
    );
    t.eq(
        "create-append-flag",
        {
            let f = open(name, O_WRONLY | O_APPEND, 0).unwrap_or(99);
            let _ = sys(Sysno::write, &[f, addr(b"ab"), 2]);
            let _ = lseek(f, 0, 0);
            let _ = sys(Sysno::write, &[f, addr(b"cd"), 2]);
            let size = fstat(f).1.size;
            let _ = close(f);
            size
        },
        4,
    );
    t.eq("unlink", sys(Sysno::unlink, &[addr(name)]), Ok(0));
    t.eq(
        "unlink-again",
        sys(Sysno::unlink, &[addr(name)]),
        Err(Errno::ENOENT),
    );
    t.eq(
        "unlinked-file-still-open",
        (fstat(fd).0, fstat(fd).1.nlink),
        (Ok(0), 0),
    );
    t.eq(
        "unlinked-file-gone",
        open(name, O_RDONLY, 0),
        Err(Errno::ENOENT),
    );
    let _ = close(fd);
    t.eq(
        "unlink-directory",
        sys(Sysno::unlink, &[addr(b"/fixture\0")]),
        Err(Errno::EISDIR),
    );
    t.eq(
        "write-to-dev-null-like-fd0-ok",
        sys(Sysno::write, &[1, addr(b""), 0]),
        Ok(0),
    );
}

fn mapping(t: &mut T) {
    let fd = open(b"/init\0", O_RDONLY, 0).unwrap_or(99);
    let size = fstat(fd).1.size as usize;
    let map = mmap(0, PAGE, 1, 0x02, fd, 0);
    let p = map.unwrap_or(0);
    t.holds(
        "mmap-file-private-read",
        map.is_ok() && peek(p) == 0x7f && peek(p + 1) == b'E',
        map,
        "ELF magic",
    );
    // Contents equal read().
    let mut page = [0u8; 64];
    let _ = sys(Sysno::pread64, &[fd, addr_mut(&mut page), 64, 0]);
    t.eq(
        "mmap-file-matches-read",
        (0..64).all(|i| peek(p + i) == page[i]),
        true,
    );
    t.eq(
        "mmap-file-tail-zero-filled",
        {
            // The part of the last page beyond EOF reads as zero.
            let last_page = mmap(0, PAGE, 1, 0x02, fd, size & !(PAGE - 1)).unwrap_or(0);
            (size % PAGE..PAGE).all(|i| peek(last_page + i) == 0)
        },
        true,
    );
    let _ = sys(Sysno::munmap, &[p, PAGE]);
    // Private writable mapping of a read-only descriptor: allowed, copy-on-write.
    let w = mmap(0, PAGE, 3, 0x02, fd, 0);
    let wp = w.unwrap_or(0);
    t.eq("mmap-file-private-writable", w.is_ok(), true);
    super::poke(wp, 0x55);
    let mut b = [0u8; 1];
    let _ = sys(Sysno::pread64, &[fd, addr_mut(&mut b), 1, 0]);
    t.eq(
        "mmap-file-cow-not-visible-to-read",
        (peek(wp), b[0]),
        (0x55, 0x7f),
    );
    let _ = sys(Sysno::munmap, &[wp, PAGE]);
    t.eq(
        "mmap-shared-writable-read-only-fd",
        mmap(0, PAGE, 3, 0x01, fd, 0),
        Err(Errno::EACCES),
    );
    t.eq(
        "mmap-file-unaligned-offset",
        mmap(0, PAGE, 1, 0x02, fd, 1),
        Err(Errno::EINVAL),
    );
    t.eq(
        "mmap-file-offset-past-end",
        mmap(0, PAGE, 1, 0x02, fd, 1 << 30).is_ok(),
        true,
    );
    t.eq(
        "mmap-file-len-zero",
        mmap(0, 0, 1, 0x02, fd, 0),
        Err(Errno::EINVAL),
    );
    let _ = close(fd);
    t.eq(
        "mmap-closed-fd",
        mmap(0, PAGE, 1, 0x02, fd, 0),
        Err(Errno::EBADF),
    );
    let dfd = open(b"/fixture\0", O_RDONLY | O_DIRECTORY, 0).unwrap_or(99);
    t.eq(
        "mmap-directory",
        mmap(0, PAGE, 1, 0x02, dfd, 0),
        Err(Errno::ENODEV),
    );
    let _ = close(dfd);
    t.eq(
        "mmap-console",
        mmap(0, PAGE, 1, 0x02, 0, 0),
        Err(Errno::ENODEV),
    );
    let wfd = open(b"/fixture/hello.txt\0", O_WRONLY, 0).unwrap_or(99);
    t.eq(
        "mmap-write-only-fd",
        mmap(0, PAGE, 1, 0x02, wfd, 0),
        Err(Errno::EACCES),
    );
    let _ = close(wfd);
}

fn devices(t: &mut T) {
    // Under this boot no devtmpfs is mounted: /dev is the archive's directory, holding only the
    // /dev/console node `default_rootfs` made. Nothing else exists until userspace runs mknod.
    let mut names = [0u8; 512];
    let n = list(b"/dev\0", &mut names).unwrap_or(0);
    t.eq(
        "dev-contains-only-console",
        &names[..n],
        b"console".as_slice(),
    );
    for path in [
        &b"/dev/null\0"[..],
        b"/dev/zero\0",
        b"/dev/tty\0",
        b"/dev/urandom\0",
        b"/dev/kmsg\0",
        b"/dev/ptmx\0",
    ] {
        t.eq(
            format_args!(
                "dev-absent-{}",
                core::str::from_utf8(&path[5..path.len() - 1]).unwrap_or("?")
            ),
            stat_path(path).0,
            Err(Errno::ENOENT),
        );
    }
    let (r, dev) = stat_path(b"/dev\0");
    t.eq(
        "dev-directory",
        (r, dev.mode, dev.nlink),
        (Ok(0), S_IFDIR | 0o755, 2),
    );
    let (r, root) = stat_path(b"/root\0");
    t.eq(
        "root-home-directory",
        (r, root.mode, root.nlink, root.uid, root.gid),
        (Ok(0), S_IFDIR | 0o700, 2, 0, 0),
    );
    let con = open(b"/dev/console\0", O_RDWR, 0);
    t.eq(
        "dev-console-reopen",
        con.map(|fd| (fcntl(fd, 3, 0), close(fd))),
        Ok((Ok(O_RDWR | O_LARGEFILE), Ok(0))),
    );
    // mknod is how userspace creates the standard nodes; they behave as the drivers define.
    let mknod = |path: &[u8], mode: usize, dev: usize| sys(Sysno::mknod, &[addr(path), mode, dev]);
    let mut buf = [0xaau8; 16];
    t.eq(
        "mknod-null",
        mknod(b"/dev/null\0", 0o20_666, (1 << 8) | 3),
        Ok(0),
    );
    let null = open(b"/dev/null\0", O_RDWR, 0).unwrap_or(99);
    t.eq(
        "dev-null-write",
        sys(Sysno::write, &[null, addr(b"discarded"), 9]),
        Ok(9),
    );
    t.eq(
        "dev-null-write-user-unmapped",
        sys(Sysno::write, &[null, 0x7000_0000_0000, 9]),
        Ok(9),
    );
    t.eq("dev-null-read", read(null, &mut buf), Ok(0));
    t.eq("dev-null-seek", lseek(null, 5, 0), Ok(0));
    let st = fstat(null).1;
    t.eq(
        "dev-null-stat",
        (st.mode, major(st.rdev), minor(st.rdev)),
        (S_IFCHR | 0o644, 1, 3),
    );
    let _ = close(null);
    t.eq(
        "mknod-zero",
        mknod(b"/dev/zero\0", 0o20_666, (1 << 8) | 5),
        Ok(0),
    );
    let zero = open(b"/dev/zero\0", O_RDONLY, 0).unwrap_or(99);
    t.eq(
        "dev-zero-read",
        (read(zero, &mut buf), buf),
        (Ok(16), [0u8; 16]),
    );
    t.eq(
        "dev-zero-read-fault",
        sys(Sysno::read, &[zero, BAD, 16]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "dev-zero-mmap-private",
        mmap(0, PAGE, 3, 0x02, zero, 0).map(peek),
        Ok(0),
    );
    let _ = close(zero);
    t.eq(
        "mknod-full",
        mknod(b"/dev/full\0", 0o20_666, (1 << 8) | 7),
        Ok(0),
    );
    let full = open(b"/dev/full\0", O_RDWR, 0).unwrap_or(99);
    t.eq(
        "dev-full-write",
        sys(Sysno::write, &[full, addr(b"x"), 1]),
        Err(Errno::ENOSPC),
    );
    let _ = close(full);
    t.eq(
        "mknod-existing",
        mknod(b"/dev/null\0", 0o20_666, (1 << 8) | 3),
        Err(Errno::EEXIST),
    );
    t.eq(
        "mknod-fifo-regular-types",
        (
            mknod(b"/dev/reg\0", 0o100_600, 0),
            sys(Sysno::unlink, &[addr(b"/dev/reg\0")]),
        ),
        (Ok(0), Ok(0)),
    );
    t.eq(
        "mknod-directory-type",
        mknod(b"/dev/bad\0", 0o040_000, 0),
        Err(Errno::EPERM),
    );
    for name in [&b"/dev/null\0"[..], b"/dev/zero\0", b"/dev/full\0"] {
        let _ = sys(Sysno::unlink, &[addr(name)]);
    }
    t.eq(
        "dev-clean",
        {
            let n = list(b"/dev\0", &mut names).unwrap_or(0);
            &names[..n] == b"console".as_slice()
        },
        true,
    );
    let _ = (S_IFMT, O_APPEND);
}
