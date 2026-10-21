// SPDX-License-Identifier: GPL-2.0-only
//! `names` group: the system calls that create, remove, rename and describe names and that move
//! bytes between files, beyond the `fs` group: `mkdir`, `rmdir`, `unlinkat`, `symlink`, `link`,
//! `rename*`, `chmod`, `chown`, `utimensat` and its relatives, `truncate`, `fsync`, `statfs`,
//! `writev`, `pwritev`, `sendfile`, `getrandom`, `#!` scripts and `vfork`. Linux 6.18.57:
//! `fs/namei.c`, `fs/open.c`, `fs/utimes.c`, `fs/attr.c`, `fs/sync.c`, `fs/statfs.c`,
//! `fs/read_write.c`, `fs/splice.c`, `fs/binfmt_script.c`, `kernel/fork.c`, `mm/shmem.c`,
//! `drivers/char/random.c`. Every check compares an `errno`, a count or an attribute, never a
//! timestamp read from the clock or an inode number, so the kernels need not agree on those.

use core::sync::atomic::{AtomicUsize, Ordering::Relaxed};

use syscalls::{Errno, Sysno};

use super::{R, T, addr, addr_mut, sys};

const BAD: usize = 0xdead_0000_0000;
const AT_FDCWD: usize = -100isize as usize;

const O_RDONLY: usize = 0;
const O_WRONLY: usize = 1;
const O_RDWR: usize = 2;
const O_CREAT: usize = 0o100;
const O_APPEND: usize = 0o2000;
const O_NONBLOCK: usize = 0o4000;
const O_DIRECTORY: usize = 0o200_000;

const UTIME_NOW: i64 = (1 << 30) - 1;
const UTIME_OMIT: i64 = (1 << 30) - 2;

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

/// `stat` (follow) or `lstat`.
fn stat(path: &[u8], follow: bool) -> (R, Stat) {
    let mut st = Stat::default();
    let call = if follow { Sysno::stat } else { Sysno::lstat };
    (sys(call, &[addr(path), addr_mut(&mut st)]), st)
}

/// `(mode, nlink, size, uid, gid)` of a name, or the error.
fn facts(path: &[u8]) -> Result<(u32, u64, i64, u32, u32), Errno> {
    let (r, st) = stat(path, true);
    r.map(|_| (st.mode, st.nlink, st.size, st.uid, st.gid))
}

fn lfacts(path: &[u8]) -> Result<(u32, u64, i64), Errno> {
    let (r, st) = stat(path, false);
    r.map(|_| (st.mode, st.nlink, st.size))
}

fn open(path: &[u8], flags: usize, mode: usize) -> R {
    sys(Sysno::open, &[addr(path), flags, mode])
}

fn close(fd: usize) {
    let _ = sys(Sysno::close, &[fd]);
}

fn mkdir(path: &[u8], mode: usize) -> R {
    sys(Sysno::mkdir, &[addr(path), mode])
}

fn rmdir(path: &[u8]) -> R {
    sys(Sysno::rmdir, &[addr(path)])
}

fn unlink(path: &[u8]) -> R {
    sys(Sysno::unlink, &[addr(path)])
}

fn rename(old: &[u8], new: &[u8]) -> R {
    sys(Sysno::rename, &[addr(old), addr(new)])
}

fn renameat2(old: &[u8], new: &[u8], flags: usize) -> R {
    sys(
        Sysno::renameat2,
        &[AT_FDCWD, addr(old), AT_FDCWD, addr(new), flags],
    )
}

fn link(old: &[u8], new: &[u8]) -> R {
    sys(Sysno::link, &[addr(old), addr(new)])
}

fn symlink(target: &[u8], path: &[u8]) -> R {
    sys(Sysno::symlink, &[addr(target), addr(path)])
}

fn create(path: &[u8], data: &[u8]) {
    if let Ok(fd) = open(path, O_CREAT | O_WRONLY, 0o644) {
        let _ = sys(Sysno::write, &[fd, addr(data), data.len()]);
        close(fd);
    }
}

fn read_all<'a>(path: &[u8], buf: &'a mut [u8]) -> &'a [u8] {
    let Ok(fd) = open(path, O_RDONLY, 0) else {
        return &[];
    };
    let n = sys(Sysno::read, &[fd, addr_mut(buf), buf.len()]).unwrap_or(0);
    close(fd);
    &buf[..n]
}

fn pipe() -> (usize, usize) {
    let mut fds = [0u32; 2];
    let _ = sys(Sysno::pipe2, &[addr_mut(&mut fds), 0]);
    (fds[0] as usize, fds[1] as usize)
}

pub fn run() -> bool {
    let mut t = T::new("names");
    // Work in a directory of our own so that names of other groups never collide.
    let _ = mkdir(b"/n\0", 0o755);
    let _ = sys(Sysno::chdir, &[addr(b"/n\0")]);
    mkdir_rmdir(&mut t);
    symlinks_and_links(&mut t);
    renames(&mut t);
    chmod_chown(&mut t);
    times(&mut t);
    truncate_sync_statfs(&mut t);
    vectors_and_sendfile(&mut t);
    random(&mut t);
    reboot(&mut t);
    mknodat(&mut t);
    scripts(&mut t);
    vfork(&mut t);
    t.finish()
}

fn mkdir_rmdir(t: &mut T) {
    t.eq("mkdir", mkdir(b"d\0", 0o777), Ok(0));
    t.eq(
        "mkdir-mode-umask",
        facts(b"d\0").map(|f| f.0),
        Ok(0o040_755),
    );
    t.eq("mkdir-eexist", mkdir(b"d\0", 0o777), Err(Errno::EEXIST));
    t.eq(
        "mkdir-eexist-slash",
        mkdir(b"d/\0", 0o777),
        Err(Errno::EEXIST),
    );
    t.eq(
        "mkdir-enoent-parent",
        mkdir(b"x/y\0", 0o777),
        Err(Errno::ENOENT),
    );
    t.eq(
        "mkdir-enoent-empty",
        mkdir(b"\0", 0o777),
        Err(Errno::ENOENT),
    );
    t.eq(
        "mkdir-efault-pointer",
        sys(Sysno::mkdir, &[BAD, 0o755]),
        Err(Errno::EFAULT),
    );
    t.eq("mkdir-high-mode-bits-cut", mkdir(b"e/\0", 0o1_0700), Ok(0));
    t.eq(
        "mkdir-mode-sticky",
        facts(b"e\0").map(|f| f.0),
        Ok(0o040_700),
    );
    t.eq("mkdir-sticky", mkdir(b"sticky\0", 0o1777), Ok(0));
    t.eq(
        "mkdir-sticky-mode",
        facts(b"sticky\0").map(|f| f.0),
        Ok(0o041_755),
    );
    let long = [b'a'; 256];
    let mut name = [0u8; 258];
    name[..256].copy_from_slice(&long);
    t.eq(
        "mkdir-name-too-long",
        mkdir(&name, 0o755),
        Err(Errno::ENAMETOOLONG),
    );
    name[255] = 0;
    t.eq("mkdir-name-255", mkdir(&name, 0o755), Ok(0));
    t.eq("rmdir-name-255", rmdir(&name), Ok(0));
    t.eq(
        "mkdir-under-file",
        {
            create(b"file\0", b"x");
            mkdir(b"file/x\0", 0o755)
        },
        Err(Errno::ENOTDIR),
    );
    // Link counts and sizes: `.` and the parent's entry, 20 bytes per entry (BOGO_DIRENT_SIZE).
    t.eq(
        "dir-nlink-size-empty",
        facts(b"d\0").map(|f| (f.1, f.2)),
        Ok((2, 40)),
    );
    t.eq("mkdir-sub", mkdir(b"d/sub\0", 0o755), Ok(0));
    t.eq(
        "dir-nlink-size-sub",
        facts(b"d\0").map(|f| (f.1, f.2)),
        Ok((3, 60)),
    );
    create(b"d/f\0", b"");
    t.eq(
        "dir-size-file",
        facts(b"d\0").map(|f| (f.1, f.2)),
        Ok((3, 80)),
    );
    // mkdirat: relative to a directory descriptor, a file descriptor, a bad one.
    let dir = open(b"d\0", O_RDONLY | O_DIRECTORY, 0).unwrap_or(99);
    t.eq(
        "mkdirat-dirfd",
        sys(Sysno::mkdirat, &[dir, addr(b"viafd\0"), 0o755]),
        Ok(0),
    );
    t.eq(
        "mkdirat-dirfd-result",
        lfacts(b"d/viafd\0").map(|f| f.0),
        Ok(0o040_755),
    );
    let file = open(b"file\0", O_RDONLY, 0).unwrap_or(99);
    t.eq(
        "mkdirat-file-fd",
        sys(Sysno::mkdirat, &[file, addr(b"x\0"), 0o755]),
        Err(Errno::ENOTDIR),
    );
    t.eq(
        "mkdirat-file-fd-empty",
        sys(Sysno::mkdirat, &[file, addr(b"\0"), 0o755]),
        Err(Errno::ENOENT),
    );
    t.eq(
        "mkdirat-bad-fd",
        sys(Sysno::mkdirat, &[77, addr(b"x\0"), 0o755]),
        Err(Errno::EBADF),
    );
    t.eq(
        "mkdirat-absolute-ignores-fd",
        sys(Sysno::mkdirat, &[77, addr(b"/n/abs\0"), 0o755]),
        Ok(0),
    );
    // rmdir
    t.eq("rmdir-notempty", rmdir(b"d\0"), Err(Errno::ENOTEMPTY));
    t.eq("rmdir-file", rmdir(b"file\0"), Err(Errno::ENOTDIR));
    t.eq("rmdir-dot", rmdir(b"d/.\0"), Err(Errno::EINVAL));
    t.eq("rmdir-dotdot", rmdir(b"d/sub/..\0"), Err(Errno::ENOTEMPTY));
    t.eq("rmdir-root", rmdir(b"/\0"), Err(Errno::EBUSY));
    t.eq("rmdir-missing", rmdir(b"none\0"), Err(Errno::ENOENT));
    t.eq("rmdir-empty-name", rmdir(b"\0"), Err(Errno::ENOENT));
    t.eq(
        "rmdir-through-file",
        rmdir(b"file/x\0"),
        Err(Errno::ENOTDIR),
    );
    t.eq("rmdir", rmdir(b"d/sub\0"), Ok(0));
    t.eq("rmdir-parent-nlink", facts(b"d\0").map(|f| f.1), Ok(3));
    t.eq("rmdir-trailing-slash", rmdir(b"abs/\0"), Ok(0));
    // A removed directory still held open or as the working directory.
    t.eq("mkdir-cwd-victim", mkdir(b"victim\0", 0o755), Ok(0));
    let held = open(b"victim\0", O_RDONLY | O_DIRECTORY, 0).unwrap_or(99);
    t.eq("rmdir-held", rmdir(b"victim\0"), Ok(0));
    t.eq(
        "mkdirat-in-removed",
        sys(Sysno::mkdirat, &[held, addr(b"x\0"), 0o755]),
        Err(Errno::ENOENT),
    );
    t.eq(
        "openat-in-removed",
        sys(
            Sysno::openat,
            &[held, addr(b"x\0"), O_CREAT | O_RDWR, 0o644],
        ),
        Err(Errno::ENOENT),
    );
    t.eq(
        "fstat-removed",
        {
            let mut st = Stat::default();
            sys(Sysno::fstat, &[held, addr_mut(&mut st)]).map(|_| st.nlink)
        },
        Ok(0),
    );
    close(held);
    let _ = mkdir(b"cwd\0", 0o755);
    let _ = sys(Sysno::chdir, &[addr(b"cwd\0")]);
    t.eq("rmdir-cwd", rmdir(b"/n/cwd\0"), Ok(0));
    let mut buf = [0u8; 64];
    t.eq(
        "getcwd-removed",
        sys(Sysno::getcwd, &[addr_mut(&mut buf), 64]),
        Err(Errno::ENOENT),
    );
    t.eq(
        "create-in-removed-cwd",
        open(b"f\0", O_CREAT | O_RDWR, 0o644),
        Err(Errno::ENOENT),
    );
    let _ = sys(Sysno::chdir, &[addr(b"/n\0")]);
    // unlinkat
    t.eq(
        "unlinkat-bad-flag",
        sys(Sysno::unlinkat, &[AT_FDCWD, addr(b"file\0"), 1]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "unlinkat-bad-flag-before-name",
        sys(Sysno::unlinkat, &[AT_FDCWD, BAD, 4]),
        Err(Errno::EINVAL),
    );
    t.eq("unlink-dir", unlink(b"d\0"), Err(Errno::EISDIR));
    t.eq("unlink-dir-slash", unlink(b"d/\0"), Err(Errno::EISDIR));
    t.eq("unlink-file-slash", unlink(b"file/\0"), Err(Errno::ENOTDIR));
    t.eq("unlink-dot", unlink(b"d/.\0"), Err(Errno::EISDIR));
    t.eq(
        "unlinkat-removedir-file",
        sys(Sysno::unlinkat, &[AT_FDCWD, addr(b"file\0"), 0x200]),
        Err(Errno::ENOTDIR),
    );
    t.eq(
        "unlinkat-removedir",
        sys(Sysno::unlinkat, &[AT_FDCWD, addr(b"d/viafd\0"), 0x200]),
        Ok(0),
    );
    t.eq("unlink", unlink(b"file\0"), Ok(0));
    t.eq("unlink-again", unlink(b"file\0"), Err(Errno::ENOENT));
    close(dir);
    close(file);
}

fn symlinks_and_links(t: &mut T) {
    let mut buf = [0u8; 64];
    t.eq("symlink", symlink(b"target\0", b"s\0"), Ok(0));
    t.eq("symlink-stat", lfacts(b"s\0"), Ok((0o120_777, 1, 6)));
    t.eq(
        "symlink-eexist",
        symlink(b"target\0", b"s\0"),
        Err(Errno::EEXIST),
    );
    t.eq(
        "symlink-empty-target",
        symlink(b"\0", b"s2\0"),
        Err(Errno::ENOENT),
    );
    t.eq(
        "symlink-parent-missing",
        symlink(b"x\0", b"nodir/s\0"),
        Err(Errno::ENOENT),
    );
    t.eq(
        "symlink-target-efault",
        sys(Sysno::symlink, &[BAD, addr(b"s3\0")]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "symlink-name-efault",
        sys(Sysno::symlink, &[addr(b"x\0"), BAD]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "symlink-target-error-first",
        sys(Sysno::symlink, &[addr(b"\0"), BAD]),
        Err(Errno::ENOENT),
    );
    t.eq(
        "symlinkat-fd",
        {
            let dir = open(b"/n\0", O_RDONLY | O_DIRECTORY, 0).unwrap_or(99);
            let r = sys(Sysno::symlinkat, &[addr(b"t2\0"), dir, addr(b"s4\0")]);
            close(dir);
            r
        },
        Ok(0),
    );
    t.eq(
        "readlink",
        {
            let n = sys(Sysno::readlink, &[addr(b"s\0"), addr_mut(&mut buf), 64]);
            (n, &buf[..6])
        },
        (Ok(6), b"target".as_slice()),
    );
    t.eq(
        "readlink-truncates",
        sys(Sysno::readlink, &[addr(b"s\0"), addr_mut(&mut buf), 3]),
        Ok(3),
    );
    t.eq(
        "readlink-not-a-link",
        sys(Sysno::readlink, &[addr(b"/n\0"), addr_mut(&mut buf), 3]),
        Err(Errno::EINVAL),
    );
    // links
    create(b"f\0", b"data");
    t.eq("link", link(b"f\0", b"g\0"), Ok(0));
    t.eq("link-count", facts(b"f\0").map(|f| f.1), Ok(2));
    t.eq("link-eexist", link(b"f\0", b"g\0"), Err(Errno::EEXIST));
    t.eq("link-enoent", link(b"none\0", b"h\0"), Err(Errno::ENOENT));
    t.eq("link-dir", link(b"d\0", b"d2\0"), Err(Errno::EPERM));
    t.eq(
        "link-target-parent-missing",
        link(b"f\0", b"nodir/h\0"),
        Err(Errno::ENOENT),
    );
    t.eq("link-symlink-itself", link(b"s\0", b"sl\0"), Ok(0));
    t.eq(
        "link-symlink-is-link",
        lfacts(b"sl\0").map(|f| f.0),
        Ok(0o120_777),
    );
    let flags_only = |flags: usize| {
        sys(
            Sysno::linkat,
            &[AT_FDCWD, addr(b"f\0"), AT_FDCWD, addr(b"lat\0"), flags],
        )
    };
    t.eq("linkat-bad-flags", flags_only(0x100), Err(Errno::EINVAL));
    t.eq(
        "linkat-bad-flags-before-names",
        sys(Sysno::linkat, &[AT_FDCWD, BAD, AT_FDCWD, BAD, 1]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "linkat-old-efault",
        sys(Sysno::linkat, &[AT_FDCWD, BAD, AT_FDCWD, addr(b"x\0"), 0]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "linkat-new-efault",
        sys(Sysno::linkat, &[AT_FDCWD, addr(b"f\0"), AT_FDCWD, BAD, 0]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "linkat-old-enoent-before-new-efault",
        sys(
            Sysno::linkat,
            &[AT_FDCWD, addr(b"none\0"), AT_FDCWD, BAD, 0],
        ),
        Err(Errno::ENOENT),
    );
    t.eq("linkat", flags_only(0), Ok(0));
    t.eq(
        "linkat-follow-dangling",
        sys(
            Sysno::linkat,
            &[AT_FDCWD, addr(b"s\0"), AT_FDCWD, addr(b"lat2\0"), 0x400],
        ),
        Err(Errno::ENOENT),
    );
    t.eq(
        "linkat-follow",
        {
            let _ = symlink(b"f\0", b"tof\0");
            let r = sys(
                Sysno::linkat,
                &[AT_FDCWD, addr(b"tof\0"), AT_FDCWD, addr(b"lat3\0"), 0x400],
            );
            (r, lfacts(b"lat3\0").map(|f| f.0))
        },
        (Ok(0), Ok(0o100_644)),
    );
    let fd = open(b"f\0", O_RDONLY, 0).unwrap_or(99);
    t.eq(
        "linkat-empty-path-needs-flag",
        sys(
            Sysno::linkat,
            &[fd, addr(b"\0"), AT_FDCWD, addr(b"fromfd\0"), 0],
        ),
        Err(Errno::ENOENT),
    );
    t.eq(
        "linkat-empty-path",
        sys(
            Sysno::linkat,
            &[fd, addr(b"\0"), AT_FDCWD, addr(b"fromfd\0"), 0x1000],
        ),
        Ok(0),
    );
    t.eq("linkat-empty-path-count", facts(b"f\0").map(|f| f.1), Ok(5));
    // An unlinked file cannot be linked back.
    for name in [&b"f\0"[..], b"g\0", b"lat\0", b"lat3\0", b"fromfd\0"] {
        let _ = unlink(name);
    }
    t.eq(
        "linkat-unlinked-file",
        sys(
            Sysno::linkat,
            &[fd, addr(b"\0"), AT_FDCWD, addr(b"again\0"), 0x1000],
        ),
        Err(Errno::ENOENT),
    );
    close(fd);
    for name in [&b"s\0"[..], b"s4\0", b"sl\0", b"tof\0"] {
        let _ = unlink(name);
    }
}

fn renames(t: &mut T) {
    for dir in [&b"a\0"[..], b"b\0", b"a/sub\0", b"b/full\0", b"b/full/x\0"] {
        let _ = mkdir(dir, 0o755);
    }
    create(b"a/f\0", b"data");
    t.eq("rename-file-across", rename(b"a/f\0", b"b/g\0"), Ok(0));
    t.eq(
        "rename-file-moved",
        facts(b"a/f\0").map(|_| ()),
        Err(Errno::ENOENT),
    );
    t.eq(
        "rename-file-keeps-content",
        facts(b"b/g\0").map(|f| (f.1, f.2)),
        Ok((1, 4)),
    );
    create(b"b/h\0", b"other");
    t.eq("rename-replaces-file", rename(b"b/g\0", b"b/h\0"), Ok(0));
    t.eq("rename-replaced-size", facts(b"b/h\0").map(|f| f.2), Ok(4));
    t.eq(
        "rename-dir-sizes-before",
        (
            facts(b"a\0").map(|f| (f.1, f.2)),
            facts(b"b\0").map(|f| (f.1, f.2)),
        ),
        (Ok((3, 60)), Ok((3, 80))),
    );
    t.eq("rename-dir", rename(b"a/sub\0", b"b/sub\0"), Ok(0));
    t.eq(
        "rename-dir-sizes-after",
        (
            facts(b"a\0").map(|f| (f.1, f.2)),
            facts(b"b\0").map(|f| (f.1, f.2)),
        ),
        (Ok((2, 40)), Ok((4, 100))),
    );
    t.eq(
        "rename-dir-dotdot",
        {
            let _ = sys(Sysno::chdir, &[addr(b"b/sub\0")]);
            let r = lfacts(b"..\0").map(|f| f.1);
            let _ = sys(Sysno::chdir, &[addr(b"/n\0")]);
            r
        },
        Ok(4),
    );
    t.eq(
        "rename-dir-over-nonempty",
        rename(b"b/sub\0", b"b/full\0"),
        Err(Errno::ENOTEMPTY),
    );
    t.eq(
        "rename-file-over-dir",
        rename(b"b/h\0", b"b/sub\0"),
        Err(Errno::EISDIR),
    );
    t.eq(
        "rename-dir-over-file",
        rename(b"b/sub\0", b"b/h\0"),
        Err(Errno::ENOTDIR),
    );
    let _ = mkdir(b"b/empty\0", 0o755);
    t.eq(
        "rename-dir-over-empty-dir",
        rename(b"b/sub\0", b"b/empty\0"),
        Ok(0),
    );
    t.eq(
        "rename-dir-over-empty-nlink",
        facts(b"b\0").map(|f| f.1),
        Ok(4),
    );
    t.eq(
        "rename-dir-into-itself",
        rename(b"b\0", b"b/full/x/b\0"),
        Err(Errno::EINVAL),
    );
    t.eq(
        "rename-onto-ancestor",
        rename(b"b/full/x\0", b"b\0"),
        Err(Errno::ENOTEMPTY),
    );
    t.eq(
        "rename-file-slash-old",
        rename(b"b/h/\0", b"b/i\0"),
        Err(Errno::ENOTDIR),
    );
    t.eq(
        "rename-file-slash-new",
        rename(b"b/h\0", b"b/i/\0"),
        Err(Errno::ENOTDIR),
    );
    t.eq(
        "rename-dir-slash-ok",
        rename(b"b/empty/\0", b"b/empty2/\0"),
        Ok(0),
    );
    t.eq(
        "rename-missing",
        rename(b"b/none\0", b"b/i\0"),
        Err(Errno::ENOENT),
    );
    t.eq(
        "rename-dot-old",
        rename(b"b/.\0", b"b/i\0"),
        Err(Errno::EBUSY),
    );
    t.eq(
        "rename-dotdot-new",
        rename(b"b/h\0", b"b/..\0"),
        Err(Errno::EBUSY),
    );
    t.eq("rename-root", rename(b"/\0", b"/z\0"), Err(Errno::EBUSY));
    t.eq(
        "rename-empty-old",
        rename(b"\0", b"z\0"),
        Err(Errno::ENOENT),
    );
    t.eq(
        "rename-empty-new",
        rename(b"b/h\0", b"\0"),
        Err(Errno::ENOENT),
    );
    t.eq(
        "rename-efault-old",
        sys(Sysno::rename, &[BAD, addr(b"z\0")]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "rename-old-enoent-before-new-efault",
        sys(Sysno::rename, &[addr(b"none\0"), BAD]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "rename-name-too-long",
        {
            let mut name = [b'a'; 258];
            name[257] = 0;
            rename(b"b/h\0", &name)
        },
        Err(Errno::ENAMETOOLONG),
    );
    t.eq(
        "rename-new-parent-missing",
        rename(b"b/h\0", b"nodir/i\0"),
        Err(Errno::ENOENT),
    );
    t.eq(
        "rename-hardlinks-are-noop",
        {
            let _ = link(b"b/h\0", b"b/h2\0");
            let r = rename(b"b/h\0", b"b/h2\0");
            (r, facts(b"b/h\0").is_ok(), facts(b"b/h2\0").map(|f| f.1))
        },
        (Ok(0), true, Ok(2)),
    );
    t.eq("rename-same-name", rename(b"b/h\0", b"b/h\0"), Ok(0));
    // renameat2 flags
    t.eq(
        "renameat2-bad-flag",
        renameat2(b"b/h\0", b"b/j\0", 8),
        Err(Errno::EINVAL),
    );
    t.eq(
        "renameat2-noreplace-exchange",
        renameat2(b"b/h\0", b"b/j\0", 3),
        Err(Errno::EINVAL),
    );
    t.eq(
        "renameat2-whiteout-exchange",
        renameat2(b"b/h\0", b"b/j\0", 6),
        Err(Errno::EINVAL),
    );
    t.eq(
        "renameat2-flags-before-names",
        sys(Sysno::renameat2, &[AT_FDCWD, BAD, AT_FDCWD, BAD, 8]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "renameat2-noreplace-exists-even-for-the-same-inode",
        renameat2(b"b/h\0", b"b/h2\0", 1),
        Err(Errno::EEXIST),
    );
    create(b"b/k\0", b"k");
    t.eq(
        "renameat2-noreplace-differs",
        renameat2(b"b/h\0", b"b/k\0", 1),
        Err(Errno::EEXIST),
    );
    t.eq(
        "renameat2-noreplace-dotdot",
        renameat2(b"b/h\0", b"b/..\0", 1),
        Err(Errno::EEXIST),
    );
    t.eq(
        "renameat2-noreplace-free",
        renameat2(b"b/k\0", b"b/free\0", 1),
        Ok(0),
    );
    t.eq(
        "renameat2-exchange-missing",
        renameat2(b"b/free\0", b"b/nothere\0", 2),
        Err(Errno::ENOENT),
    );
    t.eq(
        "renameat",
        sys(
            Sysno::renameat,
            &[AT_FDCWD, addr(b"b/free\0"), AT_FDCWD, addr(b"b/free2\0")],
        ),
        Ok(0),
    );
    t.eq(
        "renameat-bad-newfd-before-old-lookup",
        sys(
            Sysno::renameat,
            &[AT_FDCWD, addr(b"b/nothing\0"), 77, addr(b"q\0")],
        ),
        Err(Errno::EBADF),
    );
    t.eq(
        "renameat-bad-newfd",
        sys(
            Sysno::renameat,
            &[AT_FDCWD, addr(b"b/free2\0"), 77, addr(b"q\0")],
        ),
        Err(Errno::EBADF),
    );
    // Directory listing order after renames: the moved entry is the newest.
    let _ = mkdir(b"ord\0", 0o755);
    create(b"ord/1\0", b"");
    create(b"ord/2\0", b"");
    create(b"ord/3\0", b"");
    let _ = rename(b"ord/1\0", b"ord/4\0");
    let mut names = [0u8; 64];
    let n = list_dir(b"ord\0", &mut names);
    t.eq(
        "rename-moves-to-the-front",
        &names[..n],
        b"4,3,2".as_slice(),
    );
    let _ = rename(b"ord/3\0", b"ord/2\0");
    let n = list_dir(b"ord\0", &mut names);
    t.eq(
        "rename-over-an-entry-takes-its-place",
        &names[..n],
        b"2,4".as_slice(),
    );
}

/// The names of the entries of `path` in kernel order, comma separated, in `out`; the byte count.
fn list_dir(path: &[u8], out: &mut [u8; 64]) -> usize {
    let Ok(fd) = open(path, O_RDONLY | O_DIRECTORY, 0) else {
        return 0;
    };
    let mut buf = [0u8; 1024];
    let (mut used, mut at) = (0, 0);
    let n = sys(Sysno::getdents64, &[fd, addr_mut(&mut buf), buf.len()]).unwrap_or(0);
    while at < n {
        let reclen = usize::from(u16::from_le_bytes([buf[at + 16], buf[at + 17]]));
        let name = &buf[at + 19..at + reclen];
        let len = name.iter().position(|&b| b == 0).unwrap_or(0);
        if name[..len] != *b"." && name[..len] != *b".." {
            if used > 0 {
                out[used] = b',';
                used += 1;
            }
            out[used..used + len].copy_from_slice(&name[..len]);
            used += len;
        }
        at += reclen;
    }
    close(fd);
    used
}

fn chmod_chown(t: &mut T) {
    create(b"m\0", b"");
    t.eq("chmod", sys(Sysno::chmod, &[addr(b"m\0"), 0o6755]), Ok(0));
    t.eq("chmod-result", facts(b"m\0").map(|f| f.0), Ok(0o106_755));
    t.eq(
        "chmod-umask-not-applied",
        {
            let _ = sys(Sysno::chmod, &[addr(b"m\0"), 0o7777]);
            facts(b"m\0").map(|f| f.0)
        },
        Ok(0o107_777),
    );
    t.eq(
        "chmod-high-bits",
        {
            let _ = sys(Sysno::chmod, &[addr(b"m\0"), 0xffff_01a4]);
            facts(b"m\0").map(|f| f.0)
        },
        Ok(0o100_644),
    );
    t.eq(
        "chmod-missing",
        sys(Sysno::chmod, &[addr(b"none\0"), 0]),
        Err(Errno::ENOENT),
    );
    t.eq(
        "chmod-efault",
        sys(Sysno::chmod, &[BAD, 0]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "chmod-dir",
        {
            let r = sys(Sysno::chmod, &[addr(b"d\0"), 0o1700]);
            (r, facts(b"d\0").map(|f| f.0))
        },
        (Ok(0), Ok(0o041_700)),
    );
    let fd = open(b"m\0", O_RDWR, 0).unwrap_or(99);
    t.eq(
        "fchmod",
        (sys(Sysno::fchmod, &[fd, 0o640]), facts(b"m\0").map(|f| f.0)),
        (Ok(0), Ok(0o100_640)),
    );
    t.eq(
        "fchmod-badfd",
        sys(Sysno::fchmod, &[99, 0]),
        Err(Errno::EBADF),
    );
    t.eq(
        "fchmodat-bad-flag",
        sys(Sysno::fchmodat2, &[AT_FDCWD, addr(b"m\0"), 0o600, 0x200]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "fchmodat2-empty-path",
        sys(Sysno::fchmodat2, &[fd, addr(b"\0"), 0o600, 0x1000]),
        Ok(0),
    );
    t.eq(
        "fchmodat2-empty-path-needs-flag",
        sys(Sysno::fchmodat2, &[fd, addr(b"\0"), 0o600, 0]),
        Err(Errno::ENOENT),
    );
    t.eq(
        "fchmodat-fd",
        sys(Sysno::fchmodat, &[AT_FDCWD, addr(b"m\0"), 0o644]),
        Ok(0),
    );
    let _ = symlink(b"m\0", b"ml\0");
    t.eq(
        "chmod-follows-symlink",
        {
            let r = sys(Sysno::chmod, &[addr(b"ml\0"), 0o611]);
            (r, facts(b"m\0").map(|f| f.0), lfacts(b"ml\0").map(|f| f.0))
        },
        (Ok(0), Ok(0o100_611), Ok(0o120_777)),
    );
    t.eq(
        "fchmodat2-nofollow-symlink",
        sys(Sysno::fchmodat2, &[AT_FDCWD, addr(b"ml\0"), 0o600, 0x100]),
        Err(Errno::EOPNOTSUPP),
    );
    // chown: root; -1 keeps an id; set-id bits fall on a change of a file
    t.eq(
        "chown",
        {
            let _ = sys(Sysno::chmod, &[addr(b"m\0"), 0o6755]);
            let r = sys(Sysno::chown, &[addr(b"m\0"), 5, 6]);
            (r, facts(b"m\0").map(|f| (f.0, f.3, f.4)))
        },
        (Ok(0), Ok((0o100_755, 5, 6))),
    );
    t.eq(
        "chown-minus-one-keeps",
        {
            let r = sys(Sysno::chown, &[addr(b"m\0"), usize::MAX, 9]);
            (r, facts(b"m\0").map(|f| (f.3, f.4)))
        },
        (Ok(0), Ok((5, 9))),
    );
    t.eq(
        "chown-32bit-minus-one",
        {
            let r = sys(Sysno::chown, &[addr(b"m\0"), 0xffff_ffff, 0xffff_ffff]);
            (r, facts(b"m\0").map(|f| (f.3, f.4)))
        },
        (Ok(0), Ok((5, 9))),
    );
    t.eq(
        "chown-sgid-without-group-exec-kept",
        {
            let _ = sys(Sysno::chmod, &[addr(b"m\0"), 0o2644]);
            let _ = sys(Sysno::chown, &[addr(b"m\0"), 5, 9]);
            facts(b"m\0").map(|f| f.0)
        },
        Ok(0o102_644),
    );
    t.eq(
        "chown-sgid-with-group-exec-cleared",
        {
            let _ = sys(Sysno::chmod, &[addr(b"m\0"), 0o2754]);
            let _ = sys(Sysno::chown, &[addr(b"m\0"), 5, 9]);
            facts(b"m\0").map(|f| f.0)
        },
        Ok(0o100_754),
    );
    t.eq(
        "chown-dir-keeps-setid",
        {
            let _ = sys(Sysno::chmod, &[addr(b"d\0"), 0o6755]);
            let _ = sys(Sysno::chown, &[addr(b"d\0"), 1, 1]);
            facts(b"d\0").map(|f| f.0)
        },
        Ok(0o046_755),
    );
    t.eq(
        "lchown-symlink",
        {
            let r = sys(Sysno::lchown, &[addr(b"ml\0"), 3, 4]);
            let (_, link_st) = stat(b"ml\0\0", false);
            (r, link_st.uid, facts(b"m\0").map(|f| f.3))
        },
        (Ok(0), 3, Ok(5)),
    );
    t.eq(
        "chown-follows-symlink",
        {
            let r = sys(Sysno::chown, &[addr(b"ml\0"), 7, 8]);
            (r, facts(b"m\0").map(|f| f.3))
        },
        (Ok(0), Ok(7)),
    );
    t.eq(
        "fchown",
        (
            sys(Sysno::fchown, &[fd, 1, 2]),
            facts(b"m\0").map(|f| (f.3, f.4)),
        ),
        (Ok(0), Ok((1, 2))),
    );
    t.eq(
        "fchown-badfd",
        sys(Sysno::fchown, &[99, 0, 0]),
        Err(Errno::EBADF),
    );
    t.eq(
        "fchownat-bad-flag",
        sys(Sysno::fchownat, &[AT_FDCWD, addr(b"m\0"), 0, 0, 0x400]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "fchownat-empty-path",
        sys(Sysno::fchownat, &[fd, addr(b"\0"), 2, 3, 0x1000]),
        Ok(0),
    );
    t.eq(
        "chown-missing",
        sys(Sysno::chown, &[addr(b"none\0"), 0, 0]),
        Err(Errno::ENOENT),
    );
    close(fd);
}

fn timespecs(list: [(i64, i64); 2]) -> [i64; 4] {
    [list[0].0, list[0].1, list[1].0, list[1].1]
}

fn times(t: &mut T) {
    create(b"t\0", b"");
    let at = |times: Option<[i64; 4]>, flags: usize| {
        let r = match times {
            Some(ref times) => sys(
                Sysno::utimensat,
                &[AT_FDCWD, addr(b"t\0"), addr(times), flags],
            ),
            None => sys(Sysno::utimensat, &[AT_FDCWD, addr(b"t\0"), 0, flags]),
        };
        let (_, st) = stat(b"t\0", true);
        (r, st.atime, st.mtime)
    };
    t.eq(
        "utimensat-set",
        at(Some(timespecs([(100, 5), (200, 6)])), 0),
        (Ok(0), [100, 5], [200, 6]),
    );
    t.eq(
        "utimensat-omit-atime",
        at(Some(timespecs([(7, UTIME_OMIT), (8, 9)])), 0),
        (Ok(0), [100, 5], [8, 9]),
    );
    t.eq(
        "utimensat-omit-mtime",
        at(Some(timespecs([(11, 12), (13, UTIME_OMIT)])), 0),
        (Ok(0), [11, 12], [8, 9]),
    );
    t.eq(
        "utimensat-nsec-max",
        at(Some(timespecs([(1, 999_999_999), (2, 0)])), 0).0,
        Ok(0),
    );
    t.eq(
        "utimensat-nsec-too-big",
        at(Some(timespecs([(1, 1_000_000_000), (2, 0)])), 0).0,
        Err(Errno::EINVAL),
    );
    t.eq(
        "utimensat-nsec-negative",
        at(Some(timespecs([(1, -1), (2, 0)])), 0).0,
        Err(Errno::EINVAL),
    );
    t.eq(
        "utimensat-negative-seconds",
        at(Some(timespecs([(-5, 0), (-6, 1)])), 0),
        (Ok(0), [-5, 0], [-6, 1]),
    );
    t.eq(
        "utimensat-both-omit-skips-the-path",
        sys(
            Sysno::utimensat,
            &[
                AT_FDCWD,
                BAD,
                addr(&timespecs([(0, UTIME_OMIT), (0, UTIME_OMIT)])),
                0x7777,
            ],
        ),
        Ok(0),
    );
    t.eq(
        "utimensat-bad-flags",
        at(Some(timespecs([(1, 1), (2, 2)])), 0x200).0,
        Err(Errno::EINVAL),
    );
    t.eq("utimensat-null-times-is-now", at(None, 0).0, Ok(0));
    t.eq(
        "utimensat-efault-times",
        sys(Sysno::utimensat, &[AT_FDCWD, addr(b"t\0"), BAD, 0]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "utimensat-efault-name",
        sys(Sysno::utimensat, &[AT_FDCWD, BAD, 0, 0]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "utimensat-null-name-fdcwd",
        sys(Sysno::utimensat, &[AT_FDCWD, 0, 0, 0]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "utimensat-missing",
        sys(Sysno::utimensat, &[AT_FDCWD, addr(b"none\0"), 0, 0]),
        Err(Errno::ENOENT),
    );
    t.eq(
        "utimensat-time-error-after-path-error",
        sys(
            Sysno::utimensat,
            &[
                AT_FDCWD,
                addr(b"none\0"),
                addr(&timespecs([(0, 5_000_000_000), (0, 0)])),
                0,
            ],
        ),
        Err(Errno::ENOENT),
    );
    let fd = open(b"t\0", O_RDWR, 0).unwrap_or(99);
    t.eq(
        "futimens",
        {
            let r = sys(
                Sysno::utimensat,
                &[fd, 0, addr(&timespecs([(55, 0), (66, 0)])), 0],
            );
            let (_, st) = stat(b"t\0", true);
            (r, st.atime[0], st.mtime[0])
        },
        (Ok(0), 55, 66),
    );
    t.eq(
        "futimens-flags",
        sys(Sysno::utimensat, &[fd, 0, 0, 0x100]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "futimens-badfd",
        sys(Sysno::utimensat, &[99, 0, 0, 0]),
        Err(Errno::EBADF),
    );
    t.eq(
        "utimensat-relative-to-fd",
        {
            let dir = open(b"/n\0", O_RDONLY | O_DIRECTORY, 0).unwrap_or(99);
            let r = sys(
                Sysno::utimensat,
                &[dir, addr(b"t\0"), addr(&timespecs([(77, 0), (78, 0)])), 0],
            );
            close(dir);
            (r, stat(b"t\0", true).1.mtime[0])
        },
        (Ok(0), 78),
    );
    t.eq(
        "utimensat-empty-path",
        {
            let r = sys(
                Sysno::utimensat,
                &[
                    fd,
                    addr(b"\0"),
                    addr(&timespecs([(31, 0), (32, 0)])),
                    0x1000,
                ],
            );
            (r, stat(b"t\0", true).1.mtime[0])
        },
        (Ok(0), 32),
    );
    t.eq(
        "utimensat-symlink-nofollow",
        {
            let _ = symlink(b"t\0", b"tl\0");
            let r = sys(
                Sysno::utimensat,
                &[
                    AT_FDCWD,
                    addr(b"tl\0"),
                    addr(&timespecs([(41, 0), (42, 0)])),
                    0x100,
                ],
            );
            (
                r,
                stat(b"tl\0", false).1.mtime[0],
                stat(b"t\0", true).1.mtime[0],
            )
        },
        (Ok(0), 42, 32),
    );
    // utimes / futimesat (struct timeval) and utime (struct utimbuf)
    let tv = |a: (i64, i64), m: (i64, i64)| [a.0, a.1, m.0, m.1];
    t.eq(
        "utimes",
        {
            let r = sys(
                Sysno::utimes,
                &[addr(b"t\0"), addr(&tv((3, 400_000), (5, 600_000)))],
            );
            let (_, st) = stat(b"t\0", true);
            (r, st.atime, st.mtime)
        },
        (Ok(0), [3, 400_000_000], [5, 600_000_000]),
    );
    t.eq(
        "utimes-usec-range",
        sys(
            Sysno::utimes,
            &[addr(b"t\0"), addr(&tv((3, 1_000_000), (5, 0)))],
        ),
        Err(Errno::EINVAL),
    );
    t.eq(
        "utimes-usec-negative",
        sys(Sysno::utimes, &[addr(b"t\0"), addr(&tv((3, 0), (5, -1)))]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "utimes-now-values-are-not-special",
        sys(
            Sysno::utimes,
            &[addr(b"t\0"), addr(&tv((3, UTIME_NOW), (5, 0)))],
        ),
        Err(Errno::EINVAL),
    );
    t.eq("utimes-null", sys(Sysno::utimes, &[addr(b"t\0"), 0]), Ok(0));
    t.eq(
        "futimesat",
        sys(
            Sysno::futimesat,
            &[AT_FDCWD, addr(b"t\0"), addr(&tv((8, 0), (9, 0)))],
        ),
        Ok(0),
    );
    t.eq(
        "futimesat-fd",
        sys(Sysno::futimesat, &[fd, 0, addr(&tv((18, 0), (19, 0)))]),
        Ok(0),
    );
    t.eq(
        "utime",
        {
            let r = sys(Sysno::utime, &[addr(b"t\0"), addr(&[111i64, 222])]);
            let (_, st) = stat(b"t\0", true);
            (r, st.atime, st.mtime)
        },
        (Ok(0), [111, 0], [222, 0]),
    );
    t.eq(
        "utime-efault",
        sys(Sysno::utime, &[addr(b"t\0"), BAD]),
        Err(Errno::EFAULT),
    );
    t.eq("utime-null", sys(Sysno::utime, &[addr(b"t\0"), 0]), Ok(0));
    // The change time follows any attribute change.
    t.eq(
        "ctime-is-the-clock-after-utimensat",
        {
            let _ = sys(
                Sysno::utimensat,
                &[
                    AT_FDCWD,
                    addr(b"t\0"),
                    addr(&timespecs([(1, 0), (1, 0)])),
                    0,
                ],
            );
            let before = stat(b"t\0", true).1.ctime;
            let again = stat(b"t\0", true).1.ctime;
            (before == again, before[0] > 1_000_000_000)
        },
        (true, true),
    );
    close(fd);
}

fn truncate_sync_statfs(t: &mut T) {
    create(b"tr\0", b"0123456789");
    t.eq(
        "truncate-shrink",
        (
            sys(Sysno::truncate, &[addr(b"tr\0"), 4]),
            facts(b"tr\0").map(|f| f.2),
        ),
        (Ok(0), Ok(4)),
    );
    t.eq(
        "truncate-grow",
        (
            sys(Sysno::truncate, &[addr(b"tr\0"), 100]),
            facts(b"tr\0").map(|f| f.2),
        ),
        (Ok(0), Ok(100)),
    );
    t.eq(
        "truncate-negative",
        sys(Sysno::truncate, &[addr(b"tr\0"), usize::MAX]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "truncate-dir",
        sys(Sysno::truncate, &[addr(b"d\0"), 0]),
        Err(Errno::EISDIR),
    );
    t.eq(
        "truncate-missing",
        sys(Sysno::truncate, &[addr(b"none\0"), 0]),
        Err(Errno::ENOENT),
    );
    t.eq(
        "truncate-efault",
        sys(Sysno::truncate, &[BAD, 0]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "truncate-symlink-follows",
        {
            let _ = symlink(b"tr\0", b"trl\0");
            let r = sys(Sysno::truncate, &[addr(b"trl\0"), 7]);
            (r, facts(b"tr\0").map(|f| f.2))
        },
        (Ok(0), Ok(7)),
    );
    t.eq(
        "truncate-chardev",
        sys(Sysno::truncate, &[addr(b"/dev/console\0"), 0]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "truncate-grows-zeroes",
        {
            let mut b = [1u8; 16];
            let n = read_all(b"tr\0", &mut b).len();
            (n, b[4], b[6])
        },
        (7, 0, 0),
    );
    // fsync kinds
    let file = open(b"tr\0", O_RDWR, 0).unwrap_or(99);
    let dir = open(b"/n\0", O_RDONLY | O_DIRECTORY, 0).unwrap_or(99);
    let (pr, pw) = pipe();
    let console = open(b"/dev/console\0", O_RDWR, 0).unwrap_or(99);
    t.eq("fsync-file", sys(Sysno::fsync, &[file]), Ok(0));
    t.eq("fdatasync-file", sys(Sysno::fdatasync, &[file]), Ok(0));
    t.eq("fsync-dir", sys(Sysno::fsync, &[dir]), Ok(0));
    t.eq("fsync-pipe", sys(Sysno::fsync, &[pr]), Err(Errno::EINVAL));
    t.eq(
        "fsync-console",
        sys(Sysno::fsync, &[console]),
        Err(Errno::EINVAL),
    );
    t.eq("fsync-badfd", sys(Sysno::fsync, &[99]), Err(Errno::EBADF));
    t.eq(
        "fsync-opath",
        {
            let p = open(b"tr\0", 0o10_000_000, 0).unwrap_or(99);
            let r = sys(Sysno::fsync, &[p]);
            close(p);
            r
        },
        Err(Errno::EBADF),
    );
    t.eq("syncfs", sys(Sysno::syncfs, &[file]), Ok(0));
    t.eq("syncfs-pipe", sys(Sysno::syncfs, &[pw]), Ok(0));
    t.eq("syncfs-badfd", sys(Sysno::syncfs, &[99]), Err(Errno::EBADF));
    t.eq("sync", sys(Sysno::sync, &[]), Ok(0));
    // statfs: the constants of tmpfs; the counts depend on RAM and are only related to each other
    let mut sf = [0u64; 15];
    let r = sys(Sysno::statfs, &[addr(b"/n\0"), addr_mut(&mut sf)]);
    t.eq(
        "statfs",
        (r, sf[0], sf[1], sf[8], sf[9], sf[10]),
        (Ok(0), 0x0102_1994, 4096, 255, 4096, 0x20),
    );
    t.holds(
        "statfs-counts",
        sf[3] == sf[4] && sf[2] >= sf[3] && sf[5] >= sf[6] && sf[2] > 0,
        (sf[2], sf[3], sf[4], sf[5], sf[6]),
        "bfree == bavail <= blocks, files >= ffree",
    );
    t.eq(
        "fstatfs",
        {
            let mut sf = [0u64; 15];
            (sys(Sysno::fstatfs, &[file, addr_mut(&mut sf)]), sf[0])
        },
        (Ok(0), 0x0102_1994),
    );
    t.eq(
        "fstatfs-pipe",
        {
            let mut sf = [0u64; 15];
            let r = sys(Sysno::fstatfs, &[pr, addr_mut(&mut sf)]);
            (r, sf[0], sf[1], sf[2], sf[8], sf[10])
        },
        (Ok(0), 0x5049_5045, 4096, 0, 255, 0x20),
    );
    t.eq(
        "fstatfs-console",
        {
            let mut sf = [0u64; 15];
            (sys(Sysno::fstatfs, &[console, addr_mut(&mut sf)]), sf[0])
        },
        (Ok(0), 0x0102_1994),
    );
    t.eq(
        "fstatfs-badfd",
        sys(Sysno::fstatfs, &[99, addr_mut(&mut sf)]),
        Err(Errno::EBADF),
    );
    t.eq(
        "fstatfs-efault",
        sys(Sysno::fstatfs, &[file, BAD]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "statfs-missing",
        sys(Sysno::statfs, &[addr(b"none\0"), addr_mut(&mut sf)]),
        Err(Errno::ENOENT),
    );
    t.eq(
        "statfs-through-symlink",
        sys(Sysno::statfs, &[addr(b"trl\0"), addr_mut(&mut sf)]),
        Ok(0),
    );
    for fd in [file, dir, pr, pw, console] {
        close(fd);
    }
}

fn vectors_and_sendfile(t: &mut T) {
    #[repr(C)]
    struct Iov {
        base: usize,
        len: usize,
    }
    let iov = |parts: &[&[u8]]| -> [Iov; 4] {
        let mut out = [const { Iov { base: 0, len: 0 } }; 4];
        for (slot, part) in out.iter_mut().zip(parts) {
            *slot = Iov {
                base: addr(*part),
                len: part.len(),
            };
        }
        out
    };
    let fd = open(b"wv\0", O_CREAT | O_RDWR, 0o644).unwrap_or(99);
    let v = iov(&[b"hello ", b"", b"world", b"!!"]);
    t.eq("writev", sys(Sysno::writev, &[fd, addr(&v), 4]), Ok(13));
    let mut buf = [0u8; 32];
    t.eq(
        "writev-content",
        (
            sys(Sysno::pread64, &[fd, addr_mut(&mut buf), 32, 0]),
            &buf[..13],
        ),
        (Ok(13), b"hello world!!".as_slice()),
    );
    t.eq(
        "writev-position-moved",
        sys(Sysno::lseek, &[fd, 0, 1]),
        Ok(13),
    );
    let v2 = iov(&[b"AB", b"CD"]);
    t.eq(
        "pwritev",
        sys(Sysno::pwritev, &[fd, addr(&v2), 2, 1]),
        Ok(4),
    );
    t.eq(
        "pwritev-position-unmoved",
        sys(Sysno::lseek, &[fd, 0, 1]),
        Ok(13),
    );
    t.eq(
        "pwritev-content",
        (
            sys(Sysno::pread64, &[fd, addr_mut(&mut buf), 13, 0]),
            &buf[..13],
        ),
        (Ok(13), b"hABCD world!!".as_slice()),
    );
    t.eq(
        "writev-badfd",
        sys(Sysno::writev, &[99, addr(&v), 4]),
        Err(Errno::EBADF),
    );
    t.eq(
        "writev-too-many",
        sys(Sysno::writev, &[fd, addr(&v), 1025]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "writev-efault-vector",
        sys(Sysno::writev, &[fd, BAD, 1]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "writev-zero-vlen-vector-unread",
        sys(Sysno::writev, &[fd, BAD, 0]),
        Ok(0),
    );
    let bad = [Iov { base: BAD, len: 4 }];
    t.eq(
        "writev-efault-segment",
        sys(Sysno::writev, &[fd, addr(&bad), 1]),
        Err(Errno::EFAULT),
    );
    let kern = [Iov {
        base: usize::MAX - 3,
        len: 8,
    }];
    t.eq(
        "writev-access-ok",
        sys(Sysno::writev, &[fd, addr(&kern), 1]),
        Err(Errno::EFAULT),
    );
    let partial = [
        Iov {
            base: addr(b"abc"),
            len: 3,
        },
        Iov {
            base: 0x1000,
            len: 4,
        },
    ];
    t.eq(
        "writev-partial-before-fault",
        sys(Sysno::writev, &[fd, addr(&partial), 2]),
        Ok(3),
    );
    t.eq(
        "pwritev-negative-offset",
        sys(Sysno::pwritev, &[fd, addr(&v2), 2, usize::MAX]),
        Err(Errno::EINVAL),
    );
    let (pr, pw) = pipe();
    t.eq(
        "pwritev-pipe",
        sys(Sysno::pwritev, &[pw, addr(&v2), 2, 0]),
        Err(Errno::ESPIPE),
    );
    t.eq(
        "writev-pipe",
        sys(Sysno::writev, &[pw, addr(&v2), 2]),
        Ok(4),
    );
    t.eq(
        "writev-pipe-content",
        (sys(Sysno::read, &[pr, addr_mut(&mut buf), 32]), &buf[..4]),
        (Ok(4), b"ABCD".as_slice()),
    );
    t.eq(
        "writev-read-end",
        sys(Sysno::writev, &[pr, addr(&v2), 2]),
        Err(Errno::EBADF),
    );
    let ro = open(b"wv\0", O_RDONLY, 0).unwrap_or(99);
    t.eq(
        "writev-readonly-fd",
        sys(Sysno::writev, &[ro, BAD, 1]),
        Err(Errno::EBADF),
    );
    // sendfile
    let mut big = [0u8; 4096];
    for (i, b) in big.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    let src = open(b"sf-src\0", O_CREAT | O_RDWR, 0o644).unwrap_or(99);
    for _ in 0..40 {
        let _ = sys(Sysno::write, &[src, addr(&big), 4096]);
    }
    let _ = sys(Sysno::lseek, &[src, 0, 0]);
    let dst = open(b"sf-dst\0", O_CREAT | O_RDWR, 0o644).unwrap_or(99);
    t.eq(
        "sendfile-file",
        sys(Sysno::sendfile, &[dst, src, 0, 100_000]),
        Ok(100_000),
    );
    t.eq(
        "sendfile-positions",
        (
            sys(Sysno::lseek, &[src, 0, 1]),
            sys(Sysno::lseek, &[dst, 0, 1]),
        ),
        (Ok(100_000), Ok(100_000)),
    );
    t.eq(
        "sendfile-rest",
        sys(Sysno::sendfile, &[dst, src, 0, 100_000]),
        Ok(163_840 - 100_000),
    );
    t.eq(
        "sendfile-eof",
        sys(Sysno::sendfile, &[dst, src, 0, 10]),
        Ok(0),
    );
    let mut want = [0u8; 8];
    for (i, b) in want.iter_mut().enumerate() {
        *b = ((163_000 + i) % 4096 % 251) as u8;
    }
    t.eq(
        "sendfile-content",
        (
            sys(Sysno::pread64, &[dst, addr_mut(&mut buf), 8, 163_000]),
            &buf[..8],
        ),
        (Ok(8), want.as_slice()),
    );
    let mut off = 1000i64;
    t.eq(
        "sendfile-offset",
        (
            sys(Sysno::sendfile, &[dst, src, addr_mut(&mut off), 10]),
            off,
        ),
        (Ok(10), 1010),
    );
    t.eq(
        "sendfile-offset-keeps-position",
        sys(Sysno::lseek, &[src, 0, 1]),
        Ok(163_840),
    );
    t.eq(
        "sendfile-offset-efault",
        sys(Sysno::sendfile, &[dst, src, BAD, 10]),
        Err(Errno::EFAULT),
    );
    let mut neg = -1i64;
    t.eq(
        "sendfile-offset-negative",
        sys(Sysno::sendfile, &[dst, src, addr_mut(&mut neg), 10]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sendfile-bad-in",
        sys(Sysno::sendfile, &[dst, 99, 0, 1]),
        Err(Errno::EBADF),
    );
    t.eq(
        "sendfile-bad-out",
        sys(Sysno::sendfile, &[99, src, 0, 1]),
        Err(Errno::EBADF),
    );
    t.eq(
        "sendfile-out-readonly",
        sys(Sysno::sendfile, &[ro, src, 0, 1]),
        Err(Errno::EBADF),
    );
    let wo = open(b"sf-dst\0", O_WRONLY, 0).unwrap_or(99);
    t.eq(
        "sendfile-in-writeonly",
        sys(Sysno::sendfile, &[dst, wo, 0, 1]),
        Err(Errno::EBADF),
    );
    t.eq(
        "sendfile-count-zero",
        sys(Sysno::sendfile, &[dst, src, 0, 0]),
        Ok(0),
    );
    t.eq(
        "sendfile-count-huge",
        sys(Sysno::sendfile, &[dst, src, 0, usize::MAX]),
        Err(Errno::EINVAL),
    );
    // to a pipe: one pipe's worth per call; a full one blocks (non-blocking: EAGAIN)
    let _ = sys(Sysno::lseek, &[src, 0, 0]);
    let (pr2, pw2) = pipe();
    t.eq(
        "sendfile-pipe-one-pipe-worth",
        sys(Sysno::sendfile, &[pw2, src, 0, 100_000]),
        Ok(65_536),
    );
    let _ = sys(Sysno::fcntl, &[pw2, 4, O_NONBLOCK]);
    t.eq(
        "sendfile-pipe-full",
        sys(Sysno::sendfile, &[pw2, src, 0, 10]),
        Err(Errno::EAGAIN),
    );
    t.eq(
        "sendfile-pipe-unaligned-offset",
        {
            let mut big = [0u8; 65_536];
            let _ = sys(Sysno::fcntl, &[pr2, 4, O_NONBLOCK]);
            let mut total = 0;
            while let Ok(n) = sys(Sysno::read, &[pr2, addr_mut(&mut big), 65_536]) {
                if n == 0 {
                    break;
                }
                total += n;
            }
            let mut off = 100i64;
            (
                total,
                sys(Sysno::sendfile, &[pw2, src, addr_mut(&mut off), 1_000_000]),
                off,
            )
        },
        (65_536, Ok(65_536 - 100), 65_536),
    );
    t.eq(
        "sendfile-pipe-to-pipe",
        sys(Sysno::sendfile, &[pw, pr2, 0, 10]),
        Err(Errno::EINVAL),
    );
    t.eq(
        "sendfile-pipe-count-zero",
        sys(Sysno::sendfile, &[pw, pr2, 0, 0]),
        Ok(0),
    );
    let mut zero = 0i64;
    t.eq(
        "sendfile-pipe-with-offset",
        sys(Sysno::sendfile, &[dst, pr2, addr_mut(&mut zero), 10]),
        Err(Errno::ESPIPE),
    );
    let dirfd = open(b"/n\0", O_RDONLY | O_DIRECTORY, 0).unwrap_or(99);
    t.eq(
        "sendfile-directory-in",
        sys(Sysno::sendfile, &[dst, dirfd, 0, 10]),
        Err(Errno::EINVAL),
    );
    let app = open(b"sf-app\0", O_CREAT | O_WRONLY | O_APPEND, 0o644).unwrap_or(99);
    t.eq(
        "sendfile-append-out",
        sys(Sysno::sendfile, &[app, src, 0, 10]),
        Err(Errno::EINVAL),
    );
    let console = open(b"/dev/console\0", O_RDWR, 0).unwrap_or(99);
    create(b"sf-line\0", b"sendfile to the console\n");
    let line = open(b"sf-line\0", O_RDONLY, 0).unwrap_or(99);
    t.eq(
        "sendfile-console",
        sys(Sysno::sendfile, &[console, line, 0, 100]),
        Ok(24),
    );
    close(line);
    t.eq(
        "sendfile-closed-pipe",
        {
            let (r3, w3) = pipe();
            close(r3);
            sys(Sysno::sendfile, &[w3, src, 0, 10])
        },
        Err(Errno::EPIPE),
    );
    for fd in [fd, ro, pr, pw, src, dst, wo, pr2, pw2, dirfd, app, console] {
        close(fd);
    }
}

/// The calls that need no entropy: argument errors come before the generator is asked. The rest
/// (sizes, partial copies, flags that succeed) is the `busybox` group's: it runs on a CPU with a
/// hardware generator, which `-cpu qemu64` lacks.
fn random(t: &mut T) {
    let mut buf = [0u8; 300];
    let get = |buf: &mut [u8], len: usize, flags: usize| {
        sys(Sysno::getrandom, &[addr_mut(buf), len, flags])
    };
    t.eq(
        "getrandom-bad-flag",
        get(&mut buf, 8, 8),
        Err(Errno::EINVAL),
    );
    t.eq(
        "getrandom-insecure-random",
        get(&mut buf, 8, 6),
        Err(Errno::EINVAL),
    );
    t.eq("getrandom-zero", get(&mut buf, 0, 0), Ok(0));
    t.eq(
        "getrandom-efault",
        sys(Sysno::getrandom, &[BAD, 16, 0]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "getrandom-access-ok-huge",
        sys(Sysno::getrandom, &[addr_mut(&mut buf), 1 << 62, 0]),
        Err(Errno::EFAULT),
    );
}

/// `AT_EMPTY_PATH` with a pipe descriptor: Linux walks from the pipe's own pipefs inode, so
/// the call acts on the pipe and the working directory stays as it was. This kernel has no inode
/// for a pipe and stops loudly at the first call (`Stop::Unimplemented`, `syscall::fs::env_for_at`),
/// so this mode is a record of the pinned Linux only (`init-reference-018`), not an oracle group
/// of `expected.tsv`.
pub fn pipe_empty_path() -> bool {
    const AT_EMPTY_PATH: usize = 0x1000;
    let mut t = T::new("pipeempty");
    let _ = mkdir(b"/pe\0", 0o755);
    let _ = sys(Sysno::chdir, &[addr(b"/pe\0")]);
    let (r, _w) = pipe();
    let fstat = |fd: usize| {
        let mut st = Stat::default();
        let r = sys(
            Sysno::newfstatat,
            &[fd, addr(b"\0"), addr_mut(&mut st), AT_EMPTY_PATH],
        );
        r.map(|_| st.mode)
    };
    t.eq("cwd-mode-before", facts(b".\0").map(|f| f.0), Ok(0o040_755));
    t.eq("pipe-mode-before", fstat(r), Ok(0o010_600));
    t.eq(
        "fchmodat2-pipe",
        sys(Sysno::fchmodat2, &[r, addr(b"\0"), 0o700, AT_EMPTY_PATH]),
        Ok(0),
    );
    t.eq("pipe-mode-after", fstat(r), Ok(0o010_700));
    t.eq("cwd-mode-after", facts(b".\0").map(|f| f.0), Ok(0o040_755));
    t.eq(
        "fchownat-pipe",
        sys(Sysno::fchownat, &[r, addr(b"\0"), 0, 0, AT_EMPTY_PATH]),
        Ok(0),
    );
    t.eq(
        "utimensat-pipe",
        sys(Sysno::utimensat, &[r, addr(b"\0"), 0, AT_EMPTY_PATH]),
        Ok(0),
    );
    t.eq(
        "linkat-pipe",
        sys(
            Sysno::linkat,
            &[r, addr(b"\0"), AT_FDCWD, addr(b"lnk\0"), AT_EMPTY_PATH],
        ),
        Err(Errno::EXDEV),
    );
    t.eq("linkat-pipe-no-entry", lfacts(b"lnk\0"), Err(Errno::ENOENT));
    t.finish()
}

/// `reboot`: the checks that come before the machine is touched. The commands that end or
/// restart the machine are not called. `CAD_OFF` is undone (Linux boots with `C_A_D` = 1).
fn reboot(t: &mut T) {
    const M1: usize = 0xfee1_dead;
    const M2: usize = 672_274_793;
    const CAD_ON: usize = 0x89ab_cdef;
    const CAD_OFF: usize = 0;
    const RESTART2: usize = 0xa1b2_c3d4;
    const SW_SUSPEND: usize = 0xd000_fce2;
    const KEXEC: usize = 0x4558_4543;
    let call =
        |m1: usize, m2: usize, cmd: usize, arg: usize| sys(Sysno::reboot, &[m1, m2, cmd, arg]);
    t.eq(
        "reboot-bad-magic1",
        call(0, M2, CAD_ON, 0),
        Err(Errno::EINVAL),
    );
    t.eq(
        "reboot-bad-magic2",
        call(M1, 1, CAD_ON, 0),
        Err(Errno::EINVAL),
    );
    t.eq(
        "reboot-unknown-command",
        call(M1, M2, 5, 0),
        Err(Errno::EINVAL),
    );
    for (name, magic2) in [
        ("reboot-magic2-a", 672_274_793usize),
        ("reboot-magic2-b", 85_072_278),
        ("reboot-magic2-c", 369_367_448),
        ("reboot-magic2-d", 537_993_216),
    ] {
        t.eq(name, call(M1, magic2, CAD_ON, 0), Ok(0));
    }
    // The magic numbers are `int`s: the upper halves are ignored.
    t.eq(
        "reboot-magic-upper-halves-ignored",
        call(M1 | 1 << 40, M2 | 1 << 33, CAD_ON, 0),
        Ok(0),
    );
    t.eq("reboot-cad-off", call(M1, M2, CAD_OFF, 0), Ok(0));
    t.eq("reboot-cad-on", call(M1, M2, CAD_ON, 0), Ok(0));
    t.eq(
        "reboot-restart2-bad-pointer",
        call(M1, M2, RESTART2, BAD),
        Err(Errno::EFAULT),
    );
    t.eq(
        "reboot-kexec-without-image",
        call(M1, M2, KEXEC, 0),
        Err(Errno::EINVAL),
    );
    t.eq(
        "reboot-sw-suspend-without-hibernation",
        call(M1, M2, SW_SUSPEND, 0),
        Err(Errno::EINVAL),
    );
}

/// `mknodat`: the file types `may_mknod` accepts and refuses, the directory descriptor and the
/// errors in `filename_create` order.
fn mknodat(t: &mut T) {
    let node = |dfd: usize, path: &[u8], mode: usize, dev: usize| {
        sys(Sysno::mknodat, &[dfd, addr(path), mode, dev])
    };
    t.eq(
        "mknodat-regular",
        node(AT_FDCWD, b"mk-reg\0", 0o100_640, 0),
        Ok(0),
    );
    t.eq(
        "mknodat-regular-attributes",
        facts(b"mk-reg\0").map(|f| (f.0, f.1, f.2)),
        Ok((0o100_640, 1, 0)),
    );
    t.eq(
        "mknodat-type-zero-is-regular",
        node(AT_FDCWD, b"mk-zero\0", 0o644, 0),
        Ok(0),
    );
    t.eq(
        "mknodat-type-zero-attributes",
        facts(b"mk-zero\0").map(|f| f.0),
        Ok(0o100_644),
    );
    t.eq(
        "mknodat-umask",
        node(AT_FDCWD, b"mk-umask\0", 0o100_777, 0),
        Ok(0),
    );
    t.eq(
        "mknodat-umask-attributes",
        facts(b"mk-umask\0").map(|f| f.0),
        Ok(0o100_755),
    );
    t.eq(
        "mknodat-directory",
        node(AT_FDCWD, b"mk-dir\0", 0o040_755, 0),
        Err(Errno::EPERM),
    );
    t.eq(
        "mknodat-symlink-type",
        node(AT_FDCWD, b"mk-lnk\0", 0o120_777, 0),
        Err(Errno::EINVAL),
    );
    t.eq(
        "mknodat-exists",
        node(AT_FDCWD, b"mk-reg\0", 0o100_644, 0),
        Err(Errno::EEXIST),
    );
    t.eq(
        "mknodat-exists-slash",
        node(AT_FDCWD, b"mk-reg/\0", 0o100_644, 0),
        Err(Errno::EEXIST),
    );
    t.eq(
        "mknodat-enoent-parent",
        node(AT_FDCWD, b"mk-no/x\0", 0o100_644, 0),
        Err(Errno::ENOENT),
    );
    t.eq(
        "mknodat-enoent-empty",
        node(AT_FDCWD, b"\0", 0o100_644, 0),
        Err(Errno::ENOENT),
    );
    t.eq(
        "mknodat-efault",
        sys(Sysno::mknodat, &[AT_FDCWD, BAD, 0o100_644, 0]),
        Err(Errno::EFAULT),
    );
    t.eq(
        "mknodat-char-device",
        node(AT_FDCWD, b"mk-chr\0", 0o020_666, (1 << 8) | 3),
        Ok(0),
    );
    t.eq(
        "mknodat-char-device-attributes",
        facts(b"mk-chr\0").map(|f| f.0),
        Ok(0o020_644),
    );
    t.eq(
        "mknodat-block-device",
        node(AT_FDCWD, b"mk-blk\0", 0o060_600, 7 << 8),
        Ok(0),
    );
    t.eq(
        "mknodat-fifo",
        node(AT_FDCWD, b"mk-fifo\0", 0o010_644, 0),
        Ok(0),
    );
    t.eq(
        "mknodat-socket",
        node(AT_FDCWD, b"mk-sock\0", 0o140_644, 0),
        Ok(0),
    );
    t.eq(
        "mknodat-special-attributes",
        (
            facts(b"mk-blk\0").map(|f| f.0),
            facts(b"mk-fifo\0").map(|f| f.0),
            facts(b"mk-sock\0").map(|f| f.0),
        ),
        (Ok(0o060_600), Ok(0o010_644), Ok(0o140_644)),
    );
    // A directory descriptor, a file descriptor, a bad one, an absolute name.
    t.eq("mknodat-mkdir", mkdir(b"mk-d\0", 0o755), Ok(0));
    let dir = open(b"mk-d\0", O_RDONLY | O_DIRECTORY, 0).unwrap_or(99);
    t.eq("mknodat-dirfd", node(dir, b"x\0", 0o100_644, 0), Ok(0));
    t.eq(
        "mknodat-dirfd-result",
        lfacts(b"mk-d/x\0").map(|f| f.0),
        Ok(0o100_644),
    );
    let file = open(b"mk-reg\0", O_RDONLY, 0).unwrap_or(99);
    t.eq(
        "mknodat-file-fd",
        node(file, b"x\0", 0o100_644, 0),
        Err(Errno::ENOTDIR),
    );
    t.eq(
        "mknodat-bad-fd",
        node(77, b"x\0", 0o100_644, 0),
        Err(Errno::EBADF),
    );
    t.eq(
        "mknodat-absolute-ignores-fd",
        node(77, b"/n/mk-abs\0", 0o100_644, 0),
        Ok(0),
    );
    close(dir);
    close(file);
}

/// A script run through `execve` with this very program as its interpreter: `/init execd ...`
/// prints its own `argv` (the `proc` group's `execd` image), here through a pipe.
fn scripts(t: &mut T) {
    create(b"script\0", b"#!  /init \t execd \t \nbody\n");
    let _ = sys(Sysno::chmod, &[addr(b"script\0"), 0o755]);
    // The wait status, and the text `execd` printed from its name up to ` envp=`.
    let run_script =
        |path: &'static [u8], argv: &'static [&'static [u8]]| -> (R, [u8; 128], usize) {
            let (r, w) = pipe();
            let mut line = [0u8; 160];
            let pid = super::proc::spawn(|| {
                let _ = sys(Sysno::dup2, &[w, 1]);
                close(r);
                close(w);
                let mut ptrs = [0usize; 8];
                for (slot, arg) in ptrs.iter_mut().zip(argv) {
                    *slot = addr(*arg);
                }
                let envp = [0usize; 1];
                let failed = sys(Sysno::execve, &[addr(path), addr(&ptrs), addr(&envp)]);
                failed.err().map_or(0, |e| e.into_raw() as usize)
            });
            close(w);
            let mut got = 0;
            while got < line.len() {
                match sys(
                    Sysno::read,
                    &[r, addr_mut(&mut line[got..]), line.len() - got],
                ) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => got += n,
                }
            }
            close(r);
            let (status, code) = super::proc::wait4(pid as isize, 0);
            let text = &line[..got];
            let from = text
                .windows(17)
                .position(|w| w == b"init: execd argv=")
                .unwrap_or(0);
            let upto = text.windows(6).position(|w| w == b" envp=").unwrap_or(from);
            let mut out = [0u8; 128];
            let n = upto.saturating_sub(from).min(128);
            out[..n].copy_from_slice(&text[from..from + n]);
            (status.map(|_| code as usize), out, n)
        };
    let exited = |code: i32| Ok((code as usize) << 8);
    let (status, line, n) = run_script(b"script\0", &[b"ignored\0", b"one\0", b"two\0"]);
    t.eq("script-exit-status", status, exited(42));
    t.eq(
        "script-argv",
        &line[..n],
        b"init: execd argv=/init,execd,script,one,two".as_slice(),
    );
    let (_, line, n) = run_script(b"./script\0", &[b"x\0"]);
    t.eq(
        "script-relative-name-kept",
        &line[..n],
        b"init: execd argv=/init,execd,./script".as_slice(),
    );
    create(b"script2\0", b"#!/n/script\n");
    let _ = sys(Sysno::chmod, &[addr(b"script2\0"), 0o755]);
    let (_, line, n) = run_script(b"script2\0", &[b"s2\0", b"y\0"]);
    t.eq(
        "script-through-script",
        &line[..n],
        b"init: execd argv=/init,execd,/n/script,script2,y".as_slice(),
    );
    create(b"loop\0", b"#!/n/loop\n");
    let _ = sys(Sysno::chmod, &[addr(b"loop\0"), 0o755]);
    t.eq(
        "script-loop",
        run_script(b"loop\0", &[b"l\0"]).0,
        exited(Errno::ELOOP.into_raw()),
    );
    create(b"missing-interp\0", b"#!/n/nothing\n");
    let _ = sys(Sysno::chmod, &[addr(b"missing-interp\0"), 0o755]);
    t.eq(
        "script-missing-interpreter",
        run_script(b"missing-interp\0", &[b"m\0"]).0,
        exited(Errno::ENOENT.into_raw()),
    );
    create(b"blank\0", b"#!   \n");
    let _ = sys(Sysno::chmod, &[addr(b"blank\0"), 0o755]);
    t.eq(
        "script-blank-line",
        run_script(b"blank\0", &[b"b\0"]).0,
        exited(Errno::ENOEXEC.into_raw()),
    );
    create(b"data-interp\0", b"#!/n/m\n");
    let _ = sys(Sysno::chmod, &[addr(b"data-interp\0"), 0o755]);
    let _ = sys(Sysno::chmod, &[addr(b"m\0"), 0o644]);
    t.eq(
        "script-interpreter-not-executable",
        run_script(b"data-interp\0", &[b"d\0"]).0,
        exited(Errno::EACCES.into_raw()),
    );
    let _ = sys(Sysno::chmod, &[addr(b"script\0"), 0o644]);
    t.eq(
        "script-not-executable",
        run_script(b"script\0", &[b"s\0"]).0,
        exited(Errno::EACCES.into_raw()),
    );
}

static FLAG: AtomicUsize = AtomicUsize::new(0);

/// `vfork` with the child's work done in the asm block itself, so that the parent's frame is never
/// touched: the child stores `value` in `FLAG`, calls `exit_group(code)`; the parent gets the pid.
#[inline(never)]
fn vfork_exit(value: usize, code: usize) -> R {
    let pid: usize;
    // SAFETY: `vfork` returns twice, in the child on the parent's stack. The child leaves this asm
    // block only through `exit_group` (it executes nothing else that touches the stack), so the
    // parent's frame is intact when it resumes; the only memory the child writes is `FLAG`.
    unsafe {
        core::arch::asm!(
            "syscall",
            "test rax, rax",
            "jnz 2f",
            "mov qword ptr [{flag}], {value}",
            "mov eax, 231",
            "mov rdi, {code}",
            "syscall",
            "ud2",
            "2:",
            flag = in(reg) core::ptr::addr_of!(FLAG),
            value = in(reg) value,
            code = in(reg) code,
            inlateout("rax") 58usize => pid,
            out("rcx") _,
            out("r11") _,
            out("rdi") _,
        );
    }
    Errno::from_ret(pid)
}

/// `vfork` whose child maps one page at `at`, stores a byte in it, then `execve`s `path`: the
/// mapping stays with the parent (one address space), the exec does not touch the parent's.
#[inline(never)]
fn vfork_map_exec(at: usize, path: usize, argv: usize, envp: usize) -> R {
    let pid: usize;
    // SAFETY: as `vfork_exit`: the child runs only register-based syscalls and one store to the
    // page it just mapped, then `execve` or `exit_group(127)`, and never returns into this frame.
    unsafe {
        core::arch::asm!(
            "syscall",
            "test rax, rax",
            "jnz 2f",
            // mmap(at, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE, -1, 0)
            "mov rdi, {at}",
            "mov esi, 4096",
            "mov edx, 3",
            "mov r10d, 0x100022",
            "mov r8, -1",
            "xor r9d, r9d",
            "mov eax, 9",
            "syscall",
            "mov byte ptr [rax], 0x5a",
            "mov rdi, {path}",
            "mov rsi, {argv}",
            "mov rdx, {envp}",
            "mov eax, 59",
            "syscall",
            "mov edi, 127",
            "mov eax, 231",
            "syscall",
            "ud2",
            "2:",
            at = in(reg) at,
            path = in(reg) path,
            argv = in(reg) argv,
            envp = in(reg) envp,
            inlateout("rax") 58usize => pid,
            out("rcx") _,
            out("r11") _,
            out("rdi") _,
            out("rsi") _,
            out("rdx") _,
            out("r10") _,
            out("r8") _,
            out("r9") _,
        );
    }
    Errno::from_ret(pid)
}

/// `struct timespec` of 300 ms: how long the vfork children below stay alive.
static NAP: [u64; 2] = [0, 300_000_000];

/// `vfork` whose child sleeps 300 ms, stores `value` in `FLAG` and exits with `code`.
#[inline(never)]
fn vfork_nap_exit(value: usize, code: usize) -> R {
    let pid: usize;
    // SAFETY: as `vfork_exit`; the child additionally runs `nanosleep` on `NAP`, a static it only
    // reads, and touches neither the stack nor any register the parent needs.
    unsafe {
        core::arch::asm!(
            "syscall",
            "test rax, rax",
            "jnz 2f",
            "mov rdi, {nap}",
            "xor esi, esi",
            "mov eax, 35",
            "syscall",
            "mov qword ptr [{flag}], {value}",
            "mov eax, 231",
            "mov rdi, {code}",
            "syscall",
            "ud2",
            "2:",
            nap = in(reg) core::ptr::addr_of!(NAP),
            flag = in(reg) core::ptr::addr_of!(FLAG),
            value = in(reg) value,
            code = in(reg) code,
            inlateout("rax") 58usize => pid,
            out("rcx") _,
            out("r11") _,
            out("rdi") _,
            out("rsi") _,
        );
    }
    Errno::from_ret(pid)
}

/// A `vfork` child (B) that `vfork`s a child (C) of its own and is killed by C while it waits; C
/// sleeps 300 ms, stores `value` in `FLAG` and exits with status 4.
#[inline(never)]
fn vfork_nested_killed(value: usize) -> R {
    let pid: usize;
    // SAFETY: as `vfork_exit`, twice over: B and C run only register-based system calls on the
    // parent's stack without pushing or calling, B leaves through `exit_group` if it is ever
    // resumed, and the only memory C touches is `FLAG` and the read-only `NAP`.
    unsafe {
        core::arch::asm!(
            "syscall",
            "test rax, rax",
            "jnz 3f",
            // B: vfork again.
            "mov eax, 58",
            "syscall",
            "test rax, rax",
            "jnz 4f",
            // C: getppid -> kill(ppid, SIGKILL) -> nanosleep(NAP) -> FLAG = value -> exit_group(4).
            "mov eax, 110",
            "syscall",
            "mov rdi, rax",
            "mov esi, 9",
            "mov eax, 62",
            "syscall",
            "mov rdi, {nap}",
            "xor esi, esi",
            "mov eax, 35",
            "syscall",
            "mov qword ptr [{flag}], {value}",
            "mov edi, 4",
            "mov eax, 231",
            "syscall",
            "ud2",
            // B, back from its vfork (not reached once C has killed it).
            "4:",
            "xor edi, edi",
            "mov eax, 231",
            "syscall",
            "ud2",
            "3:",
            nap = in(reg) core::ptr::addr_of!(NAP),
            flag = in(reg) core::ptr::addr_of!(FLAG),
            value = in(reg) value,
            inlateout("rax") 58usize => pid,
            out("rcx") _,
            out("r11") _,
            out("rdi") _,
            out("rsi") _,
        );
    }
    Errno::from_ret(pid)
}

/// A chain of three `vfork`s: A (child of the caller) `vfork`s B, B kills A while A waits and
/// `vfork`s C, C kills B while B waits, sleeps 300 ms, stores `value` in `FLAG` and exits with
/// status 4. The address space then passes through two dead lenders.
#[inline(never)]
fn vfork_chain_killed(value: usize) -> R {
    let pid: usize;
    // SAFETY: as `vfork_nested_killed`, one level deeper: A, B and C run only register-based
    // system calls on the caller's stack without pushing or calling, A and B leave through
    // `exit_group` if they are ever resumed, and the only memory C touches is `FLAG` and the
    // read-only `NAP`.
    unsafe {
        core::arch::asm!(
            "syscall",
            "test rax, rax",
            "jnz 3f",
            // A: vfork again.
            "mov eax, 58",
            "syscall",
            "test rax, rax",
            "jnz 5f",
            // B: getppid -> kill(ppid, SIGKILL) -> vfork again.
            "mov eax, 110",
            "syscall",
            "mov rdi, rax",
            "mov esi, 9",
            "mov eax, 62",
            "syscall",
            "mov eax, 58",
            "syscall",
            "test rax, rax",
            "jnz 4f",
            // C: getppid -> kill(ppid, SIGKILL) -> nanosleep(NAP) -> FLAG = value -> exit_group(4).
            "mov eax, 110",
            "syscall",
            "mov rdi, rax",
            "mov esi, 9",
            "mov eax, 62",
            "syscall",
            "mov rdi, {nap}",
            "xor esi, esi",
            "mov eax, 35",
            "syscall",
            "mov qword ptr [{flag}], {value}",
            "mov edi, 4",
            "mov eax, 231",
            "syscall",
            "ud2",
            // B and A, back from their vforks (not reached once killed).
            "4:",
            "5:",
            "xor edi, edi",
            "mov eax, 231",
            "syscall",
            "ud2",
            "3:",
            nap = in(reg) core::ptr::addr_of!(NAP),
            flag = in(reg) core::ptr::addr_of!(FLAG),
            value = in(reg) value,
            inlateout("rax") 58usize => pid,
            out("rcx") _,
            out("r11") _,
            out("rdi") _,
            out("rsi") _,
        );
    }
    Errno::from_ret(pid)
}

fn vfork(t: &mut T) {
    FLAG.store(0, Relaxed);
    let pid = vfork_exit(0x1234, 7);
    t.holds(
        "vfork-pid",
        pid.is_ok_and(|pid| pid > 1),
        &pid,
        "a child pid",
    );
    t.eq(
        "vfork-child-memory-visible-to-parent",
        FLAG.load(Relaxed),
        0x1234,
    );
    let pid = pid.unwrap_or(usize::MAX);
    t.eq(
        "vfork-child-exit-status",
        super::proc::wait4(pid as isize, 0).1,
        7 << 8,
    );
    t.eq(
        "vfork-wait-again",
        super::proc::wait4(pid as isize, 0).0,
        Err(Errno::ECHILD),
    );
    // A mapping the child makes stays with the parent; the exec leaves it alone.
    let at = 0x6000_0000_0000usize;
    let argv = [addr(b"/init\0"), addr(b"execd\0"), 0];
    let envp = [0usize; 1];
    // The child execs this program, which says hello on its standard output: keep that off the console.
    let _ = sys(
        Sysno::mknod,
        &[addr(b"/dev/null\0"), 0o20_666, (1 << 8) | 3],
    );
    let null = open(b"/dev/null\0", O_RDWR, 0).unwrap_or(99);
    let saved = sys(Sysno::dup, &[1]).unwrap_or(99);
    let _ = sys(Sysno::dup2, &[null, 1]);
    let pid = vfork_map_exec(at, addr(b"/init\0"), addr(&argv), addr(&envp));
    let _ = sys(Sysno::dup2, &[saved, 1]);
    close(saved);
    close(null);
    t.holds("vfork-exec-pid", pid.is_ok(), &pid, "a child pid");
    t.eq(
        "vfork-child-mapping-visible-to-parent",
        super::peek(at),
        0x5a,
    );
    let pid = pid.unwrap_or(usize::MAX);
    t.eq(
        "vfork-exec-status",
        super::proc::wait4(pid as isize, 0).1,
        42 << 8,
    );
    t.eq("vfork-mapping-survives-the-exec", super::peek(at), 0x5a);
    t.eq(
        "vfork-unmap-mapping",
        sys(Sysno::munmap, &[at, 4096]),
        Ok(0),
    );
    // CLONE_VFORK without CLONE_VM: the parent waits, the child has its own memory.
    FLAG.store(0, Relaxed);
    let pid = sys(Sysno::clone, &[0x4000 | 17, 0, 0, 0, 0]);
    if pid == Ok(0) {
        FLAG.store(9, Relaxed);
        super::die(5);
    }
    t.eq(
        "clone-vfork-without-vm-memory-private",
        FLAG.load(Relaxed),
        0,
    );
    t.eq(
        "clone-vfork-without-vm-status",
        super::proc::wait4(pid.unwrap_or(usize::MAX) as isize, 0).1,
        5 << 8,
    );
    super::proc::reap_all();
    // The parent's interval timer runs out while it waits for its child: the wait still ends
    // when the child does (SIGALRM is ignored, so nothing else is visible).
    let ignore = [1u64, 0, 0, 0];
    let timer = [0i64, 0, 0, 100_000];
    let _ = sys(Sysno::rt_sigaction, &[14, addr(&ignore), 0, 8]);
    t.eq(
        "itimer-armed",
        sys(Sysno::setitimer, &[0, addr(&timer), 0]),
        Ok(0),
    );
    FLAG.store(0, Relaxed);
    let pid = vfork_nap_exit(0x77, 3);
    t.eq(
        "vfork-itimer-expires-while-waiting",
        FLAG.load(Relaxed),
        0x77,
    );
    t.eq(
        "vfork-itimer-child-status",
        super::proc::wait4(pid.unwrap_or(usize::MAX) as isize, 0).1,
        3 << 8,
    );
    let _ = sys(Sysno::setitimer, &[0, addr(&[0i64; 4]), 0]);
    let _ = sys(Sysno::rt_sigaction, &[14, addr(&[0u64; 4]), 0, 8]);
    // A `vfork` child killed while its own `vfork` child still works in the borrowed address
    // space: the parent keeps a usable address space whenever it resumes, and both children are
    // reaped with the statuses they died with.
    FLAG.store(0, Relaxed);
    let pid = vfork_nested_killed(0x99);
    let pid = pid.unwrap_or(usize::MAX);
    t.eq(
        "vfork-nested-killed-parent-status",
        super::proc::wait4(pid as isize, 0).1,
        9,
    );
    let (grandchild, status) = super::proc::wait4(-1, 0);
    t.holds(
        "vfork-nested-grandchild-reaped",
        grandchild.is_ok_and(|g| g != pid),
        &grandchild,
        "the grandchild's pid",
    );
    t.eq("vfork-nested-grandchild-status", status, 4 << 8);
    t.eq("vfork-nested-memory-visible", FLAG.load(Relaxed), 0x99);
    // The parent's address space still works: map, store, load, unmap.
    let at = 0x6000_0000_0000usize;
    let page = super::mmap(at, 4096, 3, 0x22 | 0x10, usize::MAX, 0);
    t.eq("vfork-nested-mmap-after", page, Ok(at));
    super::poke(at, 0x3c);
    t.eq("vfork-nested-mapping-works", super::peek(at), 0x3c);
    t.eq(
        "vfork-nested-munmap-after",
        sys(Sysno::munmap, &[at, 4096]),
        Ok(0),
    );
    super::proc::reap_all();
    // Three levels: A and B are both killed while they wait, so C's completion crosses two dead
    // lenders. The caller resumes (Linux: when A dies), A is reaped with SIGKILL, B and C are
    // reparented and reaped with their own statuses once C is done.
    FLAG.store(0, Relaxed);
    let pid = vfork_chain_killed(0x55).unwrap_or(usize::MAX);
    t.eq(
        "vfork-chain-first-status",
        super::proc::wait4(pid as isize, 0).1,
        9,
    );
    let (b, status) = super::proc::wait4(-1, 0);
    t.holds(
        "vfork-chain-second-reaped",
        b.is_ok_and(|b| b != pid),
        &b,
        "the second child's pid",
    );
    t.eq("vfork-chain-second-status", status, 9);
    let (c, status) = super::proc::wait4(-1, 0);
    t.holds(
        "vfork-chain-third-reaped",
        c.is_ok_and(|c| c != pid && c != b.unwrap_or(0)),
        &c,
        "the third child's pid",
    );
    t.eq("vfork-chain-third-status", status, 4 << 8);
    t.eq("vfork-chain-memory-visible", FLAG.load(Relaxed), 0x55);
    let at = 0x6000_0000_0000usize;
    let page = super::mmap(at, 4096, 3, 0x22 | 0x10, usize::MAX, 0);
    t.eq("vfork-chain-mmap-after", page, Ok(at));
    super::poke(at, 0x3c);
    t.eq("vfork-chain-mapping-works", super::peek(at), 0x3c);
    t.eq(
        "vfork-chain-munmap-after",
        sys(Sysno::munmap, &[at, 4096]),
        Ok(0),
    );
    super::proc::reap_all();
}
