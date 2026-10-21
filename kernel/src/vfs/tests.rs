// SPDX-License-Identifier: GPL-2.0-only
//! Host tests of the VFS spine: tmpfs, path walk, the descriptor table, pipes
//! and the initramfs unpacker, on the same code the kernel runs. The expected
//! values come from the pinned sources named in the module headers and from the
//! oracle recordings (`xtask/oracle/expected.tsv`, group `fs`).

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::too_many_lines
)]

extern crate std;

use std::{format, string::String, vec, vec::Vec};

use super::{
    Cred, FdTable, FileId, InodeId, KResult, MAY_EXEC, MAY_READ, MAY_WRITE, NR_OPEN, O_CREAT,
    O_DIRECTORY, O_EXCL, O_NOFOLLOW, O_RDONLY, O_RDWR, O_TRUNC, S_IFCHR, S_IFDIR, S_IFIFO, S_IFLNK,
    S_IFREG, S_ISVTX, Timespec, Vfs,
    initramfs::Unpacker,
    ops::{Env, build_open_flags},
    path::{LOOKUP_DIRECTORY, LOOKUP_FOLLOW},
    tmpfs::{BOGO_DIRENT_SIZE, DIR_OFFSET_EOD},
};
use syscalls::Errno;

fn clock() -> Timespec {
    Timespec { sec: 1000, nsec: 5 }
}

fn rootfs(blocks: u64) -> (Vfs, Env) {
    let mut vfs = Vfs::new(blocks, 1 << 16, clock).expect("rootfs");
    vfs.default_rootfs().expect("default rootfs");
    let env = vfs.kernel_env();
    (vfs, env)
}

fn user(uid: u32) -> Cred {
    Cred {
        fsuid: uid,
        fsgid: uid,
        dac_override: false,
        dac_read_search: false,
        fowner: false,
        mknod: false,
        chown: false,
        fsetid: false,
        sys_admin: false,
        sys_boot: false,
    }
}

/// `open(path, flags, mode)` as the syscall layer builds it.
fn open(vfs: &mut Vfs, env: &Env, path: &[u8], flags: u32, mode: u32) -> KResult<FileId> {
    let op = build_open_flags(flags, mode)?;
    vfs.open(env, path, &op)
}

fn inode_of(vfs: &Vfs, file: FileId) -> InodeId {
    vfs.files.get(file).inode.expect("file with an inode")
}

fn names(vfs: &Vfs, dir: InodeId, from: i64) -> (Vec<(String, i64)>, i64) {
    let mut out = Vec::new();
    let mut pos = from;
    vfs.fs.tmp().readdir(dir, &mut pos, &mut |name, off, _, _| {
        out.push((String::from_utf8_lossy(name).into_owned(), off));
        true
    });
    (out, pos)
}

// ---- the default rootfs ----------------------------------------------------

#[test]
fn default_rootfs_is_what_console_on_rootfs_needs() {
    let (vfs, env) = rootfs(1 << 10);
    let root = vfs.fs.getattr(vfs.fs.root());
    assert_eq!(root.mode, S_IFDIR | S_ISVTX | 0o777, "tmpfs root is 01777");
    // `.` and `..` are accounted by the initial size, every entry adds 20.
    assert_eq!(
        root.size,
        (2 * BOGO_DIRENT_SIZE + 2 * BOGO_DIRENT_SIZE) as i64
    );
    assert_eq!(root.nlink, 4, "two subdirectories");
    let console = vfs.lookup(&env, b"/dev/console", 0).unwrap();
    let console = vfs.fs.getattr(console);
    assert_eq!(console.mode, S_IFCHR | 0o600);
    assert_eq!(
        (super::major(console.rdev), super::minor(console.rdev)),
        (5, 1)
    );
    let root_home = vfs.lookup(&env, b"/root", 0).unwrap();
    assert_eq!(vfs.fs.getattr(root_home).mode, S_IFDIR | 0o700);
}

#[test]
fn console_on_rootfs_opens_three_descriptors_on_one_file() {
    let (mut vfs, _) = rootfs(1 << 10);
    let mut fds = FdTable::default();
    vfs.console_on_rootfs(&mut fds).unwrap();
    let (a, b, c) = (
        fds.get(0).unwrap(),
        fds.get(1).unwrap(),
        fds.get(2).unwrap(),
    );
    assert!(a == b && b == c);
    let file = vfs.files.get(a);
    assert_eq!(file.flags & 3, O_RDWR);
    assert_eq!(file.flags & super::O_LARGEFILE, 0, "no O_LARGEFILE");
    assert_eq!(vfs.files.open_count(), 1);
}

// ---- tmpfs data and accounting ----------------------------------------------

#[test]
fn sparse_write_reads_back_with_zero_holes() {
    let (mut vfs, env) = rootfs(1 << 10);
    let file = open(&mut vfs, &env, b"/f", O_CREAT | O_RDWR, 0o644).unwrap();
    let inode = inode_of(&vfs, file);
    assert_eq!(vfs.fs.write(inode, 5000, b"tail").unwrap(), 4);
    assert_eq!(vfs.fs.inode(inode).size, 5004);
    let mut buf = [0xaa; 5010];
    assert_eq!(vfs.fs.read(inode, 0, &mut buf), 5004);
    assert!(buf[..5000].iter().all(|&b| b == 0));
    assert_eq!(&buf[5000..5004], b"tail");
    assert_eq!(vfs.fs.read(inode, 5004, &mut buf), 0, "EOF");
    // Only the touched page is allocated: one block, 8 sectors.
    assert_eq!(vfs.fs.getattr(inode).blocks, 8);
}

#[test]
fn truncate_discards_data_beyond_the_new_size() {
    let (mut vfs, env) = rootfs(1 << 10);
    let file = open(&mut vfs, &env, b"/f", O_CREAT | O_RDWR, 0o644).unwrap();
    let inode = inode_of(&vfs, file);
    vfs.fs.write(inode, 0, b"abcdef").unwrap();
    vfs.truncate(&env, inode, 2).unwrap();
    vfs.truncate(&env, inode, 6).unwrap();
    let mut buf = [0xaa; 6];
    assert_eq!(vfs.fs.read(inode, 0, &mut buf), 6);
    assert_eq!(&buf, b"ab\0\0\0\0");
    assert_eq!(vfs.truncate(&env, vfs.fs.root(), 0), Err(Errno::EISDIR));
}

#[test]
fn space_runs_out_at_the_block_limit() {
    let (mut vfs, env) = rootfs(2);
    let file = open(&mut vfs, &env, b"/f", O_CREAT | O_RDWR, 0o644).unwrap();
    let inode = inode_of(&vfs, file);
    let page = vec![1u8; super::PAGE_SIZE];
    // Two pages fit; the third reports the bytes stored, then ENOSPC.
    assert_eq!(vfs.fs.write(inode, 0, &page).unwrap(), 4096);
    assert_eq!(vfs.fs.write(inode, 4096, &page).unwrap(), 4096);
    assert_eq!(vfs.fs.write(inode, 8192, &page), Err(Errno::ENOSPC));
    assert_eq!(vfs.fs.used_blocks(), 2);
    // Dropping the file returns its pages.
    vfs.unlink(&env, b"/f").unwrap();
    vfs.fput(file);
    assert_eq!(vfs.fs.used_blocks(), 0);
}

#[test]
fn inode_limit_is_enospc_and_leaves_no_entry() {
    let mut vfs = Vfs::new(16, 4, clock).unwrap();
    let env = vfs.kernel_env();
    // The root took one inode.
    for name in [&b"/a"[..], b"/b", b"/c"] {
        vfs.mknod(&env, name, S_IFREG | 0o600, 0).unwrap();
    }
    assert_eq!(
        vfs.mknod(&env, b"/d", S_IFREG | 0o600, 0),
        Err(Errno::ENOSPC)
    );
    assert_eq!(vfs.lookup(&env, b"/d", 0), Err(Errno::ENOENT));
    assert_eq!(vfs.fs.inode_count(), 4);
}

#[test]
fn extra_hard_links_are_charged_as_inodes_and_freed_by_unlink() {
    // shmem_link reserves an inode for every link beyond the first name and
    // shmem_unlink frees it while another name remains.
    let mut vfs = Vfs::new(16, 4, clock).unwrap();
    let env = vfs.kernel_env();
    vfs.mknod(&env, b"/a", S_IFREG | 0o600, 0).unwrap();
    vfs.link(&env, b"/a", 0, b"/b").unwrap();
    vfs.link(&env, b"/a", 0, b"/c").unwrap();
    assert_eq!(vfs.fs.inode_count(), 4);
    assert_eq!(vfs.link(&env, b"/a", 0, b"/d"), Err(Errno::ENOSPC));
    assert_eq!(vfs.lookup(&env, b"/d", 0), Err(Errno::ENOENT));
    vfs.unlink(&env, b"/b").unwrap();
    assert_eq!(vfs.fs.inode_count(), 3);
    vfs.link(&env, b"/a", 0, b"/d").unwrap();
    // Removing the last names frees the inode itself exactly once.
    for name in [&b"/a"[..], b"/c", b"/d"] {
        vfs.unlink(&env, name).unwrap();
    }
    assert_eq!(vfs.fs.inode_count(), 1, "only the root remains");
}

#[test]
fn a_removed_directory_stays_dead_while_pinned() {
    let (mut vfs, env) = rootfs(1 << 10);
    let dir = vfs.mkdir(&env, b"/d", 0o755).unwrap();
    vfs.fs.iget(dir);
    assert!(!vfs.fs.is_dead(dir));
    vfs.rmdir(&env, b"/d").unwrap();
    assert!(vfs.fs.is_dead(dir));
    let inside = Env { start: dir, ..env };
    assert_eq!(
        vfs.mknod(&inside, b"x", S_IFREG | 0o600, 0),
        Err(Errno::ENOENT)
    );
    let op = build_open_flags(O_CREAT | O_RDWR, 0o600).unwrap();
    assert_eq!(vfs.open(&inside, b"x", &op), Err(Errno::ENOENT));
    // A name that would be too long is still ENOENT: the dead check comes first.
    let long = [b'n'; 300];
    assert_eq!(vfs.open(&inside, &long, &op), Err(Errno::ENOENT));
    let before = vfs.fs.inode_count();
    vfs.fs.iput(dir);
    assert_eq!(vfs.fs.inode_count(), before - 1, "freed with the last pin");
}

// ---- directories ------------------------------------------------------------

#[test]
fn readdir_lists_newest_first_with_tmpfs_cookies() {
    let (mut vfs, env) = rootfs(1 << 10);
    vfs.mkdir(&env, b"/d", 0o755).unwrap();
    for name in [&b"/d/a"[..], b"/d/b", b"/d/c"] {
        vfs.mknod(&env, name, S_IFREG | 0o600, 0).unwrap();
    }
    let dir = vfs.lookup(&env, b"/d", 0).unwrap();
    let (all, end) = names(&vfs, dir, 0);
    let order: Vec<_> = all.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(order, [".", "..", "c", "b", "a"]);
    // Entries are numbered from 3 in creation order and listed newest first.
    assert_eq!(all[2..].iter().map(|e| e.1).collect::<Vec<_>>(), [5, 4, 3]);
    assert_eq!(end, DIR_OFFSET_EOD);
    // A cookie names the next entry to list (`mas_find_rev`): resuming at 4
    // lists `b` and then the older `a`.
    let (rest, _) = names(&vfs, dir, 4);
    assert_eq!(
        rest.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
        ["b", "a"]
    );
    // Removing the entry a cookie names does not lose the position: the search
    // falls back to the nearest older entry.
    vfs.unlink(&env, b"/d/b").unwrap();
    let (rest, _) = names(&vfs, dir, 4);
    assert_eq!(
        rest.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
        ["a"]
    );
}

#[test]
fn directory_size_and_link_counts_follow_shmem() {
    let (mut vfs, env) = rootfs(1 << 10);
    let d = vfs.mkdir(&env, b"/d", 0o755).unwrap();
    assert_eq!(vfs.fs.getattr(d).size, 2 * BOGO_DIRENT_SIZE as i64);
    assert_eq!(vfs.fs.getattr(d).nlink, 2);
    vfs.mkdir(&env, b"/d/sub", 0o755).unwrap();
    vfs.mknod(&env, b"/d/f", S_IFREG | 0o600, 0).unwrap();
    let attr = vfs.fs.getattr(d);
    assert_eq!(attr.size, 4 * BOGO_DIRENT_SIZE as i64);
    assert_eq!(attr.nlink, 3, "a subdirectory's `..`");
    assert_eq!(vfs.rmdir(&env, b"/d"), Err(Errno::ENOTEMPTY));
    vfs.rmdir(&env, b"/d/sub").unwrap();
    assert_eq!(vfs.fs.getattr(d).nlink, 2);
}

#[test]
fn removal_error_precedence() {
    let (mut vfs, env) = rootfs(1 << 10);
    vfs.mkdir(&env, b"/d", 0o755).unwrap();
    vfs.mknod(&env, b"/f", S_IFREG | 0o600, 0).unwrap();
    assert_eq!(vfs.unlink(&env, b"/d"), Err(Errno::EISDIR));
    assert_eq!(vfs.unlink(&env, b"/f/"), Err(Errno::ENOTDIR));
    assert_eq!(vfs.unlink(&env, b"/missing"), Err(Errno::ENOENT));
    assert_eq!(vfs.rmdir(&env, b"/f"), Err(Errno::ENOTDIR));
    assert_eq!(vfs.rmdir(&env, b"/d/."), Err(Errno::EINVAL));
    assert_eq!(vfs.rmdir(&env, b"/d/.."), Err(Errno::ENOTEMPTY));
    assert_eq!(vfs.rmdir(&env, b"/"), Err(Errno::EBUSY));
    assert_eq!(vfs.mkdir(&env, b"/d", 0o755), Err(Errno::EEXIST));
    assert_eq!(vfs.mkdir(&env, b"/", 0o755), Err(Errno::EEXIST));
    assert_eq!(vfs.link(&env, b"/d", 0, b"/d2"), Err(Errno::EPERM));
    assert_eq!(
        vfs.mknod(&env, b"/x", super::S_IFDIR | 0o755, 0),
        Err(Errno::EPERM)
    );
    assert_eq!(
        vfs.mknod(&env, b"/x", S_IFLNK | 0o777, 0),
        Err(Errno::EINVAL)
    );
}

#[test]
fn hard_links_share_one_inode_until_the_last_name_and_descriptor_go() {
    let (mut vfs, env) = rootfs(1 << 10);
    let file = open(&mut vfs, &env, b"/a", O_CREAT | O_RDWR, 0o600).unwrap();
    let inode = inode_of(&vfs, file);
    vfs.fs.write(inode, 0, b"data").unwrap();
    vfs.link(&env, b"/a", 0, b"/b").unwrap();
    assert_eq!(vfs.fs.getattr(inode).nlink, 2);
    vfs.unlink(&env, b"/a").unwrap();
    assert_eq!(vfs.lookup(&env, b"/b", 0), Ok(inode));
    vfs.unlink(&env, b"/b").unwrap();
    // The open file keeps the unnamed inode alive and readable.
    assert_eq!(vfs.fs.getattr(inode).nlink, 0);
    let mut buf = [0; 4];
    assert_eq!(vfs.fs.read(inode, 0, &mut buf), 4);
    assert_eq!(vfs.link(&env, b"/gone", 0, b"/c"), Err(Errno::ENOENT));
    let count = vfs.fs.inode_count();
    vfs.fput(file);
    assert_eq!(vfs.fs.inode_count(), count - 1, "evicted on the last put");
}

// ---- path walk ----------------------------------------------------------------

#[test]
fn walk_handles_dots_symlinks_and_trailing_slashes() {
    let (mut vfs, env) = rootfs(1 << 10);
    vfs.mkdir(&env, b"/d", 0o755).unwrap();
    vfs.mknod(&env, b"/d/f", S_IFREG | 0o600, 0).unwrap();
    vfs.symlink(&env, b"d", b"/ld").unwrap();
    vfs.symlink(&env, b"/d/f", b"/lf").unwrap();
    vfs.symlink(&env, b"loop2", b"/loop1").unwrap();
    vfs.symlink(&env, b"loop1", b"/loop2").unwrap();
    let root = vfs.fs.root();
    let f = vfs.lookup(&env, b"/d/f", 0).unwrap();
    assert_eq!(
        vfs.lookup(&env, b"/..", 0),
        Ok(root),
        "`..` of the root is the root"
    );
    assert_eq!(vfs.lookup(&env, b"/d/../d/./f", 0), Ok(f));
    assert_eq!(vfs.lookup(&env, b"//d///f", 0), Ok(f));
    assert_eq!(
        vfs.lookup(&env, b"/ld/f", 0),
        Ok(f),
        "intermediate links always resolve"
    );
    assert_eq!(vfs.lookup(&env, b"/lf", LOOKUP_FOLLOW), Ok(f));
    let lf = vfs.lookup(&env, b"/lf", 0).unwrap();
    assert_ne!(
        lf, f,
        "the final link is not followed without LOOKUP_FOLLOW"
    );
    assert!(vfs.fs.inode(lf).is_symlink());
    assert_eq!(vfs.lookup(&env, b"/d/f/", 0), Err(Errno::ENOTDIR));
    assert_eq!(vfs.lookup(&env, b"/d/f/x", 0), Err(Errno::ENOTDIR));
    assert_eq!(
        vfs.lookup(&env, b"/d/", LOOKUP_DIRECTORY),
        vfs.lookup(&env, b"/d", 0)
    );
    assert_eq!(
        vfs.lookup(&env, b"/d/f", LOOKUP_DIRECTORY),
        Err(Errno::ENOTDIR)
    );
    assert_eq!(vfs.lookup(&env, b"/nope/x", 0), Err(Errno::ENOENT));
    assert_eq!(
        vfs.lookup(&env, b"/loop1", LOOKUP_FOLLOW),
        Err(Errno::ELOOP)
    );
    assert_eq!(vfs.lookup(&env, b"/loop1/x", 0), Err(Errno::ELOOP));
}

#[test]
fn name_and_path_length_limits() {
    let (vfs, env) = rootfs(1 << 10);
    let long = [b'a'; 256];
    let mut path = vec![b'/'];
    path.extend_from_slice(&long);
    assert_eq!(vfs.lookup(&env, &path, 0), Err(Errno::ENAMETOOLONG));
    let ok = [b'a'; 255];
    let mut path = vec![b'/'];
    path.extend_from_slice(&ok);
    assert_eq!(vfs.lookup(&env, &path, 0), Err(Errno::ENOENT));
}

#[test]
fn relative_walks_start_at_the_given_directory_and_dotdot_stays_inside_root() {
    let (mut vfs, env) = rootfs(1 << 10);
    let d = vfs.mkdir(&env, b"/d", 0o755).unwrap();
    let f = vfs.mknod(&env, b"/d/f", S_IFREG | 0o600, 0).unwrap();
    let inner = Env { start: d, ..env };
    assert_eq!(vfs.lookup(&inner, b"f", 0), Ok(f));
    assert_eq!(vfs.lookup(&inner, b"../d/f", 0), Ok(f));
    assert_eq!(vfs.lookup(&inner, b"", 0), Ok(d));
    // A chroot-like root: `..` cannot climb out of it.
    let jailed = Env {
        root: d,
        start: d,
        ..env
    };
    assert_eq!(vfs.lookup(&jailed, b"../..", 0), Ok(d));
    assert_eq!(vfs.dir_path(vfs.fs.root(), d).unwrap(), b"/d");
    assert_eq!(vfs.dir_path(vfs.fs.root(), vfs.fs.root()).unwrap(), b"/");
    // A removed directory has no path (a working directory pins its inode).
    vfs.fs.iget(d);
    vfs.unlink(&env, b"/d/f").unwrap();
    vfs.rmdir(&env, b"/d").unwrap();
    assert_eq!(vfs.dir_path(vfs.fs.root(), d), Err(Errno::ENOENT));
}

#[test]
fn permission_checks_use_the_owner_group_other_class() {
    let (mut vfs, env) = rootfs(1 << 10);
    let private = vfs.lookup(&env, b"/root", 0).unwrap();
    let stranger = Env {
        cred: user(1000),
        ..env
    };
    // Search permission on /root (0700, owner 0) is denied to uid 1000 ...
    assert_eq!(vfs.lookup(&stranger, b"/root/x", 0), Err(Errno::EACCES));
    assert_eq!(
        vfs.access_check(&stranger, private, MAY_READ),
        Err(Errno::EACCES)
    );
    // ... but the directory itself can still be found, and root bypasses it.
    assert_eq!(vfs.lookup(&stranger, b"/root", 0), Ok(private));
    assert_eq!(
        vfs.access_check(&env, private, MAY_READ | MAY_WRITE | MAY_EXEC),
        Ok(())
    );
    // Root needs an execute bit somewhere to execute a regular file.
    let plain = vfs.mknod(&env, b"/plain", S_IFREG | 0o644, 0).unwrap();
    assert_eq!(vfs.access_check(&env, plain, MAY_EXEC), Err(Errno::EACCES));
    let script = vfs.mknod(&env, b"/script", S_IFREG | 0o744, 0).unwrap();
    assert_eq!(vfs.access_check(&env, script, MAY_EXEC), Ok(()));
    // The sticky root lets a user delete only what the user owns.
    vfs.mknod(&env, b"/rootfile", S_IFREG | 0o666, 0).unwrap();
    assert_eq!(vfs.unlink(&stranger, b"/rootfile"), Err(Errno::EPERM));
    let mine = vfs.mknod(&stranger, b"/mine", S_IFREG | 0o666, 0).unwrap();
    assert_eq!(vfs.fs.inode(mine).uid, 1000);
    assert_eq!(vfs.unlink(&stranger, b"/mine"), Ok(()));
    // Device nodes need CAP_MKNOD.
    assert_eq!(
        vfs.mknod(&stranger, b"/null", S_IFCHR | 0o666, 0),
        Err(Errno::EPERM)
    );
}

#[test]
fn creation_applies_the_umask_and_keeps_only_the_requested_bits() {
    let (mut vfs, env) = rootfs(1 << 10);
    let env = Env {
        umask: 0o077,
        ..env
    };
    let f = vfs.mknod(&env, b"/f", S_IFREG | 0o777, 0).unwrap();
    assert_eq!(vfs.fs.getattr(f).mode, S_IFREG | 0o700);
    let fifo = vfs.mknod(&env, b"/p", S_IFIFO | 0o666, 0).unwrap();
    assert_eq!(vfs.fs.getattr(fifo).mode, S_IFIFO | 0o600);
    // mkdir keeps the sticky bit, drops set-id.
    let d = vfs.mkdir(&env, b"/d", 0o7777).unwrap();
    assert_eq!(vfs.fs.getattr(d).mode, S_IFDIR | S_ISVTX | 0o700);
}

// ---- open ---------------------------------------------------------------------

#[test]
fn open_flag_combinations_follow_do_filp_open() {
    let (mut vfs, env) = rootfs(1 << 10);
    let created = open(&mut vfs, &env, b"/f", O_CREAT | O_EXCL | O_RDWR, 0o600).unwrap();
    let inode = inode_of(&vfs, created);
    vfs.fs.write(inode, 0, b"xyz").unwrap();
    vfs.fput(created);
    assert_eq!(
        open(&mut vfs, &env, b"/f", O_CREAT | O_EXCL | O_RDWR, 0o600),
        Err(Errno::EEXIST)
    );
    // O_TRUNC empties; O_DIRECTORY on a file is ENOTDIR; writing a directory is EISDIR.
    let file = open(&mut vfs, &env, b"/f", O_RDWR | O_TRUNC, 0).unwrap();
    assert_eq!(vfs.fs.inode(inode_of(&vfs, file)).size, 0);
    assert_eq!(
        open(&mut vfs, &env, b"/f", O_RDONLY | O_DIRECTORY, 0),
        Err(Errno::ENOTDIR)
    );
    assert_eq!(open(&mut vfs, &env, b"/", O_RDWR, 0), Err(Errno::EISDIR));
    assert_eq!(
        open(&mut vfs, &env, b"/missing", O_RDONLY, 0),
        Err(Errno::ENOENT)
    );
    assert_eq!(
        open(&mut vfs, &env, b"/f/", O_RDONLY, 0),
        Err(Errno::ENOTDIR)
    );
    assert_eq!(
        open(&mut vfs, &env, b"/f/", O_CREAT | O_RDWR, 0o600),
        Err(Errno::EISDIR)
    );
    // O_DIRECTORY | O_CREAT is invalid before the path is looked at.
    assert_eq!(
        build_open_flags(O_DIRECTORY | O_CREAT, 0).map(|_| ()),
        Err(Errno::EINVAL)
    );
    // A symbolic link opens through, unless O_NOFOLLOW (ELOOP) or O_EXCL | O_CREAT.
    vfs.symlink(&env, b"f", b"/l").unwrap();
    assert!(open(&mut vfs, &env, b"/l", O_RDONLY, 0).is_ok());
    assert_eq!(
        open(&mut vfs, &env, b"/l", O_RDONLY | O_NOFOLLOW, 0),
        Err(Errno::ELOOP)
    );
    assert_eq!(
        open(&mut vfs, &env, b"/l", O_CREAT | O_EXCL | O_RDWR, 0o600),
        Err(Errno::EEXIST)
    );
    // Opening for write the file of a stranger is checked, not assumed.
    vfs.mknod(&env, b"/ro", S_IFREG | 0o444, 0).unwrap();
    let stranger = Env {
        cred: user(1000),
        ..env
    };
    assert_eq!(
        open(&mut vfs, &stranger, b"/ro", super::O_WRONLY, 0),
        Err(Errno::EACCES)
    );
    assert!(open(&mut vfs, &stranger, b"/ro", O_RDONLY, 0).is_ok());
}

#[test]
fn opening_device_nodes_picks_the_driver_or_says_enxio() {
    let (mut vfs, env) = rootfs(1 << 10);
    vfs.mknod(
        &env,
        b"/null",
        S_IFCHR | 0o666,
        super::new_encode_dev(super::mkdev(1, 3)),
    )
    .unwrap();
    vfs.mknod(
        &env,
        b"/none",
        S_IFCHR | 0o666,
        super::new_encode_dev(super::mkdev(0, 0)),
    )
    .unwrap();
    vfs.mknod(
        &env,
        b"/misc",
        S_IFCHR | 0o666,
        super::new_encode_dev(super::mkdev(10, 144)),
    )
    .unwrap();
    vfs.mknod(
        &env,
        b"/tty",
        S_IFCHR | 0o666,
        super::new_encode_dev(super::mkdev(4, 1)),
    )
    .unwrap();
    let null = open(&mut vfs, &env, b"/null", O_RDWR, 0).unwrap();
    assert_eq!(
        vfs.files.get(null).kind,
        super::file::FileKind::Char(super::file::CharDev::Null)
    );
    // Major 0 has no driver; a number the reference configuration may register
    // opens as an unported device (every use stops) and stays seekable, while a
    // tty is `nonseekable_open`.
    assert_eq!(open(&mut vfs, &env, b"/none", O_RDWR, 0), Err(Errno::ENXIO));
    let misc = open(&mut vfs, &env, b"/misc", O_RDWR, 0).unwrap();
    let misc = vfs.files.get(misc);
    assert_eq!(misc.kind, super::file::FileKind::Unsupported);
    assert_ne!(misc.mode & super::FMODE_LSEEK, 0);
    let tty = open(&mut vfs, &env, b"/tty", O_RDWR, 0).unwrap();
    assert_eq!(vfs.files.get(tty).mode & super::FMODE_LSEEK, 0);
}

// ---- descriptor table ------------------------------------------------------------

#[test]
fn descriptors_are_allocated_lowest_first_and_reused() {
    let mut fds = FdTable::default();
    let first = fds.alloc_fd(0, 1024, false).unwrap();
    let second = fds.alloc_fd(0, 1024, true).unwrap();
    assert_eq!((first, second), (0, 1));
    assert!(fds.cloexec(1) && !fds.cloexec(0));
    assert_eq!(fds.max_fds(), 64, "NR_OPEN_DEFAULT words");
    fds.put_unused(0);
    assert_eq!(fds.alloc_fd(0, 1024, false), Ok(0));
    assert_eq!(fds.alloc_fd(10, 1024, false), Ok(10), "F_DUPFD minimum");
    assert_eq!(fds.alloc_fd(0, 1024, false), Ok(2));
    // The table grows by powers of two as high numbers are used.
    assert_eq!(fds.alloc_fd(100, 1024, false), Ok(100));
    assert_eq!(fds.max_fds(), 128);
}

#[test]
fn descriptor_limits_are_emfile() {
    let mut fds = FdTable::default();
    assert_eq!(
        fds.alloc_fd(0, 0, false),
        Err(Errno::EMFILE),
        "RLIMIT_NOFILE 0"
    );
    assert_eq!(fds.alloc_fd(5, 5, false), Err(Errno::EMFILE));
    assert_eq!(fds.expand(NR_OPEN), Err(Errno::EMFILE));
    assert_eq!(fds.alloc_fd(u32::MAX, u64::MAX, false), Err(Errno::EMFILE));
    for expected in 0..4 {
        assert_eq!(fds.alloc_fd(0, 4, false), Ok(expected));
    }
    assert_eq!(fds.alloc_fd(0, 4, false), Err(Errno::EMFILE));
}

#[test]
fn dup2_style_replace_returns_the_old_file_and_detects_a_reservation() {
    let (mut vfs, env) = rootfs(1 << 10);
    let a = open(&mut vfs, &env, b"/a", O_CREAT | O_RDWR, 0o600).unwrap();
    let b = open(&mut vfs, &env, b"/b", O_CREAT | O_RDWR, 0o600).unwrap();
    let mut fds = FdTable::default();
    let fd = fds.alloc_fd(0, 64, false).unwrap();
    fds.install(fd, a);
    // Replacing an installed descriptor hands back the old file ...
    assert_eq!(fds.replace(fd, b, true), Ok(Some(a)));
    assert!(fds.cloexec(fd));
    assert_eq!(fds.get(fd), Some(b));
    // ... a reserved-but-empty slot is EBUSY (`do_dup2` racing `open`).
    let reserved = fds.alloc_fd(0, 64, false).unwrap();
    assert_eq!(fds.replace(reserved, b, false), Err(Errno::EBUSY));
    assert_eq!(fds.get(reserved), None);
    // Closing returns the file and frees the number.
    assert_eq!(fds.close(fd), Some(b));
    assert_eq!(fds.close(fd), None);
    assert_eq!(fds.alloc_fd(0, 64, false), Ok(fd));
}

#[test]
fn shared_files_are_released_by_the_last_put() {
    let (mut vfs, env) = rootfs(1 << 10);
    let file = open(&mut vfs, &env, b"/a", O_CREAT | O_RDWR, 0o600).unwrap();
    vfs.files.dup(file);
    vfs.fput(file);
    assert_eq!(vfs.files.open_count(), 1);
    vfs.fput(file);
    assert_eq!(vfs.files.open_count(), 0);
    // The arena slot is reused.
    let again = open(&mut vfs, &env, b"/a", O_RDONLY, 0).unwrap();
    assert_eq!(again, file);
}

// ---- pipes ---------------------------------------------------------------------

#[test]
fn pipe_buffers_merge_small_writes_and_fill_after_sixteen_pages() {
    let (mut vfs, _) = rootfs(1 << 10);
    let (read, write) = vfs.pipe_create(0, &Cred::root()).unwrap();
    let id = match vfs.files.get(read).kind {
        super::file::FileKind::Pipe {
            pipe,
            writer: false,
        } => pipe,
        other => panic!("{other:?}"),
    };
    assert!(matches!(
        vfs.files.get(write).kind,
        super::file::FileKind::Pipe { writer: true, .. }
    ));
    let pipe = vfs.pipe_mut(id);
    assert!(pipe.is_empty());
    assert_eq!(pipe.size(), 65536);
    pipe.push_page(b"hello").unwrap();
    assert_eq!(pipe.merge_room(), 4091);
    pipe.merge(b" world").unwrap();
    assert_eq!(pipe.available(), 11);
    assert_eq!(pipe.front(), Some(&b"hello world"[..]));
    pipe.consume(6);
    assert_eq!(pipe.front(), Some(&b"world"[..]));
    pipe.consume(5);
    assert!(pipe.is_empty());
    for _ in 0..16 {
        pipe.push_page(&[7; 4096]).unwrap();
    }
    assert!(pipe.is_full());
    assert_eq!(pipe.push_page(b"x"), Err(Errno::EINVAL));
    assert_eq!(pipe.available(), 16 * 4096);
    // The pipe lives until both ends are gone.
    vfs.fput(read);
    assert_eq!(vfs.pipe_ref(id).readers, 0);
    assert_eq!(vfs.pipe_ref(id).writers, 1);
    vfs.fput(write);
    assert_eq!(vfs.files.open_count(), 0);
}

// ---- fork and exit: descriptors, fs_struct, mapping pins ------------------------

/// Install `file` at the lowest free descriptor (`get_unused_fd` + `fd_install`).
fn install(fdt: &mut FdTable, file: FileId, cloexec: bool) -> u32 {
    let fd = fdt.alloc_fd(0, 1024, cloexec).unwrap();
    fdt.install(fd, file);
    fd
}

#[test]
fn dup_fd_gives_the_child_its_own_table_over_shared_descriptions() {
    let (mut vfs, env) = rootfs(1 << 10);
    let mut parent = FdTable::default();
    let file = open(&mut vfs, &env, b"/dev/console", O_RDWR, 0).unwrap();
    let (read, write) = vfs.pipe_create(0, &Cred::root()).unwrap();
    assert_eq!(install(&mut parent, file, false), 0);
    assert_eq!(install(&mut parent, read, true), 1);
    assert_eq!(install(&mut parent, write, false), 2);
    // A high descriptor sizes the child's table for it.
    parent.expand(100).unwrap();
    let high = open(&mut vfs, &env, b"/dev/console", O_RDWR, 0).unwrap();
    let fd = parent.alloc_fd(100, 1024, false).unwrap();
    parent.install(fd, high);
    let open_files = vfs.files.open_count();
    let refs = vfs.files.total_refs();

    let mut child = vfs.dup_fd(&parent).unwrap();
    assert_eq!(
        vfs.files.open_count(),
        open_files,
        "descriptions are shared"
    );
    assert_eq!(
        vfs.files.total_refs(),
        refs + 4,
        "one reference per descriptor"
    );
    let seen = |t: &FdTable| t.iter().collect::<Vec<_>>();
    assert_eq!(seen(&child), seen(&parent));
    assert_eq!(seen(&child).len(), 4);
    assert!(child.cloexec(1) && !child.cloexec(0));
    // The tables are independent: closing in the child leaves the parent's.
    vfs.close_files(&mut child);
    assert_eq!(seen(&child), []);
    assert_eq!(seen(&parent).len(), 4);
    assert_eq!(vfs.files.open_count(), open_files);
    assert_eq!(vfs.files.total_refs(), refs);
    // The child's next descriptor is the lowest free one of its own table.
    let mut child = vfs.dup_fd(&parent).unwrap();
    assert_eq!(child.close(0).map(|f| vfs.fput(f)), Some(()));
    assert_eq!(child.alloc_fd(0, 1024, false).unwrap(), 0);
    child.put_unused(0);
    // Both closed: the last reference frees the descriptions and pipe ends.
    vfs.close_files(&mut child);
    vfs.close_files(&mut parent);
    assert_eq!(vfs.files.open_count(), 0);
    // An empty table duplicates to an empty table.
    let empty = vfs.dup_fd(&FdTable::default()).unwrap();
    assert_eq!(empty.max_fds(), 0);
}

#[test]
fn dup_fs_and_put_fs_balance_the_directory_references() {
    let (mut vfs, _) = rootfs(1 << 10);
    let fs = vfs.new_fs_struct(0o077);
    let (root, pwd) = (fs.root, fs.pwd);
    let before = (vfs.fs.inode_refs(root), vfs.fs.inode_refs(pwd));
    let child = vfs.dup_fs(&fs);
    assert_eq!(child, fs, "the same root, cwd and umask");
    assert_eq!(
        vfs.fs.inode_refs(root),
        before.0 + 2,
        "root and cwd are both the root"
    );
    vfs.put_fs(&child);
    assert_eq!((vfs.fs.inode_refs(root), vfs.fs.inode_refs(pwd)), before);
}

#[test]
fn mapping_pins_belong_to_an_address_space_and_clone_with_fork() {
    let (mut vfs, env) = rootfs(1 << 10);
    let file = open(&mut vfs, &env, b"/dev/console", O_RDWR, 0).unwrap();
    let id = u64::from(file.index());
    for _ in 0..2 {
        vfs.reserve_pin().unwrap();
    }
    vfs.pin(1, id);
    vfs.pin(1, id); // idempotent per owner
    assert_eq!(vfs.pin_count(), 1);
    // A forked address space holds its own reference; the other owner's
    // stays when one of them goes away.
    vfs.pin_clone(1, 2).unwrap();
    assert_eq!(
        (vfs.pin_count(), vfs.pin_owner(0), vfs.pin_owner(1)),
        (2, 1, 2)
    );
    vfs.unpin_all(1);
    assert_eq!((vfs.pin_count(), vfs.pin_owner(0)), (1, 2));
    vfs.fput(file);
    assert_eq!(
        vfs.files.open_count(),
        1,
        "the child's mapping keeps it open"
    );
    vfs.unpin_all(2);
    assert_eq!((vfs.pin_count(), vfs.files.open_count()), (0, 0));
}

// ---- the initramfs unpacker ---------------------------------------------------

/// One `newc` record: header, NUL-terminated name, data, 4-byte padding.
fn newc(name: &str, mode: u32, nlink: u32, ino: u32, data: &[u8], rdev: (u32, u32)) -> Vec<u8> {
    let mut out = format!(
        "070701{ino:08X}{mode:08X}{uid:08X}{gid:08X}{nlink:08X}{mtime:08X}{size:08X}\
         {dmaj:08X}{dmin:08X}{rmaj:08X}{rmin:08X}{namesize:08X}{check:08X}",
        uid = 0,
        gid = 0,
        mtime = 0x1234,
        size = data.len(),
        dmaj = 0,
        dmin = 1,
        rmaj = rdev.0,
        rmin = rdev.1,
        namesize = name.len() + 1,
        check = 0,
    )
    .into_bytes();
    out.extend_from_slice(name.as_bytes());
    out.push(0);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out.extend_from_slice(data);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

fn trailer() -> Vec<u8> {
    newc("TRAILER!!!", 0, 1, 0, b"", (0, 0))
}

fn unpacked(archive: &[u8]) -> (Vfs, Env, Option<&'static str>) {
    let (mut vfs, env) = rootfs(1 << 10);
    let message = Unpacker::new().unpack(&mut vfs, archive);
    (vfs, env, message)
}

#[test]
fn unpacks_directories_files_symlinks_and_devices_with_their_attributes() {
    let mut archive = Vec::new();
    archive.extend(newc("etc", 0o040_755, 2, 1, b"", (0, 0)));
    archive.extend(newc("etc/motd", 0o100_640, 1, 2, b"hello\n", (0, 0)));
    archive.extend(newc("etc/link", 0o120_777, 1, 3, b"motd", (0, 0)));
    archive.extend(newc("dev/null", 0o020_666, 1, 4, b"", (1, 3)));
    archive.extend(newc("empty", 0o100_600, 1, 5, b"", (0, 0)));
    archive.extend(newc("etc/dangling", 0o120_777, 1, 6, b"nowhere", (0, 0)));
    archive.extend(trailer());
    let (mut vfs, env, message) = unpacked(&archive);
    assert_eq!(message, None);
    let motd = vfs.lookup(&env, b"/etc/motd", 0).unwrap();
    let attr = vfs.fs.getattr(motd);
    assert_eq!((attr.mode, attr.size), (S_IFREG | 0o640, 6));
    assert_eq!(
        attr.mtime,
        Timespec {
            sec: 0x1234,
            nsec: 0
        }
    );
    assert_eq!(vfs.fs.read_all(motd).unwrap(), b"hello\n");
    // The symlink is stored verbatim and resolves through the tree.
    assert_eq!(vfs.lookup(&env, b"/etc/link", LOOKUP_FOLLOW), Ok(motd));
    let link = vfs.lookup(&env, b"/etc/link", 0).unwrap();
    assert_eq!(vfs.fs.getattr(link).size, 4);
    // `init_utimes` does not follow the link: the symlink itself has the archive time, the file
    // it names keeps its own (here the same), and a dangling link is dated too.
    let time = Timespec {
        sec: 0x1234,
        nsec: 0,
    };
    assert_eq!(vfs.fs.getattr(link).mtime, time);
    let dangling = vfs.lookup(&env, b"/etc/dangling", 0).unwrap();
    assert_eq!(vfs.fs.getattr(dangling).mtime, time);
    // Directory mtimes are applied after the whole archive (`dir_utime`).
    let etc = vfs.lookup(&env, b"/etc", 0).unwrap();
    assert_eq!(
        vfs.fs.getattr(etc).mtime,
        Timespec {
            sec: 0x1234,
            nsec: 0
        }
    );
    let null = vfs.lookup(&env, b"/dev/null", 0).unwrap();
    assert_eq!(vfs.fs.getattr(null).rdev, super::mkdev(1, 3));
    let file = open(&mut vfs, &env, b"/dev/null", O_RDWR, 0).unwrap();
    assert!(matches!(
        vfs.files.get(file).kind,
        super::file::FileKind::Char(super::file::CharDev::Null)
    ));
    let empty = vfs.lookup(&env, b"/empty", 0).unwrap();
    assert!(vfs.fs.inode(empty).is_reg());
}

#[test]
fn hard_links_in_an_archive_become_one_inode() {
    let mut archive = Vec::new();
    // The first name is stored empty, the last carries the data (cpio's rule).
    archive.extend(newc("one", 0o100_644, 2, 7, b"", (0, 0)));
    archive.extend(newc("two", 0o100_644, 2, 7, b"shared", (0, 0)));
    archive.extend(newc("other", 0o100_644, 1, 8, b"x", (0, 0)));
    archive.extend(trailer());
    let (vfs, env, message) = unpacked(&archive);
    assert_eq!(message, None);
    let (one, two) = (
        vfs.lookup(&env, b"/one", 0).unwrap(),
        vfs.lookup(&env, b"/two", 0).unwrap(),
    );
    assert_eq!(one, two);
    assert_eq!(vfs.fs.getattr(one).nlink, 2);
    assert_eq!(vfs.fs.read_all(one).unwrap(), b"shared");
    assert_ne!(vfs.lookup(&env, b"/other", 0).unwrap(), one);
}

#[test]
fn an_entry_replaces_an_existing_name_of_another_type_only() {
    let mut archive = Vec::new();
    archive.extend(newc("dev/console", 0o100_600, 1, 1, b"now a file", (0, 0)));
    archive.extend(newc("root", 0o040_755, 2, 2, b"", (0, 0)));
    archive.extend(trailer());
    let (vfs, env, message) = unpacked(&archive);
    assert_eq!(message, None);
    let console = vfs.lookup(&env, b"/dev/console", 0).unwrap();
    assert!(
        vfs.fs.inode(console).is_reg(),
        "the char node was unlinked first"
    );
    // Same type: the directory is kept and its mode re-applied.
    let root = vfs.lookup(&env, b"/root", 0).unwrap();
    assert_eq!(vfs.fs.getattr(root).mode, S_IFDIR | 0o755);
}

#[test]
fn archives_concatenate_across_zero_padding_and_keep_partial_progress() {
    let mut archive = Vec::new();
    archive.extend(newc("a", 0o100_600, 1, 1, b"A", (0, 0)));
    archive.extend(trailer());
    archive.extend([0; 12]);
    archive.extend(newc("b", 0o100_600, 1, 2, b"B", (0, 0)));
    archive.extend(trailer());
    let (vfs, env, message) = unpacked(&archive);
    assert_eq!(message, None);
    assert!(vfs.lookup(&env, b"/a", 0).is_ok() && vfs.lookup(&env, b"/b", 0).is_ok());

    // A short archive keeps what was complete before the cut.
    let mut cut = newc("whole", 0o100_600, 1, 1, b"complete", (0, 0));
    cut.extend(newc("partial", 0o100_600, 1, 2, b"truncated body", (0, 0)));
    cut.truncate(cut.len() - 6);
    let (vfs, env, _) = unpacked(&cut);
    let whole = vfs.lookup(&env, b"/whole", 0).unwrap();
    assert_eq!(vfs.fs.read_all(whole).unwrap(), b"complete");
    let partial = vfs.lookup(&env, b"/partial", 0).unwrap();
    assert_eq!(
        vfs.fs.getattr(partial).size,
        14,
        "the file was sized before its data"
    );
}

#[test]
fn damaged_archives_report_linux_messages() {
    let mut old = b"070707".to_vec();
    old.resize(120, b'0');
    let (_, _, message) = unpacked(&old);
    assert_eq!(
        message,
        Some("incorrect cpio method used: use -H newc option")
    );
    let mut junk = b"07070Z".to_vec();
    junk.resize(120, b'0');
    let (_, _, message) = unpacked(&junk);
    assert_eq!(message, Some("no cpio magic"));
    let (_, _, message) = unpacked(&[0x1f, 0x8b, 8, 0, 0, 0]);
    assert_eq!(message, Some(crate::vfs::initramfs::NOT_PORTED));
    let (_, _, message) = unpacked(b"garbage that is not an archive");
    assert_eq!(
        message,
        Some("invalid magic at start of compressed archive")
    );
    // A name field without its NUL.
    let mut bad = newc("name", 0o100_600, 1, 1, b"", (0, 0));
    bad[6 + 8 * 11..6 + 8 * 12].copy_from_slice(b"00000003");
    let (_, _, message) = unpacked(&bad);
    assert_eq!(message, Some("malformed archive"));
    // A bad data checksum of a `070702` record.
    let mut sum = newc("c", 0o100_600, 1, 1, b"abc", (0, 0));
    sum[5] = b'2';
    let (_, _, message) = unpacked(&sum);
    assert_eq!(message, Some("bad data checksum"));
}

#[test]
fn unpacking_into_a_full_rootfs_reports_a_write_error() {
    let (mut vfs, env) = rootfs(1);
    let mut archive = newc("big", 0o100_600, 1, 1, &[1u8; 6000], (0, 0));
    archive.extend(trailer());
    let message = Unpacker::new().unpack(&mut vfs, &archive);
    assert_eq!(message, Some("write error"));
    assert!(vfs.lookup(&env, b"/big", 0).is_ok(), "the entry stays");
}

#[test]
fn a_later_archive_replaces_init_even_with_an_empty_body_or_another_type() {
    let (mut vfs, env) = rootfs(1 << 10);
    let mut unpacker = Unpacker::new();
    let mut first = newc("init", 0o100_755, 1, 1, b"first", (0, 0));
    first.extend(trailer());
    assert_eq!(unpacker.unpack(&mut vfs, &first), None);
    let read = |vfs: &Vfs| {
        let inode = vfs.lookup(&env, b"/init", LOOKUP_FOLLOW).unwrap();
        vfs.fs.read_all(inode).unwrap()
    };
    assert_eq!(read(&vfs), b"first");
    // Same type: the file is opened with O_TRUNC, so an empty body empties it.
    let mut second = newc("init", 0o100_755, 1, 1, b"", (0, 0));
    second.extend(trailer());
    assert_eq!(unpacker.unpack(&mut vfs, &second), None);
    assert_eq!(read(&vfs), b"");
    // Another spelling of the same name lands on the same file.
    let mut third = newc("./init", 0o100_755, 1, 1, b"third", (0, 0));
    third.extend(newc("//dev/./console", 0o100_600, 1, 2, b"", (0, 0)));
    third.extend(trailer());
    assert_eq!(unpacker.unpack(&mut vfs, &third), None);
    assert_eq!(read(&vfs), b"third");
    assert!(
        vfs.fs
            .inode(vfs.lookup(&env, b"/dev/console", 0).unwrap())
            .is_reg()
    );
    // A directory named like the file replaces it (and the reverse).
    let mut fourth = newc("init", 0o040_755, 2, 1, b"", (0, 0));
    fourth.extend(trailer());
    assert_eq!(unpacker.unpack(&mut vfs, &fourth), None);
    let init = vfs.lookup(&env, b"/init", 0).unwrap();
    assert!(vfs.fs.inode(init).is_dir());
    let mut fifth = newc("init", 0o100_755, 1, 1, b"fifth", (0, 0));
    fifth.extend(trailer());
    assert_eq!(unpacker.unpack(&mut vfs, &fifth), None);
    assert_eq!(read(&vfs), b"fifth");
}

#[test]
fn a_symlinked_init_resolves_and_a_name_with_a_missing_parent_is_dropped() {
    let mut archive = Vec::new();
    archive.extend(newc("real", 0o100_755, 1, 1, b"elf", (0, 0)));
    archive.extend(newc("init", 0o120_777, 1, 2, b"real", (0, 0)));
    // `init_mkdir` fails below a missing directory; Linux ignores it and moves on.
    archive.extend(newc("no/such/dir/file", 0o100_600, 1, 3, b"lost", (0, 0)));
    archive.extend(newc("after", 0o100_600, 1, 4, b"kept", (0, 0)));
    archive.extend(trailer());
    let (vfs, env, message) = unpacked(&archive);
    assert_eq!(message, None);
    let init = vfs.lookup(&env, b"/init", LOOKUP_FOLLOW).unwrap();
    assert_eq!(vfs.fs.read_all(init).unwrap(), b"elf");
    assert_eq!(
        vfs.lookup(&env, b"/no/such/dir/file", 0),
        Err(Errno::ENOENT)
    );
    assert!(vfs.lookup(&env, b"/after", 0).is_ok());
}

#[test]
fn chown_that_drops_a_set_id_bit_also_needs_the_mode_change_permission() {
    let (mut vfs, env) = rootfs(1 << 10);
    vfs.mknod(&env, b"/su", S_IFREG | 0o4755, 0).unwrap();
    vfs.mknod(&env, b"/plain", S_IFREG | 0o644, 0).unwrap();
    let su = vfs.lookup(&env, b"/su", 0).unwrap();
    let plain = vfs.lookup(&env, b"/plain", 0).unwrap();
    // CAP_CHOWN without CAP_FOWNER, not the owner: `setattr_prepare` refuses ATTR_MODE.
    let chowner = Env {
        cred: Cred {
            chown: true,
            ..user(1000)
        },
        ..env
    };
    assert_eq!(
        vfs.chown(&chowner, su, u32::MAX, u32::MAX),
        Err(Errno::EPERM)
    );
    assert_eq!(vfs.fs.getattr(su).mode, S_IFREG | 0o4755, "nothing changed");
    assert_eq!(vfs.chown(&chowner, plain, 7, 8), Ok(()));
    let both = Env {
        cred: Cred {
            fowner: true,
            ..chowner.cred
        },
        ..chowner
    };
    assert_eq!(vfs.chown(&both, su, 7, u32::MAX), Ok(()));
    assert_eq!(vfs.fs.getattr(su).mode, S_IFREG | 0o755);
}

#[test]
fn the_descriptor_log_replays_recent_changes_and_reports_a_gap() {
    let mut fds = FdTable::default();
    let seen = fds.generation();
    let a = fds.alloc_fd(0, 1024, false).unwrap();
    fds.install(a, FileId::from_index(1));
    fds.set_cloexec(a, true);
    fds.close(a);
    assert_eq!(
        fds.changed_since(seen).unwrap().collect::<Vec<_>>(),
        [0, 0, 0, 0],
        "alloc, install, FD_CLOEXEC, close"
    );
    // A failed allocation changes nothing.
    let now = fds.generation();
    assert!(fds.alloc_fd(0, 0, false).is_err());
    assert_eq!(fds.generation(), now);
    for fd in 0..40u32 {
        fds.expand(u64::from(fd)).unwrap();
        fds.set_cloexec(fd, true);
    }
    assert!(fds.changed_since(seen).is_none(), "wider than the log");
    let tail = fds.changed_since(fds.generation() - 32).unwrap();
    assert_eq!(tail.collect::<Vec<_>>(), (8..40).collect::<Vec<u32>>());
    assert!(fds.changed_since(fds.generation() + 1).is_none());
}

#[test]
fn statfs_is_per_filesystem_and_follows_the_mount_flags() {
    use super::mountops::MountArgs;
    let (mut vfs, env) = rootfs(1 << 10);
    vfs.mkdir(&env, b"/p", 0o755).unwrap();
    vfs.mkdir(&env, b"/t", 0o755).unwrap();
    let (p, t) = (
        vfs.lookup(&env, b"/p", 0).unwrap(),
        vfs.lookup(&env, b"/t", 0).unwrap(),
    );
    let mut env = env;
    env.cred.sys_admin = true;
    let ms_rdonly = 1;
    let mount = |vfs: &mut Vfs, point, fstype: &[u8], flags, data: Option<&[u8]>| {
        let args = MountArgs {
            source: Some(b"none"),
            point,
            fstype: Some(fstype),
            flags,
            data,
        };
        vfs.do_mount(&env, &args)
            .unwrap_or_else(|_| panic!("mount"));
    };
    mount(&mut vfs, p, b"proc", ms_rdonly, None);
    mount(&mut vfs, t, b"tmpfs", 0, Some(b"size=8k,nr_inodes=5\0"));
    let (root, p, t) = (
        vfs.lookup(&env, b"/", 0).unwrap(),
        vfs.lookup(&env, b"/p", 0).unwrap(),
        vfs.lookup(&env, b"/t", 0).unwrap(),
    );
    // procfs: `simple_statfs` (no counts); the mount adds `ST_RDONLY` and the default `ST_RELATIME`.
    let st = vfs.fs.statfs(p);
    assert_eq!(
        (st.magic, st.blocks, st.files, st.flags),
        (0x9fa0, 0, 0, 0x1021)
    );
    // A size-limited tmpfs: two pages, five inodes of which the root uses one.
    let st = vfs.fs.statfs(t);
    assert_eq!(
        (st.magic, st.blocks, st.bfree, st.files, st.ffree, st.flags),
        (0x0102_1994, 2, 2, 5, 4, 0x1020)
    );
    // The rootfs: the limits it was made with.
    let st = vfs.fs.statfs(root);
    assert_eq!(
        (st.magic, st.blocks, st.files),
        (0x0102_1994, 1024, 1 << 16)
    );
}

/// A tmpfs mounted at `/t` with `flags`, and the environment that mounts it.
fn tmpfs_at_t(flags: u64) -> (Vfs, Env) {
    use super::mountops::MountArgs;
    let (mut vfs, env) = rootfs(1 << 10);
    vfs.mkdir(&env, b"/t", 0o755).unwrap();
    let point = vfs.lookup(&env, b"/t", 0).unwrap();
    let mut env = env;
    env.cred.sys_admin = true;
    let args = MountArgs {
        source: Some(b"none"),
        point,
        fstype: Some(b"tmpfs"),
        flags,
        data: None,
    };
    vfs.do_mount(&env, &args)
        .unwrap_or_else(|_| panic!("mount"));
    (vfs, env)
}

#[test]
fn an_open_file_on_a_detached_mount_keeps_the_flags_of_its_mount() {
    use super::{
        mount::{MNT_DETACH, MS_NOSUID, MS_RDONLY, MS_REMOUNT},
        mountops::MountArgs,
    };
    // include/linux/statfs.h
    const ST_RDONLY: u64 = 1;
    const ST_NOSUID: u64 = 2;
    let (mut vfs, env) = tmpfs_at_t(MS_NOSUID);
    let fd = open(&mut vfs, &env, b"/t/f", O_CREAT | O_RDWR, 0o644).unwrap();
    let file = vfs.files.get(fd).inode.unwrap();
    let point = vfs.lookup(&env, b"/t", 0).unwrap();
    let remount = MountArgs {
        source: None,
        point,
        fstype: Some(b"tmpfs"),
        flags: MS_REMOUNT | MS_NOSUID | MS_RDONLY,
        data: None,
    };
    // The file is open for writing: the superblock cannot go read-only (EBUSY), but the mount
    // flag changes with a bind remount only; drop the write reference first.
    vfs.fput(fd);
    let fd = open(&mut vfs, &env, b"/t/f", O_RDONLY, 0).unwrap();
    vfs.do_mount(&env, &remount)
        .unwrap_or_else(|_| panic!("remount"));
    let st = vfs.fs.statfs(file);
    assert_eq!(st.flags & (ST_NOSUID | ST_RDONLY), ST_NOSUID | ST_RDONLY);
    assert!(vfs.fs.want_write(file).is_err());
    // Detached with the file still open: the mount is gone from the tree, its flags stay.
    let root = vfs.lookup(&env, b"/t", 0).unwrap();
    vfs.do_umount(&env, root, MNT_DETACH).unwrap();
    assert!(vfs.fs.mount_of(file).is_none());
    let st = vfs.fs.statfs(file);
    assert_eq!(st.flags & (ST_NOSUID | ST_RDONLY), ST_NOSUID | ST_RDONLY);
    assert_eq!(vfs.fs.want_write(file), Err(Errno::EROFS));
    // The last close ends it.
    vfs.fput(fd);
    vfs.fs.reap();
}

#[test]
fn truncate_checks_the_permission_before_the_read_only_mount() {
    use super::mount::{MS_BIND, MS_RDONLY, MS_REMOUNT};
    use super::mountops::MountArgs;
    let (mut vfs, env) = tmpfs_at_t(0);
    let no_umask = Env { umask: 0, ..env };
    let readonly = open(&mut vfs, &no_umask, b"/t/ro", O_CREAT | O_RDWR, 0o444).unwrap();
    let writable = open(&mut vfs, &no_umask, b"/t/rw", O_CREAT | O_RDWR, 0o666).unwrap();
    let (ro, rw) = (
        vfs.files.get(readonly).inode.unwrap(),
        vfs.files.get(writable).inode.unwrap(),
    );
    vfs.fput(readonly);
    vfs.fput(writable);
    let point = vfs.lookup(&env, b"/t", 0).unwrap();
    let remount = MountArgs {
        source: None,
        point,
        fstype: Some(b"tmpfs"),
        // A read-only mount over a writable superblock (`mount -o remount,bind,ro`): a read-only
        // superblock would make `inode_permission` itself answer `EROFS`.
        flags: MS_REMOUNT | MS_BIND | MS_RDONLY,
        data: None,
    };
    vfs.do_mount(&env, &remount)
        .unwrap_or_else(|_| panic!("remount"));
    // vfs_truncate: inode_permission first, mnt_want_write after.
    let other = Env {
        cred: user(1000),
        ..env
    };
    assert_eq!(vfs.truncate_check(&other, ro), Err(Errno::EACCES));
    assert_eq!(vfs.truncate_check(&other, rw), Err(Errno::EROFS));
    // The owner of the system (root) passes the permission and meets the mount.
    assert_eq!(vfs.truncate_check(&env, ro), Err(Errno::EROFS));
}

#[test]
fn newsize_ok_checks_the_limit_first_and_then_the_superblock_maximum() {
    use super::ops::{NewSizeRefused, inode_newsize_ok};
    let signal = Err(NewSizeRefused { signal: true });
    let big = Err(NewSizeRefused { signal: false });
    assert_eq!(inode_newsize_ok(0, 10, 100, u64::MAX), Ok(()));
    assert_eq!(inode_newsize_ok(0, 101, 100, u64::MAX), big);
    assert_eq!(inode_newsize_ok(0, 101, 100, 50), signal);
    // The limit is for growth only.
    assert_eq!(inode_newsize_ok(60, 60, 100, 50), Ok(()));
    assert_eq!(inode_newsize_ok(60, 10, 100, 0), Ok(()));
    assert_eq!(inode_newsize_ok(60, 61, 100, 50), signal);
    assert_eq!(inode_newsize_ok(0, 50, 100, 50), Ok(()));
}

#[test]
fn procfs_has_the_non_lfs_maximum_and_keeps_the_times_a_setattr_stamped() {
    use super::{
        MAX_NON_LFS,
        mount::{MNT_DETACH, MS_RDONLY},
        mountops::MountArgs,
    };
    let (mut vfs, env) = rootfs(1 << 10);
    vfs.mkdir(&env, b"/p", 0o755).unwrap();
    let mut env = env;
    env.cred.sys_admin = true;
    let point = vfs.lookup(&env, b"/p", 0).unwrap();
    let args = MountArgs {
        source: Some(b"proc"),
        point,
        fstype: Some(b"proc"),
        flags: 0,
        data: None,
    };
    vfs.do_mount(&env, &args)
        .unwrap_or_else(|_| panic!("mount"));
    let version = vfs.lookup(&env, b"/p/version", 0).unwrap();
    assert!(version.is_proc());
    let edge = MAX_NON_LFS as u64;
    assert_eq!(vfs.newsize_ok(version, edge, u64::MAX), Ok(()));
    assert!(vfs.newsize_ok(version, edge + 1, u64::MAX).is_err());
    let hit = vfs.newsize_ok(version, edge + 1, 10).unwrap_err();
    assert!(hit.signal, "the limit is checked first");
    // A tmpfs file is limited by MAX_LFS_FILESIZE only.
    let file = open(&mut vfs, &env, b"/f", O_CREAT | O_RDWR, 0o644).unwrap();
    let inode = vfs.files.get(file).inode.unwrap();
    assert_eq!(vfs.newsize_ok(inode, edge + 1, u64::MAX), Ok(()));
    // The stamp is the moment of the call, and nothing else changes.
    let before = vfs.getattr(version);
    vfs.proc_touch(version).unwrap();
    let after = vfs.getattr(version);
    assert_eq!((after.mtime, after.ctime), (clock(), clock()));
    assert_eq!((after.size, after.mode), (before.size, before.mode));
    // Another node keeps reporting the time of its getattr.
    let other = vfs.lookup(&env, b"/p/uptime", 0).unwrap();
    assert_eq!(vfs.getattr(other).mtime, vfs.getattr(other).atime);
    // The stamps go with the superblock.
    let _ = (MS_RDONLY, MNT_DETACH);
    let root = vfs.lookup(&env, b"/p", 0).unwrap();
    vfs.do_umount(&env, root, 0).unwrap();
    vfs.fs.reap();
    assert!(vfs.fs.ns.proc.stamp(version).is_none());
}
