// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: mm/shmem.c (GPL-2.0-only:
// `__shmem_get_inode`, `shmem_mknod`, `shmem_mkdir`, `shmem_link`,
// `shmem_unlink`, `shmem_rmdir`, `shmem_symlink`, `shmem_setattr`,
// `shmem_getattr`, `shmem_file_read_iter`, `shmem_reserve_inode`,
// `shmem_inode_acct_blocks`, `BOGO_DIRENT_SIZE`), fs/libfs.c (GPL-2.0:
// `simple_offset_add`, `offset_readdir`, `offset_iterate_dir`,
// `find_positive_dentry`, `DIR_OFFSET_*`), fs/inode.c (`inode_init_owner`),
// fs/attr.c (`setattr_copy` mode handling). Copyright of the originals:
// Linus Torvalds, Hugh Dickins, Christoph Rohland, Al Viro and others as
// stated in those files.
// Transformation: inodes live in an arena; the dentry is the `Child` record in
// the parent's vector (creation order = Linux's `d_children` list, newest
// first when listed); the page cache is a sorted vector of pages; the maple
// tree of directory offsets is the monotonically increasing `offset` field.
#![forbid(unsafe_code)]
//! tmpfs: inode arena, directories, sparse page store and space accounting.
//!
//! No permission checks happen here (the `ops` layer owns them, like
//! `may_create` and `inode_permission` own them in Linux). Every operation
//! either completes or changes nothing observable (the allocation it needs is
//! made first), except that a write reports the bytes stored before an
//! allocation failure as Linux's `generic_perform_write` does.
//!
//! Directory order: `getdents` lists the entry created last first
//! (`d_first_child` / `d_next_sibling` over `hlist_add_head`), the starting
//! point of a seek is the entry with the largest offset not above the cookie
//! (`mas_find_rev`), and the `d_off` of an entry is the offset of the entry
//! listed after it (`DIR_OFFSET_EOD` for the last).

use alloc::vec::Vec;
use syscalls::Errno;

use super::{
    Cred, InodeId, KResult, Kstat, MAX_LFS_FILESIZE, PAGE_SIZE, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG,
    S_ISGID, S_ISUID, S_ISVTX, S_IXGRP, STATX_ATTR_APPEND, STATX_ATTR_AUTOMOUNT, STATX_ATTR_DAX,
    STATX_ATTR_IMMUTABLE, STATX_ATTR_MOUNT_ROOT, STATX_ATTR_NODUMP, Timespec, dtype, try_copy,
    try_push,
};

/// The timestamp of an inode created before timekeeping runs; replaced by
/// [`Tmpfs::start_timekeeping`]. No archive time can equal it (they are `u32`).
pub const UNSET_TIME: Timespec = Timespec {
    sec: i64::MIN,
    nsec: 0,
};

/// `BOGO_DIRENT_SIZE`: what each directory entry adds to the directory's size.
pub const BOGO_DIRENT_SIZE: u64 = 20;
/// `SHORT_SYMLINK_LEN`: longer targets occupy a page.
const SHORT_SYMLINK_LEN: usize = 128;
/// `DIR_OFFSET_FIRST`: the position after `.` and `..`.
pub const DIR_OFFSET_FIRST: i64 = 2;
/// `DIR_OFFSET_EOD`: the position past the last entry.
pub const DIR_OFFSET_EOD: i64 = i32::MAX as i64;
const DIR_OFFSET_MIN: u32 = 3;
const DIR_OFFSET_MAX: u32 = i32::MAX as u32 - 1;

/// One directory entry (a positive tmpfs dentry).
pub struct Child {
    pub name: Vec<u8>,
    pub inode: InodeId,
    /// The `d_fsdata` offset `simple_offset_add` assigned.
    pub offset: u32,
}

pub struct Dir {
    /// Creation order, oldest first (a renamed entry counts as created by the rename).
    pub children: Vec<Child>,
    pub parent: InodeId,
    /// `octx->next_offset`.
    next_offset: u32,
    /// `IS_DEADDIR` (`S_DEAD`, set by `vfs_rmdir`): the directory was removed
    /// but is still pinned by a working directory or an open file.
    dead: bool,
}

impl Dir {
    /// `simple_offset_add`'s `mtree_alloc_cyclic` over
    /// `[DIR_OFFSET_MIN, DIR_OFFSET_MAX]`: the next free offset after the last
    /// one handed out, wrapping.
    ///
    /// # Errors
    /// `ENOSPC` when every offset is in use.
    fn alloc_offset(&mut self) -> KResult<u32> {
        let used = |offset: u32, children: &[Child]| children.iter().any(|c| c.offset == offset);
        let mut offset = self.next_offset;
        let mut tries = 0usize;
        while used(offset, &self.children) || !(DIR_OFFSET_MIN..=DIR_OFFSET_MAX).contains(&offset) {
            offset = if offset >= DIR_OFFSET_MAX {
                DIR_OFFSET_MIN
            } else {
                offset + 1
            };
            tries += 1;
            if tries > self.children.len() + 1 {
                return Err(Errno::ENOSPC);
            }
        }
        self.next_offset = if offset >= DIR_OFFSET_MAX {
            DIR_OFFSET_MIN
        } else {
            offset + 1
        };
        Ok(offset)
    }
}

/// A present page of a regular file.
struct Page {
    index: u64,
    data: Vec<u8>,
}

#[derive(Default)]
pub struct Pages(Vec<Page>);

pub enum Body {
    Reg(Pages),
    Dir(Dir),
    Link(Vec<u8>),
    /// Character and block devices, FIFOs and sockets (`init_special_inode`).
    Special,
}

pub struct Inode {
    pub ino: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub rdev: u32,
    pub size: u64,
    pub atime: Timespec,
    pub mtime: Timespec,
    pub ctime: Timespec,
    pub btime: Timespec,
    /// Holders other than links: open files, working directories and child
    /// directories' `..` (a dentry's reference on its parent).
    refs: u32,
    pub body: Body,
}

impl Inode {
    #[must_use]
    pub fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }
    #[must_use]
    pub fn is_reg(&self) -> bool {
        self.mode & S_IFMT == S_IFREG
    }
    #[must_use]
    pub fn is_symlink(&self) -> bool {
        self.mode & S_IFMT == S_IFLNK
    }
    #[must_use]
    pub fn dir(&self) -> Option<&Dir> {
        match &self.body {
            Body::Dir(dir) => Some(dir),
            _ => None,
        }
    }
    /// `i_blocks` in 512-byte units.
    #[must_use]
    pub fn blocks(&self) -> u64 {
        let pages = match &self.body {
            Body::Reg(pages) => pages.0.len() as u64,
            Body::Link(target) => u64::from(target.len() >= SHORT_SYMLINK_LEN),
            _ => 0,
        };
        pages * (PAGE_SIZE as u64 / 512)
    }
}

/// The superblock, its inode arena and the space accounting of one tmpfs.
pub struct Tmpfs {
    inodes: Vec<Option<Inode>>,
    free: Vec<u32>,
    next_ino: u64,
    used_blocks: u64,
    max_blocks: u64,
    nr_inodes: u64,
    max_inodes: u64,
    root: InodeId,
    clock: fn() -> Timespec,
    /// `sb->s_dev`: an anonymous device (major 0).
    pub dev: u32,
}

/// What `shmem_statfs` reports besides the constants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Statfs {
    pub blocks: u64,
    pub bfree: u64,
    pub files: u64,
    pub ffree: u64,
}

/// The callback of [`Tmpfs::readdir`]: `(name, pos, ino, d_type)`, false when full.
pub type Actor<'a> = dyn FnMut(&[u8], i64, u64, u8) -> bool + 'a;

impl Tmpfs {
    /// # Errors
    /// `ENOMEM` for the root inode.
    pub fn new(max_blocks: u64, max_inodes: u64, clock: fn() -> Timespec) -> KResult<Self> {
        let mut fs = Self {
            inodes: Vec::new(),
            free: Vec::new(),
            next_ino: 2,
            used_blocks: 0,
            max_blocks,
            nr_inodes: 0,
            max_inodes,
            root: InodeId(0),
            clock,
            dev: 2,
        };
        // `shmem_fill_super`: the root is `S_IFDIR | sbinfo->mode` with the
        // default mode 01777 and root ownership.
        let root = fs.alloc(None, S_IFDIR | S_ISVTX | 0o777, 0, &Cred::root())?;
        fs.root = root;
        if let Some(inode) = fs.inodes[root.0 as usize].as_mut()
            && let Body::Dir(dir) = &mut inode.body
        {
            dir.parent = root;
        }
        Ok(fs)
    }

    #[must_use]
    pub fn root(&self) -> InodeId {
        self.root
    }

    #[must_use]
    pub fn now(&self) -> Timespec {
        (self.clock)()
    }

    /// The inode behind a handle.
    ///
    /// # Panics
    /// On a stale handle, which is a kernel bug: handles are only issued here
    /// and stay valid while a reference or a link keeps the inode alive.
    #[must_use]
    pub fn inode(&self, id: InodeId) -> &Inode {
        self.inodes
            .get(id.0 as usize)
            .and_then(Option::as_ref)
            .expect("stale inode handle")
    }

    /// Mutable access to an inode.
    ///
    /// # Panics
    /// On a stale handle (a kernel bug).
    pub fn inode_mut(&mut self, id: InodeId) -> &mut Inode {
        self.inodes
            .get_mut(id.0 as usize)
            .and_then(Option::as_mut)
            .expect("stale inode handle")
    }

    /// The pins on an inode (`i_count` beyond its links): working directories,
    /// roots, open files and mappings. A leak check reads it.
    #[must_use]
    pub fn inode_refs(&self, id: InodeId) -> u32 {
        self.inode(id).refs
    }

    /// Pin an inode beyond its links (`ihold`/`dget`).
    pub fn iget(&mut self, id: InodeId) {
        let inode = self.inode_mut(id);
        inode.refs += 1;
    }

    /// Drop a pin; the last pin of an unlinked inode frees it (`iput` ->
    /// `shmem_evict_inode`: pages and the inode charge are returned).
    pub fn iput(&mut self, id: InodeId) {
        let inode = self.inode_mut(id);
        inode.refs -= 1;
        if inode.refs == 0 && inode.nlink == 0 {
            self.evict(id);
        }
    }

    fn evict(&mut self, id: InodeId) {
        let Some(inode) = self.inodes[id.0 as usize].take() else {
            return;
        };
        if let Body::Reg(pages) = &inode.body {
            self.used_blocks -= pages.0.len() as u64;
        } else if let Body::Link(target) = &inode.body
            && target.len() >= SHORT_SYMLINK_LEN
        {
            self.used_blocks -= 1;
        }
        self.nr_inodes -= 1;
        // The slot was just emptied and `free` only ever grows by evictions,
        // so reserving can fail only under memory pressure; losing the slot
        // then wastes one arena entry, never correctness.
        let _ = try_push(&mut self.free, id.0);
        if let Body::Dir(dir) = inode.body
            && dir.parent != id
        {
            self.iput(dir.parent);
        }
    }

    fn alloc(
        &mut self,
        dir: Option<InodeId>,
        mode: u32,
        rdev: u32,
        cred: &Cred,
    ) -> KResult<InodeId> {
        // shmem_reserve_inode
        if self.max_inodes != 0 && self.nr_inodes >= self.max_inodes {
            return Err(Errno::ENOSPC);
        }
        let now = self.now();
        // inode_init_owner
        let (mut mode, mut gid) = (mode, cred.fsgid);
        if let Some(dir) = dir {
            let parent = self.inode(dir);
            if parent.mode & S_ISGID != 0 {
                gid = parent.gid;
                if mode & S_IFMT == S_IFDIR {
                    mode |= S_ISGID;
                }
            }
        }
        if mode & S_IFMT != S_IFDIR
            && mode & (S_ISGID | S_IXGRP) == (S_ISGID | S_IXGRP)
            && cred.fsgid != gid
            && !cred.fsetid
        {
            mode &= !S_ISGID;
        }
        let (body, nlink, size) = match mode & S_IFMT {
            S_IFREG => (Body::Reg(Pages::default()), 1, 0),
            S_IFDIR => (
                Body::Dir(Dir {
                    children: Vec::new(),
                    parent: dir.unwrap_or(InodeId(0)),
                    next_offset: DIR_OFFSET_MIN,
                    dead: false,
                }),
                2,
                2 * BOGO_DIRENT_SIZE,
            ),
            S_IFLNK => (Body::Link(Vec::new()), 1, 0),
            _ => (Body::Special, 1, 0),
        };
        let inode = Inode {
            ino: self.next_ino,
            mode,
            uid: cred.fsuid,
            gid,
            nlink,
            rdev: if matches!(mode & S_IFMT, super::S_IFCHR | super::S_IFBLK) {
                rdev
            } else {
                0
            },
            size,
            atime: now,
            mtime: now,
            ctime: now,
            btime: now,
            refs: 0,
            body,
        };
        let slot = if let Some(slot) = self.free.pop() {
            self.inodes[slot as usize] = Some(inode);
            slot
        } else {
            self.inodes.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
            let slot = u32::try_from(self.inodes.len()).map_err(|_| Errno::ENOSPC)?;
            if self.inodes.push_within_capacity(Some(inode)).is_err() {
                return Err(Errno::ENOMEM);
            }
            slot
        };
        self.next_ino += 1;
        self.nr_inodes += 1;
        let id = InodeId(slot);
        if let Some(dir) = dir
            && mode & S_IFMT == S_IFDIR
        {
            // A directory's dentry references its parent for as long as it exists.
            self.iget(dir);
        }
        Ok(id)
    }

    /// The child `name` of `dir`, if the entry exists.
    #[must_use]
    pub fn lookup(&self, dir: InodeId, name: &[u8]) -> Option<InodeId> {
        self.inode(dir)
            .dir()?
            .children
            .iter()
            .find(|child| child.name == name)
            .map(|child| child.inode)
    }

    /// `d_parent` of a directory (the root is its own parent).
    #[must_use]
    pub fn parent(&self, dir: InodeId) -> InodeId {
        self.inode(dir).dir().map_or(dir, |dir| dir.parent)
    }

    /// `IS_DEADDIR`: `dir` was removed by `rmdir` and can no longer be
    /// searched, listed or given entries (`ENOENT`).
    #[must_use]
    pub fn is_dead(&self, dir: InodeId) -> bool {
        self.inode(dir).dir().is_some_and(|dir| dir.dead)
    }

    /// The name under which `child` is linked in `dir`.
    #[must_use]
    pub fn name_of(&self, dir: InodeId, child: InodeId) -> Option<&[u8]> {
        self.inode(dir)
            .dir()?
            .children
            .iter()
            .find(|entry| entry.inode == child)
            .map(|entry| entry.name.as_slice())
    }

    /// Add the entry (`simple_offset_add` + the directory bookkeeping every
    /// `shmem_*` creator repeats). The caller owns the new inode and frees it
    /// on error.
    fn add_entry(&mut self, dir: InodeId, name: &[u8], inode: InodeId) -> KResult<()> {
        let name = try_copy(name)?;
        let now = self.now();
        let parent = self.inode_mut(dir);
        let Body::Dir(d) = &mut parent.body else {
            return Err(Errno::ENOTDIR);
        };
        d.children.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
        let offset = d.alloc_offset()?;
        if d.children
            .push_within_capacity(Child {
                name,
                inode,
                offset,
            })
            .is_err()
        {
            return Err(Errno::ENOMEM);
        }
        parent.size += BOGO_DIRENT_SIZE;
        parent.mtime = now;
        parent.ctime = now;
        Ok(())
    }

    /// `shmem_mknod` / `shmem_mkdir` / `shmem_create`: a new inode of the type
    /// in `mode` named `name` in `dir`. `mode` already has the umask applied.
    ///
    /// # Errors
    /// `ENOSPC` (inode limit), `ENOMEM`.
    pub fn mknod(
        &mut self,
        dir: InodeId,
        name: &[u8],
        mode: u32,
        rdev: u32,
        cred: &Cred,
    ) -> KResult<InodeId> {
        let id = self.alloc(Some(dir), mode, rdev, cred)?;
        if let Err(error) = self.add_entry(dir, name, id) {
            self.discard(id);
            return Err(error);
        }
        if mode & S_IFMT == S_IFDIR {
            self.inode_mut(dir).nlink += 1;
        }
        Ok(id)
    }

    /// `shmem_tmpfile`: an inode with no name (`nlink` 0) that the caller pins
    /// through an open file. Freed by [`Tmpfs::drop_unlinked`] if that fails.
    ///
    /// # Errors
    /// `ENOSPC`, `ENOMEM`.
    pub fn mknod_unlinked(&mut self, mode: u32, cred: &Cred) -> KResult<InodeId> {
        let id = self.alloc(None, mode, 0, cred)?;
        self.inode_mut(id).nlink = 0;
        Ok(id)
    }

    /// Free an unnamed inode nobody pinned.
    pub fn drop_unlinked(&mut self, id: InodeId) {
        if self.inode(id).refs == 0 && self.inode(id).nlink == 0 {
            self.evict(id);
        }
    }

    /// An inode that never got linked: free it as `iput` of a fresh inode does.
    fn discard(&mut self, id: InodeId) {
        let inode = self.inode_mut(id);
        inode.nlink = 0;
        if inode.refs == 0 {
            self.evict(id);
        }
    }

    /// `shmem_symlink`.
    ///
    /// # Errors
    /// `ENAMETOOLONG` when the target and its NUL do not fit a page.
    pub fn symlink(
        &mut self,
        dir: InodeId,
        name: &[u8],
        target: &[u8],
        cred: &Cred,
    ) -> KResult<InodeId> {
        if target.len() + 1 > PAGE_SIZE {
            return Err(Errno::ENAMETOOLONG);
        }
        let copy = try_copy(target)?;
        let long = target.len() + 1 > SHORT_SYMLINK_LEN;
        if long && self.used_blocks >= self.max_blocks && self.max_blocks != 0 {
            return Err(Errno::ENOSPC);
        }
        let id = self.alloc(Some(dir), S_IFLNK | 0o777, 0, cred)?;
        if let Err(error) = self.add_entry(dir, name, id) {
            self.discard(id);
            return Err(error);
        }
        if long {
            self.used_blocks += 1;
        }
        let inode = self.inode_mut(id);
        inode.size = target.len() as u64;
        inode.body = Body::Link(copy);
        Ok(id)
    }

    /// `shmem_link` (permission checks are `vfs_link`'s).
    ///
    /// # Errors
    /// `ENOSPC` (inode limit), `ENOMEM`.
    pub fn link(&mut self, old: InodeId, dir: InodeId, name: &[u8]) -> KResult<()> {
        // Each extra name pins a dentry: it is charged as an inode, except the
        // first name of an `O_TMPFILE` file (`inode->i_nlink` is zero).
        let charged = self.inode(old).nlink != 0;
        if charged {
            if self.max_inodes != 0 && self.nr_inodes >= self.max_inodes {
                return Err(Errno::ENOSPC);
            }
            self.nr_inodes += 1;
        }
        if let Err(error) = self.add_entry(dir, name, old) {
            if charged {
                self.nr_inodes -= 1;
            }
            return Err(error);
        }
        let now = self.now();
        let inode = self.inode_mut(old);
        inode.nlink += 1;
        inode.ctime = now;
        let parent = self.inode_mut(dir);
        parent.mtime = now;
        parent.ctime = now;
        Ok(())
    }

    /// Remove the entry `name` (`shmem_unlink`; `shmem_rmdir` additionally
    /// drops both directory link counts). The inode survives while pinned.
    ///
    /// # Errors
    /// `ENOENT` if there is no such entry, `ENOTEMPTY` for a non-empty `rmdir`.
    /// A removed directory is marked dead (`vfs_rmdir`: `S_DEAD`).
    pub fn unlink(&mut self, dir: InodeId, name: &[u8], rmdir: bool) -> KResult<()> {
        let Some(Body::Dir(d)) = self.inodes[dir.0 as usize].as_ref().map(|i| &i.body) else {
            return Err(Errno::ENOTDIR);
        };
        let at = d
            .children
            .iter()
            .position(|child| child.name == name)
            .ok_or(Errno::ENOENT)?;
        let victim = d.children[at].inode;
        if rmdir
            && self
                .inode(victim)
                .dir()
                .is_some_and(|d| !d.children.is_empty())
        {
            return Err(Errno::ENOTEMPTY);
        }
        let now = self.now();
        // shmem_unlink: the extra names of a file were charged as inodes.
        if !rmdir && self.inode(victim).nlink > 1 && !self.inode(victim).is_dir() {
            self.nr_inodes -= 1;
        }
        let parent = self.inode_mut(dir);
        if let Body::Dir(d) = &mut parent.body {
            d.children.remove(at);
        }
        parent.size -= BOGO_DIRENT_SIZE;
        parent.mtime = now;
        parent.ctime = now;
        if rmdir {
            parent.nlink -= 1;
            let removed = self.inode_mut(victim);
            removed.nlink -= 1;
            if let Body::Dir(d) = &mut removed.body {
                d.dead = true;
            }
        }
        let inode = self.inode_mut(victim);
        inode.nlink -= 1;
        inode.ctime = now;
        if inode.nlink == 0 && inode.refs == 0 {
            self.evict(victim);
        }
        Ok(())
    }

    /// `shmem_rename2` for a plain rename (no `RENAME_EXCHANGE`/`RENAME_WHITEOUT`;
    /// `RENAME_NOREPLACE` was decided by the lookup): move the entry `old_name` of
    /// `old_dir` to `new_name` of `new_dir`, replacing the entry already there.
    /// The moved entry keeps the directory offset of the entry it replaces
    /// (`simple_offset_rename`: user space expects it unchanged), else takes a
    /// fresh offset of `new_dir`; it becomes the newest entry of `new_dir`
    /// (`d_move`). A replaced inode loses a link (`shmem_unlink`); a replaced
    /// directory is marked dead (`vfs_rename`: `S_DEAD`). All allocations are
    /// made before anything changes.
    ///
    /// # Errors
    /// `ENOENT` (no such source), `ENOTEMPTY` (a non-empty target directory),
    /// `ENOSPC`, `ENOMEM`.
    pub fn rename(
        &mut self,
        old_dir: InodeId,
        old_name: &[u8],
        new_dir: InodeId,
        new_name: &[u8],
    ) -> KResult<()> {
        let find = |fs: &Self, dir: InodeId, name: &[u8]| {
            fs.inode(dir)
                .dir()
                .and_then(|d| d.children.iter().position(|c| c.name == name))
        };
        let src_at = find(self, old_dir, old_name).ok_or(Errno::ENOENT)?;
        let src = self.inode(old_dir).dir().ok_or(Errno::ENOTDIR)?.children[src_at].inode;
        let they_are_dirs = self.inode(src).is_dir();
        let target = find(self, new_dir, new_name).map(|at| {
            let child = &self.inode(new_dir).dir().map_or(&[][..], |d| &d.children)[at];
            (child.inode, child.offset)
        });
        // simple_empty(new_dentry)
        if let Some((victim, _)) = target
            && self
                .inode(victim)
                .dir()
                .is_some_and(|d| !d.children.is_empty())
        {
            return Err(Errno::ENOTEMPTY);
        }
        // Everything that can fail: the name, the room, the offset.
        let name = try_copy(new_name)?;
        let Body::Dir(nd) = &mut self.inode_mut(new_dir).body else {
            return Err(Errno::ENOTDIR);
        };
        nd.children.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
        let offset = match target {
            Some((_, offset)) => offset,
            None => nd.alloc_offset()?,
        };
        // From here on nothing fails.
        let now = self.now();
        if let Body::Dir(od) = &mut self.inode_mut(old_dir).body {
            od.children.remove(src_at);
        }
        if let Some((victim, _)) = target {
            // shmem_unlink(new_dir, new_dentry)
            let victim_is_dir = self.inode(victim).is_dir();
            if self.inode(victim).nlink > 1 && !victim_is_dir {
                self.nr_inodes -= 1;
            }
            let at = find(self, new_dir, new_name).unwrap_or(0);
            let nd = self.inode_mut(new_dir);
            if let Body::Dir(d) = &mut nd.body {
                d.children.remove(at);
            }
            nd.size -= BOGO_DIRENT_SIZE;
            nd.mtime = now;
            nd.ctime = now;
            let gone = self.inode_mut(victim);
            gone.nlink -= 1;
            gone.ctime = now;
            if they_are_dirs {
                gone.nlink -= 1;
                if let Body::Dir(d) = &mut gone.body {
                    d.dead = true;
                }
                self.inode_mut(old_dir).nlink -= 1;
            }
        } else if they_are_dirs {
            self.inode_mut(old_dir).nlink -= 1;
            self.inode_mut(new_dir).nlink += 1;
        }
        let od = self.inode_mut(old_dir);
        od.size -= BOGO_DIRENT_SIZE;
        od.mtime = now;
        od.ctime = now;
        let nd = self.inode_mut(new_dir);
        nd.size += BOGO_DIRENT_SIZE;
        nd.mtime = now;
        nd.ctime = now;
        if let Body::Dir(d) = &mut nd.body {
            // Room was reserved above and the replaced entry only freed some.
            let _ = d.children.push_within_capacity(Child {
                name,
                inode: src,
                offset,
            });
        }
        self.inode_mut(src).ctime = now;
        if they_are_dirs && old_dir != new_dir {
            // The dentry's reference on its parent moves with it.
            if let Body::Dir(d) = &mut self.inode_mut(src).body {
                d.parent = new_dir;
            }
            self.iget(new_dir);
            self.iput(old_dir);
        }
        if let Some((victim, _)) = target
            && self.inode(victim).nlink == 0
            && self.inode(victim).refs == 0
        {
            self.evict(victim);
        }
        Ok(())
    }

    // ---- attributes --------------------------------------------------------

    /// `chmod_common`'s `ia_mode` plus `setattr_copy`: the permission, set-id
    /// and sticky bits are replaced; `S_ISGID` goes unless the caller is in the
    /// file's group or has `CAP_FSETID`.
    pub fn set_mode(&mut self, id: InodeId, mode: u32, cred: &Cred) {
        let now = self.now();
        let inode = self.inode_mut(id);
        let mut mode = mode & super::S_IALLUGO;
        if cred.fsgid != inode.gid && !cred.fsetid {
            mode &= !S_ISGID;
        }
        inode.mode = mode | (inode.mode & !super::S_IALLUGO);
        inode.ctime = now;
    }

    /// `chown_common`'s `notify_change`: `u32::MAX` leaves the id alone. A
    /// non-directory loses `S_ISUID` (`ATTR_KILL_SUID`) and `S_ISGID` when
    /// `setattr_should_drop_sgid` says so (group-execute set, or the caller is
    /// neither in the file's group nor has `CAP_FSETID`), judged before the
    /// change; `setattr_copy` then drops `S_ISGID` of a changed mode again unless
    /// the caller is in the file's new group or has `CAP_FSETID`.
    pub fn set_owner(&mut self, id: InodeId, uid: u32, gid: u32, cred: &Cred) {
        let now = self.now();
        let inode = self.inode_mut(id);
        let in_group_or_capable = |inode: &Inode| cred.fsgid == inode.gid || cred.fsetid;
        let is_dir = inode.mode & S_IFMT == S_IFDIR;
        let kill_user_id = !is_dir && inode.mode & S_ISUID != 0;
        let kill_group_id = !is_dir
            && inode.mode & S_ISGID != 0
            && (inode.mode & S_IXGRP != 0 || !in_group_or_capable(inode));
        if uid != u32::MAX {
            inode.uid = uid;
        }
        if gid != u32::MAX {
            inode.gid = gid;
        }
        if kill_user_id || kill_group_id {
            if kill_user_id {
                inode.mode &= !S_ISUID;
            }
            if kill_group_id {
                inode.mode &= !S_ISGID;
            }
            if !in_group_or_capable(inode) {
                inode.mode &= !S_ISGID;
            }
        }
        inode.ctime = now;
    }

    /// `vfs_utimes`/`do_utime`: set both times.
    pub fn set_times(&mut self, id: InodeId, atime: Timespec, mtime: Timespec) {
        let now = self.now();
        let inode = self.inode_mut(id);
        inode.atime = atime;
        inode.mtime = mtime;
        inode.ctime = now;
    }

    /// `generic_fillattr` + `shmem_getattr` + the `vfs_statx_path` mount-root
    /// attribute.
    #[must_use]
    pub fn getattr(&self, id: InodeId) -> Kstat {
        let inode = self.inode(id);
        Kstat {
            dev: super::mkdev(0, self.dev),
            ino: inode.ino,
            mode: inode.mode,
            nlink: inode.nlink,
            uid: inode.uid,
            gid: inode.gid,
            rdev: inode.rdev,
            size: i64::try_from(inode.size).unwrap_or(i64::MAX),
            blksize: PAGE_SIZE as u32,
            blocks: inode.blocks(),
            atime: inode.atime,
            mtime: inode.mtime,
            ctime: inode.ctime,
            btime: inode.btime,
            attributes: if id == self.root {
                STATX_ATTR_MOUNT_ROOT
            } else {
                0
            },
            // AUTOMOUNT | DAX (vfs_getattr_nosec), APPEND | IMMUTABLE | NODUMP
            // (shmem_getattr), MOUNT_ROOT (vfs_statx_path).
            attributes_mask: STATX_ATTR_AUTOMOUNT
                | STATX_ATTR_DAX
                | STATX_ATTR_APPEND
                | STATX_ATTR_IMMUTABLE
                | STATX_ATTR_NODUMP
                | STATX_ATTR_MOUNT_ROOT,
        }
    }

    // ---- regular file data -------------------------------------------------

    fn pages(&self, id: InodeId) -> &Pages {
        match &self.inode(id).body {
            Body::Reg(pages) => pages,
            _ => panic!("page access on a non-regular inode"),
        }
    }

    /// Copy file bytes starting at `pos` into `buf`; holes read as zero.
    /// Returns the bytes produced: zero at or past `i_size`.
    #[must_use]
    pub fn read(&self, id: InodeId, pos: u64, buf: &mut [u8]) -> usize {
        let size = self.inode(id).size;
        if pos >= size {
            return 0;
        }
        let count = (buf.len() as u64).min(size - pos) as usize;
        let pages = self.pages(id);
        let mut done = 0;
        while done < count {
            let at = pos + done as u64;
            let (index, offset) = (at / PAGE_SIZE as u64, (at % PAGE_SIZE as u64) as usize);
            let chunk = (PAGE_SIZE - offset).min(count - done);
            match pages.0.binary_search_by_key(&index, |page| page.index) {
                Ok(found) => {
                    buf[done..done + chunk]
                        .copy_from_slice(&pages.0[found].data[offset..offset + chunk]);
                }
                Err(_) => buf[done..done + chunk].fill(0),
            }
            done += chunk;
        }
        count
    }

    /// Store `data` at `pos`, allocating pages as `shmem_get_folio(SGP_WRITE)`
    /// does. Returns the bytes stored (a prefix if space or memory ran out
    /// after some progress); `i_size` grows to cover them.
    ///
    /// # Errors
    /// `ENOSPC` past the block limit, `ENOMEM`, and only when nothing was stored.
    ///
    /// The timestamps are the caller's (`file_update_time` runs before the
    /// copy, so a write that stores nothing still updates them): see
    /// [`Tmpfs::touch`].
    pub fn write(&mut self, id: InodeId, pos: u64, data: &[u8]) -> KResult<usize> {
        let mut done = 0;
        let mut failure = None;
        while done < data.len() {
            let at = pos + done as u64;
            let (index, offset) = (at / PAGE_SIZE as u64, (at % PAGE_SIZE as u64) as usize);
            let chunk = (PAGE_SIZE - offset).min(data.len() - done);
            if let Err(error) = self.store(id, index, offset, &data[done..done + chunk]) {
                failure = Some(error);
                break;
            }
            done += chunk;
            let end = pos + done as u64;
            let inode = self.inode_mut(id);
            if end > inode.size {
                inode.size = end;
            }
        }
        match failure {
            Some(error) if done == 0 => Err(error),
            _ => Ok(done),
        }
    }

    fn store(&mut self, id: InodeId, index: u64, offset: usize, data: &[u8]) -> KResult<()> {
        let existing = self
            .pages(id)
            .0
            .binary_search_by_key(&index, |page| page.index);
        let at = match existing {
            Ok(at) => at,
            Err(at) => {
                if self.max_blocks != 0 && self.used_blocks >= self.max_blocks {
                    return Err(Errno::ENOSPC);
                }
                let mut page = Vec::new();
                page.try_reserve_exact(PAGE_SIZE)
                    .map_err(|_| Errno::ENOMEM)?;
                for _ in 0..PAGE_SIZE {
                    page.push_within_capacity(0).map_err(|_| Errno::ENOMEM)?;
                }
                let Body::Reg(pages) = &mut self.inode_mut(id).body else {
                    return Err(Errno::EINVAL);
                };
                pages.0.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
                if pages
                    .0
                    .push_within_capacity(Page { index, data: page })
                    .is_err()
                {
                    return Err(Errno::ENOMEM);
                }
                pages.0[at..].rotate_right(1);
                self.used_blocks += 1;
                at
            }
        };
        let Body::Reg(pages) = &mut self.inode_mut(id).body else {
            return Err(Errno::EINVAL);
        };
        pages.0[at].data[offset..offset + data.len()].copy_from_slice(data);
        Ok(())
    }

    /// `file_update_time`: `mtime` and `ctime` become the current time.
    pub fn touch(&mut self, id: InodeId) {
        let now = self.now();
        let inode = self.inode_mut(id);
        inode.mtime = now;
        inode.ctime = now;
    }

    /// `touch_atime` on a mount without `MNT_RELATIME` (the rootfs: `init_mount_tree`
    /// passes no flags): `atime` becomes the current time on every access.
    pub fn touch_atime(&mut self, id: InodeId) {
        let now = self.now();
        self.inode_mut(id).atime = now;
    }

    /// `shmem_setattr` with `ATTR_SIZE` (`truncate_setsize` +
    /// `shmem_truncate_range`): shrinking frees the pages past the new end and
    /// zeroes the tail of the last one; growing allocates nothing.
    pub fn set_size(&mut self, id: InodeId, size: u64) {
        let now = self.now();
        if size < self.inode(id).size {
            let keep = size.div_ceil(PAGE_SIZE as u64);
            let tail = (size % PAGE_SIZE as u64) as usize;
            let Body::Reg(pages) = &mut self.inode_mut(id).body else {
                return;
            };
            let before = pages.0.len();
            pages
                .0
                .truncate(pages.0.partition_point(|page| page.index < keep));
            if tail != 0
                && let Some(last) = pages.0.last_mut()
                && last.index == keep - 1
            {
                last.data[tail..].fill(0);
            }
            let freed = (before - pages.0.len()) as u64;
            self.used_blocks -= freed;
        }
        let inode = self.inode_mut(id);
        inode.size = size;
        inode.mtime = now;
        inode.ctime = now;
    }

    /// `shmem_statfs`: the block and inode counts (`f_blocks`, `f_bfree` = `f_bavail`,
    /// `f_files`, `f_ffree`; all zero for an unlimited size or inode count).
    #[must_use]
    pub fn statfs(&self) -> Statfs {
        let (blocks, bfree) = if self.max_blocks != 0 {
            (self.max_blocks, self.max_blocks - self.used_blocks)
        } else {
            (0, 0)
        };
        let (files, ffree) = if self.max_inodes != 0 {
            (
                self.max_inodes,
                self.max_inodes.saturating_sub(self.nr_inodes),
            )
        } else {
            (0, 0)
        };
        Statfs {
            blocks,
            bfree,
            files,
            ffree,
        }
    }

    /// `mapping_seek_hole_data` over the present pages (`SEEK_DATA` /
    /// `SEEK_HOLE`); `None` is `-ENXIO`.
    #[must_use]
    pub fn seek_hole_data(&self, id: InodeId, start: u64, data: bool) -> Option<u64> {
        let size = self.inode(id).size;
        if start >= size {
            return None;
        }
        let pages = self.pages(id);
        let present = |index: u64| pages.0.binary_search_by_key(&index, |p| p.index).is_ok();
        let mut at = start;
        loop {
            let index = at / PAGE_SIZE as u64;
            if present(index) == data {
                return Some(at);
            }
            at = (index + 1) * PAGE_SIZE as u64;
            if at >= size {
                return if data { None } else { Some(size) };
            }
        }
    }

    /// Timekeeping is up: stamp every placeholder timestamp with `now` and take
    /// later timestamps from `clock`.
    pub fn start_timekeeping(&mut self, clock: fn() -> Timespec, now: Timespec) {
        self.clock = clock;
        for inode in self.inodes.iter_mut().flatten() {
            for time in [
                &mut inode.atime,
                &mut inode.mtime,
                &mut inode.ctime,
                &mut inode.btime,
            ] {
                if *time == UNSET_TIME {
                    *time = now;
                }
            }
        }
    }

    /// The whole content of a regular file, for `kernel_read` of an executable.
    ///
    /// # Errors
    /// `ENOMEM`.
    pub fn read_all(&self, id: InodeId) -> KResult<Vec<u8>> {
        let size = usize::try_from(self.inode(id).size).map_err(|_| Errno::ENOMEM)?;
        let mut out = Vec::new();
        out.try_reserve_exact(size).map_err(|_| Errno::ENOMEM)?;
        let mut bounce = [0u8; PAGE_SIZE];
        let mut pos = 0u64;
        while (pos as usize) < size {
            let n = self.read(id, pos, &mut bounce);
            if n == 0 {
                break;
            }
            for &byte in &bounce[..n] {
                out.push_within_capacity(byte).map_err(|_| Errno::ENOMEM)?;
            }
            pos += n as u64;
        }
        Ok(out)
    }

    /// Space charged against the superblock, in pages (tests, `statfs`).
    #[must_use]
    pub fn used_blocks(&self) -> u64 {
        self.used_blocks
    }

    /// Live inodes (tests).
    #[must_use]
    pub fn inode_count(&self) -> u64 {
        self.nr_inodes
    }

    // ---- directories -------------------------------------------------------

    /// `offset_readdir` (with `dir_emit_dots`): call `actor(name, pos, ino,
    /// d_type)` for each entry from `*pos`, newest entry first. `pos` is the
    /// `ctx->pos` the entry is emitted at; the actor returns false when its
    /// buffer is full (the position then stays at that entry).
    pub fn readdir(&self, dir: InodeId, pos: &mut i64, actor: &mut Actor<'_>) {
        let inode = self.inode(dir);
        let Some(d) = inode.dir() else { return };
        if *pos == 0 {
            if !actor(b".", *pos, inode.ino, dtype(S_IFDIR)) {
                return;
            }
            *pos = 1;
        }
        if *pos == 1 {
            let parent = self.inode(d.parent).ino;
            if !actor(b"..", *pos, parent, dtype(S_IFDIR)) {
                return;
            }
            *pos = DIR_OFFSET_FIRST;
        }
        if *pos == DIR_OFFSET_EOD {
            return;
        }
        // offset_dir_lookup: from the first entry, or from the entry with the
        // largest offset not above the cookie (all entries when none is).
        let start = if *pos == DIR_OFFSET_FIRST {
            d.children.len()
        } else {
            d.children
                .iter()
                .enumerate()
                .filter(|(_, child)| i64::from(child.offset) <= *pos)
                .max_by_key(|(_, child)| child.offset)
                .map_or(d.children.len(), |(at, _)| at + 1)
        };
        for child in d.children[..start].iter().rev() {
            *pos = i64::from(child.offset);
            let target = self.inode(child.inode);
            if !actor(&child.name, *pos, target.ino, dtype(target.mode)) {
                return;
            }
        }
        *pos = DIR_OFFSET_EOD;
    }

    /// Cap on a write's end (`MAX_LFS_FILESIZE`).
    #[must_use]
    pub fn max_file_size() -> i64 {
        MAX_LFS_FILESIZE
    }
}
