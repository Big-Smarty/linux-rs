// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: fs/namei.c (GPL-2.0:
// `link_path_walk`, `walk_component`, `step_into`, `pick_link`,
// `reserve_stack` (MAXSYMLINKS), `handle_dots`, `lookup_last`, `path_init`,
// `path_lookupat`, `path_parentat`, `generic_permission`,
// `acl_permission_check`, `may_lookup`, `complete_walk`'s `LOOKUP_DIRECTORY`
// check), fs/libfs.c (`simple_lookup`: `-ENAMETOOLONG` beyond `NAME_MAX`).
// Copyright of the original: Linus Torvalds and the VFS authors (Al Viro).
// Transformation: ref-walk only; one filesystem, no mounts, no automount, no
// LSM and no RCU-walk; symlink bodies are borrowed from the tmpfs arena so the
// walk allocates nothing. `protected_symlinks` is off (the sysctl default).
#![forbid(unsafe_code)]
//! Pathname resolution with Linux's component rules and error precedence.
//!
//! Order of checks per component (`link_path_walk`): search permission on the
//! directory (`may_lookup`), then the lookup (`ENOENT`; `ENAMETOOLONG` when the
//! name is absent and longer than `NAME_MAX`), then symlink following (`ELOOP`
//! at the 41st link), then `ENOTDIR` when a non-final component is not a
//! directory. The final component is resolved by [`lookup`] (`lookup_last`)
//! or handed back by [`parent_of`] for creation and removal.

use alloc::vec::Vec;
use syscalls::Errno;

use super::{
    Cred, InodeId, KResult, MAXSYMLINKS, MAY_EXEC, MAY_READ, MAY_WRITE, NAME_MAX, S_IFDIR, S_IFMT,
    S_IXUGO,
    ops::Env,
    tmpfs::{Body, Inode, Tmpfs},
};

/// `LOOKUP_FOLLOW`: resolve a symlink in the final component.
pub const LOOKUP_FOLLOW: u32 = 1;
/// `LOOKUP_DIRECTORY`: the result must be a directory.
pub const LOOKUP_DIRECTORY: u32 = 2;

/// `nd->last_type`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LastKind {
    /// `LAST_ROOT`: no component (`""`, `"/"`).
    Root,
    Norm,
    Dot,
    DotDot,
}

/// The final component of a path and what followed it.
#[derive(Clone, Copy, Debug)]
pub struct Last<'p> {
    pub name: &'p [u8],
    pub kind: LastKind,
    /// `nd->last.name[nd->last.len]`: the name is followed by `/`.
    pub trailing_slash: bool,
}

/// `inode_permission` + `generic_permission` for the VFS-internal checks.
///
/// # Errors
/// `EACCES`.
pub fn permission(inode: &Inode, cred: &Cred, mask: u32) -> KResult<()> {
    let mode = inode.mode;
    // acl_permission_check
    let bits = mask & 7;
    if (bits * 0o111) & !mode == 0 {
        return Ok(());
    }
    let denied = if inode.uid == cred.fsuid {
        bits & !(mode >> 6) != 0
    } else {
        let mut shifted = mode;
        if bits & (mode ^ (mode >> 3)) != 0 && inode.gid == cred.fsgid {
            shifted >>= 3;
        }
        bits & !shifted != 0
    };
    if !denied {
        return Ok(());
    }
    // generic_permission: capability overrides.
    if inode.mode & S_IFMT == S_IFDIR {
        if mask & MAY_WRITE == 0 && cred.dac_read_search {
            return Ok(());
        }
        return if cred.dac_override {
            Ok(())
        } else {
            Err(Errno::EACCES)
        };
    }
    let rwx = mask & (MAY_READ | MAY_WRITE | MAY_EXEC);
    if rwx == MAY_READ && cred.dac_read_search {
        return Ok(());
    }
    if (rwx & MAY_EXEC == 0 || inode.mode & S_IXUGO != 0) && cred.dac_override {
        return Ok(());
    }
    Err(Errno::EACCES)
}

/// One pathname walk (`struct nameidata`): the directory reached so far, the
/// symlinks followed and whether a final symlink is followed.
pub(crate) struct Walk<'a> {
    pub(crate) fs: &'a Tmpfs,
    env: &'a Env,
    pub(crate) cur: InodeId,
    /// `nd->total_link_count`.
    links: u32,
    /// `LOOKUP_FOLLOW` of the final component.
    pub(crate) follow: bool,
}

pub(crate) const WALK_TRAILING: u32 = 1;
const WALK_MORE: u32 = 2;

fn skip_slashes(mut name: &[u8]) -> &[u8] {
    while let [b'/', rest @ ..] = name {
        name = rest;
    }
    name
}

impl<'a> Walk<'a> {
    /// `path_init`.
    pub(crate) fn new(fs: &'a Tmpfs, env: &'a Env, path: &[u8], follow: bool) -> KResult<Self> {
        Ok(Self {
            fs,
            env,
            cur: init(fs, env, path)?,
            links: 0,
            follow,
        })
    }

    pub(crate) fn is_dir(&self, id: InodeId) -> bool {
        self.fs.inode(id).is_dir()
    }

    /// `may_lookup`: search permission on the directory being walked.
    fn may_lookup(&self) -> KResult<()> {
        permission(self.fs.inode(self.cur), &self.env.cred, MAY_EXEC)
    }

    /// `handle_dots`: `..` stays at the process root (`follow_dotdot`).
    fn dotdot(&mut self) {
        if self.cur != self.env.root {
            self.cur = self.fs.parent(self.cur);
        }
    }

    /// `pick_link`: the body to walk next, or `None` for a pure jump.
    fn pick_link(&mut self, link: InodeId) -> KResult<Option<&'a [u8]>> {
        // reserve_stack: `total_link_count++ >= MAXSYMLINKS`
        let count = self.links;
        self.links += 1;
        if count >= MAXSYMLINKS {
            return Err(Errno::ELOOP);
        }
        let Body::Link(body) = &self.fs.inode(link).body else {
            return Err(Errno::EINVAL);
        };
        let mut body: &'a [u8] = body;
        if body.first() == Some(&b'/') {
            self.cur = self.env.root; // nd_jump_root
            body = skip_slashes(body);
        }
        Ok((!body.is_empty()).then_some(body))
    }

    /// `walk_component` (+ `step_into`).
    pub(crate) fn walk_component(
        &mut self,
        last: &Last<'_>,
        flags: u32,
    ) -> KResult<Option<&'a [u8]>> {
        match last.kind {
            LastKind::Root | LastKind::Dot => return Ok(None),
            LastKind::DotDot => {
                self.dotdot();
                return Ok(None);
            }
            LastKind::Norm => {}
        }
        let Some(child) = self.fs.lookup(self.cur, last.name) else {
            // __lookup_slow: no dentry is created in a removed directory.
            if self.fs.is_dead(self.cur) {
                return Err(Errno::ENOENT);
            }
            // simple_lookup rejects an over-long name only when it must create
            // the negative dentry, i.e. when no entry of that name exists.
            return Err(if last.name.len() > NAME_MAX {
                Errno::ENAMETOOLONG
            } else {
                Errno::ENOENT
            });
        };
        let symlink = self.fs.inode(child).is_symlink();
        let stop = (flags & WALK_TRAILING != 0 && !self.follow) && symlink;
        if !symlink || stop {
            self.cur = child;
            return Ok(None);
        }
        self.pick_link(child)
    }

    /// `link_path_walk`: resolve every component but the last, which is
    /// returned (the walk stands in its parent directory).
    pub(crate) fn link_path_walk<'p>(&mut self, name: &'p [u8]) -> KResult<Last<'p>>
    where
        'a: 'p,
    {
        // `stack[i]` holds the unwalked rest of the path that a symlink body
        // interrupted. Bodies live as long as the filesystem borrow `'a`.
        let mut stack: [&'p [u8]; MAXSYMLINKS as usize + 1] = [&[]; MAXSYMLINKS as usize + 1];
        let mut depth = 0usize;
        let mut name = skip_slashes(name);
        if name.is_empty() {
            return Ok(Last {
                name: &[],
                kind: LastKind::Root,
                trailing_slash: false,
            });
        }
        loop {
            self.may_lookup()?;
            let end = name.iter().position(|&b| b == b'/').unwrap_or(name.len());
            let (component, rest) = name.split_at(end);
            let kind = match component {
                b".." => LastKind::DotDot,
                b"." => LastKind::Dot,
                _ => LastKind::Norm,
            };
            let last = Last {
                name: component,
                kind,
                trailing_slash: !rest.is_empty(),
            };
            let after = skip_slashes(rest);
            name = after;
            let link = if after.is_empty() {
                // `OK:` pathname or trailing symlink, done
                if depth == 0 {
                    return Ok(last);
                }
                // last component of a nested symlink body
                depth -= 1;
                name = stack[depth];
                self.walk_component(&last, 0)?
            } else {
                self.walk_component(&last, WALK_MORE)?
            };
            if let Some(body) = link {
                if depth >= stack.len() {
                    return Err(Errno::ELOOP);
                }
                stack[depth] = name;
                depth += 1;
                name = body;
                continue;
            }
            if !self.is_dir(self.cur) {
                return Err(Errno::ENOTDIR);
            }
        }
    }
}

/// `path_init`: where a walk of `path` begins.
fn init(fs: &Tmpfs, env: &Env, path: &[u8]) -> KResult<InodeId> {
    let start = if path.first() == Some(&b'/') {
        env.root
    } else {
        env.start
    };
    if !path.is_empty() && path.first() != Some(&b'/') && !fs.inode(start).is_dir() {
        return Err(Errno::ENOTDIR);
    }
    Ok(start)
}

/// `path_lookupat`: the inode `path` names. `flags` are [`LOOKUP_FOLLOW`] and
/// [`LOOKUP_DIRECTORY`]; a trailing slash adds both (`lookup_last`).
///
/// # Errors
/// `ENOENT`, `ENOTDIR`, `ELOOP`, `ENAMETOOLONG`, `EACCES`.
pub fn lookup<'x>(fs: &'x Tmpfs, env: &'x Env, path: &'x [u8], flags: u32) -> KResult<InodeId> {
    let mut walk = Walk::new(fs, env, path, flags & LOOKUP_FOLLOW != 0)?;
    let mut want_dir = flags & LOOKUP_DIRECTORY != 0;
    let mut remaining = path;
    loop {
        let last = walk.link_path_walk(remaining)?;
        if last.kind == LastKind::Norm && last.trailing_slash {
            walk.follow = true;
            want_dir = true;
        }
        // lookup_last -> walk_component(WALK_TRAILING)
        match walk.walk_component(&last, WALK_TRAILING)? {
            // The body is walked by a fresh link_path_walk; what follows it in
            // the original path is nothing (this was the final component).
            Some(body) => remaining = body,
            None => break,
        }
    }
    if want_dir && !walk.is_dir(walk.cur) {
        return Err(Errno::ENOTDIR);
    }
    Ok(walk.cur)
}

/// The parent directory of the final component and that component
/// (`path_parentat`), for `mknod`, `unlink`, `link` and the creating open. The
/// name is copied so the walk's borrow of the filesystem ends here.
pub struct Parent {
    pub dir: InodeId,
    pub name: Vec<u8>,
    pub kind: LastKind,
    pub trailing_slash: bool,
}

/// # Errors
/// As [`lookup`] for the directories on the way; `ENOMEM`.
pub fn parent_of<'x>(fs: &'x Tmpfs, env: &'x Env, path: &'x [u8]) -> KResult<Parent> {
    let mut walk = Walk::new(fs, env, path, false)?;
    let last = walk.link_path_walk(path)?;
    Ok(Parent {
        dir: walk.cur,
        name: super::try_copy(last.name)?,
        kind: last.kind,
        trailing_slash: last.trailing_slash,
    })
}
