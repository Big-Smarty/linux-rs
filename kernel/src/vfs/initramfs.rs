// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics translated from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: init/initramfs.c (GPL-2.0:
// `unpack_to_rootfs`, `write_buffer`, `do_start`/`do_collect`/`do_header`/
// `do_skip`/`do_reset`/`do_name`/`do_copy`/`do_symlink`, `read_into`,
// `parse_header`, `clean_path`, `maybe_link`, `find_link`, `free_hash`,
// `dir_add`/`dir_utime` (`CONFIG_INITRAMFS_PRESERVE_MTIME=y`), `xwrite`),
// init/noinitramfs.c (`default_rootfs`, the contents of usr/default_cpio_list
// of the builtin initramfs), fs/init.c (`init_*` helpers).
// Copyright of the original: its authors (H. Peter Anvin, Rob Landley and
// others); lib/vsprintf.c `simple_strntoul` semantics are reused through
// `image::cpio::hex_field`.
// Transformation: the finite-state machine runs over one borrowed buffer; the
// `init_*` kernel syscalls are `Vfs` operations as the kernel thread; `pr_err`
// lines are not emitted (no console at this layer); decompression is a named
// blocker (`image::cpio::compression`), reported as Linux's "decompressor
// failed".
#![forbid(unsafe_code)]
//! The initramfs unpacker, state for state, so a damaged archive leaves
//! exactly the tree Linux leaves.
//!
//! Context: task context during boot, before any user task exists. The unpacker
//! mutates the rootfs through the same [`Vfs`] operations the syscalls use
//! (`init_mkdir` is `mkdir`, `filp_open` is `open`, ...), as `current` = a
//! kernel thread: root credentials, umask 022, working directory `/`.
//! Failures of individual `init_*` calls are ignored exactly where Linux
//! ignores them; only a parse error or a short write sets the final message.
//!
//! Persistent state: `next_state` survives from one archive to the next
//! because the C static does ([`Unpacker`] is created once per boot).

use alloc::vec::Vec;

use super::{
    FileId, KResult, O_CREAT, O_LARGEFILE, O_TRUNC, O_WRONLY, S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO,
    S_IFLNK, S_IFMT, S_IFREG, S_IFSOCK, Timespec, Vfs, mkdev, new_encode_dev,
    ops::{Env, build_open_flags},
    path::LOOKUP_FOLLOW,
    try_copy, try_push,
};
use crate::image::cpio::{compression, hex_field};

const CPIO_HDRLEN: usize = 110;
const PATH_MAX: usize = 4096;

/// `N_ALIGN(len)`: the name field's padded length, which makes the file data
/// 4-aligned given the 110-byte header.
const fn n_align(len: usize) -> usize {
    ((len + 1) & !3) + 2
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Start,
    Collect,
    GotHeader,
    SkipIt,
    GotName,
    CopyFile,
    GotSymlink,
    Reset,
}

struct Link {
    ino: i32,
    minor: i32,
    major: i32,
    mode: u16,
    name: Vec<u8>,
}

/// Header fields of the record being processed (the `__initdata` globals).
#[derive(Default)]
struct Header {
    ino: u64,
    major: u64,
    minor: u64,
    nlink: u64,
    mode: u16,
    body_len: u64,
    name_len: usize,
    uid: u32,
    gid: u32,
    rdev: u32,
    hdr_csum: u32,
    mtime: i64,
}

/// What the archive walk stopped on.
pub type Message = &'static str;

pub struct Unpacker {
    next_state: State,
}

impl Default for Unpacker {
    fn default() -> Self {
        Self::new()
    }
}

struct Run<'a, 'v> {
    vfs: &'v mut Vfs,
    env: Env,
    buf: &'a [u8],
    victim: usize,
    byte_count: usize,
    state: State,
    next_state: State,
    this_header: u64,
    next_header: u64,
    header: Header,
    csum_present: bool,
    io_csum: u32,
    collected: Vec<u8>,
    remains: usize,
    wfile: Option<(FileId, u64)>,
    message: Option<Message>,
    links: Vec<Link>,
    dirs: Vec<(Vec<u8>, i64)>,
}

/// The bytes of a C string stored in `bytes` (up to the first NUL).
fn cstr(bytes: &[u8]) -> &[u8] {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    &bytes[..end]
}

impl Unpacker {
    #[must_use]
    pub const fn new() -> Self {
        // A zero-initialised enum static is `Start`.
        Self {
            next_state: State::Start,
        }
    }

    /// `unpack_to_rootfs`: extract one initramfs image; the message is the
    /// first error Linux's `error()` recorded, if any. Entries processed before
    /// an error stay in the tree.
    pub fn unpack(&mut self, vfs: &mut Vfs, buf: &[u8]) -> Option<Message> {
        let env = vfs.kernel_env();
        let mut run = Run {
            vfs,
            env,
            buf,
            victim: 0,
            byte_count: 0,
            state: State::Start,
            next_state: self.next_state,
            this_header: 0,
            next_header: 0,
            header: Header::default(),
            csum_present: false,
            io_csum: 0,
            collected: Vec::new(),
            remains: 0,
            wfile: None,
            message: None,
            links: Vec::new(),
            dirs: Vec::new(),
        };
        let mut at = 0usize;
        while run.message.is_none() && at < buf.len() {
            let saved_offset = run.this_header;
            if buf[at] == b'0' && run.this_header.trailing_zeros() >= 2 {
                run.state = State::Start;
                at += run.write_buffer(at);
                continue;
            }
            if buf[at] == 0 {
                at += 1;
                run.this_header += 1;
                continue;
            }
            run.this_header = 0;
            // decompress_method: no decompressor is ported (named blocker).
            if compression(&buf[at..]).is_some() {
                run.error("decompressor failed");
            } else {
                run.error("invalid magic at start of compressed archive");
            }
            if run.state != State::Reset {
                run.error("junk at the end of compressed archive");
            }
            run.this_header = saved_offset;
        }
        run.dir_utime();
        let message = run.message;
        self.next_state = run.next_state;
        message
    }
}

impl Run<'_, '_> {
    fn error(&mut self, message: Message) {
        if self.message.is_none() {
            self.message = Some(message);
        }
    }

    fn eat(&mut self, n: usize) {
        self.victim += n;
        self.this_header += n as u64;
        self.byte_count -= n;
    }

    /// `write_buffer`: run the machine over `buf[from..]`; returns the bytes
    /// consumed.
    fn write_buffer(&mut self, from: usize) -> usize {
        let len = self.buf.len() - from;
        self.byte_count = len;
        self.victim = from;
        while !self.action() {}
        len - self.byte_count
    }

    fn action(&mut self) -> bool {
        match self.state {
            State::Start => self.do_start(),
            State::Collect => self.do_collect(),
            State::GotHeader => self.do_header(),
            State::SkipIt => self.do_skip(),
            State::GotName => self.do_name(),
            State::CopyFile => self.do_copy(),
            State::GotSymlink => self.do_symlink(),
            State::Reset => self.do_reset(),
        }
    }

    /// `read_into`.
    fn read_into(&mut self, size: usize, next: State) {
        self.collected.clear();
        if self.byte_count >= size {
            let bytes = &self.buf[self.victim..self.victim + size];
            if self.fill(bytes).is_err() {
                self.error("out of memory");
            }
            self.eat(size);
            self.state = next;
        } else {
            self.remains = size;
            self.next_state = next;
            self.state = State::Collect;
        }
    }

    fn fill(&mut self, bytes: &[u8]) -> KResult<()> {
        // `collected` is cleared by `read_into`; appending keeps Collect cheap.
        self.collected
            .try_reserve(bytes.len())
            .map_err(|_| syscalls::Errno::ENOMEM)?;
        for &byte in bytes {
            self.collected
                .push_within_capacity(byte)
                .map_err(|_| syscalls::Errno::ENOMEM)?;
        }
        Ok(())
    }

    fn do_start(&mut self) -> bool {
        self.read_into(CPIO_HDRLEN, State::GotHeader);
        false
    }

    fn do_collect(&mut self) -> bool {
        let n = self.remains.min(self.byte_count);
        let bytes = &self.buf[self.victim..self.victim + n];
        if self.collected.try_reserve(n).is_err() {
            self.error("out of memory");
            return true;
        }
        for &byte in bytes {
            let _ = self.collected.push_within_capacity(byte);
        }
        self.eat(n);
        self.remains -= n;
        if self.remains != 0 {
            return true;
        }
        self.state = self.next_state;
        false
    }

    fn parse_header(&mut self) {
        let s = &self.collected;
        let mut parsed = [0u32; 13];
        let (fields, _) = s[6..].as_chunks::<8>();
        for (value, field) in parsed.iter_mut().zip(fields) {
            *value = hex_field(field);
        }
        self.header = Header {
            ino: u64::from(parsed[0]),
            mode: parsed[1] as u16, // `umode_t`
            uid: parsed[2],
            gid: parsed[3],
            nlink: u64::from(parsed[4]),
            mtime: i64::from(parsed[5]),
            body_len: u64::from(parsed[6]),
            major: u64::from(parsed[7]),
            minor: u64::from(parsed[8]),
            rdev: new_encode_dev(mkdev(parsed[9], parsed[10])),
            name_len: parsed[11] as usize,
            hdr_csum: parsed[12],
        };
    }

    fn do_header(&mut self) -> bool {
        match &self.collected[..6] {
            b"070701" => self.csum_present = false,
            b"070702" => self.csum_present = true,
            magic => {
                if magic == b"070707" {
                    self.error("incorrect cpio method used: use -H newc option");
                } else {
                    self.error("no cpio magic");
                }
                return true;
            }
        }
        self.parse_header();
        let h = &self.header;
        self.next_header = self.this_header + n_align(h.name_len) as u64 + h.body_len;
        self.next_header = (self.next_header + 3) & !3;
        self.state = State::SkipIt;
        let (name_len, body_len, mode) = (h.name_len, h.body_len, u32::from(h.mode));
        if name_len == 0 || name_len > PATH_MAX {
            return false;
        }
        if mode & S_IFMT == S_IFLNK {
            if body_len > PATH_MAX as u64 {
                return false;
            }
            self.collected.clear();
            self.remains = n_align(name_len) + body_len as usize;
            self.next_state = State::GotSymlink;
            self.state = State::Collect;
            return false;
        }
        if mode & S_IFMT == S_IFREG || body_len == 0 {
            self.read_into(n_align(name_len), State::GotName);
        }
        false
    }

    fn do_skip(&mut self) -> bool {
        if self.this_header + (self.byte_count as u64) < self.next_header {
            self.eat(self.byte_count);
            true
        } else {
            let n = (self.next_header - self.this_header) as usize;
            self.eat(n);
            self.state = self.next_state;
            false
        }
    }

    fn do_reset(&mut self) -> bool {
        while self.byte_count > 0 && self.buf[self.victim] == 0 {
            self.eat(1);
        }
        if self.byte_count > 0 && self.this_header & 3 != 0 {
            self.error("broken padding");
        }
        true
    }

    /// `clean_path`: remove an existing entry of a different type.
    fn clean_path(&mut self, path: &[u8], fmode: u32) {
        let Ok(inode) = self.vfs.lookup(&self.env, path, 0) else {
            return;
        };
        let mode = self.vfs.fs.inode(inode).mode;
        if (mode ^ fmode) & S_IFMT != 0 {
            if mode & S_IFMT == S_IFDIR {
                let _ = self.vfs.rmdir(&self.env, path);
            } else {
                let _ = self.vfs.unlink(&self.env, path);
            }
        }
    }

    /// `find_link`: the first name seen for this (major, minor, ino, type), or
    /// remember `name` as that first name.
    fn find_link(&mut self, name: &[u8]) -> Option<Vec<u8>> {
        let h = &self.header;
        let (ino, minor, major) = (h.ino as i32, h.minor as i32, h.major as i32);
        for link in &self.links {
            if link.ino == ino
                && link.minor == minor
                && link.major == major
                && (u32::from(link.mode) ^ u32::from(h.mode)) & S_IFMT == 0
            {
                return try_copy(&link.name).ok();
            }
        }
        let mode = h.mode;
        match try_copy(name) {
            Ok(name) => {
                let _ = try_push(
                    &mut self.links,
                    Link {
                        ino,
                        minor,
                        major,
                        mode,
                        name,
                    },
                );
            }
            Err(_) => self.error("can't allocate link hash entry"),
        }
        None
    }

    /// `maybe_link`: 1 linked, 0 not a hard link, -1 link failure.
    fn maybe_link(&mut self, name: &[u8]) -> i32 {
        if self.header.nlink >= 2
            && let Some(old) = self.find_link(name)
        {
            self.clean_path(name, 0);
            return match self.vfs.link(&self.env, &old, 0, name) {
                Ok(()) => 1,
                Err(_) => -1,
            };
        }
        0
    }

    fn do_utime(&mut self, path: &[u8], mtime: i64) {
        let time = Timespec {
            sec: mtime,
            nsec: 0,
        };
        if let Ok(inode) = self.vfs.lookup(&self.env, path, LOOKUP_FOLLOW) {
            self.vfs.utimes(inode, time, time);
        }
    }

    fn dir_utime(&mut self) {
        // list_add puts new entries at the head: newest first.
        while let Some((name, mtime)) = self.dirs.pop() {
            self.do_utime(&name, mtime);
        }
    }

    fn do_name(&mut self) -> bool {
        self.state = State::SkipIt;
        self.next_state = State::Reset;
        let name_len = self.header.name_len;
        if self.collected.get(name_len - 1) != Some(&0) {
            self.error("malformed archive");
            return true;
        }
        let Ok(name) = try_copy(cstr(&self.collected[..name_len])) else {
            self.error("out of memory");
            return true;
        };
        if name == b"TRAILER!!!" {
            self.links.clear();
            return false;
        }
        let mode = u32::from(self.header.mode);
        let (uid, gid, mtime) = (self.header.uid, self.header.gid, self.header.mtime);
        self.clean_path(&name, mode);
        match mode & S_IFMT {
            S_IFREG => {
                let ml = self.maybe_link(&name);
                if ml >= 0 {
                    let mut flags = O_WRONLY | O_CREAT | O_LARGEFILE;
                    if ml != 1 {
                        flags |= O_TRUNC;
                    }
                    let Ok(op) = build_open_flags(flags, mode) else {
                        return false;
                    };
                    let Ok(file) = self.vfs.open(&self.env, &name, &op) else {
                        return false;
                    };
                    self.io_csum = 0;
                    if let Some(inode) = self.vfs.files.get(file).inode {
                        let _ = self.vfs.chown(&self.env, inode, uid, gid); // vfs_fchown
                        let _ = self.vfs.chmod(&self.env, inode, mode); // vfs_fchmod
                        if self.header.body_len != 0 {
                            let _ = self.vfs.truncate(&self.env, inode, self.header.body_len);
                        }
                    }
                    self.wfile = Some((file, 0));
                    self.state = State::CopyFile;
                }
            }
            S_IFDIR => {
                let _ = self.vfs.mkdir(&self.env, &name, mode);
                self.chown_path(&name, uid, gid, true);
                self.chmod_path(&name, mode);
                if let Ok(copy) = try_copy(&name) {
                    let _ = try_push(&mut self.dirs, (copy, mtime));
                }
            }
            S_IFBLK | S_IFCHR | S_IFIFO | S_IFSOCK if self.maybe_link(&name) == 0 => {
                // init_mknod: FIFOs and sockets carry no device number.
                let dev = if matches!(mode & S_IFMT, S_IFBLK | S_IFCHR) {
                    self.header.rdev
                } else {
                    0
                };
                let _ = self.vfs.mknod(&self.env, &name, mode, dev);
                self.chown_path(&name, uid, gid, true);
                self.chmod_path(&name, mode);
                self.do_utime(&name, mtime);
            }
            _ => {}
        }
        false
    }

    /// `init_chown`.
    fn chown_path(&mut self, path: &[u8], uid: u32, gid: u32, follow: bool) {
        let flags = if follow { LOOKUP_FOLLOW } else { 0 };
        if let Ok(inode) = self.vfs.lookup(&self.env, path, flags) {
            let _ = self.vfs.chown(&self.env, inode, uid, gid);
        }
    }

    /// `init_chmod`.
    fn chmod_path(&mut self, path: &[u8], mode: u32) {
        if let Ok(inode) = self.vfs.lookup(&self.env, path, LOOKUP_FOLLOW) {
            let _ = self.vfs.chmod(&self.env, inode, mode);
        }
    }

    /// `xwrite` to the open output file at its position.
    fn xwrite(&mut self, data: &[u8]) -> usize {
        let Some((file, pos)) = self.wfile else {
            return 0;
        };
        let Some(inode) = self.vfs.files.get(file).inode else {
            return 0;
        };
        let mut out = 0usize;
        while out < data.len() {
            match self.vfs.fs.write(inode, pos + out as u64, &data[out..]) {
                Ok(0) | Err(_) => break,
                Ok(n) => out += n,
            }
        }
        if self.csum_present {
            for &byte in &data[..out] {
                self.io_csum = self.io_csum.wrapping_add(u32::from(byte));
            }
        }
        if let Some((_, p)) = self.wfile.as_mut() {
            *p += out as u64;
        }
        out
    }

    fn do_copy(&mut self) -> bool {
        let body_len = self.header.body_len;
        if self.byte_count as u64 >= body_len {
            let n = body_len as usize;
            let data = &self.buf[self.victim..self.victim + n];
            if self.xwrite(data) != n {
                self.error("write error");
            }
            self.finish_file();
            if self.csum_present && self.io_csum != self.header.hdr_csum {
                self.error("bad data checksum");
            }
            self.eat(n);
            self.state = State::SkipIt;
            false
        } else {
            let n = self.byte_count;
            let data = &self.buf[self.victim..self.victim + n];
            if self.xwrite(data) != n {
                self.error("write error");
            }
            self.header.body_len -= n as u64;
            self.eat(n);
            true
        }
    }

    /// `do_utime_path` + `fput` of the output file.
    fn finish_file(&mut self) {
        if let Some((file, _)) = self.wfile.take() {
            let time = Timespec {
                sec: self.header.mtime,
                nsec: 0,
            };
            if let Some(inode) = self.vfs.files.get(file).inode {
                self.vfs.utimes(inode, time, time);
            }
            self.vfs.fput(file);
        }
    }

    fn do_symlink(&mut self) -> bool {
        let (name_len, body_len) = (self.header.name_len, self.header.body_len as usize);
        if self.collected.get(name_len - 1) != Some(&0) {
            self.error("malformed archive");
            return true;
        }
        let start = n_align(name_len);
        let (Ok(name), Ok(target)) = (
            try_copy(cstr(&self.collected[..name_len])),
            try_copy(cstr(&self.collected[start..start + body_len])),
        ) else {
            self.error("out of memory");
            return true;
        };
        let (uid, gid, mtime) = (self.header.uid, self.header.gid, self.header.mtime);
        self.clean_path(&name, 0);
        let _ = self.vfs.symlink(&self.env, &target, &name);
        self.chown_path(&name, uid, gid, false);
        self.do_utime(&name, mtime);
        self.state = State::SkipIt;
        self.next_state = State::Reset;
        false
    }
}

impl Vfs {
    /// `default_rootfs` / the builtin initramfs (`usr/default_cpio_list`): `/dev`
    /// 0755, the `/dev/console` node (char 5:1, 0600) and `/root` 0700, created
    /// with the same operations a cpio entry would use.
    ///
    /// # Errors
    /// The first failing creation (Linux logs `Failed to create a rootfs`).
    pub fn default_rootfs(&mut self) -> KResult<()> {
        let env = self.kernel_env();
        self.mkdir(&env, b"/dev", 0o755)?;
        let dev = self.lookup(&env, b"/dev", 0)?;
        self.chmod(&env, dev, 0o755)?;
        self.mknod(
            &env,
            b"/dev/console",
            S_IFCHR | 0o600,
            new_encode_dev(mkdev(5, 1)),
        )?;
        let node = self.lookup(&env, b"/dev/console", 0)?;
        self.chmod(&env, node, 0o600)?;
        self.mkdir(&env, b"/root", 0o700)?;
        let root = self.lookup(&env, b"/root", 0)?;
        self.chmod(&env, root, 0o700)?;
        Ok(())
    }
}
