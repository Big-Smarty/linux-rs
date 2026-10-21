// SPDX-License-Identifier: GPL-2.0-only
//! `procfs` group, part three: what `/proc/<pid>` shows of a task whose address space a `vfork`
//! child is working in. Linux 6.18.57: `kernel/fork.c` (`copy_mm` with `CLONE_VM` shares the
//! `mm_struct`), `fs/proc/task_mmu.c` (`show_pid_map`, `proc_pid_statm`, `task_mem`),
//! `fs/proc/base.c` (`get_mm_cmdline`, `proc_pid_cmdline_read`).
//!
//! The parent and the child have one `mm_struct`, so the files of `/proc/<parent>` show the live
//! address space: what the parent mapped or exec'd before the `vfork`, and what the child maps
//! while the parent waits. A child that itself `vfork`s sees the same through two levels.
//!
//! The child must not touch the parent's stack, so `clone` is called from assembly and the child
//! runs on a stack of its own (`clone_vfork`), writing what it read to statics the parent checks
//! after the child is gone.

use core::cell::UnsafeCell;

use syscalls::{Errno, Sysno};

use super::{
    O_RDONLY, R, T, Txt, addr, addr_mut, close, field, getppid, lines, num, open, status_kb,
};

const PROT_READ: usize = 1;
const MAP_PRIVATE_ANON_FIXED_NOREPLACE: usize = 0x2 | 0x20 | 0x10_0000;
const MARK1: usize = 0x5000_0000_0000;
const MARK2: usize = 0x5000_0001_0000;
const MARK3: usize = 0x5000_0002_0000;

/// A static the vfork children and their parent share. Only one of them runs at a time (the
/// parent sleeps in `vfork` until the child has exited), so no access is concurrent.
struct Shared<T>(UnsafeCell<T>);

// SAFETY: see the type's contract: the writer is the one task that is not waiting for another.
unsafe impl<T> Sync for Shared<T> {}

impl<T> Shared<T> {
    /// # Safety
    /// No other reference to the contents may be live: the caller is the only task running.
    #[allow(clippy::mut_from_ref)]
    unsafe fn get(&self) -> &mut T {
        // SAFETY: the caller's contract.
        unsafe { &mut *self.0.get() }
    }
}

/// A stack for a child: 32 KiB, 16-byte aligned.
#[repr(C, align(16))]
struct Stack([u8; 32768]);

impl Stack {
    fn top(this: &Shared<Self>) -> usize {
        this.0.get().expose_provenance() + 32768
    }
}

/// A text read from `/proc`.
struct Text {
    len: usize,
    buf: [u8; 8192],
}

impl Text {
    const fn new() -> Self {
        Self {
            len: 0,
            buf: [0; 8192],
        }
    }

    fn bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Replace the text with the whole content of `path`.
    fn load(&mut self, path: &str) {
        self.len = 0;
        let Ok(fd) = open(path, O_RDONLY) else {
            return;
        };
        while self.len < self.buf.len() {
            match super::read(fd, &mut self.buf[self.len..]) {
                Ok(0) | Err(_) => break,
                Ok(n) => self.len += n,
            }
        }
        let _ = close(fd);
    }

    /// Whether some line starts with `prefix`.
    fn has_line(&self, prefix: &str) -> bool {
        lines(self.bytes()).any(|line| line.starts_with(prefix.as_bytes()))
    }

    /// The first field of `statm` (pages of address space).
    fn size(&self) -> u64 {
        num(field(self.bytes(), b' ', 0)).unwrap_or(u64::MAX)
    }
}

/// What the children saw.
struct Seen {
    /// The pid of the task whose files are read.
    parent: usize,
    kid: usize,
    cmdline: Text,
    maps1: Text,
    statm1: Text,
    status1: Text,
    maps2: Text,
    statm2: Text,
    status2: Text,
    kid_own: Text,
    grand_parent: Text,
    grand_kid: Text,
    maps3: Text,
}

impl Seen {
    const fn new() -> Self {
        Self {
            parent: 0,
            kid: 0,
            cmdline: Text::new(),
            maps1: Text::new(),
            statm1: Text::new(),
            status1: Text::new(),
            maps2: Text::new(),
            statm2: Text::new(),
            status2: Text::new(),
            kid_own: Text::new(),
            grand_parent: Text::new(),
            grand_kid: Text::new(),
            maps3: Text::new(),
        }
    }
}

static SEEN: Shared<Seen> = Shared(UnsafeCell::new(Seen::new()));
static KID_STACK: Shared<Stack> = Shared(UnsafeCell::new(Stack([0; 32768])));
static GRAND_STACK: Shared<Stack> = Shared(UnsafeCell::new(Stack([0; 32768])));

/// `clone(CLONE_VM | CLONE_VFORK | SIGCHLD, stack)`; the child calls `body` on `stack` and then
/// leaves with `exit_group(0)`; the parent gets the child's pid when the child has exited or
/// exec'd.
#[inline(never)]
fn clone_vfork(body: extern "C" fn(), stack: usize) -> R {
    let pid: usize;
    // SAFETY: `clone` returns twice. The parent continues after the asm block with every
    // register but rax, rcx and r11 as it had them (the kernel restores the rest). The child has
    // the parent's registers, rax = 0 and rsp = `stack`, the 16-byte aligned top of a static
    // stack that nothing else uses: it calls `body` (an `extern "C"` function that touches no
    // memory of the parent's stack frames, only statics and its own stack), then `exit_group(0)`,
    // and never reaches the code after this block.
    unsafe {
        core::arch::asm!(
            "syscall",
            "test rax, rax",
            "jnz 2f",
            "call {body}",
            "xor edi, edi",
            "mov eax, 231",
            "syscall",
            "ud2",
            "2:",
            body = in(reg) body as usize,
            inlateout("rax") 56usize => pid,
            in("rdi") 0x4111usize, // CLONE_VM | CLONE_VFORK | SIGCHLD
            in("rsi") stack,
            in("rdx") 0usize,
            in("r10") 0usize,
            in("r8") 0usize,
            out("rcx") _,
            out("r11") _,
        );
    }
    Errno::from_ret(pid)
}

fn map_page(at: usize) -> R {
    super::super::mmap(
        at,
        4096,
        PROT_READ,
        MAP_PRIVATE_ANON_FIXED_NOREPLACE,
        usize::MAX,
        0,
    )
}

fn pid_path(buf: &mut [u8; 48], pid: usize, name: &str) -> usize {
    use core::fmt::Write as _;
    struct W<'a>(&'a mut [u8; 48], usize);
    impl core::fmt::Write for W<'_> {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let n = s.len().min(self.0.len() - self.1);
            self.0[self.1..self.1 + n].copy_from_slice(&s.as_bytes()[..n]);
            self.1 += n;
            Ok(())
        }
    }
    let mut w = W(buf, 0);
    let _ = write!(w, "/proc/{pid}/{name}");
    w.1
}

/// Load `/proc/<pid>/<name>` into `text`.
fn load(text: &mut Text, pid: usize, name: &str) {
    let mut path = [0u8; 48];
    let n = pid_path(&mut path, pid, name);
    text.load(core::str::from_utf8(&path[..n]).unwrap_or(""));
}

/// The first `vfork` child: reads its parent's files, maps a page, reads again, runs a child of
/// its own, and reads once more.
extern "C" fn kid_body() {
    // SAFETY: the parent sleeps in `vfork` until this task has exited, and this task's own child
    // (below) runs while this one sleeps: the accesses never overlap.
    let seen = unsafe { SEEN.get() };
    seen.kid = super::getpid();
    let parent = getppid();
    seen.parent = parent;
    load(&mut seen.cmdline, parent, "cmdline");
    load(&mut seen.maps1, parent, "maps");
    load(&mut seen.statm1, parent, "statm");
    load(&mut seen.status1, parent, "status");
    let _ = map_page(MARK2);
    load(&mut seen.maps2, parent, "maps");
    load(&mut seen.statm2, parent, "statm");
    load(&mut seen.status2, parent, "status");
    load(&mut seen.kid_own, seen.kid, "maps");
    let _ = clone_vfork(grand_body, Stack::top(&GRAND_STACK));
    // SAFETY: as above; the grandchild has exited.
    let seen = unsafe { SEEN.get() };
    load(&mut seen.maps3, parent, "maps");
}

/// The grandchild: the parent of its parent is the task the files name.
extern "C" fn grand_body() {
    // SAFETY: the first child sleeps in `vfork` until this task has exited.
    let seen = unsafe { SEEN.get() };
    load(&mut seen.grand_parent, seen.parent, "maps");
    load(&mut seen.grand_kid, seen.kid, "maps");
    let _ = map_page(MARK3);
}

fn line_of(at: usize) -> &'static str {
    match at {
        MARK1 => "500000000000-500000001000 r--p 00000000 00:00 0",
        MARK2 => "500000010000-500000011000 r--p 00000000 00:00 0",
        _ => "500000020000-500000021000 r--p 00000000 00:00 0",
    }
}

/// The parent maps a page and `vfork`s at once, so nothing has published the page for it.
pub(super) fn window(t: &mut T) {
    use super::super::proc::wait4;
    let mut own_cmdline = Text::new();
    own_cmdline.load("/proc/self/cmdline");
    // SAFETY: no child exists yet.
    *unsafe { SEEN.get() } = Seen::new();
    let mapped = map_page(MARK1);
    let pid = clone_vfork(kid_body, Stack::top(&KID_STACK));
    t.eq("vfork-mark", mapped, Ok(MARK1));
    t.holds("vfork-child", pid.is_ok(), pid, "a child pid");
    let status = wait4(pid.unwrap_or(usize::MAX) as isize, 0).1;
    t.eq("vfork-child-status", status, 0);
    // SAFETY: the children are gone.
    let seen = unsafe { SEEN.get() };
    t.eq("vfork-child-saw-parent", seen.parent, super::getpid());
    t.eq("vfork-cmdline-own-length", own_cmdline.len > 0, true);
    t.eq(
        "vfork-cmdline",
        Txt(seen.cmdline.bytes()),
        Txt(own_cmdline.bytes()),
    );
    t.eq(
        "vfork-maps-before-child-mapping",
        seen.maps1.has_line(line_of(MARK1)),
        true,
    );
    t.eq(
        "vfork-maps-not-yet-mapped",
        seen.maps1.has_line(line_of(MARK2)),
        false,
    );
    t.eq(
        "vfork-maps-child-mapping",
        (
            seen.maps2.has_line(line_of(MARK1)),
            seen.maps2.has_line(line_of(MARK2)),
        ),
        (true, true),
    );
    t.eq(
        "vfork-statm-child-mapping",
        seen.statm2.size(),
        seen.statm1.size() + 1,
    );
    t.eq(
        "vfork-status-child-mapping",
        status_kb(seen.status2.bytes(), "VmSize"),
        status_kb(seen.status1.bytes(), "VmSize") + 4,
    );
    t.eq(
        "vfork-child-own-maps",
        Txt(seen.kid_own.bytes()),
        Txt(seen.maps2.bytes()),
    );
    t.eq(
        "vfork-grandchild-maps",
        (
            seen.grand_parent.has_line(line_of(MARK1)),
            seen.grand_parent.has_line(line_of(MARK2)),
            seen.grand_parent.has_line(line_of(MARK3)),
        ),
        (true, true, false),
    );
    t.eq(
        "vfork-grandchild-both-names",
        Txt(seen.grand_kid.bytes()),
        Txt(seen.grand_parent.bytes()),
    );
    t.eq(
        "vfork-grandchild-mapping",
        (
            seen.maps3.has_line(line_of(MARK2)),
            seen.maps3.has_line(line_of(MARK3)),
        ),
        (true, true),
    );
    // Back in the parent: the one address space holds what the children mapped.
    let mut own = Text::new();
    own.load("/proc/self/maps");
    t.eq(
        "vfork-parent-after",
        (
            own.has_line(line_of(MARK1)),
            own.has_line(line_of(MARK2)),
            own.has_line(line_of(MARK3)),
        ),
        (true, true, true),
    );
    let mut statm = Text::new();
    statm.load("/proc/self/statm");
    t.eq("vfork-statm-after", statm.size(), seen.statm1.size() + 2);
    for at in [MARK1, MARK2, MARK3] {
        let _ = super::sys(Sysno::munmap, &[at, 4096]);
    }
}

/// The image `execve`d by the parent of [`exec`]: it maps a page and `vfork`s before it has done
/// anything else, so what `/proc` knows of it is what the exec made, not what the process it was
/// forked from looked like.
pub fn image() -> ! {
    // SAFETY: nothing else runs yet.
    let seen = unsafe { SEEN.get() };
    *seen = Seen::new();
    let _ = map_page(MARK1);
    let _ = clone_vfork(exec_kid, Stack::top(&KID_STACK));
    // SAFETY: the child is gone.
    let seen = unsafe { SEEN.get() };
    let mut own_statm = Text::new();
    own_statm.load("/proc/self/statm");
    // The size the child saw is the size now, except for the page the child mapped.
    let result = [
        seen.cmdline.bytes() == b"/init\0procvfork\0",
        seen.maps1.has_line(line_of(MARK1)),
        seen.statm1.size() != u64::MAX && seen.statm1.size() + 1 == own_statm.size(),
        seen.maps2.has_line(line_of(MARK1)) && seen.maps2.has_line(line_of(MARK2)),
        seen.statm2.size() == own_statm.size(),
    ]
    .map(|ok| if ok { b'1' } else { b'0' });
    let _ = super::sys(Sysno::write, &[200, addr(&result), result.len()]);
    super::super::die(0)
}

extern "C" fn exec_kid() {
    // SAFETY: the parent sleeps in `vfork` until this task has exited.
    let seen = unsafe { SEEN.get() };
    let parent = getppid();
    seen.parent = parent;
    load(&mut seen.cmdline, parent, "cmdline");
    load(&mut seen.maps1, parent, "maps");
    load(&mut seen.statm1, parent, "statm");
    let _ = map_page(MARK2);
    load(&mut seen.maps2, parent, "maps");
    load(&mut seen.statm2, parent, "statm");
}

/// A process that `execve`s the image above, reporting through a pipe.
pub(super) fn exec(t: &mut T) {
    use super::super::proc::{spawn, wait4};
    let mut fds = [0u32; 2];
    let _ = super::sys(Sysno::pipe2, &[addr_mut(&mut fds), 0]);
    let (r, w) = (fds[0] as usize, fds[1] as usize);
    let child = spawn(|| {
        let _ = super::sys(Sysno::dup2, &[w, 200]);
        let argv = [addr(b"/init\0"), addr(b"procvfork\0"), 0];
        let envp = [0usize; 1];
        let _ = super::sys(Sysno::execve, &[addr(b"/init\0"), addr(&argv), addr(&envp)]);
        127
    });
    let _ = close(w);
    let status = wait4(child as isize, 0).1;
    let mut got = [b'?'; 5];
    let n = super::read(r, &mut got).unwrap_or(0);
    let _ = close(r);
    t.eq("vfork-exec-status", status, 0);
    t.eq("vfork-exec-report-length", n, 5);
    for (i, name) in [
        "vfork-exec-cmdline",
        "vfork-exec-maps",
        "vfork-exec-statm",
        "vfork-exec-live-maps",
        "vfork-exec-live-statm",
    ]
    .into_iter()
    .enumerate()
    {
        t.eq(name, got[i], b'1');
    }
}
