// SPDX-License-Identifier: GPL-2.0-only AND (GPL-2.0 WITH Linux-syscall-note)
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: fs/binfmt_elf.c
// (`load_elf_binary`, `elf_load`, `elf_map`, `padzero`, `make_prot`; GPL-2.0-only,
// Copyright 1993, 1994: Eric Youngdale), mm/mmap.c and mm/util.c (`vm_mmap`,
// `do_mmap`, `__get_unmapped_area`, `vm_brk_flags` argument checks; GPL-2.0),
// arch/x86/include/asm/elf.h and page_64_types.h (GPL-2.0). Constants from
// include/uapi/linux/elf.h (GPL-2.0 WITH Linux-syscall-note).
// Transformation: the checks are evaluated in Linux order against a plan instead
// of mutating an mm; the page-level content of every mapped page is computed so
// the freestanding loader can fill owned frames without a page cache.
#![forbid(unsafe_code)]
//! ELF acceptance and load plan for a static `ET_EXEC` x86-64 `/init`.
//!
//! Linux order is kept: header and program-table checks (all `-ENOEXEC`), the
//! `PT_INTERP` scan, `PT_GNU_STACK`, then each `PT_LOAD` through the mmap and
//! brk argument checks of `elf_load` (`-EOVERFLOW`, `-EINVAL`, `-ENOMEM`,
//! `-EEXIST`) followed by the post-mapping `TASK_SIZE` checks (`-EINVAL`), and
//! finally the entry check. `load_bias` is zero (`ET_EXEC`). Unsigned
//! arithmetic wraps exactly where the C does, so hostile sizes take the same
//! branch Linux takes.
//!
//! # Differences from Linux (all explicit, none silent)
//! * shortcut: `ET_DYN` (static PIE) and `PT_INTERP` (dynamic) fail with
//!   [`Unsupported`]; upgrade with the mmap-base/ASLR and interpreter work.
//! * shortcut: a segment overlapping another segment or the stack fails with
//!   [`Unsupported::Overlap`]; Linux lets later `MAP_FIXED` segments replace
//!   earlier pages. (The first segment overlapping the stack is `-EEXIST`.)
//! * shortcut: a file mapping whose last page starts at or beyond EOF fails
//!   with [`Unsupported::BeyondEof`]; Linux maps it and raises `SIGBUS` on use.
//! * shortcut: at most [`MAX_LOADS`] `PT_LOAD` segments (Linux: 1170).
//! * `PF_X`/`PF_W` without `PF_R` map readable too: x86 has no write-only or
//!   (without protection keys) execute-only pages.
//! * `p_flags == 0` segments are `PROT_NONE`: accounted for, never mapped.
//! * No randomisation: this is Linux with `norandmaps` (`randomize_va_space=0`).

use super::stack::{STACK_START, STACK_TOP};
use crate::{
    image::elf::{self, ET_DYN, Elf, PF_R, PF_W, PF_X, PT_LOAD},
    memory::PAGE,
    usercopy::TASK_SIZE_MAX,
};
use syscalls::Errno;

pub const MAX_LOADS: usize = 16;
/// ramfs/tmpfs `s_maxbytes` (`MAX_LFS_FILESIZE`) for `file_mmap_ok`.
const MAX_LFS_FILESIZE: u64 = i64::MAX.cast_unsigned();
/// `sizeof(struct elf_phdr)` for `AT_PHENT`.
pub const PHENT: u64 = 56;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unsupported {
    SharedObject,
    Interpreter,
    Overlap,
    BeyondEof,
    TooManyLoads,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadError {
    /// What Linux's `execve` returns.
    Errno(Errno),
    /// Valid for Linux, outside this slice.
    Unsupported(Unsupported),
}

const fn failed(errno: Errno) -> LoadError {
    LoadError::Errno(errno)
}

const fn page_start(value: u64) -> u64 {
    value & !(PAGE - 1)
}
const fn page_align(value: u64) -> u64 {
    value.wrapping_add(PAGE - 1) & !(PAGE - 1)
}

/// `make_prot`: `PROT_READ/WRITE/EXEC` from `p_flags`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Prot {
    pub read: bool,
    pub write: bool,
    pub exec: bool,
}

impl Prot {
    /// Any `PROT_*` bit makes an x86 page present and readable.
    #[must_use]
    pub const fn accessible(self) -> bool {
        self.read || self.write || self.exec
    }
}

/// One validated `PT_LOAD`: `file_pages` pages starting at `start` come from
/// the file at `file_offset` with `prot`; `anon_pages` zero pages follow them
/// (readable, writable, executable only when the segment is: `vm_brk_flags`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Segment {
    pub start: u64,
    pub file_pages: u64,
    pub anon_pages: u64,
    pub file_offset: u64,
    pub prot: Prot,
    /// `padzero()` target: bytes from here to the end of its page are zeroed.
    /// Zero when Linux would not (aligned, no bss, or a read-only mapping).
    zero_from: u64,
}

impl Segment {
    #[must_use]
    pub const fn pages(&self) -> u64 {
        self.file_pages + self.anon_pages
    }

    /// Permissions of page `index` (file pages first, then anonymous bss).
    #[must_use]
    pub const fn page_prot(&self, index: u64) -> Prot {
        if index < self.file_pages {
            self.prot
        } else {
            Prot {
                read: true,
                write: true,
                exec: self.prot.exec,
            }
        }
    }

    /// Contents of page `index`: the file bytes of that page (zero past EOF),
    /// then `padzero()`. `out` is exactly one page.
    pub fn fill_page(&self, file: &[u8], index: u64, out: &mut [u8]) {
        out.fill(0);
        if index < self.file_pages {
            let from = self.file_offset + index * PAGE;
            if let Some(tail) = usize::try_from(from).ok().and_then(|from| file.get(from..)) {
                let count = tail.len().min(out.len());
                out[..count].copy_from_slice(&tail[..count]);
            }
            let last = self.start + index * PAGE;
            if self.zero_from != 0 && page_start(self.zero_from) == last {
                // Below one page by construction.
                #[allow(clippy::cast_possible_truncation)]
                out[(self.zero_from - last) as usize..].fill(0);
            }
        }
    }

    fn end(&self) -> u64 {
        self.start + self.pages() * PAGE
    }
}

/// A file-backed region for `print_vma_addr`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Vma {
    pub start: u64,
    pub end: u64,
    pub pgoff: u64,
    prot: Prot,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Vmas {
    items: [Vma; MAX_LOADS],
    len: usize,
}

impl Vmas {
    fn push(&mut self, start: u64, end: u64, pgoff: u64, prot: Prot) {
        // vma_merge: adjacent, same permissions, contiguous file offsets.
        if let Some(last) = self.items[..self.len].last_mut()
            && last.end == start
            && last.prot == prot
            && last.pgoff + (last.end - last.start) / PAGE == pgoff
        {
            last.end = end;
            return;
        }
        self.items[self.len] = Vma {
            start,
            end,
            pgoff,
            prot,
        };
        self.len += 1;
    }
    /// `vma_lookup` restricted to file-backed regions.
    #[must_use]
    pub fn find(&self, address: u64) -> Option<&Vma> {
        self.items[..self.len]
            .iter()
            .find(|vma| vma.start <= address && address < vma.end)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LoadPlan {
    pub entry: u64,
    /// `AT_PHDR`: zero when no segment maps the program-header table.
    pub phdr: u64,
    pub phnum: u16,
    /// `mm->start_brk`.
    pub brk: u64,
    /// `PT_GNU_STACK` with `PF_X` (the 64-bit default is non-executable).
    pub exec_stack: bool,
    pub vmas: Vmas,
    segments: [Segment; MAX_LOADS],
    loads: usize,
}

fn vm_fixed(addr: u64, len: u64) -> Result<(), LoadError> {
    // __get_unmapped_area for MAP_FIXED: len > TASK_SIZE, addr > TASK_SIZE - len.
    if len > TASK_SIZE_MAX || addr > TASK_SIZE_MAX - len {
        return Err(failed(Errno::ENOMEM));
    }
    Ok(())
}

impl LoadPlan {
    /// # Errors
    /// The `execve` errno Linux 6.18.57 returns for the same bytes, or an
    /// explicit [`Unsupported`] for valid input this slice does not load.
    pub fn new(file: &[u8]) -> Result<Self, LoadError> {
        let enoexec = |_: elf::Error| failed(Errno::ENOEXEC);
        // Magic, e_type, elf_check_arch, e_phentsize, e_phnum, table bytes.
        let image = Elf::linux_x86_64(file).map_err(enoexec)?;
        match image.interpreter() {
            Ok(None) => {}
            Ok(Some(_)) => return Err(LoadError::Unsupported(Unsupported::Interpreter)),
            Err(elf::Error::Bounds(_)) => return Err(failed(Errno::EIO)),
            Err(_) => return Err(failed(Errno::ENOEXEC)),
        }
        let exec_stack = image.executable_stack().map_err(enoexec)? == Some(true);
        if image.header().file_type == ET_DYN {
            return Err(LoadError::Unsupported(Unsupported::SharedObject));
        }

        let phoff = image.header().program_offset;
        let mut plan = Self {
            entry: image.header().entry,
            phdr: 0,
            phnum: image.header().program_count,
            brk: 0,
            exec_stack,
            vmas: Vmas::default(),
            segments: [Segment::default(); MAX_LOADS],
            loads: 0,
        };
        let mut elf_brk = 0u64;
        for index in 0..plan.phnum {
            let header = image.program(index).map_err(enoexec)?;
            if header.kind != PT_LOAD {
                continue;
            }
            if plan.loads == MAX_LOADS {
                return Err(LoadError::Unsupported(Unsupported::TooManyLoads));
            }
            let segment = plan.map_segment(&header, file.len() as u64)?;
            // Figure out which segment contains the program header table.
            if header.offset <= phoff && phoff < header.offset.wrapping_add(header.file_size) {
                plan.phdr = (phoff - header.offset).wrapping_add(header.virtual_address);
            }
            // Post-mapping TASK_SIZE checks (BAD_ADDR and overflow guards).
            let (k, filesz, memsz) = (header.virtual_address, header.file_size, header.memory_size);
            if k >= TASK_SIZE_MAX
                || filesz > memsz
                || memsz > TASK_SIZE_MAX
                || TASK_SIZE_MAX - memsz < k
            {
                return Err(failed(Errno::EINVAL));
            }
            // Replacing earlier pages (MAP_FIXED) is not modelled: fail loudly.
            let overlaps = |other_start: u64, other_end: u64| {
                segment.pages() != 0 && segment.start < other_end && other_start < segment.end()
            };
            if overlaps(STACK_START, STACK_TOP)
                || plan
                    .segments()
                    .iter()
                    .any(|other| overlaps(other.start, other.end()))
            {
                return Err(LoadError::Unsupported(Unsupported::Overlap));
            }
            elf_brk = elf_brk.max(k + memsz);
            if segment.file_pages > 0 {
                plan.vmas.push(
                    segment.start,
                    segment.start + segment.file_pages * PAGE,
                    segment.file_offset / PAGE,
                    segment.prot,
                );
            }
            plan.segments[plan.loads] = segment;
            plan.loads += 1;
        }
        if plan.entry >= TASK_SIZE_MAX {
            return Err(failed(Errno::EINVAL));
        }
        plan.brk = page_align(elf_brk);
        Ok(plan)
    }

    #[must_use]
    pub fn segments(&self) -> &[Segment] {
        &self.segments[..self.loads]
    }

    /// `elf_load()` up to (not including) the post-mapping checks.
    fn map_segment(
        &self,
        header: &elf::ProgramHeader,
        file_len: u64,
    ) -> Result<Segment, LoadError> {
        let prot = Prot {
            read: header.flags & PF_R != 0,
            write: header.flags & PF_W != 0,
            exec: header.flags & PF_X != 0,
        };
        let (vaddr, filesz, memsz) = (header.virtual_address, header.file_size, header.memory_size);
        let page_offset = vaddr & (PAGE - 1);
        let map_start = page_start(vaddr);
        let mut segment = Segment {
            start: map_start,
            prot,
            ..Segment::default()
        };
        let (mut zero_start, mut zero_end);
        if filesz != 0 {
            // elf_map(): a wrapped size of zero maps nothing (and then fails
            // the post-mapping checks, as no valid segment wraps).
            let size = page_align(filesz.wrapping_add(page_offset));
            let offset = header.offset.wrapping_sub(page_offset);
            if size != 0 {
                // vm_mmap(), then do_mmap() (its pgoff overflow test cannot fire
                // after vm_mmap's), then file_mmap_ok() (ramfs s_maxbytes).
                if offset.wrapping_add(size) < offset || offset & (PAGE - 1) != 0 {
                    return Err(failed(Errno::EINVAL));
                }
                vm_fixed(map_start, size)?;
                // Only the first segment is MAP_FIXED_NOREPLACE.
                if self.loads == 0 && map_start < STACK_TOP && map_start + size > STACK_START {
                    return Err(failed(Errno::EEXIST));
                }
                if size > MAX_LFS_FILESIZE || offset / PAGE > (MAX_LFS_FILESIZE - size) / PAGE {
                    return Err(failed(Errno::EOVERFLOW));
                }
                segment.file_pages = size / PAGE;
                segment.file_offset = offset;
                if offset.saturating_add((segment.file_pages - 1) * PAGE) >= file_len {
                    return Err(LoadError::Unsupported(Unsupported::BeyondEof));
                }
            }
            zero_start = map_start.wrapping_add(page_offset).wrapping_add(filesz);
            zero_end = map_start.wrapping_add(page_offset).wrapping_add(memsz);
            // padzero(): clear_user() faults on a read-only mapping and the
            // error is ignored then, so only writable segments are zeroed.
            if memsz > filesz && prot.write && zero_start & (PAGE - 1) != 0 {
                segment.zero_from = zero_start;
            }
        } else {
            zero_start = map_start;
            zero_end = zero_start.wrapping_add(page_offset).wrapping_add(memsz);
        }
        if memsz > filesz {
            zero_start = page_align(zero_start);
            zero_end = page_align(zero_end);
            let length = zero_end.wrapping_sub(zero_start);
            if length != 0 {
                // vm_brk_flags(): check_brk_limits -> get_unmapped_area(MAP_FIXED).
                vm_fixed(zero_start, length)?;
                segment.anon_pages = length / PAGE;
                if segment.file_pages == 0 {
                    segment.start = zero_start;
                }
            }
        }
        Ok(segment)
    }
}

#[cfg(test)]
pub(crate) mod tests;
