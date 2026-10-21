// SPDX-License-Identifier: GPL-2.0-only AND (GPL-2.0 WITH Linux-syscall-note)
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: fs/binfmt_elf.c
// (`load_elf_binary`, `elf_load`, `elf_map`, `padzero`, `make_prot`; GPL-2.0-only,
// Copyright 1993, 1994: Eric Youngdale), arch/x86/include/asm/elf.h and
// page_64_types.h (GPL-2.0). Constants from include/uapi/linux/elf.h
// (GPL-2.0 WITH Linux-syscall-note).
// Transformation: this file keeps only the binfmt_elf side (header and program
// table acceptance, the arithmetic of `elf_load`); every mapping rule
// (`do_mmap`, `__get_unmapped_area`, `vm_brk_flags` checks, `MAP_FIXED`
// replacement, `-EEXIST`/`-EOVERFLOW`/`-ENOMEM`) is the address-space model's
// (`crate::mm`), driven by `super::load`. The page-level content of every file
// page is computed so the freestanding loader can fill owned frames without a
// page cache.
#![forbid(unsafe_code)]
//! ELF acceptance and load plan for a static `ET_EXEC` x86-64 `/init`.
//!
//! Linux order is kept: header and program-table checks (all `-ENOEXEC`), the
//! `PT_INTERP` scan, `PT_GNU_STACK`; the `PT_LOAD` segments are then described
//! ([`Segment`]) and [`super::load`] maps them one by one through the
//! address-space model, followed by the post-mapping `TASK_SIZE` checks
//! (`-EINVAL`) and finally the entry check. `load_bias` is zero (`ET_EXEC`). Unsigned
//! arithmetic wraps exactly where the C does, so hostile sizes take the same
//! branch Linux takes.
//!
//! `ET_DYN` images and `PT_INTERP` are planned here and placed by [`super::load`]: the plan keeps
//! the unbiased numbers (`total_mapping_size`, `maximum_alignment`), the bias is chosen when the
//! first segment is mapped. The interpreter is an [`InterpPlan`] built from the file the caller
//! opened (`open_exec`), with the `-ELIBBAD`/`-EIO` order of `load_elf_binary`.
//!
//! # Differences from Linux (all explicit, none silent)
//! * `PT_GNU_PROPERTY` is not read: `CONFIG_ARCH_USE_GNU_PROPERTY` is not selected on x86
//!   (`arch/x86/Kconfig`), so `parse_elf_properties` returns 0 before looking at the note.
//! * shortcut: a later `MAP_FIXED` segment that replaces the argument stack
//!   fails with [`Unsupported::Overlap`] (Linux runs on with the clobbered
//!   stack); replacing other segments' pages is exact (the model unmaps them).
//! * shortcut: a file mapping whose last page starts at or beyond EOF fails
//!   with [`Unsupported::BeyondEof`]; Linux maps it and raises `SIGBUS` on use.
//! * shortcut: at most [`MAX_LOADS`] `PT_LOAD` segments (Linux: 1170).
//! * `PF_X`/`PF_W` without `PF_R` map readable too: x86 has no write-only page and, without
//!   protection keys, no execute-only page. With them (`Env::ospke`) a `PF_X`-only segment is
//!   [`Unsupported::ExecuteOnlyPkey`] (a loud stop: Linux gives it the execute-only key).
//! * `p_flags == 0` segments are `PROT_NONE`: accounted for, never mapped.
//! * No randomisation: this is Linux with `norandmaps` (`randomize_va_space=0`).

use crate::{
    image::elf::{self, Elf, PF_R, PF_W, PF_X, PT_LOAD},
    memory::PAGE,
};
use syscalls::Errno;

pub const MAX_LOADS: usize = 16;
/// `ELF_ET_DYN_BASE` for a 64-bit task: `DEFAULT_MAP_WINDOW / 3 * 2`.
pub const ELF_ET_DYN_BASE: u64 = crate::mm::DEFAULT_MAP_WINDOW / 3 * 2;
/// `sizeof(struct elf_phdr)` for `AT_PHENT`.
pub const PHENT: u64 = 56;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unsupported {
    /// An `ET_DYN` image where the caller (the boot loader) cannot place one.
    SharedObject,
    /// A `PT_INTERP` image where the caller (the boot loader) cannot load an interpreter.
    Interpreter,
    Overlap,
    BeyondEof,
    TooManyLoads,
    /// A `#!` script whose interpreter exists in the rootfs.
    Script,
    /// A `PF_X`-only segment with protection keys on: `do_mmap` gives it the execute-only key.
    ExecuteOnlyPkey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadError {
    /// What Linux's `execve` returns.
    Errno(Errno),
    /// Valid for Linux, outside this slice.
    Unsupported(Unsupported),
}

pub(super) const fn failed(errno: Errno) -> LoadError {
    LoadError::Errno(errno)
}

pub(super) const fn page_start(value: u64) -> u64 {
    value & !(PAGE - 1)
}
pub(super) const fn page_align(value: u64) -> u64 {
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

/// One `PT_LOAD`, with the arithmetic of `elf_load`/`elf_map` evaluated (wrapping
/// where the C wraps) but no mapping rule applied: [`super::load`] hands these
/// numbers to the address-space model, which decides.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Segment {
    pub prot: Prot,
    /// The raw header fields (`p_vaddr`, `p_filesz`, `p_memsz`, `p_offset`).
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub offset: u64,
    /// `ELF_PAGESTART(p_vaddr)`: where `elf_map` maps the file part.
    pub start: u64,
    /// Pages `elf_map` maps from the file at `file_offset` (`p_offset` minus the
    /// page offset); zero when `p_filesz` is zero or the size wraps to zero.
    pub file_pages: u64,
    pub file_offset: u64,
    /// The `vm_brk_flags(anon_start, anon_len)` request (bss); length 0 = none.
    pub anon_start: u64,
    pub anon_len: u64,
    /// `padzero()` target: bytes from here to the end of its page are zeroed.
    /// Zero when Linux would not (aligned, no bss, or a read-only mapping).
    zero_from: u64,
}

impl Segment {
    /// `elf_load()`/`elf_map()` arithmetic for one header.
    fn new(header: &elf::ProgramHeader) -> Self {
        let prot = Prot {
            read: header.flags & PF_R != 0,
            write: header.flags & PF_W != 0,
            exec: header.flags & PF_X != 0,
        };
        let (vaddr, filesz, memsz) = (header.virtual_address, header.file_size, header.memory_size);
        let page_offset = vaddr & (PAGE - 1);
        let map_start = page_start(vaddr);
        let mut segment = Self {
            prot,
            vaddr,
            filesz,
            memsz,
            offset: header.offset,
            start: map_start,
            ..Self::default()
        };
        let (mut zero_start, mut zero_end);
        if filesz != 0 {
            // elf_map(): a wrapped size of zero maps nothing (and then fails
            // the post-mapping checks, as no valid segment wraps).
            let size = page_align(filesz.wrapping_add(page_offset));
            if size != 0 {
                segment.file_pages = size / PAGE;
                segment.file_offset = header.offset.wrapping_sub(page_offset);
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
            segment.anon_start = zero_start;
            segment.anon_len = zero_end.wrapping_sub(zero_start);
        }
        segment
    }

    /// Contents of file page `index`: the file bytes of that page (zero past
    /// EOF), then `padzero()`. `out` is exactly one page.
    pub fn fill_page(&self, file: &[u8], index: u64, out: &mut [u8]) {
        out.fill(0);
        if index < self.file_pages {
            // `start` is the unbiased page start and an `ET_DYN` interpreter's `vaddr` may lie
            // anywhere (only the biased address is range checked), so these wrap like the C.
            let from = self.file_offset.wrapping_add(index * PAGE);
            if let Some(tail) = usize::try_from(from).ok().and_then(|from| file.get(from..)) {
                let count = tail.len().min(out.len());
                out[..count].copy_from_slice(&tail[..count]);
            }
            let last = self.start.wrapping_add(index * PAGE);
            if self.zero_from != 0 && page_start(self.zero_from) == last {
                // Below one page by construction.
                #[allow(clippy::cast_possible_truncation)]
                out[(self.zero_from - last) as usize..].fill(0);
            }
        }
    }
}

/// `total_mapping_size`: the span from the lowest page start to the highest end of the `PT_LOAD`s
/// (zero without any), wrapping where the C does.
fn total_mapping_size(segments: &[Segment]) -> u64 {
    if segments.is_empty() {
        return 0;
    }
    let min = segments.iter().map(|s| s.start).min().unwrap_or(u64::MAX);
    let max = segments
        .iter()
        .map(|s| s.vaddr.wrapping_add(s.memsz))
        .max()
        .unwrap_or(0);
    max.wrapping_sub(min)
}

/// `maximum_alignment`: the largest power-of-two `p_align` of a `PT_LOAD`, page aligned (a page
/// when none is valid).
fn maximum_alignment(aligns: impl Iterator<Item = u64>) -> u64 {
    let widest = aligns.filter(|a| a.is_power_of_two()).max().unwrap_or(0);
    page_align(widest)
}

#[derive(Clone, Copy, Debug)]
pub struct LoadPlan {
    /// `e_type`: `ET_EXEC` or `ET_DYN`.
    pub file_type: u16,
    /// `e_entry`, not biased.
    pub entry: u64,
    /// `AT_PHDR` before the bias: zero when no segment maps the program-header table.
    pub phdr: u64,
    pub phnum: u16,
    /// `PT_GNU_STACK` with `PF_X` (the 64-bit default is non-executable).
    pub exec_stack: bool,
    /// The image names an interpreter (`PT_INTERP`): [`LoadPlan::interpreter`].
    pub has_interpreter: bool,
    /// `total_mapping_size` and `maximum_alignment` of the `PT_LOAD`s (used for `ET_DYN`).
    pub total_size: u64,
    pub alignment: u64,
    segments: [Segment; MAX_LOADS],
    loads: usize,
}

impl LoadPlan {
    /// # Errors
    /// The `execve` errno Linux 6.18.57 returns for the same header bytes, or
    /// an explicit [`Unsupported`] for valid input this slice does not load.
    /// Mapping errors come later, from [`super::load::map_image`].
    pub fn new(file: &[u8]) -> Result<Self, LoadError> {
        let enoexec = |_: elf::Error| failed(Errno::ENOEXEC);
        // Magic, e_type, elf_check_arch, e_phentsize, e_phnum, table bytes.
        let image = Elf::linux_x86_64(file).map_err(enoexec)?;
        let has_interpreter = match image.interpreter() {
            Ok(path) => path.is_some(),
            Err(elf::Error::Bounds(_)) => return Err(failed(Errno::EIO)),
            Err(_) => return Err(failed(Errno::ENOEXEC)),
        };
        let exec_stack = image.executable_stack().map_err(enoexec)? == Some(true);

        let phoff = image.header().program_offset;
        let mut plan = Self {
            file_type: image.header().file_type,
            entry: image.header().entry,
            phdr: 0,
            phnum: image.header().program_count,
            exec_stack,
            has_interpreter,
            total_size: 0,
            alignment: 0,
            segments: [Segment::default(); MAX_LOADS],
            loads: 0,
        };
        let mut aligns = [0u64; MAX_LOADS];
        for index in 0..plan.phnum {
            let header = image.program(index).map_err(enoexec)?;
            if header.kind != PT_LOAD {
                continue;
            }
            if plan.loads == MAX_LOADS {
                return Err(LoadError::Unsupported(Unsupported::TooManyLoads));
            }
            // Figure out which segment in the file contains the Program Header
            // table (mapping success is the loader's business: same value).
            if header.offset <= phoff && phoff < header.offset.wrapping_add(header.file_size) {
                plan.phdr = (phoff - header.offset).wrapping_add(header.virtual_address);
            }
            aligns[plan.loads] = header.alignment;
            plan.segments[plan.loads] = Segment::new(&header);
            plan.loads += 1;
        }
        plan.total_size = total_mapping_size(plan.segments());
        plan.alignment = maximum_alignment(aligns[..plan.loads].iter().copied());
        Ok(plan)
    }

    #[must_use]
    pub fn segments(&self) -> &[Segment] {
        &self.segments[..self.loads]
    }

    /// The first `PT_INTERP` string of `file` (the one [`LoadPlan::new`] validated), up to its
    /// first NUL: `elf_interpreter` is used as a C string by `open_exec`. `None` for an image
    /// without one.
    #[must_use]
    pub fn interpreter(file: &[u8]) -> Option<&[u8]> {
        Elf::linux_x86_64(file).ok()?.interpreter().ok().flatten()
    }
}

/// The interpreter image, validated the way `load_elf_binary` does before `begin_new_exec`, with
/// the numbers `load_elf_interp` needs afterwards.
#[derive(Clone, Copy, Debug)]
pub struct InterpPlan {
    /// `e_type` (checked by [`super::load`] after the point of no return, as Linux does).
    pub file_type: u16,
    /// `e_entry`, not biased.
    pub entry: u64,
    pub total_size: u64,
    segments: [Segment; MAX_LOADS],
    loads: usize,
}

impl InterpPlan {
    /// `elf_read` of the header, the `ELFMAG`/`elf_check_arch` checks and `load_elf_phdrs` of
    /// the interpreter. Every failure after the header read is `-ELIBBAD` (`load_elf_binary`
    /// keeps that value when `load_elf_phdrs` returns `NULL`).
    ///
    /// # Errors
    /// `EIO` (a file shorter than the header), `ELIBBAD`, or an [`Unsupported`] case.
    pub fn new(file: &[u8]) -> Result<Self, LoadError> {
        let libbad = |_: elf::Error| failed(Errno::ELIBBAD);
        if file.len() < 64 {
            return Err(failed(Errno::EIO));
        }
        // Magic and machine; the class and byte order are not looked at (`elf_check_arch` is
        // `e_machine == EM_X86_64`).
        let image = Elf::parse_as(file, elf::Class::Elf64, crate::image::bytes::Endian::Little)
            .map_err(libbad)?;
        let header = image.header();
        if header.ident[..4] != *b"\x7fELF" || header.machine != elf::EM_X86_64 {
            return Err(failed(Errno::ELIBBAD));
        }
        // load_elf_phdrs
        let table = u64::from(header.program_entry_size) * u64::from(header.program_count);
        if header.program_entry_size != elf::Class::Elf64.program_bytes()
            || table == 0
            || table > 65536
        {
            return Err(failed(Errno::ELIBBAD));
        }
        let mut plan = Self {
            file_type: header.file_type,
            entry: header.entry,
            total_size: 0,
            segments: [Segment::default(); MAX_LOADS],
            loads: 0,
        };
        for index in 0..header.program_count {
            let program = image.program(index).map_err(libbad)?;
            if program.kind != PT_LOAD {
                continue;
            }
            if plan.loads == MAX_LOADS {
                return Err(LoadError::Unsupported(Unsupported::TooManyLoads));
            }
            plan.segments[plan.loads] = Segment::new(&program);
            plan.loads += 1;
        }
        plan.total_size = total_mapping_size(plan.segments());
        Ok(plan)
    }

    #[must_use]
    pub fn segments(&self) -> &[Segment] {
        &self.segments[..self.loads]
    }
}

#[cfg(test)]
pub(crate) mod tests;
