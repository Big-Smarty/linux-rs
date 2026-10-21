// SPDX-License-Identifier: GPL-2.0-only
//! `procfs` group, part three: how a private writable file mapping is counted. Linux 6.18.57:
//! `mm/memory.c` (`do_read_fault`, `do_cow_fault`, `do_wp_page`, `wp_page_copy`, `finish_fault`,
//! `set_pte_range`, `mm_counter_file`), `mm/filemap.c` (`filemap_map_pages`), `mm/shmem.c`
//! (`shmem_vm_ops`), `fs/proc/task_mmu.c` (`task_mem`), `fs/proc/array.c` (`proc_pid_statm`).
//!
//! A read fault of a `MAP_PRIVATE | PROT_WRITE` file mapping maps the page-cache page read-only
//! (`do_read_fault`, fault-around included), so it is a file or shmem page (`RssShmem` on tmpfs); a
//! write fault of an absent page (`do_cow_fault`) or of a page the read fault mapped
//! (`do_wp_page` -> `wp_page_copy`) leaves a private anonymous copy (`RssAnon`) and gives the file
//! page back (`dec_mm_counter(mm_counter_file(old))`); `mprotect` does not change either class.
//!
//! Every expectation was recorded on the pinned Linux first.

use syscalls::Sysno;

use super::{
    O_CREAT, O_RDONLY, O_RDWR, Page, T, addr, addr_mut, c, close, getpid, open, pid_text,
    status_kb, sys,
};

const PAGES: usize = 16;
const PROT_READ: usize = 1;
const PROT_WRITE: usize = 2;
const MAP_PRIVATE: usize = 2;

/// `(RssAnon, RssFile, RssShmem)` in kB and `statm`'s `(resident, shared)` in pages.
fn counters(page: &mut Page) -> [i64; 5] {
    let me = getpid();
    let status = pid_text(me, "status", page).unwrap_or_default();
    let kb = |key| status_kb(status, key) as i64;
    let (anon, file, shmem) = (kb("RssAnon"), kb("RssFile"), kb("RssShmem"));
    let statm = pid_text(me, "statm", page).unwrap_or_default();
    let field = |n| super::num(super::field(statm.trim_ascii_end(), b' ', n)).unwrap_or(0) as i64;
    [anon, file, shmem, field(1), field(2)]
}

fn since(now: [i64; 5], before: [i64; 5]) -> [i64; 5] {
    core::array::from_fn(|i| now[i] - before[i])
}

pub(super) fn private_file(t: &mut T) {
    let mut page: Page = [0; 16384];
    let path = "/rss-private-file";
    let fd = open(path, O_RDWR | O_CREAT).unwrap_or(99);
    let mut written = true;
    for i in 0..PAGES {
        let data = [i as u8 + 1; 4096];
        written &= sys(Sysno::write, &[fd, addr(&data), 4096]) == Ok(4096);
    }
    t.eq("rss-file-created", written, true);
    let _ = close(fd);
    let fd = open(path, O_RDONLY).unwrap_or(99);
    let base = counters(&mut page);

    let map = super::super::mmap(0, PAGES * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)
        .unwrap_or(0);
    t.eq("rss-file-mapped", map != 0, true);
    t.eq(
        "rss-file-map-resident-nothing",
        since(counters(&mut page), base),
        [0; 5],
    );

    // Reads only: the pages are the file's (fault-around only changes how many faults it takes).
    let mut data = true;
    for i in 0..PAGES {
        data &= super::super::peek(map + i * 4096 + 7) == i as u8 + 1;
    }
    t.eq("rss-file-read-data", data, true);
    t.eq(
        "rss-file-read-counters",
        since(counters(&mut page), base),
        [0, 0, 64, PAGES as i64, PAGES as i64],
    );

    // A write to every other page copies it: shmem -> anon, resident unchanged.
    for i in (0..PAGES).step_by(2) {
        super::super::poke(map + i * 4096 + 7, 0xee);
    }
    let split = [32, 0, 32, PAGES as i64, PAGES as i64 / 2];
    t.eq(
        "rss-file-write-counters",
        since(counters(&mut page), base),
        split,
    );
    let mut copy = true;
    let mut untouched = true;
    for i in 0..PAGES {
        let (first, byte) = (
            super::super::peek(map + i * 4096),
            super::super::peek(map + i * 4096 + 7),
        );
        copy &= first == i as u8 + 1 && byte == if i % 2 == 0 { 0xee } else { i as u8 + 1 };
        let mut file_byte = [0u8; 1];
        let n = sys(
            Sysno::pread64,
            &[fd, addr_mut(&mut file_byte), 1, i * 4096 + 7],
        );
        untouched &= n == Ok(1) && file_byte[0] == i as u8 + 1;
    }
    t.eq("rss-file-write-copy", copy, true);
    t.eq("rss-file-write-file-untouched", untouched, true);

    // mprotect changes the write permission, not what a page is.
    let _ = sys(Sysno::mprotect, &[map, PAGES * 4096, PROT_READ]);
    t.eq(
        "rss-file-protect-read-counters",
        since(counters(&mut page), base),
        split,
    );
    let _ = sys(
        Sysno::mprotect,
        &[map, PAGES * 4096, PROT_READ | PROT_WRITE],
    );
    t.eq(
        "rss-file-protect-write-counters",
        since(counters(&mut page), base),
        split,
    );
    // The copied pages stay private after the round trip, the others copy on their first write.
    super::super::poke(map + 7, 0x11);
    super::super::poke(map + 4096 + 7, 0x22);
    t.eq(
        "rss-file-rewrite-counters",
        since(counters(&mut page), base),
        [36, 0, 28, PAGES as i64, PAGES as i64 / 2 - 1],
    );

    // A write fault of an absent page copies it at once and never counts as the file's.
    let second =
        super::super::mmap(0, 4 * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0).unwrap_or(0);
    let before = counters(&mut page);
    for i in 0..4 {
        super::super::poke(second + i * 4096, 0x33);
    }
    t.eq(
        "rss-file-cow-counters",
        since(counters(&mut page), before),
        [16, 0, 0, 4, 0],
    );

    let _ = sys(Sysno::munmap, &[map, PAGES * 4096]);
    let _ = sys(Sysno::munmap, &[second, 4 * 4096]);
    t.eq(
        "rss-file-unmapped-counters",
        since(counters(&mut page), base),
        [0; 5],
    );
    let _ = close(fd);
    let _ = sys(Sysno::unlink, &[addr(&c(path))]);
}
