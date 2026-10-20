// SPDX-License-Identifier: GPL-2.0-only
//! Host fakes for the syscall tests: a task whose user memory is the sparse
//! `usercopy::fake::Space`, whose console collects bytes, and whose files are a
//! real tmpfs rootfs (`/dev/console`, `/root`, optional extra entries) with
//! descriptors 0-2 on the console, as `console_on_rootfs` leaves init.

use super::{
    AddressSpace, Console, Context, Files, Machine,
    time::{ClockState, Clocks, RestartBlock},
};
use crate::{
    cputime::CpuSample,
    mm::{Env, Mm, VmFlags, tests::Fake},
    task::Attributes,
    usercopy::{UserPages, fake::Space},
    vfs::{FdTable, Timespec, Vfs},
};
extern crate std;
use std::{boxed::Box, collections::BTreeMap, vec::Vec};

#[derive(Default)]
pub struct Sink(pub Vec<u8>);
impl Console for Sink {
    fn write(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }
}

/// Scriptable timekeeper and CPU accounting for the time group.
pub struct FakeClocks {
    pub state: ClockState,
    pub sample: CpuSample,
    pub adjusted: (u64, u64),
    pub rtc: bool,
    pub capable: bool,
    /// The next sleep is interrupted with this many ns remaining.
    pub interrupt: Option<u64>,
    /// Deadlines passed to `sleep_until`.
    pub slept: Vec<u64>,
    /// Offsets passed to `set_realtime`.
    pub set: Vec<i64>,
    /// Every `restart_block` store, in order.
    pub restarts: Vec<RestartBlock>,
}

impl Default for FakeClocks {
    fn default() -> Self {
        Self {
            state: ClockState {
                mono_ns: 5_123_456_789,
                boot_offset_ns: 0,
                real_offset_ns: 1_800_000_000_000_000_000,
                settod_real_ns: 0,
            },
            sample: CpuSample {
                runtime_ns: 3_000_000,
                user_ns: 2_000_000,
                system_ns: 1_000_000,
            },
            adjusted: (2_000_000, 1_000_000),
            rtc: true,
            capable: true,
            interrupt: None,
            slept: Vec::new(),
            set: Vec::new(),
            restarts: Vec::new(),
        }
    }
}

pub struct Task<P = Space, C = Sink> {
    pub pages: P,
    pub sink: C,
    pub tgid: u32,
    pub attrs: Attributes,
    pub fs_base: u64,
    pub gs_base: u64,
    pub machine: Machine,
    pub cpuid_fault_absent: bool,
    pub clocks: FakeClocks,
    /// The address space the memory syscalls edit, over the model's fake tables.
    pub mm: Mm,
    pub env: Env,
    pub tables: Fake,
    pub vfs: Vfs,
    pub fdt: FdTable,
    /// Private copies of file pages a kernel access faulted in (the binary's
    /// `user_fault` for `NeedsFile`: `Vfs::fault_page`, then a private frame).
    pub file_pages: BTreeMap<u64, Box<[u8; 4096]>>,
}

fn clock() -> Timespec {
    Timespec { sec: 0, nsec: 0 }
}

impl<P, C> Task<P, C> {
    pub fn new(pages: P, sink: C) -> Self {
        let env = Env::init(1 << 17, 0);
        let mut vfs = Vfs::new(1 << 20, 1 << 20, clock).expect("rootfs");
        vfs.default_rootfs().expect("default rootfs");
        let mut fdt = FdTable::default();
        vfs.console_on_rootfs(&mut fdt).expect("console");
        let mut attrs = Attributes::init(1000);
        attrs.fs = vfs.new_fs_struct(0o022);
        Self {
            pages,
            sink,
            tgid: 1,
            attrs,
            fs_base: 0,
            gs_base: 0,
            machine: Machine {
                uptime_ns: 0,
                total_pages: 100,
                free_pages: 40,
                loads: [0; 3],
            },
            cpuid_fault_absent: false,
            clocks: FakeClocks::default(),
            mm: Mm::new(&env),
            env,
            tables: Fake::default(),
            vfs,
            fdt,
            file_pages: BTreeMap::new(),
        }
    }
}

pub fn task() -> Task {
    Task::new(Space::default(), Sink::default())
}

impl<P: UserPages, C> UserPages for Task<P, C> {
    fn page(&mut self, page: u64, write: bool) -> Option<&mut [u8; 4096]> {
        if self.pages.page(page, write).is_some() {
            return self.pages.page(page, write);
        }
        // A page of a private file mapping is supplied on first access.
        let vma = *self.mm.find_vma_intersection(page, page + 4096)?;
        let file = vma.file?;
        if !vma
            .flags
            .contains(if write { VmFlags::WRITE } else { VmFlags::READ })
        {
            return None;
        }
        if !self.file_pages.contains_key(&page) {
            let mut bytes = Box::new([0u8; 4096]);
            let pgoff = vma.pgoff + ((page - vma.start) >> 12);
            self.vfs.fault_page(file, pgoff, &mut bytes).ok()?;
            self.file_pages.insert(page, bytes);
        }
        self.file_pages.get_mut(&page).map(|bytes| &mut **bytes)
    }
}

impl<P: UserPages, C: Console> Context for Task<P, C> {
    fn console(&mut self) -> &mut dyn Console {
        &mut self.sink
    }
    fn tgid(&self) -> u32 {
        self.tgid
    }
    fn tid(&self) -> u32 {
        self.tgid
    }
    fn attrs(&mut self) -> &mut Attributes {
        &mut self.attrs
    }
    fn fs_base(&self) -> u64 {
        self.fs_base
    }
    fn set_fs_base(&mut self, base: u64) {
        self.fs_base = base;
    }
    fn gs_base(&self) -> u64 {
        self.gs_base
    }
    fn set_gs_base(&mut self, base: u64) {
        self.gs_base = base;
    }
    fn machine(&self) -> Machine {
        self.machine
    }
    fn cpuid_fault_absent(&self) -> bool {
        self.cpuid_fault_absent
    }
    fn address_space(&mut self) -> AddressSpace<'_> {
        AddressSpace {
            mm: &mut self.mm,
            env: &self.env,
            pages: &mut self.tables,
        }
    }
    fn files(&mut self) -> Files<'_> {
        Files {
            vfs: &mut self.vfs,
            fdt: &mut self.fdt,
            fs: &mut self.attrs.fs,
        }
    }
}

impl<P, C> Clocks for Task<P, C> {
    fn clock_state(&self) -> ClockState {
        self.clocks.state
    }
    fn set_realtime(&mut self, offset: i64, real_ns: i64) {
        self.clocks.set.push(offset);
        self.clocks.state.real_offset_ns = offset;
        self.clocks.state.settod_real_ns = real_ns;
    }
    fn set_restart_block(&mut self, block: RestartBlock) {
        self.clocks.restarts.push(block);
    }
    fn cpu_sample(&self) -> CpuSample {
        self.clocks.sample
    }
    fn cpu_adjusted(&mut self) -> (u64, u64) {
        self.clocks.adjusted
    }
    fn sleep_until(&mut self, deadline_ns: u64) -> Option<u64> {
        self.clocks.slept.push(deadline_ns);
        self.clocks.interrupt.take()
    }
    fn capable_sys_time(&self) -> bool {
        self.clocks.capable
    }
    fn capable_wake_alarm(&self) -> bool {
        self.clocks.capable
    }
    fn alarm_rtc(&self) -> bool {
        self.clocks.rtc
    }
}
