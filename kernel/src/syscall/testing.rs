// SPDX-License-Identifier: GPL-2.0-only
//! Host fakes for the syscall tests: a task whose user memory is the sparse
//! `usercopy::fake::Space` and whose console collects bytes.

use super::{
    Console, Context, Machine,
    time::{ClockState, Clocks},
};
use crate::{
    cputime::CpuSample,
    task::Attributes,
    usercopy::{UserPages, fake::Space},
};
extern crate std;
use std::vec::Vec;

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
    /// Offsets passed to `set_real_offset_ns`.
    pub set: Vec<i64>,
}

impl Default for FakeClocks {
    fn default() -> Self {
        Self {
            state: ClockState {
                mono_ns: 5_123_456_789,
                boot_offset_ns: 0,
                real_offset_ns: 1_800_000_000_000_000_000,
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
}

impl<P, C> Task<P, C> {
    pub fn new(pages: P, sink: C) -> Self {
        Self {
            pages,
            sink,
            tgid: 1,
            attrs: Attributes::init(1000),
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
        }
    }
}

pub fn task() -> Task {
    Task::new(Space::default(), Sink::default())
}

impl<P: UserPages, C> UserPages for Task<P, C> {
    fn page(&mut self, page: u64, write: bool) -> Option<&mut [u8; 4096]> {
        self.pages.page(page, write)
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
}

impl<P, C> Clocks for Task<P, C> {
    fn clock_state(&self) -> ClockState {
        self.clocks.state
    }
    fn set_real_offset_ns(&mut self, offset: i64) {
        self.clocks.set.push(offset);
        self.clocks.state.real_offset_ns = offset;
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
