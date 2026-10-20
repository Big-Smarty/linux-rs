// SPDX-License-Identifier: GPL-2.0-only
//! Host fakes for the syscall tests: a task whose user memory is the sparse
//! `usercopy::fake::Space` and whose console collects bytes.

use super::{Console, Context, Machine};
use crate::task::Attributes;
use crate::usercopy::{UserPages, fake::Space};
extern crate std;
use std::vec::Vec;

#[derive(Default)]
pub struct Sink(pub Vec<u8>);
impl Console for Sink {
    fn write(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
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
