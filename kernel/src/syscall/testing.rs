// SPDX-License-Identifier: GPL-2.0-only
//! Host fakes for the syscall tests: a task whose user memory is the sparse
//! `usercopy::fake::Space` and whose console collects bytes.

use super::{Console, Context};
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
}

impl<P, C> Task<P, C> {
    pub fn new(pages: P, sink: C) -> Self {
        Self {
            pages,
            sink,
            tgid: 1,
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
}
