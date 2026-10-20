// SPDX-License-Identifier: GPL-2.0-only
#![no_std]
// `Vec::push_within_capacity`: the only way to grow a `Vec` under the kernel's
// `--cfg no_global_oom_handling` `alloc` (see `mm`).
#![feature(vec_push_within_capacity)]
//! Shared early-kernel contracts. Host tests execute the same pure parsers and
//! primitives as the freestanding entry; privileged code is in the gated binary.
pub mod bitmap;
pub mod boot;
pub mod config;
pub mod cputime;
pub mod exec;
pub mod fbtext;
pub mod firmware;
pub mod heap;
pub mod image;
pub mod intc;
pub mod loadavg;
pub mod memory;
extern crate alloc;
pub mod mm;
pub mod signal;
pub mod sync;
pub mod syscall;
pub mod task;
pub mod time;
pub mod usercopy;
pub mod vfs;
