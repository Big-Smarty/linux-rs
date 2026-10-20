// SPDX-License-Identifier: GPL-2.0-only
#![forbid(unsafe_code)]
//! Pure logic of the first-userspace slice (decision A18): locate `/init` in the
//! boot archives, validate and plan its ELF image, lay out its initial stack,
//! and format its death. Nothing here maps memory or enters ring 3; the
//! freestanding binary owns frames, page tables and privileged transitions.

pub mod args;
pub mod bprm;
pub mod load;
pub mod plan;
pub mod report;
pub mod script;
pub mod stack;
