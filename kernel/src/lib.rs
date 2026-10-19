// SPDX-License-Identifier: GPL-2.0-only
#![no_std]
//! Shared early-kernel contracts. Host tests execute the same pure parsers and
//! primitives as the freestanding entry; privileged code is in the gated binary.
pub mod bitmap;
pub mod boot;
pub mod firmware;
pub mod image;
pub mod memory;
pub mod sync;
