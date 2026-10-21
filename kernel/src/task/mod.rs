// SPDX-License-Identifier: GPL-2.0-only
//! Tasks: the per-task attributes the identity syscalls read ([`attrs`]) and
//! the task list with its process tree ([`tasklist`], [`pid`], [`exit`],
//! [`wait`], [`jobctl`], [`ctty`], [`kill`], and the `clone` arguments of [`fork`]), a pure `forbid(unsafe_code)` model that
//! the binary drives and the host tests exercise.

pub mod attrs;
pub mod ctty;
pub mod dethread;
pub mod exit;
pub mod fork;
pub mod jobctl;
pub mod kill;
pub mod pid;
pub mod tasklist;
pub mod wait;

pub use attrs::*;
pub use tasklist::{CredSnapshot, TaskId, Tasklist};

#[cfg(test)]
mod tests;
