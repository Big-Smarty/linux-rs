// SPDX-License-Identifier: GPL-2.0-only
// Replaces the pointer identity that Linux gives `struct task_struct` and
// `struct pid` (kernel/fork.c `dup_task_struct`, kernel/pid.c `alloc_pid`) with
// a generation-checked index, so a freed object's id can never alias a later
// object (RCU-protected pointers stay valid in Linux until a grace period; an
// id here simply stops resolving).
#![forbid(unsafe_code)]
//! A generational arena with fallible growth.
//!
//! # Contract
//! * Context: any; no locks (the owner serialises access).
//! * Allocation: only [`Arena::try_reserve`] and [`Arena::try_insert`]
//!   allocate, and both report failure; [`Arena::insert_reserved`] never
//!   allocates, so code that must not fail after a publication point reserves
//!   first (`reserve`-before-publish, see `task::tasklist`).
//! * An [`Id`] resolves only while its slot still holds the object it was made
//!   for. Removal bumps the slot generation (wrapping; a slot is reused at most
//!   2^32 times before an old id could alias, far beyond `pid_max` churn).
//!
//! The crates `slab`, `slotmap` and `generational-arena` were rejected because
//! their insertion grows infallibly (`docs/dependencies.md`).

use alloc::{collections::TryReserveError, vec::Vec};
use core::{
    fmt,
    hash::{Hash, Hasher},
    marker::PhantomData,
};

/// A handle to an object of type `T` in an [`Arena`].
pub struct Id<T> {
    index: u32,
    generation: u32,
    marker: PhantomData<fn() -> T>,
}

impl<T> Clone for Id<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for Id<T> {}
impl<T> PartialEq for Id<T> {
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index && self.generation == other.generation
    }
}
impl<T> Eq for Id<T> {}
impl<T> Hash for Id<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.index.hash(state);
        self.generation.hash(state);
    }
}
impl<T> fmt::Debug for Id<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Id({}v{})", self.index, self.generation)
    }
}

impl<T> Id<T> {
    /// A handle that never resolves (no arena has `u32::MAX` slots), for a
    /// field that is filled in right after construction.
    pub const DANGLING: Self = Self {
        index: u32::MAX,
        generation: u32::MAX,
        marker: PhantomData,
    };

    /// The slot number, for diagnostics only (it is reused after removal).
    #[must_use]
    pub const fn slot(self) -> u32 {
        self.index
    }
}

enum Entry<T> {
    Used(T),
    /// The next free slot, if any (an intrusive free list).
    Free(Option<u32>),
}

struct Slot<T> {
    generation: u32,
    entry: Entry<T>,
}

/// Slots addressed by generation-checked [`Id`]s.
pub struct Arena<T> {
    slots: Vec<Slot<T>>,
    free_head: Option<u32>,
    free_count: usize,
    len: usize,
}

impl<T> Default for Arena<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Arena<T> {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: Vec::new(),
            free_head: None,
            free_count: 0,
            len: 0,
        }
    }

    /// Live objects.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Insertions that [`Arena::insert_reserved`] can serve without allocating.
    #[must_use]
    pub fn spare(&self) -> usize {
        self.free_count + (self.slots.capacity() - self.slots.len())
    }

    /// Make [`Arena::spare`] at least `additional`.
    ///
    /// # Errors
    /// The allocation failed; nothing changed.
    pub fn try_reserve(&mut self, additional: usize) -> Result<(), TryReserveError> {
        let need = additional.saturating_sub(self.spare());
        if need > 0 {
            self.slots.try_reserve(need)?;
        }
        Ok(())
    }

    /// Insert without allocating.
    ///
    /// # Errors
    /// Gives `value` back when [`Arena::spare`] is zero.
    pub fn insert_reserved(&mut self, value: T) -> Result<Id<T>, T> {
        if let Some(index) = self.free_head {
            let slot = &mut self.slots[index as usize];
            let Entry::Free(next) = slot.entry else {
                unreachable!("free list points at a used slot");
            };
            slot.entry = Entry::Used(value);
            self.free_head = next;
            self.free_count -= 1;
            self.len += 1;
            return Ok(Id {
                index,
                generation: slot.generation,
                marker: PhantomData,
            });
        }
        let Ok(index) = u32::try_from(self.slots.len()) else {
            return Err(value);
        };
        match self.slots.push_within_capacity(Slot {
            generation: 0,
            entry: Entry::Used(value),
        }) {
            Ok(_) => {
                self.len += 1;
                Ok(Id {
                    index,
                    generation: 0,
                    marker: PhantomData,
                })
            }
            Err(slot) => match slot.entry {
                Entry::Used(value) => Err(value),
                Entry::Free(_) => unreachable!("built as used"),
            },
        }
    }

    /// Reserve one slot, then insert.
    ///
    /// # Errors
    /// Gives `value` back when the allocation failed.
    pub fn try_insert(&mut self, value: T) -> Result<Id<T>, T> {
        if self.try_reserve(1).is_err() {
            return Err(value);
        }
        self.insert_reserved(value)
    }

    fn slot(&self, id: Id<T>) -> Option<&Slot<T>> {
        self.slots
            .get(id.index as usize)
            .filter(|slot| slot.generation == id.generation)
    }

    #[must_use]
    pub fn get(&self, id: Id<T>) -> Option<&T> {
        match &self.slot(id)?.entry {
            Entry::Used(value) => Some(value),
            Entry::Free(_) => None,
        }
    }

    pub fn get_mut(&mut self, id: Id<T>) -> Option<&mut T> {
        match &mut self
            .slots
            .get_mut(id.index as usize)
            .filter(|slot| slot.generation == id.generation)?
            .entry
        {
            Entry::Used(value) => Some(value),
            Entry::Free(_) => None,
        }
    }

    /// Remove and return the object; `id` (and every copy of it) stops
    /// resolving.
    pub fn remove(&mut self, id: Id<T>) -> Option<T> {
        let slot = self
            .slots
            .get_mut(id.index as usize)
            .filter(|slot| slot.generation == id.generation)?;
        if matches!(slot.entry, Entry::Free(_)) {
            return None;
        }
        let Entry::Used(value) = core::mem::replace(&mut slot.entry, Entry::Free(self.free_head))
        else {
            unreachable!("checked used above");
        };
        slot.generation = slot.generation.wrapping_add(1);
        self.free_head = Some(id.index);
        self.free_count += 1;
        self.len -= 1;
        Some(value)
    }

    /// Live objects in slot order.
    pub fn iter(&self) -> impl Iterator<Item = (Id<T>, &T)> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| match &slot.entry {
                Entry::Used(value) => Some((
                    Id {
                        // `slots.len()` fits `u32`: `insert_reserved` refuses to grow past it.
                        index: u32::try_from(index).ok()?,
                        generation: slot.generation,
                        marker: PhantomData,
                    },
                    value,
                )),
                Entry::Free(_) => None,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::Arena;

    #[test]
    fn ids_go_stale_and_slots_are_reused_in_lifo_order() {
        let mut arena = Arena::new();
        let a = arena.try_insert("a").unwrap();
        let b = arena.try_insert("b").unwrap();
        assert_eq!(
            (arena.get(a), arena.get(b), arena.len()),
            (Some(&"a"), Some(&"b"), 2)
        );
        assert_eq!(arena.remove(a), Some("a"));
        assert_eq!(arena.remove(a), None, "double remove");
        assert_eq!(arena.get(a), None);
        let c = arena.try_insert("c").unwrap();
        // The slot is reused, but the stale id still does not resolve.
        assert_eq!(c.slot(), a.slot());
        assert_ne!(c, a);
        assert_eq!((arena.get(a), arena.get(c)), (None, Some(&"c")));
        assert!(arena.get_mut(a).is_none());
        assert_eq!(
            arena
                .iter()
                .map(|(_, v)| *v)
                .collect::<alloc::vec::Vec<_>>(),
            ["c", "b"]
        );
    }

    #[test]
    fn reserved_insertion_never_allocates() {
        let mut arena: Arena<u8> = Arena::new();
        arena.try_reserve(3).unwrap();
        assert!(arena.spare() >= 3);
        let capacity = arena.spare();
        let ids: alloc::vec::Vec<_> = (0..u8::try_from(capacity).unwrap())
            .map(|i| arena.insert_reserved(i).unwrap())
            .collect();
        assert_eq!(arena.spare(), 0);
        // Exhausted: the value comes back instead of growing.
        assert_eq!(arena.insert_reserved(99), Err(99));
        arena.remove(ids[0]);
        assert_eq!(arena.spare(), 1);
        assert!(arena.insert_reserved(7).is_ok());
    }
}
