// SPDX-License-Identifier: GPL-2.0-only AND GPL-2.0-or-later
//
// Bit-search algorithm ported from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692, lib/find_bit.c
// (original SPDX-License-Identifier: GPL-2.0-or-later).
// Original notices, including attribution for other functions in that file:
// Copyright (C) 2004 Red Hat, Inc. All Rights Reserved.
// Written by David Howells (dhowells@redhat.com)
// Copyright (C) 2008 IBM Corporation
// 'find_last_bit' is written by Rusty Russell <rusty@rustcorp.com.au>
// (Inspired by David Howell's find_next_bit implementation)
// Rewritten by Yury Norov <yury.norov@gmail.com> to decrease
// size and improve performance, 2015.
//
// The borrowed view, checked bounds and integration are GPL-2.0-only project
// material. The upstream grant is preserved, not relabelled or broadened.
// The 500-bit clear-iteration test fixture is ported from the same Linux commit,
// lib/test_bitmap.c (SPDX-License-Identifier: GPL-2.0-only).
//! Exclusive, non-atomic native-word bitmaps. This is not a wire-format decoder
//! or an atomic bitmap API: concurrent mutation requires separate exclusion.

pub const BITS_PER_WORD: usize = usize::BITS as usize;

/// A borrowed bitmap whose logical bits fit in initialized native-word storage.
/// Unused final-word bits and excess backing words are never logical members.
pub struct Bitmap<'a> {
    words: &'a mut [usize],
    bits: usize,
}

impl<'a> Bitmap<'a> {
    /// Returns `None` if storage is too short. No contents are changed, including
    /// for an empty view; the caller chooses the initial logical bit values.
    pub fn new(words: &'a mut [usize], bits: usize) -> Option<Self> {
        let words = words.get_mut(..bits.div_ceil(BITS_PER_WORD))?;
        Some(Self { words, bits })
    }

    #[must_use]
    pub const fn bit_count(&self) -> usize {
        self.bits
    }

    /// Reads one logical bit without exposing unused tail storage.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<bool> {
        (index < self.bits)
            .then(|| self.words[index / BITS_PER_WORD] & (1usize << (index % BITS_PER_WORD)) != 0)
    }

    /// Sets a half-open logical range. Invalid bounds leave all storage intact;
    /// unused tail bits and excess backing words are preserved.
    pub fn fill_range(&mut self, start: usize, end: usize, value: bool) -> bool {
        if start > end || end > self.bits {
            return false;
        }
        let mut cursor = start;
        while cursor < end {
            let shift = cursor % BITS_PER_WORD;
            let count = (BITS_PER_WORD - shift).min(end - cursor);
            let mask = (usize::MAX >> (BITS_PER_WORD - count)) << shift;
            let word = &mut self.words[cursor / BITS_PER_WORD];
            if value {
                *word |= mask;
            } else {
                *word &= !mask;
            }
            cursor += count;
        }
        true
    }

    /// Replaces one logical bit, returning its previous value. Out-of-range
    /// indices return `None` without modifying storage, including unused tails.
    pub fn replace(&mut self, index: usize, value: bool) -> Option<bool> {
        if index >= self.bits {
            return None;
        }
        let word = &mut self.words[index / BITS_PER_WORD];
        let mask = 1usize << (index % BITS_PER_WORD);
        let previous = *word & mask != 0;
        if value {
            *word |= mask;
        } else {
            *word &= !mask;
        }
        Some(previous)
    }

    /// Searches only `[start, min(end, bit_count()))`, returning that end
    /// sentinel if empty/full. Does not scan unrelated later bitmap regions.
    #[must_use]
    pub fn find_next_zero_in(&self, start: usize, end: usize) -> usize {
        let end = end.min(self.bits);
        if start >= end {
            return end;
        }
        let words_end = end.div_ceil(BITS_PER_WORD);
        let mut index = start / BITS_PER_WORD;
        let mut candidate = !self.words[index] & (usize::MAX << (start % BITS_PER_WORD));
        loop {
            if candidate != 0 {
                // This is an existing word; its base plus an in-word offset
                // fits usize even at the largest logical size.
                let bit = index * BITS_PER_WORD + candidate.trailing_zeros() as usize;
                return bit.min(end);
            }
            index += 1;
            if index == words_end {
                return end;
            }
            candidate = !self.words[index];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BITS_PER_WORD, Bitmap};

    #[test]
    fn storage_capacity_and_empty_views_do_not_mutate() {
        let mut empty_storage = [];
        let mut empty = Bitmap::new(&mut empty_storage, 0).expect("empty bitmap");
        assert_eq!(empty.bit_count(), 0);
        assert_eq!(empty.find_next_zero_in(0, 0), 0);
        assert_eq!(empty.find_next_zero_in(usize::MAX, usize::MAX), 0);
        assert_eq!(empty.replace(0, true), None);
        assert!(Bitmap::new(&mut empty_storage, 1).is_none());

        let mut words = [usize::MAX, 0];
        assert!(Bitmap::new(&mut words, 2 * BITS_PER_WORD + 1).is_none());
        assert!(Bitmap::new(&mut words, usize::MAX).is_none());
        assert_eq!(words, [usize::MAX, 0]);
        let empty = Bitmap::new(&mut words, 0).expect("empty view of nonempty storage");
        assert_eq!(empty.find_next_zero_in(1, 1), 0);
        assert_eq!(words, [usize::MAX, 0]);
    }

    #[test]
    fn next_zero_matches_independent_bitwise_search() {
        let alternating = usize::MAX / 3;
        let cases = [
            [0, 0, 0],
            [usize::MAX, usize::MAX, usize::MAX],
            [0, usize::MAX, 0],
            [usize::MAX, 0, usize::MAX],
            [alternating, !alternating, alternating],
            [1, 1usize << (BITS_PER_WORD - 1), usize::MAX - 1],
        ];
        for bits in 0..=3 * BITS_PER_WORD {
            for original in cases {
                let mut storage = original;
                let bitmap = Bitmap::new(&mut storage, bits).expect("sufficient storage");
                for start in 0..=bits + 1 {
                    let expected = (start..bits)
                        .find(|&bit| {
                            original[bit / BITS_PER_WORD] & (1usize << (bit % BITS_PER_WORD)) == 0
                        })
                        .unwrap_or(bits);
                    assert_eq!(
                        bitmap.find_next_zero_in(start, bits),
                        expected,
                        "bits={bits} start={start} words={original:?}"
                    );
                }
                assert_eq!(bitmap.find_next_zero_in(usize::MAX, bits), bits);
                assert_eq!(storage, original);
            }
        }
    }

    #[test]
    fn replace_returns_previous_and_preserves_other_bits_and_tail() {
        for bits in 0..=2 * BITS_PER_WORD + 3 {
            let mut storage = [usize::MAX; 4];
            storage[3] = usize::MAX / 7;
            let mut expected = storage;
            for bit in 0..bits {
                {
                    let mut bitmap = Bitmap::new(&mut storage, bits).expect("sufficient storage");
                    assert_eq!(bitmap.replace(bits, false), None);
                    assert_eq!(bitmap.replace(usize::MAX, false), None);
                    assert_eq!(bitmap.replace(bit, false), Some(true));
                    assert_eq!(bitmap.replace(bit, false), Some(false));
                    assert_eq!(bitmap.replace(bit, true), Some(false));
                    assert_eq!(bitmap.replace(bit, false), Some(true));
                }
                expected[bit / BITS_PER_WORD] &= !(1usize << (bit % BITS_PER_WORD));
                assert_eq!(storage, expected, "bits={bits} bit={bit}");
            }
        }
    }

    #[test]
    fn upstream_clear_bit_iteration_fixture() {
        const BITS: usize = 500;
        let mut storage = [usize::MAX; BITS.div_ceil(BITS_PER_WORD)];
        let mut bitmap = Bitmap::new(&mut storage, BITS).expect("fixture storage");
        for bit in (0..BITS).step_by(10).chain(100..150) {
            bitmap.replace(bit, false).expect("fixture bit");
        }
        for start in 0..BITS {
            let mut observed = [false; BITS];
            let mut cursor = start;
            loop {
                let bit = bitmap.find_next_zero_in(cursor, BITS);
                if bit == BITS {
                    break;
                }
                assert!(bit >= cursor && bit < BITS, "non-progressing iteration");
                observed[bit] = true;
                cursor = bit + 1;
            }
            for (bit, &found) in observed.iter().enumerate() {
                assert_eq!(
                    found,
                    bit >= start && (bit % 10 == 0 || (100..150).contains(&bit)),
                    "start={start} bit={bit}"
                );
            }
        }
    }

    #[test]
    fn range_updates_reads_and_bounded_search_preserve_neighbors() {
        const BITS: usize = 2 * BITS_PER_WORD + 3;
        for start in 0..=BITS {
            for end in start..=BITS {
                for value in [false, true] {
                    let original = [usize::MAX / 3; 4];
                    let mut storage = original;
                    let mut bitmap = Bitmap::new(&mut storage, BITS).expect("fixture");
                    assert!(!bitmap.fill_range(end + 1, start, value));
                    assert!(!bitmap.fill_range(0, BITS + 1, value));
                    assert!(!bitmap.fill_range(0, usize::MAX, value));
                    assert!(bitmap.fill_range(start, end, value));
                    for bit in 0..BITS {
                        let expected = if (start..end).contains(&bit) {
                            value
                        } else {
                            original[bit / BITS_PER_WORD] & (1 << (bit % BITS_PER_WORD)) != 0
                        };
                        assert_eq!(bitmap.get(bit), Some(expected));
                    }
                    assert_eq!(bitmap.get(BITS), None);
                    assert_eq!(bitmap.get(usize::MAX), None);
                    let expected = (start..end)
                        .find(|&bit| bitmap.get(bit) == Some(false))
                        .unwrap_or(end);
                    assert_eq!(bitmap.find_next_zero_in(start, end), expected);
                    assert_eq!(bitmap.find_next_zero_in(end, start), start);
                    assert_eq!(bitmap.find_next_zero_in(usize::MAX, usize::MAX), BITS);
                    assert_eq!(storage[2] >> 3, original[2] >> 3);
                    assert_eq!(storage[3], original[3]);
                }
            }
        }
    }
}
