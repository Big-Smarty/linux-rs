// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: lib/cmdline.c (`next_arg`,
// GPL-2.0), kernel/params.c (`parse_args`, GPL-2.0), init/main.c
// (`set_init_arg`, `repair_env_string`, `argv_init`, `envp_init`, GPL-2.0-only),
// lib/ctype.c (`_ctype` whitespace set, GPL-2.0).
// Transformation: the in-place NUL-patching tokenizer becomes a non-mutating
// one that yields (param, value) pieces; `repair_env_string` becomes the
// piece-wise `Word` spelling `param[=value]`.
#![forbid(unsafe_code)]
//! Kernel command line to init's `argv`/`envp`.
//!
//! shortcut: only the words after a standalone `--` become `argv[1..]`. Linux
//! also forwards unknown `key=value` parameters to `envp` and unknown bare
//! words to `argv`, and honours `init=`/`rdinit=`; none of that is implemented.
//! Upgrade when a harness or user needs `rdinit=` or command-line environment.

/// `CONFIG_INIT_ENV_ARG_LIMIT` of the pinned reference configuration.
pub const MAX_INIT_ARGS: usize = 32;

/// One exec string as `param` or `param=value`, without NUL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Word<'a> {
    pub param: &'a [u8],
    pub value: Option<&'a [u8]>,
}

impl<'a> Word<'a> {
    #[must_use]
    pub const fn plain(text: &'a [u8]) -> Self {
        Self {
            param: text,
            value: None,
        }
    }
    /// Length without the terminating NUL.
    #[must_use]
    pub fn len(&self) -> usize {
        self.param.len() + self.value.map_or(0, |value| 1 + value.len())
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// The spelled-out bytes, in order.
    pub fn bytes(&self) -> impl Iterator<Item = u8> + 'a {
        let value = self.value;
        self.param
            .iter()
            .copied()
            .chain(value.map(|_| b'='))
            .chain(value.into_iter().flatten().copied())
    }
}

/// Linux `isspace`: HT LF VT FF CR, space and 0xA0 (see `_ctype`).
fn is_space(byte: u8) -> bool {
    matches!(byte, 9..=13 | b' ' | 0xa0)
}

fn skip_spaces(args: &[u8]) -> &[u8] {
    let start = args.iter().take_while(|&&b| is_space(b)).count();
    &args[start..]
}

/// `next_arg()`: one token and the remainder with leading spaces skipped.
fn next_arg(args: &[u8]) -> (Word<'_>, &[u8]) {
    let (args, quoted) = match args {
        [b'"', rest @ ..] => (rest, true),
        _ => (args, false),
    };
    let mut in_quote = quoted;
    let mut equals = 0;
    let mut end = 0;
    while end < args.len() {
        let byte = args[end];
        if is_space(byte) && !in_quote {
            break;
        }
        if equals == 0 && byte == b'=' {
            equals = end;
        }
        if byte == b'"' {
            in_quote = !in_quote;
        }
        end += 1;
    }
    // C overwrites a closing quote with NUL: the token then stops one earlier.
    let closing = end > 0 && args[end - 1] == b'"';
    let word = if equals == 0 {
        Word::plain(&args[..if quoted && closing { end - 1 } else { end }])
    } else {
        let mut start = equals + 1;
        let mut nul = quoted && closing;
        // "Don't include quotes in value."
        if args.get(start) == Some(&b'"') {
            start += 1;
            nul |= closing;
        }
        let stop = if nul { end - 1 } else { end };
        Word {
            param: &args[..equals],
            value: Some(&args[start..stop.max(start)]),
        }
    };
    // The separator is whitespace, so skipping spaces consumes it as well.
    (word, skip_spaces(&args[end..]))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgsError {
    /// Linux panics with "Too many boot init vars".
    TooMany,
}

/// The words after the first standalone `--`, up to a second standalone `--`.
#[derive(Clone, Debug)]
pub struct InitArgv<'a> {
    rest: &'a [u8],
}

impl<'a> InitArgv<'a> {
    /// # Errors
    /// More than [`MAX_INIT_ARGS`] words, where Linux panics.
    pub fn parse(command_line: &'a [u8]) -> Result<Self, ArgsError> {
        let mut rest = skip_spaces(command_line);
        let rest = loop {
            if rest.is_empty() {
                break rest;
            }
            let (word, next) = next_arg(rest);
            rest = next;
            if word.value.is_none() && word.param == b"--" {
                break rest;
            }
        };
        let argv = Self { rest };
        if argv.clone().count() > MAX_INIT_ARGS {
            return Err(ArgsError::TooMany);
        }
        Ok(argv)
    }
}

impl<'a> Iterator for InitArgv<'a> {
    type Item = Word<'a>;
    fn next(&mut self) -> Option<Word<'a>> {
        if self.rest.is_empty() {
            return None;
        }
        let (word, next) = next_arg(self.rest);
        if word.value.is_none() && word.param == b"--" {
            self.rest = &[];
            return None;
        }
        self.rest = next;
        Some(word)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::{ArgsError, InitArgv, MAX_INIT_ARGS, Word, next_arg};
    use std::{string::String, vec::Vec};

    fn spell(word: Word<'_>) -> String {
        String::from_utf8(word.bytes().collect()).unwrap()
    }
    fn argv(line: &str) -> Vec<String> {
        InitArgv::parse(line.as_bytes())
            .unwrap()
            .map(spell)
            .collect()
    }

    #[test]
    fn words_after_standalone_double_dash_only() {
        assert_eq!(argv(""), Vec::<String>::new());
        assert_eq!(argv("console=ttyS0 panic=-1"), Vec::<String>::new());
        assert_eq!(argv("a b -- fault"), ["fault"]);
        assert_eq!(argv("--"), Vec::<String>::new());
        assert_eq!(argv("  --   x   y  "), ["x", "y"]);
        assert_eq!(argv("quiet -- fault 3"), ["fault", "3"]);
        // `--x`, `x--`, `--=1` are not the separator.
        assert_eq!(argv("--x a"), Vec::<String>::new());
        assert_eq!(argv("x-- a"), Vec::<String>::new());
        assert_eq!(argv("--=1 -- a"), ["a"]);
        // The first `--` wins; a second one ends the init words.
        assert_eq!(argv("-- a -- b"), ["a"]);
        assert_eq!(argv("a -- -- b"), Vec::<String>::new());
    }

    #[test]
    fn quoting_and_equals_follow_next_arg() {
        assert_eq!(argv("-- \"a b\" c"), ["a b", "c"]);
        assert_eq!(
            argv("-- k=v k=\"x y\" \"p q=r s\""),
            ["k=v", "k=x y", "p q=r s"]
        );
        assert_eq!(argv("-- k= =v \"\""), ["k=", "=v", ""]);
        assert_eq!(argv("-- \"unterminated x"), ["unterminated x"]);
    }

    #[test]
    fn whitespace_set_is_linux_ctype() {
        let line = b"-- a\x0bb\x0cc\xa0d";
        let words: Vec<Vec<u8>> = InitArgv::parse(line)
            .unwrap()
            .map(|w| w.bytes().collect())
            .collect();
        assert_eq!(
            words,
            [b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec()]
        );
    }

    #[test]
    fn at_most_thirty_two_words() {
        let mut line = String::from("--");
        for _ in 0..MAX_INIT_ARGS {
            line.push_str(" w");
        }
        assert_eq!(argv(&line).len(), MAX_INIT_ARGS);
        line.push_str(" w");
        assert_eq!(
            InitArgv::parse(line.as_bytes()).unwrap_err(),
            ArgsError::TooMany
        );
        // Words past a second `--` are not init's, so they do not count.
        let mut line = String::from("--");
        for _ in 0..MAX_INIT_ARGS {
            line.push_str(" w");
        }
        line.push_str(" -- w w w");
        assert!(InitArgv::parse(line.as_bytes()).is_ok());
    }

    #[test]
    fn next_arg_never_reads_past_the_input() {
        for input in [
            &b""[..],
            b"\"",
            b"=",
            b"\"=",
            b"a=\"",
            b"\"a=\"",
            b"\"\"\"",
            b"a=\"\"\"",
            b"=\"x",
        ] {
            let (word, rest) = next_arg(input);
            assert!(word.len() <= input.len() && rest.len() <= input.len());
        }
    }
}
