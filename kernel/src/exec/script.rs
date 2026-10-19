// SPDX-License-Identifier: GPL-2.0-only
// Selected semantics from Linux 6.18.57, commit
// 2ff600d29ee478d0a8d46ef8a58afb5e038fe692: fs/binfmt_script.c (`load_script`,
// GPL-2.0-only; Copyright (C) 1991, 1992 Linus Torvalds), include/uapi/linux/
// binfmts.h (`BINPRM_BUF_SIZE`).
// Transformation: only the `#!` line parse is ported, over a zero-padded copy
// of the first 256 bytes; the interpreter lookup and re-exec stay with the caller.
#![forbid(unsafe_code)]
//! `#!` scripts: which interpreter would `load_script` open, and with which errno
//! does it give up before opening anything. Scripts are never executed here:
//! the caller reports `-ENOENT` when the interpreter is not in the rootfs (what
//! `open_exec` returns) and an explicit unsupported failure when it is.

use syscalls::Errno;

const BUF: usize = 256;

const fn spacetab(byte: u8) -> bool {
    byte == b' ' || byte == b'\t'
}

/// `next_non_spacetab(first, last)`: inclusive, `None` when only space/tab.
fn next_non_spacetab(buf: &[u8], first: usize, last: usize) -> Option<usize> {
    (first..=last).find(|&index| !spacetab(buf[index]))
}

/// `next_terminator`: first space, tab or NUL.
fn next_terminator(buf: &[u8], first: usize, last: usize) -> Option<usize> {
    (first..=last).find(|&index| spacetab(buf[index]) || buf[index] == 0)
}

/// The interpreter path named by a `#!` line.
///
/// `Ok(None)` when the file does not start with `#!` (not a script),
/// `Ok(Some(path))` when `load_script` would call `open_exec(path)`.
///
/// # Errors
/// `-ENOEXEC` for the lines `load_script` rejects: no interpreter, only
/// spaces/tabs, or a path that may be truncated by the 256-byte buffer.
pub fn interpreter(file: &[u8]) -> Result<Option<&[u8]>, Errno> {
    // prepare_binprm: the buffer is cleared, then filled by a short read.
    let mut buf = [0u8; BUF];
    let count = file.len().min(BUF);
    buf[..count].copy_from_slice(&file[..count]);
    if &buf[..2] != b"#!" {
        return Ok(None);
    }
    let buf_end = BUF - 1;
    // strnchr(buf, 256, '\n') stops at a NUL.
    let newline = buf
        .iter()
        .take_while(|&&byte| byte != 0)
        .position(|&byte| byte == b'\n');
    let mut end = if let Some(index) = newline {
        index
    } else {
        let first = next_non_spacetab(&buf, 2, buf_end).ok_or(Errno::ENOEXEC)?;
        // Without a later terminator the path may be truncated.
        next_terminator(&buf, first, buf_end).ok_or(Errno::ENOEXEC)?;
        buf_end
    };
    while spacetab(buf[end - 1]) {
        end -= 1;
    }
    let name = match next_non_spacetab(&buf, 2, end) {
        Some(index) if index != end => index,
        _ => return Err(Errno::ENOEXEC),
    };
    // The name ends at the separator before an optional argument, else at i_end.
    let stop = next_terminator(&buf, name, end).map_or(end, |sep| sep.min(end));
    Ok(Some(&file[name..stop.min(file.len())]))
}

#[cfg(test)]
mod tests {
    use super::interpreter;
    use syscalls::Errno;

    #[test]
    fn plain_scripts_name_their_interpreter() {
        assert_eq!(interpreter(b"#!/bin/sh\necho"), Ok(Some(&b"/bin/sh"[..])));
        assert_eq!(interpreter(b"#!  /bin/sh -e\n"), Ok(Some(&b"/bin/sh"[..])));
        assert_eq!(
            interpreter(b"#!\t/usr/bin/env\tpython\n"),
            Ok(Some(&b"/usr/bin/env"[..]))
        );
        assert_eq!(
            interpreter(b"#!/bin/sh"),
            Ok(Some(&b"/bin/sh"[..])),
            "no newline, NUL padding ends it"
        );
        assert_eq!(interpreter(b"#!sh\n"), Ok(Some(&b"sh"[..])));
    }

    #[test]
    fn not_a_script_is_none_and_malformed_lines_are_enoexec() {
        assert_eq!(interpreter(b""), Ok(None));
        assert_eq!(interpreter(b"\x7fELF"), Ok(None));
        assert_eq!(interpreter(b"#"), Ok(None));
        for line in [&b"#!\n"[..], b"#!   \n", b"#!\t \t\n"] {
            assert_eq!(interpreter(line), Err(Errno::ENOEXEC), "{line:?}");
        }
    }

    #[test]
    fn bare_hash_bang_names_an_empty_interpreter() {
        // NUL is not space/tab: load_script then asks open_exec("") (-ENOENT).
        assert_eq!(interpreter(b"#!"), Ok(Some(&b""[..])));
    }

    #[test]
    fn a_path_cut_by_the_buffer_is_not_exec_ed() {
        let mut long = b"#!/".to_vec();
        long.resize(300, b'a');
        assert_eq!(interpreter(&long), Err(Errno::ENOEXEC));
        // A newline inside the 256 bytes makes the path complete.
        let mut ok = b"#!/".to_vec();
        ok.resize(100, b'a');
        ok.push(b'\n');
        ok.resize(300, b'x');
        assert_eq!(interpreter(&ok).unwrap().unwrap().len(), 98);
        // Spaces to the end of the buffer: only spaces.
        let mut spaces = b"#!".to_vec();
        spaces.resize(300, b' ');
        assert_eq!(interpreter(&spaces), Err(Errno::ENOEXEC));
        // Path, then a separator inside the buffer but no newline: truncated args are fine.
        let mut args = b"#!/bin/sh ".to_vec();
        args.resize(300, b'z');
        assert_eq!(interpreter(&args), Ok(Some(&b"/bin/sh"[..])));
    }
}
