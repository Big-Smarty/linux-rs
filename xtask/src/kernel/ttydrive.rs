// SPDX-License-Identifier: GPL-2.0-only
//! The tty input driver of the harness: it plays the part of a person at the guest's serial line
//! (and keyboard). A script says, per stage the guest announces with `init: stage <name>`, which
//! bytes to write to the guest's serial port, which keys to press through QMP `send-key` and how long
//! to wait in between. The same driver runs the pinned Linux (to record the expected output) and the
//! candidate kernel (to compare with it), so the observations are produced the same way.
//!
//! The driver is a poll loop, not a thread: [`Driver::step`] is called every few milliseconds by
//! whoever waits for QEMU to exit (the `kernel-test` case runner, [`run_reference`]).
//!
//! The serial transcript of a stage (what the guest wrote between the marker and its first result
//! line: the tty's echo, the output under test) is part of the evidence: [`transcript`] cuts the
//! raw log into items, [`rows`] renders them as `expected.tsv` rows and [`compare`] checks a log
//! against rows. A log that carries echo is not text for the generic serial validator, so
//! [`sanitize`] removes the echo segments from the copy it checks.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// One thing the driver does.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Act {
    /// Write these bytes to the serial port (one `write`, so one burst).
    Send(&'static [u8]),
    /// Wait this many milliseconds before the next action.
    Sleep(u64),
    /// Press the keys (QMP qcodes) together, hold them, release them.
    Keys(&'static [&'static str]),
}

/// The stages of a group: the marker name and what to do when it appears.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Script {
    pub(crate) group: &'static str,
    pub(crate) stages: &'static [(&'static str, &'static [Act])],
}

const CR: &[u8] = b"\r";
const X100: [u8; 100] = [b'x'; 100];

const fn s(bytes: &'static [u8]) -> Act {
    Act::Send(bytes)
}

/// Delay between bursts: long enough for the guest to take each burst as a batch of its own.
const GAP: u64 = 120;

/// The `ttyin` group of `user/init`: what to type at each stage.
pub(crate) const TTYIN: Script = Script {
    group: "ttyin",
    stages: &[
        (
            "canon-echo",
            &[
                s(b"hello"),
                Act::Sleep(GAP),
                s(CR),
                Act::Sleep(GAP),
                s(b"ab"),
                Act::Sleep(GAP),
                s(b"\x7f"),
                Act::Sleep(GAP),
                s(b"c\n"),
                Act::Sleep(GAP),
                s(b"foo bar"),
                Act::Sleep(GAP),
                s(b"\x17"),
                Act::Sleep(GAP),
                s(b"baz\n"),
                Act::Sleep(GAP),
                s(b"xyz"),
                Act::Sleep(GAP),
                s(b"\x15"),
                Act::Sleep(GAP),
                s(b"ok\n"),
                Act::Sleep(GAP),
                s(b"abc"),
                Act::Sleep(GAP),
                s(b"\x04"),
                Act::Sleep(GAP),
                s(b"\x04"),
                Act::Sleep(GAP),
                s(b"\x16"),
                Act::Sleep(GAP),
                s(b"\x03"),
                Act::Sleep(GAP),
                s(b"q\n"),
                Act::Sleep(GAP),
                s(b"abc"),
                Act::Sleep(GAP),
                s(b"\x12"),
                Act::Sleep(GAP),
                s(b"def\n"),
                Act::Sleep(GAP),
                s(b"a"),
                Act::Sleep(GAP),
                s(b"\t"),
                Act::Sleep(GAP),
                s(b"\x7f"),
                Act::Sleep(GAP),
                s(b"b\n"),
            ],
        ),
        (
            "canon-long",
            &[
                s(&X100),
                Act::Sleep(GAP),
                s(b"\n"),
                Act::Sleep(GAP),
                s(b"yyyyyyyyyyyyyyyyyyy"),
                Act::Sleep(GAP),
                s(b"y\n"),
            ],
        ),
        ("nonblock", &[Act::Sleep(300), s(b"k!\n")]),
        (
            "raw-vmin3",
            &[
                Act::Sleep(GAP),
                s(b"a"),
                Act::Sleep(GAP),
                s(b"b"),
                Act::Sleep(GAP),
                s(b"c"),
            ],
        ),
        (
            "raw-vmin1",
            &[Act::Sleep(GAP), s(b"x"), Act::Sleep(GAP), s(b"yz")],
        ),
        (
            "raw-vmin100",
            &[
                Act::Sleep(GAP),
                s(b"0123456789"),
                Act::Sleep(50),
                s(b"0123456789"),
                Act::Sleep(50),
                s(b"0123456789"),
                Act::Sleep(50),
                s(b"0123456789"),
                Act::Sleep(50),
                s(b"0123456789"),
                Act::Sleep(50),
                s(b"0123456789"),
                Act::Sleep(50),
                s(b"0123"),
            ],
        ),
        ("raw-vtime-timeout", &[]),
        ("raw-vtime-early", &[Act::Sleep(100), s(b"e")]),
        ("raw-vtime-interbyte", &[Act::Sleep(100), s(b"i")]),
        (
            "raw-vtime-two",
            &[Act::Sleep(100), s(b"p"), Act::Sleep(200), s(b"q")],
        ),
        (
            "input-icrnl",
            &[
                s(b"a"),
                Act::Sleep(GAP),
                s(b"\r"),
                Act::Sleep(GAP),
                s(b"b\rc\r"),
            ],
        ),
        (
            "input-no-icrnl",
            &[
                s(b"a"),
                Act::Sleep(GAP),
                s(b"\r"),
                Act::Sleep(GAP),
                s(b"b\rc\r"),
            ],
        ),
        (
            "input-inlcr",
            &[
                s(b"a"),
                Act::Sleep(GAP),
                s(b"\n"),
                Act::Sleep(GAP),
                s(b"b\nc\n"),
            ],
        ),
        (
            "input-igncr",
            &[s(b"a"), Act::Sleep(GAP), s(b"\r"), Act::Sleep(GAP), s(b"c")],
        ),
        (
            "input-istrip",
            &[
                s(b"a"),
                Act::Sleep(GAP),
                s(b"\xe2"),
                Act::Sleep(GAP),
                s(b"c"),
            ],
        ),
        (
            "input-iuclc",
            &[s(b"A"), Act::Sleep(GAP), s(b"B"), Act::Sleep(GAP), s(b"C")],
        ),
        ("echo-off", EDIT),
        ("echo-nl-only", EDIT),
        ("no-echoe", EDIT),
        ("no-echok", EDIT),
        ("no-echoctl", EDIT),
        ("echoprt", EDIT),
        ("no-echoke", EDIT),
        ("no-iexten", EDIT),
        ("flow-xoff", &[s(b"\x13"), Act::Sleep(500), s(b"\x11")]),
        ("flow-ixany", &[s(b"\x13"), Act::Sleep(500), s(b"x")]),
        ("flow-tcooff", &[Act::Sleep(100), s(b"\x11")]),
        (
            "poll-canon",
            &[Act::Sleep(300), s(b"ab"), Act::Sleep(500), s(b"\n")],
        ),
        (
            "poll-vmin",
            &[
                Act::Sleep(100),
                s(b"a"),
                Act::Sleep(100),
                s(b"b"),
                Act::Sleep(600),
                s(b"c"),
            ],
        ),
        (
            "fionread",
            &[Act::Sleep(100), s(b"abc"), Act::Sleep(900), s(b"\n")],
        ),
        (
            "fionread-canon",
            &[
                s(b"xy"),
                Act::Sleep(GAP),
                s(b"\x04"),
                Act::Sleep(GAP),
                s(b"z\n"),
            ],
        ),
        ("fionread-raw", &[s(b"p"), Act::Sleep(GAP), s(b"q")]),
        ("tcflsh", &[s(b"junk"), Act::Sleep(GAP), s(b"\n")]),
        ("tcsetsf", &[s(b"mores"), Act::Sleep(GAP), s(b"\n")]),
        (
            "isig",
            &[
                Act::Sleep(100),
                s(b"ab"),
                Act::Sleep(GAP),
                s(b"\x03"),
                Act::Sleep(GAP),
                s(b"\x1c"),
                Act::Sleep(GAP),
                s(b"\x1a"),
            ],
        ),
        (
            "isig-off",
            &[
                Act::Sleep(100),
                s(b"\x03"),
                Act::Sleep(GAP),
                s(b"\x1c"),
                Act::Sleep(GAP),
                s(b"\x1a"),
                Act::Sleep(GAP),
                s(b"\n"),
            ],
        ),
        (
            "isig-noflsh",
            &[
                Act::Sleep(100),
                s(b"ab"),
                Act::Sleep(GAP),
                s(b"\x03"),
                Act::Sleep(GAP),
                s(b"\n"),
            ],
        ),
    ],
};

/// The line the echo-flag stages type: edits, a kill, a control character.
const EDIT: &[Act] = &[
    s(b"abc"),
    Act::Sleep(GAP),
    s(b"\x7f"),
    Act::Sleep(GAP),
    s(b"d"),
    Act::Sleep(GAP),
    s(b"\x15"),
    Act::Sleep(GAP),
    s(b"xy"),
    Act::Sleep(GAP),
    s(b"\x01"),
    Act::Sleep(GAP),
    s(b"z"),
    Act::Sleep(GAP),
    s(b"\n"),
];

/// The `ttykbd` group: keys pressed with QMP `send-key` (the PS/2 keyboard on both kernels).
pub(crate) const TTYKBD: Script = Script {
    group: "ttykbd",
    stages: &[
        (
            "kbd-ascii",
            &[
                Act::Sleep(300),
                Act::Keys(&["a"]),
                Act::Sleep(160),
                Act::Keys(&["b"]),
                Act::Sleep(160),
                Act::Keys(&["z"]),
                Act::Sleep(160),
                Act::Keys(&["0"]),
                Act::Sleep(160),
                Act::Keys(&["9"]),
                Act::Sleep(160),
                Act::Keys(&["minus"]),
                Act::Sleep(160),
                Act::Keys(&["equal"]),
                Act::Sleep(160),
                Act::Keys(&["spc"]),
                Act::Sleep(160),
                Act::Keys(&["bracket_left"]),
                Act::Sleep(160),
                Act::Keys(&["backslash"]),
                Act::Sleep(160),
                Act::Keys(&["semicolon"]),
                Act::Sleep(160),
                Act::Keys(&["apostrophe"]),
                Act::Sleep(160),
                Act::Keys(&["grave_accent"]),
                Act::Sleep(160),
                Act::Keys(&["comma"]),
                Act::Sleep(160),
                Act::Keys(&["dot"]),
                Act::Sleep(160),
                Act::Keys(&["slash"]),
                Act::Sleep(160),
            ],
        ),
        (
            "kbd-shift",
            &[
                Act::Sleep(300),
                Act::Keys(&["shift", "a"]),
                Act::Sleep(160),
                Act::Keys(&["shift", "1"]),
                Act::Sleep(160),
                Act::Keys(&["shift", "minus"]),
                Act::Sleep(160),
                Act::Keys(&["shift", "equal"]),
                Act::Sleep(160),
                Act::Keys(&["shift", "bracket_left"]),
                Act::Sleep(160),
                Act::Keys(&["shift", "grave_accent"]),
                Act::Sleep(160),
                Act::Keys(&["shift", "slash"]),
                Act::Sleep(160),
                Act::Keys(&["shift", "comma"]),
                Act::Sleep(160),
            ],
        ),
        (
            "kbd-ctrl",
            &[
                Act::Sleep(300),
                Act::Keys(&["ctrl", "a"]),
                Act::Sleep(160),
                Act::Keys(&["ctrl", "c"]),
                Act::Sleep(160),
                Act::Keys(&["ctrl", "d"]),
                Act::Sleep(160),
                Act::Keys(&["ctrl", "z"]),
                Act::Sleep(160),
                Act::Keys(&["ctrl", "bracket_left"]),
                Act::Sleep(160),
                Act::Keys(&["ctrl", "backslash"]),
                Act::Sleep(160),
                Act::Keys(&["ctrl", "bracket_right"]),
                Act::Sleep(160),
                Act::Keys(&["ctrl", "2"]),
                Act::Sleep(160),
                Act::Keys(&["ctrl", "6"]),
                Act::Sleep(160),
                Act::Keys(&["ctrl", "minus"]),
                Act::Sleep(160),
                Act::Keys(&["ctrl", "h"]),
                Act::Sleep(160),
                Act::Keys(&["ctrl", "m"]),
                Act::Sleep(160),
                Act::Keys(&["ctrl", "i"]),
                Act::Sleep(160),
                Act::Keys(&["ctrl", "j"]),
                Act::Sleep(160),
            ],
        ),
        (
            "kbd-special",
            &[
                Act::Sleep(300),
                Act::Keys(&["ret"]),
                Act::Sleep(160),
                Act::Keys(&["backspace"]),
                Act::Sleep(160),
                Act::Keys(&["tab"]),
                Act::Sleep(160),
                Act::Keys(&["esc"]),
                Act::Sleep(160),
                Act::Keys(&["spc"]),
                Act::Sleep(160),
            ],
        ),
        (
            "kbd-cursor",
            &[
                Act::Sleep(300),
                Act::Keys(&["up"]),
                Act::Sleep(160),
                Act::Keys(&["down"]),
                Act::Sleep(160),
                Act::Keys(&["right"]),
                Act::Sleep(160),
                Act::Keys(&["left"]),
                Act::Sleep(160),
                Act::Keys(&["home"]),
                Act::Sleep(160),
                Act::Keys(&["insert"]),
                Act::Sleep(160),
                Act::Keys(&["delete"]),
                Act::Sleep(160),
                Act::Keys(&["end"]),
                Act::Sleep(160),
                Act::Keys(&["pgup"]),
                Act::Sleep(160),
                Act::Keys(&["pgdn"]),
                Act::Sleep(160),
            ],
        ),
        (
            "kbd-function",
            &[
                Act::Sleep(300),
                Act::Keys(&["f1"]),
                Act::Sleep(160),
                Act::Keys(&["f2"]),
                Act::Sleep(160),
                Act::Keys(&["f3"]),
                Act::Sleep(160),
                Act::Keys(&["f4"]),
                Act::Sleep(160),
                Act::Keys(&["f5"]),
                Act::Sleep(160),
                Act::Keys(&["f6"]),
                Act::Sleep(160),
                Act::Keys(&["f7"]),
                Act::Sleep(160),
                Act::Keys(&["f8"]),
                Act::Sleep(160),
                Act::Keys(&["f9"]),
                Act::Sleep(160),
                Act::Keys(&["f10"]),
                Act::Sleep(160),
                Act::Keys(&["shift", "f1"]),
                Act::Sleep(160),
                Act::Keys(&["shift", "f2"]),
                Act::Sleep(160),
            ],
        ),
        (
            "kbd-alt",
            &[
                Act::Sleep(300),
                Act::Keys(&["alt", "a"]),
                Act::Sleep(160),
                Act::Keys(&["alt", "1"]),
                Act::Sleep(160),
                Act::Keys(&["alt", "ret"]),
                Act::Sleep(160),
                Act::Keys(&["alt", "backspace"]),
                Act::Sleep(160),
                Act::Keys(&["ctrl", "alt", "a"]),
                Act::Sleep(160),
            ],
        ),
        (
            "kbd-caps",
            &[
                Act::Sleep(300),
                Act::Keys(&["caps_lock"]),
                Act::Sleep(160),
                Act::Keys(&["a"]),
                Act::Sleep(160),
                Act::Keys(&["1"]),
                Act::Sleep(160),
                Act::Keys(&["shift", "a"]),
                Act::Sleep(160),
                Act::Keys(&["caps_lock"]),
                Act::Sleep(160),
                Act::Keys(&["a"]),
                Act::Sleep(160),
            ],
        ),
        (
            "kbd-numpad-off",
            &[
                Act::Sleep(300),
                Act::Keys(&["kp_7"]),
                Act::Sleep(160),
                Act::Keys(&["kp_8"]),
                Act::Sleep(160),
                Act::Keys(&["kp_4"]),
                Act::Sleep(160),
                Act::Keys(&["kp_5"]),
                Act::Sleep(160),
                Act::Keys(&["kp_0"]),
                Act::Sleep(160),
                Act::Keys(&["kp_decimal"]),
                Act::Sleep(160),
                Act::Keys(&["kp_enter"]),
                Act::Sleep(160),
                Act::Keys(&["kp_add"]),
                Act::Sleep(160),
                Act::Keys(&["kp_subtract"]),
                Act::Sleep(160),
                Act::Keys(&["kp_multiply"]),
                Act::Sleep(160),
                Act::Keys(&["kp_divide"]),
                Act::Sleep(160),
            ],
        ),
        (
            "kbd-numpad-on",
            &[
                Act::Sleep(300),
                Act::Keys(&["num_lock"]),
                Act::Sleep(160),
                Act::Keys(&["kp_7"]),
                Act::Sleep(160),
                Act::Keys(&["kp_8"]),
                Act::Sleep(160),
                Act::Keys(&["kp_7"]),
                Act::Sleep(160),
                Act::Keys(&["kp_decimal"]),
                Act::Sleep(160),
                Act::Keys(&["kp_0"]),
                Act::Sleep(160),
                Act::Keys(&["num_lock"]),
                Act::Sleep(160),
            ],
        ),
    ],
};

/// The script of an oracle group that needs input.
pub(crate) fn script_for(group: &str) -> Option<Script> {
    match group {
        "ttyin" => Some(TTYIN),
        "ttykbd" => Some(TTYKBD),
        _ => None,
    }
}

/// Escape a transcript for a TSV cell: printable ASCII stays, `\` is `\\`, everything else is
/// `\xNN` (so `\r`, `\n`, `\t` too).
pub(crate) fn escape(text: &str) -> String {
    let mut out = String::new();
    // The transcript holds one char per guest byte (Latin-1).
    for byte in text.chars().map(|c| c as u8) {
        match byte {
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(byte as char),
            _ => {
                let _ = write!(out, "\\x{byte:02x}");
            }
        }
    }
    out
}

/// The inverse of [`escape`], or `None` for a malformed escape.
pub(crate) fn unescape(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'\\' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        match bytes.get(i + 1)? {
            b'\\' => {
                out.push(b'\\');
                i += 2;
            }
            b'x' => {
                let hex = text.get(i + 2..i + 4)?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 4;
            }
            _ => return None,
        }
    }
    // The transcript is guest bytes; keep them one byte per char (Latin-1) so any byte survives.
    Some(out.iter().map(|&b| b as char).collect())
}

/// One item of a cut serial log.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Item {
    /// `check`, `summary`, `info`, `stage` or `echo`.
    pub(crate) kind: &'static str,
    /// The check name, or the stage name (for `stage` and `echo`).
    pub(crate) name: String,
    /// The exact line, or the raw transcript of the stage (Latin-1, one char per byte).
    pub(crate) text: String,
}

fn latin1(raw: &[u8]) -> String {
    raw.iter().map(|&b| b as char).collect()
}

fn is_result_line(line: &str) -> Option<&'static str> {
    if line.starts_with("init: tests ") {
        Some("summary")
    } else if line.starts_with("init: test ") {
        Some("check")
    } else if line.starts_with("init: info ") {
        Some("info")
    } else {
        None
    }
}

/// Cut the serial bytes of a group run into [`Item`]s: the result lines, the stage markers and the
/// raw text between a marker and the next line that starts with `init: ` (the stage's transcript).
pub(crate) fn transcript(raw: &[u8]) -> Vec<Item> {
    let text = latin1(raw);
    let mut items = Vec::new();
    let mut echo: Option<(String, String)> = None;
    for piece in text.split_inclusive('\n') {
        let line = piece.trim_end_matches('\n').trim_end_matches('\r');
        let result = is_result_line(line);
        let marker = line.strip_prefix("init: stage ");
        if (result.is_some() || marker.is_some())
            && piece.ends_with('\n')
            && let Some((name, body)) = echo.take()
        {
            items.push(Item {
                kind: "echo",
                name,
                text: body,
            });
        }
        if let Some(kind) = result {
            let name = line
                .split(' ')
                .nth(2)
                .and_then(|word| word.split_once('.'))
                .map_or("", |(_, name)| name)
                .to_owned();
            items.push(Item {
                kind,
                name,
                text: line.to_owned(),
            });
        } else if let Some(name) = marker {
            items.push(Item {
                kind: "stage",
                name: name.to_owned(),
                text: line.to_owned(),
            });
            echo = Some((name.to_owned(), String::new()));
        } else if let Some((_, body)) = echo.as_mut() {
            body.push_str(piece);
        }
    }
    if let Some((name, body)) = echo {
        items.push(Item {
            kind: "echo",
            name,
            text: body,
        });
    }
    items
}

/// The log without the stage transcripts: what the generic serial validator may look at.
pub(crate) fn sanitize(raw: &[u8]) -> String {
    let mut out = String::new();
    let mut skipping = false;
    for piece in latin1(raw).split_inclusive('\n') {
        let line = piece.trim_end_matches('\n').trim_end_matches('\r');
        if line.starts_with("init: stage ") {
            skipping = true;
            out.push_str(piece);
        } else if skipping && !line.starts_with("init: ") {
            // The kernel's own printk lines between the marker and the first result: not echo.
        } else {
            skipping = false;
            out.push_str(piece);
        }
    }
    out
}

/// `expected.tsv` rows (without the leading group cell columns' header) for a log:
/// `group<TAB>kind<TAB>name<TAB>text` with `echo` text escaped.
pub(crate) fn rows(group: &str, raw: &[u8]) -> String {
    let mut out = String::new();
    for item in transcript(raw) {
        let text = if item.kind == "echo" {
            escape(&item.text)
        } else {
            item.text
        };
        let name = if item.name.is_empty() {
            "-"
        } else {
            &item.name
        };
        let _ = writeln!(out, "{group}\t{}\t{name}\t{text}", item.kind);
    }
    out
}

/// Compare a log with the expected rows of its group: every item in order, `info` rows by their
/// key only. Returns the first difference.
pub(crate) fn compare(
    group: &str,
    raw: &[u8],
    expected: impl Iterator<Item = (&'static str, &'static str, &'static str)>,
) -> Result<(), String> {
    let observed = transcript(raw);
    let expected: Vec<_> = expected.collect();
    if expected.is_empty() {
        return Err(format!("no expected rows for group {group}"));
    }
    for (position, ((kind, name, want), got)) in expected.iter().zip(&observed).enumerate() {
        let same_kind = *kind == got.kind;
        let same = same_kind
            && match *kind {
                "info" => {
                    want.splitn(4, ' ').take(3).collect::<Vec<_>>()
                        == got.text.splitn(4, ' ').take(3).collect::<Vec<_>>()
                }
                "echo" => unescape(want).as_deref() == Some(got.text.as_str()),
                _ => *want == got.text,
            };
        if !same {
            let shown = if *kind == "echo" {
                escape(&got.text)
            } else {
                got.text.clone()
            };
            return Err(format!(
                "{group} item {position} ({kind} {name}): expected {want:?}, got {} {shown:?}",
                got.kind
            ));
        }
    }
    if observed.len() != expected.len() {
        return Err(format!(
            "{group}: expected {} items, got {}",
            expected.len(),
            observed.len()
        ));
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// The running driver: the guest's serial socket, its QMP, the log and the pending actions.
pub(crate) struct Driver {
    script: Script,
    serial: UnixStream,
    qmp: Option<UnixStream>,
    qmp_path: Option<PathBuf>,
    log: File,
    seen: Vec<u8>,
    scanned: usize,
    queue: VecDeque<Act>,
    resume_at: Instant,
    stages_seen: usize,
}

impl Driver {
    /// A driver over an already connected serial socket. `log` receives every byte the guest
    /// writes; `qmp_path` is where QEMU's QMP socket will appear (keys need it).
    pub(crate) fn new(
        script: Script,
        serial: UnixStream,
        log: File,
        qmp_path: Option<PathBuf>,
    ) -> io::Result<Self> {
        serial.set_nonblocking(true)?;
        Ok(Self {
            script,
            serial,
            qmp: None,
            qmp_path,
            log,
            seen: Vec::new(),
            scanned: 0,
            queue: VecDeque::new(),
            resume_at: Instant::now(),
            stages_seen: 0,
        })
    }

    /// Stage markers seen so far that the script knows.
    #[cfg(test)]
    pub(crate) fn stages_seen(&self) -> usize {
        self.stages_seen
    }

    /// Take the guest's new output, start the actions of a stage that was announced and perform the
    /// ones that are due. Cheap when idle; call every few milliseconds.
    pub(crate) fn step(&mut self) -> io::Result<()> {
        let mut chunk = [0u8; 4096];
        loop {
            match self.serial.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    self.log.write_all(&chunk[..n])?;
                    self.seen.extend_from_slice(&chunk[..n]);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        self.detect_markers();
        self.perform_due()
    }

    fn detect_markers(&mut self) {
        while let Some(end) = self.seen[self.scanned..].iter().position(|&b| b == b'\n') {
            let line = &self.seen[self.scanned..self.scanned + end];
            self.scanned += end + 1;
            let line = String::from_utf8_lossy(line);
            let line = line.trim_end_matches('\r');
            let Some(name) = line.strip_prefix("init: stage ") else {
                continue;
            };
            if let Some((_, actions)) = self.script.stages.iter().find(|(n, _)| *n == name) {
                self.stages_seen += 1;
                self.queue.clear();
                self.queue.extend(actions.iter().copied());
                self.resume_at = Instant::now();
            }
        }
    }

    fn perform_due(&mut self) -> io::Result<()> {
        while Instant::now() >= self.resume_at {
            let Some(act) = self.queue.pop_front() else {
                return Ok(());
            };
            match act {
                Act::Sleep(ms) => self.resume_at = Instant::now() + Duration::from_millis(ms),
                Act::Send(bytes) => {
                    // The socket is non-blocking; a burst this small always fits.
                    self.serial.set_nonblocking(false)?;
                    self.serial.write_all(bytes)?;
                    self.serial.set_nonblocking(true)?;
                }
                Act::Keys(keys) => self.qmp_send_key(keys)?,
            }
        }
        Ok(())
    }

    fn qmp(&mut self) -> io::Result<&mut UnixStream> {
        if self.qmp.is_none() {
            let path = self
                .qmp_path
                .clone()
                .ok_or_else(|| invalid("the script needs QMP but no socket path was given"))?;
            let mut stream = connect_unix(&path)?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            stream.set_write_timeout(Some(Duration::from_secs(5)))?;
            let mut greeting = [0u8; 1024];
            let _ = stream.read(&mut greeting)?;
            stream.write_all(b"{\"execute\":\"qmp_capabilities\"}\n")?;
            let mut reply = [0u8; 256];
            let _ = stream.read(&mut reply)?;
            self.qmp = Some(stream);
        }
        self.qmp
            .as_mut()
            .ok_or_else(|| invalid("QMP connection vanished"))
    }

    fn qmp_command(&mut self, request: &str) -> io::Result<()> {
        let stream = self.qmp()?;
        stream.write_all(request.as_bytes())?;
        stream.write_all(b"\n")?;
        let mut reply = [0u8; 512];
        let n = stream.read(&mut reply)?;
        let text = String::from_utf8_lossy(&reply[..n]);
        if text.contains("\"error\"") {
            return Err(invalid(format!("QMP refused {request}: {text}")));
        }
        Ok(())
    }

    fn qmp_send_key(&mut self, keys: &[&str]) -> io::Result<()> {
        let mut list = String::new();
        for (i, key) in keys.iter().enumerate() {
            if i > 0 {
                list.push(',');
            }
            let _ = write!(list, "{{\"type\":\"qcode\",\"data\":\"{key}\"}}");
        }
        self.qmp_command(&format!(
            "{{\"execute\":\"send-key\",\"arguments\":{{\"keys\":[{list}],\"hold-time\":60}}}}"
        ))
    }
}

/// Connect to the socket `path`, however deep it lies: `sockaddr_un` holds 108 bytes, a case
/// directory under a worktree does not fit, so the connection goes through an open descriptor of
/// the socket's directory (`/proc/self/fd/<n>/<name>`, Linux). A missing directory or socket is
/// `NotFound`, as for a direct connect.
fn connect_unix(path: &Path) -> io::Result<UnixStream> {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str())) else {
        return Err(invalid("a socket path needs a directory and a file name"));
    };
    let dir = File::open(dir)?;
    UnixStream::connect(format!("/proc/self/fd/{}/{name}", dir.as_raw_fd()))
}

/// Connect to the serial socket QEMU listens on (`wait=on`: the guest does not start before this
/// succeeds). `alive` tells whether QEMU still runs.
pub(crate) fn connect_serial(
    path: &Path,
    timeout: Duration,
    mut alive: impl FnMut() -> io::Result<bool>,
) -> io::Result<UnixStream> {
    let start = Instant::now();
    loop {
        match connect_unix(path) {
            Ok(stream) => return Ok(stream),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                ) => {}
            Err(error) => return Err(error),
        }
        if !alive()? {
            return Err(invalid("QEMU exited before its serial socket was ready"));
        }
        if start.elapsed() >= timeout {
            return Err(invalid("the serial socket did not appear in time"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

// ---- running QEMU under a driver ------------------------------------------------------

use super::{ProcessResult, create_new, create_process};
use std::process::Command;

/// Run `command` (a QEMU whose serial port and QMP are the sockets named here) to its end under a
/// driver for `script`; the guest's serial bytes go to `serial_log`. `timeout` bounds the run.
#[allow(
    clippy::too_many_arguments,
    reason = "the paths and the script of one run, used once"
)]
pub(crate) fn run_driven(
    command: &mut Command,
    stdout_path: &Path,
    stderr_path: &Path,
    serial_sock: &Path,
    qmp_sock: Option<&Path>,
    serial_log: &Path,
    script: Script,
    timeout: Duration,
) -> io::Result<ProcessResult> {
    let stdout = create_new(stdout_path)?;
    let stderr = create_new(stderr_path)?;
    command
        .stdout(std::process::Stdio::from(stdout))
        .stderr(std::process::Stdio::from(stderr));
    let mut child = create_process(command)?;
    let start = Instant::now();
    let stream = connect_serial(serial_sock, timeout, || Ok(child.try_wait()?.is_none()))?;
    let mut driver = Driver::new(
        script,
        stream,
        create_new(serial_log)?,
        qmp_sock.map(Path::to_path_buf),
    )?;
    loop {
        if let Some(status) = child.try_wait()? {
            // QEMU closed the socket; take what is left.
            let _ = driver.step();
            return Ok(ProcessResult {
                exit_code: status.code(),
                timed_out: false,
            });
        }
        if start.elapsed() >= timeout {
            let status = child
                .stop_and_reap()?
                .ok_or_else(|| invalid("timed-out process disappeared before reaping"))?;
            let _ = driver.step();
            return Ok(ProcessResult {
                exit_code: status.code(),
                timed_out: true,
            });
        }
        driver.step()?;
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// `xtask tty-oracle --script <name> --output <new-directory> [--timeout-seconds N] -- <qemu
/// command line>`: run a QEMU command line (the program first; no `-serial`, `-qmp`, `-monitor` or
/// `-display`) under the driver of `<name>`; write `<dir>/serial.log` and `<dir>/expected-rows.tsv`
/// (the `expected.tsv` rows the log yields) and exit with 0 when the run ended by itself.
pub(crate) fn cli(args: Vec<std::ffi::OsString>) -> io::Result<()> {
    let mut script = None;
    let mut output = None;
    let mut timeout = Duration::from_secs(300);
    let mut iter = args.into_iter();
    let mut qemu = Vec::new();
    while let Some(arg) = iter.next() {
        let arg = arg
            .into_string()
            .map_err(|_| invalid("tty-oracle: arguments must be UTF-8"))?;
        match arg.as_str() {
            "--script" => script = iter.next().and_then(|v| v.into_string().ok()),
            "--output" => output = iter.next().map(PathBuf::from),
            "--timeout-seconds" => {
                let v = iter
                    .next()
                    .and_then(|v| v.into_string().ok())
                    .and_then(|v| v.parse::<u64>().ok())
                    .ok_or_else(|| invalid("--timeout-seconds needs a number"))?;
                timeout = Duration::from_secs(v);
            }
            "--" => {
                qemu.extend(iter.by_ref().filter_map(|v| v.into_string().ok()));
            }
            other => return Err(invalid(format!("tty-oracle: unknown argument {other}"))),
        }
    }
    let script = match script.as_deref() {
        Some("ttyin") => TTYIN,
        Some("ttykbd") => TTYKBD,
        Some(other) => return Err(invalid(format!("tty-oracle: no script named {other}"))),
        None => return Err(invalid("tty-oracle: --script is required")),
    };
    let output = output.ok_or_else(|| invalid("tty-oracle: --output is required"))?;
    let (program, rest) = qemu
        .split_first()
        .ok_or_else(|| invalid("tty-oracle: the QEMU command line follows --"))?;
    std::fs::create_dir(&output)?;
    let serial_sock = output.join("serial.sock");
    let qmp_sock = output.join("qmp.sock");
    let mut command = Command::new(program);
    command
        .args(rest)
        .args(["-display", "none", "-monitor", "none", "-chardev"])
        .arg(format!(
            "socket,id=ttys0,path={},server=on,wait=on",
            serial_sock.display()
        ))
        .args(["-serial", "chardev:ttys0", "-qmp"])
        .arg(format!("unix:{},server=on,wait=off", qmp_sock.display()));
    let serial_log = output.join("serial.log");
    let result = run_driven(
        &mut command,
        &output.join("qemu.stdout.log"),
        &output.join("qemu.stderr.log"),
        &serial_sock,
        Some(&qmp_sock),
        &serial_log,
        script,
        timeout,
    )?;
    let raw = std::fs::read(&serial_log)?;
    std::fs::write(output.join("expected-rows.tsv"), rows(script.group, &raw))?;
    let verdict = format!(
        "exit={:?} timed_out={} stages_in_script={}\n",
        result.exit_code,
        result.timed_out,
        script.stages.len()
    );
    std::fs::write(output.join("result.txt"), &verdict)?;
    print!("{verdict}");
    if result.timed_out {
        return Err(invalid("the guest did not finish in time"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_round_trips_every_byte() {
        let all: String = (0u8..=255).map(|b| b as char).collect();
        assert_eq!(unescape(&escape(&all)).as_deref(), Some(all.as_str()));
        assert_eq!(escape("a\r\n\\"), "a\\x0d\\x0a\\\\");
        assert_eq!(escape("\u{c3}\u{a9}"), "\\xc3\\xa9");
        assert_eq!(unescape("\\q"), None);
        assert_eq!(unescape("\\x4"), None);
    }

    const LOG: &[u8] = b"boot noise\r\ninit: stage one\r\nhi\x08 \x08\r\n\r\ninit: test g.a ok\r\ninit: info g.b value 1\r\ninit: stage two\r\ninit: test g.c ok\r\ninit: tests g passed=2 failed=0\r\n";

    #[test]
    fn transcript_cuts_stages_and_results() {
        let items = transcript(LOG);
        let kinds: Vec<_> = items.iter().map(|i| (i.kind, i.name.as_str())).collect();
        assert_eq!(
            kinds,
            [
                ("stage", "one"),
                ("echo", "one"),
                ("check", "a"),
                ("info", "b"),
                ("stage", "two"),
                ("echo", "two"),
                ("check", "c"),
                ("summary", ""),
            ]
        );
        assert_eq!(items[1].text, "hi\x08 \x08\r\n\r\n");
        assert_eq!(items[5].text, "");
    }

    #[test]
    fn sanitize_drops_only_the_echo() {
        let clean = sanitize(LOG);
        assert!(!clean.contains('\x08'));
        assert!(clean.contains("init: test g.a ok"));
        assert!(clean.contains("boot noise"));
    }

    #[test]
    fn rows_compare_with_themselves_and_detect_a_change() {
        let tsv = rows("g", LOG);
        let leaked: Vec<(&'static str, &'static str, &'static str)> = tsv
            .lines()
            .map(|line| {
                let mut f = line.splitn(4, '\t');
                let _ = f.next();
                let kind: &'static str = Box::leak(f.next().unwrap().to_owned().into_boxed_str());
                let name: &'static str = Box::leak(f.next().unwrap().to_owned().into_boxed_str());
                let text: &'static str = Box::leak(f.next().unwrap().to_owned().into_boxed_str());
                (kind, name, text)
            })
            .collect();
        assert_eq!(compare("g", LOG, leaked.iter().copied()), Ok(()));
        let changed = LOG
            .to_vec()
            .iter()
            .map(|&b| if b == 0x08 { b'?' } else { b })
            .collect::<Vec<_>>();
        assert!(compare("g", &changed, leaked.iter().copied()).is_err());
    }

    #[test]
    fn driver_sends_after_the_marker_with_the_scripted_delays() {
        const SCRIPT: Script = Script {
            group: "t",
            stages: &[("go", &[Act::Send(b"A"), Act::Sleep(30), Act::Send(b"B")])],
        };
        let (guest, host) = UnixStream::pair().unwrap();
        let dir = std::env::temp_dir().join(format!("ttydrive-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = File::create(dir.join("serial.log")).unwrap();
        let mut driver = Driver::new(SCRIPT, host, log, None).unwrap();
        (&guest).write_all(b"init: stage go\r\n").unwrap();
        let mut got = Vec::new();
        let start = Instant::now();
        guest
            .set_read_timeout(Some(Duration::from_millis(10)))
            .unwrap();
        while start.elapsed() < Duration::from_millis(400) && got.len() < 2 {
            driver.step().unwrap();
            let mut byte = [0u8; 1];
            if let Ok(1) = (&guest).read(&mut byte) {
                got.push((byte[0], start.elapsed()));
            }
        }
        assert_eq!(got.iter().map(|g| g.0).collect::<Vec<_>>(), b"AB");
        assert!(got[1].1.saturating_sub(got[0].1) >= Duration::from_millis(25));
        assert_eq!(driver.stages_seen(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
