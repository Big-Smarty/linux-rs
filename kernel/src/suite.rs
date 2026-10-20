// SPDX-License-Identifier: GPL-2.0-only
#![forbid(unsafe_code)]
//! Pure logic of the kernel-run bare-metal suite (decision A21): the oracle
//! comparison, the log digest, calendar conversion and the small name tables of
//! the hardware inventory. The privileged half (capture buffer, PCI port
//! access, group loop, screen) is `kernel/src/baremetal.rs` and
//! `kernel/src/pci.rs` of the binary crate, compiled only with the
//! `baremetal-suite` feature.
//!
//! Provenance: the comparison reproduces `validate_oracle` of the host harness
//! (`xtask/src/kernel.rs`) rule for rule, over the same checked-in table
//! (`xtask/oracle/expected.tsv`, recorded from the pinned Linux 6.18.57
//! reference run): the lines of a group's output that start with
//! `init: test `, `init: tests ` or `init: info ` are compared in order, `check`
//! and `summary` rows exactly, `info` rows by their `init: info <group>.<name>`
//! key only; a missing or extra line is a mismatch. Calendar conversion is the
//! proleptic-Gregorian civil-from-days algorithm (public domain, H. Hinnant).
//!
//! Context: any; no allocation, no locks, no sleeping.

/// The checked-in expected output of the oracle groups; the host harness
/// embeds the same file.
pub const ORACLE_EXPECTED: &[u8] = include_bytes!("../../xtask/oracle/expected.tsv");

/// Oracle groups the kernel can run today, in run order.
pub const GROUPS: [&str; 9] = [
    "ids", "time", "mm", "fs", "signal", "fork", "proc", "jobctl", "pipe",
];

/// Oracle groups that exist in `user/init` but are not run, with the reason
/// that appears on the summary screen. None today: `proc` needed pipes between
/// tasks, `poll` and job control, not procfs, and runs since the
/// [job-control lane](../../docs/implementation.md#pipes-poll-and-job-control).
pub const UNSUPPORTED: [(&str, &str); 0] = [];

/// Longest line text kept for a report; longer lines are cut (and end in `~`).
pub const LINE_MAX: usize = 100;
/// Mismatches kept per group (the count of all of them is kept as well).
pub const MAX_MISMATCHES: usize = 3;

/// The prefixes of the lines that belong to a group's comparison.
pub const PREFIXES: [&[u8]; 3] = [b"init: test ", b"init: tests ", b"init: info "];

/// A line of text cut to [`LINE_MAX`] bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Text {
    bytes: [u8; LINE_MAX],
    len: usize,
}

impl Text {
    pub const EMPTY: Self = Self {
        bytes: [0; LINE_MAX],
        len: 0,
    };

    #[must_use]
    pub fn new(line: &[u8]) -> Self {
        let mut text = Self::EMPTY;
        let keep = line.len().min(LINE_MAX);
        text.bytes[..keep].copy_from_slice(&line[..keep]);
        text.len = keep;
        if line.len() > LINE_MAX {
            text.bytes[LINE_MAX - 1] = b'~';
        }
        text
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// The text `args` formats to, cut to [`LINE_MAX`] bytes (no `~` marker:
    /// the cut is silent, these are the fixed inventory lines).
    #[must_use]
    pub fn from_args(args: core::fmt::Arguments<'_>) -> Self {
        struct Cut(Text);
        impl core::fmt::Write for Cut {
            fn write_str(&mut self, text: &str) -> core::fmt::Result {
                let room = LINE_MAX - self.0.len;
                let keep = &text.as_bytes()[..text.len().min(room)];
                self.0.bytes[self.0.len..self.0.len + keep.len()].copy_from_slice(keep);
                self.0.len += keep.len();
                Ok(())
            }
        }
        let mut cut = Cut(Self::EMPTY);
        // `Cut` never fails; a failing `Display` impl just ends the text early.
        let _ = core::fmt::write(&mut cut, args);
        cut.0
    }
}

/// Printable ASCII as is, anything else (init output is ASCII; kernel text can
/// carry a stray byte) as `?`, so a screen line never holds a control byte.
impl core::fmt::Display for Text {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use core::fmt::Write as _;
        for &byte in self.as_bytes() {
            let shown = if (0x20..0x7f).contains(&byte) {
                byte
            } else {
                b'?'
            };
            f.write_char(char::from(shown))?;
        }
        Ok(())
    }
}

/// One differing position of a group's comparison.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Mismatch {
    /// Index among the expected lines (0-based).
    pub position: usize,
    pub expected: Text,
    pub got: Text,
}

/// The outcome of comparing one group's output with the pinned Linux's.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GroupReport {
    /// Expected lines (rows of the table for the group).
    pub expected: usize,
    /// Lines of the output that carry a compared prefix.
    pub observed: usize,
    /// Positions that agree.
    pub matched: usize,
    /// All differing positions, including extra and missing lines.
    pub mismatch_count: usize,
    /// The first [`MAX_MISMATCHES`] of them.
    pub mismatches: [Mismatch; MAX_MISMATCHES],
    /// The first `init: FAIL ...` line, if init printed one.
    pub init_failure: Option<Text>,
    /// Whether init printed its closing `init: ok`.
    pub finished: bool,
}

impl GroupReport {
    /// Count one differing `position`, keeping the first [`MAX_MISMATCHES`].
    fn note(&mut self, position: usize, expected: &[u8], got: &[u8]) {
        if self.mismatch_count < MAX_MISMATCHES {
            self.mismatches[self.mismatch_count] = Mismatch {
                position,
                expected: Text::new(expected),
                got: Text::new(got),
            };
        }
        self.mismatch_count += 1;
    }

    /// The output equals the pinned Linux's and init ran to its end.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.expected > 0
            && self.mismatch_count == 0
            && self.expected == self.observed
            && self.init_failure.is_none()
            && self.finished
    }
}

fn is_compared(line: &[u8]) -> bool {
    PREFIXES.iter().any(|prefix| line.starts_with(prefix))
}

/// The part of an `info` line that must match: its first three words.
fn info_key(line: &[u8]) -> impl Iterator<Item = &[u8]> {
    line.splitn(4, |&b| b == b' ').take(3)
}

/// `(kind, line)` of the table rows of `group`, in file order. The header row
/// and `#` comments are skipped, as in the host harness.
pub fn expected_rows<'a>(
    table: &'a [u8],
    group: &'a str,
) -> impl Iterator<Item = (&'a [u8], &'a [u8])> + 'a {
    table
        .split(|&b| b == b'\n')
        .filter(|row| !row.starts_with(b"#"))
        .skip(1)
        .filter_map(move |row| {
            let mut fields = row.split(|&b| b == b'\t');
            let (row_group, kind, _name, line) = (
                fields.next()?,
                fields.next()?,
                fields.next()?,
                fields.next()?,
            );
            (row_group == group.as_bytes()).then_some((kind, line))
        })
}

/// Compare the console output of one group run with the table.
#[must_use]
pub fn compare_group(table: &[u8], group: &str, output: &[u8]) -> GroupReport {
    let mut report = GroupReport {
        expected: 0,
        observed: 0,
        matched: 0,
        mismatch_count: 0,
        mismatches: [Mismatch {
            position: 0,
            expected: Text::EMPTY,
            got: Text::EMPTY,
        }; MAX_MISMATCHES],
        init_failure: None,
        finished: false,
    };
    let (mut failure, mut finished) = (None, false);
    // The console turns "\n" into "\r\n" (the tty's ONLCR, as on the serial
    // line the reference output was recorded on); the table has bare "\n".
    let mut observed = output
        .split(|&b| b == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .inspect(|line| {
            if failure.is_none() && line.starts_with(b"init: FAIL") {
                failure = Some(Text::new(line));
            }
            if *line == b"init: ok" {
                finished = true;
            }
        })
        .filter(|line| is_compared(line));
    let mut position = 0;
    for (kind, want) in expected_rows(table, group) {
        report.expected += 1;
        match observed.next() {
            Some(got) => {
                report.observed += 1;
                let same = if kind == b"info" {
                    info_key(want).eq(info_key(got))
                } else {
                    want == got
                };
                if same {
                    report.matched += 1;
                } else {
                    report.note(position, want, got);
                }
            }
            None => report.note(position, want, b"<missing>"),
        }
        position += 1;
    }
    // Lines beyond the table are extra: each is a mismatch.
    for got in observed {
        report.observed += 1;
        report.note(position, b"<none>", got);
        position += 1;
    }
    // The exhausted iterator has released its borrows of the two locals.
    report.init_failure = failure;
    report.finished = finished;
    report
}

/// Screen rows a text of `len` bytes takes on a grid `columns` wide (long lines
/// wrap); `columns == 0` (no framebuffer) is one row, as nothing can scroll.
#[must_use]
pub fn rows_for(len: usize, columns: usize) -> usize {
    match columns {
        0 => 1,
        columns => len.div_ceil(columns).max(1),
    }
}

/// The row budget of the summary's failure detail. The lines above it are
/// fixed, so the detail may use only the rows left below them (less the final
/// line and an omission note): an overflow would scroll the heading, digest
/// and RESULT line off the one screen the user photographs. The whole budget
/// is shared by the failing groups ([`RowBudget::group`]); what does not fit
/// is counted, not printed.
#[derive(Clone, Copy, Debug)]
pub struct RowBudget {
    left: usize,
    group_left: usize,
    share: usize,
    omitted: usize,
}

impl RowBudget {
    /// `rows` for the whole detail, split between `groups` failing groups
    /// (each at least two rows, so its stop line and first fact show).
    #[must_use]
    pub fn new(rows: usize, groups: usize) -> Self {
        Self {
            left: rows,
            group_left: 0,
            share: (rows / groups.max(1)).max(2),
            omitted: 0,
        }
    }

    /// Start the next group's share.
    pub fn group(&mut self) {
        self.group_left = self.share;
    }

    /// Whether `rows` rows still fit this group and the whole; takes them when
    /// they do, counts one omitted row when they do not.
    pub fn take(&mut self, rows: usize) -> bool {
        if rows <= self.left.min(self.group_left) {
            self.left -= rows;
            self.group_left -= rows;
            true
        } else {
            self.omitted += 1;
            false
        }
    }

    /// Whether `rows` rows fit, without taking them or counting an omission.
    #[must_use]
    pub fn fits(&self, rows: usize) -> bool {
        rows <= self.left.min(self.group_left)
    }

    /// Rows that did not fit.
    #[must_use]
    pub fn omitted(&self) -> usize {
        self.omitted
    }

    /// Count `rows` that were dropped without trying them.
    pub fn omit(&mut self, rows: usize) {
        self.omitted += rows;
    }
}

/// FNV-1a, 64 bit: the digest printed on the summary so that photographs can be
/// matched to a log. Not a security hash.
#[derive(Clone, Copy, Debug)]
pub struct Fnv64(u64);

impl Fnv64 {
    #[must_use]
    pub const fn new() -> Self {
        Self(0xcbf2_9ce4_8422_2325)
    }

    pub fn update(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.0 ^= u64::from(byte);
            self.0 = self.0.wrapping_mul(0x0100_0000_01b3);
        }
    }

    #[must_use]
    pub const fn finish(self) -> u64 {
        self.0
    }
}

impl Default for Fnv64 {
    fn default() -> Self {
        Self::new()
    }
}

/// The 16 lowercase hex digits of `value`.
#[must_use]
pub fn hex16(value: u64) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, digit) in out.iter_mut().enumerate() {
        let nibble = u8::try_from((value >> (60 - 4 * i)) & 0xf).unwrap_or(0);
        *digit = b"0123456789abcdef"[usize::from(nibble)];
    }
    out
}

/// A UTC calendar time.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DateTime {
    pub year: i64,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

/// Civil time of a Unix timestamp (seconds since 1970-01-01T00:00:00Z).
#[must_use]
pub fn civil_from_unix(secs: i64) -> DateTime {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Hinnant's civil_from_days, era = 400 years.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let narrow = |value: i64| u8::try_from(value).unwrap_or(0);
    DateTime {
        year,
        month: narrow(month),
        day: narrow(day),
        hour: narrow(rem / 3600),
        minute: narrow(rem % 3600 / 60),
        second: narrow(rem % 60),
    }
}

/// PCI vendor names for the inventory: only the vendors a workstation lists
/// most often, anything else prints as its id.
#[must_use]
pub fn pci_vendor(id: u16) -> &'static str {
    match id {
        0x1002 => "AMD/ATI",
        0x1022 => "AMD",
        0x10de => "NVIDIA",
        0x8086 => "Intel",
        0x10ec => "Realtek",
        0x14c3 => "MediaTek",
        0x1b21 => "ASMedia",
        0x144d => "Samsung",
        0x15b7 => "SanDisk/WD",
        0x1987 => "Phison",
        0x1d97 => "Longsys",
        0x1e0f => "KIOXIA",
        0x2646 => "Kingston",
        0x1969 | 0x168c => "Qualcomm Atheros",
        0x1b73 => "Fresco Logic",
        0x1912 => "Renesas",
        0x1af4 => "virtio",
        0x1234 => "QEMU",
        0x1b36 => "Red Hat/QEMU",
        _ => "",
    }
}

/// Name of a PCI class (`base`, `sub`) as in the PCI code-and-ID assignment
/// list; empty for classes the inventory does not name.
#[must_use]
pub fn pci_class(base: u8, sub: u8) -> &'static str {
    match (base, sub) {
        (0x01, 0x01) => "IDE",
        (0x01, 0x06) => "SATA",
        (0x01, 0x08) => "NVMe/NVM",
        (0x01, _) => "storage",
        (0x02, 0x00) => "ethernet",
        (0x02, _) => "network",
        (0x03, 0x00) => "VGA",
        (0x03, 0x02) => "3D",
        (0x03, _) => "display",
        (0x04, 0x03) => "HD audio",
        (0x04, _) => "multimedia",
        (0x05, _) => "memory",
        (0x06, 0x00) => "host bridge",
        (0x06, 0x01) => "ISA bridge",
        (0x06, 0x04) => "PCI bridge",
        (0x06, _) => "bridge",
        (0x07, _) => "communication",
        (0x08, 0x06) => "IOMMU",
        (0x08, _) => "system peripheral",
        (0x0c, 0x03) => "USB",
        (0x0c, 0x05) => "SMBus",
        (0x0c, _) => "serial bus",
        (0x0d, _) => "wireless",
        (0x10, _) => "encryption",
        (0x11, _) => "signal processing",
        (0x12, _) => "accelerator",
        (0xff, _) => "unassigned",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{borrow::ToOwned, format, string::String, vec::Vec};

    fn table(group: &str) -> Vec<String> {
        expected_rows(ORACLE_EXPECTED, group)
            .map(|(_, line)| String::from_utf8(line.to_vec()).unwrap())
            .collect()
    }

    fn output_of(lines: &[String]) -> Vec<u8> {
        let mut out = b"init: argc=1 argv0=/init\nkernel noise\n".to_vec();
        for line in lines {
            out.extend_from_slice(line.as_bytes());
            out.push(b'\n');
        }
        out.extend_from_slice(b"init: ok\n");
        out
    }

    #[test]
    fn every_supported_and_unsupported_group_has_rows() {
        for group in GROUPS {
            assert!(!table(group).is_empty(), "{group}");
        }
        for (group, _) in UNSUPPORTED {
            assert!(!table(group).is_empty(), "{group}");
        }
        assert_eq!(table("nonexistent").len(), 0);
    }

    #[test]
    fn exact_output_passes() {
        for group in GROUPS {
            let lines = table(group);
            let report = compare_group(ORACLE_EXPECTED, group, &output_of(&lines));
            assert!(report.passed(), "{group}: {report:?}");
            assert_eq!(report.expected, lines.len());
            assert_eq!(report.matched, lines.len());
        }
    }

    #[test]
    fn console_crlf_output_passes() {
        let lines = table("time");
        let mut crlf = Vec::new();
        for byte in output_of(&lines) {
            if byte == b'\n' {
                crlf.push(b'\r');
            }
            crlf.push(byte);
        }
        assert!(compare_group(ORACLE_EXPECTED, "time", &crlf).passed());
    }

    #[test]
    fn a_changed_missing_extra_or_reordered_line_fails() {
        let lines = table("ids");
        let mutate = |f: &dyn Fn(&mut Vec<String>)| {
            let mut changed = lines.clone();
            f(&mut changed);
            compare_group(ORACLE_EXPECTED, "ids", &output_of(&changed))
        };
        let changed = mutate(&|l| l[2].push_str(" FAIL"));
        assert!(!changed.passed());
        assert_eq!(changed.mismatch_count, 1);
        assert_eq!(changed.mismatches[0].position, 2);
        assert_eq!(
            changed.mismatches[0].expected.as_bytes(),
            lines[2].as_bytes()
        );
        let missing = mutate(&|l| {
            l.remove(1);
        });
        assert!(!missing.passed());
        assert!(missing.mismatch_count >= 1);
        let extra = mutate(&|l| l.push("init: test ids.extra ok".to_owned()));
        assert!(!extra.passed());
        assert_eq!(extra.observed, lines.len() + 1);
        assert_eq!(extra.mismatches[0].expected.as_bytes(), b"<none>");
        let swapped = mutate(&|l| l.swap(0, 1));
        assert!(!swapped.passed());
        // Another group's lines never satisfy this group.
        let wrong = compare_group(ORACLE_EXPECTED, "ids", &output_of(&table("time")));
        assert!(!wrong.passed());
    }

    #[test]
    fn mismatches_are_counted_beyond_the_kept_ones() {
        let lines: Vec<String> = table("ids").iter().map(|l| format!("{l}x")).collect();
        let report = compare_group(ORACLE_EXPECTED, "ids", &output_of(&lines));
        assert!(report.mismatch_count > MAX_MISMATCHES);
        assert_eq!(report.mismatches[MAX_MISMATCHES - 1].position, 2);
    }

    #[test]
    fn info_rows_match_by_key_only() {
        let fs = expected_rows(ORACLE_EXPECTED, "fs")
            .map(|(kind, line)| (kind.to_vec(), String::from_utf8(line.to_vec()).unwrap()))
            .collect::<Vec<_>>();
        let info = fs
            .iter()
            .position(|(kind, _)| kind == b"info")
            .expect("fs has an info row");
        let mut lines = table("fs");
        let key: Vec<&str> = lines[info].splitn(4, ' ').take(3).collect();
        lines[info] = format!("{} different value", key.join(" "));
        assert!(compare_group(ORACLE_EXPECTED, "fs", &output_of(&lines)).passed());
        lines[info] = "init: info other.key value".to_owned();
        assert!(!compare_group(ORACLE_EXPECTED, "fs", &output_of(&lines)).passed());
    }

    #[test]
    fn init_failure_and_truncation_are_reported() {
        let lines = table("time");
        let mut out = output_of(&lines[..3]);
        let end = out.len() - b"init: ok\n".len();
        out.truncate(end);
        out.extend_from_slice(b"init: FAIL something got=Err(EINVAL)\n");
        let report = compare_group(ORACLE_EXPECTED, "time", &out);
        assert!(!report.passed());
        assert!(!report.finished);
        assert_eq!(
            report.init_failure.unwrap().as_bytes(),
            b"init: FAIL something got=Err(EINVAL)"
        );
        // An empty output (init never ran) fails with every line missing.
        let none = compare_group(ORACLE_EXPECTED, "time", b"");
        assert!(!none.passed());
        assert_eq!(none.mismatches[0].got.as_bytes(), b"<missing>");
        // A group the table does not know cannot pass.
        assert!(!compare_group(ORACLE_EXPECTED, "nonexistent", b"init: ok\n").passed());
    }

    #[test]
    fn text_formats_cuts_and_displays_safely() {
        let text = Text::from_args(format_args!("cpu {} {:#x}", "abc", 255));
        assert_eq!(text.as_bytes(), b"cpu abc 0xff");
        let long = Text::from_args(format_args!("{}", "x".repeat(LINE_MAX + 20)));
        assert_eq!(long.as_bytes().len(), LINE_MAX);
        assert_eq!(format!("{}", Text::new(b"a\x01b\xffc")), "a?b?c");
    }

    #[test]
    fn text_truncates_and_marks_it() {
        let long = [b'a'; LINE_MAX + 5];
        let text = Text::new(&long);
        assert_eq!(text.as_bytes().len(), LINE_MAX);
        assert_eq!(text.as_bytes()[LINE_MAX - 1], b'~');
        assert_eq!(Text::new(b"short").as_bytes(), b"short");
    }

    #[test]
    fn digest_is_fnv1a_64() {
        assert_eq!(Fnv64::new().finish(), 0xcbf2_9ce4_8422_2325);
        let mut hash = Fnv64::new();
        hash.update(b"a");
        assert_eq!(hash.finish(), 0xaf63_dc4c_8601_ec8c);
        let mut split = Fnv64::new();
        split.update(b"foo");
        split.update(b"bar");
        let mut whole = Fnv64::new();
        whole.update(b"foobar");
        assert_eq!(split.finish(), whole.finish());
        assert_eq!(whole.finish(), 0x8594_4171_f739_67e8);
        assert_eq!(&hex16(0xaf63_dc4c_8601_ec8c), b"af63dc4c8601ec8c");
        assert_eq!(&hex16(1), b"0000000000000001");
    }

    #[test]
    fn civil_time_matches_known_dates() {
        let date = |secs| {
            let t = civil_from_unix(secs);
            (t.year, t.month, t.day, t.hour, t.minute, t.second)
        };
        assert_eq!(date(0), (1970, 1, 1, 0, 0, 0));
        assert_eq!(date(951_782_400), (2000, 2, 29, 0, 0, 0));
        assert_eq!(date(1_000_000_000), (2001, 9, 9, 1, 46, 40));
        assert_eq!(date(1_781_913_600 + 3661), (2026, 6, 20, 1, 1, 1));
        assert_eq!(date(-1), (1969, 12, 31, 23, 59, 59));
        assert_eq!(date(4_102_444_799), (2099, 12, 31, 23, 59, 59));
    }

    #[test]
    fn pci_names_cover_the_common_classes() {
        assert_eq!(pci_class(0x03, 0x00), "VGA");
        assert_eq!(pci_class(0x06, 0x04), "PCI bridge");
        assert_eq!(pci_class(0x01, 0x08), "NVMe/NVM");
        assert_eq!(pci_class(0x7e, 0), "");
        assert_eq!(pci_vendor(0x1022), "AMD");
        assert_eq!(pci_vendor(0xdead), "");
    }

    #[test]
    fn long_lines_wrap_and_the_budget_is_shared() {
        assert_eq!(rows_for(0, 80), 1);
        assert_eq!(rows_for(80, 80), 1);
        assert_eq!(rows_for(81, 80), 2);
        assert_eq!(rows_for(500, 0), 1);
        // Nine rows for three failing groups: three each.
        let mut budget = RowBudget::new(9, 3);
        let mut shown = [0usize; 3];
        for slot in &mut shown {
            budget.group();
            while budget.take(1) {
                *slot += 1;
            }
        }
        assert_eq!(shown, [3, 3, 3]);
        assert_eq!(budget.omitted(), 3);
        // A pair that does not fit is dropped whole and counted.
        let mut budget = RowBudget::new(3, 1);
        budget.group();
        assert!(budget.take(2));
        assert!(!budget.fits(2));
        budget.omit(2);
        assert_eq!(budget.omitted(), 2);
        // The minimum share is two rows, but never more than the whole.
        let mut budget = RowBudget::new(1, 4);
        budget.group();
        assert!(budget.take(1));
        assert!(!budget.take(1));
    }
}
