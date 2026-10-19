// SPDX-License-Identifier: GPL-2.0-only
//! Offline structural audit and bounded kernel artifact tooling, not parity proof.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

mod fixture;
mod kernel;
mod package;

const USAGE: &str = "Usage: xtask <check|status> [--root PATH]
       xtask kernel-build --output target/kernel-tooling/<new-directory> [--root PATH]
       xtask kernel-test --output target/kernel-tooling/<new-directory> [--root PATH] [--timeout-seconds N]
       xtask kernel-package --build-output PATH --output target/kernel-tooling/<new-directory> [--root PATH]
       xtask --help

Offline structural audit plus bounded x86_64 QEMU tooling; kernel test results do not establish physical Linux parity or performance.
--root may precede or follow the command. Kernel output must be a new direct child of <root>/target/kernel-tooling.
Exit: 0 success, 1 audit/build/test failure, 2 usage error.";
const REFERENCE: &str = "planning/reference.tsv";
const WORKSTREAMS: &str = "planning/workstreams.tsv";
const UPSTREAM: &str = "planning/upstream-paths.tsv";
const SKILLS: [&str; 16] = [
    "kernel-abi",
    "kernel-architecture",
    "kernel-concurrency",
    "kernel-dependencies",
    "kernel-documentation",
    "kernel-drivers",
    "kernel-firmware",
    "kernel-memory",
    "kernel-networking",
    "kernel-performance",
    "kernel-porting",
    "kernel-release",
    "kernel-security",
    "kernel-storage",
    "kernel-unsafe",
    "kernel-verification",
];
const PROHIBITED_EXTENSIONS: &[&str] = &[
    "c", "h", "cc", "hh", "cpp", "hpp", "cxx", "hxx", "c++", "h++", "m", "mm", "s", "asm", "zig",
    "go", "py", "pyw", "pyc", "pyo", "sh", "bash", "zsh", "fish", "ksh", "csh", "pl", "pm", "rb",
    "js", "mjs", "cjs", "jsx", "ts", "tsx", "lua", "java", "class", "kt", "kts", "scala", "cs",
    "fs", "fsx", "vb", "swift", "d", "f", "f77", "f90", "f95", "for", "pas", "pp", "ada", "adb",
    "ads", "v", "sv", "vhd", "vhdl", "ll", "bc", "wasm", "wat", "o", "obj", "a", "so", "dll",
    "exe", "bat", "cmd", "ps1", "r", "php", "ex", "exs", "erl", "hrl", "hs", "lhs", "ml", "mli",
    "clj", "cljs", "lisp", "el", "tcl", "awk", "sed", "nix", "meson",
];

type Result<T, E = io::Error> = std::result::Result<T, E>;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn contextual(path: &Path, error: &io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{}: {error}", path.display()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Command {
    Check,
    Status,
    KernelBuild,
    KernelTest,
    KernelPackage,
}

struct Options {
    command: Command,
    root: PathBuf,
    // Empty unless the command requires them; the parser rejects empty values and
    // `validate_command_options` guarantees kernel commands supply them.
    output: PathBuf,
    build_output: PathBuf,
    timeout_seconds: u64,
}

fn arguments() -> std::result::Result<Option<Options>, String> {
    arguments_from(env::args_os().skip(1))
}

fn arguments_from(
    mut args: impl Iterator<Item = std::ffi::OsString>,
) -> std::result::Result<Option<Options>, String> {
    let mut command = None;
    let mut root = None;
    let mut output = None;
    let mut build_output = None;
    let mut timeout_seconds = None;
    let mut help = false;
    while let Some(arg) = args.next() {
        if arg == "--root" {
            if root.is_some() {
                return Err("--root supplied more than once".into());
            }
            let value = args.next().ok_or("--root requires a path")?;
            if value.is_empty() || value.to_string_lossy().starts_with('-') {
                return Err("--root requires a nonempty path (use ./ for a leading hyphen)".into());
            }
            root = Some(PathBuf::from(value));
        } else if arg == "--output" {
            if output.is_some() {
                return Err("--output supplied more than once".into());
            }
            let value = args.next().ok_or("--output requires a path")?;
            if value.is_empty() || value.to_string_lossy().starts_with('-') {
                return Err("--output requires a nonempty path".into());
            }
            output = Some(PathBuf::from(value));
        } else if arg == "--build-output" {
            if build_output.is_some() {
                return Err("--build-output supplied more than once".into());
            }
            let value = args.next().ok_or("--build-output requires a path")?;
            if value.is_empty() || value.to_string_lossy().starts_with('-') {
                return Err("--build-output requires a nonempty path".into());
            }
            build_output = Some(PathBuf::from(value));
        } else if arg == "--timeout-seconds" {
            if timeout_seconds.is_some() {
                return Err("--timeout-seconds supplied more than once".into());
            }
            let value = args
                .next()
                .ok_or("--timeout-seconds requires a positive integer")?;
            let seconds = value
                .to_str()
                .ok_or("--timeout-seconds requires a positive integer")?
                .parse::<u64>()
                .map_err(|_| "--timeout-seconds requires a positive integer")?;
            if !(1..=300).contains(&seconds) {
                return Err("--timeout-seconds must be between 1 and 300".into());
            }
            timeout_seconds = Some(seconds);
        } else if arg == "--help" || arg == "-h" {
            help = true;
        } else {
            let parsed = if arg == "check" {
                Command::Check
            } else if arg == "status" {
                Command::Status
            } else if arg == "kernel-build" {
                Command::KernelBuild
            } else if arg == "kernel-test" {
                Command::KernelTest
            } else if arg == "kernel-package" {
                Command::KernelPackage
            } else {
                // Preserve escaped raw OS bytes instead of emitting terminal
                // controls or replacing invalid UTF-8 in an unknown argument.
                return Err(format!(
                    "unknown argument '{}'",
                    arg.as_encoded_bytes().escape_ascii()
                ));
            };
            if command.replace(parsed).is_some() {
                return Err("supply exactly one command".into());
            }
        }
    }
    if help {
        return Ok(None);
    }
    let command = command.ok_or(
        "missing command: expected check, status, kernel-build, kernel-test or kernel-package",
    )?;
    validate_command_options(
        command,
        output.as_deref(),
        build_output.as_deref(),
        timeout_seconds,
    )?;
    Ok(Some(Options {
        command,
        root: root.unwrap_or_else(|| PathBuf::from(".")),
        output: output.unwrap_or_default(),
        build_output: build_output.unwrap_or_default(),
        timeout_seconds: timeout_seconds.unwrap_or(15),
    }))
}

fn validate_command_options(
    command: Command,
    output: Option<&Path>,
    build_output: Option<&Path>,
    timeout_seconds: Option<u64>,
) -> std::result::Result<(), String> {
    match command {
        Command::KernelBuild | Command::KernelTest | Command::KernelPackage => {
            if output.is_none() {
                return Err(
                    "kernel commands require --output target/kernel-tooling/<new-directory>".into(),
                );
            }
        }
        Command::Check | Command::Status => {
            if output.is_some() {
                return Err("--output is only valid with a kernel artifact command".into());
            }
        }
    }
    if timeout_seconds.is_some() && command != Command::KernelTest {
        return Err("--timeout-seconds is only valid with kernel-test".into());
    }
    if command == Command::KernelPackage && build_output.is_none() {
        return Err("kernel-package requires --build-output for an existing default build".into());
    }
    if build_output.is_some() && command != Command::KernelPackage {
        return Err("--build-output is only valid with kernel-package".into());
    }
    Ok(())
}

fn main() -> ExitCode {
    let options = match arguments() {
        Ok(Some(options)) => options,
        Ok(None) => {
            return match writeln!(io::stdout().lock(), "{USAGE}") {
                Ok(()) => ExitCode::SUCCESS,
                Err(_) => ExitCode::FAILURE,
            };
        }
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "xtask: {error}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let result = match options.command {
        Command::Check | Command::Status => audit(&options),
        Command::KernelBuild => kernel::build(&options.root, &options.output),
        Command::KernelTest => kernel::test(
            &options.root,
            &options.output,
            std::time::Duration::from_secs(options.timeout_seconds),
        ),
        Command::KernelPackage => {
            package::create(&options.root, &options.build_output, &options.output)
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "xtask: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Reject aliases before reading project-controlled content. This is not a race-proof sandbox.
fn project_files(root: &Path) -> Result<BTreeSet<String>> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = BTreeSet::new();
    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(&directory).map_err(|error| contextual(&directory, &error))?;
        let mut entries = entries.collect::<std::result::Result<Vec<_>, _>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let metadata =
                fs::symlink_metadata(&path).map_err(|error| contextual(&path, &error))?;
            if metadata.file_type().is_symlink() {
                return Err(invalid(format!(
                    "{}: symlinks are not permitted",
                    path.display()
                )));
            }
            if metadata.is_dir() {
                // vendor/ is third-party source checked by `verify_project_vendor`, not Rust-only project code.
                if [".git", "target", "vendor"]
                    .iter()
                    .any(|skipped| path == root.join(skipped))
                {
                    continue;
                }
                if directory.strip_prefix(root).ok() == Some(Path::new(".agents/skills"))
                    && !entry
                        .file_name()
                        .to_str()
                        .is_some_and(|name| SKILLS.contains(&name))
                    // Symposium (`cargo agents sync`) marks its self-gitignored skill copies;
                    // they are still walked and audited, just not counted as project skills.
                    && !path.join(".symposium").is_file()
                {
                    return Err(invalid(format!(
                        "{}: unexpected skill directory",
                        path.display()
                    )));
                }
                pending.push(path);
            } else if metadata.is_file() {
                let relative = path
                    .strip_prefix(root)
                    .map_err(|error| invalid(error.to_string()))?;
                let name = relative.to_str().ok_or_else(|| {
                    invalid(format!(
                        "{}: project filenames must be UTF-8",
                        path.display()
                    ))
                })?;
                safe_path(name)?;
                if path.file_name().is_some_and(|name| name == "build.rs") {
                    return Err(invalid(format!("{name}: build scripts are not permitted")));
                }
                if path
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| {
                        PROHIBITED_EXTENSIONS
                            .iter()
                            .any(|denied| ext.eq_ignore_ascii_case(denied))
                    })
                {
                    return Err(invalid(format!(
                        "{name}: prohibited non-Rust source/artifact extension"
                    )));
                }
                files.insert(name.to_owned());
            } else {
                return Err(invalid(format!(
                    "{}: special files are not permitted",
                    path.display()
                )));
            }
        }
    }
    Ok(files)
}

fn safe_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.contains(['\\', ':'])
        || path.chars().any(char::is_control)
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(invalid(format!(
            "unsafe or non-normalized relative path {path:?}"
        )));
    }
    Ok(())
}

fn read_file(root: &Path, files: &BTreeSet<String>, path: &str) -> Result<String> {
    if !files.contains(path) {
        return Err(invalid(format!(
            "{path}: required regular project file is missing"
        )));
    }
    let full = root.join(path);
    fs::read_to_string(&full).map_err(|error| contextual(&full, &error))
}

struct Tsv<'data, const N: usize> {
    path: &'static str,
    lines: std::iter::Enumerate<std::str::SplitTerminator<'data, char>>,
    previous: Option<&'data str>,
}

impl<'data, const N: usize> Tsv<'data, N> {
    fn new(path: &'static str, text: &'data str, header: &str) -> Result<Self> {
        if !text.ends_with('\n') || text.contains('\r') {
            return Err(invalid(format!(
                "{path}: expected LF-only text with a final newline"
            )));
        }
        let mut lines = text.split_terminator('\n').enumerate();
        if lines.next().map(|(_, line)| line) != Some(header) {
            return Err(invalid(format!("{path}: expected exact header {header:?}")));
        }
        Ok(Self {
            path,
            lines,
            previous: None,
        })
    }
}

impl<'data, const N: usize> Iterator for Tsv<'data, N> {
    type Item = Result<(usize, [&'data str; N])>;

    fn next(&mut self) -> Option<Self::Item> {
        let (index, line) = self.lines.next()?;
        let number = index + 1;
        let parse = || {
            let mut fields = line.split('\t');
            let mut row = [""; N];
            for field in &mut row {
                *field = fields.next().ok_or_else(|| {
                    invalid(format!("{}:{number}: expected {N} TSV fields", self.path))
                })?;
                if field.is_empty() || field.chars().any(char::is_control) {
                    return Err(invalid(format!(
                        "{}:{number}: empty/control-containing field",
                        self.path
                    )));
                }
            }
            if fields.next().is_some() {
                return Err(invalid(format!(
                    "{}:{number}: expected exactly {N} TSV fields",
                    self.path
                )));
            }
            let first = row
                .first()
                .copied()
                .ok_or_else(|| invalid("internal empty TSV schema"))?;
            if self.previous.is_some_and(|previous| first <= previous) {
                return Err(invalid(format!(
                    "{}:{number}: duplicate identifier or records not sorted by first column: {first:?}",
                    self.path
                )));
            }
            Ok((number, row))
        };
        let result = parse();
        if let Ok((_, row)) = &result {
            self.previous = row.first().copied();
        }
        Some(result)
    }
}

fn sha(value: &str, context: &str) -> Result<()> {
    if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid(format!(
            "{context}: expected a 40-digit hexadecimal Git object ID"
        )));
    }
    Ok(())
}

fn reference(text: &str) -> Result<BTreeMap<&str, &str>> {
    let mut values = BTreeMap::new();
    for row in Tsv::<2>::new(REFERENCE, text, "key\tvalue")? {
        let (_, [key, value]) = row?;
        values.insert(key, value);
    }
    for (key, expected) in [
        ("version", "6.18.57"),
        ("tag", "v6.18.57"),
        ("repository", "https://github.com/gregkh/linux"),
        ("retrieved", "2026-10-19"),
        (
            "signature_status",
            "locally_verified_kernel_org_wkd_fingerprint_pinned_trust_undefined",
        ),
        (
            "github_signature_status",
            "github_verified_not_locally_verified",
        ),
        ("local_gpg_trust_status", "TRUST_UNDEFINED"),
        (
            "local_signature_status",
            "good_signature_fingerprint_pinned",
        ),
        (
            "local_signature_fingerprint",
            "647F28654894E3BD457199BE38DBBDC86092693E",
        ),
        (
            "local_signature_trust_path",
            "kernel.org_https_signature_page_and_wkd_tls",
        ),
        ("local_source_objects_match", "true"),
        ("inventory_complete", "true"),
    ] {
        if values.get(key).copied() != Some(expected) {
            return Err(invalid(format!("{REFERENCE}: {key} must be {expected:?}")));
        }
    }
    for key in ["tag_object", "commit", "tree"] {
        let value = values
            .get(key)
            .ok_or_else(|| invalid(format!("{REFERENCE}: missing {key}")))?;
        sha(value, &format!("{REFERENCE}: {key}"))?;
    }
    for (key, expected) in [
        ("tag_object", "c05de972ca192e22ce318dd70ce8e990b9466f6d"),
        ("commit", "2ff600d29ee478d0a8d46ef8a58afb5e038fe692"),
        ("tree", "911d5155c230d7d778ac38585e01e8ab46d75a90"),
    ] {
        if values.get(key).copied() != Some(expected) {
            return Err(invalid(format!(
                "{REFERENCE}: {key} differs from the pinned baseline object"
            )));
        }
    }
    decimal(values.get("entry_count").copied(), "entry_count")?;
    Ok(values)
}

fn decimal(value: Option<&str>, key: &str) -> Result<usize> {
    let value = value.ok_or_else(|| invalid(format!("{REFERENCE}: missing {key}")))?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid(format!(
            "{REFERENCE}: {key} must be unsigned decimal"
        )));
    }
    value
        .parse()
        .map_err(|error| invalid(format!("{REFERENCE}: invalid {key}: {error}")))
}

struct Workstream<'data> {
    id: &'data str,
    priority: &'data str,
    status: &'data str,
}

fn workstreams<'data>(
    text: &'data str,
    files: &BTreeSet<String>,
) -> Result<BTreeMap<&'data str, Workstream<'data>>> {
    let mut streams = BTreeMap::new();
    for row in Tsv::<5>::new(
        WORKSTREAMS,
        text,
        "id\tupstream_prefix\tplan\tpriority\tstatus",
    )? {
        let (line, [id, prefix, plan, priority, status]) = row?;
        if !id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(invalid(format!(
                "{WORKSTREAMS}:{line}: invalid workstream ID {id:?}"
            )));
        }
        if prefix != "." {
            safe_path(prefix)?;
        }
        safe_path(plan)?;
        if !plan.starts_with("docs/")
            || !is_markdown(plan)
            || plan.contains(['#', '?'])
            || !files.contains(plan)
        {
            return Err(invalid(format!(
                "{WORKSTREAMS}:{line}: plan {plan:?} must be an existing docs Markdown file without fragment"
            )));
        }
        if !matches!(priority, "P0" | "P1" | "P2" | "P3")
            || !matches!(status, "not_started" | "in_progress")
        {
            return Err(invalid(format!(
                "{WORKSTREAMS}:{line}: expected priority P0/P1/P2/P3 and status not_started/in_progress"
            )));
        }
        if streams
            .insert(
                prefix,
                Workstream {
                    id,
                    priority,
                    status,
                },
            )
            .is_some()
        {
            return Err(invalid(format!(
                "{WORKSTREAMS}:{line}: duplicate upstream prefix {prefix:?}"
            )));
        }
    }
    if !streams.contains_key(".") {
        return Err(invalid(format!("{WORKSTREAMS}: missing '.' root fallback")));
    }
    Ok(streams)
}

fn assignment<'streams, 'data>(
    path: &str,
    streams: &'streams BTreeMap<&'data str, Workstream<'data>>,
) -> Option<&'streams Workstream<'data>> {
    let mut prefix = path;
    loop {
        if let Some(stream) = streams.get(prefix) {
            return Some(stream);
        }
        match prefix.rsplit_once('/') {
            Some((parent, _)) => prefix = parent,
            None => return streams.get("."),
        }
    }
}

struct Inventory<'data> {
    kinds: BTreeMap<&'data str, &'data str>,
    counts: BTreeMap<&'data str, usize>,
}

fn inventory<'data>(
    text: &'data str,
    streams: &BTreeMap<&'data str, Workstream<'data>>,
) -> Result<Inventory<'data>> {
    let mut kinds = BTreeMap::new();
    let mut counts = BTreeMap::new();
    let known_ids: BTreeSet<_> = streams.values().map(|stream| stream.id).collect();
    for row in Tsv::<4>::new(UPSTREAM, text, "path\tkind\tobject\tworkstream")? {
        let (line, [path, kind, object, id]) = row?;
        safe_path(path)?;
        if !matches!(kind, "tree" | "blob" | "commit") {
            return Err(invalid(format!(
                "{UPSTREAM}:{line}: unknown object kind {kind:?}"
            )));
        }
        sha(object, UPSTREAM).map_err(|error| invalid(format!("{UPSTREAM}:{line}: {error}")))?;
        if let Some((parent, _)) = path.rsplit_once('/')
            && kinds.get(parent).copied() != Some("tree")
        {
            return Err(invalid(format!(
                "{UPSTREAM}:{line}: missing/non-tree parent {parent:?}"
            )));
        }
        if !known_ids.contains(id) {
            return Err(invalid(format!(
                "{UPSTREAM}:{line}: unknown workstream {id:?}"
            )));
        }
        let expected =
            assignment(path, streams).ok_or_else(|| invalid("missing root assignment"))?;
        if expected.id != id {
            return Err(invalid(format!(
                "{UPSTREAM}:{line}: {path:?} assigned to {id:?}, expected longest component-prefix owner {:?}",
                expected.id
            )));
        }
        kinds.insert(path, kind);
        *counts.entry(expected.id).or_default() += 1;
    }
    if kinds.is_empty() {
        return Err(invalid(format!("{UPSTREAM}: inventory must not be empty")));
    }
    for prefix in streams.keys().copied().filter(|prefix| *prefix != ".") {
        if !kinds.contains_key(prefix) {
            return Err(invalid(format!(
                "{WORKSTREAMS}: prefix {prefix:?} does not exist in pinned inventory"
            )));
        }
    }
    for (&path, &kind) in &kinds {
        let first_level_mechanism = path.split_once('/').is_some_and(|(parent, child)| {
            matches!(parent, "arch" | "drivers" | "fs" | "net")
                && !child.contains('/')
                && kind == "tree"
        });
        if ((!path.contains('/') && kind == "tree") || first_level_mechanism)
            && !streams.contains_key(path)
        {
            return Err(invalid(format!(
                "{WORKSTREAMS}: missing explicit coverage prefix {path:?}"
            )));
        }
    }
    Ok(Inventory { kinds, counts })
}

fn scalar(value: &str) -> Result<&str> {
    let value = value.trim();
    let value = if value.starts_with('"') || value.starts_with('\'') {
        let quote = value
            .chars()
            .next()
            .ok_or_else(|| invalid("empty scalar"))?;
        value
            .strip_prefix(quote)
            .and_then(|inner| inner.strip_suffix(quote))
            .ok_or_else(|| invalid("unclosed quoted skill scalar"))?
    } else {
        if value.contains(" #") || value.starts_with(['#', '|', '>', '[', '{', '&', '*', '!']) {
            return Err(invalid(
                "skill metadata requires a plain or quoted single-line scalar",
            ));
        }
        value
    };
    if value.trim().is_empty() || matches!(value, "null" | "~") {
        return Err(invalid("skill scalar must be nonempty text"));
    }
    Ok(value)
}

fn skill(path: &str, text: &str, expected: &str) -> Result<()> {
    let mut lines = text.lines();
    if lines.next() != Some("---") {
        return Err(invalid(format!(
            "{path}: missing opening frontmatter delimiter"
        )));
    }
    let mut fields = BTreeMap::new();
    let mut closed = false;
    for line in &mut lines {
        if line == "---" {
            closed = true;
            break;
        }
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once(':')
            .ok_or_else(|| invalid(format!("{path}: invalid frontmatter field")))?;
        if key.trim() != key || key.is_empty() || fields.insert(key, value).is_some() {
            return Err(invalid(format!(
                "{path}: indented/empty/duplicate frontmatter key {key:?}"
            )));
        }
    }
    if !closed {
        return Err(invalid(format!(
            "{path}: missing closing frontmatter delimiter"
        )));
    }
    let name = scalar(
        fields
            .get("name")
            .copied()
            .ok_or_else(|| invalid(format!("{path}: missing name")))?,
    )?;
    if name != expected
        || name.len() > 64
        || name.starts_with('-')
        || name.ends_with('-')
        || name.contains("--")
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(invalid(format!(
            "{path}: invalid name or name does not match directory {expected:?}"
        )));
    }
    let description = scalar(
        fields
            .get("description")
            .copied()
            .ok_or_else(|| invalid(format!("{path}: missing description")))?,
    )?;
    if description.chars().count() > 1024 {
        return Err(invalid(format!(
            "{path}: description exceeds 1024 characters"
        )));
    }
    Ok(())
}

#[derive(Default)]
struct Links {
    local: usize,
    external: usize,
    anchors: usize,
}

fn destination(
    source: &str,
    line: usize,
    target: &str,
    files: &BTreeSet<String>,
    links: &mut Links,
) -> Result<()> {
    if target.starts_with("//")
        || target.split_once(':').is_some_and(|(scheme, _)| {
            !scheme.is_empty()
                && scheme
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
        })
    {
        links.external += 1;
        return Ok(());
    }
    let file = target.split_once('#').map_or(target, |(file, _)| file);
    if file.is_empty() {
        links.anchors += 1;
        return Ok(());
    }
    if file.starts_with('/')
        || target.chars().any(char::is_whitespace)
        || file.contains(['\\', '<', '>', '(', ')', '%', '?'])
    {
        return Err(invalid(format!(
            "{source}:{line}: unsupported/unsafe local link destination {target:?}; use plain relative file links"
        )));
    }
    let mut components: Vec<_> = source.split('/').collect();
    components.pop();
    for part in file.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if components.pop().is_none() {
                    return Err(invalid(format!(
                        "{source}:{line}: link escapes project root: {target:?}"
                    )));
                }
            }
            _ => components.push(part),
        }
    }
    let normalized = components.join("/");
    if !files.contains(&normalized) {
        return Err(invalid(format!(
            "{source}:{line}: broken local file link {target:?} (resolved {normalized:?})"
        )));
    }
    links.local += 1;
    Ok(())
}

fn markdown_line(
    source: &str,
    number: usize,
    line: &str,
    files: &BTreeSet<String>,
    links: &mut Links,
) -> Result<()> {
    let mut offset = 0;
    while let Some(&byte) = line.as_bytes().get(offset) {
        if byte == b'`' {
            let run = line
                .as_bytes()
                .iter()
                .skip(offset)
                .take_while(|&&byte| byte == b'`')
                .count();
            offset += run;
            let mut closing = offset;
            while closing < line.len() {
                if line.as_bytes()[closing] == b'`' {
                    let length = line.as_bytes()[closing..]
                        .iter()
                        .take_while(|&&byte| byte == b'`')
                        .count();
                    if length == run {
                        offset = closing + length;
                        break;
                    }
                    closing += length;
                } else {
                    closing += 1;
                }
            }
        } else if byte == b'[' {
            if let Some(end) = line[offset + 1..].find("](") {
                let start = offset + 1 + end + 2;
                if let Some(close) = line[start..].find(')') {
                    destination(source, number, &line[start..start + close], files, links)?;
                    offset = start + close + 1;
                } else {
                    return Err(invalid(format!(
                        "{source}:{number}: unterminated inline link"
                    )));
                }
            } else {
                offset += 1;
            }
        } else {
            // Only ASCII delimiter positions are sliced; UTF-8 continuation bytes are never sliced.
            offset += 1;
        }
    }
    Ok(())
}

fn markdown(source: &str, text: &str, files: &BTreeSet<String>, links: &mut Links) -> Result<()> {
    let mut fence = None;
    for (index, line) in text.lines().enumerate() {
        if line.starts_with("    ") || line.starts_with('\t') {
            continue;
        }
        let trimmed = line.trim_start_matches(' ');
        let marker = trimmed.as_bytes().first().copied();
        let run = trimmed
            .bytes()
            .take_while(|byte| Some(*byte) == marker)
            .count();
        if let Some((open, length)) = fence {
            if marker == Some(open) && run >= length && trimmed[run..].trim().is_empty() {
                fence = None;
            }
            continue;
        }
        if matches!(marker, Some(b'`' | b'~')) && run >= 3 {
            if let Some(marker) = marker {
                fence = Some((marker, run));
            }
            continue;
        }
        markdown_line(source, index + 1, line, files, links)?;
    }
    Ok(())
}

fn is_markdown(path: &str) -> bool {
    Path::new(path)
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("md"))
}

fn validate_skills(root: &Path, files: &BTreeSet<String>) -> Result<()> {
    for path in files {
        if let Some(relative) = path.strip_prefix(".agents/skills/") {
            let name = relative
                .split('/')
                .next()
                .ok_or_else(|| invalid("invalid skill path"))?;
            if !SKILLS.contains(&name) {
                if files.contains(&format!(".agents/skills/{name}/.symposium")) {
                    continue;
                }
                return Err(invalid(format!(
                    "{path}: unexpected skill (expected the approved 16-skill set)"
                )));
            }
            if path.ends_with("/SKILL.md") && relative.split('/').count() != 2 {
                return Err(invalid(format!(
                    "{path}: nested skill entry points are not permitted"
                )));
            }
        }
    }
    for name in SKILLS {
        let path = format!(".agents/skills/{name}/SKILL.md");
        let text = read_file(root, files, &path)?;
        skill(&path, &text, name)?;
    }
    Ok(())
}

fn implementation_routes(streams: &BTreeMap<&str, Workstream<'_>>, evidence: &str) -> Result<()> {
    for stream in streams
        .values()
        .filter(|stream| stream.status == "in_progress")
    {
        let routed = evidence.lines().any(|line| {
            line.strip_prefix("| `")
                .and_then(|row| row.split_once("` /"))
                .is_some_and(|(id, _)| id == stream.id)
        });
        if !routed {
            return Err(invalid(format!(
                "{}: in_progress workstream requires an explicit routing-table row in docs/implementation.md",
                stream.id
            )));
        }
    }
    Ok(())
}

fn audit(options: &Options) -> Result<()> {
    let metadata =
        fs::symlink_metadata(&options.root).map_err(|error| contextual(&options.root, &error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(invalid("--root must name a real directory, not a symlink"));
    }
    let mut vendored = 0;
    let root =
        fs::canonicalize(&options.root).map_err(|error| contextual(&options.root, &error))?;
    let files = project_files(&root)?;
    if files.contains("Cargo.lock") || root.join("vendor").exists() {
        let sha256sum = kernel::resolve_program(Path::new("sha256sum"))?;
        let packages = kernel::verify_project_vendor(&root, &sha256sum)?;
        vendored = packages.len();
    }
    let reference_text = read_file(&root, &files, REFERENCE)?;
    let reference = reference(&reference_text)?;
    let workstream_text = read_file(&root, &files, WORKSTREAMS)?;
    let streams = workstreams(&workstream_text, &files)?;
    if streams
        .values()
        .any(|stream| stream.status == "in_progress")
    {
        let evidence = read_file(&root, &files, "docs/implementation.md")?;
        implementation_routes(&streams, &evidence)?;
    }
    let upstream_text = read_file(&root, &files, UPSTREAM)?;
    let inventory = inventory(&upstream_text, &streams)?;
    let expected = decimal(reference.get("entry_count").copied(), "entry_count")?;
    if expected != inventory.kinds.len() {
        return Err(invalid(format!(
            "{REFERENCE}: entry_count {expected} does not match {} inventory records",
            inventory.kinds.len()
        )));
    }
    for kind in ["tree", "blob", "commit"] {
        let key = format!("{kind}_count");
        if let Some(value) = reference.get(key.as_str()) {
            let expected = decimal(Some(value), &key)?;
            let actual = inventory
                .kinds
                .values()
                .filter(|&&value| value == kind)
                .count();
            if expected != actual {
                return Err(invalid(format!(
                    "{REFERENCE}: {key} {expected} does not match {actual}"
                )));
            }
        }
    }
    validate_skills(&root, &files)?;
    let mut links = Links::default();
    let mut markdown_count = 0;
    for path in files.iter().filter(|path| is_markdown(path)) {
        let text = read_file(&root, &files, path)?;
        markdown(path, &text, &files, &mut links)?;
        markdown_count += 1;
    }
    let mut output = io::stdout().lock();
    // `main` routes only check and status here.
    match options.command {
        Command::Check => writeln!(
            output,
            "check: structural audit passed; {} pinned upstream entries, {} planned workstreams, {} skills, {markdown_count} Markdown files, {} local file links checked, {vendored} vendored packages verified",
            inventory.kinds.len(),
            streams.len(),
            SKILLS.len(),
            links.local
        )?,
        _ => {
            write_status(&mut output, &streams, &inventory)?;
        }
    }
    writeln!(
        output,
        "Not validated: {} external link destinations, {} anchor-only links, all fragment anchors, signatures, semantic completeness, kernel execution or performance.",
        links.external, links.anchors
    )?;
    writeln!(
        output,
        "Planning counts are not a Linux compatibility percentage. These audit commands do not build or test the kernel."
    )?;
    Ok(())
}

fn write_status(
    output: &mut impl Write,
    streams: &BTreeMap<&str, Workstream<'_>>,
    inventory: &Inventory<'_>,
) -> Result<()> {
    writeln!(
        output,
        "Baseline: Linux 6.18.57; inventory records: {}",
        inventory.kinds.len()
    )?;
    writeln!(
        output,
        "Planned workstreams: {}; statuses describe routed activity, not completion",
        streams.len()
    )?;
    for status in ["not_started", "in_progress"] {
        let count = streams
            .values()
            .filter(|stream| stream.status == status)
            .count();
        writeln!(output, "  {status}: {count} workstreams")?;
    }
    for priority in ["P0", "P1", "P2", "P3"] {
        let count = streams
            .values()
            .filter(|stream| stream.priority == priority)
            .count();
        writeln!(output, "  {priority}: {count} planned workstreams")?;
    }
    writeln!(
        output,
        "workstream\tpriority\tstatus\tassigned_upstream_entries"
    )?;
    let by_id: BTreeMap<_, _> = streams.values().map(|stream| (stream.id, stream)).collect();
    for (id, stream) in by_id {
        writeln!(
            output,
            "{id}\t{}\t{}\t{}",
            stream.priority,
            stream.status,
            inventory.counts.get(id).copied().unwrap_or_default()
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_root_target_git_and_vendor_are_skipped() -> Result<()> {
        let root = std::env::temp_dir().join(format!("linux-rs-audit-{}", std::process::id()));
        for directory in [".git", "target", "vendor", "src/target"] {
            fs::create_dir_all(root.join(directory))?;
            fs::write(root.join(directory).join("evil.txt"), "")?;
        }
        let files = project_files(&root);
        fs::write(root.join("src/target/evil.c"), "")?;
        let rejected = project_files(&root);
        fs::remove_dir_all(&root)?;
        assert_eq!(
            files?.into_iter().collect::<Vec<_>>(),
            ["src/target/evil.txt"]
        );
        assert!(rejected.is_err());
        Ok(())
    }

    #[test]
    fn tsv_rejects_bad_framing_and_duplicates() -> Result<()> {
        for input in ["wrong\tvalue\n", "key\tvalue\r\n", "key\tvalue"] {
            assert!(Tsv::<2>::new(REFERENCE, input, "key\tvalue").is_err());
        }
        for input in [
            "key\tvalue\na\t1\na\t2\n",
            "key\tvalue\nb\t1\na\t2\n",
            "key\tvalue\na\t\n",
            "key\tvalue\na\t1\textra\n",
            "key\tvalue\n\n",
        ] {
            let rows = Tsv::<2>::new(REFERENCE, input, "key\tvalue")?;
            assert!(rows.collect::<Result<Vec<_>>>().is_err());
        }
        let rows = Tsv::<2>::new(REFERENCE, "key\tvalue\na\t1\nb\t2\n", "key\tvalue")?;
        assert_eq!(rows.collect::<Result<Vec<_>>>()?.len(), 2);
        Ok(())
    }

    #[test]
    fn active_workstreams_require_routing_without_a_completion_state() -> Result<()> {
        let files = BTreeSet::from(["docs/plan.md".to_owned()]);
        let header = "id\tupstream_prefix\tplan\tpriority\tstatus\n";
        let text = format!("{header}root\t.\tdocs/plan.md\tP0\tin_progress\n");
        let streams = workstreams(&text, &files)?;
        assert_eq!(
            streams.get(".").map(|stream| stream.status),
            Some("in_progress")
        );
        assert!(implementation_routes(&streams, "no implementation route").is_err());
        implementation_routes(&streams, "| `root` / . | actual implementation |")?;
        for status in ["done", "ported", "qualified", "unknown"] {
            let text = format!("{header}root\t.\tdocs/plan.md\tP0\t{status}\n");
            assert!(workstreams(&text, &files).is_err());
        }
        Ok(())
    }

    #[test]
    fn package_arguments_require_an_explicit_build_and_reject_test_flags() -> Result<()> {
        let output = "target/kernel-tooling/new-package";
        let parsed = arguments_from(
            [
                "kernel-package",
                "--build-output",
                "target/kernel-tooling/run/default-build",
                "--output",
                output,
            ]
            .into_iter()
            .map(std::ffi::OsString::from),
        )
        .map_err(invalid)?
        .ok_or_else(|| invalid("unexpected help response"))?;
        assert_eq!(parsed.command, Command::KernelPackage);
        assert_eq!(parsed.output, Path::new(output));
        let invalid_args: &[&[&str]] = &[
            &["kernel-package", "--output", output],
            &[
                "kernel-build",
                "--output",
                output,
                "--build-output",
                "input",
            ],
            &[
                "kernel-package",
                "--build-output",
                "input",
                "--output",
                output,
                "--timeout-seconds",
                "1",
            ],
            &["status", "--build-output", "input"],
        ];
        for args in invalid_args {
            assert!(arguments_from(args.iter().map(|arg| std::ffi::OsString::from(*arg))).is_err());
        }
        Ok(())
    }

    #[test]
    fn routing_uses_longest_component_prefix() {
        let streams = BTreeMap::from([
            (
                ".",
                Workstream {
                    id: "root",
                    priority: "P0",
                    status: "not_started",
                },
            ),
            (
                "net",
                Workstream {
                    id: "net",
                    priority: "P1",
                    status: "not_started",
                },
            ),
            (
                "net/ipv4",
                Workstream {
                    id: "ipv4",
                    priority: "P1",
                    status: "not_started",
                },
            ),
        ]);
        assert_eq!(
            assignment("net/ipv4/tcp.c", &streams).map(|stream| stream.id),
            Some("ipv4")
        );
        assert_eq!(
            assignment("net/ipv6/ip6.c", &streams).map(|stream| stream.id),
            Some("net")
        );
        assert_eq!(
            assignment("network/file", &streams).map(|stream| stream.id),
            Some("root")
        );
        assert_eq!(
            assignment("net", &streams).map(|stream| stream.id),
            Some("net")
        );
    }

    #[test]
    fn paths_and_object_ids_are_validated() {
        for path in [
            "",
            "/root",
            "../outside",
            "a/../b",
            "a//b",
            "a/",
            "a\\b",
            "C:drive",
        ] {
            assert!(safe_path(path).is_err());
        }
        assert!(safe_path(".config/valid file").is_ok());
        assert!(sha("0123456789abcdef0123456789abcdef01234567", "fixture").is_ok());
        assert!(sha("g123456789abcdef0123456789abcdef01234567", "fixture").is_err());
        assert!(sha("abc", "fixture").is_err());
    }

    #[test]
    fn markdown_checks_files_without_fetching_external_links() -> Result<()> {
        let files = BTreeSet::from(["docs/source.md".to_owned(), "README.md".to_owned()]);
        let mut links = Links::default();
        markdown(
            "docs/source.md",
            "[root](../README.md#unverified)\n[remote](https://invalid.example/no-fetch)\n[anchor](#unverified)\n```\n[ignored](missing.md)\n```\n`[ignored](missing.md)`\n",
            &files,
            &mut links,
        )?;
        assert_eq!((links.local, links.external, links.anchors), (1, 1, 1));
        assert!(destination("docs/source.md", 1, "../../outside", &files, &mut links).is_err());
        assert!(destination("docs/source.md", 1, "missing.md", &files, &mut links).is_err());
        assert!(destination("docs/source.md", 1, "../", &files, &mut links).is_err());
        Ok(())
    }

    #[test]
    fn markdown_does_not_open_fences_in_indented_code() {
        let files = BTreeSet::new();
        for text in [
            "    ~~~\n\n[broken](missing.md)\n",
            "    ```\n\n[broken](missing.md)\n",
            "\t~~~\n\n[broken](missing.md)\n",
            "\u{2003}~~~\n\n[broken](missing.md)\n",
        ] {
            let error = markdown("source.md", text, &files, &mut Links::default())
                .expect_err("a non-fence must not hide the following link");
            assert!(
                error
                    .to_string()
                    .contains("source.md:3: broken local file link")
            );
        }
    }

    #[test]
    fn markdown_fences_allow_only_up_to_three_leading_spaces() -> Result<()> {
        let files = BTreeSet::from(["README.md".to_owned()]);
        for indent in ["", " ", "  ", "   "] {
            for delimiter in ["```", "~~~"] {
                let text = format!(
                    "{indent}{delimiter}rust\n[ignored](missing.md)\n    {delimiter}\n[still ignored](missing.md)\n{indent}{delimiter}\n[root](README.md)\n"
                );
                let mut links = Links::default();
                markdown("source.md", &text, &files, &mut links)?;
                assert_eq!(links.local, 1);
            }
        }
        Ok(())
    }

    #[test]
    fn markdown_unmatched_backtick_runs_are_literal() {
        let files = BTreeSet::new();
        for text in [
            "literal ` [broken](missing.md)",
            "literal `` [broken](missing.md)",
            "literal `unmatched`` [broken](missing.md)",
            "literal ``unmatched``` [broken](missing.md)",
            "literal ``unmatched` [broken](missing.md)",
        ] {
            let error = markdown("source.md", text, &files, &mut Links::default())
                .expect_err("unmatched delimiters must not hide rendered links");
            assert!(error.to_string().contains("broken local file link"));
        }
    }

    #[test]
    fn markdown_code_spans_close_only_on_equal_backtick_runs() -> Result<()> {
        let files = BTreeSet::from(["README.md".to_owned()]);
        for text in [
            "`[ignored](missing.md)` [root](README.md)",
            "``[ignored](missing.md)`` [root](README.md)",
            "`code``[ignored](missing.md)` [root](README.md)",
            "``code```[ignored](missing.md)`` [root](README.md)",
            "``code`[ignored](missing.md)`` [root](README.md)",
        ] {
            let mut links = Links::default();
            markdown("source.md", text, &files, &mut links)?;
            assert_eq!(links.local, 1);
        }
        Ok(())
    }

    #[test]
    fn skills_reject_comment_only_values_but_accept_quoted_hashes() {
        let path = ".agents/skills/kernel-abi/SKILL.md";
        for description in ["# explanation", "  # explanation", "#"] {
            let text = format!("---\nname: kernel-abi\ndescription: {description}\n---\n");
            assert!(skill(path, &text, "kernel-abi").is_err());
        }
        for description in ["'#'", "\"#\"", "'# explanation'", "\"# explanation\""] {
            let text = format!("---\nname: kernel-abi\ndescription: {description}\n---\n");
            assert!(skill(path, &text, "kernel-abi").is_ok());
        }
    }

    #[test]
    fn skills_require_matching_name_and_nonempty_description() {
        let path = ".agents/skills/kernel-abi/SKILL.md";
        assert!(
            skill(
                path,
                "---\nname: kernel-abi\ndescription: Check ABI contracts.\n---\n",
                "kernel-abi"
            )
            .is_ok()
        );
        for text in [
            "name: kernel-abi\ndescription: ABI\n",
            "---\nname: kernel-abi\ndescription: ABI\n",
            "---\nname: wrong\ndescription: ABI\n---\n",
            "---\nname: kernel-abi\ndescription: ''\n---\n",
            "---\nname: kernel-abi\nname: kernel-abi\ndescription: ABI\n---\n",
        ] {
            assert!(skill(path, text, "kernel-abi").is_err());
        }
    }

    #[test]
    fn unknown_arguments_escape_controls_and_non_utf8_bytes() -> Result<()> {
        use std::os::unix::ffi::OsStringExt;
        let argument = std::ffi::OsString::from_vec(vec![0xff, b'\n', 0x1b]);
        let Err(error) = arguments_from([argument].into_iter()) else {
            return Err(invalid("unknown raw argument unexpectedly accepted"));
        };
        assert!(error.contains("\\xff"));
        assert!(error.contains("\\n"));
        assert!(error.contains("\\x1b"));
        assert!(!error.contains('\n'));
        assert!(!error.contains('\u{1b}'));
        Ok(())
    }
}
