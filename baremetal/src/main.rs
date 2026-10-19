// SPDX-License-Identifier: GPL-2.0-only

#![forbid(unsafe_code)]

#[cfg(not(target_os = "linux"))]
compile_error!("baremetal runs on Linux-compatible userspace only");

use std::env;
use std::ffi::OsString;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::{Shutdown, TcpListener, TcpStream, UdpSocket};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, symlink};
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitCode, ExitStatus, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const HELP: &str = "baremetal: bounded, non-destructive Linux functional smoke (NOT qualification)\n\nUsage:\n  baremetal run --output <new-directory> --label <label> --expect-release <exact-osrelease> --environment <reference|qemu|bare-metal>\n  baremetal --help\n  baremetal run --help\n\nAll run options are required once. No positional arguments or implicit environment.\nLabels: 1..80 ASCII letters/digits/dot/underscore/hyphen, starting with a letter/digit.\nThe release must exactly match /proc/sys/kernel/osrelease before output is created.\nEnvironment is the operator's assertion, not automatic physical-machine detection.\nOutput parent must already exist and be trusted; output itself must not exist.\nPreserves reports and a private bounded sandbox; does not clean up arbitrary paths.\nNever use root. No raw devices, mounts, external networking, boot or system changes.\nExit: 0=no failed cases (SKIP is not coverage), 1=failed cases/runtime error, 2=invalid CLI.\n";
const LIMIT: u16 = 8192;
// Only /proc/self/status gets this larger cap: it grows with supplementary groups and CPU lists.
const STATUS_LIMIT: u64 = 1024 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(2);
const CASE_TIMEOUT: Duration = Duration::from_secs(10);
const CASES: &[&str] = &[
    "memory-pages",
    "thread-synchronization",
    "file-roundtrip-seek-truncate",
    "fsync-rename-visibility",
    "hardlink-symlink",
    "directory-metadata",
    "process-exec-wait-exit",
    "tcp-loopback-eof",
    "udp-datagrams",
    "unix-socket-transfer",
    "proc-self-maps",
    "proc-self-status",
    "sysfs-cpu-online",
    "sysfs-node-online",
];

type CaseResult = io::Result<Observation>;

struct Config {
    output: PathBuf,
    label: String,
    release: String,
    environment: String,
}

enum Cli {
    Help,
    Run(Config),
    Case(String),
    Exec,
}

enum Observation {
    Pass(String),
    Skip(String),
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

fn require(condition: bool, message: &str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid(message))
    }
}

fn safe_text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
}

fn valid_label(value: &str) -> bool {
    safe_text(value, 80)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        && value.as_bytes()[0].is_ascii_alphanumeric()
}

fn parse(args: &[OsString]) -> Result<Cli, String> {
    if matches!(args, [flag] if flag == "--help" || flag == "-h")
        || matches!(args, [command, flag] if command == "run" && flag == "--help")
    {
        return Ok(Cli::Help);
    }
    if matches!(args, [flag] if flag == "--internal-exec") {
        return Ok(Cli::Exec);
    }
    if args.len() == 2 && args[0] == "--internal-case" {
        let name = args[1].to_str().ok_or("case must be UTF-8")?;
        if CASES.contains(&name) {
            return Ok(Cli::Case(name.to_owned()));
        }
        return Err("unknown internal case".to_owned());
    }
    if args.first().is_none_or(|arg| arg != "run") {
        return Err("expected run or --help".to_owned());
    }
    let mut output = None;
    let mut label = None;
    let mut release = None;
    let mut environment = None;
    let options = &args[1..];
    if options.len() != 8 {
        return Err("run requires exactly four option/value pairs; see --help".to_owned());
    }
    for pair in options.as_chunks::<2>().0 {
        let key = pair[0].to_str().ok_or("option must be UTF-8")?;
        match key {
            "--output" => {
                if output.replace(PathBuf::from(&pair[1])).is_some() {
                    return Err("duplicate --output".to_owned());
                }
            }
            "--label" | "--expect-release" | "--environment" => {
                let value = pair[1]
                    .to_str()
                    .ok_or("option value must be UTF-8")?
                    .to_owned();
                let slot = match key {
                    "--label" => &mut label,
                    "--expect-release" => &mut release,
                    _ => &mut environment,
                };
                if slot.replace(value).is_some() {
                    return Err(format!("duplicate {key}"));
                }
            }
            _ => return Err(format!("unknown option: {}", cell(key))),
        }
    }
    let config = Config {
        output: output.ok_or("missing --output")?,
        label: label.ok_or("missing --label")?,
        release: release.ok_or("missing --expect-release")?,
        environment: environment.ok_or("missing --environment")?,
    };
    validate_config(&config)?;
    Ok(Cli::Run(config))
}

fn validate_config(config: &Config) -> Result<(), String> {
    if !valid_label(&config.label) {
        return Err("invalid label; see --help".to_owned());
    }
    if !safe_text(&config.release, 256) {
        return Err("release must contain 1..256 bytes and no control characters".to_owned());
    }
    if !["reference", "qemu", "bare-metal"].contains(&config.environment.as_str()) {
        return Err("environment must be reference, qemu, or bare-metal".to_owned());
    }
    let path = config.output.to_str().ok_or("output path must be UTF-8")?;
    if !safe_text(path, 4096)
        || !matches!(
            config.output.components().next_back(),
            Some(Component::Normal(_))
        )
        || config
            .output
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(
            "output must be a normal new directory path, without controls or '..'".to_owned(),
        );
    }
    Ok(())
}

fn cell(value: &str) -> String {
    let mut result = String::new();
    for character in value.chars() {
        match character {
            '\\' => result.push_str("\\\\"),
            '\t' => result.push_str("\\t"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(result, "\\u{{{:x}}}", u32::from(character));
            }
            character => result.push(character),
        }
    }
    result
}

fn read_bounded(path: &Path) -> io::Result<String> {
    read_limited(path, u64::from(LIMIT))
}

fn read_limited(path: &Path, limit: u64) -> io::Result<String> {
    let mut bytes = Vec::new();
    File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
    require(
        bytes.len() as u64 <= limit,
        &format!("input exceeds {limit}-byte limit"),
    )?;
    String::from_utf8(bytes).map_err(|error| invalid(error.to_string()))
}

fn create_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

fn create_directory(path: &Path) -> io::Result<()> {
    DirBuilder::new().mode(0o700).create(path)
}

fn new_output(path: &Path) -> io::Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| invalid("missing output directory name"))?;
    let output = fs::canonicalize(parent)?.join(name);
    create_directory(&output)?;
    Ok(output)
}

fn refuse_root() -> io::Result<()> {
    let status = read_limited(Path::new("/proc/self/status"), STATUS_LIMIT)?;
    let uids = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .ok_or_else(|| {
            invalid("cannot establish unprivileged effective UID from /proc/self/status")
        })?;
    let effective = uids
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| invalid("proc status lacks effective UID"))?
        .parse::<u32>()
        .map_err(|error| invalid(error.to_string()))?;
    require(
        effective != 0,
        "refusing effective UID 0; run without sudo/root",
    )
}

fn metadata(config: &Config, actual: &str, output: &Path) -> io::Result<()> {
    let mut file = create_file(&output.join("metadata.tsv"))?;
    writeln!(file, "key\tvalue")?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| invalid(error.to_string()))?
        .as_secs()
        .to_string();
    for (key, value) in [
        ("schema", "baremetal-smoke-1"),
        ("tool_package", env!("CARGO_PKG_NAME")),
        ("tool_version", env!("CARGO_PKG_VERSION")),
        ("expected_release", config.release.as_str()),
        ("actual_release", actual),
        ("operator_label", config.label.as_str()),
        ("environment_assertion", config.environment.as_str()),
        ("environment_detection", "not_performed"),
        ("qualified", "false"),
        (
            "elapsed_interpretation",
            "observation_only_not_performance_qualification",
        ),
        ("architecture", env::consts::ARCH),
        ("userspace_os", env::consts::OS),
        ("started_unix_seconds", timestamp.as_str()),
        ("case_timeout_seconds", "10"),
        ("io_timeout_seconds", "2"),
        (
            "evidence",
            "sandbox_and_child_logs_retained_no_automatic_cleanup",
        ),
    ] {
        writeln!(file, "{key}\t{}", cell(value))?;
    }
    file.sync_all()
}

fn wait_bounded(child: &mut Child, timeout: Duration) -> io::Result<Option<ExitStatus>> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(Some(status)),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                // Always attempt reaping, even if kill races with normal exit.
                let kill = child.kill();
                let reap = child.wait();
                reap?;
                kill?;
                return Ok(None);
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        }
    }
}

fn child_command(executable: &Path, directory: &Path) -> Command {
    let mut command = Command::new(executable);
    command
        .current_dir(directory)
        .env_clear()
        .stdin(Stdio::null());
    command
}

fn run_case(
    executable: &Path,
    output: &Path,
    sandbox: &Path,
    name: &str,
) -> io::Result<(&'static str, String)> {
    let directory = sandbox.join(name);
    create_directory(&directory)?;
    let stdout_path = output.join(format!("{name}.stdout.txt"));
    let stderr_path = output.join(format!("{name}.stderr.txt"));
    let mut child = child_command(executable, &directory)
        .args(["--internal-case", name])
        .stdout(Stdio::from(create_file(&stdout_path)?))
        .stderr(Stdio::from(create_file(&stderr_path)?))
        .spawn()?;
    let status = wait_bounded(&mut child, CASE_TIMEOUT)?;
    let stdout = read_bounded(&stdout_path)?;
    let stderr = read_bounded(&stderr_path)?;
    let (outcome, reason) = match status {
        None => (
            "fail",
            "case exceeded 10-second deadline; child killed and reaped".to_owned(),
        ),
        Some(status) if status.success() => ("pass", stdout.trim().to_owned()),
        Some(status) if status.code() == Some(77) => ("skip", stdout.trim().to_owned()),
        Some(status) => ("fail", format!("{status}; {}", stderr.trim())),
    };
    require(!reason.is_empty(), "child returned no observation")?;
    Ok((outcome, reason))
}

fn run(config: &Config) -> io::Result<bool> {
    let release = read_bounded(Path::new("/proc/sys/kernel/osrelease"))?;
    let actual = release.strip_suffix('\n').unwrap_or(&release);
    require(
        actual == config.release,
        &format!(
            "release mismatch: expected {}, actual {}; no output created",
            cell(&config.release),
            cell(actual)
        ),
    )?;
    refuse_root()?;
    let executable = env::current_exe()?;
    let output = new_output(&config.output)?;
    metadata(config, actual, &output)?;
    let sandbox = output.join("sandbox");
    create_directory(&sandbox)?;
    let mut report = create_file(&output.join("report.tsv"))?;
    writeln!(report, "case\tstatus\telapsed_ms\tdetails")?;
    report.flush()?;
    let mut failures = 0;
    let mut skipped = 0;
    for name in CASES {
        let started = Instant::now();
        let (status, detail) = run_case(&executable, &output, &sandbox, name)
            .unwrap_or_else(|error| ("fail", error.to_string()));
        failures += usize::from(status == "fail");
        skipped += usize::from(status == "skip");
        writeln!(
            report,
            "{name}\t{status}\t{}\t{}",
            started.elapsed().as_millis(),
            cell(&detail)
        )?;
        report.flush()?;
    }
    report.sync_all()?;
    println!(
        "{} cases; {failures} failed; {skipped} skipped; qualified=false",
        CASES.len()
    );
    println!(
        "Reports and sandbox retained in {}",
        cell(&output.to_string_lossy())
    );
    Ok(failures == 0)
}

fn memory_pages() -> CaseResult {
    const SIZE: usize = 4 * 1024 * 1024;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(SIZE)
        .map_err(|error| invalid(error.to_string()))?;
    bytes.resize(SIZE, 0);
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = (index ^ (index / 4096)).to_le_bytes()[0];
    }
    for index in (0..SIZE).step_by(4096) {
        bytes[index] ^= 0xa5;
    }
    for (index, byte) in bytes.iter().enumerate() {
        let expected =
            (index ^ (index / 4096)).to_le_bytes()[0] ^ if index % 4096 == 0 { 0xa5 } else { 0 };
        require(
            *byte == expected,
            "allocated byte content changed unexpectedly",
        )?;
    }
    Ok(Observation::Pass("4194304 bytes initialized and verified; 4096-byte stride mutation verified (not proof of physical page placement)".to_owned()))
}

fn thread_synchronization() -> CaseResult {
    let state = Mutex::new((0_u64, 0_u64));
    thread::scope(|scope| -> io::Result<()> {
        let mut handles = Vec::with_capacity(4);
        for worker in 0_u64..4 {
            let state = &state;
            handles.push(thread::Builder::new().spawn_scoped(
                scope,
                move || -> io::Result<()> {
                    for iteration in 0_u64..2000 {
                        let mut state = state.lock().map_err(|error| invalid(error.to_string()))?;
                        state.0 += 1;
                        state.1 += worker * 2000 + iteration;
                    }
                    Ok(())
                },
            )?);
        }
        for handle in handles {
            handle.join().map_err(|_| invalid("worker panicked"))??;
        }
        Ok(())
    })?;
    let state = state
        .into_inner()
        .map_err(|error| invalid(error.to_string()))?;
    require(
        state == (8000, 7999 * 8000 / 2),
        "mutex updates lost or corrupted",
    )?;
    Ok(Observation::Pass(
        "four joined workers; 8000 synchronized updates and exact arithmetic checksum".to_owned(),
    ))
}

fn file_roundtrip() -> CaseResult {
    let mut file = create_file(Path::new("bytes.bin"))?;
    let mut expected: Vec<u8> = (0_usize..65_536)
        .map(|index| index.to_le_bytes()[0])
        .collect();
    file.write_all(&expected)?;
    file.seek(SeekFrom::Start(4093))?;
    file.write_all(b"boundary")?;
    expected[4093..4101].copy_from_slice(b"boundary");
    file.rewind()?;
    let mut actual = vec![0; expected.len()];
    file.read_exact(&mut actual)?;
    require(
        actual == expected,
        "roundtrip or cross-boundary seek write differs",
    )?;
    file.set_len(4097)?;
    require(file.metadata()?.len() == 4097, "truncate length differs")?;
    file.rewind()?;
    actual.resize(4097, 0);
    file.read_exact(&mut actual)?;
    require(
        actual == expected[..4097],
        "truncate did not preserve prefix",
    )?;
    let mut eof = [0];
    require(file.read(&mut eof)? == 0, "truncate did not establish EOF")?;
    file.set_len(8192)?;
    actual.resize(8192 - 4097, 1);
    file.read_exact(&mut actual)?;
    require(
        actual.iter().all(|byte| *byte == 0),
        "extended file bytes are not zero",
    )?;
    Ok(Observation::Pass("65536-byte roundtrip; cross-boundary seek write; truncate/prefix/EOF; zero-filled extension".to_owned()))
}

fn fsync_rename() -> CaseResult {
    let mut original = create_file(Path::new("visible"))?;
    original.write_all(b"old content")?;
    original.rewind()?;
    let mut staged = create_file(Path::new("staged"))?;
    staged.write_all(b"new synced content")?;
    staged.sync_all()?;
    fs::rename("staged", "visible")?;
    File::open(".")?.sync_all()?;
    require(
        read_bounded(Path::new("visible"))? == "new synced content",
        "renamed content not visible to new open",
    )?;
    let mut previous = String::new();
    original.take(64).read_to_string(&mut previous)?;
    require(
        previous == "old content",
        "replacement changed the old open descriptor",
    )?;
    require(
        matches!(fs::symlink_metadata("staged"), Err(error) if error.kind() == io::ErrorKind::NotFound),
        "old rename source still exists or lookup failed",
    )?;
    Ok(Observation::Pass("file fsync, replacement rename, directory fsync, new-open visibility and old-descriptor identity; NOT crash durability".to_owned()))
}

fn links() -> CaseResult {
    create_file(Path::new("original"))?.write_all(b"linked contents")?;
    fs::hard_link("original", "hard")?;
    let original = fs::metadata("original")?;
    let hard = fs::metadata("hard")?;
    require(
        original.ino() == hard.ino() && original.dev() == hard.dev() && hard.nlink() == 2,
        "hard links do not share inode/link count",
    )?;
    symlink("hard", "symbolic")?;
    require(
        fs::read_link("symbolic")? == Path::new("hard"),
        "readlink target differs",
    )?;
    require(
        fs::symlink_metadata("symbolic")?.file_type().is_symlink(),
        "lstat did not identify symlink",
    )?;
    fs::remove_file("original")?;
    require(
        fs::metadata("hard")?.nlink() == 1,
        "unlink did not decrement hard-link count",
    )?;
    require(
        read_bounded(Path::new("symbolic"))? == "linked contents",
        "relative symlink did not resolve surviving hard link",
    )?;
    Ok(Observation::Pass("hard-link identity/count, relative symlink/readlink/lstat and content after original unlink".to_owned()))
}

fn directory_metadata() -> CaseResult {
    create_directory(Path::new("tree"))?;
    create_directory(Path::new("tree/nested"))?;
    create_file(Path::new("tree/payload"))?.write_all(b"metadata")?;
    let mut names = Vec::with_capacity(2);
    for entry in fs::read_dir("tree")? {
        let entry = entry?;
        require(names.len() < 2, "unexpected directory entry")?;
        names.push(entry.file_name());
    }
    names.sort();
    require(
        names == [OsString::from("nested"), OsString::from("payload")],
        "directory enumeration differs",
    )?;
    let file = fs::metadata("tree/payload")?;
    require(
        file.is_file() && file.len() == 8,
        "file metadata type/length differs",
    )?;
    require(
        fs::metadata("tree/nested")?.is_dir(),
        "nested metadata is not directory",
    )?;
    require(
        fs::read_dir("tree/nested")?.next().is_none(),
        "new nested directory is not empty",
    )?;
    Ok(Observation::Pass(
        "exact two-entry traversal, nested directory, regular-file type and byte length".to_owned(),
    ))
}

fn process_exec() -> CaseResult {
    let output_path = Path::new("exec.stdout.txt");
    let error_path = Path::new("exec.stderr.txt");
    let mut child = child_command(&env::current_exe()?, Path::new("."))
        .arg("--internal-exec")
        .stdout(Stdio::from(create_file(output_path)?))
        .stderr(Stdio::from(create_file(error_path)?))
        .spawn()?;
    let status = wait_bounded(&mut child, IO_TIMEOUT)?
        .ok_or_else(|| invalid("exec child timed out; killed and reaped"))?;
    require(
        status.code() == Some(23),
        "exec/wait exit status was not 23",
    )?;
    require(
        read_bounded(output_path)? == "baremetal-exec-ok\n",
        "exec child stdout differs",
    )?;
    require(
        read_bounded(error_path)?.is_empty(),
        "exec child wrote unexpected stderr",
    )?;
    Ok(Observation::Pass("self-exec produced exact stdout, empty stderr and exit 23; waited/reaped with two-second deadline".to_owned()))
}

fn socket_exchange(left: &mut impl Read, expected: &[u8]) -> io::Result<()> {
    let mut actual = [0_u8; 64];
    require(
        expected.len() <= actual.len(),
        "internal socket payload exceeds bound",
    )?;
    left.read_exact(&mut actual[..expected.len()])?;
    require(
        &actual[..expected.len()] == expected,
        "stream payload differs",
    )?;
    require(
        left.read(&mut actual[..1])? == 0,
        "stream did not signal EOF after write shutdown",
    )
}

fn tcp_loopback() -> CaseResult {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let mut client = TcpStream::connect_timeout(&listener.local_addr()?, IO_TIMEOUT)?;
    let deadline = Instant::now() + IO_TIMEOUT;
    let mut server = loop {
        match listener.accept() {
            Ok((stream, peer)) => {
                require(peer.ip().is_loopback(), "TCP peer is not loopback")?;
                break stream;
            }
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(error),
        }
    };
    for stream in [&client, &server] {
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
    }
    client.write_all(b"tcp request")?;
    client.shutdown(Shutdown::Write)?;
    socket_exchange(&mut server, b"tcp request")?;
    server.write_all(b"tcp response")?;
    server.shutdown(Shutdown::Write)?;
    socket_exchange(&mut client, b"tcp response")?;
    Ok(Observation::Pass(
        "IPv4 loopback ephemeral-port connection; exact bidirectional bytes and half-close EOF"
            .to_owned(),
    ))
}

fn udp_datagrams() -> CaseResult {
    let sender = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let receiver = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    for socket in [&sender, &receiver] {
        socket.set_read_timeout(Some(IO_TIMEOUT))?;
        socket.set_write_timeout(Some(IO_TIMEOUT))?;
    }
    sender.connect(receiver.local_addr()?)?;
    receiver.connect(sender.local_addr()?)?;
    for datagram in [b"first datagram".as_slice(), b"", b"third"] {
        require(
            sender.send(datagram)? == datagram.len(),
            "UDP send length differs",
        )?;
        let mut buffer = [0; 64];
        let count = receiver.recv(&mut buffer)?;
        require(
            &buffer[..count] == datagram,
            "UDP datagram boundary/content differs",
        )?;
    }
    require(
        receiver.send(b"ack")? == 3,
        "UDP response send length differs",
    )?;
    let mut response = [0; 64];
    let count = sender.recv(&mut response)?;
    require(&response[..count] == b"ack", "UDP response differs")?;
    Ok(Observation::Pass("connected IPv4 loopback sockets; three exact datagrams including zero-length; reverse acknowledgment".to_owned()))
}

fn unix_socket() -> CaseResult {
    // socketpair avoids the small pathname limit and never creates a socket outside the sandbox.
    let (mut left, mut right) = UnixStream::pair()?;
    for stream in [&left, &right] {
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
    }
    left.write_all(b"unix request")?;
    left.shutdown(Shutdown::Write)?;
    socket_exchange(&mut right, b"unix request")?;
    right.write_all(b"unix response")?;
    right.shutdown(Shutdown::Write)?;
    socket_exchange(&mut left, b"unix response")?;
    Ok(Observation::Pass("Unix stream socketpair; exact bidirectional payload and half-close EOF; no pathname length dependency".to_owned()))
}

fn optional_observation(path: &str, limit: u64) -> io::Result<Result<String, Observation>> {
    match read_limited(Path::new(path), limit) {
        Ok(value) => Ok(Ok(value)),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
            ) =>
        {
            Ok(Err(Observation::Skip(format!(
                "{path} unavailable: {}; unavailable is not covered",
                error.kind()
            ))))
        }
        Err(error) => Err(error),
    }
}

fn proc_maps() -> CaseResult {
    // Maps may exceed the general input bound: inspect only a bounded prefix, not raw address evidence.
    let mut prefix = Vec::with_capacity(usize::from(LIMIT));
    match File::open("/proc/self/maps") {
        Ok(file) => {
            file.take(u64::from(LIMIT)).read_to_end(&mut prefix)?;
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
            ) =>
        {
            return Ok(Observation::Skip(format!(
                "/proc/self/maps unavailable: {}; not covered",
                error.kind()
            )));
        }
        Err(error) => return Err(error),
    }
    validate_maps_prefix(&prefix)
}

fn validate_maps_prefix(prefix: &[u8]) -> CaseResult {
    let mut readable = false;
    let mut executable = false;
    for line in prefix.split_inclusive(|&byte| byte == b'\n') {
        // The byte bound can cut any field, including a multibyte pathname character.
        let Some(line) = line.strip_suffix(b"\n") else {
            break;
        };
        let mut fields = line
            .split(u8::is_ascii_whitespace)
            .filter(|field| !field.is_empty());
        let range = fields
            .next()
            .ok_or_else(|| invalid("maps lacks address range"))?;
        require(range.is_ascii(), "maps address range is malformed")?;
        let range =
            std::str::from_utf8(range).map_err(|_| invalid("maps address range is malformed"))?;
        let (start, end) = range
            .split_once('-')
            .ok_or_else(|| invalid("maps address range is malformed"))?;
        let start = u64::from_str_radix(start, 16).map_err(|error| invalid(error.to_string()))?;
        let end = u64::from_str_radix(end, 16).map_err(|error| invalid(error.to_string()))?;
        require(start < end, "maps address range is empty/reversed")?;
        let permissions = fields
            .next()
            .ok_or_else(|| invalid("maps lacks permissions"))?;
        require(permissions.len() == 4, "maps permissions length differs")?;
        readable |= permissions[0] == b'r';
        executable |= permissions[2] == b'x';
    }
    if !(readable && executable) && prefix.len() == usize::from(LIMIT) {
        return Ok(Observation::Skip(
            "8192-byte maps prefix exhausted before readable/executable mappings could be established; not covered"
                .to_owned(),
        ));
    }
    require(
        readable && executable,
        "bounded maps prefix lacks readable/executable mapping",
    )?;
    Ok(Observation::Pass("bounded /proc/self/maps prefix contains valid ranges and readable/executable mappings; raw addresses not recorded".to_owned()))
}

fn proc_status() -> CaseResult {
    let value = match optional_observation("/proc/self/status", STATUS_LIMIT)? {
        Ok(value) => value,
        Err(skip) => return Ok(skip),
    };
    for key in ["Name:", "State:", "Threads:"] {
        require(
            value
                .lines()
                .any(|line| line.starts_with(key) && !line[key.len()..].trim().is_empty()),
            "proc status missing required nonempty field",
        )?;
    }
    let threads = value
        .lines()
        .find_map(|line| line.strip_prefix("Threads:"))
        .ok_or_else(|| invalid("missing Threads"))?;
    require(
        threads
            .trim()
            .parse::<usize>()
            .map_err(|error| invalid(error.to_string()))?
            >= 1,
        "proc status reports zero threads",
    )?;
    Ok(Observation::Pass("/proc/self/status exposes nonempty Name/State and positive Threads; identity/address fields not copied".to_owned()))
}

fn sysfs_online(path: &str) -> CaseResult {
    let value = match optional_observation(path, u64::from(LIMIT))? {
        Ok(value) => value,
        Err(skip) => return Ok(skip),
    };
    let value = value.trim();
    require(!value.is_empty(), "sysfs online list is empty")?;
    let mut previous = None;
    for item in value.split(',') {
        let (start, end) = item.split_once('-').unwrap_or((item, item));
        let start = start
            .parse::<u32>()
            .map_err(|error| invalid(error.to_string()))?;
        let end = end
            .parse::<u32>()
            .map_err(|error| invalid(error.to_string()))?;
        require(
            start <= end && previous.is_none_or(|last| start > last),
            "sysfs online list ranges overlap or are unordered",
        )?;
        previous = Some(end);
    }
    Ok(Observation::Pass(format!(
        "{path} readable; ordered nonoverlapping online ranges: {value}; no device serial identifiers read"
    )))
}

fn execute_case(name: &str) -> CaseResult {
    match name {
        "memory-pages" => memory_pages(),
        "thread-synchronization" => thread_synchronization(),
        "file-roundtrip-seek-truncate" => file_roundtrip(),
        "fsync-rename-visibility" => fsync_rename(),
        "hardlink-symlink" => links(),
        "directory-metadata" => directory_metadata(),
        "process-exec-wait-exit" => process_exec(),
        "tcp-loopback-eof" => tcp_loopback(),
        "udp-datagrams" => udp_datagrams(),
        "unix-socket-transfer" => unix_socket(),
        "proc-self-maps" => proc_maps(),
        "proc-self-status" => proc_status(),
        "sysfs-cpu-online" => sysfs_online("/sys/devices/system/cpu/online"),
        "sysfs-node-online" => sysfs_online("/sys/devices/system/node/online"),
        _ => Err(invalid("unknown case")),
    }
}

fn main() -> ExitCode {
    let args: Vec<_> = env::args_os().skip(1).take(32).collect();
    match parse(&args) {
        Ok(Cli::Help) => {
            print!("{HELP}");
            ExitCode::SUCCESS
        }
        Ok(Cli::Exec) => {
            println!("baremetal-exec-ok");
            ExitCode::from(23)
        }
        Ok(Cli::Case(name)) => match execute_case(&name) {
            Ok(Observation::Pass(detail)) => {
                println!("{detail}");
                ExitCode::SUCCESS
            }
            Ok(Observation::Skip(detail)) => {
                println!("{detail}");
                ExitCode::from(77)
            }
            Err(error) => {
                eprintln!("{name}: {error}");
                ExitCode::FAILURE
            }
        },
        Ok(Cli::Run(config)) => match run(&config) {
            Ok(true) => ExitCode::SUCCESS,
            Ok(false) => ExitCode::FAILURE,
            Err(error) => {
                eprintln!("baremetal: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("baremetal: {error}\nUse --help for usage.");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn maps_accepts_normal_readable_and_executable_mappings() {
        assert!(matches!(
            validate_maps_prefix(
                b"1000-2000 r--p 00000000 00:00 0\n2000-3000 --xp 00000000 00:00 0 /bin/program\n"
            ),
            Ok(Observation::Pass(_))
        ));
    }

    #[test]
    fn maps_ignores_non_utf8_pathnames() {
        assert!(matches!(
            validate_maps_prefix(b"1000-2000 r-xp 00000000 00:00 0 /tmp/\xff/program\n"),
            Ok(Observation::Pass(_))
        ));
    }

    #[test]
    fn maps_discards_final_line_split_inside_utf8_pathname() {
        let mut prefix =
            b"1000-2000 r-xp 00000000 00:00 0 /bin/program\n3000-4000 r--p 00000000 00:00 0 /tmp/"
                .to_vec();
        prefix.resize(usize::from(LIMIT) - 1, b'a');
        prefix.extend_from_slice("€\n".as_bytes());
        prefix.truncate(usize::from(LIMIT));
        assert_eq!(prefix.last(), Some(&0xe2));
        assert!(matches!(
            validate_maps_prefix(&prefix),
            Ok(Observation::Pass(_))
        ));
        // An incomplete line must not supply a missing executable mapping.
        assert!(
            validate_maps_prefix(b"1000-2000 r--p 0 00:00 0\n2000-3000 r-xp 0 00:00 0 /tmp/\xe2")
                .is_err()
        );
    }

    #[test]
    fn maps_skips_capped_long_path_prefix_without_complete_executable_record() {
        let pathname = vec![b'a'; 4069];
        let mut prefix = b"1000-2000 r--p 00000000 00:00 0 /".to_vec();
        prefix.extend_from_slice(&pathname);
        prefix.extend_from_slice(b"\n2000-3000 r-xp 00000000 00:00 0 /");
        prefix.extend_from_slice(&pathname);
        prefix.push(b'\n');
        prefix.truncate(usize::from(LIMIT));
        assert_eq!(prefix.len(), usize::from(LIMIT));
        assert_ne!(prefix.last(), Some(&b'\n'));
        assert!(matches!(
            validate_maps_prefix(&prefix),
            Ok(Observation::Skip(_))
        ));
    }

    #[test]
    fn maps_rejects_missing_mappings_below_cap() {
        for prefix in [
            b"1000-2000 r--p 00000000 00:00 0\n".as_slice(),
            b"1000-2000 --xp 00000000 00:00 0\n".as_slice(),
            b"".as_slice(),
        ] {
            assert!(validate_maps_prefix(prefix).is_err());
        }
    }

    #[test]
    fn maps_rejects_malformed_complete_records_even_at_cap() {
        for malformed in [
            b"2000-1000 r--p 00000000 00:00 0\n".as_slice(),
            b"3000-4000 rw 00000000 00:00 0\n".as_slice(),
        ] {
            for permissions in [b"r--p", b"r-xp"] {
                let mut prefix = b"1000-2000 ".to_vec();
                prefix.extend_from_slice(permissions);
                prefix.extend_from_slice(b" 00000000 00:00 0\n");
                prefix.extend_from_slice(malformed);
                prefix.resize(usize::from(LIMIT), b'a');
                assert!(validate_maps_prefix(&prefix).is_err());
            }
        }
    }

    #[test]
    fn maps_rejects_invalid_address_ranges() {
        for range in [
            "2000-1000",
            "1000-1000",
            "xyz-2000",
            "1000",
            "1000-2000-3000",
            "10000000000000000-2000",
        ] {
            let prefix = format!("{range} r-xp 00000000 00:00 0\n");
            assert!(validate_maps_prefix(prefix.as_bytes()).is_err(), "{range}");
        }
        assert!(validate_maps_prefix(b"1000-\xff r-xp 00000000 00:00 0\n").is_err());
    }

    #[test]
    fn cli_requires_explicit_environment_and_rejects_duplicates() {
        assert!(
            parse(&arguments(&[
                "run",
                "--output",
                "fresh",
                "--label",
                "ref",
                "--expect-release",
                "6.18.57"
            ]))
            .is_err()
        );
        assert!(
            parse(&arguments(&[
                "run",
                "--output",
                "fresh",
                "--label",
                "ref",
                "--label",
                "again",
                "--environment",
                "reference"
            ]))
            .is_err()
        );
        assert!(
            parse(&arguments(&[
                "run",
                "--output",
                "fresh",
                "--label",
                "ref",
                "--expect-release",
                "6.18.57",
                "--environment",
                "reference"
            ]))
            .is_ok()
        );
    }

    #[test]
    fn labels_paths_and_report_cells_cannot_inject_rows() {
        assert!(!valid_label("bad\nlabel"));
        assert!(!valid_label("../escape"));
        assert!(!valid_label(""));
        assert!(valid_label("reference-01.good"));
        assert_eq!(
            cell("tab\tline\n\\end\u{1b}"),
            "tab\\tline\\n\\\\end\\u{1b}"
        );
        assert!(
            parse(&arguments(&[
                "run",
                "--output",
                "../escape",
                "--label",
                "ref",
                "--expect-release",
                "6.18.57",
                "--environment",
                "reference"
            ]))
            .is_err()
        );
    }

    #[test]
    fn help_is_dry_and_unknown_input_is_invalid() {
        assert!(matches!(parse(&arguments(&["--help"])), Ok(Cli::Help)));
        assert!(matches!(
            parse(&arguments(&["run", "--help"])),
            Ok(Cli::Help)
        ));
        assert!(parse(&[]).is_err());
        assert!(parse(&arguments(&["run", "--unknown"])).is_err());
        assert!(parse(&arguments(&["--internal-case", "not-a-case"])).is_err());
    }
}
