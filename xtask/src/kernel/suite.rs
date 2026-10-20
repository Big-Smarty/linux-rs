// SPDX-License-Identifier: GPL-2.0-only
//! The harness side of the kernel-run bare-metal suite (decision A21).
//!
//! * [`create`] (`xtask baremetal-suite`) builds the physical suite kernel
//!   (`freestanding` + `baremetal-suite`, no `qemu-self-test`), the harness
//!   `/init` and the generated initramfs, lays out the directory tree the user
//!   copies onto a separate FAT32 USB stick, boots exactly those files once in
//!   QEMU (TCG, UEFI, Limine) and keeps QMP screendumps of the replay pages and
//!   of the final summary screen as evidence. It never writes to a block
//!   device: the only writes are files under the new output directory.
//! * [`validate`] judges the serial log of the composed (`qemu-self-test` +
//!   `baremetal-suite`) build for the `kernel-test` cases in `SUITE_CASES`.

use super::*;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

/// Wall-clock allowance of one suite case in `kernel-test` (the QEMU cell runs
/// every group and the whole-RAM exhaustion walk under TCG).
pub(super) const TIMEOUT: Duration = Duration::from_secs(180);

/// The groups of a normal run, in the kernel's order, all expected to pass.
pub(super) const ALL_PASS: &[(&str, bool)] = &[
    ("ids", true),
    ("time", true),
    ("mm", true),
    ("fs", true),
    ("signal", true),
    ("fork", true),
];
/// A run that selects three probes ending abnormally (a SIGSEGV, an unimplemented
/// syscall, a loop that outruns the one-second group bound), then one real group.
pub(super) const STOPS: &[(&str, bool)] = &[
    ("fault", false),
    ("io_uring", false),
    ("spin", false),
    ("ids", true),
];

/// Boot proofs the kernel records on the QEMU q35 cells, in order.
const PROOFS: [&str; 23] = [
    "console-scroll",
    "scalar-rust-memory-boundaries",
    "table-allocation-rollback",
    "retain-initramfs",
    "breakpoint-return",
    "page-fault-all-gpr-preservation",
    "guard-page-fault",
    "readonly-page-fault",
    "readonly-value-preserved",
    "nx-execution-fault",
    "user-mm",
    "timer-init",
    "irq-guard",
    "irq-all-gpr-preservation",
    "timer-delivery",
    "timer-period-observation",
    "timer-mask",
    "timer-tick-count",
    "timer-period-vs-tsc",
    "timekeeping",
    "heap",
    "buddy-orders",
    "exhaustion",
];
/// What the user acts on; the kernel prints it as the last screen line.
const FINAL_LINE: &str = "linux-rs suite complete - photograph this screen, then hard-reset";
/// The first line the kernel prints (and so captures: `console::init`'s), and the line that starts the summary.
const CAPTURE_START: &str = "console: framebuffers used=";
const SUMMARY_HEAD: &str = "linux-rs bare-metal suite   build ";

/// FNV-1a 64 (the kernel's `Fnv64`), to recompute the digest from the serial log.
fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, &byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

fn position(lines: &[&str], from: usize, wanted: &str) -> Result<usize, String> {
    lines[from..]
        .iter()
        .position(|line| *line == wanted)
        .map(|offset| offset + from)
        .ok_or_else(|| format!("missing or out of order: {wanted}"))
}

fn digest_in<'a>(line: &'a str, marker: &str) -> Option<&'a str> {
    let digest = line.split_once(marker)?.1.split_whitespace().next()?;
    (digest.len() == 16 && digest.bytes().all(|b| b.is_ascii_hexdigit())).then_some(digest)
}

/// Judge the serial log of a suite case: the boot proofs, every group's start and
/// result with the right cause, the host harness's own oracle comparison of each
/// passing group's output (an independent check of the kernel's comparison), the
/// final records and screen lines, and the digest recomputed from the raw log.
pub(super) fn validate(
    serial: &str,
    lines: &[&str],
    groups: &[(&str, bool)],
) -> Result<(), String> {
    check_proofs(lines)?;
    let mut cursor = 0;
    let mut passed = 0;
    for &(group, must_pass) in groups {
        cursor = check_group(lines, group, must_pass, cursor)?;
        passed += usize::from(must_pass);
    }
    let ok = passed == groups.len();
    let complete = format!(
        "SUITE complete ok={ok} groups={passed}/{} proofs={n}/{n}",
        groups.len(),
        n = PROOFS.len()
    );
    let complete_at = position(lines, cursor, &complete)?;
    // The failure detail is the last block of the screen: a stopped group's stop line is in it.
    for &(group, must_pass) in groups {
        let prefix = format!("  {group} stopped: FAIL ");
        if !must_pass
            && matches!(group, "io_uring" | "spin")
            && !lines[complete_at..]
                .iter()
                .any(|line| line.starts_with(&prefix))
        {
            return Err(format!("summary has no `{prefix}...` failure detail row"));
        }
    }
    let result_line = if ok {
        format!(
            "RESULT: ALL PASS ({} groups, {} self-tests)",
            groups.len(),
            PROOFS.len()
        )
    } else {
        format!(
            "RESULT: FAIL - {passed}/{} groups, {n}/{n} self-tests passed",
            groups.len(),
            n = PROOFS.len()
        )
    };
    check_screen(serial, lines, &result_line)
}

/// Every boot proof passed exactly once, none failed.
fn check_proofs(lines: &[&str]) -> Result<(), String> {
    for name in PROOFS {
        let pass = format!("PROOF {name} PASS");
        if lines.iter().filter(|line| **line == pass).count() != 1 {
            return Err(format!("self-test {name} must pass exactly once"));
        }
    }
    match lines
        .iter()
        .find(|line| line.starts_with("PROOF ") && line.ends_with(" FAIL"))
    {
        Some(line) => Err(format!("self-test failed: {line}")),
        None => Ok(()),
    }
}

/// One group's start and result records after line `cursor`: the verdict, the
/// cause, the counts, and for a passing group the host harness's own comparison
/// of its output (independent of the kernel's). Returns the line after the result.
fn check_group(
    lines: &[&str],
    group: &str,
    must_pass: bool,
    cursor: usize,
) -> Result<usize, String> {
    let started = format!("SUITE group {group} start uptime_s=");
    let start = lines[cursor..]
        .iter()
        .position(|line| line.starts_with(&started))
        .map(|offset| offset + cursor)
        .ok_or_else(|| format!("missing or out of order: {started}<seconds>"))?;
    let prefix = format!("SUITE group {group} result=");
    let end = lines[start..]
        .iter()
        .position(|line| line.starts_with(&prefix))
        .map(|offset| offset + start)
        .ok_or_else(|| format!("group {group} has no result record"))?;
    let result = lines[end];
    let verdict = if must_pass { "pass" } else { "fail" };
    if record_field(result, "result") != Some(verdict) {
        return Err(format!("group {group} must be {verdict}: {result}"));
    }
    let cause = match group {
        "fault" => "init signal 11",
        "io_uring" => "kernel stop",
        "spin" => "timeout",
        _ => "init exit 0",
    };
    if !result.contains(&format!("cause=\"{cause}\"")) {
        return Err(format!("group {group} must end with `{cause}`: {result}"));
    }
    let body = &lines[start + 1..end];
    if group == "io_uring" && !body.contains(&"FAIL syscall unimplemented nr=425") {
        return Err("io_uring probe must end in the unimplemented-syscall stop".to_owned());
    }
    if group == "spin" && !body.contains(&"FAIL group timeout after 1 s") {
        return Err("spin probe must end in the group time bound".to_owned());
    }
    if group == "fault"
        && !body
            .iter()
            .any(|line| line.starts_with("init[1]: segfault at 0 ip "))
    {
        return Err("fault probe must print Linux's segfault line".to_owned());
    }
    if must_pass {
        let number = |key| record_field(result, key).and_then(|v| v.parse::<usize>().ok());
        let (matched, expected, observed) =
            (number("matched"), number("expected"), number("observed"));
        if expected.is_none_or(|n| n == 0)
            || matched != expected
            || observed != expected
            || number("mismatches") != Some(0)
        {
            return Err(format!("group {group} counts differ: {result}"));
        }
        validate_oracle(body, group).map_err(|error| format!("group {group}: {error}"))?;
    }
    Ok(end + 1)
}

/// The summary screen's lines in order, one log digest on the heading and the
/// footer, and that digest equal to the FNV-1a of the serial transcript the
/// kernel captured (from its first banner to the line before the heading).
fn check_screen(serial: &str, lines: &[&str], result_line: &str) -> Result<(), String> {
    let head = lines
        .iter()
        .position(|line| line.starts_with(SUMMARY_HEAD))
        .ok_or("missing summary heading")?;
    let foot = lines
        .iter()
        .position(|line| line.starts_with("log: "))
        .ok_or("missing log footer")?;
    let last = position(lines, foot, FINAL_LINE)?;
    position(lines, head, result_line)?;
    if !(head < foot && foot < last) {
        return Err("summary lines out of order".to_owned());
    }
    let (Some(shown), Some(printed)) = (
        digest_in(lines[head], "log digest "),
        digest_in(lines[foot], "digest "),
    ) else {
        return Err("summary and footer must carry a 16-digit log digest".to_owned());
    };
    if shown != printed || !lines[foot].contains(" 0 dropped") {
        return Err(
            "log digest differs between heading and footer, or the log dropped bytes".to_owned(),
        );
    }
    let begin = serial
        .find(CAPTURE_START)
        .ok_or("serial log has no kernel banner")?;
    let finish = serial
        .find(SUMMARY_HEAD)
        .ok_or("serial log has no summary heading")?;
    let recomputed = format!("{:016x}", fnv1a(&serial.as_bytes()[begin..finish]));
    if recomputed != shown {
        return Err(format!(
            "log digest {shown} differs from the serial transcript's {recomputed}"
        ));
    }
    Ok(())
}

/// The suite cases' entries of the top-level `kernel-test` manifest.
pub(super) fn record(
    values: &mut BTreeMap<String, String>,
    output: &Output,
    cases: &[CaseResult],
    build: &Build,
) -> io::Result<()> {
    manifest_value(
        values,
        "baremetal_suite_case_count",
        cases.len().to_string(),
    );
    manifest_value(
        values,
        "baremetal_suite_cases_matched",
        cases.iter().filter(|case| case.passed).count().to_string(),
    );
    manifest_value(
        values,
        "baremetal_suite_elf",
        display_path(&build.elf_relative)?,
    );
    manifest_value(values, "sha256_baremetal_suite_elf", build.elf_hash.clone());
    for case in cases {
        record_case(values, output, case)?;
    }
    Ok(())
}

/// The `limine.conf` of the stick: a visible menu with a countdown, one entry,
/// no forced video mode (the firmware's own mode, whatever the monitor is).
const LIMINE_CONF: &str = "timeout: 5\n\n/linux-rs bare-metal suite (A21)\n    protocol: limine\n    path: boot():/linux-rs-kernel\n    module_path: boot():/initramfs.cpio\n    module_string: initramfs.cpio\n";

/// The source commit, marked when the tree has uncommitted changes: what the
/// summary screen prints as the build.
pub(super) fn build_id(root: &Path) -> String {
    let dirty = !git_value(root, &["status", "--porcelain", "--untracked-files=all"]).is_empty();
    format!(
        "{}{}",
        git_value(root, &["rev-parse", "--short=12", "HEAD"]),
        if dirty { "+dirty" } else { "" }
    )
}

fn readme(id: &str, kernel_sha: &str) -> String {
    format!(
        "\
linux-rs bare-metal test suite (decision A21)
=============================================

build id on the summary screen : {id}
kernel (linux-rs-kernel) sha256: {kernel_sha}

WHAT THIS IS
  A directory tree for ONE separate USB stick. It boots the linux-rs kernel
  with Limine 12.9.3 (the BOOTX64.EFI of your /usr/share/limine). The kernel
  runs its boot self-tests, prints a hardware inventory (CPU, memory map, ACPI,
  APIC/timers, framebuffers, PCI ids), runs the oracle syscall groups ids,
  time, mm, fs, signal and fork each as a fresh /init on a fresh rootfs, compares
  each group's output line by line with what the pinned Linux 6.18.57 printed,
  and ends on a summary screen. The group proc is not run (the kernel has no
  procfs yet; the summary says so).

WHAT IT NEVER DOES
  It has no disk, USB-storage, network or sound driver and calls no firmware
  runtime service, so it writes nothing anywhere: no disk, no NVRAM, no EFI
  variables, no BIOS settings. Besides the CPU, its own page tables and the
  framebuffers it draws on, it uses the timers every boot of this kernel uses
  (TSC calibration against the PIT, the HPET and the ACPI PM-timer port when
  the firmware describes them; the local APIC and IOAPIC timer/interrupt
  registers; the legacy 8259 and RTC), and it touches PCI only by reading
  vendor, device and class registers (it writes only the 0xCF8 address
  register). Your CachyOS install, its ESP and its boot entries are not read
  or changed.

WHAT YOU DO (the tool never writes to a block device; you do the copy)
  1. Take a spare USB stick whose contents you do not need. Formatting
     DESTROYS everything on it. Check the device name twice -- picking the
     wrong device erases the wrong disk. Do NOT use any internal drive. Before
     any sudo command run
         lsblk -o NAME,SIZE,MODEL,TRAN,MOUNTPOINTS
     and continue only if the device you mean shows TRAN=usb and the size and
     model of the stick (internal NVMe/SATA drives show nvme/sata).
  2. If the desktop mounted the stick automatically, unmount it first
     (MOUNTPOINTS must be empty for the stick's partitions). Format it as
     FAT32 with one partition (GPT or MBR both work for UEFI), for example,
     with /dev/sdX1 the partition of the STICK:
         sudo mkfs.fat -F 32 -n LINUXRS /dev/sdX1
     A desktop may automount it again after formatting: unmount that mount
     before step 3 (or use its mount point instead of /mnt below).
  3. Mount it and, from inside this directory (the one holding EFI/,
     limine.conf, linux-rs-kernel and initramfs.cpio), copy the tree and
     check the files:
         sudo mount /dev/sdX1 /mnt
         sudo cp -r EFI limine.conf linux-rs-kernel initramfs.cpio /mnt/
         sync
         (cd /mnt && sha256sum -c <this-directory>/SHA256SUMS)
         sudo umount /mnt
  4. Keep your normal boot entry as it is. Boot the stick once through the
     firmware's one-time boot menu (ASUS: press F8 at power-on, pick the
     \"UEFI: <your stick>\" entry); do not change the boot order.
  5. Limine shows one entry with a 5 second countdown; press Enter or wait.
  6. Wait. Expected run time: about 3 to 10 minutes on 30 GiB of RAM. The
     screen first scrolls the boot log, then shows one dot per passing test
     line while the groups run, and then walks the whole of RAM once more (the
     allocator exhaustion proof; the screen is quiet during it, this is the
     longest part). Then the kernel clears the screen and replays the log in
     pages: each page stays up for 6 seconds (take a photo of each), the
     machine keeps going by itself. The last screen is the SUMMARY; it stays
     until you reset. Photograph it so every line is readable.
  7. Hard-reset (reset button, or hold the power button for 5 seconds), remove
     the stick and boot your usual system.
  8. Send the photos back (page order matters; the summary's 'log digest' ties
     the pages to one run; every replay page header carries the build id and
     the digest too). Each test group has a 120 second bound and the
     kernel reports a group that outruns it, so a screen that stays unchanged
     for 10 minutes is an unexpected hang: photograph it and hard-reset, that
     is a result too.

IF NOTHING APPEARS
  The kernel draws on every framebuffer the firmware offers. If the monitor
  stays black after Limine's menu, try the other GPU's output once and report
  which one you used.

FILES
  EFI/BOOT/BOOTX64.EFI   Limine 12.9.3 (copy of /usr/share/limine/BOOTX64.EFI)
  limine.conf            one entry, 5 s timeout, no forced resolution
  linux-rs-kernel        the suite kernel (freestanding + baremetal-suite)
  initramfs.cpio         generated archive holding the harness /init
  SHA256SUMS             sha256 of every file above
"
    )
}

/// Copy `from` into the tree and return its hash.
fn put(output: &Output, tools: &QemuTools, from: &Path, to: &Path) -> io::Result<String> {
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent)?;
    }
    copy_file(from, to)?;
    file_hash(&output.root, &tools.sha256sum.path, to)
}

/// A FAT32 image holding exactly the files of `tree` (the user's stick), verified
/// by copying them back out and comparing hashes with `hashes`.
fn tree_image(
    output: &Output,
    dir: &Path,
    tree: &Path,
    tools: &QemuTools,
    hashes: &[(&str, String)],
) -> io::Result<BootImage> {
    let root = &output.root;
    let image = dir.join("disk.img");
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&image)
        .map_err(|error| super::contextual(&image, &error))?;
    file.set_len(FAT_IMAGE_BYTES)?;
    drop(file);
    let image_relative = display_path(&relative_path(root, &image)?)?;
    let format = run_simple(
        root,
        &tools.mkfs_fat,
        &["-F", "32", "-n", "LINUXRS", &image_relative],
        dir,
        "mkfs.stdout.log",
        "mkfs.stderr.log",
        Duration::from_secs(30),
    )?;
    require_exit(&tools.mkfs_fat, &format, 0, Duration::from_secs(30))?;
    let vars_copy = dir.join("OVMF_VARS.4m.fd");
    copy_file(Path::new(OVMF_VARS), &vars_copy)?;
    let vars_sha256_initial = file_hash(root, &tools.sha256sum.path, &vars_copy)?;
    for (index, directory) in ["::/EFI", "::/EFI/BOOT"].into_iter().enumerate() {
        let result = run_simple(
            root,
            &tools.mmd.path,
            &["-i", &image_relative, directory],
            dir,
            &format!("mmd-{index}.stdout.log"),
            &format!("mmd-{index}.stderr.log"),
            Duration::from_secs(30),
        )?;
        require_exit(&tools.mmd.path, &result, 0, Duration::from_secs(30))?;
    }
    let mut specs = Vec::new();
    for (name, _) in hashes {
        specs.push((
            display_path(&relative_path(root, &tree.join(name))?)?,
            format!("::/{name}"),
        ));
    }
    copy_fat_payloads(root, dir, &image_relative, specs, tools)?;
    let mut verified = BTreeMap::new();
    for (index, (name, expected)) in hashes.iter().enumerate() {
        let copy = dir.join(format!("image-verified-{index}"));
        let copy_relative = display_path(&relative_path(root, &copy)?)?;
        let result = run_simple(
            root,
            &tools.mcopy.path,
            &["-i", &image_relative, &format!("::/{name}"), &copy_relative],
            dir,
            &format!("mcopy-verify-{index}.stdout.log"),
            &format!("mcopy-verify-{index}.stderr.log"),
            Duration::from_secs(30),
        )?;
        require_exit(&tools.mcopy.path, &result, 0, Duration::from_secs(30))?;
        let actual = file_hash(root, &tools.sha256sum.path, &copy)?;
        if &actual != expected {
            return Err(invalid(format!(
                "FAT image copy of {name} differs from the tree"
            )));
        }
        verified.insert(*name, actual);
    }
    let disk_sha256_initial = file_hash(root, &tools.sha256sum.path, &image)?;
    Ok(BootImage {
        disk: image,
        vars_copy,
        vars_sha256_initial,
        disk_sha256_initial,
        kernel_image_sha256: verified["linux-rs-kernel"].clone(),
        limine_image_sha256: verified["EFI/BOOT/BOOTX64.EFI"].clone(),
        module_image_sha256: vec![("initramfs.cpio", verified["initramfs.cpio"].clone())],
    })
}

/// Boot the tree's image in QEMU (TCG, UEFI, no serial, no debug-exit: the real
/// profile) and wait for the kernel's final HLT, saving a screendump about every
/// `PAGE_SHOT` seconds on the way (the replay pages) and one at the end (the
/// summary). Returns the final screendump's path.
fn boot_and_capture(
    output: &Output,
    dir: &Path,
    image: &BootImage,
    build: &Build,
    tools: &QemuTools,
    timeout: Duration,
) -> io::Result<(std::path::PathBuf, &'static str, usize)> {
    const PAGE_SHOT: Duration = Duration::from_secs(4);
    let root = &output.root;
    let qmp_dir = QmpDir::create(&output.path)?;
    let socket = qmp_dir.socket();
    let args = default_qemu_args(root, &socket, image)?;
    let mut command = supervised(&tools.qemu.path);
    command.args(&args).current_dir(root).stdin(Stdio::null());
    command.stdout(Stdio::from(create_new(&dir.join("qemu.stdout.log"))?));
    command.stderr(Stdio::from(create_new(&dir.join("qemu.stderr.log"))?));
    let start = Instant::now();
    let mut child = create_process(&mut command)?;
    let stream = wait_qmp_socket(&socket, &mut child, timeout)?;
    let mut qmp = Qmp::new(stream, &dir.join("qmp.log"), start + timeout)?;
    qmp.greeting()?;
    qmp.execute("qmp_capabilities")?;
    let mut shots = 0;
    let mut last_shot = Instant::now();
    loop {
        let response = qmp.human_monitor("info registers")?;
        if terminal_kernel_halt(
            response.ret.as_str().unwrap_or_default(),
            &build.executable_segments,
        )
        .is_some()
        {
            break;
        }
        if let Some(status) = child.try_wait()? {
            return Err(invalid(format!(
                "QEMU exited with {:?} before the kernel's final HLT",
                status.code()
            )));
        }
        if start.elapsed() >= timeout {
            return Err(invalid(format!(
                "the suite kernel did not halt within {} seconds; timeout is not a pass",
                timeout.as_secs()
            )));
        }
        if last_shot.elapsed() >= PAGE_SHOT && shots < 40 {
            let shot = dir.join(format!("page-{shots:02}.ppm"));
            qmp.screendump(&display_path(&relative_path(root, &shot)?)?, "ppm")?;
            shots += 1;
            last_shot = Instant::now();
        }
        thread::sleep(Duration::from_millis(100));
    }
    let png = dir.join("summary-screen.png");
    let png_relative = display_path(&relative_path(root, &png)?)?;
    let (screen, format) = if qmp.screendump(&png_relative, "png").is_ok()
        && valid_image(&png).ok().flatten() == Some("png")
    {
        (png, "png")
    } else {
        let ppm = dir.join("summary-screen.ppm");
        qmp.screendump(&display_path(&relative_path(root, &ppm)?)?, "ppm")?;
        if valid_image(&ppm)? != Some("ppm") {
            return Err(invalid("QMP screendump produced no valid PNG or PPM image"));
        }
        (ppm, "ppm")
    };
    qmp.quit()?;
    let cleanup = wait_for_exit(child, Duration::from_secs(3))?;
    require_exit(&tools.qemu.path, &cleanup, 0, Duration::from_secs(3))?;
    Ok((screen, format, shots))
}

/// The files of the stick, their hashes and the build id the screen will print.
struct Tree {
    dir: PathBuf,
    id: String,
    /// `(path on the stick, sha256)`, in `SHA256SUMS` order.
    hashes: [(&'static str, String); 4],
}

/// Write the tree the user copies, named exactly as on the stick, with its
/// `SHA256SUMS` and `README.txt`.
fn stage_tree(output: &Output, tools: &QemuTools, suite_build: &Build) -> io::Result<Tree> {
    let tree = output.path.join("usb");
    create_directory(&tree)?;
    let id = build_id(&output.root);
    let limine = put(
        output,
        tools,
        Path::new(LIMINE_EFI),
        &tree.join("EFI/BOOT/BOOTX64.EFI"),
    )?;
    let kernel = put(
        output,
        tools,
        &suite_build.elf,
        &tree.join("linux-rs-kernel"),
    )?;
    let initramfs = put(
        output,
        tools,
        &tools.fixtures.dir.join(super::Module::Archive.file()),
        &tree.join("initramfs.cpio"),
    )?;
    write_new(&tree.join("limine.conf"), LIMINE_CONF.as_bytes())?;
    let conf = file_hash(
        &output.root,
        &tools.sha256sum.path,
        &tree.join("limine.conf"),
    )?;
    let hashes = [
        ("EFI/BOOT/BOOTX64.EFI", limine),
        ("limine.conf", conf),
        ("linux-rs-kernel", kernel.clone()),
        ("initramfs.cpio", initramfs),
    ];
    let mut sums = String::new();
    for (name, hash) in &hashes {
        writeln!(sums, "{hash}  {name}").map_err(io::Error::other)?;
    }
    write_new(&tree.join("SHA256SUMS"), sums.as_bytes())?;
    write_new(&tree.join("README.txt"), readme(&id, &kernel).as_bytes())?;
    Ok(Tree {
        dir: tree,
        id,
        hashes,
    })
}

/// What one `baremetal-suite` run produced, for its manifest.
struct Report<'a> {
    output: &'a Output,
    tools: &'a QemuTools,
    tree: &'a Tree,
    init_sha256: &'a str,
    screen: &'a Path,
    format: &'a str,
    pages: usize,
}

fn write_report(report: &Report<'_>) -> io::Result<()> {
    let Report {
        output,
        tools,
        tree,
        init_sha256,
        screen,
        format,
        pages,
    } = report;
    let screen_hash = file_hash(&output.root, &tools.sha256sum.path, screen)?;
    let mut manifest = BTreeMap::new();
    for (key, value) in [
        ("schema", "1"),
        ("command", "baremetal-suite"),
        (
            "kernel_feature_set",
            "freestanding + baremetal-suite; no qemu-self-test",
        ),
        (
            "tree_boot_machine",
            "QEMU q35 TCG qemu64 512M, OVMF, std VGA, no serial",
        ),
        ("tree_boot_final_screen_format", format),
        (
            "visual_review",
            "pending: the final screen is not parsed; a person must read it",
        ),
        (
            "result_scope",
            "QEMU boot of the produced tree; not physical evidence (docs/bare-metal-suite.md)",
        ),
    ] {
        manifest_value(&mut manifest, key, value);
    }
    manifest_value(&mut manifest, "build_id", &tree.id);
    manifest_value(
        &mut manifest,
        "usb_tree",
        display_path(&relative_path(&output.root, &tree.dir)?)?,
    );
    for (name, hash) in &tree.hashes {
        manifest_value(
            &mut manifest,
            &format!("sha256_{}", name.replace('/', "_")),
            hash,
        );
    }
    manifest_value(&mut manifest, "sha256_init_elf", (*init_sha256).to_owned());
    manifest_value(
        &mut manifest,
        "sha256_initramfs_fixture",
        tools.fixtures.archive_sha256.clone(),
    );
    manifest_value(
        &mut manifest,
        "tree_boot_final_screen",
        display_path(&relative_path(&output.root, screen)?)?,
    );
    manifest_value(&mut manifest, "tree_boot_final_screen_sha256", screen_hash);
    manifest_value(
        &mut manifest,
        "tree_boot_page_screendumps",
        pages.to_string(),
    );
    manifest_value(
        &mut manifest,
        "qemu_version",
        single_line(&tools.qemu.version),
    );
    write_manifest(&output.path.join("manifest.tsv"), manifest)?;
    Ok(())
}

/// `xtask baremetal-suite --output <new dir>`.
///
/// # Errors
/// Any build, staging or QEMU failure; a timeout is never a pass.
pub fn create(root: &Path, requested: &Path, timeout: Duration) -> io::Result<()> {
    let output = prepare_output(root, requested)?;
    let init_dir = output.path.join("init-build");
    create_directory(&init_dir)?;
    let init_build = build_target(&output.root, &init_dir, Target::Init)?;
    let suite_dir = output.path.join("suite-build");
    create_directory(&suite_dir)?;
    let suite_build = build_target(
        &output.root,
        &suite_dir,
        Target::Kernel {
            qemu_self_test: false,
            suite: true,
        },
    )?;
    if fs::read(init_dir.join("source-inputs-before.tsv"))?
        != fs::read(suite_dir.join("source-inputs-before.tsv"))?
    {
        return Err(invalid(
            "source inputs changed between the init and kernel builds",
        ));
    }
    let tools = prepare_qemu_inputs(&output.root, &output.path, &init_build.elf)?;
    copy_notices(&output.root, &output.path, &tools.sha256sum.path)?;
    let tree = stage_tree(&output, &tools, &suite_build)?;

    // Boot those exact files once.
    let boot_dir = output.path.join("tree-boot");
    create_directory(&boot_dir)?;
    let image = tree_image(&output, &boot_dir, &tree.dir, &tools, &tree.hashes)?;
    let (screen, format, pages) =
        boot_and_capture(&output, &boot_dir, &image, &suite_build, &tools, timeout)?;
    let sha = &tools.sha256sum.path;
    if file_hash(&output.root, sha, &image.disk)? != image.disk_sha256_initial {
        return Err(invalid("the stick image changed during the QEMU boot"));
    }
    let kernel = &tree.hashes[2].1;
    if &file_hash(&output.root, sha, &tree.dir.join("linux-rs-kernel"))? != kernel
        || &suite_build.elf_hash != kernel
    {
        return Err(invalid(
            "the kernel in the tree differs from the build snapshot",
        ));
    }

    write_report(&Report {
        output: &output,
        tools: &tools,
        tree: &tree,
        init_sha256: &init_build.elf_hash,
        screen: &screen,
        format,
        pages,
    })?;
    println!(
        "baremetal-suite: USB tree {}",
        display_path(&relative_path(&output.root, &tree.dir)?)?
    );
    println!("Build id: {}", tree.id);
    println!(
        "QEMU boot of the tree: final screen {}",
        display_path(&relative_path(&output.root, &screen)?)?
    );
    println!("Manifest: {}/manifest.tsv", display_path(&output.relative)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_recomputed_like_the_kernel() {
        // Same vectors as `kernel::suite::tests::digest_is_fnv1a_64`.
        assert_eq!(fnv1a(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a(b"foobar"), 0x8594_4171_f739_67e8);
    }

    #[test]
    fn digests_are_taken_from_the_summary_lines() {
        let line = "linux-rs bare-metal suite   build abc   log digest 0123456789abcdef";
        assert_eq!(digest_in(line, "log digest "), Some("0123456789abcdef"));
        assert_eq!(digest_in("log digest 12345", "log digest "), None);
        assert_eq!(digest_in("x", "log digest "), None);
    }

    #[test]
    fn suite_cases_have_unique_names_and_a_catalog_disjoint_from_the_debug_cases() {
        let names = super::super::SUITE_CASES
            .iter()
            .map(|case| case.name)
            .collect::<Vec<_>>();
        let mut unique = names.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), names.len());
        assert!(
            super::super::debug_case_catalog().all(|(name, _)| !names.contains(&name)),
            "suite cases must not join the packaged catalog"
        );
    }

    /// A serial log the kernel would print for `groups` (a passing group repeats
    /// the pinned Linux's lines for it), with a correct digest.
    fn log_of(groups: &[(&str, bool)]) -> String {
        let mut log = String::from("firmware noise\n");
        let begin = log.len();
        log.push_str("console: framebuffers used=1 reported=1 grid=160x50 limit=fb0\nlinux-rs bootstrap x86_64 limine-base=5 firmware=efi64\n");
        for name in PROOFS {
            writeln!(log, "PROOF {name} PASS").unwrap();
        }
        let mut passed = 0;
        for &(group, must_pass) in groups {
            writeln!(log, "SUITE group {group} start uptime_s=3").unwrap();
            if must_pass {
                let rows = oracle_rows(group).map(|(_, line)| line).collect::<Vec<_>>();
                for line in &rows {
                    writeln!(log, "{line}").unwrap();
                }
                let n = rows.len();
                writeln!(log, "SUITE group {group} result=pass cause=\"init exit 0\" matched={n} expected={n} observed={n} mismatches=0 millis=1").unwrap();
                passed += 1;
            } else if group == "fault" {
                writeln!(log, "init[1]: segfault at 0 ip 0000000000243a3d sp 00007fffffffed80 error 4 in init[42a3d,20a000+47000] likely on CPU 0 (core 0, socket 0)").unwrap();
                writeln!(log, "SUITE group {group} result=fail cause=\"init signal 11\" matched=0 expected=0 observed=0 mismatches=0 millis=1").unwrap();
            } else if group == "spin" {
                writeln!(log, "FAIL group timeout after 1 s").unwrap();
                writeln!(log, "SUITE group {group} result=fail cause=\"timeout\" matched=0 expected=0 observed=0 mismatches=0 millis=1000").unwrap();
            } else {
                writeln!(log, "FAIL syscall unimplemented nr=425").unwrap();
                writeln!(log, "SUITE group {group} result=fail cause=\"kernel stop\" matched=0 expected=0 observed=0 mismatches=0 millis=1").unwrap();
            }
        }
        let digest = fnv1a(&log.as_bytes()[begin..]);
        let (ok, n) = (passed == groups.len(), PROOFS.len());
        writeln!(log, "{SUMMARY_HEAD}abc   log digest {digest:016x}").unwrap();
        if ok {
            writeln!(
                log,
                "RESULT: ALL PASS ({} groups, {n} self-tests)",
                groups.len()
            )
            .unwrap();
        } else {
            writeln!(
                log,
                "RESULT: FAIL - {passed}/{} groups, {n}/{n} self-tests passed",
                groups.len()
            )
            .unwrap();
        }
        writeln!(
            log,
            "log: 1 bytes captured, 0 dropped, up 1 s, digest {digest:016x}"
        )
        .unwrap();
        writeln!(
            log,
            "SUITE complete ok={ok} groups={passed}/{} proofs={n}/{n}",
            groups.len()
        )
        .unwrap();
        if !ok {
            writeln!(
                log,
                "FAILURE DETAIL (first rows only; the replay pages hold the rest)"
            )
            .unwrap();
            for &(group, must_pass) in groups {
                let stop = match group {
                    "io_uring" => "FAIL syscall unimplemented nr=425",
                    "spin" => "FAIL group timeout after 1 s",
                    _ => continue,
                };
                if !must_pass {
                    writeln!(log, "  {group} stopped: {stop}").unwrap();
                }
            }
        }
        writeln!(log, "{FINAL_LINE}").unwrap();
        log
    }

    fn judge(log: &str, groups: &[(&str, bool)]) -> Result<(), String> {
        let lines = log.lines().collect::<Vec<_>>();
        validate(log, &lines, groups)
    }

    #[test]
    fn a_log_the_kernel_would_print_is_accepted() {
        judge(&log_of(ALL_PASS), ALL_PASS).unwrap();
        judge(&log_of(STOPS), STOPS).unwrap();
    }

    #[test]
    fn a_wrong_digest_proof_or_verdict_is_rejected() {
        let log = log_of(ALL_PASS);
        let error =
            judge(&log.replace("PROOF heap PASS", "PROOF heap FAIL"), ALL_PASS).unwrap_err();
        assert!(error.contains("heap"), "{error}");
        let error = judge(&log, &[("ids", false)]).unwrap_err();
        assert!(error.contains("must be fail"), "{error}");
        // One character of the captured transcript changes: the digest no longer fits.
        let error =
            judge(&log.replacen("limine-base=5", "limine-base=6", 1), ALL_PASS).unwrap_err();
        assert!(
            error.contains("differs from the serial transcript"),
            "{error}"
        );
        // A group whose lines differ from the pinned Linux's fails the host comparison too.
        let error = judge(
            &log.replacen("init: test ids.getuid ok", "init: test ids.getuid FAIL", 1),
            ALL_PASS,
        )
        .unwrap_err();
        assert!(error.contains("ids"), "{error}");
        assert!(judge(&log.replace(FINAL_LINE, "done"), ALL_PASS).is_err());
        // A stopped group's stop line must be in the failure detail at the end of the screen.
        let stops = log_of(STOPS);
        let error = judge(&stops.replace("  spin stopped: FAIL", "  spin x"), STOPS).unwrap_err();
        assert!(error.contains("failure detail"), "{error}");
    }

    #[test]
    fn the_limine_config_has_one_entry_a_countdown_and_no_forced_mode() {
        assert!(LIMINE_CONF.contains("timeout: 5"));
        assert_eq!(LIMINE_CONF.matches("\n/").count(), 1);
        assert!(!LIMINE_CONF.contains("resolution"));
        assert!(LIMINE_CONF.contains("path: boot():/linux-rs-kernel"));
        assert!(LIMINE_CONF.contains("module_path: boot():/initramfs.cpio"));
    }
}
