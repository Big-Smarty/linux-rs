// SPDX-License-Identifier: GPL-2.0-only
//! A separate, unsigned ALPM diagnostic payload. This module never installs it.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, DirBuilder, File, FileTimes, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::kernel::{
    Output, SOURCE_MEMBERS, debug_case_catalog, file_hash, hash_files, prepare_output,
    resolve_program, run_with_logs, tool_output,
};

mod metadata;

use metadata::{Recipe, installed_packages, recipe_text};

const NAME: &str = "linux-rs-bootstrap-diagnostic";
const PAYLOAD: &str = "usr/lib/linux-rs-bootstrap-diagnostic";
const DOCUMENTS: &str = "usr/share/doc/linux-rs-bootstrap-diagnostic";
const COMPILER_COMMIT: &str = "5c543b0b8c73c7b72bc8284ced4fb22ead15734d";
const RECIPE: &str = "usr/share/doc/linux-rs-bootstrap-diagnostic/corresponding-source/PKGBUILD";
const PACKAGER: &str = "linux-rs local diagnostic builder (unsigned)";
const ARCHIVE_TIMEOUT: Duration = Duration::from_secs(300);
const TEXT_LIMIT: u64 = 64 * 1024 * 1024;

type Manifest = BTreeMap<String, String>;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn path_text(path: &Path) -> io::Result<&str> {
    let value = path
        .to_str()
        .ok_or_else(|| invalid("package paths must be UTF-8"))?;
    if value.chars().any(char::is_control) || value.contains('\\') {
        return Err(invalid(
            "package paths cannot contain control characters or backslashes",
        ));
    }
    Ok(value)
}

fn clean_path(path: &Path, absolute: bool) -> io::Result<()> {
    let value = path_text(path)?;
    if value.is_empty()
        || path.is_absolute() != absolute
        || value.split('/').enumerate().any(|(index, part)| {
            (part.is_empty() && !(absolute && index == 0)) || part == "." || part == ".."
        })
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_) | Component::RootDir))
    {
        return Err(invalid(format!(
            "noncanonical package input path: {}",
            path.display()
        )));
    }
    Ok(())
}

/// Check every ancestor, not merely the final file's metadata.
fn real_path(path: &Path, directory: bool) -> io::Result<()> {
    clean_path(path, true)?;
    let mut prefix = PathBuf::new();
    let count = path.components().count();
    for (index, component) in path.components().enumerate() {
        prefix.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&prefix)?;
        let want_directory = index + 1 != count || directory;
        if metadata.file_type().is_symlink()
            || (want_directory && !metadata.is_dir())
            || (!want_directory && !metadata.is_file())
        {
            return Err(invalid(format!(
                "{} must be a real {}, not a symlink or special file",
                prefix.display(),
                if want_directory {
                    "directory"
                } else {
                    "regular file"
                }
            )));
        }
    }
    Ok(())
}

fn open_regular(path: &Path) -> io::Result<File> {
    real_path(path, false)?;
    // Linux O_NOFOLLOW | O_NONBLOCK: a last-component replacement must not
    // follow a symlink or block opening a FIFO. Ancestors must remain quiescent;
    // these checks are not a sandbox against a hostile same-UID writer.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(0x0002_0000 | 0x0000_0800)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid(format!("{} is no longer regular", path.display())));
    }
    Ok(file)
}

fn read_text(path: &Path) -> io::Result<String> {
    let mut input = open_regular(path)?.take(TEXT_LIMIT + 1);
    let mut text = String::new();
    input.read_to_string(&mut text)?;
    if text.len() as u64 > TEXT_LIMIT {
        return Err(invalid(format!(
            "metadata exceeds 64 MiB: {}",
            path.display()
        )));
    }
    Ok(text)
}

fn parse_manifest(text: &str) -> io::Result<Manifest> {
    let mut lines = text.lines();
    if lines.next() != Some("key\tvalue") {
        return Err(invalid("expected a key/value TSV manifest"));
    }
    let mut values = Manifest::new();
    for line in lines {
        let (key, value) = line
            .split_once('\t')
            .ok_or_else(|| invalid("manifest row lacks its tab separator"))?;
        if key.is_empty()
            || key.chars().any(char::is_control)
            || value.chars().any(char::is_control)
            || values.insert(key.to_owned(), value.to_owned()).is_some()
        {
            return Err(invalid(format!(
                "invalid or duplicate manifest field {key:?}"
            )));
        }
    }
    Ok(values)
}

fn field<'a>(manifest: &'a Manifest, key: &str) -> io::Result<&'a str> {
    manifest
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| invalid(format!("required build/evidence field is missing: {key}")))
}

fn require(manifest: &Manifest, key: &str, expected: &str) -> io::Result<()> {
    let actual = field(manifest, key)?;
    if actual != expected {
        return Err(invalid(format!(
            "{key}: expected {expected:?}, found {actual:?}"
        )));
    }
    Ok(())
}

fn digest(value: &str) -> io::Result<&str> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid("expected a lowercase SHA-256 digest"));
    }
    Ok(value)
}

fn recorded_files(manifest: &Manifest) -> io::Result<BTreeMap<PathBuf, String>> {
    let mut files = BTreeMap::new();
    for (key, value) in manifest {
        let Some(index) = key
            .strip_prefix("source_")
            .and_then(|key| key.strip_suffix("_path"))
        else {
            continue;
        };
        if index.is_empty() || !index.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid("invalid source index in build manifest"));
        }
        let hash = digest(field(manifest, &format!("source_{index}_sha256"))?)?;
        let path = PathBuf::from(value);
        clean_path(&path, path.is_absolute())?;
        if files.insert(path, hash.to_owned()).is_some() {
            return Err(invalid("duplicate source path in build manifest"));
        }
    }
    if files.is_empty() {
        return Err(invalid(
            "build manifest contains no source hash bindings; rebuild with current tooling",
        ));
    }
    if let Some(count) = manifest.get("source_count")
        && count.parse::<usize>().ok() != Some(files.len())
    {
        return Err(invalid("source manifest count does not match its records"));
    }
    Ok(files)
}

fn files_under(directory: &Path) -> io::Result<BTreeSet<PathBuf>> {
    real_path(directory, true)?;
    let mut pending = vec![directory.to_path_buf()];
    let mut files = BTreeSet::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            path_text(&path)?;
            let kind = entry.file_type()?;
            if kind.is_dir() {
                pending.push(path);
            } else if kind.is_file() {
                files.insert(path);
            } else {
                return Err(invalid(format!(
                    "source tree contains a symlink/special file: {}",
                    path.display()
                )));
            }
        }
    }
    Ok(files)
}

fn input_path(
    root: &Path,
    manifest: &Manifest,
    key: &str,
    directory: &Path,
) -> io::Result<PathBuf> {
    let relative = Path::new(field(manifest, key)?);
    clean_path(relative, false)?;
    let path = root.join(relative);
    if !path.starts_with(directory) {
        return Err(invalid(format!(
            "{key} escapes its build/evidence directory"
        )));
    }
    real_path(&path, false)?;
    Ok(path)
}

struct Inputs {
    root: PathBuf,
    build: PathBuf,
    output: PathBuf,
    manifest: Manifest,
    manifest_hash: String,
    elf_hash: String,
}

impl Inputs {
    fn load(output: Output, build: &Path, sha: &Path) -> io::Result<Self> {
        let Output {
            root, path: output, ..
        } = output;
        let base = root.join("target/kernel-tooling");
        real_path(&base, true)?;
        let build = Self::absolute(&root, build)?;
        let relative = build
            .strip_prefix(&base)
            .map_err(|_| invalid("--build-output must be inside target/kernel-tooling"))?;
        let depth = relative.components().count();
        if depth != 1
            && !(depth == 2 && relative.file_name() == Some("freestanding-build".as_ref()))
        {
            return Err(invalid(
                "select a kernel-build directory or kernel-test's freestanding-build directory",
            ));
        }
        real_path(&build, true)?;
        let manifest_path = build.join("build-manifest.tsv");
        let manifest = parse_manifest(&read_text(&manifest_path)?)?;
        validate_profile(&manifest)?;
        let manifest_hash = file_hash(&root, sha, &manifest_path)?;
        let elf_hash = digest(field(&manifest, "sha256_kernel_elf_snapshot")?)?.to_owned();
        Ok(Self {
            root,
            build,
            output,
            manifest,
            manifest_hash,
            elf_hash,
        })
    }

    fn absolute(root: &Path, path: &Path) -> io::Result<PathBuf> {
        clean_path(path, path.is_absolute())?;
        Ok(if path.is_absolute() {
            path.to_path_buf()
        } else {
            root.join(path)
        })
    }
}

fn validate_profile(manifest: &Manifest) -> io::Result<()> {
    for (key, value) in [
        ("schema", "1"),
        ("build_profile", "freestanding"),
        ("feature_set", "freestanding"),
        ("target", "x86_64-unknown-none"),
        ("binary", "linux-rs-kernel"),
        ("cargo_exit_code", "0"),
        ("qualified_rustc_commit", COMPILER_COMMIT),
    ] {
        require(manifest, key, value)?;
    }
    let arguments = field(manifest, "cargo_arguments")?;
    if arguments.contains("qemu-self-test") || !arguments.contains("--features | freestanding") {
        return Err(invalid(
            "only an explicit freestanding-only build can be packaged",
        ));
    }
    if !field(manifest, "rustc_version")?.contains(COMPILER_COMMIT) {
        return Err(invalid(
            "build compiler identity does not match its qualified commit",
        ));
    }
    Ok(())
}

struct Staging<'a> {
    inputs: &'a Inputs,
    sha: &'a Path,
    directory: PathBuf,
    files: BTreeMap<PathBuf, String>,
    directories: BTreeSet<PathBuf>,
    pending_hashes: Vec<PathBuf>,
    epoch: u64,
    start_directory: PathBuf,
}

impl<'a> Staging<'a> {
    fn new(inputs: &'a Inputs, sha: &'a Path) -> io::Result<Self> {
        let directory = inputs.output.join("staging");
        DirBuilder::new().mode(0o755).create(&directory)?;
        let epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| invalid(error.to_string()))?
            .as_secs();
        let start_directory = std::env::current_dir()?;
        real_path(&start_directory, true)?;
        Ok(Self {
            inputs,
            sha,
            directory,
            files: BTreeMap::new(),
            directories: BTreeSet::new(),
            pending_hashes: Vec::new(),
            epoch,
            start_directory,
        })
    }

    fn destination(&mut self, relative: &Path) -> io::Result<PathBuf> {
        clean_path(relative, false)?;
        if self.files.contains_key(relative) {
            return Err(invalid(format!(
                "duplicate staged path: {}",
                relative.display()
            )));
        }
        let mut directory = PathBuf::new();
        if let Some(parent) = relative.parent() {
            for component in parent.components() {
                directory.push(component);
                if self.directories.insert(directory.clone()) {
                    DirBuilder::new()
                        .mode(0o755)
                        .create(self.directory.join(&directory))?;
                    fs::set_permissions(
                        self.directory.join(&directory),
                        fs::Permissions::from_mode(0o755),
                    )?;
                }
            }
        }
        Ok(self.directory.join(relative))
    }

    fn remember(&mut self, relative: &Path, path: &Path, expected: Option<&str>) -> io::Result<()> {
        let hash = match expected {
            Some(expected)
                if relative.starts_with(Path::new(DOCUMENTS).join("corresponding-source")) =>
            {
                digest(expected)?;
                self.pending_hashes.push(path.to_path_buf());
                expected.to_owned()
            }
            expected => {
                let hash = file_hash(&self.inputs.root, self.sha, path)?;
                if let Some(expected) = expected
                    && hash != digest(expected)?
                {
                    return Err(invalid(format!(
                        "source/hash mismatch for {}; refusing stale or changed artifact",
                        relative.display()
                    )));
                }
                hash
            }
        };
        let file = open_regular(path)?;
        file.set_permissions(fs::Permissions::from_mode(0o644))?;
        file.set_times(
            FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(self.epoch)),
        )?;
        self.files.insert(relative.to_path_buf(), hash);
        Ok(())
    }

    fn copy(&mut self, source: &Path, relative: &Path, expected: &str) -> io::Result<()> {
        let mut source = open_regular(source)?;
        let destination = self.destination(relative)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&destination)?;
        io::copy(&mut source, &mut file)?;
        drop(file);
        self.remember(relative, &destination, Some(expected))
    }

    fn capture(&mut self, source: &Path, relative: &Path) -> io::Result<()> {
        real_path(source, false)?;
        let hash = file_hash(&self.inputs.root, self.sha, source)?;
        self.copy(source, relative, &hash)
    }

    fn text(&mut self, relative: &Path, content: &str) -> io::Result<()> {
        let destination = self.destination(relative)?;
        write_new(&destination, content.as_bytes())?;
        self.remember(relative, &destination, None)
    }

    fn verify_sources(&mut self) -> io::Result<()> {
        let hashes = hash_files(&self.inputs.root, self.sha, &self.pending_hashes)?;
        for (path, hash) in hashes {
            let relative = path
                .strip_prefix(&self.directory)
                .map_err(|error| invalid(error.to_string()))?;
            if self.files.get(relative) != Some(&hash) {
                return Err(invalid(format!(
                    "copied source/hash mismatch: {}",
                    relative.display()
                )));
            }
        }
        self.pending_hashes.clear();
        Ok(())
    }
}

fn write_new(path: &Path, content: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(content)
}

/// Files the corresponding-source tree must hold: the root manifests and every workspace member.
fn expected_project_files(root: &Path) -> io::Result<BTreeSet<PathBuf>> {
    let mut expected = BTreeSet::new();
    for name in ["Cargo.toml", "Cargo.lock", "LICENSE"] {
        expected.insert(PathBuf::from(name));
    }
    for name in [
        "rust-toolchain",
        "rust-toolchain.toml",
        ".cargo/config.toml",
    ] {
        match fs::symlink_metadata(root.join(name)) {
            Ok(_) => {
                real_path(&root.join(name), false)?;
                expected.insert(PathBuf::from(name));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    for member in SOURCE_MEMBERS.into_iter().chain(["vendor"]) {
        for path in files_under(&root.join(member))? {
            expected.insert(
                path.strip_prefix(root)
                    .map_err(|error| invalid(error.to_string()))?
                    .to_path_buf(),
            );
        }
    }
    Ok(expected)
}

fn stage_project(staging: &mut Staging<'_>) -> io::Result<()> {
    let inputs = staging.inputs;
    let sources = recorded_files(&inputs.manifest)?;
    let expected = expected_project_files(&inputs.root)?;
    let recorded = sources.keys().cloned().collect::<BTreeSet<_>>();
    if recorded != expected {
        return Err(invalid(
            "build source inventory differs from complete current workspace; rebuild after freezing every member source/manifest",
        ));
    }
    for (relative, hash) in sources {
        let destination = Path::new(DOCUMENTS)
            .join("corresponding-source/project")
            .join(&relative);
        staging.copy(&inputs.root.join(relative), &destination, &hash)?;
    }
    Ok(())
}

fn stage_runtime(staging: &mut Staging<'_>) -> io::Result<()> {
    let inputs = staging.inputs;
    let before = input_path(
        &inputs.root,
        &inputs.manifest,
        "runtime_inputs_before",
        &inputs.build,
    )?;
    let after = input_path(
        &inputs.root,
        &inputs.manifest,
        "runtime_inputs_after",
        &inputs.build,
    )?;
    let before_hash = digest(field(&inputs.manifest, "sha256_runtime_inputs_before")?)?;
    require(&inputs.manifest, "sha256_runtime_inputs_after", before_hash)?;
    for (path, name) in [
        (&before, "runtime-inputs-before.tsv"),
        (&after, "runtime-inputs-after.tsv"),
    ] {
        staging.copy(
            path,
            &Path::new(DOCUMENTS).join("provenance/build").join(name),
            before_hash,
        )?;
    }
    let runtime = parse_manifest(&read_text(
        &staging
            .directory
            .join(DOCUMENTS)
            .join("provenance/build/runtime-inputs-before.tsv"),
    )?)?;
    let sources = recorded_files(&runtime)?;
    let library = Path::new(field(&inputs.manifest, "rust_src_library_path")?);
    real_path(library, true)?;
    let suffix = Path::new("lib/rustlib/src/rust/library");
    let sysroot = library
        .ancestors()
        .nth(5)
        .ok_or_else(|| invalid("invalid rust-src library path"))?;
    if sysroot.join(suffix) != library {
        return Err(invalid(
            "runtime source library is not inside its recorded compiler sysroot",
        ));
    }
    let notices = sysroot.join("share/doc/rust");
    let actual = files_under(library)?;
    let recorded = sources
        .keys()
        .filter(|path| path.starts_with(library))
        .cloned()
        .collect::<BTreeSet<_>>();
    if actual != recorded {
        return Err(invalid(
            "installed rust-src tree differs from the build-bound runtime inventory",
        ));
    }
    for required in [
        "COPYRIGHT-library.html",
        "licenses/MIT.txt",
        "licenses/Apache-2.0.txt",
        "licenses/LLVM-exception.txt",
        "licenses/Unicode-3.0.txt",
    ] {
        if !sources.contains_key(&notices.join(required)) {
            return Err(invalid(format!(
                "build did not bind required compiler notice {required}"
            )));
        }
    }
    for (source, hash) in sources {
        if let Ok(relative) = source.strip_prefix(library) {
            staging.copy(
                &source,
                &Path::new(DOCUMENTS)
                    .join("corresponding-source/rust-library")
                    .join(relative),
                &hash,
            )?;
        } else if let Ok(relative) = source.strip_prefix(&notices) {
            staging.copy(
                &source,
                &Path::new(DOCUMENTS).join("notices/rust").join(relative),
                &hash,
            )?;
        } else {
            verify_external_input(staging, &source, &hash, sysroot)?;
        }
    }
    Ok(())
}

fn verify_external_input(
    staging: &Staging<'_>,
    source: &Path,
    hash: &str,
    sysroot: &Path,
) -> io::Result<()> {
    let inputs = staging.inputs;
    let name = source
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let mut declared = source.parent() == Some(sysroot.join("lib").as_path())
        && (name.starts_with("librustc_driver") || name.starts_with("libLLVM"));
    for (key, hash_key) in [
        ("cargo_path", "sha256_cargo"),
        ("rustc_path", "sha256_rustc"),
        ("rust_lld_path", "sha256_rust_lld"),
        ("readelf_path", "sha256_readelf"),
        ("sha256sum_path", "sha256_sha256sum"),
        ("process_group_kill_path", "sha256_process_group_kill"),
        ("setpriv_path", "sha256_setpriv"),
        ("harness_executable_path", "sha256_harness_executable"),
        ("local_cargo_config", "local_cargo_config_sha256"),
        ("vendored_std_inputs", "vendored_std_inputs_sha256"),
        ("target_spec_path", "target_spec_sha256"),
    ] {
        let path = Path::new(field(&inputs.manifest, key)?);
        let path = Inputs::absolute(&inputs.root, path)?;
        if path == source {
            require(&inputs.manifest, hash_key, hash)?;
            declared = true;
        }
    }
    // Tools and generated build configuration are verified, never redistributed
    // as runtime source or copied from an arbitrary manifest-supplied location.
    real_path(source, false)?;
    if !declared || file_hash(&inputs.root, staging.sha, source)? != hash {
        return Err(invalid(format!(
            "undeclared or changed external build input: {}",
            source.display()
        )));
    }
    Ok(())
}

fn check_elf(path: &Path) -> io::Result<()> {
    let mut file = open_regular(path)?;
    let mut header = [0_u8; 64];
    file.read_exact(&mut header)?;
    if header[..7] != [0x7f, b'E', b'L', b'F', 2, 1, 1]
        || u16::from_le_bytes([header[16], header[17]]) != 2
        || u16::from_le_bytes([header[18], header[19]]) != 62
        || u16::from_le_bytes([header[52], header[53]]) != 64
        || u16::from_le_bytes([header[54], header[55]]) != 56
        || u16::from_le_bytes([header[56], header[57]]) == 0
    {
        return Err(invalid(
            "payload is not a little-endian ELF64 x86_64 ET_EXEC kernel",
        ));
    }
    let size = file.metadata()?.len();
    let word = |bytes: &[u8]| {
        <[u8; 8]>::try_from(bytes)
            .map(u64::from_le_bytes)
            .map_err(|error| invalid(error.to_string()))
    };
    let entry = word(&header[24..32])?;
    let offset = word(&header[32..40])?;
    let count = u64::from(u16::from_le_bytes([header[56], header[57]]));
    if offset.checked_add(count * 56).is_none_or(|end| end > size) {
        return Err(invalid("ELF program header table escapes the regular file"));
    }
    file.seek(SeekFrom::Start(offset))?;
    let mut executable_entry = false;
    for _ in 0..count {
        let mut program = [0_u8; 56];
        file.read_exact(&mut program)?;
        let kind = u32::from_le_bytes([program[0], program[1], program[2], program[3]]);
        if kind == 3 {
            return Err(invalid(
                "diagnostic ELF must not require a userspace interpreter",
            ));
        }
        if kind != 1 {
            continue;
        }
        let flags = u32::from_le_bytes([program[4], program[5], program[6], program[7]]);
        let start = word(&program[16..24])?;
        let filesz = word(&program[32..40])?;
        let memsz = word(&program[40..48])?;
        if filesz > memsz
            || word(&program[8..16])?
                .checked_add(filesz)
                .is_none_or(|end| end > size)
            || start.checked_add(memsz).is_none()
            || flags & 3 == 3
        {
            return Err(invalid(
                "ELF contains an invalid or writable-executable load segment",
            ));
        }
        executable_entry |= flags & 1 != 0 && start <= entry && entry < start + filesz;
    }
    if !executable_entry {
        return Err(invalid(
            "ELF entry is not backed by an executable file segment",
        ));
    }
    Ok(())
}

fn stage_build(staging: &mut Staging<'_>) -> io::Result<()> {
    let inputs = staging.inputs;
    staging.copy(
        &inputs.build.join("build-manifest.tsv"),
        &Path::new(DOCUMENTS).join("provenance/build/build-manifest.tsv"),
        &inputs.manifest_hash,
    )?;
    for (key, hash, destination) in [
        (
            "kernel_elf_snapshot",
            "sha256_kernel_elf_snapshot",
            Path::new(PAYLOAD).join("linux-rs-kernel.elf"),
        ),
        (
            "map_path",
            "sha256_link_map",
            Path::new(DOCUMENTS).join("provenance/build/kernel.map"),
        ),
        (
            "target_spec_path",
            "target_spec_sha256",
            Path::new(DOCUMENTS).join("provenance/build/target-spec.json"),
        ),
        (
            "local_cargo_config",
            "local_cargo_config_sha256",
            Path::new(DOCUMENTS).join("provenance/build/cargo-config.toml"),
        ),
        (
            "vendored_std_inputs",
            "vendored_std_inputs_sha256",
            Path::new(DOCUMENTS).join("provenance/build/vendored-std-inputs.tsv"),
        ),
    ] {
        let source = input_path(&inputs.root, &inputs.manifest, key, &inputs.build)?;
        staging.copy(&source, &destination, field(&inputs.manifest, hash)?)?;
    }
    check_elf(&staging.directory.join(PAYLOAD).join("linux-rs-kernel.elf"))?;
    let before_hash = field(&inputs.manifest, "sha256_source_inputs_before")?;
    require(&inputs.manifest, "sha256_source_inputs_after", before_hash)?;
    for (key, name) in [
        ("source_inputs_before", "source-inputs-before.tsv"),
        ("source_inputs_after", "source-inputs-after.tsv"),
    ] {
        let source = input_path(&inputs.root, &inputs.manifest, key, &inputs.build)?;
        staging.copy(
            &source,
            &Path::new(DOCUMENTS).join("provenance/build").join(name),
            before_hash,
        )?;
    }
    // Only these named attachments are staged; no disk images, EFI binaries,
    // mutable OVMF variables, sockets or unrecognized build-directory contents.
    for name in [
        "cargo.stdout.log",
        "cargo.stderr.log",
        "readelf-header.txt",
        "program-headers.txt",
    ] {
        staging.capture(
            &inputs.build.join(name),
            &Path::new(DOCUMENTS).join("provenance/build").join(name),
        )?;
    }
    Ok(())
}

fn stage_case(
    staging: &mut Staging<'_>,
    run: &Path,
    (case, expected_exit): (&str, i32),
    self_hash: &str,
) -> io::Result<()> {
    let directory = run.join("cases").join(case);
    let result = parse_manifest(&read_text(&directory.join("result.tsv"))?)?;
    require(&result, "case", case)?;
    require(&result, "status", "matched")?;
    require(&result, "timed_out", "false")?;
    require(&result, "sha256_kernel_elf", self_hash)?;
    require(&result, "sha256_kernel_elf_after_run", self_hash)?;
    let exit = expected_exit.to_string();
    require(&result, "expected_exit", &exit)?;
    require(&result, "observed_exit", &exit)?;
    for name in [
        "result.tsv",
        "serial.log",
        "qemu.stdout.log",
        "qemu.stderr.log",
        "limine.conf",
    ] {
        // Guest-controlled, so bounded like the verdict's own serial read.
        let log = directory.join(name);
        if fs::metadata(&log)?.len() > crate::kernel::SERIAL_LOG_LIMIT {
            return Err(invalid(format!(
                "{} exceeds the evidence size limit",
                log.display()
            )));
        }
        staging.capture(
            &log,
            &Path::new(DOCUMENTS)
                .join("provenance/qemu/cases")
                .join(case)
                .join(name),
        )?;
    }
    Ok(())
}

fn validate_test_manifest(top: &Manifest) -> io::Result<()> {
    let expected_count = debug_case_catalog().len().to_string();
    for (key, value) in [
        ("command", "kernel-test"),
        ("automated_case_count", expected_count.as_str()),
        ("automated_cases_matched", expected_count.as_str()),
        ("automated_cases_failed", "0"),
        ("default_feature_set", "freestanding"),
    ] {
        require(top, key, value)?;
    }
    Ok(())
}

fn stage_evidence(staging: &mut Staging<'_>) -> io::Result<&'static str> {
    let inputs = staging.inputs;
    if inputs.build.parent() == Some(inputs.root.join("target/kernel-tooling").as_path()) {
        return Ok("build-only; no QEMU execution evidence supplied");
    }
    let run = inputs
        .build
        .parent()
        .ok_or_else(|| invalid("missing kernel-test run directory"))?;
    let top = parse_manifest(&read_text(&run.join("manifest.tsv"))?)?;
    validate_test_manifest(&top)?;
    let default_elf = input_path(&inputs.root, &top, "default_elf", &inputs.build)?;
    if default_elf
        != input_path(
            &inputs.root,
            &inputs.manifest,
            "kernel_elf_snapshot",
            &inputs.build,
        )?
    {
        return Err(invalid(
            "QEMU run's default ELF is not this package's build",
        ));
    }
    let self_directory = run.join("qemu-self-test-build");
    let self_manifest = parse_manifest(&read_text(&self_directory.join("build-manifest.tsv"))?)?;
    if recorded_files(&self_manifest)? != recorded_files(&inputs.manifest)? {
        return Err(invalid(
            "self-test and default build source inventories differ",
        ));
    }
    let self_hash = digest(field(&self_manifest, "sha256_kernel_elf_snapshot")?)?;
    for case in debug_case_catalog() {
        stage_case(staging, run, case, self_hash)?;
    }
    staging.capture(
        &self_directory.join("build-manifest.tsv"),
        &Path::new(DOCUMENTS).join("provenance/qemu/self-test-build-manifest.tsv"),
    )?;
    staging.capture(
        &run.join("manifest.tsv"),
        &Path::new(DOCUMENTS).join("provenance/qemu/manifest.tsv"),
    )?;
    stage_default_evidence(staging, run)?;
    Ok(
        "complete current QEMU case catalog recorded matched; exact default ELF framebuffer captured; visual review remains human; no physical result",
    )
}

fn stage_default_evidence(staging: &mut Staging<'_>, run: &Path) -> io::Result<()> {
    let inputs = staging.inputs;
    let directory = run.join("default-boot");
    let result = parse_manifest(&read_text(&directory.join("result.tsv"))?)?;
    require(&result, "sha256_kernel_elf", &inputs.elf_hash)?;
    require(&result, "sha256_kernel_elf_after_run", &inputs.elf_hash)?;
    let screenshot = input_path(&inputs.root, &result, "screenshot", &directory)?;
    let name = screenshot
        .file_name()
        .ok_or_else(|| invalid("missing screenshot filename"))?;
    if name != "framebuffer.png" && name != "framebuffer.ppm" {
        return Err(invalid("unexpected framebuffer screenshot filename"));
    }
    staging.copy(
        &screenshot,
        &Path::new(DOCUMENTS)
            .join("provenance/qemu/default-boot")
            .join(name),
        field(&result, "screenshot_sha256")?,
    )?;
    for name in [
        "result.tsv",
        "qmp.log",
        "qmp-cpus.jsonl",
        "qmp-registers.jsonl",
        "qmp-status.jsonl",
        "qemu.stdout.log",
        "qemu.stderr.log",
        "limine.conf",
    ] {
        staging.capture(
            &directory.join(name),
            &Path::new(DOCUMENTS)
                .join("provenance/qemu/default-boot")
                .join(name),
        )?;
    }
    Ok(())
}

fn stage_documentation(staging: &mut Staging<'_>) -> io::Result<()> {
    for name in [
        "diagnostic-handoff.md",
        "implementation.md",
        "kernel-tooling.md",
        "licensing.md",
    ] {
        staging.capture(
            &staging.inputs.root.join("docs").join(name),
            &Path::new(DOCUMENTS).join(name),
        )?;
    }
    let source = staging
        .directory
        .join(DOCUMENTS)
        .join("corresponding-source/project");
    staging.capture(
        &source.join("LICENSE"),
        &Path::new(DOCUMENTS).join("notices/GPL-2.0-only.txt"),
    )?;
    let boot = read_text(&source.join("kernel/src/boot.rs"))?;
    let notice = boot
        .lines()
        .take_while(|line| line.starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    if !notice.contains("Copyright (C) 2022-2026 Mintsuki and contributors.")
        || !notice.contains("GPL-2.0-only AND 0BSD")
    {
        return Err(invalid(
            "Limine protocol notice changed; review the package's notice extraction",
        ));
    }
    staging.text(
        &Path::new(DOCUMENTS).join("notices/limine-protocol-0BSD.txt"),
        &format!("{notice}\n"),
    )?;
    staging.text(&Path::new(DOCUMENTS).join("NOTICE.txt"), NOTICE)?;
    staging.text(&Path::new(DOCUMENTS).join("REPRODUCING.txt"), REPRODUCING)?;
    staging.text(&Path::new(DOCUMENTS).join("limine-entry.example.conf"), "# Example only. Never installed or selected by xtask.\n/linux-rs EXPERIMENTAL storage-free diagnostic\n    protocol: limine\n    path: boot():/linux-rs-bootstrap-diagnostic/linux-rs-kernel.elf\n    resolution: 1024x768x32\n")
}

const NOTICE: &str = "Experimental storage-free bootstrap diagnostic; NOT a Linux-replacement kernel.\n\nProject kernel and host sources: GPL-2.0-only, complete LICENSE and original\nsource comments retained. Selected Limine protocol definitions retain 0BSD\ncopyright/permission/warranty notices in kernel/src/boot.rs and notices/.\nNo Limine executable, OVMF, machine firmware, microcode, initramfs or Linux\nroot filesystem is redistributed. Existing external Limine must load the ELF.\n\nThe matching Rust core is MIT OR Apache-2.0; MIT is elected for its selected\ncode. COPYRIGHT-library.html preserves actual authorship and per-file terms;\nthe generic MIT.txt template is not an invented project copyright holder.\nUnicode and other per-file exceptions remain in the original source/notices.\nCompiler-builtins 0.1.160 retains MIT AND Apache-2.0 WITH LLVM-exception AND\n(MIT OR Apache-2.0); the optional MIT branch is elected, not a removal of the\nconjunctive LLVM-exception terms. Its complete LICENSE.txt and libm/LICENSE.txt\nremain in corresponding-source/rust-library/compiler-builtins/. The kernel\nsupplies the required scalar Rust memset; see its link map and actual runtime\naudit, not an assumption that every builtins archive member is linked.\n\nThird-party crates in corresponding-source/project/vendor keep their own MIT,\nApache-2.0 or (syscalls, user/init only) BSD-2-Clause terms and notices; MIT is\nelected where dual. The whole installed rust-src library workspace and vendor source are retained\nto reproduce Cargo's locked build-std resolution. Inactive targets, build-only\ndependencies, external upstream scripts and C/assembly test/reference sources\ninside that separate compiler-source bundle are NOT project-owned packaging\nlogic or claims of linked kernel implementation. Original copyright, NOTICE,\nlicense and checksum files are preserved without relabeling them GPL. Review\nthose file-specific terms for further distribution or changed build features.\n\nThis package is unsigned. No signing approval, approved SPDX/CycloneDX SBOM,\nindependent reproducibility result, legal release clearance, physical pass,\nsecurity certification, full M1 or Linux 6.18.57 compatibility is asserted.\nChecksums are local integrity/lineage evidence, not source authentication.\n";

const REPRODUCING: &str = "Corresponding source and reproduction boundary\n\ncorresponding-source/project contains the exact build-bound root Cargo.toml,\nCargo.lock, LICENSE, .cargo/config.toml and complete kernel, rt, user/init, xtask,\nbaremetal and vendor trees. vendor/ is the checksum-verified third-party Rust source of\nevery locked registry crate linked into or used to build the kernel, with its\nlicense files; it is corresponding source, not project-owned code. It is not a root workspace pointing at omitted members. Build arguments,\nsource hashes, exact compiler/linker identities, target specification and map\nare under provenance/build. Source changes after build are refused, not\nsilently repackaged under an older ELF hash.\n\ncorresponding-source/rust-library is the complete build-bound installed\nrust-src library workspace, including vendor, Cargo.lock, .cargo configuration,\ncore, compiler-builtins and their workspace members. It is external compiler\nsource, not an admission of every archived provider for target linkage.\nUse the exact compiler commit in build-manifest.tsv and matching installed\nrust-src from this source set in a separate disposable development workspace.\nDo not overwrite a global toolchain or install a target as a packaging step.\nCompiler/tool executables are identified and checked, not included.\n\nFrom a writable copy of corresponding-source/project, with that exact already\navailable nightly toolchain and its matching rust-src library/vendor, run:\n\ncargo +1.88.0 run -p xtask --locked --offline -- kernel-build --output target/kernel-tooling/reproduce\n\nThe maintained build command creates a private Cargo home and target directory,\nuses locked offline build-std for core/compiler_builtins, and refuses compiler\ndrift. Compare the rebuilt ELF, map, target specification and source/runtime\ninput manifests to this package. Original build paths and debug information\nare recorded; changing absolute paths or toolchain layout can change bytes.\nNo independently reproduced or bit-identical result is claimed. The package\narchive additionally records its actual creation time; rebuilding the same\nELF does not promise a byte-identical package archive.\n\ncorresponding-source/PKGBUILD is the actual constant assignment-only recipe\nparsed and consumed by the Rust producer; BUILDINFO hashes those exact bytes.\nIt is not an executable makepkg/AUR recipe and is never sourced as shell.\nBUILDINFO describes package assembly: actual xtask version, directories, time\nand queried installed packages. Original kernel compilation has its separate\nbuild-bound compiler/runtime manifest; no past host inventory is fabricated.\nThe package has no shell installer, hooks or automatic boot selection. The kernel\nbuild itself runs two reviewed third-party host build scripts (vendor/const_fn-0.4.12/build.rs and\nvendor/rustversion-1.0.23/build/build.rs; each only queries rustc), and building the host xtask runs\nfour more (serde, serde_core, serde_json, zmij), all unsandboxed as the build user.\nSee diagnostic-handoff.md for inspection and user-only trial/recovery.\n";

fn manifest_text(values: &Manifest) -> io::Result<String> {
    let mut text = String::from("key\tvalue\n");
    for (key, value) in values {
        if key.chars().any(char::is_control) || value.chars().any(char::is_control) {
            return Err(invalid(
                "package manifest value contains a control character",
            ));
        }
        text.push_str(key);
        text.push('\t');
        text.push_str(value);
        text.push('\n');
    }
    Ok(text)
}

fn run_archive_command(command: &mut Command, stdout: &Path, stderr: &Path) -> io::Result<()> {
    command
        .stdin(Stdio::null())
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .env_remove("TAR_OPTIONS")
        .env_remove("BSDTAR_OPTIONS")
        .env_remove("ZSTD_CLEVEL")
        .env_remove("ZSTD_NBTHREADS");
    let result = run_with_logs(command, stdout, stderr, ARCHIVE_TIMEOUT)?;
    if result.timed_out || result.exit_code != Some(0) {
        return Err(invalid(format!(
            "package tool failed (exit {:?}, timed_out {}); inspect {}",
            result.exit_code,
            result.timed_out,
            stderr.display()
        )));
    }
    Ok(())
}

fn archive_list(staging: &Staging<'_>, path: &Path) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    // Metadata is a root member named .PKGINFO, not an accidental ./ prefix.
    for name in [".PKGINFO", ".BUILDINFO", ".MTREE"] {
        if staging.files.contains_key(Path::new(name)) {
            file.write_all(name.as_bytes())?;
            file.write_all(&[0])?;
        }
    }
    let paths = staging
        .directories
        .iter()
        .chain(staging.files.keys())
        .collect::<BTreeSet<_>>();
    for path in paths {
        if [".PKGINFO", ".BUILDINFO", ".MTREE"]
            .iter()
            .any(|name| path == Path::new(name))
        {
            continue;
        }
        file.write_all(path_text(path)?.as_bytes())?;
        file.write_all(&[0])?;
    }
    Ok(())
}

fn archive_command(tool: &Path, staging: &Staging<'_>, list: &Path, mtree: bool) -> Command {
    let mut command = Command::new(tool);
    command.current_dir(&staging.directory).args([
        "--uid",
        "0",
        "--gid",
        "0",
        "--uname",
        "root",
        "--gname",
        "root",
        "--no-acls",
        "--no-xattrs",
        "--no-fflags",
        "--no-recursion",
        "--null",
    ]);
    if mtree {
        command.args(["--format=mtree", "--options=mtree:!all,mtree:type,mtree:uid,mtree:gid,mtree:mode,mtree:size,mtree:time,mtree:sha256,gzip:!timestamp", "-czf", "-"]);
    } else {
        command.args(["--format=pax", "-cf", "-"]);
    }
    command.arg("-T").arg(list);
    command
}

fn stage_recipe(staging: &mut Staging<'_>) -> io::Result<String> {
    let inputs = staging.inputs;
    let text = recipe_text(
        NAME,
        [
            &inputs.elf_hash,
            &inputs.manifest_hash,
            field(&inputs.manifest, "sha256_source_inputs_before")?,
            field(&inputs.manifest, "sha256_runtime_inputs_before")?,
        ],
    );
    let recipe = Recipe::parse(&text)?;
    for (&source, &expected) in recipe
        .array("source")?
        .iter()
        .zip(recipe.array("sha256sums")?)
    {
        if file_hash(&inputs.root, staging.sha, &inputs.build.join(source))? != expected {
            return Err(invalid(format!(
                "PKGBUILD source digest mismatch: {source}"
            )));
        }
    }
    staging.text(Path::new(RECIPE), &text)?;
    Ok(text)
}

fn package_buildinfo(
    staging: &mut Staging<'_>,
    recipe: &Recipe<'_>,
    installed: &BTreeSet<String>,
) -> io::Result<()> {
    let recipe_hash = &staging.files[Path::new(RECIPE)];
    let mut text = format!(
        "format = 2\npkgname = {}\npkgbase = {}\npkgver = {}\npkgarch = {}\npkgbuild_sha256sum = {recipe_hash}\npackager = {PACKAGER}\nbuilddate = {}\nbuilddir = {}\nstartdir = {}\nbuildtool = {}\nbuildtoolver = {}\n",
        recipe.scalar("pkgname")?,
        recipe.scalar("pkgbase")?,
        recipe.version()?,
        recipe.scalar("arch")?,
        staging.epoch,
        path_text(&staging.directory)?,
        path_text(&staging.start_directory)?,
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
    );
    for package in installed {
        text.push_str("installed = ");
        text.push_str(package);
        text.push('\n');
    }
    staging.text(Path::new(".BUILDINFO"), &text)
}

fn package_metadata(staging: &mut Staging<'_>, recipe: &Recipe<'_>) -> io::Result<()> {
    let mut size = 0_u64;
    for path in staging.files.keys() {
        size = size
            .checked_add(fs::metadata(staging.directory.join(path))?.len())
            .ok_or_else(|| invalid("package size overflow"))?;
    }
    let mut text = format!(
        "# Generated by Rust xtask; unsigned local experimental diagnostic.\npkgname = {}\npkgbase = {}\npkgver = {}\npkgdesc = {}\nurl = {}\nbuilddate = {}\npackager = {PACKAGER}\nsize = {size}\narch = {}\nxdata = pkgtype=pkg\nxdata = experimental=true\nxdata = kernel_sha256={}\n",
        recipe.scalar("pkgname")?,
        recipe.scalar("pkgbase")?,
        recipe.version()?,
        recipe.scalar("pkgdesc")?,
        recipe.scalar("url")?,
        staging.epoch,
        recipe.scalar("arch")?,
        staging.inputs.elf_hash,
    );
    for license in recipe.array("license")? {
        text.push_str("license = ");
        text.push_str(license);
        text.push('\n');
    }
    staging.text(Path::new(".PKGINFO"), &text)
}

fn create_archive(
    staging: &mut Staging<'_>,
    bsdtar: &Path,
    zstd: &Path,
    version: &str,
) -> io::Result<PathBuf> {
    let output = &staging.inputs.output;
    let mtree_list = output.join("mtree-members.nul");
    archive_list(staging, &mtree_list)?;
    for path in &staging.directories {
        File::open(staging.directory.join(path))?.set_times(
            FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(staging.epoch)),
        )?;
    }
    let mtree = staging.directory.join(".MTREE");
    run_archive_command(
        &mut archive_command(bsdtar, staging, &mtree_list, true),
        &mtree,
        &output.join("mtree.stderr.log"),
    )?;
    staging.remember(Path::new(".MTREE"), &mtree, None)?;
    let list = output.join("archive-members.nul");
    archive_list(staging, &list)?;
    let tar = output.join("payload.tar");
    run_archive_command(
        &mut archive_command(bsdtar, staging, &list, false),
        &tar,
        &output.join("bsdtar.stderr.log"),
    )?;
    let pending = output.join("package.partial");
    let mut compress = Command::new(zstd);
    compress
        .current_dir(output)
        .args(["--compress", "--stdout", "-T1", "-10", "--"])
        .arg(&tar);
    run_archive_command(&mut compress, &pending, &output.join("zstd.stderr.log"))?;
    let archive = output.join(format!("{NAME}-{version}-x86_64.pkg.tar.zst"));
    // Atomic no-clobber publication. A partial archive never gets a package name.
    fs::hard_link(&pending, &archive)?;
    fs::remove_file(&pending)?;
    fs::remove_file(&tar)?;
    Ok(archive)
}

fn package_provenance(
    inputs: &Inputs,
    mut provenance: Manifest,
    version: &str,
    evidence: &str,
) -> io::Result<Manifest> {
    for (key, value) in [
        ("schema", "1"),
        ("package", NAME),
        ("version", version),
        ("architecture", "x86_64"),
        ("profile", "freestanding"),
        ("kernel_sha256", inputs.elf_hash.as_str()),
        ("build_manifest_sha256", inputs.manifest_hash.as_str()),
        ("evidence_scope", evidence),
        ("physical_result", "not-run"),
        ("signature", "unsigned; no signing approval"),
        (
            "sbom",
            "file inventory only; no approved SPDX/CycloneDX SBOM asserted",
        ),
        ("host_mutation", "none; package creation only"),
        (
            "archive_policy",
            "Rust-owned explicit regular-file staging; bsdtar pax root ownership, no xattrs/ACLs; zstd -T1 -10; 300-second tool deadlines",
        ),
    ] {
        provenance.insert(key.to_owned(), value.to_owned());
    }
    provenance.insert(
        "build_output".to_owned(),
        path_text(&inputs.build)?.to_owned(),
    );
    Ok(provenance)
}

fn stage_inventory(staging: &mut Staging<'_>, provenance: &Manifest) -> io::Result<()> {
    staging.text(
        &Path::new(DOCUMENTS).join("provenance/package.tsv"),
        &manifest_text(provenance)?,
    )?;
    let mut checksums = String::new();
    for (path, hash) in &staging.files {
        checksums.push_str(hash);
        checksums.push_str("  ");
        checksums.push_str(path_text(path)?);
        checksums.push('\n');
    }
    staging.text(&Path::new(DOCUMENTS).join("SHA256SUMS"), &checksums)
}

fn write_receipt(
    inputs: &Inputs,
    sha: &Path,
    archive: &Path,
    mut provenance: Manifest,
) -> io::Result<()> {
    let archive_hash = file_hash(&inputs.root, sha, archive)?;
    provenance.insert("archive".to_owned(), path_text(archive)?.to_owned());
    provenance.insert("archive_sha256".to_owned(), archive_hash.clone());
    provenance.insert(
        "inspection".to_owned(),
        "pending independent bsdtar and pacman -Qip read-only inspection".to_owned(),
    );
    write_new(
        &inputs.output.join("package-manifest.tsv"),
        manifest_text(&provenance)?.as_bytes(),
    )?;
    let name = archive
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| invalid("archive name is not UTF-8"))?;
    write_new(
        &inputs.output.join("SHA256SUMS"),
        format!("{archive_hash}  {name}\n").as_bytes(),
    )?;
    println!("kernel-package: {}", archive.display());
    println!("SHA-256: {archive_hash}");
    println!(
        "Unsigned experimental diagnostic only; no installation, boot change or physical qualification."
    );
    Ok(())
}

/// Package an existing hash-bound default build; never build, install or boot.
///
/// # Errors
/// Rejects stale/incomplete provenance, self-test profiles, unsafe paths, reused
/// output directories, changed sources, missing notices and failed/timed-out tools.
/// Incomplete private output is retained for diagnosis and cannot be reused.
pub fn create(root: &Path, build_output: &Path, requested_output: &Path) -> io::Result<()> {
    let sha = resolve_program(Path::new("sha256sum"))?;
    let bsdtar = resolve_program(Path::new("bsdtar"))?;
    let zstd = resolve_program(Path::new("zstd"))?;
    let pacman = resolve_program(Path::new("pacman"))?;
    let output = prepare_output(root, requested_output)?;
    let inputs = Inputs::load(output, build_output, &sha)?;
    let mut provenance = Manifest::new();
    for (name, path) in [
        ("bsdtar", &bsdtar),
        ("zstd", &zstd),
        ("sha256sum", &sha),
        ("pacman", &pacman),
    ] {
        provenance.insert(format!("{name}_path"), path_text(path)?.to_owned());
        provenance.insert(
            format!("{name}_version"),
            tool_output(path, &["--version"], &inputs.root)?
                .lines()
                .collect::<Vec<_>>()
                .join("; "),
        );
        provenance.insert(
            format!("sha256_{name}"),
            file_hash(&inputs.root, &sha, path)?,
        );
    }
    let mut staging = Staging::new(&inputs, &sha)?;
    let environment_before = tool_output(&pacman, &["--query", "--info"], &inputs.root)?;
    let installed = installed_packages(&environment_before)?;
    staging.text(
        &Path::new(DOCUMENTS).join("provenance/package-environment-before.txt"),
        &environment_before,
    )?;
    let recipe_bytes = stage_recipe(&mut staging)?;
    let recipe = Recipe::parse(&recipe_bytes)?;
    stage_project(&mut staging)?;
    stage_build(&mut staging)?;
    stage_runtime(&mut staging)?;
    let evidence = stage_evidence(&mut staging)?;
    stage_documentation(&mut staging)?;
    staging.verify_sources()?;
    let environment_after = tool_output(&pacman, &["--query", "--info"], &inputs.root)?;
    if installed_packages(&environment_after)? != installed {
        return Err(invalid(
            "installed package environment changed during assembly",
        ));
    }
    staging.text(
        &Path::new(DOCUMENTS).join("provenance/package-environment-after.txt"),
        &environment_after,
    )?;
    package_buildinfo(&mut staging, &recipe, &installed)?;
    provenance.insert(
        "pkgbuild_sha256sum".to_owned(),
        staging.files[Path::new(RECIPE)].clone(),
    );
    provenance.insert(
        "buildinfo_sha256".to_owned(),
        staging.files[Path::new(".BUILDINFO")].clone(),
    );
    provenance.insert(
        "buildinfo_scope".to_owned(),
        "actual package assembly environment; original kernel compiler/runtime provenance is separate"
            .to_owned(),
    );
    let version = recipe.version()?;
    let provenance = package_provenance(&inputs, provenance, &version, evidence)?;
    stage_inventory(&mut staging, &provenance)?;
    package_metadata(&mut staging, &recipe)?;
    let archive = create_archive(&mut staging, &bsdtar, &zstd, &version)?;
    write_receipt(&inputs, &sha, &archive, provenance)
}

#[cfg(test)]
mod tests {
    use super::{
        COMPILER_COMMIT, DOCUMENTS, Inputs, Manifest, NAME, RECIPE, Recipe, Staging, archive_list,
        check_elf, clean_path, debug_case_catalog, digest, expected_project_files, file_hash,
        files_under, open_regular, package_buildinfo, package_metadata, parse_manifest,
        prepare_output, recipe_text, recorded_files, resolve_program, stage_case, validate_profile,
        validate_test_manifest, verify_external_input,
    };
    use std::fs;
    use std::os::unix::{fs::symlink, net::UnixListener};
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("linux-rs-pkg-{}-{nonce}", std::process::id()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn setpriv_runtime_input_is_a_declared_external_input() {
        let fixture = Fixture::new();
        let output =
            prepare_output(&fixture.0, Path::new("target/kernel-tooling/external")).unwrap();
        let sha = resolve_program(Path::new("sha256sum")).unwrap();
        let setpriv = fs::canonicalize("/usr/bin/setpriv").unwrap();
        let hash = file_hash(&fixture.0, &sha, &setpriv).unwrap();
        let mut manifest = Manifest::new();
        // Every other declared input points elsewhere, as in a real build manifest.
        for (key, hash_key) in [
            ("cargo_path", "sha256_cargo"),
            ("rustc_path", "sha256_rustc"),
            ("rust_lld_path", "sha256_rust_lld"),
            ("readelf_path", "sha256_readelf"),
            ("sha256sum_path", "sha256_sha256sum"),
            ("process_group_kill_path", "sha256_process_group_kill"),
            ("harness_executable_path", "sha256_harness_executable"),
            ("local_cargo_config", "local_cargo_config_sha256"),
            ("vendored_std_inputs", "vendored_std_inputs_sha256"),
            ("target_spec_path", "target_spec_sha256"),
        ] {
            manifest.insert(key.to_owned(), "/nonexistent/other".to_owned());
            manifest.insert(hash_key.to_owned(), "0".repeat(64));
        }
        manifest.insert("setpriv_path".to_owned(), setpriv.display().to_string());
        manifest.insert("sha256_setpriv".to_owned(), hash.clone());
        let inputs = Inputs {
            root: fixture.0.clone(),
            build: fixture.0.clone(),
            output: output.path,
            manifest,
            manifest_hash: "b".repeat(64),
            elf_hash: "a".repeat(64),
        };
        let staging = Staging::new(&inputs, &sha).unwrap();
        let sysroot = fixture.0.join("sysroot");
        verify_external_input(&staging, &setpriv, &hash, &sysroot).unwrap();
        assert!(verify_external_input(&staging, &setpriv, &"1".repeat(64), &sysroot).is_err());
    }

    #[test]
    fn buildinfo_binds_consumed_recipe_and_all_required_metadata() {
        let fixture = Fixture::new();
        let output =
            prepare_output(&fixture.0, Path::new("target/kernel-tooling/metadata")).unwrap();
        let inputs = Inputs {
            root: fixture.0.clone(),
            build: fixture.0.clone(),
            output: output.path,
            manifest: Manifest::new(),
            manifest_hash: "b".repeat(64),
            elf_hash: "a".repeat(64),
        };
        let sha = resolve_program(Path::new("sha256sum")).unwrap();
        let mut staging = Staging::new(&inputs, &sha).unwrap();
        let text = recipe_text(NAME, [&inputs.elf_hash; 4]);
        staging.text(Path::new(RECIPE), &text).unwrap();
        let recipe = Recipe::parse(&text).unwrap();
        let installed = ["real-example-1:2.3-4-x86_64".to_owned()].into();
        package_buildinfo(&mut staging, &recipe, &installed).unwrap();
        package_metadata(&mut staging, &recipe).unwrap();
        let buildinfo = fs::read_to_string(staging.directory.join(".BUILDINFO")).unwrap();
        let fields = buildinfo
            .lines()
            .map(|line| line.split_once(" = ").unwrap())
            .collect::<Vec<_>>();
        for key in [
            "format",
            "pkgname",
            "pkgbase",
            "pkgver",
            "pkgarch",
            "pkgbuild_sha256sum",
            "packager",
            "builddate",
            "builddir",
            "startdir",
            "buildtool",
            "buildtoolver",
        ] {
            assert_eq!(
                fields.iter().filter(|(name, _)| *name == key).count(),
                1,
                "{key}"
            );
        }
        let recipe_hash = file_hash(&inputs.root, &sha, &staging.directory.join(RECIPE)).unwrap();
        assert!(fields.contains(&("pkgbuild_sha256sum", recipe_hash.as_str())));
        assert!(fields.contains(&("format", "2")));
        assert!(fields.contains(&("buildtool", env!("CARGO_PKG_NAME"))));
        assert!(fields.contains(&("installed", "real-example-1:2.3-4-x86_64")));
        assert!(
            !fields
                .iter()
                .any(|(key, _)| matches!(*key, "buildenv" | "options"))
        );
        let invocation_directory = std::env::current_dir().unwrap();
        assert_ne!(invocation_directory, inputs.root);
        assert!(fields.contains(&("startdir", invocation_directory.to_str().unwrap())));
        assert!(fields.contains(&("builddir", staging.directory.to_str().unwrap())));
        let list = inputs.output.join("members");
        archive_list(&staging, &list).unwrap();
        let members = fs::read(list).unwrap();
        for name in [".PKGINFO", ".BUILDINFO", RECIPE] {
            assert_eq!(
                members
                    .split(|byte| *byte == 0)
                    .filter(|member| *member == name.as_bytes())
                    .count(),
                1
            );
        }
    }

    #[test]
    fn current_case_catalog_is_validated_and_copied_without_an_eight_case_snapshot() {
        let count = debug_case_catalog().len();
        let mut manifest = parse_manifest(&format!(
            "key\tvalue\ncommand\tkernel-test\nautomated_case_count\t{count}\nautomated_cases_matched\t{count}\nautomated_cases_failed\t0\ndefault_feature_set\tfreestanding\n"
        ))
        .unwrap();
        validate_test_manifest(&manifest).unwrap();
        for key in ["automated_case_count", "automated_cases_matched"] {
            manifest.insert(key.to_owned(), (count - 1).to_string());
            assert!(validate_test_manifest(&manifest).is_err());
            manifest.insert(key.to_owned(), count.to_string());
        }
        manifest.insert("automated_cases_failed".to_owned(), "1".to_owned());
        assert!(validate_test_manifest(&manifest).is_err());

        let fixture = Fixture::new();
        let output =
            prepare_output(&fixture.0, Path::new("target/kernel-tooling/case-copy")).unwrap();
        let inputs = Inputs {
            root: fixture.0.clone(),
            build: fixture.0.clone(),
            output: output.path,
            manifest: Manifest::new(),
            manifest_hash: "b".repeat(64),
            elf_hash: "a".repeat(64),
        };
        let sha = resolve_program(Path::new("sha256sum")).unwrap();
        let mut staging = Staging::new(&inputs, &sha).unwrap();
        let run = fixture.0.join("run-fixture");
        // Explicit unit-test receipt/payload fixtures, not claims of QEMU
        // execution. Exercise the real consumer's validation, copying and hash
        // checks for every case from the same catalog used by the producer.
        for case @ (name, exit) in debug_case_catalog() {
            let directory = run.join("cases").join(name);
            fs::create_dir_all(&directory).unwrap();
            fs::write(
                directory.join("result.tsv"),
                format!(
                    "key\tvalue\ncase\t{name}\nstatus\tmatched\ntimed_out\tfalse\nsha256_kernel_elf\t{}\nsha256_kernel_elf_after_run\t{}\nexpected_exit\t{exit}\nobserved_exit\t{exit}\n",
                    inputs.elf_hash, inputs.elf_hash
                ),
            )
            .unwrap();
            for file in [
                "serial.log",
                "qemu.stdout.log",
                "qemu.stderr.log",
                "limine.conf",
            ] {
                fs::write(
                    directory.join(file),
                    format!("unit-test payload {name}/{file}\n"),
                )
                .unwrap();
            }
            stage_case(&mut staging, &run, case, &inputs.elf_hash).unwrap();
            let relative = Path::new(DOCUMENTS)
                .join("provenance/qemu/cases")
                .join(name);
            for file in [
                "result.tsv",
                "serial.log",
                "qemu.stdout.log",
                "qemu.stderr.log",
                "limine.conf",
            ] {
                assert_eq!(
                    fs::read(directory.join(file)).unwrap(),
                    fs::read(staging.directory.join(&relative).join(file)).unwrap()
                );
            }
        }
        staging.verify_sources().unwrap();
        assert_eq!(staging.files.len(), count * 5);
        drop(staging);
        let output =
            prepare_output(&fixture.0, Path::new("target/kernel-tooling/failed-case")).unwrap();
        let inputs = Inputs {
            output: output.path,
            ..inputs
        };
        let mut staging = Staging::new(&inputs, &sha).unwrap();
        let case = debug_case_catalog()
            .find(|(name, _)| *name == "irq-restore-early")
            .expect("the new real IRQ mutation is part of the execution catalog");
        let receipt = run.join("cases").join(case.0).join("result.tsv");
        let original = fs::read_to_string(&receipt).unwrap();
        fs::write(
            &receipt,
            original.replace("status\tmatched", "status\tfailed"),
        )
        .unwrap();
        assert_eq!(
            stage_case(&mut staging, &run, case, &inputs.elf_hash)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidData
        );
        fs::remove_file(receipt).unwrap();
        assert_eq!(
            stage_case(&mut staging, &run, case, &inputs.elf_hash)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::NotFound
        );
    }

    #[test]
    fn project_source_covers_every_workspace_member() {
        let fixture = Fixture::new();
        for file in [
            "Cargo.toml",
            "Cargo.lock",
            "LICENSE",
            "kernel/src/main.rs",
            "rt/src/lib.rs",
            "user/init/src/main.rs",
            "xtask/src/main.rs",
            "baremetal/src/main.rs",
            "vendor/crate-1.0.0/src/lib.rs",
        ] {
            let path = fixture.0.join(file);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"x").unwrap();
        }
        let files = expected_project_files(&fixture.0).unwrap();
        for member in ["rt/src/lib.rs", "user/init/src/main.rs"] {
            assert!(files.contains(Path::new(member)), "{member}");
        }
        assert!(files.contains(Path::new("vendor/crate-1.0.0/src/lib.rs")));
        assert_eq!(files.len(), 9);
        // An absent member tree is an error, not a silently smaller package.
        fs::remove_dir_all(fixture.0.join("rt")).unwrap();
        assert!(expected_project_files(&fixture.0).is_err());
    }

    #[test]
    fn rejects_traversal_and_ambiguous_package_paths() {
        for name in [
            "../escape",
            "target/../escape",
            "target/./escape",
            "target//escape",
            "target/escape/",
            "target/a\nb",
            "target/a\\b",
            "",
        ] {
            assert!(clean_path(Path::new(name), false).is_err(), "{name:?}");
        }
        assert!(clean_path(Path::new("target/kernel-tooling/pkg1"), false).is_ok());
        assert!(clean_path(Path::new("/tmp/project"), true).is_ok());
    }

    #[test]
    fn rejects_duplicate_or_malformed_manifest_fields() {
        assert!(parse_manifest("key\tvalue\nx\ta\nx\tb\n").is_err());
        assert!(parse_manifest("key\tvalue\nx\ta\tb\n").is_err());
        assert!(parse_manifest("wrong\n").is_err());
        assert!(digest(&"g".repeat(64)).is_err());
        assert!(digest(&"a".repeat(63)).is_err());
    }

    #[test]
    fn requires_source_hashes_and_unique_paths() {
        assert!(
            recorded_files(
                &parse_manifest("key\tvalue\nsource_0000_path\tkernel/Cargo.toml\n").unwrap()
            )
            .is_err()
        );
        let hash = "a".repeat(64);
        let duplicate = format!(
            "key\tvalue\nsource_0000_path\tkernel/Cargo.toml\nsource_0000_sha256\t{hash}\nsource_0001_path\tkernel/Cargo.toml\nsource_0001_sha256\t{hash}\n"
        );
        assert!(recorded_files(&parse_manifest(&duplicate).unwrap()).is_err());
    }

    #[test]
    fn refuses_self_test_profile_even_with_freestanding_enabled() {
        let text = format!(
            "key\tvalue\nschema\t1\nbuild_profile\tfreestanding\nfeature_set\tfreestanding\ntarget\tx86_64-unknown-none\nbinary\tlinux-rs-kernel\ncargo_exit_code\t0\nqualified_rustc_commit\t{COMPILER_COMMIT}\nrustc_version\tcommit-hash: {COMPILER_COMMIT}\ncargo_arguments\trustc | --features | freestanding\n"
        );
        let mut manifest = parse_manifest(&text).unwrap();
        assert!(validate_profile(&manifest).is_ok());
        manifest.insert(
            "feature_set".to_owned(),
            "qemu-self-test (includes freestanding)".to_owned(),
        );
        assert!(validate_profile(&manifest).is_err());
        manifest.insert("feature_set".to_owned(), "freestanding".to_owned());
        manifest.insert(
            "cargo_arguments".to_owned(),
            "rustc | --features | freestanding,qemu-self-test".to_owned(),
        );
        assert!(validate_profile(&manifest).is_err());
    }

    #[test]
    fn rejects_symlink_ancestors_and_special_inputs() {
        let fixture = Fixture::new();
        let input = fixture.0.join("input");
        fs::write(&input, b"source").unwrap();
        assert!(open_regular(&input).is_ok());
        symlink(&input, fixture.0.join("linked-file")).unwrap();
        symlink(&fixture.0, fixture.0.join("linked-directory")).unwrap();
        assert!(open_regular(&fixture.0.join("linked-file")).is_err());
        assert!(open_regular(&fixture.0.join("linked-directory/input")).is_err());
        assert!(files_under(&fixture.0).is_err());
        let socket = fixture.0.join("socket");
        let _listener = UnixListener::bind(&socket).unwrap();
        assert!(open_regular(&socket).is_err());
        assert!(open_regular(Path::new("/dev/null")).is_err());
    }

    #[test]
    fn validates_elf_entry_permissions_and_file_bounds() {
        let fixture = Fixture::new();
        let input = fixture.0.join("elf-parser-fixture");
        let mut bytes = [0_u8; 128];
        bytes[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
        bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
        bytes[24..32].copy_from_slice(&4096_u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
        bytes[68..72].copy_from_slice(&5_u32.to_le_bytes());
        bytes[72..80].copy_from_slice(&120_u64.to_le_bytes());
        bytes[80..88].copy_from_slice(&4096_u64.to_le_bytes());
        bytes[96..104].copy_from_slice(&1_u64.to_le_bytes());
        bytes[104..112].copy_from_slice(&1_u64.to_le_bytes());
        fs::write(&input, bytes).unwrap();
        assert!(check_elf(&input).is_ok());
        bytes[68..72].copy_from_slice(&7_u32.to_le_bytes());
        fs::write(&input, bytes).unwrap();
        assert!(check_elf(&input).is_err());
        bytes[68..72].copy_from_slice(&5_u32.to_le_bytes());
        bytes[72..80].copy_from_slice(&128_u64.to_le_bytes());
        fs::write(&input, bytes).unwrap();
        assert!(check_elf(&input).is_err());
        bytes[72..80].copy_from_slice(&120_u64.to_le_bytes());
        bytes[24..32].copy_from_slice(&4097_u64.to_le_bytes());
        fs::write(&input, bytes).unwrap();
        assert!(check_elf(&input).is_err());
    }
}
