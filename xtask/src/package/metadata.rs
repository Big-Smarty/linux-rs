// SPDX-License-Identifier: GPL-2.0-only
//! Restricted package inputs and actual ALPM environment records; never shell.

use std::collections::{BTreeMap, BTreeSet};
use std::io;

use super::{digest, invalid};

const SCALARS: [&str; 6] = ["pkgname", "pkgbase", "pkgver", "pkgrel", "pkgdesc", "url"];
const ARRAYS: [&str; 4] = ["arch", "license", "source", "sha256sums"];

pub(super) struct Recipe<'a> {
    fields: BTreeMap<&'a str, Vec<&'a str>>,
}

fn quoted_values(mut text: &str) -> io::Result<Vec<&str>> {
    let mut values = Vec::new();
    while !text.is_empty() {
        let (value, rest) = text
            .strip_prefix('\'')
            .and_then(|value| value.split_once('\''))
            .ok_or_else(|| invalid("PKGBUILD values must be constant single-quoted strings"))?;
        if value
            .bytes()
            .any(|byte| !(0x20..=0x7e).contains(&byte) || b"$`\\".contains(&byte))
        {
            return Err(invalid(
                "PKGBUILD expansion, escape or control is forbidden",
            ));
        }
        values.push(value);
        if !rest.is_empty() && !rest.starts_with(' ') {
            return Err(invalid("PKGBUILD values need a space separator"));
        }
        text = rest.trim_matches(' ');
    }
    Ok(values)
}

impl<'a> Recipe<'a> {
    pub(super) fn parse(text: &'a str) -> io::Result<Self> {
        let mut fields = BTreeMap::new();
        for line in text.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| invalid("PKGBUILD permits only constant assignments"))?;
            let values = if ARRAYS.contains(&key) {
                let body = value
                    .strip_prefix('(')
                    .and_then(|value| value.strip_suffix(')'))
                    .ok_or_else(|| invalid("PKGBUILD array needs parentheses"))?;
                quoted_values(body)?
            } else if SCALARS.contains(&key) {
                let values = quoted_values(value)?;
                if values.len() != 1 {
                    return Err(invalid("PKGBUILD scalar needs exactly one value"));
                }
                values
            } else {
                return Err(invalid(format!("unsupported PKGBUILD assignment: {key}")));
            };
            if fields.insert(key, values).is_some() {
                return Err(invalid(format!("duplicate PKGBUILD assignment: {key}")));
            }
        }
        if fields.len() != SCALARS.len() + ARRAYS.len() {
            return Err(invalid("PKGBUILD is missing required assignments"));
        }
        let recipe = Self { fields };
        if recipe.array("arch")?.len() != 1 || recipe.array("license")?.is_empty() {
            return Err(invalid(
                "diagnostic recipe needs one architecture and licenses",
            ));
        }
        let sources = recipe.array("source")?;
        let hashes = recipe.array("sha256sums")?;
        if sources.is_empty() || sources.len() != hashes.len() {
            return Err(invalid(
                "PKGBUILD sources and SHA-256 digests must pair exactly",
            ));
        }
        let mut seen = BTreeSet::new();
        for (&source, &hash) in sources.iter().zip(hashes) {
            if !matches!(
                source,
                "linux-rs-kernel.elf"
                    | "build-manifest.tsv"
                    | "source-inputs-before.tsv"
                    | "runtime-inputs-before.tsv"
            ) || !seen.insert(source)
            {
                return Err(invalid("unsupported or duplicate PKGBUILD source"));
            }
            digest(hash)?;
        }
        if seen.len() != 4 {
            return Err(invalid("PKGBUILD must bind all four original build inputs"));
        }
        Ok(recipe)
    }

    pub(super) fn scalar(&self, key: &str) -> io::Result<&'a str> {
        match self.array(key)? {
            [value] => Ok(value),
            _ => Err(invalid(format!("PKGBUILD {key} is not a scalar"))),
        }
    }

    pub(super) fn array(&self, key: &str) -> io::Result<&[&'a str]> {
        self.fields
            .get(key)
            .map(Vec::as_slice)
            .ok_or_else(|| invalid(format!("PKGBUILD lacks {key}")))
    }

    pub(super) fn version(&self) -> io::Result<String> {
        Ok(format!(
            "{}-{}",
            self.scalar("pkgver")?,
            self.scalar("pkgrel")?
        ))
    }
}

pub(super) fn recipe_text(name: &str, hashes: [&str; 4]) -> String {
    format!(
        "# Rust xtask input, not an executable makepkg/AUR recipe.\npkgname='{name}'\npkgbase='{name}'\npkgver='0.1.0.elf{}'\npkgrel='1'\npkgdesc='Experimental storage-free Limine bootstrap diagnostic, not a Linux replacement'\nurl=''\narch=('x86_64')\nlicense=('GPL-2.0-only' '0BSD' 'MIT' 'Apache-2.0 WITH LLVM-exception' 'Unicode-3.0')\nsource=('linux-rs-kernel.elf' 'build-manifest.tsv' 'source-inputs-before.tsv' 'runtime-inputs-before.tsv')\nsha256sums=('{}' '{}' '{}' '{}')\n",
        hashes[0], hashes[0], hashes[1], hashes[2], hashes[3]
    )
}

/// Parse the C-locale output of read-only `pacman --query --info`.
/// No package-manager state is changed, and missing/duplicate identities fail.
pub(super) fn installed_packages(text: &str) -> io::Result<BTreeSet<String>> {
    let mut result = BTreeSet::new();
    let mut names = BTreeSet::new();
    for block in text.split("\n\n").filter(|block| !block.trim().is_empty()) {
        let mut fields = BTreeMap::new();
        for line in block.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let key = key.trim_end();
            if matches!(key, "Name" | "Version" | "Architecture")
                && fields.insert(key, value.trim()).is_some()
            {
                return Err(invalid("duplicate installed package identity field"));
            }
        }
        let get = |key| {
            fields
                .get(key)
                .copied()
                .ok_or_else(|| invalid("incomplete installed package identity"))
        };
        let name = get("Name")?;
        let version = get("Version")?;
        let arch = get("Architecture")?;
        if name.is_empty()
            || name.starts_with(['.', '-'])
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"@._+-".contains(&b))
            || !version.contains('-')
            || !version
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b":._+~-".contains(&b))
            || arch.is_empty()
            || !arch.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || !names.insert(name)
        {
            return Err(invalid("invalid or duplicate installed package identity"));
        }
        result.insert(format!("{name}-{version}-{arch}"));
    }
    if result.is_empty() {
        return Err(invalid(
            "package environment query returned no installed packages",
        ));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::{Recipe, installed_packages, recipe_text};

    #[test]
    fn consumes_constant_recipe_metadata_and_source_pairs() {
        let hash = "a".repeat(64);
        let text = recipe_text("linux-rs-bootstrap-diagnostic", [&hash; 4]);
        let recipe = Recipe::parse(&text).unwrap();
        assert_eq!(recipe.version().unwrap(), format!("0.1.0.elf{hash}-1"));
        assert_eq!(
            recipe.scalar("pkgname").unwrap(),
            "linux-rs-bootstrap-diagnostic"
        );
        assert_eq!(recipe.array("source").unwrap().len(), 4);
        assert_eq!(recipe.array("sha256sums").unwrap(), [&hash; 4]);
        assert_eq!(
            recipe.array("license").unwrap()[3],
            "Apache-2.0 WITH LLVM-exception"
        );
    }

    #[test]
    fn rejects_executable_ambiguous_or_unbound_recipes() {
        let hash = "a".repeat(64);
        let text = recipe_text("linux-rs-bootstrap-diagnostic", [&hash; 4]);
        for addition in [
            "package() { true; }",
            "pkgrel='2'",
            "unknown='value'",
            "pkgver=$(id)",
            "pkgver=`id`",
        ] {
            assert!(Recipe::parse(&format!("{text}{addition}\n")).is_err());
        }
        for replacement in [
            "'$(id)'", "'`id`'", "'a\\b'", "'1'; id", "\"1\"", "'1''2'", "('1')",
        ] {
            assert!(
                Recipe::parse(&text.replace("pkgrel='1'", &format!("pkgrel={replacement}")))
                    .is_err()
            );
        }
        assert!(Recipe::parse(&text.replace("pkgrel='1'\n", "")).is_err());
        assert!(
            Recipe::parse(&text.replace("'build-manifest.tsv'", "'linux-rs-kernel.elf'")).is_err()
        );
        assert!(Recipe::parse(&text.replace("'build-manifest.tsv'", "'../escape'")).is_err());
        assert!(Recipe::parse(&text.replace(&format!("'{hash}'"), "'SKIP'")).is_err());
    }

    #[test]
    fn installed_inventory_uses_actual_versions_and_architectures() {
        let text = "Name            : package-one\nVersion         : 1:2.3-4\nArchitecture    : x86_64\nDescription     : ignored description\n\nName            : package-two\nVersion         : 5.6-7\nArchitecture    : any\n\n";
        let installed = installed_packages(text).unwrap();
        assert_eq!(
            installed.into_iter().collect::<Vec<_>>(),
            ["package-one-1:2.3-4-x86_64", "package-two-5.6-7-any"]
        );
        for invalid in [
            String::new(),
            text.replace("Architecture    : any\n", ""),
            format!("{text}{text}"),
            text.replace("x86_64", "x86_64\ninstalled = injected"),
        ] {
            // Unknown ordinary pacman fields are ignored, but never parsed as
            // additional BUILDINFO assignments. The injected newline cannot
            // alter the architecture field's already delimited value.
            if invalid.contains("installed = injected") {
                assert_eq!(installed_packages(&invalid).unwrap().len(), 2);
            } else {
                assert!(installed_packages(&invalid).is_err());
            }
        }
    }
}
