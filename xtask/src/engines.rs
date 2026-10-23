// SPDX-License-Identifier: GPL-3.0-or-later

//! The Go engines (design §4): the pins of `engines.lock.toml`, read as a
//! typed lock, and the commands of the hosted engine build (D-7: Go builds
//! never run on the exit Mac).
//!
//! - `engines-pins` prints the pins as `KEY=value` lines for the workflow,
//!   which downloads the pinned Go and checks out the pinned sources;
//! - `engines-prepare <dir>` puts each engine's `go.mod` and `go.sum` patch
//!   (Xray's REALITY replace, and either engine's reviewed security bumps)
//!   into its tree: a pinned patch is checked and applied, an unpinned one
//!   is made from the lock and written out for review and pinning;
//! - `engines-build <dir>` builds every engine from the sources checked
//!   out in `<dir>` (`xray/`, `sing-box/`, `Xray-linux-64.zip`) into
//!   `<dir>/out`, after checking the Go version, the commits and the
//!   pinned patches;
//! - `engines-govulncheck <dir>` runs govulncheck on every output's
//!   package with its own tags and target, and reports every scan that
//!   finds a reachable vulnerability;
//! - `engines-verify <dir>` checks `<dir>/out` against the output digests
//!   the lock records, and prints them while none are recorded;
//! - `engines-metadata <dir>` checks each binary against its recipe: its
//!   build information (`go version -m`), its empty build ID and, for the
//!   binaries built for this computer, the version stamp it prints.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use mooring_model::Sha256Digest;
use serde::Deserialize;

/// The lock, relative to the workspace root.
const LOCK: &str = "engines.lock.toml";

/// The codename in Xray's version statement (`core/core.go` at the pinned
/// commit).
const XRAY_CODENAME: &str = "Xray, Penetrates Everything.";

/// Where a build's outputs go inside its directory.
const OUT: &str = "out";

/// Xray's main package, inside its source directory.
const XRAY_PACKAGE: &str = "./main";

/// sing-box's main package, inside its source directory.
const SING_BOX_PACKAGE: &str = "./cmd/sing-box";

#[derive(Debug, thiserror::Error)]
pub(crate) enum EnginesError {
    #[error("could not read {}", .path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("could not write {}", .path.display())]
    Write {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{} is not a valid engine lock: {message}", .path.display())]
    Lock { path: PathBuf, message: String },
    #[error("could not start `{command}`")]
    Spawn {
        command: String,
        #[source]
        source: io::Error,
    },
    #[error("`{command}` failed:\n{stderr}")]
    Failed { command: String, stderr: String },
    #[error("go is {found}, the lock pins {pinned}")]
    GoVersion { found: String, pinned: String },
    #[error("{} is at {found}, the lock pins {pinned}", .source_dir.display())]
    Commit {
        source_dir: PathBuf,
        found: String,
        pinned: String,
    },
    #[error(
        "the {source_name} patch is not pinned yet: run `cargo xtask engines-prepare` on the hosted runner, review its patch, commit it and pin its sha256"
    )]
    PatchNotPinned { source_name: &'static str },
    #[error(
        "govulncheck did not pass for {}; bump each reachable module to its latest stable version in the lock's security-bumps (design §4.4)",
        .scans.join(", ")
    )]
    Vulnerable { scans: Vec<String> },
    #[error("{} hashes to {actual}, the lock pins {pinned}", .path.display())]
    Digest {
        path: PathBuf,
        actual: Sha256Digest,
        pinned: Sha256Digest,
    },
    #[error("the lock records no output digests yet; pin the ones printed above")]
    OutputsNotPinned,
    #[error("{output} is in the lock but not in the build")]
    OutputMissing { output: String },
    #[error("{output} is not built as its recipe says: {problem}")]
    Metadata { output: String, problem: String },
    #[error(
        "no engine is built for this computer ({os}-{arch}); check the outputs on the hosted runner"
    )]
    NoNativeOutput {
        os: &'static str,
        arch: &'static str,
    },
}

/// A Go target, `<os>-<arch>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Target {
    LinuxAmd64,
    LinuxArm64,
    DarwinArm64,
}

impl Target {
    /// This computer's target, when it is one of the three.
    pub(crate) const fn host() -> Option<Self> {
        if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            Some(Self::LinuxAmd64)
        } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
            Some(Self::LinuxArm64)
        } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
            Some(Self::DarwinArm64)
        } else {
            None
        }
    }

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::LinuxAmd64 => "linux-amd64",
            Self::LinuxArm64 => "linux-arm64",
            Self::DarwinArm64 => "darwin-arm64",
        }
    }

    const fn goos(self) -> &'static str {
        match self {
            Self::LinuxAmd64 | Self::LinuxArm64 => "linux",
            Self::DarwinArm64 => "darwin",
        }
    }

    const fn goarch(self) -> &'static str {
        match self {
            Self::LinuxAmd64 => "amd64",
            Self::LinuxArm64 | Self::DarwinArm64 => "arm64",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct Lock {
    pub(crate) schema: u32,
    pub(crate) go: Go,
    pub(crate) govulncheck: Govulncheck,
    pub(crate) xray: Xray,
    pub(crate) sing_box: SingBox,
    pub(crate) geodata: Geodata,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct Go {
    pub(crate) version: String,
    pub(crate) darwin_arm64_sha256: String,
    pub(crate) linux_amd64_sha256: String,
    pub(crate) env: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct Govulncheck {
    pub(crate) module: String,
    pub(crate) version: String,
    pub(crate) sum: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct Xray {
    pub(crate) module: String,
    pub(crate) tag: String,
    pub(crate) commit: String,
    pub(crate) prerelease: bool,
    pub(crate) upstream_reality: String,
    pub(crate) reality_replace: String,
    pub(crate) reality_replace_commit: String,
    pub(crate) ldflags: String,
    pub(crate) gcflags: String,
    pub(crate) targets: Vec<Target>,
    pub(crate) security_bumps: Vec<String>,
    pub(crate) patch: String,
    pub(crate) patch_sha256: String,
    pub(crate) outputs: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct SingBox {
    pub(crate) module: String,
    pub(crate) tag: String,
    pub(crate) commit: String,
    pub(crate) prerelease: bool,
    pub(crate) ldflags: String,
    pub(crate) common_tags: Vec<String>,
    pub(crate) roles: BTreeMap<String, Role>,
    pub(crate) security_bumps: Vec<String>,
    /// Empty, with its digest, while there are no security bumps.
    pub(crate) patch: String,
    pub(crate) patch_sha256: String,
    pub(crate) outputs: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct Role {
    pub(crate) targets: Vec<Target>,
    pub(crate) tags: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct Geodata {
    pub(crate) source: String,
    pub(crate) zip_url: String,
    pub(crate) zip_sha256: String,
    pub(crate) files: Vec<String>,
    pub(crate) outputs: BTreeMap<String, String>,
}

/// A recorded digest: 64 lowercase hex characters, or empty while none is
/// recorded.
fn pinned(text: &str) -> Result<Option<Sha256Digest>, String> {
    if text.is_empty() {
        return Ok(None);
    }
    Sha256Digest::parse(text)
        .map(Some)
        .map_err(|_| format!("{text:?} is not a sha256"))
}

impl Lock {
    /// Reads and checks the lock at `path`: schema 1, every digest well
    /// formed, every output named for a target the lock builds.
    pub(crate) fn read(path: &Path) -> Result<Self, EnginesError> {
        let text = fs::read_to_string(path).map_err(|source| EnginesError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse(&text).map_err(|message| EnginesError::Lock {
            path: path.to_path_buf(),
            message,
        })
    }

    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        let lock: Self = toml::from_str(text).map_err(|error| error.to_string())?;
        if lock.schema != 1 {
            return Err(format!("schema {} is not 1", lock.schema));
        }
        for digest in [
            &lock.go.darwin_arm64_sha256,
            &lock.go.linux_amd64_sha256,
            &lock.xray.patch_sha256,
            &lock.sing_box.patch_sha256,
            &lock.geodata.zip_sha256,
        ] {
            pinned(digest)?;
        }
        lock.check_recipes()?;
        let expected: Vec<String> = lock
            .builds()
            .into_iter()
            .map(|build| build.output)
            .collect();
        for (output, digest) in lock.recorded_outputs() {
            pinned(digest)?;
            if !expected.contains(&output)
                && !lock
                    .geodata
                    .files
                    .iter()
                    .any(|file| output == format!("geodata/{file}"))
            {
                return Err(format!("output {output} is not one the lock builds"));
            }
        }
        Ok(lock)
    }

    /// The recipes agree with the pins they restate: each engine's version
    /// is stamped from its own module and tag, the REALITY replace is the
    /// pinned commit, govulncheck's sum is a module sum, and the geodata
    /// come from the pinned Xray release.
    fn check_recipes(&self) -> Result<(), String> {
        let xray = &self.xray;
        let stamped = format!("-X {}/core.build={} -s -w -buildid=", xray.module, xray.tag);
        if xray.ldflags != stamped {
            return Err(format!(
                "xray ldflags {:?} are not {stamped:?}",
                xray.ldflags
            ));
        }
        let short = xray.reality_replace_commit.get(..12).unwrap_or_default();
        if short.len() != 12 || !xray.reality_replace.ends_with(&format!("-{short}")) {
            return Err("reality-replace is not the version of reality-replace-commit".to_owned());
        }
        let module = |pin: &str| pin.split_once(' ').map(|(module, _)| module.to_owned());
        if module(&xray.reality_replace).is_none()
            || module(&xray.reality_replace) != module(&xray.upstream_reality)
        {
            return Err("reality-replace does not replace upstream-reality's module".to_owned());
        }
        let sing_box = &self.sing_box;
        let version = sing_box.tag.strip_prefix('v').unwrap_or(&sing_box.tag);
        if !sing_box.ldflags.starts_with(&format!(
            "-X '{}/constant.Version={version}'",
            sing_box.module
        )) {
            return Err("sing-box ldflags do not stamp its module's tag".to_owned());
        }
        if !self.govulncheck.sum.starts_with("h1:") {
            return Err("govulncheck sum is not a module sum".to_owned());
        }
        if !self.geodata.source.contains(&xray.tag) || !self.geodata.zip_url.contains(&xray.tag) {
            return Err("the geodata are not from the pinned Xray release".to_owned());
        }
        if xray.prerelease && !xray.tag.contains('.') {
            return Err("xray tag is not a release".to_owned());
        }
        if sing_box.prerelease {
            return Err("sing-box is pinned to a prerelease".to_owned());
        }
        for (engine, bumps) in [
            ("xray", &xray.security_bumps),
            ("sing-box", &sing_box.security_bumps),
        ] {
            let mut modules = Vec::new();
            for bump in bumps {
                let module = bump_module(bump).ok_or_else(|| {
                    format!(
                        "{engine} security bump {bump:?} is not `<module>@v<major>.<minor>.<patch>`"
                    )
                })?;
                if modules.contains(&module) {
                    return Err(format!("{engine} bumps {module} twice"));
                }
                modules.push(module);
            }
        }
        if xray.patch.is_empty() {
            return Err("xray has no patch for its REALITY replace".to_owned());
        }
        if sing_box.security_bumps.is_empty()
            != (sing_box.patch.is_empty() && sing_box.patch_sha256.is_empty())
        {
            return Err("sing-box has a patch exactly when it has security bumps".to_owned());
        }
        Ok(())
    }

    /// The engines that carry a `go.mod` and `go.sum` patch: Xray always,
    /// for its REALITY replace, and sing-box while it has security bumps.
    pub(crate) fn patches(&self) -> Vec<EnginePatch> {
        let mut patches = vec![EnginePatch {
            source: "xray",
            replace: self
                .xray
                .reality_replace
                .split_once(' ')
                .map(|(module, version)| format!("-replace={module}={module}@{version}")),
            bumps: self.xray.security_bumps.clone(),
            path: self.xray.patch.clone(),
            sha256: self.xray.patch_sha256.clone(),
        }];
        if !self.sing_box.security_bumps.is_empty() {
            patches.push(EnginePatch {
                source: "sing-box",
                replace: None,
                bumps: self.sing_box.security_bumps.clone(),
                path: self.sing_box.patch.clone(),
                sha256: self.sing_box.patch_sha256.clone(),
            });
        }
        patches
    }

    /// Every output the lock records, by its path in a build's `out`.
    fn recorded_outputs(&self) -> Vec<(String, &String)> {
        let mut outputs = Vec::new();
        for (target, digest) in &self.xray.outputs {
            outputs.push((format!("{target}/xray"), digest));
        }
        for (role_target, digest) in &self.sing_box.outputs {
            let (role, target) = role_target.split_once('/').unwrap_or((role_target, ""));
            outputs.push((format!("{target}/{role}"), digest));
        }
        for (file, digest) in &self.geodata.outputs {
            outputs.push((format!("geodata/{file}"), digest));
        }
        outputs
    }

    /// The pins the workflow needs, as `KEY=value` lines.
    pub(crate) fn pins(&self) -> Vec<(&'static str, String)> {
        vec![
            ("GO_VERSION", self.go.version.clone()),
            ("GO_LINUX_AMD64_SHA256", self.go.linux_amd64_sha256.clone()),
            ("XRAY_COMMIT", self.xray.commit.clone()),
            ("SING_BOX_COMMIT", self.sing_box.commit.clone()),
            ("XRAY_TAG", self.xray.tag.clone()),
            ("SING_BOX_TAG", self.sing_box.tag.clone()),
            ("GEODATA_URL", self.geodata.zip_url.clone()),
            ("GEODATA_SHA256", self.geodata.zip_sha256.clone()),
            (
                "GOVULNCHECK",
                format!(
                    "{}/cmd/govulncheck@{}",
                    self.govulncheck.module, self.govulncheck.version
                ),
            ),
        ]
    }

    /// Every engine build the lock describes, Xray's first.
    pub(crate) fn builds(&self) -> Vec<Build> {
        let mut builds: Vec<Build> = self
            .xray
            .targets
            .iter()
            .map(|&target| Build {
                source: "xray",
                target,
                output: format!("{}/xray", target.name()),
                package: XRAY_PACKAGE,
                tags: Vec::new(),
                gcflags: Some(self.xray.gcflags.clone()),
                version_line: format!(
                    "Xray {} ({XRAY_CODENAME}) {} ({} {}/{})",
                    self.xray.tag.trim_start_matches('v'),
                    self.xray.tag,
                    self.go.version,
                    target.goos(),
                    target.goarch(),
                ),
                args: vec![
                    "build".to_owned(),
                    "-trimpath".to_owned(),
                    "-buildvcs=false".to_owned(),
                    format!("-gcflags={}", self.xray.gcflags),
                    format!("-ldflags={}", self.xray.ldflags),
                    "-o".to_owned(),
                    String::new(),
                    XRAY_PACKAGE.to_owned(),
                ],
            })
            .collect();
        for (name, role) in &self.sing_box.roles {
            let mut tags = role.tags.clone();
            tags.extend(self.sing_box.common_tags.iter().cloned());
            for &target in &role.targets {
                builds.push(Build {
                    source: "sing-box",
                    target,
                    output: format!("{}/{name}", target.name()),
                    package: SING_BOX_PACKAGE,
                    tags: tags.clone(),
                    gcflags: None,
                    version_line: format!(
                        "sing-box version {}",
                        self.sing_box.tag.trim_start_matches('v')
                    ),
                    args: vec![
                        "build".to_owned(),
                        "-trimpath".to_owned(),
                        "-buildvcs=false".to_owned(),
                        format!("-tags={}", tags.join(",")),
                        format!("-ldflags={}", self.sing_box.ldflags),
                        "-o".to_owned(),
                        String::new(),
                        SING_BOX_PACKAGE.to_owned(),
                    ],
                });
            }
        }
        builds
    }

    /// The environment of a build for `target`: the lock's Go environment,
    /// `GOOS` and `GOARCH`.
    pub(crate) fn env(&self, target: Target) -> Vec<(String, String)> {
        let mut env: Vec<(String, String)> = self
            .go
            .env
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        env.push(("GOOS".to_owned(), target.goos().to_owned()));
        env.push(("GOARCH".to_owned(), target.goarch().to_owned()));
        env
    }
}

/// One `go build`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Build {
    /// The source directory inside the build directory.
    pub(crate) source: &'static str,
    pub(crate) target: Target,
    /// Its path inside `out`.
    pub(crate) output: String,
    /// The main package, inside the source directory.
    pub(crate) package: &'static str,
    /// The build tags, in recipe order.
    pub(crate) tags: Vec<String>,
    pub(crate) gcflags: Option<String>,
    /// The first line `<binary> version` prints: the recipe's `-X` stamp.
    pub(crate) version_line: String,
    /// `go` arguments; the empty one after `-o` is the output path.
    pub(crate) args: Vec<String>,
}

impl Build {
    /// The arguments with the output path in place.
    fn args_to(&self, output: &Path) -> Vec<String> {
        self.args
            .iter()
            .map(|arg| {
                if arg.is_empty() {
                    output.display().to_string()
                } else {
                    arg.clone()
                }
            })
            .collect()
    }

    /// Checks `go version -m`'s report on the built binary against the
    /// recipe: the pinned Go, `-trimpath`, `CGO_ENABLED=0`, the target, the
    /// gcflags and the exact tag set.
    ///
    /// The report cannot show the ldflags: under `-trimpath` cmd/go records
    /// none (go1.27.3 `src/cmd/go/internal/load/pkg.go:2469-2481`,
    /// go.dev/issue/52372). Their effects are checked instead, by
    /// [`check_build_id`] and [`Build::check_version`].
    pub(crate) fn check_metadata(&self, go_version: &str, report: &str) -> Result<(), String> {
        let mut lines = report.lines();
        let first = lines.next().ok_or("an empty report")?;
        if !first.trim_end().ends_with(&format!(": {go_version}")) {
            return Err(format!("built with another Go: {first}"));
        }
        let settings: BTreeMap<&str, String> = report
            .lines()
            .filter_map(|line| line.trim_start().strip_prefix("build\t"))
            .filter_map(|setting| setting.split_once('='))
            .map(|(key, value)| (key, unquote(value)))
            .collect();
        let want = |key: &str, value: &str| match settings.get(key) {
            Some(found) if found == value => Ok(()),
            found => Err(format!("{key} is {found:?}, the recipe has {value:?}")),
        };
        want("-trimpath", "true")?;
        want("CGO_ENABLED", "0")?;
        want("GOOS", self.target.goos())?;
        want("GOARCH", self.target.goarch())?;
        if settings.contains_key("-ldflags") {
            return Err(
                "-ldflags is recorded, which cmd/go does only without -trimpath; review this check against the pinned Go"
                    .to_owned(),
            );
        }
        match &self.gcflags {
            Some(gcflags) => want("-gcflags", gcflags)?,
            None if settings.contains_key("-gcflags") => {
                return Err("built with gcflags; the recipe has none".to_owned());
            }
            None => {}
        }
        if self.tags.is_empty() {
            if settings.contains_key("-tags") {
                return Err("built with tags; the recipe has none".to_owned());
            }
        } else {
            want("-tags", &self.tags.join(","))?;
        }
        Ok(())
    }

    /// Checks what the built binary printed for `version` against the
    /// recipe's `-X` stamp.
    pub(crate) fn check_version(&self, printed: &str) -> Result<(), String> {
        match printed.lines().next() {
            Some(line) if line == self.version_line => Ok(()),
            line => Err(format!(
                "`version` prints {line:?}, the recipe stamps {:?}",
                self.version_line
            )),
        }
    }
}

/// One engine's `go.mod` and `go.sum` patch (design §4.2, §4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EnginePatch {
    /// The source directory inside the build directory.
    pub(crate) source: &'static str,
    /// The `go mod edit` argument of Xray's REALITY replace.
    pub(crate) replace: Option<String>,
    /// The reviewed security bumps, `<module>@<version>` each.
    pub(crate) bumps: Vec<String>,
    /// The committed patch, relative to the workspace root.
    pub(crate) path: String,
    /// Its pinned digest; empty until it is reviewed and pinned.
    pub(crate) sha256: String,
}

/// The module of a security bump `<module>@v<major>.<minor>.<patch>`: a
/// released version, never a prerelease or a pseudo-version.
fn bump_module(bump: &str) -> Option<&str> {
    let (module, version) = bump.split_once('@')?;
    let numbers: Vec<&str> = version.strip_prefix('v')?.split('.').collect();
    let released = numbers.len() == 3
        && numbers
            .iter()
            .all(|number| !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit()));
    let path = module.contains('/')
        && module
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"./-_~".contains(&byte));
    (released && path).then_some(module)
}

/// Checks `go tool buildid`'s report on a built binary: the ID is empty, as
/// the recipe's `-buildid=` makes it. That flag is part of the single
/// `-ldflags` argument, so an empty ID shows the recipe's ldflags reached
/// the linker.
pub(crate) fn check_build_id(report: &str) -> Result<(), String> {
    if report == "\n" {
        Ok(())
    } else {
        Err(format!(
            "the build ID is {:?}; the recipe's -buildid= makes it empty",
            report.trim_end()
        ))
    }
}

/// A build setting as `go version -m` prints it: quoted Go-style when it
/// holds a space, a quote or a backslash (`debug/buildinfo`).
pub(crate) fn unquote(value: &str) -> String {
    let Some(inner) = value
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
    else {
        return value.to_owned();
    };
    let mut text = String::new();
    let mut chars = inner.chars();
    while let Some(character) = chars.next() {
        if character != '\\' {
            text.push(character);
            continue;
        }
        match chars.next() {
            Some('t') => text.push('\t'),
            Some('n') => text.push('\n'),
            Some(escaped) => text.push(escaped),
            None => text.push('\\'),
        }
    }
    text
}

fn run(command: &mut Command) -> Result<String, EnginesError> {
    let shown = format!("{command:?}");
    let output = command
        .stdin(Stdio::null())
        .output()
        .map_err(|source| EnginesError::Spawn {
            command: shown.clone(),
            source,
        })?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(EnginesError::Failed {
            command: shown,
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

fn digest_of(path: &Path) -> Result<Sha256Digest, EnginesError> {
    let bytes = fs::read(path).map_err(|source| EnginesError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(Sha256Digest::of(&bytes))
}

/// `engines-pins`.
pub(crate) fn pins(root: &Path, out: &mut impl Write) -> Result<(), EnginesError> {
    let lock = Lock::read(&root.join(LOCK))?;
    for (key, value) in lock.pins() {
        writeln!(out, "{key}={value}").map_err(|source| EnginesError::Write {
            path: PathBuf::from("<stdout>"),
            source,
        })?;
    }
    Ok(())
}

/// Checks that `dir/<source>` is the pinned commit.
fn check_commit(dir: &Path, source: &str, pinned: &str) -> Result<(), EnginesError> {
    let source_dir = dir.join(source);
    let found = run(Command::new("git")
        .arg("-C")
        .arg(&source_dir)
        .args(["rev-parse", "HEAD"]))?;
    let found = found.trim().to_owned();
    if found == pinned {
        Ok(())
    } else {
        Err(EnginesError::Commit {
            source_dir,
            found,
            pinned: pinned.to_owned(),
        })
    }
}

fn check_go(lock: &Lock) -> Result<(), EnginesError> {
    let found = run(Command::new("go").args(["env", "GOVERSION"]))?;
    let found = found.trim().to_owned();
    if found == lock.go.version {
        Ok(())
    } else {
        Err(EnginesError::GoVersion {
            found,
            pinned: lock.go.version.clone(),
        })
    }
}

/// `engines-prepare <dir>`: every engine's patch into its tree. A pinned
/// patch is checked against its pin and applied. An unpinned one is made
/// from the lock: from upstream's `go.mod` and `go.sum`, Xray's REALITY
/// replace, `go get` of each security bump, and a build of each of that
/// engine's outputs, so that `go.sum` holds every line the builds need. It
/// is written to `<dir>/<source>.patch` for review and left applied, so
/// that govulncheck scans what the build would build. The last line is
/// `prepared=true` when a patch was made, for the workflow.
pub(crate) fn prepare(root: &Path, dir: &Path, out: &mut impl Write) -> Result<(), EnginesError> {
    let dir = &absolute(dir)?;
    let lock = Lock::read(&root.join(LOCK))?;
    check_go(&lock)?;
    check_commit(dir, "xray", &lock.xray.commit)?;
    check_commit(dir, "sing-box", &lock.sing_box.commit)?;
    let mut prepared = false;
    for patch in lock.patches() {
        let tree = dir.join(patch.source);
        let unpinned = pinned(&patch.sha256)
            .map_err(|message| EnginesError::Lock {
                path: root.join(LOCK),
                message,
            })?
            .is_none();
        if !unpinned {
            apply_patch(root, &patch, &tree)?;
            continue;
        }
        run(Command::new("git")
            .arg("-C")
            .arg(&tree)
            .args(["checkout", "--", "go.mod", "go.sum"]))?;
        if let Some(replace) = &patch.replace {
            run(Command::new("go")
                .current_dir(&tree)
                .args(["mod", "edit", replace]))?;
        }
        if !patch.bumps.is_empty() {
            run(Command::new("go")
                .current_dir(&tree)
                .envs(lock.go.env.iter())
                .env("GOFLAGS", "-mod=mod")
                .arg("get")
                .args(&patch.bumps))?;
        }
        for build in lock.builds() {
            if build.source == patch.source {
                run(Command::new("go")
                    .current_dir(&tree)
                    .envs(lock.env(build.target))
                    .env("GOFLAGS", "-mod=mod -trimpath")
                    .args(build.args_to(Path::new("/dev/null"))))?;
            }
        }
        let diff = run(Command::new("git")
            .arg("-C")
            .arg(&tree)
            .args(["diff", "--", "go.mod", "go.sum"]))?;
        let path = dir.join(format!("{}.patch", patch.source));
        fs::write(&path, &diff).map_err(|source| EnginesError::Write {
            path: path.clone(),
            source,
        })?;
        writeln!(
            out,
            "{} sha256 {}",
            path.display(),
            Sha256Digest::of(diff.as_bytes())
        )
        .map_err(stdout_error)?;
        prepared = true;
    }
    writeln!(out, "prepared={prepared}").map_err(stdout_error)
}

/// Applies an engine's committed patch to `tree`, after checking it
/// against its pin, unless the tree has it already (a second build).
fn apply_patch(root: &Path, patch: &EnginePatch, tree: &Path) -> Result<(), EnginesError> {
    let Some(pin) = pinned(&patch.sha256).map_err(|message| EnginesError::Lock {
        path: root.join(LOCK),
        message,
    })?
    else {
        return Err(EnginesError::PatchNotPinned {
            source_name: patch.source,
        });
    };
    let path = root.join(&patch.path);
    let actual = digest_of(&path)?;
    if actual != pin {
        return Err(EnginesError::Digest {
            path,
            actual,
            pinned: pin,
        });
    }
    let applied = Command::new("git")
        .arg("-C")
        .arg(tree)
        .args(["apply", "--reverse", "--check"])
        .arg(&path)
        .stderr(Stdio::null())
        .status()
        .map_err(|source| EnginesError::Spawn {
            command: "git apply --reverse --check".to_owned(),
            source,
        })?
        .success();
    if !applied {
        run(Command::new("git")
            .arg("-C")
            .arg(tree)
            .arg("apply")
            .arg(&path))?;
    }
    Ok(())
}

fn stdout_error(source: io::Error) -> EnginesError {
    EnginesError::Write {
        path: PathBuf::from("<stdout>"),
        source,
    }
}

/// `dir` made absolute: each `go build` runs in its source directory, and
/// a relative output path would land inside it.
fn absolute(dir: &Path) -> Result<PathBuf, EnginesError> {
    std::path::absolute(dir).map_err(|source| EnginesError::Read {
        path: dir.to_path_buf(),
        source,
    })
}

/// `engines-build <dir>`.
pub(crate) fn build(root: &Path, dir: &Path, out: &mut impl Write) -> Result<(), EnginesError> {
    let dir = &absolute(dir)?;
    let lock = Lock::read(&root.join(LOCK))?;
    check_go(&lock)?;
    check_commit(dir, "xray", &lock.xray.commit)?;
    check_commit(dir, "sing-box", &lock.sing_box.commit)?;
    for patch in lock.patches() {
        apply_patch(root, &patch, &dir.join(patch.source))?;
    }
    let out_dir = dir.join(OUT);
    let zip = dir.join("Xray-linux-64.zip");
    let zip_pin = pinned(&lock.geodata.zip_sha256)
        .map_err(|message| EnginesError::Lock {
            path: root.join(LOCK),
            message,
        })?
        .ok_or(EnginesError::Lock {
            path: root.join(LOCK),
            message: "geodata zip-sha256 is empty".to_owned(),
        })?;
    let zip_actual = digest_of(&zip)?;
    if zip_actual != zip_pin {
        return Err(EnginesError::Digest {
            path: zip,
            actual: zip_actual,
            pinned: zip_pin,
        });
    }
    let geodata = out_dir.join("geodata");
    fs::create_dir_all(&geodata).map_err(|source| EnginesError::Write {
        path: geodata.clone(),
        source,
    })?;
    run(Command::new("unzip")
        .arg("-o")
        .arg(&zip)
        .args(&lock.geodata.files)
        .arg("-d")
        .arg(&geodata))?;
    for build in lock.builds() {
        let output = out_dir.join(&build.output);
        let parent = output.parent().unwrap_or(&out_dir).to_path_buf();
        fs::create_dir_all(&parent).map_err(|source| EnginesError::Write {
            path: parent,
            source,
        })?;
        run(Command::new("go")
            .current_dir(dir.join(build.source))
            .envs(lock.env(build.target))
            .args(build.args_to(&output)))?;
    }
    let manifest = manifest(&lock, &out_dir)?;
    let path = out_dir.join("MANIFEST.json");
    let text = serde_json::to_string_pretty(
        &manifest
            .iter()
            .map(|(output, digest)| (output.clone(), digest.to_string()))
            .collect::<BTreeMap<_, _>>(),
    )
    .map_err(|error| EnginesError::Write {
        path: path.clone(),
        source: io::Error::other(error),
    })?;
    fs::write(&path, text + "\n").map_err(|source| EnginesError::Write {
        path: path.clone(),
        source,
    })?;
    for (output, digest) in &manifest {
        writeln!(out, "{digest}  {output}").map_err(|source| EnginesError::Write {
            path: PathBuf::from("<stdout>"),
            source,
        })?;
    }
    Ok(())
}

/// Every output of a build in `out_dir`, with its digest.
fn manifest(lock: &Lock, out_dir: &Path) -> Result<BTreeMap<String, Sha256Digest>, EnginesError> {
    let mut manifest = BTreeMap::new();
    for build in lock.builds() {
        manifest.insert(
            build.output.clone(),
            digest_of(&out_dir.join(&build.output))?,
        );
    }
    for file in &lock.geodata.files {
        let output = format!("geodata/{file}");
        manifest.insert(output.clone(), digest_of(&out_dir.join(&output))?);
    }
    Ok(manifest)
}

/// The lock's output tables as they should read for `manifest`.
pub(crate) fn outputs_toml(manifest: &BTreeMap<String, Sha256Digest>) -> String {
    let mut xray = String::from("[xray.outputs]\n");
    let mut sing_box = String::from("[sing-box.outputs]\n");
    let mut geodata = String::from("[geodata.outputs]\n");
    for (output, digest) in manifest {
        let Some((first, second)) = output.split_once('/') else {
            continue;
        };
        match (first, second) {
            ("geodata", file) => geodata.push_str(&format!("\"{file}\" = \"{digest}\"\n")),
            (target, "xray") => xray.push_str(&format!("\"{target}\" = \"{digest}\"\n")),
            (target, role) => sing_box.push_str(&format!("\"{role}/{target}\" = \"{digest}\"\n")),
        }
    }
    format!("{xray}\n{sing_box}\n{geodata}")
}

/// Compares a build's manifest with the outputs the lock records.
pub(crate) fn compare(
    lock: &Lock,
    manifest: &BTreeMap<String, Sha256Digest>,
) -> Result<(), EnginesError> {
    let recorded = lock.recorded_outputs();
    if recorded.is_empty() {
        return Err(EnginesError::OutputsNotPinned);
    }
    for (output, digest) in recorded {
        let pinned = pinned(digest)
            .map_err(|message| EnginesError::Lock {
                path: PathBuf::from(LOCK),
                message,
            })?
            .ok_or_else(|| EnginesError::OutputMissing {
                output: output.clone(),
            })?;
        let actual = manifest
            .get(&output)
            .copied()
            .ok_or_else(|| EnginesError::OutputMissing {
                output: output.clone(),
            })?;
        if actual != pinned {
            return Err(EnginesError::Digest {
                path: PathBuf::from(output),
                actual,
                pinned,
            });
        }
    }
    if lock.recorded_outputs().len() != manifest.len() {
        return Err(EnginesError::OutputsNotPinned);
    }
    Ok(())
}

/// `engines-verify <dir>`.
pub(crate) fn verify(root: &Path, dir: &Path, out: &mut impl Write) -> Result<(), EnginesError> {
    let lock = Lock::read(&root.join(LOCK))?;
    let manifest = manifest(&lock, &dir.join(OUT))?;
    let result = compare(&lock, &manifest);
    if matches!(result, Err(EnginesError::OutputsNotPinned)) {
        write!(out, "{}", outputs_toml(&manifest)).map_err(|source| EnginesError::Write {
            path: PathBuf::from("<stdout>"),
            source,
        })?;
    } else if result.is_ok() {
        writeln!(out, "every engine output matches {LOCK}").map_err(|source| {
            EnginesError::Write {
                path: PathBuf::from("<stdout>"),
                source,
            }
        })?;
    }
    result
}

/// `engines-govulncheck <dir>`: govulncheck on every output's main package,
/// with that output's tags and target, from the patched trees in `<dir>`
/// (design §4.1). Every scan runs, and its report is printed as it comes;
/// the error lists each scan that did not pass: exit status 3 is a
/// reachable vulnerability, any other failure is govulncheck's own.
pub(crate) fn govulncheck(
    root: &Path,
    dir: &Path,
    out: &mut impl Write,
) -> Result<(), EnginesError> {
    let dir = &absolute(dir)?;
    let lock = Lock::read(&root.join(LOCK))?;
    let mut failed = Vec::new();
    for build in lock.builds() {
        writeln!(
            out,
            "== govulncheck {} ({} for {}, tags [{}])",
            build.output,
            build.package,
            build.target.name(),
            build.tags.join(",")
        )
        .map_err(stdout_error)?;
        out.flush().map_err(stdout_error)?;
        let mut command = Command::new("govulncheck");
        command
            .current_dir(dir.join(build.source))
            .envs(lock.env(build.target))
            .stdin(Stdio::null());
        if !build.tags.is_empty() {
            command.arg(format!("-tags={}", build.tags.join(",")));
        }
        let status = command
            .arg(build.package)
            .status()
            .map_err(|source| EnginesError::Spawn {
                command: format!("govulncheck {}", build.package),
                source,
            })?;
        match status.code() {
            Some(0) => {}
            Some(3) => failed.push(format!("{} (reachable vulnerabilities)", build.output)),
            code => failed.push(format!("{} (govulncheck failed: {code:?})", build.output)),
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(EnginesError::Vulnerable { scans: failed })
    }
}

/// `engines-metadata <dir>`: every binary's build information and build
/// ID, and the version stamps of the binaries built for this computer.
pub(crate) fn metadata(root: &Path, dir: &Path, out: &mut impl Write) -> Result<(), EnginesError> {
    let lock = Lock::read(&root.join(LOCK))?;
    let builds = lock.builds();
    let host = Target::host();
    if !builds.iter().any(|build| Some(build.target) == host) {
        return Err(EnginesError::NoNativeOutput {
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
        });
    }
    for build in builds {
        let binary = dir.join(OUT).join(&build.output);
        let not_as_recipe = |problem| EnginesError::Metadata {
            output: build.output.clone(),
            problem,
        };
        let report = run(Command::new("go").args([
            OsStr::new("version"),
            OsStr::new("-m"),
            binary.as_os_str(),
        ]))?;
        build
            .check_metadata(&lock.go.version, &report)
            .map_err(not_as_recipe)?;
        let build_id = run(Command::new("go").args([
            OsStr::new("tool"),
            OsStr::new("buildid"),
            binary.as_os_str(),
        ]))?;
        check_build_id(&build_id).map_err(not_as_recipe)?;
        let stamp = if Some(build.target) == host {
            let printed = run(Command::new(&binary).arg("version"))?;
            build.check_version(&printed).map_err(not_as_recipe)?;
            format!("prints {:?}", build.version_line)
        } else {
            "built for another computer, so its version stamp is not run here".to_owned()
        };
        writeln!(out, "{}: built as its recipe says; {stamp}", build.output)
            .map_err(stdout_error)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
