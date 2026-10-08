// SPDX-License-Identifier: GPL-3.0-or-later

//! `contract/cfm-manifest.toml`: the CFM revision of each client line that
//! the export contract is checked against (design §9.3 items 1, 2 and 4).
//!
//! The format is ours, so every table denies unknown keys. Parsing also
//! checks what the file states about itself: each line's `importer_digest`
//! is the digest of its `importer` objects (the formula in the file's
//! header), and no CFM patch is listed twice, by path or by content, since
//! a patch cannot be applied twice. [`CfmManifest::require_lines`] checks
//! the file against the emitter: it must describe exactly the client lines
//! `mooring_export::shapes()` enumerates.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use mooring_model::digest::Sha256Digest;
use serde::Deserialize;

use super::object_id::GitObjectId;
use crate::version::{ReleaseLine, Version};

/// The manifest version this reader understands.
const MANIFEST_VERSION: u32 = 1;

/// The paths of the importer objects, in the order the importer digest
/// hashes them.
const IMPORTER_PATHS: [&str; 3] = [
    "apps/cfw-tauri-shell/src/subscription_import",
    "apps/cfw-tauri-shell/src/subscription_import.rs",
    "crates/cfw-singbox-config",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestToml {
    manifest_version: u32,
    cfm: BTreeMap<String, CfmRevision>,
}

/// The CFM revision of one client line (`[cfm.<client line>]`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CfmRevision {
    /// The CFM release line, such as `0.4`.
    line: ReleaseLine,
    revision: GitObjectId,
    /// The sing-box release CFM builds its core from.
    sing_box_tag: SingBoxTag,
    sing_box_commit: GitObjectId,
    importer_digest: Sha256Digest,
    importer: ImporterObjects,
    /// The CFM sing-box patches, in the order CFM applies them.
    patch: Vec<Patch>,
}

/// A sing-box release tag: `v` followed by a plain release version, such
/// as `v1.14.1`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
struct SingBoxTag(Version);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0:?} is not a sing-box release tag such as `v1.14.1`")]
struct SingBoxTagError(String);

impl TryFrom<String> for SingBoxTag {
    type Error = SingBoxTagError;

    fn try_from(text: String) -> Result<Self, SingBoxTagError> {
        match text.strip_prefix('v').map(Version::parse) {
            Some(Ok(version)) if version.is_release() => Ok(Self(version)),
            Some(Ok(_) | Err(_)) | None => Err(SingBoxTagError(text)),
        }
    }
}

impl fmt::Display for SingBoxTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}

/// The git object ids of the CFM importer at the revision.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImporterObjects {
    subscription_import_tree: GitObjectId,
    subscription_import_rs_blob: GitObjectId,
    cfw_singbox_config_tree: GitObjectId,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Patch {
    path: String,
    sha256: Sha256Digest,
}

/// The parsed and checked manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CfmManifest {
    lines: BTreeMap<String, CfmRevision>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ManifestError {
    /// Not TOML, or a key is missing, unknown or of the wrong type.
    #[error(transparent)]
    Toml(#[from] toml::de::Error),
    #[error("manifest_version {found} is not the supported version {MANIFEST_VERSION}")]
    UnsupportedVersion { found: u32 },
    #[error(
        "{line}: importer_digest {recorded} is not the digest of its importer objects ({computed})"
    )]
    ImporterDigestMismatch {
        line: String,
        recorded: Sha256Digest,
        computed: Sha256Digest,
    },
    #[error("{line}: patch {path} repeats an earlier patch's path or content")]
    DuplicatePatch { line: String, path: String },
    /// The `[cfm.<client line>]` tables are not the client lines the
    /// emitter enumerates.
    #[error(
        "the [cfm.<client line>] tables do not match the enumerated client lines: missing {missing:?}, unknown {unknown:?}"
    )]
    ClientLines {
        /// Enumerated client lines without a table.
        missing: Vec<String>,
        /// Tables for client lines the emitter does not enumerate.
        unknown: Vec<String>,
    },
}

impl CfmManifest {
    pub(crate) fn parse(text: &str) -> Result<Self, ManifestError> {
        let ManifestToml {
            manifest_version,
            cfm,
        } = toml::from_str(text)?;
        if manifest_version != MANIFEST_VERSION {
            return Err(ManifestError::UnsupportedVersion {
                found: manifest_version,
            });
        }
        for (line, revision) in &cfm {
            revision.check(line)?;
        }
        Ok(Self { lines: cfm })
    }

    /// Requires a table for exactly the client lines in `enumerated` (the
    /// names `mooring_export::shapes()` uses), so that every shape has a
    /// current importer to be accepted against and no table is stale.
    pub(crate) fn require_lines(&self, enumerated: &BTreeSet<&str>) -> Result<(), ManifestError> {
        let missing: Vec<String> = enumerated
            .iter()
            .filter(|line| !self.lines.contains_key(**line))
            .map(|line| (*line).to_owned())
            .collect();
        let unknown: Vec<String> = self
            .lines
            .keys()
            .filter(|line| !enumerated.contains(line.as_str()))
            .cloned()
            .collect();
        if missing.is_empty() && unknown.is_empty() {
            Ok(())
        } else {
            Err(ManifestError::ClientLines { missing, unknown })
        }
    }

    /// The current revision of the client line named `line`.
    pub(crate) fn revision(&self, line: &str) -> Option<&CfmRevision> {
        self.lines.get(line)
    }

    /// Every client line name with its revision, in name order.
    pub(crate) fn lines(&self) -> impl Iterator<Item = (&str, &CfmRevision)> {
        self.lines
            .iter()
            .map(|(line, revision)| (line.as_str(), revision))
    }
}

impl CfmRevision {
    /// The importer digest an acceptance of this line must be taken against.
    pub(crate) const fn importer_digest(&self) -> Sha256Digest {
        self.importer_digest
    }

    /// Whether a CFM build reporting `bundle` as its version and `core` as
    /// its sing-box core is a build of this revision's line: the bundle is
    /// in the CFM release line, and the core is the sing-box release.
    pub(crate) fn is_build(&self, bundle: &Version, core: &Version) -> bool {
        bundle.release_line() == self.line && *core == self.sing_box_tag.0
    }

    fn check(&self, line: &str) -> Result<(), ManifestError> {
        let computed = self.importer.digest();
        if computed != self.importer_digest {
            return Err(ManifestError::ImporterDigestMismatch {
                line: line.to_owned(),
                recorded: self.importer_digest,
                computed,
            });
        }
        let mut paths = BTreeSet::new();
        let mut contents = BTreeSet::new();
        for patch in &self.patch {
            if !paths.insert(patch.path.as_str()) || !contents.insert(patch.sha256) {
                return Err(ManifestError::DuplicatePatch {
                    line: line.to_owned(),
                    path: patch.path.clone(),
                });
            }
        }
        Ok(())
    }
}

impl ImporterObjects {
    /// The importer digest: SHA-256 of one `<path> <object id>\n` line per
    /// importer object, in [`IMPORTER_PATHS`] order.
    fn digest(&self) -> Sha256Digest {
        let ids = [
            &self.subscription_import_tree,
            &self.subscription_import_rs_blob,
            &self.cfw_singbox_config_tree,
        ];
        let mut text = String::new();
        for (path, id) in IMPORTER_PATHS.into_iter().zip(ids) {
            text.push_str(path);
            text.push(' ');
            text.push_str(id.as_str());
            text.push('\n');
        }
        Sha256Digest::of(text.as_bytes())
    }
}

/// One line for the `acceptance` report.
impl fmt::Display for CfmRevision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CFM {} at {}, sing-box {} at {}, {} patch(es), importer digest {}",
            self.line,
            self.revision,
            self.sing_box_tag,
            self.sing_box_commit,
            self.patch.len(),
            self.importer_digest
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{CfmManifest, ManifestError};
    use crate::version::Version;

    const CONTRACT: &str = include_str!("../../../contract/cfm-manifest.toml");

    /// The cfm04 importer digest, computed with `shasum -a 256` over the
    /// three object lines when the manifest was written.
    const CFM04_IMPORTER: &str = "be5ad5c27b251901a77ee5912812282c9b8088535868c5e2994973b5dbf267e7";
    const CFM05_IMPORTER: &str = "e9c2cfa8e886ee34d65765b743a7a6396880f2c67aa657e4d40c0680359647be";

    fn rejects(text: &str) -> ManifestError {
        CfmManifest::parse(text).unwrap_err()
    }

    fn toml_error(error: &ManifestError, text: &str) -> bool {
        matches!(error, ManifestError::Toml(toml) if toml.message().contains(text))
    }

    fn importer(manifest: &CfmManifest, line: &str) -> String {
        manifest
            .revision(line)
            .unwrap()
            .importer_digest()
            .to_string()
    }

    fn v(text: &str) -> Version {
        Version::parse(text).unwrap()
    }

    #[test]
    fn the_contract_manifest_parses_with_matching_importer_digests() {
        let manifest = CfmManifest::parse(CONTRACT).unwrap();
        let lines: Vec<&str> = manifest.lines().map(|(line, _)| line).collect();
        assert_eq!(lines, ["cfm04", "cfm05"]);
        assert_eq!(importer(&manifest, "cfm04"), CFM04_IMPORTER);
        assert_eq!(importer(&manifest, "cfm05"), CFM05_IMPORTER);
        assert_eq!(manifest.revision("cfm06"), None);
        let (_, cfm04) = manifest.lines().next().unwrap();
        assert_eq!(
            cfm04.to_string(),
            format!(
                "CFM 0.4 at ac981c3b6c3284824e1018de367335aa6d69433e, sing-box v1.14.1 at \
                 1ac1a339cb1223e9c70eae14c44411c75033c02d, 6 patch(es), importer digest \
                 {CFM04_IMPORTER}"
            )
        );
    }

    #[test]
    fn the_manifest_names_exactly_the_enumerated_client_lines() {
        let manifest = CfmManifest::parse(CONTRACT).unwrap();
        manifest
            .require_lines(&BTreeSet::from(["cfm04", "cfm05"]))
            .unwrap();
        assert_eq!(
            manifest.require_lines(&BTreeSet::from(["cfm04", "cfm05", "cfm06"])),
            Err(ManifestError::ClientLines {
                missing: vec!["cfm06".to_owned()],
                unknown: Vec::new(),
            })
        );
        assert_eq!(
            manifest.require_lines(&BTreeSet::from(["cfm05"])),
            Err(ManifestError::ClientLines {
                missing: Vec::new(),
                unknown: vec!["cfm04".to_owned()],
            })
        );
        // A renamed table is both.
        let renamed = CfmManifest::parse(&CONTRACT.replace("cfm.cfm04", "cfm.cfm4")).unwrap();
        assert_eq!(
            renamed.require_lines(&BTreeSet::from(["cfm04", "cfm05"])),
            Err(ManifestError::ClientLines {
                missing: vec!["cfm04".to_owned()],
                unknown: vec!["cfm4".to_owned()],
            })
        );
    }

    #[test]
    fn a_build_of_a_line_has_its_release_line_and_sing_box_core() {
        let manifest = CfmManifest::parse(CONTRACT).unwrap();
        let cfm04 = manifest.revision("cfm04").unwrap();
        let cfm05 = manifest.revision("cfm05").unwrap();
        assert!(cfm04.is_build(&v("0.4.0"), &v("1.14.1")));
        assert!(cfm04.is_build(&v("0.4.12"), &v("1.14.1")));
        assert!(cfm05.is_build(&v("0.5.3"), &v("1.14.2")));
        for (bundle, core) in [
            ("0.5.0", "1.14.1"),
            ("1.4.0", "1.14.1"),
            ("0.4.0", "1.14.2"),
            ("0.4.0", "1.14.10"),
        ] {
            assert!(!cfm04.is_build(&v(bundle), &v(core)), "{bundle} {core}");
        }
        assert!(!cfm05.is_build(&v("0.4.0"), &v("1.14.2")));
    }

    #[test]
    fn an_importer_digest_must_be_the_digest_of_its_objects() {
        let edited = CONTRACT.replacen(
            "subscription_import_rs_blob = \"21c932e65f9f60f3a64691bff930eaeda9c5ca77\"",
            "subscription_import_rs_blob = \"21c932e65f9f60f3a64691bff930eaeda9c5ca78\"",
            1,
        );
        assert_ne!(edited, CONTRACT);
        let error = rejects(&edited);
        assert!(
            matches!(
                &error,
                ManifestError::ImporterDigestMismatch { line, recorded, computed }
                    if line == "cfm04" && recorded.to_string() == CFM04_IMPORTER
                        && computed.to_string() != CFM04_IMPORTER
            ),
            "{error:?}"
        );
        let edited = CONTRACT.replacen(CFM05_IMPORTER, &"0".repeat(64), 1);
        assert!(matches!(
            rejects(&edited),
            ManifestError::ImporterDigestMismatch { line, .. } if line == "cfm05"
        ));
    }

    #[test]
    fn a_patch_is_listed_once_by_path_and_by_content() {
        let first = "[[cfm.cfm04.patch]]\n\
            path = \"native/macos/patches/sing-box-v1.14.1-security-dependencies.patch\"\n\
            sha256 = \"7279aef88a394ee8caf00505ef797e8c6f798047d99615c62da9dca03d987645\"\n";
        assert!(CONTRACT.contains(first));
        let error = rejects(&format!("{CONTRACT}\n{first}"));
        assert_eq!(
            error,
            ManifestError::DuplicatePatch {
                line: "cfm04".to_owned(),
                path: "native/macos/patches/sing-box-v1.14.1-security-dependencies.patch"
                    .to_owned(),
            }
        );
        let same_path = first.replace(
            "7279aef88a394ee8caf00505ef797e8c6f798047d99615c62da9dca03d987645",
            &"1".repeat(64),
        );
        assert!(matches!(
            rejects(&format!("{CONTRACT}\n{same_path}")),
            ManifestError::DuplicatePatch { path, .. }
                if path == "native/macos/patches/sing-box-v1.14.1-security-dependencies.patch"
        ));
        let same_content = first.replace("security-dependencies", "renamed");
        assert!(matches!(
            rejects(&format!("{CONTRACT}\n{same_content}")),
            ManifestError::DuplicatePatch { path, .. }
                if path == "native/macos/patches/sing-box-v1.14.1-renamed.patch"
        ));
    }

    #[test]
    fn rejects_other_versions_unknown_keys_and_malformed_values() {
        assert_eq!(
            rejects(&CONTRACT.replace("manifest_version = 1", "manifest_version = 2")),
            ManifestError::UnsupportedVersion { found: 2 }
        );
        let cases = [
            (
                CONTRACT.replace("manifest_version = 1", "manifest_version = 1\nextra = 1"),
                "unknown field `extra`",
            ),
            (
                CONTRACT.replacen("line = \"0.4\"", "line = \"0.4\"\nbranch = \"main\"", 1),
                "unknown field `branch`",
            ),
            (
                CONTRACT.replacen(
                    "cfw_singbox_config_tree",
                    "extra_tree = \"b9ef0c0b339d8cc03a6ae7e174fb9e7d44dc5ddf\"\ncfw_singbox_config_tree",
                    1,
                ),
                "unknown field `extra_tree`",
            ),
            (
                CONTRACT.replacen("sha256 = ", "size = 1\nsha256 = ", 1),
                "unknown field `size`",
            ),
            (
                CONTRACT.replacen("sing_box_tag = \"v1.14.1\"\n", "", 1),
                "missing field `sing_box_tag`",
            ),
            (
                CONTRACT.replacen(
                    "revision = \"ac981c3b6c3284824e1018de367335aa6d69433e\"",
                    "revision = \"ac981c3\"",
                    1,
                ),
                "is not a git object id (40 lowercase hex characters)",
            ),
            (
                CONTRACT.replacen(
                    "7279aef88a394ee8caf00505ef797e8c6f798047d99615c62da9dca03d987645",
                    "7279AEF88A394EE8CAF00505EF797E8C6F798047D99615C62DA9DCA03D987645",
                    1,
                ),
                "invalid SHA-256 digest (64 lowercase hex characters)",
            ),
            (
                CONTRACT.replacen("line = \"0.4\"", "line = \"0.4.0\"", 1),
                "`0.4.0` is not a `major.minor` release line",
            ),
            (
                CONTRACT.replacen("sing_box_tag = \"v1.14.1\"", "sing_box_tag = \"1.14.1\"", 1),
                "\"1.14.1\" is not a sing-box release tag",
            ),
            (
                CONTRACT.replacen(
                    "sing_box_tag = \"v1.14.1\"",
                    "sing_box_tag = \"v1.14.1-rc.1\"",
                    1,
                ),
                "\"v1.14.1-rc.1\" is not a sing-box release tag",
            ),
            (
                CONTRACT.replace("manifest_version = 1", "manifest_version = -1"),
                "expected u32",
            ),
        ];
        for (text, message) in cases {
            assert_ne!(text, CONTRACT, "{message}");
            let error = rejects(&text);
            assert!(toml_error(&error, message), "{message}: {error}");
        }
    }
}
