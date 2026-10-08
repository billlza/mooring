// SPDX-License-Identifier: GPL-3.0-or-later

//! The subset of `cargo metadata --format-version 1` this tool reads.
//!
//! Unknown fields are ignored on purpose: cargo adds fields over time and
//! none of them changes the meaning of the fields read here.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::cargo::{Cargo, CommandError};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(transparent)]
pub(crate) struct PackageId(pub(crate) String);

impl fmt::Display for PackageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct Metadata {
    pub(crate) packages: Vec<Package>,
    pub(crate) workspace_members: Vec<PackageId>,
    /// Absent (`null`) only with `--no-deps`.
    pub(crate) resolve: Option<Resolve>,
    pub(crate) target_directory: PathBuf,
    pub(crate) build_directory: PathBuf,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Package {
    pub(crate) id: PackageId,
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) manifest_path: PathBuf,
    pub(crate) dependencies: Vec<Dependency>,
    /// Every feature, including the implicit `name = ["dep:name"]` ones.
    pub(crate) features: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Dependency {
    /// The package name, not the rename.
    pub(crate) name: String,
    pub(crate) rename: Option<String>,
    #[serde(with = "dependency_kind")]
    pub(crate) kind: DependencyKind,
    pub(crate) optional: bool,
    /// Present only for path dependencies.
    pub(crate) path: Option<PathBuf>,
}

impl Dependency {
    /// The key under which the manifest declares the dependency, as used by
    /// `dep:<key>` and `<key>/<feature>` entries in feature tables.
    pub(crate) fn key(&self) -> &str {
        self.rename.as_deref().unwrap_or(&self.name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum DependencyKind {
    Normal,
    Dev,
    Build,
}

impl fmt::Display for DependencyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Normal => "normal",
            Self::Dev => "dev",
            Self::Build => "build",
        })
    }
}

/// Cargo encodes the kind as `null` (normal), `"dev"` or `"build"`; any other
/// value is a deserialisation error rather than a guess.
mod dependency_kind {
    use serde::{Deserialize, Deserializer};

    use super::DependencyKind;

    #[derive(Deserialize)]
    #[serde(rename_all = "lowercase")]
    enum Tagged {
        Dev,
        Build,
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<DependencyKind, D::Error> {
        Ok(match Option::<Tagged>::deserialize(deserializer)? {
            None => DependencyKind::Normal,
            Some(Tagged::Dev) => DependencyKind::Dev,
            Some(Tagged::Build) => DependencyKind::Build,
        })
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct Resolve {
    pub(crate) nodes: Vec<Node>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Node {
    pub(crate) id: PackageId,
    pub(crate) deps: Vec<NodeDep>,
    /// The activated features of this package (already closed over).
    pub(crate) features: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct NodeDep {
    pub(crate) pkg: PackageId,
    pub(crate) dep_kinds: Vec<DepKindInfo>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct DepKindInfo {
    #[serde(with = "dependency_kind")]
    pub(crate) kind: DependencyKind,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum MetadataError {
    #[error(transparent)]
    Command(#[from] CommandError),
    #[error("cannot parse the output of cargo metadata")]
    Parse(#[source] serde_json::Error),
    #[error("workspace member {0} is not in the package list")]
    UnknownMember(PackageId),
    #[error("manifest path {} has no parent directory", .0.display())]
    ManifestWithoutParent(PathBuf),
}

/// Runs `cargo metadata --format-version 1 --locked <extra>`.
pub(crate) fn load(cargo: &Cargo, extra: &[&str]) -> Result<Metadata, MetadataError> {
    let mut args = vec!["metadata", "--format-version", "1", "--locked"];
    args.extend_from_slice(extra);
    let stdout = cargo.capture(&args)?;
    parse(&stdout)
}

pub(crate) fn parse(json: &[u8]) -> Result<Metadata, MetadataError> {
    serde_json::from_slice(json).map_err(MetadataError::Parse)
}

impl Metadata {
    /// The workspace members, in `workspace_members` order.
    pub(crate) fn members(&self) -> Result<Vec<&Package>, MetadataError> {
        let by_id: BTreeMap<&PackageId, &Package> = self
            .packages
            .iter()
            .map(|package| (&package.id, package))
            .collect();
        self.workspace_members
            .iter()
            .map(|id| {
                by_id
                    .get(id)
                    .copied()
                    .ok_or_else(|| MetadataError::UnknownMember(id.clone()))
            })
            .collect()
    }
}

impl Package {
    pub(crate) fn manifest_dir(&self) -> Result<&Path, MetadataError> {
        self.manifest_path
            .parent()
            .ok_or_else(|| MetadataError::ManifestWithoutParent(self.manifest_path.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::{DependencyKind, MetadataError, parse};

    #[test]
    fn decodes_dependency_kinds_and_rejects_unknown_ones() {
        let json = br#"{
            "packages": [{
                "id": "a 0.1.0", "name": "a", "version": "0.1.0",
                "manifest_path": "/w/a/Cargo.toml", "features": {},
                "dependencies": [
                    {"name": "b", "rename": null, "kind": null, "optional": false},
                    {"name": "c", "rename": "cc", "kind": "dev", "optional": false, "path": "/w/c"},
                    {"name": "d", "rename": null, "kind": "build", "optional": true}
                ]
            }],
            "workspace_members": ["a 0.1.0"],
            "resolve": null,
            "target_directory": "/w/target",
            "build_directory": "/w/target"
        }"#;
        let metadata = parse(json).unwrap();
        let kinds: Vec<_> = metadata.packages[0]
            .dependencies
            .iter()
            .map(|dependency| (dependency.key().to_owned(), dependency.kind))
            .collect();
        assert_eq!(
            kinds,
            [
                ("b".to_owned(), DependencyKind::Normal),
                ("cc".to_owned(), DependencyKind::Dev),
                ("d".to_owned(), DependencyKind::Build),
            ]
        );

        let unknown = String::from_utf8(json.to_vec())
            .unwrap()
            .replace(r#""kind": "build""#, r#""kind": "runtime""#);
        assert!(matches!(
            parse(unknown.as_bytes()),
            Err(MetadataError::Parse(_))
        ));
    }

    #[test]
    fn members_must_exist_in_the_package_list() {
        let json = br#"{
            "packages": [], "workspace_members": ["ghost 0.1.0"], "resolve": null,
            "target_directory": "/w/target", "build_directory": "/w/target"
        }"#;
        let metadata = parse(json).unwrap();
        assert!(matches!(
            metadata.members(),
            Err(MetadataError::UnknownMember(id)) if id.0 == "ghost 0.1.0"
        ));
    }
}
