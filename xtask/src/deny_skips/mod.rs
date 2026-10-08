// SPDX-License-Identifier: GPL-3.0-or-later

//! `deny-skips` (design §4.4): `deny.toml`'s `[bans] skip` list must name
//! exactly the superseded versions of every crate that the deny graph
//! resolves at more than one version. The newest version of each such crate
//! is the one generation the workspace standardises on; every older version
//! needs a `{ crate = "name@version", reason = "…" }` entry.
//!
//! A missing entry would make `cargo deny` fail; a stale one (a version that
//! is gone, the only version left, or the newest) would hide the next
//! duplicate of that crate. Both fail here.

mod config;
mod graph;

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use crate::cargo::Cargo;
use crate::metadata::{self, MetadataError};
use crate::output::{OutputError, say};

use self::config::{ConfigError, DenyConfig, SkipEntry};
use self::graph::{CrateVersions, GraphError};
use crate::version::Version;

#[derive(Debug, thiserror::Error)]
pub(crate) enum DenySkipsError {
    #[error("failed to read {}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot use {}", path.display())]
    Config {
        path: PathBuf,
        #[source]
        source: ConfigError,
    },
    #[error(transparent)]
    Metadata(#[from] MetadataError),
    #[error("cannot compute the deny graph")]
    Graph(#[from] GraphError),
    #[error(transparent)]
    Output(#[from] OutputError),
    #[error("deny-skips found {0} problem(s) in the [bans] skip list")]
    Mismatch(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Staleness {
    NotInGraph,
    OnlyVersion,
    Newest,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Finding {
    Missing {
        name: String,
        version: Version,
        newest: Version,
    },
    Stale {
        name: String,
        version: Version,
        why: Staleness,
    },
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing {
                name,
                version,
                newest,
            } => write!(
                f,
                "missing skip entry {name}@{version} (superseded by {name} {newest})"
            ),
            Self::Stale { name, version, why } => {
                let why = match why {
                    Staleness::NotInGraph => "that version is not in the deny graph",
                    Staleness::OnlyVersion => "it is the only version of the crate",
                    Staleness::Newest => "it is the newest version; skip the older ones",
                };
                write!(f, "stale skip entry {name}@{version}: {why}")
            }
        }
    }
}

pub(crate) fn run(cargo: &Cargo, out: &mut impl Write) -> Result<(), DenySkipsError> {
    let path = cargo.workspace_root().join("deny.toml");
    let source = fs::read_to_string(&path).map_err(|source| DenySkipsError::Read {
        path: path.clone(),
        source,
    })?;
    let config =
        DenyConfig::parse(&source).map_err(|source| DenySkipsError::Config { path, source })?;

    let mut args = vec!["--all-features"];
    for target in &config.targets {
        args.extend(["--filter-platform", target.as_str()]);
    }
    let versions = graph::crate_versions(&metadata::load(cargo, &args)?)?;

    for (name, set) in versions.iter().filter(|(_, set)| set.len() > 1) {
        let list: Vec<String> = set.iter().map(Version::to_string).collect();
        say!(out, "deny-skips: {name} resolves at {}", list.join(", "))?;
    }
    let findings = compare(&versions, &config.skips);
    for finding in &findings {
        say!(out, "deny-skips: {finding}")?;
    }
    if findings.is_empty() {
        say!(
            out,
            "deny-skips: [bans] skip lists exactly the {} superseded version(s) for {}",
            config.skips.len(),
            config.targets.join(", ")
        )?;
        Ok(())
    } else {
        Err(DenySkipsError::Mismatch(findings.len()))
    }
}

/// Compares the skip list with the superseded versions in `versions`.
pub(crate) fn compare(versions: &CrateVersions, skips: &[SkipEntry]) -> Vec<Finding> {
    let listed: BTreeSet<(&str, &Version)> = skips
        .iter()
        .map(|skip| (skip.name.as_str(), &skip.version))
        .collect();
    let mut findings = BTreeSet::new();
    for (name, set) in versions {
        let Some(newest) = set.last() else {
            continue;
        };
        for version in set.iter().filter(|version| *version != newest) {
            if !listed.contains(&(name.as_str(), version)) {
                findings.insert(Finding::Missing {
                    name: name.clone(),
                    version: version.clone(),
                    newest: newest.clone(),
                });
            }
        }
    }
    for skip in skips {
        let set = versions.get(&skip.name);
        let why = match set {
            Some(set) if !set.contains(&skip.version) => Some(Staleness::NotInGraph),
            None => Some(Staleness::NotInGraph),
            Some(set) if set.len() == 1 => Some(Staleness::OnlyVersion),
            Some(set) if set.last() == Some(&skip.version) => Some(Staleness::Newest),
            Some(_) => None,
        };
        if let Some(why) = why {
            findings.insert(Finding::Stale {
                name: skip.name.clone(),
                version: skip.version.clone(),
                why,
            });
        }
    }
    findings.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::{Finding, Staleness, compare};
    use crate::deny_skips::config::SkipEntry;
    use crate::deny_skips::graph::CrateVersions;
    use crate::version::Version;

    fn v(text: &str) -> Version {
        Version::parse(text).unwrap()
    }

    /// The duplicates of this workspace when the skip list was written.
    fn graph() -> CrateVersions {
        [
            ("getrandom", &["0.2.17", "0.3.4", "0.4.3"][..]),
            ("rand_core", &["0.9.5", "0.10.1"][..]),
            ("syn", &["2.0.119", "3.0.6"][..]),
            ("serde", &["1.0.229"][..]),
        ]
        .into_iter()
        .map(|(name, versions)| {
            (
                name.to_owned(),
                versions.iter().map(|text| v(text)).collect(),
            )
        })
        .collect()
    }

    fn skip(spec: &str) -> SkipEntry {
        let (name, version) = spec.split_once('@').unwrap();
        SkipEntry {
            name: name.to_owned(),
            version: v(version),
        }
    }

    fn exact_list() -> Vec<SkipEntry> {
        [
            "getrandom@0.2.17",
            "getrandom@0.3.4",
            "rand_core@0.9.5",
            "syn@2.0.119",
        ]
        .into_iter()
        .map(skip)
        .collect()
    }

    #[test]
    fn the_exact_list_passes() {
        assert_eq!(compare(&graph(), &exact_list()), []);
    }

    #[test]
    fn an_unlisted_duplicate_is_missing() {
        let mut skips = exact_list();
        skips.retain(|entry| entry.name != "rand_core");
        assert_eq!(
            compare(&graph(), &skips),
            [Finding::Missing {
                name: "rand_core".to_owned(),
                version: v("0.9.5"),
                newest: v("0.10.1"),
            }]
        );
    }

    #[test]
    fn entries_that_no_longer_name_a_superseded_version_are_stale() {
        let mut skips = exact_list();
        skips.extend([
            skip("bit-vec@0.8.0"),
            skip("getrandom@0.2.16"),
            skip("serde@1.0.229"),
            skip("syn@3.0.6"),
        ]);
        let stale = |spec: &str, why| {
            let (name, version) = spec.split_once('@').unwrap();
            Finding::Stale {
                name: name.to_owned(),
                version: v(version),
                why,
            }
        };
        assert_eq!(
            compare(&graph(), &skips),
            [
                stale("bit-vec@0.8.0", Staleness::NotInGraph),
                stale("getrandom@0.2.16", Staleness::NotInGraph),
                stale("serde@1.0.229", Staleness::OnlyVersion),
                stale("syn@3.0.6", Staleness::Newest),
            ]
        );
    }

    #[test]
    fn skipping_the_newest_instead_of_an_older_version_fails_both_ways() {
        let mut skips = exact_list();
        skips.retain(|entry| entry.name != "syn");
        skips.push(skip("syn@3.0.6"));
        let findings = compare(&graph(), &skips);
        assert_eq!(findings.len(), 2);
        assert!(matches!(&findings[0], Finding::Missing { name, .. } if name == "syn"));
        assert!(matches!(
            &findings[1],
            Finding::Stale {
                why: Staleness::Newest,
                ..
            }
        ));
    }
}
