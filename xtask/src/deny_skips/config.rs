// SPDX-License-Identifier: GPL-3.0-or-later

//! The parts of `deny.toml` that decide which duplicates `cargo deny`
//! reports, and the `[bans] skip` list itself.
//!
//! `deny.toml` is cargo-deny's format, not ours, so only the keys this check
//! depends on are modelled. Every other table and key (`[advisories]`,
//! `[licenses]`, `[sources]`, the other `[bans]` settings) is ignored here by
//! design: `cargo deny check`, which `cargo xtask ci` also runs, validates
//! them.
//!
//! The duplicate computation models one configuration: all features, dev
//! dependencies counted (`multiple-versions-include-dev = true`), no
//! `skip-tree`, and a `[graph]` table with only `targets` and
//! `all-features`. `[graph]` therefore denies unknown keys, since any other
//! graph key changes the graph this check computes; it is rejected instead
//! of being modelled wrongly. Skip entries deny unknown keys too, because
//! their `{ crate, reason }` form is this workspace's policy.

use std::collections::BTreeSet;

use serde::Deserialize;
use serde::de::IgnoredAny;

use crate::version::Version;

/// One `{ crate = "name@version", reason = "…" }` entry. The reason is
/// required to be non-blank; its text is for reviewers, not for this check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SkipEntry {
    pub(crate) name: String,
    pub(crate) version: Version,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DenyConfig {
    pub(crate) targets: Vec<String>,
    pub(crate) skips: Vec<SkipEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ConfigError {
    /// Not TOML, or a modelled key is missing, unknown or of the wrong type.
    #[error(transparent)]
    Toml(#[from] toml::de::Error),
    #[error("`{key}` must be {expected}")]
    Unsupported {
        key: &'static str,
        expected: &'static str,
    },
    #[error("`bans.skip-tree` entries are not supported; skip exact versions instead")]
    SkipTree,
    #[error("`{spec}` is not `name@major.minor.patch`")]
    CrateSpec { spec: String },
    #[error("skip entry `{spec}` has an empty reason")]
    EmptyReason { spec: String },
    #[error("`{spec}` is listed twice")]
    DuplicateSkip { spec: String },
}

/// The modelled subset of `deny.toml`; other top-level tables are ignored.
#[derive(Debug, Deserialize)]
struct DenyToml {
    graph: Graph,
    bans: Bans,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct Graph {
    targets: Vec<String>,
    all_features: bool,
}

/// The modelled `[bans]` keys; `multiple-versions`, `wildcards` and the
/// other settings are cargo-deny's alone.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct Bans {
    multiple_versions_include_dev: bool,
    /// Absent means no `skip-tree`, as for cargo-deny.
    #[serde(default)]
    skip_tree: Vec<IgnoredAny>,
    skip: Vec<RawSkip>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSkip {
    #[serde(rename = "crate")]
    spec: String,
    reason: String,
}

impl DenyConfig {
    pub(crate) fn parse(source: &str) -> Result<Self, ConfigError> {
        let DenyToml { graph, bans } = toml::from_str(source)?;
        require_true(graph.all_features, "graph.all-features")?;
        require_true(
            bans.multiple_versions_include_dev,
            "bans.multiple-versions-include-dev",
        )?;
        if !bans.skip_tree.is_empty() {
            return Err(ConfigError::SkipTree);
        }
        if graph.targets.is_empty() {
            return Err(ConfigError::Unsupported {
                key: "graph.targets",
                expected: "a non-empty array of strings",
            });
        }
        let mut seen = BTreeSet::new();
        let mut skips = Vec::with_capacity(bans.skip.len());
        for raw in bans.skip {
            let entry = skip_entry(raw)?;
            if !seen.insert((entry.name.clone(), entry.version.clone())) {
                return Err(ConfigError::DuplicateSkip {
                    spec: format!("{}@{}", entry.name, entry.version),
                });
            }
            skips.push(entry);
        }
        Ok(Self {
            targets: graph.targets,
            skips,
        })
    }
}

fn require_true(value: bool, key: &'static str) -> Result<(), ConfigError> {
    if value {
        Ok(())
    } else {
        Err(ConfigError::Unsupported {
            key,
            expected: "`true`",
        })
    }
}

fn skip_entry(raw: RawSkip) -> Result<SkipEntry, ConfigError> {
    let RawSkip { spec, reason } = raw;
    let bad_spec = || ConfigError::CrateSpec { spec: spec.clone() };
    let (name, version) = spec.split_once('@').ok_or_else(bad_spec)?;
    let valid_name = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !valid_name {
        return Err(bad_spec());
    }
    let version = Version::parse(version).map_err(|_| bad_spec())?;
    if reason.trim().is_empty() {
        return Err(ConfigError::EmptyReason { spec });
    }
    Ok(SkipEntry {
        name: name.to_owned(),
        version,
    })
}

#[cfg(test)]
mod tests {
    use super::{ConfigError, DenyConfig, SkipEntry};
    use crate::version::Version;

    /// A `deny.toml` with the modelled keys and some that are ignored by design.
    const VALID: &str = r#"
[graph]
targets = ["aarch64-apple-darwin", "x86_64-unknown-linux-musl"]
all-features = true

[advisories]
yanked = "deny"

[bans]
multiple-versions = "deny"
multiple-versions-include-dev = true
skip-tree = []
skip = [
    { crate = "getrandom@0.2.17", reason = "ring needs 0.2" },
    { reason = "proc macros", crate = "syn@2.0.119" },
]
"#;

    #[test]
    fn reads_targets_and_skip_entries() {
        let config = DenyConfig::parse(VALID).unwrap();
        assert_eq!(
            config.targets,
            ["aarch64-apple-darwin", "x86_64-unknown-linux-musl"]
        );
        assert_eq!(
            config.skips,
            [
                SkipEntry {
                    name: "getrandom".to_owned(),
                    version: Version::parse("0.2.17").unwrap(),
                },
                SkipEntry {
                    name: "syn".to_owned(),
                    version: Version::parse("2.0.119").unwrap(),
                },
            ]
        );
        // An absent skip-tree is no skip-tree.
        let config = DenyConfig::parse(&VALID.replace("skip-tree = []\n", "")).unwrap();
        assert_eq!(config.skips.len(), 2);
    }

    /// cargo-deny reads `[bans] skip` written as an array of tables, so
    /// this check reads it the same way.
    #[test]
    fn reads_skip_entries_written_as_an_array_of_tables() {
        let inline = r#"skip = [
    { crate = "getrandom@0.2.17", reason = "ring needs 0.2" },
    { reason = "proc macros", crate = "syn@2.0.119" },
]
"#;
        let tables = r#"
[[bans.skip]]
crate = "getrandom@0.2.17"
reason = "ring needs 0.2"

[[bans.skip]]
reason = "proc macros"
crate = "syn@2.0.119"
"#;
        let source = VALID.replace(inline, tables);
        assert_ne!(source, VALID);
        assert_eq!(
            DenyConfig::parse(&source).unwrap(),
            DenyConfig::parse(VALID).unwrap()
        );
    }

    fn rejects(source: &str) -> ConfigError {
        DenyConfig::parse(source).unwrap_err()
    }

    /// Whether `error` is a TOML error whose message contains `text`.
    fn toml_error(error: &ConfigError, text: &str) -> bool {
        matches!(error, ConfigError::Toml(toml) if toml.message().contains(text))
    }

    /// Recognises the expected error variant.
    type Expectation = fn(&ConfigError) -> bool;

    const SYN_ENTRY: &str = r#"{ reason = "proc macros", crate = "syn@2.0.119" }"#;

    #[test]
    fn rejects_entries_without_a_reason_or_an_exact_version() {
        let cases: [(&str, Expectation); 9] = [
            (
                r#"{ crate = "syn@2.0.119", reason = "  " }"#,
                |e| matches!(e, ConfigError::EmptyReason { spec } if spec == "syn@2.0.119"),
            ),
            (r#"{ crate = "syn@2.0.119" }"#, |e| {
                toml_error(e, "missing field `reason`")
            }),
            (r#""syn@2.0.119""#, |e| {
                toml_error(e, "invalid type: string")
            }),
            (
                r#"{ crate = "syn", reason = "r" }"#,
                |e| matches!(e, ConfigError::CrateSpec { spec } if spec == "syn"),
            ),
            (
                r#"{ crate = "syn@^2", reason = "r" }"#,
                |e| matches!(e, ConfigError::CrateSpec { spec } if spec == "syn@^2"),
            ),
            (
                r#"{ crate = "@2.0.119", reason = "r" }"#,
                |e| matches!(e, ConfigError::CrateSpec { spec } if spec == "@2.0.119"),
            ),
            (
                r#"{ crate = "sy n@2.0.119", reason = "r" }"#,
                |e| matches!(e, ConfigError::CrateSpec { spec } if spec == "sy n@2.0.119"),
            ),
            (
                r#"{ crate = "syn@2.0.119", reason = "r", extra = 1 }"#,
                |e| toml_error(e, "unknown field `extra`"),
            ),
            (
                r#"{ name = "syn", version = "=2.0.119", reason = "r" }"#,
                |e| toml_error(e, "unknown field `name`"),
            ),
        ];
        for (entry, is_expected) in cases {
            let error = rejects(&VALID.replace(SYN_ENTRY, entry));
            assert!(is_expected(&error), "{entry}: {error:?}");
        }
    }

    #[test]
    fn rejects_duplicate_entries() {
        let source = VALID.replace("syn@2.0.119", "getrandom@0.2.17");
        assert!(matches!(
            rejects(&source),
            ConfigError::DuplicateSkip { spec } if spec == "getrandom@0.2.17"
        ));
    }

    #[test]
    fn rejects_configurations_it_does_not_model() {
        let targets = r#"targets = ["aarch64-apple-darwin", "x86_64-unknown-linux-musl"]"#;
        let cases: [(String, Expectation); 10] = [
            (
                VALID.replace("all-features = true", "all-features = false"),
                |e| {
                    matches!(
                        e,
                        ConfigError::Unsupported {
                            key: "graph.all-features",
                            ..
                        }
                    )
                },
            ),
            (VALID.replace("all-features = true", ""), |e| {
                toml_error(e, "missing field `all-features`")
            }),
            (
                VALID.replace("multiple-versions-include-dev = true\n", ""),
                |e| toml_error(e, "missing field `multiple-versions-include-dev`"),
            ),
            (
                VALID.replace(
                    "multiple-versions-include-dev = true",
                    "multiple-versions-include-dev = false",
                ),
                |e| {
                    matches!(
                        e,
                        ConfigError::Unsupported {
                            key: "bans.multiple-versions-include-dev",
                            ..
                        }
                    )
                },
            ),
            (
                VALID.replace(
                    "all-features = true",
                    "all-features = true\nexclude-dev = true",
                ),
                |e| toml_error(e, "unknown field `exclude-dev`"),
            ),
            (
                VALID.replace("skip-tree = []", r#"skip-tree = [{ crate = "x@1.0.0" }]"#),
                |e| matches!(e, ConfigError::SkipTree),
            ),
            (VALID.replace(targets, "targets = []"), |e| {
                matches!(
                    e,
                    ConfigError::Unsupported {
                        key: "graph.targets",
                        ..
                    }
                )
            }),
            // A complete entry, so only the redefinition of the inline
            // `skip` array can fail.
            (
                format!("{VALID}\n[[bans.skip]]\ncrate = \"x@1.0.0\"\nreason = \"r\"\n"),
                |e| matches!(e, ConfigError::Toml(toml) if toml.message() == "duplicate key"),
            ),
            (
                VALID
                    .replace("skip = [", "skip-list = [")
                    .replace("skip-tree = []", ""),
                |e| toml_error(e, "missing field `skip`"),
            ),
            (VALID.replace("[graph]", "[graf]"), |e| {
                toml_error(e, "missing field `graph`")
            }),
        ];
        for (source, is_expected) in cases {
            let error = rejects(&source);
            assert!(is_expected(&error), "{error:?}");
        }
    }
}
