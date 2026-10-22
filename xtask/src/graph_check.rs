// SPDX-License-Identifier: GPL-3.0-or-later

//! `graph-check`: the edges between workspace crates must equal
//! [`ALLOWED_EDGES`] exactly (design §6.1), and test-only crates must never be
//! a normal or build dependency.
//!
//! Edges are read from the declared dependencies in `cargo metadata`, so an
//! optional or target-specific dependency is an edge even when it is not
//! activated.

use std::collections::BTreeSet;
use std::fmt;
use std::io::Write;
use std::path::Path;

use crate::cargo::Cargo;
use crate::metadata::{self, DependencyKind, Metadata, MetadataError};
use crate::output::{OutputError, say};

/// The permitted workspace-internal edges of one crate.
#[derive(Debug)]
pub(crate) struct AllowedEdges {
    pub(crate) krate: &'static str,
    pub(crate) normal: &'static [&'static str],
    pub(crate) dev: &'static [&'static str],
}

/// Design §6.1, restricted to the crates that exist. Build edges between
/// workspace crates are never permitted. Later milestones extend this table.
pub(crate) const ALLOWED_EDGES: &[AllowedEdges] = &[
    AllowedEdges {
        krate: "mooring-model",
        normal: &[],
        dev: &[],
    },
    AllowedEdges {
        krate: "mooring-keys",
        normal: &["mooring-model"],
        dev: &[],
    },
    AllowedEdges {
        krate: "mooring-export",
        normal: &["mooring-model"],
        dev: &["mooring-keys", "mooring-fixtures"],
    },
    AllowedEdges {
        krate: "mooring-agent-proto",
        normal: &[],
        dev: &[],
    },
    AllowedEdges {
        krate: "mooring-render",
        normal: &["mooring-model", "mooring-export", "mooring-agent-proto"],
        dev: &["mooring-keys", "mooring-fixtures"],
    },
    AllowedEdges {
        krate: "mooring-store",
        normal: &["mooring-model"],
        dev: &[],
    },
    AllowedEdges {
        krate: "mooring-fixtures",
        normal: &["mooring-model"],
        dev: &[],
    },
    // The console core: pure over model and wire types. The design's
    // `render` and `export` edges join with the daemon wiring that needs
    // them (M5).
    AllowedEdges {
        krate: "mooring-daemon-core",
        normal: &["mooring-model", "mooring-agent-proto"],
        dev: &["mooring-fixtures"],
    },
    // The only crate with `unsafe` (libc only): no workspace edge, so it
    // returns std types and its callers convert them.
    AllowedEdges {
        krate: "mooring-macsys",
        normal: &[],
        dev: &[],
    },
    // The CLI's first slice (revision 7): the router commands. The design's
    // keys, render, export and agent-proto edges join with the daemon (M5).
    // The user commands (M5) draw credentials with mooring-keys, export
    // through mooring-export and test against the fixture deployments.
    AllowedEdges {
        krate: "mooringctl",
        normal: &[
            "mooring-model",
            "mooring-store",
            "mooring-macsys",
            "mooring-daemon-core",
            "mooring-export",
            "mooring-keys",
        ],
        dev: &["mooring-fixtures"],
    },
    AllowedEdges {
        krate: "xtask",
        normal: &["mooring-export", "mooring-model"],
        dev: &[],
    },
    // The M2b field measurements (dev-only, never shipped): the model's
    // types for what they decide (`UplinkBaseline`, `Keepalive`, `Pairing`,
    // `InterfaceSelector`), and macsys on macOS for the interface list and
    // the open-files limit.
    AllowedEdges {
        krate: "fieldkit",
        normal: &["mooring-model", "mooring-macsys"],
        dev: &[],
    },
];

/// Crates that may only ever be dev-dependencies.
pub(crate) const TEST_ONLY_CRATES: &[&str] = &["mooring-fixtures"];

/// One workspace-internal dependency edge.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Edge {
    pub(crate) kind: DependencyKind,
    pub(crate) to: String,
}

/// A workspace member and its edges to other workspace members.
#[derive(Debug)]
pub(crate) struct MemberEdges {
    pub(crate) name: String,
    pub(crate) edges: BTreeSet<Edge>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Finding {
    UnexpectedEdge {
        from: String,
        kind: DependencyKind,
        to: String,
    },
    MissingEdge {
        from: String,
        kind: DependencyKind,
        to: String,
    },
    TestOnlyInProduction {
        from: String,
        kind: DependencyKind,
        to: String,
    },
    UnlistedMember {
        name: String,
    },
    StaleRow {
        name: &'static str,
    },
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEdge { from, kind, to } => {
                write!(f, "undeclared {kind} edge {from} -> {to}")
            }
            Self::MissingEdge { from, kind, to } => {
                write!(
                    f,
                    "missing {kind} edge {from} -> {to} (listed in ALLOWED_EDGES)"
                )
            }
            Self::TestOnlyInProduction { from, kind, to } => {
                write!(f, "{to} is test-only but is a {kind} dependency of {from}")
            }
            Self::UnlistedMember { name } => {
                write!(f, "workspace member {name} has no row in ALLOWED_EDGES")
            }
            Self::StaleRow { name } => {
                write!(f, "ALLOWED_EDGES row {name} names no workspace member")
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum GraphCheckError {
    #[error(transparent)]
    Metadata(#[from] MetadataError),
    #[error(transparent)]
    Output(#[from] OutputError),
    #[error("graph-check found {0} offending edge(s) or table row(s)")]
    Violations(usize),
}

pub(crate) fn run(cargo: &Cargo, out: &mut impl Write) -> Result<(), GraphCheckError> {
    let metadata = metadata::load(cargo, &[])?;
    let members = workspace_edges(&metadata)?;
    let findings = check(&members, ALLOWED_EDGES, TEST_ONLY_CRATES);
    for finding in &findings {
        say!(out, "graph-check: {finding}")?;
    }
    if findings.is_empty() {
        say!(
            out,
            "graph-check: {} workspace crates match the allowed-edge table",
            members.len()
        )?;
        Ok(())
    } else {
        Err(GraphCheckError::Violations(findings.len()))
    }
}

/// Each workspace member with its declared path dependencies on other members.
pub(crate) fn workspace_edges(metadata: &Metadata) -> Result<Vec<MemberEdges>, MetadataError> {
    let members = metadata.members()?;
    let member_dirs = members
        .iter()
        .map(|package| Ok((package.manifest_dir()?, package.name.as_str())))
        .collect::<Result<Vec<(&Path, &str)>, MetadataError>>()?;
    Ok(members
        .iter()
        .map(|package| MemberEdges {
            name: package.name.clone(),
            edges: package
                .dependencies
                .iter()
                .filter_map(|dependency| {
                    let path = dependency.path.as_deref()?;
                    member_dirs
                        .iter()
                        .find(|(dir, _)| *dir == path)
                        .map(|(_, name)| Edge {
                            kind: dependency.kind,
                            to: (*name).to_owned(),
                        })
                })
                .collect(),
        })
        .collect())
}

/// Compares the actual edges with the table; an empty result means they match.
pub(crate) fn check(
    members: &[MemberEdges],
    table: &[AllowedEdges],
    test_only: &[&str],
) -> Vec<Finding> {
    let mut findings = BTreeSet::new();
    for member in members {
        for edge in &member.edges {
            if edge.kind != DependencyKind::Dev && test_only.contains(&edge.to.as_str()) {
                findings.insert(Finding::TestOnlyInProduction {
                    from: member.name.clone(),
                    kind: edge.kind,
                    to: edge.to.clone(),
                });
            }
        }
        match table.iter().find(|row| row.krate == member.name) {
            Some(row) => compare_row(member, &allowed_set(row), &mut findings),
            None => {
                findings.insert(Finding::UnlistedMember {
                    name: member.name.clone(),
                });
            }
        }
    }
    for row in table {
        if !members.iter().any(|member| member.name == row.krate) {
            findings.insert(Finding::StaleRow { name: row.krate });
        }
    }
    findings.into_iter().collect()
}

fn allowed_set(row: &AllowedEdges) -> BTreeSet<Edge> {
    let normal = row.normal.iter().map(|to| (DependencyKind::Normal, to));
    let dev = row.dev.iter().map(|to| (DependencyKind::Dev, to));
    normal
        .chain(dev)
        .map(|(kind, to)| Edge {
            kind,
            to: (*to).to_owned(),
        })
        .collect()
}

fn compare_row(member: &MemberEdges, allowed: &BTreeSet<Edge>, findings: &mut BTreeSet<Finding>) {
    for edge in member.edges.difference(allowed) {
        findings.insert(Finding::UnexpectedEdge {
            from: member.name.clone(),
            kind: edge.kind,
            to: edge.to.clone(),
        });
    }
    for edge in allowed.difference(&member.edges) {
        findings.insert(Finding::MissingEdge {
            from: member.name.clone(),
            kind: edge.kind,
            to: edge.to.clone(),
        });
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{
        ALLOWED_EDGES, AllowedEdges, Edge, Finding, MemberEdges, TEST_ONLY_CRATES, check,
        workspace_edges,
    };
    use crate::metadata::{DependencyKind, parse};

    /// The members and edges exactly as the table describes them.
    fn members_matching(table: &[AllowedEdges]) -> Vec<MemberEdges> {
        table
            .iter()
            .map(|row| MemberEdges {
                name: row.krate.to_owned(),
                edges: super::allowed_set(row),
            })
            .collect()
    }

    fn member_mut<'a>(members: &'a mut [MemberEdges], name: &str) -> &'a mut MemberEdges {
        members.iter_mut().find(|m| m.name == name).unwrap()
    }

    fn edge(kind: DependencyKind, to: &str) -> Edge {
        Edge {
            kind,
            to: to.to_owned(),
        }
    }

    #[test]
    fn the_table_itself_passes() {
        let members = members_matching(ALLOWED_EDGES);
        assert_eq!(check(&members, ALLOWED_EDGES, TEST_ONLY_CRATES), []);
    }

    #[test]
    fn the_table_is_well_formed() {
        let names: BTreeSet<_> = ALLOWED_EDGES.iter().map(|row| row.krate).collect();
        assert_eq!(names.len(), ALLOWED_EDGES.len(), "duplicate rows");
        for row in ALLOWED_EDGES {
            for to in row.normal.iter().chain(row.dev) {
                assert!(names.contains(to), "{} -> {to}: no row for {to}", row.krate);
                assert_ne!(*to, row.krate, "{} depends on itself", row.krate);
            }
            for test_only in TEST_ONLY_CRATES {
                assert!(
                    !row.normal.contains(test_only),
                    "{} lists test-only {test_only} as a normal dependency",
                    row.krate
                );
            }
        }
    }

    #[test]
    fn reports_an_undeclared_edge() {
        let mut members = members_matching(ALLOWED_EDGES);
        member_mut(&mut members, "mooring-export")
            .edges
            .insert(edge(DependencyKind::Normal, "mooring-keys"));
        assert_eq!(
            check(&members, ALLOWED_EDGES, TEST_ONLY_CRATES),
            [Finding::UnexpectedEdge {
                from: "mooring-export".to_owned(),
                kind: DependencyKind::Normal,
                to: "mooring-keys".to_owned(),
            }]
        );
    }

    #[test]
    fn reports_a_missing_edge_and_a_kind_change() {
        let mut members = members_matching(ALLOWED_EDGES);
        let render = member_mut(&mut members, "mooring-render");
        assert!(
            render
                .edges
                .remove(&edge(DependencyKind::Dev, "mooring-keys"))
        );
        assert!(
            render
                .edges
                .insert(edge(DependencyKind::Build, "mooring-keys"))
        );
        assert_eq!(
            check(&members, ALLOWED_EDGES, TEST_ONLY_CRATES),
            [
                Finding::UnexpectedEdge {
                    from: "mooring-render".to_owned(),
                    kind: DependencyKind::Build,
                    to: "mooring-keys".to_owned(),
                },
                Finding::MissingEdge {
                    from: "mooring-render".to_owned(),
                    kind: DependencyKind::Dev,
                    to: "mooring-keys".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn rejects_a_test_only_crate_as_a_normal_or_build_dependency_even_if_tabled() {
        // A table that wrongly permits fixtures as a normal dependency must not hide it.
        let table = [
            AllowedEdges {
                krate: "mooring-store",
                normal: &["mooring-fixtures"],
                dev: &[],
            },
            AllowedEdges {
                krate: "mooring-keys",
                normal: &[],
                dev: &["mooring-fixtures"],
            },
            AllowedEdges {
                krate: "mooring-fixtures",
                normal: &[],
                dev: &[],
            },
        ];
        let mut members = members_matching(&table);
        member_mut(&mut members, "mooring-keys")
            .edges
            .insert(edge(DependencyKind::Build, "mooring-fixtures"));
        let test_only_findings: Vec<_> = check(&members, &table, TEST_ONLY_CRATES)
            .into_iter()
            .filter(|finding| matches!(finding, Finding::TestOnlyInProduction { .. }))
            .collect();
        assert_eq!(
            test_only_findings,
            [
                Finding::TestOnlyInProduction {
                    from: "mooring-keys".to_owned(),
                    kind: DependencyKind::Build,
                    to: "mooring-fixtures".to_owned(),
                },
                Finding::TestOnlyInProduction {
                    from: "mooring-store".to_owned(),
                    kind: DependencyKind::Normal,
                    to: "mooring-fixtures".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn reports_unlisted_members_and_stale_rows() {
        let mut members = members_matching(ALLOWED_EDGES);
        members.retain(|m| m.name != "mooring-store");
        members.push(MemberEdges {
            name: "mooring-unlisted".to_owned(),
            edges: BTreeSet::new(),
        });
        assert_eq!(
            check(&members, ALLOWED_EDGES, TEST_ONLY_CRATES),
            [
                Finding::UnlistedMember {
                    name: "mooring-unlisted".to_owned(),
                },
                Finding::StaleRow {
                    name: "mooring-store",
                },
            ]
        );
    }

    #[test]
    fn reads_edges_from_declared_path_dependencies_only() {
        let json = br#"{
            "packages": [
                {"id": "a", "name": "a", "version": "0.1.0", "manifest_path": "/w/a/Cargo.toml",
                 "features": {}, "dependencies": [
                    {"name": "b", "rename": null, "kind": null, "optional": true, "path": "/w/b"},
                    {"name": "b", "rename": "bee", "kind": "dev", "optional": false, "path": "/w/b"},
                    {"name": "serde", "rename": null, "kind": null, "optional": false},
                    {"name": "vendored", "rename": null, "kind": null, "optional": false, "path": "/w/vendor/v"}
                 ]},
                {"id": "b", "name": "b", "version": "0.1.0", "manifest_path": "/w/b/Cargo.toml",
                 "features": {}, "dependencies": []}
            ],
            "workspace_members": ["a", "b"], "resolve": null,
            "target_directory": "/w/target", "build_directory": "/w/target"
        }"#;
        let members = workspace_edges(&parse(json).unwrap()).unwrap();
        assert_eq!(members[0].name, "a");
        assert_eq!(
            members[0].edges,
            BTreeSet::from([
                edge(DependencyKind::Normal, "b"),
                edge(DependencyKind::Dev, "b")
            ])
        );
        assert!(members[1].edges.is_empty());
    }
}
