// SPDX-License-Identifier: GPL-3.0-or-later

//! The crate versions in the `cargo deny` graph, computed from
//! `cargo metadata --all-features --filter-platform <target>…`.
//!
//! `cargo metadata` lists optional dependencies that are only named through
//! weak features (`dep?/feature`) as resolved edges even though cargo never
//! builds them. Like `cargo deny`, an optional edge is kept only when an
//! activated feature of the parent enables it (`dep:name` or `name/feature`).
//! Workspace members are the roots; dev-dependencies of members are included.

use std::collections::{BTreeMap, BTreeSet};

use crate::metadata::{Dependency, DependencyKind, Metadata, Node, Package, PackageId};

use crate::version::{Version, VersionError};

#[derive(Debug, thiserror::Error)]
pub(crate) enum GraphError {
    #[error("cargo metadata has no resolve graph")]
    NoResolve,
    #[error("the resolve graph references package {0}, which is not in the package list")]
    UnknownPackage(PackageId),
    #[error("package {0} has no node in the resolve graph")]
    MissingNode(PackageId),
    #[error("{parent} -> {child} ({kind}) is resolved but not declared in {parent}'s manifest")]
    UndeclaredEdge {
        parent: PackageId,
        child: PackageId,
        kind: DependencyKind,
    },
    #[error("package {package}")]
    Version {
        package: PackageId,
        #[source]
        source: VersionError,
    },
}

/// Every crate name in the graph with the set of its versions.
pub(crate) type CrateVersions = BTreeMap<String, BTreeSet<Version>>;

pub(crate) fn crate_versions(metadata: &Metadata) -> Result<CrateVersions, GraphError> {
    let resolve = metadata.resolve.as_ref().ok_or(GraphError::NoResolve)?;
    let packages: BTreeMap<&PackageId, &Package> = metadata
        .packages
        .iter()
        .map(|package| (&package.id, package))
        .collect();
    let nodes: BTreeMap<&PackageId, &Node> =
        resolve.nodes.iter().map(|node| (&node.id, node)).collect();
    let lookup = |id: &PackageId| {
        packages
            .get(id)
            .copied()
            .ok_or_else(|| GraphError::UnknownPackage(id.clone()))
    };

    let mut reachable: BTreeSet<&PackageId> = BTreeSet::new();
    let mut pending: Vec<&PackageId> = metadata.workspace_members.iter().collect();
    while let Some(id) = pending.pop() {
        if !reachable.insert(id) {
            continue;
        }
        let package = lookup(id)?;
        let node = nodes
            .get(id)
            .ok_or_else(|| GraphError::MissingNode(id.clone()))?;
        for dep in &node.deps {
            let child = lookup(&dep.pkg)?;
            let mut active = false;
            for kind_info in &dep.dep_kinds {
                active |= edge_active(package, node, child, kind_info.kind)?;
            }
            if active {
                pending.push(&dep.pkg);
            }
        }
    }

    let mut versions = CrateVersions::new();
    for id in reachable {
        let package = lookup(id)?;
        let version = Version::parse(&package.version).map_err(|source| GraphError::Version {
            package: id.clone(),
            source,
        })?;
        versions
            .entry(package.name.clone())
            .or_default()
            .insert(version);
    }
    Ok(versions)
}

/// Whether `parent` really depends on `child` with `kind`: some matching
/// declaration is either not optional or enabled by an activated feature.
fn edge_active(
    parent: &Package,
    node: &Node,
    child: &Package,
    kind: DependencyKind,
) -> Result<bool, GraphError> {
    let declared: Vec<&Dependency> = parent
        .dependencies
        .iter()
        .filter(|dependency| dependency.name == child.name && dependency.kind == kind)
        .collect();
    if declared.is_empty() {
        return Err(GraphError::UndeclaredEdge {
            parent: parent.id.clone(),
            child: child.id.clone(),
            kind,
        });
    }
    Ok(declared
        .iter()
        .any(|dependency| !dependency.optional || optional_enabled(parent, node, dependency.key())))
}

/// `dep:<key>` or a non-weak `<key>/<feature>` in an activated feature.
fn optional_enabled(parent: &Package, node: &Node, key: &str) -> bool {
    node.features
        .iter()
        .filter_map(|feature| parent.features.get(feature))
        .flatten()
        .any(|entry| {
            entry.strip_prefix("dep:") == Some(key)
                || entry.split_once('/').is_some_and(|(dep, _)| dep == key)
        })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{GraphError, crate_versions};
    use crate::metadata::parse;
    use crate::version::Version;

    /// A workspace `app` with a normal dependency on `lib` 1.0.0, which has
    /// an optional `opt` reachable only through a weak feature, and a
    /// dev-dependency on `lib` 2.0.0 (renamed `lib2`).
    const METADATA: &str = r#"{
        "packages": [
            {"id": "app", "name": "app", "version": "0.1.0", "manifest_path": "/w/app/Cargo.toml",
             "features": {},
             "dependencies": [
                {"name": "lib", "rename": null, "kind": null, "optional": false},
                {"name": "lib", "rename": "lib2", "kind": "dev", "optional": false}
             ]},
            {"id": "lib1", "name": "lib", "version": "1.0.0", "manifest_path": "/r/lib1/Cargo.toml",
             "features": {"std": ["opt?/std", "on/std"], "opt": ["dep:opt"], "on": ["dep:on"]},
             "dependencies": [
                {"name": "opt", "rename": null, "kind": null, "optional": true},
                {"name": "on", "rename": null, "kind": null, "optional": true}
             ]},
            {"id": "lib2", "name": "lib", "version": "2.0.0", "manifest_path": "/r/lib2/Cargo.toml",
             "features": {}, "dependencies": []},
            {"id": "opt", "name": "opt", "version": "0.1.0", "manifest_path": "/r/opt/Cargo.toml",
             "features": {}, "dependencies": []},
            {"id": "on", "name": "on", "version": "0.3.0", "manifest_path": "/r/on/Cargo.toml",
             "features": {}, "dependencies": []}
        ],
        "workspace_members": ["app"],
        "resolve": {"nodes": [
            {"id": "app", "features": [], "deps": [
                {"pkg": "lib1", "dep_kinds": [{"kind": null, "target": null}]},
                {"pkg": "lib2", "dep_kinds": [{"kind": "dev", "target": null}]}
            ]},
            {"id": "lib1", "features": ["std"], "deps": [
                {"pkg": "opt", "dep_kinds": [{"kind": null, "target": null}]},
                {"pkg": "on", "dep_kinds": [{"kind": null, "target": null}]}
            ]},
            {"id": "lib2", "features": [], "deps": []},
            {"id": "opt", "features": [], "deps": []},
            {"id": "on", "features": [], "deps": []}
        ]},
        "target_directory": "/w/target", "build_directory": "/w/target"
    }"#;

    fn versions(texts: &[&str]) -> BTreeSet<Version> {
        texts
            .iter()
            .map(|text| Version::parse(text).unwrap())
            .collect()
    }

    #[test]
    fn includes_dev_dependencies_and_prunes_weak_feature_edges() {
        let graph = crate_versions(&parse(METADATA.as_bytes()).unwrap()).unwrap();
        let names: Vec<_> = graph.keys().map(String::as_str).collect();
        assert_eq!(names, ["app", "lib", "on"]);
        assert_eq!(graph["lib"], versions(&["1.0.0", "2.0.0"]));
    }

    #[test]
    fn an_explicitly_enabled_optional_dependency_is_kept() {
        let enabled = METADATA.replace(r#""features": ["std"]"#, r#""features": ["opt", "std"]"#);
        let graph = crate_versions(&parse(enabled.as_bytes()).unwrap()).unwrap();
        assert!(graph.contains_key("opt"));
    }

    #[test]
    fn a_resolved_edge_without_a_declaration_is_an_error() {
        let undeclared = METADATA.replace(
            r#"{"name": "lib", "rename": "lib2", "kind": "dev", "optional": false}"#,
            r#"{"name": "lib", "rename": "lib2", "kind": "build", "optional": false}"#,
        );
        assert!(matches!(
            crate_versions(&parse(undeclared.as_bytes()).unwrap()),
            Err(GraphError::UndeclaredEdge { .. })
        ));
    }

    #[test]
    fn metadata_without_a_resolve_graph_is_an_error() {
        let no_deps = r#"{"packages": [], "workspace_members": [], "resolve": null,
            "target_directory": "/w/target", "build_directory": "/w/target"}"#;
        assert!(matches!(
            crate_versions(&parse(no_deps.as_bytes()).unwrap()),
            Err(GraphError::NoResolve)
        ));
    }
}
