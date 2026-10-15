// SPDX-License-Identifier: GPL-3.0-or-later

//! The lint tables of the workspace's manifests (design §6.2): every
//! member inherits `[workspace.lints]`, except `mooring-macsys`, the one
//! crate allowed `unsafe`, which cannot inherit them (they forbid
//! `unsafe_code`). Its tables must equal the workspace's without
//! `unsafe_code`, plus exactly the three unsafe-discipline lints, so the
//! two cannot drift apart.

use std::fs;
use std::path::Path;

use toml::{Table, Value};

use crate::testing::workspace_root;

/// The member that repeats the lint tables.
const UNSAFE_MEMBER: &str = "crates/macsys";

fn manifest(dir: &Path) -> Table {
    toml::from_str(&fs::read_to_string(dir.join("Cargo.toml")).unwrap()).unwrap()
}

fn table<'a>(table: &'a Table, path: &[&str]) -> &'a Table {
    path.iter().fold(table, |table, key| {
        table
            .get(*key)
            .and_then(Value::as_table)
            .unwrap_or_else(|| panic!("no table {path:?}"))
    })
}

fn deny() -> Value {
    Value::String("deny".to_owned())
}

/// The lint tables `crates/macsys` must have, derived from the workspace's.
fn expected_unsafe_member_lints(workspace: &Table) -> (Table, Table) {
    let mut rust = table(workspace, &["workspace", "lints", "rust"]).clone();
    assert_eq!(
        rust.remove("unsafe_code"),
        Some(Value::String("forbid".to_owned())),
        "the workspace forbids unsafe code"
    );
    rust.insert("unsafe_op_in_unsafe_fn".to_owned(), deny());
    let mut clippy = table(workspace, &["workspace", "lints", "clippy"]).clone();
    for lint in [
        "undocumented_unsafe_blocks",
        "multiple_unsafe_ops_per_block",
    ] {
        assert!(clippy.insert(lint.to_owned(), deny()).is_none(), "{lint}");
    }
    (rust, clippy)
}

#[test]
fn macsys_lints_are_the_workspace_lints_with_unsafe_allowed() {
    let root = workspace_root();
    let workspace = manifest(&root);
    let members: Vec<&str> = table(&workspace, &["workspace"])
        .get("members")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .map(|member| member.as_str().unwrap())
        .collect();
    assert!(members.contains(&UNSAFE_MEMBER));
    let inherit: Table = toml::from_str("workspace = true").unwrap();
    for member in members {
        let lints = table(&manifest(&root.join(member)), &["lints"]).clone();
        if member == UNSAFE_MEMBER {
            let (rust, clippy) = expected_unsafe_member_lints(&workspace);
            let mut expected = Table::new();
            expected.insert("rust".to_owned(), Value::Table(rust));
            expected.insert("clippy".to_owned(), Value::Table(clippy));
            assert_eq!(lints, expected, "{member}");
        } else {
            assert_eq!(lints, inherit, "{member} inherits the workspace lints");
        }
    }
}
