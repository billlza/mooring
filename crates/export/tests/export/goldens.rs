// SPDX-License-Identifier: GPL-3.0-or-later

//! Byte-exact export goldens (design §9.3 item 3) for every fixture
//! deployment × format × client profile, in `contract/golden/<fixture>/`.
//!
//! Each golden is the fixture's first user re-profiled to the profile. A
//! snapshot holds the document without its final newline (insta trims
//! trailing whitespace), so the newline is asserted separately. Clash
//! goldens are also read back with saphyr to prove they are YAML whose
//! scalars have the intended types.

use std::collections::BTreeSet;
use std::path::Path;

use mooring_export::ExportFormat;
use saphyr::YamlOwned;

use crate::support::{export, first_user, fixtures, keys, parse, profiles, text, with_profile};

fn assert_golden(fixture: &str, name: &str, document: &str) {
    let body = document
        .strip_suffix('\n')
        .expect("a document ends with a newline");
    assert!(
        !body.ends_with(char::is_whitespace),
        "{name}: one final newline"
    );
    assert!(!document.contains('\r'), "{name}: LF line endings");
    let mut settings = insta::Settings::clone_current();
    settings.set_snapshot_path(format!("../../../../contract/golden/{fixture}"));
    settings.set_prepend_module_to_snapshot(false);
    settings.set_omit_expression(true);
    settings.set_description(
        "SPDX-License-Identifier: GPL-3.0-or-later. mooring-export user export (design 9.1); \
         the file is this text plus one newline.",
    );
    settings.bind(|| insta::assert_snapshot!(name, body));
}

/// One export golden: the fixture directory, the snapshot name (without
/// `.snap`), the format and the document text.
struct Golden {
    fixture: &'static str,
    name: String,
    format: ExportFormat,
    document: String,
}

/// Every fixture's first user, re-profiled to every profile, in every
/// format.
fn export_goldens() -> Vec<Golden> {
    let mut goldens = Vec::new();
    for fixture in fixtures() {
        let user = first_user(&fixture);
        for profile in profiles() {
            let deployment = with_profile(&fixture.deployment, &user, &profile.profile);
            for format in ExportFormat::ALL {
                let document = export(&fixture, &deployment, &user, format);
                goldens.push(Golden {
                    fixture: fixture.name,
                    name: format!("export-{}-{}", format.name(), profile.name),
                    format,
                    document: text(&document).to_owned(),
                });
            }
        }
    }
    goldens
}

#[test]
fn export_goldens_match() {
    for golden in export_goldens() {
        assert_golden(golden.fixture, &golden.name, &golden.document);
        match golden.format {
            ExportFormat::SingBoxJson => check_json(&golden.document),
            ExportFormat::ClashYaml => check_yaml(&golden.document),
        }
    }
}

/// The `export-*` files of `contract/golden/` are exactly the goldens
/// [`export_goldens_match`] asserts, so a golden left behind for a removed
/// fixture, format or profile fails here (design §16 L2, "a stale
/// golden"). mooring-render's tests own the directory's other files.
#[test]
fn the_golden_directories_hold_exactly_the_exported_documents() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contract/golden");
    let mut found = BTreeSet::new();
    for directory in std::fs::read_dir(root).unwrap() {
        let directory = directory.unwrap();
        let directory_name = directory.file_name().into_string().unwrap();
        for file in std::fs::read_dir(directory.path()).unwrap() {
            let file_name = file.unwrap().file_name().into_string().unwrap();
            if file_name.starts_with("export-") {
                found.insert((directory_name.clone(), file_name));
            }
        }
    }
    let exported: BTreeSet<_> = export_goldens()
        .into_iter()
        .map(|golden| (golden.fixture.to_owned(), format!("{}.snap", golden.name)))
        .collect();
    assert_eq!(found, exported);
}

fn check_json(document: &str) {
    let value: serde_json::Value = serde_json::from_str(document).unwrap();
    let root = value.as_object().unwrap();
    assert_eq!(root.keys().collect::<Vec<_>>(), ["outbounds"]);
    assert!(!root["outbounds"].as_array().unwrap().is_empty());
}

/// Keys whose values are YAML integers; every other scalar but the
/// booleans is a string.
const INTEGER_KEYS: [&str; 2] = ["port", "hop-interval"];
const BOOLEAN_KEYS: [&str; 2] = ["tls", "support-x25519mlkem768"];

fn check_yaml(document: &str) {
    let root = parse(document);
    assert_eq!(keys(&root), ["proxies"]);
    let proxies = root["proxies"].as_vec().unwrap();
    assert!(!proxies.is_empty());
    for proxy in proxies {
        check_scalar_types(proxy);
    }
    check_quoting(document);
}

fn check_scalar_types(mapping: &YamlOwned) {
    for (key, value) in mapping.as_mapping().unwrap() {
        let key = key.as_str().unwrap();
        if value.is_mapping() {
            check_scalar_types(value);
        } else if INTEGER_KEYS.contains(&key) {
            assert!(value.is_integer(), "{key} is an integer");
        } else if BOOLEAN_KEYS.contains(&key) {
            assert_eq!(value.as_bool(), Some(true), "{key} is plain true");
        } else {
            assert!(value.is_string(), "{key} is a string");
        }
    }
}

/// Every string scalar is double-quoted; integers and booleans are plain;
/// keys are plain identifiers.
fn check_quoting(document: &str) {
    for line in document.lines().skip(1) {
        let entry = line.trim_start().trim_start_matches("- ");
        let (key, value) = entry.split_once(':').unwrap();
        assert!(
            key.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "plain key {key:?}"
        );
        let value = value.strip_prefix(' ').unwrap_or(value);
        let plain_ok = value.is_empty()
            || value == "true"
            || value.bytes().all(|b| b.is_ascii_digit())
            || (value.starts_with('"') && value.ends_with('"') && value.len() >= 2);
        assert!(
            plain_ok,
            "value of {key} is quoted, an integer, true or a block"
        );
    }
}
