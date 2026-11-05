// SPDX-License-Identifier: GPL-3.0-or-later

//! An engine directory checked against its pins (design §4, §5.1): a pin
//! table that lacks an engine the catalog needs is refused, naming where
//! the file would be; a blob no engine has is none, and one an engine has
//! is that engine's bytes.

use std::fs;
use std::path::Path;

use mooring_agent_proto::Sha256Hex;
use mooring_model::Sha256Digest;

use crate::error::LocalError;
use crate::node::engines::{Engines, PINS};

/// Stand-in files for `paths` in `dir`, and their pins.
fn stand_ins(dir: &Path, paths: &[&'static str]) -> Vec<(&'static str, String)> {
    paths
        .iter()
        .map(|path| {
            let file = dir.join(path);
            fs::create_dir_all(file.parent().unwrap()).unwrap();
            let bytes = format!("stand-in for {path}");
            fs::write(&file, &bytes).unwrap();
            (*path, Sha256Digest::of(bytes.as_bytes()).to_string())
        })
        .collect()
}

fn as_pins<'a>(owned: &'a [(&'static str, String)]) -> Vec<(&'static str, &'a str)> {
    owned
        .iter()
        .map(|(path, hex)| (*path, hex.as_str()))
        .collect()
}

#[test]
fn a_pin_table_without_an_engine_the_catalog_needs_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let paths: Vec<&'static str> = PINS
        .iter()
        .map(|(path, _)| *path)
        .filter(|path| *path != "linux-arm64/mooring-hy2")
        .collect();
    let owned = stand_ins(dir.path(), &paths);
    let pins = as_pins(&owned);
    let error = Engines::open(dir.path(), &pins).unwrap_err();
    assert!(
        matches!(&error, LocalError::EngineFile { path } if *path == dir.path().join("linux-arm64/mooring-hy2")),
        "{error:?}"
    );
}

#[test]
fn a_blob_is_an_engine_s_bytes_or_none() {
    let dir = tempfile::tempdir().unwrap();
    let paths: Vec<&'static str> = PINS.iter().map(|(path, _)| *path).collect();
    let owned = stand_ins(dir.path(), &paths);
    let pins = as_pins(&owned);
    let engines = Engines::open(dir.path(), &pins).unwrap();
    assert_eq!(engines.blob(&Sha256Hex::from_bytes([7; 32])).unwrap(), None);
    let geoip: Sha256Hex = pins
        .iter()
        .find(|(path, _)| *path == "geodata/geoip.dat")
        .unwrap()
        .1
        .parse()
        .unwrap();
    assert_eq!(
        engines.blob(&geoip).unwrap(),
        Some(b"stand-in for geodata/geoip.dat".to_vec())
    );
}
