// SPDX-License-Identifier: GPL-3.0-or-later

//! The engine artifacts a node runs (design §4, §5.1), from a directory
//! laid out as the hosted engine build's `out/`, which `cargo xtask
//! engines-verify` checks against `engines.lock.toml`:
//! `linux-<arch>/xray`, `linux-<arch>/mooring-hy2` and
//! `geodata/{geoip,geosite}.dat`. Each file must hash to the digest pinned
//! here, the lock's own (a test keeps the two equal), so a file changed or
//! damaged after the check is refused before it can reach a node. The
//! digests detect accidental corruption (design §12, Level 1).

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use mooring_agent_proto::{EngineSet, Sha256Hex};
use mooring_model::Sha256Digest;
use mooring_render::EngineCatalog;

use crate::error::LocalError;

/// The largest engine file read, in bytes.
const MAX_ENGINE_BYTES: u64 = 256 * 1024 * 1024;

/// The VPS engines and the geodata, by path in the directory, with the
/// digests `engines.lock.toml` pins (hosted run 39915405073, 2026-10-23).
pub(crate) const PINS: [(&str, &str); 6] = [
    (
        "linux-amd64/xray",
        "49e1f3b3a0c3c82cbcdb167e0eb604dc7125e7b86927f7431b994d9a8415f5cf",
    ),
    (
        "linux-arm64/xray",
        "b66ba500b9f654bbe3b34224ddc06390d4858c1157f14faa46b48f009ca6714b",
    ),
    (
        "linux-amd64/mooring-hy2",
        "dcf12e2314dd0a0897284fb4eb82adf2db931d3c14c20210c9547b3427b8dd58",
    ),
    (
        "linux-arm64/mooring-hy2",
        "0e8a249a7004acc30b9dd1d3cc737e0eedd0b16e13104ee5a6b1e4b077596ad2",
    ),
    (
        "geodata/geoip.dat",
        "3cf2236c19063c1c80803368cca5ff589c5033129fdf9ba154230c689b81fc2a",
    ),
    (
        "geodata/geosite.dat",
        "51211fde21696bbde05d1102f47f586261e98987a3cae23f7dd1cd742c62c2d2",
    ),
];

/// The pins an engine directory is checked against: `(path, digest)`
/// pairs, [`PINS`] in the binary.
pub(crate) type Pins<'a> = &'a [(&'a str, &'a str)];

/// A checked engine directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Engines<'p> {
    dir: PathBuf,
    pins: Pins<'p>,
    catalog: EngineCatalog,
}

impl<'p> Engines<'p> {
    /// Checks every pinned file in `dir` against its pin.
    pub(crate) fn open(dir: &Path, pins: Pins<'p>) -> Result<Self, LocalError> {
        for (path, _) in pins {
            read_pinned(dir, pins, path)?;
        }
        let pin = |path: &str| -> Result<Sha256Hex, LocalError> {
            pins.iter()
                .find(|(pinned, _)| *pinned == path)
                .and_then(|(_, hex)| parse_hex(hex))
                .ok_or_else(|| LocalError::EngineFile {
                    path: dir.join(path),
                })
        };
        let set = |arch: &str| -> Result<EngineSet, LocalError> {
            Ok(EngineSet {
                xray: pin(&format!("linux-{arch}/xray"))?,
                hy2: pin(&format!("linux-{arch}/mooring-hy2"))?,
                geoip: pin("geodata/geoip.dat")?,
                geosite: pin("geodata/geosite.dat")?,
            })
        };
        Ok(Self {
            dir: dir.to_path_buf(),
            pins,
            catalog: EngineCatalog {
                amd64: set("amd64")?,
                arm64: set("arm64")?,
            },
        })
    }

    /// The engines for every architecture.
    pub(crate) const fn catalog(&self) -> &EngineCatalog {
        &self.catalog
    }

    /// The bytes of the pinned file whose digest is `sha256`, checked
    /// again as they are read; `None` when no engine has that digest.
    pub(crate) fn blob(&self, sha256: &Sha256Hex) -> Result<Option<Vec<u8>>, LocalError> {
        for (path, hex) in self.pins {
            if parse_hex(hex).as_ref() == Some(sha256) {
                return read_pinned(&self.dir, self.pins, path).map(Some);
            }
        }
        Ok(None)
    }
}

/// The file `path` in `dir`, which must hash to its pin.
fn read_pinned(dir: &Path, pins: Pins<'_>, path: &str) -> Result<Vec<u8>, LocalError> {
    let full = dir.join(path);
    let failed = |source| LocalError::EngineRead {
        path: full.clone(),
        source,
    };
    let mut bytes = Vec::new();
    File::open(&full)
        .map_err(failed)?
        .take(MAX_ENGINE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(failed)?;
    let pinned = pins
        .iter()
        .find(|(pinned, _)| *pinned == path)
        .and_then(|(_, hex)| parse_hex(hex));
    let actual = Sha256Hex::from_bytes(*Sha256Digest::of(&bytes).as_bytes());
    if bytes.len() as u64 > MAX_ENGINE_BYTES || pinned != Some(actual) {
        return Err(LocalError::EngineDigest {
            path: full,
            actual: actual.to_string(),
        });
    }
    Ok(bytes)
}

/// A pinned digest: 64 lowercase hex characters, as the protocol parses
/// one.
pub(crate) fn parse_hex(text: &str) -> Option<Sha256Hex> {
    text.parse().ok()
}
