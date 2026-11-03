// SPDX-License-Identifier: GPL-3.0-or-later

//! Validation of a staged generation (design §11.2 step 3): every validator
//! must succeed with **zero** warning or error lines, and nothing is
//! switched before all have. Validator output reaches the Mac only as a
//! scrubbed [`StderrTail`]: the bundle's secrets are replaced before it
//! leaves the node.
//!
//! The host profile's validators (the sysctl keys, `sshd -t`,
//! `systemd-analyze verify`) follow the bundle's, on the generation's
//! staged `host/` files.

use std::fs;
use std::path::{Path, PathBuf};

use mooring_agent_proto::{AgentError, IoOp, ManagedFile, StderrTail, ValidationTool};
use serde_json::Value;

use super::stage::{GEOIP, HY2, XRAY, program};
use crate::host::{Node, Tool};
use crate::paths::Paths;
use crate::store::{Scratch, ensure_dir, io_error};

/// Every secret in a staged generation: the WireGuard keys, and in the
/// engine configurations every string under a key that holds a credential.
pub(crate) fn secrets(dir: &Path) -> Result<Vec<Vec<u8>>, AgentError> {
    Configs::read(dir).map(|configs| configs.secrets())
}

/// A staged generation's configurations that hold its secrets, each read
/// once: the tunnel's, and the engines' as JSON.
struct Configs {
    wg: Vec<u8>,
    xray: Value,
    hy2: Value,
}

impl Configs {
    fn read(dir: &Path) -> Result<Self, AgentError> {
        let read = |file: ManagedFile| {
            fs::read(dir.join(file.file_name())).map_err(|error| io_error(IoOp::ReadState, &error))
        };
        let json = |file: ManagedFile| {
            serde_json::from_slice(&read(file)?)
                .map_err(|_| crate::store::malformed(IoOp::ReadState))
        };
        Ok(Self {
            wg: read(ManagedFile::WgConf)?,
            xray: json(ManagedFile::XrayConfig)?,
            hy2: json(ManagedFile::Hy2Config)?,
        })
    }

    fn secrets(&self) -> Vec<Vec<u8>> {
        let mut found = Vec::new();
        for line in String::from_utf8_lossy(&self.wg).lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            if matches!(key.trim(), "PrivateKey" | "PresharedKey") && !value.trim().is_empty() {
                found.push(value.trim().as_bytes().to_vec());
            }
        }
        for value in [&self.xray, &self.hy2] {
            collect(value, false, &mut found);
        }
        found.sort();
        found.dedup();
        found
    }
}

/// The keys whose string values (or arrays of strings) are credentials in
/// the rendered Xray and sing-box configurations (design §8.2, §8.3).
const SECRET_KEYS: [&str; 5] = ["privateKey", "id", "password", "shortIds", "uuid"];

fn collect(value: &Value, secret: bool, found: &mut Vec<Vec<u8>>) {
    match value {
        Value::String(text) if secret && !text.is_empty() => found.push(text.as_bytes().to_vec()),
        Value::Array(items) => items.iter().for_each(|item| collect(item, secret, found)),
        Value::Object(fields) => fields
            .iter()
            .for_each(|(key, item)| collect(item, SECRET_KEYS.contains(&key.as_str()), found)),
        Value::String(_) | Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// Whether a validator's output holds a warning or error line: any line
/// with the word `warn`, `warning`, `error` or `fatal` in any case. Broad on
/// purpose, so that no engine's level spelling slips through.
pub(crate) fn has_warning(output: &[u8]) -> bool {
    String::from_utf8_lossy(output).lines().any(|line| {
        line.split(|c: char| !c.is_ascii_alphanumeric())
            .map(str::to_ascii_lowercase)
            .any(|word| matches!(word.as_str(), "warn" | "warning" | "error" | "fatal"))
    })
}

/// A validator of a bundle's files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Validator {
    /// `xray run -test` on a warning-level copy with the staged geodata.
    Xray,
    /// `mooring-hy2 check` on a warn-level copy.
    Hy2,
    /// `nft -c -f`.
    Nft,
    /// `wg-quick strip`.
    WgQuick,
}

impl Validator {
    /// The tool a failure names.
    pub(crate) const fn tool(self) -> ValidationTool {
        match self {
            Self::Xray => ValidationTool::Xray,
            Self::Hy2 => ValidationTool::Hy2,
            Self::Nft => ValidationTool::Nft,
            Self::WgQuick => ValidationTool::WgQuick,
        }
    }
}

/// The bundle validators, in the order they run; the first that fails ends
/// validation.
pub(crate) const BUNDLE_VALIDATORS: [Validator; 4] = [
    Validator::Xray,
    Validator::Hy2,
    Validator::Nft,
    Validator::WgQuick,
];

/// Runs every validator on the staged generation in `dir`.
pub(crate) fn validate(paths: &Paths, node: &dyn Node, dir: &Path) -> Result<(), AgentError> {
    let configs = Configs::read(dir)?;
    let secrets = configs.secrets();
    let scratch = paths.validate_dir();
    ensure_dir(&scratch).map_err(|error| io_error(IoOp::WriteState, &error))?;
    let xray_copy = warn_copy(
        configs.xray,
        scratch.join(ManagedFile::XrayConfig.file_name()),
        &["log", "loglevel"],
        "warning",
    )?;
    let hy2_copy = warn_copy(
        configs.hy2,
        scratch.join(ManagedFile::Hy2Config.file_name()),
        &["log", "level"],
        "warn",
    )?;
    let xray_arg = xray_copy.path().display().to_string();
    let hy2_arg = hy2_copy.path().display().to_string();
    let geodata_dir = dir.join(GEOIP.dir).display().to_string();
    let nft_file = dir
        .join(ManagedFile::Nftables.file_name())
        .display()
        .to_string();
    let wg_file = dir
        .join(ManagedFile::WgConf.file_name())
        .display()
        .to_string();
    let run = |validator: Validator| match validator {
        Validator::Xray => node.run_program(
            &program(dir, XRAY),
            &["run", "-test", "-c", &xray_arg],
            &[("XRAY_LOCATION_ASSET", &geodata_dir)],
        ),
        Validator::Hy2 => node.run_program(&program(dir, HY2), &["check", "-c", &hy2_arg], &[]),
        Validator::Nft => node.run(Tool::Nft, &["-c", "-f", &nft_file]),
        Validator::WgQuick => node.run(Tool::WgQuick, &["strip", &wg_file]),
    };
    let outcome = BUNDLE_VALIDATORS.into_iter().try_for_each(|validator| {
        let tool = validator.tool();
        let output = run(validator).map_err(|error| io_error(IoOp::SpawnProcess, &error))?;
        // `wg-quick strip` prints the configuration itself, private key
        // included, so only its stderr is judged and kept.
        let judged: Vec<u8> = if tool == ValidationTool::WgQuick {
            output.stderr.clone()
        } else {
            [output.stdout.as_slice(), output.stderr.as_slice()].concat()
        };
        if output.success && !has_warning(&judged) {
            Ok(())
        } else {
            let refs: Vec<&[u8]> = secrets.iter().map(Vec::as_slice).collect();
            Err(AgentError::StageValidation {
                tool,
                stderr_tail: StderrTail::scrubbed(&judged, &refs),
            })
        }
    });
    // The copies hold the bundle's secrets: they go before the host
    // validators run, and on any return before this, when dropped.
    drop((xray_copy, hy2_copy));
    outcome?;
    crate::hostfiles::validate(
        paths,
        node,
        &dir.join(crate::hostfiles::HOST_DIR),
        Some(dir),
    )
}

/// `config`, an engine's staged configuration, written to `copy` with the
/// log level at `path` set to `level`, so that the validator reports
/// warnings it would otherwise keep quiet. The copy is removed when
/// dropped.
fn warn_copy(
    mut config: Value,
    copy: PathBuf,
    path: &[&str; 2],
    level: &str,
) -> Result<Scratch, AgentError> {
    let malformed = || crate::store::malformed(IoOp::ReadState);
    let section = config
        .as_object_mut()
        .ok_or_else(malformed)?
        .entry(path[0])
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    section
        .as_object_mut()
        .ok_or_else(malformed)?
        .insert(path[1].to_owned(), Value::String(level.to_owned()));
    Scratch::write(copy, config.to_string().as_bytes())
        .map_err(|error| io_error(IoOp::WriteState, &error))
}
