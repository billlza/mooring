// SPDX-License-Identifier: GPL-3.0-or-later

//! Validation of a staged generation (design §11.2 step 3): every validator
//! must succeed with **zero** warning or error lines, and nothing is
//! switched before all have. Validator output reaches the Mac only as a
//! scrubbed [`StderrTail`]: the bundle's secrets are replaced before it
//! leaves the node.
//!
//! Host-profile validators (`sshd -t`, `systemd-analyze verify`, the sysctl
//! keys) join with host-profile convergence in M4e.

use std::fs;
use std::path::Path;

use mooring_agent_proto::{AgentError, IoOp, ManagedFile, StderrTail, ValidationTool};
use serde_json::Value;

use super::stage::{GEOIP, HY2, XRAY, program};
use crate::host::{Node, Tool};
use crate::paths::Paths;
use crate::store::{ensure_dir, io_error};

/// Every secret in a staged generation: the WireGuard keys, and in the
/// engine configurations every string under a key that holds a credential.
pub(crate) fn secrets(dir: &Path) -> Result<Vec<Vec<u8>>, AgentError> {
    let read = |file: ManagedFile| {
        fs::read(dir.join(file.file_name())).map_err(|error| io_error(IoOp::ReadState, &error))
    };
    let mut found = Vec::new();
    let wg = read(ManagedFile::WgConf)?;
    for line in String::from_utf8_lossy(&wg).lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if matches!(key.trim(), "PrivateKey" | "PresharedKey") && !value.trim().is_empty() {
            found.push(value.trim().as_bytes().to_vec());
        }
    }
    for file in [ManagedFile::XrayConfig, ManagedFile::Hy2Config] {
        let value: Value = serde_json::from_slice(&read(file)?)
            .map_err(|_| crate::store::malformed(IoOp::ReadState))?;
        collect(&value, false, &mut found);
    }
    found.sort();
    found.dedup();
    Ok(found)
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
    let secrets = secrets(dir)?;
    let scratch = paths.validate_dir();
    ensure_dir(&scratch).map_err(|error| io_error(IoOp::WriteState, &error))?;
    let xray_copy = warn_copy(
        dir,
        ManagedFile::XrayConfig,
        &scratch,
        &["log", "loglevel"],
        "warning",
    )?;
    let hy2_copy = warn_copy(
        dir,
        ManagedFile::Hy2Config,
        &scratch,
        &["log", "level"],
        "warn",
    )?;
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
            &["run", "-test", "-c", &xray_copy],
            &[("XRAY_LOCATION_ASSET", &geodata_dir)],
        ),
        Validator::Hy2 => node.run_program(&program(dir, HY2), &["check", "-c", &hy2_copy], &[]),
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
    for copy in [&xray_copy, &hy2_copy] {
        let _absent = fs::remove_file(copy);
    }
    outcome
}

/// A copy of a staged JSON configuration in `scratch` with the log level
/// at `path` set to `level`, so the validator reports warnings it would
/// otherwise keep quiet. Returns the copy's path.
fn warn_copy(
    dir: &Path,
    file: ManagedFile,
    scratch: &Path,
    path: &[&str; 2],
    level: &str,
) -> Result<String, AgentError> {
    let malformed = || crate::store::malformed(IoOp::ReadState);
    let mut value: Value = serde_json::from_slice(
        &fs::read(dir.join(file.file_name())).map_err(|error| io_error(IoOp::ReadState, &error))?,
    )
    .map_err(|_| malformed())?;
    let section = value
        .as_object_mut()
        .ok_or_else(malformed)?
        .entry(path[0])
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    section
        .as_object_mut()
        .ok_or_else(malformed)?
        .insert(path[1].to_owned(), Value::String(level.to_owned()));
    let copy = scratch.join(file.file_name());
    let bytes = serde_json::to_vec(&value).map_err(|_| malformed())?;
    crate::store::write_atomic(&copy, &bytes, 0o600)
        .map_err(|error| io_error(IoOp::WriteState, &error))?;
    Ok(copy.display().to_string())
}
