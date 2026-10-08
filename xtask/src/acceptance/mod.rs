// SPDX-License-Identifier: GPL-3.0-or-later

//! `acceptance` and `release-acceptance` (design §9.3 item 2, §16 L7): the
//! export contract files checked against the shapes
//! `mooring_export::shapes()` enumerates.
//!
//! Both commands require `contract/cfm-manifest.toml` to parse, with
//! importer digests that match their objects, and to describe exactly the
//! enumerated client lines. Then:
//!
//! - `acceptance` ([`Gate::Recorded`], a step of `cargo xtask ci`) requires
//!   `contract/cfm-acceptance.toml` to record every enumerated shape once
//!   per client line, and nothing else ([`AcceptanceFile::require_recorded`]);
//!   a pending entry counts as recorded.
//! - `release-acceptance` ([`Gate::Accepted`], the release gate) also
//!   requires every entry to be accepted by real CFM against its line's
//!   current importer digest ([`AcceptanceFile::require_accepted`]). It
//!   fails until M6 has imported every shape into real CFM.

mod file;
mod manifest;
mod object_id;

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use mooring_export::Shape;

use crate::cargo::Cargo;
use crate::output::{OutputError, say};

use self::file::{AcceptanceFile, Entry, FileError, GateError};
use self::manifest::{CfmManifest, ManifestError};

/// The acceptance record, relative to the workspace root.
const ACCEPTANCE_FILE: &str = "contract/cfm-acceptance.toml";
/// The CFM revisions it is checked against, relative to the workspace root.
const MANIFEST_FILE: &str = "contract/cfm-manifest.toml";

/// The gate a command requires of the acceptance file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Gate {
    /// Every enumerated shape is recorded; pending entries count (`ci`).
    Recorded,
    /// Every enumerated shape is accepted by real CFM (release verification).
    Accepted,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum AcceptanceError {
    #[error("failed to read {}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot use {}", path.display())]
    Manifest {
        path: PathBuf,
        #[source]
        source: ManifestError,
    },
    #[error("cannot use {}", path.display())]
    File {
        path: PathBuf,
        #[source]
        source: FileError,
    },
    #[error("{} fails the acceptance gate", path.display())]
    Gate {
        path: PathBuf,
        #[source]
        source: GateError,
    },
    #[error(transparent)]
    Output(#[from] OutputError),
}

/// A contract file's text and the path it was read from.
#[derive(Debug)]
struct Source {
    path: PathBuf,
    text: String,
}

impl Source {
    fn read(path: PathBuf) -> Result<Self, AcceptanceError> {
        match fs::read_to_string(&path) {
            Ok(text) => Ok(Self { path, text }),
            Err(source) => Err(AcceptanceError::Read { path, source }),
        }
    }
}

/// Both contract files, parsed and past the gate.
#[derive(Debug)]
struct Checked {
    manifest: CfmManifest,
    file: AcceptanceFile,
    shapes: usize,
}

pub(crate) fn run(cargo: &Cargo, out: &mut impl Write, gate: Gate) -> Result<(), AcceptanceError> {
    let root = cargo.workspace_root();
    let manifest = Source::read(root.join(MANIFEST_FILE))?;
    let acceptance = Source::read(root.join(ACCEPTANCE_FILE))?;
    let checked = check(&manifest, &acceptance, &mooring_export::shapes(), gate)?;
    report(out, &checked, gate)
}

/// Parses both files and requires `gate` of them against `shapes`.
fn check(
    manifest: &Source,
    acceptance: &Source,
    shapes: &[Shape],
    gate: Gate,
) -> Result<Checked, AcceptanceError> {
    let manifest_error = |source| AcceptanceError::Manifest {
        path: manifest.path.clone(),
        source,
    };
    let parsed = CfmManifest::parse(&manifest.text).map_err(manifest_error)?;
    let lines: BTreeSet<&str> = shapes.iter().map(Shape::line_name).collect();
    parsed.require_lines(&lines).map_err(manifest_error)?;
    let file = AcceptanceFile::parse(&acceptance.text).map_err(|source| AcceptanceError::File {
        path: acceptance.path.clone(),
        source,
    })?;
    match gate {
        Gate::Recorded => file.require_recorded(shapes),
        Gate::Accepted => file.require_accepted(shapes, &parsed),
    }
    .map_err(|source| AcceptanceError::Gate {
        path: acceptance.path.clone(),
        source,
    })?;
    Ok(Checked {
        manifest: parsed,
        file,
        shapes: shapes.len(),
    })
}

fn report(out: &mut impl Write, checked: &Checked, gate: Gate) -> Result<(), AcceptanceError> {
    for (line, revision) in checked.manifest.lines() {
        say!(out, "acceptance: {line}: {revision}")?;
    }
    for accepted in checked.file.accepted() {
        say!(out, "acceptance: {accepted}")?;
    }
    match gate {
        Gate::Recorded => {
            let pending = checked
                .file
                .entries()
                .iter()
                .filter(|entry| matches!(entry, Entry::Pending(_)))
                .count();
            let accepted = checked.file.accepted().count();
            say!(
                out,
                "acceptance: {ACCEPTANCE_FILE} records all {} enumerated shape(s); {accepted} accepted, {pending} pending real CFM import",
                checked.shapes
            )?;
        }
        Gate::Accepted => say!(
            out,
            "acceptance: release gate met: all {} enumerated shape(s) accepted by real CFM against the current importer digests",
            checked.shapes
        )?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use mooring_export::shapes;

    use super::file::GateError;
    use super::manifest::ManifestError;
    use super::{ACCEPTANCE_FILE, AcceptanceError, Gate, MANIFEST_FILE, Source, check, report};

    const CONTRACT: &str = include_str!("../../../contract/cfm-acceptance.toml");
    const MANIFEST: &str = include_str!("../../../contract/cfm-manifest.toml");

    fn manifest(text: &str) -> Source {
        Source {
            path: MANIFEST_FILE.into(),
            text: text.to_owned(),
        }
    }

    fn acceptance(text: &str) -> Source {
        Source {
            path: ACCEPTANCE_FILE.into(),
            text: text.to_owned(),
        }
    }

    /// The contract file without its last entry.
    fn without_last_entry() -> String {
        let (kept, _last) = CONTRACT.rsplit_once("[[shape]]").unwrap();
        kept.to_owned()
    }

    #[test]
    fn the_contract_passes_the_ci_gate_and_reports_a_one_line_count() {
        let checked = check(
            &manifest(MANIFEST),
            &acceptance(CONTRACT),
            &shapes(),
            Gate::Recorded,
        )
        .unwrap();
        let mut out = Vec::new();
        report(&mut out, &checked, Gate::Recorded).unwrap();
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3, "{text}");
        assert!(lines[0].starts_with("acceptance: cfm04: CFM 0.4 at "));
        assert!(lines[1].starts_with("acceptance: cfm05: CFM 0.5 at "));
        assert_eq!(
            lines[2],
            "acceptance: contract/cfm-acceptance.toml records all 10 enumerated shape(s); \
             0 accepted, 10 pending real CFM import"
        );
    }

    #[test]
    fn the_report_lists_accepted_entries_and_counts_both_kinds() {
        let pending = "status = \"pending-real-cfm-import\"\n";
        let first_accepted = CONTRACT.replacen(
            pending,
            "status = \"accepted\"\n\
             importer_digest = \"be5ad5c27b251901a77ee5912812282c9b8088535868c5e2994973b5dbf267e7\"\n\
             cfm_build = 40073\nbundle_version = \"0.4.0\"\nsing_box_core = \"1.14.1\"\n\
             export_sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n\
             import_date = 2026-10-20\nconnect = \"connected\"\n\
             evidence_sha256 = \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"\n",
            1,
        );
        assert_ne!(first_accepted, CONTRACT);
        let checked = check(
            &manifest(MANIFEST),
            &acceptance(&first_accepted),
            &shapes(),
            Gate::Recorded,
        )
        .unwrap();
        let mut out = Vec::new();
        report(&mut out, &checked, Gate::Recorded).unwrap();
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 4, "{text}");
        assert!(
            lines[2].starts_with("acceptance: cfm04 sing-box-json/vless-reality/chrome "),
            "{text}"
        );
        assert!(lines[2].contains(" accepted: CFM build 40073, bundle 0.4.0, sing-box 1.14.1, "));
        assert_eq!(
            lines[3],
            "acceptance: contract/cfm-acceptance.toml records all 10 enumerated shape(s); \
             1 accepted, 9 pending real CFM import"
        );
        // The release gate still fails, on the nine pending entries.
        let error = check(
            &manifest(MANIFEST),
            &acceptance(&first_accepted),
            &shapes(),
            Gate::Accepted,
        )
        .unwrap_err();
        assert!(
            matches!(
                &error,
                AcceptanceError::Gate { source: GateError::NotAccepted { pending }, .. }
                    if pending.len() == 9
            ),
            "{error:?}"
        );
    }

    /// The contract file with every entry accepted by a build of its line
    /// (contract/cfm-manifest.toml: 0.4 with v1.14.1, 0.5 with v1.14.2).
    fn all_accepted() -> String {
        let (header, entries) = CONTRACT.split_once("[[shape]]").unwrap();
        let mut text = header.to_owned();
        for entry in entries.split("[[shape]]") {
            let (importer, bundle, core) = if entry.contains("client_line = \"cfm04\"") {
                (
                    "be5ad5c27b251901a77ee5912812282c9b8088535868c5e2994973b5dbf267e7",
                    "0.4.0",
                    "1.14.1",
                )
            } else {
                (
                    "e9c2cfa8e886ee34d65765b743a7a6396880f2c67aa657e4d40c0680359647be",
                    "0.5.0",
                    "1.14.2",
                )
            };
            text.push_str("[[shape]]");
            text.push_str(&entry.replace(
                "status = \"pending-real-cfm-import\"\n",
                &format!(
                    "status = \"accepted\"\nimporter_digest = \"{importer}\"\ncfm_build = 50027\n\
                     bundle_version = \"{bundle}\"\nsing_box_core = \"{core}\"\n\
                     export_sha256 = \"{}\"\nimport_date = 2026-10-20\n\
                     connect = \"connected\"\nevidence_sha256 = \"{}\"\n",
                    "a".repeat(64),
                    "b".repeat(64)
                ),
            ));
        }
        assert!(!text.contains("pending-real-cfm-import\"\n"));
        text
    }

    #[test]
    fn the_release_gate_passes_once_every_shape_is_accepted() {
        let text = all_accepted();
        let checked = check(
            &manifest(MANIFEST),
            &acceptance(&text),
            &shapes(),
            Gate::Accepted,
        )
        .unwrap();
        let mut out = Vec::new();
        report(&mut out, &checked, Gate::Accepted).unwrap();
        let report = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = report.lines().collect();
        assert_eq!(lines.len(), 2 + 10 + 1, "{report}");
        assert_eq!(
            lines[12],
            "acceptance: release gate met: all 10 enumerated shape(s) accepted by real CFM \
             against the current importer digests"
        );
        // Evidence from another line's build fails it.
        let crossed = text.replacen("\"0.4.0\"", "\"0.5.0\"", 1);
        let error = check(
            &manifest(MANIFEST),
            &acceptance(&crossed),
            &shapes(),
            Gate::Accepted,
        )
        .unwrap_err();
        assert!(
            matches!(
                &error,
                AcceptanceError::Gate { source: GateError::OtherLineEvidence { entries }, .. }
                    if entries.len() == 1
            ),
            "{error:?}"
        );
    }

    #[test]
    fn the_release_gate_fails_on_the_pending_contract() {
        let error = check(
            &manifest(MANIFEST),
            &acceptance(CONTRACT),
            &shapes(),
            Gate::Accepted,
        )
        .unwrap_err();
        assert!(
            matches!(
                &error,
                AcceptanceError::Gate { path, source: GateError::NotAccepted { pending } }
                    if path == Path::new(ACCEPTANCE_FILE) && pending.len() == 10
            ),
            "{error:?}"
        );
    }

    #[test]
    fn either_gate_fails_on_an_unrecorded_shape() {
        for gate in [Gate::Recorded, Gate::Accepted] {
            let error = check(
                &manifest(MANIFEST),
                &acceptance(&without_last_entry()),
                &shapes(),
                gate,
            )
            .unwrap_err();
            assert!(
                matches!(
                    &error,
                    AcceptanceError::Gate { path, source: GateError::Unrecorded { missing, stale } }
                        if path == Path::new(ACCEPTANCE_FILE) && missing.len() == 1 && stale.is_empty()
                ),
                "{gate:?}: {error:?}"
            );
        }
    }

    #[test]
    fn the_manifest_must_describe_exactly_the_enumerated_client_lines() {
        let (head, cfm05_tables) = MANIFEST.split_once("[cfm.cfm05]").unwrap();
        let (preamble, _) = head.split_once("[cfm.cfm04]").unwrap();
        let only_cfm05 = format!("{preamble}[cfm.cfm05]{cfm05_tables}");
        let with_cfm06 = format!(
            "{MANIFEST}\n[cfm.cfm06]{}",
            cfm05_tables.replace("cfm.cfm05", "cfm.cfm06")
        );
        for (text, missing, unknown) in [
            (only_cfm05.as_str(), ["cfm04"].as_slice(), [].as_slice()),
            (with_cfm06.as_str(), [].as_slice(), ["cfm06"].as_slice()),
        ] {
            let error = check(
                &manifest(text),
                &acceptance(CONTRACT),
                &shapes(),
                Gate::Recorded,
            )
            .unwrap_err();
            assert!(
                matches!(
                    &error,
                    AcceptanceError::Manifest {
                        path,
                        source: ManifestError::ClientLines { missing: m, unknown: u },
                    } if path == Path::new(MANIFEST_FILE) && m == missing && u == unknown
                ),
                "{error:?}"
            );
        }
    }

    #[test]
    fn a_file_that_does_not_parse_is_named() {
        let error = check(
            &manifest("manifest_version = 2\ncfm = {}\n"),
            &acceptance(CONTRACT),
            &shapes(),
            Gate::Recorded,
        )
        .unwrap_err();
        assert!(
            matches!(
                &error,
                AcceptanceError::Manifest { path, source: ManifestError::UnsupportedVersion { found: 2 } }
                    if path == Path::new(MANIFEST_FILE)
            ),
            "{error:?}"
        );
        let error = check(
            &manifest(MANIFEST),
            &acceptance("[[shape]]\n"),
            &shapes(),
            Gate::Recorded,
        )
        .unwrap_err();
        assert!(
            matches!(&error, AcceptanceError::File { path, .. } if path == Path::new(ACCEPTANCE_FILE)),
            "{error:?}"
        );
    }
}
