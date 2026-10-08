// SPDX-License-Identifier: GPL-3.0-or-later

//! `contract/cfm-acceptance.toml`: the record of which enumerated shapes
//! real CFM builds imported and connected with (design §9.3 item 2, §16 L7).
//!
//! Two gates read it:
//!
//! - [`AcceptanceFile::require_recorded`] (`cargo xtask acceptance`, a step
//!   of `cargo xtask ci`): every shape `mooring_export::shapes()` enumerates
//!   has exactly one entry and no entry is stale. A
//!   `pending-real-cfm-import` entry counts as recorded.
//! - [`AcceptanceFile::require_accepted`] (`cargo xtask
//!   release-acceptance`, the release gate): every entry is also
//!   `accepted`, with evidence taken against the current importer digest of
//!   its line in `contract/cfm-manifest.toml` from a build of that line.
//!   Pending never counts as accepted.
//!
//! The format is ours, so every entry denies unknown keys, and `status`
//! selects the entry's variant: an accepted entry without all of its
//! evidence, or a pending entry with any, does not parse.

use std::collections::BTreeSet;
use std::fmt;
use std::num::NonZeroU32;

use mooring_export::Shape;
use mooring_model::digest::Sha256Digest;
use serde::Deserialize;
use toml::value::{Date, Datetime};

use super::manifest::CfmManifest;
use crate::version::Version;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptanceToml {
    /// A file without entries records nothing, so the gates report every
    /// enumerated shape as missing.
    #[serde(default)]
    shape: Vec<Entry>,
}

/// One `[[shape]]` entry: one shape for one client line.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "status")]
pub(crate) enum Entry {
    /// No real CFM import has confirmed the shape yet (M6 has not run).
    #[serde(rename = "pending-real-cfm-import")]
    Pending(PendingEntry),
    /// Imported into real CFM and connected; the evidence says where and when.
    #[serde(rename = "accepted")]
    Accepted(Box<AcceptedEntry>),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingEntry {
    name: String,
    client_line: String,
    hash: Sha256Digest,
}

/// An accepted entry with its evidence (design §9.3 item 2).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AcceptedEntry {
    name: String,
    client_line: String,
    hash: Sha256Digest,
    /// The importer digest of the CFM revision imported into.
    importer_digest: Sha256Digest,
    /// The CFM build number.
    cfm_build: NonZeroU32,
    /// The installed bundle version.
    bundle_version: ReleaseVersion,
    /// The sing-box core version.
    sing_box_core: ReleaseVersion,
    /// SHA-256 of the exported file imported.
    export_sha256: Sha256Digest,
    /// The day of the import.
    import_date: ImportDate,
    /// The connect result.
    connect: ConnectResult,
    /// SHA-256 of the evidence file.
    evidence_sha256: Sha256Digest,
}

/// A plain `major.minor.patch` version.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
struct ReleaseVersion(Version);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0:?} is not a major.minor.patch release version")]
struct ReleaseVersionError(String);

impl TryFrom<String> for ReleaseVersion {
    type Error = ReleaseVersionError;

    fn try_from(text: String) -> Result<Self, ReleaseVersionError> {
        match Version::parse(&text) {
            Ok(version) if version.is_release() => Ok(Self(version)),
            Ok(_) | Err(_) => Err(ReleaseVersionError(text)),
        }
    }
}

impl fmt::Display for ReleaseVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// A TOML local date, such as `2026-10-20`; TOML itself rejects a day the
/// month does not have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "Datetime")]
struct ImportDate(Date);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{0} is not a local date without a time or offset")]
struct ImportDateError(Datetime);

impl TryFrom<Datetime> for ImportDate {
    type Error = ImportDateError;

    fn try_from(value: Datetime) -> Result<Self, ImportDateError> {
        match value {
            Datetime {
                date: Some(date),
                time: None,
                offset: None,
            } => Ok(Self(date)),
            other => Err(ImportDateError(other)),
        }
    }
}

impl fmt::Display for ImportDate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// The only connect result an accepted entry may record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
enum ConnectResult {
    #[serde(rename = "connected")]
    Connected,
}

impl fmt::Display for ConnectResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Connected => "connected",
        })
    }
}

/// One line for the `acceptance` report.
impl fmt::Display for AcceptedEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} accepted: CFM build {}, bundle {}, sing-box {}, imported {} and {}, \
             export {}, evidence {}, importer digest {}",
            self.client_line,
            self.name,
            self.hash,
            self.cfm_build,
            self.bundle_version,
            self.sing_box_core,
            self.import_date,
            self.connect,
            self.export_sha256,
            self.evidence_sha256,
            self.importer_digest
        )
    }
}

impl Entry {
    fn shape(&self) -> ShapeRef {
        let (line, name, hash) = match self {
            Self::Pending(entry) => (&entry.client_line, &entry.name, &entry.hash),
            Self::Accepted(entry) => (&entry.client_line, &entry.name, &entry.hash),
        };
        ShapeRef {
            line: line.clone(),
            name: name.clone(),
            hash: *hash,
        }
    }
}

/// Identifies a shape for one client line in a gate failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ShapeRef {
    line: String,
    name: String,
    hash: Sha256Digest,
}

impl ShapeRef {
    fn of(shape: &Shape) -> Self {
        Self {
            line: shape.line_name().to_owned(),
            name: shape.name(),
            hash: shape.hash(),
        }
    }
}

impl fmt::Display for ShapeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.line, self.name, self.hash)
    }
}

/// Formats a list of shape references for an error message.
struct Refs<'a>(&'a [ShapeRef]);

impl fmt::Display for Refs<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[")?;
        for (position, shape) in self.0.iter().enumerate() {
            if position > 0 {
                f.write_str("; ")?;
            }
            write!(f, "{shape}")?;
        }
        f.write_str("]")
    }
}

/// The acceptance file is not valid.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum FileError {
    /// Not TOML, or an entry has a missing, unknown or invalid key.
    #[error(transparent)]
    Toml(#[from] toml::de::Error),
    /// Two entries record the same shape hash for the same client line.
    #[error("{shape} is recorded twice")]
    DuplicateEntry { shape: ShapeRef },
}

/// A gate failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum GateError {
    /// The entries do not match the enumerated shapes.
    #[error(
        "the acceptance file does not match the enumerated shapes: missing {}, stale {}",
        Refs(missing),
        Refs(stale)
    )]
    Unrecorded {
        /// Enumerated shapes without an entry.
        missing: Vec<ShapeRef>,
        /// Entries for shapes the emitter does not produce.
        stale: Vec<ShapeRef>,
    },
    /// Some shapes have not been accepted by real CFM.
    #[error("shapes not accepted by real CFM: {}", Refs(pending))]
    NotAccepted { pending: Vec<ShapeRef> },
    /// Some acceptances were recorded against an importer that has changed
    /// since, or against a line with no current importer digest.
    #[error("acceptances recorded against another CFM importer: {}", Refs(stale))]
    ImporterChanged { stale: Vec<ShapeRef> },
    /// Some acceptances carry the bundle version or sing-box core of a CFM
    /// build that is not of their client line.
    #[error(
        "acceptances whose bundle version or sing-box core is not of their CFM line: {}",
        Refs(entries)
    )]
    OtherLineEvidence { entries: Vec<ShapeRef> },
}

/// The parsed acceptance file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AcceptanceFile {
    entries: Vec<Entry>,
}

impl AcceptanceFile {
    pub(crate) fn parse(text: &str) -> Result<Self, FileError> {
        let AcceptanceToml { shape: entries } = toml::from_str(text)?;
        let mut seen = BTreeSet::new();
        for entry in &entries {
            let shape = entry.shape();
            if !seen.insert((shape.line.clone(), shape.hash)) {
                return Err(FileError::DuplicateEntry { shape });
            }
        }
        Ok(Self { entries })
    }

    /// The entries, in file order.
    pub(crate) fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The accepted entries, in file order.
    pub(crate) fn accepted(&self) -> impl Iterator<Item = &AcceptedEntry> {
        self.entries.iter().filter_map(|entry| match entry {
            Entry::Pending(_) => None,
            Entry::Accepted(accepted) => Some(&**accepted),
        })
    }

    /// The CI gate: every shape in `shapes` has an entry with its client
    /// line, name and hash, and every entry is such a shape. Pending
    /// entries count.
    pub(crate) fn require_recorded(&self, shapes: &[Shape]) -> Result<(), GateError> {
        let enumerated: Vec<ShapeRef> = shapes.iter().map(ShapeRef::of).collect();
        let recorded: Vec<ShapeRef> = self.entries.iter().map(Entry::shape).collect();
        let missing: Vec<ShapeRef> = enumerated
            .iter()
            .filter(|shape| !recorded.contains(shape))
            .cloned()
            .collect();
        let stale: Vec<ShapeRef> = recorded
            .into_iter()
            .filter(|shape| !enumerated.contains(shape))
            .collect();
        if missing.is_empty() && stale.is_empty() {
            Ok(())
        } else {
            Err(GateError::Unrecorded { missing, stale })
        }
    }

    /// The release gate: [`Self::require_recorded`], and every entry is
    /// accepted against the importer digest `manifest` records for its line,
    /// by a CFM build of that line (its bundle version and sing-box core).
    /// Pending entries are reported first, then stale importers, then
    /// evidence from another line.
    pub(crate) fn require_accepted(
        &self,
        shapes: &[Shape],
        manifest: &CfmManifest,
    ) -> Result<(), GateError> {
        self.require_recorded(shapes)?;
        let mut pending = Vec::new();
        let mut stale = Vec::new();
        let mut other_line = Vec::new();
        for entry in &self.entries {
            match entry {
                Entry::Pending(_) => pending.push(entry.shape()),
                Entry::Accepted(accepted) => match manifest.revision(&accepted.client_line) {
                    Some(revision) if revision.importer_digest() == accepted.importer_digest => {
                        if !revision.is_build(&accepted.bundle_version.0, &accepted.sing_box_core.0)
                        {
                            other_line.push(entry.shape());
                        }
                    }
                    Some(_) | None => stale.push(entry.shape()),
                },
            }
        }
        if !pending.is_empty() {
            return Err(GateError::NotAccepted { pending });
        }
        if !stale.is_empty() {
            return Err(GateError::ImporterChanged { stale });
        }
        if !other_line.is_empty() {
            return Err(GateError::OtherLineEvidence {
                entries: other_line,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use mooring_export::{Shape, shapes};
    use mooring_model::digest::Sha256Digest;

    use super::{AcceptanceFile, Entry, FileError, GateError, ShapeRef};
    use crate::acceptance::manifest::CfmManifest;

    const CONTRACT: &str = include_str!("../../../contract/cfm-acceptance.toml");
    const MANIFEST: &str = include_str!("../../../contract/cfm-manifest.toml");

    const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const PENDING: &str = "status = \"pending-real-cfm-import\"\n";

    /// The bundle version and sing-box core of a CFM build of each line
    /// (contract/cfm-manifest.toml: 0.4 with v1.14.1, 0.5 with v1.14.2).
    fn build_of(line: &str) -> (&'static str, &'static str) {
        match line {
            "cfm04" => ("0.4.0", "1.14.1"),
            "cfm05" => ("0.5.0", "1.14.2"),
            other => panic!("no CFM build for {other}"),
        }
    }

    /// The pending entry an enumerated shape needs before real CFM imported it.
    fn pending(shape: &Shape) -> String {
        format!(
            "[[shape]]\nname = \"{}\"\nclient_line = \"{}\"\nhash = \"{}\"\n{PENDING}",
            shape.name(),
            shape.line_name(),
            shape.hash()
        )
    }

    fn file_of(shapes: &[Shape]) -> String {
        shapes.iter().map(pending).collect::<Vec<_>>().join("\n")
    }

    /// `entry` turned into an accepted entry imported against `importer` by
    /// a CFM build reporting `bundle` and `core`.
    fn accepted(entry: &str, importer: &str, (bundle, core): (&str, &str)) -> String {
        assert!(entry.contains(PENDING));
        entry.replace(
            PENDING,
            &format!(
                "status = \"accepted\"\nimporter_digest = \"{importer}\"\ncfm_build = 50027\n\
                 bundle_version = \"{bundle}\"\nsing_box_core = \"{core}\"\n\
                 export_sha256 = \"{DIGEST_A}\"\nimport_date = 2026-10-20\n\
                 connect = \"connected\"\nevidence_sha256 = \"{DIGEST_B}\"\n"
            ),
        )
    }

    fn manifest() -> CfmManifest {
        CfmManifest::parse(MANIFEST).unwrap()
    }

    /// The contract manifest's current importer digest of `line`.
    fn importer(line: &str) -> String {
        manifest()
            .revision(line)
            .unwrap()
            .importer_digest()
            .to_string()
    }

    /// `shape` accepted by a build of its line against the line's current importer.
    fn accepted_shape(shape: &Shape) -> String {
        let line = shape.line_name();
        accepted(&pending(shape), &importer(line), build_of(line))
    }

    /// Every enumerated shape accepted by a build of its line against the
    /// contract manifest's importer digest of that line.
    fn all_accepted() -> String {
        shapes()
            .iter()
            .map(accepted_shape)
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn shape_ref(shape: &Shape) -> ShapeRef {
        ShapeRef {
            line: shape.line_name().to_owned(),
            name: shape.name(),
            hash: shape.hash(),
        }
    }

    fn parse_error(text: &str) -> FileError {
        AcceptanceFile::parse(text).unwrap_err()
    }

    /// Whether `error` is a TOML error whose message contains `text`.
    fn toml_error(error: &FileError, text: &str) -> bool {
        matches!(error, FileError::Toml(toml) if toml.message().contains(text))
    }

    fn unrecorded(error: &GateError) -> (&[ShapeRef], &[ShapeRef]) {
        match error {
            GateError::Unrecorded { missing, stale } => (missing, stale),
            other => panic!("expected Unrecorded, got {other:?}"),
        }
    }

    fn release_gate(text: &str) -> Result<(), GateError> {
        AcceptanceFile::parse(text)
            .unwrap()
            .require_accepted(&shapes(), &manifest())
    }

    #[test]
    fn every_enumerated_shape_is_recorded_in_the_contract() {
        let file = AcceptanceFile::parse(CONTRACT).unwrap();
        file.require_recorded(&shapes()).unwrap();
        assert_eq!(file.entries().len(), shapes().len());
    }

    #[test]
    fn pending_is_never_accepted_for_release() {
        let file = AcceptanceFile::parse(CONTRACT).unwrap();
        assert!(
            file.entries()
                .iter()
                .all(|entry| matches!(entry, Entry::Pending(_)))
        );
        assert_eq!(file.accepted().count(), 0);
        let error = file.require_accepted(&shapes(), &manifest()).unwrap_err();
        assert!(
            matches!(&error, GateError::NotAccepted { pending } if pending.len() == shapes().len()),
            "{error:?}"
        );
        // One pending entry among accepted ones still fails, and is named.
        let all = shapes();
        let mixed = all_accepted().replacen(&accepted_shape(&all[0]), &pending(&all[0]), 1);
        let expected = GateError::NotAccepted {
            pending: vec![shape_ref(&all[0])],
        };
        assert_eq!(release_gate(&mixed), Err(expected.clone()));
        // A pending entry is reported before acceptances against another
        // importer, and before evidence from another line.
        let mixed_and_stale = mixed.replace(&importer("cfm05"), DIGEST_B);
        assert_ne!(mixed_and_stale, mixed);
        assert_eq!(release_gate(&mixed_and_stale), Err(expected.clone()));
        let mixed_and_crossed = mixed.replace("\"1.14.2\"", "\"1.14.1\"");
        assert_ne!(mixed_and_crossed, mixed);
        assert_eq!(release_gate(&mixed_and_crossed), Err(expected));
    }

    #[test]
    fn a_missing_or_stale_entry_fails_the_gate() {
        let all = shapes();
        let missing_last = AcceptanceFile::parse(&file_of(&all[..all.len() - 1])).unwrap();
        let error = missing_last.require_recorded(&all).unwrap_err();
        let (missing, stale) = unrecorded(&error);
        assert_eq!(missing, [shape_ref(&all[all.len() - 1])]);
        assert!(stale.is_empty());
        // A renamed entry is both stale and missing.
        let renamed = file_of(&all).replacen("sing-box-json/hysteria2", "sing-box-json/hy2", 1);
        let error = AcceptanceFile::parse(&renamed)
            .unwrap()
            .require_recorded(&all)
            .unwrap_err();
        let (missing, stale) = unrecorded(&error);
        assert_eq!((missing.len(), stale.len()), (1, 1));
        assert!(error.to_string().contains("sing-box-json/hy2"));
        // So is an entry for a client line the emitter does not produce.
        let other_line = file_of(&all).replacen("\"cfm04\"", "\"cfm06\"", 1);
        let error = AcceptanceFile::parse(&other_line)
            .unwrap()
            .require_recorded(&all)
            .unwrap_err();
        let (missing, stale) = unrecorded(&error);
        assert_eq!((missing.len(), stale.len()), (1, 1));
        assert_eq!(
            (missing[0].line.as_str(), stale[0].line.as_str()),
            ("cfm04", "cfm06")
        );
        // An extra entry for a shape the emitter no longer produces is stale
        // even when nothing is missing.
        let extra = format!(
            "{}\n{}",
            file_of(&all),
            pending(&all[0]).replace(&all[0].hash().to_string(), DIGEST_A)
        );
        let error = AcceptanceFile::parse(&extra)
            .unwrap()
            .require_recorded(&all)
            .unwrap_err();
        let (missing, stale) = unrecorded(&error);
        assert!(missing.is_empty());
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].hash, Sha256Digest::parse(DIGEST_A).unwrap());
        // A file without entries records nothing.
        let empty = AcceptanceFile::parse("# only a comment\n\n").unwrap();
        assert!(empty.entries().is_empty());
        let error = empty.require_recorded(&all).unwrap_err();
        assert_eq!(unrecorded(&error).0.len(), all.len());
        // Release verification refuses an unrecorded file before anything else.
        assert!(matches!(
            missing_last
                .require_accepted(&all, &manifest())
                .unwrap_err(),
            GateError::Unrecorded { .. }
        ));
    }

    #[test]
    fn accepted_entries_must_match_the_current_importer() {
        let all = shapes();
        let file = AcceptanceFile::parse(&all_accepted()).unwrap();
        file.require_recorded(&all).unwrap();
        file.require_accepted(&all, &manifest()).unwrap();
        assert_eq!(file.accepted().count(), all.len());
        let first = file.accepted().next().unwrap();
        let cfm04 = importer("cfm04");
        assert_eq!(
            first.to_string(),
            format!(
                "cfm04 {} {} accepted: CFM build 50027, bundle 0.4.0, sing-box 1.14.1, \
                 imported 2026-10-20 and connected, export {DIGEST_A}, evidence {DIGEST_B}, \
                 importer digest {cfm04}",
                all[0].name(),
                all[0].hash()
            )
        );
        // Every acceptance taken against another importer is stale.
        let other = all
            .iter()
            .map(|shape| accepted(&pending(shape), DIGEST_B, build_of(shape.line_name())))
            .collect::<Vec<_>>()
            .join("\n");
        let error = release_gate(&other).unwrap_err();
        assert!(
            matches!(&error, GateError::ImporterChanged { stale } if stale.len() == all.len()),
            "{error:?}"
        );
        // Accepting against the other line's digest is stale too.
        let crossed = all_accepted().replacen(&cfm04, &importer("cfm05"), 1);
        assert_eq!(
            release_gate(&crossed),
            Err(GateError::ImporterChanged {
                stale: vec![shape_ref(&all[0])]
            })
        );
        // A line without a current importer digest cannot be verified either.
        let (head, cfm05_tables) = MANIFEST.split_once("[cfm.cfm05]").unwrap();
        let (preamble, _) = head.split_once("[cfm.cfm04]").unwrap();
        let only_cfm05 =
            CfmManifest::parse(&format!("{preamble}[cfm.cfm05]{cfm05_tables}")).unwrap();
        assert_eq!(only_cfm05.revision("cfm04"), None);
        let error = file.require_accepted(&all, &only_cfm05).unwrap_err();
        assert!(
            matches!(&error, GateError::ImporterChanged { stale }
                if !stale.is_empty() && stale.iter().all(|shape| shape.line == "cfm04")),
            "{error:?}"
        );
    }

    #[test]
    fn accepted_evidence_must_come_from_a_build_of_its_line() {
        let all = shapes();
        let first = accepted_shape(&all[0]);
        assert!(first.contains("client_line = \"cfm04\""));
        let first_crossed = |bundle: &str, core: &str| {
            let crossed = accepted(&pending(&all[0]), &importer("cfm04"), (bundle, core));
            all_accepted().replacen(&first, &crossed, 1)
        };
        let expected = Err(GateError::OtherLineEvidence {
            entries: vec![shape_ref(&all[0])],
        });
        // A cfm04 entry recorded from a CFM 0.5 build ...
        assert_eq!(release_gate(&first_crossed("0.5.0", "1.14.2")), expected);
        // ... from a 0.4 bundle with another sing-box core ...
        assert_eq!(release_gate(&first_crossed("0.4.0", "1.14.2")), expected);
        // ... or from another release line with the right core.
        assert_eq!(release_gate(&first_crossed("1.4.0", "1.14.1")), expected);
        // Any patch release of the line is a build of it.
        release_gate(&first_crossed("0.4.7", "1.14.1")).unwrap();
        // Every cfm05 entry recorded from a CFM 0.4 build.
        let cfm05_from_04 = all_accepted().replace("\"0.5.0\"", "\"0.4.0\"");
        let cfm05: Vec<ShapeRef> = all
            .iter()
            .filter(|shape| shape.line_name() == "cfm05")
            .map(shape_ref)
            .collect();
        assert_eq!(cfm05.len(), 6);
        assert_eq!(
            release_gate(&cfm05_from_04),
            Err(GateError::OtherLineEvidence { entries: cfm05 })
        );
        // A stale importer is reported before evidence from another line.
        let stale_and_crossed =
            first_crossed("0.5.0", "1.14.2").replace(&importer("cfm05"), DIGEST_B);
        assert!(matches!(
            release_gate(&stale_and_crossed),
            Err(GateError::ImporterChanged { .. })
        ));
    }

    #[test]
    fn the_reader_rejects_what_the_format_does_not_allow() {
        let entry = pending(&shapes()[0]);
        let cases = [
            ("garbage\n".to_owned(), "key with no value"),
            ("name = \"x\"\n".to_owned(), "unknown field `name`"),
            (
                "[shape]\nname = \"x\"\n".to_owned(),
                "invalid type: map, expected a sequence",
            ),
            (
                format!("{entry}colour = \"blue\"\n"),
                "unknown field `colour`",
            ),
            (format!("{entry}status=\"accepted\"\n"), "duplicate key"),
            (format!("{entry}name = 'single'\n"), "duplicate key"),
            (entry.replace(PENDING, ""), "missing field `status`"),
            ("[[shape]]\n".to_owned(), "missing field `status`"),
            (
                entry.replace("pending-real-cfm-import", "rejected"),
                "unknown variant `rejected`",
            ),
            (
                format!("{entry}export_sha256 = \"{DIGEST_A}\"\n"),
                "unknown field `export_sha256`",
            ),
            (
                format!("{entry}connect = \"connected\"\n"),
                "unknown field `connect`",
            ),
            (
                entry.replace("hash = \"", "hash = \"X"),
                "invalid SHA-256 digest (64 lowercase hex characters)",
            ),
            (
                entry.replace("client_line = \"cfm04\"\n", ""),
                "missing field `client_line`",
            ),
        ];
        for (text, message) in &cases {
            let error = parse_error(text);
            assert!(toml_error(&error, message), "{text:?}: {error}");
        }
        assert_eq!(
            parse_error(&format!("{entry}\n{entry}")),
            FileError::DuplicateEntry {
                shape: shape_ref(&shapes()[0])
            }
        );
        // The same shape for the other client line is not a duplicate.
        AcceptanceFile::parse(&format!("{entry}\n{}", entry.replace("cfm04", "cfm05"))).unwrap();
    }

    #[test]
    fn any_toml_spelling_of_the_same_entries_is_read_the_same() {
        let entry = pending(&shapes()[0]);
        let expected = AcceptanceFile::parse(&entry).unwrap();
        for text in [
            entry.replace('\n', "\r\n"),
            format!("  # indented comment\n{entry}"),
            entry.replace("\"cfm04\"", "'cfm04'"),
            entry.replace("name = ", "name   =   "),
            entry.replace("\"cfm04\"", "\"cfm\\u00304\""),
        ] {
            assert_ne!(text, entry);
            assert_eq!(AcceptanceFile::parse(&text).unwrap(), expected, "{text:?}");
        }
    }

    #[test]
    fn evidence_values_outside_their_domains_are_rejected() {
        let entry = accepted(&pending(&shapes()[0]), DIGEST_A, build_of("cfm04"));
        AcceptanceFile::parse(&entry).unwrap();
        let invalid = |from: &str, to: &str, message: &str| {
            assert!(entry.contains(from), "{from}");
            let error = parse_error(&entry.replacen(from, to, 1));
            assert!(toml_error(&error, message), "{to}: {error}");
        };
        invalid("\"connected\"", "\"failed\"", "unknown variant `failed`");
        invalid(
            "connect = \"connected\"\n",
            "connect = \"connected\"\noperator = \"bill\"\n",
            "unknown field `operator`",
        );
        invalid("cfm_build = 50027", "cfm_build = 0", "nonzero");
        invalid(
            "cfm_build = 50027",
            "cfm_build = \"50027\"",
            "invalid type: string",
        );
        invalid("cfm_build = 50027", "cfm_build = -1", "invalid value");
        invalid(
            "\"0.4.0\"",
            "\"0.4\"",
            "is not a major.minor.patch release version",
        );
        invalid(
            "\"0.4.0\"",
            "\"0.4.0.1\"",
            "is not a major.minor.patch release version",
        );
        invalid(
            "\"0.4.0\"",
            "\"0.4.0-rc.1\"",
            "is not a major.minor.patch release version",
        );
        invalid(
            "\"1.14.1\"",
            "\"1.14.x\"",
            "is not a major.minor.patch release version",
        );
        invalid(
            &format!("importer_digest = \"{DIGEST_A}\""),
            "importer_digest = \"abc\"",
            "invalid SHA-256 digest (64 lowercase hex characters)",
        );
        invalid(
            &format!("evidence_sha256 = \"{DIGEST_B}\""),
            "evidence_sha256 = \"\"",
            "invalid SHA-256 digest (64 lowercase hex characters)",
        );
        invalid(
            &format!("export_sha256 = \"{DIGEST_A}\"\n"),
            "",
            "missing field `export_sha256`",
        );
        invalid(
            "import_date = 2026-10-20",
            "import_date = 2026-10-20T10:00:00",
            "is not a local date without a time or offset",
        );
        invalid(
            "import_date = 2026-10-20",
            "import_date = \"2026-10-20\"",
            "invalid type: string",
        );
        // 2028 is a leap year.
        AcceptanceFile::parse(&entry.replace("2026-10-20", "2028-02-29")).unwrap();
        // TOML itself refuses what is not a date or a canonical integer.
        for (from, to) in [
            ("2026-10-20", "2026-02-29"),
            ("2026-10-20", "2026-13-01"),
            ("2026-10-20", "2026-04-31"),
            ("2026-10-20", "2026-1-01"),
            ("2026-10-20", "20261020xx"),
            ("50027", "050027"),
        ] {
            let error = parse_error(&entry.replacen(from, to, 1));
            assert!(matches!(error, FileError::Toml(_)), "{to}: {error:?}");
        }
    }
}
