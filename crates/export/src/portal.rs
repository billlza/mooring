// SPDX-License-Identifier: GPL-3.0-or-later

//! The portal's CFM profile bundle (design §9.5; contract
//! `mooring-portal-cfm-profiles` version 2, `docs/portal-contract.md`): for
//! each user the operator names, those bound to a portal account, either
//! the user's sing-box JSON file or why it is withheld, in one document
//! the portal imports whole, keeps, and hands to each user by download or
//! subscription link.
//!
//! # Who is in it
//!
//! Exactly the users named, each once ([`named_users`]). Mooring cannot
//! tell who is bound to a portal account, and the portal refuses a bundle
//! that leaves out a bound user, so the operator names them all; a list
//! that names no one, an id no user has or a user twice is refused. A user
//! named is delivered when active and with an acceptance of the agreement
//! revision the portal requires ([`PortalAgreement`]). Every other user
//! named is withheld, with the reason ([`Withheld`]); an exhaustive match
//! puts each status on one side, so a status added later has to be placed
//! there. A user to be delivered whose file cannot be made (a node not
//! applied, a certificate no longer current, no credentials) refuses the
//! whole bundle: withheld, they would lose their subscription link at the
//! portal for good.
//!
//! # What it holds
//!
//! For each user delivered, in id order, the document a user export writes
//! in [`ExportFormat::SingBoxJson`](crate::ExportFormat::SingBoxJson),
//! built by the same function from the same checked outbounds, as a JSON
//! object; for each user withheld, in id order, the reason. The
//! credentials make the bundle a secret: it is written into a zeroizing
//! buffer of exactly its size, and its `Debug` output gives counts and
//! sizes only.

mod document;

use std::collections::BTreeSet;
use std::fmt;
use std::io;

use mooring_model::secret::{SecretRef, SecretSnapshot};
use mooring_model::{
    AgreementVersion, Deployment, PortalAgreement, RecordedAgreement, UnixTime, User, UserId,
    UserStatus, named_users,
};
use zeroize::Zeroizing;

use crate::error::{ExportError, ProfilesError};
use crate::export::{export_secret_refs, user_outbounds};
use crate::json::exact_json;
use crate::singbox::document_tree;
use crate::tree::{Scalar, Tree};

use self::document::{BundleV2, EntryV2, FORMAT, ReasonV2, VERSION, WithheldV2};

/// The most bytes of a bundle the portal reads.
pub const MAX_BUNDLE_BYTES: usize = 1024 * 1024;

/// The most bytes of one user's document, as it stands in the bundle, the
/// portal accepts.
pub const MAX_PROFILE_DOCUMENT_BYTES: usize = 64 * 1024;

/// How much deeper than a file's root a document's lines stand in the
/// bundle: three levels of two spaces (the bundle, its `profiles` list,
/// the user's entry).
const NESTED_INDENT: usize = 3 * 2;

/// Why a user named is withheld from a bundle: Mooring does not serve
/// them, or may not deliver their file through the portal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Withheld {
    /// The user is suspended, for whatever reason, so served nowhere; the
    /// credentials are kept, and the user's file works again once resumed.
    Suspended,
    /// The user is being revoked.
    BeingRevoked,
    /// The user is revoked.
    Revoked,
    /// The user is active but has not accepted the revision the portal
    /// requires, so no file of theirs is exported.
    AgreementNotAccepted {
        /// The revision the user accepted, if a record exists.
        recorded: Option<AgreementVersion>,
        /// The revision required.
        required: AgreementVersion,
    },
}

impl fmt::Display for Withheld {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Suspended => f.write_str("suspended"),
            Self::BeingRevoked => f.write_str("being revoked"),
            Self::Revoked => f.write_str("revoked"),
            Self::AgreementNotAccepted { recorded, required } => write!(
                f,
                "has not accepted agreement revision {required}: {}",
                RecordedAgreement(*recorded)
            ),
        }
    }
}

/// Who a bundle delivers, who it withholds and which secrets making it
/// reads, decided from the deployment before any secret is read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileSelection {
    delivered: Vec<UserId>,
    withheld: Vec<(UserId, Withheld)>,
    refs: BTreeSet<SecretRef>,
}

impl ProfileSelection {
    /// The users whose file the bundle holds, in id order.
    #[must_use]
    pub fn delivered(&self) -> &[UserId] {
        &self.delivered
    }

    /// The users it withholds, in id order, with why.
    #[must_use]
    pub fn withheld(&self) -> &[(UserId, Withheld)] {
        &self.withheld
    }

    /// Exactly the secrets the bundle's files need: those of each
    /// delivered user's export.
    #[must_use]
    pub const fn secret_refs(&self) -> &BTreeSet<SecretRef> {
        &self.refs
    }
}

/// A bundle: pretty-printed JSON ending with one newline, holding every
/// delivered user's credentials.
pub struct ProfileBundle {
    selection: ProfileSelection,
    bytes: Zeroizing<Vec<u8>>,
}

impl ProfileBundle {
    /// The file's contents.
    #[must_use]
    pub fn expose_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Who it delivers and who it withholds.
    #[must_use]
    pub const fn selection(&self) -> &ProfileSelection {
        &self.selection
    }
}

impl fmt::Debug for ProfileBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProfileBundle")
            .field("delivered", &self.selection.delivered.len())
            .field("withheld", &self.selection.withheld.len())
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// Who a bundle of `users` made at `now` delivers and withholds, after
/// every check making it makes before reading a secret, in this order: the
/// agreement covers the portal (`NotCovered`), the users named are
/// distinct users of the deployment (`Named`, [`named_users`]), then, user
/// by user in id order, whether the user is delivered and, if so, every
/// check of its export (`User`, with [`export_secret_refs`]'s error).
pub fn profile_selection(
    deployment: &Deployment,
    users: &[UserId],
    now: UnixTime,
    agreement: PortalAgreement,
) -> Result<ProfileSelection, ProfilesError> {
    sort(deployment, users, now, agreement).map(Sorted::into_selection)
}

/// The bundle of `users` at `now`, the delivered users' files made from
/// `secrets`, which must hold [`ProfileSelection::secret_refs`]. Refused
/// as [`profile_selection`] refuses, then when a file cannot be made
/// (`User`), when a user's document or the bundle is larger than the
/// portal accepts (`DocumentTooLarge`, `BundleTooLarge`), or when encoding
/// fails. A bundle that withholds every user named is made: the portal
/// stops serving them on its import.
pub fn export_profiles(
    deployment: &Deployment,
    secrets: &SecretSnapshot,
    users: &[UserId],
    now: UnixTime,
    agreement: PortalAgreement,
) -> Result<ProfileBundle, ProfilesError> {
    bounded_profiles(deployment, secrets, users, now, agreement, PORTAL_BOUNDS)
}

/// The portal's bounds on one document in a bundle and on the bundle.
#[derive(Debug, Clone, Copy)]
struct Bounds {
    document: usize,
    bundle: usize,
}

/// What the portal accepts.
const PORTAL_BOUNDS: Bounds = Bounds {
    document: MAX_PROFILE_DOCUMENT_BYTES,
    bundle: MAX_BUNDLE_BYTES,
};

/// [`export_profiles`] against `bounds`: one function, so the tests reach
/// both size refusals through the path every bundle takes.
fn bounded_profiles(
    deployment: &Deployment,
    secrets: &SecretSnapshot,
    users: &[UserId],
    now: UnixTime,
    agreement: PortalAgreement,
    bounds: Bounds,
) -> Result<ProfileBundle, ProfilesError> {
    let sorted = sort(deployment, users, now, agreement)?;
    let mut profiles = Vec::with_capacity(sorted.delivered.len());
    for &(id, user) in &sorted.delivered {
        let outbounds = user_outbounds(deployment, secrets, user, now)
            .map_err(|source| user_error(id, source))?;
        let document = document_tree(&outbounds);
        let bytes = nested_len(&document).map_err(ProfilesError::Encode)?;
        fits_document(id, bytes, bounds.document)?;
        profiles.push(EntryV2 { user: id, document });
    }
    let withheld = sorted
        .withheld
        .iter()
        .map(|&(user, why)| WithheldV2 {
            user,
            reason: ReasonV2::of(why),
        })
        .collect();
    let bytes = exact_json(&BundleV2 {
        format: FORMAT,
        version: VERSION,
        generated_at: now,
        profiles,
        withheld,
    })
    .map_err(ProfilesError::Encode)?;
    fits_bundle(bytes.len(), bounds.bundle)?;
    Ok(ProfileBundle {
        selection: sorted.into_selection(),
        bytes,
    })
}

/// The users named, sorted: those delivered, with their records, and those
/// withheld, with why, each in id order; and the secrets the delivered
/// users' files need.
struct Sorted<'a> {
    delivered: Vec<(&'a UserId, &'a User)>,
    withheld: Vec<(&'a UserId, Withheld)>,
    refs: BTreeSet<SecretRef>,
}

impl Sorted<'_> {
    fn into_selection(self) -> ProfileSelection {
        ProfileSelection {
            delivered: self
                .delivered
                .into_iter()
                .map(|(id, _)| id.clone())
                .collect(),
            withheld: self
                .withheld
                .into_iter()
                .map(|(id, why)| (id.clone(), why))
                .collect(),
            refs: self.refs,
        }
    }
}

/// [`profile_selection`]'s checks, keeping the users' records for making
/// the files.
fn sort<'a>(
    deployment: &'a Deployment,
    users: &[UserId],
    now: UnixTime,
    agreement: PortalAgreement,
) -> Result<Sorted<'a>, ProfilesError> {
    let required = agreement.required()?;
    let named = named_users(deployment, users)?;
    let mut sorted = Sorted {
        delivered: Vec::new(),
        withheld: Vec::new(),
        refs: BTreeSet::new(),
    };
    for (id, user) in named {
        if let Some(why) = withheld(user, required) {
            sorted.withheld.push((id, why));
            continue;
        }
        let refs =
            export_secret_refs(deployment, id, now).map_err(|source| user_error(id, source))?;
        sorted.refs.extend(refs);
        sorted.delivered.push((id, user));
    }
    Ok(sorted)
}

/// Why `user` is withheld, or `None` when it is delivered: every status
/// named, none by a wildcard.
fn withheld(user: &User, required: AgreementVersion) -> Option<Withheld> {
    match user.status {
        UserStatus::Active => user
            .accepted(required)
            .err()
            .map(
                |RecordedAgreement(recorded)| Withheld::AgreementNotAccepted { recorded, required },
            ),
        UserStatus::Suspended { .. } => Some(Withheld::Suspended),
        UserStatus::RevokePending => Some(Withheld::BeingRevoked),
        UserStatus::Revoked => Some(Withheld::Revoked),
    }
}

fn user_error(user: &UserId, source: ExportError) -> ProfilesError {
    ProfilesError::User {
        user: user.clone(),
        source: Box::new(source),
    }
}

/// `DocumentTooLarge` when `user`'s document takes more than `limit`
/// bytes in the bundle.
fn fits_document(user: &UserId, bytes: usize, limit: usize) -> Result<(), ProfilesError> {
    if bytes > limit {
        return Err(ProfilesError::DocumentTooLarge {
            user: user.clone(),
            bytes,
            limit,
        });
    }
    Ok(())
}

/// `BundleTooLarge` when the bundle is more than `limit` bytes.
const fn fits_bundle(bytes: usize, limit: usize) -> Result<(), ProfilesError> {
    if bytes > limit {
        return Err(ProfilesError::BundleTooLarge { bytes, limit });
    }
    Ok(())
}

/// The bytes `document` takes in the bundle, which is what the portal
/// measures: its pretty-printed text with every line after the first
/// indented by [`NESTED_INDENT`]. Counted, never written down, so the
/// credentials are not copied for it.
fn nested_len(document: &Tree<Scalar>) -> Result<usize, serde_json::Error> {
    let mut measure = Measure::default();
    serde_json::to_writer_pretty(&mut measure, document)?;
    Ok(measure.bytes + NESTED_INDENT * measure.newlines)
}

/// A writer that counts the bytes and line breaks it is given and keeps
/// none of them.
#[derive(Debug, Default)]
struct Measure {
    bytes: usize,
    newlines: usize,
}

impl io::Write for Measure {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.bytes += buf.len();
        self.newlines += buf.iter().filter(|&&byte| byte == b'\n').count();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The size bounds refuse only what is past them.
    #[test]
    fn the_size_bounds_refuse_only_what_is_past_them() {
        let user = UserId::parse("aaaaaaaaaa").unwrap();
        assert!(fits_document(&user, 10, 10).is_ok());
        let error = fits_document(&user, 11, 10).unwrap_err();
        assert!(
            matches!(&error, ProfilesError::DocumentTooLarge { user: named, bytes: 11, limit: 10 } if *named == user),
            "{error:?}"
        );
        assert_eq!(
            error.to_string(),
            "user aaaaaaaaaa's document is 11 bytes in the bundle, more than the portal's 10"
        );
        assert!(fits_bundle(10, 10).is_ok());
        let error = fits_bundle(11, 10).unwrap_err();
        assert!(
            matches!(
                error,
                ProfilesError::BundleTooLarge {
                    bytes: 11,
                    limit: 10
                }
            ),
            "{error:?}"
        );
        assert_eq!(
            error.to_string(),
            "the bundle is 11 bytes, more than the portal's 10"
        );
    }

    /// The text of each `"document"` value in `bundle`, as the portal reads
    /// it: from its opening brace to the matching closing one, braces in
    /// strings skipped.
    fn documents(bundle: &str) -> Vec<&str> {
        let key = "\"document\": ";
        let mut found = Vec::new();
        let mut rest = bundle;
        while let Some(at) = rest.find(key) {
            let text = &rest[at + key.len()..];
            let (mut depth, mut in_string, mut escaped) = (0_usize, false, false);
            let mut end = None;
            for (index, byte) in text.bytes().enumerate() {
                match (in_string, escaped, byte) {
                    (true, true, _) => escaped = false,
                    (true, false, b'\\') => escaped = true,
                    (true, false, b'"') | (false, _, b'"') => in_string = !in_string,
                    (false, _, b'{') => depth += 1,
                    (false, _, b'}') => {
                        depth -= 1;
                        if depth == 0 {
                            end = Some(index + 1);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let end = end.unwrap();
            found.push(&text[..end]);
            rest = &text[end..];
        }
        found
    }

    /// What `nested_len` counts is what the portal measures: the length of
    /// each user's document as it stands in the bundle.
    #[test]
    fn each_document_is_measured_as_the_portal_measures_it() {
        let fixture = mooring_fixtures::two_nodes_twenty_users().unwrap();
        let open = PortalAgreement::since(Some(AgreementVersion::CURRENT));
        let now = mooring_fixtures::FIXTURE_NOW;
        let users: Vec<UserId> = fixture.deployment.users().keys().cloned().collect();
        let bundle =
            export_profiles(&fixture.deployment, &fixture.secrets, &users, now, open).unwrap();
        let text = std::str::from_utf8(bundle.expose_bytes()).unwrap();
        let documents = documents(text);
        assert_eq!(documents.len(), fixture.deployment.users().len());
        for (user, document) in fixture.deployment.users().values().zip(documents) {
            let outbounds =
                user_outbounds(&fixture.deployment, &fixture.secrets, user, now).unwrap();
            assert_eq!(
                nested_len(&document_tree(&outbounds)).unwrap(),
                document.len(),
                "{}",
                user.id
            );
            assert!(document.len() <= MAX_PROFILE_DOCUMENT_BYTES);
        }
    }

    /// A document or a bundle past its bound refuses the bundle, on the
    /// path every bundle takes; at the bound it is made.
    #[test]
    fn a_document_or_bundle_past_its_bound_refuses_the_bundle() {
        let fixture = mooring_fixtures::two_nodes_three_users().unwrap();
        let open = PortalAgreement::since(Some(AgreementVersion::CURRENT));
        let now = mooring_fixtures::FIXTURE_NOW;
        let users: Vec<UserId> = fixture.deployment.users().keys().cloned().collect();
        let make = |bounds| {
            bounded_profiles(
                &fixture.deployment,
                &fixture.secrets,
                &users,
                now,
                open,
                bounds,
            )
        };
        let made = make(PORTAL_BOUNDS).unwrap();
        let largest = documents(std::str::from_utf8(made.expose_bytes()).unwrap())
            .iter()
            .map(|document| document.len())
            .max()
            .unwrap();
        let total = made.expose_bytes().len();
        assert!(
            make(Bounds {
                document: largest,
                bundle: total
            })
            .is_ok()
        );
        let error = make(Bounds {
            document: largest - 1,
            bundle: total,
        })
        .unwrap_err();
        assert!(
            matches!(error, ProfilesError::DocumentTooLarge { bytes, limit, .. } if bytes == largest && limit == largest - 1),
            "{error:?}"
        );
        let error = make(Bounds {
            document: largest,
            bundle: total - 1,
        })
        .unwrap_err();
        assert!(
            matches!(error, ProfilesError::BundleTooLarge { bytes, limit } if bytes == total && limit == total - 1),
            "{error:?}"
        );
    }

    /// The measure counts every byte and line break, and flushing keeps
    /// nothing either.
    #[test]
    fn the_measure_counts_bytes_and_line_breaks() {
        use std::io::Write as _;
        let mut measure = Measure::default();
        measure.write_all(b"{\n  \"a\": 1\n}").unwrap();
        measure.flush().unwrap();
        assert_eq!((measure.bytes, measure.newlines), (12, 2));
    }
}
