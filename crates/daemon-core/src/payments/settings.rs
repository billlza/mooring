// SPDX-License-Identifier: GPL-3.0-or-later

//! The pull's settings (design §9.6): `payment-pull.json`, which
//! `mooringctl portal connect | rehearsal | stripe-check | plans |
//! disconnect` write and the daemon reads, the plans on the Mac among them
//! ([`PlanBook`]). The token and Stripe's read key are not here: they are
//! keychain items (`SecretRef::PortalPullToken`,
//! `SecretRef::StripeReadKey`).
//!
//! Every change raises the revision, and the file is kept when the pull is
//! disconnected, so a revision is never used twice: a stop records the
//! revision it was made under, and ends when the settings move past it.

use std::fmt;

use mooring_model::dns::DnsName;
use serde::{Deserialize, Serialize};

use super::ledger::Stop;
use super::plans::PlanBook;

/// The settings' version: 3 since the plans on the Mac (2026-11-14).
/// Version 2, which had the check against Stripe and no plans, is read
/// with none; version 1, which had neither, with the check off too.
pub const SETTINGS_VERSION: u32 = 3;

/// The version before the plans on the Mac.
const SETTINGS_VERSION_2: u32 = 2;

/// The version before the check against Stripe.
const SETTINGS_VERSION_1: u32 = 1;

/// The largest settings file read, in bytes: the most plans kept, each as
/// long as the portal lets a plan be, take 36 280 bytes with the longest
/// origin.
pub const MAX_SETTINGS_BYTES: usize = 64 * 1024;

/// The path of the portal's answer to a pull.
pub const ENTITLEMENTS_PATH: &str = "/api/mooring/entitlements";

/// An origin that is not `https://` with a DNS name and an optional port.
/// The text is never echoed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "the portal's address must be https:// followed by a lower-case DNS name and an optional port (1 to 65535), with nothing after it"
)]
pub struct OriginError;

/// Where the portal answers: `https://` with a lower-case DNS name (never an
/// address) and an optional port, and nothing else (no user, path, query
/// or fragment).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PortalOrigin {
    host: DnsName,
    port: Option<u16>,
}

impl PortalOrigin {
    /// Accepts `https://<host>` or `https://<host>:<port>`: the host a
    /// lower-case DNS name whose top label is not all digits (so never an
    /// IPv4 address), the port 1 to 65535 without a leading zero.
    pub fn parse(text: &str) -> Result<Self, OriginError> {
        let rest = text.strip_prefix("https://").ok_or(OriginError)?;
        let (host, port) = match rest.split_once(':') {
            None => (rest, None),
            Some((host, port)) => (host, Some(parse_port(port)?)),
        };
        let host = DnsName::parse(host).map_err(|_| OriginError)?;
        Ok(Self { host, port })
    }

    /// The host.
    #[must_use]
    pub const fn host(&self) -> &DnsName {
        &self.host
    }

    /// The address of the entries after `after`.
    #[must_use]
    pub fn entitlements_url(&self, after: u64) -> String {
        format!("{self}{ENTITLEMENTS_PATH}?after={after}")
    }
}

fn parse_port(text: &str) -> Result<u16, OriginError> {
    let canonical = !text.is_empty()
        && text.len() <= 5
        && text.bytes().all(|byte| byte.is_ascii_digit())
        && !text.starts_with('0');
    if !canonical {
        return Err(OriginError);
    }
    text.parse::<u16>().map_err(|_| OriginError)
}

impl fmt::Display for PortalOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "https://{}", self.host.as_str())?;
        match self.port {
            Some(port) => write!(f, ":{port}"),
            None => Ok(()),
        }
    }
}

impl TryFrom<String> for PortalOrigin {
    type Error = OriginError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::parse(&text)
    }
}

impl From<PortalOrigin> for String {
    fn from(origin: PortalOrigin) -> Self {
        origin.to_string()
    }
}

/// The settings could not be read.
#[derive(Debug, thiserror::Error)]
pub enum SettingsError {
    /// Larger than [`MAX_SETTINGS_BYTES`].
    #[error("the payment pull's settings are larger than {MAX_SETTINGS_BYTES} bytes")]
    TooLarge,
    /// Not the settings' document.
    #[error("the payment pull's settings do not decode")]
    Decode(#[source] serde_json::Error),
    /// Of another version.
    #[error(
        "the payment pull's settings are of version {found}, and this build reads versions 1 to {SETTINGS_VERSION}"
    )]
    UnknownVersion {
        /// The version written.
        found: u32,
    },
    /// Encoding failed.
    #[error("the payment pull's settings could not be encoded")]
    Encode(#[source] serde_json::Error),
}

/// The pull's settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullSettings {
    revision: u64,
    origin: Option<PortalOrigin>,
    rehearsal: bool,
    stripe_check: bool,
    plans: PlanBook,
}

/// The version of a document on disk, read first to choose its shape.
#[derive(Debug, Deserialize)]
struct Version {
    version: u32,
}

/// The document on disk, as read.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SettingsFile {
    /// [`SETTINGS_VERSION`], read first ([`Version`]).
    #[serde(rename = "version")]
    _version: u32,
    revision: u64,
    #[serde(deserialize_with = "Option::deserialize")]
    origin: Option<PortalOrigin>,
    rehearsal: bool,
    stripe_check: bool,
    plans: PlanBook,
}

/// A version-2 document, from before the plans on the Mac.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SettingsFileV2 {
    /// [`SETTINGS_VERSION_2`], read first ([`Version`]).
    #[serde(rename = "version")]
    _version: u32,
    revision: u64,
    #[serde(deserialize_with = "Option::deserialize")]
    origin: Option<PortalOrigin>,
    rehearsal: bool,
    stripe_check: bool,
}

/// A version-1 document, from before the check against Stripe.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SettingsFileV1 {
    /// [`SETTINGS_VERSION_1`], read first ([`Version`]).
    #[serde(rename = "version")]
    _version: u32,
    revision: u64,
    #[serde(deserialize_with = "Option::deserialize")]
    origin: Option<PortalOrigin>,
    rehearsal: bool,
}

/// The document on disk, as written: [`SettingsFile`]'s keys in its order.
#[derive(Debug, Serialize)]
struct SettingsFileRef<'a> {
    version: u32,
    revision: u64,
    origin: Option<&'a PortalOrigin>,
    rehearsal: bool,
    stripe_check: bool,
    plans: &'a PlanBook,
}

/// The settings as their file holds them.
impl Serialize for PullSettings {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        SettingsFileRef {
            version: SETTINGS_VERSION,
            revision: self.revision,
            origin: self.origin.as_ref(),
            rehearsal: self.rehearsal,
            stripe_check: self.stripe_check,
            plans: &self.plans,
        }
        .serialize(serializer)
    }
}

impl PullSettings {
    /// The revision a change makes: above the settings' own (`current`) and
    /// above the revision of the ledger's stop, so a stop never outlives a
    /// change even when the file was lost.
    #[must_use]
    pub fn next_revision(current: Option<&Self>, stop: Option<Stop>) -> u64 {
        let settings = current.map_or(0, |settings| settings.revision);
        let stopped = stop.map_or(0, |stop| stop.settings_revision);
        settings.max(stopped).saturating_add(1)
    }

    /// Settings that pull from `origin`, in rehearsal or not, with the
    /// check against Stripe on or off, and no plans, at `revision`.
    #[must_use]
    pub fn connected(
        revision: u64,
        origin: PortalOrigin,
        rehearsal: bool,
        stripe_check: bool,
    ) -> Self {
        Self {
            revision,
            origin: Some(origin),
            rehearsal,
            stripe_check,
            plans: PlanBook::default(),
        }
    }

    /// Settings that pull from nowhere, with the check against Stripe on or
    /// off for when the pull is connected again, and no plans, at
    /// `revision`.
    #[must_use]
    pub fn disconnected(revision: u64, stripe_check: bool) -> Self {
        Self {
            revision,
            origin: None,
            rehearsal: false,
            stripe_check,
            plans: PlanBook::default(),
        }
    }

    /// These settings pulling from `origin`, at `revision`: the rehearsal,
    /// the check against Stripe and the plans as they were.
    #[must_use]
    pub fn connecting(&self, revision: u64, origin: PortalOrigin) -> Self {
        Self {
            revision,
            origin: Some(origin),
            ..self.clone()
        }
    }

    /// These settings pulling from nowhere, at `revision`: the rehearsal
    /// off, and the check against Stripe and the plans kept for when the
    /// pull is connected again.
    #[must_use]
    pub fn disconnecting(&self, revision: u64) -> Self {
        Self {
            revision,
            origin: None,
            rehearsal: false,
            ..self.clone()
        }
    }

    /// These settings with the plans `plans` (none: the plan check off),
    /// at `revision`.
    #[must_use]
    pub fn planning(&self, revision: u64, plans: PlanBook) -> Self {
        Self {
            revision,
            plans,
            ..self.clone()
        }
    }

    /// These settings with `rehearsal`, at `revision`.
    #[must_use]
    pub fn rehearsing(&self, revision: u64, rehearsal: bool) -> Self {
        Self {
            revision,
            rehearsal,
            ..self.clone()
        }
    }

    /// These settings with the check against Stripe on or off, at
    /// `revision`.
    #[must_use]
    pub fn checking(&self, revision: u64, stripe_check: bool) -> Self {
        Self {
            revision,
            stripe_check,
            ..self.clone()
        }
    }

    /// The revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Where to pull from, or `None` when the pull is disconnected.
    #[must_use]
    pub const fn origin(&self) -> Option<&PortalOrigin> {
        self.origin.as_ref()
    }

    /// Whether the operator rehearses: test-mode payments are granted and
    /// count while this holds.
    #[must_use]
    pub const fn rehearsal(&self) -> bool {
        self.rehearsal
    }

    /// Whether the check against Stripe is on (design §9.6): each live
    /// grant that would give a period or a pack waits until Stripe confirms
    /// its payment, and is held when Stripe does not.
    #[must_use]
    pub const fn stripe_check(&self) -> bool {
        self.stripe_check
    }

    /// The plans the Mac knows (design §9.6): while there are any, a live
    /// grant that would give a period or a pack is granted only at the
    /// terms of one of them.
    #[must_use]
    pub const fn plans(&self) -> &PlanBook {
        &self.plans
    }

    /// Reads the settings file, of this version, of version 2, which is
    /// read with no plans, or of version 1, which is read with the check
    /// against Stripe off too.
    pub fn decode(bytes: &[u8]) -> Result<Self, SettingsError> {
        if bytes.len() > MAX_SETTINGS_BYTES {
            return Err(SettingsError::TooLarge);
        }
        let Version { version } = serde_json::from_slice(bytes).map_err(SettingsError::Decode)?;
        match version {
            SETTINGS_VERSION => {
                let file: SettingsFile =
                    serde_json::from_slice(bytes).map_err(SettingsError::Decode)?;
                Ok(Self {
                    revision: file.revision,
                    origin: file.origin,
                    rehearsal: file.rehearsal,
                    stripe_check: file.stripe_check,
                    plans: file.plans,
                })
            }
            SETTINGS_VERSION_2 => {
                let file: SettingsFileV2 =
                    serde_json::from_slice(bytes).map_err(SettingsError::Decode)?;
                Ok(Self {
                    revision: file.revision,
                    origin: file.origin,
                    rehearsal: file.rehearsal,
                    stripe_check: file.stripe_check,
                    plans: PlanBook::default(),
                })
            }
            SETTINGS_VERSION_1 => {
                let file: SettingsFileV1 =
                    serde_json::from_slice(bytes).map_err(SettingsError::Decode)?;
                Ok(Self {
                    revision: file.revision,
                    origin: file.origin,
                    rehearsal: file.rehearsal,
                    stripe_check: false,
                    plans: PlanBook::default(),
                })
            }
            found => Err(SettingsError::UnknownVersion { found }),
        }
    }

    /// The file: pretty-printed JSON with a trailing newline.
    pub fn encode(&self) -> Result<Vec<u8>, SettingsError> {
        let mut bytes = serde_json::to_vec_pretty(self).map_err(SettingsError::Encode)?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}
