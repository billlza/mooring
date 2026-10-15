// SPDX-License-Identifier: GPL-3.0-or-later

//! The M7 router adapter (design §15.6): read only towards the M7.
//!
//! `status` and `capture` follow one order, so nothing secret is sent
//! before it may be:
//!
//! 1. the pinned identity and (unless the capture is anonymous) the admin
//!    password are read; nothing has touched the network yet;
//! 2. the interface's index and default gateway;
//! 3. the anonymous `GET` of `model.json`, which must come from an MR7450,
//!    through the M7's session set-up when it asks for one (design §15.6
//!    rule 9: at most three requests);
//! 4. the identity check: the gateway's link-layer address equals the pin;
//! 5. unless the anonymous answer is already an administrator's, and only
//!    when the M7 reports no password cool-off, the login `POST`; a `302`
//!    to the M7's login-failed page ends the command there (`LoginRefused`,
//!    with the page's `errno` and `errdetail` when each has its shape;
//!    nothing more is sent), and any other answer is followed by a second
//!    read of `model.json` with the session's cookies, which may go through
//!    the set-up the same way and whose session decides;
//! 6. the document is parsed (`status`) or redacted (`capture`) through
//!    `daemon-core`'s one allowlist.

pub(crate) mod cookies;
pub(crate) mod error;
pub(crate) mod form;
pub(crate) mod http;
pub(crate) mod link;
pub(crate) mod output;

use std::fmt;
use std::path::Path;

use mooring_daemon_core::router::netgear::{
    RedactedModelJson, parse_netgear_model_json, parse_netgear_session, redact_netgear_model_json,
};
use mooring_daemon_core::{RouterParseError, RouterStatus};
use mooring_model::iface::{BsdName, MacAddr};
use mooring_model::secret::{RouterAdminPassword, SecretMaterial, SecretRef};
use mooring_store::{RouterPin, SecretStore, SecretStoreError, read_router_pin};

use crate::error::{CommandError, LocalError};
use crate::router::error::{
    AuthCause, LoginAnswer, Missing, RouterError, UnreachableCause, UnsupportedCause,
};
use crate::router::form::LoginBody;
use crate::router::http::{Body, Client, Timeouts};
use crate::router::link::{
    Attachment, GatewayLink, LinkLayer, attach, check_identity, gateway_link,
};

/// What the router commands reach the world through.
pub(crate) struct RouterEnv<'a> {
    /// The kernel's interface, routing and neighbour tables.
    pub(crate) link: &'a dyn LinkLayer,
    /// The M7's HTTP port (80; a loopback stub's port in tests).
    pub(crate) port: u16,
    /// The client's limits on time.
    pub(crate) timeouts: Timeouts,
}

impl fmt::Debug for RouterEnv<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RouterEnv")
            .field("port", &self.port)
            .field("timeouts", &self.timeouts)
            .finish_non_exhaustive()
    }
}

/// Step 1: the pinned identity; `NotConfigured{Pin}` without one.
pub(crate) fn configured_pin(support_dir: &Path) -> Result<RouterPin, CommandError> {
    read_router_pin(support_dir)
        .map_err(|error| CommandError::Local(LocalError::Store(error)))?
        .ok_or(CommandError::Router(RouterError::NotConfigured {
            missing: Missing::Pin,
        }))
}

/// Step 1: the admin password; `NotConfigured{Password}` without one.
pub(crate) fn configured_password(
    secrets: &dyn SecretStore,
) -> Result<RouterAdminPassword, CommandError> {
    match secrets.get(&SecretRef::RouterAdmin) {
        Ok(SecretMaterial::RouterAdminPassword(password)) => Ok(password),
        Ok(_) => Err(CommandError::Local(LocalError::Keychain(
            SecretStoreError::ItemInvalid {
                secret_ref: SecretRef::RouterAdmin,
            },
        ))),
        Err(SecretStoreError::SecretMissing { .. }) => {
            Err(CommandError::Router(RouterError::NotConfigured {
                missing: Missing::Password,
            }))
        }
        Err(other) => Err(CommandError::Local(LocalError::Keychain(other))),
    }
}

/// The document a session read: the body and the login's answer (`None`
/// when no login was sent).
#[derive(Debug)]
struct Fetched {
    body: Body,
    login: Option<LoginAnswer>,
}

/// Steps 2 to 5.
fn fetch(
    env: &RouterEnv<'_>,
    interface: &BsdName,
    pin: &RouterPin,
    password: Option<&RouterAdminPassword>,
) -> Result<Fetched, CommandError> {
    let attachment = attach(env.link, interface)?;
    let mut client = Client::new(attachment.endpoint(env.port), env.timeouts);
    let anonymous = client.model_json()?;
    let session = parse_netgear_session(anonymous.as_bytes())
        .map_err(|error| RouterError::Document { error, login: None })?;
    let verified = check_identity(env.link, &attachment, pin, env.port)?;
    let Some(password) = password else {
        return Ok(Fetched {
            body: anonymous,
            login: None,
        });
    };
    if session.is_admin() {
        return Ok(Fetched {
            body: anonymous,
            login: None,
        });
    }
    if session.cooloff() != 0 {
        return Err(CommandError::Router(RouterError::AuthFailed {
            cause: AuthCause::Cooloff {
                reported: session.cooloff(),
            },
        }));
    }
    let body = LoginBody::new(&verified, session.token(), password);
    let login = client.login(&verified, &body)?;
    if let Some(cause) = login.refusal() {
        return Err(CommandError::Router(RouterError::AuthFailed { cause }));
    }
    Ok(Fetched {
        body: client.model_json()?,
        login: Some(login),
    })
}

/// `router status`: the M7's status, logging in as needed.
pub(crate) fn status(
    env: &RouterEnv<'_>,
    support_dir: &Path,
    secrets: &dyn SecretStore,
    interface: &BsdName,
) -> Result<RouterStatus, CommandError> {
    let pin = configured_pin(support_dir)?;
    let password = configured_password(secrets)?;
    let fetched = fetch(env, interface, &pin, Some(&password))?;
    parse_netgear_model_json(fetched.body.as_bytes()).map_err(|error| {
        CommandError::Router(RouterError::Document {
            error,
            login: fetched.login,
        })
    })
}

/// `router capture`: the redacted document, an administrator's unless
/// `anonymous` (then no password is read and no login is sent). Only
/// `redact_netgear_model_json` constructs a [`RedactedModelJson`], so what
/// a capture writes is the redactor's output and never a raw document.
pub(crate) fn capture(
    env: &RouterEnv<'_>,
    support_dir: &Path,
    secrets: &dyn SecretStore,
    interface: &BsdName,
    anonymous: bool,
) -> Result<RedactedModelJson, CommandError> {
    let pin = configured_pin(support_dir)?;
    let password = if anonymous {
        None
    } else {
        Some(configured_password(secrets)?)
    };
    let fetched = fetch(env, interface, &pin, password.as_ref())?;
    if !anonymous {
        let refused = |error| {
            CommandError::Router(RouterError::Document {
                error,
                login: fetched.login,
            })
        };
        let session = parse_netgear_session(fetched.body.as_bytes()).map_err(refused)?;
        if !session.is_admin() {
            return Err(refused(RouterParseError::NotAdmin));
        }
    }
    redact_netgear_model_json(fetched.body.as_bytes()).map_err(|error| {
        CommandError::Router(RouterError::Document {
            error,
            login: fetched.login,
        })
    })
}

/// What `router pin` found: the interface, its gateway and the gateway's
/// link-layer address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PinCandidate {
    /// The interface and its gateway.
    pub(crate) attachment: Attachment,
    /// The gateway's link-layer address.
    pub(crate) lladdr: MacAddr,
}

/// Opens one TCP connection to the gateway and closes it, sending no
/// bytes, so the kernel resolves the gateway's link-layer address.
fn warm_neighbour_table(env: &RouterEnv<'_>, attachment: &Attachment) -> Result<(), RouterError> {
    http::connect_only(&attachment.endpoint(env.port), &env.timeouts)
}

/// `router pin`, its read-only part: the gateway's link-layer address
/// (design §15.6 rules 4 and 10).
///
/// A first read of the neighbour table that finds an address, or one that
/// cannot identify a device, decides with no connection. When it has no
/// address for the gateway (no entry, one still being resolved, or an
/// empty table, which may only be cold), one connection that sends nothing
/// asks the kernel to resolve it, and the table is read again:
/// - an address, or one that cannot identify a device, decides as in a
///   first read, whether or not the connection succeeded: the address is
///   trusted as a first read's would be, and the operator's confirmation is
///   the safeguard;
/// - still no address after a connection that failed: that failure;
/// - still no address after one that succeeded: `GatewayUnresolved`, unless
///   both reads returned an empty table, which is the local
///   `NeighbourTableHidden`. A first read that was not empty showed that
///   this binary can read the table, so an empty second read does not make
///   it hidden.
///
/// A kernel failure of either read is the error; the second read's takes
/// precedence over a connection that failed.
pub(crate) fn pin_candidate(
    env: &RouterEnv<'_>,
    interface: &BsdName,
) -> Result<PinCandidate, CommandError> {
    let attachment = attach(env.link, interface)?;
    let found = match gateway_link(env.link, &attachment)? {
        first @ (GatewayLink::Unresolved | GatewayLink::TableEmpty) => {
            let warmed = warm_neighbour_table(env, &attachment);
            let second = gateway_link(env.link, &attachment)?;
            match (first, second, warmed) {
                (_, GatewayLink::Unresolved | GatewayLink::TableEmpty, Err(connect)) => {
                    return Err(CommandError::Router(connect));
                }
                // Readable before the warm-up, so not hidden after it.
                (GatewayLink::Unresolved, GatewayLink::TableEmpty, Ok(())) => {
                    GatewayLink::Unresolved
                }
                (_, second, _) => second,
            }
        }
        first => first,
    };
    // A `TableEmpty` here is one both reads returned, around a warm-up that
    // reached the gateway.
    match found {
        GatewayLink::Address(lladdr) => Ok(PinCandidate { attachment, lladdr }),
        GatewayLink::Unusable(unusable) => Err(CommandError::Router(RouterError::Unsupported {
            cause: UnsupportedCause::GatewayLink(unusable),
        })),
        GatewayLink::Unresolved => Err(CommandError::Router(RouterError::unreachable(
            UnreachableCause::GatewayUnresolved,
        ))),
        GatewayLink::TableEmpty => Err(CommandError::Local(LocalError::NeighbourTableHidden)),
    }
}

/// What `router pin` does with an existing pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PinDecision {
    /// The same address is pinned: nothing is written.
    AlreadyPinned,
    /// Write the pin (there is none, or `--replace` replaces another).
    Write,
}

/// Decides what to do with `existing`: the same address is already
/// pinned; another one is replaced only with `replace`
/// (`PinExists` otherwise).
pub(crate) fn decide_pin(
    existing: Option<&RouterPin>,
    lladdr: MacAddr,
    replace: bool,
) -> Result<PinDecision, LocalError> {
    match existing {
        Some(pin) if pin.gateway_lladdr == lladdr => Ok(PinDecision::AlreadyPinned),
        Some(pin) if !replace => Err(LocalError::PinExists {
            pinned: pin.gateway_lladdr,
        }),
        Some(_) | None => Ok(PinDecision::Write),
    }
}
