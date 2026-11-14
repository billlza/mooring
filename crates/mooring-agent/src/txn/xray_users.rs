// SPDX-License-Identifier: GPL-3.0-or-later

//! Opening users on the running Xray (design §13.6). A transaction whose
//! `xray.json` differs from the generation before it only by clients added
//! to the two VLESS inbounds, with the same engines and unit, adds those
//! clients through Xray's API instead of restarting it, so that no
//! connection drops. Anything else restarts Xray, as every rollback does.
//!
//! What the pinned source does (Xray v26.9.30, `b26a91de`, read on
//! 2026-11-14):
//!
//! - `xray api adu FILE` decodes FILE as a configuration, builds each of
//!   its tagged inbounds as a start would (`infra/conf/xray.go`
//!   `InboundDetourConfig.Build`, `infra/conf/vless.go`), and adds each
//!   client with an email through `HandlerService.AlterInbound`
//!   (`main/commands/all/api/inbound_user_add.go`). It prints a result per
//!   user and exits 0 even when the engine refused one, as it refuses an
//!   email it holds (`proxy/vless/validator.go` `Add`); it exits 1 only when
//!   FILE cannot be read or decoded or the API cannot be reached.
//! - `xray api inbounduser -tag=TAG` prints the users the inbound holds
//!   (`app/proxyman/command/command.go` `GetInboundUsers`: the validator's
//!   email map, in no order) as indented JSON with every zero or empty field
//!   left out (`common/reflect/marshal.go`): `{}` with no users, the account
//!   as its typed message, named in `_TypedMessage_`, and the id in its
//!   canonical form (`common/uuid` `String`).
//!
//! So the users read back decide: whatever `adu` printed, the transaction
//! goes on only when each inbound holds exactly the file's clients. A
//! client the engine held already, as after a crash restart that read the
//! new file, is no failure.
//!
//! Removing a user through the API would not cut its open connections
//! (`proxy/vless/inbound/inbound.go` `RemoveUser` deletes only the
//! validator's entry), so a removal restarts.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::Path;

use mooring_agent_proto::{
    AgentError, ApplyStep, BundleHeader, EngineUser, IoOp, ManagedFile, RollbackCause, UnitName,
};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::changes::Step;
use crate::accounting::stats::XRAY_API_SERVER;
use crate::host::{Node, Tool};
use crate::paths::Paths;
use crate::store::{Scratch, ensure_dir, io_error, malformed};

/// The VLESS inbounds whose clients the running Xray takes, by tag (design
/// §8.2): REALITY, and the loopback inbound Hysteria 2 hands over to.
pub(crate) const LIVE_INBOUNDS: [&str; 2] = ["reality-in", "hy2-loop-in"];

/// The API listener the rendered configuration opens (design §8.2), as
/// [`XRAY_API_SERVER`] names it.
const API_LISTEN: &str = "127.0.0.1:10085";

/// The API service that adds and lists an inbound's users.
const HANDLER_SERVICE: &str = "HandlerService";

/// The typed message `inbounduser` names a VLESS account by.
const VLESS_ACCOUNT: &str = "xray.proxy.vless.Account";

/// The file `adu` reads, in the validators' scratch directory.
const REQUEST_FILE: &str = "xray-users.json";

/// A VLESS client: as the rendered configuration lists it, every field and
/// no other, and as the engine holds it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Client {
    /// The UUID.
    pub(crate) id: String,
    /// `xtls-rprx-vision`, or empty.
    pub(crate) flow: String,
    /// The policy level.
    pub(crate) level: u32,
    /// The accounting email.
    pub(crate) email: String,
}

impl Client {
    /// The client as the configuration lists it.
    fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "flow": self.flow,
            "level": self.level,
            "email": self.email,
        })
    }
}

/// One VLESS inbound's part of an [`Opening`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct LiveInbound {
    tag: &'static str,
    /// The inbound as `adu` builds its users: tag, address, port, protocol
    /// and settings, without clients.
    inbound: Value,
    /// The clients added, in the file's order.
    added: Vec<Client>,
    /// Every client the inbound holds once they are: the file's.
    clients: BTreeSet<Client>,
}

/// Clients to add to the running Xray, inbound by inbound, and what each
/// inbound then holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Opening {
    inbounds: Vec<LiveInbound>,
}

impl Opening {
    /// The emails added, inbound by inbound.
    #[cfg(test)]
    pub(crate) fn added(&self) -> Vec<(&'static str, Vec<&str>)> {
        self.inbounds
            .iter()
            .map(|inbound| {
                let emails = inbound.added.iter().map(|client| client.email.as_str());
                (inbound.tag, emails.collect())
            })
            .collect()
    }

    /// The configuration `adu` reads: each inbound with clients added,
    /// holding only those.
    fn request(&self) -> Value {
        let inbounds = self
            .inbounds
            .iter()
            .filter(|live| !live.added.is_empty())
            .map(|live| {
                let mut inbound = live.inbound.clone();
                inbound["settings"]["clients"] =
                    live.added.iter().map(Client::to_json).collect::<Value>();
                inbound
            })
            .collect::<Value>();
        json!({ "inbounds": inbounds })
    }
}

/// The opening that takes Xray from `before` to `next`, both `xray.json`:
/// `None` unless they differ only by clients added to the VLESS inbounds,
/// and `before` serves `HandlerService` on the rendered API listener.
///
/// Each VLESS inbound must appear once in each, with protocol `vless` and
/// settings of only `decryption: "none"` and its clients; each client must
/// list exactly the rendered fields, with an id in canonical form (as Xray
/// reads it back), and no two clients of an inbound may share an email in
/// any case (Xray keys emails so). Every client `before` had stays as it
/// was, and at least one is added.
pub(crate) fn classify(before: &Value, next: &Value) -> Option<Opening> {
    if !serves_handler(before) {
        return None;
    }
    let (mut before, mut next) = (before.clone(), next.clone());
    let mut inbounds = Vec::new();
    for tag in LIVE_INBOUNDS {
        let had: BTreeSet<Client> = take_clients(&mut before, tag)?.0.into_iter().collect();
        let (has, inbound) = take_clients(&mut next, tag)?;
        let clients: BTreeSet<Client> = has.iter().cloned().collect();
        if !had.is_subset(&clients) {
            return None;
        }
        let added = has
            .into_iter()
            .filter(|client| !had.contains(client))
            .collect();
        inbounds.push(LiveInbound {
            tag,
            inbound,
            added,
            clients,
        });
    }
    let adds = inbounds.iter().any(|live| !live.added.is_empty());
    (adds && before == next).then_some(Opening { inbounds })
}

/// Whether `config` serves `HandlerService` on the rendered API listener.
fn serves_handler(config: &Value) -> bool {
    let api = &config["api"];
    api["listen"] == API_LISTEN
        && api["services"]
            .as_array()
            .is_some_and(|services| services.iter().any(|service| service == HANDLER_SERVICE))
}

/// Removes the clients of the inbound tagged `tag` from `config` and
/// returns them, with the inbound as `adu` builds it; `None` unless the
/// inbound has the shape [`classify`] takes.
fn take_clients(config: &mut Value, tag: &str) -> Option<(Vec<Client>, Value)> {
    let mut tagged = config
        .get_mut("inbounds")?
        .as_array_mut()?
        .iter_mut()
        .filter(|inbound| inbound["tag"] == tag);
    let inbound = tagged.next()?.as_object_mut()?;
    if tagged.next().is_some() || inbound.get("protocol")? != "vless" {
        return None;
    }
    let settings = inbound.get_mut("settings")?.as_object_mut()?;
    let clients = settings.remove("clients")?;
    if settings.len() != 1 || settings.get("decryption")? != "none" {
        return None;
    }
    let clients: Vec<Client> = serde_json::from_value(clients).ok()?;
    let emails: BTreeSet<String> = clients
        .iter()
        .map(|client| client.email.to_lowercase())
        .collect();
    if emails.len() != clients.len() || !clients.iter().all(|client| canonical_uuid(&client.id)) {
        return None;
    }
    let mut built = Map::new();
    for key in ["tag", "listen", "port", "protocol", "settings"] {
        if let Some(value) = inbound.get(key) {
            built.insert(key.to_owned(), value.clone());
        }
    }
    Some((clients, Value::Object(built)))
}

/// Whether `text` is a UUID in canonical form: lowercase hexadecimal in
/// groups of 8, 4, 4, 4 and 12 digits joined by hyphens.
fn canonical_uuid(text: &str) -> bool {
    text.len() == 36
        && text.char_indices().all(|(at, digit)| match at {
            8 | 13 | 18 | 23 => digit == '-',
            _ => digit.is_ascii_digit() || ('a'..='f').contains(&digit),
        })
}

/// The opening that applies the generation in `dir` to the running Xray in
/// place of a restart, if there is one: its `xray.json` differs from
/// `before`'s only by clients added ([`classify`]), and Xray is running
/// (`systemctl is-active`), since an engine that is not cannot take them
/// and must start. A file of `before` that cannot be read or parsed counts
/// as a change of everything, as the tunnel's does.
pub(super) fn opening(
    paths: &Paths,
    step: &Step<'_>,
    before: &BundleHeader,
    dir: &Path,
) -> Result<Option<Opening>, RollbackCause> {
    let file = ManagedFile::XrayConfig.file_name();
    let next =
        read_json(&dir.join(file)).map_err(|error| step.failed(ApplyStep::XrayUsers, &error))?;
    let Ok(previous) = read_json(&paths.generation(before.config_generation).join(file)) else {
        return Ok(None);
    };
    let Some(opening) = classify(&previous, &next) else {
        return Ok(None);
    };
    let unit = UnitName::engine(EngineUser::Xray);
    let state = step
        .node
        .run(Tool::Systemctl, &["is-active", unit.as_str()])
        .map_err(|error| {
            let error = AgentError::Io {
                op: IoOp::SpawnProcess,
                errno: error.raw_os_error(),
            };
            step.failed(ApplyStep::XrayUsers, &error)
        })?;
    let running = state.success
        && String::from_utf8_lossy(&state.stdout)
            .lines()
            .eq(["active"]);
    Ok(running.then_some(opening))
}

fn read_json(path: &Path) -> Result<Value, AgentError> {
    let bytes = fs::read(path).map_err(|error| io_error(IoOp::ReadState, &error))?;
    serde_json::from_slice(&bytes).map_err(|_| malformed(IoOp::ReadState))
}

/// Why the running Xray was not brought to hold the file's clients. The
/// text reaches the Mac scrubbed of the generation's secrets, and names
/// users by email only, never by id.
#[derive(Debug, thiserror::Error)]
pub(crate) enum OpenError {
    /// The request file could not be written.
    #[error("cannot write the request for xray api adu: {0}")]
    Request(#[source] io::Error),
    /// `xray` could not be started.
    #[error("cannot start xray api {command}: {source}")]
    Spawn {
        /// The API command.
        command: &'static str,
        /// Why.
        #[source]
        source: io::Error,
    },
    /// `xray api` exited non-zero.
    #[error("xray api {command} failed: {}", String::from_utf8_lossy(stderr))]
    Api {
        /// The API command.
        command: &'static str,
        /// What it printed on stderr.
        stderr: Vec<u8>,
    },
    /// `inbounduser` printed what the pinned source never prints.
    #[error("xray api inbounduser -tag={tag} printed what the pinned Xray never prints")]
    Unreadable {
        /// The inbound.
        tag: &'static str,
    },
    /// The inbound holds other users than the file's clients. The finding
    /// comes last, so that a tail cut to its size keeps it.
    #[error(
        "xray api adu printed:\n{}\n{tag} holds other users than the file: not held {missing:?}, \
         held but not in the file {unexpected:?}, held otherwise {differing:?}",
        String::from_utf8_lossy(adu).trim_end()
    )]
    Held {
        /// The inbound.
        tag: &'static str,
        /// The emails of the file's clients the inbound does not hold.
        missing: Vec<String>,
        /// The emails the inbound holds that no client of the file has.
        unexpected: Vec<String>,
        /// The emails it holds with another id, flow or level.
        differing: Vec<String>,
        /// What `adu` printed.
        adu: Vec<u8>,
    },
}

/// Adds `opening`'s clients to the running Xray with `xray`, the
/// generation's own binary, through a request file in `scratch` (it holds
/// the clients' ids: mode 0600, removed whatever happens), then reads each
/// inbound back and requires exactly the file's clients.
pub(crate) fn open(
    node: &dyn Node,
    xray: &Path,
    scratch: &Path,
    opening: &Opening,
) -> Result<(), OpenError> {
    ensure_dir(scratch).map_err(OpenError::Request)?;
    let request = Scratch::write(
        scratch.join(REQUEST_FILE),
        opening.request().to_string().as_bytes(),
    )
    .map_err(OpenError::Request)?;
    let request_arg = request.path().display().to_string();
    let adu = api(node, xray, "adu", &[&request_arg])?;
    drop(request);
    for live in &opening.inbounds {
        let tag = format!("-tag={}", live.tag);
        let reply = api(node, xray, "inbounduser", &[&tag])?;
        let held = parse_held(&reply).ok_or(OpenError::Unreadable { tag: live.tag })?;
        compare(live, &held, &adu)?;
    }
    Ok(())
}

/// Runs `xray api <command> --server=… <args>`; its stdout, or why not.
fn api(
    node: &dyn Node,
    xray: &Path,
    command: &'static str,
    args: &[&str],
) -> Result<Vec<u8>, OpenError> {
    let mut all = vec!["api", command, XRAY_API_SERVER];
    all.extend_from_slice(args);
    let output = node
        .run_program(xray, &all, &[])
        .map_err(|source| OpenError::Spawn { command, source })?;
    if output.success {
        Ok(output.stdout)
    } else {
        Err(OpenError::Api {
            command,
            stderr: output.stderr,
        })
    }
}

/// `inbounduser`'s reply: `{}` with no users.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HeldReply {
    #[serde(default)]
    users: Vec<HeldUser>,
}

/// A user as `inbounduser` prints it: a level of 0 and an empty email are
/// left out.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HeldUser {
    #[serde(default)]
    level: u32,
    #[serde(default)]
    email: String,
    account: HeldAccount,
}

/// A VLESS account as `inbounduser` prints it: an empty id or flow is left
/// out, as is every field the rendered clients never set.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HeldAccount {
    #[serde(rename = "_TypedMessage_")]
    message: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    flow: String,
}

/// The users an inbound holds, from `inbounduser`'s output: `None` for
/// anything the pinned source never prints, such as an account that is not
/// VLESS, or two users sharing an email: the engine keys its users by
/// email, folded to lower case, and refuses a second (an empty email is
/// not keyed).
pub(crate) fn parse_held(stdout: &[u8]) -> Option<Vec<Client>> {
    let reply: HeldReply = serde_json::from_slice(stdout).ok()?;
    let held: Vec<Client> = reply
        .users
        .into_iter()
        .map(|user| {
            (user.account.message == VLESS_ACCOUNT).then_some(Client {
                id: user.account.id,
                flow: user.account.flow,
                level: user.level,
                email: user.email,
            })
        })
        .collect::<Option<_>>()?;
    let mut keys = BTreeSet::new();
    held.iter()
        .filter(|client| !client.email.is_empty())
        .all(|client| keys.insert(client.email.to_lowercase()))
        .then_some(held)
}

/// Requires `held`, what the inbound holds as [`parse_held`] reads it, to
/// be exactly the file's clients, and names every email that differs
/// otherwise. The file's clients all have emails, distinct as the engine
/// keys them, so `held` matches them as a set only when it lists each of
/// them once and nothing else.
fn compare(live: &LiveInbound, held: &[Client], adu: &[u8]) -> Result<(), OpenError> {
    let held_set: BTreeSet<&Client> = held.iter().collect();
    let expected: BTreeSet<&Client> = live.clients.iter().collect();
    if held_set == expected {
        return Ok(());
    }
    let held_emails = emails(held.iter());
    let file_emails = emails(live.clients.iter());
    let differing =
        emails(held.iter().filter(|client| {
            file_emails.contains(&client.email) && !live.clients.contains(*client)
        }));
    Err(OpenError::Held {
        tag: live.tag,
        missing: file_emails.difference(&held_emails).cloned().collect(),
        unexpected: held_emails.difference(&file_emails).cloned().collect(),
        differing: differing.into_iter().collect(),
        adu: adu.to_vec(),
    })
}

fn emails<'a>(clients: impl Iterator<Item = &'a Client>) -> BTreeSet<String> {
    clients.map(|client| client.email.clone()).collect()
}
