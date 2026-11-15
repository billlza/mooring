// SPDX-License-Identifier: GPL-3.0-or-later

//! Taking a live change back out of the running Xray (design §13.6). Once
//! the links are back on the generation before the change, the running Xray
//! is brought to hold exactly the clients that generation's `xray.json`
//! lists on the two VLESS inbounds, through its API, with no restart and no
//! stop.
//!
//! What the pinned source does (Xray v26.9.30, `b26a91de`, read on
//! 2026-11-15): `xray api rmu -tag=TAG -- EMAIL…` removes each email from the
//! inbound through `HandlerService.AlterInbound`
//! (`main/commands/all/api/inbound_user_remove.go`; the flags end at `--`),
//! and the validator folds it to lower case (`proxy/vless/validator.go`
//! `Del`). It prints each removal and each failure, then the number
//! removed, and exits 0 even when a removal failed: it exits 1 only when the
//! API cannot be reached. So the users read back decide, as for an opening.
//! A removed user's open connections stay open
//! (`proxy/vless/inbound/inbound.go` `RemoveUser`): the undo refuses only
//! new ones.

use std::collections::BTreeSet;
use std::path::Path;

use mooring_agent_proto::{ApplyStep, ManagedFile, RollbackCause};
use serde_json::Value;

use super::{
    Client, Difference, LIVE_INBOUNDS, LiveInbound, OpenError, Opening, add, api, difference, held,
    read_json, running, take_clients,
};
use crate::host::Node;
use crate::paths::Paths;
use crate::txn::changes::{Step, secrets};
use crate::txn::stage::{XRAY, program};

/// Brings the running Xray to hold exactly the clients of the `xray.json` in
/// `dir`, the generation the links are back on. A stopped Xray holds nothing
/// to take back and reads that file when it starts: it is asked nothing.
/// Every failure is [`ApplyStep::XrayUndo`]'s, scrubbed of that
/// generation's secrets.
pub(crate) fn take_back(paths: &Paths, node: &dyn Node, dir: &Path) -> Result<(), RollbackCause> {
    // Whether a unit runs is no secret, and no secret is read before it is
    // known.
    let asked = Step { node, secrets: &[] };
    if !running(node).map_err(|error| asked.failed(ApplyStep::XrayUndo, &error))? {
        return Ok(());
    }
    let secrets = secrets(dir, ApplyStep::XrayUndo)?;
    let step = Step {
        node,
        secrets: &secrets,
    };
    let config = read_json(&dir.join(ManagedFile::XrayConfig.file_name()))
        .map_err(|error| step.failed(ApplyStep::XrayUndo, &error))?;
    restore(node, &program(dir, XRAY), &paths.validate_dir(), &config).map_err(|error| {
        RollbackCause::Apply {
            step: ApplyStep::XrayUndo,
            stderr_tail: step.tail(error.to_string().as_bytes()),
        }
    })
}

/// Brings the running Xray, with `xray`, to hold exactly `config`'s clients
/// on each live inbound. Each inbound is read; every user it holds that the
/// file does not list exactly so is removed by email; then what it lacks of
/// the file's clients is added as the file lists them (removals first, since
/// `adu` refuses an email the inbound holds, as it holds a client the file
/// lists otherwise); then both inbounds are read back, and each must hold
/// exactly the file's clients. Inbounds that already do are only read.
pub(crate) fn restore(
    node: &dyn Node,
    xray: &Path,
    scratch: &Path,
    config: &Value,
) -> Result<(), OpenError> {
    let mut rest = config.clone();
    let mut listed = Vec::new();
    for tag in LIVE_INBOUNDS {
        let (clients, inbound) = take_clients(&mut rest, tag).ok_or(OpenError::Unlisted { tag })?;
        listed.push((tag, inbound, clients));
    }
    let mut printed = Vec::new();
    let mut asked = false;
    let mut inbounds = Vec::new();
    let mut first_read = Vec::new();
    for (tag, inbound, clients) in listed {
        let wanted: BTreeSet<Client> = clients.iter().cloned().collect();
        let holds = held(node, xray, tag)?;
        let out: Vec<&str> = holds
            .iter()
            .filter(|client| !client.email.is_empty() && !wanted.contains(*client))
            .map(|client| client.email.as_str())
            .collect();
        if !out.is_empty() {
            let tag_arg = format!("-tag={tag}");
            let mut args = vec![tag_arg.as_str(), "--"];
            args.extend(out);
            printed.extend(api(node, xray, "rmu", &args)?);
            asked = true;
        }
        let added = clients
            .into_iter()
            .filter(|client| !holds.contains(client))
            .collect();
        inbounds.push(LiveInbound {
            tag,
            inbound,
            added,
            clients: wanted,
        });
        first_read.push(holds);
    }
    let opening = Opening { inbounds };
    if opening.adds() {
        printed.extend(add(node, xray, scratch, &opening)?);
        asked = true;
    }
    for (live, holds) in opening.inbounds.iter().zip(first_read) {
        let now = if asked {
            held(node, xray, live.tag)?
        } else {
            holds
        };
        if let Some(Difference {
            missing,
            unexpected,
            differing,
        }) = difference(&live.clients, &now)
        {
            return Err(OpenError::Unrestored {
                tag: live.tag,
                missing,
                unexpected,
                differing,
                printed,
            });
        }
    }
    Ok(())
}
