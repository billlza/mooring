// SPDX-License-Identifier: GPL-3.0-or-later

//! `mooringctl abuse records | cut | clear` (design §11.8): a node's cuts
//! and abuse records, kept in this Mac's copy (`abuse/records.json`, 13
//! months), and the operator's own cut and lift on a node. Each command
//! asks one node over the operations key, bound to the interface facing
//! the M7. None changes the deployment's state: a suspension for the
//! review is `user suspend` (§7).
//!
//! What it prints names users by opaque id, never by label, with the
//! records' aggregate figures; no record holds a destination.

use std::io::Write;
use std::time::{Duration, Instant};

use mooring_agent_proto::{
    AbuseAction, AbuseCuts, AbuseFigures, AbuseRecord, AbuseRecordsV1, AbuseSeq,
    DESTINATION_BUCKETS, LineRequest, OpaqueUserId, RequestKind, Response, estimate_distinct,
};
use mooring_daemon_core::abuse::{MAC_ABUSE_RECORDS_MAX_BYTES, MacAbuseRecords};
use mooring_daemon_core::control::{MAX_REPLY_LINE_BYTES, encode_line};
use mooring_model::iface::BsdName;
use mooring_model::{CalendarDate, NodeId, UserId};
use mooring_store::{Store, update_abuse_records};

use crate::app::{Env, support_dir};
use crate::error::{CommandError, LocalError};
use crate::node::session::{deployed_node, ops_session};
use crate::node::{NodeError, NodeSession};
use crate::state::{load, output, store_failure};

/// How long one command may take with its node.
const NODE_DEADLINE: Duration = Duration::from_secs(45);

/// The most pages `abuse records` reads: a node keeps at most 4,096
/// records, eight pages of 512.
const MAX_PAGES: usize = 16;

/// `abuse records <node>`: every record the node keeps, page by page,
/// merged into this Mac's copy (pruned of what is past its 13 months), then
/// printed: one JSON line per page with `--json`, else a summary.
pub(crate) fn records(
    env: &Env<'_>,
    out: &mut dyn Write,
    node: &NodeId,
    interface: &BsdName,
    json: bool,
) -> Result<(), CommandError> {
    let mut session = session(env, node, interface)?;
    let mut pages: Vec<AbuseRecordsV1> = Vec::new();
    let mut since = AbuseSeq::FIRST;
    for _ in 0..MAX_PAGES {
        let page = match session.request(&LineRequest::AbuseRecords { since })? {
            Response::AbuseRecords(page) => *page,
            other => return Err(unexpected(RequestKind::AbuseRecords, &other)),
        };
        let next = page.records().last().map(|last| last.seq.get() + 1);
        let end = page.end();
        pages.push(page);
        match next {
            Some(next) if next < end.get() => since = AbuseSeq::new(next),
            _ => break,
        }
    }
    let now = (env.clock)()?;
    let now = mooring_agent_proto::UnixTime::from_secs(now.as_secs());
    let added = keep(env, node, &pages, now)?;
    let Some(last) = pages.last() else {
        return Ok(());
    };
    if json {
        for page in &pages {
            let line = encode_line(page, MAX_REPLY_LINE_BYTES).map_err(LocalError::ClientEncode)?;
            out.write_all(&line).map_err(output)?;
        }
        return Ok(());
    }
    write_cuts(out, node, last.cuts())?;
    let records: Vec<&AbuseRecord> = pages.iter().flat_map(|page| page.records()).collect();
    writeln!(
        out,
        "{node}: {} records kept on the node, {added} new to this Mac's copy",
        records.len()
    )
    .map_err(output)?;
    for record in records {
        writeln!(out, "  {}", record_line(record)).map_err(output)?;
    }
    Ok(())
}

/// `abuse cut <node> <user>`: cuts the user on the node at once.
pub(crate) fn cut(
    env: &Env<'_>,
    out: &mut dyn Write,
    node: &NodeId,
    user: &UserId,
    interface: &BsdName,
) -> Result<(), CommandError> {
    let opaque = known_user(env, user)?;
    let mut session = session(env, node, interface)?;
    match session.request(&LineRequest::AbuseCut { user: opaque })? {
        Response::AbuseCutDone { record, cuts } => {
            writeln!(
                out,
                "{node}: user {user} is cut (record {}); lift it with `abuse clear`",
                record.get()
            )
            .map_err(output)?;
            write_cuts(out, node, &cuts)
        }
        other => Err(unexpected(RequestKind::AbuseCut, &other)),
    }
}

/// `abuse clear <node> <user>`: lifts the user's cut on the node at once.
pub(crate) fn clear(
    env: &Env<'_>,
    out: &mut dyn Write,
    node: &NodeId,
    user: &UserId,
    interface: &BsdName,
) -> Result<(), CommandError> {
    let opaque = known_user(env, user)?;
    let mut session = session(env, node, interface)?;
    match session.request(&LineRequest::AbuseClear { user: opaque })? {
        Response::AbuseCleared { record, cuts } => {
            match record {
                Some(record) => writeln!(
                    out,
                    "{node}: user {user}'s cut is lifted (record {})",
                    record.get()
                ),
                None => writeln!(out, "{node}: user {user} was not cut"),
            }
            .map_err(output)?;
            write_cuts(out, node, &cuts)
        }
        other => Err(unexpected(RequestKind::AbuseClear, &other)),
    }
}

/// The node's session, for a node the deployment has adopted or applied.
fn session<'a>(
    env: &Env<'a>,
    node: &NodeId,
    interface: &BsdName,
) -> Result<Box<dyn NodeSession + 'a>, CommandError> {
    let state = load(&Store::new(support_dir(env)?))?;
    let target = deployed_node(state.deployment.nodes(), node)?;
    ops_session(env, target, interface, Some(Instant::now() + NODE_DEADLINE))
}

/// The user's id as a node knows it, for a user of the deployment.
fn known_user(env: &Env<'_>, user: &UserId) -> Result<OpaqueUserId, CommandError> {
    let state = load(&Store::new(support_dir(env)?))?;
    if !state.deployment.users().contains_key(user) {
        return Err(LocalError::UnknownUser { user: user.clone() }.into());
    }
    OpaqueUserId::new(user.as_str())
        .map_err(|_| LocalError::UnknownUser { user: user.clone() }.into())
}

/// Merges the pages into this Mac's copy, pruned at `now`; returns how
/// many records were new to it.
fn keep(
    env: &Env<'_>,
    node: &NodeId,
    pages: &[AbuseRecordsV1],
    now: mooring_agent_proto::UnixTime,
) -> Result<usize, CommandError> {
    let mut added = 0;
    update_abuse_records(&support_dir(env)?, MAC_ABUSE_RECORDS_MAX_BYTES, |bytes| {
        let mut copy = MacAbuseRecords::decode(bytes.as_deref())?;
        copy.prune(now);
        for page in pages {
            added += copy.merge(node, page)?;
        }
        copy.encode()
    })
    .map_err(store_failure)?
    .map_err(LocalError::AbuseRecords)?;
    Ok(added)
}

fn write_cuts(out: &mut dyn Write, node: &NodeId, cuts: &AbuseCuts) -> Result<(), CommandError> {
    writeln!(out, "{node}: {} users cut", cuts.len()).map_err(output)?;
    for cut in cuts.entries() {
        writeln!(
            out,
            "  {} cut since {} (record {})",
            cut.user,
            utc_text(cut.since),
            cut.record.get()
        )
        .map_err(output)?;
    }
    Ok(())
}

/// One record: its number, time, user, what happened and its figures.
fn record_line(record: &AbuseRecord) -> String {
    let action = match record.action {
        AbuseAction::Cut { findings } => format!(
            "cut for {}",
            findings
                .iter()
                .map(|finding| finding.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        AbuseAction::Alerted { findings } => format!(
            "alert for {}",
            findings
                .iter()
                .map(|finding| finding.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        AbuseAction::OperatorCut => "cut by the operator".to_owned(),
        AbuseAction::Cleared => "cut lifted by the operator".to_owned(),
    };
    let figures = record.figures.map_or(String::new(), |figures| {
        format!(" [{}]", figures_text(&figures))
    });
    format!(
        "#{} {} {}: {action}{figures}",
        record.seq.get(),
        utc_text(record.at),
        record.user
    )
}

/// The figures as the review reads them.
fn figures_text(figures: &AbuseFigures) -> String {
    let destinations = estimate_distinct(figures.destination_buckets, DESTINATION_BUCKETS)
        .map_or_else(|| "over 34000".to_owned(), |count| format!("about {count}"));
    let mut parts = vec![
        format!("{destinations} destinations in 5 min"),
        format!("{} port buckets in 5 min", figures.port_buckets),
        format!(
            "{} new flows to one destination in 2 min",
            figures.busiest_destination_flows
        ),
        format!(
            "{} to one login service in 10 min",
            figures.busiest_login_flows
        ),
        format!("{} mail servers in 1 h", figures.submission_buckets),
    ];
    if let Some(rate) = figures.new_flows_per_min {
        parts.push(format!("{rate} new flows/min"));
    }
    if let Some(rate) = figures.datagrams_per_sec {
        parts.push(format!("{rate} datagrams/s"));
    }
    if let Some(share) = figures.udp_share_permille {
        parts.push(format!("UDP {}.{} % of bytes sent", share / 10, share % 10));
    }
    if let Some(ratio) = figures.received_per_sent_permille {
        parts.push(format!(
            "{}.{:03} bytes received per byte sent",
            ratio / 1000,
            ratio % 1000
        ));
    }
    if let Some(bytes) = figures.received_bytes_per_flow {
        parts.push(format!("{bytes} bytes received per new flow"));
    }
    parts.push(format!(
        "{} packets refused by the limits",
        figures.refused_packets
    ));
    parts.join("; ")
}

/// `2026-11-11 10:00:05 UTC`; a time outside the calendar (a node's clock
/// gone wrong) is printed as its seconds, `@<secs>`, rather than hidden.
fn utc_text(at: mooring_agent_proto::UnixTime) -> String {
    let secs = at.as_secs();
    match CalendarDate::utc_of(mooring_model::time::UnixTime::from_secs(secs)) {
        Ok(date) => {
            let of_day = secs % 86_400;
            format!(
                "{date} {:02}:{:02}:{:02} UTC",
                of_day / 3600,
                of_day % 3600 / 60,
                of_day % 60
            )
        }
        Err(_) => format!("@{secs}"),
    }
}

fn unexpected(request: RequestKind, response: &Response) -> CommandError {
    NodeError::Unexpected {
        request,
        response: response.kind(),
    }
    .into()
}
