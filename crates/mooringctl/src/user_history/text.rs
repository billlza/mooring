// SPDX-License-Identifier: GPL-3.0-or-later

//! The summary `user usage` prints without `--json`: a header with the
//! user's id, alias, status and the time, how the history is kept, then per
//! node and tier each stretch held with the bins the user had traffic in,
//! and the months, the folded months and the lifetime. Times are UTC;
//! bytes are exact, up (client to destination) and down per protocol.

use mooring_daemon_core::usage::ProtocolTraffic;
use mooring_daemon_core::usage::history::{
    NodeHistory, NodeStage, Retention, SuspendedFor, Tier, UsageScope, UserState, UserUsageHistory,
};
use mooring_model::error::ModelError;
use mooring_model::{CalendarDate, UnixTime};

use crate::router::output::{hour_stamp, utc_stamp};

/// The summary; every line ends in a newline. `Err` only for a time past
/// the year 9999: every time of the history but a suspension's comes no
/// later than the read, and that one only a corrupt state puts there.
pub(super) fn summary(history: &UserUsageHistory) -> Result<String, ModelError> {
    let alias = history
        .alias()
        .map_or_else(|| "no alias".to_owned(), |alias| format!("alias {alias}"));
    let mut text = format!(
        "user {} ({alias}), {}, at {}\n",
        history.user(),
        status(history.status())?,
        utc_stamp(history.generated_at())?
    );
    text.push_str(&retention(history.retention())?);
    if history.retention() == Retention::Erased {
        return Ok(text);
    }
    if history.scope() == UsageScope::BinsOnly {
        text.push_str("totals left out (--bins-only)\n");
    }
    if history.nodes().is_empty() {
        text.push_str("no node has served yet: nothing is held\n");
    }
    for node in history.nodes() {
        node_text(&mut text, node)?;
    }
    Ok(text)
}

fn status(state: UserState) -> Result<String, ModelError> {
    Ok(match state {
        UserState::Active => "active".to_owned(),
        UserState::Suspended { reason, since } => {
            format!(
                "suspended {} since {}",
                reason_text(reason),
                utc_stamp(since)?
            )
        }
        UserState::RevokePending => "being revoked".to_owned(),
        UserState::Revoked => "revoked".to_owned(),
    })
}

const fn reason_text(reason: SuspendedFor) -> &'static str {
    match reason {
        SuspendedFor::Operator => "by the operator",
        SuspendedFor::QuotaExceeded => "over quota",
        SuspendedFor::Expired => "at expiry",
        SuspendedFor::AbuseReview => "for an abuse review",
    }
}

/// How long the history is kept, as its line. What it says is the
/// retention rule, which the daemon applies at each prune: a read cannot
/// tell whether a stopped daemon still holds what is past its deadline.
fn retention(retention: Retention) -> Result<String, ModelError> {
    const FIVE_MINUTES: &str = "five-minute bins are kept 7 days and not printed";
    Ok(match retention {
        Retention::Tiered => format!(
            "kept by tier: hourly bins 35 days, daily bins and months 13 months after they end; {FIVE_MINUTES}\n"
        ),
        Retention::Until(until) => format!(
            "due for deletion by {} at the latest, each tier sooner as it expires; {FIVE_MINUTES}\n",
            utc_stamp(until)?
        ),
        Retention::Erased => "past its deletion deadline: nothing of it is shown, and the daemon deletes what it may still hold at its next prune\n".to_owned(),
    })
}

const fn stage_text(stage: NodeStage) -> &'static str {
    match stage {
        NodeStage::Adopted => "adopted",
        NodeStage::Applied => "applied",
        NodeStage::Retiring => "retiring",
        NodeStage::RetiredPendingProviderDeletion => "retired, its VM still to be deleted",
        NodeStage::Retired => "retired",
    }
}

/// `reality <up> B up, <down> B down; hy2 <up> B up, <down> B down`.
fn bytes_text(bytes: ProtocolTraffic) -> String {
    format!(
        "reality {} B up, {} B down; hy2 {} B up, {} B down",
        bytes.reality.uplink, bytes.reality.downlink, bytes.hy2.uplink, bytes.hy2.downlink
    )
}

fn node_text(text: &mut String, node: &NodeHistory) -> Result<(), ModelError> {
    text.push_str(&format!("{} ({})\n", node.node, stage_text(node.stage)));
    tier_text(text, "hourly", &node.hourly, hour_stamp)?;
    tier_text(text, "daily", &node.daily, day_stamp)?;
    let Some(totals) = &node.totals else {
        return Ok(());
    };
    for month in &totals.months {
        text.push_str(&format!(
            "  month {}, counted through {}, {}: {}\n",
            month.month,
            utc_stamp(month.counted_through)?,
            if month.is_final { "final" } else { "not final" },
            bytes_text(month.bytes)
        ));
    }
    if let Some(folded) = totals.folded {
        let which = if folded.complete {
            format!("every month before {}", folded.before)
        } else {
            format!("the months held before {}, a lower bound", folded.before)
        };
        text.push_str(&format!(
            "  folded, {which}: {}\n",
            bytes_text(folded.bytes)
        ));
    }
    text.push_str(&match totals.lifetime {
        Some(lifetime) => format!("  lifetime: {}\n", bytes_text(lifetime)),
        None => "  lifetime: unknown\n".to_owned(),
    });
    Ok(())
}

/// `<yyyy-mm-dd>`, the UTC day `start` begins.
fn day_stamp(start: UnixTime) -> Result<String, ModelError> {
    CalendarDate::utc_of(start).map(|date| date.to_string())
}

/// A tier: each stretch held, with the bins in it the user had traffic
/// in, each named by `stamp`; or that none is held.
fn tier_text(
    text: &mut String,
    name: &str,
    tier: &Tier,
    stamp: fn(UnixTime) -> Result<String, ModelError>,
) -> Result<(), ModelError> {
    if tier.held.is_empty() {
        text.push_str(&format!("  {name} bins: none held\n"));
    }
    for range in &tier.held {
        let inside: Vec<_> = tier
            .bins
            .iter()
            .filter(|bin| range.from <= bin.start && bin.start < range.to)
            .collect();
        text.push_str(&format!(
            "  {name} bins {} to {}:{}\n",
            utc_stamp(range.from)?,
            utc_stamp(range.to)?,
            if inside.is_empty() { " no traffic" } else { "" }
        ));
        for bin in inside {
            text.push_str(&format!(
                "    {}  {}\n",
                stamp(bin.start)?,
                bytes_text(bin.bytes)
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use mooring_daemon_core::usage::history::{NodeStage, Retention, SuspendedFor, UserState};
    use mooring_model::UnixTime;

    use super::{reason_text, retention, stage_text, status};

    /// 2026-11-05T12:00:00Z.
    const AT: UnixTime = UnixTime::from_secs(1_793_880_000);

    /// Every status, reason, stage and retention has its own words.
    #[test]
    fn every_status_reason_stage_and_retention_has_its_words() {
        let suspended = |reason| status(UserState::Suspended { reason, since: AT }).unwrap();
        assert_eq!(status(UserState::Active).unwrap(), "active");
        assert_eq!(status(UserState::RevokePending).unwrap(), "being revoked");
        assert_eq!(status(UserState::Revoked).unwrap(), "revoked");
        assert_eq!(
            suspended(SuspendedFor::Operator),
            "suspended by the operator since 2026-11-05 12:00:00 UTC"
        );
        for (reason, words) in [
            (SuspendedFor::Operator, "by the operator"),
            (SuspendedFor::QuotaExceeded, "over quota"),
            (SuspendedFor::Expired, "at expiry"),
            (SuspendedFor::AbuseReview, "for an abuse review"),
        ] {
            assert_eq!(reason_text(reason), words);
        }
        for (stage, words) in [
            (NodeStage::Adopted, "adopted"),
            (NodeStage::Applied, "applied"),
            (NodeStage::Retiring, "retiring"),
            (
                NodeStage::RetiredPendingProviderDeletion,
                "retired, its VM still to be deleted",
            ),
            (NodeStage::Retired, "retired"),
        ] {
            assert_eq!(stage_text(stage), words);
        }
        assert!(
            retention(Retention::Tiered)
                .unwrap()
                .starts_with("kept by tier: ")
        );
        assert_eq!(
            retention(Retention::Until(AT)).unwrap(),
            "due for deletion by 2026-11-05 12:00:00 UTC at the latest, each tier sooner as it expires; five-minute bins are kept 7 days and not printed\n"
        );
        assert_eq!(
            retention(Retention::Erased).unwrap(),
            "past its deletion deadline: nothing of it is shown, and the daemon deletes what it may still hold at its next prune\n"
        );
    }
}
