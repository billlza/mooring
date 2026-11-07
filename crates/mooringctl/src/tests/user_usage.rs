// SPDX-License-Identifier: GPL-3.0-or-later

//! `user usage` against a state file and the daemon's collected usage in
//! the harness's support directory (design §15.3): the summary and the
//! document it prints, the file it writes, the label it never shows, the
//! refusals that print nothing, and the files it leaves as they were.

mod refusals;

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use mooring_agent_proto::{
    Inbound, OpaqueUserId, Principal, Resolution, SeriesRange, StatsEmail, Traffic, UsageBin,
    UsageMonth, UsageSeriesV1, UsageV1,
};
use mooring_daemon_core::usage::history::{UsageScope, UserUsageHistory};
use mooring_daemon_core::usage::{CollectedUsage, NodeUsageHistory};
use mooring_model::{
    Deployment, DeploymentParts, LocalLabel, NodeId, PublicAlias, UnixTime, UserId, UserStatus,
};
use mooring_store::write_user_usage;

use super::export::{arg, mode};
use super::support::{BackupAnswer, Harness, NOW, Outcome};
use super::user::{fixture, harness_with};

/// 2026-10-12T00:00:00Z, the day before the harness's now.
const DAY_BEFORE: u64 = 1_791_763_200;

/// 2026-10-13T00:00:00Z.
const TODAY: u64 = 1_791_849_600;

/// 2026-10-13T19:00:00Z, the last five-minute boundary the detail reaches.
const DETAIL_TO: u64 = 1_791_918_000;

/// 2026-10-13T06:00:00Z, where lon1's detail has an hour's gap.
const GAP_FROM: u64 = 1_791_871_200;

/// The label the subject is given: it must never be printed or written.
const CANARY: &str = "Canary label 7f3a";

fn wire(at: u64) -> mooring_agent_proto::UnixTime {
    mooring_agent_proto::UnixTime::from_secs(at)
}

fn email(user: &UserId, inbound: Inbound) -> StatsEmail {
    StatsEmail {
        principal: Principal::User(OpaqueUserId::new(user.as_str()).unwrap()),
        inbound,
    }
}

fn probe(inbound: Inbound) -> StatsEmail {
    StatsEmail {
        principal: Principal::Probe,
        inbound,
    }
}

const fn traffic(uplink: u64, downlink: u64) -> Traffic {
    Traffic { uplink, downlink }
}

type Entries = Vec<(StatsEmail, Traffic)>;

/// Records five-minute detail over `[from, to)` as the collector pulls it,
/// in pages of at most the agent's 144 bins.
fn detail(history: &mut NodeUsageHistory, node: &str, from: u64, to: u64, bins: &[(u64, Entries)]) {
    let id = NodeId::parse(node).unwrap();
    let mut start = from;
    while start < to {
        let end = to.min(start + 144 * 300);
        let page = bins
            .iter()
            .filter(|(at, _)| (start..end).contains(at))
            .map(|(at, entries)| {
                UsageBin::new(wire(*at), entries.iter().cloned().collect()).unwrap()
            })
            .collect();
        let range = SeriesRange::new(wire(start), wire(end), Resolution::FiveMin).unwrap();
        history
            .record_series(&id, &UsageSeriesV1::new(range, page).unwrap())
            .unwrap();
        start = end;
    }
}

/// Records October as sampled at 19:18 and received at 19:19 today.
fn october(history: &mut NodeUsageHistory, node: &str, entries: Entries) {
    history
        .record_month(
            &NodeId::parse(node).unwrap(),
            UsageV1 {
                month: "2026-10".parse::<UsageMonth>().unwrap(),
                updated_at: wire(NOW - 120),
                traffic: entries.into_iter().collect::<BTreeMap<_, _>>(),
            },
            UnixTime::from_secs(NOW - 60),
        )
        .unwrap();
}

/// The fixture's users in id order: the subject, another and an idle one.
fn ids(deployment: &Deployment) -> Vec<UserId> {
    deployment.users().keys().cloned().collect()
}

/// The fixture with the subject labelled [`CANARY`] and aliased, after
/// `edit`.
fn deployment(edit: impl FnOnce(&mut DeploymentParts)) -> Deployment {
    fixture(|parts| {
        let subject = &mut parts.users[0];
        subject.label = LocalLabel::parse(CANARY).unwrap();
        subject.alias = Some(PublicAlias::from_random_bytes([
            0x9b, 0x18, 0x6d, 0x0e, 0x55,
        ]));
        edit(parts);
    })
}

/// The deployment with lon1 still planned, as the daemon saw it before lon1
/// served: a sighting then gives lon1 its lifetime origin.
fn lon1_planned() -> Deployment {
    deployment(|parts| {
        for node in &mut parts.nodes {
            if node.id.as_str() == "lon1" {
                node.lifecycle = mooring_model::node::NodeLifecycle::Planned;
            }
        }
    })
}

/// lon1's October so far.
fn lon1_october(deployment: &Deployment) -> Entries {
    let ids = ids(deployment);
    let (subject, other) = (&ids[0], &ids[1]);
    vec![
        (email(subject, Inbound::Reality), traffic(1500, 35_000)),
        (email(subject, Inbound::Hy2), traffic(500, 7_000)),
        (email(other, Inbound::Reality), traffic(9, 99)),
        (probe(Inbound::Reality), traffic(0, 4_000)),
    ]
}

/// What the daemon collected by now:
/// - lon1: detail from yesterday's midnight to 19:00 today but for the hour
///   from 06:00, the subject on REALITY yesterday and on Hysteria2 this
///   morning, sharing that bin with another user, and the probe; October
///   so far.
/// - ams1: detail from midnight to 19:00, without the subject's traffic;
///   October so far.
fn collected(deployment: &Deployment) -> CollectedUsage {
    let ids = ids(deployment);
    let (subject, other) = (&ids[0], &ids[1]);
    let mut lon = NodeUsageHistory::default();
    let bins = [
        (
            DAY_BEFORE + 8 * 3600 + 900,
            vec![(email(subject, Inbound::Reality), traffic(1200, 34_000))],
        ),
        (
            DAY_BEFORE + 10 * 3600,
            vec![(probe(Inbound::Reality), traffic(0, 4_000))],
        ),
        (
            TODAY + 7 * 3600 + 2400,
            vec![
                (email(subject, Inbound::Hy2), traffic(500, 7_000)),
                (email(other, Inbound::Reality), traffic(9, 99)),
            ],
        ),
    ];
    // An hour this morning was never pulled: two stretches.
    detail(&mut lon, "lon1", DAY_BEFORE, GAP_FROM, &bins);
    detail(&mut lon, "lon1", GAP_FROM + 3600, DETAIL_TO, &bins);
    october(&mut lon, "lon1", lon1_october(deployment));
    let mut ams = NodeUsageHistory::default();
    detail(
        &mut ams,
        "ams1",
        TODAY,
        DETAIL_TO,
        &[(
            TODAY + 3600,
            vec![(email(other, Inbound::Hy2), traffic(1, 2))],
        )],
    );
    october(
        &mut ams,
        "ams1",
        vec![(email(other, Inbound::Hy2), traffic(1, 2))],
    );
    let mut collected = CollectedUsage::default();
    collected.set_node(NodeId::parse("lon1").unwrap(), lon);
    collected.set_node(NodeId::parse("ams1").unwrap(), ams);
    collected
}

/// A harness holding `deployment` and `collected` as the daemon wrote it.
fn holding(deployment: Deployment, collected: &CollectedUsage) -> Harness {
    let harness = harness_with(deployment);
    write_user_usage(&harness.support_dir(), &collected.encode().unwrap()).unwrap();
    harness
}

/// The subject's history as the core makes it at the harness's now.
fn expected(
    deployment: &Deployment,
    collected: &CollectedUsage,
    scope: UsageScope,
) -> UserUsageHistory {
    collected
        .user_history(
            deployment,
            &ids(deployment)[0],
            UnixTime::from_secs(NOW),
            scope,
        )
        .unwrap()
}

fn run(harness: &mut Harness, user: &UserId, flags: &[&str]) -> Outcome {
    let mut args = vec!["user", "usage", user.as_str()];
    args.extend_from_slice(flags);
    harness.run(&args)
}

/// A folder for files the command writes, in the harness's home.
fn folder(harness: &Harness) -> PathBuf {
    let folder = harness.home.path().join("records");
    fs::create_dir_all(&folder).unwrap();
    folder
}

const SUMMARY: &str = "\
user fxuseraaab (alias tmmg-2dsv), active, at 2026-10-13 19:20:00 UTC
kept by tier: hourly bins 35 days, daily bins and months 13 months after they end; five-minute bins are kept 7 days and not printed
ams1 (applied)
  hourly bins 2026-10-13 00:00:00 UTC to 2026-10-13 19:00:00 UTC: no traffic
  daily bins: none held
  month 2026-10, counted through 2026-10-13 19:18:00 UTC, not final: reality 0 B up, 0 B down; hy2 0 B up, 0 B down
  lifetime: unknown
lon1 (applied)
  hourly bins 2026-10-12 00:00:00 UTC to 2026-10-13 06:00:00 UTC:
    2026-10-12 08:00  reality 1200 B up, 34000 B down; hy2 0 B up, 0 B down
  hourly bins 2026-10-13 07:00:00 UTC to 2026-10-13 19:00:00 UTC:
    2026-10-13 07:00  reality 0 B up, 0 B down; hy2 500 B up, 7000 B down
  daily bins 2026-10-12 00:00:00 UTC to 2026-10-13 00:00:00 UTC:
    2026-10-12  reality 1200 B up, 34000 B down; hy2 0 B up, 0 B down
  month 2026-10, counted through 2026-10-13 19:18:00 UTC, not final: reality 1500 B up, 35000 B down; hy2 500 B up, 7000 B down
  lifetime: unknown
";

/// Without a flag it prints the summary: the user by id and alias, how the
/// history is kept, and per node and tier each stretch held with the bins
/// the user had traffic in, then the months and the lifetime.
#[test]
fn user_usage_prints_the_users_history_as_a_summary() {
    let deployment = deployment(|_| {});
    let mut harness = holding(deployment.clone(), &collected(&deployment));
    let outcome = run(&mut harness, &ids(&deployment)[0], &[]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(outcome.stderr, "");
    assert_eq!(outcome.stdout, SUMMARY);
}

/// `--json` prints the core's document as one line, the probe's and the
/// other user's bytes left out.
#[test]
fn user_usage_json_prints_the_document_as_one_line() {
    let deployment = deployment(|_| {});
    let usage = collected(&deployment);
    let mut harness = holding(deployment.clone(), &usage);
    let outcome = run(&mut harness, &ids(&deployment)[0], &["--json"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(outcome.stderr, "");
    let mut line = serde_json::to_string(&expected(&deployment, &usage, UsageScope::All)).unwrap();
    line.push('\n');
    assert_eq!(outcome.stdout, line);
    assert_eq!(outcome.stdout.matches('\n').count(), 1);
    let document: serde_json::Value = serde_json::from_str(&outcome.stdout).unwrap();
    assert_eq!(document["format"], "mooring-user-usage");
    assert_eq!(document["user"], "fxuseraaab");
    assert_eq!(document["alias"], "tmmg-2dsv");
    assert_eq!(
        document["nodes"][1]["hourly"]["bins"][1]["bytes"],
        serde_json::json!({"reality": {"uplink": 0, "downlink": 0}, "hy2": {"uplink": 500, "downlink": 7000}})
    );
    assert_eq!(
        document["nodes"][1]["hourly"]["bins"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

/// `--bins-only` leaves every node's totals out, in the summary and in the
/// document.
#[test]
fn bins_only_leaves_the_totals_out() {
    let deployment = deployment(|_| {});
    let usage = collected(&deployment);
    let mut harness = holding(deployment.clone(), &usage);
    let subject = &ids(&deployment)[0];
    let outcome = run(&mut harness, subject, &["--bins-only"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let expected_text: String = SUMMARY
        .lines()
        .filter(|line| !line.starts_with("  month ") && !line.starts_with("  lifetime"))
        .flat_map(|line| {
            let mut lines = vec![line.to_owned()];
            if line.starts_with("kept by tier") {
                lines.push("totals left out (--bins-only)".to_owned());
            }
            lines
        })
        .map(|line| line + "\n")
        .collect();
    assert_eq!(outcome.stdout, expected_text);
    let outcome = run(&mut harness, subject, &["--bins-only", "--json"]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let mut line =
        serde_json::to_string(&expected(&deployment, &usage, UsageScope::BinsOnly)).unwrap();
    line.push('\n');
    assert_eq!(outcome.stdout, line);
    let document: serde_json::Value = serde_json::from_str(&outcome.stdout).unwrap();
    assert_eq!(document["scope"], "bins_only");
    assert!(document["nodes"][0]["totals"].is_null());
    assert!(document["nodes"][1]["totals"].is_null());
}

/// `--out` writes the pretty-printed document, and a newline, to a new
/// file with mode 0600, and says so; nothing goes to the file's folder's
/// warnings when Time Machine excludes it.
#[test]
fn user_usage_out_writes_a_new_file_with_mode_0600() {
    let deployment = deployment(|_| {});
    let usage = collected(&deployment);
    let mut harness = holding(deployment.clone(), &usage);
    let out = folder(&harness).join("fxuseraaab.json");
    let outcome = run(&mut harness, &ids(&deployment)[0], &["--out", arg(&out)]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(outcome.stderr, "");
    assert_eq!(
        outcome.stdout,
        format!(
            "wrote {}: the usage history of user fxuseraaab, mode 0600; it names the user by id and alias, never by label\n",
            out.display()
        )
    );
    let mut pretty =
        serde_json::to_string_pretty(&expected(&deployment, &usage, UsageScope::All)).unwrap();
    pretty.push('\n');
    assert_eq!(fs::read_to_string(&out).unwrap(), pretty);
    assert_eq!(
        fs::read(&out).unwrap(),
        expected(&deployment, &usage, UsageScope::All)
            .pretty()
            .unwrap()
    );
    assert_eq!(mode(&out), 0o600);
    // The bins alone go to a file the same way.
    let bins = folder(&harness).join("fxuseraaab-bins.json");
    let outcome = run(
        &mut harness,
        &ids(&deployment)[0],
        &["--bins-only", "--out", arg(&bins)],
    );
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        fs::read(&bins).unwrap(),
        expected(&deployment, &usage, UsageScope::BinsOnly)
            .pretty()
            .unwrap()
    );
    assert_eq!(mode(&bins), 0o600);
}

/// `--out` never overwrites a file, whatever is there, and prints nothing.
#[test]
fn user_usage_out_never_overwrites_a_file() {
    let deployment = deployment(|_| {});
    let mut harness = holding(deployment.clone(), &collected(&deployment));
    let out = folder(&harness).join("earlier.json");
    fs::write(&out, b"earlier\n").unwrap();
    fs::set_permissions(&out, fs::Permissions::from_mode(0o644)).unwrap();
    let outcome = run(&mut harness, &ids(&deployment)[0], &["--out", arg(&out)]);
    assert_eq!(outcome.code, 1);
    assert_eq!(outcome.stdout, "");
    assert_eq!(
        outcome.stderr,
        format!(
            "mooringctl: {} already exists; an export never overwrites a file\n",
            out.display()
        )
    );
    assert_eq!(fs::read(&out).unwrap(), b"earlier\n");
    assert_eq!(mode(&out), 0o644);
}

/// A folder Time Machine backs up is warned about, as for every export,
/// and the file is written all the same.
#[test]
fn user_usage_out_warns_about_a_backed_up_folder() {
    let deployment = deployment(|_| {});
    let mut harness = holding(deployment.clone(), &collected(&deployment));
    harness.backups.answer = BackupAnswer::Included;
    let records = folder(&harness);
    let out = records.join("fxuseraaab.json");
    let outcome = run(&mut harness, &ids(&deployment)[0], &["--out", arg(&out)]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let dir = fs::canonicalize(&records).unwrap();
    assert_eq!(
        outcome.stderr,
        format!(
            "mooringctl: warning: Time Machine backs up {dir}; exclude it with `tmutil addexclusion {dir}`\n",
            dir = dir.display()
        )
    );
    assert!(out.exists());
}

/// The label never leaves: not in the summary, the document, the file or
/// any message, whatever the flags.
#[test]
fn the_label_is_never_printed_or_written() {
    let deployment = deployment(|_| {});
    let mut harness = holding(deployment.clone(), &collected(&deployment));
    let subject = &ids(&deployment)[0];
    let out = folder(&harness).join("record.json");
    for flags in [
        &[][..],
        &["--json"],
        &["--bins-only"],
        &["--bins-only", "--json"],
        &["--out", arg(&out)],
        // A refusal does not name it either: the file is there now.
        &["--out", arg(&out)],
    ] {
        let outcome = run(&mut harness, subject, flags);
        assert!(!outcome.stdout.contains(CANARY), "{flags:?}");
        assert!(!outcome.stderr.contains(CANARY), "{flags:?}");
    }
    assert!(out.exists());
    assert!(!fs::read_to_string(&out).unwrap().contains(CANARY));
    // The canary is the subject's label in the state the command read.
    assert_eq!(
        super::user::store(&harness)
            .load()
            .unwrap()
            .deployment
            .users()[subject]
            .label
            .as_str(),
        CANARY
    );
}

/// A user with no traffic sees every stretch held as no traffic and its
/// months as real zeros.
#[test]
fn a_user_without_traffic_sees_no_traffic_in_every_stretch_held() {
    let deployment = deployment(|_| {});
    let mut harness = holding(deployment.clone(), &collected(&deployment));
    let outcome = run(&mut harness, &ids(&deployment)[2], &[]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        outcome.stdout,
        "\
user fxuseraaad (no alias), active, at 2026-10-13 19:20:00 UTC
kept by tier: hourly bins 35 days, daily bins and months 13 months after they end; five-minute bins are kept 7 days and not printed
ams1 (applied)
  hourly bins 2026-10-13 00:00:00 UTC to 2026-10-13 19:00:00 UTC: no traffic
  daily bins: none held
  month 2026-10, counted through 2026-10-13 19:18:00 UTC, not final: reality 0 B up, 0 B down; hy2 0 B up, 0 B down
  lifetime: unknown
lon1 (applied)
  hourly bins 2026-10-12 00:00:00 UTC to 2026-10-13 06:00:00 UTC: no traffic
  hourly bins 2026-10-13 07:00:00 UTC to 2026-10-13 19:00:00 UTC: no traffic
  daily bins 2026-10-12 00:00:00 UTC to 2026-10-13 00:00:00 UTC: no traffic
  month 2026-10, counted through 2026-10-13 19:18:00 UTC, not final: reality 0 B up, 0 B down; hy2 0 B up, 0 B down
  lifetime: unknown
"
    );
    // Its document says it has no alias, as `null`.
    let outcome = run(&mut harness, &ids(&deployment)[2], &["--json"]);
    let document: serde_json::Value = serde_json::from_str(&outcome.stdout).unwrap();
    assert!(document["alias"].is_null());
    assert_eq!(document["user"], "fxuseraaad");
}

/// The fixture with the subject revoked on every node.
fn revoked(parts: &mut DeploymentParts) {
    let subject = &mut parts.users[0];
    subject.status = UserStatus::Revoked;
    subject.per_node.clear();
}

/// A revoked user's history is shown with its deadline while the daemon
/// keeps it; once it is deleted, the command says nothing is held.
#[test]
fn a_revoked_user_is_shown_with_its_deadline_and_then_as_erased() {
    let active = deployment(|_| {});
    let mut kept = collected(&active);
    // The daemon last saw the subject active now.
    kept.prune(&active, UnixTime::from_secs(NOW)).unwrap();
    let gone = deployment(revoked);
    let mut harness = holding(gone.clone(), &kept);
    let subject = &ids(&gone)[0];
    let outcome = run(&mut harness, subject, &[]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let mut lines = outcome.stdout.lines();
    assert_eq!(
        lines.next(),
        Some("user fxuseraaab (alias tmmg-2dsv), revoked, at 2026-10-13 19:20:00 UTC")
    );
    assert_eq!(
        lines.next(),
        Some(
            "due for deletion by 2027-11-13 19:20:00 UTC at the latest, each tier sooner as it expires; five-minute bins are kept 7 days and not printed"
        )
    );
    assert_eq!(
        outcome.stdout.lines().skip(2).collect::<Vec<_>>(),
        SUMMARY.lines().skip(2).collect::<Vec<_>>()
    );
    // Never seen active, a revoked user's history is deleted at once.
    let mut harness = holding(gone.clone(), &collected(&active));
    let outcome = run(&mut harness, subject, &[]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        outcome.stdout,
        "user fxuseraaab (alias tmmg-2dsv), revoked, at 2026-10-13 19:20:00 UTC\nits retention has ended: nothing of it is shown, and the daemon deletes what it may still hold at its next prune\n"
    );
    let outcome = run(&mut harness, subject, &["--json"]);
    let document: serde_json::Value = serde_json::from_str(&outcome.stdout).unwrap();
    assert_eq!(document["retention"], "erased");
    assert_eq!(document["status"], "revoked");
    assert_eq!(document["nodes"], serde_json::json!([]));
}

/// A suspended user's status is named with its reason and time.
#[test]
fn a_suspended_users_status_names_its_reason_and_time() {
    let deployment = deployment(|parts| {
        parts.users[0].status = UserStatus::Suspended {
            reason: mooring_model::SuspendReason::AbuseReview,
            since: UnixTime::from_secs(NOW - 3600),
        };
    });
    let mut harness = holding(deployment.clone(), &collected(&deployment));
    let outcome = run(&mut harness, &ids(&deployment)[0], &[]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        outcome.stdout.lines().next(),
        Some(
            "user fxuseraaab (alias tmmg-2dsv), suspended for an abuse review since 2026-10-13 18:20:00 UTC, at 2026-10-13 19:20:00 UTC"
        )
    );
}

/// Records `month` as sampled at `updated` and received at `received`.
fn record(
    history: &mut NodeUsageHistory,
    node: &str,
    month: &str,
    (updated, received): (u64, u64),
    entries: Entries,
) {
    history
        .record_month(
            &NodeId::parse(node).unwrap(),
            UsageV1 {
                month: month.parse::<UsageMonth>().unwrap(),
                updated_at: wire(updated),
                traffic: entries.into_iter().collect::<BTreeMap<_, _>>(),
            },
            UnixTime::from_secs(received),
        )
        .unwrap();
}

/// A final month, months folded once their retention ended, and a node's
/// lifetime are shown as such; a tier a node holds nothing of says so.
#[test]
fn the_summary_shows_final_and_folded_months_and_the_lifetime() {
    let deployment = deployment(|_| {});
    let subject = ids(&deployment)[0].clone();
    let mut usage = CollectedUsage::default();
    // lon1 was observed before it served, on 2026-09-01.
    usage.observe_unserved_nodes(&lon1_planned(), UnixTime::from_secs(1_788_220_800));
    let mut lon = usage.node(&NodeId::parse("lon1").unwrap()).unwrap().clone();
    record(
        &mut lon,
        "lon1",
        "2026-09",
        (1_790_812_740, 1_790_812_920),
        vec![(email(&subject, Inbound::Reality), traffic(10, 20))],
    );
    record(
        &mut lon,
        "lon1",
        "2026-10",
        (NOW - 120, NOW - 60),
        vec![(email(&subject, Inbound::Hy2), traffic(3, 4))],
    );
    usage.set_node(NodeId::parse("lon1").unwrap(), lon);
    let mut ams = NodeUsageHistory::default();
    // August 2025's retention ended on 2026-10-01: it is folded by now.
    record(
        &mut ams,
        "ams1",
        "2025-08",
        (1_756_684_740, 1_756_684_920),
        vec![(email(&subject, Inbound::Reality), traffic(5, 6))],
    );
    record(&mut ams, "ams1", "2026-10", (NOW - 120, NOW - 60), vec![]);
    usage.set_node(NodeId::parse("ams1").unwrap(), ams);
    let mut harness = holding(deployment, &usage);
    let outcome = run(&mut harness, &subject, &[]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        outcome.stdout.lines().skip(2).collect::<Vec<_>>(),
        [
            "ams1 (applied)",
            "  hourly bins: none held",
            "  daily bins: none held",
            "  month 2026-10, counted through 2026-10-13 19:18:00 UTC, not final: reality 0 B up, 0 B down; hy2 0 B up, 0 B down",
            "  folded, the months held before 2025-09, a lower bound: reality 5 B up, 6 B down; hy2 0 B up, 0 B down",
            "  lifetime: unknown",
            "lon1 (applied)",
            "  hourly bins: none held",
            "  daily bins: none held",
            "  month 2026-09, counted through 2026-09-30 23:59:00 UTC, final: reality 10 B up, 20 B down; hy2 0 B up, 0 B down",
            "  month 2026-10, counted through 2026-10-13 19:18:00 UTC, not final: reality 0 B up, 0 B down; hy2 3 B up, 4 B down",
            "  lifetime: reality 10 B up, 20 B down; hy2 3 B up, 4 B down",
        ]
    );
}

/// Folded months are a complete total, and say so, when the node's origin
/// is recorded and every month from it was held and final: here lon1 from
/// August 2025, whose first month is folded by now.
#[test]
fn a_folded_total_is_complete_when_every_month_was_held() {
    let deployment = deployment(|_| {});
    let subject = ids(&deployment)[0].clone();
    let mut usage = collected(&deployment);
    let lon1 = NodeId::parse("lon1").unwrap();
    let mut scratch = CollectedUsage::default();
    // 2025-08-01T00:00:00Z.
    scratch.observe_unserved_nodes(&lon1_planned(), UnixTime::from_secs(1_754_006_400));
    let mut lon = scratch.node(&lon1).unwrap().clone();
    let mut month: UsageMonth = "2025-08".parse().unwrap();
    let current: UsageMonth = "2026-10".parse().unwrap();
    while month < current {
        let end = month.next().unwrap().start().as_secs();
        let entries = if month.to_string() == "2025-08" {
            vec![(email(&subject, Inbound::Reality), traffic(10, 20))]
        } else {
            vec![]
        };
        record(
            &mut lon,
            "lon1",
            &month.to_string(),
            (end - 60, end + 60),
            entries,
        );
        month = month.next().unwrap();
    }
    record(&mut lon, "lon1", "2026-10", (NOW - 120, NOW - 60), vec![]);
    usage.set_node(lon1, lon);
    let mut harness = holding(deployment, &usage);
    let outcome = run(&mut harness, &subject, &[]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let lines: Vec<&str> = outcome.stdout.lines().collect();
    assert!(
        lines.contains(&"  folded, every month before 2025-09: reality 10 B up, 20 B down; hy2 0 B up, 0 B down"),
        "{}",
        outcome.stdout
    );
    assert!(
        lines.contains(&"  lifetime: reality 10 B up, 20 B down; hy2 0 B up, 0 B down"),
        "{}",
        outcome.stdout
    );
    // September 2025 to October 2026 are still months of their own.
    assert_eq!(
        lines
            .iter()
            .skip_while(|line| **line != "lon1 (applied)")
            .filter(|line| line.starts_with("  month "))
            .count(),
        14
    );
}

/// With no node past `Planned`, no node may have counted traffic: nothing
/// is held, and the summary says so.
#[test]
fn with_no_node_past_planned_nothing_is_held() {
    let deployment = deployment(|parts| {
        for node in &mut parts.nodes {
            node.lifecycle = mooring_model::node::NodeLifecycle::Planned;
        }
    });
    let mut harness = holding(deployment.clone(), &CollectedUsage::default());
    let outcome = run(&mut harness, &ids(&deployment)[0], &[]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        outcome.stdout.lines().skip(2).collect::<Vec<_>>(),
        ["no node has served yet: nothing is held"]
    );
    let outcome = run(&mut harness, &ids(&deployment)[0], &["--json"]);
    let document: serde_json::Value = serde_json::from_str(&outcome.stdout).unwrap();
    assert_eq!(document["retention"], "tiered");
    assert_eq!(document["nodes"], serde_json::json!([]));
}

/// A node past `Planned` that the daemon has not collected from yet holds
/// nothing on this Mac. It is listed with nothing held and its lifetime
/// unknown, and the user's history on the other nodes is shown: the node
/// is no reason to refuse it.
#[test]
fn a_node_not_collected_from_yet_is_shown_holding_nothing() {
    let deployment = deployment(|_| {});
    let lon1 = NodeId::parse("lon1").unwrap();
    let mut partial = CollectedUsage::default();
    partial.set_node(
        lon1.clone(),
        collected(&deployment).node(&lon1).unwrap().clone(),
    );
    let mut harness = holding(deployment.clone(), &partial);
    let outcome = run(&mut harness, &ids(&deployment)[0], &[]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let expected = SUMMARY.replace(
        "\
ams1 (applied)
  hourly bins 2026-10-13 00:00:00 UTC to 2026-10-13 19:00:00 UTC: no traffic
  daily bins: none held
  month 2026-10, counted through 2026-10-13 19:18:00 UTC, not final: reality 0 B up, 0 B down; hy2 0 B up, 0 B down
  lifetime: unknown
",
        "\
ams1 (applied)
  hourly bins: none held
  daily bins: none held
  months: none held
  lifetime: unknown
",
    );
    assert_ne!(expected, SUMMARY);
    assert_eq!(outcome.stdout, expected);
}

/// What a file in the support directory is: its mode, inode and
/// modification time, and its bytes (none for a folder).
type Entry = (u32, u64, std::time::SystemTime, Option<Vec<u8>>);

/// Every file in `dir`, by its path below it.
fn tree(dir: &Path) -> BTreeMap<PathBuf, Entry> {
    let mut found = BTreeMap::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(next) = pending.pop() {
        for entry in fs::read_dir(&next).unwrap() {
            let path = entry.unwrap().path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            let bytes = if metadata.is_dir() {
                pending.push(path.clone());
                None
            } else {
                Some(fs::read(&path).unwrap())
            };
            found.insert(
                path.strip_prefix(dir).unwrap().to_path_buf(),
                (
                    metadata.permissions().mode(),
                    metadata.ino(),
                    metadata.modified().unwrap(),
                    bytes,
                ),
            );
        }
    }
    found
}

/// Reading changes nothing in the support directory, the state and the
/// collected usage included, not a byte, a mode, an inode or a time,
/// whatever the flags and whether it succeeds or is refused; `--out`
/// writes only its own file, outside it.
#[test]
fn the_support_directory_is_left_as_it_was() {
    let deployment = deployment(|_| {});
    let mut harness = holding(deployment.clone(), &collected(&deployment));
    // `state.lock`, which every reader of the state takes, is there since
    // the deployment's creation; the harness's first read makes it here.
    super::user::store(&harness).load().unwrap();
    let support = harness.support_dir();
    let before = tree(&support);
    assert!(before.contains_key(Path::new("usage/users.json")));
    let subject = ids(&deployment)[0].clone();
    let out = folder(&harness).join("record.json");
    for (flags, code) in [
        (&[][..], 0),
        (&["--json"], 0),
        (&["--bins-only"], 0),
        (&["--out", arg(&out)], 0),
        // Refused: the file is there now.
        (&["--out", arg(&out)], 1),
    ] {
        let outcome = run(&mut harness, &subject, flags);
        assert_eq!(outcome.code, code, "{flags:?}: {}", outcome.stderr);
    }
    let stranger = UserId::from_low_bits(0x3_1415_9265);
    assert_eq!(run(&mut harness, &stranger, &[]).code, 1);
    assert_eq!(tree(&support), before);
    // Nor does a refusal for an inconsistent document change it: here
    // lon1's October, received after now.
    let lon1 = NodeId::parse("lon1").unwrap();
    let mut future = collected(&deployment);
    let mut lon = future.node(&lon1).unwrap().clone();
    lon.record_month(
        &lon1,
        UsageV1 {
            month: "2026-10".parse().unwrap(),
            updated_at: wire(NOW + 60),
            traffic: lon1_october(&deployment).into_iter().collect(),
        },
        UnixTime::from_secs(NOW + 60),
    )
    .unwrap();
    future.set_node(lon1, lon);
    write_user_usage(&support, &future.encode().unwrap()).unwrap();
    let before = tree(&support);
    assert_eq!(run(&mut harness, &subject, &["--json"]).code, 1);
    assert_eq!(tree(&support), before);
}
