// SPDX-License-Identifier: GPL-3.0-or-later

//! `user set-quota <uid> (--gb <n> | --none)` (design §7, §9.6, §15.3)
//! against a state file in the harness's support directory: the quota it
//! records and what it says of the one replaced, the generation and node
//! confirmations it keeps, the refusals that change nothing, what it takes
//! on the command line, and that the apply job's policy step suspends and
//! resumes by the quota it recorded while the command itself does neither.

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use clap::Parser;
use mooring_daemon_core::apply::{Lapse, Lapsed, Suspension, plan_policy};
use mooring_daemon_core::payments::Entitlements;
use mooring_daemon_core::period::BillingCycle;
use mooring_daemon_core::policy::paid_quota;
use mooring_daemon_core::usage::CycleUsage;
use mooring_model::user::SuspendReason;
use mooring_model::{
    Deployment, QuotaAction, UnixTime, UserId, UserPolicy, UserQuota, UserStatus, WarnPercent,
};

use super::payments::{FIRST, SECOND};
use super::support::{Harness, NOW};
use super::user::{fixture, harness_with, state_bytes, store};
use crate::apply::policy::carry_out;
use crate::cli::{Cli, Command, UserCommand};
use crate::error::EXIT_LOCAL;

/// What follows every record that changed a quota.
const NEXT: &str = "the apply job acts on it at its next nightly run, or at once with `mooringctl apply --now`; this record suspends and resumes nobody, and needs no node apply\n";

const GB: u64 = 1_000_000_000;

fn id(text: &str) -> UserId {
    UserId::parse(text).unwrap()
}

fn limit(bytes: u64, warn_percent: u8, action: QuotaAction) -> UserQuota {
    UserQuota {
        cycle_served_bytes: NonZeroU64::new(bytes).unwrap(),
        warn_percent: WarnPercent::new(warn_percent).unwrap(),
        action,
    }
}

/// The quota `--gb <gigabytes>` records.
fn typed(gigabytes: u64) -> UserQuota {
    limit(gigabytes * GB, 80, QuotaAction::Suspend)
}

fn deployment(harness: &Harness) -> Deployment {
    store(harness).load().unwrap().deployment
}

/// `before` with `FIRST`'s own quota `quota` and nothing else changed.
fn with_quota(before: &Deployment, quota: Option<UserQuota>) -> Deployment {
    let mut parts = before.clone().into_parts();
    parts
        .users
        .iter_mut()
        .find(|user| user.id.as_str() == FIRST)
        .unwrap()
        .policy
        .quota = quota;
    Deployment::try_from(parts).unwrap()
}

/// Runs `user set-quota FIRST` with `form` and returns what it printed,
/// having succeeded with nothing on stderr.
fn set(harness: &mut Harness, form: &[&str]) -> String {
    let mut args = vec!["user", "set-quota", FIRST];
    args.extend_from_slice(form);
    let outcome = harness.run(&args);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(outcome.stderr, "");
    outcome.stdout
}

/// `--gb 100` on a user without a quota records 100,000,000,000 bytes per
/// billing cycle with a warning at 80 % and a suspension at all of it, the
/// terms a paid period's quota has, and says so. It is a bookkeeping
/// record: the generation, every node's confirmation and every other
/// record stay, so no node goes stale and no export needs an apply.
#[test]
fn set_quota_records_100_gb_on_a_paid_periods_terms_and_changes_nothing_else() {
    let before = fixture(|_| {});
    assert_eq!(before.users()[&id(FIRST)].policy, UserPolicy::NONE);
    let mut harness = harness_with(before.clone());
    assert_eq!(
        set(&mut harness, &["--gb", "100"]),
        format!(
            "recorded: user {FIRST} has a quota of 100 GB per billing cycle, with a warning at 80 % and a suspension at all of it; they had none of their own\n{NEXT}"
        )
    );
    let after = deployment(&harness);
    let recorded = limit(100_000_000_000, 80, QuotaAction::Suspend);
    assert_eq!(after.users()[&id(FIRST)].policy.quota, Some(recorded));
    assert_eq!(
        recorded,
        paid_quota(NonZeroU64::new(100_000_000_000).unwrap())
    );
    assert_eq!(after.config_generation(), before.config_generation());
    assert_eq!(after.nodes(), before.nodes());
    assert_eq!(after, with_quota(&before, Some(recorded)));
}

/// Each run replaces the quota recorded, whatever it was, and names it; a
/// run that records the same quota says that it was kept, and one that
/// removes a quota the user does not have says so. The user's expiry stays
/// throughout.
#[test]
fn set_quota_replaces_keeps_and_removes_and_names_what_it_replaced() {
    let expiry = Some(UnixTime::from_secs(NOW + 30 * 86_400));
    // A quota no run of the command records: not a whole number of GB,
    // another warning share, and a warning only.
    let odd = limit(1_500_000_001, 50, QuotaAction::Warn);
    let before = fixture(|parts| {
        let user = parts
            .users
            .iter_mut()
            .find(|user| user.id.as_str() == FIRST)
            .unwrap();
        user.policy = UserPolicy {
            expires_at: expiry,
            quota: Some(odd),
        };
    });
    let mut harness = harness_with(before.clone());
    let terms = |gigabytes: u64| {
        format!(
            "{gigabytes} GB per billing cycle, with a warning at 80 % and a suspension at all of it"
        )
    };
    for (form, quota, said) in [
        (
            &["--gb", "200"][..],
            Some(typed(200)),
            format!(
                "recorded: user {FIRST} has a quota of {}; it replaces one of 1500000001 bytes per billing cycle, with a warning at 50 % and no suspension\n{NEXT}",
                terms(200)
            ),
        ),
        (
            &["--gb", "200"][..],
            Some(typed(200)),
            format!("kept: user {FIRST} already has a quota of {}\n", terms(200)),
        ),
        (
            &["--gb", "1"][..],
            Some(typed(1)),
            format!(
                "recorded: user {FIRST} has a quota of {}; it replaces one of {}\n{NEXT}",
                terms(1),
                terms(200)
            ),
        ),
        (
            &["--none"][..],
            None,
            format!(
                "recorded: user {FIRST} has no quota of their own any more; it was {}\n{NEXT}",
                terms(1)
            ),
        ),
        (
            &["--none"][..],
            None,
            format!("kept: user {FIRST} has no quota of their own\n"),
        ),
        (
            &["--gb", "18446744073"][..],
            Some(limit(18_446_744_073 * GB, 80, QuotaAction::Suspend)),
            format!(
                "recorded: user {FIRST} has a quota of {}; they had none of their own\n{NEXT}",
                terms(18_446_744_073)
            ),
        ),
    ] {
        assert_eq!(set(&mut harness, form), said, "{form:?}");
        let after = deployment(&harness);
        assert_eq!(after, with_quota(&before, quota), "{form:?}");
        assert_eq!(after.users()[&id(FIRST)].policy.expires_at, expiry);
    }
}

/// A quota of the same bytes on other terms is not the quota the command
/// records: it is replaced, not kept.
#[test]
fn set_quota_replaces_a_quota_of_the_same_bytes_on_other_terms() {
    for (other, was) in [
        (
            limit(100 * GB, 80, QuotaAction::Warn),
            "100 GB per billing cycle, with a warning at 80 % and no suspension",
        ),
        (
            limit(100 * GB, 79, QuotaAction::Suspend),
            "100 GB per billing cycle, with a warning at 79 % and a suspension at all of it",
        ),
    ] {
        let before = with_quota(&fixture(|_| {}), Some(other));
        let mut harness = harness_with(before.clone());
        assert_eq!(
            set(&mut harness, &["--gb", "100"]),
            format!(
                "recorded: user {FIRST} has a quota of 100 GB per billing cycle, with a warning at 80 % and a suspension at all of it; it replaces one of {was}\n{NEXT}"
            )
        );
        assert_eq!(deployment(&harness), with_quota(&before, Some(typed(100))));
    }
}

/// Every refusal exits 1, names its cause, prints nothing else and leaves
/// `state.json` byte for byte as it was, whether a quota is set or
/// removed.
#[test]
fn set_quota_refuses_a_revoking_or_revoked_user_and_an_unknown_user() {
    let first = |parts: &mut mooring_model::DeploymentParts, status: UserStatus, held: bool| {
        let user = parts
            .users
            .iter_mut()
            .find(|user| user.id.as_str() == FIRST)
            .unwrap();
        user.status = status;
        if !held {
            user.per_node.clear();
        }
    };
    let revoking = fixture(|parts| first(parts, UserStatus::RevokePending, true));
    let revoked = fixture(|parts| {
        first(
            parts,
            UserStatus::Revoked {
                since: UnixTime::from_secs(NOW),
            },
            false,
        );
    });
    let started = format!("user {FIRST} is already pending revocation or revoked");
    for (before, target, cause) in [
        (revoking, FIRST, started.clone()),
        (revoked, FIRST, started),
        (
            fixture(|_| {}),
            "zzzzzzzzzz",
            "unknown user zzzzzzzzzz".to_owned(),
        ),
    ] {
        for form in [&["--gb", "100"][..], &["--none"][..]] {
            let mut harness = harness_with(before.clone());
            let bytes = state_bytes(&harness);
            let mut args = vec!["user", "set-quota", target];
            args.extend_from_slice(form);
            let outcome = harness.run(&args);
            assert_eq!(outcome.code, EXIT_LOCAL, "{args:?}");
            assert_eq!(outcome.stdout, "", "{args:?}");
            assert_eq!(
                outcome.stderr,
                format!(
                    "mooringctl: the state was not changed\n  caused by: the new or changed deployment is invalid\n  caused by: {cause}\n"
                ),
                "{args:?}"
            );
            assert_eq!(state_bytes(&harness), bytes, "{args:?}");
        }
    }
}

/// What `user set-quota abcdefghij` with `form` parses to: the bytes of
/// `--gb` and whether `--none` was given, or clap's error.
fn parsed(form: &[&str]) -> Result<(Option<u64>, bool), String> {
    let mut args = vec!["mooringctl", "user", "set-quota", "abcdefghij"];
    args.extend_from_slice(form);
    match Cli::try_parse_from(args) {
        Ok(Cli {
            command: Command::User(UserCommand::SetQuota { user, bytes, none }),
        }) => {
            assert_eq!(user, id("abcdefghij"));
            Ok((bytes.map(NonZeroU64::get), none))
        }
        Ok(other) => panic!("{other:?}"),
        Err(error) => Err(error.to_string()),
    }
}

/// The command takes exactly one of `--gb` and `--none`. `--gb` takes a
/// whole number of GB from 1, of 1,000,000,000 bytes each, up to the most
/// that fits the 64 bits a quota is kept in: 18,446,744,073 GB.
#[test]
fn set_quota_takes_whole_gb_from_1_and_exactly_one_form() {
    assert_eq!(parsed(&["--gb", "100"]), Ok((Some(100_000_000_000), false)));
    assert_eq!(parsed(&["--gb", "1"]), Ok((Some(1_000_000_000), false)));
    assert_eq!(
        parsed(&["--gb", "18446744073"]),
        Ok((Some(18_446_744_073_000_000_000), false))
    );
    assert_eq!(parsed(&["--none"]), Ok((None, true)));
    for form in [
        &[][..],
        &["--gb", "100", "--none"],
        &["--none", "--gb", "100"],
        &["--gb"],
        &["--gb", ""],
        &["--gb", "-1"],
        &["--gb", "+-1"],
        &["--gb", "1.5"],
        &["--gb", "100GB"],
        &["--gb", "100 "],
        &["--gb", "0x10"],
        &["--gb", "100", "--gb", "200"],
        &["100"],
        &["--bytes", "100"],
    ] {
        assert!(parsed(form).is_err(), "{form:?}");
    }
    let zero = parsed(&["--gb", "0"]).unwrap_err();
    assert!(
        zero.contains("invalid value '0' for '--gb <GB>': number would be zero"),
        "{zero}"
    );
    // One GB more than fits, and a number of GB that does not fit by
    // itself.
    let over = parsed(&["--gb", "18446744074"]).unwrap_err();
    assert!(
        over.contains(
            "invalid value '18446744074' for '--gb <GB>': 18446744074 GB is more bytes than a quota can hold"
        ),
        "{over}"
    );
    let far = parsed(&["--gb", "18446744073709551616"]).unwrap_err();
    assert!(far.contains("number too large to fit"), "{far}");
}

/// The cycle's usage at the harness's clock: `served` bytes for `FIRST`,
/// none for every other user.
fn usage(deployment: &Deployment, served: u64) -> CycleUsage {
    let now = UnixTime::from_secs(NOW);
    CycleUsage {
        cycle: BillingCycle::of_instant(deployment.exit().sim.cycle(), now).unwrap(),
        through: now,
        served: deployment
            .users()
            .keys()
            .map(|user| {
                (
                    user.clone(),
                    Some(if *user == id(FIRST) { served } else { 0 }),
                )
            })
            .collect(),
        reality_downlink: BTreeMap::new(),
    }
}

/// The apply job's policy step on the state as the command left it, with
/// `FIRST` having been served `served` bytes this cycle: what the step
/// suspended and resumed, carried out on the state.
fn policy_step(harness: &Harness, served: u64) -> (Vec<Suspension>, Vec<Lapsed>) {
    let read = deployment(harness);
    let plan = plan_policy(
        &read,
        &Entitlements::none(),
        Some(&usage(&read, served)),
        UnixTime::from_secs(NOW),
    )
    .unwrap();
    assert_eq!(plan.kept, []);
    assert_eq!(plan.held_back, []);
    let done = carry_out(&store(harness), &plan, None);
    assert!(done.failed.is_empty(), "{:?}", done.failed);
    (done.suspended, done.resumed)
}

/// The quota the command records is the one the apply job acts on, and
/// the command itself suspends and resumes nobody. With 120 GB served this
/// cycle: a quota of 100 GB leaves the user active until the job's policy
/// step suspends them for quota; a quota equal to the use lifts nothing; a
/// quota above it leaves the user suspended until the step resumes them;
/// and removing the quota of a user suspended for it lifts the suspension
/// at the step too. No other user is touched.
#[test]
fn the_apply_job_suspends_and_resumes_by_the_quota_the_command_recorded() {
    let served = 120 * GB;
    let before = fixture(|_| {});
    let mut harness = harness_with(before.clone());
    let cycle_start = BillingCycle::of_instant(before.exit().sim.cycle(), UnixTime::from_secs(NOW))
        .unwrap()
        .start();
    let over = SuspendReason::QuotaExceeded { cycle_start };
    let suspended = UserStatus::Suspended {
        reason: over,
        since: UnixTime::from_secs(NOW),
    };
    let status = |harness: &Harness, user: &str| deployment(harness).users()[&id(user)].status;
    let lifted = [Lapsed {
        user: id(FIRST),
        reason: over,
        since: UnixTime::from_secs(NOW),
        why: Lapse::NoLongerOverQuota,
    }];

    // Without a quota the step proposes nothing.
    assert_eq!(policy_step(&harness, served), (vec![], vec![]));
    set(&mut harness, &["--gb", "100"]);
    assert_eq!(status(&harness, FIRST), UserStatus::Active);
    assert_eq!(
        policy_step(&harness, served),
        (
            vec![Suspension {
                user: id(FIRST),
                reason: over,
            }],
            vec![]
        )
    );
    assert_eq!(status(&harness, FIRST), suspended);

    // A quota that the use has reached still suspends.
    set(&mut harness, &["--gb", "120"]);
    assert_eq!(policy_step(&harness, served), (vec![], vec![]));
    assert_eq!(status(&harness, FIRST), suspended);

    // One above the use lifts the suspension, at the step.
    set(&mut harness, &["--gb", "121"]);
    assert_eq!(status(&harness, FIRST), suspended);
    assert_eq!(policy_step(&harness, served), (vec![], lifted.to_vec()));
    assert_eq!(status(&harness, FIRST), UserStatus::Active);

    // Suspended again under the lower quota, then freed of any quota.
    set(&mut harness, &["--gb", "100"]);
    assert_eq!(policy_step(&harness, served).0.len(), 1);
    assert_eq!(status(&harness, FIRST), suspended);
    set(&mut harness, &["--none"]);
    assert_eq!(status(&harness, FIRST), suspended);
    assert_eq!(policy_step(&harness, served), (vec![], lifted.to_vec()));
    assert_eq!(status(&harness, FIRST), UserStatus::Active);
    assert_eq!(status(&harness, SECOND), UserStatus::Active);
    assert_eq!(
        deployment(&harness).users()[&id(SECOND)].policy,
        UserPolicy::NONE
    );
}
