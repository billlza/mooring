// SPDX-License-Identifier: GPL-3.0-or-later

//! `user make-up` (design §9.6; the agreement's clauses 1 and 3), layer by
//! layer. The payment pull records a make-up on its ledger only for an
//! asker who waits, writes it before it keeps it, and records nothing
//! while the ledger cannot be read. A connection hands the request to the
//! loop, waits a bounded while for the decision and then for the write,
//! and ends without a reply when what came of the write does not come:
//! whoever asked cannot tell whether it was recorded, and the command says
//! so. The command names the user by id and alias, asks, and reports the
//! make-up as recorded or each refusal in a sentence. The daemon the
//! command talks to is a stand-in on a Unix socket.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::num::{NonZeroU32, NonZeroU64};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{Arc, mpsc};
use std::time::Duration;

use clap::Parser;
use mooring_daemon_core::control::{
    DaemonReply, DaemonRequest, MAX_REPLY_LINE_BYTES, MAX_REQUEST_LINE_BYTES, ProtocolLine,
    Refusal, encode_line,
};
use mooring_daemon_core::payments::{
    FeedPage, MakeUpAsk, MakeUpGift, MakeUpNumber, MakeUpReason, MakeUpRecord, PaymentLedger,
};
use mooring_model::ids::PublicAlias;
use mooring_model::user::SuspendReason;
use mooring_model::{Deployment, UnixTime, UserId, UserStatus};
use mooring_store::{PAYMENT_LEDGER_FILE, PAYMENTS_DIRECTORY, write_payment_ledger};

use super::daemon::Running;
use super::deployed::{CARRIER, deployed_with, statuses, with_exit_on};
use super::payments::{FIRST, SECOND, connect, grant, harness, ledger_on_disk, page};
use super::sim_accept::{
    BRIEF, DEADLINE, PATIENT, changed, daemon_answering, deployed_control, files_under, reply,
};
use super::support::{Harness, NOW};
use super::user::{fixture, holding};
use crate::cli::Cli;
use crate::daemon::deployed::{self, Stopped};
use crate::daemon::serve::{End, Limits, MAX_CLIENTS, serve};
use crate::daemon::{Control, Handover, Intervals, MakeUpOutcome, MakeUpRequest, RunPaths};
use crate::error::{EXIT_LOCAL, EXIT_USAGE, LocalError};
use crate::payments::notes::{made_up, stamp};
use crate::payments::pull::{Gate, Puller};
use crate::prompt::Answer;
use crate::user_make_up::asked;

const A: &str = "aaaaaaaaaaaaaaaaaaaa";
const DAY: u64 = 86_400;
const GB: u64 = 1_000_000_000;

fn first() -> UserId {
    UserId::parse(FIRST).unwrap()
}

fn at(secs: u64) -> UnixTime {
    UnixTime::from_secs(secs)
}

fn days(count: u32) -> MakeUpAsk {
    MakeUpAsk::Days(NonZeroU32::new(count).unwrap())
}

fn traffic(gigabytes: u64) -> MakeUpAsk {
    MakeUpAsk::TrafficBytes(NonZeroU64::new(gigabytes * GB).unwrap())
}

/// The ledger `page` gives, applied at [`NOW`] for the fixture's users,
/// rehearsing or not.
fn ledger_of(body: &[u8], rehearsal: bool) -> PaymentLedger {
    let page = FeedPage::decode(body, 0).unwrap();
    PaymentLedger::new()
        .apply(&page, fixture(|_| {}).users(), at(NOW), rehearsal)
        .unwrap()
        .ledger
}

/// A ledger in which [`FIRST`] was granted a live month at [`NOW`]: 30
/// days of 100 GB.
fn month_for_first() -> PaymentLedger {
    ledger_of(&page(true, 0, vec![grant(1, A, FIRST)], false), false)
}

/// Writes `ledger` as the harness's payment ledger.
fn write_ledger(harness: &Harness, ledger: &PaymentLedger) {
    write_payment_ledger(&harness.support_dir(), &ledger.encode().unwrap()).unwrap();
}

/// The week [`FIRST`] is given at [`NOW`] for an outage, on the ledger of
/// [`month_for_first`]: it follows the month.
fn week_for_first() -> MakeUpRecord {
    MakeUpRecord {
        number: MakeUpNumber::new(NonZeroU64::MIN),
        user: first(),
        reason: MakeUpReason::Outage,
        granted_at: at(NOW),
        after: 1,
        gift: MakeUpGift::Period {
            from: at(NOW + 30 * DAY),
            until: at(NOW + 37 * DAY),
            quota_bytes: NonZeroU64::new(100 * GB).unwrap(),
        },
    }
}

/// The daemon's line for [`week_for_first`].
fn week_line() -> String {
    format!(
        "make-up 1: user fxuseraaab is given service from {} until {}, with a quota of 100000000000 bytes a billing cycle, for an outage",
        stamp(at(NOW + 30 * DAY)),
        stamp(at(NOW + 37 * DAY))
    )
}

// --- The record ---------------------------------------------------------

/// What an asker heard: the loop's decision, and, once that was that the
/// make-up is taken, what came of the ledger's write.
type Heard = (
    Result<Result<(), Refusal>, mpsc::RecvTimeoutError>,
    Option<Result<MakeUpOutcome, mpsc::RecvTimeoutError>>,
);

/// How the asker of a make-up waits.
#[derive(Debug, Clone, Copy)]
enum Asker {
    /// For the decision, and then for the write.
    Waits,
    /// For the decision only: it has stopped waiting before the write.
    LeavesAtTheDecision,
    /// Not at all: it has gone.
    Gone,
}

/// A request for `ask` for `user`, for an outage, as a connection hands it
/// to the loop, and its asker.
fn asking(user: &str, ask: MakeUpAsk, asker: Asker) -> (MakeUpRequest, Option<Running<Heard>>) {
    let (decided, decision) = Handover::pair();
    let (recorded, outcome) = mpsc::sync_channel(1);
    let request = MakeUpRequest {
        user: UserId::parse(user).unwrap(),
        ask,
        reason: MakeUpReason::Outage,
        decided,
        recorded,
    };
    let heard = match asker {
        Asker::Waits => Some(Running::start(move || {
            let decided = decision.recv_timeout(DEADLINE);
            let recorded = matches!(decided, Ok(Ok(()))).then(|| outcome.recv_timeout(DEADLINE));
            (decided, recorded)
        })),
        Asker::LeavesAtTheDecision => {
            drop(outcome);
            Some(Running::start(move || {
                (decision.recv_timeout(DEADLINE), None)
            }))
        }
        Asker::Gone => None,
    };
    (request, heard)
}

/// A make-up for one who waits is decided, written and then kept: the
/// asker hears that it is taken and then the make-up as recorded, the
/// ledger on disk holds it, what the users are given counts it, and the
/// log's line names it. A make-up refused, or one whose asker has gone
/// before the decision, is neither written nor kept, and nothing is
/// logged.
#[test]
fn the_pull_records_a_make_up_for_one_who_waits() {
    let harness = harness();
    write_ledger(&harness, &month_for_first());
    let mut puller = Puller::open(&harness.support_dir());
    let deployment = fixture(|_| {});
    for (user, ask, refusal) in [
        ("nobodyhere", days(7), Refusal::UnknownUser),
        (SECOND, days(7), Refusal::NoPaidPeriod),
        (SECOND, traffic(5), Refusal::NoQuota),
    ] {
        let (request, heard) = asking(user, ask, Asker::Waits);
        assert!(puller.make_up(&deployment, &request, at(NOW)).is_empty());
        assert_eq!(heard.unwrap().result(), (Ok(Err(refusal)), None), "{user}");
    }
    for user in [FIRST, "nobodyhere"] {
        let (request, heard) = asking(user, days(7), Asker::Gone);
        assert!(heard.is_none());
        assert!(puller.make_up(&deployment, &request, at(NOW)).is_empty());
    }
    assert_eq!(ledger_on_disk(&harness).unwrap(), month_for_first());

    let (request, heard) = asking(FIRST, days(7), Asker::Waits);
    assert_eq!(
        puller.make_up(&deployment, &request, at(NOW)),
        [week_line()]
    );
    assert_eq!(
        heard.unwrap().result(),
        (Ok(Ok(())), Some(Ok(Ok((week_for_first(), None)))))
    );
    assert_eq!(made_up(&week_for_first(), None), week_line());
    let on_disk = ledger_on_disk(&harness).unwrap();
    assert_eq!(
        on_disk.make_ups().values().collect::<Vec<_>>(),
        [&week_for_first()]
    );
    assert_eq!(
        puller.entitlements().user(&first()).unwrap().paid_until(),
        Some(at(NOW + 37 * DAY))
    );
}

/// An asker who stops waiting after the decision does not undo the
/// make-up: it is written and kept, and the log says that they did not
/// hear it.
#[test]
fn a_make_up_whose_asker_left_after_the_decision_is_kept_and_said() {
    let harness = harness();
    write_ledger(&harness, &month_for_first());
    let mut puller = Puller::open(&harness.support_dir());
    let (request, heard) = asking(FIRST, days(7), Asker::LeavesAtTheDecision);
    assert_eq!(
        puller.make_up(&fixture(|_| {}), &request, at(NOW)),
        [format!(
            "{}; whoever asked had stopped waiting before they heard it",
            week_line()
        )]
    );
    assert_eq!(heard.unwrap().result(), (Ok(Ok(())), None));
    assert_eq!(ledger_on_disk(&harness).unwrap().make_ups().len(), 1);
}

/// A make-up whose ledger cannot be written is not kept: the asker hears
/// that it was taken and then that the ledger was not written, and the
/// log says so by the user's id. Once the ledger can be written, the next
/// make-up is numbered 1.
#[test]
fn a_make_up_that_cannot_be_written_is_not_kept() {
    let harness = harness();
    write_ledger(&harness, &month_for_first());
    let mut puller = Puller::open(&harness.support_dir());
    let dir = harness.support_dir().join(PAYMENTS_DIRECTORY);
    let aside = harness.support_dir().join("payments-aside");
    fs::rename(&dir, &aside).unwrap();
    fs::write(&dir, b"not a directory").unwrap();
    let (request, heard) = asking(FIRST, days(7), Asker::Waits);
    let said = puller.make_up(&fixture(|_| {}), &request, at(NOW));
    assert_eq!(said.len(), 1, "{said:?}");
    assert!(
        said[0]
            .starts_with("make-up for user fxuseraaab: the payment ledger could not be written ("),
        "{said:?}"
    );
    assert!(said[0].ends_with("); nothing was recorded"), "{said:?}");
    assert_eq!(
        heard.unwrap().result(),
        (Ok(Ok(())), Some(Ok(Err(Refusal::LedgerNotWritten))))
    );
    assert_eq!(
        puller.entitlements().user(&first()).unwrap().paid_until(),
        Some(at(NOW + 30 * DAY))
    );
    fs::remove_file(&dir).unwrap();
    fs::rename(&aside, &dir).unwrap();
    let (request, heard) = asking(FIRST, days(7), Asker::Waits);
    assert_eq!(
        puller.make_up(&fixture(|_| {}), &request, at(NOW)),
        [week_line()]
    );
    assert_eq!(heard.unwrap().result().0, Ok(Ok(())));
}

/// While the ledger cannot be read, nothing is recorded in it: the asker
/// hears why, and its file is left as it is.
#[test]
fn nothing_is_recorded_while_the_ledger_cannot_be_read() {
    let harness = harness();
    let dir = harness.support_dir().join(PAYMENTS_DIRECTORY);
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join(PAYMENT_LEDGER_FILE), b"not a ledger").unwrap();
    let mut puller = Puller::open(&harness.support_dir());
    assert!(puller.fault().is_some());
    for ask in [days(7), traffic(5)] {
        let (request, heard) = asking(FIRST, ask, Asker::Waits);
        assert!(
            puller
                .make_up(&fixture(|_| {}), &request, at(NOW))
                .is_empty()
        );
        assert_eq!(
            heard.unwrap().result(),
            (Ok(Err(Refusal::LedgerUnreadable)), None)
        );
    }
    assert_eq!(
        fs::read(dir.join(PAYMENT_LEDGER_FILE)).unwrap(),
        b"not a ledger"
    );
}

/// Whether a rehearsal's period gives the user a quota that traffic adds
/// to is as the pull's settings last read say.
#[test]
fn a_rehearsals_period_gives_a_quota_while_the_settings_say_so() {
    let mut harness = harness();
    write_ledger(
        &harness,
        &ledger_of(&page(false, 0, vec![grant(1, A, FIRST)], false), true),
    );
    let mut puller = Puller::open(&harness.support_dir());
    let deployment = fixture(|_| {});
    let (request, heard) = asking(FIRST, traffic(5), Asker::Waits);
    assert!(puller.make_up(&deployment, &request, at(NOW)).is_empty());
    assert_eq!(heard.unwrap().result(), (Ok(Err(Refusal::NoQuota)), None));
    // A tick without room reads the settings and asks nothing.
    connect(&mut harness, 1, true, 1);
    let users = deployment.users().clone();
    let mut clear = || true;
    harness.with_env(|env| {
        puller.tick(
            env,
            &users,
            at(NOW),
            Gate {
                room: None,
                network_clear: &mut clear,
            },
        )
    });
    assert!(harness.portal.requests.borrow().is_empty());
    let (request, heard) = asking(FIRST, traffic(5), Asker::Waits);
    assert_eq!(puller.make_up(&deployment, &request, at(NOW)).len(), 1);
    assert_eq!(heard.unwrap().result().0, Ok(Ok(())));
}

/// The daemon's line for a make-up names its number, its user, what it
/// gave and why, and says what the user's suspension, if any, comes to.
#[test]
fn the_daemons_line_names_the_make_up_and_the_users_suspension() {
    let traffic_record = MakeUpRecord {
        number: MakeUpNumber::new(NonZeroU64::new(12).unwrap()),
        gift: MakeUpGift::Traffic {
            bytes: NonZeroU64::new(5 * GB).unwrap(),
        },
        ..week_for_first()
    };
    let given = "make-up 12: user fxuseraaab is given 5000000000 bytes of traffic for the billing cycle it was given in";
    for (reason, why) in [
        (MakeUpReason::Outage, "for an outage"),
        (MakeUpReason::MistakenCut, "for a mistaken cut"),
        (
            MakeUpReason::Unrefundable,
            "in place of a refund the card can no longer take",
        ),
        (MakeUpReason::MistakenBan, "for a mistaken ban"),
    ] {
        let record = MakeUpRecord {
            reason,
            ..traffic_record.clone()
        };
        assert_eq!(made_up(&record, None), format!("{given}, {why}"));
    }
    let quota = SuspendReason::QuotaExceeded {
        cycle_start: mooring_model::CalendarDate::parse("2026-10-01").unwrap(),
    };
    for (suspended, said) in [
        (
            SuspendReason::Expired,
            "; the user is suspended at expiry, and the nightly apply job resumes them once their paid time covers it, while the cap on active users leaves room",
        ),
        (
            quota,
            "; the user is suspended for quota, and the nightly apply job resumes them once their quota covers what they used this cycle, or in the next billing cycle",
        ),
        (
            SuspendReason::Operator,
            "; the user is suspended, and only the operator resumes them",
        ),
        (
            SuspendReason::AbuseReview,
            "; the user is suspended, and only the operator resumes them",
        ),
    ] {
        assert_eq!(
            made_up(&traffic_record, Some(suspended)),
            format!("{given}, for an outage{said}")
        );
    }
}

// --- The loop -----------------------------------------------------------

/// The deployed loop answers each make-up that waits, in the order they
/// came, against the state as it is: the log says what was recorded, and
/// of the files under the support directory only the payment ledger has
/// changed.
#[test]
fn the_loop_answers_each_make_up_and_changes_no_other_file() {
    let mut harness = deployed_with(fixture(|_| {}));
    write_ledger(&harness, &month_for_first());
    let support = harness.support_dir();
    let (log, before, heard, after) = with_exit_on(&mut harness, Intervals::DAEMON, |exit, log| {
        let before = files_under(&support);
        let (requests, waiting) = mpsc::channel();
        let askers: Vec<Running<Heard>> = [(FIRST, days(7)), (SECOND, traffic(5))]
            .into_iter()
            .map(|(user, ask)| {
                let (request, heard) = asking(user, ask, Asker::Waits);
                requests.send(request).unwrap();
                heard.unwrap()
            })
            .collect();
        exit.make_ups(log, &waiting).unwrap();
        let after = files_under(&support);
        let heard: Vec<Heard> = askers.into_iter().map(Running::result).collect();
        (
            String::from_utf8(log.clone()).unwrap(),
            before,
            heard,
            after,
        )
    });
    assert_eq!(
        heard,
        [
            (Ok(Ok(())), Some(Ok(Ok((week_for_first(), None))))),
            (Ok(Err(Refusal::NoQuota)), None),
        ]
    );
    assert_eq!(log.matches("make-up").count(), 1, "{log}");
    assert!(
        log.contains(&format!("mooringctl daemon: {}\n", week_line())),
        "{log}"
    );
    assert_eq!(
        changed(&before, &after),
        [PathBuf::from(PAYMENTS_DIRECTORY).join(PAYMENT_LEDGER_FILE)]
    );
    assert!(before.len() > 1, "{:?}", before.keys());
}

/// The loop as the daemon runs it answers a make-up that waits for it.
#[test]
fn the_served_loop_answers_a_make_up_that_waits() {
    let mut harness = deployed_with(fixture(|_| {}));
    harness.probes.borrow_mut().push_back(Ok(CARRIER));
    statuses(&harness);
    write_ledger(&harness, &month_for_first());
    let (control, asked) = Control::new();
    let (request, heard) = asking(FIRST, days(7), Asker::Waits);
    control.make_up.try_send(request).unwrap();
    let (ended, acceptor_ended) = mpsc::channel();
    ended.send(()).unwrap();
    let stopped = with_exit_on(&mut harness, Intervals::DAEMON, |exit, log| {
        deployed::serve(exit, log, &control, &acceptor_ended, &asked).unwrap()
    });
    assert_eq!(stopped, Stopped::AcceptorEnded);
    assert_eq!(
        heard.unwrap().result(),
        (Ok(Ok(())), Some(Ok(Ok((week_for_first(), None)))))
    );
    assert_eq!(ledger_on_disk(&harness).unwrap().make_ups().len(), 1);
}

// --- The connection -----------------------------------------------------

/// The request for a week for [`FIRST`], for an outage.
fn week_request() -> DaemonRequest {
    DaemonRequest::MakeUp {
        user: first(),
        ask: days(7),
        reason: MakeUpReason::Outage,
    }
}

/// Serves one connection under `limits` whose client has sent
/// [`week_request`]: the client's reader, past the protocol line, and how
/// the connection ended. The client's time limit is set before the
/// connection is served: setsockopt(2) fails on macOS once the peer has
/// closed.
fn asked_to_make_up(
    control: &Arc<Control>,
    limits: Limits,
) -> (BufReader<UnixStream>, Running<End>) {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.set_read_timeout(Some(DEADLINE)).unwrap();
    client
        .write_all(&encode_line(&week_request(), MAX_REQUEST_LINE_BYTES).unwrap())
        .unwrap();
    let control = Arc::clone(control);
    let served = Running::start(move || serve(server, &control, limits));
    let mut reader = BufReader::new(client);
    let mut line = Vec::new();
    reader.read_until(b'\n', &mut line).unwrap();
    assert_eq!(
        line,
        encode_line(&ProtocolLine::CURRENT, MAX_REPLY_LINE_BYTES).unwrap()
    );
    (reader, served)
}

/// What is left on `reader`: nothing, once the connection ended without a
/// reply.
fn rest(mut reader: BufReader<UnixStream>) -> Vec<u8> {
    let mut rest = Vec::new();
    reader.read_to_end(&mut rest).unwrap();
    rest
}

/// Without a deployment the request is refused, and the loop hears
/// nothing of it.
#[test]
fn a_make_up_is_refused_without_a_deployment() {
    let (control, asked) = Control::new();
    let (mut reader, served) = asked_to_make_up(&Arc::new(control), PATIENT);
    assert_eq!(
        reply(&mut reader),
        DaemonReply::Refused {
            reason: Refusal::NotDeployed
        }
    );
    assert_eq!(served.result(), End::Refused(Refusal::NotDeployed));
    assert!(asked.make_ups.try_recv().is_err());
}

/// The request reaches the loop as it was asked, and what the loop
/// answers goes back to the client: the make-up as recorded, with the
/// user's suspension; a refusal at the decision; or, after the decision,
/// that the ledger could not be written.
#[test]
fn the_loops_decision_and_its_write_go_back_to_the_client() {
    let (control, asked) = deployed_control();
    let (mut reader, served) = asked_to_make_up(&control, PATIENT);
    let request = asked.make_ups.recv_timeout(DEADLINE).unwrap();
    assert_eq!(
        (request.user.clone(), request.ask, request.reason),
        (first(), days(7), MakeUpReason::Outage)
    );
    assert!(request.decided.send(Ok(())).is_ok());
    let suspended = Some(SuspendReason::Operator);
    assert!(
        request
            .recorded
            .send(Ok((week_for_first(), suspended)))
            .is_ok()
    );
    assert_eq!(
        reply(&mut reader),
        DaemonReply::MadeUp {
            record: week_for_first(),
            suspended
        }
    );
    assert_eq!(served.result(), End::Answered);

    for refusal in [
        Refusal::UnknownUser,
        Refusal::NoPaidPeriod,
        Refusal::LedgerUnreadable,
    ] {
        let (mut reader, served) = asked_to_make_up(&control, PATIENT);
        let request = asked.make_ups.recv_timeout(DEADLINE).unwrap();
        assert!(request.decided.send(Err(refusal)).is_ok());
        assert_eq!(reply(&mut reader), DaemonReply::Refused { reason: refusal });
        assert_eq!(served.result(), End::Refused(refusal));
    }

    let (mut reader, served) = asked_to_make_up(&control, PATIENT);
    let request = asked.make_ups.recv_timeout(DEADLINE).unwrap();
    assert!(request.decided.send(Ok(())).is_ok());
    assert!(
        request
            .recorded
            .send(Err(Refusal::LedgerNotWritten))
            .is_ok()
    );
    assert_eq!(
        reply(&mut reader),
        DaemonReply::Refused {
            reason: Refusal::LedgerNotWritten
        }
    );
    assert_eq!(served.result(), End::Refused(Refusal::LedgerNotWritten));
}

/// A loop that does not come to the request within the decision's limit
/// is reported as busy, and when it comes to it then, it finds no one to
/// hand its decision to: it records nothing for a client that was told
/// nothing was changed.
#[test]
fn a_loop_late_to_decide_is_reported_busy_and_then_finds_no_one_waiting() {
    let (control, asked) = deployed_control();
    let (mut reader, served) = asked_to_make_up(&control, BRIEF);
    let request = asked.make_ups.recv_timeout(DEADLINE).unwrap();
    assert_eq!(
        reply(&mut reader),
        DaemonReply::Refused {
            reason: Refusal::LoopBusy
        }
    );
    assert_eq!(served.result(), End::Refused(Refusal::LoopBusy));
    assert!(request.decided.send(Ok(())).is_err());
}

/// The loop hands its answer to a connection over a [`Handover`], a
/// make-up's decision as a network to take: the send returns only once the
/// connection took the answer, and fails once the connection stopped
/// waiting, so the loop never acts on an answer that no one heard.
#[test]
fn the_loops_answer_is_handed_only_to_a_connection_that_takes_it() {
    let (handover, taken) = Handover::pair();
    let (sent, returned) = mpsc::channel();
    let handing = Running::start(move || {
        let outcome = handover.send(7_u8);
        sent.send(outcome.is_ok()).unwrap();
    });
    // No one has taken the answer yet, so the send has not returned.
    assert_eq!(
        returned.recv_timeout(BRIEF.answer),
        Err(mpsc::RecvTimeoutError::Timeout)
    );
    assert_eq!(taken.recv_timeout(DEADLINE), Ok(7));
    assert_eq!(returned.recv_timeout(DEADLINE), Ok(true));
    handing.result();

    let (handover, taken) = Handover::pair();
    drop(taken);
    assert_eq!(handover.send(7_u8), Err(mpsc::SendError(7)));
}

/// A loop that takes no request holds as many make-ups as the connections
/// that can wait at once, and no more: the one that finds as many waiting
/// is told that the loop is busy without waiting, and adds none.
#[test]
fn a_loop_that_takes_no_make_up_holds_a_bounded_number_of_them() {
    let (control, asked) = deployed_control();
    let busy = DaemonReply::Refused {
        reason: Refusal::LoopBusy,
    };
    for _ in 0..MAX_CLIENTS {
        let (mut reader, served) = asked_to_make_up(&control, BRIEF);
        assert_eq!(reply(&mut reader), busy);
        assert_eq!(served.result(), End::Refused(Refusal::LoopBusy));
    }
    let (mut reader, served) = asked_to_make_up(&control, PATIENT);
    assert_eq!(reply(&mut reader), busy);
    assert_eq!(served.result(), End::Refused(Refusal::LoopBusy));
    let waiting: Vec<MakeUpRequest> = asked.make_ups.try_iter().collect();
    assert_eq!(waiting.len(), MAX_CLIENTS);
    for request in waiting {
        assert!(request.decided.send(Ok(())).is_err());
    }
}

/// A loop that took the make-up and does not say within the write's
/// limit what came of it leaves the client without a reply: whether it
/// was recorded is not known. Its outcome then finds no one waiting.
#[test]
fn a_write_whose_outcome_does_not_come_leaves_the_client_without_a_reply() {
    let (control, asked) = deployed_control();
    let limits = Limits {
        recorded: Duration::from_millis(50),
        ..PATIENT
    };
    let (reader, served) = asked_to_make_up(&control, limits);
    let request = asked.make_ups.recv_timeout(DEADLINE).unwrap();
    assert!(request.decided.send(Ok(())).is_ok());
    assert_eq!(served.result(), End::RecordUnknown);
    assert_eq!(rest(reader), b"");
    assert!(request.recorded.send(Ok((week_for_first(), None))).is_err());
}

/// A loop that has ended, before the request, with it in hand, or after
/// its decision, ends the connection without a reply.
#[test]
fn a_loop_that_has_ended_ends_the_connection_without_a_reply() {
    let (control, asked) = deployed_control();
    drop(asked);
    let (reader, served) = asked_to_make_up(&control, PATIENT);
    assert_eq!(served.result(), End::Stopping);
    assert_eq!(rest(reader), b"");

    let (control, asked) = deployed_control();
    let (reader, served) = asked_to_make_up(&control, PATIENT);
    drop(asked.make_ups.recv_timeout(DEADLINE).unwrap());
    assert_eq!(served.result(), End::Stopping);
    assert_eq!(rest(reader), b"");

    let (control, asked) = deployed_control();
    let (reader, served) = asked_to_make_up(&control, PATIENT);
    let request = asked.make_ups.recv_timeout(DEADLINE).unwrap();
    assert!(request.decided.send(Ok(())).is_ok());
    drop(request);
    assert_eq!(served.result(), End::Stopping);
    assert_eq!(rest(reader), b"");
}

// --- The command --------------------------------------------------------

/// A harness whose home is short enough for the control socket's path,
/// holding `deployment`.
fn command_harness(deployment: Deployment) -> Harness {
    holding(super::daemon::harness(), deployment)
}

/// What the command prints before it asks for a week for [`FIRST`].
const DESCRIBED: &str = "make-up: user fxuseraaab is to be given 7 day(s) of service, from the end of their paid time or from now once that has passed, with the quota of their last paid period, for an outage\n";

/// The request for a week for [`FIRST`], as the daemon reads it.
const WEEK: &str =
    "{\"make_up\":{\"user\":\"fxuseraaab\",\"ask\":{\"days\":7},\"reason\":\"outage\"}}\n";

const QUESTION: &str = "Record this make-up? It cannot be undone.";

/// What the command prints of [`week_for_first`] recorded.
fn recorded_week() -> String {
    format!(
        "recorded {}; the console shows it from the daemon's next status, and the portal once `portal export` is imported there again; no node apply is needed\n",
        week_line()
    )
}

/// The command names the user, asks, sends the make-up and prints it as
/// recorded; with `--yes` it does not ask.
#[test]
fn the_command_names_the_user_asks_and_prints_the_make_up_recorded() {
    let recorded = DaemonReply::MadeUp {
        record: week_for_first(),
        suspended: None,
    };
    for yes in [false, true] {
        let mut harness = command_harness(fixture(|_| {}));
        let daemon = daemon_answering(&harness, vec![recorded.clone()]);
        let mut args = vec![
            "user", "make-up", FIRST, "--days", "7", "--reason", "outage",
        ];
        if yes {
            args.push("--yes");
        } else {
            harness.console.answers.push_back(Answer::Yes);
        }
        let outcome = harness.run(&args);
        assert_eq!(daemon.result(), [WEEK]);
        assert_eq!(outcome.code, 0, "{}", outcome.stderr);
        assert_eq!(outcome.stdout, format!("{DESCRIBED}{}", recorded_week()));
        assert_eq!(outcome.stderr, "");
        if yes {
            assert!(harness.console.asked.is_empty());
        } else {
            assert_eq!(harness.console.asked, [QUESTION]);
        }
    }
}

/// The user is named with their alias when they have one; traffic is
/// asked in decimal gigabytes, each reason by its own name, and printed
/// as the daemon recorded it.
#[test]
fn the_command_names_the_alias_and_asks_traffic_in_gigabytes() {
    let alias = PublicAlias::from_random_bytes([0x9b, 0x18, 0x6d, 0x0e, 0x55]);
    let mut aliased = command_harness(fixture(|parts| {
        parts.users[0].alias = Some(alias.clone());
    }));
    let record = MakeUpRecord {
        reason: MakeUpReason::MistakenCut,
        gift: MakeUpGift::Traffic {
            bytes: NonZeroU64::new(20 * GB).unwrap(),
        },
        ..week_for_first()
    };
    let suspended = Some(SuspendReason::Operator);
    let daemon = daemon_answering(
        &aliased,
        vec![DaemonReply::MadeUp {
            record: record.clone(),
            suspended,
        }],
    );
    let outcome = aliased.run(&[
        "user",
        "make-up",
        FIRST,
        "--gb",
        "20",
        "--reason",
        "mistaken-cut",
        "--yes",
    ]);
    assert_eq!(
        daemon.result(),
        [
            "{\"make_up\":{\"user\":\"fxuseraaab\",\"ask\":{\"traffic_bytes\":20000000000},\"reason\":\"mistaken_cut\"}}\n"
        ]
    );
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(
        outcome.stdout,
        format!(
            "make-up: user fxuseraaab ({alias}) is to be given 20 GB (20000000000 bytes) of traffic for this billing cycle, for a mistaken cut\n\
             recorded {}; the console shows it from the daemon's next status, and the portal once `portal export` is imported there again; no node apply is needed\n",
            made_up(&record, suspended)
        )
    );
    for (reason, phrase, wire) in [
        (
            "unrefundable",
            "in place of a refund the card can no longer take",
            "unrefundable",
        ),
        ("mistaken-ban", "for a mistaken ban", "mistaken_ban"),
    ] {
        let mut harness = command_harness(fixture(|_| {}));
        let daemon = daemon_answering(
            &harness,
            vec![DaemonReply::Refused {
                reason: Refusal::NoQuota,
            }],
        );
        let outcome = harness.run(&[
            "user", "make-up", FIRST, "--days", "2", "--reason", reason, "--yes",
        ]);
        assert_eq!(
            daemon.result(),
            [format!(
                "{{\"make_up\":{{\"user\":\"fxuseraaab\",\"ask\":{{\"days\":2}},\"reason\":\"{wire}\"}}}}\n"
            )]
        );
        assert_eq!(outcome.code, EXIT_LOCAL);
        assert_eq!(
            outcome.stdout,
            format!(
                "make-up: user fxuseraaab is to be given 2 day(s) of service, from the end of their paid time or from now once that has passed, with the quota of their last paid period, {phrase}\n"
            )
        );
    }
}

/// An answer other than yes sends the daemon nothing: no daemon listens,
/// and the command does not try to reach one.
#[test]
fn an_answer_other_than_yes_sends_the_daemon_nothing() {
    for (answer, stderr) in [
        (
            Answer::No,
            "mooringctl: not recorded: the answer was not yes\n",
        ),
        (
            Answer::NoTerminal,
            "mooringctl: not recorded: no terminal to ask and --yes was not given\n",
        ),
    ] {
        let mut harness = command_harness(fixture(|_| {}));
        harness.console.answers.push_back(answer);
        let outcome = harness.run(&[
            "user", "make-up", FIRST, "--days", "7", "--reason", "outage",
        ]);
        assert_eq!(outcome.code, EXIT_LOCAL);
        assert_eq!(outcome.stdout, DESCRIBED);
        assert_eq!(outcome.stderr, stderr);
        assert_eq!(harness.console.asked, [QUESTION]);
    }
}

/// A user the deployment does not hold, or one being revoked or revoked,
/// is refused before anything is asked or sent.
#[test]
fn a_user_unknown_or_revoked_is_refused_at_once() {
    let mut harness = command_harness(fixture(|_| {}));
    let outcome = harness.run(&[
        "user",
        "make-up",
        "nobodyhere",
        "--days",
        "7",
        "--reason",
        "outage",
    ]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(outcome.stdout, "");
    assert_eq!(outcome.stderr, "mooringctl: unknown user nobodyhere\n");
    for status in [
        UserStatus::RevokePending,
        UserStatus::Revoked { since: at(NOW) },
    ] {
        let revoking = status == UserStatus::RevokePending;
        let mut harness = command_harness(fixture(|parts| {
            let user = &mut parts.users[1];
            assert_eq!(user.id.as_str(), SECOND);
            if !revoking {
                user.per_node.clear();
            }
            user.status = status;
        }));
        let outcome = harness.run(&[
            "user", "make-up", SECOND, "--gb", "5", "--reason", "outage", "--yes",
        ]);
        assert_eq!(outcome.code, EXIT_LOCAL);
        assert_eq!(outcome.stdout, "");
        assert_eq!(
            outcome.stderr,
            "mooringctl: user fxuseraaac is being revoked or is revoked, and a make-up is given only to a user who is not; nothing was recorded\n"
        );
        assert!(harness.console.asked.is_empty());
    }
}

/// Each refusal of the daemon is reported in its own sentence, and a
/// reply to another request is refused.
#[test]
fn each_refusal_of_the_daemon_is_reported_in_its_sentence() {
    let other_request = "the daemon answered with a reply to another request";
    let refused = |sentence: &str| format!("the daemon refused the request: {sentence}");
    for (answer, said) in [
        (Refusal::UnknownUser, refused("the deployment holds no user of that id; nothing was recorded")),
        (Refusal::UserRevoked, refused("the user is being revoked or is revoked; nothing was recorded")),
        (Refusal::NoPaidPeriod, refused("the user has no paid service period to extend, so days of service give them nothing; nothing was recorded (give traffic instead)")),
        (Refusal::NoQuota, refused("the user has no quota this billing cycle, so traffic adds nothing; nothing was recorded (give days instead)")),
        (Refusal::QuotaUnknown, refused("the user's quota cannot be computed now, as the console says; nothing was recorded")),
        (Refusal::BeyondCalendar, refused("the service would end after 9999-12-31; nothing was recorded")),
        (Refusal::MakeUpNumbersSpent, refused("the payment ledger has numbered as many make-ups as it can; nothing was recorded")),
        (Refusal::LedgerUnreadable, refused("the payment ledger could not be read when the daemon started, so nothing is recorded in it until the daemon starts again; nothing was recorded")),
        (Refusal::LedgerNotWritten, refused("the payment ledger could not be written, as the daemon's log says; nothing was recorded")),
        (Refusal::LoopBusy, refused("its loop did not come to the request in time; nothing was changed, try again")),
        (Refusal::NotDeployed, refused("there is no deployment yet (`exit init` creates it)")),
    ]
    .map(|(reason, said)| (DaemonReply::Refused { reason }, said))
    .into_iter()
    .chain([
        (DaemonReply::RetryQueued, other_request.to_owned()),
        (DaemonReply::SimNetworkAccepted, other_request.to_owned()),
    ]) {
        let mut harness = command_harness(fixture(|_| {}));
        let daemon = daemon_answering(&harness, vec![answer]);
        let outcome = harness.run(&[
            "user", "make-up", FIRST, "--days", "7", "--reason", "outage", "--yes",
        ]);
        assert_eq!(daemon.result(), [WEEK]);
        assert_eq!(outcome.code, EXIT_LOCAL, "{said}");
        assert_eq!(outcome.stdout, DESCRIBED);
        assert_eq!(outcome.stderr, format!("mooringctl: {said}\n"));
    }
}

/// Without a daemon the command says that it is not running: nothing was
/// recorded.
#[test]
fn without_a_daemon_the_command_says_that_it_is_not_running() {
    let mut harness = command_harness(fixture(|_| {}));
    let socket = RunPaths::under(&harness.support_dir()).socket;
    let outcome = harness.run(&[
        "user", "make-up", FIRST, "--days", "7", "--reason", "outage", "--yes",
    ]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(outcome.stdout, DESCRIBED);
    assert_eq!(
        outcome.stderr,
        format!(
            "mooringctl: the Mooring daemon is not running (nothing listens on {})\n",
            socket.display()
        )
    );
}

/// A daemon that could not be reached heard nothing, so nothing was
/// recorded: the command says why it could not reach it, as any command
/// does. A harness's own home is too long for a socket's path.
#[test]
fn a_daemon_that_could_not_be_reached_heard_nothing() {
    let mut harness = harness();
    let socket = RunPaths::under(&harness.support_dir()).socket;
    let outcome = harness.run(&[
        "user", "make-up", FIRST, "--days", "7", "--reason", "outage", "--yes",
    ]);
    assert_eq!(outcome.code, EXIT_LOCAL);
    assert_eq!(outcome.stdout, DESCRIBED);
    assert_eq!(
        outcome.stderr,
        format!(
            "mooringctl: talking to the daemon on {} failed\n  caused by: path must be shorter than SUN_LEN\n",
            socket.display()
        )
    );
}

/// A stand-in daemon on the harness's control socket that sends `first`
/// as its first line, reads the request, sends `then`, and closes; it
/// returns the request.
fn daemon_sending(harness: &Harness, first: Vec<u8>, then: Vec<u8>) -> Running<String> {
    let paths = RunPaths::under(&harness.support_dir());
    fs::create_dir_all(&paths.dir).unwrap();
    let listener = UnixListener::bind(&paths.socket).unwrap();
    Running::start(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.write_all(&first).unwrap();
        let mut request = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut request)
            .unwrap();
        stream.write_all(&then).unwrap();
        request
    })
}

/// A daemon that read the request and gave no answer may have recorded the
/// make-up: the command says that whether it did is not known, and where
/// to look. So does a daemon of a later protocol, which may read the
/// request. A daemon of an earlier protocol, or of none, cannot read it,
/// and is reported as such.
#[test]
fn a_make_up_without_an_answer_is_said_to_be_unknown() {
    let protocol = encode_line(&ProtocolLine::CURRENT, MAX_REPLY_LINE_BYTES).unwrap();
    let unknown = |causes: &str| {
        format!(
            "mooringctl: the daemon gave no answer to the make-up, so whether it was recorded is not known: `mooringctl portal payments` lists every make-up recorded; read it before asking again\n{causes}"
        )
    };
    let closed = "  caused by: the daemon closed the status stream\n";
    for (first, then, stderr) in [
        (protocol.clone(), Vec::new(), unknown(closed)),
        (
            protocol.clone(),
            b"{\"made_up\":{}}\n".to_vec(),
            unknown(
                "  caused by: the daemon's reply could not be read\n  caused by: a control line is not a well-formed request or reply\n",
            ),
        ),
        (protocol.clone(), b"{\"made_up\"".to_vec(), unknown(closed)),
        (
            b"{\"control_protocol\":6}\n".to_vec(),
            Vec::new(),
            unknown(
                "  caused by: the daemon speaks control protocol 6 and this mooringctl speaks 5: use the mooringctl inside Mooring.app, and after updating the app restart the daemon (Stop the Daemon, then Start the Daemon at Login, in Mooring's menu)\n",
            ),
        ),
        (
            b"{\"control_protocol\":4}\n".to_vec(),
            Vec::new(),
            "mooringctl: the daemon speaks control protocol 4 and this mooringctl speaks 5: use the mooringctl inside Mooring.app, and after updating the app restart the daemon (Stop the Daemon, then Start the Daemon at Login, in Mooring's menu)\n".to_owned(),
        ),
        (
            b"\"status\"\n".to_vec(),
            Vec::new(),
            "mooringctl: the daemon did not name its control protocol on its first line, as a daemon built before this mooringctl may not: restart the daemon (Stop the Daemon, then Start the Daemon at Login, in Mooring's menu)\n".to_owned(),
        ),
    ] {
        let mut harness = command_harness(fixture(|_| {}));
        let daemon = daemon_sending(&harness, first, then);
        let outcome = harness.run(&[
            "user", "make-up", FIRST, "--days", "7", "--reason", "outage", "--yes",
        ]);
        assert_eq!(daemon.result(), WEEK);
        assert_eq!(outcome.code, EXIT_LOCAL, "{stderr}");
        assert_eq!(outcome.stdout, DESCRIBED);
        assert_eq!(outcome.stderr, stderr);
    }
}

/// The command line takes either `--days` or `--gb`, each a whole number
/// from 1, and one of the four reasons; anything else is a usage error.
/// The two are one ask, whatever the command line lets through.
#[test]
fn the_command_line_takes_days_or_gigabytes_and_a_reason() {
    for args in [
        &["mooringctl", "user", "make-up", FIRST, "--reason", "outage"][..],
        &[
            "mooringctl",
            "user",
            "make-up",
            FIRST,
            "--days",
            "1",
            "--gb",
            "1",
            "--reason",
            "outage",
        ],
        &[
            "mooringctl",
            "user",
            "make-up",
            FIRST,
            "--days",
            "0",
            "--reason",
            "outage",
        ],
        &[
            "mooringctl",
            "user",
            "make-up",
            FIRST,
            "--gb",
            "0",
            "--reason",
            "outage",
        ],
        &[
            "mooringctl",
            "user",
            "make-up",
            FIRST,
            "--days",
            "-1",
            "--reason",
            "outage",
        ],
        &["mooringctl", "user", "make-up", FIRST, "--days", "7"],
        &[
            "mooringctl",
            "user",
            "make-up",
            FIRST,
            "--days",
            "7",
            "--reason",
            "goodwill",
        ],
        &[
            "mooringctl",
            "user",
            "make-up",
            "Not-An-Id",
            "--days",
            "7",
            "--reason",
            "outage",
        ],
    ] {
        let error = Cli::try_parse_from(args).unwrap_err();
        assert_eq!(error.exit_code(), i32::from(EXIT_USAGE), "{args:?}");
    }
    for reason in ["outage", "mistaken-cut", "unrefundable", "mistaken-ban"] {
        Cli::try_parse_from([
            "mooringctl",
            "user",
            "make-up",
            FIRST,
            "--days",
            "4294967295",
            "--reason",
            reason,
        ])
        .unwrap();
        Cli::try_parse_from([
            "mooringctl",
            "user",
            "make-up",
            FIRST,
            "--gb",
            "4294967295",
            "--reason",
            reason,
        ])
        .unwrap();
    }
    let one = NonZeroU32::MIN;
    assert_eq!(asked(Some(one), None).unwrap(), MakeUpAsk::Days(one));
    assert_eq!(
        asked(None, Some(NonZeroU32::MAX)).unwrap(),
        MakeUpAsk::TrafficBytes(NonZeroU64::new(u64::from(u32::MAX) * GB).unwrap())
    );
    for (days, gb) in [(Some(one), Some(one)), (None, None)] {
        let error = asked(days, gb).unwrap_err();
        assert!(matches!(error, LocalError::MakeUpAsk), "{error:?}");
        assert_eq!(
            error.to_string(),
            "give `user make-up` either --days or --gb: one of them, not both"
        );
    }
}
